#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ! $1 =~ ^[a-z_]+$ || ! $2 =~ ^[a-z_]+$ ]]; then
  echo "usage: $0 <integration-test-target> <exact-ignored-test-name>" >&2
  exit 2
fi
target=$1
test_name=$2
if [[ $target == native_target || $target == native_volume || $target == native_network || $target == native_volume_label || $target == native_identity || $target == native_port || $target == native_health_metadata || $target == native_network_attachment || $target == native_bind_relabel || $target == native_external_network || $target == native_stop_signal || $target == native_lifecycle || $target == native_runtime_filesystem || $target == native_tmpfs_effect || $target == native_health_start_interval_boundary || $target == native_lifecycle_default_effect || $target == native_hostname || $target == native_command_clear || $target == native_shm_size || $target == native_supplementary_groups || $target == native_kernel_settings || $target == native_pids ]]; then
  # Native target tests need crate-private, test-only capability claims.
  # It is a library unit test; no public constructor is exposed for the harness.
  cargo_target=(--lib)
  selected="${target}_tests::$test_name"
  if [[ $target == native_stop_signal ]]; then
    selected="native_health_metadata_tests::stop_signal::$test_name"
  elif [[ $target == native_lifecycle ]]; then
    selected="native_health_metadata_tests::lifecycle::$test_name"
  elif [[ $target == native_runtime_filesystem ]]; then
    selected="native_health_metadata_tests::lifecycle::runtime_filesystem::$test_name"
  elif [[ $target == native_tmpfs_effect ]]; then
    selected="native_health_metadata_tests::lifecycle::tmpfs_effect::$test_name"
  elif [[ $target == native_health_start_interval_boundary ]]; then
    selected="native_health_metadata_tests::lifecycle::health_start_interval_boundary::$test_name"
  elif [[ $target == native_lifecycle_default_effect ]]; then
    selected="native_health_metadata_tests::lifecycle::default_effect::$test_name"
  elif [[ $target == native_hostname ]]; then
    selected="native_health_metadata_tests::lifecycle::hostname::$test_name"
  elif [[ $target == native_command_clear ]]; then
    selected="native_health_metadata_tests::command_clear::$test_name"
  elif [[ $target == native_shm_size ]]; then
    selected="native_health_metadata_tests::lifecycle::shm_size::$test_name"
  elif [[ $target == native_supplementary_groups ]]; then
    selected="native_health_metadata_tests::lifecycle::supplementary_groups::$test_name"
  elif [[ $target == native_kernel_settings ]]; then
    selected="native_health_metadata_tests::lifecycle::kernel_settings::$test_name"
  elif [[ $target == native_pids ]]; then
    selected="native_health_metadata_tests::lifecycle::pids::$test_name"
  fi
else
  cargo_target=(--test "$target")
  selected=$test_name
fi

# libtest returns success for zero selected tests. Check the ignored-only list
# first, then require exactly one executed success in the final summary.
exact_pids=0
capture_directory=
if [[ $target == native_pids && $test_name == live_pids_limits_and_effects_match_engine ]]; then
  exact_pids=1
  capture_directory=$(mktemp -d 2>/dev/null) || {
    echo "required native test private capture unavailable" >&2
    exit 1
  }
  remove_native_capture() {
    if [[ -z $capture_directory ]]; then return 0; fi
    local held_directory=$capture_directory
    capture_directory=
    if ! rm -rf -- "$held_directory" >/dev/null 2>&1; then
      echo "required native test private capture cleanup unavailable" >&2
      return 1
    fi
  }
  cleanup_native_capture() {
    local status=$?
    trap - EXIT
    if ! remove_native_capture; then
      if (( status == 0 )); then status=1; fi
    fi
    exit "$status"
  }
  trap cleanup_native_capture EXIT
fi

capture_native_raw() {
  # Keep at most 1 MiB plus one overflow byte, but drain to EOF so capture
  # overflow cannot replace the original Cargo status with a broken pipe.
  python3 -I -c '
import os, sys
failed, size = False, 0
try:
    descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    output = os.fdopen(descriptor, "wb")
except OSError:
    failed, output = True, None
try:
    while part := sys.stdin.buffer.read(65536):
        if output is not None and size < 1048577:
            retained = part[:1048577 - size]
            try:
                output.write(retained)
            except OSError:
                failed = True
            size += len(retained)
    if output is not None:
        try:
            output.close()
        except OSError:
            failed = True
except OSError:
    failed = True
sys.exit(1 if failed else 2 if size > 1048576 else 0)
' "$1" 2>/dev/null
}

materialize_native_raw() {
  # Validate original bytes before Bash can discard NUL or issue a path-bearing
  # command-substitution warning. Ordinary UTF-8 and ANSI output is unchanged.
  python3 -I -c '
import os, stat, sys
try:
    descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as capture:
        info = os.fstat(capture.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 1048576):
            raise ValueError()
        data = capture.read(1048577)
    if len(data) != info.st_size or b"\0" in data:
        raise ValueError()
    sys.stdout.buffer.write(data)
except (OSError, ValueError):
    sys.exit(1)
' "$1" 2>/dev/null
}

list_status=0
if (( exact_pids )); then
  set +e
  timeout 180 cargo test --locked "${cargo_target[@]}" -- --ignored --list 2>&1 | capture_native_raw "$capture_directory/list.raw"
  capture_status=("${PIPESTATUS[@]}")
  set -e
  list_status=${capture_status[0]}
  listing=
  if (( capture_status[1] != 0 )) || ! listing=$(materialize_native_raw "$capture_directory/list.raw"); then
    if (( list_status == 0 )); then list_status=1; fi
  fi
else
  listing=$(timeout 180 cargo test --locked "${cargo_target[@]}" -- --ignored --list 2>&1) || list_status=$?
fi
if (( list_status != 0 )); then
  echo "failed to list required ignored native test $target::$test_name (exit $list_status)" >&2
  exit 1
fi
if [[ $(grep -Fxc "$selected: test" <<<"$listing" || true) != 1 ]]; then
  echo "required ignored native test $target::$test_name is absent" >&2
  exit 1
fi
run_status=0
# Bind optional failure diagnostics to this invocation's existing hard timeout.
# The native test reserves its own cleanup and reporting margin before this time.
run_deadline_epoch=$(( $(date +%s) + 180 ))
run_exact_native() {
  NATIVE_NETWORK_TEST_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_HEALTH_METADATA_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_STOP_SIGNAL_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_LIFECYCLE_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_RUNTIME_FILESYSTEM_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_TMPFS_EFFECT_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_HEALTH_START_INTERVAL_BOUNDARY_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_LIFECYCLE_DEFAULT_EFFECT_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_HOSTNAME_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_COMMAND_CLEAR_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_SHM_SIZE_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_SUPPLEMENTARY_GROUPS_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_KERNEL_SETTINGS_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_PIDS_DEADLINE_EPOCH=$run_deadline_epoch timeout 180 cargo test --locked "${cargo_target[@]}" -- --ignored --exact "$selected" 2>&1
}
raw_capture_invalid=0
if (( exact_pids )); then
  set +e
  run_exact_native | capture_native_raw "$capture_directory/run.raw"
  capture_status=("${PIPESTATUS[@]}")
  set -e
  run_status=${capture_status[0]}
  original_run_status=$run_status
  result=
  if (( capture_status[1] != 0 )) || ! result=$(materialize_native_raw "$capture_directory/run.raw"); then
    raw_capture_invalid=1
    if (( run_status == 0 )); then run_status=1; fi
  fi
else
  result=$(run_exact_native) || run_status=$?
fi
pids_setup_refusal=
if (( exact_pids && !raw_capture_invalid )); then
  # Validate the original file, not a Bash-normalized string. Only one distinct
  # valid general/detail record may project; identical duplicates deduplicate.
  # Either prefix, even malformed/unpaired, contradicts evidence or success.
  setup_projection_status=0
  pids_setup_refusal=$(python3 -I -c '
import os, re, stat, sys
try:
    descriptor = os.open(sys.argv[2], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as capture:
        info = os.fstat(capture.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 1048576):
            raise ValueError()
        data = capture.read(1048577)
    if len(data) != info.st_size or b"\0" in data:
        raise ValueError()
    prefix = b"DOCKERLENS_NATIVE_PIDS_SETUP_REFUSAL: code="
    lines = data.split(b"\n")
    detail_prefix = b"DOCKERLENS_NATIVE_PIDS_IO:"
    startup_prefix = b"DOCKERLENS_NATIVE_PIDS_START:"
    seen = any(line.startswith((b"DOCKERLENS_NATIVE_PIDS_SETUP_REFUSAL:", detail_prefix, startup_prefix)) for line in lines)
    positive = any(line == b"DOCKERLENS_NATIVE_CHECK: pids_evidence" or line.startswith(b"test result: ok.") for line in lines)
    if seen and (positive or sys.argv[3] == "0"):
        sys.stdout.buffer.write(prefix + b"unclassified\n")
        sys.exit(3)
    descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as registry:
        info = os.fstat(registry.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 704:
            raise ValueError()
        registry_data = registry.read(705)
    if len(registry_data) != info.st_size or not registry_data.endswith(b"\n"):
        raise ValueError()
    codes = registry_data[:-1].split(b"\n")
    if (len(codes) != 32 or codes != sorted(set(codes))
            or any(len(code) > 21 or re.fullmatch(rb"pids-[a-z]+(?:-[a-z]+)*", code) is None for code in codes)):
        raise ValueError()
    allowed = set(codes) | {b"unclassified"}
    candidate, tainted = None, False
    detail, detail_tainted = None, False
    startup, startup_tainted = None, False
    startup_sites = set(b"s_imports s_args s_fd0 s_socket_wrap s_root_uid s_root_deadline s_gate_pipe s_block_signals s_source_fork s_par_gate_close s_par_pgroup s_par_pidfd s_par_sockclose s_par_gate_send s_par_gate_done s_mon_handlers s_mon_unmask s_mon_wait s_peer_shape s_peer_cred s_peer_pidfd s_peer_cloexec s_peer_live w_kid_gate_close w_kid_pgroup w_kid_pdeath w_kid_parent w_kid_gate_read w_kid_gate_done w_kid_unmask w_source_peer_eq w_source_budget w_source_init w_locator_init w_source_api w_source_libc w_source_getdents w_source_proc w_source_procfs w_source_readfs w_source_read w_self_stat w_self_status w_self_pidns w_self_userns w_self_cgroupns w_self_timens w_parent_live w_parent_stat w_parent_process w_parent_uid w_parent_cgroup w_parent_time w_parent_link w_anc_load w_anc_uid w_anc_ppid w_anc_sudo w_anc_exe w_anc_recheck w_anc_end w_proc_pidfd w_proc_dir w_proc_fs w_proc_start w_proc_cgroup w_proc_root w_proc_ns w_proc_status w_proc_identity w_proc_check w_proc_timens w_proc_live w_proc_reopen w_proc_fdinfo w_stat_delimiter w_stat_state w_stat_start w_status_fields w_status_pid w_status_tgid w_status_uid w_status_nspid w_status_nstgid w_cgroup_record w_channel_fds w_chan_nonblock w_chan_cloexec w_boot_wait w_boot_recv w_boot_ancillary w_boot_accumulate w_boot_marker w_boot_count w_boot_stat w_boot_dir w_boot_mode w_boot_uid w_boot_cloexec w_ready_budget w_ready_wait w_ready_send w_budget_deadline w_budget_reads w_budget_bytes w_budget_fds w_budget_opens w_budget_output w_peer_shape w_peer_cred w_peer_pidfd w_peer_cloexec w_peer_live".split())
    startup_kinds = set(b"guard no_api import bad_arg denied missing unsupported resource io cancelled other".split())
    for line in lines:
        if line.startswith(b"DOCKERLENS_NATIVE_PIDS_SETUP_REFUSAL:"):
            code = line[len(prefix):] if line.startswith(prefix) else None
            if len(line) > 64 or code not in allowed:
                tainted = True
            elif candidate is None:
                candidate = code
            elif candidate != code:
                tainted = True
        elif line.startswith(detail_prefix):
            if (len(line) > 64 or re.fullmatch(
                    rb"DOCKERLENS_NATIVE_PIDS_IO: phase=(ready|bind|confirm) kind=(reset|not_connected|bad_descriptor|invalid_argument|permission_denied|resource|other|eof)", line) is None):
                detail_tainted = True
            elif detail is None:
                detail = line
            elif detail != line:
                detail_tainted = True
        elif line.startswith(startup_prefix):
            match = re.fullmatch(rb"DOCKERLENS_NATIVE_PIDS_START: s=([a-z_0-9]+) k=([a-z_]+)", line)
            if (len(line) > 63 or match is None or match[1] not in startup_sites
                    or match[2] not in startup_kinds):
                startup_tainted = True
            elif startup is None:
                startup = line
            elif startup != line:
                startup_tainted = True
    if seen and not tainted and candidate is not None:
        sys.stdout.buffer.write(prefix + candidate + b"\n")
        # Detail is useful only with the same raw stream failure code. It never
        # replaces the general refusal or attributes a privileged helper cause.
        if detail is not None and not detail_tainted:
            eof = detail.endswith(b" kind=eof")
            paired = (candidate == b"pids-eof" and eof) or (candidate == b"pids-read" and not eof)
            if paired:
                sys.stdout.buffer.write(detail + b"\n")
                ready = (detail == b"DOCKERLENS_NATIVE_PIDS_IO: phase=ready kind=eof" if eof else
                         detail == b"DOCKERLENS_NATIVE_PIDS_IO: phase=ready kind=reset")
                if ready and startup is not None and not startup_tainted:
                    sys.stdout.buffer.write(startup + b"\n")
except (OSError, ValueError):
    pass
' "$(dirname "$0")/../src/native_pids_setup_refusals.txt" "$capture_directory/run.raw" "$original_run_status" 2>/dev/null) || setup_projection_status=$?
  if (( setup_projection_status == 3 )); then
    result=
    if (( run_status == 0 )); then run_status=1; fi
  fi
fi
# Only libtest's numeric summary is safe to print. Test and compiler output can
# contain protected native values, socket payloads, or authored secrets.
summary=$(grep -Eo '^test result: (ok|FAILED)\. [0-9]+ passed; [0-9]+ failed; [0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out;' <<<"$result" | tail -n 1 || true)
# Only constant markers authored by the native tests may pass this boundary.
# Never print arbitrary assertion, compiler, daemon, or captured API output.
marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: (capture_(input|decode|daemon|counts|image|ports|mounts|environment|command|privacy)|acquire_(input|oracle|socket|route|network|decode|mode|settings|replay)|target_(daemon_uid|mode|ports|mounts|settings|traffic(_probe)?|health_(create|start|wait)|shape_(network_attach|bind_rw|volume_ro(_created|_inspected|_started|_accessible|_write_(zero|one|other))?|restart)|uid_(probe_failed|shape|count)|rootless_uid_zero|rootful_uid_nonzero|start_(uidmap|userns|cgroup|network|mount|storage|runtime|permission|unclassified|timeout|exec))|read_only_(acquire|route|status|decode|daemon|mode|api))$' <<<"$result" | tail -n 1 || true)
source_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: (source_(fixture_oracles|discovery|narrow_selectors|all_and_resource_roots|multiple_bindings|typed_oracle|network_membership)|membership_cleanup_unverified)$' <<<"$result" | tail -n 1 || true)
if [[ -n $source_marker ]]; then marker=$source_marker; fi
network_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: network_(identity|oracle(_((primary|alternate)_(create|inspect|assert)|external_(create|inspect)))?|render|apply|inspect|aliases|traffic|isolation(_(edge_fixture(_exited)?|edge_alias_missing|backend_alias_missing|edge_dns(_(output_limit|cli_(timeout|resolver|lookup|docker|exec|answer_present|unclassified)|answer_(missing|wrong_ip|malformed|inconsistent)|alias_missing|fixture_exited|readiness_exhausted))?|edge_http|local_dns|local_http|collision_dns|collision_http|foreign_route|cleanup_unverified))?|internal_(oracle|render|sidecar|peers|cli_control|control|blocked|cleanup|topology)|external|negative|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $network_marker ]]; then marker=$network_marker; fi
inner_topology_diag=
if [[ $target == native_network && $test_name == live_internal_network_blocks_external_egress &&
      $network_marker == 'DOCKERLENS_NATIVE_CHECK: network_internal_topology' ]]; then
    inner_topology_diag=$(grep -Ex '^DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=(snapshot_array|snapshot_bounds|network_count|held_count|outer_pools|held_roles|held_ids|native_id|native_name|duplicate_id|duplicate_name|scope|ipam_driver|builtin_pools|bridge_membership|bridge_driver|held_binding|bridge_ipam|ipv4_overlap|retained_set)$' <<<"$result" || true)
    # The original evaluation emits once. Duplicate/conflicting lines are not
    # evidence; never concatenate them or project arbitrary native text.
    if [[ $inner_topology_diag == *$'\n'* ]]; then inner_topology_diag=; fi
fi
volume_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: volume_(missing_precheck|seed|read_only|read_write|persistence|identity|cleanup_unverified)$' <<<"$result" | tail -n 1 || true)
if [[ -n $volume_marker ]]; then marker=$volume_marker; fi
dns_diag=$(grep -Eo '^DOCKERLENS_NATIVE_DNS_DIAG: peer=(ready|invalid|unavailable) resolver=(unrun|unavailable|embedded_(search|plain)|other_(search|plain)) default_a=(pass|fail|unrun) explicit_a=(pass|fail|unrun) dotted_a=(pass|fail|unrun) name_http=(pass|fail|unrun) ip_http=(pass|fail|unrun) edge_app=(pass|fail|unrun) cleanup=(pass|fail)$' <<<"$result" | tail -n 1 || true)
collision_dns_diag=$(grep -Eo '^DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=(backend|edge) category=(output_limit|cli_(timeout|resolver|lookup|docker|exec|answer_present|unclassified)|answer_(missing|wrong_ip|malformed|inconsistent)|alias_missing) exit=(success|lookup|timeout|other) response=(nxdomain|servfail|refused|no_error_no_a|has_expected_a|other)$' <<<"$result" | tail -n 1 || true)
volume_label_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: volume_labels_(create|persistence|ownership|cleanup_unverified)$' <<<"$result" | tail -n 1 || true)
if [[ -n $volume_label_marker ]]; then marker=$volume_label_marker; fi
pids_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: pids_(context|cleanup|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $pids_marker ]]; then marker=$pids_marker; fi
identity_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: identity_(context|oracle|render|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $identity_marker ]]; then marker=$identity_marker; fi
health_metadata_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: health_metadata_(context|derive|grace_positive|period_zero|inherited_failure|disabled|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $health_metadata_marker ]]; then marker=$health_metadata_marker; fi
stop_signal_causal_marker=
lifecycle_causal_marker=
lifecycle_stage=
lifecycle_handoff=
if [[ $target == native_lifecycle || $target == native_runtime_filesystem || $target == native_tmpfs_effect || $target == native_health_start_interval_boundary || $target == native_lifecycle_default_effect || $target == native_hostname || $target == native_shm_size || $target == native_supplementary_groups || $target == native_kernel_settings || $target == native_pids ]]; then
  if [[ $target == native_lifecycle ]]; then
    marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: lifecycle_(context|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
    lifecycle_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: lifecycle_(context|cleanup|cleanup_unverified|evidence)$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup(_unverified)?$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
    lifecycle_stage=$(sed -E '/^DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup(_unverified)?$/q' <<<"$result" | grep -Eo '^DOCKERLENS_NATIVE_LIFECYCLE_STAGE: case=[0-5] stage=(create|stop|early|late)$' | tail -n 1 || true)
  else
    child_cleanup_marker=$(grep -Fx 'DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified' <<<"$result" | tail -n 1 || true)
    if [[ -n $child_cleanup_marker ]]; then marker=$child_cleanup_marker; fi
  fi
  lifecycle_handoff=$(grep -Fx 'DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required' <<<"$result" | tail -n 1 || true)
  if [[ -n $lifecycle_handoff ]] || grep -Fxq 'DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified' <<<"$result"; then
    if (( run_status == 0 )); then run_status=1; fi
  fi
fi
if [[ $target == native_runtime_filesystem ]]; then
  runtime_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: runtime_filesystem_(context|omitted|false|true|cleanup|evidence)$' <<<"$result" | tail -n 1 || true)
  if [[ -n $runtime_marker ]]; then marker=$runtime_marker; fi
  lifecycle_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: runtime_filesystem_(context|omitted|false|true|cleanup|evidence)$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: runtime_filesystem_cleanup$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
fi
if [[ $target == native_health_start_interval_boundary ]]; then
  boundary_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: health_start_interval_boundary_(context|configuration|cleanup|evidence)$' <<<"$result" | tail -n 1 || true)
  if [[ -n $boundary_marker ]]; then marker=$boundary_marker; fi
  lifecycle_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: health_start_interval_boundary_(context|configuration|cleanup|evidence)$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: health_start_interval_boundary_cleanup$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
fi
if [[ $target == native_hostname ]]; then
  hostname_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: hostname_(context|effects|cleanup|evidence)$' <<<"$result" | tail -n 1 || true)
  if [[ -n $hostname_marker && $marker != 'DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified' ]]; then marker=$hostname_marker; fi
  lifecycle_causal_marker=$(awk '/^thread .* panicked at / || /^DOCKERLENS_NATIVE_CHECK: hostname_cleanup$/ { exit } /^DOCKERLENS_NATIVE_CHECK: hostname_(context|effects|evidence)$/ { last=$0 } END { if (last != "") print last }' <<<"$result")
fi
if [[ $target == native_shm_size ]]; then
  shm_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: shm_size_(context|seed|effects|capture|cleanup|proof)$' <<<"$result" | tail -n 1 || true)
  if [[ -n $shm_marker && $marker != 'DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified' ]]; then marker=$shm_marker; fi
  lifecycle_causal_marker=$(awk '/^thread .* panicked at / || /^DOCKERLENS_NATIVE_CHECK: shm_size_cleanup$/ { exit } /^DOCKERLENS_NATIVE_CHECK: shm_size_(context|seed|effects|capture|proof)$/ { last=$0 } END { if (last != "") print last }' <<<"$result")
fi
if [[ $target == native_supplementary_groups || $target == native_kernel_settings || $target == native_pids ]]; then
  family=${target#native_}
  family_marker=$(grep -Eo "^DOCKERLENS_NATIVE_CHECK: ${family}_(context|effects|capture|cleanup|proof)$" <<<"$result" | tail -n 1 || true)
  if [[ -n $family_marker && $marker != 'DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified' ]]; then marker=$family_marker; fi
  lifecycle_causal_marker=$(awk -v family="$family" '/^thread .* panicked at / { exit } $0 == "DOCKERLENS_NATIVE_CHECK: " family "_cleanup" { exit } $0 ~ "^DOCKERLENS_NATIVE_CHECK: " family "_(context|effects|capture|proof)$" { last=$0 } END { if (last != "") print last }' <<<"$result")
fi
stop_signal_stage=
stop_signal_lifecycle=
if [[ $target == native_stop_signal ]]; then
  stop_signal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: stop_signal_(context|term|int|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
  if [[ -n $stop_signal_marker ]]; then marker=$stop_signal_marker; fi
  stop_signal_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: stop_signal_(context|term|int|cleanup|cleanup_unverified|evidence)$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup(_unverified)?$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
  # Retain the last fixed-only operation before the first cleanup, even when a
  # shared/worker-thread panic has no selected-test location. Never copy values.
  stop_signal_stage=$(sed -E '/^DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup(_unverified)?$/q' <<<"$result" | grep -Eo '^DOCKERLENS_NATIVE_STOP_SIGNAL_STAGE: case=(term|int) role=(oracle|rendered) stage=(create|created|start|readiness|running|clock|stop|elapsed|output|inspect|exit|state|causality)$' | tail -n 1 || true)
  # Only a successful observation boundary before cleanup permits a later
  # lifecycle diagnostic. Stop at the first panic, including worker panics.
  stop_signal_lifecycle=$(awk '
    /^thread .* panicked at / { exit }
    !cleanup && /^DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: observations_complete$/ { complete=1; last=$0; next }
    /^DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup(_unverified)?$/ { cleanup=1; next }
    complete && cleanup && /^DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: (cleanup_verified|borrowed_image|outer_context|publication)$/ { last=$0 }
    END { if (complete && cleanup) print last }
  ' <<<"$result")
fi
network_attachment_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: network_attachment_(context|oracle|rendered|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $network_attachment_marker ]]; then marker=$network_attachment_marker; fi
network_attachment_causal_marker=
network_attachment_diagnostics=
if [[ $target == native_network_attachment ]]; then
  network_attachment_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: network_attachment_(context|oracle|rendered|cleanup|cleanup_unverified|evidence)$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup(_unverified)?$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
fi
if [[ $target == native_network_attachment && $test_name == live_network_attachments_match_engine ]]; then
  # These are invocation-wide first-failure latches, not progress markers.
  # Validate the whole family before projection: even identical duplicates,
  # unknown tokens or private suffixes invalidate it rather than selecting last.
  network_attachment_diagnostics=$(awk '
    /DOCKERLENS_NATIVE_ATTACHMENT_/ {
      if ($0 ~ /^DOCKERLENS_NATIVE_ATTACHMENT_WORK: role=context stage=(outer_context|engine_version|package|client_version|engine_info|client_info|daemon_mode|acquisition)$/ ||
          $0 ~ /^DOCKERLENS_NATIVE_ATTACHMENT_WORK: role=(oracle|rendered) stage=(request_plan|primary_network_create|secondary_network_create|network_labels|server_create|server_start|primary_readback|secondary_connect|connected_readback|primary_peer_create|primary_peer_start|secondary_peer_create|secondary_peer_start|topology_readback|(primary|secondary)_(peer_ownership|resolver|unique_dns|shared_dns|unique_http|shared_http|direct_http)|final_readback|role_record|outer_readback)$/) {
        work_count++; work=$0
      } else if ($0 ~ /^DOCKERLENS_NATIVE_ATTACHMENT_CLEANUP: origin=(role|terminal|drop) role=(context|oracle|rendered) operation=(outer_ownership|inspect|status|ownership|delete|name_absence|id_absence) slot=(none|primary_network|secondary_network|server|primary_peer|secondary_peer)$/) {
        cleanup_count++; cleanup=$0
      } else invalid=1
    }
    END {
      if (invalid || work_count > 1 || cleanup_count > 1) exit
      if (work_count == 1) print work
      if (cleanup_count == 1) print cleanup
    }
  ' <<<"$result")
fi
bind_relabel_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: bind_relabel_(context|oracle|rendered|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $bind_relabel_marker ]]; then marker=$bind_relabel_marker; fi
bind_relabel_causal_marker=
if [[ $target == native_bind_relabel ]]; then
  bind_relabel_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: bind_relabel_(context|oracle|rendered|cleanup|cleanup_unverified|evidence)$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup(_unverified)?$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
fi
external_network_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: external_network_(context|oracle|assessment|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $external_network_marker ]]; then marker=$external_network_marker; fi
external_network_causal_marker=
if [[ $target == native_external_network ]]; then
  external_network_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: external_network_(context|oracle|assessment|cleanup|cleanup_unverified|evidence)$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: external_network_cleanup(_unverified)?$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
fi
health_metadata_causal_marker=
if [[ $target == native_health_metadata ]]; then
  health_metadata_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: health_metadata_(context|derive|grace_positive|period_zero|inherited_failure|disabled|cleanup|cleanup_unverified|evidence)$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: health_metadata_cleanup(_unverified)?$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
fi
port_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: (port_(context|cleanup|cleanup_unverified|evidence|ipv4|ipv6|outer_identity|host_curl_preflight|host_bash_preflight)|(port_(fixed_ipv4_oracle|fixed_ipv4_rendered|fixed_ipv6_oracle|fixed_ipv6_rendered|dynamic_ipv6_oracle|dynamic_ipv6_rendered|repeated_dynamic_ipv4_oracle|repeated_dynamic_ipv4_rendered)_(cli_create|cli_inspect|oracle_bindings|oracle_cleanup|oracle_start|cli_http|cli_http_secondary|local_service|http_assert|http_assert_secondary|render|render_body|api_create|api_inspect|rendered_bindings|api_start|dynamic_binding|dynamic_binding_secondary|isolated_http|isolated_assert|udp_assignment|udp_send|udp_receive|udp_assert|tcp6_boundary|negative_recheck|runtime_absence)))$' <<<"$result" | tail -n 1 || true)
if [[ -n $port_marker ]]; then marker=$port_marker; fi
# Port cleanup runs after a caught assertion and can mask its last causal stage.
# Select only the existing closed marker grammar, stopping at the first cleanup.
port_causal_marker=
port_diagnostics=
if [[ $target == native_port ]]; then
  port_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: (port_(context|cleanup|cleanup_unverified|evidence|ipv4|ipv6|outer_identity|host_curl_preflight|host_bash_preflight)|port_(fixed_ipv4_oracle|fixed_ipv4_rendered|fixed_ipv6_oracle|fixed_ipv6_rendered|dynamic_ipv6_oracle|dynamic_ipv6_rendered|repeated_dynamic_ipv4_oracle|repeated_dynamic_ipv4_rendered)_(cli_create|cli_inspect|oracle_bindings|oracle_cleanup|oracle_start|cli_http|cli_http_secondary|local_service|http_assert|http_assert_secondary|render|render_body|api_create|api_inspect|rendered_bindings|api_start|dynamic_binding|dynamic_binding_secondary|isolated_http|isolated_assert|udp_assignment|udp_send|udp_receive|udp_assert|tcp6_boundary|negative_recheck|runtime_absence))$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: port_cleanup(_unverified)?$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
  port_cleanup_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: port_cleanup(_unverified)?$' <<<"$result" | tail -n 1 || true)
  marker=${port_cleanup_marker:-$port_causal_marker}
  # Full-line, finite grammars only. Keep at most one line per family (and one
  # per cleanup attempt); never export native values, messages or suffixes.
  port_patterns=(
    '^DOCKERLENS_NATIVE_API_DIAG: transport=(timeout|other)$'
    '^DOCKERLENS_NATIVE_PORT_API_DIAG: action=(version|info|create|start|inspect_name|inspect_id|delete) phase=probe exit=(curl_timeout|outer_timeout|signal|other)$'
    '^DOCKERLENS_NATIVE_PORT_API_DIAG: action=(version|info|create|start|inspect_name|inspect_id|delete) phase=cleanup exit=(curl_timeout|outer_timeout|signal|other)$'
    '^DOCKERLENS_NATIVE_PORT_START_DIAG: outcome=(observed|skipped|panic) version=(responsive|timeout|other|unknown) object=(responsive|timeout|other|unknown) identity=(same|mismatch|unknown) state=(created|running|restarting|paused|exited|dead|removing|unknown) primary=(zero|one|two|many|unknown) secondary=(zero|one|two|many|unknown) allocation_relation=(same|different|unknown) mutation=(clear|uncertain)$'
    '^DOCKERLENS_NATIVE_API_DIAG: operation=(inspect|create|start) status=(invalid_request|not_found|conflict|server|other)$'
    '^DOCKERLENS_NATIVE_HTTP_DIAG: exit=(timeout|signal|other|success) category=(connection_refused|missing_tool|address_family|invalid_address|no_route|permission|storage_exhausted|invalid_reference|missing_resource|image_storage|unknown|body_mismatch)$'
    '^DOCKERLENS_NATIVE_CLI_DIAG: exit=(timeout|signal|other) stderr=(connection_refused|missing_tool|address_family|invalid_address|no_route|permission|storage_exhausted|invalid_reference|missing_resource|image_storage|unknown)$'
    '^DOCKERLENS_NATIVE_NAMESPACE_DIAG: category=(input|inspect|identity|changed|process|missing_tool|probe)$'
    '^DOCKERLENS_NATIVE_IPV6_DIAG: local_service=(pass|fail) inner_all=(enabled|disabled|unavailable) inner_lo=(enabled|disabled|unavailable) outer_tcp6=(available|tcp6_unavailable|bind_unavailable|loopback_unavailable|probe_failed) curl_exit=(0|6|7|22|28|35|52|56|60|124|137|other)$'
    '^DOCKERLENS_NATIVE_IPV6_BOUNDARY_DIAG: result=(refused|connected|timeout|other|malformed)$'
    '^DOCKERLENS_NATIVE_ISOLATION_DIAG: result=(refused|connected|timeout|other)$'
    '^DOCKERLENS_NATIVE_PORT_BINDINGS_DIAG: key=(missing|null|array|other) count=(zero|one|two|many) ipv4=(zero|one|two|many) ipv6=(zero|one|two|many) other=(zero|one|two|many) v4_port=(absent|empty|zero|nonzero|malformed|multiple) v6_port=(absent|empty|zero|nonzero|malformed|multiple)$'
    '^DOCKERLENS_NATIVE_PORT_CLEANUP_DIAG: attempt=primary outcome=(pass|fail|panic) reserve=(exhausted|low|reserved) mutation=(clear|uncertain)$'
    '^DOCKERLENS_NATIVE_PORT_CLEANUP_DIAG: attempt=drop outcome=(pass|fail|panic) reserve=(exhausted|low|reserved) mutation=(clear|uncertain)$'
  )
  for port_pattern in "${port_patterns[@]}"; do
    if [[ $port_pattern == '^DOCKERLENS_NATIVE_API_DIAG: transport=(timeout|other)$' || $port_pattern == '^DOCKERLENS_NATIVE_PORT_API_DIAG:'* ]]; then
      # Later cleanup transport failures must not replace the original failure.
      port_diagnostic=$(grep -Eo "$port_pattern" <<<"$result" | sed -n '1p' || true)
    else
      port_diagnostic=$(grep -Eo "$port_pattern" <<<"$result" | tail -n 1 || true)
    fi
    if [[ -n $port_diagnostic ]]; then port_diagnostics+="$port_diagnostic"$'\n'; fi
  done
fi
reason_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: target_start_reason_(operation_not_permitted|permission_denied|invalid_argument|read_only_filesystem|not_found|timeout|unclassified)$' <<<"$result" | tail -n 1 || true)
error_category=$(grep -Eo '^DOCKERLENS_NATIVE_ERROR: (endpoint|cancelled|deadline|io|protocol|status|version|shape|budget)$' <<<"$result" | tail -n 1 || true)
selection_error=$(grep -Eo '^DOCKERLENS_NATIVE_ERROR: selection$' <<<"$result" | tail -n 1 || true)
if [[ -n $selection_error ]]; then error_category=$selection_error; fi
network_cli_diag=$(grep -Eo '^DOCKERLENS_NATIVE_NETWORK_CLI_DIAG: exit=(timeout|other) category=(bridge_filter|icc_configuration|firewall_disabled|firewall|permission|address_pool|invalid_label|invalid_option|unknown)$' <<<"$result" | tail -n 1 || true)
wget_diag=$(grep -Eo '^DOCKERLENS_NATIVE_WGET_DIAG: category=(connection_refused|no_route|timeout|http_error|unknown)$' <<<"$result" | tail -n 1 || true)
control_subnet_diag=$(grep -Eo '^DOCKERLENS_NATIVE_CONTROL_SUBNET_DIAG: sidecar_on_control_subnet=(true|false|unknown)$' <<<"$result" | tail -n 1 || true)
internal_subnet_diag=$(grep -Eo '^(DOCKERLENS_NATIVE_INTERNAL_SUBNET_DIAG: sidecar_on_internal_subnet=(true|false|unknown)|DOCKERLENS_NATIVE_FIXTURE_SUBNET_DIAG: sidecar_on_fixture_subnet=((true|false)|unknown reason=unavailable))$' <<<"$result" | tail -n 1 || true)
default_bridge_subnet_diag=$(grep -Eo '^DOCKERLENS_NATIVE_DEFAULT_BRIDGE_SUBNET_DIAG: sidecar_on_default_bridge_subnet=((true|false)|unknown reason=(unavailable|budget_exhausted))$' <<<"$result" | tail -n 1 || true)
internal_cleanup=$(grep -Eo '^DOCKERLENS_NATIVE_CLEANUP: internal_proof=(pass|fail)$' <<<"$result" | tail -n 1 || true)
# A panic's selected test source and numeric location identify an assertion
# without disclosing its message, compared values, or an absolute build path.
panic_site=
if [[ $target == native_command_clear ]]; then
  command_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: command_clear_(context|derive|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
  if [[ -n $command_marker ]]; then marker=$command_marker; fi
  lifecycle_causal_marker=$(awk '/^thread .* panicked at / || /^DOCKERLENS_NATIVE_CHECK: command_clear_cleanup(_unverified)?$/ { exit } /^DOCKERLENS_NATIVE_CHECK: command_clear_(context|derive|evidence)$/ { last=$0 } END { if (last != "") print last }' <<<"$result")
  lifecycle_stage=$(awk '/^thread .* panicked at / || /^DOCKERLENS_NATIVE_CHECK: command_clear_cleanup(_unverified)?$/ { exit } /^DOCKERLENS_NATIVE_COMMAND_CLEAR_STAGE: case=(image_defaults|entrypoint_inherit|command_clear|entrypoint_clear) role=(oracle|rendered) stage=(create|effect)$/ { last=$0 } END { if (last != "") print last }' <<<"$result")
  if grep -Eq '^DOCKERLENS_NATIVE_CHECK: command_clear_cleanup_unverified$' <<<"$result" ||
      grep -Fxq 'DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified' <<<"$result" ||
      grep -Fxq 'DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required' <<<"$result"; then
    if (( run_status == 0 )); then run_status=1; fi
  fi
fi
case $target in
  native_command_clear)
    panic_site=$(awk '/^thread .* panicked at / { print; exit }' <<<"$result" | sed -nE \
      "s/^thread '${selected}'( \\([0-9]{1,10}\\))? panicked at src\\/(native_command_clear_tests|native_health_metadata_tests)\\.rs:([1-9][0-9]{0,5}):([1-9][0-9]{0,3}):$/DOCKERLENS_NATIVE_PANIC: source=\\2 line=\\3 column=\\4/p")
    if [[ -z $panic_site ]]; then panic_site='DOCKERLENS_NATIVE_PANIC: source=native_command_clear_tests location=unavailable'; fi
    ;;
  native_lifecycle | native_runtime_filesystem | native_tmpfs_effect | native_health_start_interval_boundary | native_lifecycle_default_effect | native_hostname | native_shm_size | native_supplementary_groups | native_kernel_settings | native_pids)
    # The first panic is primary even when later bounded cleanup also fails.
    # Never project arbitrary panic payloads, paths, native IDs or timestamps.
    lifecycle_source=native_lifecycle_tests
    if [[ $target == native_runtime_filesystem ]]; then lifecycle_source=native_runtime_filesystem_tests; fi
    if [[ $target == native_tmpfs_effect ]]; then lifecycle_source=native_tmpfs_effect_tests; fi
    if [[ $target == native_health_start_interval_boundary ]]; then lifecycle_source=native_health_start_interval_boundary_tests; fi
    if [[ $target == native_lifecycle_default_effect ]]; then lifecycle_source=native_lifecycle_default_effect_tests; fi
    if [[ $target == native_hostname ]]; then lifecycle_source=native_hostname_tests; fi
    if [[ $target == native_shm_size ]]; then lifecycle_source=native_shm_size_tests; fi
    if [[ $target == native_supplementary_groups ]]; then lifecycle_source=native_supplementary_groups_tests; fi
    if [[ $target == native_kernel_settings ]]; then lifecycle_source=native_kernel_settings_tests; fi
    if [[ $target == native_pids ]]; then lifecycle_source=native_pids_tests; fi
    panic_site=$(awk '/^thread .* panicked at / { print; exit }' <<<"$result" | sed -nE \
      "s/^thread '${selected}'( \([0-9]{1,10}\))? panicked at src\/(${lifecycle_source}|native_lifecycle_tests|native_health_metadata_tests)\.rs:([1-9][0-9]{0,5}):([1-9][0-9]{0,3}):$/DOCKERLENS_NATIVE_PANIC: source=\2 line=\3 column=\4/p")
    if [[ -z $panic_site ]]; then panic_site="DOCKERLENS_NATIVE_PANIC: source=$lifecycle_source location=unavailable"; fi
    ;;
  native_stop_signal)
    # Select the first panic of any thread before projecting an allowed site;
    # never substitute a later selected-thread join/resume panic for a worker.
    panic_site=$(awk '/^DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup(_unverified)?$/ { exit } /^thread .* panicked at / { print; exit }' <<<"$result" | sed -nE \
      "s/^thread '${selected}'( \([0-9]{1,10}\))? panicked at src\/(native_stop_signal_tests|native_health_metadata_tests)\.rs:([1-9][0-9]{0,5}):([1-9][0-9]{0,3}):$/DOCKERLENS_NATIVE_PANIC: source=\2 line=\3 column=\4/p")
    if [[ -z $panic_site && -n $stop_signal_lifecycle ]]; then
      panic_site=$(awk '/^DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup(_unverified)?$/ { cleanup=1 } cleanup && /^thread .* panicked at / { print; exit }' <<<"$result" | sed -nE \
        "s/^thread '${selected}'( \([0-9]{1,10}\))? panicked at src\/(native_stop_signal_tests|native_health_metadata_tests)\.rs:([1-9][0-9]{0,5}):([1-9][0-9]{0,3}):$/DOCKERLENS_NATIVE_PANIC: source=\2 line=\3 column=\4/p" | sed -n '1p')
    fi
    if [[ -z $panic_site ]]; then panic_site='DOCKERLENS_NATIVE_PANIC: source=native_stop_signal_tests location=unavailable'; fi
    ;;
  native_bind_relabel)
    # The test catches its original assertion, then cleans up and may panic at
    # a final aggregate assertion. Only the first selected-test site before the
    # first exact cleanup marker identifies the causal assertion. Never export
    # the panic message, thread text, private suffixes or an absolute build path.
    panic_site=$(sed -nE \
      -e '/^DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup(_unverified)?$/q' \
      -e "s/^thread '${selected}'( \([0-9]{1,10}\))? panicked at src\/(native_bind_relabel_tests)\.rs:([1-9][0-9]{0,5}):([1-9][0-9]{0,3}):$/DOCKERLENS_NATIVE_PANIC: source=\2 line=\3 column=\4/p" \
      <<<"$result" | sed -n '1p')
    if [[ -z $panic_site ]]; then
      panic_site='DOCKERLENS_NATIVE_PANIC: source=native_bind_relabel_tests location=unavailable'
    fi
    ;;
  native_port)
    # Optional IPv6 follow-ups catch panics before the original HTTP assertion.
    # Project only the first selected panic outside valid diagnostic scopes;
    # buffer it until the whole event stream proves balanced and well-formed.
    # Malformed scopes yield a constant uncertainty result, never a source site.
    panic_site=$(sed -nE \
      -e "s/^thread '${selected}'( \([0-9]{1,10}\))? panicked at src\/(native_port_tests)\.rs:([0-9]{1,6}):([0-9]{1,4}):$/DOCKERLENS_NATIVE_PANIC: source=\2 line=\3 column=\4/p" \
      -e '/^[[:space:]]*DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE/p' <<<"$result" | awk '
        $0 == "DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: begin" {
          if (active) invalid=1
          active=1
          next
        }
        $0 == "DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: end" {
          if (!active) invalid=1
          active=0
          next
        }
        /^DOCKERLENS_NATIVE_PANIC:/ {
          if (!active && first == "") first=$0
          next
        }
        { invalid=1 }
        END {
          if (invalid || active) print "DOCKERLENS_NATIVE_PORT_SCOPE_DIAG: state=invalid"
          else if (first != "") print first
        }')
    ;;
  native_target | native_volume | native_network | native_volume_label | native_container | native_identity | native_external_network)
    panic_site=$(sed -nE "s/^thread '.*'( \([0-9]{1,10}\))? panicked at src\/(${target}_tests)\.rs:([0-9]{1,6}):([0-9]{1,4}):$/DOCKERLENS_NATIVE_PANIC: source=\2 line=\3 column=\4/p" <<<"$result" | tail -n 1)
    ;;
esac
if (( run_status != 0 )); then
  echo "required native test $target::$test_name failed (exit $run_status)" >&2
  if [[ -n $pids_setup_refusal ]]; then echo "$pids_setup_refusal" >&2; fi
  if [[ -n $port_causal_marker && $port_causal_marker != "$marker" ]]; then echo "$port_causal_marker" >&2; fi
  if [[ -n $marker ]]; then echo "$marker" >&2; fi
  if [[ -n $lifecycle_causal_marker && $lifecycle_causal_marker != "$marker" ]]; then echo "$lifecycle_causal_marker" >&2; fi
  if [[ -n $lifecycle_stage ]]; then echo "$lifecycle_stage" >&2; fi
  if [[ -n $lifecycle_handoff ]]; then echo "$lifecycle_handoff" >&2; fi
  if [[ -n $health_metadata_causal_marker && $health_metadata_causal_marker != "$marker" ]]; then echo "$health_metadata_causal_marker" >&2; fi
  if [[ -n $stop_signal_causal_marker && $stop_signal_causal_marker != "$marker" ]]; then echo "$stop_signal_causal_marker" >&2; fi
  if [[ -n $stop_signal_stage ]]; then echo "$stop_signal_stage" >&2; fi
  if [[ -n $stop_signal_lifecycle ]]; then echo "$stop_signal_lifecycle" >&2; fi
  if [[ -n $network_attachment_causal_marker && $network_attachment_causal_marker != "$marker" ]]; then echo "$network_attachment_causal_marker" >&2; fi
  if [[ -n $network_attachment_diagnostics ]]; then printf '%s\n' "$network_attachment_diagnostics" >&2; fi
  if [[ -n $bind_relabel_causal_marker && $bind_relabel_causal_marker != "$marker" ]]; then echo "$bind_relabel_causal_marker" >&2; fi
  if [[ -n $external_network_causal_marker && $external_network_causal_marker != "$marker" ]]; then echo "$external_network_causal_marker" >&2; fi
  if [[ -n $port_diagnostics ]]; then printf '%s' "$port_diagnostics" >&2; fi
  if [[ -n $dns_diag ]]; then echo "$dns_diag" >&2; fi
  if [[ -n $collision_dns_diag ]]; then echo "$collision_dns_diag" >&2; fi
  if [[ -n $reason_marker ]]; then echo "$reason_marker" >&2; fi
  if [[ -n $error_category ]]; then echo "$error_category" >&2; fi
  if [[ -n $network_cli_diag ]]; then echo "$network_cli_diag" >&2; fi
  if [[ -n $wget_diag ]]; then echo "$wget_diag" >&2; fi
  if [[ -n $control_subnet_diag ]]; then echo "$control_subnet_diag" >&2; fi
  if [[ -n $internal_subnet_diag ]]; then echo "$internal_subnet_diag" >&2; fi
  if [[ -n $default_bridge_subnet_diag ]]; then echo "$default_bridge_subnet_diag" >&2; fi
  if [[ -n $internal_cleanup ]]; then echo "$internal_cleanup" >&2; fi
    if [[ -n $inner_topology_diag ]]; then echo "$inner_topology_diag" >&2; fi
  if [[ -n $panic_site ]]; then echo "$panic_site" >&2; fi
  if [[ -n $summary ]]; then
    echo "$summary" >&2
  fi
  exit 1
fi
if ! grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;' <<<"$result"; then
  echo "required native test $target::$test_name did not execute exactly once (exit $run_status)" >&2
  if [[ -n $summary ]]; then
    echo "$summary" >&2
  fi
  exit 1
fi
if (( exact_pids )) && ! remove_native_capture; then exit 1; fi
echo "required native test passed: $target::$test_name"
