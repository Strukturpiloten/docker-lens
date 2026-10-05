#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ! $1 =~ ^[a-z_]+$ || ! $2 =~ ^[a-z_]+$ ]]; then
  echo "usage: $0 <integration-test-target> <exact-ignored-test-name>" >&2
  exit 2
fi
target=$1
test_name=$2
if [[ $target == native_target || $target == native_volume || $target == native_network || $target == native_volume_label || $target == native_container || $target == native_identity ]]; then
  # Native target tests need crate-private, test-only capability claims.
  # It is a library unit test; no public constructor is exposed for the harness.
  cargo_target=(--lib)
  selected="${target}_tests::$test_name"
else
  cargo_target=(--test "$target")
  selected=$test_name
fi

# Cargo and libtest output is private. Bound only the capture stream, not
# Cargo's regular-file writes to compiler artifacts in a cold native lane.
output_limit_bytes=$((256 * 1024))
capture_path=$(mktemp "${NATIVE_CAPTURE_DIR:-${TMPDIR:-/tmp}}/dockerlens-native-test-output.XXXXXXXX")
trap 'rm -f -- "$capture_path"' EXIT
capture_test_output() {
  local capture_status=0
  "$@" 2>&1 | head -c "$((output_limit_bytes + 1))" >"$capture_path" || capture_status=$?
  if (( $(wc -c <"$capture_path") > output_limit_bytes )); then
    echo 'required native test output exceeded closed byte limit' >&2
    exit 1
  fi
  return "$capture_status"
}

# libtest returns success for zero selected tests. Check the ignored-only list
# first, then require exactly one executed success in the final summary.
list_status=0
capture_test_output timeout 180 cargo test --locked "${cargo_target[@]}" -- --ignored --list || list_status=$?
if (( list_status != 0 )); then
  echo "failed to list required ignored native test $target::$test_name (exit $list_status)" >&2
  exit 1
fi
if [[ $(grep -Fxc "$selected: test" "$capture_path" || true) != 1 ]]; then
  echo "required ignored native test $target::$test_name is absent" >&2
  exit 1
fi
run_status=0
# Bind optional failure diagnostics to this invocation's existing hard timeout.
# The native test reserves its own cleanup and reporting margin before this time.
run_deadline_epoch=$(( $(date +%s) + 180 ))
export NATIVE_NETWORK_TEST_DEADLINE_EPOCH=$run_deadline_epoch
capture_test_output timeout 180 cargo test --locked "${cargo_target[@]}" -- --ignored --exact "$selected" || run_status=$?
# Validate the new group-scoped records as a set, never by taking a matching
# substring or choosing one duplicate. The existing private capture is bounded.
first_failure_diag=
if ! first_failure_diag=$(python3 - "$capture_path" "$run_status" "$target" 2>/dev/null <<'PY'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_bytes().split(b"\n")
groups = (b"resources_security", b"ports", b"identity_health_clear",
          b"storage_lifecycle", b"resolver_logging")
first_prefix = b"DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE:"
oracle_prefix = b"DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=oracle"
body_prefix = b"DOCKERLENS_NATIVE_RESOURCE_ORACLE_START_BODY_DIAG:"
failure_prefix = b"DOCKERLENS_NATIVE_GROUP_FAILURE:"
first_pattern = rb"DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=(\w+) checkpoint=(\w+) outcome=(\w+)"
oracle_pattern = rb"DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=oracle status=([1-5][0-9]{2}|unknown) category=(success|invalid_request|not_found|conflict|server|other|unknown)"
body_fields = (b"cgroup_mention", b"device_mention", b"sysctl_mention", b"ulimit_mention",
               b"apparmor_mention", b"permission_phrase", b"errno_mention",
               b"controller_mention", b"bpf_mention")
body_pattern = (body_prefix + rb" role=oracle status=([1-5][0-9]{2}|unknown) shape=(message|missing|malformed|oversize)"
                + b"".join(b" " + field + rb"=(present|absent|unknown)" for field in body_fields))
pairs = {(b"resource_oracle_start", b"http_status"),
         *((checkpoint, outcome) for checkpoint in (b"api", b"cli")
           for outcome in (b"timeout", b"unknown")),
         *((checkpoint, b"unknown") for checkpoint in (b"probe", b"preflight", b"cleanup"))}
first = {}
oracle = None
body = None
records = []
for index, line in enumerate(lines):
    if line.lstrip().startswith(first_prefix.removesuffix(b":")):
        match = re.fullmatch(first_pattern, line)
        if match is None:
            raise ValueError
        group, checkpoint, outcome = match.groups()
        if group not in groups or group in first or (checkpoint, outcome) not in pairs:
            raise ValueError
        if checkpoint == b"resource_oracle_start" and group != b"resources_security":
            raise ValueError
        first[group] = (checkpoint, outcome, index)
        records.append(line)
    elif line.lstrip().startswith(oracle_prefix):
        match = re.fullmatch(oracle_pattern, line)
        if match is None or oracle is not None:
            raise ValueError
        status, category = match.groups()
        if status == b"unknown":
            expected = b"unknown"
        else:
            numeric = int(status)
            expected = (b"success" if numeric == 204 else b"invalid_request" if numeric in (400, 422)
                        else b"not_found" if numeric == 404 else b"conflict" if numeric == 409
                        else b"server" if numeric >= 500 else b"other")
        if category != expected:
            raise ValueError
        oracle = (status, index)
        records.append(line)
    elif line.lstrip().startswith(body_prefix.removesuffix(b":")):
        match = re.fullmatch(body_pattern, line)
        if match is None or body is not None:
            raise ValueError
        status, shape, *flags = match.groups()
        if (shape == b"message" and any(flag == b"unknown" for flag in flags)
                or shape != b"message" and any(flag != b"unknown" for flag in flags)):
            raise ValueError
        body = (status, index)
        records.append(line)
failures = {}
for index, line in enumerate(lines):
    if not line.lstrip().startswith(failure_prefix.removesuffix(b":")):
        continue
    match = re.fullmatch(rb"DOCKERLENS_NATIVE_GROUP_FAILURE: group=(\w+) reason=(preflight|probe|cleanup_unverified|mutation_uncertain)", line)
    if match is None or match[1] not in groups or match[1] in failures:
        raise ValueError
    failures[match[1]] = index
if failures or records:
    if sys.argv[3] != "native_container":
        raise ValueError
    if set(first) != set(failures) or list(first) != sorted(first, key=groups.index):
        raise ValueError
    if any(index >= failures[group] for group, (_, _, index) in first.items()):
        raise ValueError
    for group, (checkpoint, _, _) in first.items():
        reason = lines[failures[group]].rsplit(b"=", 1)[1]
        if (checkpoint == b"preflight" and reason != b"preflight"
                or checkpoint == b"cleanup" and reason not in (b"cleanup_unverified", b"mutation_uncertain")):
            raise ValueError
    if first and int(sys.argv[2]) == 0:
        raise ValueError
    resource = first.get(b"resources_security")
    if oracle is not None and oracle[0] != b"204":
        if (resource is None or resource[:2] != (b"resource_oracle_start", b"http_status")
                or body is None):
            raise ValueError
    if body is not None:
        if (oracle is None or oracle[0] == b"204" or body[0] != oracle[0]
                or resource is None or not oracle[1] < body[1] < resource[2]):
            raise ValueError
        # The original classifier must precede the original inspect result and
        # every failure-only control, not merely precede the aggregate panic.
        for index, line in enumerate(lines):
            if (line.startswith((b"DOCKERLENS_NATIVE_ORACLE_START_STATE:",
                                 b"DOCKERLENS_NATIVE_RESOURCE_CONTROL:"))
                    or line.startswith(b"DOCKERLENS_NATIVE_RESOURCE_START_HTTP:")
                    and not line.startswith(oracle_prefix)):
                if index <= body[1]:
                    raise ValueError
    if resource is not None and resource[0] == b"resource_oracle_start":
        if oracle is None or oracle[0] == b"204" or oracle[1] >= resource[2]:
            raise ValueError
    if int(sys.argv[2]) != 0:
        for record in records:
            print(record.decode("ascii"))
PY
); then
  echo 'required native test rejected malformed first-failure diagnostics' >&2
  exit 1
fi
# Only libtest's numeric summary is safe to print. Test and compiler output can
# contain protected native values, socket payloads, or authored secrets.
summary=$(grep -Eo '^test result: (ok|FAILED)\. [0-9]+ passed; [0-9]+ failed; [0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out;' "$capture_path" | tail -n 1 || true)
# Only constant markers authored by the native tests may pass this boundary.
# Never print arbitrary assertion, compiler, daemon, or captured API output.
marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: (capture_(input|decode|daemon|counts|image|ports|mounts|environment|command|privacy)|acquire_(input|oracle|socket|route|network|decode|mode|settings|replay)|target_(daemon_uid|mode|ports|mounts|settings|traffic(_probe)?|health_(create|start|wait)|shape_(network_attach|bind_rw|volume_ro(_created|_inspected|_started|_accessible|_write_(zero|one|other))?|restart)|uid_(probe_failed|shape|count)|rootless_uid_zero|rootful_uid_nonzero|start_(uidmap|userns|cgroup|network|mount|storage|runtime|permission|unclassified|timeout|exec))|read_only_(acquire|route|status|decode|daemon|mode|api))$' "$capture_path" | tail -n 1 || true)
source_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: (source_(fixture_oracles|discovery|narrow_selectors|all_and_resource_roots|multiple_bindings|typed_oracle|network_membership)|membership_cleanup_unverified)$' "$capture_path" | tail -n 1 || true)
if [[ -n $source_marker ]]; then marker=$source_marker; fi
network_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: network_(identity|oracle(_((primary|alternate)_(create|inspect|assert)|external_(create|inspect)))?|render|apply|inspect|aliases|traffic|isolation(_(edge_fixture(_exited)?|edge_alias_missing|backend_alias_missing|edge_dns(_(output_limit|cli_(timeout|resolver|lookup|docker|exec|answer_present|unclassified)|answer_(missing|wrong_ip|malformed|inconsistent)|alias_missing|fixture_exited|readiness_exhausted))?|edge_http|local_dns|local_http|collision_dns|collision_http|foreign_route|cleanup_unverified))?|internal_(oracle|render|sidecar|peers|control|blocked|cleanup|topology)|external|negative|evidence)$' "$capture_path" | tail -n 1 || true)
if [[ -n $network_marker ]]; then marker=$network_marker; fi
volume_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: volume_(missing_precheck|seed|read_only|read_write|persistence|identity|cleanup_unverified)$' "$capture_path" | tail -n 1 || true)
if [[ -n $volume_marker ]]; then marker=$volume_marker; fi
dns_diag=$(grep -Eo '^DOCKERLENS_NATIVE_DNS_DIAG: peer=(ready|invalid|unavailable) resolver=(unrun|unavailable|embedded_(search|plain)|other_(search|plain)) default_a=(pass|fail|unrun) explicit_a=(pass|fail|unrun) dotted_a=(pass|fail|unrun) name_http=(pass|fail|unrun) ip_http=(pass|fail|unrun) edge_app=(pass|fail|unrun) cleanup=(pass|fail)$' "$capture_path" | tail -n 1 || true)
collision_dns_diag=$(grep -Eo '^DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=(backend|edge) category=(output_limit|cli_(timeout|resolver|lookup|docker|exec|answer_present|unclassified)|answer_(missing|wrong_ip|malformed|inconsistent)|alias_missing) exit=(success|lookup|timeout|other) response=(nxdomain|servfail|refused|no_error_no_a|has_expected_a|other)$' "$capture_path" | tail -n 1 || true)
container_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: container_((ports|ports_ipv6|outer_identity|host_(curl|bash)_preflight|identity_health|health_disabled(_(source_(create|inspect|cleanup)|image_(commit|inspect)|inherited_(create|start|wait)|oracle_(create|start)|rendered_(create|start|wait)))?|clear(_(baseline|cmd_alone|override_omit|paired_literal|rendered|entrypoint))?|start_interval|storage_lifecycle|resources_security(_(oracle|rendered)_(create|inspect|start|ulimit|status|groups|sysctl|device|memory|pids|shm))?|resolver_logging(_(ipv4|ipv6|local|none)_(oracle|rendered)_(create|inspect|body|start|resolver|hosts|logs))?)|port_(fixed_ipv4|fixed_ipv6|dynamic_ipv6|repeated_dynamic_ipv4)_(oracle|rendered)_(cli_create|cli_inspect|oracle_bindings|oracle_cleanup|oracle_start|cli_http(_secondary)?|http_assert(_secondary)?|local_service|render|render_body|api_create|api_inspect|rendered_bindings|api_start|dynamic_binding(_secondary)?|isolated_http|isolated_assert|udp_assignment|udp_send|udp_receive|udp_assert|tcp6_boundary|negative_recheck|runtime_absence))$' "$capture_path" | tail -n 1 || true)
if [[ -n $container_marker ]]; then marker=$container_marker; fi
cli_diag=$(grep -Eo '^DOCKERLENS_NATIVE_CLI_DIAG: exit=(timeout|signal|other) stderr=(connection_refused|missing_tool|address_family|invalid_address|no_route|permission|storage_exhausted|invalid_reference|missing_resource|image_storage|unknown)$' "$capture_path" | tail -n 1 || true)
http_diag=$(grep -Eo '^DOCKERLENS_NATIVE_HTTP_DIAG: exit=(success|timeout|signal|other) category=(body_mismatch|connection_refused|missing_tool|address_family|invalid_address|no_route|permission|unknown)$' "$capture_path" | tail -n 1 || true)
ipv6_diag=$(grep -Eo '^DOCKERLENS_NATIVE_IPV6_DIAG: local_service=(pass|fail) inner_all=(enabled|disabled|unavailable) inner_lo=(enabled|disabled|unavailable) outer_tcp6=(available|tcp6_unavailable|bind_unavailable|loopback_unavailable|probe_failed) curl_exit=(0|6|7|22|23|28|35|52|56|60|124|137|other)$' "$capture_path" | tail -n 1 || true)
ipv6_boundary_diag=$(grep -Eo '^DOCKERLENS_NATIVE_IPV6_BOUNDARY_DIAG: result=(refused|connected|timeout|other|malformed)$' "$capture_path" | tail -n 1 || true)
port_bindings_diag=$(grep -Eo '^DOCKERLENS_NATIVE_PORT_BINDINGS_DIAG: key=(missing|null|array|other) count=(zero|one|two|many) ipv4=(zero|one|two|many) ipv6=(zero|one|two|many) other=(zero|one|two|many) v4_port=(absent|nonzero|zero|empty|malformed|multiple) v6_port=(absent|nonzero|zero|empty|malformed|multiple)$' "$capture_path" | tail -n 1 || true)
clear_diag=$(grep -Eo '^DOCKERLENS_NATIVE_CLEAR_DIAG: phase=(alone|override_omit|paired|rendered) cmd=(missing|null|empty_array|image_default|other) entrypoint=(missing|shell|other) path=(missing|shell|other) args=(missing|empty|image_default|other)$' "$capture_path" | tail -n 1 || true)
cap_drop_diag=$(grep -Eo '^DOCKERLENS_NATIVE_CAP_DROP_DIAG: phase=(oracle|rendered) state=(array|null|other) count=(zero|one|two|many) spelling=(sys_admin|cap_sys_admin|other|absent|multiple)$' "$capture_path" | tail -n 1 || true)
isolation_diag=$(grep -Eo '^DOCKERLENS_NATIVE_ISOLATION_DIAG: result=(refused|connected|timeout|other)$' "$capture_path" | tail -n 1 || true)
namespace_diag=$(grep -Eo '^DOCKERLENS_NATIVE_NAMESPACE_DIAG: category=(input|inspect|identity|changed|process|missing_tool|probe)$' "$capture_path" | tail -n 1 || true)
api_diag=$(grep -E '^DOCKERLENS_NATIVE_API_DIAG: (transport=(timeout|other)|operation=(inspect|create|start) status=(invalid_request|not_found|conflict|server|other))$' "$capture_path" | tail -n 1 | sed 's/^DOCKERLENS_NATIVE_API_DIAG: /DOCKERLENS_NATIVE_API_DIAG: observation=last /' || true)
resolver_logs_diag=$(grep -E '^DOCKERLENS_NATIVE_RESOLVER_LOGS_DIAG: operation=logs outcome=cli_failure$' "$capture_path" | tail -n 1 || true)
resolver_log_canary_diag=$(grep -E '^DOCKERLENS_NATIVE_RESOLVER_LOG_CANARY: side=(oracle|rendered) outcome=(present|missing)$' "$capture_path" | tail -n 2 || true)
start_body_diag=$(grep -Eo '^DOCKERLENS_NATIVE_START_BODY_DIAG: shape=(message|missing|malformed|oversize) cgroup_mention=(present|absent|unknown) device_mention=(present|absent|unknown) sysctl_mention=(present|absent|unknown) ulimit_mention=(present|absent|unknown) apparmor_mention=(present|absent|unknown) permission_phrase=(present|absent|unknown) errno_mention=(present|absent|unknown) controller_mention=(present|absent|unknown) bpf_mention=(present|absent|unknown)$' "$capture_path" | tail -n 1 || true)
resource_control_diag=$(grep -E '^DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=(baseline|memory|pids|device|device-same-path) phase=(create|inspect|start) outcome=(begin|ready|started|rejected|timeout|uncertain|invalid|budget)$' "$capture_path" | tail -n 35 || true)
resource_start_http_diag=$(grep -E '^DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=(baseline|memory|pids|device|device-same-path) status=[1-5][0-9][0-9]$' "$capture_path" | tail -n 5 || true)
resource_start_body_diag=$(grep -E '^DOCKERLENS_NATIVE_RESOURCE_START_BODY_DIAG: control=(baseline|memory|pids|device|device-same-path) shape=(message|missing|malformed|oversize) cgroup_mention=(present|absent|unknown) device_mention=(present|absent|unknown) sysctl_mention=(present|absent|unknown) ulimit_mention=(present|absent|unknown) apparmor_mention=(present|absent|unknown) permission_phrase=(present|absent|unknown) errno_mention=(present|absent|unknown) controller_mention=(present|absent|unknown) bpf_mention=(present|absent|unknown)$' "$capture_path" | tail -n 5 || true)
resource_start_state_diag=$(grep -E '^DOCKERLENS_NATIVE_RESOURCE_START_STATE: control=(baseline|memory|pids|device|device-same-path) state=(created|running|other)$' "$capture_path" | tail -n 5 || true)
resource_effect_diag=$(grep -E '^DOCKERLENS_NATIVE_RESOURCE_EFFECT_DIAG: control=(baseline|memory|pids|device|device-same-path) memory_configured=(finite|unset|unknown) memory_read=(finite|unlimited|missing|denied|invalid_file|oversized|malformed|read_error|not_running|unavailable) memory_effect=(matches|differs|unlimited|unknown) pids_configured=(finite|unset|unlimited|unknown) pids_read=(finite|unlimited|missing|denied|invalid_file|oversized|malformed|read_error|not_running|unavailable) pids_effect=(matches|differs|unlimited|unknown) enforcement=unknown$' "$capture_path" | tail -n 5 || true)
device_start_body_diag=$(grep -E '^DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG: control=(device|device-same-path) host_path_mention=(present|absent|unknown) destination_path_mention=(present|absent|unknown) errno_phrase=(enoent|eacces|eperm|einval|ambiguous|unknown) namespace=unknown source_presence=unknown source_type=unknown$' "$capture_path" | tail -n 2 || true)
oracle_start_state_diag=$(grep -E '^DOCKERLENS_NATIVE_ORACLE_START_STATE: state=(created|running|exited|missing|mismatch|unavailable)$' "$capture_path" | tail -n 1 || true)
start_timeout_diag=$(grep -E '^DOCKERLENS_NATIVE_START_TIMEOUT_DIAG: (state=(created|running|exited|other) reason=none|state=missing reason=status|state=identity_mismatch reason=identity_mismatch|state=unavailable reason=(input|transport|status|invalid_payload))$' "$capture_path" | tail -n 1 || true)
cleanup_step_diag=$(grep -E '^DOCKERLENS_NATIVE_CLEANUP_STEP: step=(tracked_delete|delete_inspect|delete_request|container_name_list|container_label_list|container_inspect|image_label_list|image_reference_list|image_inspect|inventory_delete_container|inventory_delete_image|readback_first|readback_stable) outcome=(begin|pass)$' "$capture_path" | tail -n 32 || true)
cleanup_readback_diag=$(grep -E '^DOCKERLENS_NATIVE_CLEANUP_READBACK: group=(ports|identity_health_clear|storage_lifecycle|resources_security|resolver_logging) phase=(first|stable) containers=(zero|nonzero) images=(zero|nonzero)$' "$capture_path" | tail -n 2 || true)
group_cleanup_diag=$(grep -E '^DOCKERLENS_NATIVE_GROUP_CLEANUP: group=(ports|identity_health_clear|storage_lifecycle|resources_security|resolver_logging) outcome=(begin|verified|unverified)$' "$capture_path" | tail -n 4 || true)
container_flow_diag=$(grep -E '^DOCKERLENS_NATIVE_CONTAINER_FLOW: (phase=mutation outcome=(timeout|uncertain)|phase=cleanup_(tracked|inventory|readback) outcome=(begin|pass|fail)|phase=decision outcome=(merge|probe_failed|cleanup_unverified|mutation_uncertain))$' "$capture_path" | tail -n 8 || true)
group_failures=$(grep -E '^DOCKERLENS_NATIVE_GROUP_FAILURE: group=(ports|identity_health_clear|storage_lifecycle|resources_security|resolver_logging) reason=(preflight|probe|cleanup_unverified|mutation_uncertain)$' "$capture_path" | head -n 5 || true)
reason_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: target_start_reason_(operation_not_permitted|permission_denied|invalid_argument|read_only_filesystem|not_found|timeout|unclassified)$' "$capture_path" | tail -n 1 || true)
error_category=$(grep -Eo '^DOCKERLENS_NATIVE_ERROR: (endpoint|cancelled|deadline|io|protocol|status|version|shape|budget)$' "$capture_path" | tail -n 1 || true)
selection_error=$(grep -Eo '^DOCKERLENS_NATIVE_ERROR: selection$' "$capture_path" | tail -n 1 || true)
volume_label_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: volume_labels_(create|persistence|ownership|cleanup_unverified)$' "$capture_path" | tail -n 1 || true)
if [[ -n $volume_label_marker ]]; then marker=$volume_label_marker; fi
identity_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: identity_(context|oracle|render|cleanup|cleanup_unverified|evidence)$' "$capture_path" | tail -n 1 || true)
if [[ -n $identity_marker ]]; then marker=$identity_marker; fi
reason_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: target_start_reason_(operation_not_permitted|permission_denied|invalid_argument|read_only_filesystem|not_found|timeout|unclassified)$' "$capture_path" | tail -n 1 || true)
error_category=$(grep -Eo '^DOCKERLENS_NATIVE_ERROR: (endpoint|cancelled|deadline|io|protocol|status|version|shape|budget)$' "$capture_path" | tail -n 1 || true)
selection_error=$(grep -Eo '^DOCKERLENS_NATIVE_ERROR: selection$' "$capture_path" | tail -n 1 || true)
if [[ -n $selection_error ]]; then error_category=$selection_error; fi
network_cli_diag=$(grep -Eo '^DOCKERLENS_NATIVE_NETWORK_CLI_DIAG: exit=(timeout|other) category=(bridge_filter|icc_configuration|firewall_disabled|firewall|permission|address_pool|invalid_label|invalid_option|unknown)$' "$capture_path" | tail -n 1 || true)
internal_cleanup=$(grep -Eo '^DOCKERLENS_NATIVE_CLEANUP: internal_proof=(pass|fail)$' "$capture_path" | tail -n 1 || true)
# The first panic's selected test source and numeric location identify the
# original assertion without disclosing its message, values, or build path.
panic_site=
case $target in
  native_target | native_volume | native_network | native_volume_label | native_container | native_identity)
    panic_site=$(sed -nE "s/^thread '.*'( \([0-9]{1,10}\))? panicked at src\/(${target}_tests)\.rs:([0-9]{1,6}):([0-9]{1,4}):$/DOCKERLENS_NATIVE_PANIC: source=\2 line=\3 column=\4/p; t matched; b; :matched; q" "$capture_path")
    ;;
esac
if (( run_status != 0 )); then
  echo "required native test $target::$test_name failed (exit $run_status)" >&2
  if [[ -n $first_failure_diag ]]; then printf '%s\n' "$first_failure_diag" >&2; fi
  if [[ -n $marker ]]; then echo "$marker" >&2; fi
  if [[ -n $cli_diag ]]; then echo "$cli_diag" >&2; fi
  if [[ -n $http_diag ]]; then echo "$http_diag" >&2; fi
  if [[ -n $ipv6_diag ]]; then echo "$ipv6_diag" >&2; fi
  if [[ -n $ipv6_boundary_diag ]]; then echo "$ipv6_boundary_diag" >&2; fi
  if [[ -n $port_bindings_diag ]]; then echo "$port_bindings_diag" >&2; fi
  if [[ -n $clear_diag ]]; then echo "$clear_diag" >&2; fi
  if [[ -n $cap_drop_diag ]]; then echo "$cap_drop_diag" >&2; fi
  if [[ -n $isolation_diag ]]; then echo "$isolation_diag" >&2; fi
  if [[ -n $namespace_diag ]]; then echo "$namespace_diag" >&2; fi
  if [[ -n $api_diag ]]; then echo "$api_diag" >&2; fi
  if [[ -n $resolver_logs_diag ]]; then echo "$resolver_logs_diag" >&2; fi
  if [[ -n $resolver_log_canary_diag ]]; then printf '%s\n' "$resolver_log_canary_diag" >&2; fi
  if [[ -n $start_body_diag ]]; then echo "$start_body_diag" >&2; fi
  if [[ -n $resource_control_diag ]]; then printf '%s\n' "$resource_control_diag" >&2; fi
  if [[ -n $resource_start_http_diag ]]; then printf '%s\n' "$resource_start_http_diag" >&2; fi
  if [[ -n $resource_start_body_diag ]]; then printf '%s\n' "$resource_start_body_diag" >&2; fi
  if [[ -n $resource_start_state_diag ]]; then printf '%s\n' "$resource_start_state_diag" >&2; fi
  if [[ -n $resource_effect_diag ]]; then printf '%s\n' "$resource_effect_diag" >&2; fi
  if [[ -n $device_start_body_diag ]]; then printf '%s\n' "$device_start_body_diag" >&2; fi
  if [[ -n $oracle_start_state_diag ]]; then echo "$oracle_start_state_diag" >&2; fi
  if [[ -n $start_timeout_diag ]]; then echo "$start_timeout_diag" >&2; fi
  if [[ -n $cleanup_step_diag ]]; then printf '%s\n' "$cleanup_step_diag" >&2; fi
  if [[ -n $cleanup_readback_diag ]]; then printf '%s\n' "$cleanup_readback_diag" >&2; fi
  if [[ -n $group_cleanup_diag ]]; then printf '%s\n' "$group_cleanup_diag" >&2; fi
  if [[ -n $container_flow_diag ]]; then printf '%s\n' "$container_flow_diag" >&2; fi
  if [[ -n $group_failures ]]; then printf '%s\n' "$group_failures" >&2; fi
  if [[ -n $dns_diag ]]; then echo "$dns_diag" >&2; fi
  if [[ -n $collision_dns_diag ]]; then echo "$collision_dns_diag" >&2; fi
  if [[ -n $reason_marker ]]; then echo "$reason_marker" >&2; fi
  if [[ -n $error_category ]]; then echo "$error_category" >&2; fi
  if [[ -n $network_cli_diag ]]; then echo "$network_cli_diag" >&2; fi
  if [[ -n $internal_cleanup ]]; then echo "$internal_cleanup" >&2; fi
  if [[ -n $panic_site ]]; then echo "$panic_site" >&2; fi
  if [[ -n $summary ]]; then
    echo "$summary" >&2
  fi
  exit 1
fi
if ! grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;' "$capture_path"; then
  echo "required native test $target::$test_name did not execute exactly once (exit $run_status)" >&2
  if [[ -n $summary ]]; then
    echo "$summary" >&2
  fi
  exit 1
fi
echo "required native test passed: $target::$test_name"
