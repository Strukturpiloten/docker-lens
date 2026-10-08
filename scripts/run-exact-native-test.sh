#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ! $1 =~ ^[a-z_]+$ || ! $2 =~ ^[a-z_]+$ ]]; then
  echo "usage: $0 <integration-test-target> <exact-ignored-test-name>" >&2
  exit 2
fi
target=$1
test_name=$2
if [[ $target == native_target || $target == native_volume || $target == native_network || $target == native_volume_label || $target == native_identity || $target == native_port || $target == native_health_metadata || $target == native_network_attachment || $target == native_bind_relabel ]]; then
  # Native target tests need crate-private, test-only capability claims.
  # It is a library unit test; no public constructor is exposed for the harness.
  cargo_target=(--lib)
  selected="${target}_tests::$test_name"
else
  cargo_target=(--test "$target")
  selected=$test_name
fi

# libtest returns success for zero selected tests. Check the ignored-only list
# first, then require exactly one executed success in the final summary.
list_status=0
listing=$(timeout 180 cargo test --locked "${cargo_target[@]}" -- --ignored --list 2>&1) || list_status=$?
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
result=$(NATIVE_NETWORK_TEST_DEADLINE_EPOCH=$run_deadline_epoch NATIVE_HEALTH_METADATA_DEADLINE_EPOCH=$run_deadline_epoch timeout 180 cargo test --locked "${cargo_target[@]}" -- --ignored --exact "$selected" 2>&1) || run_status=$?
# Only libtest's numeric summary is safe to print. Test and compiler output can
# contain protected native values, socket payloads, or authored secrets.
summary=$(grep -Eo '^test result: (ok|FAILED)\. [0-9]+ passed; [0-9]+ failed; [0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out;' <<<"$result" | tail -n 1 || true)
# Only constant markers authored by the native tests may pass this boundary.
# Never print arbitrary assertion, compiler, daemon, or captured API output.
marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: (capture_(input|decode|daemon|counts|image|ports|mounts|environment|command|privacy)|acquire_(input|oracle|socket|route|network|decode|mode|settings|replay)|target_(daemon_uid|mode|ports|mounts|settings|traffic(_probe)?|health_(create|start|wait)|shape_(network_attach|bind_rw|volume_ro(_created|_inspected|_started|_accessible|_write_(zero|one|other))?|restart)|uid_(probe_failed|shape|count)|rootless_uid_zero|rootful_uid_nonzero|start_(uidmap|userns|cgroup|network|mount|storage|runtime|permission|unclassified|timeout|exec))|read_only_(acquire|route|status|decode|daemon|mode|api))$' <<<"$result" | tail -n 1 || true)
source_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: (source_(fixture_oracles|discovery|narrow_selectors|all_and_resource_roots|multiple_bindings|typed_oracle|network_membership)|membership_cleanup_unverified)$' <<<"$result" | tail -n 1 || true)
if [[ -n $source_marker ]]; then marker=$source_marker; fi
network_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: network_(identity|oracle(_((primary|alternate)_(create|inspect|assert)|external_(create|inspect)))?|render|apply|inspect|aliases|traffic|isolation(_(edge_fixture(_exited)?|edge_alias_missing|backend_alias_missing|edge_dns(_(output_limit|cli_(timeout|resolver|lookup|docker|exec|answer_present|unclassified)|answer_(missing|wrong_ip|malformed|inconsistent)|alias_missing|fixture_exited|readiness_exhausted))?|edge_http|local_dns|local_http|collision_dns|collision_http|foreign_route|cleanup_unverified))?|internal_(oracle|render|sidecar|peers|control|blocked|cleanup|topology)|external|negative|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $network_marker ]]; then marker=$network_marker; fi
volume_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: volume_(missing_precheck|seed|read_only|read_write|persistence|identity|cleanup_unverified)$' <<<"$result" | tail -n 1 || true)
if [[ -n $volume_marker ]]; then marker=$volume_marker; fi
dns_diag=$(grep -Eo '^DOCKERLENS_NATIVE_DNS_DIAG: peer=(ready|invalid|unavailable) resolver=(unrun|unavailable|embedded_(search|plain)|other_(search|plain)) default_a=(pass|fail|unrun) explicit_a=(pass|fail|unrun) dotted_a=(pass|fail|unrun) name_http=(pass|fail|unrun) ip_http=(pass|fail|unrun) edge_app=(pass|fail|unrun) cleanup=(pass|fail)$' <<<"$result" | tail -n 1 || true)
collision_dns_diag=$(grep -Eo '^DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=(backend|edge) category=(output_limit|cli_(timeout|resolver|lookup|docker|exec|answer_present|unclassified)|answer_(missing|wrong_ip|malformed|inconsistent)|alias_missing) exit=(success|lookup|timeout|other) response=(nxdomain|servfail|refused|no_error_no_a|has_expected_a|other)$' <<<"$result" | tail -n 1 || true)
volume_label_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: volume_labels_(create|persistence|ownership|cleanup_unverified)$' <<<"$result" | tail -n 1 || true)
if [[ -n $volume_label_marker ]]; then marker=$volume_label_marker; fi
identity_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: identity_(context|oracle|render|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $identity_marker ]]; then marker=$identity_marker; fi
health_metadata_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: health_metadata_(context|derive|grace_positive|period_zero|inherited_failure|disabled|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $health_metadata_marker ]]; then marker=$health_metadata_marker; fi
network_attachment_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: network_attachment_(context|oracle|rendered|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $network_attachment_marker ]]; then marker=$network_attachment_marker; fi
network_attachment_causal_marker=
if [[ $target == native_network_attachment ]]; then
  network_attachment_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: network_attachment_(context|oracle|rendered|cleanup|cleanup_unverified|evidence)$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup(_unverified)?$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
fi
bind_relabel_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: bind_relabel_(context|oracle|rendered|cleanup|cleanup_unverified|evidence)$' <<<"$result" | tail -n 1 || true)
if [[ -n $bind_relabel_marker ]]; then marker=$bind_relabel_marker; fi
bind_relabel_causal_marker=
if [[ $target == native_bind_relabel ]]; then
  bind_relabel_causal_marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: bind_relabel_(context|oracle|rendered|cleanup|cleanup_unverified|evidence)$' <<<"$result" | awk '/^DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup(_unverified)?$/ { exit } { last=$0 } END { if (last != "") print last }' || true)
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
internal_cleanup=$(grep -Eo '^DOCKERLENS_NATIVE_CLEANUP: internal_proof=(pass|fail)$' <<<"$result" | tail -n 1 || true)
# A panic's selected test source and numeric location identify an assertion
# without disclosing its message, compared values, or an absolute build path.
panic_site=
case $target in
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
  native_target | native_volume | native_network | native_volume_label | native_container | native_identity)
    panic_site=$(sed -nE "s/^thread '.*'( \([0-9]{1,10}\))? panicked at src\/(${target}_tests)\.rs:([0-9]{1,6}):([0-9]{1,4}):$/DOCKERLENS_NATIVE_PANIC: source=\2 line=\3 column=\4/p" <<<"$result" | tail -n 1)
    ;;
esac
if (( run_status != 0 )); then
  echo "required native test $target::$test_name failed (exit $run_status)" >&2
  if [[ -n $port_causal_marker && $port_causal_marker != "$marker" ]]; then echo "$port_causal_marker" >&2; fi
  if [[ -n $marker ]]; then echo "$marker" >&2; fi
  if [[ -n $health_metadata_causal_marker && $health_metadata_causal_marker != "$marker" ]]; then echo "$health_metadata_causal_marker" >&2; fi
  if [[ -n $network_attachment_causal_marker && $network_attachment_causal_marker != "$marker" ]]; then echo "$network_attachment_causal_marker" >&2; fi
  if [[ -n $bind_relabel_causal_marker && $bind_relabel_causal_marker != "$marker" ]]; then echo "$bind_relabel_causal_marker" >&2; fi
  if [[ -n $port_diagnostics ]]; then printf '%s' "$port_diagnostics" >&2; fi
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
if ! grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;' <<<"$result"; then
  echo "required native test $target::$test_name did not execute exactly once (exit $run_status)" >&2
  if [[ -n $summary ]]; then
    echo "$summary" >&2
  fi
  exit 1
fi
echo "required native test passed: $target::$test_name"
