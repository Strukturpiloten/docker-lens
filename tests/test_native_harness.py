"""Fault injection for exact resource cleanup and ignored native test selection."""

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeHarnessTests(unittest.TestCase):
    def test_sidecar_failure_categories_are_closed_and_hide_native_text(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        classifier = "classify_sidecar_error() {" + source.split(
            "classify_sidecar_error() {", 1
        )[1].split("\n}\nsidecar_failure_diagnostic()", 1)[0] + "\n}\n"
        cases = (
            ("sh: httpd: not found private-canary", "applet_missing"),
            ("sh: syntax error: private-canary", "shell_error"),
            ("httpd: invalid option private-canary", "config_error"),
            ("httpd: can't bind to port private-canary", "bind_error"),
            ("permission denied private-canary", "permission"),
            ("no space left on device private-canary", "storage"),
            ("runtime error private-canary", "runtime_error"),
            ("private-canary", "unknown"),
            ("", "unknown"),
        )
        for native_text, expected in cases:
            with self.subTest(category=expected):
                result = subprocess.run(
                    ["bash", "-c", classifier + "classify_sidecar_error"],
                    input=native_text, capture_output=True, text=True, timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, expected + "\n")
                self.assertEqual(result.stderr, "")
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_outer_ipv4_diagnostics_are_closed_for_each_rejection(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        helper = source.split("validated_outer_ipv4() {", 1)[1].split(
            "\n}\nsidecar_setup_failed()", 1
        )[0]
        network = "dl-native-net-fixture"
        valid = {network: {"IPAddress": "10.89.0.2"}}
        fixtures = (
            ('{"private-canary":', "json_shape", "0"),
            (json.dumps([]), "json_shape", "0"),
            (json.dumps({}), "network_missing", "0"),
            (json.dumps({**valid, "unexpected": {"IPAddress": "10.89.0.3"}}), "network_extra", "0"),
            (json.dumps({network: {}}), "ipv4_missing", "0"),
            (json.dumps({network: {"IPAddress": "private-canary"}}), "ipv4_malformed", "0"),
            (json.dumps({network: {"IPAddress": 173604866}}), "ipv4_malformed", "0"),
            (json.dumps({network: {"IPAddress": "8.8.8.8"}}), "ipv4_nonprivate", "0"),
            (json.dumps(valid), "inspect_failed", "42"),
            ("private-canary" * 300, "output_limit", "0"),
        )
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "podman"
            fake.write_text(
                '#!/usr/bin/env bash\nprintf %s "$FAKE_NETWORKS"\nexit "$FAKE_PODMAN_STATUS"\n',
                encoding="utf-8",
            )
            fake.chmod(0o755)
            script = (
                'podman_cmd=("$FAKE_PODMAN")\n'
                f'outer_network={network}\n'
                f'validated_outer_ipv4() {{{helper}\n}}\n'
                'validated_outer_ipv4 "$FAKE_ROLE" dl-native-fixture\n'
            )
            for role in ("sidecar", "daemon"):
                for networks, category, status in fixtures:
                    with self.subTest(role=role, category=category, status=status):
                        env = os.environ.copy()
                        env.update(FAKE_PODMAN=str(fake), FAKE_ROLE=role,
                                   FAKE_NETWORKS=networks, FAKE_PODMAN_STATUS=status)
                        result = subprocess.run(
                            ["bash", "-c", script], env=env, capture_output=True,
                            text=True, timeout=15, check=False,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(
                            result.stderr.strip(),
                            f"DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=attachment role={role} category={category}",
                        )
                        self.assertNotIn("private-canary", result.stderr)
            env = os.environ.copy()
            env.update(FAKE_PODMAN=str(fake), FAKE_ROLE="sidecar",
                       FAKE_NETWORKS=json.dumps(valid), FAKE_PODMAN_STATUS="0")
            result = subprocess.run(
                ["bash", "-c", script], env=env, capture_output=True,
                text=True, timeout=15, check=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "10.89.0.2\n")
            self.assertEqual(result.stderr, "")

    def test_network_oracle_diagnostics_are_closed_and_do_not_hide_failure(self) -> None:
        source = (ROOT / "src/native_network_tests.rs").read_text(encoding="utf-8")
        negative_cli = source.split("fn cli(args:", 1)[1].split("fn network_cli_failure_category", 1)[0]
        self.assertNotIn("DOCKERLENS_NATIVE_NETWORK_CLI_DIAG", negative_cli)
        positive_cli = source.split("fn cli_ok(args:", 1)[1].split("struct BoundedDnsCliOutput", 1)[0]
        self.assertIn("DOCKERLENS_NATIVE_NETWORK_CLI_DIAG", positive_cli)
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_network_render_matches_engine: test'
else
  echo 'DOCKERLENS_NATIVE_CHECK: network_oracle_alternate_create' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_oracle_private' >&2
  echo 'DOCKERLENS_NATIVE_NETWORK_CLI_DIAG: exit=other category=bridge_filter' >&2
  echo 'DOCKERLENS_NATIVE_NETWORK_CLI_DIAG: exit=other category=private-canary' >&2
  echo 'private-canary raw native output' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 101
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                 "live_network_render_matches_engine"],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("network_oracle_alternate_create", result.stderr)
            self.assertIn("exit=other category=bridge_filter", result.stderr)
            self.assertNotIn("private-canary", result.stdout + result.stderr)
            self.assertNotIn("network_oracle_private", result.stdout + result.stderr)

    def test_host_network_prerequisite_runs_before_owned_resources(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        preflight = 'python3 "$script_dir/native-bridge-prerequisite.py"'
        self.assertIn(preflight, source)
        self.assertLess(source.index(preflight), source.index('run_dir=$(mktemp -d'))
        self.assertNotIn("sysctl -w", source)
        self.assertNotIn("DOCKER_IGNORE_BR_NETFILTER_ERROR", source)

    def test_failure_exposes_only_selected_native_panic_location(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_network_render_matches_engine: test'
else
  printf '%s\\n' "$TEST_PANIC"
  echo 'assertion contains protected-native-canary and private path' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 101
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            # Current libtest includes a numeric thread ID; older Rust omits it.
            # Observed independently in an actual local Rust panic, not inferred
            # from the extractor's synthetic fixture. Never disclose that ID.
            for location, thread_suffix, expected in (
                ("src/native_network_tests.rs:1931:5", "", True),
                ("src/native_network_tests.rs:1931:5", " (342)", True),
                ("src/native_network_tests.rs:1931:5", " (private)", False),
                ("src/native_network_tests.rs:1931:5", " (12345678901)", False),
                ("/private/source/native_network_tests.rs:1931:5", " (342)", False),
                ("src/native_target_tests.rs:1931:5", " (342)", False),
                ("src/native_network_tests.rs:private:5", "", False),
                ("src/native_network_tests.rs:1931:50000", "", False),
            ):
                with self.subTest(location=location, thread_suffix=thread_suffix):
                    env["TEST_PANIC"] = f"thread 'protected-name-canary'{thread_suffix} panicked at {location}:"
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                         "live_network_render_matches_engine"],
                        env=env, text=True, capture_output=True, timeout=10,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual("DOCKERLENS_NATIVE_PANIC:" in result.stderr, expected)
                    if expected:
                        self.assertIn("source=native_network_tests line=1931 column=5", result.stderr)
                    for private in ("protected-native-canary", "protected-name-canary", "/private/source", "(342)"):
                        self.assertNotIn(private, result.stdout + result.stderr)

    def test_isolation_positive_controls_query_ipv4_before_negative_controls(self) -> None:
        source = (ROOT / "src/native_network_tests.rs").read_text(encoding="utf-8")
        markers = [
            "network_isolation_edge_dns", "network_isolation_edge_http",
            "network_isolation_local_dns", "network_isolation_local_http",
            "network_isolation_collision_dns", "network_isolation_collision_http",
            "network_isolation_foreign_route",
        ]
        self.assertEqual([source.count(f'DOCKERLENS_NATIVE_CHECK: {marker}"')
                          for marker in markers], [1] * len(markers))
        self.assertEqual([source.index(f'DOCKERLENS_NATIVE_CHECK: {marker}')
                          for marker in markers],
                         sorted(source.index(f'DOCKERLENS_NATIVE_CHECK: {marker}')
                                for marker in markers))
        self.assertEqual(re.findall(r'"nslookup",\s*"-type=A",\s*"([^"]+)"', source),
                         ["edge-sentinel", "edge-sentinel", "edge-sentinel.",
                          "backend-app", "edge-sentinel.", "edge-sentinel."])
        edge_dns = source[source.index('let edge_dns_outcome ='):source.index('if let Err(category) = edge_dns_outcome')]
        self.assertTrue('exec nslookup -type=A edge-sentinel 127.0.0.11' in edge_dns)
        self.assertTrue('/etc/resolv.conf || exit 42;' in edge_dns)
        local_dns = source[source.index('network_isolation_local_dns"'):source.index('network_isolation_local_http"')]
        self.assertIsNotNone(re.search(
            r'"exec",\s*&backend_only,\s*"cat",\s*"/etc/resolv\.conf"', local_dns,
        ))
        self.assertIsNotNone(re.search(
            r'"backend-app",\s*EMBEDDED_DNS_SERVER,', local_dns,
        ))
        self.assertTrue('resolver_category(&backend_resolver.stdout)' in local_dns)
        collision_dns = source[source.index('network_isolation_collision_dns"'):source.index('network_isolation_collision_http"')]
        self.assertEqual(len(re.findall(r'"edge-sentinel\.",\s*EMBEDDED_DNS_SERVER,', collision_dns)), 2)
        self.assertTrue('nslookup_has_only_exact_named_a(&edge_collision.stdout, "edge-sentinel", edge_ip)' in collision_dns)
        self.assertTrue('nslookup_has_only_exact_named_a(' in collision_dns)
        self.assertTrue('backend_canary_ip,' in collision_dns)
        self.assertTrue('DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=edge' in collision_dns)
        self.assertTrue('DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=backend' in collision_dns)
        self.assertIsNotNone(re.search(r'assert!\(\s*edge_exact', collision_dns))
        self.assertIsNotNone(re.search(r'assert!\(\s*backend_exact', collision_dns))
        edge_http = source[source.index('network_isolation_edge_http"'):source.index('network_isolation_local_dns"')]
        local_http = source[source.index('network_isolation_local_http"'):source.index('network_isolation_collision_dns"')]
        collision_http = source[source.index('network_isolation_collision_http"'):source.index('network_isolation_foreign_route"')]
        self.assertTrue('"http://edge-sentinel:8080/"' in edge_http)
        self.assertTrue('"http://backend-app:8080/"' in local_http)
        self.assertEqual(collision_http.count('"http://edge-sentinel:8080/"'), 2)
        self.assertTrue('b"edge-canary"' in collision_http)
        self.assertTrue('b"backend-canary"' in collision_http)
        self.assertTrue('canonical_inspected_container_id(&edge_only_body)' in source)
        self.assertTrue('canonical_inspected_container_id(&isolated)' in source)
        self.assertIsNotNone(re.search(r'assert!\(\s*edge_id != backend_id', source))
        self.assertIsNotNone(re.search(r'assert!\(\s*edge_ip != backend_canary_ip', source))
        self.assertTrue('network_isolation_cleanup_unverified' in source)
        self.assertTrue('let backend_cleaned = backend_fixture.cleanup();' in source)
        self.assertTrue('let edge_cleaned = edge_fixture.cleanup();' in source)
        self.assertTrue('fn nslookup_exact_named_a_rejects_extra_foreign_and_malformed_answers()' in source)
        self.assertIn('let edge_dns_outcome = wait_for_exact_dns_answer(', source)
        self.assertIn('if category != "cli_lookup"', source)
        self.assertIn('edge_dns_outcome.is_ok()', source)
        self.assertIn('let edge_alias_present =', source)
        self.assertIn('aliases.iter().any(|alias| alias == "edge-sentinel")', source)
        self.assertTrue('nslookup_has_ipv4_answer(&backend_answer.stdout, "backend-app", backend_ip)' in local_dns)
        self.assertIn("fn nslookup_ipv4_answer_requires_exact_named_address_not_prefix_or_resolver()", source)
        self.assertIn('edge_only_body["State"]["Running"] != true', source)
        self.assertIn("fn edge_dns_failure_categories_are_closed_and_value_free()", source)
        self.assertIn("fn exact_dns_readiness_retries_only_transient_lookup_with_finite_budget()", source)
        self.assertIn("const LIMIT: usize = 8192;", source)
        self.assertIn("let stdout_reader = std::thread::spawn", source)
        self.assertIn("let stderr_reader = std::thread::spawn", source)
        self.assertIn('private_docker_command("8")', source)
        self.assertIn('api_with_timeout("GET", path, None, "3")', source)
        self.assertLess(source.index("match named_dns_answer_category"),
                        source.index('if message.contains("can\'t resolve")'))
        self.assertIn("mixed wrong answer must not be retried", source)
        failure = source.index('if let Err(category) = edge_dns_outcome')
        self.assertLess(failure, source.index('diagnose_edge_dns(&run_id', failure))
        self.assertLess(source.index('diagnose_edge_dns(&run_id', failure),
                        source.index('edge_dns_outcome.is_ok()', failure))
        self.assertIsNotNone(re.search(
            r'"--name",\s*&peer,\s*"--network",\s*edge,\s*image,\s*"sleep",\s*"120"',
            source,
        ))
        self.assertIsNotNone(re.search(
            r'api_with_timeout_and_cap\("GET",\s*&path,\s*None,\s*"3",\s*Some\(1024 \* 1024\)\)',
            source,
        ))
        self.assertTrue('NATIVE_NETWORK_TEST_DEADLINE_EPOCH' in source)
        self.assertTrue('DNS_CLI_HARD_LIMIT_SECS' in source)
        self.assertTrue('command.args(["--kill-after=1", seconds])' in source)
        self.assertIn('networks.len() == 1 && networks.contains_key(edge)', source)
        self.assertIn('summary.cleanup = if guard.cleanup()', source)

    def test_dns_diagnostic_summary_is_closed_and_surfaced_separately(self) -> None:
        valid = ("DOCKERLENS_NATIVE_DNS_DIAG: peer=ready resolver=embedded_search "
                 "default_a=fail explicit_a=pass dotted_a=pass name_http=pass "
                 "ip_http=pass edge_app=pass cleanup=pass")
        invalid = ("DOCKERLENS_NATIVE_DNS_DIAG: peer=ready resolver=protected-secret "
                   "default_a=pass explicit_a=pass dotted_a=pass name_http=pass "
                   "ip_http=pass edge_app=pass cleanup=pass")
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_network_render_matches_engine: test'
else
  [[ ${NATIVE_NETWORK_TEST_DEADLINE_EPOCH:-} =~ ^[0-9]+$ ]] || exit 24
  remaining=$((NATIVE_NETWORK_TEST_DEADLINE_EPOCH - $(date +%s)))
  (( remaining >= 170 && remaining <= 180 )) || exit 24
  echo 'protected native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_isolation_edge_dns_readiness_exhausted' >&2
  printf '%s\n' "$TEST_DIAG" >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for supplied, accepted in ((valid, True), (invalid, False),
                                       (valid + " raw=protected-secret", False)):
                with self.subTest(accepted=accepted, supplied=supplied):
                    env["TEST_DIAG"] = supplied
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                         "live_network_render_matches_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(valid in result.stderr, accepted)
                    self.assertIn("network_isolation_edge_dns_readiness_exhausted", result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)
                    self.assertNotIn("protected native response", result.stdout + result.stderr)

    def test_collision_dns_diagnostic_is_closed_and_keeps_failure(self) -> None:
        valid = ("DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=backend category=cli_unclassified "
                 "exit=other response=no_error_no_a")
        invalid = ("DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=protected-secret category=cli_unclassified "
                   "exit=other response=no_error_no_a")
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_network_render_matches_engine: test'
else
  echo 'protected native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_isolation_collision_dns' >&2
  printf '%s\n' "$TEST_DIAG" >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for supplied, accepted in ((valid, True), (invalid, False),
                                       (valid + " raw=protected-secret", False)):
                with self.subTest(accepted=accepted, supplied=supplied):
                    env["TEST_DIAG"] = supplied
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                         "live_network_render_matches_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(valid in result.stderr, accepted)
                    self.assertIn("network_isolation_collision_dns", result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)
                    self.assertNotIn("protected native response", result.stdout + result.stderr)

    def test_network_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = '"$(dirname "$0")/run-exact-native-test.sh" native_network live_network_render_matches_engine'
        internal = '"$(dirname "$0")/run-exact-native-test.sh" native_network live_internal_network_blocks_external_egress'
        target = '"$(dirname "$0")/run-exact-native-test.sh" native_target live_target_render_matches_engine'
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertEqual(source.count(internal), 1)
        self.assertLess(source.index(target), source.index(selected))
        self.assertLess(source.index(selected), source.index(internal))
        self.assertLess(source.index(internal), source.index(manifest))
        self.assertIn('"$NATIVE_NETWORK_PROBES_PATH"', source)

    def test_internal_network_failure_marker_is_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_internal_network_blocks_external_egress: test'
else
  echo 'protected native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_internal_blocked' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_internal_private-canary' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                 "live_internal_network_blocks_external_egress"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("network_internal_blocked", result.stderr)
            self.assertNotIn("private-canary", result.stdout + result.stderr)
            self.assertNotIn("protected native response", result.stdout + result.stderr)

    def test_internal_cleanup_diagnostics_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_internal_network_blocks_external_egress: test'
else
  echo 'protected native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_internal_sidecar' >&2
  printf '%s\n' "$TEST_ENDPOINT_DIAG" "$TEST_CLEANUP_DIAG" >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for cleanup, accepted in (
                ("DOCKERLENS_NATIVE_CLEANUP: internal_proof=pass", True),
                ("DOCKERLENS_NATIVE_CLEANUP: internal_proof=fail", True),
                ("DOCKERLENS_NATIVE_CLEANUP: internal_proof=private-canary", False),
            ):
                with self.subTest(accepted=accepted):
                    env["TEST_ENDPOINT_DIAG"] = "DOCKERLENS_NATIVE_ENDPOINT_DIAG: phase=create category=host_mode_unsupported exit=other"
                    env["TEST_CLEANUP_DIAG"] = cleanup
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                         "live_internal_network_blocks_external_egress"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(cleanup in result.stderr, accepted)
                    self.assertNotIn("DOCKERLENS_NATIVE_ENDPOINT_DIAG", result.stderr)
                    self.assertNotIn("private-canary", result.stdout + result.stderr)
                    self.assertNotIn("protected native response", result.stdout + result.stderr)

    def test_network_option_value_and_label_controls_are_closed(self) -> None:
        source = (ROOT / "src/native_network_tests.rs").read_text(encoding="utf-8")
        version = (ROOT / "src/version.rs").read_text(encoding="utf-8")
        self.assertIn('"NetworkBridgeIccDisabled"', source)
        self.assertIn('"NetworkBridgeMasqueradeEnabled"', source)
        self.assertIn('"NetworkCreateLabelsValueDomain"', source)
        self.assertIn('Self::NetworkBridgeIccDisabled,', version)
        self.assertIn('Self::NetworkBridgeMasqueradeEnabled,', version)
        self.assertIn('"com.docker.network.bridge.enable_icc=false"', source)
        self.assertIn('"com.docker.network.bridge.enable_ip_masquerade=true"', source)
        self.assertIn('NetworkLabel::new(EMPTY_LABEL_KEY.as_bytes().to_vec(), Vec::new())', source)
        self.assertIn('SPECIAL_LABEL_VALUE.as_bytes().to_vec()', source)
        self.assertIn('oracle_control_body["Labels"] == expected_labels', source)
        self.assertIn('control_request["body"] == expected_option_control_body(&control, false)', source)
        self.assertIn('enabled_request["body"] == expected_option_control_body(&control_enabled, true)', source)
        self.assertIn('matched["Options"]["com.docker.network.bridge.enable_icc"] = json!("true")', source)
        self.assertIn('control_body["Labels"] == expected_labels', source)
        enabled = source.index('backend_http.as_slice()')
        disabled = source.index('ICC-disabled control must block healthy same-bridge peers')
        self.assertLess(enabled, disabled)
        self.assertIn('"http://127.0.0.1:8080/"', source[enabled:disabled])
        self.assertIn('let cross_url = format!("http://{server_ip}:8080/")', source[enabled:disabled])
        self.assertIn('let enabled_cross_url = format!("http://{enabled_server_ip}:8080/")', source[enabled:disabled])
        self.assertIn('enabled_cross_success && enabled_cross_body.as_slice() == b"control-server"', source[enabled:disabled])
        self.assertIn('!cross_success && cross_body.is_empty()', source[enabled:disabled])

    def test_network_failure_marker_is_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_network_render_matches_engine: test'
else
  echo 'protected native response' >&2
  echo "DOCKERLENS_NATIVE_CHECK: network_isolation_$TEST_MARKER" >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for marker in (
                "edge_fixture_exited", "edge_alias_missing", "edge_dns",
                "edge_dns_fixture_exited", "edge_dns_readiness_exhausted",
                "edge_dns_output_limit",
                "edge_dns_cli_timeout", "edge_dns_cli_resolver", "edge_dns_cli_lookup",
                "edge_dns_cli_docker", "edge_dns_cli_exec",
                "edge_dns_cli_answer_present", "edge_dns_cli_unclassified",
                "edge_dns_answer_missing", "edge_dns_answer_wrong_ip",
                "edge_dns_answer_malformed", "edge_dns_answer_inconsistent",
                "edge_dns_alias_missing", "edge_http", "backend_alias_missing",
                "local_dns", "local_http", "collision_dns", "collision_http",
                "foreign_route", "cleanup_unverified",
            ):
                with self.subTest(marker=marker):
                    env["TEST_MARKER"] = marker
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                         "live_network_render_matches_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"DOCKERLENS_NATIVE_CHECK: network_isolation_{marker}",
                                  result.stderr)
                    self.assertNotIn("private", result.stdout + result.stderr)

    def test_source_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = '"$(dirname "$0")/run-exact-native-test.sh" native_selection live_native_selection_and_source_observations'
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertLess(source.index(selected), source.index(manifest))
        self.assertIn('"$NATIVE_SOURCE_PROBES_PATH"', source)
        self.assertIn('io.dockerlens.fixture=decoy', source)

    def test_membership_probe_follows_source_and_precedes_manifest(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        baseline = 'native_selection live_native_selection_and_source_observations'
        membership = ('"$(dirname "$0")/run-exact-native-test.sh" native_selection '
                      'live_network_membership_matches_engine')
        self.assertEqual(source.count(membership), 1)
        self.assertLess(source.index(baseline), source.index(membership))
        self.assertLess(source.index(membership), source.index('python3 "$script_dir/native-evidence.py"'))

    def test_membership_failure_markers_remain_closed_and_private(self) -> None:
        for marker in ("source_network_membership", "membership_cleanup_unverified"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                bin_dir = Path(directory)
                self._tool(bin_dir, "cargo", f'''#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'live_network_membership_matches_engine: test'
else
  echo 'private native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: {marker}' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: membership_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
''')
                env = os.environ.copy()
                env["PATH"] = f"{bin_dir}:{env['PATH']}"
                result = subprocess.run(
                    [str(ROOT / "scripts/run-exact-native-test.sh"), "native_selection",
                     "live_network_membership_matches_engine"],
                    env=env, capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: {marker}", result.stderr)
                self.assertNotIn("private", result.stdout + result.stderr)

    def test_existing_volume_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = ('"$(dirname "$0")/run-exact-native-test.sh" native_volume '
                    'live_existing_volume_prerequisite_matches_engine')
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertLess(source.index(selected), source.index(manifest))
        self.assertIn('export NATIVE_VOLUME_PROBES_PATH="$run_dir/volume-probes.json"', source)
        self.assertIn('"$NATIVE_VOLUME_PROBES_PATH"', source)

    def test_created_volume_label_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = ('"$(dirname "$0")/run-exact-native-test.sh" native_volume_label '
                    'live_created_volume_labels_match_engine')
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertLess(source.index(selected), source.index(manifest))
        self.assertIn('export NATIVE_VOLUME_LABEL_PROBES_PATH="$run_dir/volume-label-probes.json"', source)
        self.assertIn('"$NATIVE_VOLUME_LABEL_PROBES_PATH"', source)

    def test_volume_label_failure_markers_remain_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_volume_label_tests::live_created_volume_labels_match_engine: test'
else
  echo 'private native volume label response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_labels_create' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_labels_private' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_labels_cleanup_unverified' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_volume_label",
                 "live_created_volume_labels_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DOCKERLENS_NATIVE_CHECK: volume_labels_cleanup_unverified", result.stderr)
            self.assertNotIn("private", result.stdout + result.stderr)

    def test_volume_failure_markers_remain_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_volume_tests::live_existing_volume_prerequisite_matches_engine: test'
else
  echo 'private native volume response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_missing_precheck' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_private' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_cleanup_unverified' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_volume",
                 "live_existing_volume_prerequisite_matches_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DOCKERLENS_NATIVE_CHECK: volume_cleanup_unverified", result.stderr)
            self.assertNotIn("private", result.stdout + result.stderr)

    def test_source_failure_markers_remain_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'live_native_selection_and_source_observations: test'
else
  echo 'private native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: source_multiple_bindings' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: source_private' >&2
  echo 'DOCKERLENS_NATIVE_ERROR: selection' >&2
  echo 'DOCKERLENS_NATIVE_ERROR: private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_selection",
                 "live_native_selection_and_source_observations"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DOCKERLENS_NATIVE_CHECK: source_multiple_bindings", result.stderr)
            self.assertIn("DOCKERLENS_NATIVE_ERROR: selection", result.stderr)
            self.assertNotIn("private", result.stdout + result.stderr)

    def test_effective_storage_check_fails_closed_before_native_work(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        block = source.split("\n\napi_get() {", 1)[0].rsplit(
            "\nif [[ $lane == debian11-rootless ]]; then", 1
        )[1]
        block = "if [[ $lane == debian11-rootless ]]; then" + block
        destination = "/home/docker/.local/share/docker"
        valid = f"18 7 0:42 /private-source {destination} rw - ext4 /private-device rw"
        for lane, mountinfo, status, admitted in (
            ("debian11-rootless", valid, 0, True),
            ("debian11-rootless", valid.replace(" rw -", " rw,nosuid,nodev -"), 0, False),
            ("debian11-rootless", valid, 42, False),
            ("debian11-rootless", "", 0, False),
            ("upstream-rootless", "", 42, True),
        ):
            with self.subTest(lane=lane, mountinfo=mountinfo, status=status):
                env = os.environ.copy()
                env.update(lane=lane, script_dir=str(ROOT / "scripts"),
                           TEST_MOUNTINFO=mountinfo, TEST_STATUS=str(status))
                result = subprocess.run(
                    ["bash", "-c", "set -euo pipefail\n"
                     "timeout() { printf '%s\\n' \"$TEST_MOUNTINFO\"; "
                     "echo protected-secret >&2; return \"$TEST_STATUS\"; }\n"
                     "podman_cmd=(unused)\ncontainer=synthetic\n" + block
                     + "\nprintf 'native-work-admitted'\n"],
                    env=env, capture_output=True, text=True, timeout=5, check=False,
                )
                self.assertEqual(result.returncode == 0, admitted, result.stderr)
                self.assertEqual("native-work-admitted" in result.stdout, admitted)
                self.assertNotIn("protected-secret", result.stdout + result.stderr)
                self.assertNotIn("private-source", result.stdout + result.stderr)

    def test_read_only_volume_start_keeps_classified_failure_probe(self) -> None:
        source = (ROOT / "src/native_target_tests.rs").read_text(encoding="utf-8")
        start = source.split(
            'eprintln!("DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_inspected");', 1
        )[1].split(
            'eprintln!("DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_started");', 1
        )[0]
        self.assertIn("start_native_source(&volume_ro_id);", start)

    def test_synthetic_bind_fixture_is_writable_but_parent_stays_private(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        fixture = source.split(
            "# A random directory, two containers, network, and volume belong to this lane.", 1
        )[1].split("\nwatchdog_pid=", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            env = os.environ.copy()
            env["TMPDIR"] = temporary
            result = subprocess.run(
                ["bash", "-c", "set -euo pipefail\numask 077\n" + fixture
                 + "\nprintf '%s\\n' \"$run_dir\""],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            run_dir = Path(result.stdout.strip())
            bind = run_dir / "socket/native-bind"
            self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((run_dir / "socket").stat().st_mode), 0o777)
            self.assertEqual(stat.S_IMODE(bind.stat().st_mode), 0o777)
            self.assertEqual(stat.S_IMODE((bind / "canary").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((bind / "index.html").stat().st_mode), 0o644)

    def test_runtime_package_versions_are_allowlisted(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        version_reader = "native_package_version() {" + source.split(
            "native_package_version() {", 1
        )[1].split("\necho \"DOCKERLENS_NATIVE_ENV:", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            self._tool(
                Path(temporary),
                "fake_package_query",
                "#!/bin/sh\ncase \"$*\" in *runc) printf '1.1.5+ds1-1+deb11u2' ;; "
                "*containerd) printf 'protected-secret value' ;; *) exit 1 ;; esac\n",
            )
            env = os.environ.copy()
            env["PATH"] = f"{temporary}:{env['PATH']}"
            result = subprocess.run(
                ["bash", "-c", "podman_cmd=(fake_package_query)\ncontainer=fake\n"
                 + version_reader
                 + "\nprintf '%s|%s|%s' "
                 "\"$(native_package_version runc)\" "
                 "\"$(native_package_version containerd)\" "
                 "\"$(native_package_version libseccomp2)\""],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "1.1.5+ds1-1+deb11u2|unavailable|unavailable")
            self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_probe_error_categories_never_echo_private_details(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        classifier = "classify_probe_error() {" + source.split(
            "classify_probe_error() {", 1
        )[1].split("\nexport -f classify_probe_error", 1)[0]
        cases = {
            "read init-p: connection reset by peer protected-secret": "init_pipe_eof",
            "state.json: no such file protected-secret": "runtime_state_missing",
            "invalid argument protected-secret": "invalid_argument",
            "failed to mount protected-secret": "mount",
            "cgroup protected-secret": "cgroup",
            "operation not permitted protected-secret": "permission",
            "OCI runtime create failed protected-secret": "oci",
            "protected-secret": "unclassified",
        }
        for detail, category in cases.items():
            with self.subTest(category=category):
                result = subprocess.run(
                    ["bash", "-c", classifier + "\nclassify_probe_error"],
                    input=detail,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), category)
                self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_both_inert_probe_modes_report_and_remove_exact_owned_containers(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        probe = "classify_probe_error() {" + source.split(
            "classify_probe_error() {", 1
        )[1].split("\nnetwork_id=", 1)[0]
        fake_docker = """#!/usr/bin/env bash
set -euo pipefail
state=$FAKE_PROBE_STATE
[[ $1 == container ]]
action=$2
shift 2
case $action in
  create)
    [[ $* == *'--entrypoint /bin/sh'* ]]
    [[ $* == *'-c exit 0'* ]]
    [[ $* == *'example.invalid/pinned:1@sha256:1234'* ]]
    if [[ $* == *'--network none'* ]]; then mode=none; else
      [[ $* == *'--network bridge'* ]]; mode=bridge
    fi
    touch "$state/$mode"
    printf '%s\\n' "$mode" >> "$state/created"
    if [[ $mode == "$FAKE_PROBE_CREATE_FAIL" ]]; then
      echo 'invalid argument protected-secret' >&2
      exit 42
    fi
    echo synthetic-id ;;
  start)
    mode=${1##*-}
    if [[ $mode == "$FAKE_PROBE_START_FAIL" ]]; then
      echo 'OCI runtime create failed: protected-secret' >&2
      exit 42
    fi
    echo synthetic-id ;;
  wait) echo 0 ;;
  inspect)
    mode=${*: -1}; mode=${mode##*-}
    [[ -f $state/$mode ]] || exit 1
    if [[ $* == *Config.Labels* ]]; then
      if [[ $mode == "$FAKE_PROBE_FOREIGN_LABEL" ]]; then echo foreign;
      else echo synthetic; fi
    elif [[ $* == *State.Error* ]]; then
      touch "$state/error_inspected-$mode"
      if [[ $mode == "$FAKE_PROBE_START_FAIL" ]]; then
        echo 'read init-p: connection reset by peer protected-secret'
      else echo; fi
    else echo 'exited|0'; fi ;;
  rm)
    mode=${*: -1}; mode=${mode##*-}
    [[ $mode != "$FAKE_PROBE_REMOVE_FAIL" ]] || exit 1
    rm "$state/$mode" ;;
  ls)
    if [[ $* == *probe-none* && -f $state/none ]]; then echo 'dl-synthetic-probe-none'; fi
    if [[ $* == *probe-bridge* && -f $state/bridge ]]; then echo 'dl-synthetic-probe-bridge'; fi ;;
  *) exit 2 ;;
esac
"""
        cases = (
            ("none", "", "", ""),
            ("", "bridge", "", ""),
            ("", "", "none", ""),
            ("", "", "", "bridge"),
        )
        for start_fail, remove_fail, create_fail, foreign_label in cases:
            with self.subTest(start_fail=start_fail, remove_fail=remove_fail,
                              create_fail=create_fail, foreign_label=foreign_label):
                with tempfile.TemporaryDirectory() as temporary:
                    state = Path(temporary)
                    self._tool(state, "fake_docker", fake_docker)
                    env = os.environ.copy()
                    env.update(
                        PATH=f"{state}:{env['PATH']}",
                        FAKE_PROBE_STATE=str(state),
                        FAKE_PROBE_START_FAIL=start_fail,
                        FAKE_PROBE_REMOVE_FAIL=remove_fail,
                        FAKE_PROBE_CREATE_FAIL=create_fail,
                        FAKE_PROBE_FOREIGN_LABEL=foreign_label,
                    )
                    result = subprocess.run(
                        ["bash", "-c", "set -euo pipefail\nrun_id=synthetic\n"
                         "FIXTURE_IMAGE=example.invalid/pinned:1@sha256:1234\n"
                         "inner_docker=(fake_docker)\n" + probe],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual((state / "created").read_text().splitlines(),
                                     ["none", "bridge"])
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)
                    if start_fail:
                        self.assertIn("none_start_init_pipe_eof", result.stderr)
                        self.assertIn("none_state_error_init_pipe_eof", result.stderr)
                        self.assertIn("bridge_start_ok", result.stderr)
                        self.assertFalse((state / "none").exists())
                        self.assertFalse((state / "bridge").exists())
                    elif create_fail:
                        self.assertIn("none_start_create_invalid_argument", result.stderr)
                        self.assertIn("bridge_start_ok", result.stderr)
                        self.assertFalse((state / "none").exists())
                        self.assertFalse((state / "bridge").exists())
                    elif remove_fail:
                        self.assertIn("bridge_cleanup_unverified", result.stderr)
                        self.assertFalse((state / "none").exists())
                        self.assertTrue((state / "bridge").exists())
                    else:
                        self.assertIn("bridge_cleanup_unverified", result.stderr)
                        self.assertFalse((state / "none").exists())
                        self.assertTrue((state / "bridge").exists())
                        self.assertFalse((state / "error_inspected-bridge").exists())

    def test_owned_resources_are_cleaned_after_early_failures(self) -> None:
        fake_podman = """#!/usr/bin/env bash
set -eu
state=$FAKE_NATIVE_STATE
command=$1; shift
case "$command" in
  info)
    case "$*" in
      *Rootless*) echo false ;;
      *GraphRoot*) echo "$state" ;;
      *) exit 3 ;;
    esac ;;
 container)
 if [[ $1 == exists && $FAKE_NATIVE_FAULT == container_query_error && -e $state/ran ]]; then exit 125; fi
 if [[ $1 != exists ]]; then exit 4; fi
 case $2 in
 dl-native-egress-*) [[ $FAKE_NATIVE_FAULT == sidecar_query_error && -e $state/sidecar ]] && exit 125
 [[ -e $state/sidecar ]] ;;
 *) [[ -e $state/container ]] ;;
 esac ;;
 network)
 action=$1; shift
 case $action in
 exists) [[ $FAKE_NATIVE_FAULT == network_query_error && -e $state/network ]] && exit 125
 [[ -e $state/network ]] ;;
 create) for name; do :; done
 printf '%s\n' "$name" > "$state/expected-network"
 touch "$state/network"
 [[ $FAKE_NATIVE_FAULT == network_create ]] && exit 42
 echo "$name" ;;
 inspect) for name; do :; done
 echo "$name" | sed 's/^dl-native-net-//'
 [[ $FAKE_NATIVE_FAULT == network_inspect_partial ]] && exit 42
 exit 0 ;;
 rm) for name; do :; done
 read -r expected < "$state/expected-network"
 [[ $name == "$expected" ]] || exit 66
 touch "$state/network_removal_attempted"
 [[ $FAKE_NATIVE_FAULT == network_remains ]] || rm -f "$state/network" ;;
 *) exit 4 ;;
 esac ;;
  volume)
    action=$1; shift
    case "$action" in
      exists)
        if [[ $FAKE_NATIVE_FAULT == volume_query_error && -e $state/ran ]]; then exit 125; fi
        [[ -e $state/volume ]] ;;
      create)
        for name; do :; done
        printf '%s\n' "$name" > "$state/expected-volume"
        touch "$state/volume"
        [[ $FAKE_NATIVE_FAULT == volume ]] && exit 42
        echo "$state/volume" ;;
      inspect)
        if [[ $* == *Labels* ]]; then
          for name; do :; done
          echo "$name" | sed 's/^dl-native-data-//'
          [[ $FAKE_NATIVE_FAULT == volume_inspect_partial ]] && exit 42
          true
        else echo "$state"; fi ;;
      rm)
        for name; do :; done
        read -r expected < "$state/expected-volume"
        [[ $name == "$expected" ]] || exit 66
        touch "$state/volume_removal_attempted"
        [[ $FAKE_NATIVE_FAULT == volume_remains ]] || rm -f "$state/volume" ;;
      *) exit 4 ;;
    esac ;;
  pull) [[ $FAKE_NATIVE_FAULT != pull ]] ;;
 run)
 prior=
 for item in "$@"; do
 if [[ $prior == --name ]]; then name=$item; fi
 prior=$item
 done
 if [[ $name == dl-native-egress-* ]]; then
   printf '%s\n' "$*" > "$state/sidecar-run-args"
   touch "$state/sidecar"
   if [[ $FAKE_NATIVE_FAULT == sidecar_start || $FAKE_NATIVE_FAULT == sidecar_start_classifier_failure ]]; then
     echo 'sh: syntax error private-canary' >&2
     exit 42
   fi
   if [[ $FAKE_NATIVE_FAULT == cancel_after_sidecar ]]; then sleep 2; fi
 else
   printf '%s\n' "$*" > "$state/run-args"
   printf '%s\n' "$name" > "$state/expected-container"
   touch "$state/ran" "$state/container"
   [[ $FAKE_NATIVE_FAULT == run ]] && exit 42
 fi
 exit 0 ;;
 logs)
 if [[ $FAKE_NATIVE_FAULT == sidecar_exited_empty_ip ]]; then
   echo 'sh: httpd: not found private-canary' >&2
 elif [[ $FAKE_NATIVE_FAULT == sidecar_state_error_field ]]; then
   :
 else
   echo 'private-canary' >&2
 fi ;;
 inspect)
 if [[ $* == *Labels* ]]; then
 for name; do :; done
 if [[ $name == dl-native-egress-* && $FAKE_NATIVE_FAULT == sidecar_inspect_hang ]]; then sleep 30; fi
 echo "$name" | sed -e 's/^dl-native-egress-//' -e 's/^dl-native-//'
 if [[ $name == dl-native-egress-* && $FAKE_NATIVE_FAULT == sidecar_inspect_partial ]]; then exit 42; fi
 if [[ $name == dl-native-* && $name != dl-native-egress-* && $FAKE_NATIVE_FAULT == container_inspect_partial ]]; then exit 42; fi
 elif [[ $* == *NetworkSettings.Networks* ]]; then
 for name; do :; done
 read -r network_name < "$state/expected-network"
 if [[ $name == dl-native-egress-* ]]; then ip=10.88.0.2; else ip=10.88.0.3; fi
 if [[ $name == dl-native-egress-* && $FAKE_NATIVE_FAULT == sidecar_running_empty_ip ]]; then ip=; fi
 if [[ $name == dl-native-egress-* && $FAKE_NATIVE_FAULT == sidecar_exited_empty_ip ]]; then ip=; fi
 printf '{"%s":{"IPAddress":"%s"}}\n' "$network_name" "$ip"
 elif [[ $* == *State.Running* ]]; then
 if [[ $FAKE_NATIVE_FAULT == sidecar_state_unavailable ]]; then exit 42; fi
 if [[ $FAKE_NATIVE_FAULT == sidecar_exited_empty_ip || $FAKE_NATIVE_FAULT == sidecar_state_error_field ]]; then
   echo 'false|exited|127'
 else
   echo 'true|running|0'
 fi
 elif [[ $* == *State.Error* ]]; then
 if [[ $FAKE_NATIVE_FAULT == sidecar_state_error_field ]]; then
   echo 'bind: address already in use private-canary'
 fi
 elif [[ $* == *HostConfig.Privileged* ]]; then echo true
    elif [[ $* == *'.Mounts'* ]]; then echo unexpected:/var/lib/docker
 else exit 4; fi ;;
 exec)
 touch "$state/health-attempted"
 if [[ $FAKE_NATIVE_FAULT == sidecar_health_dead ]]; then exit 42; fi
 if [[ $FAKE_NATIVE_FAULT == sidecar_health_race && ! -e $state/health-first ]]; then
   touch "$state/health-first"; exit 42
 fi
 echo proof-egress ;;
 rm)
 for name; do :; done
 if [[ $name == dl-native-egress-* ]]; then
   touch "$state/sidecar_removal_attempted"
   [[ $FAKE_NATIVE_FAULT == sidecar_remains ]] || rm -f "$state/sidecar"
 else
   read -r expected < "$state/expected-container"
   [[ $name == "$expected" ]] || exit 66
   touch "$state/container_removal_attempted"
   [[ $FAKE_NATIVE_FAULT == container_remains ]] || rm -f "$state/container"
 fi ;;
  *) exit 4 ;;
esac
"""
        for lane, fault in (
            ("debian11-rootful", "volume"),
            ("debian11-rootful", "pull"),
            ("debian11-rootful", "network_create"),
            ("debian11-rootful", "sidecar_start"),
            ("debian11-rootful", "sidecar_start_classifier_failure"),
            ("debian11-rootful", "sidecar_health_dead"),
            ("debian11-rootful", "sidecar_health_race"),
            ("debian11-rootful", "sidecar_exited_empty_ip"),
            ("debian11-rootful", "sidecar_state_error_field"),
            ("debian11-rootful", "sidecar_running_empty_ip"),
            ("debian11-rootful", "sidecar_state_unavailable"),
            ("debian11-rootful", "cancel_after_sidecar"),
            ("debian11-rootful", "run"),
            ("debian11-rootless", "unexpected_mount"),
            ("upstream-rootful", "unexpected_mount"),
            ("upstream-rootless", "run"),
            ("debian11-rootful", "container_query_error"),
            ("debian11-rootless", "volume_query_error"),
            ("upstream-rootful", "container_remains"),
            ("upstream-rootless", "volume_remains"),
            ("upstream-rootful", "sidecar_remains"),
            ("upstream-rootless", "network_remains"),
            ("debian11-rootful", "sidecar_query_error"),
            ("debian11-rootless", "network_query_error"),
            ("debian11-rootful", "container_inspect_partial"),
            ("debian11-rootless", "sidecar_inspect_partial"),
            ("debian11-rootless", "sidecar_inspect_hang"),
            ("upstream-rootful", "network_inspect_partial"),
            ("upstream-rootless", "volume_inspect_partial"),
        ):
            with self.subTest(lane=lane, fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = root / "state"
                bin_dir = root / "bin"
                state.mkdir()
                (state / "foreign-resource").write_text("untouched")
                bin_dir.mkdir()
                self._tool(bin_dir, "sudo", "#!/bin/sh\n[ \"$1\" = -n ] && shift\nexec \"$@\"\n")
                self._tool(bin_dir, "df",
                           "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted\n'"
                           "\nprintf 'fake 100000000 1 100000000 1%% /tmp\n'\n")
                self._tool(bin_dir, "podman", fake_podman)
                # These cleanup fixtures do not test kernel preflight. Admit
                # that single helper in the fake PATH, leaving every other
                # Python helper on the real interpreter.
                self._tool(bin_dir, "python3", "#!/bin/sh\n"
                           "case \"$1\" in */native-bridge-prerequisite.py) "
                           "echo DOCKERLENS_NATIVE_HOST_NETWORK:bridge_filter=ready; exit 0;; esac\n"
                           "if [ \"${FAKE_NATIVE_FAULT:-}\" = sidecar_start_classifier_failure ] "
                           "&& [ \"$1\" = -c ]; then "
                           "echo private-canary; exit 87; fi\n"
                           f'exec "{sys.executable}" "$@"\n')
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}",
                           FAKE_NATIVE_STATE=str(state), FAKE_NATIVE_FAULT=fault)
                command = ["bash", str(ROOT / "scripts/native-conformance.sh"), lane]
                if fault == "cancel_after_sidecar":
                    process = subprocess.Popen(
                        command, env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True,
                    )
                    deadline = time.monotonic() + 5
                    while not (state / "sidecar").exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue((state / "sidecar").exists())
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=15)
                    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                else:
                    started = time.monotonic()
                    result = subprocess.run(
                        command, env=env, capture_output=True, text=True,
                        timeout=25 if fault == "sidecar_inspect_hang" else 15,
                        check=False,
                    )
                    if fault == "sidecar_inspect_hang":
                        self.assertLess(time.monotonic() - started, 18)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((state / "volume").exists(), fault in ("volume_remains", "volume_inspect_partial"))
                self.assertEqual((state / "container").exists(), fault in ("container_remains", "container_inspect_partial"))
                self.assertEqual((state / "sidecar").exists(), fault in ("sidecar_remains", "sidecar_inspect_partial", "sidecar_inspect_hang"))
                self.assertEqual((state / "network").exists(), fault in ("network_remains", "network_inspect_partial"))
                self.assertEqual((state / "foreign-resource").read_text(), "untouched")
                if fault in ("container_query_error", "container_remains"):
                    self.assertTrue((state / "container_removal_attempted").exists())
                if fault in ("volume_query_error", "volume_remains"):
                    self.assertTrue((state / "volume_removal_attempted").exists())
                if fault in ("sidecar_query_error", "sidecar_remains"):
                    self.assertTrue((state / "sidecar_removal_attempted").exists())
                if fault in ("network_query_error", "network_remains"):
                    self.assertTrue((state / "network_removal_attempted").exists())
                if fault == "container_query_error":
                    self.assertIn("could not verify whether owned container", result.stderr)
                if fault == "volume_query_error":
                    self.assertIn("could not verify whether owned volume", result.stderr)
                if fault == "container_remains":
                    self.assertIn("owned container cleanup readback failed", result.stderr)
                if fault == "volume_remains":
                    self.assertIn("owned volume cleanup readback failed", result.stderr)
                if fault == "sidecar_remains":
                    self.assertIn("owned sidecar cleanup readback failed", result.stderr)
                if fault == "sidecar_inspect_hang":
                    self.assertIn("refusing to remove sidecar", result.stderr)
                    self.assertFalse((state / "sidecar_removal_attempted").exists())
                    self.assertTrue((state / "network_removal_attempted").exists())
                    self.assertTrue((state / "volume_removal_attempted").exists())
                if fault == "network_remains":
                    self.assertIn("owned network cleanup readback failed", result.stderr)
                for role in ("container", "sidecar", "network", "volume"):
                    if fault == f"{role}_inspect_partial":
                        self.assertIn(f"refusing to remove {role}", result.stderr)
                        self.assertFalse((state / f"{role}_removal_attempted").exists())
                if fault == "sidecar_health_dead":
                    self.assertIn("DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=sidecar_health", result.stderr)
                if fault == "sidecar_health_race":
                    self.assertTrue((state / "health-first").exists())
                    self.assertNotIn("phase=sidecar_health", result.stderr)
                if fault == "sidecar_exited_empty_ip":
                    self.assertIn(
                        "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=sidecar_state category=exited exit=nonzero",
                        result.stderr,
                    )
                    self.assertNotIn("phase=attachment", result.stderr)
                    self.assertFalse((state / "health-attempted").exists())
                    self.assertIn("phase=sidecar_failure category=applet_missing", result.stderr)
                if fault == "sidecar_state_error_field":
                    self.assertIn("phase=sidecar_failure category=bind_error", result.stderr)
                    self.assertFalse((state / "health-attempted").exists())
                if fault == "sidecar_start":
                    self.assertIn("phase=sidecar_failure category=shell_error", result.stderr)
                if fault == "sidecar_start_classifier_failure":
                    self.assertIn("phase=sidecar_failure category=unknown", result.stderr)
                    self.assertIn("phase=sidecar_start", result.stderr)
                    self.assertFalse((state / "sidecar").exists())
                    self.assertTrue((state / "sidecar_removal_attempted").exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)
                if fault == "sidecar_running_empty_ip":
                    self.assertTrue((state / "health-attempted").exists())
                    self.assertIn(
                        "phase=attachment role=sidecar category=ipv4_missing",
                        result.stderr,
                    )
                if fault == "sidecar_state_unavailable":
                    self.assertIn(
                        "phase=sidecar_state category=inspect_failed exit=unavailable",
                        result.stderr,
                    )
                    self.assertFalse((state / "health-attempted").exists())
                if (state / "sidecar-run-args").exists():
                    sidecar_args = (state / "sidecar-run-args").read_text()
                    self.assertIn("--network dl-native-net-", sidecar_args)
                    self.assertIn("--cap-drop=all", sidecar_args)
                if (state / "run-args").exists():
                    args = (state / "run-args").read_text()
                    self.assertIn("--image-volume=ignore", args)
                    self.assertEqual("--security-opt apparmor=unconfined" in args,
                                     lane == "debian11-rootless")
                    self.assertEqual("--oom-score-adj=0" in args, lane == "debian11-rootless")
                    self.assertIn("/usr/local/bin/start-dockerd", args)
                    self.assertIn("--host=unix:///dockerlens-native/docker.sock", args)
                    self.assertIn(":/dockerlens-native", args)
                    expected_store = (
                        "/home/docker/.local/share/docker:U,suid,dev"
                        if lane == "debian11-rootless"
                        else "/home/docker/.local/share/docker:U"
                        if lane == "upstream-rootless"
                        else "/var/lib/docker:U"
                    )
                    self.assertIn(expected_store, args)
                    if fault == "unexpected_mount":
                        self.assertIn("unexpected image or data-root volumes", result.stderr)

    def test_published_image_and_fixture_contracts_are_static(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        self.assertIn("DEBIAN_DOCKER_PACKAGE='20.10.5+dfsg1-1+deb11u2'", source)
        self.assertIn('storage_mount="$volume:', source)
        self.assertIn('rootless ]]; then printf /home/docker/.local/share/docker', source)
        self.assertIn('--user 0:0 --workdir /tmp --hostname dockerlens-native', source)
        self.assertIn('--label io.dockerlens.fixture=synthetic', source)
        self.assertNotIn('/run/dockerlens', source)
        self.assertIn('curl -fs --max-time 5 --unix-socket "$socket" http://localhost/_ping', source)
        self.assertNotIn('apt-get', source)
        self.assertFalse((ROOT / "scripts/native-apt-install.sh").exists())
        self.assertFalse((ROOT / "scripts/native-debian-snapshot.sh").exists())

    def test_engine_release_match_has_exact_boundaries(self) -> None:
        source = (ROOT / "scripts/native-version.sh").read_text()
        for lane, expected, actual, should_pass in (
            ("upstream-rootful", "29.8.1", "29.8.1", True),
            ("upstream-rootless", "29.8.1", "29.8.10", False),
            ("upstream-rootful", "29.8.1", "29.8.1+dfsg1", False),
            ("debian11-rootful", "20.10.5", "20.10.5", True),
            ("debian11-rootless", "20.10.5", "20.10.5+dfsg1", True),
            ("debian11-rootful", "20.10.5", "20.10.50", False),
            ("debian11-rootful", "20.10.5", "20.10.5+unexpected", False),
        ):
            with self.subTest(lane=lane, actual=actual):
                result = subprocess.run(
                    ["bash", "-c", f'source "{ROOT}/scripts/native-version.sh"; '
                     'native_engine_release_matches "$1" "$2" "$3"',
                     "native-test", lane, expected, actual],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode == 0, should_pass)

    def test_only_one_ignored_test_counts_as_native_success(self) -> None:
        for mode, expected_success in (
            ("ignored", True),
            ("nonignored", False),
            ("zero", False),
            ("runfail", False),
            ("acquirefail", False),
            ("uidfail", False),
            ("phasefail", False),
            ("shapefail", False),
            ("volumefail", False),
            ("startfail", False),
            ("listfail", False),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                bin_dir = Path(directory)
                self._tool(
                    bin_dir,
                    "cargo",
                    """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  if [[ $FAKE_NATIVE_TEST_MODE == listfail ]]; then
    echo 'protected listing detail' >&2
    exit 23
  fi
  [[ $FAKE_NATIVE_TEST_MODE == nonignored ]] || echo 'live_check: test'
elif [[ $FAKE_NATIVE_TEST_MODE == zero ]]; then
  echo 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;'
elif [[ $FAKE_NATIVE_TEST_MODE == runfail ]]; then
  echo 'protected native secret and socket payload' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: capture_mounts' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: capture_protected_secret' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; trailing protected value'
  exit 7
elif [[ $FAKE_NATIVE_TEST_MODE == acquirefail ]]; then
  echo 'protected native response and secret' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: acquire_socket' >&2
  echo 'DOCKERLENS_NATIVE_ERROR: shape' >&2
  echo 'DOCKERLENS_NATIVE_ERROR: protected-secret' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 8
elif [[ $FAKE_NATIVE_TEST_MODE == uidfail ]]; then
  echo 'protected process details' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_uid_count' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_uid_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 9
elif [[ $FAKE_NATIVE_TEST_MODE == phasefail ]]; then
  echo 'protected network details' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_traffic_probe' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_traffic_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 10
elif [[ $FAKE_NATIVE_TEST_MODE == shapefail ]]; then
  echo 'protected native shape detail' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_shape_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 12
elif [[ $FAKE_NATIVE_TEST_MODE == volumefail ]]; then
  echo 'protected read-only volume detail' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_accessible' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_write_other' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_write_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 13
elif [[ $FAKE_NATIVE_TEST_MODE == startfail ]]; then
  echo 'protected daemon start detail' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_start_cgroup' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_start_private' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_start_reason_operation_not_permitted' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_start_reason_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 11
else
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""",
                )
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}", FAKE_NATIVE_TEST_MODE=mode)
                result = subprocess.run(
                    [str(ROOT / "scripts/run-exact-native-test.sh"), "fixture", "live_check"],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, expected_success)
                self.assertNotIn("protected", result.stdout + result.stderr)
                if mode == "runfail":
                    self.assertIn("fixture::live_check failed (exit 7)", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: capture_mounts", result.stderr)
                    self.assertNotIn("capture_protected_secret", result.stderr)
                    self.assertIn("test result: FAILED. 0 passed; 1 failed;", result.stderr)
                elif mode == "acquirefail":
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: acquire_socket", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_ERROR: shape", result.stderr)
                    self.assertNotIn("protected-secret", result.stderr)
                elif mode == "uidfail":
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: target_uid_count", result.stderr)
                    self.assertNotIn("target_uid_private", result.stderr)
                elif mode == "phasefail":
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: target_traffic_probe", result.stderr)
                    self.assertNotIn("target_traffic_private", result.stderr)
                elif mode == "shapefail":
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro", result.stderr)
                    self.assertNotIn("target_shape_private", result.stderr)
                elif mode == "volumefail":
                    self.assertIn(
                        "DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_write_other",
                        result.stderr,
                    )
                    self.assertNotIn("target_shape_volume_ro_write_private", result.stderr)
                elif mode == "startfail":
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: target_start_cgroup", result.stderr)
                    self.assertIn(
                        "DOCKERLENS_NATIVE_CHECK: target_start_reason_operation_not_permitted",
                        result.stderr,
                    )
                    self.assertNotIn("target_start_private", result.stderr)
                    self.assertNotIn("target_start_reason_private", result.stderr)
                elif mode == "listfail":
                    self.assertIn("fixture::live_check (exit 23)", result.stderr)

    def test_native_target_uses_private_library_test_by_exact_name(self) -> None:
        for listed, expected_success in ((0, False), (1, True), (2, False)):
            with self.subTest(listed=listed), tempfile.TemporaryDirectory() as directory:
                bin_dir = Path(directory)
                self._tool(
                    bin_dir,
                    "cargo",
                    """#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$FAKE_NATIVE_INVOCATIONS"
if [[ $* == *--list* ]]; then
  for ((i=0; i<FAKE_NATIVE_LISTED; i++)); do
    echo 'native_target_tests::live_target_render_matches_engine: test'
  done
else
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""",
                )
                invocation = bin_dir / "invocations"
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}",
                           FAKE_NATIVE_INVOCATIONS=str(invocation),
                           FAKE_NATIVE_LISTED=str(listed))
                result = subprocess.run(
                    [str(ROOT / "scripts/run-exact-native-test.sh"),
                     "native_target", "live_target_render_matches_engine"],
                    env=env, capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertEqual(result.returncode == 0, expected_success)
                calls = invocation.read_text().splitlines()
                self.assertEqual(len(calls), 2 if expected_success else 1)
                self.assertTrue(all("--lib" in call and "--test" not in call for call in calls))
                if expected_success:
                    self.assertIn(
                        "--ignored --exact native_target_tests::live_target_render_matches_engine",
                        calls[1],
                    )

        invalid = subprocess.run(
            [str(ROOT / "scripts/run-exact-native-test.sh"),
             "native-target", "live_target_render_matches_engine"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(invalid.returncode, 2)

    def test_native_volume_uses_private_library_test_by_exact_name(self) -> None:
        selected = "native_volume_tests::live_existing_volume_prerequisite_matches_engine"
        for listed, expected_success in ((0, False), (1, True), (2, False)):
            with self.subTest(listed=listed), tempfile.TemporaryDirectory() as directory:
                bin_dir = Path(directory)
                self._tool(
                    bin_dir,
                    "cargo",
                    """#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$FAKE_NATIVE_INVOCATIONS"
if [[ $* == *--list* ]]; then
  for ((i=0; i<FAKE_NATIVE_LISTED; i++)); do
    echo 'native_volume_tests::live_existing_volume_prerequisite_matches_engine: test'
  done
else
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""",
                )
                invocation = bin_dir / "invocations"
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}",
                           FAKE_NATIVE_INVOCATIONS=str(invocation),
                           FAKE_NATIVE_LISTED=str(listed))
                result = subprocess.run(
                    [str(ROOT / "scripts/run-exact-native-test.sh"), "native_volume",
                     "live_existing_volume_prerequisite_matches_engine"],
                    env=env, capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertEqual(result.returncode == 0, expected_success)
                calls = invocation.read_text().splitlines()
                self.assertEqual(len(calls), 2 if expected_success else 1)
                self.assertTrue(all("--lib" in call and "--test" not in call for call in calls))
                if expected_success:
                    self.assertIn(f"--ignored --exact {selected}", calls[1])

        invalid = subprocess.run(
            [str(ROOT / "scripts/run-exact-native-test.sh"), "native-volume",
             "live_existing_volume_prerequisite_matches_engine"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(invalid.returncode, 2)

    def test_native_volume_label_uses_private_library_test_by_exact_name(self) -> None:
        selected = "native_volume_label_tests::live_created_volume_labels_match_engine"
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$FAKE_NATIVE_INVOCATIONS"
if [[ $* == *--list* ]]; then
  echo 'native_volume_label_tests::live_created_volume_labels_match_engine: test'
else
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""")
            invocation = bin_dir / "invocations"
            env = os.environ.copy()
            env.update(PATH=f"{bin_dir}:{env['PATH']}", FAKE_NATIVE_INVOCATIONS=str(invocation))
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_volume_label",
                 "live_created_volume_labels_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = invocation.read_text().splitlines()
            self.assertEqual(len(calls), 2)
            self.assertTrue(all("--lib" in call and "--test" not in call for call in calls))
            self.assertIn(f"--ignored --exact {selected}", calls[1])

    @staticmethod
    def _tool(directory: Path, name: str, content: str) -> None:
        path = directory / name
        path.write_text(content)
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
