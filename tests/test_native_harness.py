"""Fault injection for exact resource cleanup and ignored native test selection."""

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeHarnessTests(unittest.TestCase):
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

    def test_container_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = '"$(dirname "$0")/run-exact-native-test.sh" native_container live_container_settings_match_engine'
        network = '"$(dirname "$0")/run-exact-native-test.sh" native_network live_network_render_matches_engine'
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertLess(source.index(network), source.index(selected))
        self.assertLess(source.index(selected), source.index(manifest))
        self.assertIn('export NATIVE_CONTAINER_PROBES_PATH="$run_dir/container-probes.json"', source)
        self.assertIn('"$NATIVE_CONTAINER_PROBES_PATH"', source)

    def test_container_failure_marker_is_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'protected native response' >&2
  echo "DOCKERLENS_NATIVE_CHECK: container_$TEST_MARKER" >&2
  echo 'DOCKERLENS_NATIVE_CHECK: container_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for marker in (
                "ports", "ports_ipv6", "identity_health", "health_disabled", "clear",
                "start_interval", "storage_lifecycle", "resources_security",
                "resolver_logging",
            ):
                with self.subTest(marker=marker):
                    env["TEST_MARKER"] = marker
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                         "live_container_settings_match_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"DOCKERLENS_NATIVE_CHECK: container_{marker}", result.stderr)
                    self.assertNotIn("private", result.stdout + result.stderr)

    def test_port_failure_stage_and_categories_never_expose_native_details(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text(encoding="utf-8")
        for suffix in (
            "port-oracle", "port-rendered", "ipv6-oracle", "ipv6-rendered",
            "ipv6-dynamic-oracle", "ipv6-dynamic-rendered",
            "multi-dynamic-oracle", "multi-dynamic-rendered",
        ):
            self.assertIn(f'"{suffix}" =>', source)
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'protected-secret native response' >&2
  echo "DOCKERLENS_NATIVE_CHECK: container_port_$TEST_PORT_STAGE" >&2
  echo 'DOCKERLENS_NATIVE_CHECK: container_port_fixed_ipv6_rendered_protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_CLI_DIAG: exit=other stderr=address_family' >&2
  echo 'DOCKERLENS_NATIVE_CLI_DIAG: exit=other stderr=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_API_DIAG: status=conflict' >&2
  echo 'DOCKERLENS_NATIVE_API_DIAG: status=protected-secret' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for stage in (
                "fixed_ipv4_oracle_cli_inspect", "fixed_ipv6_rendered_cli_http",
                "dynamic_ipv6_oracle_dynamic_binding",
                "repeated_dynamic_ipv4_rendered_cli_http_secondary",
                "fixed_ipv4_rendered_udp_assert",
            ):
                with self.subTest(stage=stage):
                    env["TEST_PORT_STAGE"] = stage
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                         "live_container_settings_match_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"container_port_{stage}", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_CLI_DIAG: exit=other stderr=address_family", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_API_DIAG: status=conflict", result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_ipv6_probe_name_and_repeated_ipv4_oracle_are_live_and_bounded(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text(encoding="utf-8")
        self.assertIn("byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'", source)
        self.assertIn('assert!(valid_container_suffix("ipv6-oracle"));', source)
        oracle_start = source.index('mark_port_stage("port-oracle", "oracle_start");')
        oracle_primary = source.index('assert_fixed_ipv4_http(run, &oracle_id, "port-oracle", false);')
        oracle_secondary = source.index('assert_fixed_ipv4_http(run, &oracle_id, "port-oracle", true);')
        oracle_cleanup = source.index('mark_port_stage("port-oracle", "oracle_cleanup");')
        rendered_start = source.index('mark_port_stage("port-rendered", "api_start");')
        self.assertLess(oracle_start, oracle_primary)
        self.assertLess(oracle_primary, oracle_secondary)
        self.assertLess(oracle_secondary, oracle_cleanup)
        self.assertLess(oracle_cleanup, rendered_start)
        self.assertIn('for attempt in 1 2 3 4 5;', source)
        self.assertIn('wget -qO- -T 2', source)
        self.assertIn('assert_fixed_ipv4_http(run, &id, "port-rendered", true);', source)

    def test_port_probes_use_outer_namespace_without_new_probe_containers(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text(encoding="utf-8")
        port_source = source.split("fn probe_ports(", 1)[1].split("fn probe_complementary_ports(", 1)[0]
        self.assertNotIn('"--network".into(),', port_source)
        self.assertIn('run.try_outer_http("http://127.0.0.2:18110/index.html")', port_source)
        self.assertIn('run.require_outer_curl();', port_source)
        self.assertIn('run.require_outer_bash();', port_source)
        self.assertRegex(port_source, r'"bash",\s*"-c",\s*"printf')
        self.assertRegex(port_source, r'"udp-probe",\s*"native-udp-canary",\s*&assigned')
        self.assertIn('let assigned: u16 = assigned.parse()', port_source)
        self.assertIn('assert!(assigned > 0);', port_source)
        self.assertRegex(source, r'"--noproxy",\s*"\*",\s*"--proxy",\s*""')
        self.assertRegex(source, r'"--connect-timeout",\s*"2",\s*"--max-time",\s*"3"')

    def test_container_http_and_health_diagnostics_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'DOCKERLENS_NATIVE_CHECK: container_health_disabled_rendered_wait'
  echo 'DOCKERLENS_NATIVE_CHECK: container_health_disabled_private'
  echo 'DOCKERLENS_NATIVE_HTTP_DIAG: exit=other category=connection_refused'
  echo 'DOCKERLENS_NATIVE_HTTP_DIAG: exit=other category=private'
  echo 'DOCKERLENS_NATIVE_IPV6_DIAG: local_service=fail'
  echo 'DOCKERLENS_NATIVE_IPV6_DIAG: local_service=private'
  echo 'private native response' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("container_health_disabled_rendered_wait", result.stderr)
            self.assertIn("exit=other category=connection_refused", result.stderr)
            self.assertIn("local_service=fail", result.stderr)
            self.assertNotIn("private", result.stdout + result.stderr)

    def test_native_test_output_limit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  if [[ $TEST_PHASE == list ]]; then
    head -c 300000 /dev/zero
  else
    echo 'native_container_tests::live_container_settings_match_engine: test'
  fi
else
  head -c 300000 /dev/zero
fi
echo 'private-canary' >&2
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for phase in ("list", "run"):
                with self.subTest(phase=phase):
                    env["TEST_PHASE"] = phase
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                         "live_container_settings_match_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("output exceeded closed byte limit", result.stderr)
                    self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_native_test_output_limit_does_not_cap_build_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            artifact = bin_dir / "fake-build-artifact"
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  head -c 300000 /dev/zero > "$TEST_ARTIFACT_PATH"
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["TEST_ARTIFACT_PATH"] = str(artifact)
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(artifact.stat().st_size, 300000)

    def test_network_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = '"$(dirname "$0")/run-exact-native-test.sh" native_network live_network_render_matches_engine'
        target = '"$(dirname "$0")/run-exact-native-test.sh" native_target live_target_render_matches_engine'
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertLess(source.index(target), source.index(selected))
        self.assertLess(source.index(selected), source.index(manifest))
        self.assertIn('"$NATIVE_NETWORK_PROBES_PATH"', source)

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

    def test_storage_sampling_resamples_only_transient_descendant_loss(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        sampler = "sample_storage_kib() {" + source.split("sample_storage_kib() {", 1)[1].split(
            "\nmain_pid=$$", 1
        )[0]
        self.assertIn('ulimit -f 4; LC_ALL=C timeout --kill-after=1 10 "${du_cmd[@]}"', sampler)
        self.assertIn('timeout --kill-after=1 10 "${df_cmd[@]}" -Pk -- "$graph_root"', sampler)
        self.assertIn('timeout --kill-after=1 10 "${stat_cmd[@]}" -c', sampler)
        self.assertIn('stat_cmd=(sudo -n stat)', source)
        bash = """set -euo pipefail
volume_path=$TEST_VOLUME_PATH
run_dir=$TEST_RUN_DIR
graph_root=$run_dir
storage_root_identity='directory|1:1'
stat_cmd=(stat)
timeout() { shift 2; "$@"; }
sudo() { shift; "$@"; }
stat() {
  [[ -d $volume_path ]] || return 1
  if [[ $TEST_STORAGE_CASE == identity_change ]]; then printf 'directory|1:2'; else printf 'directory|1:1'; fi
}
df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\\nmock 9000000 0 8000000 0%% /\\n'; }
du() {
  mock_calls=$(<"$TEST_COUNT_FILE")
  mock_calls=$((mock_calls + 1))
  printf '%s' "$mock_calls" >"$TEST_COUNT_FILE"
  case $TEST_STORAGE_CASE in
    transient) if (( mock_calls == 1 )); then printf "du: cannot access '%s/vanished': No such file or directory\\n" "$volume_path" >&2; return 1; fi ;;
    unterminated) if (( mock_calls == 1 )); then printf "du: cannot access '%s/vanished': No such file or directory" "$volume_path" >&2; return 1; fi ;;
    persistent) printf "du: cannot access '%s/vanished': No such file or directory\\n" "$volume_path" >&2; return 1 ;;
    root_loss) rmdir "$volume_path"; printf "du: cannot access '%s': No such file or directory\\n" "$volume_path" >&2; return 1 ;;
    permission) printf "du: cannot read directory '%s/private': Permission denied\\n" "$volume_path" >&2; return 1 ;;
    stderr_overflow) head -c 100000 /dev/zero >&2; return 1 ;;
    timeout) return 124 ;;
    malformed) printf 'not-a-total\\t%s\\n' "$volume_path"; return 0 ;;
    large) printf '5000000\\t%s\\n' "$volume_path"; return 0 ;;
  esac
  printf '100\\t%s\\n' "$volume_path"
}
""" + sampler + """
if sample_storage_kib; then printf 'admitted:%s\\n' "$SAMPLED_STORAGE_KIB"; else printf 'rejected\\n'; fi
"""
        for case, admitted in (
            ("transient", True), ("unterminated", True), ("persistent", False),
            ("identity_change", False), ("root_loss", False),
            ("permission", False), ("stderr_overflow", False), ("timeout", False),
            ("malformed", False),
            ("large", False),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                volume = Path(directory) / "owned-volume"
                volume.mkdir()
                counter = Path(directory) / "du-calls"
                counter.write_text("0")
                env = os.environ.copy()
                env.update(TEST_VOLUME_PATH=str(volume), TEST_RUN_DIR=directory,
                           TEST_STORAGE_CASE=case, TEST_COUNT_FILE=str(counter))
                result = subprocess.run(
                    ["bash", "-c", bash], env=env, text=True,
                    capture_output=True, timeout=5, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "admitted:100" if admitted else "rejected")

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
            "# A random directory, container, and volume belong to exactly this lane.", 1
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
    [[ $1 == exists && -e $state/container ]] ;;
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
    printf '%s\n' "$*" > "$state/run-args"
    prior=
    for item in "$@"; do
      if [[ $prior == --name ]]; then printf '%s\n' "$item" > "$state/expected-container"; fi
      prior=$item
    done
    touch "$state/ran"
    touch "$state/container"
    [[ $FAKE_NATIVE_FAULT == unexpected_mount ]] ;;
  inspect)
    if [[ $* == *Labels* ]]; then
      for name; do :; done
      echo "$name" | sed 's/^dl-native-//'
    elif [[ $* == *HostConfig.Privileged* ]]; then echo true
    elif [[ $* == *'.Mounts'* ]]; then echo unexpected:/var/lib/docker
    else exit 4; fi ;;
  rm)
    for name; do :; done
    read -r expected < "$state/expected-container"
    [[ $name == "$expected" ]] || exit 66
    touch "$state/container_removal_attempted"
    [[ $FAKE_NATIVE_FAULT == container_remains ]] || rm -f "$state/container" ;;
  *) exit 4 ;;
esac
"""
        for lane, fault in (
            ("debian11-rootful", "volume"),
            ("debian11-rootful", "pull"),
            ("debian11-rootful", "run"),
            ("debian11-rootless", "unexpected_mount"),
            ("upstream-rootful", "unexpected_mount"),
            ("upstream-rootless", "run"),
            ("debian11-rootful", "container_query_error"),
            ("debian11-rootless", "volume_query_error"),
            ("upstream-rootful", "container_remains"),
            ("upstream-rootless", "volume_remains"),
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
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}",
                           FAKE_NATIVE_STATE=str(state), FAKE_NATIVE_FAULT=fault)
                result = subprocess.run(
                    ["bash", str(ROOT / "scripts/native-conformance.sh"), lane],
                    env=env, capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((state / "volume").exists(), fault == "volume_remains")
                self.assertEqual((state / "container").exists(), fault == "container_remains")
                self.assertEqual((state / "foreign-resource").read_text(), "untouched")
                if fault in ("container_query_error", "container_remains"):
                    self.assertTrue((state / "container_removal_attempted").exists())
                if fault in ("volume_query_error", "volume_remains"):
                    self.assertTrue((state / "volume_removal_attempted").exists())
                if fault == "container_query_error":
                    self.assertIn("could not verify whether owned container", result.stderr)
                if fault == "volume_query_error":
                    self.assertIn("could not verify whether owned volume", result.stderr)
                if fault == "container_remains":
                    self.assertIn("owned container cleanup readback failed", result.stderr)
                if fault == "volume_remains":
                    self.assertIn("owned volume cleanup readback failed", result.stderr)
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
