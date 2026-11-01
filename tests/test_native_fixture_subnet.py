"""Capture-only fixture observation wiring and real sanitizer controls; no runtime."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/native_network_tests.rs").read_text()
SELECTED = "native_network_tests::live_internal_network_blocks_external_egress"
MARKER = "DOCKERLENS_NATIVE_FIXTURE_SUBNET_DIAG: sidecar_on_fixture_subnet="
STAGE = "DOCKERLENS_NATIVE_CHECK: network_internal_cli_control"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;"
PASSED = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
CANARY = "private-canary /private/socket 10.23.7.9 id=raw-native-id 10.23.7.0/24"


def function(name):
    match = re.search(r'\nfn ' + re.escape(name) + r'\(', SOURCE)
    if match is None:
        raise AssertionError("missing Rust function: " + name)
    start = match.start() + 1
    return SOURCE[start:SOURCE.index("\n}\n", start) + 2]


class FixtureSubnetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dockerlens-fixture-subnet-")
        self.addCleanup(temporary.cleanup)
        self.tools = Path(temporary.name)
        # Private PATH contains no Docker, Podman, curl, sudo or real cargo.
        for name in ("timeout", "grep", "sed", "tail", "date"):
            (self.tools / name).symlink_to("/usr/bin/" + name)

    def run_fixture(self, lines, *, status=101, summary=FAILED):
        cargo = self.tools / "cargo"
        cargo.write_text(
            f"#!{sys.executable}\nimport sys\n"
            f"if '--list' in sys.argv: print({SELECTED + ': test'!r})\n"
            f"else:\n print({chr(10).join([*lines, summary])!r})\n raise SystemExit({status})\n"
        )
        cargo.chmod(0o700)
        return subprocess.run(
            ["/bin/bash", str(ROOT / "scripts/run-exact-native-test.sh"),
             "native_network", "live_internal_network_blocks_external_egress"],
            env={"PATH": str(self.tools)}, capture_output=True, text=True, timeout=4,
        )

    def test_closed_fixture_values_preserve_failure_stage_cleanup_and_summary(self):
        for value in ("true", "false", "unknown reason=unavailable"):
            with self.subTest(value=value):
                old = [STAGE, "DOCKERLENS_NATIVE_WGET_DIAG: category=timeout",
                       "DOCKERLENS_NATIVE_CLEANUP: internal_proof=pass"]
                result = self.run_fixture([*old, MARKER + value, CANARY])
                self.assertEqual((result.returncode, result.stdout), (1, ""))
                for line in [*old, MARKER + value, FAILED]:
                    self.assertIn(line + "\n", result.stderr)
                self.assertIn("failed (exit 101)", result.stderr)
                for private in CANARY.split():
                    self.assertNotIn(private, result.stderr)
                self.assertNotIn("network_internal_control\n", result.stderr)

    def test_near_misses_cross_product_fields_and_private_values_never_pass(self):
        for line in (
            MARKER + "unknown", MARKER + "TRUE", MARKER + "null", MARKER + CANARY,
            MARKER + "unknown reason=budget_exhausted", MARKER + "unknown reason=timeout",
            MARKER + "true reason=unavailable", MARKER + "false reason=unavailable",
            MARKER + "true extra=private-canary", MARKER + "false\t", MARKER + "true\r",
            MARKER + "true\x1b[0m", MARKER + "true\x00private-canary", "prefix " + MARKER + "true",
            MARKER + "unknown\nreason=unavailable", MARKER + "unknown reason=\nunavailable",
            MARKER.replace("sidecar_on_fixture_subnet", "sidecar_on_internal_subnet") + "true",
            MARKER.replace("FIXTURE", "INTERNAL") + "true",
            MARKER + "true_suffix", MARKER + "unknown reason=unavailable private-canary",
        ):
            with self.subTest(line=line):
                result = self.run_fixture([STAGE, line])
                self.assertEqual((result.returncode, result.stdout), (1, ""))
                self.assertNotIn("SUBNET_DIAG:", result.stderr)
                self.assertNotIn("private-canary", result.stderr)
                self.assertIn(STAGE + "\n", result.stderr)
                self.assertIn(FAILED + "\n", result.stderr)

    def test_success_suppresses_observation_and_last_complete_line_is_retained(self):
        result = self.run_fixture([STAGE, MARKER + "true", CANARY], status=0, summary=PASSED)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(MARKER, result.stdout + result.stderr)
        self.assertNotIn("private-canary", result.stdout + result.stderr)
        result = self.run_fixture([MARKER + "true", MARKER + "false", MARKER + CANARY])
        self.assertEqual(result.stderr.count(MARKER), 1)
        self.assertIn(MARKER + "false\n", result.stderr)

    def test_only_capture_bytes_feed_collector_and_no_new_execution_or_deadline(self):
        collector = function("captured_fixture_membership")
        for required in ("capture.exchanges()", "UniqueDiagnosticJson(source)",
                         "UniqueDiagnosticJson(body)", "capture.network_name_fallbacks()",
                         "container.api_version()?", "network.api_version() != Some(api)",
                         "sidecar_on_subnet(address, &body)", "capture.selected_roots()",
                         "capture.selector()", "CaptureRoute::ExplicitUnixSocket"):
            self.assertIn(required, collector)
        for forbidden in ("Command", "acquire(", "proof_api(", "proof_inspect(", "required(",
                          "Instant", "SystemTime", "deadline", "NATIVE_API_VERSION", "eprintln!", "assert!"):
            self.assertNotIn(forbidden, collector)
        live = function("live_internal_network_blocks_external_egress")
        self.assertEqual(live.count("acquire("), 1)
        for bound in ("max_requests: 16", "max_selected_resources: 2", "max_expansions: 6",
                      "max_response_bytes: 8 * 1024 * 1024", "max_total_bytes: 16 * 1024 * 1024",
                      "max_elapsed: Duration::from_secs(30)"):
            self.assertIn(bound, live)
        self.assertIn('std::env::var("NATIVE_NETWORK_ID").ok().as_deref()', live)
        begin = live.index("resources.fixture_subnet = Some(")
        end = live.index("resources.fixture_subnet = None;", begin)
        context = live[begin:end]
        self.assertLess(live.index("assert_single_homed_running(&resources, &cli_control_client"), begin)
        self.assertIn("let cli_control_response = proof_cli_ok(", context)
        self.assertNotIn('"create"', context)
        self.assertNotIn('"start"', context)
        self.assertLess(end, live.index('"independent CLI ordinary bridge reaches task endpoint"'))
        self.assertLess(end, live.index('eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_control")'))
        self.assertEqual(SOURCE.count('"DOCKERLENS_NATIVE_FIXTURE_SUBNET_DIAG:'), 1)
        helper = function("failed_fixture_subnet")
        self.assertIn("!result.success", helper)
        self.assertIn("context.client.as_str()", helper)
        self.assertIn('format!("http://{}:18084/", context.address)', helper)


if __name__ == "__main__":
    unittest.main()
