"""Canonical fifteenth-test wiring and closed, value-free runner controls."""

import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_external_network"
TEST = "live_external_network_internal_matches_engine"
SELECTED = f"{TARGET}_tests::{TEST}"
SECRET = "PRIVATE_EXTERNAL_NETWORK_CANARY"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 130 filtered out;"
FAILURE = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 130 filtered out;"


class ExternalNetworkWiringTests(unittest.TestCase):
    def wrapper(self, output=SUCCESS, status=0, listing=None, list_status=0):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            cargo.write_text("#!/usr/bin/env bash\n"
                             'printf "%s\\n" "$*" >> "$FAKE_CALLS"\n'
                             'if [[ " $* " == *" --list "* ]]; then\n'
                             '  printf "%s\\n" "$FAKE_LIST"; exit "$FAKE_LIST_STATUS"\n'
                             'fi\n'
                             'printf "%s\\n" "$FAKE_OUTPUT"; exit "$FAKE_STATUS"\n')
            cargo.chmod(0o700)
            calls = root / "calls"
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, TEST],
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                     "FAKE_CALLS": str(calls), "FAKE_LIST": f"{SELECTED}: test" if listing is None else listing,
                     "FAKE_LIST_STATUS": str(list_status), "FAKE_OUTPUT": output, "FAKE_STATUS": str(status)},
                capture_output=True, text=True, timeout=10, check=False)
            return result, calls.read_text().splitlines()

    def test_exact_library_selection_and_exactly_one_success(self):
        for case in ("pass", "absent", "duplicate", "list_failed", "zero", "two", "nonzero"):
            with self.subTest(case=case):
                listing = {"absent": "", "duplicate": f"{SELECTED}: test\n{SELECTED}: test"}.get(case)
                output = SUCCESS.replace("1 passed", "0 passed" if case == "zero" else "2 passed") if case in ("zero", "two") else SUCCESS
                result, calls = self.wrapper(output, 101 if case == "nonzero" else 0,
                                             listing, 42 if case == "list_failed" else 0)
                self.assertEqual(result.returncode == 0, case == "pass")
                self.assertTrue(all("--lib" in call and "--test" not in call for call in calls))
                self.assertIn("--ignored --list", calls[0])
                if case in ("absent", "duplicate", "list_failed"):
                    self.assertEqual(len(calls), 1)
                else:
                    self.assertEqual(len(calls), 2)
                    self.assertIn(f"--ignored --exact {SELECTED}", calls[1])

    def test_six_exact_stage_markers_and_private_suffix_refusal(self):
        for stage in ("context", "oracle", "assessment", "cleanup", "cleanup_unverified", "evidence"):
            with self.subTest(stage=stage):
                marker = f"DOCKERLENS_NATIVE_CHECK: external_network_{stage}"
                result, _ = self.wrapper(f"{marker}\n{marker} {SECRET}\n{FAILURE}", 101)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(marker + "\n", result.stderr)
                self.assertNotIn(SECRET, result.stdout + result.stderr)
        invalid = [f"DOCKERLENS_NATIVE_CHECK: external_network_{stage} {SECRET}"
                   for stage in ("context", "oracle", "assessment", "cleanup", "cleanup_unverified", "evidence")]
        invalid += ["DOCKERLENS_NATIVE_CHECK: external_network_private",
                    "DOCKERLENS_NATIVE_CHECK: external_network_rendered"]
        result, _ = self.wrapper("\n".join(invalid + [FAILURE]), 101)
        self.assertNotIn("DOCKERLENS_NATIVE_CHECK:", result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_cleanup_cannot_mask_original_causal_stage(self):
        for stage in ("context", "oracle", "assessment"):
            with self.subTest(stage=stage):
                result, _ = self.wrapper("\n".join([
                    f"DOCKERLENS_NATIVE_CHECK: external_network_{stage}",
                    "DOCKERLENS_NATIVE_CHECK: external_network_cleanup",
                    "DOCKERLENS_NATIVE_CHECK: external_network_cleanup_unverified", FAILURE]), 101)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: external_network_{stage}\n", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: external_network_cleanup_unverified\n", result.stderr)

    def test_only_fixed_source_and_bounded_numeric_panic_location_escape(self):
        for thread in (f"'{SELECTED}'", f"'{SECRET}' (123)"):
            result, _ = self.wrapper(
                f"thread {thread} panicked at src/native_external_network_tests.rs:123:4:\n{SECRET}\n{FAILURE}", 101)
            self.assertIn("DOCKERLENS_NATIVE_PANIC: source=native_external_network_tests line=123 column=4\n", result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
        for site in (f"/private/{SECRET}/src/native_external_network_tests.rs:123:4:",
                     "src/native_network_tests.rs:123:4:",
                     "src/native_external_network_tests.rs:notnumeric:4:",
                     "src/native_external_network_tests.rs:1234567:4:",
                     "src/native_external_network_tests.rs:123:12345:",
                     f"src/native_external_network_tests.rs:123:4: {SECRET}"):
            with self.subTest(site=site):
                result, _ = self.wrapper(f"thread '{SELECTED}' panicked at {site}\n{SECRET}\n{FAILURE}", 101)
                self.assertNotIn("DOCKERLENS_NATIVE_PANIC:", result.stderr)
                self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_fixed_proof_and_verified_context_precede_last_invocation_and_emission(self):
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        invocations = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$',
                                 harness, re.MULTILINE)
        self.assertEqual(len(invocations), 16)
        self.assertEqual(invocations[-3:-1], [("native_bind_relabel", "live_bind_relabel_configuration_matches_engine"),
                                           (TARGET, TEST)])
        command = f'"$(dirname "$0")/run-exact-native-test.sh" {TARGET} {TEST}'
        self.assertEqual(harness.count(command), 1)
        for fact in ('export NATIVE_EXTERNAL_NETWORK_PROOF_PATH="$run_dir/external-network-internal-v1.json"',
                     "export NATIVE_EXTERNAL_NETWORK_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA",
                     '"$script_dir/native-daemon-uid.py"'):
            self.assertLess(harness.index(fact), harness.index(command))
        self.assertLess(harness.index(command), harness.index('python3 "$script_dir/native-evidence.py"'))

    def test_emitter_keeps_nineteen_positional_arguments_and_fixed_private_child(self):
        harness = (ROOT / "scripts/native-conformance.sh").read_text().replace("\\\n", "")
        emitter_line = next(line for line in harness.splitlines() if 'python3 "$script_dir/native-evidence.py"' in line)
        self.assertEqual(len(shlex.split(emitter_line)) - 2, 19)
        self.assertNotIn("NATIVE_EXTERNAL_NETWORK_PROOF_PATH", emitter_line)
        emitter = (ROOT / "scripts/native-evidence.py").read_text()
        self.assertIn("len(sys.argv) != 20", emitter)
        self.assertIn("capture_dir / EXTERNAL_NETWORK_FILENAME, capture_dir, external_context", emitter)
        self.assertIn('external_context = {**network_context, "daemon_uid": int(daemon_uid)}', emitter)


if __name__ == "__main__":
    unittest.main()
