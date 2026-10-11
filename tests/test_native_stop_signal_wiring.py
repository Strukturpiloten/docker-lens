"""Sixteenth exact ignored invocation and fixed-only failure diagnostics."""
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELECTED = "native_health_metadata_tests::stop_signal::live_stop_signal_matches_engine"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILURE = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"


class StopSignalWiringTests(unittest.TestCase):
    def wrapper(self, output=SUCCESS, status=0, listing=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            cargo.write_text('#!/bin/sh\n'
                             'printf "%s\\n" "$*" >> "$CALLS"\n'
                             'case " $* " in *" --list "*) printf "%s\\n" "$LIST"; exit 0;; esac\n'
                             'test -n "$NATIVE_STOP_SIGNAL_DEADLINE_EPOCH" || exit 97\n'
                             'printf "%s\\n" "$OUTPUT"; exit "$STATUS"\n')
            cargo.chmod(0o700)
            calls = root / "calls"
            result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                                     "native_stop_signal", "live_stop_signal_matches_engine"],
                                    env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                                         "CALLS": str(calls), "LIST": f"{SELECTED}: test" if listing is None else listing,
                                         "OUTPUT": output, "STATUS": str(status)},
                                    capture_output=True, text=True, timeout=10, check=False)
            return result, calls.read_text().splitlines()

    def test_exact_one_ignored_test_is_mandatory(self):
        for case in ("pass", "zero", "two", "absent", "duplicate", "failed"):
            listing = {"absent": "", "duplicate": f"{SELECTED}: test\n{SELECTED}: test"}.get(case)
            output = SUCCESS.replace("1 passed", "0 passed" if case == "zero" else "2 passed") if case in ("zero", "two") else SUCCESS
            result, calls = self.wrapper(output, 101 if case == "failed" else 0, listing)
            self.assertEqual(result.returncode == 0, case == "pass")
            self.assertTrue(all("--lib" in call and "--test" not in call for call in calls))
            if len(calls) == 2:
                self.assertIn(f"--ignored --exact {SELECTED}", calls[-1])

    def test_causal_stage_and_first_location_survive_cleanup(self):
        for stage in ("context", "term", "int"):
            output = (f"DOCKERLENS_NATIVE_CHECK: stop_signal_{stage}\n"
                      f"DOCKERLENS_NATIVE_CHECK: stop_signal_{stage} PRIVATE_CANARY\n"
                      f"thread '{SELECTED}' (123) panicked at src/native_stop_signal_tests.rs:123:4:\nPRIVATE_CANARY\n"
                      "DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup\n"
                      f"thread '{SELECTED}' panicked at src/native_stop_signal_tests.rs:456:8:\n{FAILURE}")
            result, _ = self.wrapper(output, 101)
            self.assertIn(f"DOCKERLENS_NATIVE_CHECK: stop_signal_{stage}\n", result.stderr)
            self.assertIn("source=native_stop_signal_tests line=123 column=4", result.stderr)
            self.assertNotIn("line=456", result.stderr)
            self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)

    def test_canonical_harness_adds_one_proof_without_changing_emitter_protocol(self):
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        invocations = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', harness, re.M)
        self.assertEqual(len(invocations), 16)
        self.assertEqual(invocations[-1], ("native_stop_signal", "live_stop_signal_matches_engine"))
        self.assertIn('export NATIVE_STOP_SIGNAL_PROOF_PATH="$run_dir/stop-signal-v1.json"', harness)
        self.assertIn("export NATIVE_STOP_SIGNAL_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA", harness)
        self.assertNotIn('"$NATIVE_STOP_SIGNAL_PROOF_PATH"', harness.split('python3 "$script_dir/native-evidence.py"', 1)[1])
        source = (ROOT / "src/native_stop_signal_tests.rs").read_text()
        self.assertNotIn('"--signal"', source)
        self.assertIn("!run.image_attempted && run.derived_id.is_none()", source)


if __name__ == "__main__":
    unittest.main()
