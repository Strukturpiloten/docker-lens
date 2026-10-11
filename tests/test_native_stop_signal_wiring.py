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
STAGES = ("create", "created", "start", "readiness", "running", "clock", "stop", "elapsed",
          "output", "inspect", "exit", "state", "causality")


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

    def test_closed_operation_stage_survives_missing_panic_location(self):
        for signal in ("term", "int"):
            for role in ("oracle", "rendered"):
                for stage in STAGES:
                    marker = f"DOCKERLENS_NATIVE_STOP_SIGNAL_STAGE: case={signal} role={role} stage={stage}"
                    output = (f"DOCKERLENS_NATIVE_CHECK: stop_signal_{signal}\n{marker}\n"
                              "thread '<unnamed>' panicked at private-worker.rs:123:4:\nPRIVATE_CANARY\n"
                              f"DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup\n{FAILURE}")
                    result, _ = self.wrapper(output, 101)
                    with self.subTest(signal=signal, role=role, stage=stage):
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(marker + "\n", result.stderr)
                        self.assertIn("source=native_stop_signal_tests location=unavailable", result.stderr)
                        self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)
                        self.assertNotIn("private-worker", result.stdout + result.stderr)

    def test_operation_stage_rejects_values_and_stops_at_first_cleanup(self):
        marker = "DOCKERLENS_NATIVE_STOP_SIGNAL_STAGE: case=int role=oracle stage=exit"
        for cleanup in ("cleanup", "cleanup_unverified"):
            output = (f"DOCKERLENS_NATIVE_CHECK: stop_signal_int\n{marker}\n"
                      f"{marker} PRIVATE_CANARY\n{marker}\rPRIVATE_CANARY\n"
                      "DOCKERLENS_NATIVE_STOP_SIGNAL_STAGE: case=PRIVATE_CANARY role=oracle stage=exit\n"
                      "DOCKERLENS_NATIVE_STOP_SIGNAL_STAGE: case=int role=PRIVATE_CANARY stage=exit\n"
                      "DOCKERLENS_NATIVE_STOP_SIGNAL_STAGE: case=int role=oracle stage=PRIVATE_CANARY\n"
                      f"DOCKERLENS_NATIVE_CHECK: stop_signal_{cleanup}\n"
                      "DOCKERLENS_NATIVE_STOP_SIGNAL_STAGE: case=term role=rendered stage=causality\n"
                      f"{FAILURE}")
            result, _ = self.wrapper(output, 101)
            self.assertIn(marker + "\n", result.stderr)
            self.assertEqual(result.stderr.count("DOCKERLENS_NATIVE_STOP_SIGNAL_STAGE:"), 1)
            self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)
            self.assertNotIn("stage=causality", result.stdout + result.stderr)

    def test_common_timeout_spelling_keeps_full_identity_and_effect_assertions(self):
        source = (ROOT / "src/native_stop_signal_tests.rs").read_text()
        self.assertIn('["stop".into(), "-t".into(), "3".into(), id.clone()]', source)
        self.assertNotIn('"--time".into()', source)
        self.assertIn('assert_eq!(output.as_slice(), format!("{id}\\n").as_bytes());', source)
        self.assertIn('assert_eq!(after["State"]["ExitCode"], SIGNALS[index / 2].1);', source)
        self.assertIn('stopped(&after, SIGNALS[index / 2].1)', source)
        self.assertIn('run.owned(&value, index, Some(id))', source)
        self.assertIn('elapsed < Duration::from_secs(5)', source)
        self.assertIn("trap 'exit 41' TERM; trap 'exit 42' INT;", source)
        self.assertEqual(set(re.findall(r'StopStage::\w+ => "(\w+)"', source)), set(STAGES))

    def test_completed_observations_allow_first_post_cleanup_location(self):
        for phase in ("observations_complete", "cleanup_verified", "borrowed_image", "outer_context", "publication"):
            for source in ("native_stop_signal_tests", "native_health_metadata_tests"):
                marker = f"DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: {phase}"
                output = ("DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: observations_complete\n"
                          "DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup\n"
                          + ("" if phase == "observations_complete" else marker + "\n")
                          + f"thread '{SELECTED}' (123) panicked at src/{source}.rs:123:4:\nPRIVATE_CANARY\n"
                          "DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: publication\n"
                          f"thread '{SELECTED}' panicked at src/native_stop_signal_tests.rs:456:8:\n{FAILURE}")
                result, _ = self.wrapper(output, 101)
                with self.subTest(phase=phase, source=source):
                    self.assertIn(marker + "\n", result.stderr)
                    self.assertEqual(result.stderr.count("DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE:"), 1)
                    self.assertIn(f"source={source} line=123 column=4", result.stderr)
                    self.assertNotIn("line=456", result.stderr)
                    self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)

    def test_pre_cleanup_failure_cannot_be_replaced_by_lifecycle_or_cleanup_panic(self):
        marker = "DOCKERLENS_NATIVE_STOP_SIGNAL_STAGE: case=int role=rendered stage=causality"
        for thread, source in ((SELECTED, "src/native_stop_signal_tests"),
                               (SELECTED, "src/native_health_metadata_tests"), ("<unnamed>", "private-worker")):
            for complete_before_panic in (False, True):
                output = (marker + "\n"
                          + ("DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: observations_complete\n" if complete_before_panic else "")
                          + f"thread '{thread}' panicked at {source}.rs:123:4:\nPRIVATE_CANARY\n"
                          f"thread '{SELECTED}' panicked at src/native_stop_signal_tests.rs:234:5:\n"
                          "DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: observations_complete\n"
                          "DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup\n"
                          "DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: outer_context\n"
                          f"thread '{SELECTED}' panicked at src/native_stop_signal_tests.rs:456:8:\n{FAILURE}")
                result, _ = self.wrapper(output, 101)
                with self.subTest(thread=thread, complete_before_panic=complete_before_panic):
                    expected = "line=123 column=4" if thread == SELECTED else "location=unavailable"
                    self.assertIn(expected, result.stderr)
                    self.assertIn(marker + "\n", result.stderr)
                    self.assertNotIn("line=234", result.stderr)
                    self.assertNotIn("line=456", result.stderr)
                    self.assertNotIn("DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE:", result.stderr)
                    self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)
                    self.assertNotIn("private-worker", result.stdout + result.stderr)

    def test_lifecycle_requires_exact_early_completion_and_closed_values(self):
        completion = "DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: observations_complete"
        cleanup = "DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup"
        for prefix in (cleanup, f"{cleanup}\n{completion}", f"{completion} PRIVATE_CANARY\n{cleanup}",
                       f"{completion}\rPRIVATE_CANARY\n{cleanup}", f"{completion}\n{cleanup} PRIVATE_CANARY"):
            output = (f"{prefix}\nDOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: outer_context\n"
                      f"thread '{SELECTED}' panicked at src/native_health_metadata_tests.rs:456:8:\n{FAILURE}")
            result, _ = self.wrapper(output, 101)
            with self.subTest(prefix=prefix):
                self.assertNotIn("DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE:", result.stderr)
                self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)
                # A malformed cleanup is not a boundary; existing pre-cleanup
                # exact-source extraction remains independent of lifecycle.
                if not prefix.endswith(cleanup + " PRIVATE_CANARY"):
                    self.assertIn("location=unavailable", result.stderr)
                    self.assertNotIn("line=456", result.stderr)
        output = (f"{completion}\n{cleanup}\nDOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: borrowed_image\n"
                  "DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: outer_context PRIVATE_CANARY\n"
                  "DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: outer_context\rPRIVATE_CANARY\n"
                  "DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: PRIVATE_CANARY\n"
                  f"thread '{SELECTED}' panicked at src/native_stop_signal_tests.rs:123:4:\n{FAILURE}")
        result, _ = self.wrapper(output, 101)
        self.assertIn("DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: borrowed_image\n", result.stderr)
        self.assertNotIn("outer_context", result.stderr)
        self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)

    def test_first_post_cleanup_unknown_panic_stays_unavailable(self):
        for panic in ("thread '<unnamed>' panicked at private-worker.rs:123:4:",
                      f"thread '{SELECTED}' panicked at src/private-worker.rs:123:4:",
                      f"thread '{SELECTED}' panicked at src/native_stop_signal_tests.rs:123:4: PRIVATE_CANARY"):
            output = ("DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: observations_complete\n"
                      "DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup\n"
                      "DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: outer_context\n"
                      f"{panic}\nPRIVATE_CANARY\nDOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: publication\n"
                      f"thread '{SELECTED}' panicked at src/native_stop_signal_tests.rs:456:8:\n{FAILURE}")
            result, _ = self.wrapper(output, 101)
            with self.subTest(panic=panic):
                self.assertIn("DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: outer_context\n", result.stderr)
                self.assertIn("location=unavailable", result.stderr)
                self.assertNotIn("line=456", result.stderr)
                self.assertNotIn("publication", result.stderr)
                self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)
                self.assertNotIn("private-worker", result.stdout + result.stderr)

    def test_final_attestations_use_ordinary_work_and_preserve_shared_reserves(self):
        source = (ROOT / "src/native_stop_signal_tests.rs").read_text()
        final = source.split('assert!(clean, "verified stop fixture cleanup");', 1)[1]
        self.assertIn("assert_eq!(image_snapshot(&run, false), base);", final)
        self.assertIn("assert_eq!(outer_context(&run, false), outer);", final)
        self.assertNotIn("image_snapshot(&run, true)", source)
        self.assertNotIn("outer_context(&run, true)", source)
        self.assertIn("fn final_attestation_stream_requires_ordinary_work_without_spending_cleanup_reserve()", source)
        self.assertIn("9 * 1024", source)
        self.assertRegex(source, r'if result\.is_ok\(\) \{\s+eprintln!\("DOCKERLENS_NATIVE_STOP_SIGNAL_LIFECYCLE: observations_complete"\);\s+\}')
        shared = (ROOT / "src/native_health_metadata_tests.rs").read_text()
        self.assertIn("stream(stdout, if cleanup { 8192 } else { 65550 })", shared)
        self.assertIn("stream(stderr, if cleanup { 2048 } else { 8192 })", shared)
        self.assertIn("const CLEANUP_CALLS: usize = 100;", shared)
        self.assertIn("const CLEANUP_BYTES: usize = 2 * 1024 * 1024;", shared)


if __name__ == "__main__":
    unittest.main()
