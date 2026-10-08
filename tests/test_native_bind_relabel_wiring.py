"""Fourteenth mandatory invocation and value-free failure-stage controls."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELECTED = "native_bind_relabel_tests::live_bind_relabel_configuration_matches_engine"
SECRET = "PRIVATE_BIND_PANIC_CANARY"
UNAVAILABLE = "DOCKERLENS_NATIVE_PANIC: source=native_bind_relabel_tests location=unavailable"
FAILURE = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out;"


class BindRelabelWiringTests(unittest.TestCase):
    def runner(self, output, status=101):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            cargo.write_text("#!/usr/bin/env bash\n"
                             'printf "%s\\n" "$*" >> "$FAKE_CALLS"\n'
                             f'if [[ " $* " == *" --list "* ]]; then echo "{SELECTED}: test"; exit 0; fi\n'
                             'printf "%s\\n" "$FAKE_OUTPUT"\n'
                             'exit "$FAKE_STATUS"\n')
            cargo.chmod(0o700)
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                 "native_bind_relabel", "live_bind_relabel_configuration_matches_engine"],
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                     "FAKE_CALLS": str(root / "calls"), "FAKE_OUTPUT": output, "FAKE_STATUS": str(status)},
                capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(len((root / "calls").read_text().splitlines()), 2)
            return result

    def test_first_causal_site_precedes_cleanup_and_later_aggregate_panic(self):
        for thread_id in ("", " (1234567890)"):
            with self.subTest(thread_id=thread_id):
                result = self.runner("\n".join([
                    "DOCKERLENS_NATIVE_CHECK: bind_relabel_rendered",
                    f"thread '{SELECTED}'{thread_id} panicked at src/native_bind_relabel_tests.rs:321:7:",
                    SECRET,
                    f"thread '{SELECTED}' panicked at src/native_bind_relabel_tests.rs:654:8:",
                    "DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup",
                    "DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup_unverified",
                    f"thread '{SELECTED}' panicked at src/native_bind_relabel_tests.rs:999:9:", FAILURE,
                ]))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("failed (exit 101)", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: bind_relabel_rendered\n", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup_unverified\n", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_PANIC: source=native_bind_relabel_tests line=321 column=7\n", result.stderr)
                for private in (SECRET, SELECTED + "'", "line=654", "line=999", UNAVAILABLE):
                    self.assertNotIn(private, result.stdout + result.stderr)

    def test_cleanup_only_panic_and_no_panic_have_constant_unavailable_location(self):
        for cleanup in ("cleanup", "cleanup_unverified"):
            result = self.runner("\n".join([
                f"DOCKERLENS_NATIVE_CHECK: bind_relabel_{cleanup}",
                f"thread '{SELECTED}' panicked at src/native_bind_relabel_tests.rs:999:9:",
                SECRET, FAILURE,
            ]))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(UNAVAILABLE + "\n", result.stderr)
            self.assertNotIn("line=999", result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
        result = self.runner(SECRET + "\n" + FAILURE)
        self.assertIn(UNAVAILABLE + "\n", result.stderr)

    def test_malformed_foreign_zero_and_overbound_sites_never_escape(self):
        headers = [
            f"thread '{SELECTED}' panicked at /private/{SECRET}/src/native_bind_relabel_tests.rs:12:4:",
            f"thread '{SELECTED}' panicked at src/native_network_tests.rs:12:4:",
            f"thread '{SECRET}' panicked at src/native_bind_relabel_tests.rs:12:4:",
            f"thread '{SELECTED}' (12345678901) panicked at src/native_bind_relabel_tests.rs:12:4:",
            f"thread '{SELECTED}' (private) panicked at src/native_bind_relabel_tests.rs:12:4:",
        ]
        for location in ("0:4", "12:0", "012:4", "12:04", "1234567:4", "12:12345", "word:4", "-1:4", "12:-1"):
            headers.append(f"thread '{SELECTED}' panicked at src/native_bind_relabel_tests.rs:{location}:")
        headers.append(f"thread '{SELECTED}' panicked at src/native_bind_relabel_tests.rs:12:4: {SECRET}")
        for header in headers:
            with self.subTest(header=header):
                result = self.runner("\n".join([header, SECRET,
                    "DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup", FAILURE]))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(UNAVAILABLE + "\n", result.stderr)
                self.assertNotIn("line=", result.stderr)
                self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_maximal_positive_site_is_bounded_and_success_output_is_unchanged(self):
        header = f"thread '{SELECTED}' (1) panicked at src/native_bind_relabel_tests.rs:999999:9999:"
        result = self.runner(header + "\n" + FAILURE)
        self.assertIn("DOCKERLENS_NATIVE_PANIC: source=native_bind_relabel_tests line=999999 column=9999\n", result.stderr)
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;"
        result = self.runner(header + "\n" + SECRET + "\n" + success, status=0)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "required native test passed: native_bind_relabel::live_bind_relabel_configuration_matches_engine\n")
        self.assertEqual(result.stderr, "")

    def test_every_role_failure_survives_cleanup_without_private_suffix(self):
        selected = "native_bind_relabel_tests::live_bind_relabel_configuration_matches_engine"
        for stage in ("context", "oracle", "rendered"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                cargo = root / "cargo"
                cargo.write_text("#!/usr/bin/env bash\n"
                                 f'if [[ " $* " == *" --list "* ]]; then echo "{selected}: test"; exit 0; fi\n'
                                 f'echo "DOCKERLENS_NATIVE_CHECK: bind_relabel_{stage}"\n'
                                 f'echo "DOCKERLENS_NATIVE_CHECK: bind_relabel_{stage} PRIVATE_BIND_CANARY"\n'
                                 'echo "DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup"\n'
                                 'echo "DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup_unverified"\n'
                                 'echo "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out;"\n'
                                 'exit 101\n')
                cargo.chmod(0o700)
                result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                                         "native_bind_relabel", "live_bind_relabel_configuration_matches_engine"],
                                        env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"]},
                                        capture_output=True, text=True, timeout=10, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: bind_relabel_{stage}\n", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup_unverified\n", result.stderr)
                self.assertNotIn("PRIVATE_BIND_CANARY", result.stdout + result.stderr)

    def test_mandatory_invocation_and_independent_uid_precede_emission(self):
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        command = '"$(dirname "$0")/run-exact-native-test.sh" native_bind_relabel live_bind_relabel_configuration_matches_engine'
        self.assertEqual(harness.count(command), 1)
        self.assertLess(harness.index(command), harness.index('python3 "$script_dir/native-evidence.py"'))
        self.assertLess(harness.index('"$script_dir/native-daemon-uid.py"'), harness.index(command))
        self.assertIn('export NATIVE_BIND_RELABEL_PROOF_PATH="$run_dir/bind-relabel-config-v1.json"', harness)
