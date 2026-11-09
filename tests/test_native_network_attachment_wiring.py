"""Authored runner controls for causal sites, cleanup and protected output."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEST = "live_network_attachments_match_engine"
SELECTED = f"native_network_attachment_tests::{TEST}"
SOURCE = "native_network_attachment_tests"
PANIC = f"DOCKERLENS_NATIVE_PANIC: source={SOURCE}"
FAILURE = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out;"
CLEANUP = "DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup"
SECRET = "PRIVATE_ATTACHMENT_CANARY"


class NetworkAttachmentWiringTests(unittest.TestCase):
    def runner(self, lines, status=101, test_name=TEST):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            cargo.write_text(
                "#!/usr/bin/env bash\n"
                'printf "%s\\n" "$*" >> "$FAKE_CALLS"\n'
                'if [[ " $* " == *" --list "* ]]; then printf "%s: test\\n" "$FAKE_SELECTED"; exit 0; fi\n'
                'printf "%s\\n" "$FAKE_OUTPUT"\n'
                'exit "$FAKE_STATUS"\n')
            cargo.chmod(0o700)
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                 "native_network_attachment", test_name],
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                     "FAKE_CALLS": str(root / "calls"), "FAKE_OUTPUT": "\n".join(lines),
                     "FAKE_STATUS": str(status),
                     "FAKE_SELECTED": f"native_network_attachment_tests::{test_name}"},
                capture_output=True, text=True, timeout=10, check=False)
            calls = (root / "calls").read_text().splitlines()
            self.assertEqual(len(calls), 2)
            self.assertIn("--ignored --list", calls[0])
            self.assertIn(f"--ignored --exact native_network_attachment_tests::{test_name}", calls[1])
            self.assertEqual(result.stdout, "" if status else
                             f"required native test passed: native_network_attachment::{test_name}\n")
            self.assertNotIn(SECRET, result.stdout + result.stderr)
            return result

    def assert_unavailable(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(PANIC + " location=unavailable\n", result.stderr)
        self.assertNotIn(" line=", result.stderr)

    def test_first_causal_site_survives_later_panics_and_cleanup(self):
        for thread_id, line, column in (("", "321", "7"), (" (1234567890)", "999999", "9999")):
            with self.subTest(thread_id=thread_id):
                result = self.runner([
                    "DOCKERLENS_NATIVE_CHECK: network_attachment_rendered",
                    f"thread '{SELECTED}'{thread_id} panicked at src/{SOURCE}.rs:{line}:{column}:",
                    f"assertion failed: left={SECRET} right=daemon-response",
                    f"thread '{SELECTED}' panicked at src/{SOURCE}.rs:654:8:",
                    CLEANUP, CLEANUP + "_unverified",
                    f"thread '{SELECTED}' panicked at src/{SOURCE}.rs:999:9:", FAILURE,
                ])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("failed (exit 101)", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: network_attachment_rendered\n", result.stderr)
                self.assertIn(CLEANUP + "_unverified\n", result.stderr)
                self.assertEqual([entry for entry in result.stderr.splitlines() if entry.startswith(PANIC)],
                                 [f"{PANIC} line={line} column={column}"])
                self.assertNotIn(SELECTED + "'", result.stderr)
                self.assertNotIn("daemon-response", result.stderr)

    def test_unverifiable_first_panic_never_becomes_later_selected_site(self):
        headers = [
            f"thread '{SECRET}' panicked at src/{SOURCE}.rs:12:4:",
            f"thread '{SELECTED}' panicked at /private/{SECRET}/src/{SOURCE}.rs:12:4:",
            f"thread '{SELECTED}' panicked at src/native_network_tests.rs:12:4:",
            f"thread '{SELECTED}' (12345678901) panicked at src/{SOURCE}.rs:12:4:",
            f"thread '{SELECTED}' (private) panicked at src/{SOURCE}.rs:12:4:",
            f" thread '{SELECTED}' panicked at src/{SOURCE}.rs:12:4:",
            f"thread '{SELECTED}' panicked at",
            f"thread '{SELECTED}' panicked at src/{SOURCE}.rs:12:4: {SECRET}",
        ]
        for location in ("0:4", "12:0", "012:4", "12:04", "1234567:4", "12:12345",
                         "word:4", "-1:4", "12:-1", "12:4:5"):
            headers.append(f"thread '{SELECTED}' panicked at src/{SOURCE}.rs:{location}:")
        for header in headers:
            with self.subTest(header=header):
                result = self.runner([
                    header, SECRET,
                    f"thread '{SELECTED}' panicked at src/{SOURCE}.rs:654:8:",
                    CLEANUP, CLEANUP + "_unverified", FAILURE,
                ])
                self.assert_unavailable(result)

    def test_cleanup_only_and_missing_metadata_are_unavailable(self):
        for cleanup in (CLEANUP, CLEANUP + "_unverified"):
            with self.subTest(cleanup=cleanup):
                result = self.runner([
                    cleanup, f"thread '{SELECTED}' panicked at src/{SOURCE}.rs:999:9:",
                    SECRET, FAILURE,
                ])
                self.assert_unavailable(result)
        self.assert_unavailable(self.runner([SECRET, FAILURE]))

    def test_different_selected_test_cannot_claim_attachment_site(self):
        result = self.runner([
            f"thread 'native_network_attachment_tests::other_test' panicked at src/{SOURCE}.rs:12:4:",
            FAILURE,
        ], test_name="other_test")
        self.assert_unavailable(result)

    def test_private_payload_and_marker_suffixes_never_escape(self):
        payloads = [f"{SECRET}:daemon-response", f"ENV={SECRET}",
                    f"unix:///private/{SECRET}/engine.sock", f"/store/{SECRET}"]
        result = self.runner([
            "DOCKERLENS_NATIVE_CHECK: network_attachment_rendered",
            f"thread '{SELECTED}' panicked at src/{SOURCE}.rs:321:7:",
            *payloads,
            f"DOCKERLENS_NATIVE_CHECK: network_attachment_oracle {SECRET}",
            CLEANUP, CLEANUP + "_unverified", FAILURE,
        ])
        self.assertEqual(result.stderr.splitlines(), [
            f"required native test native_network_attachment::{TEST} failed (exit 101)",
            CLEANUP + "_unverified",
            "DOCKERLENS_NATIVE_CHECK: network_attachment_rendered",
            PANIC + " line=321 column=7", FAILURE,
        ])
        for payload in payloads:
            self.assertNotIn(payload, result.stdout + result.stderr)

    def test_each_role_failure_survives_cleanup_without_native_output(self):
        for stage in ("context", "oracle", "rendered"):
            with self.subTest(stage=stage):
                result = self.runner([
                    f"DOCKERLENS_NATIVE_CHECK: network_attachment_{stage}",
                    f"DOCKERLENS_NATIVE_CHECK: network_attachment_{stage} {SECRET}",
                    CLEANUP, CLEANUP + "_unverified", FAILURE,
                ])
                self.assert_unavailable(result)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: network_attachment_{stage}\n", result.stderr)
                self.assertIn(CLEANUP + "_unverified\n", result.stderr)

    def test_success_still_prints_only_the_required_test_confirmation(self):
        result = self.runner([
            f"thread '{SELECTED}' panicked at src/{SOURCE}.rs:321:7:", SECRET,
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;",
        ], status=0)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
