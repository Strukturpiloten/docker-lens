"""Runner causality, ownership markers and private-suffix projection controls."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORK = "DOCKERLENS_NATIVE_ATTACHMENT_WORK: role=oracle stage=primary_unique_dns"
CLEANUP = "DOCKERLENS_NATIVE_ATTACHMENT_CLEANUP: origin=role role=oracle operation=ownership slot=server"
SECRET = "PRIVATE_ATTACHMENT_CANARY"


class NetworkAttachmentWiringTests(unittest.TestCase):
    def run_fake(self, lines, *, target="native_network_attachment",
                 name="live_network_attachments_match_engine", success=False, summary_ok=False):
        selected = f"{target}_tests::{name}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            summary = ("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;"
                       if success or summary_ok else
                       "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out;")
            cargo.write_text("#!/usr/bin/env bash\n"
                             f'if [[ " $* " == *" --list "* ]]; then echo "{selected}: test"; exit 0; fi\n'
                             + "".join(f"printf '%s\\n' {shlex.quote(line)}\n" for line in [*lines, summary])
                             + f"exit {0 if success else 101}\n")
            cargo.chmod(0o700)
            return subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"), target, name],
                                  env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"]},
                                  capture_output=True, text=True, timeout=10, check=False)

    def test_each_role_failure_survives_cleanup_without_native_output(self):
        for stage in ("context", "oracle", "rendered"):
            with self.subTest(stage=stage):
                result = self.run_fake([
                    f"DOCKERLENS_NATIVE_CHECK: network_attachment_{stage}",
                    f"DOCKERLENS_NATIVE_CHECK: network_attachment_{stage} {SECRET}",
                    "DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup",
                    "DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup_unverified",
                ])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: network_attachment_{stage}\n", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup_unverified\n", result.stderr)
                self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_specific_first_work_and_cleanup_survive_later_generic_markers(self):
        result = self.run_fake([
            "DOCKERLENS_NATIVE_CHECK: network_attachment_oracle", WORK, CLEANUP,
            "DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup",
            "DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup_unverified",
            "DOCKERLENS_NATIVE_CHECK: network_attachment_oracle",
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.count(WORK + "\n"), 1)
        self.assertEqual(result.stderr.count(CLEANUP + "\n"), 1)
        self.assertIn("test result: FAILED. 0 passed; 1 failed;", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_context_oracle_rendered_and_effect_boundaries_remain_distinct(self):
        for role, stage in (("context", "acquisition"), ("oracle", "primary_unique_dns"),
                            ("rendered", "secondary_shared_http"), ("rendered", "outer_readback")):
            marker = f"DOCKERLENS_NATIVE_ATTACHMENT_WORK: role={role} stage={stage}"
            with self.subTest(role=role, stage=stage):
                result = self.run_fake([marker])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(marker + "\n", result.stderr)
                self.assertNotIn("DOCKERLENS_NATIVE_ATTACHMENT_CLEANUP:", result.stderr)

    def test_cleanup_only_failures_never_fabricate_work_and_cover_all_caught_categories(self):
        for origin in ("role", "terminal", "drop"):
            for operation in ("outer_ownership", "inspect", "status", "ownership", "delete", "name_absence", "id_absence"):
                slot = "none" if operation == "outer_ownership" else "secondary_peer"
                marker = (f"DOCKERLENS_NATIVE_ATTACHMENT_CLEANUP: origin={origin} role=rendered "
                          f"operation={operation} slot={slot}")
                with self.subTest(origin=origin, operation=operation):
                    result = self.run_fake([
                        "DOCKERLENS_NATIVE_CHECK: network_attachment_rendered", marker,
                        "DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup_unverified",
                    ])
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(marker + "\n", result.stderr)
                    self.assertNotIn("DOCKERLENS_NATIVE_ATTACHMENT_WORK:", result.stderr)

    def test_malformed_duplicate_conflicting_or_private_records_invalidate_whole_family(self):
        bad_records = [
            WORK + " " + SECRET, " " + WORK, WORK.replace("oracle", SECRET),
            "\x1b[31m" + WORK, "\r" + WORK, "\x01" + WORK, SECRET + ": " + WORK,
            "\x1b[31m" + CLEANUP, "\r" + CLEANUP, "\x01" + CLEANUP,
            WORK.replace("primary_unique_dns", "deadline"), WORK.replace("role=oracle", "role=context"),
            WORK.replace("WORK:", "WORK_EXTRA:"), WORK.replace("WORK:", "UNKNOWN:"),
            WORK.replace("role=oracle stage=primary_unique_dns", "stage=primary_unique_dns role=oracle"),
            CLEANUP + " id=" + SECRET, CLEANUP.replace("origin=role", "origin=" + SECRET),
            CLEANUP.replace("operation=ownership", "operation=" + SECRET),
            CLEANUP.replace("slot=server", "slot=" + SECRET),
        ]
        extra_records = [[bad] for bad in bad_records] + [
            [WORK], [CLEANUP], [WORK.replace("oracle", "rendered")],
            [CLEANUP.replace("origin=role", "origin=drop")],
        ]
        for extra in extra_records:
            with self.subTest(extra=extra):
                result = self.run_fake([WORK, CLEANUP, *extra])
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("DOCKERLENS_NATIVE_ATTACHMENT_", result.stdout + result.stderr)
                self.assertNotIn(SECRET, result.stdout + result.stderr)
                self.assertIn("test result: FAILED.", result.stderr)

    def test_exact_test_only_and_unrelated_marker_compatibility(self):
        for target, name in (("native_network_attachment", "other_ignored_test"),
                             ("native_target", "live_standalone_target_matches_engine")):
            with self.subTest(target=target):
                result = self.run_fake([WORK, CLEANUP, "DOCKERLENS_NATIVE_CHECK: target_daemon_uid"],
                                       target=target, name=name)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("DOCKERLENS_NATIVE_ATTACHMENT_", result.stdout + result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: target_daemon_uid\n", result.stderr)

    def test_diagnostics_do_not_change_native_status_or_numeric_success_requirement(self):
        success = self.run_fake([WORK, CLEANUP], success=True)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertNotIn("DOCKERLENS_NATIVE_ATTACHMENT_", success.stdout + success.stderr)
        failed = self.run_fake([WORK + " " + SECRET], summary_ok=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertNotIn("DOCKERLENS_NATIVE_ATTACHMENT_", failed.stdout + failed.stderr)
        self.assertNotIn(SECRET, failed.stdout + failed.stderr)
        self.assertNotIn("required native test passed:", failed.stdout)

    def test_rust_latch_wiring_preserves_original_limits_and_cleanup_attempts(self):
        source = (ROOT / "src/native_network_attachment_tests.rs").read_text()
        self.assertIn("self.cleanup(CleanupOrigin::Drop)", source)
        self.assertIn("self.cleanup(CleanupOrigin::Role)", source)
        self.assertIn("run.cleanup(CleanupOrigin::Terminal)", source)
        self.assertLess(source.index("run.record_work_failure();"), source.index("let cleaned = run.cleanup("))
        self.assertIn("self.work_site = None;", source)
        for operation in ("Inspect", "Status", "Ownership", "Delete", "NameAbsence", "IdAbsence"):
            self.assertIn(f"self.cleanup_stage(origin, CleanupOperation::{operation}, Some(index))", source)
        self.assertIn("self.work_calls <= 200", source)
        self.assertIn("self.cleanup_calls <= 160", source)
        self.assertIn(".min(Duration::from_secs(180))", source)
        self.assertNotIn("set_hook", source)
        self.assertNotIn("downcast", source)

TEST = "live_network_attachments_match_engine"
SELECTED = f"native_network_attachment_tests::{TEST}"
SOURCE = "native_network_attachment_tests"
PANIC = f"DOCKERLENS_NATIVE_PANIC: source={SOURCE}"
FAILURE = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out;"
CLEANUP_MARKER = "DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup"


class NetworkAttachmentCausalSiteTests(unittest.TestCase):
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
                    CLEANUP_MARKER, CLEANUP_MARKER + "_unverified",
                    f"thread '{SELECTED}' panicked at src/{SOURCE}.rs:999:9:", FAILURE,
                ])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("failed (exit 101)", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: network_attachment_rendered\n", result.stderr)
                self.assertIn(CLEANUP_MARKER + "_unverified\n", result.stderr)
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
                    CLEANUP_MARKER, CLEANUP_MARKER + "_unverified", FAILURE,
                ])
                self.assert_unavailable(result)

    def test_cleanup_only_and_missing_metadata_are_unavailable(self):
        for cleanup in (CLEANUP_MARKER, CLEANUP_MARKER + "_unverified"):
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
            CLEANUP_MARKER, CLEANUP_MARKER + "_unverified", FAILURE,
        ])
        self.assertEqual(result.stderr.splitlines(), [
            f"required native test native_network_attachment::{TEST} failed (exit 101)",
            CLEANUP_MARKER + "_unverified",
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
                    CLEANUP_MARKER, CLEANUP_MARKER + "_unverified", FAILURE,
                ])
                self.assert_unavailable(result)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: network_attachment_{stage}\n", result.stderr)
                self.assertIn(CLEANUP_MARKER + "_unverified\n", result.stderr)

    def test_success_still_prints_only_the_required_test_confirmation(self):
        result = self.runner([
            f"thread '{SELECTED}' panicked at src/{SOURCE}.rs:321:7:", SECRET,
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;",
        ], status=0)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
