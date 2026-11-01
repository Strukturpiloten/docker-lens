"""Runner causality and private-suffix projection controls."""

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
