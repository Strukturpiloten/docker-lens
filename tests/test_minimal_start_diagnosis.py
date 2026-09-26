"""Bounded, private diagnostics for the inert native Docker start probe."""

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SCRIPT = (ROOT / "scripts/native-conformance.sh").read_text()
START = NATIVE_SCRIPT.index("# Docker CLI errors may contain authored values.")
END = NATIVE_SCRIPT.index('network_id=$(timeout 30', START)
PROBE = NATIVE_SCRIPT[START:END]


class MinimalStartDiagnosisTests(unittest.TestCase):
    def run_probe(
        self,
        error: str,
        exit_code: int = 125,
        owner: str = "abc",
        *,
        open_writer: bool = False,
        inspect_fails: bool = False,
        short_deadline: bool = False,
    ):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            docker = fixture / "fake-docker"
            docker.write_text(
                """#!/bin/sh
if [ "$1" = run ]; then
  case " $* " in
    *" --network none --entrypoint /bin/sh synthetic-image -c exit 0 "*) ;;
    *) exit 3 ;;
  esac
  if [ "$FAKE_OPEN_WRITER" = 1 ]; then sleep 30 >&2 & fi
  printf '%s\\n' "$FAKE_ERROR" >&2
  exit "$FAKE_EXIT"
fi
if [ "$1" = container ] && [ "$2" = inspect ]; then
  if [ "$FAKE_INSPECT_FAIL" = 1 ]; then exit 1; fi
  printf '%s\\n' "$FAKE_OWNER"
  exit 0
fi
if [ "$1" = container ] && [ "$2" = rm ]; then
  : > "$FAKE_REMOVED"
  exit 0
fi
exit 7
"""
            )
            docker.chmod(0o755)
            removed = fixture / "removed"
            environment = os.environ.copy()
            environment.update(
                FAKE_DOCKER=str(docker),
                FAKE_ERROR=error,
                FAKE_EXIT=str(exit_code),
                FAKE_OWNER=owner,
                FAKE_REMOVED=str(removed),
                FAKE_OPEN_WRITER="1" if open_writer else "0",
                FAKE_INSPECT_FAIL="1" if inspect_fails else "0",
            )
            prelude = (
                'set -euo pipefail\ninner_docker=("$FAKE_DOCKER")\n'
                'run_id=abc\nFIXTURE_IMAGE=synthetic-image\n'
            )
            probe = PROBE.replace("44s bash -c", "1s bash -c", 1) if short_deadline else PROBE
            started = time.monotonic()
            result = subprocess.run(
                ["bash", "-c", prelude + probe],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result, removed.exists(), time.monotonic() - started

    def test_specific_cause_precedes_oci_envelope_and_cleans_up(self):
        secret = "synthetic-secret-never-print"
        result, removed, _ = self.run_probe(
            f"OCI runtime create failed: runc: cgroup unavailable {secret}"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(removed)
        self.assertIn("DOCKERLENS_NATIVE_PROBE: minimal_start_cgroup", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_oversized_error_retains_only_tail_and_never_prints_values(self):
        secret = "private-oversized-value"
        result, removed, _ = self.run_probe(
            "OCI runtime create failed: runc " + ("x" * 12_000) + secret
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(removed)
        self.assertIn("DOCKERLENS_NATIVE_PROBE: minimal_start_unclassified", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_timeout_and_unknown_fail_closed(self):
        for exit_code, category in ((124, "timeout"), (125, "unclassified")):
            with self.subTest(exit_code=exit_code):
                result, removed, _ = self.run_probe("opaque synthetic-secret", exit_code)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(removed)
                self.assertIn(f"minimal_start_{category}", result.stderr)
                self.assertNotIn("synthetic-secret", result.stdout + result.stderr)

    def test_unowned_container_is_not_removed(self):
        result, removed, _ = self.run_probe("OCI runtime failed", owner="someone-else")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(removed)
        self.assertIn("minimal_cleanup_unverified", result.stderr)
        self.assertIn("minimal_start_runtime", result.stderr)

    def test_inspect_failure_does_not_delete_unverified_container(self):
        result, removed, _ = self.run_probe("OCI runtime failed", inspect_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(removed)
        self.assertIn("minimal_cleanup_unverified", result.stderr)

    def test_open_stderr_writer_cannot_hold_classifier_forever(self):
        result, removed, elapsed = self.run_probe(
            "private-error", open_writer=True, short_deadline=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(removed)
        self.assertLess(elapsed, 5)
        self.assertIn("DOCKERLENS_NATIVE_PROBE: minimal_start_timeout", result.stderr)
        self.assertNotIn("private-error", result.stdout + result.stderr)

    def test_success_keeps_existing_fixed_marker(self):
        result, removed, _ = self.run_probe("", exit_code=0)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(removed)
        self.assertIn("DOCKERLENS_NATIVE_PROBE: minimal_start_ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
