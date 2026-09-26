"""Bounded, private diagnostics for the inert native Docker start probes."""

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SCRIPT = (ROOT / "scripts/native-conformance.sh").read_text()
START = NATIVE_SCRIPT.index("# Docker CLI errors may contain authored values.")
END = NATIVE_SCRIPT.index("network_id=$(timeout 30", START)
PROBE = NATIVE_SCRIPT[START:END]


class MinimalStartDiagnosisTests(unittest.TestCase):
    def run_probe(
        self,
        error: str,
        exit_code: int = 125,
        owner: str = "abc",
        *,
        state_error: str = "",
        open_writer: bool = False,
        inspect_fails: bool = False,
        short_deadline: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], list[str], list[str], float]:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            docker = fixture / "fake-docker"
            docker.write_text(
                """#!/bin/sh
set -eu
state=$FAKE_STATE
[ "$1" = container ] || exit 7
action=$2
shift 2
case "$action" in
  create)
    case " $* " in
      *" --network none "*) mode=none ;;
      *" --network bridge "*) mode=bridge ;;
      *) exit 3 ;;
    esac
    case " $* " in
      *" --entrypoint /bin/sh synthetic-image -c exit 0 "*) ;;
      *) exit 3 ;;
    esac
    : > "$state/$mode"
    printf '%s\\n' "$mode" >> "$state/created"
    echo synthetic-id ;;
  start)
    mode=${1##*-}
    if [ "$mode" = none ] && [ "$FAKE_EXIT" != 0 ]; then
      if [ "$FAKE_OPEN_WRITER" = 1 ]; then sleep 3 >&2 & fi
      printf '%s\\n' "$FAKE_ERROR" >&2
      exit "$FAKE_EXIT"
    fi
    echo synthetic-id ;;
  wait) echo 0 ;;
  inspect)
    [ "$FAKE_INSPECT_FAIL" = 0 ] || exit 1
    name=
    for value in "$@"; do name=$value; done
    mode=${name##*-}
    [ -f "$state/$mode" ] || exit 1
    case " $* " in
      *Config.Labels*) echo "$FAKE_OWNER" ;;
      *State.Status*) echo 'exited|0' ;;
      *State.Error*) printf '%s\\n' "$FAKE_STATE_ERROR" ;;
      *) exit 3 ;;
    esac ;;
  rm)
    name=
    for value in "$@"; do name=$value; done
    mode=${name##*-}
    printf '%s\\n' "$mode" >> "$state/removed"
    rm "$state/$mode" ;;
  ls)
    [ -f "$state/none" ] && echo dl-abc-probe-none
    [ -f "$state/bridge" ] && echo dl-abc-probe-bridge
    exit 0 ;;
  *) exit 7 ;;
esac
"""
            )
            docker.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                FAKE_DOCKER=str(docker),
                FAKE_STATE=str(fixture),
                FAKE_ERROR=error,
                FAKE_EXIT=str(exit_code),
                FAKE_OWNER=owner,
                FAKE_STATE_ERROR=state_error,
                FAKE_OPEN_WRITER="1" if open_writer else "0",
                FAKE_INSPECT_FAIL="1" if inspect_fails else "0",
            )
            prelude = (
                'set -euo pipefail\ninner_docker=("$FAKE_DOCKER")\n'
                'run_id=abc\nFIXTURE_IMAGE=synthetic-image\n'
            )
            probe = PROBE.replace("44s bash -c", "1s bash -c") if short_deadline else PROBE
            started = time.monotonic()
            result = subprocess.run(
                ["bash", "-c", prelude + probe],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            created = (fixture / "created").read_text().splitlines()
            removed_file = fixture / "removed"
            removed = removed_file.read_text().splitlines() if removed_file.exists() else []
            return result, created, removed, time.monotonic() - started

    def test_specific_cause_precedes_oci_envelope_and_cleans_up(self) -> None:
        secret = "synthetic-secret-never-print"
        result, created, removed, _ = self.run_probe(
            f"OCI runtime create failed: runc: cgroup unavailable {secret}"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(created, ["none", "bridge"])
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_start_cgroup", result.stderr)
        self.assertIn("bridge_start_ok", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_oversized_error_retains_only_tail_and_never_prints_values(self) -> None:
        secret = "private-oversized-value"
        result, _, removed, _ = self.run_probe(
            "OCI runtime create failed: runc " + ("x" * 12_000) + secret
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_start_unclassified", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_timeout_and_unknown_fail_closed(self) -> None:
        for exit_code, category in ((124, "timeout"), (125, "unclassified")):
            with self.subTest(exit_code=exit_code):
                result, _, removed, _ = self.run_probe("opaque synthetic-secret", exit_code)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(removed, ["none", "bridge"])
                self.assertIn(f"none_start_{category}", result.stderr)
                self.assertIn("none_state_error_unclassified", result.stderr)
                self.assertNotIn("synthetic-secret", result.stdout + result.stderr)

    def test_unowned_container_is_not_removed_or_inspected_for_state(self) -> None:
        result, created, removed, _ = self.run_probe(
            "OCI runtime failed", owner="someone-else",
            state_error="private-state-error"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(created, ["none", "bridge"])
        self.assertEqual(removed, [])
        self.assertIn("none_cleanup_unverified", result.stderr)
        self.assertIn("none_state_error_unavailable", result.stderr)
        self.assertNotIn("private-state-error", result.stdout + result.stderr)

    def test_inspect_failure_does_not_delete_unverified_container(self) -> None:
        result, _, removed, _ = self.run_probe("OCI runtime failed", inspect_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(removed, [])
        self.assertIn("none_cleanup_unverified", result.stderr)
        self.assertIn("none_state_error_unavailable", result.stderr)

    def test_open_stderr_writer_cannot_hold_classifier_forever(self) -> None:
        result, _, removed, elapsed = self.run_probe(
            "private-error", open_writer=True, short_deadline=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(removed, ["none", "bridge"])
        self.assertLess(elapsed, 5)
        self.assertIn("none_start_timeout", result.stderr)
        self.assertNotIn("private-error", result.stdout + result.stderr)

    def test_private_state_error_refines_generic_oci_category(self) -> None:
        result, _, removed, _ = self.run_probe(
            "OCI runtime create failed: private-cli-detail",
            state_error="read init-p: connection reset by peer private-state-detail",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_start_init_pipe_eof", result.stderr)
        self.assertIn("none_state_error_init_pipe_eof", result.stderr)
        self.assertNotIn("private", result.stdout + result.stderr)

    def test_success_cleans_up_both_modes_and_keeps_fixed_markers(self) -> None:
        result, created, removed, _ = self.run_probe("", exit_code=0)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(created, ["none", "bridge"])
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_start_ok", result.stderr)
        self.assertIn("bridge_start_ok", result.stderr)


if __name__ == "__main__":
    unittest.main()
