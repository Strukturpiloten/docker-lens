"""Bounded, private diagnostics for the inert native Docker start probes."""

import os
import shlex
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
PRESENCE_HELPER = NATIVE_SCRIPT[NATIVE_SCRIPT.index("native_presence() {"):
                               NATIVE_SCRIPT.index("cleanup_remove() {")]


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
        daemon_log: str = "",
        daemon_owner: str = "abc",
        daemon_log_exit: int = 0,
        daemon_inspect_fails: bool = False,
        daemon_open_writer: bool = False,
        lane: str = "debian11-rootless",
        both_fail: bool = False,
        temporal_logs: bool = False,
        record_first_log: bool = True,
        boundary_override: str | None = None,
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
    if [ "$FAKE_EXIT" != 0 ] && { [ "$mode" = none ] || [ "$FAKE_BOTH_FAIL" = 1 ]; }; then
      if [ "$FAKE_TEMPORAL_LOGS" = 1 ] && [ "$FAKE_RECORD_FIRST_LOG" = 1 ] && [ "$mode" = none ]; then
        python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"))' > "$state/first-log-time"
      fi
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
            podman = fixture / "fake-podman"
            podman.write_text(
                """#!/bin/sh
set -eu
state=$FAKE_STATE
case "$1" in
  inspect)
    printf '%s\\n' inspect >> "$state/podman-inspected"
    [ "$FAKE_DAEMON_INSPECT_FAIL" = 0 ] || exit 1
    [ "$2" = --format ] || exit 7
    [ "$4" = dl-outer-abc ] || exit 7
    echo "$FAKE_DAEMON_OWNER" ;;
  logs)
    printf '%s\\n' logs >> "$state/podman-logged"
    [ "$2" = --since ] && [ "$4" = --tail ] && [ "$5" = 160 ] && [ "$6" = dl-outer-abc ] || exit 7
    since=$3
    printf '%s\\n' "$since" >> "$state/since-values"
    if [ "$FAKE_DAEMON_OPEN_WRITER" = 1 ]; then sleep 3 >&1 & fi
    if [ "$FAKE_TEMPORAL_LOGS" = 1 ]; then
      if awk -v event='2000-01-01T00:00:00.000000Z' -v since="$since" 'BEGIN { exit !(event >= since) }'; then
        printf 'failed to start daemon: cgroup pre-probe-error\\n'
      fi
      if [ -f "$state/first-log-time" ]; then
        event=$(cat "$state/first-log-time")
        if awk -v event="$event" -v since="$since" 'BEGIN { exit !(event >= since) }'; then
          printf 'failed to start daemon: resource temporarily unavailable first-probe-error\\n'
        fi
      fi
      exit "$FAKE_DAEMON_LOG_EXIT"
    fi
    printf '%s\\n' "$FAKE_DAEMON_LOG"
    exit "$FAKE_DAEMON_LOG_EXIT" ;;
  *) exit 7 ;;
esac
"""
            )
            podman.chmod(0o755)
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
                FAKE_DAEMON_LOG=daemon_log,
                FAKE_DAEMON_OWNER=daemon_owner,
                FAKE_DAEMON_LOG_EXIT=str(daemon_log_exit),
                FAKE_DAEMON_INSPECT_FAIL="1" if daemon_inspect_fails else "0",
                FAKE_DAEMON_OPEN_WRITER="1" if daemon_open_writer else "0",
                FAKE_BOTH_FAIL="1" if both_fail else "0",
                FAKE_TEMPORAL_LOGS="1" if temporal_logs else "0",
                FAKE_RECORD_FIRST_LOG="1" if record_first_log else "0",
            )
            prelude = (
                'set -euo pipefail\ninner_docker=("$FAKE_DOCKER")\n'
                f'podman_cmd=("{podman}")\n'
                f'lane={lane}\ncontainer=dl-outer-abc\n'
                'run_id=abc\nFIXTURE_IMAGE=synthetic-image\n'
                f'script_dir={shlex.quote(str(ROOT / "scripts"))}\n'
                f'run_dir={shlex.quote(str(fixture))}\npreserve_run_dir=0\n'
            ) + PRESENCE_HELPER
            probe = PROBE.replace("44s bash -c", "1s bash -c").replace(
                "12s bash -c", "1s bash -c"
            ) if short_deadline else PROBE
            if boundary_override is not None:
                replacement = "return 1" if boundary_override == "failure" else f"printf '%s' '{boundary_override}'"
                probe = probe.replace(
                    "probe_failed=0", f"probe_log_boundary() {{ {replacement}; }}\nprobe_failed=0"
                )
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
            self.podman_inspects = (fixture / "podman-inspected").read_text().splitlines() if (
                fixture / "podman-inspected"
            ).exists() else []
            self.podman_logs = (fixture / "podman-logged").read_text().splitlines() if (
                fixture / "podman-logged"
            ).exists() else []
            self.since_values = (fixture / "since-values").read_text().splitlines() if (
                fixture / "since-values"
            ).exists() else []
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

    def test_fixed_oci_symptoms_are_distinct_and_private(self) -> None:
        symptoms = (
            ("error waiting for final child pid from pipe: EOF", "final_pid_pipe_eof"),
            ("error waiting for final child pid from pipe: unexpected end of file", "final_pid_pipe_eof"),
            ("error waiting for final child pid from pipe: connection reset by peer", "final_pid_pipe_reset"),
            ("error waiting for final child pid from pipe: broken pipe", "final_pid_pipe_other"),
            ("unable to spawn stage-1: resource temporarily unavailable", "stage1_eagain"),
            ("failed to spawn stage-2: EAGAIN", "stage2_eagain"),
            (
                "unable to spawn stage-2: resource temporarily unavailable; "
                "error waiting for final child pid from pipe: EOF",
                "stage2_eagain",
            ),
            ("unable to spawn stage-2: operation not permitted", "stage2_permission"),
            ("unable to spawn stage-2: invalid argument", "stage2_invalid_argument"),
            ("unable to spawn stage-1: unexpected runtime failure", "stage1_other"),
            (
                "unable to spawn stage-1: operation not permitted; unrelated EAGAIN",
                "stage1_permission",
            ),
            (
                "unable to spawn stage-2: invalid argument\nunrelated EAGAIN",
                "stage2_invalid_argument",
            ),
            (
                "unable to spawn stage-1: unexpected failure; unrelated EAGAIN",
                "stage1_other",
            ),
            (
                "unable to spawn stage-1: permission denied\n"
                "failed to spawn stage-2: EAGAIN",
                "stage1_permission",
            ),
            (
                "failed to spawn stage-2: EAGAIN; unable to spawn stage-1: permission denied",
                "stage2_eagain",
            ),
            ("runc: resource temporarily unavailable", "resource_unavailable"),
            ("runc: too many open files", "file_descriptors"),
        )
        secret = "synthetic-private-value-never-print"
        for detail, category in symptoms:
            with self.subTest(category=category, detail=detail):
                result, created, removed, _ = self.run_probe(
                    f"OCI runtime create failed: {detail} {secret}"
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(created, ["none", "bridge"])
                self.assertEqual(removed, ["none", "bridge"])
                self.assertIn(f"none_start_{category}", result.stderr)
                self.assertIn("bridge_start_ok", result.stderr)
                self.assertNotIn(secret, result.stdout + result.stderr)

    def test_state_error_reports_fixed_oci_symptom_after_generic_cli_error(self) -> None:
        secret = "private-state-detail-never-print"
        result, _, removed, _ = self.run_probe(
            "OCI runtime create failed: runc private-cli-detail",
            state_error=f"error waiting for final child pid from pipe: EOF {secret}",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_start_final_pid_pipe_eof", result.stderr)
        self.assertIn("none_state_error_final_pid_pipe_eof", result.stderr)
        self.assertNotIn("private", result.stdout + result.stderr)

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
        self.assertIn("none_daemon_unavailable", result.stderr)
        self.assertEqual(self.podman_inspects, [])
        self.assertEqual(self.podman_logs, [])
        self.assertNotIn("private-state-error", result.stdout + result.stderr)

    def test_inspect_failure_does_not_delete_unverified_container(self) -> None:
        result, _, removed, _ = self.run_probe("OCI runtime failed", inspect_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(removed, [])
        self.assertIn("none_cleanup_unverified", result.stderr)
        self.assertIn("none_state_error_unavailable", result.stderr)
        self.assertEqual(self.podman_inspects, [])
        self.assertEqual(self.podman_logs, [])

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

    def test_daemon_log_distinguishes_specific_cause_from_generic_oci(self) -> None:
        secret = "private-daemon-value-never-print"
        result, created, removed, _ = self.run_probe(
            "OCI runtime create failed: runc private-cli-detail",
            daemon_log=(
                "DOCKERLENS_APT_STAGE: install\n"
                "time=\"2026-09-27T10:00:00Z\" level=error msg=\"permission denied\"\n"
                "DOCKERLENS_APT_STAGE: daemon\n"
                "time=\"2026-09-27T10:00:30Z\" level=warning msg=\"cgroup earlier-error\"\n"
                "+ echo 'stage-2: EAGAIN private-trace'\n"
                "time=\"2026-09-27T10:01:00Z\" level=error "
                f"msg=\"failed to spawn stage-2: EAGAIN {secret}\""
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(created, ["none", "bridge"])
        self.assertEqual(removed, ["none", "bridge"])
        self.assertEqual(self.podman_inspects, ["inspect"])
        self.assertEqual(self.podman_logs, ["logs"])
        self.assertIn("none_start_oci", result.stderr)
        self.assertIn("none_daemon_stage2_eagain", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertNotIn("private-trace", result.stdout + result.stderr)

        result, _, removed, _ = self.run_probe(
            "opaque CLI error",
            daemon_log=(
                "DOCKERLENS_APT_STAGE: daemon\n"
                "time=\"2026-09-27T10:01:00Z\" level=error msg=\"OCI runtime runc failed\""
            ),
        )
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_daemon_oci", result.stderr)

        result, _, removed, _ = self.run_probe(
            "opaque CLI error",
            daemon_log=(
                "DOCKERLENS_APT_STAGE: daemon\n"
                "time=\"2026-09-27T10:00:00Z\" level=error "
                "msg=\"failed to spawn stage-2: EAGAIN earlier-error\"\n"
                "time=\"2026-09-27T10:01:00Z\" level=error msg=\"cgroup current-error\""
            ),
        )
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_daemon_cgroup", result.stderr)
        self.assertNotIn("none_daemon_stage2_eagain", result.stderr)

        result, _, removed, _ = self.run_probe(
            "opaque CLI error",
            daemon_log=(
                "DOCKERLENS_APT_STAGE: daemon\n"
                + "time=\"2026-09-27T10:00:00Z\" level=info msg=\"routine\"\n" * 90
                + "time=\"2026-09-27T10:01:00Z\" level=error msg=\"cgroup failure\""
            ),
        )
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_daemon_cgroup", result.stderr)

        result, _, removed, _ = self.run_probe(
            "opaque CLI error",
            daemon_log="time=\"2026-09-27T10:01:00Z\" level=error msg=\"cgroup failure\"",
            lane="upstream-rootless",
        )
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_daemon_cgroup", result.stderr)

    def test_daemon_log_ignores_apt_trace_and_info(self) -> None:
        result, _, removed, _ = self.run_probe(
            "opaque CLI error",
            daemon_log=(
                "DOCKERLENS_APT_STAGE: install\n"
                "time=\"2026-09-27T10:00:00Z\" level=error msg=\"cgroup apt-secret\"\n"
                "DOCKERLENS_APT_STAGE: daemon\n"
                "+ runc --secret=private-trace eagain\n"
                "time=\"2026-09-27T10:01:00Z\" level=info msg=\"permission denied\""
            ),
        )
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_daemon_unavailable", result.stderr)
        self.assertNotIn("apt-secret", result.stdout + result.stderr)
        self.assertNotIn("private-trace", result.stdout + result.stderr)

        result, _, removed, _ = self.run_probe(
            "opaque CLI error",
            daemon_log="time=\"2026-09-27T10:01:00Z\" level=error msg=\"cgroup failure\"",
        )
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_daemon_cgroup", result.stderr)

    def test_sequential_failed_probes_do_not_inherit_earlier_daemon_error(self) -> None:
        result, created, removed, _ = self.run_probe(
            "opaque CLI error", both_fail=True, temporal_logs=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(created, ["none", "bridge"])
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_daemon_resource_unavailable", result.stderr)
        self.assertIn("bridge_daemon_unavailable", result.stderr)
        self.assertNotIn("bridge_daemon_resource_unavailable", result.stderr)
        self.assertEqual(self.podman_logs, ["logs", "logs"])
        self.assertEqual(len(self.since_values), 2)
        for boundary in self.since_values:
            self.assertRegex(boundary, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
        self.assertLess(self.since_values[0], self.since_values[1])

    def test_preprobe_daemon_error_is_excluded(self) -> None:
        result, _, removed, _ = self.run_probe(
            "opaque CLI error", temporal_logs=True, record_first_log=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_daemon_unavailable", result.stderr)
        self.assertNotIn("none_daemon_cgroup", result.stderr)

    def test_invalid_or_failed_probe_boundary_disables_daemon_log_read(self) -> None:
        for boundary in ("invalid", "failure"):
            with self.subTest(boundary=boundary):
                result, _, removed, _ = self.run_probe(
                    "opaque CLI error",
                    daemon_log="failed to start daemon: cgroup",
                    boundary_override=boundary,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(removed, ["none", "bridge"])
                self.assertIn("none_daemon_unavailable", result.stderr)
                self.assertEqual(self.podman_inspects, [])
                self.assertEqual(self.podman_logs, [])

    def test_daemon_log_discards_oversized_private_line(self) -> None:
        secret = "private-oversized-daemon-value"
        result, _, removed, _ = self.run_probe(
            "opaque CLI error",
            daemon_log=(
                "DOCKERLENS_APT_STAGE: daemon\n"
                + 'time="2026-09-27T10:00:00Z" level=error msg="'
                + ("x" * 60_000)
                + secret
                + '"\nfailed to start daemon: cgroup failure'
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_daemon_cgroup", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_daemon_log_unavailable_and_failed_stay_failed(self) -> None:
        for options in (
            {},
            {"daemon_log": "DOCKERLENS_APT_STAGE: daemon\nfailed to start daemon: cgroup", "daemon_log_exit": 7},
            {"daemon_log": "DOCKERLENS_APT_STAGE: daemon\nfailed to start daemon: cgroup", "daemon_owner": "other-run"},
            {"daemon_inspect_fails": True},
        ):
            with self.subTest(options=options):
                result, _, removed, _ = self.run_probe("opaque CLI error", **options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(removed, ["none", "bridge"])
                self.assertIn("none_daemon_unavailable", result.stderr)
                self.assertEqual(self.podman_inspects, ["inspect"])
                if options.get("daemon_owner") == "other-run" or options.get("daemon_inspect_fails"):
                    self.assertEqual(self.podman_logs, [])

    def test_open_daemon_log_writer_times_out_and_keeps_cleanup(self) -> None:
        result, _, removed, elapsed = self.run_probe(
            "opaque CLI error",
            daemon_log="DOCKERLENS_APT_STAGE: daemon\nfailed to start daemon: cgroup",
            daemon_open_writer=True,
            short_deadline=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 5)
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_daemon_unavailable", result.stderr)

    def test_success_cleans_up_both_modes_and_keeps_fixed_markers(self) -> None:
        result, created, removed, _ = self.run_probe("", exit_code=0)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(created, ["none", "bridge"])
        self.assertEqual(removed, ["none", "bridge"])
        self.assertIn("none_start_ok", result.stderr)
        self.assertIn("bridge_start_ok", result.stderr)
        self.assertEqual(self.podman_inspects, [])
        self.assertEqual(self.podman_logs, [])


if __name__ == "__main__":
    unittest.main()
