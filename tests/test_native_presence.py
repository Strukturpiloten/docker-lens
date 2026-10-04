"""Independent command and cleanup faults; no native runtime is launched."""

import importlib.util
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/native-presence.py"
SPEC = importlib.util.spec_from_file_location("native_presence", HELPER)
assert SPEC is not None and SPEC.loader is not None
PRESENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRESENCE)


class NativePresenceTests(unittest.TestCase):
    def test_empty_native_status_is_the_only_exists_evidence(self) -> None:
        cases = (
            (0, b"", b"", ("present", 0)),
            (1, b"", b"", ("absent", 1)),
            (0, b"", b"private warning", ("unknown", 2)),
            (1, b"", b"private configuration diagnostic", ("unknown", 2)),
            (0, b"\n", b"", ("unknown", 2)),
            (1, b" ", b"", ("unknown", 2)),
            (2, b"", b"", ("unknown", 2)),
            (125, b"", b"", ("unknown", 2)),
        )
        for status, stdout, stderr, expected in cases:
            with self.subTest(status=status, stdout=stdout, stderr=stderr), tempfile.TemporaryDirectory() as temporary:
                code = (f"import os; os.write(1, {stdout!r}); os.write(2, {stderr!r}); "
                        f"raise SystemExit({status})")
                self.assertEqual(PRESENCE.query([sys.executable, "-c", code], Path(temporary), "exists"), expected)
                evidence = list(Path(temporary).glob("presence-*"))
                self.assertEqual(len(evidence), 1)
                self.assertEqual(evidence[0].stat().st_mode & 0o777, 0o600)
                self.assertEqual(evidence[0].read_bytes(), stdout + stderr)

    def test_listing_requires_empty_success_including_stderr(self) -> None:
        for status, output, expected in ((0, b"", ("absent", 1)),
                                         (1, b"", ("unknown", 2)),
                                         (0, b"private warning", ("unknown", 2))):
            with self.subTest(status=status, output=output), tempfile.TemporaryDirectory() as temporary:
                code = f"import os; os.write(2, {output!r}); raise SystemExit({status})"
                self.assertEqual(PRESENCE.query([sys.executable, "-c", code], Path(temporary), "empty-success"), expected)

    def test_timeout_overflow_signal_and_launch_failure_are_unknown(self) -> None:
        cases = (
            [sys.executable, "-c", "import time; time.sleep(30)"],
            [sys.executable, "-c", "import os; os.write(2, b'x' * 100000); raise SystemExit(1)"],
            [sys.executable, "-c", "import os,signal; os.kill(os.getpid(),signal.SIGTERM)"],
            ["/nonexistent/native-presence-command"],
        )
        for command in cases:
            with self.subTest(command=command), tempfile.TemporaryDirectory() as temporary:
                started = time.monotonic()
                self.assertEqual(PRESENCE.query(command, Path(temporary), "exists", seconds=0.15), ("unknown", 2))
                self.assertLess(time.monotonic() - started, 3)
                self.assertTrue(all(path.stat().st_size <= 16384 for path in Path(temporary).iterdir()))

    def test_unverified_group_termination_rejects_an_empty_native_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch.object(PRESENCE, "terminate_group", return_value=(1, False)):
            # Reap the actual short-lived test child after the injected failure.
            real_popen = subprocess.Popen
            children = []

            def capture(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                children.append(child)
                return child

            with patch.object(PRESENCE.subprocess, "Popen", side_effect=capture):
                self.assertEqual(PRESENCE.query([sys.executable, "-c", "raise SystemExit(1)"], Path(temporary), "exists"), ("unknown", 2))
            for child in children:
                child.wait(timeout=2)

    def test_early_eof_requires_actual_completion_before_classification(self) -> None:
        for delay, seconds, expected in ((0.03, 1, ("absent", 1)),
                                         (30, 0.1, ("unknown", 2))):
            with self.subTest(delay=delay), tempfile.TemporaryDirectory() as temporary:
                code = f"import os,time; os.close(1); os.close(2); time.sleep({delay}); raise SystemExit(1)"
                self.assertEqual(PRESENCE.query([sys.executable, "-c", code], Path(temporary), "exists", seconds=seconds), expected)

    def test_descendant_holding_pipe_cannot_make_leader_exit_one_absence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            code = "import os,time; child=os.fork(); time.sleep(30) if child==0 else None; raise SystemExit(1)"
            self.assertEqual(PRESENCE.query([sys.executable, "-c", code], Path(temporary), "exists", seconds=0.1), ("unknown", 2))

    def test_group_signal_failure_does_not_reap_a_leader_before_teardown(self) -> None:
        from unittest.mock import Mock
        child = Mock(pid=12345)
        with patch.object(PRESENCE.os, "killpg", side_effect=PermissionError):
            self.assertEqual(PRESENCE.terminate_group(child), (None, False))
        child.wait.assert_not_called()

    def test_cancellation_is_unknown_and_reaps_the_native_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            pid_file = directory / "child-pid"
            command = [sys.executable, str(HELPER), "exists", temporary, "--", sys.executable, "-c",
                       f"import os,time; open({str(pid_file)!r},'w').write(str(os.getpid())); time.sleep(30)"]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 3
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(pid_file.exists())
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=4)
            self.assertEqual((process.returncode, stdout, stderr), (2, "unknown\n", ""))
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)


class PresenceCleanupTests(unittest.TestCase):
    def run_shell(self, role: str, phase: str, fault: str, *, elevated: bool = False):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        helpers = source[source.index("cleanup_podman() {"):source.index("trap cleanup EXIT")]
        preflight = source[source.index("for resource in container sidecar network volume; do"):
                           source.index('"${podman_cmd[@]}" volume create')]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            run_dir = directory / "dockerlens-native.fixture"
            run_dir.mkdir(mode=0o700)
            command = directory / "fake-podman"
            command.write_text("#!/usr/bin/env python3\n" + '''
import os,sys
from pathlib import Path
args=sys.argv[1:]
state=Path(os.environ["PRESENCE_STATE"])
name=args[-1]
role=name.removeprefix("r_")
if "exists" in args:
    present=(state/role).exists()
    inject=role==os.environ["PRESENCE_ROLE"] and (
        os.environ["PRESENCE_PHASE"] in ("preflight", "initial") or (state/(role+"-removed")).exists())
    if inject:
        fault=os.environ["PRESENCE_FAULT"]
        if fault=="stderr1":
            print("private configuration diagnostic",file=sys.stderr); sys.exit(1)
        if fault=="warning0":
            print("private warning",file=sys.stderr); sys.exit(0)
        if fault=="stdout1":
            print("private stdout"); sys.exit(1)
        if fault=="error": sys.exit(125)
    sys.exit(0 if present else 1)
if "inspect" in args:
    print("owner"); sys.exit(0)
if "rm" in args:
    (state/(role+"-removed")).touch()
    (state/role).unlink(missing_ok=True)
    sys.exit(0)
sys.exit(125)
''')
            command.chmod(0o700)
            if phase != "preflight":
                for owned in ("container", "sidecar", "network", "volume"):
                    (directory / owned).touch()
            sudo = directory / "sudo"
            sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$PRESENCE_STATE/privileged"\nshift 1\nexec "$@"\n')
            sudo.chmod(0o700)
            podman = ("sudo -n " if elevated else "") + shlex.quote(str(command))
            setup = f'''set -euo pipefail
script_dir={shlex.quote(str(ROOT / "scripts"))}
run_dir={shlex.quote(str(run_dir))}
podman_cmd=({podman})
container=r_container; sidecar=r_sidecar; outer_network=r_network; volume=r_volume
run_id=owner; lane=mock; watchdog_pid=; native_success_summary=passed; preserve_run_dir=0
'''
            body = preflight if phase == "preflight" else "true\ncleanup\n"
            environment = os.environ.copy()
            environment.update(PATH=f"{directory}:{environment['PATH']}", TMPDIR=temporary,
                               PRESENCE_STATE=temporary, PRESENCE_ROLE=role,
                               PRESENCE_PHASE=phase, PRESENCE_FAULT=fault)
            result = subprocess.run(["bash", "-c", setup + helpers + body], env=environment,
                                    capture_output=True, text=True, timeout=15, check=False)
            retained = run_dir.exists()
            evidence = [path.read_bytes() for path in run_dir.glob("presence-*")]
            privileged = (directory / "privileged").read_text() if elevated else ""
            removed = [(directory / (owned + "-removed")).exists()
                       for owned in ("container", "sidecar", "network", "volume")]
            return result, retained, evidence, privileged, removed

    def test_diagnostics_never_prove_absence_for_any_role_or_phase(self) -> None:
        for role in ("container", "sidecar", "network", "volume"):
            for phase in ("preflight", "initial", "readback"):
                for fault in ("stderr1", "warning0", "stdout1", "error"):
                    with self.subTest(role=role, phase=phase, fault=fault):
                        result, retained, evidence, _, _ = self.run_shell(role, phase, fault)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertTrue(retained)
                        self.assertTrue(evidence)
                        self.assertNotIn("private", result.stdout)
                        self.assertNotIn("private configuration", result.stderr)
                        self.assertNotIn("private warning", result.stderr)
                        self.assertNotIn("private stdout", result.stderr)
                        self.assertNotIn("passed", result.stdout)

    def test_clean_absence_readback_releases_private_directory(self) -> None:
        result, retained, _, _, removed = self.run_shell("container", "readback", "none")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(retained)
        self.assertTrue(all(removed))
        self.assertEqual(result.stdout, "passed\n")

    def test_empty_exit_one_passes_generated_name_preflight(self) -> None:
        result, retained, evidence, _, removed = self.run_shell("container", "preflight", "none")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(retained)
        self.assertEqual(evidence, [b""] * 4)
        self.assertFalse(any(removed))

    def test_inner_probe_requires_empty_success_on_both_streams(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        presence = source[source.index("native_presence() {"):source.index("cleanup_remove() {")]
        cleanup = source[source.index("probe_cleanup() {"):source.index("run_inert_probe() {")]
        cases = ((0, "", 0), (0, "private warning", 1), (1, "", 1), (1, "private error", 1))
        for status, diagnostic, expected in cases:
            with self.subTest(status=status, diagnostic=diagnostic), tempfile.TemporaryDirectory() as temporary:
                code = ("import sys; args=sys.argv[1:]; "
                        "print('owner') if 'inspect' in args else None; "
                        f"print({diagnostic!r},file=sys.stderr) if 'ls' in args and {bool(diagnostic)!r} else None; "
                        f"raise SystemExit({status} if 'ls' in args else 0)")
                setup = (f"script_dir={shlex.quote(str(ROOT / 'scripts'))}; "
                         f"run_dir={shlex.quote(temporary)}; run_id=owner; preserve_run_dir=0; "
                         f"inner_docker=({shlex.quote(sys.executable)} -c {shlex.quote(code)}); ")
                result = subprocess.run(["bash", "-c", setup + presence + cleanup + "\nprobe_cleanup owned"],
                                        capture_output=True, text=True, timeout=5, check=False)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(result.stdout + result.stderr, "")

    def test_elevated_presence_timer_and_helper_share_client_privileges(self) -> None:
        result, retained, _, privileged, _ = self.run_shell("volume", "readback", "stderr1", elevated=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(retained)
        self.assertIn("-n timeout --signal=TERM --kill-after=2s 8s python3", privileged)
        self.assertNotIn("private configuration", result.stderr)

    def test_helper_launch_one_without_marker_is_unknown(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        function = source[source.index("native_presence() {"):source.index("cleanup_remove() {")]
        result = subprocess.run(["bash", "-c", 'set -u; script_dir=/nonexistent; run_dir=/tmp; '
                                 'preserve_run_dir=0; ' + function +
                                 '\nnative_presence exists true; result=$?; '
                                 'printf "%s:%s" "$result" "$preserve_run_dir"'],
                                capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.stdout, "2:1")
        self.assertEqual(result.stderr, "")

    def test_reply_requires_exact_marker_newline_and_matching_status(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        function = source[source.index("native_presence() {"):source.index("cleanup_remove() {")]
        cases = (("present\n", 0, "0:0"), ("absent\n", 1, "1:0"),
                 ("present\n\n", 0, "2:1"), ("absent\n\n", 1, "2:1"),
                 ("present", 0, "2:1"), ("absent", 1, "2:1"),
                 ("absent\n", 0, "2:1"), ("present\n", 1, "2:1"),
                 ("unknown\n", 2, "2:1"), ("malformed\n", 1, "2:1"))
        for marker, status, expected in cases:
            with self.subTest(marker=marker, status=status), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                (directory / "native-presence.py").write_text(
                    f"import sys; sys.stdout.write({marker!r}); raise SystemExit({status})")
                setup = (f"script_dir={shlex.quote(temporary)}; run_dir={shlex.quote(temporary)}; "
                         "preserve_run_dir=0; ")
                result = subprocess.run(["bash", "-c", setup + function +
                                         '\nnative_presence exists true; result=$?; '
                                         'printf "%s:%s" "$result" "$preserve_run_dir"'],
                                        capture_output=True, text=True, timeout=5, check=False)
                self.assertEqual(result.stdout, expected)
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
