"""Hermetic cleanup diagnostics: fake clients only, never a native runtime."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_outer_diagnostic_capture as capture

SCRIPT = ROOT / "scripts/native-cleanup-inspect-diagnostic.py"
SPEC = importlib.util.spec_from_file_location("cleanup_inspect", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CANARY = "private-error /secret/socket resource=private-id"


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def context(self, source, limit=65536, total=131072):
        query = (sys.executable, "-c", source)
        return capture.CaptureContext(MODULE.Unavailable, capture.Cancelled, ((query, "inspect"),),
                                      dict(os.environ), self.directory, limit, total, False), query

    def test_complete_nonzero_and_both_streams_are_data(self):
        for status in (0, 1, 2, 124, 126, 127, 137):
            with self.subTest(status=status):
                context, query = self.context(f"import sys;print('out');print('err',file=sys.stderr);sys.exit({status})")
                with context.private_outputs() as files:
                    result = context.capture_outcome(query, files, "inspect", time.monotonic() + 3)
                self.assertEqual((result.stdout, result.stderr, result.returncode,
                                  result.stdout_count, result.stderr_count), (b"out\n", b"err\n", status, 4, 4))
                self.assertNotIn("b'out", repr(result))

    def test_legacy_status_precedence_and_stdout_only_validation(self):
        for status, expected in ((1, "command_failed"), (124, "timeout"), (137, "timeout"),
                                 (126, "tool_unavailable"), (127, "tool_unavailable")):
            context, query = self.context(f"import sys;print('out');sys.exit({status})")
            with context.private_outputs() as files:
                original = capture.os.read
                with patch.object(capture.os, "read", side_effect=lambda fd, n: b"corrupt" if fd == files["inspect.stdout"] else original(fd, n)):
                    with self.assertRaisesRegex(MODULE.Unavailable, "^" + expected + "$"):
                        context.capture(query, files, "inspect", time.monotonic() + 3)
        context, query = self.context("print('out')")
        with context.private_outputs() as files:
            original = capture.os.read
            with patch.object(capture.os, "read", side_effect=lambda fd, n: b"tampered" if fd == files["inspect.stderr"] else original(fd, n)):
                self.assertEqual(context.capture(query, files, "inspect", time.monotonic() + 3), b"out\n")
        with context.private_outputs() as files:
            original = capture.os.read
            with patch.object(capture.os, "read", side_effect=lambda fd, n: b"tampered" if fd == files["inspect.stderr"] else original(fd, n)):
                with self.assertRaisesRegex(MODULE.Unavailable, "^collector_io_failure$"):
                    context.capture_outcome(query, files, "inspect", time.monotonic() + 3)

    def test_overflow_precedes_legacy_complete_timeout_status(self):
        for status in (0, 124, 137):
            context, query = self.context(f"import sys;print('overflow');sys.exit({status})", limit=2, total=None)
            with context.private_outputs() as files:
                with self.assertRaisesRegex(MODULE.Unavailable, "^output_overflow$"):
                    context.capture(query, files, "inspect", time.monotonic() + 3)

    def test_spawn_reason_labels_unchanged(self):
        context, query = self.context("pass")
        for error, reason in ((FileNotFoundError(), "tool_unavailable"), (OSError(), "command_failed")):
            with context.private_outputs() as files, patch.object(capture.subprocess, "Popen", side_effect=error):
                with self.assertRaisesRegex(MODULE.Unavailable, "^" + reason + "$"):
                    context.capture(query, files, "inspect", time.monotonic() + 3)

    def test_unknown_completion_beats_overflow_and_never_becomes_command_failed(self):
        context, query = self.context("import os,time;os.write(1,b'overflow');os.close(1);os.close(2);time.sleep(.2)", limit=2, total=None)
        original = capture.subprocess.Popen
        children = []

        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        try:
            with context.private_outputs() as files, patch.object(capture.subprocess, "Popen", side_effect=spawn):
                with self.assertRaisesRegex(MODULE.Unavailable, "^completion_unknown$"):
                    context.capture(query, files, "inspect", time.monotonic() + .1)
        finally:
            for child in children:
                child.wait(timeout=3)

    def test_cancellation_reason_and_private_cleanup_flag_remain_legacy(self):
        context, query = self.context("pass")
        cancellation = capture.Cancellation()
        cancellation.request(signal.SIGTERM)
        original = capture.RawFiles.discard

        def failed(files):
            original(files)
            files.clean = False

        with patch.object(capture.RawFiles, "discard", failed), self.assertRaises(capture.Cancelled) as caught:
            with context.private_outputs() as files:
                context.capture(query, files, "inspect", time.monotonic() + 3, cancellation)
        self.assertEqual((caught.exception.reason, caught.exception.cleanup), ("cancelled", "failed"))


class FrontendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "dockerlens-native.ABC123xy"
        self.directory.mkdir(mode=0o700)
        (self.directory / "docker-client").mkdir(mode=0o700)
        self.binary = self.root / "bin"
        self.binary.mkdir()
        self.environment = dict(os.environ, PATH=str(self.binary) + ":" + os.environ["PATH"])
        self.args = ["owner", "--engine", "docker", "--directory", str(self.directory),
                     "--kind", "network-owner-inspect", "--name", "dl-native-net-ABC123xy"]

    def fake(self, body):
        path = self.binary / "docker"
        path.write_text("#!" + sys.executable + "\n" + body + "\n")
        path.chmod(0o700)

    def run_frontend(self):
        return subprocess.run([sys.executable, str(SCRIPT), *self.args], env=self.environment,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False)

    def test_exit_one_has_closed_diagnostic_no_canary_and_one_query(self):
        marker = self.root / "calls"
        self.fake(f"import pathlib,sys;pathlib.Path({str(marker)!r}).open('a').write('one\\n');"
                  f"print({CANARY!r},file=sys.stderr);print('private stdout');sys.exit(1)")
        result = self.run_frontend()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(marker.read_text(), "one\n")
        self.assertEqual(result.stderr, b"DOCKERLENS_NATIVE_CLEANUP_INSPECT: kind=network-owner-inspect query_exit=one stderr_family=unclassified collector_completion=complete\n")

    def test_success_wrong_identity_is_unchanged_not_authorized(self):
        self.fake("print('wrong-owner')")
        result = self.run_frontend()
        self.assertEqual((result.returncode, result.stdout), (0, b"wrong-owner\n"))
        self.assertIn(b"query_exit=success", result.stderr)

    def test_signalled_client_matches_original_timeout_status(self):
        self.fake("import os,signal;os.kill(os.getpid(),signal.SIGTERM)")
        original = subprocess.run(["/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", "8s",
                                   str(self.binary / "docker")], capture_output=True, timeout=12, check=False)
        result = self.run_frontend()
        original_status = original.returncode if original.returncode >= 0 else 128 - original.returncode
        self.assertEqual(result.returncode, original_status)
        self.assertEqual(result.returncode, 143)
        self.assertIn(b"query_exit=cancelled", result.stderr)

    def test_cancellation_holds_original_owner_and_group_until_kill(self):
        marker = self.root / "identity"
        private = self.root / "private"
        private.mkdir(mode=0o700)
        self.environment["TMPDIR"] = str(private)
        self.fake("import os,pathlib,signal,time,sys\n"
                  "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                  f"pathlib.Path({str(marker)!r}).write_text(str(os.getpgrp())+'|'+str(os.getsid(0)))\n"
                  f"print({CANARY!r},file=sys.stderr,flush=True)\n"
                  "time.sleep(60)")
        process = subprocess.Popen([sys.executable, str(SCRIPT), *self.args], env=self.environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            until = time.monotonic() + 3
            while not marker.exists() and time.monotonic() < until:
                time.sleep(.01)
            self.assertTrue(marker.exists())
            group, session = map(int, marker.read_text().split("|"))
            self.assertEqual(group, process.pid)
            self.assertEqual(session, os.getsid(0))
            process.send_signal(signal.SIGTERM)
            time.sleep(.2)
            self.assertIsNone(process.poll(), "frontend must not disarm its owner on cancellation")
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            self.assertEqual(stdout, b"")
            self.assertNotIn(CANARY.encode(), stderr)
            self.assertIn(b"collector_completion=unavailable", stderr)
            self.assertEqual(list(private.iterdir()), [])
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=3)

    def test_deadline_retains_original_eight_plus_two_owner_without_retry(self):
        marker = self.root / "calls"
        private = self.root / "private"
        private.mkdir(mode=0o700)
        self.environment["TMPDIR"] = str(private)
        self.fake("import pathlib,signal,time,sys\n"
                  "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                  f"pathlib.Path({str(marker)!r}).open('a').write('one\\n')\n"
                  f"print({CANARY!r},file=sys.stderr,flush=True)\n"
                  "time.sleep(60)")
        start = time.monotonic()
        process = subprocess.Popen([sys.executable, str(SCRIPT), *self.args], env=self.environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=14)
            self.assertGreaterEqual(time.monotonic() - start, 9.5)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            self.assertEqual(stdout, b"")
            self.assertEqual(marker.read_text(), "one\n")
            self.assertNotIn(CANARY.encode(), stderr)
            self.assertIn(b"collector_completion=unavailable", stderr)
            self.assertEqual(list(private.iterdir()), [])
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=3)

    def test_owner_is_single_exec_with_original_budget_and_handed_deadline(self):
        with patch.object(MODULE.time, "monotonic", return_value=10.25), patch.object(MODULE.os, "execv") as execute:
            MODULE.owner(self.args)
        executable, argv = execute.call_args.args
        self.assertEqual(executable, "/usr/bin/timeout")
        self.assertEqual(argv[:5], ("/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", "8s", "/usr/bin/python3"))
        self.assertEqual(argv[-2:], ("--deadline", "18.25"))
        self.assertEqual(argv[6], "collect")

    def test_deadline_rejects_nonfinite_malformed_stale_and_renewed_values(self):
        with patch.object(MODULE.time, "monotonic", return_value=100):
            for value in ("nan", "inf", "-1", "100.0", "99.0", "108.1", "1e100", "101.0junk"):
                with self.subTest(value=value), self.assertRaises(MODULE.Unavailable):
                    MODULE.held_deadline(value)
            self.assertEqual(MODULE.held_deadline("107.5"), 107.5)

    def test_closed_stderr_families_and_ambiguity(self):
        for raw, expected in ((b"", "empty"), (b"permission denied " + CANARY.encode(), "permission_denied"),
                              (b"Cannot connect to the Docker daemon", "connection_unavailable"),
                              (b"No such volume", "not_found"), (b"template parsing error", "template_error"),
                              (b"error calling index", "template_error"), (b"can't evaluate field", "template_error"),
                              (b"permission denied: no such volume", "unclassified"),
                              (CANARY.encode(), "unclassified")):
            self.assertEqual(MODULE.stderr_family(raw), expected)

    def test_complete_success_bytes_are_unchanged_for_callers_identity_comparison(self):
        for raw, kind in ((b"", MODULE.KINDS[0]), (b"line\nsecond\n", MODULE.KINDS[0]),
                          (b"bad\0value", MODULE.KINDS[0]), (b"\xff", MODULE.KINDS[0]),
                          (b"only|two", MODULE.KINDS[1])):
            with self.subTest(raw=raw):
                self.args[6] = kind
                self.args[8] = "dl-native-net-ABC123xy" if kind == MODULE.KINDS[0] else "dl-native-data-ABC123xy"
                self.fake(f"import os;os.write(1,{raw!r})")
                result = self.run_frontend()
                self.assertEqual((result.returncode, result.stdout), (0, raw))
                self.assertIn(b"query_exit=success", result.stderr)

    def test_closed_names_kinds_engine_and_argv(self):
        MODULE.arguments(self.args)
        volume = self.args.copy()
        volume[6], volume[8] = "volume-identity-inspect", "dl-native-data-ABC123xy"
        MODULE.arguments(volume)
        for index, value in ((2, "podman"), (6, "network-rm"), (8, "other"), (4, "/tmp/../dockerlens-native.ABC123xy")):
            args = self.args.copy()
            args[index] = value
            with self.subTest(index=index), self.assertRaises(MODULE.Unavailable):
                MODULE.arguments(args)
        with self.assertRaises(MODULE.Unavailable):
            MODULE.arguments(self.args + ["--", "rm"])

    def test_vector_matches_actual_canonical_shell_builder(self):
        shell = ('source "$1"; native_outer_privilege=(); native_outer_client docker "$2"; '
                 'printf "%s\\0" "${native_outer_cmd[@]}"')
        result = subprocess.run(["bash", "-c", shell, "test", str(ROOT / "scripts/native-outer-runtime.sh"),
                                 str(self.directory)], capture_output=True, check=True, env=self.environment)
        expected = result.stdout.decode().rstrip("\0").split("\0")
        with patch.dict(os.environ, self.environment, clear=True):
            actual = MODULE.command(str(self.directory), MODULE.KINDS[0], self.args[8])
        self.assertEqual(Path(actual[0]).name, expected[0])
        self.assertEqual(list(actual[1:-5]), expected[1:])
        self.assertEqual(actual[-5:], ("network", "inspect", "--format", MODULE.NETWORK_FORMAT, self.args[8]))

    def test_private_cleanup_failure_never_projects(self):
        @contextlib.contextmanager
        def failed_cleanup(_context):
            yield {}
            raise MODULE.Unavailable("cleanup_failure")

        outcome = capture.CaptureOutcome(b"secret", CANARY.encode(), 0, 6, len(CANARY))
        args = ["collect", *self.args[1:], "--deadline", repr(time.monotonic() + 8)]
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(MODULE, "client_context"), patch.object(MODULE, "command", return_value=(sys.executable,)), \
                patch.object(capture.CaptureContext, "private_outputs", failed_cleanup), \
                patch.object(capture.CaptureContext, "capture_outcome", return_value=outcome), \
                patch("signal.signal"), \
                patch("sys.stdout", output), patch("sys.stderr", errors):
            with self.assertRaisesRegex(MODULE.Unavailable, "cleanup_failure"):
                MODULE.collect(args)
        self.assertEqual((output.getvalue(), errors.getvalue()), ("", ""))

    def test_uncertainty_awaits_owner_and_contains_no_exception_text(self):
        errors = io.StringIO()
        with patch.object(MODULE, "collect", side_effect=MODULE.Unavailable(CANARY)), \
                patch.object(MODULE, "await_owner", side_effect=RuntimeError("held")) as await_owner, \
                patch("sys.stderr", errors):
            with self.assertRaisesRegex(RuntimeError, "held"):
                MODULE.main(["collect"])
        await_owner.assert_called_once()
        self.assertNotIn(CANARY, errors.getvalue())
        self.assertIn("collector_completion=unavailable", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
