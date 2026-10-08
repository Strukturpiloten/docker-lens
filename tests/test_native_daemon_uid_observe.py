"""Hermetic daemon-UID observation controls; no subprocess or native evidence.

This module is intended for tests/test_native_daemon_uid_observe.py. Every
process, stream, selector event, clock tick and syscall below is synthetic.
Neither these controls nor parser success establish Docker compatibility.
"""

import contextlib
import errno
import importlib.util
import io
import runpy
import signal
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "uid_observe_spec", ROOT / "scripts/native-daemon-uid.py"
)
UID_OBSERVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UID_OBSERVE)

OUTER = "ab" * 32  # Synthetic selector only; never a native ID.
CANARY = "DO_NOT_DUMP_UID_OBSERVE_PRIVATE_CANARY"
REFUSAL = "native daemon UID evidence rejected"


class FakeStream:
    def __init__(self, name, descriptor, chunks, events):
        self.name = name
        self.descriptor = descriptor
        self.chunks = list(chunks)
        self.events = events
        self.closed = False
        self.close_count = 0

    def fileno(self):
        if self.closed:
            raise AssertionError("closed synthetic descriptor")
        return self.descriptor

    def close(self):
        self.events.append(("close", self.name))
        self.closed = True
        self.close_count += 1


class FakeProcess:
    def __init__(self, stdout, stderr, waits, events, returncode=None):
        self.stdout = stdout
        self.stderr = stderr
        self.pid = 910  # Only ever passed to mocked killpg.
        self.returncode = returncode
        self.waits = list(waits)
        self.wait_calls = []
        self.events = events

    def wait(self, *, timeout):
        if not 0 < timeout <= 12:
            raise AssertionError("unbounded synthetic wait")
        self.wait_calls.append(timeout)
        self.events.append(("wait", timeout))
        outcome = self.waits.pop(0) if self.waits else 0
        if isinstance(outcome, BaseException):
            raise outcome
        self.returncode = outcome
        return outcome


class FakeClock:
    def __init__(self, values=None):
        self.values = list(values) if values is not None else None
        self.tick = 0

    def monotonic(self):
        if self.values is not None:
            if not self.values:
                raise AssertionError("unexpected synthetic clock read")
            return self.values.pop(0)
        value = self.tick / 64
        self.tick += 1
        return value


class FakeSelector:
    def __init__(self, events, selections=None, register_error=None, select_error=None):
        self.events = events
        self.selections = list(selections) if selections is not None else None
        self.register_error = register_error
        self.select_error = select_error
        self.keys = {}
        self.registrations = []
        self.unregistered = []
        self.select_calls = []
        self.closed = False

    def __enter__(self):
        self.events.append(("selector_enter",))
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.events.append(("selector_close",))
        self.closed = True

    def register(self, stream, mask, data):
        self.registrations.append((stream.name, mask, data))
        if self.register_error is not None:
            raise self.register_error
        self.keys[stream.descriptor] = types.SimpleNamespace(fileobj=stream, data=data)

    def unregister(self, stream):
        self.unregistered.append(stream.name)
        del self.keys[stream.descriptor]

    def get_map(self):
        return self.keys

    def select(self, timeout):
        if not 0 <= timeout <= 0.1:
            raise AssertionError("unbounded synthetic select")
        self.select_calls.append(timeout)
        if self.select_error is not None:
            raise self.select_error
        names = self.selections.pop(0) if self.selections else (
            () if self.selections is not None else tuple(key.data for key in self.keys.values())
        )
        return [(key, UID_OBSERVE.selectors.EVENT_READ)
                for key in self.keys.values() if key.data in names]


class ObservationHarness:
    def __init__(self, stdout=(b"0\n", b""), stderr=(b"",), waits=(0,),
                 selections=None, clock_values=None, spawn_error=None, read_error=None,
                 blocking_error=None, register_error=None, select_error=None, selector_error=None,
                 kill_error=None, initial_returncode=None, host_uid=1000):
        self.events = []
        self.stdout = FakeStream("stdout", 101, stdout, self.events)
        self.stderr = FakeStream("stderr", 102, stderr, self.events)
        self.process = FakeProcess(self.stdout, self.stderr, waits, self.events, initial_returncode)
        self.selector = FakeSelector(self.events, selections, register_error, select_error)
        self.clock = FakeClock(clock_values)
        self.spawn_error = spawn_error
        self.read_error = read_error
        self.blocking_error = blocking_error
        self.selector_error = selector_error
        self.kill_error = kill_error
        self.host_uid = host_uid
        self.read_calls = []
        self.blocking_calls = []
        self.output = io.StringIO()
        self.error_output = io.StringIO()

    def spawn(self, *_args, **_kwargs):
        self.events.append(("spawn",))
        if self.spawn_error is not None:
            raise self.spawn_error
        return self.process

    def set_blocking(self, descriptor, blocking):
        self.blocking_calls.append((descriptor, blocking))
        if descriptor not in (101, 102) or blocking is not False:
            raise AssertionError("unexpected synthetic blocking change")
        if self.blocking_error is not None:
            raise self.blocking_error

    def make_selector(self):
        if self.selector_error is not None:
            raise self.selector_error
        return self.selector

    def read(self, descriptor, count):
        if descriptor not in (101, 102) or count != 256:
            raise AssertionError("unexpected synthetic read")
        self.read_calls.append((descriptor, count))
        if self.read_error is not None:
            raise self.read_error
        stream = self.stdout if descriptor == 101 else self.stderr
        if not stream.chunks:
            raise AssertionError("unplanned synthetic stream read")
        data = stream.chunks.pop(0)
        if len(data) > count:
            raise AssertionError("synthetic chunk exceeds read size")
        return data

    def killpg(self, pid, sig):
        if pid != self.process.pid or sig != signal.SIGKILL:
            raise AssertionError("unexpected synthetic kill target")
        self.events.append(("kill", pid, sig, self.process.returncode))
        if self.kill_error is not None:
            raise self.kill_error

    def __enter__(self):
        self.stack = contextlib.ExitStack()
        self.stack.__enter__()
        self.popen = self.stack.enter_context(
            patch.object(UID_OBSERVE.subprocess, "Popen", side_effect=self.spawn))
        self.factory = self.stack.enter_context(
            patch.object(UID_OBSERVE.selectors, "DefaultSelector", side_effect=self.make_selector))
        self.stack.enter_context(patch.object(UID_OBSERVE.os, "geteuid", return_value=self.host_uid))
        self.stack.enter_context(patch.object(UID_OBSERVE.os, "set_blocking", side_effect=self.set_blocking))
        self.stack.enter_context(patch.object(UID_OBSERVE.os, "read", side_effect=self.read))
        self.kill = self.stack.enter_context(
            patch.object(UID_OBSERVE.os, "killpg", side_effect=self.killpg))
        self.stack.enter_context(patch.object(UID_OBSERVE.time, "monotonic", side_effect=self.clock.monotonic))
        self.parse = self.stack.enter_context(patch.object(UID_OBSERVE, "uid", wraps=UID_OBSERVE.uid))
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        self.stack.enter_context(contextlib.redirect_stderr(self.error_output))
        return self

    def __exit__(self, kind, value, traceback):
        return self.stack.__exit__(kind, value, traceback)

    def cli(self, mode="rootful"):
        # The newly executed module imports the same patched stdlib modules;
        # it cannot spawn, select, read, signal or consult the real host clock.
        with patch.object(sys, "argv", ["native-daemon-uid.py", OUTER, mode]):
            return runpy.run_path(str(ROOT / "scripts/native-daemon-uid.py"), run_name="__main__")


class DaemonUidObserveTests(unittest.TestCase):
    def assert_closed(self, harness, *, selector=True):
        self.assertTrue(harness.stdout.closed)
        self.assertTrue(harness.stderr.closed)
        self.assertEqual((harness.stdout.close_count, harness.stderr.close_count), (1, 1))
        if selector:
            self.assertTrue(harness.selector.closed)
        self.assertEqual(harness.output.getvalue(), "")
        self.assertEqual(harness.error_output.getvalue(), "")
        for event in harness.events:
            if event[0] == "kill":
                self.assertIsNone(event[3])

    def assert_refused(self, harness, exception=ValueError, reason=None, *, parsed=False, selector=True):
        with harness:
            with self.assertRaises(exception) as refused:
                UID_OBSERVE.observe(OUTER, "rootful")
            if reason is not None:
                self.assertEqual(str(refused.exception), reason)
                self.assertNotIn(CANARY, str(refused.exception))
                self.assertNotIn(OUTER, str(refused.exception))
            if not parsed:
                harness.parse.assert_not_called()
        self.assert_closed(harness, selector=selector)

    def test_completed_valid_outputs_both_modes_and_independent_eof_order(self):
        for index, (mode, chunks, expected, selections) in enumerate((
            ("rootful", (b"0\n", b""), 0, None),
            ("rootless", (b"1", b"000", b"\n", b""), 1000,
             [("stderr",), ("stdout",), ("stdout",), ("stdout",), ("stdout",)]),
            ("rootless", (b"4294967295\n", b""), 4294967295, None),
        )):
            with self.subTest(case=index):
                harness = ObservationHarness(stdout=chunks, selections=selections)
                with harness:
                    self.assertEqual(UID_OBSERVE.observe(OUTER, mode), expected)
                    harness.parse.assert_called_once_with(b"".join(chunks), b"", 0, mode)
                    harness.kill.assert_not_called()
                self.assert_closed(harness)
                self.assertEqual(set(harness.selector.unregistered), {"stdout", "stderr"})
                self.assertEqual(len(harness.process.wait_calls), 1)
                self.assertEqual(harness.blocking_calls, [(101, False), (102, False)])

    def test_spawn_uses_fixed_root_owned_timeout_and_separate_bounded_pipes(self):
        for host_uid in (0, 1000):
            harness = ObservationHarness(host_uid=host_uid)
            with harness:
                self.assertEqual(UID_OBSERVE.observe(OUTER, "rootful"), 0)
                arguments, keywords = harness.popen.call_args
                prefix = [] if host_uid == 0 else ["sudo", "-n"]
                self.assertEqual(arguments[0][:-1], prefix + [
                    "timeout", "--signal=TERM", "--kill-after=2s", "8s",
                    "podman", "exec", OUTER, "sh", "-ec"])
                self.assertEqual(keywords, {"stdin": subprocess.DEVNULL,
                                           "stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
                                           "start_new_session": True})
            self.assert_closed(harness)

    def test_stdout_bound_is_aggregate_across_many_small_chunks(self):
        for chunks in ((b"0\n" + b"x" * 30, b"x", b""),
                       tuple(b"x" for _ in range(33)) + (b"",)):
            harness = ObservationHarness(stdout=chunks)
            self.assert_refused(harness, reason="daemon UID output bound")
            harness.kill.assert_called_once_with(910, signal.SIGKILL)
            self.assertEqual(harness.process.wait_calls, [12])

    def test_stderr_bound_is_aggregate_and_cannot_be_hidden_by_valid_stdout(self):
        harness = ObservationHarness(stderr=(b"x" * 256,) * 16 + (b"x", b""))
        self.assert_refused(harness, reason="daemon UID output bound")
        self.assertEqual(len([call for call in harness.read_calls if call[0] == 102]), 17)
        self.assertEqual(harness.process.wait_calls, [12])

    def test_exact_byte_caps_do_not_overflow_but_still_require_valid_evidence(self):
        for harness in (
            ObservationHarness(stdout=(b"1" * 31 + b"\n", b"")),
            ObservationHarness(stderr=(b"x" * 256,) * 16 + (b"",)),
            ObservationHarness(stderr=(b"x" * 256,) * 15 + (b"x" * 255, b"")),
        ):
            self.assert_refused(harness, reason="invalid daemon UID evidence", parsed=True)
            harness.parse.assert_called_once()
            harness.kill.assert_not_called()

    def test_nonzero_completion_never_becomes_uid_and_does_not_kill_exited_process(self):
        for status in (1, 124, 137, -9):
            harness = ObservationHarness(waits=(status,))
            self.assert_refused(harness, reason="invalid daemon UID evidence", parsed=True)
            self.assertEqual(harness.process.returncode, status)
            self.assertEqual(len(harness.process.wait_calls), 1)
            harness.kill.assert_not_called()

    def test_stderr_or_malformed_stdout_is_refused_after_completed_eof(self):
        cases = [ObservationHarness(stderr=(CANARY.encode(), b""))]
        cases.extend(ObservationHarness(stdout=(value, b"")) for value in (
            b"", b"0", b"00\n", b"0\n0\n", b"-1\n", b"4294967296\n",
            b"1000\n", b"\xff\n", b"0\r\n", b" 0\n", b"0\x00\n"))
        for index, harness in enumerate(cases):
            with self.subTest(case=index):
                self.assert_refused(harness, reason="invalid daemon UID evidence", parsed=True)
                harness.kill.assert_not_called()

    def test_deadline_refuses_missing_eof_on_either_pipe_and_no_ready_events(self):
        for selections, stdout, stderr in (
            ([], (), ()),
            ([("stdout",)], (b"0\n",), ()),
            ([("stdout",), ("stdout",)], (b"0\n", b""), ()),
            ([("stderr",)], (), (b"",)),
        ):
            harness = ObservationHarness(stdout=stdout, stderr=stderr, selections=selections)
            self.assert_refused(harness, reason="daemon UID deadline")
            self.assertLessEqual(len(harness.selector.select_calls), 384)
            self.assertEqual(harness.process.wait_calls, [12])

    def test_deadline_at_boundary_prevents_read_and_still_closes_both_pipes(self):
        harness = ObservationHarness(clock_values=[100, 112])
        self.assert_refused(harness, reason="daemon UID deadline")
        self.assertEqual(harness.read_calls, [])
        self.assertEqual(harness.selector.select_calls, [])
        self.assertEqual(harness.process.wait_calls, [12])

    def test_deadline_after_both_eof_refuses_before_status_wait_or_uid_parse(self):
        harness = ObservationHarness(clock_values=[100, 101, 102, 103, 104, 112])
        self.assert_refused(harness, reason="daemon UID deadline")
        self.assertEqual(harness.read_calls, [(101, 256), (102, 256), (101, 256)])
        self.assertEqual(harness.selector.unregistered, ["stderr", "stdout"])
        self.assertEqual(harness.selector.get_map(), {})
        harness.parse.assert_not_called()
        harness.kill.assert_called_once_with(910, signal.SIGKILL)
        self.assertEqual(harness.process.wait_calls, [12])
        self.assertEqual(harness.clock.values, [])

    def test_initial_spawn_error_has_no_created_descriptors_or_cleanup_calls(self):
        harness = ObservationHarness(spawn_error=OSError(errno.EIO, CANARY))
        with harness:
            with self.assertRaises(OSError):
                UID_OBSERVE.observe(OUTER, "rootful")
            harness.factory.assert_not_called()
            harness.kill.assert_not_called()
            harness.parse.assert_not_called()
        self.assertEqual(harness.read_calls, [])
        self.assertEqual(harness.process.wait_calls, [])
        self.assertFalse(harness.stdout.closed)
        self.assertFalse(harness.stderr.closed)
        self.assertEqual(harness.output.getvalue(), "")
        self.assertEqual(harness.error_output.getvalue(), "")

    def test_initial_registration_blocking_selector_and_read_errors_close_all_pipes(self):
        for options in (
            {"blocking_error": OSError(errno.EIO, CANARY)},
            {"register_error": OSError(errno.EIO, CANARY)},
            {"select_error": OSError(errno.EIO, CANARY)},
            {"read_error": OSError(errno.EIO, CANARY)},
        ):
            harness = ObservationHarness(**options)
            self.assert_refused(harness, exception=OSError)
            self.assertEqual(harness.process.wait_calls, [12])
            harness.kill.assert_called_once_with(910, signal.SIGKILL)

    def test_initial_selector_creation_error_still_cleans_process_and_closes_streams(self):
        harness = ObservationHarness(selector_error=OSError(errno.EIO, CANARY))
        self.assert_refused(harness, exception=OSError, selector=False)
        self.assertFalse(harness.selector.closed)
        self.assertEqual(harness.blocking_calls, [])
        self.assertEqual(harness.read_calls, [])
        self.assertEqual(harness.process.wait_calls, [12])
        harness.kill.assert_called_once_with(910, signal.SIGKILL)

    def test_status_wait_error_or_timeout_never_calls_parser_or_returns_success(self):
        for failure in (OSError(errno.EIO, CANARY), subprocess.TimeoutExpired(CANARY, 12)):
            harness = ObservationHarness(waits=(failure, 0))
            self.assert_refused(harness, exception=type(failure))
            self.assertEqual(len(harness.process.wait_calls), 2)
            self.assertEqual(harness.process.wait_calls[1], 12)
            harness.kill.assert_called_once_with(910, signal.SIGKILL)

    def test_kill_denial_or_vanished_group_and_cleanup_timeout_cannot_promote_failure(self):
        for kill_error in (PermissionError(errno.EPERM, CANARY),
                           ProcessLookupError(errno.ESRCH, CANARY)):
            for cleanup_error in (subprocess.TimeoutExpired(CANARY, 12), OSError(errno.EIO, CANARY)):
                harness = ObservationHarness(stdout=(b"x" * 33,), kill_error=kill_error,
                                             waits=(cleanup_error,))
                self.assert_refused(harness, reason="daemon UID output bound")
                harness.kill.assert_called_once_with(910, signal.SIGKILL)
                self.assertEqual(harness.process.wait_calls, [12])
                self.assertIsNone(harness.process.returncode)
                sequence = [event[0] for event in harness.events]
                self.assertLess(sequence.index("kill"), sequence.index("wait"))
                self.assertLess(sequence.index("wait"), sequence.index("close"))

    def test_failure_with_known_completed_returncode_skips_kill_but_still_refuses(self):
        for returncode in (0, 1, -9):
            harness = ObservationHarness(stdout=(b"x" * 33,), initial_returncode=returncode)
            self.assert_refused(harness, reason="daemon UID output bound")
            harness.kill.assert_not_called()
            self.assertEqual(harness.process.wait_calls, [])

    def test_cancellation_during_read_or_status_wait_refuses_and_closes_streams(self):
        for options in ({"read_error": KeyboardInterrupt()},
                        {"waits": (KeyboardInterrupt(), 0)}):
            harness = ObservationHarness(**options)
            self.assert_refused(harness, exception=KeyboardInterrupt)
            harness.kill.assert_called_once_with(910, signal.SIGKILL)
            self.assertEqual(harness.process.wait_calls[-1], 12)

    def test_cli_refuses_all_failure_classes_with_fixed_message_and_no_private_output(self):
        factories = (
            lambda: ObservationHarness(stdout=(b"private\n", b"")),
            lambda: ObservationHarness(stderr=(CANARY.encode(), b"")),
            lambda: ObservationHarness(waits=(124,)),
            lambda: ObservationHarness(stdout=(b"x" * 33,)),
            lambda: ObservationHarness(stderr=(b"x" * 256,) * 16 + (b"x",)),
            lambda: ObservationHarness(selections=[], stdout=(), stderr=()),
            lambda: ObservationHarness(spawn_error=OSError(errno.EIO, CANARY)),
            lambda: ObservationHarness(read_error=OSError(errno.EIO, CANARY)),
            lambda: ObservationHarness(blocking_error=OSError(errno.EIO, CANARY)),
            lambda: ObservationHarness(register_error=OSError(errno.EIO, CANARY)),
            lambda: ObservationHarness(select_error=OSError(errno.EIO, CANARY)),
            lambda: ObservationHarness(selector_error=OSError(errno.EIO, CANARY)),
            lambda: ObservationHarness(read_error=KeyboardInterrupt()),
            lambda: ObservationHarness(waits=(OSError(errno.EIO, CANARY), 0)),
            lambda: ObservationHarness(waits=(subprocess.TimeoutExpired(CANARY, 12),
                                              subprocess.TimeoutExpired(CANARY, 12))),
            lambda: ObservationHarness(stdout=(b"x" * 33,),
                                      kill_error=PermissionError(errno.EPERM, CANARY),
                                      waits=(subprocess.TimeoutExpired(CANARY, 12),)),
            lambda: ObservationHarness(stdout=(b"x" * 33,),
                                      kill_error=ProcessLookupError(errno.ESRCH, CANARY),
                                      waits=(subprocess.TimeoutExpired(CANARY, 12),)),
        )
        for index, factory in enumerate(factories):
            with self.subTest(case=index):
                harness = factory()
                with harness:
                    with self.assertRaises(SystemExit) as refused:
                        harness.cli()
                    self.assertEqual(refused.exception.code, REFUSAL)
                    self.assertNotIn(CANARY, str(refused.exception))
                    self.assertNotIn(OUTER, str(refused.exception))
                    self.assertTrue(refused.exception.__suppress_context__)
                if harness.spawn_error is None:
                    self.assert_closed(harness, selector=harness.selector_error is None)
                else:
                    self.assertEqual(harness.output.getvalue(), "")
                    self.assertEqual(harness.error_output.getvalue(), "")
