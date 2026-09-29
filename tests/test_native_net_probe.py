"""Closed outer-network probe identity, namespace pin, and argument checks."""

import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/native-net-probe.py"
SPEC = importlib.util.spec_from_file_location("dockerlens_native_net_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROBE
SPEC.loader.exec_module(PROBE)


class NativeNetProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.outer = "dl-native-Safe123"
        self.run_id = "Safe123"
        self.container_id = "a" * 64
        self.started = "2026-09-29T02:00:00+00:00"
        self.expected = (self.container_id, 4321, self.started)

    def inspect_output(self, *, pid: str = "4321", running: str = "true",
                       label: str = "Safe123") -> str:
        return f"{self.container_id}|{pid}|{self.started}|{running}|{label}\n"

    @staticmethod
    def fake_podman(directory: Path) -> None:
        path = directory / "podman"
        path.write_text("""#!/usr/bin/env python3
import os
import sys
import time
with open(os.environ['TEST_PIDFILE'], 'w') as pidfile:
    pidfile.write(str(os.getpid()))
mode = os.environ['TEST_INSPECT_MODE']
if mode == 'normal':
    sys.stdout.write(os.environ['TEST_INSPECT_LINE'])
elif mode == 'overflow':
    sys.stdout.write('x' * 513)
    sys.stdout.flush()
    time.sleep(30)
else:
    time.sleep(30)
""")
        path.chmod(0o755)

    def test_inspect_requires_exact_running_label_and_numeric_pid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.fake_podman(Path(directory))
            for output, valid in (
            (self.inspect_output(), True),
            (self.inspect_output(pid="0"), False),
            (self.inspect_output(pid="private"), False),
            (self.inspect_output(running="false"), False),
            (self.inspect_output(label="other-run"), False),
            ):
                with self.subTest(output=output), mock.patch.dict(os.environ, {
                    "PATH": f"{directory}:{os.environ['PATH']}",
                    "TEST_PIDFILE": str(Path(directory) / "pid"),
                    "TEST_INSPECT_MODE": "normal", "TEST_INSPECT_LINE": output,
                }):
                    if valid:
                        self.assertEqual(PROBE.inspect(self.outer, self.run_id), self.expected)
                    else:
                        with self.assertRaises(PROBE.ProbeFailure):
                            PROBE.inspect(self.outer, self.run_id)

    def test_inspect_kills_and_reaps_oversized_or_stalled_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.fake_podman(Path(directory))
            pidfile = Path(directory) / "pid"
            for mode in ("overflow", "timeout"):
                with self.subTest(mode=mode), mock.patch.dict(os.environ, {
                    "PATH": f"{directory}:{os.environ['PATH']}",
                    "TEST_PIDFILE": str(pidfile), "TEST_INSPECT_MODE": mode,
                    "TEST_INSPECT_LINE": "",
                }):
                    start = time.monotonic()
                    with self.assertRaises(PROBE.ProbeFailure):
                        PROBE.inspect(self.outer, self.run_id)
                    self.assertLess(time.monotonic() - start, 3)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(int(pidfile.read_text()), 0)

    def test_identity_token_is_closed_and_rejects_wrong_pid_or_source(self) -> None:
        token = PROBE.Identity(*self.expected, 777).token()
        self.assertEqual(PROBE.parse_token(token), PROBE.Identity(*self.expected, 777))
        for invalid in (token.replace("|4321|", "|0|"), token.replace("a" * 64, "private"),
                        token.replace("|777", "|0"), token + "|extra"):
            with self.subTest(invalid=invalid), self.assertRaises(PROBE.ProbeFailure):
                PROBE.parse_token(invalid)

    def test_only_closed_host_commands_and_loopback_targets_are_constructed(self) -> None:
        self.assertEqual(PROBE.probe_command("curl_version", None), ["curl", "--version"])
        self.assertEqual(PROBE.probe_command("bash_version", None), ["bash", "--version"])
        self.assertEqual(PROBE.probe_command("udp", "18113")[-3:],
                         ["udp-probe", "native-udp-canary", "18113"])
        for invalid in ("0", "65536", "8;touch /tmp/private", "-1"):
            with self.subTest(invalid=invalid), self.assertRaises(PROBE.ProbeFailure):
                PROBE.probe_command("udp", invalid)
        for valid in ("http://127.0.0.1:18110/index.html",
                      "http://127.0.0.2:18111/index.html",
                      "http://[::1]:18112/index.html"):
            self.assertEqual(PROBE.probe_command("http", valid)[-1], valid)
        for invalid in ("http://example.com:80/index.html", "http://127.0.0.3:80/index.html",
                        "http://127.0.0.1:80/private", "http://127.0.0.1:65536/index.html"):
            with self.subTest(invalid=invalid), self.assertRaises(PROBE.ProbeFailure):
                PROBE.probe_command("http", invalid)

    def test_verified_process_closes_pinned_fd_on_identity_change_or_exit(self) -> None:
        for second in (("other", 4321, self.started), PROBE.ProbeFailure("inspect")):
            with self.subTest(second=second), mock.patch.object(
                PROBE, "inspect", side_effect=[self.expected, second]
            ), mock.patch.object(PROBE.os, "open", side_effect=[10, 11]) as opened, mock.patch.object(
                PROBE, "process_start_ticks", return_value=777
            ), mock.patch.object(PROBE.os, "close") as closed:
                with self.assertRaises(PROBE.ProbeFailure):
                    PROBE.verified_process(self.outer, self.run_id, self.expected)
                self.assertEqual(opened.call_args_list[0].args[0], "/proc/4321")
                self.assertEqual(opened.call_args_list[1].args[0], "ns/net")
                self.assertEqual(opened.call_args_list[1].kwargs["dir_fd"], 10)
                closed.assert_any_call(11)

    def test_proc_start_ticks_require_same_live_pid(self) -> None:
        fields = ["S", *(["0"] * 18), "777"]
        stat = f"4321 (outer launch) {' '.join(fields)}\n".encode()
        with mock.patch.object(PROBE.os, "open", return_value=12), mock.patch.object(
            PROBE.os, "read", return_value=stat
        ), mock.patch.object(PROBE.os, "close"):
            self.assertEqual(PROBE.process_start_ticks(10, 4321), 777)
            with self.assertRaises(PROBE.ProbeFailure):
                PROBE.process_start_ticks(10, 4322)
        fields[0] = "Z"
        stat = f"4321 (outer launch) {' '.join(fields)}\n".encode()
        with mock.patch.object(PROBE.os, "open", return_value=12), mock.patch.object(
            PROBE.os, "read", return_value=stat
        ), mock.patch.object(PROBE.os, "close"):
            with self.assertRaises(PROBE.ProbeFailure):
                PROBE.process_start_ticks(10, 4321)

    def test_cached_pid_start_mismatch_prevents_nsenter(self) -> None:
        cached = PROBE.Identity(*self.expected, 777)
        with mock.patch.object(sys, "argv", [str(SCRIPT), "http", self.outer, cached.token(),
                                             "http://127.0.0.1:18110/index.html"]), mock.patch.object(
            PROBE, "verified_process", return_value=(778, 11)
        ), mock.patch.object(PROBE, "inspect") as inspect, mock.patch.object(
            PROBE.shutil, "which", return_value="/usr/bin/tool"
        ), mock.patch.object(PROBE.subprocess, "run") as launched, mock.patch.object(
            PROBE.os, "close"
        ) as closed:
            with self.assertRaises(PROBE.ProbeFailure):
                PROBE.main()
            inspect.assert_not_called()
            launched.assert_not_called()
            closed.assert_called_with(11)

    def test_nsenter_receives_held_fd_and_after_readback_must_match(self) -> None:
        cached = PROBE.Identity(*self.expected, 777)
        for after, valid in ((self.expected, True), (("other", 4321, self.started), False)):
            with self.subTest(valid=valid), mock.patch.object(
                sys, "argv", [str(SCRIPT), "http", self.outer, cached.token(),
                              "http://127.0.0.1:18110/index.html"]
            ), mock.patch.object(PROBE, "verified_process", return_value=(777, 11)), mock.patch.object(
                PROBE, "inspect", return_value=after
            ), mock.patch.object(PROBE.shutil, "which", return_value="/usr/bin/tool"), mock.patch.object(
                PROBE.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
            ) as launched, mock.patch.object(PROBE.os, "close") as closed:
                if valid:
                    self.assertEqual(PROBE.main(), 0)
                else:
                    with self.assertRaises(PROBE.ProbeFailure):
                        PROBE.main()
                args, kwargs = launched.call_args
                self.assertEqual(args[0][:3], ["nsenter", "--net=/proc/self/fd/11", "--"])
                self.assertEqual(kwargs["pass_fds"], (11,))
                closed.assert_called_with(11)


if __name__ == "__main__":
    unittest.main()
