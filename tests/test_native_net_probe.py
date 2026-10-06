"""Closed outer-network probe identity, namespace pin, and argument checks."""

import importlib.util
import contextlib
import errno
import io
import socket
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/native-net-probe.py"
SPEC = importlib.util.spec_from_file_location("dockerlens_native_net_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROBE
SPEC.loader.exec_module(PROBE)


class NativeNetProbeTests(unittest.TestCase):
    def test_http_probe_disables_default_config_as_first_curl_option(self) -> None:
        url = "http://127.0.0.1:18110/index.html"
        self.assertEqual(PROBE.probe_command("http", url), [
            "curl", "-q", "--noproxy", "*", "--proxy", "", "--globoff", "--fail",
            "--silent", "--show-error", "--connect-timeout", "2", "--max-time", "3",
            "--max-filesize", "8192", url,
        ])

    def test_tcp6_boundary_accepts_only_exact_kernel_refusal(self) -> None:
        self.assertEqual(PROBE.probe_command("tcp6_refusal", "18112"),
                         [sys.executable, "-c", PROBE.TCP6_REFUSAL_SCRIPT, "18112"])
        for invalid in (None, "0", "65536", "private", "18112;touch /tmp/private"):
            with self.subTest(invalid=invalid), self.assertRaises(PROBE.ProbeFailure):
                PROBE.probe_command("tcp6_refusal", invalid)
        for result, expected, status in (
            (errno.ECONNREFUSED, "refused", 0), (0, "connected", 1),
            (errno.ETIMEDOUT, "timeout", 1), (errno.ENETUNREACH, "other", 1),
            (errno.EACCES, "other", 1), (OSError("private-canary"), "other", 1),
        ):
            with self.subTest(result=result), mock.patch.object(socket, "socket") as factory:
                connection = factory.return_value.__enter__.return_value
                if isinstance(result, Exception):
                    connection.connect_ex.side_effect = result
                else:
                    connection.connect_ex.return_value = result
                output = io.StringIO()
                with mock.patch.object(sys, "argv", [str(SCRIPT), "18112"]), \
                     contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exited:
                    exec(PROBE.TCP6_REFUSAL_SCRIPT, {})
                self.assertEqual(exited.exception.code, status)
                self.assertEqual(output.getvalue(), expected + "\n")
                connection.settimeout.assert_called_once_with(3)
                connection.connect_ex.assert_called_once_with(("::1", 18112))

    def test_ipv6_socket_diagnostic_is_fixed_and_closed(self) -> None:
        self.assertEqual(PROBE.probe_command("ipv6_socket", None),
                         [sys.executable, "-c", PROBE.IPV6_SOCKET_SCRIPT])
        with self.assertRaises(PROBE.ProbeFailure):
            PROBE.probe_command("ipv6_socket", "private-input")
        for failed_stage, expected in (
            ("socket", "tcp6_unavailable"),
            ("bind", "bind_unavailable"),
            ("connect", "loopback_unavailable"),
            (None, "available"),
        ):
            with self.subTest(failed_stage=failed_stage):
                listener = mock.MagicMock()
                listener.__enter__.return_value = listener
                listener.getsockname.return_value = ("::1", 54321, 0, 0)
                client = mock.MagicMock()
                client.__enter__.return_value = client
                accepted = mock.MagicMock()
                listener.accept.return_value = (accepted, ("::1", 54321, 0, 0))
                if failed_stage == "bind":
                    listener.bind.side_effect = OSError("private-canary")
                if failed_stage == "connect":
                    client.connect.side_effect = OSError("private-canary")
                side_effect = (OSError("private-canary") if failed_stage == "socket"
                               else [listener, client])
                with mock.patch.object(socket, "socket", side_effect=side_effect) as factory:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        exec(PROBE.IPV6_SOCKET_SCRIPT, {})
                self.assertEqual(output.getvalue(), expected + "\n")
                factory.assert_called_with(socket.AF_INET6, socket.SOCK_STREAM)
                if failed_stage != "socket":
                    listener.bind.assert_called_once_with(("::1", 0))
                if failed_stage in ("connect", None):
                    client.connect.assert_called_once_with(("::1", 54321))
                if failed_stage is None:
                    accepted.close.assert_called_once_with()

    def test_tcp_isolation_accepts_only_kernel_connection_refusal(self) -> None:
        self.assertEqual(PROBE.probe_command("tcp_refusal", None),
                         [sys.executable, "-c", PROBE.TCP_REFUSAL_SCRIPT])
        with self.assertRaises(PROBE.ProbeFailure):
            PROBE.probe_command("tcp_refusal", "private-input")
        for result, expected, status in (
            (errno.ECONNREFUSED, "refused", 0), (0, "connected", 1),
            (errno.ETIMEDOUT, "timeout", 1), (errno.EHOSTUNREACH, "other", 1),
            (errno.EACCES, "other", 1), (OSError("private-canary"), "other", 1),
        ):
            with self.subTest(result=result), mock.patch.object(socket, "socket") as factory:
                connection = factory.return_value.__enter__.return_value
                if isinstance(result, Exception):
                    connection.connect_ex.side_effect = result
                else:
                    connection.connect_ex.return_value = result
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exited:
                    exec(PROBE.TCP_REFUSAL_SCRIPT, {})
                self.assertEqual(exited.exception.code, status)
                self.assertEqual(output.getvalue(), expected + "\n")
                connection.settimeout.assert_called_once_with(3)
                connection.connect_ex.assert_called_once_with(("127.0.0.2", 18110))

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
            ), mock.patch.object(PROBE.os, "fstat", return_value=SimpleNamespace(st_dev=5, st_ino=201)), mock.patch.object(
                PROBE.os, "stat", return_value=SimpleNamespace(st_dev=5, st_ino=101)
            ), mock.patch.object(PROBE.os, "close") as closed:
                with self.assertRaises(PROBE.ProbeFailure) as failed:
                    PROBE.verified_process(self.outer, self.run_id, self.expected)
                self.assertEqual(failed.exception.category, "changed" if isinstance(second, tuple) else "inspect")
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

    def test_same_host_namespace_refuses_identity_publication_and_nsenter(self) -> None:
        cached = PROBE.Identity(*self.expected, 777)
        for arguments in ([str(SCRIPT), "identity", self.outer],
                          [str(SCRIPT), "http", self.outer, cached.token(), "http://127.0.0.1:18110/index.html"]):
            with self.subTest(mode=arguments[1]), mock.patch.object(sys, "argv", arguments), \
                    mock.patch.object(PROBE, "inspect", return_value=self.expected), \
                    mock.patch.object(PROBE.os, "open", side_effect=[10, 11]), \
                    mock.patch.object(PROBE, "process_start_ticks", return_value=777), \
                    mock.patch.object(PROBE.os, "fstat", return_value=SimpleNamespace(st_dev=5, st_ino=101)), \
                    mock.patch.object(PROBE.os, "stat", return_value=SimpleNamespace(st_dev=5, st_ino=101)), \
                    mock.patch.object(PROBE.os, "close") as closed, \
                    mock.patch.object(PROBE.shutil, "which", return_value="/tool"), \
                    mock.patch.object(PROBE.subprocess, "run") as launched, \
                    contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(PROBE.ProbeFailure) as failed:
                PROBE.main()
            self.assertEqual(failed.exception.category, "identity")
            self.assertEqual(output.getvalue(), "")
            launched.assert_not_called()
            self.assertEqual(closed.call_args_list, [mock.call(10), mock.call(11)])

    def test_distinct_kernel_namespace_identity_retains_pinned_route_and_brackets(self) -> None:
        cached = PROBE.Identity(*self.expected, 777)
        for held in (SimpleNamespace(st_dev=5, st_ino=201), SimpleNamespace(st_dev=6, st_ino=101)):
            with self.subTest(device=held.st_dev), \
                    mock.patch.object(sys, "argv", [str(SCRIPT), "http", self.outer, cached.token(), "http://127.0.0.1:18110/index.html"]), \
                    mock.patch.object(PROBE, "inspect", return_value=self.expected) as inspected, \
                    mock.patch.object(PROBE.os, "open", side_effect=[10, 11]) as opened, \
                    mock.patch.object(PROBE, "process_start_ticks", return_value=777), \
                    mock.patch.object(PROBE.os, "fstat", return_value=held) as held_stat, \
                    mock.patch.object(PROBE.os, "stat", return_value=SimpleNamespace(st_dev=5, st_ino=101)) as host_stat, \
                    mock.patch.object(PROBE.os, "close") as closed, \
                    mock.patch.object(PROBE.shutil, "which", return_value="/tool"), \
                    mock.patch.object(PROBE.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as launched:
                self.assertEqual(PROBE.main(), 0)
            held_stat.assert_called_once_with(11)
            host_stat.assert_called_once_with("/proc/self/ns/net")
            self.assertEqual(opened.call_args_list[1].kwargs["dir_fd"], 10)
            self.assertEqual(inspected.call_count, 3)
            self.assertEqual(launched.call_args.args[0][:3], ["nsenter", "--net=/proc/self/fd/11", "--"])
            self.assertEqual(launched.call_args.kwargs["pass_fds"], (11,))
            self.assertEqual(closed.call_args_list, [mock.call(10), mock.call(11)])

    def test_unavailable_or_invalid_namespace_witness_closes_fd_and_never_nsenter(self) -> None:
        cached = PROBE.Identity(*self.expected, 777)
        cases = ((OSError("private-held"), SimpleNamespace(st_dev=5, st_ino=101)),
                 (SimpleNamespace(st_dev=5, st_ino=201), FileNotFoundError("private-host")),
                 (SimpleNamespace(st_dev=5, st_ino=201), OSError("private-host")),
                 (SimpleNamespace(st_dev=0, st_ino=201), SimpleNamespace(st_dev=5, st_ino=101)),
                 (SimpleNamespace(st_dev=5, st_ino=201), SimpleNamespace(st_dev=5, st_ino=0)),
                 (SimpleNamespace(st_dev=True, st_ino=201), SimpleNamespace(st_dev=5, st_ino=101)))
        for held, host in cases:
            with self.subTest(held=type(held), host=type(host)), \
                    mock.patch.object(sys, "argv", [str(SCRIPT), "http", self.outer, cached.token(), "http://127.0.0.1:18110/index.html"]), \
                    mock.patch.object(PROBE, "inspect", return_value=self.expected), \
                    mock.patch.object(PROBE.os, "open", side_effect=[10, 11]), \
                    mock.patch.object(PROBE, "process_start_ticks", return_value=777), \
                    mock.patch.object(PROBE.os, "fstat", side_effect=held if isinstance(held, Exception) else None, return_value=held), \
                    mock.patch.object(PROBE.os, "stat", side_effect=host if isinstance(host, Exception) else None, return_value=host), \
                    mock.patch.object(PROBE.os, "close") as closed, \
                    mock.patch.object(PROBE.shutil, "which", return_value="/tool"), \
                    mock.patch.object(PROBE.subprocess, "run") as launched, self.assertRaises(PROBE.ProbeFailure) as failed:
                PROBE.main()
            self.assertEqual(failed.exception.category, "identity")
            launched.assert_not_called()
            self.assertEqual(closed.call_args_list, [mock.call(10), mock.call(11)])

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

    def test_ipv6_socket_uses_the_same_pinned_outer_namespace(self) -> None:
        cached = PROBE.Identity(*self.expected, 777)
        with mock.patch.object(
            sys, "argv", [str(SCRIPT), "ipv6_socket", self.outer, cached.token()]
        ), mock.patch.object(
            PROBE, "verified_process", return_value=(777, 11)
        ), mock.patch.object(
            PROBE, "inspect", return_value=self.expected
        ), mock.patch.object(
            PROBE.shutil, "which", return_value="/usr/bin/tool"
        ), mock.patch.object(
            PROBE.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
        ) as launched, mock.patch.object(PROBE.os, "close") as closed:
            self.assertEqual(PROBE.main(), 0)
            args, kwargs = launched.call_args
            self.assertEqual(args[0][:3], ["nsenter", "--net=/proc/self/fd/11", "--"])
            self.assertEqual(args[0][3:], [sys.executable, "-c", PROBE.IPV6_SOCKET_SCRIPT])
            self.assertEqual(kwargs["pass_fds"], (11,))
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
