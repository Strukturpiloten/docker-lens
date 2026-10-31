#!/usr/bin/env python3
"""Closed namespace probes with explicit canonical outer-client context.

The Rust caller retains its original privilege-aware sixteen-second window.
Each raw inspect, including attach-only custody validation, retains the original
two-second/512-byte observation budget and one-second termination allowance.
"""

import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass


NAME = re.compile(r"dl-native-([A-Za-z0-9-]{1,64})\Z")
IDENTITY = re.compile(
    r"([0-9a-f]{64})\|([1-9][0-9]{0,9})\|([0-9a-f]{2,128})\|([1-9][0-9]{0,19})\Z"
)
URL = re.compile(r"http://(?:127\.0\.0\.[12]|\[::1\]):([1-9][0-9]{0,4})/index\.html\Z")
INSPECT_FORMAT = (
    '{{.Id}}|{{.State.Pid}}|{{.State.StartedAt}}|{{.State.Running}}|'
    '{{index .Config.Labels "io.dockerlens.native-run"}}'
)
TCP_REFUSAL_SCRIPT = """import errno, socket, sys
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        result = connection.connect_ex(('127.0.0.2', 18110))
except (OSError, TimeoutError):
    outcome = 'other'
else:
    outcome = ('refused' if result == errno.ECONNREFUSED else
               'connected' if result == 0 else
               'timeout' if result in (errno.ETIMEDOUT, errno.EAGAIN) else 'other')
print(outcome)
sys.exit(0 if outcome == 'refused' else 1)
"""
TCP6_REFUSAL_SCRIPT = """import errno, socket, sys
try:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        result = connection.connect_ex(('::1', int(sys.argv[1])))
except (OSError, TimeoutError):
    outcome = 'other'
else:
    outcome = ('refused' if result == errno.ECONNREFUSED else
               'connected' if result == 0 else
               'timeout' if result in (errno.ETIMEDOUT, errno.EAGAIN) else 'other')
print(outcome)
sys.exit(0 if outcome == 'refused' else 1)
"""
IPV6_SOCKET_SCRIPT = """import socket
outcome = 'tcp6_unavailable'
try:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
        outcome = 'bind_unavailable'
        listener.settimeout(1)
        listener.bind(('::1', 0))
        listener.listen(1)
        outcome = 'loopback_unavailable'
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect(('::1', listener.getsockname()[1]))
            accepted, _ = listener.accept()
            accepted.close()
            outcome = 'available'
except (OSError, TimeoutError):
    pass
print(outcome)
"""


class ProbeFailure(Exception):
    def __init__(self, category: str):
        self.category = category


@dataclass(frozen=True)
class Identity:
    container_id: str
    pid: int
    started_at: str
    start_ticks: int

    def token(self) -> str:
        started_hex = self.started_at.encode("ascii").hex()
        return f"{self.container_id}|{self.pid}|{started_hex}|{self.start_ticks}"


def parse_token(value: str) -> Identity:
    match = IDENTITY.fullmatch(value)
    if match is None:
        raise ProbeFailure("identity")
    container_id, pid, started_hex, ticks = match.groups()
    if int(pid) <= 1:
        raise ProbeFailure("identity")
    try:
        started_at = bytes.fromhex(started_hex).decode("ascii")
    except (UnicodeError, ValueError) as error:
        raise ProbeFailure("identity") from error
    if not started_at or any(ord(char) < 32 or char == "|" for char in started_at):
        raise ProbeFailure("identity")
    return Identity(container_id, int(pid), started_at, int(ticks))


def inspect(outer: str, run_id: str, engine: str, directory: str) -> tuple[str, int, str]:
    if engine not in ("podman", "docker") or not Path(directory).is_absolute():
        raise ProbeFailure("input")
    try:
        process = subprocess.Popen(
            ["timeout", "--signal=TERM", "--kill-after=1s", "2s", "bash",
             str(Path(__file__).resolve().with_name("native-outer-command.sh")),
             "--engine", engine, "--directory", directory,
             "inspect", "--format", INSPECT_FORMAT, outer],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as error:
        raise ProbeFailure("inspect") from error
    deadline = time.monotonic() + 2
    output = bytearray()
    try:
        assert process.stdout is not None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeFailure("inspect")
            readable, _, _ = select.select([process.stdout], [], [], remaining)
            if not readable:
                raise ProbeFailure("inspect")
            chunk = os.read(process.stdout.fileno(), 513 - len(output))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 512:
                raise ProbeFailure("inspect")
        exited = None
        while time.monotonic() < deadline:
            exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None:
                break
            time.sleep(min(0.005, max(0, deadline - time.monotonic())))
        if exited is None or exited.si_code != os.CLD_EXITED or exited.si_status != 0:
            raise ProbeFailure("inspect")
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProbeFailure("inspect") from error
    finally:
        # Keep the leader unreaped until its group is signaled: no PID reuse
        # window, including when a client exits but descendants hold the pipe.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=1)
        if process.stdout is not None:
            process.stdout.close()
    try:
        fields = output.decode("ascii").strip().split("|")
    except UnicodeDecodeError as error:
        raise ProbeFailure("identity") from error
    if len(fields) != 5:
        raise ProbeFailure("identity")
    container_id, pid, started_at, running, label = fields
    if running != "true" or label != run_id:
        raise ProbeFailure("identity")
    if not started_at or len(started_at) > 64 or not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise ProbeFailure("identity")
    candidate = f"{container_id}|{pid}|{started_at.encode('ascii').hex()}|1"
    parsed = parse_token(candidate)
    return parsed.container_id, parsed.pid, parsed.started_at


def process_start_ticks(proc_fd: int, pid: int) -> int:
    try:
        fd = os.open("stat", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc_fd)
        try:
            stat = os.read(fd, 4096).decode("ascii")
        finally:
            os.close(fd)
        before, after = stat.rsplit(") ", 1)
        if not before.startswith(f"{pid} ("):
            raise ProbeFailure("process")
        fields = after.split()
        if len(fields) < 20 or fields[0] == "Z":
            raise ProbeFailure("process")
        ticks = int(fields[19])
        if ticks <= 0:
            raise ProbeFailure("process")
        return ticks
    except (OSError, ValueError, UnicodeError) as error:
        raise ProbeFailure("process") from error


def verified_process(outer: str, run_id: str, expected: tuple[str, int, str], engine: str, directory: str):
    if inspect(outer, run_id, engine, directory) != expected:
        raise ProbeFailure("changed")
    pid = expected[1]
    try:
        proc_fd = os.open(
            f"/proc/{pid}", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            ticks = process_start_ticks(proc_fd, pid)
            net_fd = os.open("ns/net", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc_fd)
        finally:
            os.close(proc_fd)
    except OSError as error:
        raise ProbeFailure("process") from error
    try:
        try:
            held = os.fstat(net_fd)
            host = os.stat("/proc/self/ns/net")
        except OSError as error:
            raise ProbeFailure("identity") from error
        held_identity = (held.st_dev, held.st_ino)
        host_identity = (host.st_dev, host.st_ino)
        if (not all(type(value) is int and value > 0 for value in (*held_identity, *host_identity))
                or held_identity == host_identity):
            raise ProbeFailure("identity")
        if inspect(outer, run_id, engine, directory) != expected:
            raise ProbeFailure("changed")
    except ProbeFailure:
        os.close(net_fd)
        raise
    return ticks, net_fd


def probe_command(mode: str, argument: str | None) -> list[str]:
    if mode == "tcp_refusal" and argument is None:
        return [sys.executable, "-c", TCP_REFUSAL_SCRIPT]
    if mode == "tcp6_refusal" and argument is not None:
        if not re.fullmatch(r"[1-9][0-9]{0,4}", argument) or int(argument) > 65535:
            raise ProbeFailure("input")
        return [sys.executable, "-c", TCP6_REFUSAL_SCRIPT, argument]
    if mode == "ipv6_socket" and argument is None:
        return [sys.executable, "-c", IPV6_SOCKET_SCRIPT]
    if mode == "curl_version" and argument is None:
        return ["curl", "--version"]
    if mode == "bash_version" and argument is None:
        return ["bash", "--version"]
    if mode == "http" and argument is not None:
        match = URL.fullmatch(argument)
        if match is None or int(match.group(1)) > 65535:
            raise ProbeFailure("input")
        return [
            "curl", "-q", "--noproxy", "*", "--proxy", "", "--globoff", "--fail",
            "--silent", "--show-error", "--connect-timeout", "2", "--max-time", "3",
            "--max-filesize", "8192", argument,
        ]
    if mode == "udp" and argument is not None:
        if not re.fullmatch(r"[1-9][0-9]{0,4}", argument) or int(argument) > 65535:
            raise ProbeFailure("input")
        return [
            "bash", "-c", 'printf \'%s\' "$1" >"/dev/udp/127.0.0.1/$2"',
            "udp-probe", "native-udp-canary", argument,
        ]
    raise ProbeFailure("input")


def main() -> int:
    if (len(sys.argv) < 7 or len(sys.argv) > 9 or sys.argv[1] != "--engine"
            or sys.argv[3] != "--directory"):
        raise ProbeFailure("input")
    engine, directory = sys.argv[2], sys.argv[4]
    if engine not in ("podman", "docker") or not Path(directory).is_absolute():
        raise ProbeFailure("input")
    arguments = sys.argv[5:]
    mode, outer = arguments[:2]
    name = NAME.fullmatch(outer)
    if name is None:
        raise ProbeFailure("input")
    run_id = name.group(1)
    if mode == "identity":
        if len(arguments) != 2:
            raise ProbeFailure("input")
        expected = inspect(outer, run_id, engine, directory)
        ticks, net_fd = verified_process(outer, run_id, expected, engine, directory)
        os.close(net_fd)
        print(Identity(*expected, ticks).token())
        return 0
    if len(arguments) not in (3, 4):
        raise ProbeFailure("input")
    cached = parse_token(arguments[2])
    argument = arguments[3] if len(arguments) == 4 else None
    command = probe_command(mode, argument)
    if shutil.which("nsenter") is None or shutil.which(command[0]) is None:
        raise ProbeFailure("missing_tool")
    expected = (cached.container_id, cached.pid, cached.started_at)
    ticks, net_fd = verified_process(outer, run_id, expected, engine, directory)
    if ticks != cached.start_ticks:
        os.close(net_fd)
        raise ProbeFailure("process")
    try:
        result = subprocess.run(
            ["nsenter", f"--net=/proc/self/fd/{net_fd}", "--", *command],
            pass_fds=(net_fd,), timeout=6, check=False,
        )
    except FileNotFoundError as error:
        raise ProbeFailure("missing_tool") from error
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProbeFailure("probe") from error
    finally:
        os.close(net_fd)
    if inspect(outer, run_id, engine, directory) != expected:
        raise ProbeFailure("changed")
    if result.returncode < 0:
        raise ProbeFailure("probe")
    return result.returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ProbeFailure as error:
        print(f"DOCKERLENS_NATIVE_NAMESPACE_DIAG: category={error.category}", file=sys.stderr)
        sys.exit(1)
