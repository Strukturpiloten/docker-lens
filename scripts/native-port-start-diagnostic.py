#!/usr/bin/env python3
"""Private, failure-only start-window observations; never native proof or causes."""
from __future__ import annotations

import datetime
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

FILE_LIMIT = 4096
OUTPUT_LIMIT = 64 * 1024
OBSERVATION_SECONDS = 4
WINDOW_FILE = "port-start-window.json"
OWNER_LABEL = "io.dockerlens.native-run"
FIELDS = frozenset((
    "schemaVersion", "phase", "status", "runId", "lane", "candidateSha",
    "outerId", "outerName", "createdId", "createdName", "apiVersion",
    "startRealtimeNs", "endRealtimeNs", "cutoffEpoch",
))
LANES = {
    "debian11-rootful": "1.41", "debian11-rootless": "1.41",
    "upstream-rootful": "1.56", "upstream-rootless": "1.56",
}
COLLECTORS = frozenset((
    "complete", "window_unavailable", "ownership_unverified", "query_failed",
    "output_limit", "timeout", "cancelled", "budget", "watchdog", "unavailable",
))
SOURCES = frozenset(("none", "daemon", "rootless_trace", "mixed"))
CATEGORIES = frozenset((
    "unavailable", "unclassified", "ambiguous", "rootless_network", "port_proxy",
    "uidmap", "permission", "daemon_network", "daemon_runtime",
))


class Unavailable(Exception):
    """Only the fixed collector category may leave the private boundary."""

    def __init__(self, collector: str):
        super().__init__()
        self.collector = collector if collector in COLLECTORS else "unavailable"


def closed(collector: str, source: str = "none", category: str = "unavailable") -> str:
    if collector not in COLLECTORS or source not in SOURCES or category not in CATEGORIES:
        collector, source, category = "unavailable", "none", "unavailable"
    return ("DOCKERLENS_NATIVE_PORT_START_LOG_DIAG: "
            f"source={source} category={category} collector={collector}")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Unavailable("window_unavailable")
        result[key] = value
    return result


def fingerprint(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def canonical(value: object, length: int = 64) -> bool:
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None


def epoch_us(value: str) -> int:
    if re.fullmatch(r"[0-9]{10,16}", value) is None:
        raise Unavailable("window_unavailable")
    return int(value)


class Window:
    """Hold both private directories and a no-follow file through collection."""

    def __init__(self, directory: Path, uid: int):
        self.directory = directory
        self.uid = uid
        self.fds: list[int] = []
        try:
            self._open()
        except BaseException:
            self.close()
            raise

    def _open(self) -> None:
        path = self.directory / "diagnostics" / WINDOW_FILE
        if not self.directory.is_absolute() or self.directory.resolve(strict=True) != self.directory:
            raise Unavailable("window_unavailable")
        self.infos = []
        for location in (self.directory, path.parent):
            info = os.lstat(location)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise Unavailable("window_unavailable")
            descriptor = os.open(location, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fds.append(descriptor)
            if fingerprint(info) != fingerprint(os.fstat(descriptor)):
                raise Unavailable("window_unavailable")
            self.infos.append(info)
        if path.parent.resolve(strict=True) != path.parent:
            raise Unavailable("window_unavailable")
        descriptor = os.open(WINDOW_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=self.fds[1])
        self.fds.append(descriptor)
        self.info = os.fstat(descriptor)
        if (not stat.S_ISREG(self.info.st_mode) or self.info.st_uid != self.uid
                or stat.S_IMODE(self.info.st_mode) != 0o600 or self.info.st_nlink != 1
                or not 0 < self.info.st_size <= FILE_LIMIT):
            raise Unavailable("window_unavailable")
        self.raw = os.read(descriptor, FILE_LIMIT + 1)
        if len(self.raw) != self.info.st_size or len(self.raw) > FILE_LIMIT:
            raise Unavailable("window_unavailable")
        self.record = json.loads(self.raw, object_pairs_hook=unique_object)
        self.recheck()

    def recheck(self) -> None:
        for location, descriptor, info in zip(
                (self.directory, self.directory / "diagnostics"), self.fds[:2], self.infos):
            if (fingerprint(os.lstat(location)) != fingerprint(info)
                    or fingerprint(os.fstat(descriptor)) != fingerprint(info)):
                raise Unavailable("window_unavailable")
        if self.directory.resolve(strict=True) != self.directory:
            raise Unavailable("window_unavailable")
        if (fingerprint(os.stat(WINDOW_FILE, dir_fd=self.fds[1], follow_symlinks=False))
                != fingerprint(self.info)
                or fingerprint(os.fstat(self.fds[2])) != fingerprint(self.info)):
            raise Unavailable("window_unavailable")
        os.lseek(self.fds[2], 0, os.SEEK_SET)
        if os.read(self.fds[2], FILE_LIMIT + 1) != self.raw:
            raise Unavailable("window_unavailable")

    def validate(self, run: str, lane: str, candidate: str, invocation_us: int,
                 now_ns: int) -> dict:
        value = self.record
        if (not isinstance(value, dict) or set(value) != FIELDS
                or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
                or value["status"] != "timeout" or value["phase"] != "multi_dynamic_oracle_start"
                or re.fullmatch(r"[A-Za-z0-9]{8}", run) is None
                or value["runId"] != run or lane not in LANES or value["lane"] != lane
                or not canonical(candidate, 40) or value["candidateSha"] != candidate
                or value["apiVersion"] != LANES[lane]
                or value["outerName"] != f"dl-native-{run}"
                or value["createdName"] != f"dl-port-{run}-multi-dynamic-oracle"
                or not canonical(value["outerId"]) or not canonical(value["createdId"])):
            raise Unavailable("window_unavailable")
        start, end, cutoff = (value[key] for key in (
            "startRealtimeNs", "endRealtimeNs", "cutoffEpoch"))
        if any(type(number) is not int or number <= 0 for number in (start, end, cutoff)):
            raise Unavailable("window_unavailable")
        cutoff_ns = cutoff * 1_000_000_000
        if (not invocation_us * 1000 <= start <= end <= now_ns
                or end - start > 11 * 1_000_000_000
                or now_ns - end > 180 * 1_000_000_000
                or not cutoff_ns - 180 * 1_000_000_000 <= start <= end <= cutoff_ns
                or cutoff_ns > now_ns + 180 * 1_000_000_000):
            raise Unavailable("window_unavailable")
        return value

    def close(self) -> None:
        for descriptor in self.fds:
            os.close(descriptor)
        self.fds.clear()


def timestamp_ns(value: bytes) -> int | None:
    matched = re.fullmatch(
        rb"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
        value)
    if matched is None:
        return None
    try:
        instant = datetime.datetime.fromisoformat(
            matched[1].decode() + matched[3].decode().replace("Z", "+00:00"))
        delta = instant.astimezone(datetime.timezone.utc) - datetime.datetime(
            1970, 1, 1, tzinfo=datetime.timezone.utc)
        fraction = int((matched[2] or b"0").ljust(9, b"0"))
        return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + fraction
    except (ValueError, OverflowError):
        return None


def timestamp_arg(value: int) -> str:
    seconds, fraction = divmod(value, 1_000_000_000)
    return (datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z")


def classify(stdout: bytes, stderr: bytes, start: int, end: int) -> tuple[str, str]:
    sources, categories = set(), set()
    checks = (
        ("rootless_network", (b"rootlesskit", b"slirp4netns")),
        ("port_proxy", (b"docker-proxy", b"port driver", b"portdriver", b"bind:",
                        b"address already in use", b"failed to expose port")),
        ("uidmap", (b"uid_map", b"newuidmap", b"newgidmap")),
        ("permission", (b"operation not permitted", b"permission denied")),
        ("daemon_network", (b"iptables", b"failed to create nat chain", b"endpoint")),
        ("daemon_runtime", (b"runc", b"containerd", b"shim")),
    )
    for stream in (stdout, stderr):
        for line in stream.splitlines():
            stamp, separator, payload = line.partition(b" ")
            observed = timestamp_ns(stamp)
            if not separator or observed is None or not start <= observed <= end:
                continue
            payload = payload.lower()
            sources.add("rootless_trace" if payload.lstrip().startswith(
                b"dockerlens_rootless_trace:") else "daemon")
            categories.update(name for name, needles in checks
                              if any(needle in payload for needle in needles))
    source = next(iter(sources)) if len(sources) == 1 else "mixed" if sources else "none"
    category = next(iter(categories)) if len(categories) == 1 else (
        "ambiguous" if categories else "unclassified")
    return source, category


class Collector:
    def __init__(self, observation_cs: int, parent_remaining: int, watchdog: int):
        boot = time.clock_gettime(time.CLOCK_BOOTTIME)
        elapsed = boot - observation_cs / 100
        if elapsed < 0 or elapsed >= OBSERVATION_SECONDS or parent_remaining < 5:
            raise Unavailable("budget")
        # Includes startup, classification, TERM/KILL and reap. The
        # shell has a same-privilege 3.5s timeout plus a 0.25s kill fallback.
        self.deadline = time.monotonic() + min(3.0, OBSERVATION_SECONDS - elapsed - 0.25)
        self.boot_deadline = observation_cs / 100 + OBSERVATION_SECONDS
        self.watchdog = watchdog
        self.bytes = 0
        self.cancelled = False
        self.check()

    def cancel(self, _number: int, _frame: object) -> None:
        self.cancelled = True

    def check(self) -> None:
        if self.cancelled:
            raise Unavailable("cancelled")
        if (time.monotonic() >= self.deadline
                or time.clock_gettime(time.CLOCK_BOOTTIME) >= self.boot_deadline):
            raise Unavailable("timeout")
        try:
            if self.watchdog <= 1:
                raise Unavailable("watchdog")
            os.kill(self.watchdog, 0)
        except OSError:
            raise Unavailable("watchdog") from None

    def query(self, arguments: list[str]) -> tuple[bytes, bytes]:
        self.check()
        seconds = min(0.8, self.deadline - time.monotonic() - 0.2)
        if seconds <= 0:
            raise Unavailable("timeout")
        process = subprocess.Popen(
            ["timeout", "--signal=TERM", "--kill-after=0.15s", f"{seconds:.6f}s",
             "podman", *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        output = (bytearray(), bytearray())
        completed = False
        try:
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((process.stdout, process.stderr)):
                    assert stream is not None
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map():
                    self.check()
                    for key, _ in selector.select(0.02):
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        self.bytes += len(chunk)
                        if self.bytes > OUTPUT_LIMIT:
                            raise Unavailable("output_limit")
                        output[key.data].extend(chunk)
                self.check()
                # Observe exit without reaping, so group signaling cannot hit
                # a reused PID. Descendants are never accepted as completion.
                status = os.waitid(os.P_PID, process.pid,
                                   os.WEXITED | os.WNOHANG | os.WNOWAIT)
                while status is None:
                    self.check()
                    time.sleep(0.005)
                    status = os.waitid(os.P_PID, process.pid,
                                       os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if status.si_code != os.CLD_EXITED or status.si_status != 0:
                    raise Unavailable("timeout" if status.si_status in (124, 137)
                                      else "query_failed")
                completed = True
        finally:
            # Same root privileges as the client; terminate the entire group
            # before reaping even on overflow, cancellation or collector error.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            try:
                process.wait(timeout=min(0.15, max(0.001, self.deadline - time.monotonic())))
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                completed = False
            else:
                # Remaining group members make the observation uncertain.
                completed = False
        self.check()
        if not completed:
            raise Unavailable("unavailable")
        return bytes(output[0]), bytes(output[1])


def verify_outer(stdout: bytes, stderr: bytes, record: dict) -> None:
    if stderr:
        raise Unavailable("ownership_unverified")
    value = json.loads(stdout, object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or value.get("Id") != record["outerId"]
            or value.get("Name") not in (record["outerName"], "/" + record["outerName"])
            or not isinstance(value.get("Config"), dict)
            or not isinstance(value["Config"].get("Labels"), dict)
            or value["Config"]["Labels"].get(OWNER_LABEL) != record["runId"]):
        raise Unavailable("ownership_unverified")


def observe(directory: Path, uid: int, run: str, lane: str, candidate: str,
            invocation_us: int, collector: Collector) -> str:
    window = None
    try:
        window = Window(directory, uid)
        record = window.validate(run, lane, candidate, invocation_us, time.time_ns())
        collector.check()
        for identity in (record["outerId"], record["outerName"]):
            stdout, stderr = collector.query(["inspect", "--format", "{{json .}}", identity])
            verify_outer(stdout, stderr, record)
            window.recheck()
        stdout, stderr = collector.query([
            "logs", "--timestamps", "--since", timestamp_arg(record["startRealtimeNs"]),
            "--until", timestamp_arg(record["endRealtimeNs"]), "--tail", "80", record["outerId"],
        ])
        source, category = classify(stdout, stderr, record["startRealtimeNs"], record["endRealtimeNs"])
        window.recheck()
        collector.check()
        return closed("complete", source, category)
    except Unavailable as error:
        return closed(error.collector)
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return closed("window_unavailable" if window is None else "unavailable")
    finally:
        if window is not None:
            window.close()


def main(arguments: list[str]) -> int:
    try:
        if os.geteuid() != 0 or len(arguments) != 9:
            raise Unavailable("unavailable")
        directory, uid, run, lane, candidate, invocation, observation, remaining, watchdog = arguments
        collector = Collector(int(observation), int(remaining), int(watchdog))
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, collector.cancel)
        result = observe(Path(directory), int(uid), run, lane, candidate,
                         epoch_us(invocation), collector)
        collector.check()
    except Unavailable as error:
        result = closed(error.collector)
    except (OSError, ValueError, TypeError, OverflowError):
        result = closed("unavailable")
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
