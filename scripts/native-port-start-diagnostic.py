#!/usr/bin/env python3
"""Private, failure-only start-window observations; never native proof or causes."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
from pathlib import Path

FILE_LIMIT = 4096
OUTPUT_LIMIT = 64 * 1024
OBSERVATION_SECONDS = 4
WINDOW_FILE = "port-start-window.json"
REGISTRATION_FILE = "port-log-registration.json"
LOG_FILE = "daemon.log"
REGISTRATION_FIELDS = frozenset((
    "schemaVersion", "status", "runId", "lane", "outerId", "outerName", "image", "imageDigest",
    "logDriver", "logPath", "device", "inode", "uid", "mode", "links",
    "prefixBytes", "prefixSha256", "registeredSize",
))
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

    def __init__(self, directory: Path, uid: int, filename: str = WINDOW_FILE):
        self.directory = directory
        self.uid = uid
        self.filename = filename
        self.fds: list[int] = []
        try:
            self._open()
        except BaseException:
            self.close()
            raise

    def _open(self) -> None:
        path = self.directory / "diagnostics" / self.filename
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
        descriptor = os.open(self.filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
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
        if (fingerprint(os.stat(self.filename, dir_fd=self.fds[1], follow_symlinks=False))
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
        # Only the already-validated Debian rootless oracle can have the new
        # 24s curl / 26s outer start allowance plus its existing 1s KILL grace.
        maximum_window_ns = (27 if lane == "debian11-rootless"
                             and value["apiVersion"] == "1.41"
                             and value["createdName"] == f"dl-port-{run}-multi-dynamic-oracle"
                             and value["phase"] == "multi_dynamic_oracle_start" else 11) * 1_000_000_000
        if (not invocation_us * 1000 <= start <= end <= now_ns
                or end - start > maximum_window_ns
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

def log_identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink)


def registered_identity(record: dict) -> tuple:
    return tuple(record[key] for key in ("device", "inode", "uid", "mode", "links"))


def check_log(descriptor: int, registration: Window) -> os.stat_result:
    value = registration.record
    actual = os.fstat(descriptor)
    named = os.stat(LOG_FILE, dir_fd=registration.fds[1], follow_symlinks=False)
    if (not stat.S_ISREG(actual.st_mode) or not stat.S_ISREG(named.st_mode)
            or log_identity(actual) != registered_identity(value)
            or fingerprint(actual) != fingerprint(named)
            or actual.st_uid != registration.uid or stat.S_IMODE(actual.st_mode) != 0o600
            or actual.st_nlink != 1):
        raise Unavailable("ownership_unverified")
    return actual


def prepare(directory: Path, run: str, lane: str) -> None:
    if re.fullmatch(r"[A-Za-z0-9]{8}", run) is None or lane not in LANES:
        raise Unavailable("unavailable")
    if not directory.is_absolute() or directory.resolve(strict=True) != directory:
        raise Unavailable("unavailable")
    uid = os.geteuid()
    parent = directory / "diagnostics"
    for location in (directory, parent):
        info = os.lstat(location)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise Unavailable("unavailable")
    held = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if (fingerprint(os.fstat(held)) != fingerprint(info)
                or fingerprint(os.lstat(parent)) != fingerprint(info)):
            raise Unavailable("unavailable")
        log = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=held)
        try:
            info = os.fstat(log)
            if log_identity(info)[2:] != (uid, 0o600, 1):
                raise Unavailable("unavailable")
            value = {
                "schemaVersion": 1, "status": "prepared", "runId": run, "lane": lane,
                "outerId": None, "outerName": f"dl-native-{run}", "image": None, "imageDigest": None,
                "logDriver": "k8s-file", "logPath": str(parent / LOG_FILE),
                "device": info.st_dev, "inode": info.st_ino, "uid": uid,
                "mode": 0o600, "links": 1, "prefixBytes": 0, "prefixSha256": None, "registeredSize": 0,
            }
            output = os.open(REGISTRATION_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=held)
            with os.fdopen(output, "wb") as stream:
                stream.write(json.dumps(value, separators=(",", ":")).encode())
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(log)
    finally:
        os.close(held)


def validate_registration(registration: Window, run: str, lane: str) -> dict:
    value = registration.record
    if (not isinstance(value, dict) or set(value) != REGISTRATION_FIELDS
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["runId"] != run or value["lane"] != lane
            or value["outerName"] != f"dl-native-{run}"
            or value["logDriver"] != "k8s-file"
            or value["logPath"] != str(registration.directory / "diagnostics" / LOG_FILE)
            or value["uid"] != registration.uid or value["mode"] != 0o600 or value["links"] != 1
            or any(type(value[key]) is not int or value[key] < 0
                   for key in ("device", "inode", "uid", "mode", "links", "prefixBytes", "registeredSize"))):
        raise Unavailable("ownership_unverified")
    return value


def register(directory: Path, run: str, lane: str, image: str, outer_id: str,
             descriptor: int, native: dict) -> None:
    registration = Window(directory, os.geteuid(), REGISTRATION_FILE)
    try:
        value = validate_registration(registration, run, lane)
        if not isinstance(native, dict):
            raise Unavailable("ownership_unverified")
        config, host = native.get("Config"), native.get("HostConfig")
        if (value["status"] != "prepared" or not canonical(outer_id)
                or native.get("Id") != outer_id or native.get("Name") != value["outerName"]
                or not isinstance(config, dict) or not isinstance(config.get("Labels"), dict)
                or config["Labels"].get(OWNER_LABEL) != run or native.get("ImageDigest") != image_digest(image)
                or not isinstance(host, dict) or not isinstance(host.get("LogConfig"), dict)
                or host["LogConfig"].get("Type") != "k8s-file"
                or host["LogConfig"].get("Path") != value["logPath"]):
            raise Unavailable("ownership_unverified")
        before = check_log(descriptor, registration)
        if not 0 < before.st_size <= OUTPUT_LIMIT:
            raise Unavailable("output_limit")
        count = min(before.st_size, 256)
        prefix = os.pread(descriptor, count, 0)
        if len(prefix) != count or fingerprint(check_log(descriptor, registration)) != fingerprint(before):
            raise Unavailable("ownership_unverified")
        registration.recheck()
        value.update(status="registered", outerId=outer_id, image=image, imageDigest=image_digest(image),
                     prefixBytes=count, prefixSha256=hashlib.sha256(prefix).hexdigest(), registeredSize=before.st_size)
        target = os.open(REGISTRATION_FILE, os.O_WRONLY | os.O_NOFOLLOW,
                         dir_fd=registration.fds[1])
        try:
            if fingerprint(os.fstat(target)) != fingerprint(registration.info):
                raise Unavailable("ownership_unverified")
            os.ftruncate(target, 0)
            payload = json.dumps(value, separators=(",", ":")).encode()
            if len(payload) > FILE_LIMIT or os.write(target, payload) != len(payload):
                raise Unavailable("unavailable")
            os.fsync(target)
            finished = os.fstat(target)
            named = os.stat(REGISTRATION_FILE, dir_fd=registration.fds[1], follow_symlinks=False)
            if (fingerprint(finished) != fingerprint(named)
                    or log_identity(finished) != log_identity(registration.info)
                    or finished.st_size != len(payload)):
                raise Unavailable("unavailable")
        finally:
            os.close(target)
    finally:
        registration.close()


def cri_records(data: bytes, start: int, end: int, collector: Collector) -> tuple[bytes, bytes]:
    if not data or not data.endswith(b"\n"):
        raise Unavailable("unavailable")
    eligible = []
    previous = None
    for line in data.splitlines():
        collector.check()
        parts = line.split(b" ", 3)
        if (len(parts) != 4 or timestamp_ns(parts[0]) is None
                or parts[1] not in (b"stdout", b"stderr") or parts[2] != b"F"):
            raise Unavailable("unavailable")
        instant = timestamp_ns(parts[0])
        if previous is not None and instant < previous:
            raise Unavailable("unavailable")
        previous = instant
        if start <= instant <= end:
            eligible.append((parts[1], parts[0] + b" " + parts[3] + b"\n"))
            if len(eligible) > 80:
                raise Unavailable("output_limit")
    return tuple(b"".join(line for stream, line in eligible if stream == selected)
                 for selected in (b"stdout", b"stderr"))


def observe(directory: Path, uid: int, run: str, lane: str, candidate: str,
            invocation_us: int, collector: Collector, descriptor: int, image: str) -> str:
    window = registration = None
    try:
        window = Window(directory, uid)
        record = window.validate(run, lane, candidate, invocation_us, time.time_ns())
        collector.check()
        registration = Window(directory, uid, REGISTRATION_FILE)
        value = validate_registration(registration, run, lane)
        if (value["status"] != "registered" or value["outerId"] != record["outerId"]
                or value["outerName"] != record["outerName"] or value["image"] != image
                or value["imageDigest"] != image_digest(image)
                or not canonical(value["outerId"]) or not image
                or not value["prefixBytes"] <= value["registeredSize"] <= OUTPUT_LIMIT
                or not 0 < value["prefixBytes"] <= 256 or not canonical(value["prefixSha256"])):
            raise Unavailable("ownership_unverified")
        before = check_log(descriptor, registration)
        if not value["registeredSize"] <= before.st_size <= OUTPUT_LIMIT:
            raise Unavailable("output_limit")
        chunks = []
        while collector.bytes < before.st_size:
            collector.check()
            chunk = os.pread(descriptor, min(4096, before.st_size - collector.bytes), collector.bytes)
            if not chunk:
                raise Unavailable("unavailable")
            collector.bytes += len(chunk)
            chunks.append(chunk)
        data = b"".join(chunks)
        if hashlib.sha256(data[:value["prefixBytes"]]).hexdigest() != value["prefixSha256"]:
            raise Unavailable("ownership_unverified")
        stdout, stderr = cri_records(data, record["startRealtimeNs"], record["endRealtimeNs"], collector)
        source, category = classify(stdout, stderr, record["startRealtimeNs"], record["endRealtimeNs"])
        if fingerprint(check_log(descriptor, registration)) != fingerprint(before):
            raise Unavailable("ownership_unverified")
        registration.recheck()
        window.recheck()
        collector.check()
        return closed("complete", source, category)
    except Unavailable as error:
        return closed(error.collector)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, AttributeError):
        return closed("window_unavailable" if window is None else "unavailable")
    finally:
        for held in (window, registration):
            if held is not None:
                held.close()


def image_digest(image: str) -> str:
    if not isinstance(image, str) or re.fullmatch(r"[^\s@]+:[^/@\s]+@sha256:[0-9a-f]{64}", image) is None:
        raise Unavailable("ownership_unverified")
    return image.rsplit("@", 1)[1]


def main(arguments: list[str]) -> int:
    try:
        if arguments and arguments[0] == "prepare" and len(arguments) == 4:
            prepare(Path(arguments[1]), arguments[2], arguments[3])
            return 0
        if arguments and arguments[0] == "register" and len(arguments) == 7:
            data = sys.stdin.buffer.read(OUTPUT_LIMIT + 1)
            if len(data) > OUTPUT_LIMIT:
                raise Unavailable("output_limit")
            register(Path(arguments[1]), arguments[2], arguments[3], arguments[4], arguments[5],
                     int(arguments[6]), json.loads(data, object_pairs_hook=unique_object))
            return 0
        if len(arguments) != 11:
            raise Unavailable("unavailable")
        (directory, uid, run, lane, candidate, invocation, observation,
         remaining, watchdog, descriptor, image) = arguments
        collector = Collector(int(observation), int(remaining), int(watchdog))
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, collector.cancel)
        result = observe(Path(directory), int(uid), run, lane, candidate,
                         epoch_us(invocation), collector, int(descriptor), image)
        collector.check()
    except Unavailable as error:
        result = closed(error.collector)
    except (OSError, ValueError, TypeError, OverflowError, AttributeError):
        result = closed("unavailable")
    if arguments and arguments[0] in ("prepare", "register"):
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
