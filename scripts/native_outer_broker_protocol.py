"""Unwired private broker IPC primitive; no launcher, runtime adapter or authority.

Each side receives independent expected Binding values; the wire cannot create
trusted identity. Caller-supplied FDs must be exclusively owned anonymous pipe
ends. FIFO metadata alone does not authenticate their anonymous provenance.
Ledger is caller-owned and never allocated/reset by Endpoint. In-process peers
may share it conservatively; cross-process aggregate enforcement and charges for
runtime children remain unwired obligations, NOT a fresh allowance per broker.
Raw OCI is returned once in memory, never an evidence file or hash substitute.
"""

import base64
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
import hashlib
import json
import math
import os
import re
import selectors
import stat
import struct
from threading import Lock

MAX_FRAME = 90000


class ProtocolError(ValueError):
    def __init__(self):
        super().__init__("outer broker protocol refused")


def need(condition):
    if not condition:
        raise ProtocolError()


def uint(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def hex_value(value, length):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


@dataclass(frozen=True, repr=False)
class Binding:
    session: str
    candidate: str
    run_id: str | None
    run_attempt: str | None
    intent_digest: str
    image_digest: str
    execution_origin: str = "github_actions"


@dataclass(frozen=True, repr=False)
class Empty:
    pass


@dataclass(frozen=True, repr=False)
class PreflightReceipt:
    runtime_profile: dict
    native_image_id: str
    native_image_digest: str
    native_repo_digests: tuple
    os: str
    architecture: str
    ordered_diff_ids: tuple
    semantic: dict


@dataclass(frozen=True, repr=False)
class DatabaseReceipt:
    init_pid: int
    native_image_id: str
    native_image_digest: str
    static_dir: str
    hostname_path: str
    hosts_path: str
    resolv_conf_path: str
    owned_volume: dict
    state: str = "initialized"


@dataclass(frozen=True, repr=False)
class ExpectationClaim:
    digest: str


@dataclass(frozen=True, repr=False)
class OCIReceipt:
    raw: bytes
    device: int
    inode: int
    uid: int
    mode: int
    links: int
    size: int
    sha256: str
    init_pid: int


@dataclass(frozen=True, repr=False)
class StartedReceipt:
    init_pid: int
    started_at: str


@dataclass(frozen=True, repr=False)
class RecheckedReceipt:
    sha256: str
    init_pid: int
    started_at: str


@dataclass(frozen=True, repr=False)
class PidsTiming:
    start_ns: int
    deadline_ns: int


@dataclass(frozen=True, repr=False)
class Message:
    verb: str
    sequence: int
    container_id: str | None
    payload: Empty | PreflightReceipt | DatabaseReceipt | ExpectationClaim | OCIReceipt | StartedReceipt | RecheckedReceipt | PidsTiming


class PidsWindow:
    """Once-only timing installation, never a resource allowance or renewal.

    Broker/caller resource reservations are immutable before fork. This object
    only installs invocation 27's actual clock window after its ignored-list
    barrier. Its lifetime counters and outer cleanup deadlines are elsewhere.
    """
    def __init__(self, lane_deadline_ns, clock_ns):
        need(uint(lane_deadline_ns, 1))
        self.lane_deadline_ns, self.clock_ns = lane_deadline_ns, clock_ns
        self.timing, self.sealed = None, False
        self.last = self.clock_ns()
        need(uint(self.last) and self.last < lane_deadline_ns)

    def _now(self):
        now = self.clock_ns()
        need(uint(now) and self.last <= now)
        self.last = now
        return now

    def install(self, timing):
        need(self.timing is None and not self.sealed and type(timing) is PidsTiming)
        start, deadline = timing.start_ns, timing.deadline_ns
        need(uint(start, 1) and uint(deadline, 1))
        now = self._now()
        need(start <= now < deadline - 46_000_000_000
             and 46_000_000_000 < deadline - start <= 180_000_000_000
             and deadline <= self.lane_deadline_ns)
        self.timing = timing

    def check(self, ordinary=False):
        need(self.timing is not None and not self.sealed)
        now = self._now()
        cutoff = self.timing.deadline_ns - (46_000_000_000 if ordinary else 0)
        need(now < cutoff)
        return cutoff - now

    def seal(self):
        self.check()
        self.sealed = True


def closed_errors(method):
    @wraps(method)
    def call(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except BaseException:
            raise ProtocolError() from None
    return call


class Ledger:
    """Existing caller budget: wire bytes/calls are conservative, never refunded.

    Calls include frames, readiness waits and read/write syscalls. Caller must
    also debit other operations. Absolute deadlines are already-owned budgets;
    the 120s/1800s checks are ceilings, not grants or resets of native allowances.
    """
    @closed_errors
    def __init__(self, max_calls, max_bytes, startup, custody, cleanup, watchdog, clock, cancelled, *, reserved_budget=None):
        try:
            now = clock()
            need(all(type(x) in (int, float) and math.isfinite(x) for x in (now, startup, custody, cleanup, watchdog)))
            need(0 < startup - now <= 120 and startup <= custody < cleanup <= watchdog and watchdog - now <= 1800)
            need(uint(max_calls, 1, 100000) and uint(max_bytes, 1, 16777216))
        except BaseException:
            raise ProtocolError() from None
        self.limits = {"startup": startup, "custody": custody, "cleanup": cleanup}
        self.max_calls, self.max_bytes = max_calls, max_bytes
        self.calls = self.bytes = 0
        self.clock, self.cancelled, self.last = clock, cancelled, now
        self.lock, self.claims = Lock(), set()
        self.reserved_budget = reserved_budget

    @closed_errors
    def check(self, stage):
        with self.lock:
            now = self.clock()
            need(stage in self.limits and type(now) in (int, float) and math.isfinite(now))
            need(self.last <= now < self.limits[stage] and self.cancelled() is False)
            self.last = now
            return self.limits[stage] - now

    @closed_errors
    def debit(self, stage, calls=0, size=0):
        self.check(stage)
        if self.reserved_budget is not None:
            self.reserved_budget.debit(io_calls=calls, source_bytes=size)
        with self.lock:
            need(uint(calls) and uint(size) and self.calls + calls <= self.max_calls and self.bytes + size <= self.max_bytes)
            self.calls += calls
            self.bytes += size

    @closed_errors
    def claim(self, binding, role):
        with self.lock:
            key = (binding.session, role)
            need(key not in self.claims)
            self.claims.add(key)


def guarded(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        try:
            need(not self.poisoned and not self.closed)
            return method(self, *args, **kwargs)
        except BaseException:
            self._poison()
            raise ProtocolError() from None
    return call


def timestamp(value):
    need(type(value) is str and len(value) <= 35)
    match = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(?:Z|([+-])([01][0-9]|2[0-3]):([0-5][0-9]))", value)
    need(match is not None)
    instant = datetime(*(int(match[index]) for index in range(1, 7)))
    seconds = (instant.toordinal() - 1) * 86400 + instant.hour * 3600 + instant.minute * 60 + instant.second
    offset = 0 if match[8] is None else (int(match[9]) * 60 + int(match[10])) * 60
    if match[8] == "-":
        offset = -offset
    need(seconds - offset != 0 or int(match[7] or "0") != 0)


def payload_wire(verb, payload):
    expected = {"preflight": PreflightReceipt, "create": Empty, "initialize": DatabaseReceipt, "bind_expectation": OCIReceipt,
                "start": StartedReceipt, "recheck": RecheckedReceipt,
                "begin_pids": PidsTiming, "pids_before_producer": RecheckedReceipt,
                "pids_before_reader": RecheckedReceipt, "seal_pids": RecheckedReceipt,
                "teardown": Empty}[verb]
    need(type(payload) is expected)
    if expected is Empty:
        return {}
    if expected is PidsTiming:
        need(uint(payload.start_ns, 1) and uint(payload.deadline_ns, 1))
        return {"start_ns": payload.start_ns, "deadline_ns": payload.deadline_ns}
    if expected is PreflightReceipt:
        profile = payload.runtime_profile
        need(type(profile) is dict and set(profile) == {"operating_system", "rootless", "remote", "podman_version",
                                                       "runtime_name", "runtime_version", "cgroup_manager", "cgroup_version"})
        need(all(type(profile[key]) is bool for key in ("rootless", "remote")))
        need(all(type(profile[key]) is str and 0 < len(profile[key]) <= 256
                 for key in set(profile) - {"rootless", "remote"}))
        need(hex_value(payload.native_image_id, 64) and image_digest(payload.native_image_digest))
        need(payload.os == "linux" and payload.architecture in ("amd64", "arm64"))
        need(type(payload.native_repo_digests) is tuple and 1 <= len(payload.native_repo_digests) <= 64
             and all(type(item) is str and len(item) <= 1024 for item in payload.native_repo_digests)
             and len(set(payload.native_repo_digests)) == len(payload.native_repo_digests)
             and len(canonical(payload.native_repo_digests)) <= 8192)
        need(type(payload.ordered_diff_ids) is tuple and 1 <= len(payload.ordered_diff_ids) <= 64
             and all(image_digest(item) for item in payload.ordered_diff_ids))
        need(type(payload.semantic) is dict and set(payload.semantic) == {"config", "healthcheck"}
             and payload.semantic["healthcheck"] is None and type(payload.semantic["config"]) is dict
             and len(canonical(payload.semantic)) <= 16384)
        config = payload.semantic["config"]
        need(set(config) == {"User", "ExposedPorts", "Env", "Entrypoint", "Cmd", "Volumes", "WorkingDir", "Labels", "StopSignal", "ArgsEscaped"})
        for key in ("User", "WorkingDir", "StopSignal"):
            need(type(config[key]) is str and "\0" not in config[key] and len(config[key].encode()) <= 4096)
        for key in ("Env", "Entrypoint", "Cmd"):
            need(type(config[key]) is list and len(config[key]) <= 128
                 and all(type(item) is str and "\0" not in item and len(item.encode()) <= 4096 for item in config[key]))
        for key in ("ExposedPorts", "Volumes", "Labels"):
            need(type(config[key]) is dict and len(config[key]) <= 128
                 and all(type(name) is str and "\0" not in name and len(name.encode()) <= 4096 for name in config[key]))
            need(all((type(item) is str and "\0" not in item and len(item.encode()) <= 4096) if key == "Labels"
                     else type(item) is dict and not item for item in config[key].values()))
        need(type(config["ArgsEscaped"]) is bool)
        return {"runtime_profile": profile, "native_image_id": payload.native_image_id,
                "native_image_digest": payload.native_image_digest, "native_repo_digests": list(payload.native_repo_digests),
                "os": payload.os, "architecture": payload.architecture, "ordered_diff_ids": list(payload.ordered_diff_ids),
                "semantic": payload.semantic}
    if expected is DatabaseReceipt:
        need(uint(payload.init_pid, 1, 4194304) and hex_value(payload.native_image_id, 64)
             and image_digest(payload.native_image_digest) and payload.state == "initialized")
        for path in (payload.static_dir, payload.hostname_path, payload.hosts_path, payload.resolv_conf_path):
            bounded_path(path)
        volume = payload.owned_volume
        need(type(volume) is dict and set(volume) == {"name", "mountpoint", "owner"})
        need(all(type(volume[key]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", volume[key]) is not None
                 for key in ("name", "owner")))
        bounded_path(volume["mountpoint"])
        return {name: getattr(payload, name) for name in payload.__dataclass_fields__}
    if expected is OCIReceipt:
        need(type(payload.raw) is bytes and 1 <= len(payload.raw) <= 65536)
        need(uint(payload.device, 1) and uint(payload.inode, 1) and type(payload.uid) is int and payload.uid == 0)
        need(uint(payload.mode, 0, 0o177777) and stat.S_ISREG(payload.mode) and payload.mode & 0o022 == 0)
        need(type(payload.links) is int and payload.links == 1 and type(payload.size) is int and payload.size == len(payload.raw))
        need(hex_value(payload.sha256, 64) and hashlib.sha256(payload.raw).hexdigest() == payload.sha256)
        need(uint(payload.init_pid, 1, 4194304))
        return {"raw": base64.b64encode(payload.raw).decode("ascii"), "device": payload.device, "inode": payload.inode,
                "uid": payload.uid, "mode": payload.mode, "links": payload.links, "size": payload.size,
                "sha256": payload.sha256, "init_pid": payload.init_pid}
    need(uint(payload.init_pid, 1, 4194304))
    timestamp(payload.started_at)
    value = {"init_pid": payload.init_pid, "started_at": payload.started_at}
    if expected is RecheckedReceipt:
        need(hex_value(payload.sha256, 64))
        value["sha256"] = payload.sha256
    return value


def image_digest(value):
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def bounded_path(value):
    need(type(value) is str and 0 < len(value.encode("utf-8")) <= 4096 and value.startswith("/")
         and not value.endswith("/") and "\0" not in value
         and all(part not in ("", ".", "..") for part in value[1:].split("/")))


def payload_read(verb, value):
    need(type(value) is dict)
    original = value
    if verb in ("create", "teardown"):
        need(value == {})
        return Empty()
    cls = {"preflight": PreflightReceipt, "initialize": DatabaseReceipt, "bind_expectation": OCIReceipt,
           "start": StartedReceipt, "recheck": RecheckedReceipt,
           "begin_pids": PidsTiming, "pids_before_producer": RecheckedReceipt,
           "pids_before_reader": RecheckedReceipt, "seal_pids": RecheckedReceipt}[verb]
    need(set(value) == set(cls.__dataclass_fields__))
    if cls is OCIReceipt:
        need(type(value["raw"]) is str and len(value["raw"]) <= 87384)
        value = dict(value, raw=base64.b64decode(value["raw"], validate=True))
    elif cls is PreflightReceipt:
        need(type(value["native_repo_digests"]) is list and type(value["ordered_diff_ids"]) is list)
        value = dict(value, native_repo_digests=tuple(value["native_repo_digests"]), ordered_diff_ids=tuple(value["ordered_diff_ids"]))
    result = cls(**value)
    need(payload_wire(verb, result) == original)
    return result


class Endpoint:
    """Exclusive owner of caller-supplied pipe FDs. No automatic retry/reconnect.

    No handshake, launch authority or publication API exists. A final recheck
    packet cannot by itself prove root custody or successful independent readers.
    """
    def __init__(self, role, binding, read_fd, write_fd, ledger, *, pids_window):
        self.poisoned = self.closed = False
        self.read_fd, self.write_fd = read_fd, write_fd
        self.id, self.pending, self.sequence, self.phase = None, None, 1, "new"
        self.role, self.binding, self.ledger = role, binding, ledger
        self.version, self.pids_window = 2, pids_window
        self.cleanup_obligation = "none"
        self.oci_sha256 = self.init_pid = self.started_at = None
        self.expectation_digest = self.pending_claim = None
        self.native_image = None
        try:
            need(role in ("client", "broker") and type(binding) is Binding and type(ledger) is Ledger)
            need(type(pids_window) is PidsWindow)
            need(hex_value(binding.session, 64) and hex_value(binding.candidate, 40) and hex_value(binding.intent_digest, 64))
            need(type(binding.image_digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", binding.image_digest) is not None)
            need(binding.execution_origin in ("github_actions", "local_process"))
            if binding.execution_origin == "github_actions":
                need(all(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in (binding.run_id, binding.run_attempt)))
            else:
                need(binding.run_id is None and binding.run_attempt is None)
            need(type(read_fd) is int and type(write_fd) is int and read_fd >= 0 and write_fd >= 0 and read_fd != write_fd)
            ledger.check("startup")
            for fd in (read_fd, write_fd):
                need(stat.S_ISFIFO(os.fstat(fd).st_mode))
                os.set_inheritable(fd, False)
                os.set_blocking(fd, False)
            ledger.claim(binding, role)
        except BaseException:
            self._poison()
            raise ProtocolError() from None

    def _stage(self, verb):
        return "cleanup" if verb == "teardown" else ("custody" if verb in ("recheck", "begin_pids", "pids_before_producer", "pids_before_reader", "seal_pids") else "startup")

    def _allowed(self, verb):
        allowed = {"new": ("preflight",), "preflighted": ("create", "teardown"),
                   "created": ("initialize", "teardown"), "initialized": ("bind_expectation", "teardown"),
                   "bound": ("start", "teardown"), "started": ("recheck", "begin_pids", "teardown"),
                   "pids_active": ("pids_before_producer", "teardown"),
                   "pids_producing": ("pids_before_reader", "teardown"),
                   "pids_reading": ("seal_pids", "teardown"), "pids_sealed": ("recheck", "teardown")}
        need(type(verb) is str and verb in allowed.get(self.phase, ()))
        if verb in ("pids_before_producer", "pids_before_reader", "seal_pids"):
            self.pids_window.check(ordinary=verb == "pids_before_producer")

    def _remaining(self, stage, pids_bound):
        remaining = self.ledger.check(stage)
        if pids_bound:
            ordinary = self.phase in ("started", "pids_active")
            remaining = min(remaining, self.pids_window.check(ordinary=ordinary) / 1_000_000_000)
        return remaining

    def _transfer(self, stage, fd, size=0, outgoing=None, *, pids_bound=False):
        result, offset = bytearray(), 0
        total = size if outgoing is None else len(outgoing)
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_READ if outgoing is None else selectors.EVENT_WRITE)
            while offset < total:
                remaining = self._remaining(stage, pids_bound)
                self.ledger.debit(stage, calls=1)
                events = selector.select(min(remaining, 0.05 if pids_bound else 0.5))
                self._remaining(stage, pids_bound)
                if not events:
                    continue
                self.ledger.debit(stage, calls=1)
                try:
                    if outgoing is None:
                        chunk = os.read(fd, min(4096, total - offset))
                        need(bool(chunk))  # EOF never acknowledges any transition.
                        result.extend(chunk)
                        offset += len(chunk)
                    else:
                        count = os.write(fd, memoryview(outgoing)[offset:offset + 4096])
                        need(count > 0)
                        offset += count
                except (BlockingIOError, InterruptedError):
                    pass
                self._remaining(stage, pids_bound)
        return bytes(result)

    def _packet(self, verb, kind, container_id, payload, expectation_digest=None):
        return dict(v=self.version, kind=kind, session=self.binding.session, candidate=self.binding.candidate,
                    execution_origin=self.binding.execution_origin,
                    run_id=self.binding.run_id, run_attempt=self.binding.run_attempt, intent_digest=self.binding.intent_digest,
                    expectation_digest=self.expectation_digest if expectation_digest is None else expectation_digest,
                    image_digest=self.binding.image_digest, sequence=self.sequence, container_id=container_id, verb=verb, payload=payload)

    def _write(self, verb, packet):
        raw = canonical(packet)
        need(0 < len(raw) <= MAX_FRAME)
        if verb in ("preflight", "initialize"):
            need(len(raw) + 4 <= (32768 if verb == "preflight" else 16384))
        stage = self._stage(verb)
        pids_bound = verb != "teardown" and self.pids_window.timing is not None and not self.pids_window.sealed
        self._remaining(stage, pids_bound)
        self.ledger.debit(stage, calls=1, size=len(raw) + 4)
        self._transfer(stage, self.write_fd, outgoing=struct.pack(">I", len(raw)) + raw, pids_bound=pids_bound)

    def _read(self, stage):
        # Until a complete request identifies teardown, it cannot bypass an
        # active PIDs deadline. Expiry closes IPC; the root owner's independent
        # recovery still uses the original outer cleanup deadline.
        pids_bound = self.pending != "teardown" and self.pids_window.timing is not None and not self.pids_window.sealed
        self.ledger.debit(stage, calls=1, size=4)
        size = struct.unpack(">I", self._transfer(stage, self.read_fd, size=4, pids_bound=pids_bound))[0]
        need(0 < size <= MAX_FRAME)
        self.ledger.debit(stage, size=size)
        raw = self._transfer(stage, self.read_fd, size=size, pids_bound=pids_bound)
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique)
        need(type(value) is dict and canonical(value) == raw)
        if value.get("verb") in ("preflight", "initialize"):
            need(len(raw) + 4 <= (32768 if value["verb"] == "preflight" else 16384))
        return value

    def _commit(self, verb, payload, container_id):
        if verb == "preflight":
            self.native_image = (payload.native_image_id, payload.native_image_digest)
            self.phase = "preflighted"
        elif verb == "create":
            self.id, self.phase = container_id, "created"
            self.cleanup_obligation = "live_id"
        elif verb == "initialize":
            self.init_pid, self.phase = payload.init_pid, "initialized"
        elif verb == "bind_expectation":
            self.oci_sha256, self.phase = payload.sha256, "bound"
        elif verb == "start":
            self.started_at, self.phase = payload.started_at, "started"
        elif verb == "begin_pids":
            self.phase = "pids_active"
        elif verb == "pids_before_producer":
            self.phase = "pids_producing"
        elif verb == "pids_before_reader":
            self.phase = "pids_reading"
        elif verb == "seal_pids":
            self.pids_window.seal()
            self.phase = "pids_sealed"
        elif verb == "teardown":
            # A codec acknowledgment does not prove owned-resource absence.
            self.cleanup_obligation = "teardown_acknowledged_unverified"
            self.close()
        self.sequence += 1
        self.pending = None

    def _receipt(self, verb, payload):
        wire = payload_wire(verb, payload)
        if verb == "begin_pids":
            need(payload == self.pids_window.timing)
            self.pids_window.check()
        if verb == "initialize":
            need((payload.native_image_id, payload.native_image_digest) == self.native_image)
        if verb in ("bind_expectation", "start", "recheck", "pids_before_producer", "pids_before_reader", "seal_pids"):
            need(payload.init_pid == self.init_pid)
        if verb in ("recheck", "pids_before_producer", "pids_before_reader", "seal_pids"):
            need(payload.sha256 == self.oci_sha256 and payload.started_at == self.started_at)
        if verb in ("pids_before_producer", "pids_before_reader", "seal_pids"):
            self.pids_window.check(ordinary=verb == "pids_before_producer")
        return wire

    @guarded
    def request(self, verb, payload=None):
        need(self.role == "client" and self.pending is None)
        self._allowed(verb)
        self.pending = verb
        if verb == "begin_pids":
            self.pids_window.install(payload)
            wire = payload_wire(verb, payload)
        elif verb == "bind_expectation":
            need(type(payload) is ExpectationClaim and hex_value(payload.digest, 64) and self.expectation_digest is None)
            self.expectation_digest = payload.digest
            wire = {"digest": payload.digest}
        else:
            need(payload is None)
            wire = {}
        if verb == "create":
            self.cleanup_obligation = "unknown_create"
        self._write(verb, self._packet(verb, "request", self.id, wire))

    @guarded
    def receive(self):
        need((self.role == "client" and self.pending is not None) or (self.role == "broker" and self.pending is None))
        # An idle broker must still receive teardown after startup/custody expiry.
        # The decoded verb is checked against its OWN existing deadline below.
        stage = self._stage(self.pending) if self.pending else "cleanup"
        value = self._read(stage)
        verb = value.get("verb")
        self._allowed(verb)
        need(uint(value.get("v"), self.version, self.version) and uint(value.get("sequence"), self.sequence, self.sequence))
        container_id = value.get("container_id")
        if self.role == "client" and verb == "create":
            need(hex_value(container_id, 64))
        else:
            need(container_id == self.id)
        kind = "reply" if self.role == "client" else "request"
        digest = None
        if self.role == "broker" and verb == "bind_expectation":
            claim = value.get("payload")
            need(type(claim) is dict and set(claim) == {"digest"} and hex_value(claim["digest"], 64)
                 and self.expectation_digest is None)
            digest = claim["digest"]
        expected = self._packet(verb, kind, container_id, value.get("payload"), expectation_digest=digest)
        need(value == expected and set(value) == set(expected))
        if self.role == "client":
            need(verb == self.pending)
            payload = payload_read(verb, value["payload"])
            self._receipt(verb, payload)
            self._commit(verb, payload, container_id)
        else:
            if verb == "begin_pids":
                payload = payload_read(verb, value["payload"])
                self.pids_window.install(payload)
            elif verb == "bind_expectation":
                payload = ExpectationClaim(digest)
                self.pending_claim = digest
            else:
                need(type(value["payload"]) is dict and value["payload"] == {})
                payload = Empty()
            self.pending = verb
            if verb == "create":
                self.cleanup_obligation = "unknown_create"
        self.ledger.check(self._stage(verb))  # Adopt a fully validated returned ID before cancellation.
        return Message(verb, value["sequence"], container_id, payload)

    @guarded
    def respond(self, payload, container_id=None, *, expectation_digest=None):
        need(self.role == "broker" and self.pending is not None)
        verb = self.pending
        if verb == "bind_expectation":
            need(hex_value(expectation_digest, 64) and expectation_digest == self.pending_claim
                 and self.expectation_digest is None)
            self.expectation_digest = expectation_digest  # Compare independent root derivation before ACK.
        else:
            need(expectation_digest is None)
        wire = self._receipt(verb, payload)
        if verb == "create":
            need(hex_value(container_id, 64))
            self.id, self.cleanup_obligation = container_id, "live_id"  # Adopt before possibly partial write.
        else:
            need(container_id is None)
            container_id = self.id
        self._write(verb, self._packet(verb, "reply", container_id, wire))
        self._commit(verb, payload, container_id)

    def _poison(self):
        self.poisoned = True
        self.close()

    def close(self):
        if not self.closed:
            self.closed = True
            for fd in (self.read_fd, self.write_fd):
                if type(fd) is int and fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
