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
    run_id: str
    run_attempt: str
    launch_digest: str
    image_digest: str


@dataclass(frozen=True, repr=False)
class Empty:
    pass


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
class Message:
    verb: str
    sequence: int
    container_id: str | None
    payload: Empty | OCIReceipt | StartedReceipt | RecheckedReceipt


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
    def __init__(self, max_calls, max_bytes, startup, custody, cleanup, watchdog, clock, cancelled):
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
    expected = {"create": Empty, "initialize": OCIReceipt, "start": StartedReceipt, "recheck": RecheckedReceipt, "teardown": Empty}[verb]
    need(type(payload) is expected)
    if expected is Empty:
        return {}
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


def payload_read(verb, value):
    need(type(value) is dict)
    original = value
    if verb in ("create", "teardown"):
        need(value == {})
        return Empty()
    cls = {"initialize": OCIReceipt, "start": StartedReceipt, "recheck": RecheckedReceipt}[verb]
    need(set(value) == set(cls.__dataclass_fields__))
    if cls is OCIReceipt:
        need(type(value["raw"]) is str and len(value["raw"]) <= 87384)
        value = dict(value, raw=base64.b64decode(value["raw"], validate=True))
    result = cls(**value)
    need(payload_wire(verb, result) == original)
    return result


class Endpoint:
    """Exclusive owner of caller-supplied pipe FDs. No automatic retry/reconnect.

    No handshake, launch authority or publication API exists. A final recheck
    packet cannot by itself prove root custody or successful independent readers.
    """
    def __init__(self, role, binding, read_fd, write_fd, ledger):
        self.poisoned = self.closed = False
        self.read_fd, self.write_fd = read_fd, write_fd
        self.id, self.pending, self.sequence, self.phase = None, None, 1, "new"
        self.role, self.binding, self.ledger = role, binding, ledger
        self.cleanup_obligation = "none"
        self.oci_sha256 = self.init_pid = self.started_at = None
        try:
            need(role in ("client", "broker") and type(binding) is Binding and type(ledger) is Ledger)
            need(hex_value(binding.session, 64) and hex_value(binding.candidate, 40) and hex_value(binding.launch_digest, 64))
            need(type(binding.image_digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", binding.image_digest) is not None)
            need(all(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in (binding.run_id, binding.run_attempt)))
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
        return "cleanup" if verb == "teardown" else ("custody" if verb == "recheck" else "startup")

    def _allowed(self, verb):
        allowed = {"new": ("create",), "created": ("initialize", "teardown"),
                   "initialized": ("start", "teardown"), "started": ("recheck", "teardown")}
        need(type(verb) is str and verb in allowed.get(self.phase, ()))

    def _transfer(self, stage, fd, size=0, outgoing=None):
        result, offset = bytearray(), 0
        total = size if outgoing is None else len(outgoing)
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_READ if outgoing is None else selectors.EVENT_WRITE)
            while offset < total:
                remaining = self.ledger.check(stage)
                self.ledger.debit(stage, calls=1)
                events = selector.select(min(remaining, 0.05))
                self.ledger.check(stage)
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
                self.ledger.check(stage)
        return bytes(result)

    def _packet(self, verb, kind, container_id, payload):
        return dict(v=1, kind=kind, session=self.binding.session, candidate=self.binding.candidate,
                    run_id=self.binding.run_id, run_attempt=self.binding.run_attempt, launch_digest=self.binding.launch_digest,
                    image_digest=self.binding.image_digest, sequence=self.sequence, container_id=container_id, verb=verb, payload=payload)

    def _write(self, verb, packet):
        raw = canonical(packet)
        need(0 < len(raw) <= MAX_FRAME)
        stage = self._stage(verb)
        self.ledger.debit(stage, calls=1, size=len(raw) + 4)
        self._transfer(stage, self.write_fd, outgoing=struct.pack(">I", len(raw)) + raw)

    def _read(self, stage):
        self.ledger.debit(stage, calls=1, size=4)
        size = struct.unpack(">I", self._transfer(stage, self.read_fd, size=4))[0]
        need(0 < size <= MAX_FRAME)
        self.ledger.debit(stage, size=size)
        raw = self._transfer(stage, self.read_fd, size=size)
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique)
        need(type(value) is dict and canonical(value) == raw)
        return value

    def _commit(self, verb, payload, container_id):
        if verb == "create":
            self.id, self.phase = container_id, "created"
            self.cleanup_obligation = "live_id"
        elif verb == "initialize":
            self.oci_sha256, self.init_pid, self.phase = payload.sha256, payload.init_pid, "initialized"
        elif verb == "start":
            self.started_at, self.phase = payload.started_at, "started"
        elif verb == "teardown":
            # A codec acknowledgment does not prove owned-resource absence.
            self.cleanup_obligation = "teardown_acknowledged_unverified"
            self.close()
        self.sequence += 1
        self.pending = None

    def _receipt(self, verb, payload):
        wire = payload_wire(verb, payload)
        if verb in ("start", "recheck"):
            need(payload.init_pid == self.init_pid)
        if verb == "recheck":
            need(payload.sha256 == self.oci_sha256 and payload.started_at == self.started_at)
        return wire

    @guarded
    def request(self, verb):
        need(self.role == "client" and self.pending is None)
        self._allowed(verb)
        self.pending = verb
        if verb == "create":
            self.cleanup_obligation = "unknown_create"
        self._write(verb, self._packet(verb, "request", self.id, {}))

    @guarded
    def receive(self):
        need((self.role == "client" and self.pending is not None) or (self.role == "broker" and self.pending is None))
        # An idle broker must still receive teardown after startup/custody expiry.
        # The decoded verb is checked against its OWN existing deadline below.
        stage = self._stage(self.pending) if self.pending else "cleanup"
        value = self._read(stage)
        verb = value.get("verb")
        self._allowed(verb)
        need(uint(value.get("v"), 1, 1) and uint(value.get("sequence"), self.sequence, self.sequence))
        container_id = value.get("container_id")
        if self.role == "client" and verb == "create":
            need(hex_value(container_id, 64))
        else:
            need(container_id == self.id)
        kind = "reply" if self.role == "client" else "request"
        expected = self._packet(verb, kind, container_id, value.get("payload"))
        need(value == expected and set(value) == set(expected))
        if self.role == "client":
            need(verb == self.pending)
            payload = payload_read(verb, value["payload"])
            self._receipt(verb, payload)
            self._commit(verb, payload, container_id)
        else:
            need(type(value["payload"]) is dict and value["payload"] == {})
            payload, self.pending = Empty(), verb
            if verb == "create":
                self.cleanup_obligation = "unknown_create"
        self.ledger.check(self._stage(verb))  # Adopt a fully validated returned ID before cancellation.
        return Message(verb, value["sequence"], container_id, payload)

    @guarded
    def respond(self, payload, container_id=None):
        need(self.role == "broker" and self.pending is not None)
        verb = self.pending
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
