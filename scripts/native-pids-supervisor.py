#!/usr/bin/env python3
"""Fixed PIDs source watchdog and anonymous capability protocol, still unwired.

There is deliberately no runtime-context/PID acquisition fallback. The executable
refuses source binding until the original Rust runtime-owner seam is integrated.
"""

import os
import sys
import errno

# Closed test-only startup observations. Prefixes are disjoint process origins;
# these are failure sites, never authenticated authority or root-cause claims.
STARTUP_KINDS = (
    "guard", "no_api", "import", "bad_arg", "denied", "missing", "unsupported",
    "resource", "io", "cancelled", "other",
)
SUPERVISOR_SITES = (
    "imports", "args", "fd0", "socket_wrap", "root_uid", "root_deadline",
    "gate_pipe", "block_signals", "source_fork", "par_gate_close", "par_pgroup",
    "par_pidfd", "par_sockclose", "par_gate_send", "par_gate_done",
    "mon_handlers", "mon_unmask", "mon_wait",
)
PEER_SITES = ("peer_shape", "peer_cred", "peer_pidfd", "peer_cloexec", "peer_live")
WORKER_SITES = (
    "kid_gate_close", "kid_pgroup", "kid_pdeath", "kid_parent", "kid_gate_read",
    "kid_gate_done", "kid_unmask", "source_peer_eq", "source_budget",
    "source_init", "locator_init", "source_api", "source_libc", "source_getdents",
    "source_proc", "source_procfs", "source_readfs", "source_read", "self_stat", "self_status", "self_pidns",
    "self_userns", "self_cgroupns", "self_timens", "parent_live", "parent_stat",
    "parent_process", "parent_uid", "parent_cgroup", "parent_time", "parent_link",
    "anc_load", "anc_uid", "anc_ppid", "anc_sudo", "anc_exe", "anc_recheck", "anc_end",
    "proc_pidfd", "proc_dir", "proc_fs", "proc_start", "proc_cgroup", "proc_root",
    "proc_ns", "proc_status", "proc_identity", "proc_check", "proc_timens",
    "proc_live", "proc_reopen", "proc_fdinfo", "stat_delimiter", "stat_state",
    "stat_start", "status_fields", "status_pid", "status_tgid", "status_uid",
    "status_nspid", "status_nstgid", "cgroup_record", "channel_fds",
    "chan_nonblock", "chan_cloexec", "boot_wait", "boot_recv", "boot_ancillary",
    "boot_accumulate", "boot_marker", "boot_count", "boot_stat", "boot_dir",
    "boot_mode", "boot_uid", "boot_cloexec", "ready_budget", "ready_wait", "ready_send",
    "budget_deadline", "budget_reads", "budget_bytes", "budget_fds", "budget_opens",
    "budget_output",
)


class RecorderScope:
    __slots__ = ("recorder", "site")

    def __init__(self, recorder, site):
        self.recorder, self.site = recorder, site

    def __enter__(self):
        return self

    def __exit__(self, _kind, error, _traceback):
        if error is not None and self.recorder is not None:
            self.recorder.fault(self.site, error)
        return False


_INACTIVE_SCOPE = RecorderScope(None, None)


class StartupRecorder:
    """One best-effort static write per process before cleanup can mask work."""

    def __init__(self, origin="s", active=False):
        self.reset(origin, active)

    def reset(self, origin, active=True):
        self.origin, self.active = origin, active
        self.seen = self.emitted = False
        self.value = None

    def stop(self):
        self.active = False

    def kind(self, error):
        boundary_module = globals().get("boundary")
        if boundary_module is not None and isinstance(error, boundary_module.Refusal):
            return "guard"
        if isinstance(error, (AttributeError, NotImplementedError)):
            return "no_api"
        if isinstance(error, ImportError):
            return "import"
        if isinstance(error, (TypeError, ValueError, OverflowError)):
            return "bad_arg"
        if isinstance(error, OSError):
            if error.errno in (errno.EACCES, errno.EPERM):
                return "denied"
            if error.errno in (errno.ENOENT, errno.ESRCH):
                return "missing"
            if error.errno in (errno.ENOSYS, errno.ENOPROTOOPT, errno.EOPNOTSUPP):
                return "unsupported"
            if error.errno in (errno.ENOMEM, errno.ENOBUFS, errno.EMFILE, errno.ENFILE, errno.EAGAIN):
                return "resource"
            return "io"
        if isinstance(error, KeyboardInterrupt):
            return "cancelled"
        return "other"

    def fault(self, site, error):
        if not self.active or self.seen:
            return
        # Cleanup-origin exceptions can cross outer work scopes. Exclude them
        # before setting seen, and fail closed on an uninspectable exception.
        try:
            cleanup = BaseException.__getattribute__(error, "_dockerlens_startup_cleanup")
        except AttributeError:
            cleanup = False
        except BaseException:
            self.stop()
            return
        if cleanup is True:
            return
        # Set before rendering/writing; no retry or cleanup-derived replacement.
        self.seen = True
        try:
            if self.origin not in ("s", "w"):
                return
            allowed = SUPERVISOR_SITES if self.origin == "s" else WORKER_SITES
            if site not in allowed + PEER_SITES:
                return
            kind = self.kind(error)
            line = f"DOCKERLENS_NATIVE_PIDS_START: s={self.origin}_{site} k={kind}"
            self.value = (self.origin, site, kind)
            self.emitted = True
            os.write(2, line.encode("ascii") + b"\n")
        except BaseException:
            pass

    def scope(self, site):
        return RecorderScope(self, site) if self.active else _INACTIVE_SCOPE


# Neutral CALL-ESCAPE sites, not guards/errnos/causes or internal work faults.
BIND_SITES = (
    "capture_adopt", "session_init", "request_read", "handler", "request_schema",
    "context_schema", "labels", "external_debit", "outer_args", "outer_process",
    "outer_vector", "outer_pidns", "outer_cgroup", "endpoint", "daemon_context",
    "daemon_bind", "reserve_api", "outer_recheck", "pending_reply",
)


class BindScope:
    __slots__ = ("recorder", "site")

    def __init__(self, recorder, site):
        self.recorder, self.site = recorder, site

    def __enter__(self):
        return self

    def __exit__(self, _kind, error, _traceback):
        if error is not None and self.recorder is not None:
            try:
                self.recorder.escape(self.site)
            except BaseException:
                pass
        return False


_INACTIVE_BIND_SCOPE = BindScope(None, None)


class BindRecorder:
    """One worker call-escape record, including opaque internal cleanup.

    Never inspect the exception or START's cleanup-origin marker. This says only
    that the named operation escaped, not why or where its internals first failed.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self.active = self.seen = self.emitted = False
        self.value = None

    def begin(self):
        self.active = True

    def stop(self):
        self.active = False

    def escape(self, site):
        if not self.active or self.seen:
            return
        self.seen = True
        try:
            if site not in BIND_SITES:
                return
            self.value = site
            self.emitted = True
            os.write(2, f"DOCKERLENS_NATIVE_PIDS_BIND: s=w_{site}\n".encode("ascii"))
        except BaseException:
            pass

    def scope(self, site):
        if self.active:
            try:
                return BindScope(self, site)
            except BaseException:
                pass
        return _INACTIVE_BIND_SCOPE


_BIND = BindRecorder()


_STARTUP = StartupRecorder(active=__name__ == "__main__")
with _STARTUP.scope("imports"):
    import array
    import fcntl
    import importlib.util
    import json
    from pathlib import Path
    import select
    import signal
    import socket
    import stat
    import struct
    import time

    _locator_path = Path(__file__).with_name("native_pids_locator.py").resolve()
    locator = sys.modules.get("native_pids_locator")
    if (locator is None or getattr(locator, "__file__", None) is None
            or Path(locator.__file__).resolve() != _locator_path):
        _locator_spec = importlib.util.spec_from_file_location("native_pids_locator", _locator_path)
        locator = importlib.util.module_from_spec(_locator_spec)
        sys.modules["native_pids_locator"] = locator
        _locator_spec.loader.exec_module(locator)
    boundary = locator.boundary

boundary.STARTUP_OBSERVER = _STARTUP

require = boundary.require
BOOT = b"BFPIDS1\n"
READY = b"BFREADY\n"
MAX_FRAME = 16 * 1024
VERSION = 1
OWNER_LABEL = "io.dockerlens.native-pids"
SLOT_LABEL = "io.dockerlens.native-pids-slot"
# Immutable fixture recipe facts; actual outer userns identity is checked before
# applying these image UID coordinates in the reader namespace. No observed
# peer chooses an expectation. See pids-exact-daemon-expectations-r1.md.
LANES = {
    "debian11-rootful": (0, ("usr", "sbin", "dockerd"), "20.10.5+dfsg1", "1.41"),
    "debian11-rootless": (1000, ("usr", "sbin", "dockerd"), "20.10.5+dfsg1", "1.41"),
    "upstream-rootful": (0, ("usr", "local", "bin", "dockerd"), "29.8.1", "1.49"),
    "upstream-rootless": (1000, ("usr", "local", "bin", "dockerd"), "29.8.1", "1.49"),
}


def close_all(fds):
    failed = False
    for fd in fds:
        try:
            os.close(fd)
        except (OSError, KeyboardInterrupt):
            failed = True
    require(not failed)


def peer_socket(stream):
    """Check the actual stdin socketpair; never accept a named listener/PTY."""
    with _STARTUP.scope("peer_shape"):
        require(stream.family == socket.AF_UNIX
                and stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
                and stream.getsockname() in ("", b"") and stream.getpeername() in ("", b""))
    with _STARTUP.scope("peer_cred"):
        pid, uid, gid = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(pid > 0 and uid >= 0 and gid >= 0)
    with _STARTUP.scope("peer_pidfd"):
        fd = stream.getsockopt(socket.SOL_SOCKET, locator.SO_PEERPIDFD)
    try:
        with _STARTUP.scope("peer_cloexec"):
            os.set_inheritable(fd, False)
        with _STARTUP.scope("peer_live"):
            locator.live(fd)
        return pid, uid, gid, fd
    except BaseException:
        with boundary.startup_cleanup():
            os.close(fd)
        raise


class Channel:
    """One stream; recvmsg remains mandatory through terminal EOF."""

    def __init__(self, stream, budget, peer_pidfd):
        self.stream, self.budget, self.peer_pidfd = stream, budget, peer_pidfd
        self.sequence = 0
        self.reservation = 0
        # Three live slots cover the accepted capture capability plus both
        # detectable ancillary descriptors during any subsequent recvmsg.
        with _STARTUP.scope("channel_fds"):
            for _ in range(3):
                budget.fd()
        with _STARTUP.scope("chan_nonblock"):
            self.stream.setblocking(False)
        with _STARTUP.scope("chan_cloexec"):
            self.stream.set_inheritable(False)

    def wait(self, writing=False):
        self.budget.check()
        locator.live(self.peer_pidfd)
        terminal = self.budget.deadline_ns if getattr(self.budget, "cleanup_only", False) else self.budget.work_ns
        timeout = min(0.1, max(0, (terminal - self.budget.clock()) / 1e9))
        while True:
            readers, writers, _ = select.select(
                [self.peer_pidfd] if writing else [self.peer_pidfd, self.stream],
                [self.stream] if writing else [], [], timeout)
            self.budget.check()
            locator.live(self.peer_pidfd)
            if writers if writing else self.stream in readers:
                return
            timeout = min(0.1, max(0, (terminal - self.budget.clock()) / 1e9))

    def receive(self, size, *, bootstrap=False):
        with _STARTUP.scope("boot_wait"):
            self.wait()
        with _STARTUP.scope("boot_recv"):
            self.budget.read(size)
            body, controls, flags, _address = self.stream.recvmsg(
                size, socket.CMSG_SPACE(2 * array.array("i").itemsize),
                socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT)
        with _STARTUP.scope("boot_ancillary"):
            rights, valid = [], not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
            for level, kind, data in controls:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    items = array.array("i")
                    width = items.itemsize
                    items.frombytes(data[:len(data) - len(data) % width])
                    rights.extend(items)
                    valid = valid and len(data) % width == 0
                else:
                    valid = False
            if not valid or (not bootstrap and rights) or len(rights) > 1:
                # The predicate already failed; close_all must not hide it.
                _STARTUP.fault("boot_ancillary", boundary.Refusal())
                close_all(rights)
                raise boundary.Refusal()
        return body, rights

    def bootstrap(self, uid):
        body, held = bytearray(), []
        try:
            while len(body) < len(BOOT):
                part, rights = self.receive(len(BOOT) - len(body), bootstrap=True)
                with _STARTUP.scope("boot_accumulate"):
                    held.extend(rights)
                    require(part and len(held) <= 1)
                    body.extend(part)
            # Preserve the original short-circuit guard and tag its failed arm.
            with _STARTUP.scope("boot_marker"):
                require(bytes(body) == BOOT)
            with _STARTUP.scope("boot_count"):
                require(len(held) == 1)
            fd = held[0]
            with _STARTUP.scope("boot_stat"):
                info = os.fstat(fd)
            with _STARTUP.scope("boot_dir"):
                require(stat.S_ISDIR(info.st_mode))
            with _STARTUP.scope("boot_mode"):
                require(stat.S_IMODE(info.st_mode) == 0o700)
            with _STARTUP.scope("boot_uid"):
                require(info.st_uid == uid)
            with _STARTUP.scope("boot_cloexec"):
                require(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            self.send_raw(READY)
            # Supervisor memory is independent and cannot observe this boundary.
            _STARTUP.stop()
            held.clear()
            return fd
        finally:
            with boundary.startup_cleanup():
                close_all(held)

    def exact(self, size):
        result = bytearray()
        while len(result) < size:
            part, _rights = self.receive(size - len(result))
            require(part)
            result.extend(part)
        return bytes(result)

    def object(self):
        self.budget.frames += 1
        require(self.budget.frames <= 64)
        size = struct.unpack("!I", self.exact(4))[0]
        require(0 < size <= MAX_FRAME)
        body = self.exact(size)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result)
                result[key] = value
            return result
        value = json.loads(body, object_pairs_hook=unique, parse_constant=lambda _: require(False))
        require(type(value) is dict and value.get("version") == VERSION
                and type(value.get("version")) is int and type(value.get("sequence")) is int)
        return value

    def request(self):
        value = self.object()
        require(value["sequence"] == self.sequence + 1)
        self.sequence += 1
        return value

    def reserve_api(self, units, maximum):
        with _BIND.scope("reserve_api"):
            require(units == 1 and maximum in (locator.VERSION_CAP, locator.INSPECT_CAP))
            self.reservation += 1
            require(self.reservation <= 31 and self.sequence > 0)
            self.response({"version": VERSION, "sequence": self.sequence, "op": "ReserveApi",
                           "reservation": self.reservation, "units": 1, "max_body_bytes": maximum})
            acknowledgment = self.object()  # same outstanding owner request, not new work
            boundary.closed(acknowledgment, ("version", "sequence", "op", "reservation"))
            require(acknowledgment["sequence"] == self.sequence
                    and acknowledgment["op"] == "ApiReservationAccepted"
                    and type(acknowledgment["reservation"]) is int
                    and acknowledgment["reservation"] == self.reservation)

    def eof(self):
        part, _rights = self.receive(1)
        require(part == b"")

    def send_raw(self, body):
        with _STARTUP.scope("ready_budget"):
            self.budget.emit(len(body))
        offset = 0
        while offset < len(body):
            with _STARTUP.scope("ready_wait"):
                self.wait(writing=True)
            with _STARTUP.scope("ready_send"):
                size = self.stream.send(body[offset:], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
                require(size > 0)
                offset += size

    def response(self, value):
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")
        require(len(payload) <= MAX_FRAME)
        self.send_raw(struct.pack("!I", len(payload)) + payload)


class RootSession:
    """All measurement/source objects live here, with two-phase finalization.

    Registration comes from a future original-runtime-owner integration, not a
    JSON request supplying process facts, paths, a provider or a new deadline.
    """

    def __init__(self, runtime_locator, registered_slots):
        require(type(runtime_locator) is locator.RuntimeLocator)
        require(type(registered_slots) is dict and tuple(registered_slots) == locator.ORDER)
        self.locator = runtime_locator
        self.source = runtime_locator.source
        self.budget = self.source.budget
        self.registered = dict(registered_slots)
        self.phase = "registered"
        self.samples = {slot: [] for slot in locator.ORDER}
        self.failed = False

    def handle(self, request, channel):
        try:
            require(not self.failed and self.phase != "finished")
            self.budget.check()
            operation = request.get("op")
            common = ("version", "sequence", "op")
            if operation == "LocateBatch":
                boundary.closed(request, common)
                require(self.phase == "registered")
                self.locator.locate_batch(self.registered)
                self.phase = "measuring"
                result = {"status": "ok"}
            elif operation == "RecheckBatch":
                boundary.closed(request, common)
                require(self.phase == "measuring")
                self.locator.recheck_batch()
                result = {"status": "ok"}
            elif operation == "Sample":
                boundary.closed(request, common + ("slot", "phase"))
                require(self.phase == "measuring" and type(request["slot"]) is str
                        and type(request["phase"]) is str and request["slot"] in self.samples)
                slot, phase = request["slot"], request["phase"]
                expected = ("before", "at_limit", "after_failure", "after_release") if slot.endswith("16") else (
                    "before", "at_limit", "control", "after_release")
                done = self.samples[slot]
                require(len(done) < 4 and phase == expected[len(done)])
                item = self.locator.bound[slot]
                self.locator.check_daemon()
                sample = self.source.snapshot(item.process, item.group)
                maximum = "max" if slot.endswith("unlimited") else (16 if slot.endswith("16") else 64)
                require(sample["maximum"] == maximum)
                self.locator.check_daemon()
                done.append(phase)
                result = {"sample": sample}
            elif operation == "SealMeasurements":
                boundary.closed(request, common)
                require(self.phase == "measuring" and all(len(x) == 4 for x in self.samples.values()))
                self.locator.seal_measurements()
                self.budget.begin_cleanup()
                self.phase = "sealed"
                result = {"status": "sealed"}
            elif operation == "OuterFinalize":
                boundary.closed(request, common)
                require(self.phase == "sealed")
                require(self.budget.clock() < self.budget.deadline_ns - 2_000_000_000)
                # The trusted owner has already removed the sealed leaves. No
                # removed PID/cgroup is required to survive this terminal check.
                channel.eof()
                self.locator.check_daemon()
                self.source.close()
                require(self.budget.clock() < self.budget.deadline_ns - 2_000_000_000)
                self.phase = "finished"
                result = {"status": "finalized"}
            else:
                raise boundary.Refusal()
            return {"version": VERSION, "sequence": request["sequence"], "op": operation, **result}
        except BaseException:
            self.failed = True
            raise


class RuntimeBoundSession:
    """Fixed root factory plus pending/confirmed measured source lifecycle.

    Outer numeric fields are locators from the exclusive original runtime
    owner. Only that owner's actual before/after CID inspections corroborate
    association; no root response or caller-declared verified flag proves it.
    """

    def __init__(self, source):
        require(type(source) is locator.LocatorSource
                and hasattr(source, "capture_directory") and source.capture_directory in source.owned)
        self.source, self.budget = source, source.budget
        self.phase, self.failed = "unbound", False
        self.context, self.runtime, self.measurements, self.accounting = None, None, None, None

    def handle(self, request, channel):
        with _BIND.scope("handler"):
            try:
                require(not self.failed and self.phase != "finished")
                self.budget.check()
                common = ("version", "sequence", "op")
                operation = request.get("op")
                if operation == "RootBindRuntime":
                    with _BIND.scope("request_schema"):
                        boundary.closed(request, common + ("context", "outer_pid", "outer_start", "owner_labels", "external_source"))
                        require(self.phase == "unbound")
                    with _BIND.scope("context_schema"):
                        context = request["context"]
                        boundary.closed(context, ("backend", "candidate", "run", "lane", "outer_id"))
                        require(context["backend"] in ("docker", "podman") and context["lane"] in LANES
                                and all(type(value) is str for value in context.values())
                                and locator.re.fullmatch(r"[a-f0-9]{40}", context["candidate"]) is not None
                                and locator.re.fullmatch(r"[a-f0-9]{64}", context["outer_id"]) is not None
                                and locator.re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", context["run"]) is not None)
                    with _BIND.scope("labels"):
                        require(request["owner_labels"] == {OWNER_LABEL: context["run"]})
                    with _BIND.scope("external_debit"):
                        external = request["external_source"]
                        boundary.closed(external, ("bytes", "reads"))
                        self.budget.debit_external(external["bytes"], external["reads"])
                    with _BIND.scope("outer_args"):
                        pid = boundary.integer(request["outer_pid"], high=(1 << 31) - 1)
                        start = boundary.integer(request["outer_start"])
                    with _BIND.scope("outer_process"):
                        outer = self.source.process(pid, start)
                    with _BIND.scope("outer_vector"):
                        _facts, vector = locator.status_vectors(self.source.read(outer.directory, "status", 4096), pid)
                        require(len(vector) >= 2 and vector[-1] == 1)
                    with _BIND.scope("outer_pidns"):
                        self.source.namespace_chain(outer.namespaces[0], vector)
                    with _BIND.scope("outer_cgroup"):
                        group = self.source.configured_outer_group(outer)
                    with _BIND.scope("endpoint"):
                        endpoint = locator.HeldEndpoint(self.source, self.source.capture_directory)
                    with _BIND.scope("daemon_context"):
                        uid, executable, engine, api = LANES[context["lane"]]
                        self.accounting = locator.ParentReservations(channel.reserve_api)
                        runtime = locator.RuntimeLocator(self.source, outer, group, endpoint,
                            locator.DaemonExpectation(uid, executable, True), api,
                            {OWNER_LABEL: context["run"]}, self.accounting, slot_label=SLOT_LABEL)
                    with _BIND.scope("daemon_bind"):
                        runtime.bind_runtime(engine, self.accounting.reserve_probe)
                    with _BIND.scope("outer_recheck"):
                        self.source.check_process(outer)
                    self.context, self.runtime = dict(context), runtime
                    self.phase = "pending"
                    result = {"status": "pending"}
                elif operation == "ConfirmRuntime":
                    boundary.closed(request, common)
                    require(self.phase == "pending")
                    # The canonical owner sends this ONLY after its second actual
                    # selected-runtime inspection equals its original CID facts.
                    # This request itself is not evidence that those calls ran.
                    self.runtime.check_daemon()
                    self.phase = "confirmed"
                    result = {"status": "confirmed"}
                elif operation == "LocateBatch":
                    boundary.closed(request, common + ("slots",))
                    require(self.phase == "confirmed" and type(request["slots"]) is dict
                            and tuple(request["slots"]) == locator.ORDER)
                    self.measurements = RootSession(self.runtime, request["slots"])
                    reply = self.measurements.handle({key: request[key] for key in common}, channel)
                    self.phase = self.measurements.phase
                    return reply
                else:
                    require(self.measurements is not None)
                    reply = self.measurements.handle(request, channel)
                    self.phase = self.measurements.phase
                    if self.phase == "finished":
                        reply["reservations"] = self.accounting.receipt()
                        reply["source_ledger"] = self.budget.ledger(len(self.source.owned))
                    return reply
                return {"version": VERSION, "sequence": request["sequence"], "op": operation, **result}
            except BaseException:
                self.failed = True
                raise


def guard_parent(source, peer, supervisor_pid):
    """Actual held peer, namespace and bounded sudo monitor ancestry."""
    pid, uid, _gid, pidfd = peer
    with _STARTUP.scope("parent_live"):
        locator.live(pidfd)
    with _STARTUP.scope("parent_stat"):
        start = boundary.start_from_stat(source.read(source.proc, str(pid) + "/stat", 1024), pid)
    with _STARTUP.scope("parent_process"):
        parent = source.process(pid, start)
    with _STARTUP.scope("parent_uid"):
        require(parent.status[1] == (uid,) * 4)
    with _STARTUP.scope("parent_cgroup"):
        require(boundary.identity(source.reader_cgroup_namespace) == boundary.identity(parent.namespaces[2]))
    source.authenticated_parent_process = parent
    source.authenticated_parent_cgroup_namespace = parent.namespaces[2]
    with _STARTUP.scope("parent_time"):
        own_time = source.open("self/ns/time", source.proc, magic=True)
        parent_time = source.open("ns/time", parent.directory, magic=True)
        require(boundary.identity(own_time) == boundary.identity(parent_time))
    with _STARTUP.scope("parent_link"):
        require(os.getppid() == supervisor_pid)
    current = supervisor_pid
    sudo_identity = None
    ancestry = []
    for _ in range(8):
        if current == pid:
            with _STARTUP.scope("anc_recheck"):
                source.check_process(parent)
                for process, ppid in ancestry:
                    source.check_process(process)
                    rows = [line.split()[1:] for line in source.read(process.directory, "status", 4096).splitlines()
                            if line.startswith(b"PPid:")]
                    require(rows == [[str(ppid).encode()]])
                locator.live(pidfd)
            return parent
        with _STARTUP.scope("anc_load"):
            start = boundary.start_from_stat(source.read(source.proc, str(current) + "/stat", 1024), current)
            process = source.process(current, start)
        with _STARTUP.scope("anc_uid"):
            # A setuid-root sudo parent may retain the peer's real UID. This
            # candidate still requires the fixed sudo inode below; never widen
            # the authenticated peer or supervisor credential contract.
            require(process.status[1] in ((0,) * 4, (uid,) * 4)
                    or (current != supervisor_pid and uid > 0
                        and process.status[1] == (uid, 0, 0, 0)))
        with _STARTUP.scope("anc_ppid"):
            status = source.read(process.directory, "status", 4096)
            rows = [line.split()[1:] for line in status.splitlines() if line.startswith(b"PPid:")]
            require(len(rows) == 1 and len(rows[0]) == 1 and rows[0][0].isdigit())
        if current != supervisor_pid:
            # Permitted sudo monitor shape, never SUDO_UID or caller JSON.
            if sudo_identity is None:
                with _STARTUP.scope("anc_sudo"):
                    sudo = source.open("/usr/bin/sudo")
                    sudo_identity = boundary.identity(sudo)
            with _STARTUP.scope("anc_exe"):
                executable = source.open("exe", process.directory, magic=True)
                require(boundary.identity(executable) == sudo_identity)
        ancestry.append((process, int(rows[0][0])))
        current = int(rows[0][0])
        with _STARTUP.scope("anc_ppid"):
            require(current > 0)
    with _STARTUP.scope("anc_end"):
        raise boundary.Refusal()


def serve_session(channel, session):
    """One request in flight; terminal acknowledgment follows EOF and cleanup."""
    try:
        while session.phase != "finished":
            with _BIND.scope("request_read"):
                request = channel.request()
            with _BIND.scope("pending_reply"):
                channel.response(session.handle(request, channel))
            if session.phase == "pending":
                # Only a FULL original pending response disables observation.
                _BIND.stop()
    finally:
        with boundary.startup_cleanup():
            if session.source.owned:
                session.source.close()


def source_server(stream, deadline_ns, peer, supervisor_pid):
    """Fixed original-owner locator factory; never invokes an outer runtime CLI."""
    source, capture = None, None
    try:
        checked = peer_socket(stream)
        try:
            with _STARTUP.scope("source_peer_eq"):
                require(checked[:3] == peer[:3])
        finally:
            with boundary.startup_cleanup():
                os.close(checked[3])
        with _STARTUP.scope("source_budget"):
            budget = locator.RuntimeBudget(deadline_ns)
        source = locator.LocatorSource(budget)
        guard_parent(source, peer, supervisor_pid)
        channel = Channel(stream, budget, peer[3])
        capture = channel.bootstrap(peer[1])
        # Bootstrap/READY and its final cleanup have already returned. The gap
        # before activation is unobserved; START stays stopped permanently.
        _BIND.begin()
        with _BIND.scope("capture_adopt"):
            source.adopt_capture_directory(capture)
        capture = None  # transfer is irreversible; never close a reused number
        with _BIND.scope("session_init"):
            session = RuntimeBoundSession(source)
        serve_session(channel, session)
    finally:
        with boundary.startup_cleanup():
            failed = False
            if capture is not None:
                try:
                    os.close(capture)
                except (OSError, KeyboardInterrupt):
                    failed = True
            if source is not None:
                try:
                    source.close()
                except (Exception, KeyboardInterrupt):
                    failed = True
            require(not failed)


def monitor(parent_pidfd, child, child_pidfd, deadline_ns, *, clock=time.monotonic_ns,
            unmask=None):
    """No JSON, filesystem or runtime I/O; retain original terminal deadline."""
    cancelled = False
    old = {}
    def cancel(_signal, _frame):
        nonlocal cancelled
        cancelled = True
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        with _STARTUP.scope("mon_handlers"):
            old[number] = signal.signal(number, cancel)
    term_at, killed = None, False
    try:
        if unmask is not None:
            with _STARTUP.scope("mon_unmask"):
                signal.pthread_sigmask(signal.SIG_SETMASK, unmask)
        while True:
            with _STARTUP.scope("mon_wait"):
                now = clock()
                parent_dead = bool(select.select([parent_pidfd], [], [], 0)[0])
            if term_at is None and (cancelled or parent_dead or now >= deadline_ns - 2_000_000_000):
                term_at = now
                try:
                    os.killpg(child, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            kill_at = min(deadline_ns, term_at + 1_000_000_000) if term_at is not None else deadline_ns
            if not killed and now >= kill_at:
                killed = True
                try:
                    os.killpg(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            with _STARTUP.scope("mon_wait"):
                done, status = os.waitpid(child, os.WNOHANG)
            if done:
                return 0 if not (cancelled or parent_dead or killed or term_at is not None) and status == 0 else 1
            if now >= deadline_ns:
                # Unreapable tasks are failed cleanup, never a blocking extension.
                return 1
            # Never block beyond the next original-deadline action.
            with _STARTUP.scope("mon_wait"):
                timeout = max(0, min(0.05, (kill_at - clock()) / 1e9))
                select.select([parent_pidfd, child_pidfd], [], [], timeout)
    finally:
        with boundary.startup_cleanup():
            for number, previous in old.items():
                signal.signal(number, previous)


def supervise(stream, deadline_ns):
    with _STARTUP.scope("root_uid"):
        require(os.geteuid() == 0)
    with _STARTUP.scope("root_deadline"):
        now = time.monotonic_ns()
        require(type(deadline_ns) is int and now + boundary.RESERVE_NS < deadline_ns <= now + 180_000_000_000)
    peer = peer_socket(stream)
    child = None
    child_pidfd = None
    with _STARTUP.scope("gate_pipe"):
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    # Block cancellation until ownership/handshake and monitor handlers exist.
    numbers = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    with _STARTUP.scope("block_signals"):
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, numbers)
    supervisor_pid = os.getpid()
    try:
        with _STARTUP.scope("source_fork"):
            child = os.fork()
        if child == 0:
            # Fork copies memory: reset role/latch before the first child work.
            _STARTUP.reset("w")
            _BIND.reset()
            try:
                with _STARTUP.scope("kid_gate_close"):
                    os.close(gate_write)
                with _STARTUP.scope("kid_pgroup"):
                    os.setpgid(0, 0)
                # A killed watchdog must not orphan a privileged blocked reader.
                with _STARTUP.scope("kid_pdeath"):
                    libc = boundary.ctypes.CDLL(None, use_errno=True)
                    require(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0)
                with _STARTUP.scope("kid_parent"):
                    require(os.getppid() == supervisor_pid)
                with _STARTUP.scope("kid_gate_read"):
                    require(os.read(gate_read, 1) == b"G")
                with _STARTUP.scope("kid_gate_done"):
                    os.close(gate_read)
                with _STARTUP.scope("kid_unmask"):
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                source_server(stream, deadline_ns, peer, supervisor_pid)
                result = 0
            except BaseException:
                result = 1
            finally:
                with boundary.startup_cleanup():
                    stream.close()
                    os.close(peer[3])
            os._exit(result)
        with _STARTUP.scope("par_gate_close"):
            os.close(gate_read)
        gate_read = None
        with _STARTUP.scope("par_pgroup"):
            os.setpgid(child, child)
        with _STARTUP.scope("par_pidfd"):
            child_pidfd = os.pidfd_open(child)
        with _STARTUP.scope("par_sockclose"):
            stream.close()
        with _STARTUP.scope("par_gate_send"):
            os.write(gate_write, b"G")
        with _STARTUP.scope("par_gate_done"):
            os.close(gate_write)
        gate_write = None
        # Signals stay blocked until monitor installed handlers; it unmasks via
        # the supplied wrapper immediately before entering its polling loop.
        return monitor(peer[3], child, child_pidfd, deadline_ns, unmask=previous_mask)
    finally:
        with boundary.startup_cleanup():
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            for fd in (gate_read, gate_write, child_pidfd, peer[3]):
                if fd is not None:
                    os.close(fd)
            if child is not None:
                try:
                    done, _status = os.waitpid(child, os.WNOHANG)
                    if not done:
                        # The unreaped child still owns this number/group. Do not
                        # signal a numeric group after reaping its original owner.
                        os.killpg(child, signal.SIGKILL)
                        os.waitpid(child, os.WNOHANG)
                except ChildProcessError:
                    pass
                except ProcessLookupError:
                    pass


def main(argv=None):
    _STARTUP.reset("s")
    try:
        with _STARTUP.scope("args"):
            args = sys.argv[1:] if argv is None else argv
            require(len(args) == 2 and args[0] == "supervise"
                    and 0 < len(args[1]) <= 19 and args[1].isascii() and args[1].isdigit())
        with _STARTUP.scope("fd0"):
            require(stat.S_ISSOCK(os.fstat(0).st_mode))
        with _STARTUP.scope("socket_wrap"):
            stream = socket.socket(fileno=0)
        with stream:
            result = supervise(stream, int(args[1]))
        if result:
            # A derived child result is not an authored startup work fault.
            raise boundary.Refusal()
        return 0
    except BaseException:
        try:
            os.write(2, b"native-pids-supervisor: refused\n")
        except OSError:
            pass
        return 1
    finally:
        _STARTUP.stop()


if __name__ == "__main__":
    sys.exit(main())
