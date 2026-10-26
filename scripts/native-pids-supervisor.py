#!/usr/bin/env python3
"""Fixed PIDs source watchdog and anonymous capability protocol, still unwired.

There is deliberately no runtime-context/PID acquisition fallback. The executable
refuses source binding until the original Rust runtime-owner seam is integrated.
"""

import array
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import sys
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
    require(stream.family == socket.AF_UNIX
            and stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
            and stream.getsockname() in ("", b"") and stream.getpeername() in ("", b""))
    pid, uid, gid = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(pid > 0 and uid >= 0 and gid >= 0)
    fd = stream.getsockopt(socket.SOL_SOCKET, locator.SO_PEERPIDFD)
    try:
        os.set_inheritable(fd, False)
        locator.live(fd)
        return pid, uid, gid, fd
    except BaseException:
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
        for _ in range(3):
            budget.fd()
        self.stream.setblocking(False)
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
        self.wait()
        self.budget.read(size)
        body, controls, flags, _address = self.stream.recvmsg(
            size, socket.CMSG_SPACE(2 * array.array("i").itemsize),
            socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT)
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
            close_all(rights)
            raise boundary.Refusal()
        return body, rights

    def bootstrap(self, uid):
        body, held = bytearray(), []
        try:
            while len(body) < len(BOOT):
                part, rights = self.receive(len(BOOT) - len(body), bootstrap=True)
                held.extend(rights)
                require(part and len(held) <= 1)
                body.extend(part)
            require(bytes(body) == BOOT and len(held) == 1)
            fd = held[0]
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                    and info.st_uid == uid
                    and fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            self.send_raw(READY)
            held.clear()
            return fd
        finally:
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
        self.budget.emit(len(body))
        offset = 0
        while offset < len(body):
            self.wait(writing=True)
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
        try:
            require(not self.failed and self.phase != "finished")
            self.budget.check()
            common = ("version", "sequence", "op")
            operation = request.get("op")
            if operation == "RootBindRuntime":
                boundary.closed(request, common + ("context", "outer_pid", "outer_start", "owner_labels", "external_source"))
                require(self.phase == "unbound")
                context = request["context"]
                boundary.closed(context, ("backend", "candidate", "run", "lane", "outer_id"))
                require(context["backend"] in ("docker", "podman") and context["lane"] in LANES
                        and all(type(value) is str for value in context.values())
                        and locator.re.fullmatch(r"[a-f0-9]{40}", context["candidate"]) is not None
                        and locator.re.fullmatch(r"[a-f0-9]{64}", context["outer_id"]) is not None
                        and locator.re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", context["run"]) is not None)
                require(request["owner_labels"] == {OWNER_LABEL: context["run"]})
                external = request["external_source"]
                boundary.closed(external, ("bytes", "reads"))
                self.budget.debit_external(external["bytes"], external["reads"])
                pid = boundary.integer(request["outer_pid"], high=(1 << 31) - 1)
                start = boundary.integer(request["outer_start"])
                outer = self.source.process(pid, start)
                _facts, vector = locator.status_vectors(self.source.read(outer.directory, "status", 4096), pid)
                require(len(vector) >= 2 and vector[-1] == 1)
                self.source.namespace_chain(outer.namespaces[0], vector)
                group = self.source.configured_outer_group(outer)
                endpoint = locator.HeldEndpoint(self.source, self.source.capture_directory)
                uid, executable, engine, api = LANES[context["lane"]]
                self.accounting = locator.ParentReservations(channel.reserve_api)
                runtime = locator.RuntimeLocator(self.source, outer, group, endpoint,
                    locator.DaemonExpectation(uid, executable, True), api,
                    {OWNER_LABEL: context["run"]}, self.accounting, slot_label=SLOT_LABEL)
                runtime.bind_runtime(engine, self.accounting.reserve_probe)
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
    locator.live(pidfd)
    start = boundary.start_from_stat(source.read(source.proc, str(pid) + "/stat", 1024), pid)
    parent = source.process(pid, start)
    require(parent.status[1] == (uid,) * 4)
    require(boundary.identity(source.reader_cgroup_namespace) == boundary.identity(parent.namespaces[2]))
    source.authenticated_parent_process = parent
    source.authenticated_parent_cgroup_namespace = parent.namespaces[2]
    own_time = source.open("self/ns/time", source.proc, magic=True)
    parent_time = source.open("ns/time", parent.directory, magic=True)
    require(boundary.identity(own_time) == boundary.identity(parent_time))
    require(os.getppid() == supervisor_pid)
    current = supervisor_pid
    sudo_identity = None
    ancestry = []
    for _ in range(8):
        if current == pid:
            source.check_process(parent)
            for process, ppid in ancestry:
                source.check_process(process)
                rows = [line.split()[1:] for line in source.read(process.directory, "status", 4096).splitlines()
                        if line.startswith(b"PPid:")]
                require(rows == [[str(ppid).encode()]])
            locator.live(pidfd)
            return parent
        start = boundary.start_from_stat(source.read(source.proc, str(current) + "/stat", 1024), current)
        process = source.process(current, start)
        require(process.status[1] in ((0,) * 4, (uid,) * 4))
        status = source.read(process.directory, "status", 4096)
        rows = [line.split()[1:] for line in status.splitlines() if line.startswith(b"PPid:")]
        require(len(rows) == 1 and len(rows[0]) == 1 and rows[0][0].isdigit())
        if current != supervisor_pid:
            # Permitted sudo monitor shape, never SUDO_UID or caller JSON.
            if sudo_identity is None:
                sudo = source.open("/usr/bin/sudo")
                sudo_identity = boundary.identity(sudo)
            executable = source.open("exe", process.directory, magic=True)
            require(boundary.identity(executable) == sudo_identity)
        ancestry.append((process, int(rows[0][0])))
        current = int(rows[0][0])
        require(current > 0)
    raise boundary.Refusal()


def serve_session(channel, session):
    """One request in flight; terminal acknowledgment follows EOF and cleanup."""
    try:
        while session.phase != "finished":
            request = channel.request()
            channel.response(session.handle(request, channel))
    finally:
        if session.source.owned:
            session.source.close()


def source_server(stream, deadline_ns, peer, supervisor_pid):
    """Fixed original-owner locator factory; never invokes an outer runtime CLI."""
    source, capture = None, None
    try:
        checked = peer_socket(stream)
        try:
            require(checked[:3] == peer[:3])
        finally:
            os.close(checked[3])
        budget = locator.RuntimeBudget(deadline_ns)
        source = locator.LocatorSource(budget)
        guard_parent(source, peer, supervisor_pid)
        channel = Channel(stream, budget, peer[3])
        capture = channel.bootstrap(peer[1])
        source.adopt_capture_directory(capture)
        capture = None  # transfer is irreversible; never close a reused number
        serve_session(channel, RuntimeBoundSession(source))
    finally:
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
        old[number] = signal.signal(number, cancel)
    term_at, killed = None, False
    try:
        if unmask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, unmask)
        while True:
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
            done, status = os.waitpid(child, os.WNOHANG)
            if done:
                return 0 if not (cancelled or parent_dead or killed or term_at is not None) and status == 0 else 1
            if now >= deadline_ns:
                # Unreapable tasks are failed cleanup, never a blocking extension.
                return 1
            # Never block beyond the next original-deadline action.
            timeout = max(0, min(0.05, (kill_at - clock()) / 1e9))
            select.select([parent_pidfd, child_pidfd], [], [], timeout)
    finally:
        for number, previous in old.items():
            signal.signal(number, previous)


def supervise(stream, deadline_ns):
    require(os.geteuid() == 0)
    now = time.monotonic_ns()
    require(type(deadline_ns) is int and now + boundary.RESERVE_NS < deadline_ns <= now + 180_000_000_000)
    peer = peer_socket(stream)
    child = None
    child_pidfd = None
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    # Block cancellation until ownership/handshake and monitor handlers exist.
    numbers = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, numbers)
    supervisor_pid = os.getpid()
    try:
        child = os.fork()
        if child == 0:
            try:
                os.close(gate_write)
                os.setpgid(0, 0)
                # A killed watchdog must not orphan a privileged blocked reader.
                libc = boundary.ctypes.CDLL(None, use_errno=True)
                require(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0)
                require(os.getppid() == supervisor_pid)
                require(os.read(gate_read, 1) == b"G")
                os.close(gate_read)
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                source_server(stream, deadline_ns, peer, supervisor_pid)
                result = 0
            except BaseException:
                result = 1
            finally:
                stream.close()
                os.close(peer[3])
            os._exit(result)
        os.close(gate_read)
        gate_read = None
        os.setpgid(child, child)
        child_pidfd = os.pidfd_open(child)
        stream.close()
        os.write(gate_write, b"G")
        os.close(gate_write)
        gate_write = None
        # Signals stay blocked until monitor installed handlers; it unmasks via
        # the supplied wrapper immediately before entering its polling loop.
        return monitor(peer[3], child, child_pidfd, deadline_ns, unmask=previous_mask)
    finally:
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
    try:
        args = sys.argv[1:] if argv is None else argv
        require(len(args) == 2 and args[0] == "supervise"
                and 0 < len(args[1]) <= 19 and args[1].isascii() and args[1].isdigit())
        require(stat.S_ISSOCK(os.fstat(0).st_mode))
        with socket.socket(fileno=0) as stream:
            result = supervise(stream, int(args[1]))
        if result:
            raise boundary.Refusal()
        return 0
    except BaseException:
        try:
            os.write(2, b"native-pids-supervisor: refused\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
