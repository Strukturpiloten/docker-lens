#!/usr/bin/env python3
"""Read fixed device metadata in one owned daemon view; never runc/access proof.

Run as host UID 0 under a root-owned timeout. Only ownership-checked Podman
inspect and procfs metadata reads occur. Every proc directory and metadata file
is filesystem-checked through its held descriptor; root/exe/ns magic-link
targets instead retain independent identity/type checks. There is no namespace
entry, guest exec, device open, mutation, native admission, or private output
capture file.
The monotonic/read/enumeration bounds and held descriptors make uncertainty
explicit; these snapshots are not an atomic account of a transient runtime.
In both modes the daemon must share the verified owned init's held PID namespace;
a foreign or nested PID namespace yields unknown, even with genuine procfs.
The private context/batch modes share one caller-timed five-second phase; an
anonymous stdin lifeline stops later reads after caller cancellation. Neither
local timeout nor lifeline EOF proves privileged/remote work was terminated.
"""

import contextlib
import ctypes
import errno
import importlib.util
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import time


def _inspection_helper():
    spec = importlib.util.spec_from_file_location(
        "device_source_inspection", Path(__file__).with_name("native-cgroup-diagnostic.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INSPECTION = _inspection_helper()
SECONDS = 5
SLICE_SECONDS = 2
PHASE_RESERVE = 0.7
BATCH_OUTPUT_LIMIT = 2048
BYTE_LIMIT = 32768
PROC_LIMIT = 1024
PROCFS = 0x9FA0
NSFS = 0x6E736673
NAMESPACES = ("mnt", "user", "pid")
ROLES = (("host-null", "null"), ("renamed-null", "native-null"))
UNCERTAINTIES = frozenset((
    "none", "input", "privilege", "identity", "ambiguous", "proc",
    "permission", "symlink", "changed", "budget", "io",
))
INSPECT_FORMAT = (
    '{{.Id}}|{{.Name}}|{{.State.Running}}|'
    '{{index .Config.Labels "io.dockerlens.native-run"}}|'
    '{{.State.Pid}}|{{json .State.StartedAt}}'
)


class Uncertain(Exception):
    """Only closed categories may escape private observations."""

    def __init__(self, category):
        assert category in UNCERTAINTIES and category != "none"
        super().__init__(category)
        self.category = category


class Budget:
    def __init__(self, clock=time.monotonic, deadline=None):
        self.clock = clock
        limit = clock() + SECONDS
        self.deadline = min(limit, deadline) if deadline is not None else limit
        self.total = 0

    def check(self):
        if self.clock() >= self.deadline:
            raise Uncertain("budget")

    def consume(self, count):
        self.check()
        self.total += count
        if self.total > BYTE_LIMIT:
            raise Uncertain("budget")


def _pid(value):
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > 2**31 - 1:
        raise Uncertain("proc")
    return int(value)


def _start_ticks(payload, pid):
    try:
        text = payload.decode("ascii")
        before, after = text.rsplit(") ", 1)
        fields = after.split()
        if (not before.startswith(f"{pid} (") or len(fields) < 20
                or fields[0] not in ("R", "S", "D", "T", "t", "W", "I", "K", "P")
                or not re.fullmatch(r"[1-9][0-9]{0,19}", fields[19])):
            raise Uncertain("proc")
        return int(fields[19])
    except (UnicodeError, ValueError) as error:
        raise Uncertain("proc") from error


def _uid(payload):
    try:
        rows = [line.split() for line in payload.decode("ascii").splitlines()
                if line.startswith("Uid:")]
    except UnicodeError as error:
        raise Uncertain("proc") from error
    if len(rows) != 1 or len(rows[0]) != 5:
        raise Uncertain("proc")
    for value in rows[0][1:]:
        if not re.fullmatch(r"[0-9]{1,10}", value) or int(value) > 2**32 - 2:
            raise Uncertain("proc")
    return int(rows[0][2])


def _key(metadata):
    return metadata.st_dev, metadata.st_ino


def _leaf_key(metadata):
    return (*_key(metadata), metadata.st_mode, metadata.st_rdev, metadata.st_ctime_ns)


def _filesystem(fd):
    # Linux statfs begins with a native long f_type. Reserve more than either
    # supported amd64/arm64 structure requires, without a platform-specific copy.
    buffer = ctypes.create_string_buffer(256)
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.fstatfs
    function.argtypes = (ctypes.c_int, ctypes.c_void_p)
    function.restype = ctypes.c_int
    if function(fd, buffer) != 0:
        code = ctypes.get_errno()
        raise OSError(code, "private filesystem read failed")
    return ctypes.c_long.from_buffer(buffer).value


class ProcReader:
    """Descriptor-only fixed paths; the private host-proc seam is test-injected."""

    def __init__(self, budget, host_proc="/proc", filesystem=_filesystem):
        self.budget = budget
        self.host_proc = host_proc
        self.filesystem = filesystem

    def directory(self, parent, name):
        self.budget.check()
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                       | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)

    def proc_directory(self, parent, name):
        fd = self.directory(parent, name)
        try:
            if self.filesystem(fd) != PROCFS:
                raise Uncertain("proc")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def host(self):
        return self.proc_directory(None, self.host_proc)

    def read(self, parent, name, limit):
        self.budget.check()
        with contextlib.ExitStack() as stack:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                         | os.O_NONBLOCK, dir_fd=parent)
            stack.callback(os.close, fd)
            if (not stat.S_ISREG(os.fstat(fd).st_mode)
                    or self.filesystem(fd) != PROCFS):
                raise Uncertain("proc")
            payload = os.read(fd, limit + 1)
            self.budget.consume(len(payload))
            if len(payload) > limit:
                raise Uncertain("budget")
            return payload

    def reference(self, parent, name, filesystem=None):
        # root/exe and ns/* are intentionally kernel procfs magic links; all
        # containing process/ns directories have already been pinned in procfs.
        self.budget.check()
        fd = os.open(name, os.O_PATH | os.O_CLOEXEC, dir_fd=parent)
        try:
            if filesystem is not None and self.filesystem(fd) != filesystem:
                raise Uncertain("proc")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def process(self, parent, pid):
        return PinnedProcess(self, parent, pid)

    def find_daemon(self, guest_proc, mode):
        selected = None
        try:
            with os.scandir(guest_proc) as entries:
                for count, entry in enumerate(entries, 1):
                    self.budget.check()
                    if count > PROC_LIMIT:
                        raise Uncertain("budget")
                    if not entry.name.isascii() or not entry.name.isdecimal():
                        continue
                    pid = _pid(entry.name)
                    with contextlib.ExitStack() as stack:
                        fd = self.proc_directory(guest_proc, entry.name)
                        stack.callback(os.close, fd)
                        comm = self.read(fd, "comm", 64)
                    if comm != b"dockerd\n":
                        continue
                    if selected is not None:
                        raise Uncertain("ambiguous")
                    selected = self.process(guest_proc, pid)
                    uid = selected.snapshot[1]
                    if (mode == "rootful" and uid != 0) or (mode == "rootless" and uid == 0):
                        raise Uncertain("identity")
                    selected.require_daemon()
            if selected is None:
                raise Uncertain("identity")
            return selected
        except BaseException:
            if selected is not None:
                selected.close()
            raise

    def leaf(self, dev, name):
        self.budget.check()
        try:
            metadata = os.stat(name, dir_fd=dev, follow_symlinks=False)
        except FileNotFoundError:
            return "missing", "none", None
        except PermissionError:
            return "unknown", "permission", None
        if stat.S_ISLNK(metadata.st_mode):
            return "unknown", "symlink", _leaf_key(metadata)
        node = ("null" if stat.S_ISCHR(metadata.st_mode)
                and metadata.st_rdev == os.makedev(1, 3) else "other")
        return node, "none", _leaf_key(metadata)


class PinnedProcess:
    def __init__(self, reader, parent, pid):
        self.reader, self.parent, self.pid = reader, parent, pid
        self.stack = contextlib.ExitStack()
        try:
            self.proc = self._hold(reader.proc_directory(parent, str(pid)))
            self.root = self._hold(reader.reference(self.proc, "root"))
            self.exe = self._hold(reader.reference(self.proc, "exe"))
            ns = self._hold(reader.proc_directory(self.proc, "ns"))
            self.namespaces = {name: self._hold(reader.reference(ns, name, NSFS))
                               for name in NAMESPACES}
            self.snapshot = self._snapshot(self.proc)
            if not stat.S_ISDIR(os.fstat(self.root).st_mode) or not stat.S_ISREG(os.fstat(self.exe).st_mode):
                raise Uncertain("proc")
            self.verify()
        except BaseException:
            self.close()
            raise

    def _hold(self, fd):
        self.stack.callback(os.close, fd)
        return fd

    def _snapshot(self, proc):
        reader = self.reader
        with contextlib.ExitStack() as stack:
            references = []
            for name in ("root", "exe"):
                fd = reader.reference(proc, name)
                stack.callback(os.close, fd)
                references.append(_key(os.fstat(fd)))
            ns = reader.proc_directory(proc, "ns")
            stack.callback(os.close, ns)
            for name in NAMESPACES:
                fd = reader.reference(ns, name, NSFS)
                stack.callback(os.close, fd)
                references.append(_key(os.fstat(fd)))
            return (_start_ticks(reader.read(proc, "stat", 4096), self.pid),
                    _uid(reader.read(proc, "status", 4096)),
                    reader.read(proc, "comm", 64), tuple(references))

    def verify(self):
        reader = self.reader
        with contextlib.ExitStack() as stack:
            current = reader.proc_directory(self.parent, str(self.pid))
            stack.callback(os.close, current)
            held = tuple(_key(os.fstat(fd)) for fd in
                         (self.root, self.exe, *self.namespaces.values()))
            if (_key(os.fstat(current)) != _key(os.fstat(self.proc))
                    or self._snapshot(current) != self.snapshot
                    or held != self.snapshot[3]):
                raise Uncertain("changed")

    def require_daemon(self):
        self.reader.budget.check()
        executable = os.readlink("exe", dir_fd=self.proc)
        self.reader.budget.consume(len(os.fsencode(executable)))
        if self.snapshot[2] != b"dockerd\n" or executable.rsplit("/", 1)[-1] != "dockerd":
            raise Uncertain("identity")

    def close(self):
        self.stack.close()


def _record(role, node="unknown", uncertainty="identity", view="unknown"):
    assert role in {item[0] for item in ROLES}
    assert node in ("null", "other", "missing", "unknown")
    assert uncertainty in UNCERTAINTIES
    assert view in ("same_mount", "different_mount", "unknown")
    return dict(role=role, scope="daemon-view", view=view, node=node,
                uncertainty=uncertainty, runtime_source="unknown", permissions="unknown")


def _unknown(category):
    return [_record(role, uncertainty=category) for role, _ in ROLES]


def _os_category(error):
    if error.errno in (errno.EACCES, errno.EPERM):
        return "permission"
    if error.errno in (errno.ELOOP, errno.ENOTDIR):
        return "symlink"
    if error.errno in (errno.ENOENT, errno.ESRCH):
        return "changed"
    return "io"


def diagnose(container, run_id, mode, *, reader_factory=ProcReader,
             runner=None, clock=time.monotonic, euid=os.geteuid, deadline=None):
    if (not re.fullmatch(r"[a-zA-Z0-9]{8}", run_id)
            or container != "dl-native-" + run_id or mode not in ("rootful", "rootless")):
        return _unknown("input")
    if euid() != 0:
        return _unknown("privilege")
    budget = Budget(clock, deadline)
    command_budget = {"total": 0}
    reader = reader_factory(budget)

    def inspect():
        budget.check()
        previous = command_budget["total"]
        command = ["podman", "inspect", "--format", INSPECT_FORMAT, container]
        if runner is None:
            payload = INSPECTION.bounded_command(command, budget.deadline, command_budget)
            budget.consume(command_budget["total"] - previous)
        else:
            payload = runner(command, budget.deadline)
            budget.consume(len(payload))
        try:
            identity = INSPECTION.inspect_identity(payload, container, run_id)
        except INSPECTION.Unavailable as error:
            raise Uncertain("identity") from error
        if _pid(identity[4]) <= 1:
            raise Uncertain("identity")
        return identity

    try:
        before = inspect()
        with contextlib.ExitStack() as stack:
            host_proc = reader.host()
            stack.callback(os.close, host_proc)
            outer = reader.process(host_proc, int(before[4]))
            stack.callback(outer.close)
            guest_proc = reader.proc_directory(outer.root, "proc")
            stack.callback(os.close, guest_proc)
            init = reader.process(guest_proc, 1)
            stack.callback(init.close)
            # The held guest proc mount must actually describe the owned outer
            # init, not another namespace's proc mount or guest-authored files.
            if init.snapshot != outer.snapshot:
                raise Uncertain("proc")
            daemon = reader.find_daemon(guest_proc, mode)
            stack.callback(daemon.close)
            # Genuine procfs can still expose a bind-mounted foreign process.
            # Conservatively reject nested PID namespaces rather than infer ancestry.
            if (_key(os.fstat(daemon.namespaces["pid"]))
                    != _key(os.fstat(init.namespaces["pid"]))):
                raise Uncertain("identity")
            dev = reader.directory(daemon.root, "dev")
            stack.callback(os.close, dev)
            view = ("same_mount" if _key(os.fstat(outer.namespaces["mnt"]))
                    == _key(os.fstat(daemon.namespaces["mnt"])) else "different_mount")
            observed = [reader.leaf(dev, name) for _, name in ROLES]
            for process in (outer, init, daemon):
                process.verify()
            current_dev = reader.directory(daemon.root, "dev")
            stack.callback(os.close, current_dev)
            if _key(os.fstat(current_dev)) != _key(os.fstat(dev)):
                raise Uncertain("changed")
            if observed != [reader.leaf(dev, name) for _, name in ROLES]:
                raise Uncertain("changed")
            after = inspect()
            if before != after:
                raise Uncertain("changed")
            for process in (outer, init, daemon):
                process.verify()
            budget.check()
            return [_record(role, node, uncertainty, view)
                    for (role, _), (node, uncertainty, _) in zip(ROLES, observed)]
    except Uncertain as error:
        return _unknown(error.category)
    except INSPECTION.Unavailable:
        return _unknown("budget" if clock() >= budget.deadline else "io")
    except OSError as error:
        return _unknown(_os_category(error))
    except subprocess.SubprocessError:
        return _unknown("io")
    except (UnicodeError, ValueError):
        return _unknown("proc")


def _context_unknown(reason="budget"):
    return [INSPECTION.unknown(scope) for scope in ("outer", "daemon")] + _unknown(reason)


def phase_clock():
    # Linux /proc/uptime and CLOCK_BOOTTIME share a monotonic, suspend-inclusive
    # clock. The runner reads the former before this interpreter starts.
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def _caller_alive(fd=0):
    # The caller never writes bytes. Only an open anonymous FIFO with no data
    # proves its lifeline is still present; tty/device stdin is not read.
    try:
        return stat.S_ISFIFO(os.fstat(fd).st_mode) and not select.select([fd], [], [], 0)[0]
    except (OSError, ValueError):
        return False


def _format_context(records):
    lines = []
    for index, record in enumerate(records):
        prefix = "CGROUP_DIAG" if index < 2 else "DEVICE_SOURCE"
        lines.append("DOCKERLENS_NATIVE_" + prefix + ": " + " ".join(
            f"{field}={value}" for field, value in record.items()
        ))
    return "\n".join(lines) + "\n"


def _parse_context(payload):
    """Accept a whole closed batch, never grep a private or partial transcript."""
    if len(payload) > BATCH_OUTPUT_LIMIT:
        raise Uncertain("budget")
    lines = payload.decode("ascii").splitlines()
    if len(lines) != 4:
        raise Uncertain("io")
    records = []
    for index, line in enumerate(lines):
        if index < 2:
            prefix = "DOCKERLENS_NATIVE_CGROUP_DIAG: "
            fields = {"scope": (("outer", "daemon")[index],),
                      "outcome": ("observed", "unavailable")}
            fields.update({field: ("present", "absent", "unknown")
                           for field in INSPECTION.FIELDS[:4]})
            fields.update({field: ("finite", "max", "missing", "unknown")
                           for field in INSPECTION.FIELDS[4:]})
        else:
            prefix = "DOCKERLENS_NATIVE_DEVICE_SOURCE: "
            fields = {"role": (ROLES[index - 2][0],), "scope": ("daemon-view",),
                      "view": ("same_mount", "different_mount", "unknown"),
                      "node": ("null", "other", "missing", "unknown"),
                      "uncertainty": UNCERTAINTIES,
                      "runtime_source": ("unknown",), "permissions": ("unknown",)}
        if not line.startswith(prefix):
            raise Uncertain("io")
        tokens = line[len(prefix):].split(" ")
        if len(tokens) != len(fields):
            raise Uncertain("io")
        record = {}
        for token, (field, allowed) in zip(tokens, fields.items()):
            key, separator, value = token.partition("=")
            if separator != "=" or key != field or value not in allowed:
                raise Uncertain("io")
            record[field] = value
        records.append(record)
    return records


def batch(container, run_id, mode, deadline, *, lane=None, clock=phase_clock,
          monotonic=time.monotonic, euid=os.geteuid, alarm=None, interrupted=lambda: False,
          lifeline=lambda: True):
    """Two optional slices under the caller's root-owned, absolute phase bound."""
    records = _context_unknown()
    try:
        INSPECTION.fixture_contract(lane, mode)
    except (INSPECTION.Unavailable, OSError, ImportError):
        return _context_unknown("input")
    if euid() != 0:
        return _context_unknown("privilege")
    deadline = min(deadline, clock() + SECONDS - PHASE_RESERVE)
    alarm = alarm or (lambda seconds: signal.setitimer(signal.ITIMER_REAL, seconds))
    operations = (
        lambda end: INSPECTION.diagnose(container, run_id, mode, ["podman"], deadline=end, lane=lane),
        lambda end: diagnose(container, run_id, mode, deadline=end),
    )
    for index, operation in enumerate(operations):
        if interrupted() or not lifeline():
            return _context_unknown()
        end = min(deadline, clock() + SLICE_SECONDS)
        remaining = end - clock()
        if remaining < 0.4:
            continue
        # The alarm interrupts blocking metadata work with local teardown still
        # reserved. Podman's own bounded capture receives the same slice end.
        alarm(remaining - 0.2)
        try:
            records[index * 2:index * 2 + 2] = operation(monotonic() + end - clock())
        except (Uncertain, INSPECTION.Unavailable, OSError, subprocess.SubprocessError):
            pass
        finally:
            alarm(0)
        if interrupted() or not lifeline():
            return _context_unknown()
    return records


def context(container, run_id, mode, use_sudo, *, lane=None, deadline=None, clock=phase_clock,
            monotonic=time.monotonic, euid=os.geteuid, runner=None):
    """One root batch, capped private pipes, and no assumption of remote teardown."""
    phase_end = min(clock() + SECONDS, deadline) if deadline is not None else clock() + SECONDS
    if (not re.fullmatch(r"[a-zA-Z0-9]{8}", run_id)
            or container != "dl-native-" + run_id or mode not in ("rootful", "rootless")
            or use_sudo not in ("0", "1")):
        return _context_unknown("input")
    try:
        INSPECTION.fixture_contract(lane, mode)
    except (INSPECTION.Unavailable, OSError, ImportError):
        return _context_unknown("input")
    work_end = phase_end - PHASE_RESERVE
    duration = work_end - clock()
    if duration < 0.4:
        return _context_unknown()
    # Truncate, never round a root timer past the allocated work deadline.
    duration = int(duration * 1000) / 1000
    local_end = monotonic() + phase_end - clock()
    command = (["sudo", "-n"] if use_sudo == "1" else []) + [
        "timeout", "--signal=TERM", "--kill-after=0.2", f"{duration:.3f}",
        sys.executable, str(Path(__file__).resolve()), "--batch",
        container, run_id, mode, f"{work_end:.6f}", lane,
    ]
    try:
        capture = runner or INSPECTION.bounded_command
        payload = capture(command, local_end, elevated_until=local_end - 0.2,
                          capture_limit=BATCH_OUTPUT_LIMIT, start_new_session=False,
                          reap_monitor=use_sudo == "1" and euid() != 0, stdin_lifeline=True)
        if clock() >= phase_end:
            return _context_unknown()
        return _parse_context(payload)
    except (Uncertain, INSPECTION.Unavailable, OSError, subprocess.SubprocessError,
            UnicodeError, ValueError):
        return _context_unknown()


def main():
    interrupted = [False]

    def cancelled(_signal, _frame):
        if _signal != signal.SIGALRM:
            interrupted[0] = True
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise Uncertain("budget")

    for kind in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(kind, cancelled)
    signal.setitimer(signal.ITIMER_REAL, SECONDS)
    is_context = len(sys.argv) > 1 and sys.argv[1] in ("--context", "--batch", "--validate-context")
    is_validation = len(sys.argv) > 1 and sys.argv[1] == "--validate-context"
    try:
        if (len(sys.argv) == 3 and is_validation
                and re.fullmatch(r"[0-9]{1,12}\.[0-9]{1,6}", sys.argv[2])):
            remaining = float(sys.argv[2]) - phase_clock()
            if remaining <= 0:
                return 1
            signal.setitimer(signal.ITIMER_REAL, min(SECONDS, remaining))
            records = _parse_context(sys.stdin.buffer.read(BATCH_OUTPUT_LIMIT + 1))
        elif is_validation:
            return 1
        elif (len(sys.argv) == 8 and sys.argv[1] == "--context"
              and re.fullmatch(r"[0-9]{1,12}\.[0-9]{1,6}", sys.argv[6])):
            remaining = float(sys.argv[6]) - phase_clock()
            if remaining <= 0:
                records = _context_unknown()
            else:
                signal.setitimer(signal.ITIMER_REAL, min(SECONDS, remaining))
                records = context(*sys.argv[2:6], deadline=float(sys.argv[6]), lane=sys.argv[7])
        elif len(sys.argv) == 7 and sys.argv[1] == "--context":
            records = context(*sys.argv[2:6], lane=sys.argv[6])
        elif (len(sys.argv) == 7 and sys.argv[1] == "--batch"
              and re.fullmatch(r"[0-9]{1,12}\.[0-9]{1,6}", sys.argv[5])):
            records = batch(*sys.argv[2:5], float(sys.argv[5]), lane=sys.argv[6],
                            interrupted=lambda: interrupted[0], lifeline=_caller_alive)
        elif is_context:
            records = _context_unknown("input")
        else:
            records = diagnose(*sys.argv[1:]) if len(sys.argv) == 4 else _unknown("input")
    except (Uncertain, UnicodeError, ValueError):
        if is_validation:
            return 1
        records = _context_unknown() if is_context else _unknown("budget")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    if is_context:
        print(_format_context(records), end="")
    else:
        for record in records:
            print("DOCKERLENS_NATIVE_DEVICE_SOURCE: " + " ".join(
                f"{field}={value}" for field, value in record.items()
            ))


if __name__ == "__main__":
    sys.exit(main())
