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
"""

import contextlib
import ctypes
import errno
import importlib.util
import os
from pathlib import Path
import re
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
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.deadline = clock() + SECONDS
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
             runner=None, clock=time.monotonic, euid=os.geteuid):
    if (not re.fullmatch(r"[a-zA-Z0-9]{8}", run_id)
            or container != "dl-native-" + run_id or mode not in ("rootful", "rootless")):
        return _unknown("input")
    if euid() != 0:
        return _unknown("privilege")
    budget = Budget(clock)
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


def main():
    def cancelled(_signal, _frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGALRM, signal.SIG_IGN)
        raise Uncertain("budget")

    for kind in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(kind, cancelled)
    signal.setitimer(signal.ITIMER_REAL, SECONDS)
    try:
        records = diagnose(*sys.argv[1:]) if len(sys.argv) == 4 else _unknown("input")
    except Uncertain:
        records = _unknown("budget")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    for record in records:
        print("DOCKERLENS_NATIVE_DEVICE_SOURCE: " + " ".join(
            f"{field}={value}" for field, value in record.items()
        ))


if __name__ == "__main__":
    main()
