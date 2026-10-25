#!/usr/bin/env python3
"""Unwired, supervised Linux PIDs boundary reader. See docs/native-pids-boundary.md.

No caller path, command, namespace entry, controller write or JSON authority replay.
Only the executable entry point constructs LinuxSource; source injection is for tests.
"""

import ctypes
import fcntl
import json
import os
import re
import select
import signal
import stat
import sys
import time
from dataclasses import dataclass


SLOTS = frozenset(("cli16", "cli64", "cli_unlimited", "rendered16", "rendered64", "rendered_unlimited"))
PHASES = frozenset(("before", "at_limit", "after_failure", "after_release", "control"))
FILES = ("pids.max", "pids.current", "pids.events", "cgroup.threads")
NS = ("pid", "mnt", "cgroup")
PROC_MAGIC = 0x9FA0
CGROUP_MAGIC = 0x63677270
FRAME = 2048
MAX_TASKS = 96
RESERVE_NS = 46_000_000_000


class Refusal(Exception):
    """Value-free failure; never wrap native errors in public diagnostics."""


def require(condition):
    if not condition:
        raise Refusal()


def integer(value, low=1, high=(1 << 63) - 1):
    require(type(value) is int and low <= value <= high)
    return value


class Budget:
    """Worst-case reservations precede I/O. Failure never refunds a charge."""

    def __init__(self, deadline_ns, clock=time.monotonic_ns):
        self.clock = clock
        now = clock()
        integer(deadline_ns)
        require(now + RESERVE_NS < deadline_ns <= now + 180_000_000_000)
        self.deadline_ns = deadline_ns
        self.work_ns = deadline_ns - RESERVE_NS
        self.reads = self.bytes = self.fds = self.opens = self.output = self.frames = 0

    def check(self):
        require(self.clock() < self.work_ns)

    def read(self, maximum):
        self.check()
        self.reads += 1
        self.bytes += maximum
        require(self.reads <= 65536 and self.bytes + self.output <= 2 * 1024 * 1024)

    def fd(self):
        self.check()
        self.fds += 1
        self.opens += 1
        require(self.fds <= 256 and self.opens <= 32768)

    def emit(self, maximum):
        self.check()
        self.output += maximum
        require(self.output <= 64 * 1024 and self.bytes + self.output <= 2 * 1024 * 1024)


@dataclass(frozen=True)
class Process:
    pid: int
    start: int
    directory: int
    pidfd: int
    root: int
    namespaces: tuple
    membership: tuple
    identity: tuple
    status: tuple


@dataclass(frozen=True)
class Group:
    # Every directory from the kernel mount root downwards stays held.
    directories: tuple
    names: tuple
    identities: tuple
    files: tuple
    membership: tuple
    mount_record: str


def identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


def fs_magic(fd):
    # Linux statfs starts with a native long f_type. Oversize storage is intentional.
    storage = ctypes.create_string_buffer(256)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.fstatfs(ctypes.c_int(fd), ctypes.byref(storage)) != 0:
        raise Refusal()
    return ctypes.c_long.from_buffer(storage).value


def components(path):
    require(type(path) is str and path.startswith("/") and "\x00" not in path)
    parts = tuple(path[1:].split("/")) if path != "/" else ()
    require(len(parts) <= 20 and all(p and p not in (".", "..") for p in parts))
    return parts


def unescape_mount(value):
    require(not re.search(r"\\(?!040|011|012|134)", value))
    return re.sub(r"\\(040|011|012|134)", lambda m: chr(int(m[1], 8)), value)


def start_from_stat(body, pid):
    # comm can contain spaces and parentheses. The closing delimiter is the last ')'.
    head, separator, rest = body.rpartition(b") ")
    require(separator and head.startswith(str(pid).encode() + b" ("))
    fields = rest.split()
    require(len(fields) >= 20 and fields[0] not in (b"Z", b"X", b"x"))
    require(fields[19].isdigit())
    return integer(int(fields[19]))


def cgroup_path(body):
    lines = body.decode("ascii").splitlines()
    require(len(lines) == 1 and lines[0].startswith("0::"))
    return components(lines[0][3:])


def process_status(body, pid, leader=False):
    fields = {}
    for line in body.splitlines():
        key, separator, value = line.partition(b":")
        require(separator and key not in fields)
        fields[key] = value.split()
    require(fields.get(b"Pid") == [str(pid).encode()])
    wanted = (b"Tgid", b"Uid", b"NSpid")
    require(all(key in fields and all(x.isdigit() for x in fields[key]) for key in wanted))
    tgid, uid, nested = (tuple(int(x) for x in fields[key]) for key in wanted)
    require(len(tgid) == 1 and len(uid) == 4 and 1 <= len(nested) <= 16)
    require(tgid[0] > 0 and nested[0] == pid and all(x > 0 for x in nested))
    require(not leader or tgid[0] == pid)
    return tgid, uid, nested


def number(body, allow_max=False):
    if allow_max and body == b"max\n":
        return "max"
    require(re.fullmatch(rb"(?:0|[1-9][0-9]{0,18})\n", body) is not None)
    return integer(int(body), 0)


class LinuxSource:
    """Real read-only kernel source. No synthetic path or authority parameters."""

    def __init__(self, budget):
        require(sys.platform == "linux" and hasattr(os, "pidfd_open"))
        self.budget = budget
        self.owned = set()
        try:
            self.libc = ctypes.CDLL(None, use_errno=True)
            self.getdents = self.libc.getdents64
            self.getdents.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t)
            self.getdents.restype = ctypes.c_ssize_t
            self.proc = self.open("/proc", directory=True)
            require(fs_magic(self.proc) == PROC_MAGIC)
            start_from_stat(self.read(self.proc, "self/stat", 1024), os.getpid())
        except BaseException:
            self.close()
            raise

    def own(self, fd):
        self.owned.add(fd)
        return fd

    def open(self, name, parent=None, directory=False, magic=False):
        self.budget.fd()
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        if not magic:
            flags |= os.O_NOFOLLOW
        return self.own(os.open(name, flags, dir_fd=parent))

    def close_fd(self, fd):
        # Remove before close: never retry a potentially reused descriptor after EINTR.
        self.owned.remove(fd)
        try:
            os.close(fd)
        finally:
            self.budget.fds -= 1

    def close(self):
        failed = False
        def cancel(_signum, _frame):
            nonlocal failed
            failed = True
        previous = signal.signal(signal.SIGINT, cancel)
        try:
            for fd in tuple(self.owned):
                try:
                    self.close_fd(fd)
                except (OSError, KeyboardInterrupt):
                    failed = True
        finally:
            signal.signal(signal.SIGINT, previous)
        require(not failed and self.budget.clock() < self.budget.deadline_ns)

    def read_fd(self, fd, maximum):
        self.budget.read(maximum + 1)
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        size = 0
        while True:
            self.budget.read(0)  # every physical syscall, including EOF/partial reads
            chunk = os.read(fd, maximum + 1 - size)
            if not chunk:
                break
            size += len(chunk)
            require(size <= maximum)
            chunks.append(chunk)
        return b"".join(chunks)

    def read(self, parent, name, maximum):
        fd = self.open(name, parent)
        try:
            require(fs_magic(fd) == PROC_MAGIC)
            return self.read_fd(fd, maximum)
        finally:
            self.close_fd(fd)

    def process(self, pid, start, within=None):
        integer(pid, high=(1 << 31) - 1)
        integer(start)
        self.budget.fd()
        pidfd = self.own(os.pidfd_open(pid, 0))
        directory = self.open(str(pid), self.proc, directory=True)
        require(fs_magic(directory) == PROC_MAGIC)
        require(start_from_stat(self.read(directory, "stat", 1024), pid) == start)
        membership = cgroup_path(self.read(directory, "cgroup", 1024))
        if within is not None:
            require(len(membership) > len(within.membership))
            require(membership[:len(within.membership)] == within.membership)
        root = self.open("root", directory, directory=True, magic=True)
        namespaces = tuple(self.open("ns/" + name, directory, magic=True) for name in NS)
        status = process_status(self.read(directory, "status", 4096), pid, leader=True)
        proc = Process(pid, start, directory, pidfd, root, namespaces, membership,
                       (identity(directory), (identity(root), self.fd_mount_id(root)),
                        tuple(identity(fd) for fd in namespaces)), status)
        self.check_process(proc)
        return proc

    def check_process(self, proc):
        self.budget.check()
        require(not select.select([proc.pidfd], [], [], 0)[0])
        require(start_from_stat(self.read(proc.directory, "stat", 1024), proc.pid) == proc.start)
        require(cgroup_path(self.read(proc.directory, "cgroup", 1024)) == proc.membership)
        require(process_status(self.read(proc.directory, "status", 4096), proc.pid, leader=True) == proc.status)
        reopened = []
        try:
            reopened.append(self.open(str(proc.pid), self.proc, directory=True))
            reopened.append(self.open("root", reopened[0], directory=True, magic=True))
            reopened.extend(self.open("ns/" + n, reopened[0], magic=True) for n in NS)
            require((identity(reopened[0]), (identity(reopened[1]), self.fd_mount_id(reopened[1])),
                     tuple(identity(fd) for fd in reopened[2:])) == proc.identity)
        finally:
            for fd in reopened:
                self.close_fd(fd)

    def group(self, proc):
        # Both files are in the reader's actual view. Never combine guest mountinfo
        # coordinates with host paths or guess runtime/container ID directories.
        body = self.read(self.proc, "self/mountinfo", 65536)
        mounts = []
        for line in body.decode("ascii").splitlines():
            fields = line.split()
            require("-" in fields)
            split = fields.index("-")
            require(split >= 6 and len(fields) >= split + 4)
            if fields[split + 1] == "cgroup2":
                root = components(unescape_mount(fields[3]))
                mount = components(unescape_mount(fields[4]))
                if proc.membership[:len(root)] == root:
                    mounts.append((root, mount, line))
        # Multiple bind mounts could alias the same hierarchy; ambiguity is refusal.
        require(len(mounts) == 1)
        root, mount, mount_record = mounts[0]
        fd = self.open("/", directory=True)
        for name in mount:
            child = self.open(name, fd, directory=True)
            self.close_fd(fd)
            fd = child
        require(fs_magic(fd) == CGROUP_MAGIC)
        self.check_mount(fd, mount_record)
        directories = [fd]
        names = proc.membership[len(root):]
        require(len(names) <= 12)
        for name in names:
            child = self.open(name, directories[-1], directory=True)
            require(fs_magic(child) == CGROUP_MAGIC)
            directories.append(child)
        held = tuple(self.open(name, directories[-1]) for name in FILES)
        for file_fd in held:
            require(fs_magic(file_fd) == CGROUP_MAGIC and stat.S_ISREG(os.fstat(file_fd).st_mode))
            require(os.fstat(file_fd).st_dev == os.fstat(directories[-1]).st_dev)
        group = Group(tuple(directories), names, tuple(identity(d) for d in directories), held, proc.membership, mount_record)
        self.check_group(group)
        return group

    def check_group(self, group):
        self.budget.check()
        require(group.mount_record in self.read(self.proc, "self/mountinfo", 65536).decode("ascii").splitlines())
        self.check_mount(group.directories[0], group.mount_record)
        require(tuple(identity(d) for d in group.directories) == group.identities)
        # Reopen only beneath held parents to detect removal/replacement of names.
        for parent, name, expected in zip(group.directories, group.names, group.identities[1:]):
            fd = self.open(name, parent, directory=True)
            try:
                require(identity(fd) == expected and fs_magic(fd) == CGROUP_MAGIC)
            finally:
                self.close_fd(fd)
        for name, held in zip(FILES, group.files):
            fd = self.open(name, group.directories[-1])
            try:
                require(identity(fd) == identity(held) and fs_magic(fd) == CGROUP_MAGIC)
            finally:
                self.close_fd(fd)
        fd = self.open("cgroup.type", group.directories[-1])
        try:
            require(fs_magic(fd) == CGROUP_MAGIC and self.read_fd(fd, 32) == b"domain\n")
        finally:
            self.close_fd(fd)

    def check_mount(self, fd, record):
        fields = record.split()
        require(str(self.fd_mount_id(fd)) == fields[0])
        device = os.fstat(fd).st_dev
        require(fields[2] == str(os.major(device)) + ":" + str(os.minor(device)))

    def fd_mount_id(self, fd):
        info = self.read(self.proc, "self/fdinfo/" + str(fd), 4096)
        ids = [line.split()[1:] for line in info.splitlines() if line.startswith(b"mnt_id:")]
        require(len(ids) == 1 and len(ids[0]) == 1 and ids[0][0].isdigit())
        return integer(int(ids[0][0]))

    def descendant(self, outer, leaf):
        require(len(leaf.identities) > len(outer.identities))
        require(leaf.identities[:len(outer.identities)] == outer.identities)
        require(leaf.membership[:len(outer.membership)] == outer.membership)

    def leaf(self, group):
        # Explicit bounded kernel buffers, rather than an unbounded listdir or
        # implementation-dependent scandir buffering. Missing libc entry refuses.
        fd = group.directories[-1]
        os.lseek(fd, 0, os.SEEK_SET)
        storage = ctypes.create_string_buffer(4096)
        count = 0
        while True:
            self.budget.read(4096)
            size = self.getdents(fd, storage, 4096)
            require(0 <= size <= 4096)
            if size == 0:
                return
            body = storage.raw[:size]
            offset = 0
            while offset < size:
                require(offset + 20 <= size)
                length = int.from_bytes(body[offset + 16:offset + 18], sys.byteorder)
                require(length >= 20 and offset + length <= size)
                kind = body[offset + 18]
                raw_name = body[offset + 19:offset + length]
                require(b"\0" in raw_name)
                name = raw_name.split(b"\0", 1)[0]
                count += 1
                require(count <= 128 and name)
                require(name in (b".", b"..") or kind == 8)  # DT_REG only; no aliases/unknown types.
                offset += length

    def values(self, group):
        maximum = number(self.read_fd(group.files[0], 32), True)
        current = number(self.read_fd(group.files[1], 32))
        events = self.read_fd(group.files[2], 128)
        require(re.fullmatch(rb"max (?:0|[1-9][0-9]{0,18})\n", events) is not None)
        return maximum, current, integer(int(events[4:]), 0)

    def tasks(self, group, proc):
        body = self.read_fd(group.files[3], 4096)
        require(re.fullmatch(rb"(?:[1-9][0-9]{0,9}\n)+", body) is not None)
        tids = tuple(int(x) for x in body.splitlines())
        require(len(tids) <= MAX_TASKS and len(set(tids)) == len(tids) and proc.pid in tids)
        result = []
        for tid in sorted(tids):
            directory = self.open(str(tid), self.proc, directory=True)
            temporary = []
            try:
                require(fs_magic(directory) == PROC_MAGIC)
                first = start_from_stat(self.read(directory, "stat", 1024), tid)
                require(cgroup_path(self.read(directory, "cgroup", 1024)) == group.membership)
                task_status = process_status(self.read(directory, "status", 4096), tid)
                require(len(task_status[2]) == len(proc.status[2]))
                for name, expected in zip(NS, proc.namespaces):
                    fd = self.open("ns/" + name, directory, magic=True)
                    temporary.append(fd)
                    require(identity(fd) == identity(expected))
                require(start_from_stat(self.read(directory, "stat", 1024), tid) == first)
                require(process_status(self.read(directory, "status", 4096), tid) == task_status)
                result.append((tid, first))
            finally:
                for fd in temporary:
                    self.close_fd(fd)
                self.close_fd(directory)
        return tuple(result)

    def snapshot(self, proc, group):
        self.check_process(proc)
        self.check_group(group)
        self.leaf(group)
        before = self.values(group)
        tasks = self.tasks(group, proc)
        require(before[1] == len(tasks))
        require(self.values(group) == before and self.tasks(group, proc) == tasks)
        self.leaf(group)
        self.check_group(group)
        self.check_process(proc)
        return {"maximum": before[0], "current": before[1], "events_max": before[2],
                "tasks": [list(task) for task in tasks]}


def closed(obj, keys):
    require(type(obj) is dict and set(obj) == set(keys))


def decode(body):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    require(type(body) is bytes and 0 < len(body) <= FRAME and body.endswith(b"\n"))
    try:
        return json.loads(body, object_pairs_hook=unique, parse_constant=lambda _: require(False))
    except Exception:
        raise Refusal() from None


class Session:
    """Fixed single-owner session; any error terminally invalidates the session."""

    def __init__(self, budget, source):
        self.budget, self.source = budget, source
        self.outer = None
        self.slots = {}
        self.phases = {}
        self.finished = False
        self.failed = False
        self.context = None

    def handle(self, request):
        try:
            self.budget.check()
            require(not self.finished and not self.failed)
            self.budget.frames += 1
            require(self.budget.frames <= 64 and type(request) is dict)
            operation = request.get("op")
            if operation == "BindOuter":
                closed(request, ("op", "pid", "start", "context"))
                require(self.outer is None)
                context = request["context"]
                closed(context, ("backend", "candidate", "run", "lane", "outer_id"))
                require(context["backend"] in ("docker", "podman"))
                require(all(type(v) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", v) for v in context.values()))
                proc = self.source.process(integer(request["pid"], high=(1 << 31) - 1), integer(request["start"]))
                group = self.source.group(proc)
                require(self.source.values(group)[0] == 512)
                self.source.check_process(proc)
                self.outer = proc, group
                self.context = dict(context)
            elif operation == "BindLeaf":
                closed(request, ("op", "slot", "pid", "start"))
                slot = request["slot"]
                require(self.outer is not None and type(slot) is str and slot in SLOTS and slot not in self.slots)
                self.check_outer()
                proc = self.source.process(integer(request["pid"], high=(1 << 31) - 1), integer(request["start"]), self.outer[1])
                group = self.source.group(proc)
                self.source.descendant(self.outer[1], group)
                require(all(group.identities[-1] != old[1].identities[-1] for old in self.slots.values()))
                snapshot = self.source.snapshot(proc, group)
                expected = "max" if slot.endswith("unlimited") else (16 if slot.endswith("16") else 64)
                require(snapshot["maximum"] == expected)
                self.slots[slot] = proc, group
                self.phases[slot] = []
            elif operation == "Sample":
                closed(request, ("op", "slot", "phase"))
                slot, phase = request["slot"], request["phase"]
                require(type(slot) is str and slot in self.slots and type(phase) is str and phase in PHASES)
                previous = self.phases[slot]
                require(phase not in previous and (previous or phase == "before"))
                orders = {"before": 0, "at_limit": 1, "after_failure": 2, "control": 2, "after_release": 3}
                require(not previous or orders[phase] > orders[previous[-1]])
                self.check_outer()
                proc, group = self.slots[slot]
                result = self.source.snapshot(proc, group)
                expected = "max" if slot.endswith("unlimited") else (16 if slot.endswith("16") else 64)
                require(result["maximum"] == expected)
                self.check_outer()
                previous.append(phase)
                self.budget.check()
                return {"op": "Sample", "slot": slot, "phase": phase, "sample": result}
            elif operation == "Finish":
                closed(request, ("op",))
                require(self.outer is not None)
                self.check_outer()
                for proc, group in self.slots.values():
                    self.source.check_process(proc)
                    self.source.check_group(group)
                self.source.close()
                self.finished = True
            else:
                raise Refusal()
            self.budget.check()
            return {"op": operation, "status": "ok"}
        except (Exception, KeyboardInterrupt):
            self.failed = True
            raise Refusal() from None

    def check_outer(self):
        self.source.check_process(self.outer[0])
        self.source.check_group(self.outer[1])
        maximum, current, _ = self.source.values(self.outer[1])
        require(maximum == 512 and current <= 512)

    def abort(self):
        self.failed = True
        self.source.close()


def pipe_fd(fd, writing):
    integer(fd, 3, 1023)
    require(stat.S_ISFIFO(os.fstat(fd).st_mode))
    require(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == (os.O_WRONLY if writing else os.O_RDONLY))
    require(re.fullmatch(r"pipe:\[[0-9]+\]", os.readlink("/proc/self/fd/" + str(fd))) is not None)
    # O_NONBLOCK makes the immutable parent deadline enforceable on both pipes.
    os.set_blocking(fd, False)
    os.set_inheritable(fd, False)
    return fd


def await_fd(fd, writing, budget):
    budget.check()
    remaining = (budget.work_ns - budget.clock()) / 1_000_000_000
    readers, writers, _ = select.select([] if writing else [fd], [fd] if writing else [], [], remaining)
    require(bool(writers if writing else readers))
    budget.check()


def receive(fd, budget):
    # Read one byte at a time to avoid consuming/accepting pipelined requests after
    # Finish. Each physical read is precharged; frame and total bytes stay bounded.
    result = bytearray()
    while len(result) <= FRAME:
        await_fd(fd, False, budget)
        budget.read(1)
        part = os.read(fd, 1)
        require(part)
        result.extend(part)
        if part == b"\n":
            return decode(bytes(result))
    raise Refusal()


def send(fd, value, budget):
    body = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"
    require(len(body) <= 8192)
    budget.emit(len(body))
    offset = 0
    while offset < len(body):
        await_fd(fd, True, budget)
        offset += os.write(fd, body[offset:])


def main(argv=None):
    source = None
    pipe_handles = []
    failed = False
    cleaning = False
    previous_handler = None
    def cancel(_signum, _frame):
        nonlocal failed
        failed = True
        if not cleaning:
            raise KeyboardInterrupt()
    try:
        previous_handler = signal.signal(signal.SIGINT, cancel)
        args = sys.argv[1:] if argv is None else argv
        require(len(args) == 3 and all(re.fullmatch(r"[1-9][0-9]{0,18}", arg) for arg in args))
        budget = Budget(int(args[2]))
        require(args[0] != args[1])
        reader = pipe_fd(int(args[0]), False)
        pipe_handles.append(reader)
        writer = pipe_fd(int(args[1]), True)
        pipe_handles.append(writer)
        require(identity(reader) != identity(writer))
        source = LinuxSource(budget)
        session = Session(budget, source)
        while not session.finished:
            response = session.handle(receive(reader, budget))
            if session.finished:
                # Parent sends Finish, closes its request writer, then reads ack.
                # Any trailing frame or retained request capability rejects Finish.
                await_fd(reader, False, budget)
                budget.read(1)
                require(os.read(reader, 1) == b"")
            send(writer, response, budget)
    except (Exception, KeyboardInterrupt):
        failed = True
    finally:
        cleaning = True
        if source is not None:
            try:
                source.close()
            except (Exception, KeyboardInterrupt):
                failed = True
        for fd in pipe_handles:
            try:
                os.close(fd)
            except (OSError, KeyboardInterrupt):
                failed = True
    if failed:
        # No exception, paths, PID, context or source bytes cross diagnostic boundary.
        try:
            os.write(2, b"native-pids-boundary: refused\n")
        except OSError:
            pass
        if previous_handler is not None:
            signal.signal(signal.SIGINT, previous_handler)
        return 1
    if previous_handler is not None:
        signal.signal(signal.SIGINT, previous_handler)
    return 0


if __name__ == "__main__":
    sys.exit(main())
