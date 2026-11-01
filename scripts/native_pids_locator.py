#!/usr/bin/env python3
"""In-process inner Engine locator; never accepts PID authority over IPC.

The original runtime owner must supply the retained outer Process/Group and
independently chosen daemon expectation. See docs/native-pids-runtime.md.
"""

import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import sys
from contextlib import contextmanager
from dataclasses import dataclass

_boundary_path = Path(__file__).with_name("native_pids_boundary.py").resolve()
boundary = sys.modules.get("native_pids_boundary")
if boundary is None:
    _boundary_spec = importlib.util.spec_from_file_location("native_pids_boundary", _boundary_path)
    boundary = importlib.util.module_from_spec(_boundary_spec)
    sys.modules["native_pids_boundary"] = boundary
    try:
        _boundary_spec.loader.exec_module(boundary)
    except BaseException:
        del sys.modules["native_pids_boundary"]
        raise
elif (getattr(boundary, "__file__", None) is None
        or Path(boundary.__file__).resolve() != _boundary_path):
    raise ValueError("pids-import")

_spec = importlib.util.spec_from_file_location(
    "_pids_unix_http", Path(__file__).with_name("native-unix-http.py"))
http = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(http)

NS_GET_PARENT = 0xB702
SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)
INSPECT_CAP = 32 * 1024
VERSION_CAP = 4096
FIXED_FD_RESERVE = 16
ORDER = ("cli16", "cli64", "cli_unlimited", "rendered16", "rendered64", "rendered_unlimited")
require = boundary.require
topology = boundary.topology


def _discovery_module():
    # Lazy loading avoids discovery -> locator -> discovery during cold imports.
    path = Path(__file__).with_name("native_pids_discovery.py").resolve()
    module = sys.modules.get("native_pids_discovery")
    if module is not None:
        require(getattr(module, "__file__", None) is not None and Path(module.__file__).resolve() == path)
        return module
    spec = importlib.util.spec_from_file_location("native_pids_discovery", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["native_pids_discovery"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules["native_pids_discovery"]
        raise
    return module


@contextmanager
def _outer_escape(observer, site):
    """Observe only an escaping whole operation; never change its exception."""
    try:
        yield
    except BaseException:
        if observer is not None:
            try:
                observer(site)
            except BaseException:
                pass
        raise


class RuntimeBudget(boundary.Budget):
    """Only RootSession's sealed cleanup phase may use the existing reserve.

    Legacy boundary.Budget retains its original work-only meaning.
    """

    def __init__(self, deadline_ns, clock=boundary.time.monotonic_ns):
        self.cleanup_only = False
        self.external_bytes = self.external_reads = 0
        self.external_debited = False
        super().__init__(deadline_ns, clock)
        # Conservative combined overhead: server HTTP/control/stdio and
        # original-peer, supervisor pidfds/stdio/gates. These slots remain
        # reserved through transport closure/reaping, after source FDs close.
        for _ in range(FIXED_FD_RESERVE):
            self.fd()

    def check(self, observer=None):
        boundary.startup_require("budget_deadline", boundary._observe(
            self.clock() < (self.deadline_ns if self.cleanup_only else self.work_ns), observer, "time"))

    def begin_cleanup(self):
        require(not self.cleanup_only)
        super().check()
        self.cleanup_only = True

    def debit_external(self, maximum_bytes, operations):
        """Only reduce remaining source capacity; caller receipts prove its I/O."""
        self.check()
        require(not self.external_debited and not self.cleanup_only)
        boundary.integer(maximum_bytes, 0, boundary.SOURCE_BYTES)
        boundary.integer(operations, 0, 65536)
        self.external_debited = True
        self.external_bytes, self.external_reads = maximum_bytes, operations
        self.bytes += maximum_bytes
        self.reads += operations
        require(self.bytes <= boundary.SOURCE_BYTES and self.reads <= 65536)

    def ledger(self, source_owned):
        return {"external_reserved": {"bytes": self.external_bytes, "reads": self.external_reads},
                "root_reserved": {"bytes": self.bytes - self.external_bytes, "reads": self.reads - self.external_reads},
                "total_reserved": {"bytes": self.bytes, "reads": self.reads},
                "limits": {"bytes": boundary.SOURCE_BYTES, "reads": 65536, "output_bytes": 65536,
                           "live_fd_reservations": 256, "fd_opens": 32768},
                "fds": {"peak_reservations": self.peak_fds, "open_reservations": self.opens,
                        "fixed_overhead_reservations": FIXED_FD_RESERVE, "source_owned_remaining": source_owned},
                "output_reserved_before_final": self.output}


class ParentReservations:
    """One-way synchronous adapter into the ORIGINAL owner's shared ledger.

    The callback must debit the original command/API and captured-body ledger.
    This local receipt is accounting evidence only, never runtime authority.
    Reserve supervisor/IPC and final outer cleanup separately before construction.
    """

    def __init__(self, reserve):
        require(callable(reserve))
        self.reserve = reserve
        self.calls = self.body_bytes = 0
        self.probe_calls = 0

    def __call__(self, units, body_maximum):
        require(units == 1 and body_maximum == INSPECT_CAP)
        self.calls += 1
        self.body_bytes += body_maximum
        require(self.calls <= 30 and self.body_bytes <= 2 * 1024 * 1024 - 64 * 1024)
        self.reserve(units, body_maximum)  # failed reservations remain debited

    def receipt(self):
        result = {"inspect_calls_reserved": self.calls, "inspect_body_bytes_reserved": self.body_bytes}
        if self.probe_calls:
            result.update(runtime_probe_calls_reserved=self.probe_calls,
                          runtime_probe_body_bytes_reserved=self.probe_calls * VERSION_CAP)
        return result

    def reserve_probe(self):
        self.probe_calls += 1
        require(self.probe_calls == 1)
        self.reserve(1, VERSION_CAP)


class LocatorRefusal(boundary.Refusal):
    def __init__(self, category="BindingFailed"):
        # No exception text or observed values are retained.
        require(category in ("BindingFailed", "UnsupportedPeerPidfd", "PeerExited",
                             "NamespaceUnreachable", "NoMatch", "AmbiguousMatch",
                             "UnsupportedEventSemantics", "ConfiguredOuterUnavailable"))
        self.category = category
        super().__init__(category)


def _host_group_exception_tag(error):
    if type(error) is LocatorRefusal:
        category = object.__getattribute__(error, "category")
        if type(category) is str and category == "UnsupportedEventSemantics":
            return "declared_unsupported_events"
        return "unclassified"
    return boundary._group_exception_tag(error)


@contextmanager
def _host_group_escape(observer, site):
    try:
        yield
    except BaseException as error:
        if observer is not None:
            try:
                tag = _host_group_exception_tag(error)
            except BaseException:
                tag = "unclassified"
            try:
                observer(site, tag)
            except BaseException:
                pass
        raise


def status_vectors(body, pid):
    status = boundary.process_status(body, pid, leader=True)
    rows = [line.split()[1:] for line in body.splitlines() if line.startswith(b"NStgid:")]
    boundary.startup_require("status_nstgid", len(rows) == 1 and rows[0] and all(x.isdigit() for x in rows[0]))
    groups = tuple(int(x) for x in rows[0])
    boundary.startup_require("status_nstgid", groups == status[2])  # leader, in every represented namespace
    return status, groups


def live(pidfd):
    if select.select([pidfd], [], [], 0)[0]:
        raise LocatorRefusal("PeerExited")


class LocatorSource(boundary.LinuxSource):
    """Real procfs, namespace ioctl and held cgroup traversal, with one ledger."""

    def __init__(self, budget):
        self.process_times = {}
        super().__init__(budget)
        try:
            with boundary.startup_scope("self_status"):
                reader = os.getpid()
                facts, groups = status_vectors(self.read(self.proc, "self/status", 4096), reader)
                require(facts[0] == (reader,) and groups == (reader,))
            with boundary.startup_scope("self_pidns"):
                self.reader_namespace = self.open("self/ns/pid", self.proc, magic=True)
            with boundary.startup_scope("self_userns"):
                self.reader_user_namespace = self.open("self/ns/user", self.proc, magic=True)
            with boundary.startup_scope("self_cgroupns"):
                self.reader_cgroup_namespace = self.open("self/ns/cgroup", self.proc, magic=True)
            with boundary.startup_scope("self_timens"):
                self.reader_time_namespace = self.open("self/ns/time", self.proc, magic=True)
        except BaseException as error:
            boundary.startup_fault("locator_init", error)
            with boundary.startup_cleanup():
                self.close()
            raise

    def process(self, pid, start, within=None):
        process = super().process(pid, start, within)
        with boundary.startup_scope("proc_timens"):
            time_namespace = self.open("ns/time", process.directory, magic=True)
            require(boundary.identity(time_namespace) == boundary.identity(self.reader_time_namespace))
        with boundary.startup_scope("proc_live"):
            live(process.pidfd)
        if not hasattr(self, "process_times"):
            self.process_times = {}
        self.process_times[process] = time_namespace
        return process

    def check_process(self, process):
        super().check_process(process)
        time_namespace = getattr(self, "process_times", {}).get(process)
        if time_namespace is not None:
            with boundary.startup_scope("proc_timens"):
                reopened = self.open("ns/time", process.directory, magic=True)
            try:
                with boundary.startup_scope("proc_timens"):
                    require(boundary.identity(reopened) == boundary.identity(time_namespace)
                            == boundary.identity(self.reader_time_namespace))
            finally:
                with boundary.startup_cleanup():
                    self.close_fd(reopened)

    def check_task_time_namespace(self, directory):
        held = self.open("ns/time", directory, magic=True)
        try:
            require(boundary.identity(held) == boundary.identity(self.reader_time_namespace))
        finally:
            self.close_fd(held)

    def close_fd(self, fd):
        for process, time_namespace in tuple(getattr(self, "process_times", {}).items()):
            if process.directory == fd or time_namespace == fd:
                del self.process_times[process]
        super().close_fd(fd)

    def release_since(self, previous):
        failed = False
        for fd in tuple(self.owned - previous):
            try:
                self.close_fd(fd)
            except OSError:
                failed = True
        require(not failed)

    def adopt_capture_directory(self, fd):
        """Transfer the sole received server capability; caller clears custody.

        Failure before own() leaves the caller responsible; after return only
        source.close owns this descriptor number, including before final ack.
        """
        require(fd not in self.owned and not hasattr(self, "capture_directory"))
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                and not os.get_inheritable(fd))
        self.budget.fd()
        self.capture_directory = self.own(fd)

    def globals(self, process):
        """Actual bounded competing-limit observations, never UID estimates."""
        require(not getattr(self.budget, "cleanup_only", False))
        names = ("sys/kernel/threads-max", "sys/kernel/pid_max", "loadavg")
        if not hasattr(self, "global_files"):
            held = []
            for name in names:
                fd = self.open(name, self.proc)
                require(boundary.fs_magic(fd) == boundary.PROC_MAGIC
                        and stat.S_ISREG(os.fstat(fd).st_mode))
                held.append(fd)
            self.global_files = tuple(held)
        for name, original in zip(names, self.global_files):
            fd = self.open(name, self.proc)
            try:
                require(boundary.identity(fd) == boundary.identity(original)
                        and boundary.fs_magic(fd) == boundary.PROC_MAGIC)
            finally:
                self.close_fd(fd)
        threads = boundary.number(self.read_fd(self.global_files[0], 32))
        pids = boundary.number(self.read_fd(self.global_files[1], 32))
        load = self.read_fd(self.global_files[2], 128)
        match = re.fullmatch(rb"(?:[0-9]+\.[0-9]{2} ){3}([0-9]+)/([0-9]+) ([0-9]+)\n", load)
        require(match is not None and threads > 0 and pids > 0)
        total = boundary.integer(int(match[2]))
        body = self.read(process.directory, "stat", 1024)
        require(boundary.start_from_stat(body, process.pid) == process.start)
        fields = body.rpartition(b") ")[2].split()
        require(len(fields) >= 39 and fields[38].isdigit())  # proc stat field41
        policy = boundary.integer(int(fields[38]), 0, 255)
        limits = self.read(process.directory, "limits", 4096)
        rows = re.findall(rb"^Max processes[ \t]+(unlimited|[0-9]{1,20})[ \t]+(unlimited|[0-9]{1,20})[ \t]+processes[ \t]*$",
                          limits, re.MULTILINE)
        require(len(rows) == 1)
        def limit(value):
            return "unlimited" if value == b"unlimited" else boundary.integer(int(value), 0, (1 << 64) - 1)
        self.budget.read(512)  # bounded uname structure, before the actual syscall
        kernel = os.uname()
        identity = (kernel.release, kernel.version, kernel.machine)
        require(all(type(value) is str and 0 < len(value) <= 128
                    and all(32 <= ord(character) < 127 for character in value) for value in identity))
        return {"threads_max": threads, "pid_max": pids, "total_tasks": total,
                "sched_policy": policy, "nproc_soft": limit(rows[0][0]), "nproc_hard": limit(rows[0][1]),
                "kernel_release": identity[0], "kernel_version": identity[1], "kernel_machine": identity[2]}

    def group(self, process, observer=None):
        if observer is None:
            group = super().group(process)
        else:
            group = super().group(process, observer=observer)
        with _host_group_escape(observer, "gh_root"):
            fields = group.mount_record.split()
            separator = fields.index("-")
            flags = set(fields[5].split(",")) | set(fields[separator + 3].split(","))
            if "pids_localevents" in flags:
                raise LocatorRefusal("UnsupportedEventSemantics")
            if not hasattr(self, "controller_cache"):
                self.controller_cache, self.controller_groups, self.root_records = {}, {}, {}
            root_key = group.identities[0]
            if root_key not in self.root_records:
                directory = group.directories[0]
                has_maximum = self.root_file_present(directory, "pids.max")
                available = self.open("cgroup.controllers", directory)
                require(boundary.fs_magic(available) == boundary.CGROUP_MAGIC)
                words = self.read_fd(available, 512).split()
                require(all(re.fullmatch(rb"[a-z_]{1,32}", word) is not None for word in words))
                self.root_records[root_key] = {"directory": directory, "available": available,
                    "available_pids": b"pids" in words, "available_words": tuple(words), "pids_max_present": has_maximum,
                    "cgroup_type_present": self.root_file_present(directory, "cgroup.type"),
                    "cgroup_events_present": self.root_file_present(directory, "cgroup.events"),
                    "mount_root_is_slash": fields[3] == "/", "identity": (*root_key, self.fd_mount_id(directory))}
            root = self.root_records[root_key]
        with _host_group_escape(observer, "gh_nodes"):
            nodes = []
            start = 0 if root["pids_max_present"] else 1
            for index in range(start, len(group.directories)):
                directory, key = group.directories[index], group.identities[index]
                if key not in self.controller_cache:
                    held = list(group.files[:3]) if index == len(group.directories) - 1 else [
                        self.open(name, directory) for name in ("pids.max", "pids.current", "pids.events")]
                    try:
                        held.append(self.open("pids.events.local", directory))
                    except FileNotFoundError:
                        raise LocatorRefusal("UnsupportedEventSemantics") from None
                    require(all(boundary.fs_magic(fd) == boundary.CGROUP_MAGIC
                                and stat.S_ISREG(os.fstat(fd).st_mode) for fd in held))
                    self.controller_cache[key] = (directory, (*key, self.fd_mount_id(directory)), tuple(held))
                nodes.append(self.controller_cache[key])
            self.controller_groups[group.identities[-1]] = (root, tuple(reversed(nodes)))
            self._typed_chain(group, self._leaf_types[group.identities[-1]])
        return group

    def type_scope(self):
        if not hasattr(self, "_type_scope"):
            self._type_scope = topology.TypeScope()
        return self._type_scope

    def read_type(self, directory):
        """One charged cap32 baseline/role read, returned only after close."""
        fd = self.open("cgroup.type", directory)
        try:
            require(boundary.fs_magic(fd) == boundary.CGROUP_MAGIC)
            kind = topology.parse_type(self.read_fd(fd, 32))
        finally:
            self.close_fd(fd)
        return kind

    def _typed_chain(self, group, leaf_kind):
        """Validate actual held roles; no type read is added for presentation.

        Setup/post-seal revalidation reads each ancestor once. During Locate,
        reuse the current discovery/acquisition epoch; only uncovered ancestors
        (not stale bootstrap observations) need a cap32 baseline read. During
        measurements the existing attribution reads provide fresh row brackets.
        """
        root, nodes = self.controller_groups[group.identities[-1]]
        scope = self.type_scope()
        authenticated = getattr(self, "authenticated_parent_cgroup_namespace", None)
        exempt = (not root["pids_max_present"] and not root["cgroup_type_present"]
                  and not root["cgroup_events_present"] and root["available_pids"]
                  and root["mount_root_is_slash"] and authenticated is not None
                  and boundary.identity(authenticated) == boundary.identity(self.reader_cgroup_namespace))
        observed = []
        for index, (directory, identity, _held) in enumerate(nodes):
            parent = nodes[index + 1][1] if index + 1 < len(nodes) else (
                None if identity == root["identity"] else root["identity"])
            if index == 0:
                kind = leaf_kind
            elif scope.phase in ("locating", "measuring"):
                available = scope.current if scope.phase == "locating" else scope.frozen
                if identity in available:
                    kind = available[identity][0]
                else:
                    require(scope.phase == "locating")
                    kind = self.read_type(directory)
            else:
                kind = self.read_type(directory)
            observed.append((identity, kind, parent))
        previous = None
        for identity, kind, parent in reversed(observed):
            if previous is None:
                require(exempt or kind in (topology.CgroupType.DOMAIN, topology.CgroupType.THREAD_ROOT))
            elif previous is topology.CgroupType.DOMAIN:
                require(kind in (topology.CgroupType.DOMAIN, topology.CgroupType.THREAD_ROOT))
            else:
                require(kind is topology.CgroupType.THREADED)
            scope.observe(identity, kind, parent)
            previous = kind
        return tuple(observed)

    def adopt_discovery_types(self, transfer, outer):
        root, nodes = self.controller_groups[outer.identities[-1]]
        outer_identity = nodes[0][1]
        outer_parent = nodes[1][1] if len(nodes) > 1 else (
            None if outer_identity == root["identity"] else root["identity"])
        require(transfer.types and transfer.types[0].identity == outer_identity
                and transfer.types[0].kind in (topology.CgroupType.DOMAIN, topology.CgroupType.THREAD_ROOT))
        scope = self.type_scope()
        for observed in transfer.types:
            scope.observe(observed.identity, observed.kind,
                          outer_parent if observed.parent is None else observed.parent)

    def freeze_measurement_types(self, groups):
        identities = set()
        for group in groups:
            self._typed_chain(group, self._leaf_types[group.identities[-1]])
            identities.update(node[1] for node in self.controller_groups[group.identities[-1]][1])
        self.type_scope().freeze(identities)

    def root_file_present(self, directory, name):
        self.budget.read(256)  # fixed stat/absence metadata; no FD allocation
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode))
            return True
        except FileNotFoundError:
            return False

    def check_controller(self, node_directory, node_identity, held):
        require((*boundary.identity(node_directory), self.fd_mount_id(node_directory)) == node_identity)
        for name, original in zip(("pids.max", "pids.current", "pids.events", "pids.events.local"), held):
            fd = self.open(name, node_directory)
            try:
                require(boundary.identity(fd) == boundary.identity(original)
                        and boundary.fs_magic(fd) == boundary.CGROUP_MAGIC)
            finally:
                self.close_fd(fd)

    def check_group(self, group, observer=None):
        if observer is None:
            kind = super().check_group(group)
        else:
            kind = super().check_group(group, observer=observer)
        with _host_group_escape(observer, "gv_cache"):
            cached = getattr(self, "controller_groups", {}).get(group.identities[-1])
            if cached is not None:
                for node in cached[1]:
                    self.check_controller(*node)
                self._typed_chain(group, kind)
            if not hasattr(self, "_leaf_types"):
                self._leaf_types = {}
            self._leaf_types[group.identities[-1]] = kind
        return kind

    def attribution(self, group):
        """Observed held prefix; an unqualified mount root is never invented."""
        root, nodes = self.controller_groups[group.identities[-1]]
        directory = root["directory"]
        present = self.root_file_present(directory, "pids.max")
        require(present == root["pids_max_present"])
        require(self.root_file_present(directory, "cgroup.type") == root["cgroup_type_present"]
                and self.root_file_present(directory, "cgroup.events") == root["cgroup_events_present"])
        current_namespace = self.open("self/ns/cgroup", self.proc, magic=True)
        try:
            require(boundary.identity(current_namespace) == boundary.identity(self.reader_cgroup_namespace))
        finally:
            self.close_fd(current_namespace)
        parent_namespace = getattr(self, "authenticated_parent_cgroup_namespace", None)
        namespace_bound = (parent_namespace is not None and boundary.identity(parent_namespace)
                           == boundary.identity(self.reader_cgroup_namespace))
        if hasattr(self, "authenticated_parent_process"):
            self.check_process(self.authenticated_parent_process)
        available = self.open("cgroup.controllers", directory)
        try:
            require(boundary.identity(available) == boundary.identity(root["available"])
                    and tuple(self.read_fd(available, 512).split()) == root["available_words"])
        finally:
            self.close_fd(available)
        controllers = []
        for node_directory, node_identity, held in nodes:
            self.check_controller(node_directory, node_identity, held)
            kind = self.open("cgroup.type", node_directory)
            try:
                require(boundary.fs_magic(kind) == boundary.CGROUP_MAGIC)
                observed_kind = topology.parse_type(self.read_fd(kind, 32))
            finally:
                self.close_fd(kind)
            parent = nodes[len(controllers) + 1][1] if len(controllers) + 1 < len(nodes) else (
                None if node_identity == root["identity"] else root["identity"])
            self.type_scope().observe(node_identity, observed_kind, parent)
            def events(fd):
                value = self.read_fd(fd, 128)
                require(re.fullmatch(rb"max (?:0|[1-9][0-9]{0,18})\n", value) is not None)
                return boundary.integer(int(value[4:]), 0)
            controllers.append({"identity": list(node_identity),
                "cgroup_type": observed_kind.value,
                "maximum": boundary.number(self.read_fd(held[0], 32), True),
                "current": boundary.number(self.read_fd(held[1], 32)),
                "events_max": events(held[2]), "events_local_max": events(held[3])})
        outer = self.outer_boundary.identities[-1]
        indexes = [index for index, node in enumerate(controllers) if tuple(node["identity"][:2]) == outer]
        require(len(indexes) == 1 and indexes[0] > 0)
        root_exempt = (not present and not root["cgroup_type_present"] and not root["cgroup_events_present"]
                       and root["available_pids"] and root["mount_root_is_slash"] and namespace_bound)
        qualification = "root_exempt" if root_exempt else (
            "observed_mount_prefix" if present else "unresolved_root_exemption")
        # Revalidate every freshly observed edge; a namespace-visible slash does
        # not supply the genuine hierarchy-root mixed-topology exception.
        previous = None
        for row in reversed(controllers):
            kind = topology.CgroupType(row["cgroup_type"])
            if previous is None:
                require(root_exempt or kind in (topology.CgroupType.DOMAIN, topology.CgroupType.THREAD_ROOT))
            elif previous is topology.CgroupType.DOMAIN:
                require(kind in (topology.CgroupType.DOMAIN, topology.CgroupType.THREAD_ROOT))
            else:
                require(kind is topology.CgroupType.THREADED)
            previous = kind
        return {"event_semantics": "hierarchical_with_local_enforcer", "pids_localevents": False,
                "candidate_membership": "typed_procs_local_membership_v1",
                "complete_chain": root_exempt, "outer_index": indexes[0],
                "reader_cgroup_namespace": list(boundary.identity(self.reader_cgroup_namespace)),
                "hierarchy_root": {"identity": list(root["identity"]), "pids_max_present": present,
                    "cgroup_type_present": root["cgroup_type_present"], "cgroup_events_present": root["cgroup_events_present"],
                    "available_pids": root["available_pids"], "mount_root_is_slash": root["mount_root_is_slash"],
                    "qualification": qualification}, "controllers": controllers}

    def snapshot(self, process, group):
        require(not getattr(self.budget, "cleanup_only", False) and self.type_scope().phase != "sealed")
        before, global_before = self.attribution(group), self.globals(process)
        sample = super().snapshot(process, group)
        after, global_after = self.attribution(group), self.globals(process)
        require({key: value for key, value in before.items() if key != "controllers"}
                == {key: value for key, value in after.items() if key != "controllers"})
        require(len(before["controllers"]) == len(after["controllers"]))
        for index, (old, observed) in enumerate(zip(before["controllers"], after["controllers"])):
            require(old["identity"] == observed["identity"] and old["maximum"] == observed["maximum"]
                    and old["cgroup_type"] == observed["cgroup_type"])
            require(observed["events_max"] >= old["events_max"]
                    and observed["events_local_max"] >= old["events_local_max"])
            if index == 0:
                require(old["current"] == observed["current"] and old["events_max"] == observed["events_max"]
                        and old["events_local_max"] == observed["events_local_max"])
            observed["current_samples"] = [old["current"], observed["current"]]
            observed["events_samples"] = [old["events_max"], observed["events_max"]]
            observed["events_local_samples"] = [old["events_local_max"], observed["events_local_max"]]
            observed["current"] = max(observed["current_samples"])
        require({key: value for key, value in global_before.items() if key != "total_tasks"}
                == {key: value for key, value in global_after.items() if key != "total_tasks"})
        global_after["total_tasks_samples"] = [global_before["total_tasks"], global_after["total_tasks"]]
        global_after["total_tasks"] = max(global_after["total_tasks_samples"])
        final_kind = self.check_group(group)
        leaf = after["controllers"][0]
        require(final_kind.value == sample["cgroup_type"] == leaf["cgroup_type"])
        require((leaf["maximum"], leaf["current"], leaf["events_max"]) ==
                (sample["maximum"], sample["current"], sample["events_max"]))
        sample.update(attribution=after, globals=global_after)
        return sample

    def guest_cgroup_mount(self, process):
        """Fixed original PID1 root view, never a CID/path-name inference."""
        intermediates, guest = [], None
        try:
            parent = process.root
            for name in ("sys", "fs"):
                parent = self.open(name, parent, directory=True)
                intermediates.append(parent)
            guest = self.open("cgroup", parent, directory=True)
            require(boundary.fs_magic(guest) == boundary.CGROUP_MAGIC)
            mount_id, device = self.fd_mount_id(guest), os.fstat(guest).st_dev
            records = []
            for line in self.read(process.directory, "mountinfo", 65536).decode("ascii").splitlines():
                fields = line.split()
                require("-" in fields)
                separator = fields.index("-")
                require(separator >= 6 and len(fields) >= separator + 4)
                if fields[0] == str(mount_id):
                    require(fields[2] == str(os.major(device)) + ":" + str(os.minor(device))
                            and fields[separator + 1] == "cgroup2"
                            and boundary.unescape_mount(fields[4]) == "/sys/fs/cgroup")
                    records.append(line)
            require(len(records) == 1)
            return guest, records[0]
        except BaseException:
            if guest is not None:
                self.close_fd(guest)
            raise
        finally:
            for fd in reversed(intermediates):
                self.close_fd(fd)

    def configured_outer_group(self, process, observer=None):
        """Bind the configured512 root by actual private guest mount identity.

        PID1 may already have moved to a descendant init.scope. The chosen node
        is the ONE actual guest-root cgroup inode on its held ancestor chain,
        never the nearest ancestor whose number happens to equal512.
        """
        with _outer_escape(observer, "oc_pre"):
            require(not hasattr(self, "configured_outer_binding"))
            require(boundary.identity(process.namespaces[2]) != boundary.identity(self.reader_cgroup_namespace))
            self.check_process(process)
        with _outer_escape(observer, "oc_host"):
            if observer is None:
                current = self.group(process)
            else:
                current = self.group(process, observer=observer)
        with _outer_escape(observer, "oc_guest"):
            guest, record = self.guest_cgroup_mount(process)
        with _outer_escape(observer, "oc_select"):
            matches = [index for index, node in enumerate(current.identities) if node == boundary.identity(guest)]
            if len(matches) != 1 or matches[0] == 0:
                raise LocatorRefusal("ConfiguredOuterUnavailable")
            index = matches[0]
            if index == len(current.directories) - 1:
                selected = current
            else:
                directory = current.directories[index]
                files = tuple(self.open(name, directory) for name in boundary.FILES)
                require(all(boundary.fs_magic(fd) == boundary.CGROUP_MAGIC and stat.S_ISREG(os.fstat(fd).st_mode)
                            for fd in files))
                root_depth = len(current.membership) - len(current.names)
                selected = boundary.Group(current.directories[:index + 1], current.names[:index],
                    current.identities[:index + 1], files, current.membership[:root_depth + index], current.mount_record)
                root, nodes = self.controller_groups[current.identities[-1]]
                self.controller_groups[selected.identities[-1]] = (root, tuple(
                    node for node in nodes if tuple(node[1][:2]) in selected.identities))
        with _outer_escape(observer, "oc_max"):
            maximum, current, _events = self.values(selected)
            require(maximum == 512 and current <= 512)
        with _outer_escape(observer, "oc_recheck"):
            require(self.check_group(selected) in (topology.CgroupType.DOMAIN, topology.CgroupType.THREAD_ROOT))
            self.configured_outer_binding = (process, selected, guest, boundary.identity(guest), record)
            self.check_configured_outer(process, selected)
            self.check_process(process)
        return selected

    def check_configured_outer(self, process, group):
        original, selected, held, identity, record = self.configured_outer_binding
        require(process is original and group is selected and boundary.identity(held) == identity
                and boundary.fs_magic(held) == boundary.CGROUP_MAGIC
                and str(self.fd_mount_id(held)) == record.split()[0])
        reopened, observed = self.guest_cgroup_mount(process)
        try:
            require(boundary.identity(reopened) == identity and observed == record)
        finally:
            self.close_fd(reopened)

    def namespace_chain(self, active, vector):
        """Return actual R..active object identities, retaining every parent FD."""
        chain = [active]
        target = boundary.identity(self.reader_namespace)
        while boundary.identity(chain[-1]) != target:
            require(len(chain) < 16)
            self.budget.fd()
            try:
                parent = fcntl.ioctl(chain[-1], NS_GET_PARENT)
            except OSError:
                raise LocatorRefusal("NamespaceUnreachable") from None
            self.own(parent)
            os.set_inheritable(parent, False)
            require(boundary.identity(parent) not in tuple(boundary.identity(fd) for fd in chain))
            chain.append(parent)
        identities = tuple(boundary.identity(fd) for fd in reversed(chain))
        require(len(identities) == len(vector))
        return identities

    def entries(self, directory):
        """Bounded actual getdents, no listdir/scandir/global proc enumeration."""
        os.lseek(directory, 0, os.SEEK_SET)
        storage = boundary.ctypes.create_string_buffer(4096)
        result = []
        while True:
            self.budget.read(4096)
            size = self.getdents(directory, storage, 4096)
            require(0 <= size <= 4096)
            if not size:
                return tuple(result)
            body, offset = storage.raw[:size], 0
            while offset < size:
                require(offset + 20 <= size)
                length = int.from_bytes(body[offset + 16:offset + 18], sys.byteorder)
                require(length >= 20 and offset + length <= size)
                field = body[offset + 19:offset + length]
                require(b"\0" in field)
                name = field.split(b"\0", 1)[0]
                kind = body[offset + 18]
                require(name and b"/" not in name and len(result) < 4096)
                if name not in (b".", b".."):
                    require(kind in (4, 8))  # only actual cgroup directories/files
                    result.append((name.decode("ascii"), kind))
                offset += length

    def candidates(self, outer):
        self.check_group(outer)
        root = outer.directories[-1]
        device = os.fstat(root).st_dev
        mount_id = self.fd_mount_id(root)
        seen, directories, records, memberships = set(), [root], [], {}
        directory_identities = {boundary.identity(root)}

        def walk(directory, depth, membership):
            require(depth <= 12 and len(directories) <= 128)
            entries = self.entries(directory)
            fd = self.open("cgroup.procs", directory)
            try:
                require(boundary.fs_magic(fd) == boundary.CGROUP_MAGIC)
                body = self.read_fd(fd, 5632)
            finally:
                self.close_fd(fd)
            require(not body or re.fullmatch(rb"(?:[1-9][0-9]{0,9}\n)+", body) is not None)
            pids = tuple(int(x) for x in body.splitlines())
            require(not seen.intersection(pids) and len(pids) == len(set(pids)))
            seen.update(pids)
            memberships.update((pid, membership) for pid in pids)
            require(len(seen) <= 512)
            children = []
            for name, kind in entries:
                if kind == 4:
                    require(len(directories) < 128 and depth < 12)
                    child = self.open(name, directory, directory=True)
                    require(boundary.fs_magic(child) == boundary.CGROUP_MAGIC
                            and os.fstat(child).st_dev == device and self.fd_mount_id(child) == mount_id
                            and boundary.identity(child) not in directory_identities)
                    directory_identities.add(boundary.identity(child))
                    directories.append(child)
                    children.append((name, child, boundary.identity(child)))
                    walk(child, depth + 1, membership + (name,))
            records.append((directory, entries, pids, children))

        previous = set(self.owned)
        try:
            walk(root, 0, outer.membership)
            # Completeness/uniqueness is only accepted at cooperative barriers.
            for directory, entries, pids, children in records:
                require(self.entries(directory) == entries)
                fd = self.open("cgroup.procs", directory)
                try:
                    require(tuple(int(x) for x in self.read_fd(fd, 5632).splitlines()) == pids)
                finally:
                    self.close_fd(fd)
                for name, _child, expected in children:
                    fd = self.open(name, directory, directory=True)
                    try:
                        require(boundary.identity(fd) == expected)
                    finally:
                        self.close_fd(fd)
            self.check_group(outer)
            self.candidate_memberships = memberships
            return tuple(sorted(seen))
        finally:
            self.release_since(previous)


class HeldEndpoint:
    """Fixed socket/docker.sock capability, never a pathname fallback."""

    def __init__(self, source, capture):
        self.source = source
        self.capture = capture
        require(capture in source.owned and source.capture_directory == capture)
        info = os.fstat(capture)
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700)
        self.capture_uid = info.st_uid
        self.directory = source.open("socket", capture, directory=True)
        source.budget.fd()
        self.socket = source.own(os.open("docker.sock", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                                         dir_fd=self.directory))
        require(stat.S_ISSOCK(os.fstat(self.socket).st_mode))
        self.identities = tuple(boundary.identity(fd) for fd in (capture, self.directory, self.socket))

    def check(self):
        source = self.source
        info = os.fstat(self.capture)
        require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == self.capture_uid)
        require(tuple(boundary.identity(fd) for fd in (self.capture, self.directory, self.socket)) == self.identities)
        directory = source.open("socket", self.capture, directory=True)
        try:
            require(boundary.identity(directory) == self.identities[1])
            source.budget.fd()
            fd = source.own(os.open("docker.sock", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=directory))
            try:
                require(boundary.identity(fd) == self.identities[2])
            finally:
                source.close_fd(fd)
        finally:
            source.close_fd(directory)

    @property
    def address(self):
        self.check()
        return "/proc/self/fd/" + str(self.socket)


@dataclass(frozen=True)
class DaemonExpectation:
    uid: int
    executable: tuple  # fixed reviewed components below the daemon's held root
    direct_managed_runtime: bool = False


class PeerLease:
    """Same-stream pidfd remains held; original daemon cannot be replaced."""

    def __init__(self, locator, stream):
        self.locator, self.fd, self.closed = locator, None, False
        source = locator.source
        try:
            source.budget.fd()
            try:
                self.fd = source.own(stream.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD))
            except OSError as error:
                if error.errno in (errno.ENOPROTOOPT, errno.EOPNOTSUPP):
                    raise LocatorRefusal("UnsupportedPeerPidfd") from None
                raise LocatorRefusal() from None
            os.set_inheritable(self.fd, False)
            live(self.fd)
            pid, uid, _gid = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(pid > 0 and uid == locator.expectation.uid)
            self.pid = pid
            locator._bind_peer(pid, uid, self.fd)
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        live(self.fd)
        self.locator.check_daemon()
        require(self.pid == self.locator.daemon.pid)
        live(self.fd)

    def reserve_read(self, maximum):
        self.locator.source.budget.read(maximum)

    def close(self):
        if not self.closed:
            self.closed = True
            if self.fd is not None:
                self.locator.source.close_fd(self.fd)


@dataclass(frozen=True)
class RuntimeBoundProcess:
    slot: str
    container_id: str
    process: object
    group: object
    namespace_chain: tuple
    inspect_facts: tuple


class RuntimeLocator:
    """One in-process owner; constructor inputs are NOT serializable authority.

    reserve_api must synchronously reserve the full call/body maximum in the
    original harness ledger before any connection. It has no permissive default.
    """

    def __init__(self, source, outer_process, outer_group, endpoint, expectation,
                 api_version, owner_labels, reserve_api, *, slot_label=None):
        require(type(source) is LocatorSource and type(expectation) is DaemonExpectation)
        require(expectation.direct_managed_runtime is True)
        require(re.fullmatch(r"1\.(?:4[1-9])", api_version) is not None)
        require(type(owner_labels) is dict and owner_labels and callable(reserve_api))
        require(all(type(k) is str and type(v) is str for k, v in owner_labels.items()))
        require(type(expectation.uid) is int and expectation.uid >= 0)
        require(expectation.executable and all(type(x) is str and x not in ("", ".", "..")
                and "/" not in x for x in expectation.executable))
        self.source, self.outer, self.outer_group = source, outer_process, outer_group
        require(outer_process.membership[:len(outer_group.membership)] == outer_group.membership)
        if hasattr(source, "outer_boundary"):
            require(source.outer_boundary.identities == outer_group.identities)
        source.outer_boundary = outer_group
        self.outer_user_namespace = source.open("ns/user", outer_process.directory, magic=True)
        require(boundary.identity(self.outer_user_namespace) == boundary.identity(source.reader_user_namespace))
        self.endpoint, self.expectation = endpoint, expectation
        self.api_version, self.labels, self.reserve_api = api_version, dict(owner_labels), reserve_api
        self.slot_label = slot_label
        self.daemon, self.daemon_chain, self.daemon_executable = None, None, None
        self.daemon_executable_fd = None
        self.daemon_peer_pidfd = None
        self.bound, self.failed, self.sealed = {}, False, False
        self.retained = set(source.owned)
        self.check_outer()

    def check_outer(self):
        self.source.check_process(self.outer)
        if hasattr(self.source, "configured_outer_binding"):
            self.source.check_configured_outer(self.outer, self.outer_group)
        user = self.source.open("ns/user", self.outer.directory, magic=True)
        try:
            require(boundary.identity(user) == boundary.identity(self.outer_user_namespace)
                    == boundary.identity(self.source.reader_user_namespace))
        finally:
            self.source.close_fd(user)
        require(self.source.check_group(self.outer_group) in (topology.CgroupType.DOMAIN, topology.CgroupType.THREAD_ROOT))
        maximum, current, _events = self.source.values(self.outer_group)
        require(maximum == 512 and current <= 512)

    def executable(self, process):
        source = self.source
        actual = source.open("exe", process.directory, magic=True)
        parents = []
        try:
            parent = process.root
            for name in self.expectation.executable[:-1]:
                parent = source.open(name, parent, directory=True)
                parents.append(parent)
            expected = source.open(self.expectation.executable[-1], parent)
            parents.append(expected)
            require(stat.S_ISREG(os.fstat(actual).st_mode)
                    and boundary.identity(actual) == boundary.identity(expected))
            return boundary.identity(actual)
        finally:
            source.close_fd(actual)
            for fd in reversed(parents):
                source.close_fd(fd)

    def _bind_peer(self, pid, uid, original_peer_pidfd):
        source = self.source
        if self.daemon is not None:
            require(pid == self.daemon.pid)
            self.check_daemon()
            return
        self.check_outer()
        previous = set(source.owned)
        live(original_peer_pidfd)
        discovery = _discovery_module()
        outer_namespace = boundary.identity(self.outer.namespaces[0])
        def consume(lease):
            record = next((record for record in lease.candidates if record.pid == pid), None)
            require(record is not None)
            with lease.acquire(record) as candidate:
                require(candidate.status[1] == (uid,) * 4 and outer_namespace in candidate.namespace_chain)
                lease.select(discovery.Role.PEER, candidate)
        transfer = discovery.discover(source, self.outer_group, discovery.Mode.PEER, consume)
        try:
            source.adopt_discovery_types(transfer, self.outer_group)
            candidate = transfer.selections[0].candidate
            process, chain = candidate.process, candidate.namespace_chain
            executable = self.executable(process)
            executable_fd = source.open("exe", process.directory, magic=True)
            require(boundary.identity(executable_fd) == executable)
            source.budget.fd()
            original_peer = source.own(fcntl.fcntl(original_peer_pidfd, fcntl.F_DUPFD_CLOEXEC, 3))
            live(original_peer)
            self.daemon, self.daemon_chain, self.daemon_executable = process, chain, executable
            self.daemon_executable_fd = executable_fd
            self.daemon_peer_pidfd = original_peer
            self.check_daemon()
            transfer.release_witnesses()
            transfer.handoff()
            self.retained.update(source.owned - previous)
        except BaseException:
            transfer.abort()
            raise

    def check_daemon(self):
        require(not self.failed and self.daemon is not None)
        live(self.daemon_peer_pidfd)
        self.endpoint.check()
        self.check_outer()
        self.source.check_process(self.daemon)
        require(boundary.identity(self.daemon_executable_fd) == self.daemon_executable)
        require(self.executable(self.daemon) == self.daemon_executable)

    def inspect(self, container_id):
        try:
            return self._inspect(container_id)
        except (Exception, KeyboardInterrupt):
            self.failed = True
            raise LocatorRefusal() from None

    def bind_runtime(self, expected_engine, reserve_probe):
        """Acquire the actual daemon before any experiment fixture exists."""
        require(not self.failed and self.daemon is None and callable(reserve_probe))
        try:
            self.source.budget.check()
            reserve_probe()
            status, body = http.request(self.endpoint.address, "GET", "/version",
                timeout=(self.source.budget.work_ns - self.source.budget.clock()) / 1e9,
                max_response_bytes=VERSION_CAP, peer_lease=lambda stream: PeerLease(self, stream))
            require(status == 200)
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    require(key not in result)
                    result[key] = value
                return result
            value = json.loads(body, object_pairs_hook=unique, parse_constant=lambda _: require(False))
            require(type(value) is dict and value.get("Version") == expected_engine)
            def api(value):
                require(type(value) is str and re.fullmatch(r"1\.[0-9]{1,2}", value) is not None)
                return int(value.split(".")[1])
            require(api(value.get("MinAPIVersion")) <= api(self.api_version) <= api(value.get("ApiVersion")))
            self.check_daemon()
        except (Exception, KeyboardInterrupt):
            self.failed = True
            raise LocatorRefusal() from None

    def _inspect(self, container_id):
        require(not self.failed and not self.sealed)
        require(re.fullmatch(r"[0-9a-f]{64}", container_id) is not None)
        self.source.budget.check()
        self.reserve_api(1, INSPECT_CAP)  # one-way; failures retain the full reservation
        status, body = http.request(self.endpoint.address, "GET",
            "/v" + self.api_version + "/containers/" + container_id + "/json",
            timeout=(self.source.budget.work_ns - self.source.budget.clock()) / 1e9,
            max_response_bytes=INSPECT_CAP, peer_lease=lambda stream: PeerLease(self, stream))
        require(status == 200)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result)
                result[key] = value
            return result
        obj = json.loads(body, object_pairs_hook=unique, parse_constant=lambda _: require(False))
        require(type(obj) is dict and obj.get("Id") == container_id)
        state, config = obj.get("State"), obj.get("Config")
        require(type(state) is dict and type(config) is dict and type(config.get("Labels")) is dict)
        require(all(config["Labels"].get(k) == v for k, v in self.labels.items()))
        require(state.get("Running") is True and state.get("Restarting") is False
                and state.get("Paused") is False and state.get("Dead") is False
                and state.get("Status") == "running")
        pid = boundary.integer(state.get("Pid"), high=(1 << 31) - 1)
        started, restarts = state.get("StartedAt"), obj.get("RestartCount")
        require(type(started) is str and 0 < len(started) <= 128)
        require(all(type(k) is str and type(v) is str for k, v in config["Labels"].items()))
        boundary.integer(restarts, 0)
        return pid, started, restarts, tuple(sorted(config["Labels"].items()))

    def locate_batch(self, slots):
        transfer = None
        try:
            require(not self.failed and not self.sealed and not self.bound and type(slots) is dict
                    and tuple(slots) == ORDER and len(set(slots.values())) == 6)
            before = {slot: self.inspect(cid) for slot, cid in slots.items()}
            if self.slot_label is not None:
                require(all(dict(before[slot][3]).get(self.slot_label) == slot for slot in ORDER))
            daemon_ns = boundary.identity(self.daemon.namespaces[0])
            discovery = _discovery_module()
            self.source.type_scope().begin_locate()
            matched = set()
            def consume(lease):
                for record in lease.candidates:
                    with lease.acquire(record) as candidate:
                        chain, vector = candidate.namespace_chain, candidate.status[2]
                        if daemon_ns not in chain:
                            continue
                        index = chain.index(daemon_ns)
                        for slot in ORDER:
                            if vector[index] == before[slot][0]:
                                require(index < len(chain) - 1 and vector[-1] == 1)
                                if slot in matched:
                                    raise LocatorRefusal("AmbiguousMatch")
                                matched.add(slot)
                                lease.select(discovery.Role(slot), candidate)
                if matched != set(ORDER):
                    raise LocatorRefusal("NoMatch")
            transfer = discovery.discover(self.source, self.outer_group, discovery.Mode.WORKERS, consume)
            self.source.adopt_discovery_types(transfer, self.outer_group)
            observed_identities = {row.identity[:2]: row.identity for row in transfer.types}
            result = {}
            for selected in transfer.selections:
                slot = selected.role.value
                candidate = selected.candidate
                process, chain = candidate.process, candidate.namespace_chain
                group = self.source.group(process)  # complete traversal already closed
                self.source.descendant(self.outer_group, group)
                self.source.leaf(group)
                expected = "max" if slot.endswith("unlimited") else (16 if slot.endswith("16") else 64)
                maximum, current, _events = self.source.values(group)
                require(maximum == expected and current == 1)
                _root, nodes = self.source.controller_groups[group.identities[-1]]
                require(nodes[0][1] == observed_identities[selected.local_witness.identity]
                        and group.membership == selected.local_witness.membership == process.membership)
                coverage = [node for node in nodes if node[1][:2] == selected.coverage_witness.identity]
                require(len(coverage) == 1 and coverage[0][1] == observed_identities[selected.coverage_witness.identity])
                result[slot] = RuntimeBoundProcess(slot, slots[slot], process, group, chain, before[slot])
            require(len({x.process.pid for x in result.values()}) == 6
                    and len({x.group.identities[-1] for x in result.values()}) == 6)
            for slot, item in result.items():
                require(self.inspect(item.container_id) == item.inspect_facts)
                self.source.check_process(item.process)
                self.source.check_group(item.group)
            self.check_daemon()
            self.source.freeze_measurement_types(item.group for item in result.values())
            transfer.release_witnesses()
            transfer.handoff()
            self.bound = result
            return result  # live Python objects directly to collector, never JSON
        except LocatorRefusal:
            self.failed = True
            if transfer is not None:
                transfer.abort()
            raise
        except (Exception, KeyboardInterrupt):
            self.failed = True
            if transfer is not None:
                transfer.abort()
            raise LocatorRefusal() from None

    def recheck_batch(self):
        try:
            require(not self.failed and not self.sealed and len(self.bound) == 6)
            self.check_daemon()
            for item in self.bound.values():
                require(self.inspect(item.container_id) == item.inspect_facts)
                self.source.check_process(item.process)
                self.source.check_group(item.group)
        except LocatorRefusal:
            self.failed = True
            raise
        except (Exception, KeyboardInterrupt):
            self.failed = True
            raise LocatorRefusal() from None

    def seal_measurements(self):
        self.recheck_batch()
        for item in self.bound.values():
            self.source.snapshot(item.process, item.group)
        self.source.type_scope().seal()
        # Keep original outer/daemon/endpoint/source objects; release inner-only
        # descriptors before the owner intentionally destroys its leaf fixtures.
        self.source.release_since(self.retained)
        self.bound.clear()
        self.sealed = True
