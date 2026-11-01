"""Synthetic descriptor controls, not real-I/O/IPC fit or native evidence.

The existing Source process/check/read/close/release/namespace implementations
run over a literal in-memory kernel model. OS-facing descriptor operations and
filesystem metadata are replaced; no real process, procfs or cgroup is acquired.
"""

from contextlib import ExitStack
import errno
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import native_pids_discovery as discovery


locator = discovery.locator
boundary = discovery.boundary


class SyntheticSource:
    def __init__(self, *, workers=False):
        self.source = locator.LocatorSource.__new__(locator.LocatorSource)
        self.source.budget = locator.RuntimeBudget(180_000_000_001, lambda: 1)
        self.source.owned, self.source.process_times = set(), {}
        self.objects, self.next_fd, self.trace, self.positions = {}, 100, [], {}
        self.reuse_next, self.cgroup_mount = None, 10
        self.graph = {
            ("owned",): [b"domain\n", b"", 1],
            ("owned", "threads"): [b"domain threaded\n", b"110\n", 2],
            ("owned", "threads", "a"): [b"threaded\n", None, 3],
            ("owned", "threads", "b"): [b"threaded\n", None, 4],
        }
        self.processes = {110: [1100, ("owned", "threads", "a"), 110, (110, 2)]}
        self.parents = {110: 0}
        if workers:
            for index, role in enumerate(locator.ORDER):
                pid = 200 + index
                self.graph[("owned", role)] = [b"domain\n", f"{pid}\n".encode(), pid]
                self.processes[pid] = [pid * 10, ("owned", role), pid, (pid, 70 + index, 1)]
                self.parents[pid] = 110
        self.fail_close = None
        self.close_error = OSError(errno.EIO, "PRIVATE_CLOSE_CANARY")
        self.read_error, self.io_hook, self.open_hook = None, None, None
        self.chunk_limit = None
        self.source.proc = self.initial("proc", None)
        self.root = self.initial("graph", ("owned",))
        self.source.reader_namespace = self.initial("namespace", ("pid", 0))
        self.source.reader_time_namespace = self.initial("namespace", ("time", 0))
        self.outer = SimpleNamespace(directories=(self.root,), membership=("owned",))
        self.source.entries = self.entries
        self.baseline = frozenset(self.source.owned)

    def allocate(self, kind, value):
        if self.reuse_next is None:
            fd, self.next_fd = self.next_fd, self.next_fd + 1
        else:
            fd, self.reuse_next = self.reuse_next, None
            assert fd not in self.source.owned
        self.objects[fd] = kind, value
        self.trace.append(("open", fd, kind, value))
        return fd

    def initial(self, kind, value):
        self.source.budget.fd()
        return self.source.own(self.allocate(kind, value))

    def identity(self, fd):
        kind, value = self.objects[fd]
        if kind == "graph":
            return 10, self.graph[value][2]
        if kind == "procdir":
            return 30, self.processes[value][2]
        if kind == "namespace":
            name, number = value
            return {"pid": 20, "mnt": 21, "cgroup": 22, "time": 23}[name], number
        if kind == "root":
            return 40, 1
        return 50, fd

    def magic(self, fd, observer=None):
        kind, value = self.objects[fd]
        return boundary.CGROUP_MAGIC if kind == "graph" or (kind == "file" and value[0] == "graph") else boundary.PROC_MAGIC

    def open(self, name, flags, *, dir_fd=None):
        if self.open_hook:
            self.open_hook(name, dir_fd)
        kind, value = self.objects[dir_fd]
        if kind == "graph":
            path = value + (name,)
            return self.allocate("graph", path) if path in self.graph else self.allocate("file", (kind, value, name))
        if kind == "proc":
            if name.startswith("self/fdinfo/"):
                return self.allocate("file", ("fdinfo", int(name.rsplit("/", 1)[1]), name))
            return self.allocate("procdir", int(name))
        if kind == "procdir":
            if name == "root":
                return self.allocate("root", value)
            if name.startswith("ns/"):
                field = name[3:]
                return self.allocate("namespace", (field, value if field == "pid" else 0))
            return self.allocate("file", (kind, value, name))
        raise AssertionError("unexpected synthetic open")

    def body(self, fd):
        kind, value = self.objects[fd]
        if kind != "file":
            raise AssertionError("unexpected synthetic read")
        parent_kind, parent, name = value
        if parent_kind == "graph":
            result = self.graph[parent][0 if name == "cgroup.type" else 1]
            if result is None:
                raise AssertionError("threaded procs must never be read")
            return result
        if parent_kind == "fdinfo":
            mount = self.cgroup_mount if self.magic(parent) == boundary.CGROUP_MAGIC else 30
            return f"mnt_id:\t{mount}\n".encode()
        start, membership, _identity, vector = self.processes[parent]
        if name == "stat":
            return f"{parent} (worker) S ".encode() + b"0 " * 18 + str(start).encode() + b"\n"
        if name == "cgroup":
            return ("0::/" + "/".join(membership) + "\n").encode()
        if name == "status":
            return (f"Pid: {parent}\nTgid: {parent}\nUid: 1000 1000 1000 1000\n"
                    f"NSpid: {' '.join(map(str, vector))}\nNStgid: {' '.join(map(str, vector))}\n").encode()
        raise AssertionError("unexpected synthetic file")

    def read(self, fd, maximum):
        if self.io_hook:
            self.io_hook(fd)
        if self.read_error:
            raise self.read_error
        self.trace.append(("read", fd, maximum))
        body = self.body(fd)
        offset = self.positions.get(fd, 0)
        size = min(maximum, self.chunk_limit) if self.chunk_limit else maximum
        result = body[offset:offset + size]
        self.positions[fd] = offset + len(result)
        return result

    def close(self, fd):
        self.trace.append(("close", fd))
        if self.fail_close and self.fail_close(fd):
            raise self.close_error

    def entries(self, fd):
        self.source.budget.read(4096)
        self.trace.append(("entries", self.objects[fd][1]))
        self.source.budget.read(4096)
        path = self.objects[fd][1]
        children = [(key[-1], 4) for key in self.graph if len(key) == len(path) + 1 and key[:-1] == path]
        return tuple(children + [("cgroup.type", 8), ("cgroup.procs", 8)])

    def ioctl(self, fd, operation):
        assert operation == locator.NS_GET_PARENT
        name, number = self.objects[fd][1]
        return self.allocate("namespace", (name, self.parents[number]))

    def environment(self):
        stack = ExitStack()
        for target, replacement in [
            ("os.open", self.open), ("os.read", self.read), ("os.close", self.close),
            ("os.lseek", lambda fd, offset, whence: self.positions.__setitem__(fd, offset)),
            ("os.pidfd_open", lambda pid, flags: self.allocate("pidfd", pid)),
            ("os.set_inheritable", lambda fd, value: None),
        ]:
            stack.enter_context(patch(target, replacement))
        stack.enter_context(patch.object(boundary, "identity", self.identity))
        stack.enter_context(patch.object(boundary, "fs_magic", self.magic))
        stack.enter_context(patch.object(locator.select, "select", lambda *args: ([], [], [])))
        stack.enter_context(patch.object(locator.fcntl, "ioctl", self.ioctl))
        return stack


class DiscoveryTests(unittest.TestCase):
    def consume_peer(self, lease):
        record = next(record for record in lease.candidates if record.pid == 110)
        with lease.acquire(record) as candidate:
            self.assertEqual(candidate.namespace_chain, ((20, 0), (20, 110)))
            lease.select(discovery.Role.PEER, candidate)

    def consume_workers(self, lease):
        for record in lease.candidates:
            with lease.acquire(record) as candidate:
                if record.pid >= 200:
                    role = discovery.Role(locator.ORDER[record.pid - 200])
                    lease.select(role, candidate)

    def test_peer_scope_transfer_and_shared_graph_witnesses_have_one_owner(self):
        fixture = SyntheticSource()
        with fixture.environment():
            transfer = discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, self.consume_peer)
            selected = transfer.selections[0]
            self.assertEqual(selected.local_witness.membership, ("owned", "threads", "a"))
            self.assertEqual(selected.coverage_witness.membership, ("owned", "threads"))
            # Full virtual LocatorSource acquisition includes timens + NS parent.
            self.assertEqual(len(transfer._process_owned), 8)
            self.assertEqual(len(transfer._witness_owned), 2)
            self.assertIn(selected.candidate.process, fixture.source.process_times)
            later = fixture.initial("root", "later group")
            transfer.release_witnesses()
            fixture.source.check_process(selected.candidate.process)
            self.assertIn(selected.candidate.process.directory, fixture.source.owned)
            transfer.close()
            self.assertEqual(fixture.source.owned, fixture.baseline | {later})
            self.assertEqual(fixture.source.process_times, {})
            closed = [event[1] for event in fixture.trace if event[0] == "close"]
            self.assertEqual(len(closed), len(set(closed)))
            with self.assertRaises(boundary.Refusal):
                transfer.close()
            self.assertNotIn(fixture.root, closed)

    def test_six_workers_close_unmatched_scopes_and_keep_borrowed_outer(self):
        fixture = SyntheticSource(workers=True)
        with fixture.environment():
            transfer = discovery.discover(fixture.source, fixture.outer, discovery.Mode.WORKERS, self.consume_workers)
            self.assertEqual([item.role.value for item in transfer.selections], list(locator.ORDER))
            self.assertEqual(len(transfer.witnesses), 6)
            self.assertEqual(len(transfer._process_owned), 54)
            self.assertTrue(all(item.local_witness is item.coverage_witness for item in transfer.selections))
            self.assertEqual({process.pid for process in fixture.source.process_times}, set(range(200, 206)))
            transfer.close()
            self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_shared_aggregate_witness_is_unique_and_baseline_root_is_borrowed(self):
        fixture = SyntheticSource(workers=True)
        for index, role in enumerate(locator.ORDER):
            pid = 200 + index
            del fixture.graph[("owned", role)]
            path = ("owned", "threads", role)
            fixture.graph[path] = [b"threaded\n", None, pid]
            fixture.processes[pid][1] = path
        fixture.graph[("owned", "threads")][1] = b"110\n200\n201\n202\n203\n204\n205\n"
        with fixture.environment():
            transfer = discovery.discover(fixture.source, fixture.outer, discovery.Mode.WORKERS, self.consume_workers)
            self.assertEqual(len(transfer.witnesses), 7)
            self.assertTrue(all(item.coverage_witness is transfer.selections[0].coverage_witness
                                for item in transfer.selections))
            transfer.close()
            closed = [event[1] for event in fixture.trace if event[0] == "close"]
            self.assertEqual(len(closed), len(set(closed)))
            self.assertEqual(fixture.source.owned, fixture.baseline)
        fixture = SyntheticSource()
        fixture.processes[110][1] = ("owned",)
        fixture.graph[("owned",)][1] = b"110\n"
        fixture.graph[("owned", "threads")][1] = b""
        with fixture.environment():
            transfer = discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, self.consume_peer)
            self.assertEqual(len(transfer.witnesses), 1)
            self.assertTrue(transfer.witnesses[0].borrowed)
            self.assertEqual(transfer._witness_owned, frozenset())
            transfer.close()
            self.assertIn(fixture.root, fixture.source.owned)

    def test_reordered_complete_procs_sets_are_allowed_but_changes_refuse(self):
        for changed in (False, True):
            fixture = SyntheticSource()
            fixture.graph[("owned", "threads")][1] = b"110\n111\n"
            fixture.processes[111] = [1110, ("owned", "threads", "b"), 111, (111, 3)]
            def consume(lease):
                self.consume_peer(lease)
                fixture.graph[("owned", "threads")][1] = b"111\n" if changed else b"111\n110\n"
            with fixture.environment():
                if changed:
                    with self.assertRaises(boundary.Refusal):
                        discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, consume)
                else:
                    transfer = discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, consume)
                    transfer.close()
                self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_provisional_start_bracket_and_actual_acquisition_drift_refuse(self):
        for change in ("bracket", "actual-start", "actual-directory"):
            fixture = SyntheticSource()
            observed_stats = []
            def hook(fd):
                kind, value = fixture.objects[fd]
                if kind == "file" and value == ("procdir", 110, "stat"):
                    observed_stats.append(fd)
                    if change == "bracket" and len(observed_stats) == 3:
                        # The first read includes its EOF; third call begins
                        # the second stat file in stat/cgroup/stat.
                        fixture.processes[110][0] += 1
            fixture.io_hook = hook
            def consume(lease):
                fixture.processes[110][0 if change == "actual-start" else 2] += 1
                self.consume_peer(lease)
            with fixture.environment(), self.assertRaises(boundary.Refusal):
                discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER,
                                   self.consume_peer if change == "bracket" else consume)
            self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_observed_local_movement_start_and_directory_drift_refuse(self):
        for change in ("membership", "start", "identity", "procfs", "type", "listing", "mount"):
            with self.subTest(change=change):
                fixture = SyntheticSource()
                consume = self.consume_peer
                def mutate(lease):
                    consume(lease)
                    if change == "membership":
                        fixture.processes[110][1] = ("owned", "threads", "b")
                    elif change == "start":
                        fixture.processes[110][0] += 1
                    elif change == "identity":
                        fixture.processes[110][2] += 1
                    elif change == "procfs":
                        fixture.source.proc = fixture.root
                    elif change == "type":
                        fixture.graph[("owned", "threads")][0] = b"domain\n"
                    elif change == "listing":
                        fixture.graph[("owned", "new")] = [b"domain\n", b"", 99]
                    else:
                        fixture.cgroup_mount += 1
                with fixture.environment(), self.assertRaises(boundary.Refusal):
                    discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, mutate)
                self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_duplicate_leaders_graph_alias_and_invalid_threaded_roles_refuse(self):
        for change in ("within", "across", "alias", "bad-root", "bad-child", "missing-local"):
            with self.subTest(change=change):
                fixture = SyntheticSource()
                if change == "within":
                    fixture.graph[("owned", "threads")][1] = b"110\n110\n"
                elif change == "across":
                    fixture.graph[("owned",)][1] = b"110\n"
                elif change == "alias":
                    fixture.graph[("owned", "threads", "b")][2] = 3
                elif change == "bad-root":
                    fixture.graph[("owned",)][0] = b"threaded\n"
                elif change == "bad-child":
                    fixture.graph[("owned", "threads", "b")][0] = b"domain\n"
                else:
                    fixture.processes[110][1] = ("outside",)
                with fixture.environment(), self.assertRaises((boundary.Refusal, discovery.topology.TopologyRefusal)):
                    discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, self.consume_peer)
                self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_callback_io_fd_and_counter_changes_are_refused(self):
        for change in ("read", "fd", "counter", "outside-acquire"):
            with self.subTest(change=change):
                fixture = SyntheticSource()
                def consume(lease):
                    with lease.acquire(lease.candidates[0]) as candidate:
                        lease.select(discovery.Role.PEER, candidate)
                        if change == "read":
                            fixture.source.read(candidate.process.directory, "stat", 1024)
                        elif change == "fd":
                            fixture.source.open("status", candidate.process.directory)
                        elif change == "counter":
                            fixture.source.budget.reads += 1
                    if change == "outside-acquire":
                        fixture.source.budget.bytes += 1
                with fixture.environment(), self.assertRaises(boundary.Refusal):
                    discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, consume)
                self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_worker_early_return_skip_duplicate_acquisition_and_role_refuse(self):
        for behavior in ("early", "skip-unmatched", "repeat", "duplicate-role", "peer-role"):
            fixture = SyntheticSource(workers=True)
            def consume(lease):
                if behavior == "early":
                    return
                for record in lease.candidates:
                    if behavior == "skip-unmatched" and record.pid == 110:
                        continue
                    with lease.acquire(record) as candidate:
                        if record.pid >= 200:
                            role = discovery.Role(locator.ORDER[record.pid - 200])
                            if behavior == "duplicate-role":
                                role = discovery.Role.CLI16
                            elif behavior == "peer-role":
                                role = discovery.Role.PEER
                            lease.select(role, candidate)
                    if behavior == "repeat":
                        with lease.acquire(record):
                            self.fail("reopened candidate must refuse before acquisition")
            with fixture.environment(), self.assertRaises(boundary.Refusal):
                discovery.discover(fixture.source, fixture.outer, discovery.Mode.WORKERS, consume)
            self.assertEqual(fixture.source.owned, fixture.baseline)
            self.assertEqual(fixture.source.process_times, {})

    def test_retired_or_abandoned_acquisition_cannot_close_later_source_scopes(self):
        fixture = SyntheticSource()
        captured = []
        def abandon(lease):
            captured.append(lease.acquire(lease.candidates[0]))
            captured[0].__enter__()
        with fixture.environment():
            with self.assertRaises(boundary.Refusal):
                discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, abandon)
            self.assertEqual(fixture.source.owned, fixture.baseline)
            later = fixture.initial("root", "later ROOT scope")
            before = list(fixture.trace)
            with self.assertRaises(boundary.Refusal):
                captured[0].__exit__(None, None, None)
            self.assertEqual(fixture.trace, before)
            self.assertEqual(fixture.source.owned, fixture.baseline | {later})

    def test_namespace_acquisition_and_callback_failures_cannot_transfer(self):
        for phase in ("namespace", "callback"):
            fixture = SyntheticSource()
            original = RuntimeError("PRIVATE_WORK_CANARY")
            def consume(lease):
                with lease.acquire(lease.candidates[0]):
                    raise original
            with fixture.environment():
                if phase == "namespace":
                    with patch.object(locator.fcntl, "ioctl", side_effect=OSError(errno.EPERM, "private")):
                        with self.assertRaises(locator.LocatorRefusal):
                            discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, self.consume_peer)
                else:
                    with self.assertRaises(RuntimeError) as result:
                        discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, consume)
                    self.assertIs(result.exception, original)
            self.assertEqual(fixture.source.owned, fixture.baseline)
            self.assertEqual(fixture.source.process_times, {})

    def test_partial_reads_use_original_reservations_and_exhaust_before_io(self):
        fixture = SyntheticSource()
        fixture.chunk_limit = 1
        with fixture.environment():
            transfer = discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, self.consume_peer)
            self.assertGreater(fixture.source.budget.reads, 500)
            transfer.close()
        for resource in ("reads", "bytes", "fds"):
            with self.subTest(resource=resource):
                fixture = SyntheticSource()
                limits = {"reads": 65536, "bytes": boundary.SOURCE_BYTES, "fds": 256}
                setattr(fixture.source.budget, resource, limits[resource])
                before_reads = len([event for event in fixture.trace if event[0] == "read"])
                with fixture.environment(), self.assertRaises(boundary.Refusal):
                    discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, self.consume_peer)
                self.assertEqual(len([event for event in fixture.trace if event[0] == "read"]), before_reads)
                self.assertEqual(fixture.source.owned, fixture.baseline)
                self.assertGreater(getattr(fixture.source.budget, resource), limits[resource])

    def test_required_procs_error_and_short_read_error_preserve_failure(self):
        for phase in ("procs", "partial"):
            fixture = SyntheticSource()
            original = OSError(errno.EOPNOTSUPP if phase == "procs" else errno.EIO, "PRIVATE_READ_CANARY")
            calls = []
            def hook(fd):
                if fixture.objects[fd] == ("file", ("graph", ("owned", "threads"), "cgroup.procs")):
                    calls.append(fd)
                    if phase == "procs" or len(calls) == 2:
                        raise original
            fixture.io_hook = hook
            fixture.chunk_limit = 1 if phase == "partial" else None
            with fixture.environment(), self.assertRaises(OSError) as result:
                discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, self.consume_peer)
            self.assertIs(result.exception, original)
            self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_structural_maximum_is_permitted_to_refuse_live_fd_budget(self):
        fixture = SyntheticSource(workers=True)
        for index in range(118):
            fixture.graph[("owned", f"empty{index:03}")] = [b"domain\n", b"", 1000 + index]
        self.assertEqual(len(fixture.graph), 128)
        for index, role in enumerate(locator.ORDER):
            pid = 200 + index
            fixture.processes[pid][3] = (pid, *range(4000, 4014), 1)
            intermediate = [10000 + index * 20 + offset for offset in range(13)]
            route = [pid, *intermediate, 110, 0]
            fixture.parents.update(zip(route, route[1:]))
        with fixture.environment(), self.assertRaises(boundary.Refusal):
            discovery.discover(fixture.source, fixture.outer, discovery.Mode.WORKERS, self.consume_workers)
        self.assertGreater(fixture.source.budget.peak_fds, 256)
        self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_cleanup_refusal_supersedes_work_and_first_cleanup_failure_survives(self):
        for unexpected in (False, True):
            fixture = SyntheticSource()
            work = RuntimeError("work")
            cleanup = RuntimeError("unexpected cleanup") if unexpected else boundary.Refusal()
            cleanup_fd = []
            def consume(lease):
                with lease.acquire(lease.candidates[0]) as candidate:
                    cleanup_fd.append(candidate.process.pidfd)
                    fixture.fail_close = lambda fd: fd == cleanup_fd[0]
                    if unexpected:
                        fixture.close_error = cleanup
                    raise work
            def require(condition):
                if not condition:
                    raise cleanup
            with fixture.environment(), patch.object(locator, "require", require):
                with self.assertRaises(type(cleanup)) as result:
                    discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, consume)
                self.assertIs(result.exception, cleanup)
                self.assertEqual(fixture.source.owned, fixture.baseline)
                self.assertEqual(fixture.trace.count(("close", cleanup_fd[0])), 1)

    def test_transfer_cleanup_failure_retires_owner_without_retry(self):
        fixture = SyntheticSource()
        with fixture.environment():
            transfer = discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, self.consume_peer)
            fd = transfer.selections[0].candidate.process.pidfd
            fixture.fail_close = lambda candidate: candidate == fd
            with self.assertRaises(boundary.Refusal):
                transfer.close()
            self.assertEqual(fixture.source.owned, fixture.baseline)
            with self.assertRaises(boundary.Refusal):
                transfer.close()
            self.assertEqual(fixture.trace.count(("close", fd)), 1)

    def test_final_graph_cleanup_uncertainty_prevents_transfer_and_keeps_first_error(self):
        fixture = SyntheticSource()
        first, second = boundary.Refusal(), boundary.Refusal()
        errors = []
        def require(condition):
            if not condition:
                error = first if not errors else second
                errors.append(error)
                raise error
        def consume(lease):
            self.consume_peer(lease)
            # First fault is an unused graph directory, second is a selected
            # pidfd cleaned by the fallback. Both numbers retire before close.
            original = next(fd for fd in fixture.source.owned
                            if fixture.objects[fd] == ("graph", ("owned", "threads", "b")))
            fixture.fail_close = lambda fd: fd == original or fixture.objects[fd] == ("pidfd", 110)
        with fixture.environment(), patch.object(locator, "require", require):
            with self.assertRaises(boundary.Refusal) as result:
                discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, consume)
            self.assertIs(result.exception, first)
            self.assertIn(second, errors)
            self.assertIs(result.exception.__cause__, second)
            self.assertEqual(fixture.source.owned, fixture.baseline)
            closed = [event[1] for event in fixture.trace if event[0] == "close"]
            self.assertEqual(len(closed), len(set(closed)))

    def test_witness_release_failure_requires_root_abort_without_process_reuse(self):
        fixture = SyntheticSource()
        with fixture.environment():
            transfer = discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, self.consume_peer)
            witness = transfer.selections[0].local_witness.directory
            process = transfer.selections[0].candidate.process
            fixture.fail_close = lambda fd: fd == witness
            with self.assertRaises(boundary.Refusal):
                transfer.release_witnesses()
            self.assertIn(process.directory, fixture.source.owned)
            with self.assertRaises(boundary.Refusal):
                transfer.close()
            fixture.source.release_since(fixture.baseline)  # original ROOT abort
            self.assertEqual(fixture.source.owned, fixture.baseline)
            self.assertEqual(fixture.trace.count(("close", witness)), 1)

    def test_reused_witness_number_is_not_closed_by_successful_or_failed_transfer(self):
        for fault in (False, True):
            with self.subTest(fault=fault):
                fixture = SyntheticSource()
                with fixture.environment():
                    transfer = discovery.discover(fixture.source, fixture.outer, discovery.Mode.PEER, self.consume_peer)
                    witness = transfer.selections[0].local_witness.directory
                    if fault:
                        fixture.fail_close = lambda fd: fd == witness
                        with self.assertRaises(boundary.Refusal):
                            transfer.release_witnesses()
                        fixture.fail_close = None
                    else:
                        transfer.release_witnesses()
                    self.assertNotIn(witness, fixture.source.owned)
                    fixture.reuse_next = witness
                    later = fixture.initial("root", "independently owned Group")
                    self.assertEqual(later, witness)
                    if fault:
                        with self.assertRaises(boundary.Refusal):
                            transfer.close()
                    else:
                        transfer.close()
                    self.assertIn(later, fixture.source.owned)
                    self.assertEqual(fixture.trace.count(("close", witness)), 1)
                    # Only original ROOT teardown owns this new incarnation.
                    fixture.source.release_since(fixture.baseline)


if __name__ == "__main__":
    unittest.main()
