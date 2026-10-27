"""Hermetic controls only: none of these tests is native runtime evidence."""

import ctypes
import ast
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "native_pids_boundary", Path(__file__).resolve().parents[1] / "scripts/native_pids_boundary.py"
)
b = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(b)


class FakeSource:
    """Independent fixed task/group facts; no JSON response can replace them."""

    def __init__(self):
        self.closed = 0
        self.broken = None
        self.cleanup_failure = False
        self.outer = SimpleNamespace(identities=((1, 1), (1, 2)), membership=("owned",), maximum=512)
        self.groups = {100: self.outer}
        self.starts = {100: 111}
        for index, slot in enumerate(sorted(b.SLOTS)):
            pid = 200 + index
            maximum = "max" if slot.endswith("unlimited") else (16 if slot.endswith("16") else 64)
            self.groups[pid] = SimpleNamespace(
                identities=((1, 1), (1, 2), (1, 20 + index)),
                membership=("owned", slot), maximum=maximum,
            )
            self.starts[pid] = 1000 + index

    def pid(self, slot):
        return 200 + sorted(b.SLOTS).index(slot)

    def process(self, pid, start, within=None):
        b.require(pid in self.starts and start == self.starts[pid])
        group = self.groups[pid]
        if within is not None:
            b.require(len(group.membership) > len(within.membership))
            b.require(group.membership[:len(within.membership)] == within.membership)
        return SimpleNamespace(pid=pid, start=start)

    def group(self, proc):
        return self.groups[proc.pid]

    def check_process(self, proc):
        b.require(self.broken not in ("exit", "reuse", "namespace", "root"))
        b.require(self.starts[proc.pid] == proc.start)

    def check_group(self, group):
        b.require(self.broken not in ("replacement", "file_replacement", "mount", "non_domain"))

    def values(self, group):
        return group.maximum, 1, 0

    def descendant(self, outer, leaf):
        b.LinuxSource.descendant(self, outer, leaf)

    def snapshot(self, proc, group):
        self.check_process(proc)
        self.check_group(group)
        b.require(self.broken not in ("thread_ambiguity", "unstable", "descendant"))
        return {"maximum": group.maximum, "current": 1, "events_max": 0, "tasks": [[proc.pid, proc.start]]}

    def close(self):
        self.closed += 1
        b.require(not self.cleanup_failure)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_000_000_000
        self.budget = b.Budget(self.now + 180_000_000_000, lambda: self.now)
        self.source = FakeSource()
        self.session = b.Session(self.budget, self.source)

    def outer(self):
        return self.session.handle({"op": "BindOuter", "pid": 100, "start": 111, "context": {
            "backend": "docker", "candidate": "a" * 40, "run": "run1", "lane": "debian-rootful", "outer_id": "b" * 64,
        }})

    def leaf(self, slot="cli16"):
        pid = self.source.pid(slot)
        return self.session.handle({"op": "BindLeaf", "slot": slot, "pid": pid, "start": self.source.starts[pid]})

    def test_synthetic_complete_six_slot_state_sequence_not_kernel_budget_fit(self):
        self.assertEqual(self.outer(), {"op": "BindOuter", "status": "ok"})
        for slot in sorted(b.SLOTS):
            self.leaf(slot)
            for phase in ("before", "at_limit", "after_failure", "after_release"):
                response = self.session.handle({"op": "Sample", "slot": slot, "phase": phase})
                self.assertEqual(response["sample"]["tasks"], [[self.source.pid(slot), self.source.starts[self.source.pid(slot)]]])
        self.assertEqual(self.session.handle({"op": "Finish"}), {"op": "Finish", "status": "ok"})
        self.assertTrue(self.session.finished)
        self.assertEqual(self.source.closed, 1)
        with self.assertRaises(b.Refusal):
            self.session.handle({"op": "Finish"})

    def test_unknown_fields_types_and_use_before_bind_are_terminal(self):
        cases = [None, [], {}, {"op": "Sample", "slot": "cli16", "phase": "before"},
                 {"op": "BindOuter", "pid": True, "start": 111, "context": {}},
                 {"op": "Finish", "path": "CANARY-private"}, {"op": "Setns"},
                 {"op": "BindLeaf", "slot": [], "pid": 1, "start": 2}]
        for request in cases:
            with self.subTest(request=request):
                session = b.Session(self.budget, FakeSource())
                with self.assertRaises(b.Refusal):
                    session.handle(request)
                self.assertTrue(session.failed)
                with self.assertRaises(b.Refusal):
                    session.handle({"op": "Finish"})

    def test_duplicate_bind_and_reordered_or_duplicate_phases(self):
        for bad in ("bind", "first", "repeat", "reverse"):
            with self.subTest(bad=bad):
                self.setUp()
                self.outer()
                self.leaf()
                if bad in ("repeat", "reverse"):
                    self.session.handle({"op": "Sample", "slot": "cli16", "phase": "before"})
                if bad == "reverse":
                    self.session.handle({"op": "Sample", "slot": "cli16", "phase": "at_limit"})
                with self.assertRaises(b.Refusal):
                    if bad == "bind":
                        self.leaf()
                    else:
                        self.session.handle({"op": "Sample", "slot": "cli16", "phase": "at_limit" if bad == "first" else "before"})

    def test_sibling_equal_parent_and_alias_rejected(self):
        for membership, ids in [(("sibling", "leaf"), ((1, 1), (1, 3), (1, 5))),
                                (("owned",), ((1, 1), (1, 2))),
                                ((), ((1, 1),)),
                                (("owned", "alias"), ((1, 1), (1, 7), (1, 20)))]:
            with self.subTest(membership=membership):
                self.setUp()
                self.outer()
                group = self.source.groups[self.source.pid("cli16")]
                group.membership, group.identities = membership, ids
                with self.assertRaises(b.Refusal):
                    self.leaf()

    def test_duplicate_actual_leaf_under_different_slots_rejected(self):
        self.outer()
        self.leaf()
        old = self.source.groups[self.source.pid("cli16")]
        other = self.source.groups[self.source.pid("rendered16")]
        other.identities = old.identities
        with self.assertRaises(b.Refusal):
            self.leaf("rendered16")

    def test_identity_exit_reuse_namespace_and_object_changes_rejected(self):
        for fault in ("exit", "reuse", "namespace", "root", "replacement", "file_replacement", "mount", "non_domain", "thread_ambiguity", "unstable", "descendant"):
            with self.subTest(fault=fault):
                self.setUp()
                self.outer()
                self.leaf()
                self.source.broken = fault
                with self.assertRaises(b.Refusal):
                    self.session.handle({"op": "Sample", "slot": "cli16", "phase": "before"})

    def test_wrong_start_limit_and_outer_limit_rejected(self):
        self.source.starts[100] += 1
        with self.assertRaises(b.Refusal):
            self.outer()
        self.setUp()
        self.source.outer.maximum = 511
        with self.assertRaises(b.Refusal):
            self.outer()
        self.setUp()
        self.outer()
        self.source.groups[self.source.pid("cli16")].maximum = 64
        with self.assertRaises(b.Refusal):
            self.leaf()

    def test_deadline_is_not_renewed_by_operations(self):
        self.outer()
        original = self.budget.work_ns
        self.now = original
        with self.assertRaises(b.Refusal):
            self.leaf()
        self.assertEqual(self.budget.work_ns, original)
        self.assertEqual(self.budget.deadline_ns - original, 46_000_000_000)

    def test_cleanup_failure_never_returns_finish_success(self):
        self.outer()
        self.source.cleanup_failure = True
        with self.assertRaises(b.Refusal):
            self.session.handle({"op": "Finish"})
        self.assertFalse(self.session.finished)


class KernelReaderTests(unittest.TestCase):
    def setUp(self):
        self.budget = b.Budget(180_000_000_001, lambda: 1)
        self.source = object.__new__(b.LinuxSource)
        self.source.budget = self.budget
        self.source.owned = set()

    def test_partial_reads_charge_every_syscall_and_do_not_refund_failure(self):
        with patch.object(b.os, "lseek"), patch.object(b.os, "read", side_effect=[b"a", b"b", b""]):
            self.assertEqual(self.source.read_fd(8, 8), b"ab")
        self.assertEqual(self.budget.bytes, 24)  # caps9,8,7; no partial/EOF refund
        self.assertEqual(self.budget.reads, 3)
        previous = self.budget.bytes
        with patch.object(b.os, "lseek"), patch.object(b.os, "read", side_effect=OSError("CANARY")):
            with self.assertRaises(OSError):
                self.source.read_fd(8, 8)
        self.assertEqual(self.budget.bytes, previous + 9)

    def test_chunk_reservation_exhaustion_precedes_seek_and_read(self):
        self.budget.bytes = 32 * 1024 * 1024
        with patch.object(b.os, "lseek") as seek, patch.object(b.os, "read") as read:
            with self.assertRaises(b.Refusal):
                self.source.read_fd(8, 65536)
            seek.assert_not_called()
            read.assert_not_called()
        self.assertEqual(self.budget.bytes, 32 * 1024 * 1024 + 1024)

    def test_chunk_caps_partial_error_and_eof_are_all_precharged(self):
        with patch.object(b.os, "lseek"), patch.object(b.os, "read", side_effect=[b"x" * 1024, b"y" * 1024, b""]) as read:
            self.assertEqual(len(self.source.read_fd(8, 3000)), 2048)
        self.assertEqual([call.args for call in read.call_args_list], [(8, 1024), (8, 1024), (8, 953)])
        self.assertEqual((self.budget.bytes, self.budget.reads), (3001, 3))
        previous = self.budget.bytes
        with patch.object(b.os, "lseek"), patch.object(b.os, "read", side_effect=[b"x", OSError("private")]):
            with self.assertRaises(OSError):
                self.source.read_fd(8, 65536)
        self.assertEqual(self.budget.bytes, previous + 2048)

    def test_oversize_read_rejected(self):
        with patch.object(b.os, "lseek"), patch.object(b.os, "read", return_value=b"123456789"):
            with self.assertRaises(b.Refusal):
                self.source.read_fd(8, 8)

    def test_fake_procfs_is_rejected_and_open_descriptor_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            actual_open = os.open
            opened = []
            def redirected(name, flags, dir_fd=None):
                fd = actual_open(directory if name == "/proc" else name, flags, dir_fd=dir_fd)
                opened.append(fd)
                return fd
            with patch.object(b.os, "open", side_effect=redirected):
                with self.assertRaises(b.Refusal):
                    b.LinuxSource(self.budget)
            for fd in opened:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_non_cgroup_filesystem_cannot_become_group(self):
        self.source.proc = 8
        self.source.read = lambda *_: b"1 0 0:1 / /tmp rw - cgroup2 cgroup rw\n"
        self.source.open = lambda *_args, **_kwargs: 9
        self.source.close_fd = lambda *_: None
        with patch.object(b, "fs_magic", return_value=0xEF53):
            with self.assertRaises(b.Refusal):
                self.source.group(SimpleNamespace(membership=()))

    def test_ambiguous_mount_or_guest_relative_mount_rejected(self):
        self.source.proc = 8
        proc = SimpleNamespace(membership=("owned", "leaf"))
        for body in (b"1 0 0:1 / /x rw - cgroup2 cgroup rw\n2 0 0:1 / /y rw - cgroup2 cgroup rw\n",
                     b"1 0 0:1 /other /x rw - cgroup2 cgroup rw\n"):
            self.source.read = lambda *_: body
            with self.assertRaises(b.Refusal):
                self.source.group(proc)

    def test_real_process_change_checks_pidfd_stat_membership_and_namespaces(self):
        proc = SimpleNamespace(pid=90, start=12, pidfd=7, directory=8, membership=("owned",), status=())
        with patch.object(b.select, "select", return_value=([7], [], [])):
            with self.assertRaises(b.Refusal):
                self.source.check_process(proc)
        stat_body = b"90 (comm) S " + b"0 " * 18 + b"13\n"
        self.source.read = lambda *_: stat_body
        with patch.object(b.select, "select", return_value=([], [], [])):
            with self.assertRaises(b.Refusal):
                self.source.check_process(proc)

    def test_real_process_root_namespace_or_proc_replacement_rejected(self):
        self.source.proc = 8
        status = b"Pid: 90\nTgid: 90\nUid: 1 1 1 1\nNSpid: 90\n"
        proc = SimpleNamespace(pid=90, start=12, pidfd=7, directory=8, membership=("owned",),
                               status=b.process_status(status, 90, True),
                               identity=((1, 20), ((1, 21), 1), ((1, 22), (1, 23), (1, 24))))
        stat_body = b"90 (comm) S " + b"0 " * 18 + b"12\n"
        self.source.read = lambda _parent, name, _maximum: {"stat": stat_body, "cgroup": b"0::/owned\n", "status": status}[name]
        for index in range(6):
            fds = iter(range(20, 25))
            closed = []
            self.source.open = lambda *_args, **_kwargs: next(fds)
            self.source.close_fd = closed.append
            self.source.fd_mount_id = lambda *_: 2 if index == 5 else 1
            with patch.object(b.select, "select", return_value=([], [], [])), patch.object(
                b, "identity", side_effect=lambda fd: (1, fd + 100 if fd == 20 + index else fd)
            ):
                with self.assertRaises(b.Refusal):
                    self.source.check_process(proc)
            self.assertEqual(closed, list(range(20, 25)))

    def test_mount_fdinfo_id_and_device_must_match_kernel_record(self):
        self.source.proc = 8
        self.source.read = lambda *_: b"pos:\t0\nmnt_id:\t41\n"
        record = "41 1 0:9 / /sys/fs/cgroup rw - cgroup2 cgroup rw"
        with patch.object(b.os, "fstat", return_value=SimpleNamespace(st_dev=os.makedev(0, 9))):
            self.source.check_mount(9, record)
            with self.assertRaises(b.Refusal):
                self.source.check_mount(9, record.replace("41 1", "42 1"))
            with self.assertRaises(b.Refusal):
                self.source.check_mount(9, record.replace("0:9", "0:10"))

    def test_controller_replacement_fails_while_all_transient_fds_close(self):
        self.source.proc = 8
        self.source.read = lambda *_: b"record\n"
        self.source.check_mount = lambda *_: None
        group = SimpleNamespace(mount_record="record", directories=(10, 11), identities=((1, 10), (1, 11)),
                                names=("leaf",), files=(20, 21, 22, 23))
        opened = iter([11, 99])
        closed = []
        self.source.open = lambda *_args, **_kwargs: next(opened)
        self.source.close_fd = closed.append
        with patch.object(b, "identity", side_effect=lambda fd: (1, fd)), patch.object(b, "fs_magic", return_value=b.CGROUP_MAGIC):
            with self.assertRaises(b.Refusal):
                self.source.check_group(group)
        self.assertEqual(closed, [11, 99])

    def test_snapshot_accounts_all_tids_and_rejects_instability(self):
        self.source.check_process = lambda *_: None
        self.source.check_group = lambda *_: b.topology.CgroupType.DOMAIN
        self.source.leaf = lambda *_: None
        self.source.values = lambda *_: (16, 2, 3)
        self.source.tasks = lambda *_: ((10, 11), (12, 13))
        self.assertEqual(self.source.snapshot(None, None), {
            "maximum": 16, "current": 2, "events_max": 3, "cgroup_type": "domain", "tasks": [[10, 11], [12, 13]],
            "task_namespace_ids": [],
        })
        for facts in [iter([((10, 11),), ((10, 11),)]),
                      iter([((10, 11), (12, 13)), ((10, 11), (12, 14))])]:
            self.source.tasks = lambda *_: next(facts)
            with self.assertRaises(b.Refusal):
                self.source.snapshot(None, None)

    def test_snapshot_rejects_persistent_empty_child_created_during_sampling(self):
        self.source.check_process = lambda *_: None
        self.source.check_group = lambda *_: b.topology.CgroupType.DOMAIN
        child = False
        scans = []
        def leaf(_group):
            scans.append(child)
            b.require(not child)
        def values(_group):
            nonlocal child
            child = True  # Child has no tasks and does not change controller values.
            return 16, 1, 0
        self.source.leaf = leaf
        self.source.values = values
        self.source.tasks = lambda *_: ((100, 1000),)
        with self.assertRaises(b.Refusal):
            self.source.snapshot(None, None)
        self.assertEqual(scans, [False, True])

    def test_real_tasks_counts_leader_and_thread_and_closes_all_temporary_fds(self):
        for fault in (None, "duplicate", "missing_leader", "membership", "namespace", "start", "status", "namespace_groups"):
            with self.subTest(fault=fault):
                self.source.proc = 9
                group = SimpleNamespace(files=(10, 11, 12, 13), membership=("owned", "leaf"))
                proc = SimpleNamespace(pid=100, namespaces=(70, 71, 72), status=((100,), (1, 1, 1, 1), (100,)))
                members = b"101\n100\n"
                if fault == "duplicate":
                    members = b"100\n101\n101\n"
                elif fault == "missing_leader":
                    members = b"101\n"
                self.source.read_fd = lambda *_: members
                opened, closed, namespace_ids, reads = [], [], {}, {}
                def open_fd(name, parent, **_kwargs):
                    if parent == 9:
                        fd = int(name) + 1000
                    else:
                        fd = 2000 + len(opened)
                        namespace_ids[fd] = 70 + b.NS.index(name[3:])
                        if fault == "namespace" and parent == 1101:
                            namespace_ids[fd] += 100
                    opened.append(fd)
                    return fd
                def read_proc(directory, name, _maximum):
                    tid = directory - 1000
                    key = tid, name
                    reads[key] = reads.get(key, 0) + 1
                    if name == "stat":
                        start = 1000 if tid == 100 else 1001
                        if fault == "start" and tid == 101 and reads[key] == 2:
                            start = 1002
                        return str(tid).encode() + b" (task) S " + b"0 " * 18 + str(start).encode() + b"\n"
                    if name == "cgroup":
                        return b"0::/other\n" if fault == "membership" and tid == 101 else b"0::/owned/leaf\n"
                    if name == "status":
                        uid = b"2" if fault == "status" and tid == 101 and reads[key] == 2 else b"1"
                        groups = b"99" if fault == "namespace_groups" and tid == 101 and reads[key] == 2 else b"100"
                        return b"Pid: " + str(tid).encode() + b"\nTgid: 100\nUid: " + b" ".join([uid] * 4) + b"\nNSpid: " + str(tid).encode() + b"\nNStgid: " + groups + b"\n"
                    self.fail("unexpected proc field")
                self.source.open = open_fd
                self.source.read = read_proc
                self.source.close_fd = closed.append
                with patch.object(b, "fs_magic", return_value=b.PROC_MAGIC), patch.object(
                    b, "identity", side_effect=lambda fd: (1, namespace_ids.get(fd, fd))
                ):
                    if fault is None:
                        self.assertEqual(self.source.tasks(group, proc), ((100, 1000), (101, 1001)))
                        self.assertEqual(self.source.task_coordinates,
                                         ((100, (100,), (100,)), (101, (101,), (100,))))
                    else:
                        with self.assertRaises(b.Refusal):
                            self.source.tasks(group, proc)
                self.assertCountEqual(closed, opened)

    def test_constructor_interrupt_closes_already_acquired_kernel_fd(self):
        actual_open = os.open
        opened = []
        def record_open(name, flags, dir_fd=None):
            fd = actual_open(name, flags, dir_fd=dir_fd)
            opened.append(fd)
            return fd
        with patch.object(b.os, "open", side_effect=record_open), patch.object(b.LinuxSource, "read", side_effect=KeyboardInterrupt("CANARY")):
            with self.assertRaises(KeyboardInterrupt):
                b.LinuxSource(self.budget)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_close_interrupt_continues_to_remaining_fd_without_retry(self):
        self.source.owned = {7, 8}
        self.budget.fds = 2
        attempted = []
        def interrupted_close(fd):
            attempted.append(fd)
            if fd == 7:
                raise KeyboardInterrupt("CANARY")
        with patch.object(b.os, "close", side_effect=interrupted_close), self.assertRaises(b.Refusal):
            self.source.close()
        self.assertCountEqual(attempted, [7, 8])
        self.assertEqual(self.source.owned, set())

    def test_bound_getdents_rejects_child_or_alias_and_unbounded_entries(self):
        def record(name, kind):
            length = 19 + len(name) + 1
            return b"\0" * 16 + length.to_bytes(2, b.sys.byteorder) + bytes([kind]) + name + b"\0"
        group = SimpleNamespace(directories=(9,))
        for body in (record(b"child", 4), record(b"alias", 10), record(b"unknown", 0), record(b"f", 8) * 129):
            def getdents(_fd, storage, _maximum):
                ctypes.memmove(storage, body, len(body))
                return len(body)
            self.source.getdents = getdents
            with patch.object(b.os, "lseek"), self.assertRaises(b.Refusal):
                self.source.leaf(group)

    def test_close_continues_after_failure_without_retrying_fd(self):
        self.source.owned = {7, 8}
        self.budget.fds = 2
        calls = []
        def close(fd):
            calls.append(fd)
            if fd == 7:
                raise OSError("CANARY")
        with patch.object(b.os, "close", side_effect=close):
            with self.assertRaises(b.Refusal):
                self.source.close()
            self.source.close()
        self.assertEqual(sorted(calls), [7, 8])
        self.assertEqual(self.source.owned, set())


class ProtocolAndBudgetTests(unittest.TestCase):
    def test_duplicate_nested_keys_malformed_nonfinite_and_extra_data(self):
        for body in (b'{"op":"Finish","op":"Finish"}\n', b'{"x":{"a":1,"a":2}}\n',
                     b'{"a":NaN}\n', b'{"a":Infinity}\n', b'{}{}\n', b'\xff\n', b'{}', b'{}\n' * 2000):
            with self.subTest(body=body[:60]), self.assertRaises(b.Refusal):
                b.decode(body)

    def test_stat_comm_delimiters_and_status_namespace_pid_checks(self):
        body = b"90 (a ) tricky ( name) S " + b"0 " * 18 + b"123\n"
        self.assertEqual(b.start_from_stat(body, 90), 123)
        with self.assertRaises(b.Refusal):
            b.start_from_stat(body.replace(b") S ", b") Z "), 90)
        status = b"Pid:\t90\nTgid:\t90\nUid:\t1 1 1 1\nNSpid:\t90 2\n"
        self.assertEqual(b.process_status(status, 90, True), ((90,), (1, 1, 1, 1), (90, 2)))
        for bad in (status.replace(b"90 2", b"91 2"), status + b"Pid: 90\n", status.replace(b"Tgid:\t90", b"Tgid:\t89")):
            with self.assertRaises(b.Refusal):
                b.process_status(bad, 90, True)

    def test_paths_are_kernel_coordinate_only_and_cannot_escape(self):
        for value in ("relative", "/../x", "/a/./b", "/a//b", "/a/", "/a\0b"):
            with self.assertRaises(b.Refusal):
                b.components(value)
        for body in (b"1:memory:/a\n", b"0::/a\n0::/b\n", b"0::/../x\n"):
            with self.assertRaises(b.Refusal):
                b.cgroup_path(body)
        self.assertEqual(b.cgroup_path(b"0::/owned/leaf\n"), ("owned", "leaf"))

    def test_limits_fail_before_io_and_failure_charges_are_retained(self):
        budget = b.Budget(180_000_000_001, lambda: 1)
        budget.bytes = 32 * 1024 * 1024
        with self.assertRaises(b.Refusal):
            budget.read(1)
        self.assertEqual(budget.bytes, 32 * 1024 * 1024 + 1)
        budget = b.Budget(180_000_000_001, lambda: 1)
        budget.fds = 256
        with self.assertRaises(b.Refusal):
            budget.fd()
        self.assertEqual(budget.fds, 257)
        budget = b.Budget(180_000_000_001, lambda: 1)
        with self.assertRaises(b.Refusal):
            budget.emit(65537)
        self.assertEqual(budget.output, 65537)
        for deadline in (True, 1, 46_000_000_001, 181_000_000_001):
            with self.assertRaises(b.Refusal):
                b.Budget(deadline, lambda: 1)

    def test_eof_rejects_incomplete_session_and_ordinary_file_is_not_pipe(self):
        reader, writer = os.pipe()
        os.close(writer)
        try:
            budget = b.Budget(180_000_000_001, lambda: 1)
            with self.assertRaises(b.Refusal):
                b.receive(reader, budget)
        finally:
            os.close(reader)
        with tempfile.TemporaryFile() as file:
            with self.assertRaises(b.Refusal):
                b.pipe_fd(file.fileno(), False)

    def test_output_partial_write_and_no_sensitive_diagnostics(self):
        budget = b.Budget(180_000_000_001, lambda: 1)
        written = bytearray()
        def short_write(_fd, body):
            written.extend(body[:2])
            return min(2, len(body))
        with patch.object(b, "await_fd"), patch.object(b.os, "write", side_effect=short_write):
            b.send(9, {"op": "Finish", "status": "ok"}, budget)
        self.assertEqual(json.loads(written), {"op": "Finish", "status": "ok"})
        captured = []
        with patch.object(b.os, "write", side_effect=lambda fd, body: captured.append((fd, body)) or len(body)):
            self.assertEqual(b.main(["CANARY-private-path", "7", "123"]), 1)
        self.assertEqual(captured, [(2, b"native-pids-boundary: refused\n")])

    def test_private_inherited_pipes_finish_eof_and_trailing_frame(self):
        for tail, expected in ((b"", 0), (b'{}\n', 1)):
            source = FakeSource()
            reader, parent_writer = os.pipe()
            parent_reader, writer = os.pipe()
            request = {"op": "BindOuter", "pid": 100, "start": 111, "context": {
                "backend": "docker", "candidate": "candidate", "run": "run", "lane": "lane", "outer_id": "owned",
            }}
            os.write(parent_writer, json.dumps(request).encode() + b'\n{"op":"Finish"}\n' + tail)
            os.close(parent_writer)
            actual_write = os.write
            diagnostics = []
            def capture(fd, body):
                if fd == 2:
                    diagnostics.append(body)
                    return len(body)
                return actual_write(fd, body)
            try:
                with patch.object(b, "LinuxSource", return_value=source), patch.object(b.os, "write", side_effect=capture):
                    self.assertEqual(b.main([str(reader), str(writer), str(b.time.monotonic_ns() + 180_000_000_000)]), expected)
                frames = os.read(parent_reader, 8192).splitlines()
                self.assertEqual(len(frames), 2 if expected == 0 else 1)
                self.assertEqual(diagnostics, [] if expected == 0 else [b"native-pids-boundary: refused\n"])
            finally:
                os.close(parent_reader)

    def test_sigint_constructor_sample_and_cleanup_fail_value_free_and_close_pipes(self):
        for stage in ("constructor", "sample", "cleanup"):
            with self.subTest(stage=stage):
                source = FakeSource()
                reader, parent_writer = os.pipe()
                parent_reader, writer = os.pipe()
                requests = [
                    {"op": "BindOuter", "pid": 100, "start": 111, "context": {
                        "backend": "docker", "candidate": "CANARY", "run": "run", "lane": "lane", "outer_id": "owned",
                    }},
                    {"op": "BindLeaf", "slot": "cli16", "pid": 200, "start": 1000},
                    {"op": "Sample", "slot": "cli16", "phase": "before"},
                    {"op": "Finish"},
                ]
                os.write(parent_writer, b"".join(json.dumps(request).encode() + b"\n" for request in requests))
                os.close(parent_writer)
                original_snapshot = source.snapshot
                snapshots = 0
                def snapshot(proc, group):
                    nonlocal snapshots
                    snapshots += 1
                    if stage == "sample" and snapshots == 2:
                        os.kill(os.getpid(), b.signal.SIGINT)
                    return original_snapshot(proc, group)
                source.snapshot = snapshot
                def constructor(_budget):
                    if stage == "constructor":
                        os.kill(os.getpid(), b.signal.SIGINT)
                    return source
                if stage == "cleanup":
                    source.close = lambda: (_ for _ in ()).throw(KeyboardInterrupt("CANARY"))
                actual_write = os.write
                diagnostics = []
                def capture(fd, body):
                    if fd == 2:
                        diagnostics.append(body)
                        return len(body)
                    return actual_write(fd, body)
                previous_handler = b.signal.getsignal(b.signal.SIGINT)
                try:
                    with patch.object(b, "LinuxSource", side_effect=constructor), patch.object(b.os, "write", side_effect=capture):
                        self.assertEqual(b.main([str(reader), str(writer), str(b.time.monotonic_ns() + 180_000_000_000)]), 1)
                    self.assertEqual(diagnostics, [b"native-pids-boundary: refused\n"])
                    self.assertEqual(b.signal.getsignal(b.signal.SIGINT), previous_handler)
                    for fd in (reader, writer):
                        with self.assertRaises(OSError):
                            os.fstat(fd)
                finally:
                    os.close(parent_reader)



class HostGroupObservationTests(unittest.TestCase):
    ERRNOS = ((errno.ENOENT, "ENOENT"), (errno.EACCES, "EACCES"), (errno.EPERM, "EPERM"),
        (errno.EMFILE, "EMFILE"), (errno.ENFILE, "ENFILE"), (errno.ENOMEM, "ENOMEM"),
        (errno.ENOSPC, "ENOSPC"), (errno.EIO, "EIO"), (errno.EINVAL, "EINVAL"),
        (errno.ESPIPE, "ESPIPE"), (errno.EINTR, "EINTR"))

    def test_exact_builtin_errno_contract_and_factory_selected_subclasses(self):
        classes = (OSError, BlockingIOError, ChildProcessError, ConnectionError, BrokenPipeError,
            ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, FileExistsError,
            FileNotFoundError, InterruptedError, IsADirectoryError, NotADirectoryError, PermissionError,
            ProcessLookupError, TimeoutError)
        self.assertEqual(b._HOST_OSERROR_TYPES, classes)
        class IntSubclass(int):
            pass
        for cls in classes:
            for number, expected in (*self.ERRNOS, (987654, "other_os"), (None, "unclassified"),
                    (True, "unclassified"), (13.0, "unclassified"), ("13", "unclassified"),
                    (IntSubclass(13), "unclassified")):
                error = cls()
                OSError.errno.__set__(error, number)
                self.assertIs(type(error), cls)
                self.assertEqual(b._group_exception_tag(error), expected)
        for number, expected in self.ERRNOS:
            error = OSError(number, "PRIVATE_HOST_CANARY", "/private/path")
            self.assertTrue(any(type(error) is cls for cls in classes))
            self.assertEqual(b._group_exception_tag(error), expected)

    def test_custom_types_and_spoofed_class_have_no_exception_attribute_reads(self):
        reads = []
        class Hostile(OSError):
            def __getattribute__(self, name):
                reads.append(name)
                raise AssertionError("PRIVATE_ATTRIBUTE_CANARY")
        class Spoof(Exception):
            @property
            def __class__(self):
                reads.append("__class__")
                return OSError
            @property
            def errno(self):
                reads.append("errno")
                raise AssertionError("PRIVATE_ATTRIBUTE_CANARY")
        for error in (Hostile(), Spoof(), b.Refusal(), KeyboardInterrupt(), GeneratorExit(), StopIteration()):
            self.assertEqual(b._group_exception_tag(error), "unclassified")
        self.assertEqual(reads, [])
        error = Hostile()
        records = []
        try:
            with b._group_escape(lambda *pair: records.append(pair), "gh_read"):
                raise error
        except BaseException as caught:
            self.assertIs(caught, error)
        self.assertEqual(records, [("gh_read", "unclassified")])
        self.assertEqual(reads, [])

    def test_scope_is_silent_on_default_success_and_handled_error(self):
        failure = PermissionError(13, "PRIVATE_HOST_CANARY")
        with patch.object(b, "_group_exception_tag", side_effect=AssertionError("must not classify")) as classify:
            with self.assertRaises(PermissionError) as caught:
                with b._group_escape(None, "gh_read"):
                    raise failure
            self.assertIs(caught.exception, failure)
            records = []
            with b._group_escape(lambda *pair: records.append(pair), "gh_read"):
                try:
                    raise FileNotFoundError(2, "expected optional file")
                except FileNotFoundError:
                    pass
            classify.assert_not_called()
            self.assertEqual(records, [])

    def test_classifier_and_callback_failure_preserve_identity_without_retry(self):
        for callback_mode in ("record", "raises", "one_arg"):
            failure = PermissionError(13, "PRIVATE_HOST_CANARY")
            attempts = []
            def observer(*pair):
                attempts.append(pair)
                if callback_mode == "raises":
                    raise KeyboardInterrupt("observer failure")
                if callback_mode == "one_arg":
                    [].append(*pair)
            with patch.object(b, "_group_exception_tag", side_effect=KeyboardInterrupt("classifier failure")) as classify:
                with self.assertRaises(PermissionError) as caught:
                    with b._group_escape(observer, "gh_read"):
                        raise failure
            self.assertIs(caught.exception, failure)
            classify.assert_called_once_with(failure)
            self.assertEqual(attempts, [("gh_read", "unclassified")])

    def test_new_host_helper_preserves_fatal_generator_identity_with_and_without_observer(self):
        for error_type in (KeyboardInterrupt, SystemExit, GeneratorExit, StopIteration):
            for observed in (False, True):
                failure = error_type("PRIVATE_HOST_CANARY")
                records = []
                classify_original = b._group_exception_tag
                with patch.object(b, "_group_exception_tag", wraps=classify_original) as classify:
                    with self.assertRaises(error_type) as caught:
                        with b._group_escape((lambda *pair: records.append(pair)) if observed else None, "gh_verify"):
                            raise failure
                self.assertIs(caught.exception, failure)
                self.assertEqual(records, [("gh_verify", "unclassified")] if observed else [])
                if observed:
                    classify.assert_called_once_with(failure)
                else:
                    classify.assert_not_called()

    def test_opaque_cleanup_tag_is_only_the_escaping_exception(self):
        work, cleanup = PermissionError(13, "work"), FileNotFoundError(2, "cleanup")
        records = []
        with self.assertRaises(FileNotFoundError) as caught:
            with b._group_escape(lambda *pair: records.append(pair), "gh_verify"):
                try:
                    raise work
                finally:
                    raise cleanup
        self.assertIs(caught.exception, cleanup)
        self.assertEqual(records, [("gh_verify", "ENOENT")])

    def test_every_verifier_scope_preserves_hostile_errors_and_observer_failures(self):
        reads = []
        class Hostile(OSError):
            def __getattribute__(self, name):
                reads.append(name)
                raise AssertionError("PRIVATE_ATTRIBUTE")
        for site in ("gv_make", "gv_call", "gv_time", "gv_record", "gv_bind", "gv_ids", "gv_dirs", "gv_files", "gv_type", "gv_cache"):
            for classifier_fails in (False, True):
                for callback_fails in (False, True):
                    failure, records = Hostile(), []
                    def observer(*pair):
                        records.append(pair)
                        if callback_fails:
                            raise KeyboardInterrupt("PRIVATE_CALLBACK")
                    classifier = {"side_effect": KeyboardInterrupt("PRIVATE_CLASSIFIER")} if classifier_fails else {"wraps": b._group_exception_tag}
                    with patch.object(b, "_group_exception_tag", **classifier) as classify:
                        try:
                            with b._group_escape(observer, site):
                                raise failure
                        except Hostile as caught:
                            self.assertIs(caught, failure)
                        else:
                            self.fail("source error must escape")
                    self.assertEqual(records, [(site, "unclassified")])
                    self.assertEqual(classify.call_count, 1)
        self.assertEqual(reads, [])

    def test_group_partition_matches_independent_frozen_source_on_this_interpreter(self):
        raw = (Path(__file__).parent / "fixtures/native_pids_host_group_baseline_methods.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            "e996736bb4c01bf63e79460003c1ed7267313faef86be71ac1bca0ba9e25d980")
        fixture = json.loads(raw)
        self.assertEqual(fixture["source_commit"], "5b73e3c4dd93de9cb80ca4c0857e19d332a53b68")
        original = fixture["methods"]["LinuxSource.group"]
        self.assertEqual((original["source_path"], original["class_name"], original["method_name"]),
            ("scripts/native_pids_boundary.py", "LinuxSource", "group"))
        self.assertEqual(hashlib.sha256(original["method_source"].encode()).hexdigest(), original["method_source_utf8_sha256"])
        tree = ast.parse(Path(b.__file__).read_text())
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "LinuxSource")
        method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "group")
        self.assertEqual([arg.arg for arg in method.args.args], ["self", "proc", "observer"])
        self.assertEqual(ast.dump(method.args.defaults[0]), "Constant(value=None)")
        blocks = method.body[:-1]
        self.assertEqual([n.items[0].context_expr.args[1].value for n in blocks],
            ["gh_read", "gh_mount", "gh_walk", "gh_leaf", "gh_verify"])
        self.assertEqual([len(n.body) for n in blocks], [1, 4, 8, 2, 2])
        for node in blocks:
            call = node.items[0].context_expr
            self.assertEqual(ast.dump(call.func), "Name(id='_group_escape', ctx=Load())")
            self.assertEqual(ast.dump(call.args[0]), "Name(id='observer', ctx=Load())")
        self.assertIsInstance(method.body[-1], ast.Return)
        verify = blocks[-1]
        self.assertEqual([n.items[0].context_expr.args[1].value for n in verify.body], ["gv_make", "gv_call"])
        make, dispatch = verify.body
        self.assertEqual([len(make.body), len(dispatch.body)], [1, 1])
        branch = dispatch.body[0]
        self.assertEqual(ast.dump(branch.test),
            "Compare(left=Name(id='observer', ctx=Load()), ops=[Is()], comparators=[Constant(value=None)])")
        self.assertEqual((len(branch.body), len(branch.orelse)), (1, 1))
        observed = branch.orelse[0]
        self.assertEqual(len(observed.value.keywords), 1)
        keyword = observed.value.keywords[0]
        self.assertEqual((keyword.arg, ast.dump(keyword.value)), ("observer", "Name(id='observer', ctx=Load())"))
        observed.value.keywords.clear()
        self.assertEqual(ast.dump(branch.body[0]), ast.dump(observed))
        verify.body = make.body + branch.body
        method.body = [child for n in blocks for child in n.body] + [method.body[-1]]
        method.args.args.pop(); method.args.defaults.clear()
        expected = ast.parse("class Original:\n" + original["method_source"]).body[0].body[0]
        self.assertEqual(ast.dump(method, include_attributes=False), ast.dump(expected, include_attributes=False))

if __name__ == "__main__":
    unittest.main()
