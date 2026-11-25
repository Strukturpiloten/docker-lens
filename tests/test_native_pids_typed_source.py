"""Literal source/type lifetime controls; synthetic files are not native evidence."""

from contextlib import contextmanager
import os
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_native_pids_locator as fixtures

b, l = fixtures.b, fixtures.l
t = b.topology
D, R, T = t.CgroupType.DOMAIN, t.CgroupType.THREAD_ROOT, t.CgroupType.THREADED


@contextmanager
def kernel_tree():
    with tempfile.TemporaryDirectory(prefix="dl-typed-source-") as directory:
        tree = fixtures.KernelTree(directory)
        try:
            with patch.object(b, "fs_magic", side_effect=tree.magic), patch.object(
                    l.fcntl, "ioctl", side_effect=tree.parent), patch.object(
                    os, "pidfd_open", side_effect=lambda *_: os.dup(tree.pipe[0])):
                yield tree
        finally:
            tree.close()


class TypedSourceTests(unittest.TestCase):
    def type_check(self, raw, *, observed=False, false_magic=False, close_error=None):
        """Exercise the real base verifier; only its type syscall result is injected."""
        with kernel_tree() as tree:
            source = tree.source
            process = source.process(200, 2000)
            group = source.group(process)
            trace, records, read_values, parsed_values, diagnosed_values = [], [], [], [], []
            type_fds = set()
            original_open, original_read, original_close = source.open, source.read_fd, source.close_fd
            original_magic, original_parse, original_observe = b.fs_magic, t.parse_type, b._observe
            initial = None
            charged = None

            def opened(name, *args, **kwargs):
                nonlocal initial
                if name == "cgroup.type":
                    initial = (source.budget.reads, source.budget.bytes, source.budget.opens, source.budget.fds)
                fd = original_open(name, *args, **kwargs)
                if name == "cgroup.type":
                    type_fds.add(fd)
                    trace.append("open")
                return fd

            def magic(fd, **kwargs):
                if fd in type_fds:
                    trace.append("magic")
                    return 0 if false_magic else b.CGROUP_MAGIC
                return original_magic(fd, **kwargs)

            def read(fd, maximum, **kwargs):
                nonlocal charged
                if fd in type_fds:
                    trace.append("read")
                    self.assertEqual(maximum, 32)
                    # Retain actual read precharges and actual kernel-file I/O.
                    original_read(fd, maximum, **kwargs)
                    charged = (source.budget.reads, source.budget.bytes, source.budget.opens, source.budget.fds)
                    read_values.append(raw)
                    return raw
                return original_read(fd, maximum, **kwargs)

            def parse(value):
                trace.append("parse")
                parsed_values.append(value)
                return original_parse(value)

            def observe(value, observer, kind):
                if kind == "domain":
                    diagnosed_values.append(value)
                return original_observe(value, observer, kind)

            def close(fd):
                original_close(fd)
                if fd in type_fds:
                    trace.append("close")
                    if close_error is not None:
                        raise close_error

            with patch.object(source, "open", side_effect=opened), patch.object(source, "read_fd", side_effect=read), \
                    patch.object(source, "close_fd", side_effect=close), patch.object(b, "fs_magic", side_effect=magic), \
                    patch.object(t, "parse_type", side_effect=parse), patch.object(b, "_observe", side_effect=observe):
                try:
                    result = b.LinuxSource.check_group(source, group,
                        observer=(lambda *record: records.append(record)) if observed else None)
                except BaseException as error:
                    result = error
            return result, trace, records, read_values, parsed_values, diagnosed_values, initial, charged

    def test_literal_types_reuse_one_actual_read_return_and_same_diagnostic_object(self):
        for raw, expected in ((b"domain\n", D), (b"domain threaded\n", R), (b"threaded\n", T)):
            for observed in (False, True):
                with self.subTest(raw=raw, observed=observed):
                    result, trace, records, read, parsed, diagnosed, initial, charged = self.type_check(raw, observed=observed)
                    self.assertIs(result, expected)
                    self.assertEqual(trace, ["open", "magic", "read", "parse", "close"])
                    self.assertEqual(records, [])
                    self.assertEqual(len(read), 1)
                    self.assertIs(parsed[0], read[0])
                    self.assertEqual(len(diagnosed), int(observed))
                    if observed:
                        self.assertIs(diagnosed[0], read[0])
                    # The authored domain file consumes 7 bytes: 33 reserved for
                    # the first syscall, then 26 for EOF. Parsing adds no I/O.
                    self.assertEqual(tuple(after - before for before, after in zip(initial, charged)), (2, 59, 1, 1))

    def test_malformed_types_and_false_magic_preserve_short_circuit_and_cleanup(self):
        for raw in (b"domain invalid\n", b"", b"domain", b"domain\r\n", b"domain\n\n", b"threaded \n", None, "domain\n"):
            with self.subTest(raw=raw):
                result, trace, records, *_ = self.type_check(raw, observed=True)
                self.assertIsInstance(result, t.TopologyRefusal)
                self.assertEqual(trace, ["open", "magic", "read", "parse", "close"])
                self.assertEqual(records[0][:2], ("gv_type", "unclassified"))
        result, trace, records, *_ = self.type_check(b"domain\n", observed=True, false_magic=True)
        self.assertIsInstance(result, b.Refusal)
        self.assertEqual(trace, ["open", "magic", "close"])
        self.assertEqual(records, [("gv_type", "unclassified", "m_guard")])

    def test_close_failure_overrides_success_type_and_parse_failure(self):
        failure = PermissionError(13, "private close canary")
        for raw in (b"domain\n", b"domain threaded\n", b"threaded\n", b"domain invalid\n"):
            with self.subTest(raw=raw):
                result, trace, records, *_ = self.type_check(raw, observed=True, close_error=failure)
                self.assertIs(result, failure)
                self.assertEqual(trace.count("close"), 1)
                self.assertEqual(records, [("gv_type", "EACCES")])

    def test_childless_domain_thread_root_and_threaded_workers_have_real_task_samples(self):
        for leaf, outer in ((D, D), (R, D), (T, R)):
            with self.subTest(leaf=leaf), kernel_tree() as tree:
                source = tree.source
                (tree.cg / "owned/cgroup.type").write_text(outer.value + "\n")
                (tree.cg / "owned/cli16/cgroup.type").write_text(leaf.value + "\n")
                outer_process = source.process(100, 1000)
                source.outer_boundary = source.group(outer_process)
                process = source.process(200, 2000)
                group = source.group(process)
                sample = source.snapshot(process, group)
                self.assertEqual(sample["cgroup_type"], leaf.value)
                self.assertEqual(sample["tasks"], [[200, 2000]])
                self.assertEqual(sample["current"], 1)
                self.assertEqual(sample["attribution"]["controllers"][0]["cgroup_type"], leaf.value)
                self.assertEqual(sample["attribution"]["candidate_membership"], "typed_procs_local_membership_v1")
                (tree.cg / "owned/cli16/child").mkdir()
                with self.assertRaises(b.Refusal):
                    source.snapshot(process, group)

    def test_second_base_bracket_rejects_domain_to_thread_root_drift(self):
        with kernel_tree() as tree:
            source = tree.source
            process = source.process(200, 2000)
            group = source.group(process)
            original = source.check_group
            checks = 0
            def check(candidate):
                nonlocal checks
                checks += 1
                if checks == 2:
                    (tree.cg / "owned/cli16/cgroup.type").write_bytes(b"domain threaded\n")
                return original(candidate)
            with patch.object(source, "check_group", side_effect=check), self.assertRaises(b.Refusal):
                b.LinuxSource.snapshot(source, process, group)
            self.assertEqual(checks, 2)

    def typed_chain(self, kinds, *, genuine_root=True):
        source = l.LocatorSource.__new__(l.LocatorSource)
        source.reader_cgroup_namespace = source.authenticated_parent_cgroup_namespace = 42
        root = {"identity": (1, 1, 10), "pids_max_present": False, "cgroup_type_present": False,
                "cgroup_events_present": False, "available_pids": True, "mount_root_is_slash": genuine_root}
        # Literal root-to-leaf kinds, represented in the required leaf-to-root order.
        nodes = tuple((100 + index, (1, 100 + index, 10), ()) for index in reversed(range(len(kinds))))
        group = SimpleNamespace(identities=((1, 1), nodes[0][1][:2]))
        source.controller_groups = {group.identities[-1]: (root, nodes)}
        by_fd = {100 + index: kind for index, kind in enumerate(kinds)}
        source.read_type = lambda directory: by_fd[directory]
        return source, group

    def test_literal_nonroot_edges_and_authenticated_root_exception(self):
        for kinds, accepted in (((D, D), True), ((D, R), True), ((D, T), False),
                ((R, D), False), ((R, R), False), ((R, T), True),
                ((R, T, D), False), ((R, T, R), False), ((R, T, T), True), ((T,), True)):
            with self.subTest(kinds=kinds):
                source, group = self.typed_chain(kinds)
                with patch.object(b, "identity", return_value=(9, 9)):
                    if accepted:
                        source._typed_chain(group, kinds[-1])
                    else:
                        with self.assertRaises(b.Refusal):
                            source._typed_chain(group, kinds[-1])
        source, group = self.typed_chain((T,), genuine_root=False)
        with patch.object(b, "identity", return_value=(9, 9)), self.assertRaises(b.Refusal):
            source._typed_chain(group, T)

    def test_locate_cannot_seed_uncovered_ancestors_from_bootstrap_types(self):
        source, group = self.typed_chain((D, D))
        with patch.object(b, "identity", return_value=(9, 9)):
            source._typed_chain(group, D)
            source.type_scope().begin_locate()
            with patch.object(source, "read_type", return_value=R) as read:
                # Fresh R parent makes retained D leaf invalid; old setup D must not pass.
                with self.assertRaises(b.Refusal):
                    source._typed_chain(group, D)
                read.assert_called_once_with(100)

    def test_all_six_chains_freeze_shared_identity_once_and_refuse_drift_and_postseal_samples(self):
        source, first = self.typed_chain((D, D))
        root, first_nodes = source.controller_groups[first.identities[-1]]
        parent = first_nodes[1]
        groups = [first]
        for index in range(1, 6):
            node = (200 + index, (1, 200 + index, 10), ())
            group = SimpleNamespace(identities=((1, 1), node[1][:2]))
            source.controller_groups[group.identities[-1]] = root, (node, parent)
            groups.append(group)
        source._leaf_types = {group.identities[-1]: D for group in groups}
        source.type_scope().begin_locate()
        with patch.object(b, "identity", return_value=(9, 9)), patch.object(source, "read_type", return_value=D) as reads:
            source.freeze_measurement_types(groups)
        reads.assert_called_once_with(100)
        scope = source.type_scope()
        self.assertEqual(len(scope.frozen), 7)
        for identity, (kind, parent_identity) in scope.frozen.items():
            scope.observe(identity, kind, parent_identity)
            with self.assertRaises(t.TopologyRefusal):
                scope.observe(identity, R, parent_identity)
            with self.assertRaises(t.TopologyRefusal):
                scope.observe(identity, kind, (99, 99, 10))
        scope.seal()
        source.budget = SimpleNamespace(cleanup_only=False)
        with self.assertRaises(b.Refusal):
            source.snapshot(None, groups[0])
        self.assertEqual(scope.phase, "sealed")

    def test_transfer_handoff_retires_without_closing_and_abort_cleans_only_owned_scope(self):
        discovery = l._discovery_module()
        source = SimpleNamespace(owned={1, 2, 3, 4})
        released = []
        def release(previous):
            released.append(source.owned - set(previous))
            source.owned.intersection_update(previous)
        source.release_since = release
        transfer = discovery.DiscoveryTransfer(source, (), (), {2}, {3}, ())
        transfer.release_witnesses()
        transfer.handoff()
        self.assertEqual(released, [{3}])
        transfer.abort()
        self.assertEqual(source.owned, {1, 2, 4})
        with self.assertRaises(b.Refusal):
            transfer.handoff()
        transfer = discovery.DiscoveryTransfer(source, (), (), {2}, set(), ())
        transfer.abort()
        self.assertEqual(released, [{3}, {2}])
        self.assertEqual(source.owned, {1, 4})


if __name__ == "__main__":
    unittest.main()
