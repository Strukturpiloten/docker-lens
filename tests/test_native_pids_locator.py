"""Independent source controls. Synthetic kernel trees are not native evidence."""

import ctypes
import ast
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import native_pids_locator as l

b = l.boundary


class KernelTree:
    """Real bounded file/descriptor I/O over an independently authored kernel tree.

    Only filesystem type, mount-ID, pidfd and namespace ioctl are simulated.
    Every proc/cgroup read, directory buffer, open and close uses the OS source.
    """

    def __init__(self, root, *, nested=True):
        self.root = Path(root)
        self.proc = self.root / "proc"
        self.cg = self.root / "cgroup"
        self.ns = self.root / "namespaces"
        self.rootfs = self.root / "rootfs"
        self.nested = nested
        for directory in (self.proc / "self", self.cg, self.ns, self.rootfs / "usr/bin"):
            directory.mkdir(parents=True)
        (self.proc / "sys/kernel").mkdir(parents=True)
        (self.proc / "sys/kernel/threads-max").write_text("65536\n")
        (self.proc / "sys/kernel/pid_max").write_text("4194304\n")
        (self.proc / "loadavg").write_text("0.00 0.00 0.00 1/1000 200\n")
        (self.rootfs / "usr/bin/dockerd").write_bytes(b"independently expected executable")
        for name in ("reader", "daemon", "sibling", "mnt", "cgroup", "user", "time", *l.ORDER):
            (self.ns / name).touch()
        self.parents = {str(self.ns / "daemon"): "reader", str(self.ns / "sibling"): "reader"}
        self.ids = {slot: format(index + 1, "064x") for index, slot in enumerate(l.ORDER)}
        self.groups = {}
        self.make_group(self.cg, 512, [])
        # Independently authored actual-root exemption: these kernel interfaces
        # are NOT_ON_ROOT; a mounted non-root prefix keeps them and is incomplete.
        for name in ("pids.max", "cgroup.type", "cgroup.events"):
            (self.cg / name).unlink()
        self.make_group(self.cg / "owned", 512, [100, 110])
        self.make_process(100, "reader", (100,), "owned", 0)
        self.make_process(110, "daemon" if nested else "reader", (110, 2) if nested else (110,), "owned", 1000)
        self.inspects = {}
        for index, slot in enumerate(l.ORDER):
            pid = 200 + index
            group = "owned/" + slot
            self.make_group(self.cg / group, "max" if slot.endswith("unlimited") else (16 if slot.endswith("16") else 64), [pid])
            self.make_process(pid, slot, (pid, 70 + index, 1) if nested else (pid, 1), group, 1000)
            self.parents[str(self.ns / slot)] = "daemon" if nested else "reader"
            self.inspects[self.ids[slot]] = (70 + index if nested else pid, "2026-10-25T12:00:00Z", 0, (("owner", "run1"),))
        device = os.stat(self.cg).st_dev
        (self.proc / "self/mountinfo").write_text(
            f"10 0 {os.major(device)}:{os.minor(device)} / {self.cg} rw - cgroup2 cgroup rw\n")
        (self.proc / "self/mount-id").write_text("10\n")
        self.pipe = os.pipe()
        self.source = l.LocatorSource.__new__(l.LocatorSource)
        self.source.budget = l.RuntimeBudget(180_000_000_001, lambda: 1)
        self.source.owned = set()
        libc = ctypes.CDLL(None, use_errno=True)
        self.source.getdents = libc.getdents64
        self.source.getdents.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t)
        self.source.getdents.restype = ctypes.c_ssize_t
        self.source.proc = self.source.open(str(self.proc), directory=True)
        self.source.reader_namespace = self.source.open(str(self.ns / "reader"))
        self.source.reader_user_namespace = self.source.open(str(self.ns / "user"))
        (self.proc / "self/ns").mkdir()
        (self.proc / "self/ns/cgroup").symlink_to(self.ns / "cgroup")
        self.source.reader_cgroup_namespace = self.source.open(str(self.ns / "cgroup"))
        self.source.reader_time_namespace = self.source.open(str(self.ns / "time"))
        self.source.authenticated_parent_cgroup_namespace = self.source.reader_cgroup_namespace
        self.source.fd_mount_id = lambda _fd: int(self.source.read(self.source.proc, "self/mount-id", 4096))

    def make_group(self, directory, maximum, pids):
        directory.mkdir(exist_ok=True)
        for name, value in {"pids.max": str(maximum) + "\n", "pids.current": str(len(pids)) + "\n",
                            "pids.events": "max 0\n", "pids.events.local": "max 0\n",
                            "cgroup.threads": "".join(str(x) + "\n" for x in pids),
                            "cgroup.procs": "".join(str(x) + "\n" for x in pids), "cgroup.type": "domain\n",
                            "cgroup.controllers": "pids\n", "cgroup.events": "populated 1\nfrozen 0\n"}.items():
            (directory / name).write_text(value)

    def make_process(self, pid, namespace, vector, membership, uid):
        directory = self.proc / str(pid)
        directory.mkdir()
        (directory / "ns").mkdir()
        (directory / "stat").write_bytes(str(pid).encode() + b" (worker) S " + b"0 " * 18 + str(pid * 10).encode() + b" " + b"0 " * 18 + b"0\n")
        (directory / "limits").write_text("Max processes             unlimited            unlimited            processes\n")
        (directory / "status").write_text(
            f"Pid: {pid}\nTgid: {pid}\nUid: {uid} {uid} {uid} {uid}\nNSpid: {' '.join(map(str, vector))}\nNStgid: {' '.join(map(str, vector))}\n")
        (directory / "cgroup").write_text("0::/" + membership + "\n")
        (directory / "root").symlink_to(self.rootfs)
        (directory / "exe").symlink_to(self.rootfs / "usr/bin/dockerd")
        for name, target in (("pid", namespace), ("mnt", "mnt"), ("cgroup", "cgroup"), ("user", "user"), ("time", "time")):
            (directory / "ns" / name).symlink_to(self.ns / target)

    def magic(self, fd):
        path = os.readlink("/proc/self/fd/" + str(fd))
        return b.CGROUP_MAGIC if path.startswith(str(self.cg)) else b.PROC_MAGIC

    def parent(self, fd, operation):
        assert operation == 0xB702
        name = os.readlink("/proc/self/fd/" + str(fd))
        target = self.parents[name]
        return os.open(self.ns / target, os.O_RDONLY | os.O_CLOEXEC)

    def close(self):
        self.source.close()
        for fd in self.pipe:
            os.close(fd)


class LocatorTests(unittest.TestCase):
    def configured_fixture(self, fault=None, *, handled=False, cleanup=False):
        """Independent operation trace; no daemon, namespace, or runtime probe."""
        source = l.LocatorSource.__new__(l.LocatorSource)
        process = SimpleNamespace(namespaces=(3, 4, 2))
        source.reader_cgroup_namespace = 1
        current = SimpleNamespace(identities=((0, 11), (0, 12)), directories=(11, 12))
        trace = []
        failure = RuntimeError("PRIVATE_OUTER_CANARY")

        def operation(name, result=None):
            def run(*_args, **_kwargs):
                trace.append(name)
                if handled and name == "host":
                    try:
                        raise OSError("handled source operation")
                    except OSError:
                        pass
                if fault == name:
                    raise failure
                return result
            return run

        source.check_process = operation("pre")
        source.group = operation("host", current)
        source.guest_cgroup_mount = operation("guest", (12, "mount record"))
        if cleanup:
            def guest_cleanup(*_args):
                try:
                    return 12, "mount record"
                finally:
                    raise failure
            source.guest_cgroup_mount = guest_cleanup
        source.values = operation("max", (512,))
        source.check_group = operation("recheck")

        def configured_check(observed_process, selected):
            trace.append("binding")
            self.assertEqual(source.configured_outer_binding,
                (process, current, 12, (0, 12), "mount record"))
            self.assertIs(observed_process, process)
            self.assertIs(selected, current)
            source.check_process = operation("final")
        source.check_configured_outer = configured_check

        def identity(fd):
            if fd == 12:
                trace.append("selection" if "max" not in trace else "binding_identity")
                if fault == "select":
                    raise failure
            return 0, fd
        return source, process, current, trace, failure, identity

    def test_configured_outer_observer_reports_only_six_propagating_blocks(self):
        for operation, site in (("pre", "oc_pre"), ("host", "oc_host"), ("guest", "oc_guest"),
                                ("select", "oc_select"), ("max", "oc_max"), ("recheck", "oc_recheck")):
            for observed in (False, True):
                with self.subTest(operation=operation, observed=observed):
                    source, process, _current, _trace, failure, identity = self.configured_fixture(operation)
                    records = []
                    with patch.object(b, "identity", side_effect=identity):
                        with self.assertRaises(RuntimeError) as caught:
                            source.configured_outer_group(process, records.append if observed else None)
                    self.assertIs(caught.exception, failure)
                    self.assertEqual(records, [site] if observed else [])

    def test_configured_outer_success_and_handled_error_have_no_observation(self):
        expected = ["pre", "host", "guest", "selection", "selection", "max", "recheck", "binding_identity", "binding", "final"]
        for handled in (False, True):
            for observed in (False, True):
                with self.subTest(handled=handled, observed=observed):
                    source, process, current, trace, _failure, identity = self.configured_fixture(handled=handled)
                    records = []
                    with patch.object(b, "identity", side_effect=identity):
                        if observed:
                            selected = source.configured_outer_group(process, records.append)
                        else:
                            selected = source.configured_outer_group(process)
                    self.assertIs(selected, current)
                    self.assertEqual(trace, expected)
                    self.assertEqual(records, [])

    def test_configured_outer_observer_failure_and_opaque_cleanup_preserve_exception(self):
        for cleanup in (False, True):
            source, process, _current, _trace, failure, identity = self.configured_fixture(
                "max" if not cleanup else None, cleanup=cleanup)
            records = []
            def broken_observer(site):
                records.append(site)
                raise KeyboardInterrupt("private observer failure")
            with patch.object(b, "identity", side_effect=identity):
                with self.assertRaises(RuntimeError) as caught:
                    source.configured_outer_group(process, broken_observer)
            self.assertIs(caught.exception, failure)
            self.assertEqual(records, ["oc_guest" if cleanup else "oc_max"])

    def test_outer_observer_preserves_fatal_and_generator_exception_identity(self):
        for failure in (b.Refusal(), PermissionError(13, "private"), KeyboardInterrupt("private"),
                        GeneratorExit("private"), StopIteration("private")):
            records = []
            with self.assertRaises(type(failure)) as caught:
                with l._outer_escape(records.append, "oc_host"):
                    raise failure
            self.assertIs(caught.exception, failure)
            self.assertEqual(records, ["oc_host"])

    def test_configured_outer_operation_ast_preserves_original_statements(self):
        tree = ast.parse(Path(l.__file__).read_text())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocatorSource")
        method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "configured_outer_group")
        self.assertEqual([arg.arg for arg in method.args.args], ["self", "process", "observer"])
        self.assertEqual(ast.dump(method.args.defaults[0]), "Constant(value=None)")
        sites = []
        block_lengths = []
        body = []
        for node in method.body:
            if isinstance(node, ast.With):
                call = node.items[0].context_expr
                self.assertEqual(ast.dump(call.func), "Name(id='_outer_escape', ctx=Load())")
                self.assertEqual(ast.dump(call.args[0]), "Name(id='observer', ctx=Load())")
                sites.append(call.args[1].value)
                block_lengths.append(len(node.body))
                if call.args[1].value == "oc_host":
                    body.append(self.collapse_host_delegation(node.body[0]))
                else:
                    body.extend(node.body)
            else:
                body.append(node)
        self.assertEqual(sites, ["oc_pre", "oc_host", "oc_guest", "oc_select", "oc_max", "oc_recheck"])
        self.assertEqual(block_lengths, [3, 1, 1, 4, 1, 4])
        method.body = body
        method.args.args.pop()
        method.args.defaults.clear()
        # Pin original source bytes, then parse both methods on this interpreter:
        # ast.dump's treatment of empty fields differs across Python versions.
        raw = (Path(__file__).parent / "fixtures/native_pids_pre_observer_methods.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            "b9b67119b1ce97aca44d7121e4f747dadcf41aa33f7d502743536838d997f46c")
        fixture = json.loads(raw)
        self.assertEqual(fixture["source_commit"], "8ac7fdf9e2162806d0a59178cdb48e485bbde629")
        original = fixture["methods"]["locator_configured_outer_group"]
        self.assertEqual(original["source_path"], "scripts/native_pids_locator.py")
        self.assertEqual(hashlib.sha256(original["method_source"].encode()).hexdigest(),
            original["method_source_utf8_sha256"])
        expected = ast.parse("class FrozenOriginal:\n" + original["method_source"]).body[0].body[0]
        self.assertEqual(ast.dump(method, include_attributes=False), ast.dump(expected, include_attributes=False))

    def collapse_host_delegation(self, node):
        self.assertIsInstance(node, ast.If)
        self.assertEqual(ast.dump(node.test),
            "Compare(left=Name(id='observer', ctx=Load()), ops=[Is()], comparators=[Constant(value=None)])")
        self.assertEqual((len(node.body), len(node.orelse)), (1, 1))
        unobserved, observed = node.body[0], node.orelse[0]
        self.assertEqual(len(observed.value.keywords), 1)
        self.assertEqual(observed.value.keywords[0].arg, "observer")
        self.assertEqual(ast.dump(observed.value.keywords[0].value), "Name(id='observer', ctx=Load())")
        observed.value.keywords.clear()
        self.assertEqual(ast.dump(unobserved, include_attributes=False), ast.dump(observed, include_attributes=False))
        return unobserved

    def test_host_group_original_methods_and_partitions_use_pinned_5b_source(self):
        raw = (Path(__file__).parent / "fixtures/native_pids_host_group_baseline_methods.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            "e996736bb4c01bf63e79460003c1ed7267313faef86be71ac1bca0ba9e25d980")
        fixture = json.loads(raw)
        self.assertEqual(fixture["source_commit"], "5b73e3c4dd93de9cb80ca4c0857e19d332a53b68")
        tree = ast.parse(Path(l.__file__).read_text())
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "LocatorSource")
        for name in ("group", "configured_outer_group"):
            original = fixture["methods"]["LocatorSource." + name]
            self.assertEqual((original["source_path"], original["class_name"], original["method_name"]),
                ("scripts/native_pids_locator.py", "LocatorSource", name))
            self.assertEqual(hashlib.sha256(original["method_source"].encode()).hexdigest(), original["method_source_utf8_sha256"])
            method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual([arg.arg for arg in method.args.args], ["self", "process", "observer"])
            self.assertEqual(ast.dump(method.args.defaults[0]), "Constant(value=None)")
            if name == "group":
                original_call = self.collapse_host_delegation(method.body[0])
                blocks = method.body[1:-1]
                self.assertEqual([n.items[0].context_expr.args[1].value for n in blocks], ["gh_root", "gh_nodes"])
                self.assertEqual([len(n.body) for n in blocks], [8, 4])
                for node in blocks:
                    call = node.items[0].context_expr
                    self.assertEqual(ast.dump(call.func), "Name(id='_host_group_escape', ctx=Load())")
                    self.assertEqual(ast.dump(call.args[0]), "Name(id='observer', ctx=Load())")
                self.assertIsInstance(method.body[-1], ast.Return)
                method.body = [original_call] + [child for n in blocks for child in n.body] + [method.body[-1]]
                method.args.args.pop(); method.args.defaults.clear()
            else:
                host = next(n for n in method.body if isinstance(n, ast.With)
                    and n.items[0].context_expr.args[1].value == "oc_host")
                self.assertEqual(len(host.body), 1)
                host.body = [self.collapse_host_delegation(host.body[0])]
            expected = ast.parse("class Original:\n" + original["method_source"]).body[0].body[0]
            self.assertEqual(ast.dump(method, include_attributes=False), ast.dump(expected, include_attributes=False))

    def install_host_failure(self, tree, site, failure, stack):
        source = tree.source
        if site in ("gh_read", "gh_mount"):
            original = source.read
            class MountBody(bytes):
                def decode(self, *_args, **_kwargs):
                    raise failure
            def read(directory, name, maximum):
                if name == "self/mountinfo":
                    if site == "gh_read":
                        raise failure
                    return MountBody(original(directory, name, maximum))
                return original(directory, name, maximum)
            stack.enter_context(patch.object(source, "read", side_effect=read))
        elif site in ("gh_walk", "gh_leaf", "gh_nodes"):
            original = source.open
            wanted = {"gh_walk": "/", "gh_leaf": "pids.max", "gh_nodes": "pids.events.local"}[site]
            def open_file(name, *args, **kwargs):
                if name == wanted:
                    raise failure
                return original(name, *args, **kwargs)
            stack.enter_context(patch.object(source, "open", side_effect=open_file))
        elif site == "gh_verify":
            original = b._group_escape
            def scope(observer, name):
                if name == "gv_make":
                    raise failure
                return original(observer, name)
            stack.enter_context(patch.object(b, "_group_escape", side_effect=scope))
        elif site == "gv_make":
            stack.enter_context(patch.object(b, "Group", side_effect=failure))
        elif site == "gv_call":
            stack.enter_context(patch.object(source, "check_group", side_effect=failure))
        elif site.startswith("gv_"):
            from contextlib import ExitStack
            original = source.check_group
            def verify(group, *args, **kwargs):
                with ExitStack() as local:
                    if site == "gv_time":
                        local.enter_context(patch.object(source.budget, "check", side_effect=failure))
                    elif site == "gv_record":
                        local.enter_context(patch.object(source, "read", side_effect=failure))
                    elif site == "gv_bind":
                        local.enter_context(patch.object(source, "check_mount", side_effect=failure))
                    elif site == "gv_ids":
                        local.enter_context(patch.object(b, "identity", side_effect=failure))
                    elif site in ("gv_dirs", "gv_files", "gv_type"):
                        open_original = source.open
                        def open_file(name, *a, **kw):
                            if ((site == "gv_dirs" and kw.get("directory") is True)
                                    or (site == "gv_files" and name == "pids.max")
                                    or (site == "gv_type" and name == "cgroup.type")):
                                raise failure
                            return open_original(name, *a, **kw)
                        local.enter_context(patch.object(source, "open", side_effect=open_file))
                    elif site == "gv_cache":
                        class Cache:
                            def get(self, _key):
                                raise failure
                        local.enter_context(patch.object(source, "controller_groups", Cache(), create=True))
                    else:
                        raise AssertionError("unreviewed injection site")
                    return original(group, *args, **kwargs)
            stack.enter_context(patch.object(source, "check_group", side_effect=verify))
        else:
            self.assertEqual(site, "gh_root")
            stack.enter_context(patch.object(source, "root_file_present", side_effect=failure))

    def test_each_host_group_block_preserves_exact_direct_error_and_pair(self):
        from contextlib import ExitStack
        for site in ("gh_read", "gh_mount", "gh_walk", "gh_leaf", "gh_verify", "gh_root", "gh_nodes", "gv_make", "gv_call", "gv_time", "gv_record", "gv_bind", "gv_ids", "gv_dirs", "gv_files", "gv_type", "gv_cache"):
            def run(tree):
                process = tree.source.process(100, 1000)
                failure = PermissionError(13, "PRIVATE_HOST_CANARY")
                records = []
                with ExitStack() as stack:
                    self.install_host_failure(tree, site, failure, stack)
                    with self.assertRaises(PermissionError) as caught:
                        tree.source.group(process, observer=lambda *pair: records.append(pair))
                self.assertIs(caught.exception, failure)
                expected = [site]
                if site.startswith("gv_"):
                    if site not in ("gv_make", "gv_call"):
                        expected.append("gv_call")
                    expected.append("gh_verify")
                self.assertEqual(records, [(name, "EACCES") for name in expected])
            with self.subTest(site=site):
                self.run_tree(True, run)

    def test_verifier_partitions_match_separate_frozen_candidate_methods(self):
        raw = (Path(__file__).parent / "fixtures/native_pids_host_verify_baseline_methods.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            "3f45885fde9e43639ece54f3b28f8eb6cbef401efc2422f663d08a2405d976ff")
        fixture = json.loads(raw)
        self.assertEqual(fixture["source_commit"], "ba22366407660447a7845d1dad5ff810de1587e0")
        for module, owner, helper, sites in (
                (b, "LinuxSource", "_group_escape", ("gv_time", "gv_record", "gv_bind", "gv_ids", "gv_dirs", "gv_files", "gv_type")),
                (l, "LocatorSource", "_host_group_escape", ("gv_cache",))):
            original = fixture["methods"][owner + ".check_group"]
            self.assertEqual(original["source_path"], "scripts/" + Path(module.__file__).name)
            self.assertEqual((original["class_name"], original["method_name"]), (owner, "check_group"))
            self.assertEqual(hashlib.sha256(original["method_source"].encode()).hexdigest(), original["method_source_utf8_sha256"])
            cls = next(n for n in ast.parse(Path(module.__file__).read_text()).body if isinstance(n, ast.ClassDef) and n.name == owner)
            method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "check_group")
            self.assertEqual([arg.arg for arg in method.args.args], ["self", "group", "observer"])
            self.assertEqual([ast.dump(n) for n in method.args.defaults], ["Constant(value=None)"])
            if owner == "LocatorSource":
                first = [self.collapse_host_delegation(method.body[0])]
                blocks = method.body[1:]
            else:
                first, blocks = [], method.body
            self.assertEqual(len(blocks), len(sites))
            for block, site in zip(blocks, sites):
                self.assertIsInstance(block, ast.With)
                self.assertEqual(len(block.items), 1)
                self.assertIsNone(block.items[0].optional_vars)
                call = block.items[0].context_expr
                self.assertEqual(ast.dump(call.func), "Name(id='" + helper + "', ctx=Load())")
                self.assertEqual([ast.dump(n) for n in call.args], ["Name(id='observer', ctx=Load())", "Constant(value='" + site + "')"])
                self.assertEqual(call.keywords, [])
            method.body = first + [child for block in blocks for child in block.body]
            method.args.args.pop(); method.args.defaults.clear()
            expected = ast.parse("class Original:\n" + original["method_source"]).body[0].body[0]
            self.assertEqual(ast.dump(method, include_attributes=False), ast.dump(expected, include_attributes=False))

    def test_default_none_verifiers_preserve_both_old_one_argument_seams(self):
        def run(tree):
            process = tree.source.process(100, 1000)
            calls = []
            def old_group_check(group):
                calls.append(group)
            tree.source.check_group = old_group_check
            group = tree.source.group(process)
            self.assertEqual(calls, [group])
            def old_base(_self, candidate):
                calls.append(candidate)
            with patch.object(b.LinuxSource, "check_group", old_base), \
                    patch.object(b, "_group_exception_tag", side_effect=AssertionError("no classify")), \
                    patch.object(l, "_host_group_exception_tag", side_effect=AssertionError("no classify")):
                l.LocatorSource.check_group(tree.source, group)
                l.LocatorSource.check_group(tree.source, group, observer=None)
            self.assertEqual(calls, [group, group, group])
        self.run_tree(True, run)

    def test_verifier_loop_cleanup_reports_only_direct_escape_including_supersession(self):
        for site in ("gv_dirs", "gv_files", "gv_type"):
            for work_fails in (False, True):
                for observed in (False, True):
                    def run(tree):
                        process = tree.source.process(100, 1000)
                        group = tree.source.group(process)
                        work, cleanup = PermissionError(13, "PRIVATE_WORK"), FileNotFoundError(2, "PRIVATE_CLOSE")
                        selected, records = set(), []
                        original_open, original_close = tree.source.open, tree.source.close_fd
                        original_identity, original_read = b.identity, tree.source.read_fd
                        def open_file(name, *args, **kwargs):
                            fd = original_open(name, *args, **kwargs)
                            if ((site == "gv_dirs" and kwargs.get("directory") is True)
                                    or (site == "gv_files" and name == "pids.max")
                                    or (site == "gv_type" and name == "cgroup.type")):
                                selected.add(fd)
                            return fd
                        def close(fd):
                            original_close(fd)
                            if fd in selected:
                                raise cleanup
                        def identity(fd):
                            if work_fails and fd in selected:
                                raise work
                            return original_identity(fd)
                        def read(fd, maximum):
                            if work_fails and fd in selected:
                                raise work
                            return original_read(fd, maximum)
                        with patch.object(tree.source, "open", side_effect=open_file), \
                                patch.object(tree.source, "close_fd", side_effect=close), \
                                patch.object(b, "identity", side_effect=identity), \
                                patch.object(tree.source, "read_fd", side_effect=read), \
                                patch.object(b, "_group_exception_tag", wraps=b._group_exception_tag) as classify:
                            before = len(tree.source.owned), tree.source.budget.fds
                            with self.assertRaises(FileNotFoundError) as caught:
                                tree.source.check_group(group, observer=(lambda *pair: records.append(pair)) if observed else None)
                            self.assertIs(caught.exception, cleanup)
                            self.assertEqual((len(tree.source.owned), tree.source.budget.fds), before)
                            self.assertEqual(records, [(site, "ENOENT")] if observed else [])
                            self.assertEqual(classify.call_count, int(observed))
                            if observed:
                                self.assertIs(classify.call_args.args[0], cleanup)
                    with self.subTest(site=site, work_fails=work_fails, observed=observed):
                        self.run_tree(True, run)

    def test_each_verifier_actual_stage_preserves_hostile_error_and_observer_failure(self):
        from contextlib import ExitStack
        for site in ("gv_make", "gv_call", "gv_time", "gv_record", "gv_bind", "gv_ids", "gv_dirs", "gv_files", "gv_type", "gv_cache"):
            for classifier_fails in (False, True):
                def run(tree):
                    process = tree.source.process(100, 1000)
                    reads, records = [], []
                    class Hostile(OSError):
                        def __getattribute__(self, name):
                            # Test-only ExitStack reads this while restoring injected patches.
                            if name == "__traceback__":
                                return BaseException.__getattribute__(self, name)
                            reads.append(name)
                            raise AssertionError("PRIVATE_ATTRIBUTE")
                    failure = Hostile()
                    def observer(*pair):
                        records.append(pair)
                        raise KeyboardInterrupt("PRIVATE_CALLBACK")
                    with ExitStack() as stack:
                        self.install_host_failure(tree, site, failure, stack)
                        if classifier_fails:
                            for module, name in ((b, "_group_exception_tag"), (l, "_host_group_exception_tag")):
                                stack.enter_context(patch.object(module, name, side_effect=KeyboardInterrupt("PRIVATE_CLASSIFIER")))
                        try:
                            tree.source.group(process, observer=observer)
                        except BaseException as caught:
                            self.assertIs(caught, failure)
                        else:
                            self.fail("source error must escape")
                    expected = [site]
                    if site not in ("gv_make", "gv_call"):
                        expected.append("gv_call")
                    expected.append("gh_verify")
                    self.assertEqual(records, [(name, "unclassified") for name in expected])
                    self.assertEqual(reads, [])
                with self.subTest(site=site, classifier_fails=classifier_fails):
                    self.run_tree(True, run)

    def test_constructor_identity_tuple_failure_is_gv_make(self):
        def run(tree):
            process = tree.source.process(100, 1000)
            failure, records = PermissionError(13, "PRIVATE_IDENTITY"), []
            with patch.object(b, "identity", side_effect=failure):
                with self.assertRaises(PermissionError) as caught:
                    tree.source.group(process, observer=lambda *pair: records.append(pair))
            self.assertIs(caught.exception, failure)
            self.assertEqual(records, [("gv_make", "EACCES"), ("gh_verify", "EACCES")])
        self.run_tree(True, run)

    def test_warm_controller_loop_failure_is_gv_cache(self):
        def run(tree):
            process = tree.source.process(100, 1000)
            group = tree.source.group(process)
            self.assertTrue(tree.source.controller_groups[group.identities[-1]][1])
            failure, records = PermissionError(13, "PRIVATE_CONTROLLER"), []
            with patch.object(tree.source, "check_controller", side_effect=failure) as check:
                with self.assertRaises(PermissionError) as caught:
                    tree.source.check_group(group, observer=lambda *pair: records.append(pair))
            self.assertIs(caught.exception, failure)
            self.assertEqual(check.call_count, 1)
            self.assertEqual(records, [("gv_cache", "EACCES")])
        self.run_tree(True, run)

    def test_expired_verifier_deadline_is_equivalent_without_source_work(self):
        results = []
        for observed in (False, True):
            def run(tree):
                process = tree.source.process(100, 1000)
                group = tree.source.group(process)
                source, records, clocks = tree.source, [], []
                def expired():
                    clocks.append("clock")
                    return source.budget.work_ns
                source.budget.clock = expired
                def snapshot():
                    return (tuple(getattr(source.budget, name) for name in
                        ("reads", "bytes", "fds", "opens", "output", "frames", "peak_fds", "deadline_ns", "work_ns")),
                        len(source.owned), len(source.controller_cache), len(source.controller_groups), len(source.root_records))
                before = snapshot()
                with self.assertRaises(b.Refusal), \
                        patch.object(source, "read", side_effect=AssertionError("expired before source I/O")), \
                        patch.object(source, "open", side_effect=AssertionError("expired before source I/O")):
                    source.check_group(group, observer=(lambda *pair: records.append(pair)) if observed else None)
                self.assertEqual(snapshot(), before)
                self.assertEqual(clocks, ["clock"])
                self.assertEqual(records, [("gv_time", "unclassified")] if observed else [])
                results.append((before, snapshot(), clocks))
            self.run_tree(True, run)
        self.assertEqual(results[0], results[1])

    def test_declared_events_are_local_exact_and_never_hidden_errno(self):
        for site in ("gh_root", "gh_nodes"):
            records = []
            failure = l.LocatorRefusal("UnsupportedEventSemantics")
            try:
                with l._host_group_escape(lambda *pair: records.append(pair), site):
                    try:
                        raise FileNotFoundError(2, "PRIVATE_HIDDEN_CAUSE")
                    except FileNotFoundError:
                        raise failure from None
            except l.LocatorRefusal as caught:
                self.assertIs(caught, failure)
            self.assertEqual(records, [(site, "declared_unsupported_events")])
            self.assertEqual(b._group_exception_tag(failure), "unclassified")
        reads = []
        class Hostile(l.LocatorRefusal):
            def __getattribute__(self, name):
                reads.append(name)
                raise AssertionError("PRIVATE_CATEGORY_READ")
        class Text(str):
            def __eq__(self, _other):
                raise AssertionError("must not compare subclass")
        for error in (l.LocatorRefusal("BindingFailed"), Hostile(), b.Refusal(), KeyboardInterrupt(), GeneratorExit()):
            self.assertEqual(l._host_group_exception_tag(error), "unclassified")
        error = l.LocatorRefusal()
        for category in (Text("UnsupportedEventSemantics"), 13, None):
            error.category = category
            self.assertEqual(l._host_group_exception_tag(error), "unclassified")
        del error.category
        records = []
        with self.assertRaises(l.LocatorRefusal) as caught:
            with l._host_group_escape(lambda *pair: records.append(pair), "gh_root"):
                raise error
        self.assertIs(caught.exception, error)
        self.assertEqual(records, [("gh_root", "unclassified")])
        self.assertEqual(reads, [])

    def test_new_host_helper_preserves_fatal_generator_identity_with_and_without_observer(self):
        for error_type in (KeyboardInterrupt, SystemExit, GeneratorExit, StopIteration):
            for observed in (False, True):
                failure = error_type("PRIVATE_HOST_CANARY")
                records = []
                classify_original = l._host_group_exception_tag
                with patch.object(l, "_host_group_exception_tag", wraps=classify_original) as classify:
                    with self.assertRaises(error_type) as caught:
                        with l._host_group_escape((lambda *pair: records.append(pair)) if observed else None, "gh_root"):
                            raise failure
                self.assertIs(caught.exception, failure)
                self.assertEqual(records, [("gh_root", "unclassified")] if observed else [])
                if observed:
                    classify.assert_called_once_with(failure)
                else:
                    classify.assert_not_called()

    def test_local_classifier_and_callback_failures_never_replace_or_retry_source(self):
        for side_effect in (lambda _site: None, KeyboardInterrupt("observer failure")):
            failure = l.LocatorRefusal("UnsupportedEventSemantics")
            observer = unittest.mock.Mock(side_effect=side_effect)
            with patch.object(l, "_host_group_exception_tag", side_effect=KeyboardInterrupt("classifier failure")) as classify:
                with self.assertRaises(l.LocatorRefusal) as caught:
                    with l._host_group_escape(observer, "gh_root"):
                        raise failure
            self.assertIs(caught.exception, failure)
            classify.assert_called_once_with(failure)
            observer.assert_called_once_with("gh_root", "unclassified")

    def test_actual_translated_missing_local_event_has_declared_tag(self):
        def run(tree):
            process = tree.source.process(100, 1000)
            (tree.cg / "owned/pids.events.local").unlink()
            records = []
            with self.assertRaises(l.LocatorRefusal) as caught:
                tree.source.group(process, observer=lambda *pair: records.append(pair))
            self.assertEqual(caught.exception.category, "UnsupportedEventSemantics")
            self.assertEqual(records, [("gh_nodes", "declared_unsupported_events")])
        self.run_tree(True, run)

    def test_default_none_retains_one_argument_fakes_and_no_classification(self):
        source, process, current, _trace, _failure, identity = self.configured_fixture()
        calls = []
        def old_group(proc):
            calls.append(proc)
            return current
        source.group = old_group
        with patch.object(b, "identity", side_effect=identity), \
                patch.object(b, "_group_exception_tag", side_effect=AssertionError("no classification")) as base, \
                patch.object(l, "_host_group_exception_tag", side_effect=AssertionError("no classification")) as local:
            self.assertIs(source.configured_outer_group(process), current)
            base.assert_not_called(); local.assert_not_called()
        self.assertEqual(calls, [process])
        # The default locator-to-base call must also keep the old one-argument seam.
        failure = RuntimeError("after old-arity base")
        class Record:
            def split(self):
                raise failure
        result = SimpleNamespace(mount_record=Record())
        def old_base(_self, proc):
            calls.append(proc)
            return result
        with patch.object(b.LinuxSource, "group", old_base), \
                patch.object(l, "_host_group_exception_tag", side_effect=AssertionError("no classification")) as local:
            with self.assertRaises(RuntimeError) as caught:
                l.LocatorSource.group(source, process)
            self.assertIs(caught.exception, failure)
            local.assert_not_called()
        self.assertEqual(calls, [process, process])

    def test_observed_and_default_source_operations_budgets_fds_and_caches_match(self):
        for root_files in (False, True):
            results = []
            for observed in (False, True):
                def run(tree):
                    if root_files:
                        tree.make_group(tree.cg, 512, [])
                    process = tree.source.process(200, 2000)
                    trace = []
                    for name in ("open", "read", "read_fd", "close_fd", "check_mount", "check_group", "root_file_present"):
                        original = getattr(tree.source, name)
                        def call(*args, _name=name, _original=original, **kwargs):
                            trace.append(_name)
                            return _original(*args, **kwargs)
                        setattr(tree.source, name, call)
                    budget_check = tree.source.budget.check
                    def check():
                        trace.append("budget.check")
                        return budget_check()
                    tree.source.budget.check = check
                    records = []
                    with patch.object(b, "_group_exception_tag", side_effect=AssertionError("success must not classify")) as base, \
                            patch.object(l, "_host_group_exception_tag", side_effect=AssertionError("success must not classify")) as local:
                        for _ in range(2):
                            tree.source.group(process, observer=(lambda *pair: records.append(pair)) if observed else None)
                        base.assert_not_called(); local.assert_not_called()
                    self.assertEqual(records, [])
                    counters = tuple(getattr(tree.source.budget, name) for name in
                        ("reads", "bytes", "fds", "opens", "output", "frames", "peak_fds", "deadline_ns", "work_ns"))
                    results.append((tuple(trace), counters, len(tree.source.owned),
                        len(tree.source.controller_cache), len(tree.source.controller_groups), len(tree.source.root_records)))
                self.run_tree(True, run)
            self.assertEqual(results[0], results[1])
            self.assertGreater(results[0][2], 0)
            self.assertGreaterEqual(results[0][3], 3 if root_files else 2)

    def test_held_socket_inode_connect_and_path_replacement_refusal(self):
        with tempfile.TemporaryDirectory(prefix="dl-held-endpoint-") as directory:
            capture = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            (Path(directory) / "socket").mkdir()
            path = str(Path(directory) / "socket/docker.sock")
            old, replacement = socket.socket(socket.AF_UNIX), socket.socket(socket.AF_UNIX)
            source = l.LocatorSource(l.RuntimeBudget(time.monotonic_ns() + 180_000_000_000))
            try:
                old.bind(path)
                old.listen(1)
                source.adopt_capture_directory(capture)
                capture = None
                endpoint = l.HeldEndpoint(source, source.capture_directory)
                endpoint.check()
                os.unlink(path)
                replacement.bind(path)
                replacement.listen(1)
                with self.assertRaises(b.Refusal):
                    endpoint.check()
                # Verify the narrow kernel recipe independently of the stricter
                # source policy: retained inode cannot redirect to replacement.
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect("/proc/self/fd/" + str(endpoint.socket))
                    with old.accept()[0] as accepted:
                        client.sendall(b"owned")
                        self.assertEqual(accepted.recv(5), b"owned")
            finally:
                old.close(); replacement.close(); source.close()
                if capture is not None:
                    os.close(capture)

    def test_actual_self_proc_namespace_and_descriptor_cleanup(self):
        budget = b.Budget(time.monotonic_ns() + 180_000_000_000)
        source = l.LocatorSource(budget)
        try:
            pid = os.getpid()
            proc = source.process(pid, b.start_from_stat(source.read(source.proc, "self/stat", 1024), pid))
            facts, vector = l.status_vectors(source.read(proc.directory, "status", 4096), pid)
            self.assertEqual(facts[0], (pid,))
            self.assertEqual(source.namespace_chain(proc.namespaces[0], vector), (b.identity(source.reader_namespace),))
            source.check_process(proc)
            competing = source.globals(proc)
            self.assertGreater(competing["threads_max"], 0)
            self.assertGreater(competing["pid_max"], 0)
            self.assertGreater(competing["total_tasks"], 0)
        finally:
            source.close()
        self.assertEqual(source.owned, set())
        self.assertEqual(budget.fds, 0)

    def run_tree(self, nested, operation):
        with tempfile.TemporaryDirectory(prefix="dl-locator-tree-") as directory:
            tree = KernelTree(directory, nested=nested)
            try:
                with patch.object(b, "fs_magic", side_effect=tree.magic), patch.object(
                    l.fcntl, "ioctl", side_effect=tree.parent), patch.object(
                    os, "pidfd_open", side_effect=lambda *_: os.dup(tree.pipe[0])):
                    return operation(tree)
            finally:
                tree.close()

    def runtime(self, tree):
        source = tree.source
        outer = source.process(100, 1000)
        group = source.group(outer)
        endpoint = SimpleNamespace(check=lambda: None)
        reservations = l.ParentReservations(lambda units, size: self.assertEqual((units, size), (1, 32768)))
        runtime = l.RuntimeLocator(source, outer, group, endpoint,
                                   l.DaemonExpectation(1000, ("usr", "bin", "dockerd"), True),
                                   "1.41", {"owner": "run1"}, reservations)
        # Bind the actual synthetic process/root/executable/namespace before
        # substituting only authored Engine replies; no caller PID JSON exists.
        class Connected:
            def getsockopt(_self, _level, option, *_size):
                return os.dup(tree.pipe[0]) if option == 77 else struct.pack("3i", 110, 1000, 1000)
        lease = l.PeerLease(runtime, Connected())
        lease.close()
        runtime.inspect = lambda cid: tree.inspects[cid]
        return runtime

    def test_six_roles_actual_source_reads_with_and_without_extra_rootlesskit_pidns(self):
        for nested in (False, True):
            with self.subTest(nested=nested):
                def run(tree):
                    runtime = self.runtime(tree)
                    result = runtime.locate_batch(tree.ids)
                    self.assertEqual(tuple(result), l.ORDER)
                    self.assertEqual([item.process.pid for item in result.values()], [200, 201, 202, 203, 204, 205])
                    self.assertTrue(all(item.process.directory in tree.source.owned for item in result.values()))
                    for slot, item in result.items():
                        self.assertEqual(item.process.status[2][-1], 1)
                        self.assertEqual(tree.source.snapshot(item.process, item.group)["current"], 1)
                    runtime.recheck_batch()
                    runtime.seal_measurements()
                    # Leaf removal after sealing is expected; finalize checks
                    # remain rooted in the held ORIGINAL daemon and outer.
                    tree.source.budget.begin_cleanup()
                    (tree.proc / "200/stat").write_bytes(b"dead")
                    runtime.check_daemon()
                    self.assertEqual(runtime.bound, {})
                    budget = tree.source.budget
                    self.assertLess(budget.bytes, 32 * 1024 * 1024)
                    self.assertGreater(budget.bytes, 2 * 1024 * 1024)
                    self.assertLess(budget.reads, 65536)
                    self.assertLess(budget.fds, 256)
                    return budget.bytes
                self.run_tree(nested, run)

    def test_sibling_namespace_collision_does_not_match(self):
        def run(tree):
            runtime = self.runtime(tree)
            # State.Pid 70 occurs in a sibling daemon namespace, never D.
            tree.parents[str(tree.ns / "cli16")] = "sibling"
            with self.assertRaisesRegex(l.LocatorRefusal, "NoMatch"):
                runtime.locate_batch(tree.ids)
        self.run_tree(True, run)

    def test_pid_reuse_movement_and_inspect_state_change_refuse(self):
        for fault in ("reuse", "movement", "inspect"):
            def run(tree):
                runtime = self.runtime(tree)
                result = runtime.locate_batch(tree.ids)
                if fault == "reuse":
                    (tree.proc / "200/stat").write_bytes(b"200 (new) S " + b"0 " * 18 + b"9999\n")
                elif fault == "movement":
                    (tree.proc / "200/cgroup").write_bytes(b"0::/owned/rendered64\n")
                else:
                    old = tree.inspects[tree.ids["cli16"]]
                    tree.inspects[tree.ids["cli16"]] = (old[0] + 1, *old[1:])
                with self.assertRaises(b.Refusal):
                    runtime.recheck_batch()
                self.assertIs(runtime.bound["cli16"], result["cli16"])
                self.assertTrue(runtime.failed)
            with self.subTest(fault=fault):
                self.run_tree(True, run)

    def test_subtree_duplicate_and_growth_limits_are_closed(self):
        for fault in ("duplicate", "leaders", "depth"):
            def run(tree):
                source = tree.source
                outer = source.process(100, 1000)
                group = source.group(outer)
                if fault == "duplicate":
                    (tree.cg / "owned/cli16/cgroup.procs").write_text("100\n")
                elif fault == "leaders":
                    (tree.cg / "owned/cgroup.procs").write_text("".join(str(x) + "\n" for x in range(1000, 1513)))
                else:
                    directory = tree.cg / "owned"
                    for _ in range(13):
                        directory /= "child"
                        tree.make_group(directory, 512, [])
                with self.assertRaises(b.Refusal):
                    source.candidates(group)
            with self.subTest(fault=fault):
                self.run_tree(True, run)

    def test_namespace_parent_failures_never_guess_a_root(self):
        budget = b.Budget(180_000_000_001, lambda: 1)
        source = l.LocatorSource.__new__(l.LocatorSource)
        source.budget, source.owned, source.reader_namespace = budget, set(), 1
        for error in (errno.EPERM, errno.ENOTTY):
            with patch.object(b, "identity", side_effect=lambda fd: (0, fd)), patch.object(
                    l.fcntl, "ioctl", side_effect=OSError(error, "private")):
                with self.assertRaisesRegex(l.LocatorRefusal, "NamespaceUnreachable"):
                    source.namespace_chain(2, (10, 1))

    def test_literal_namespace_vectors_reject_thread_and_partial_coordinate_views(self):
        good = b"Pid: 400\nTgid: 400\nUid: 1 1 1 1\nNSpid: 400 20 1\nNStgid: 400 20 1\n"
        self.assertEqual(l.status_vectors(good, 400)[1], (400, 20, 1))
        for body in (good.replace(b"Tgid: 400", b"Tgid: 399"), good.replace(b"NStgid: 400 20 1", b"NStgid: 400 1"),
                     good.replace(b"NSpid: 400", b"NSpid: 401")):
            with self.assertRaises(b.Refusal):
                l.status_vectors(body, 400)

    def test_real_inspect_projection_and_same_connection_peer_lease_use_precharged_api(self):
        def run(tree):
            runtime = self.runtime(tree)
            del runtime.inspect  # exercise actual bounded JSON projection
            observed = []
            class Connected:
                def getsockopt(_self, level, option, *_size):
                    self.assertEqual(level, socket.SOL_SOCKET)
                    if option == 77:
                        return os.dup(tree.pipe[0])
                    self.assertEqual(option, socket.SO_PEERCRED)
                    return struct.pack("3i", 110, 1000, 1000)
            body = {"Id": "0" * 63 + "1", "RestartCount": 0, "Config": {"Labels": {"owner": "run1"}},
                    "State": {"Status": "running", "Running": True, "Restarting": False, "Paused": False, "Dead": False,
                              "Pid": 70, "StartedAt": "2026-10-25T12:00:00Z"}}
            def response(address, method, route, **options):
                self.assertEqual(runtime.reserve_api.calls, 1)
                self.assertEqual((method, route), ("GET", "/v1.41/containers/" + "0" * 63 + "1/json"))
                self.assertEqual(options["max_response_bytes"], 32768)
                peer = options["peer_lease"](Connected())
                observed.append(peer.fd)
                try:
                    peer.check()
                    wire = json.dumps(body).encode()
                    peer.check()
                    return 200, wire
                finally:
                    peer.close()
            runtime.endpoint.address = "/held-only"
            with patch.object(l.http, "request", side_effect=response):
                self.assertEqual(runtime.inspect("0" * 63 + "1"),
                                 (70, "2026-10-25T12:00:00Z", 0, (("owner", "run1"),)))
            self.assertTrue(all(fd not in tree.source.owned for fd in observed))
        self.run_tree(True, run)

    def test_inspect_wrong_cid_owner_running_and_malformed_json_are_value_free(self):
        for fault in ("cid", "owner", "running", "json"):
            def run(tree):
                runtime = self.runtime(tree)
                del runtime.inspect
                runtime.endpoint.address = "/held-only"
                body = {"Id": "0" * 63 + "1", "RestartCount": 0, "Config": {"Labels": {"owner": "run1"}},
                        "State": {"Status": "running", "Running": True, "Restarting": False, "Paused": False, "Dead": False,
                                  "Pid": 70, "StartedAt": "2026-10-25T12:00:00Z"}}
                if fault == "cid": body["Id"] = "private-wrong-id"
                if fault == "owner": body["Config"]["Labels"]["owner"] = "private-wrong-owner"
                if fault == "running": body["State"]["Restarting"] = True
                wire = b"private malformed" if fault == "json" else json.dumps(body).encode()
                with patch.object(l.http, "request", return_value=(200, wire)):
                    with self.assertRaises(l.LocatorRefusal) as error:
                        runtime.inspect("0" * 63 + "1")
                self.assertEqual(str(error.exception), "BindingFailed")
                self.assertTrue(runtime.failed)
            with self.subTest(fault=fault):
                self.run_tree(True, run)

    def test_peer_interface_refusal_replacement_and_exit_keep_original_binding(self):
        for fault in ("unsupported", "replacement", "exit"):
            def run(tree):
                runtime = self.runtime(tree)
                original = runtime.daemon
                class Connected:
                    def getsockopt(_self, _level, option, *_size):
                        if option == 77:
                            if fault == "unsupported":
                                raise OSError(errno.ENOPROTOOPT, "private")
                            return os.dup(tree.pipe[0])
                        return struct.pack("3i", 111, 1000, 1000)
                if fault == "exit":
                    os.close(tree.pipe[1])
                    tree.pipe = tree.pipe[:1]
                    with self.assertRaisesRegex(l.LocatorRefusal, "PeerExited"):
                        runtime.check_daemon()
                else:
                    with self.assertRaises(b.Refusal) as error:
                        l.PeerLease(runtime, Connected())
                    if fault == "unsupported":
                        self.assertEqual(error.exception.category, "UnsupportedPeerPidfd")
                self.assertIs(runtime.daemon, original)
            with self.subTest(fault=fault):
                self.run_tree(True, run)

    def test_original_parent_capture_debit_exhaustion_precedes_all_api_io(self):
        def run(tree):
            runtime = self.runtime(tree)
            del runtime.inspect
            original = {"calls": 299, "bytes": 2 * 1024 * 1024 - 32768 + 1}
            def debit(units, maximum):
                original["calls"] += units
                original["bytes"] += maximum
                b.require(original["calls"] <= 300 and original["bytes"] <= 2 * 1024 * 1024)
            runtime.reserve_api = l.ParentReservations(debit)
            before = tree.source.budget.bytes, tree.source.budget.opens
            with patch.object(l.http, "request") as transport:
                with self.assertRaises(l.LocatorRefusal):
                    runtime.inspect("0" * 63 + "1")
                transport.assert_not_called()
            self.assertEqual((tree.source.budget.bytes, tree.source.budget.opens), before)
            self.assertEqual(original, {"calls": 300, "bytes": 2097153})
            self.assertEqual(runtime.reserve_api.receipt(),
                             {"inspect_calls_reserved": 1, "inspect_body_bytes_reserved": 32768})
            self.assertTrue(runtime.failed)
        self.run_tree(True, run)

    def test_mapped_outer_user_namespace_is_refused_without_observing_daemon_uid(self):
        def run(tree):
            (tree.ns / "mapped-user").touch()
            (tree.proc / "100/ns/user").unlink()
            (tree.proc / "100/ns/user").symlink_to(tree.ns / "mapped-user")
            with patch.object(l.RuntimeLocator, "_bind_peer") as peer:
                with self.assertRaises(b.Refusal):
                    self.runtime(tree)
                peer.assert_not_called()
        self.run_tree(True, run)

    def test_outer_daemon_and_inner_time_namespaces_must_match_host_deadline_reader(self):
        for pid in (100, 110, 200):
            def run(tree):
                (tree.ns / "offset-time").touch()
                path = tree.proc / str(pid) / "ns/time"
                path.unlink(); path.symlink_to(tree.ns / "offset-time")
                with self.assertRaises(b.Refusal):
                    runtime = self.runtime(tree)
                    runtime.locate_batch(tree.ids)
            with self.subTest(pid=pid):
                self.run_tree(True, run)

    def test_accounted_worker_child_time_namespace_is_rechecked_too(self):
        def run(tree):
            runtime = self.runtime(tree)
            item = runtime.locate_batch(tree.ids)["cli16"]
            tree.make_process(1000, "cli16", (1000, 9000, 2), "owned/cli16", 1000)
            (tree.ns / "offset-child-time").touch()
            child_time = tree.proc / "1000/ns/time"
            child_time.unlink(); child_time.symlink_to(tree.ns / "offset-child-time")
            (tree.cg / "owned/cli16/cgroup.threads").write_text("200\n1000\n")
            (tree.cg / "owned/cli16/pids.current").write_text("2\n")
            with self.assertRaises(b.Refusal):
                tree.source.snapshot(item.process, item.group)
        self.run_tree(True, run)

    def test_actual_held_chain_records_local_enforcer_and_hierarchical_propagation(self):
        def run(tree):
            runtime = self.runtime(tree)
            item = runtime.locate_batch(tree.ids)["cli16"]
            before = tree.source.snapshot(item.process, item.group)
            attribution = before["attribution"]
            self.assertEqual(attribution["event_semantics"], "hierarchical_with_local_enforcer")
            self.assertTrue(attribution["complete_chain"])
            self.assertEqual(attribution["outer_index"], 1)
            self.assertEqual(attribution["hierarchy_root"]["qualification"], "root_exempt")
            self.assertEqual([(row["maximum"], row["current"], row["events_max"], row["events_local_max"])
                              for row in attribution["controllers"]], [(16, 1, 0, 0), (512, 2, 0, 0)])
            self.assertEqual({key: value for key, value in before["globals"].items() if not key.startswith("kernel_")},
                             {"threads_max": 65536, "pid_max": 4194304, "total_tasks": 1000,
                              "sched_policy": 0, "nproc_soft": "unlimited", "nproc_hard": "unlimited",
                              "total_tasks_samples": [1000, 1000]})
            self.assertEqual((before["globals"]["kernel_release"], before["globals"]["kernel_version"],
                              before["globals"]["kernel_machine"]), (os.uname().release, os.uname().version, os.uname().machine))
            (tree.cg / "owned/cli16/pids.events").write_text("max 1\n")
            (tree.cg / "owned/cli16/pids.events.local").write_text("max 1\n")
            (tree.cg / "owned/pids.events").write_text("max 1\n")
            after = tree.source.snapshot(item.process, item.group)
            self.assertEqual([(row["events_max"], row["events_local_max"])
                              for row in after["attribution"]["controllers"]], [(1, 1), (1, 0)])
            # An actual finite NPROC remains observed data, never a fabricated
            # per-UID count or an automatic refusal of measured local causality.
            (tree.proc / "200/limits").write_text("Max processes 1024 2048 processes\n")
            finite = tree.source.snapshot(item.process, item.group)["globals"]
            self.assertEqual((finite["nproc_soft"], finite["nproc_hard"]), (1024, 2048))
        self.run_tree(True, run)

    def test_unqualified_mount_prefix_and_parent_namespace_never_claim_complete_chain(self):
        for fault in ("hidden_prefix", "root_core_file", "unbound_parent"):
            def run(tree):
                if fault == "hidden_prefix":
                    (tree.cg / "pids.max").write_text("1024\n")
                    (tree.cg / "cgroup.type").write_text("domain\n")
                elif fault == "root_core_file":
                    (tree.cg / "cgroup.events").write_text("populated 1\nfrozen 0\n")
                else:
                    del tree.source.authenticated_parent_cgroup_namespace
                runtime = self.runtime(tree)
                item = runtime.locate_batch(tree.ids)["cli16"]
                attribution = tree.source.snapshot(item.process, item.group)["attribution"]
                self.assertFalse(attribution["complete_chain"])
                self.assertNotEqual(attribution["hierarchy_root"]["qualification"], "root_exempt")
            with self.subTest(fault=fault):
                self.run_tree(True, run)

    def test_localevents_mount_flag_and_missing_local_file_are_explicit_unsupported(self):
        for fault in ("flag", "file"):
            def run(tree):
                if fault == "flag":
                    path = tree.proc / "self/mountinfo"
                    path.write_text(path.read_text().replace("cgroup rw\n", "cgroup rw,pids_localevents\n"))
                else:
                    (tree.cg / "owned/pids.events.local").unlink()
                with self.assertRaises(l.LocatorRefusal) as failure:
                    self.runtime(tree)
                self.assertEqual(failure.exception.category, "UnsupportedEventSemantics")
            with self.subTest(fault=fault):
                self.run_tree(True, run)

    def test_actual_global_sources_reject_malformed_duplicate_and_changed_fields(self):
        for fault in ("loadavg", "limits", "policy"):
            def run(tree):
                runtime = self.runtime(tree)
                item = runtime.locate_batch(tree.ids)["cli16"]
                if fault == "loadavg":
                    (tree.proc / "loadavg").write_text("0.00 0.00 0.00 unknown\n")
                elif fault == "limits":
                    path = tree.proc / "200/limits"
                    path.write_text(path.read_text() * 2)
                else:
                    path = tree.proc / "200/stat"
                    body = path.read_bytes().rstrip().rsplit(b" ", 1)[0] + b" bad\n"
                    path.write_bytes(body)
                with self.assertRaises(b.Refusal):
                    tree.source.snapshot(item.process, item.group)
            with self.subTest(fault=fault):
                self.run_tree(True, run)

    def test_all_held_nonroot_prefix_above_outer_is_reported_and_rechecked(self):
        def run(tree):
            tree.make_group(tree.cg / "ancestor", 2048, [999])
            (tree.cg / "ancestor/pids.current").write_text("1000\n")
            (tree.cg / "owned").rename(tree.cg / "ancestor/owned")
            for pid in (100, 110, *range(200, 206)):
                path = tree.proc / str(pid) / "cgroup"
                path.write_bytes(path.read_bytes().replace(b"0::/owned", b"0::/ancestor/owned"))
            runtime = self.runtime(tree)
            item = runtime.locate_batch(tree.ids)["cli16"]
            attribution = tree.source.snapshot(item.process, item.group)["attribution"]
            self.assertTrue(attribution["complete_chain"])
            self.assertEqual(attribution["outer_index"], 1)
            self.assertEqual([(node["maximum"], node["current"]) for node in attribution["controllers"]],
                             [(16, 1), (512, 2), (2048, 1000)])
            # Fixed inode custody remains required at every retained ancestor.
            path = tree.cg / "ancestor/pids.events.local"
            path.unlink(); path.write_text("max 0\n")
            with self.assertRaises(b.Refusal):
                tree.source.snapshot(item.process, item.group)
        self.run_tree(True, run)

    def test_background_task_counts_preserve_endpoints_and_only_derive_observed_max(self):
        def run(tree):
            runtime = self.runtime(tree)
            item = runtime.locate_batch(tree.ids)["cli16"]
            original_globals, original_attribution = tree.source.globals, tree.source.attribution
            calls = {"globals": 0, "ancestors": 0}
            def globals_record(process):
                calls["globals"] += 1
                if calls["globals"] == 2:
                    (tree.proc / "loadavg").write_text("0.00 0.00 0.00 1/1005 200\n")
                return original_globals(process)
            def attribution_record(group):
                calls["ancestors"] += 1
                if calls["ancestors"] == 2:
                    (tree.cg / "owned/pids.current").write_text("10\n")
                    # These unrelated descendant events are observed, never
                    # claimed as effects of this barrier's nonexistent fork.
                    (tree.cg / "owned/pids.events").write_text("max 5\n")
                return original_attribution(group)
            with patch.object(tree.source, "globals", side_effect=globals_record), patch.object(
                    tree.source, "attribution", side_effect=attribution_record):
                sample = tree.source.snapshot(item.process, item.group)
            self.assertEqual((sample["globals"]["total_tasks"], sample["globals"]["total_tasks_samples"]), (1005, [1000, 1005]))
            ancestor = sample["attribution"]["controllers"][1]
            self.assertEqual((ancestor["current"], ancestor["current_samples"]), (10, [2, 10]))
            self.assertEqual((ancestor["events_max"], ancestor["events_samples"]), (5, [0, 5]))
            self.assertEqual(ancestor["events_local_samples"], [0, 0])
            self.assertEqual(sample["attribution"]["controllers"][0]["current_samples"], [1, 1])
        self.run_tree(True, run)

    def test_racing_static_limit_and_leaf_or_decreasing_counter_refuse(self):
        for fault in ("static", "leaf", "decreasing"):
            def run(tree):
                runtime = self.runtime(tree)
                item = runtime.locate_batch(tree.ids)["cli16"]
                if fault == "decreasing":
                    (tree.cg / "owned/pids.events.local").write_text("max 2\n")
                original_globals, original_attribution = tree.source.globals, tree.source.attribution
                calls = {"globals": 0, "attribution": 0}
                def globals_record(process):
                    calls["globals"] += 1
                    if fault == "static" and calls["globals"] == 2:
                        (tree.proc / "sys/kernel/threads-max").write_text("1001\n")
                    return original_globals(process)
                def attribution_record(group):
                    calls["attribution"] += 1
                    if calls["attribution"] == 2:
                        if fault == "leaf":
                            (tree.cg / "owned/cli16/pids.events.local").write_text("max 1\n")
                        elif fault == "decreasing":
                            (tree.cg / "owned/pids.events.local").write_text("max 1\n")
                    return original_attribution(group)
                with patch.object(tree.source, "globals", side_effect=globals_record), patch.object(
                        tree.source, "attribution", side_effect=attribution_record):
                    with self.assertRaises(b.Refusal):
                        tree.source.snapshot(item.process, item.group)
            with self.subTest(fault=fault):
                self.run_tree(True, run)

    def test_unsafe_global_headroom_is_preserved_as_observation_not_positive_evidence(self):
        def run(tree):
            runtime = self.runtime(tree)
            item = runtime.locate_batch(tree.ids)["cli16"]
            (tree.proc / "loadavg").write_text("0.00 0.00 0.00 1/65536 200\n")
            record = tree.source.snapshot(item.process, item.group)["globals"]
            self.assertEqual(record["threads_max"] - record["total_tasks"], 0)
            self.assertFalse(record["threads_max"] - record["total_tasks"] >= 16)
            # The strict producer must refuse to release this planned workload;
            # source measurements intentionally have no native27 constructor.
        self.run_tree(True, run)

    def test_parent_reservations_are_one_way_and_not_capture_allowance(self):
        actual = []
        adapter = l.ParentReservations(lambda calls, maximum: actual.append((calls, maximum)))
        for _ in range(24):  # literal full six-role locate + recheck + seal
            adapter(1, 32768)
        self.assertEqual(actual, [(1, 32768)] * 24)
        self.assertEqual(adapter.receipt(), {"inspect_calls_reserved": 24, "inspect_body_bytes_reserved": 786432})
        adapter.reserve = lambda *_: (_ for _ in ()).throw(b.Refusal())
        with self.assertRaises(b.Refusal):
            adapter(1, 32768)
        self.assertEqual(adapter.calls, 25)

    def test_external_source_only_debits_existing_capacity_including_prior_root_io(self):
        budget = l.RuntimeBudget(180_000_000_001, lambda: 1)
        budget.read(128)
        budget.debit_external(1024, 2)
        self.assertEqual((budget.bytes, budget.reads), (1152, 3))
        self.assertEqual(budget.ledger(0)["root_reserved"], {"bytes": 128, "reads": 1})
        with self.assertRaises(b.Refusal):
            budget.debit_external(0, 0)
        exhausted = l.RuntimeBudget(180_000_000_001, lambda: 1)
        exhausted.read(128)
        with self.assertRaises(b.Refusal):
            exhausted.debit_external(33554432, 0)
        self.assertEqual(exhausted.bytes, 33554560)
        self.assertTrue(exhausted.external_debited)

    def test_executable_six_role_full_worker_task_ledger(self):
        def run(tree):
            runtime = self.runtime(tree)
            bound = runtime.locate_batch(tree.ids)
            output = 8  # BFREADY marker, charged separately from physical reads
            for index, slot in enumerate(l.ORDER):
                item = bound[slot]
                maximum_tasks = 16 if slot.endswith("16") else 33
                # Independently literal phase counts: PID1 plus15children for
                # finite16, PID1 plus32controls for finite64/unlimited.
                for count in (1, maximum_tasks, maximum_tasks, 1):
                    pids = [200 + index]
                    for child_index in range(1, count):
                        pid = 1000 + index * 100 + child_index
                        if not (tree.proc / str(pid)).exists():
                            tree.make_process(pid, slot, (pid, 7000 + pid, child_index + 1), "owned/" + slot, 1000)
                        pids.append(pid)
                    (tree.cg / "owned" / slot / "cgroup.threads").write_text("".join(str(x) + "\n" for x in pids))
                    (tree.cg / "owned" / slot / "pids.current").write_text(str(count) + "\n")
                    sample = tree.source.snapshot(item.process, item.group)
                    self.assertEqual(sample["current"], count)
                    self.assertEqual(len(sample["task_namespace_ids"]), count)
                    frame_size = len(json.dumps({"sample": sample}, separators=(",", ":")).encode()) + 4
                    tree.source.budget.emit(frame_size)
                    output += frame_size
            runtime.recheck_batch()
            runtime.seal_measurements()
            budget = tree.source.budget
            # This is an executable bounded-source ledger, not native fit.
            self.assertEqual(output - 8, budget.output)
            self.assertLess(output, 65536)
            self.assertGreater(budget.bytes, 8 * 1024 * 1024)
            self.assertLess(budget.bytes, 32 * 1024 * 1024)
            self.assertLess(budget.reads, 65536)
        self.run_tree(True, run)


if __name__ == "__main__":
    unittest.main()
