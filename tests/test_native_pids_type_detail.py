"""Independent finite type observations; authored fixtures are not native proof."""
import ast
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from native_pids_type_detail_support import normalized_type_metadata
import test_native_pids_locator as locator_tests
b, l = locator_tests.b, locator_tests.l

DETAILS = ("o_time", "o_fds", "o_opens", "o_other", "m_syscall", "m_guard", "m_other",
    "r_time", "r_reads", "r_bytes", "r_cap", "r_other", "d_domain", "d_domthr", "d_dominv",
    "d_thread", "d_other", "cleanup")


class TypeDetailTests(unittest.TestCase):
    def test_every_altered_method_matches_frozen_source_after_only_metadata_erasure(self):
        raw = (Path(__file__).parent / "fixtures/native_pids_type_detail_baseline_methods.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "518b3821527e594a0ee396ab049fdb94abcb2754463d89d44261917e8dbdf1f5")
        fixture = json.loads(raw)
        self.assertEqual(fixture["source_commit"], "ea69314435b036c94afb84ed8d09ba6ff967d583")
        self.assertEqual(len(fixture["methods"]), 10)
        for name, record in fixture["methods"].items():
            with self.subTest(method=name):
                self.assertEqual(hashlib.sha256(record["method_source"].encode()).hexdigest(), record["method_source_utf8_sha256"])
                tree = ast.parse((Path(__file__).resolve().parents[1] / record["source_path"]).read_text())
                body = tree.body if record["class_name"] is None else next(n.body for n in tree.body if isinstance(n, ast.ClassDef) and n.name == record["class_name"])
                current = next(n for n in body if isinstance(n, ast.FunctionDef) and n.name == record["method_name"])
                original = ast.parse("class Frozen:\n" + record["method_source"]).body[0].body[0] if record["class_name"] else ast.parse(record["method_source"]).body[0]
                if name == "_group_escape":
                    self.assertEqual([ast.dump(n) for n in current.decorator_list], ["Name(id='contextmanager', ctx=Load())"])
                    current.decorator_list = []
                self.assertEqual(ast.dump(normalized_type_metadata(current)), ast.dump(original))

    def test_metadata_erasure_rejects_unknown_wrappers_plumbing_and_branch_work(self):
        for statement in ('return _observe(value, other, "time")', 'return _observe(value, observer, "secret")',
                'return _observe(value, observer, "time", extra)',
                'if observer is None:\n    original()\nelse:\n    extra()'):
            method = ast.parse('def check(observer=None):\n' + '\n'.join('    ' + line for line in statement.splitlines())).body[0]
            with self.assertRaises(AssertionError):
                normalized_type_metadata(method)

    def current_method(self, owner, name):
        tree = ast.parse(Path(b.__file__).read_text())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == owner)
        return next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == name)

    def test_metadata_erasure_rejects_actual_native_call_keyword_mutations(self):
        for owner, method_name, callee in (("LinuxSource", "read_fd", "os.read"),
                ("LinuxSource", "read_fd", "os.lseek"), ("LinuxSource", "open", "os.open"),
                ("Budget", "check", "self.clock")):
            with self.subTest(owner=owner, method=method_name, callee=callee):
                method = self.current_method(owner, method_name)
                call = next(node for node in ast.walk(method) if isinstance(node, ast.Call)
                    and ast.dump(node.func) == ast.dump(ast.parse(callee, mode="eval").body))
                call.keywords.append(ast.keyword(arg="observer", value=ast.Name(id="observer", ctx=ast.Load())))
                with self.assertRaisesRegex(AssertionError, "unreviewed observer/detail"):
                    normalized_type_metadata(method)

    def test_metadata_erasure_rejects_unconditional_actual_forwarding(self):
        for owner, method_name in (("Budget", "read"), ("Budget", "fd"),
                ("LinuxSource", "open"), ("LinuxSource", "read_fd")):
            with self.subTest(owner=owner, method=method_name):
                method = self.current_method(owner, method_name)
                position = next(index for index, node in enumerate(method.body) if isinstance(node, ast.If)
                    and ast.dump(node.test) == ast.dump(ast.parse("observer is None", mode="eval").body))
                # Same reviewed callee and argument values, but the old default
                # one-argument seam has been replaced by unconditional forwarding.
                method.body[position:position + 1] = method.body[position].orelse
                with self.assertRaisesRegex(AssertionError, "unreviewed observer/detail"):
                    normalized_type_metadata(method)

    def test_metadata_erasure_rejects_altered_actual_forwarding_context_and_arguments(self):
        for mutation in ("callee", "positional", "observer", "default", "condition"):
            with self.subTest(mutation=mutation):
                method = self.current_method("LinuxSource", "read_fd")
                branch = next(node for node in method.body if isinstance(node, ast.If))
                call = branch.orelse[0].value
                if mutation == "callee":
                    # A function named read on another object is not an approved edge.
                    call.func.value = ast.parse("self.other", mode="eval").body
                elif mutation == "positional":
                    call.args[0] = ast.Constant(value=1)
                elif mutation == "observer":
                    call.keywords[0].value = ast.Name(id="detail", ctx=ast.Load())
                elif mutation == "default":
                    branch.body[0].value.keywords.append(ast.keyword(arg="observer",
                        value=ast.Name(id="observer", ctx=ast.Load())))
                else:
                    branch.test.ops[0] = ast.IsNot()
                with self.assertRaisesRegex(AssertionError, "unreviewed observer/detail"):
                    normalized_type_metadata(method)

    def test_metadata_erasure_rejects_unconditional_or_altered_actual_type_forwarding(self):
        for mutation in ("unconditional_open", "unconditional_predicate", "open_parent", "read_cap"):
            with self.subTest(mutation=mutation):
                method = self.current_method("LinuxSource", "check_group")
                scope = method.body[-1]
                if mutation == "unconditional_open":
                    scope.body[0:1] = scope.body[0].orelse
                elif mutation == "unconditional_predicate":
                    body = scope.body[1].body
                    body[0:1] = body[0].orelse
                else:
                    branch = scope.body[0] if mutation == "open_parent" else scope.body[1].body[0]
                    callee = "self.open" if mutation == "open_parent" else "self.read_fd"
                    call = next(node for node in ast.walk(branch.orelse[0]) if isinstance(node, ast.Call)
                        and ast.dump(node.func) == ast.dump(ast.parse(callee, mode="eval").body))
                    call.args[1] = ast.Constant(value=0 if mutation == "open_parent" else 33)
                with self.assertRaisesRegex(AssertionError, "unreviewed observer/detail"):
                    normalized_type_metadata(method)

    def run_case(self, token, *, cleanup=False, observed=True, metadata=None, classify=False):
        result = []
        real_magic = b.fs_magic
        def run(tree):
            source = tree.source
            process = source.process(100, 1000)
            group = source.group(process)
            path = tree.cg / "owned/cgroup.type"
            bodies = {"d_domain": b"domain\n", "d_domthr": b"domain threaded\n",
                "d_dominv": b"domain invalid\n", "d_thread": b"threaded\n", "d_other": b"domain"}
            if token in bodies:
                path.write_bytes(bodies[token])
            if token == "r_cap":
                path.write_bytes(b"x" * 33)
            original_open, original_read, original_close = source.open, source.read_fd, source.close_fd
            original_require, original_startup = b.require, b.startup_require
            errors, records, type_fds, trace = [], [], set(), []
            work_error, close_error = RuntimeError("PRIVATE_WORK"), RuntimeError("PRIVATE_CLOSE")
            completed = False
            checkpoints = {}
            original_clock = source.budget.clock
            def clock():
                trace.append("clock")
                return original_clock()
            def expired():
                trace.append("clock")
                return source.budget.work_ns
            source.budget.clock = clock
            def open_file(name, *args, **kwargs):
                if name == "cgroup.type":
                    trace.append("type.open")
                    checkpoints["open"] = (source.budget.fds, source.budget.opens)
                    if token == "o_time":
                        source.budget.clock = expired
                    elif token == "o_fds":
                        source.budget.fds = 256
                    elif token == "o_opens":
                        source.budget.opens = 32768
                    elif token == "o_other":
                        raise work_error
                fd = original_open(name, *args, **kwargs)
                if name == "cgroup.type":
                    type_fds.add(fd)
                return fd
            def magic(fd, observer=None):
                if fd not in type_fds:
                    return tree.magic(fd)
                trace.append("type.magic")
                if token == "m_other":
                    raise work_error
                if token == "m_syscall":
                    with patch.object(b.ctypes, "CDLL", return_value=SimpleNamespace(fstatfs=lambda *_: -1)):
                        try:
                            return real_magic(fd, observer=observer)
                        except BaseException as error:
                            errors.append(error)
                            raise
                return 0 if token == "m_guard" else b.CGROUP_MAGIC
            def read(fd, maximum, **kwargs):
                nonlocal completed
                if fd in type_fds:
                    trace.append("type.read")
                    checkpoints["read"] = (source.budget.reads, source.budget.bytes)
                    if token == "r_time":
                        source.budget.clock = expired
                    elif token == "r_reads":
                        source.budget.reads = 65536
                    elif token == "r_bytes":
                        source.budget.bytes = b.SOURCE_BYTES
                    elif token == "r_other":
                        raise work_error
                body = original_read(fd, maximum, **kwargs)
                if fd in type_fds:
                    completed = True
                return body
            def require(condition):
                if completed and token == "d_domain" and condition is True:
                    raise work_error
                try:
                    return original_require(condition)
                except BaseException as error:
                    errors.append(error)
                    raise
            def startup(site, condition):
                try:
                    return original_startup(site, condition)
                except BaseException as error:
                    errors.append(error)
                    raise
            def close(fd):
                original_close(fd)
                if fd in type_fds:
                    trace.append("type.close")
                    if cleanup:
                        raise close_error
            with patch.object(source, "open", side_effect=open_file), patch.object(source, "read_fd", side_effect=read), \
                    patch.object(source, "close_fd", side_effect=close), patch.object(b, "fs_magic", side_effect=magic), \
                    patch.object(b, "require", side_effect=require), patch.object(b, "startup_require", side_effect=startup):
                from contextlib import ExitStack
                with ExitStack() as stack:
                    if metadata is not None:
                        if metadata.get("factory"):
                            stack.enter_context(patch.object(b, "_type_observation", return_value=None))
                        else:
                            stack.enter_context(patch.object(b._TypeObservation, "note", **metadata))
                    if classify:
                        stack.enter_context(patch.object(b, "_group_exception_tag", side_effect=KeyboardInterrupt("PRIVATE_CLASSIFIER")))
                    try:
                        source.check_group(group, observer=(lambda *pair: records.append(pair)) if observed else None)
                    except BaseException as caught:
                        expected = close_error if cleanup else (errors[0] if errors else work_error)
                        self.assertIs(caught, expected)
                    else:
                        self.fail("injected or false-predicate failure must escape")
            if token == "o_time":
                self.assertEqual((source.budget.fds, source.budget.opens), checkpoints["open"])
            elif token == "o_fds":
                self.assertEqual((source.budget.fds, source.budget.opens), (257, checkpoints["open"][1] + 1))
            elif token == "o_opens":
                self.assertEqual((source.budget.fds, source.budget.opens), (checkpoints["open"][0] + 1, 32769))
            elif token == "r_time":
                self.assertEqual((source.budget.reads, source.budget.bytes), checkpoints["read"])
            elif token == "r_reads":
                self.assertEqual((source.budget.reads, source.budget.bytes), (65537, checkpoints["read"][1] + 33))
            elif token == "r_bytes":
                self.assertEqual((source.budget.reads, source.budget.bytes), (checkpoints["read"][0] + 1, b.SOURCE_BYTES + 33))
            elif token == "r_cap":
                self.assertEqual((source.budget.reads, source.budget.bytes), (checkpoints["read"][0] + 1, checkpoints["read"][1] + 33))
            expected = ("gv_type", "unclassified")
            if observed and metadata is None and not classify:
                expected += ("cleanup" if cleanup else token,)
            self.assertEqual(records, [expected] if observed else [])
            if token in ("m_guard", "m_syscall", "m_other"):
                self.assertNotIn("type.read", trace)
            if token.startswith("o_"):
                self.assertNotIn("type.close", trace)
            else:
                self.assertEqual(trace.count("type.close"), 1)
            result.append((tuple(trace), tuple(getattr(source.budget, name) for name in
                ("reads", "bytes", "fds", "opens", "peak_fds", "deadline_ns", "work_ns")), len(source.owned)))
        locator_tests.LocatorTests().run_tree(True, run)
        return result[0]

    def test_all_eighteen_independent_details_and_failed_charge_retention(self):
        for token in DETAILS:
            with self.subTest(detail=token):
                self.run_case(token, cleanup=token == "cleanup")

    def test_observed_default_failure_work_order_and_ledgers_match(self):
        for token in DETAILS:
            with self.subTest(detail=token):
                self.assertEqual(self.run_case(token, cleanup=token == "cleanup", observed=False),
                    self.run_case(token, cleanup=token == "cleanup", observed=True))

    def test_cleanup_supersedes_every_post_open_work_detail(self):
        for token in DETAILS[4:-1]:
            with self.subTest(detail=token):
                self.run_case(token, cleanup=True)

    def test_missing_or_hostile_metadata_and_classifier_failure_keep_honest_bare_record(self):
        for token in ("m_guard", "d_other", "r_cap", "cleanup"):
            for metadata in ({"return_value": None}, {"side_effect": KeyboardInterrupt("PRIVATE_METADATA")}, {"factory": True}):
                self.run_case(token, cleanup=token == "cleanup", metadata=metadata)
            self.run_case(token, cleanup=token == "cleanup", classify=True)
        with patch.object(b, "_TypeObservation", side_effect=KeyboardInterrupt("PRIVATE_FACTORY")):
            self.assertIsNone(b._type_observation(lambda *_: None))

    def test_known_errors_hostile_callback_and_classifier_never_retry_or_read_error(self):
        reads = []
        class Hostile(OSError):
            def __getattribute__(self, name):
                reads.append(name)
                raise AssertionError("PRIVATE_ATTRIBUTE")
        for token in DETAILS:
            for known in (False, True):
                for classifier_fails in (False, True):
                    failure = PermissionError(13, "PRIVATE_ERROR") if known else Hostile()
                    detail, attempts = b._TypeObservation(), []
                    detail.token = token
                    def observer(*record):
                        attempts.append(record)
                        raise KeyboardInterrupt("PRIVATE_CALLBACK")
                    from contextlib import ExitStack
                    with ExitStack() as stack:
                        if classifier_fails:
                            stack.enter_context(patch.object(b, "_group_exception_tag", side_effect=KeyboardInterrupt("PRIVATE_CLASSIFIER")))
                        try:
                            with b._group_escape(observer, "gv_type", detail=detail):
                                raise failure
                        except BaseException as caught:
                            self.assertIs(caught, failure)
                        else:
                            self.fail("must escape")
                    expected = ("gv_type", "EACCES" if known and not classifier_fails else "unclassified")
                    if not known and not classifier_fails:
                        expected += (token,)
                    self.assertEqual(attempts, [expected])
        self.assertEqual(reads, [])

    def test_default_none_preserves_old_budget_primitive_fakes(self):
        budget = b.Budget(180_000_000_001, lambda: 1)
        calls = []
        budget.check = lambda: calls.append("check")
        budget.fd(); budget.fd(observer=None)
        budget.read(9); budget.read(9, observer=None)
        self.assertEqual(calls, ["check"] * 4)
        import tempfile
        source = object.__new__(b.LinuxSource)
        source.owned = set()
        source.budget = SimpleNamespace(fd=lambda: calls.append("fd"), read=lambda n: calls.append(("read", n)), fds=0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "body"
            path.write_bytes(b"x")
            fd = source.open(str(path))
            self.assertEqual(source.read_fd(fd, 8), b"x")
            source.close_fd(fd)
        self.assertEqual(calls[4:], ["fd", ("read", 9), ("read", 8)])

    def test_partial_reads_keep_identical_syscalls_clocks_charges_and_return_identity(self):
        results = []
        for observed in (False, True):
            clocks = []
            def clock():
                clocks.append("clock")
                return 1
            source = object.__new__(b.LinuxSource)
            source.budget = b.Budget(180_000_000_001, clock)
            detail = b._TypeObservation() if observed else None
            if detail is not None:
                detail.token = "r_other"
            with patch.object(b.os, "lseek") as seek, patch.object(b.os, "read", side_effect=[b"dom", b"ain\n", b""]) as read:
                body = source.read_fd(8, 32, observer=detail) if observed else source.read_fd(8, 32)
            self.assertEqual(body, b"domain\n")
            self.assertEqual(seek.call_args.args, (8, 0, os.SEEK_SET))
            self.assertEqual([call.args for call in read.call_args_list], [(8, 33), (8, 30), (8, 26)])
            self.assertEqual((source.budget.reads, source.budget.bytes), (3, 89))
            self.assertEqual(clocks, ["clock"] * 4)
            results.append((body, seek.call_count, read.call_args_list, source.budget.reads, source.budget.bytes, clocks))
        self.assertEqual(results[0], results[1])

    def test_type_detail_catalogue_matches_all_four_closed_definitions(self):
        import re
        root = Path(__file__).resolve().parents[1]
        from test_native_pids_supervisor import s
        self.assertEqual(b._TYPE_DETAILS, DETAILS)
        self.assertEqual(s.HOST_TYPE_DETAILS, DETAILS)
        rust = (root / "src/native_pids_tests.rs").read_text()
        catalog = rust.split("const HOST_TYPE_DETAILS:", 1)[1].split("];", 1)[0]
        self.assertEqual(re.findall(r'"([a-z_]+)"', catalog), list(DETAILS))
        wrapper = (root / "scripts/run-exact-native-test.sh").read_text()
        self.assertEqual(re.search(r'host_type_details = set\(b"([a-z_ ]+)"\.split\(\)\)', wrapper)[1].split(), list(DETAILS))

    def test_type_whitelist_exact_bytes_and_identity_wrapper(self):
        cases = ((b"domain\n", "d_domain"), (b"domain threaded\n", "d_domthr"),
            (b"domain invalid\n", "d_dominv"), (b"threaded\n", "d_thread"),
            (b"", "d_other"), (b"domain", "d_other"), (b"domain\r\n", "d_other"), (b"threaded\nPRIVATE", "d_other"))
        for body, token in cases:
            detail = b._TypeObservation()
            self.assertIs(b._observe(body, detail, "domain"), body)
            self.assertEqual(detail.token, token)
        class Hostile(bytes):
            def __eq__(self, other):
                raise AssertionError("must not compare subclass")
            __hash__ = bytes.__hash__
        body = Hostile(b"domain\n")
        detail = b._TypeObservation()
        self.assertIs(b._observe(body, detail, "domain"), body)
        self.assertFalse(detail.valid)


if __name__ == "__main__":
    unittest.main()
