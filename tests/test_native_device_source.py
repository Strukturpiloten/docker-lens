"""Injected procfs/device metadata only; no daemon, namespace entry or device I/O."""

import contextlib
import errno
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_device_source", ROOT / "scripts/native-device-source.py"
)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
RUN = "Ab12Cd34"
CONTAINER = "dl-native-" + RUN


def process_stat(pid, name, ticks=20):
    return f"{pid} ({name}) S " + "0 " * 18 + f"{ticks}\n"


class Fixture:
    def __init__(self, directory):
        self.path = Path(directory)
        self.host = self.path / "host-proc"
        self.root = self.path / "guest-root"
        self.daemon_root = self.path / "daemon-root"
        self.guest = self.root / "proc"
        self.dev = self.daemon_root / "dev"
        self.host.mkdir()
        self.guest.mkdir(parents=True)
        self.dev.mkdir(parents=True)
        self.dev.joinpath("null").write_text("not an actual device")
        self.exe = self.path / "dockerd"
        self.exe.write_text("not an actual executable")
        self.init_exe = self.path / "systemd"
        self.init_exe.write_text("not an actual executable")
        self.namespaces = {}
        for name in ("mnt", "user", "pid", "other-mnt", "other-user", "other-pid"):
            target = self.path / name
            target.write_text("not an actual namespace")
            self.namespaces[name] = target
        self.process(self.host / "99", 99, "systemd", self.root, self.init_exe)
        self.process(self.guest / "1", 1, "systemd", self.root, self.init_exe)
        self.process(self.guest / "7", 7, "dockerd", self.daemon_root, self.exe, uid=1000, different=True)
        self.action = None
        self.action_calls = 0
        self.null_identity = True
        self.stat_error = None
        self.inspect_calls = []
        self.inspection_change = None
        self.non_proc_paths = set()

    def process(self, directory, pid, name, root, exe, uid=0, different=False):
        directory.mkdir()
        directory.joinpath("comm").write_text(name + "\n")
        directory.joinpath("stat").write_text(process_stat(pid, name))
        directory.joinpath("status").write_text(f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        directory.joinpath("root").symlink_to(root, target_is_directory=True)
        directory.joinpath("exe").symlink_to(exe)
        ns = directory / "ns"
        ns.mkdir()
        for name in HELPER.NAMESPACES:
            target = "other-" + name if different and name in ("mnt", "user") else name
            ns.joinpath(name).symlink_to(self.namespaces[target])

    def inspection(self, command, deadline):
        self.inspect_calls.append((command, deadline))
        values = ["a" * 64, CONTAINER, "true", RUN, "99", '"2026-10-03T10:00:00.123Z"']
        if len(self.inspect_calls) == 2 and self.inspection_change:
            self.inspection_change(values)
        return "|".join(values).encode() + b"\n"

    def reader(self, budget):
        fixture = self

        class Reader(HELPER.ProcReader):
            def leaf(self, dev, name):
                fixture.action_calls += 1
                if fixture.action_calls == 1 and fixture.action:
                    fixture.action()
                return super().leaf(dev, name)

        # Only fake proc and namespace directories/files receive synthetic
        # filesystem types. Production rejects ordinary guest-authored files.
        def filesystem(fd):
            identity = HELPER._key(os.fstat(fd))
            if identity in {HELPER._key(os.stat(path)) for path in fixture.non_proc_paths}:
                return 0
            if identity in {HELPER._key(os.stat(path)) for path in fixture.namespaces.values()}:
                return HELPER.NSFS
            paths = {fixture.host, fixture.guest}
            for root in (fixture.host, fixture.guest):
                for pattern in ("*", "*/ns", "*/comm", "*/stat", "*/status"):
                    paths.update(root.glob(pattern))
            if identity in {HELPER._key(os.stat(path)) for path in paths}:
                return HELPER.PROCFS
            # Root and executable magic-link targets are not procfs objects.
            return 0

        return Reader(budget, str(self.host), filesystem)

    def diagnose(self, mode="rootless", **kwargs):
        real_stat = os.stat
        fixture = self

        def metadata(name, *, dir_fd=None, follow_symlinks=True):
            result = real_stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
            if dir_fd is not None and name == "null" and not follow_symlinks:
                if fixture.stat_error:
                    raise OSError(fixture.stat_error, "protected-secret")
                if fixture.null_identity and stat.S_ISREG(result.st_mode):
                    return types.SimpleNamespace(
                        st_mode=stat.S_IFCHR | 0o666, st_rdev=os.makedev(1, 3),
                        st_dev=result.st_dev, st_ino=result.st_ino,
                        st_ctime_ns=result.st_ctime_ns,
                    )
            return result

        with patch.object(HELPER.os, "stat", side_effect=metadata):
            return HELPER.diagnose(CONTAINER, RUN, mode, reader_factory=self.reader,
                                   runner=self.inspection, euid=lambda: 0, **kwargs)


class DeviceSourceTests(unittest.TestCase):
    def assert_private(self, records):
        text = json.dumps(records)
        self.assertNotIn("protected-secret", text)
        self.assertNotIn(CONTAINER, text)
        self.assertNotIn(RUN, text)
        self.assertNotIn("/", text)
        self.assertEqual([row["role"] for row in records], ["host-null", "renamed-null"])
        for row in records:
            self.assertEqual(set(row), {"role", "scope", "view", "node", "uncertainty",
                                        "runtime_source", "permissions"})
            self.assertEqual(row["scope"], "daemon-view")
            self.assertEqual(row["runtime_source"], "unknown")
            self.assertEqual(row["permissions"], "unknown")

    def assert_unknown(self, records, reason):
        self.assert_private(records)
        self.assertEqual([row["node"] for row in records], ["unknown", "unknown"])
        self.assertEqual([row["uncertainty"] for row in records], [reason, reason])
        self.assertEqual([row["view"] for row in records], ["unknown", "unknown"])

    def test_exact_owned_daemon_view_and_fixed_inspection_only(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            records = fixture.diagnose()
            self.assert_private(records)
            self.assertEqual([row["node"] for row in records], ["null", "missing"])
            self.assertEqual([row["uncertainty"] for row in records], ["none", "none"])
            self.assertEqual([row["view"] for row in records], ["different_mount"] * 2)
            self.assertEqual(len(fixture.inspect_calls), 2)
            command, deadline = fixture.inspect_calls[0]
            self.assertEqual(command, ["podman", "inspect", "--format", HELPER.INSPECT_FORMAT, CONTAINER])
            self.assertEqual(deadline, fixture.inspect_calls[1][1])

    def test_rootful_same_namespace_and_other_device_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            fixture.guest.joinpath("7/status").write_text("Uid:\t0\t0\t0\t0\n")
            fixture.guest.joinpath("7/ns/mnt").unlink()
            fixture.guest.joinpath("7/ns/mnt").symlink_to(fixture.namespaces["mnt"])
            fixture.null_identity = False
            fixture.dev.joinpath("native-null").write_text("protected-secret")
            records = fixture.diagnose("rootful")
            self.assertEqual([row["node"] for row in records], ["other", "other"])
            self.assertEqual([row["view"] for row in records], ["same_mount"] * 2)
            self.assert_private(records)

    def test_genuine_procfs_foreign_daemon_pid_namespace_is_unknown_in_both_modes(self):
        for mode in ("rootful", "rootless"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                if mode == "rootful":
                    fixture.guest.joinpath("7/status").write_text("Uid:\t0\t0\t0\t0\n")
                namespace = fixture.guest / "7/ns/pid"
                namespace.unlink()
                namespace.symlink_to(fixture.namespaces["other-pid"])
                # All process directories and metadata still pass PROCFS checks;
                # the held, valid NSFS target alone belongs to another PID namespace.
                self.assert_unknown(fixture.diagnose(mode), "identity")
                self.assertEqual(fixture.action_calls, 0)

    def test_wrong_uid_executable_or_missing_daemon_remains_unknown(self):
        for fault in ("uid", "exe", "missing"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                if fault == "uid":
                    fixture.guest.joinpath("7/status").write_text("Uid:\t0\t0\t0\t0\n")
                elif fault == "exe":
                    fixture.guest.joinpath("7/exe").unlink()
                    fixture.guest.joinpath("7/exe").symlink_to(fixture.init_exe)
                else:
                    fixture.guest.joinpath("7/comm").write_text("protected-secret\n")
                self.assert_unknown(fixture.diagnose(), "identity")

    def test_process_namespace_root_leaf_and_dev_replacement_invalidate_reads(self):
        for fault in ("outer", "daemon", "namespace", "root", "dev", "leaf", "uid"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)

                def replace():
                    if fault in ("outer", "daemon"):
                        source = fixture.host / "99" if fault == "outer" else fixture.guest / "7"
                        source.rename(source.with_name("old"))
                        source.mkdir()
                    elif fault == "namespace":
                        source = fixture.guest / "7/ns/mnt"
                        source.unlink()
                        source.symlink_to(fixture.namespaces["mnt"])
                    elif fault == "root":
                        source = fixture.guest / "7/root"
                        source.unlink()
                        source.symlink_to(fixture.root)
                    elif fault == "dev":
                        fixture.dev.rename(fixture.dev.with_name("old-dev"))
                        fixture.dev.mkdir()
                    elif fault == "leaf":
                        fixture.dev.joinpath("null").unlink()
                    else:
                        fixture.guest.joinpath("7/status").write_text("Uid:\t1001\t1001\t1001\t1001\n")

                # Replace after the first leaf's snapshot, not before it. The
                # second fixed read is the injected race boundary.
                original_reader = fixture.reader

                def reader(budget):
                    value = original_reader(budget)
                    leaf = value.leaf

                    def changed(dev, name):
                        result = leaf(dev, name)
                        if fixture.action_calls == 1:
                            replace()
                        return result

                    value.leaf = changed
                    return value

                fixture.reader = reader
                self.assert_unknown(fixture.diagnose(), "changed")

    def test_ambiguous_daemon_scan_churn_and_malformed_proc_are_unknown(self):
        for fault, reason in (("ambiguous", "ambiguous"), ("churn", "changed"),
                              ("pid", "proc"), ("stat", "proc"), ("status", "proc"),
                              ("init-correspondence", "proc")):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                if fault in ("ambiguous", "churn"):
                    extra = fixture.guest / "9"
                    if fault == "ambiguous":
                        # Either daemon may be encountered first. Both need a
                        # complete identity; missing references model churn.
                        fixture.process(extra, 9, "dockerd", fixture.daemon_root,
                                        fixture.exe, uid=1000, different=True)
                    else:
                        extra.mkdir()
                elif fault == "pid":
                    fixture.guest.joinpath("07").mkdir()
                elif fault == "stat":
                    fixture.guest.joinpath("7/stat").write_text("protected-secret malformed stat")
                elif fault == "status":
                    fixture.guest.joinpath("7/status").write_text("Uid: 1000 1000 1000 1000\nUid: 0 0 0 0\n")
                else:
                    fixture.guest.joinpath("1/stat").write_text(process_stat(1, "systemd", ticks=21))
                self.assert_unknown(fixture.diagnose(), reason)

    def test_ambiguous_complete_daemons_are_independent_of_proc_scan_order(self):
        real_scandir = os.scandir
        for mode in ("rootful", "rootless"):
            for first in ("1", "7", "9"):
                with self.subTest(mode=mode, first=first), tempfile.TemporaryDirectory() as directory:
                    fixture = Fixture(directory)
                    fixture.process(fixture.guest / "9", 9, "dockerd", fixture.daemon_root,
                                    fixture.exe, uid=1000, different=True)
                    if mode == "rootful":
                        for pid in ("7", "9"):
                            fixture.guest.joinpath(pid, "status").write_text("Uid:\t0\t0\t0\t0\n")

                    def ordered(path):
                        # Descriptor enumeration is the production scan; leave
                        # ordinary-path fixture filesystem checks untouched.
                        if not isinstance(path, int):
                            return real_scandir(path)
                        with real_scandir(path) as entries:
                            rows = sorted(entries, key=lambda row: (row.name != first, row.name))
                        return contextlib.nullcontext(iter(rows))

                    with patch.object(HELPER.os, "scandir", side_effect=ordered):
                        self.assert_unknown(fixture.diagnose(mode), "ambiguous")
                    self.assertEqual(fixture.action_calls, 0)

    def test_symlink_directories_and_leaves_are_never_followed(self):
        for fault in ("proc", "pid", "dev", "leaf"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                if fault == "proc":
                    fixture.guest.rename(fixture.guest.with_name("old-proc"))
                    fixture.guest.symlink_to(fixture.guest.with_name("old-proc"))
                elif fault == "pid":
                    fixture.guest.joinpath("8").symlink_to(fixture.guest / "7")
                elif fault == "dev":
                    fixture.dev.rename(fixture.dev.with_name("old-dev"))
                    fixture.dev.symlink_to(fixture.dev.with_name("old-dev"))
                else:
                    fixture.dev.joinpath("null").unlink()
                    fixture.dev.joinpath("null").symlink_to(fixture.exe)
                records = fixture.diagnose()
                if fault == "leaf":
                    self.assertEqual(records[0]["node"], "unknown")
                    self.assertEqual(records[0]["uncertainty"], "symlink")
                    self.assertEqual(records[1]["node"], "missing")
                    self.assert_private(records)
                else:
                    self.assert_unknown(records, "symlink")

    def test_permission_denial_never_becomes_missing(self):
        for code in (errno.EACCES, errno.EPERM):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                fixture.stat_error = code
                records = fixture.diagnose()
                self.assertEqual(records[0]["node"], "unknown")
                self.assertEqual(records[0]["uncertainty"], "permission")
                self.assertEqual(records[1]["node"], "missing")
                self.assert_private(records)

    def test_non_procfs_and_inaccessible_proc_references_are_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            fixture.reader = lambda budget: HELPER.ProcReader(budget, str(fixture.host), lambda _: 0)
            self.assert_unknown(fixture.diagnose(), "proc")
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            with patch.object(HELPER.os, "open", side_effect=PermissionError(errno.EACCES, "protected-secret")):
                self.assert_unknown(fixture.diagnose(), "permission")

    def test_non_procfs_process_and_namespace_directories_are_unknown(self):
        for process in ("host/99", "guest/1", "guest/7"):
            for leaf in ("", "ns"):
                for phase in ("initial", "verification"):
                    with self.subTest(process=process, leaf=leaf, phase=phase), tempfile.TemporaryDirectory() as directory:
                        fixture = Fixture(directory)
                        root, pid = process.split("/")
                        path = (fixture.host if root == "host" else fixture.guest) / pid / leaf
                        if phase == "initial":
                            fixture.non_proc_paths.add(path)
                        else:
                            fixture.action = lambda: fixture.non_proc_paths.add(path)
                        self.assert_unknown(fixture.diagnose(), "proc")
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            fixture.non_proc_paths.add(fixture.guest)
            self.assert_unknown(fixture.diagnose(), "proc")

    def test_non_procfs_individual_process_metadata_files_are_unknown(self):
        for process in ("host/99", "guest/1", "guest/7"):
            for leaf in ("comm", "stat", "status"):
                for phase in ("initial", "verification"):
                    with self.subTest(process=process, leaf=leaf, phase=phase), tempfile.TemporaryDirectory() as directory:
                        fixture = Fixture(directory)
                        root, pid = process.split("/")
                        path = (fixture.host if root == "host" else fixture.guest) / pid / leaf
                        if phase == "initial":
                            fixture.non_proc_paths.add(path)
                        else:
                            fixture.action = lambda: fixture.non_proc_paths.add(path)
                        self.assert_unknown(fixture.diagnose(), "proc")

    def test_non_procfs_unselected_process_directory_or_comm_is_unknown(self):
        for leaf in ("", "comm"):
            with self.subTest(leaf=leaf), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                fixture.process(fixture.guest / "8", 8, "sleep", fixture.root, fixture.init_exe)
                fixture.non_proc_paths.add(fixture.guest / "8" / leaf)
                self.assert_unknown(fixture.diagnose(), "proc")

    def test_filesystem_identity_reads_only_held_local_descriptors(self):
        # Validate the Linux ABI seam independently of the synthetic proc tree.
        # These are our own read-only references, never an entered namespace.
        for path, expected in (
                ("/proc", HELPER.PROCFS), ("/proc/self", HELPER.PROCFS),
                ("/proc/self/ns", HELPER.PROCFS), ("/proc/self/comm", HELPER.PROCFS),
                ("/proc/self/stat", HELPER.PROCFS), ("/proc/self/status", HELPER.PROCFS),
                ("/proc/self/ns/mnt", HELPER.NSFS)):
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                self.assertEqual(HELPER._filesystem(fd), expected)
            finally:
                os.close(fd)
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_PATH | os.O_CLOEXEC)
            try:
                self.assertNotEqual(HELPER._filesystem(fd), HELPER.PROCFS)
            finally:
                os.close(fd)

    def test_inspection_ownership_replacement_and_malformed_payloads(self):
        for fault in ("id", "label", "pid", "start", "malformed"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                if fault == "id":
                    fixture.inspection_change = lambda values: values.__setitem__(0, "b" * 64)
                    reason = "changed"
                elif fault == "label":
                    fixture.inspection_change = lambda values: values.__setitem__(3, "protected-secret")
                    reason = "identity"
                elif fault == "pid":
                    fixture.inspection_change = lambda values: values.__setitem__(4, "1")
                    reason = "identity"
                elif fault == "start":
                    fixture.inspection_change = lambda values: values.__setitem__(5, '"2026-10-03T10:00:01Z"')
                    reason = "changed"
                else:
                    fixture.inspection = lambda *_: b"protected-secret malformed inspect"
                    reason = "identity"
                self.assert_unknown(fixture.diagnose(), reason)

    def test_closed_input_and_privilege_guard_do_not_inspect(self):
        with patch.object(HELPER.INSPECTION, "bounded_command") as command:
            for values in (("protected-secret", RUN, "rootless"),
                           (CONTAINER, RUN, "protected-secret"),
                           (CONTAINER, "../private", "rootful")):
                self.assert_unknown(HELPER.diagnose(*values, euid=lambda: 0), "input")
            self.assert_unknown(HELPER.diagnose(CONTAINER, RUN, "rootless", euid=lambda: 1000), "privilege")
            command.assert_not_called()

    def test_byte_enumeration_and_time_budgets_fail_closed(self):
        for fault in ("bytes", "entries", "time", "file"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                if fault == "bytes":
                    context = patch.object(HELPER, "BYTE_LIMIT", 32)
                elif fault == "entries":
                    context = patch.object(HELPER, "PROC_LIMIT", 1)
                elif fault == "file":
                    fixture.guest.joinpath("7/status").write_text("protected-secret" * 400)
                    context = patch.object(HELPER, "BYTE_LIMIT", HELPER.BYTE_LIMIT)
                else:
                    context = patch.object(HELPER, "SECONDS", 0)
                with context:
                    self.assert_unknown(fixture.diagnose(), "budget")

    def test_all_held_descriptors_close_after_success_and_failure(self):
        for fault in (False, True):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                if fault:
                    fixture.action = lambda: fixture.guest.joinpath("7/status").write_text("protected-secret")
                before = set(os.listdir("/proc/self/fd"))
                fixture.diagnose()
                self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_inspection_timeout_and_output_overflow_reap_private_subprocess(self):
        for fault in ("timeout", "overflow"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                pid_path = Path(directory) / "private-child-pid"
                program = (
                    "import os,sys,time; "
                    "open(sys.argv[1],'w').write(str(os.getpid())); "
                    + ("print('protected-secret',flush=True); time.sleep(10)" if fault == "timeout"
                       else "print('protected-secret'*900,flush=True); time.sleep(10)")
                )
                original = HELPER.INSPECTION.bounded_command

                def command(_argv, deadline, budget):
                    return original([sys.executable, "-c", program, str(pid_path)], deadline, budget)

                with patch.object(HELPER, "SECONDS", 0.7), patch.object(
                    HELPER.INSPECTION, "bounded_command", side_effect=command
                ):
                    started = time.monotonic()
                    records = HELPER.diagnose(CONTAINER, RUN, "rootless", euid=lambda: 0)
                    self.assertLess(time.monotonic() - started, 1.5)
                    self.assert_unknown(records, "io")
                pid = int(pid_path.read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)

    def test_fixed_cli_records_never_print_arguments(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/native-device-source.py"),
             "protected-secret", RUN, "rootless"],
            capture_output=True, text=True, timeout=2, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 2)
        self.assertNotIn("protected-secret", result.stdout)
        self.assertNotIn(RUN, result.stdout)
        self.assertIn("scope=daemon-view view=unknown node=unknown uncertainty=input", result.stdout)
        self.assertIn("runtime_source=unknown permissions=unknown", result.stdout)

    def test_inspection_cleanup_exception_never_prints_private_argv(self):
        with patch.object(HELPER.INSPECTION, "bounded_command", side_effect=subprocess.TimeoutExpired(
            ["protected-secret"], 0.1
        )):
            self.assert_unknown(HELPER.diagnose(CONTAINER, RUN, "rootless", euid=lambda: 0), "io")

    def test_cli_cancellation_reaps_inspection_and_reports_only_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "private-child-pid"
            program = """import functools, importlib.util, sys
spec = importlib.util.spec_from_file_location('helper', sys.argv[1])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
original = helper.INSPECTION.bounded_command
pid_path = sys.argv[2]
child = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); print('protected-secret',flush=True); time.sleep(10)"
def command(argv, deadline, budget):
    return original([sys.executable, '-c', child, pid_path], deadline, budget)
helper.INSPECTION.bounded_command = command
helper.diagnose = functools.partial(helper.diagnose, euid=lambda: 0)
sys.argv = ['helper', 'dl-native-Ab12Cd34', 'Ab12Cd34', 'rootless']
helper.main()
"""
            process = subprocess.Popen(
                [sys.executable, "-c", program, str(ROOT / "scripts/native-device-source.py"), str(pid_path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                deadline = time.monotonic() + 2
                while not pid_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pid_path.exists())
                pid = int(pid_path.read_text())
                process.terminate()
                stdout, stderr = process.communicate(timeout=2)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(stderr, "")
                self.assertEqual(len(stdout.splitlines()), 2)
                self.assertIn("node=unknown uncertainty=budget", stdout)
                self.assertNotIn("protected-secret", stdout)
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=2)

    def test_proc_parsers_and_failure_strings_are_closed(self):
        self.assertEqual(HELPER._start_ticks(process_stat(7, "dockerd").encode(), 7), 20)
        self.assertEqual(HELPER._uid(b"Uid:\t1000\t1000\t1000\t1000\n"), 1000)
        for value in ("0", "07", "../7", "2147483648", "protected-secret"):
            with self.subTest(value=value), self.assertRaises(HELPER.Uncertain) as failure:
                HELPER._pid(value)
            self.assertEqual(str(failure.exception), "proc")
        for payload in (b"Uid: secret", b"Uid: 0 0 0 0\nUid: 0 0 0 0\n",
                        b"Uid: 0 4294967295 0 0\n", b"\xff"):
            with self.subTest(payload=payload), self.assertRaises(HELPER.Uncertain) as failure:
                HELPER._uid(payload)
            self.assertEqual(str(failure.exception), "proc")
        for payload in (process_stat(7, "dockerd").replace(") S ", ") ? ").encode(),
                        process_stat(7, "dockerd").replace(") S ", ") Z ").encode(),
                        process_stat(8, "dockerd").encode()):
            with self.subTest(payload=payload), self.assertRaises(HELPER.Uncertain):
                HELPER._start_ticks(payload, 7)


if __name__ == "__main__":
    unittest.main()
