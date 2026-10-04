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

    def test_context_root_timer_deadline_output_cap_and_closed_validation(self):
        expected = HELPER._context_unknown()
        expected[0].update(outcome="observed", memory_controller="present", memory_max="finite")
        expected[2].update(view="different_mount", node="null", uncertainty="none")
        expected[3].update(view="different_mount", node="missing", uncertainty="none")
        payload = HELPER._format_context(expected).encode()
        for sudo in ("0", "1"):
            calls = []

            def capture(command, deadline, **kwargs):
                calls.append((command, deadline, kwargs))
                return payload

            self.assertEqual(HELPER.context(CONTAINER, RUN, "rootless", sudo,
                                           clock=lambda: 10, monotonic=lambda: 10,
                                           euid=lambda: 1000 if sudo == "1" else 0,
                                           runner=capture, lane="upstream-rootless"), expected)
            command, deadline, options = calls[0]
            offset = 2 if sudo == "1" else 0
            self.assertEqual(command[:offset], ["sudo", "-n"] if offset else [])
            self.assertEqual(command[offset:offset + 3],
                             ["timeout", "--signal=TERM", "--kill-after=0.2"])
            self.assertEqual(command[offset + 3], "4.300")
            self.assertEqual(command[offset + 6:],
                             ["--batch", CONTAINER, RUN, "rootless", "14.300000", "upstream-rootless"])
            self.assertEqual(deadline, 15)
            self.assertEqual(options, {"elevated_until": 14.8, "capture_limit": 2048,
                                       "start_new_session": False, "reap_monitor": sudo == "1",
                                       "stdin_lifeline": True})
            self.assertNotIn("exec", command)

        lines = payload.splitlines(keepends=True)
        for invalid in (payload + b"protected-secret\n", b"".join(lines[:3]),
                        b"".join(lines[:2] + [lines[2], lines[2]]),
                        payload.replace(b"runtime_source=unknown", b"runtime_source=known"),
                        payload.replace(b"node=null", b"node=null secret=protected-secret"),
                        payload.replace(b"scope=daemon-view", b"scope=/protected-secret"),
                        b"\xff", b"protected-secret" * 200):
            with self.subTest(invalid=invalid[:50]):
                result = HELPER.context(CONTAINER, RUN, "rootless", "0", clock=lambda: 10,
                                        runner=lambda *_args, **_kwargs: invalid, lane="upstream-rootless")
                self.assertEqual(result, HELPER._context_unknown())
                self.assertNotIn("protected-secret", HELPER._format_context(result))

    def test_context_requires_explicit_canonical_mode_matching_lane(self):
        for lane in (None, "unknown", "debian11-rootful", "upstream-rootful"):
            capture = unittest.mock.Mock()
            self.assertEqual(HELPER.context(CONTAINER, RUN, "rootless", "0", lane=lane,
                                           runner=capture), HELPER._context_unknown("input"))
            capture.assert_not_called()
            with patch.object(HELPER.INSPECTION, "diagnose") as cgroup, patch.object(
                HELPER, "diagnose"
            ) as source:
                self.assertEqual(HELPER.batch(CONTAINER, RUN, "rootless", 14, lane=lane,
                                             clock=lambda: 10, euid=lambda: 0),
                                 HELPER._context_unknown("input"))
                cgroup.assert_not_called()
                source.assert_not_called()

    def test_context_expired_startup_invalid_input_and_nonzero_capture_never_leak(self):
        for args in ((CONTAINER, RUN, "rootless", "2"),
                     ("protected-secret", RUN, "rootless", "0")):
            capture = unittest.mock.Mock()
            self.assertEqual(HELPER.context(*args, runner=capture, lane="upstream-rootless"), HELPER._context_unknown("input"))
            capture.assert_not_called()
        times = iter((10, 14.1))
        capture = unittest.mock.Mock()
        self.assertEqual(HELPER.context(CONTAINER, RUN, "rootless", "0",
                                       clock=lambda: next(times), runner=capture, lane="upstream-rootless"), HELPER._context_unknown())
        capture.assert_not_called()
        for error in (HELPER.INSPECTION.Unavailable(), PermissionError("protected-secret"),
                      subprocess.TimeoutExpired(["protected-secret"], 1)):
            with patch.object(HELPER.INSPECTION, "bounded_command", side_effect=error):
                self.assertEqual(HELPER.context(CONTAINER, RUN, "rootless", "0", lane="upstream-rootless"),
                                 HELPER._context_unknown())

    def test_batch_slices_share_absolute_deadline_and_skip_exhausted_or_cancelled(self):
        for elapsed, cancel in ((0, False), (3.5, False), (0, True)):
            with self.subTest(elapsed=elapsed, cancel=cancel):
                now = [10 + elapsed]
                interrupted = [False]
                calls, alarms = [], []

                def cgroup(_container, _run, _mode, podman, *, deadline, lane):
                    self.assertEqual(podman, ["podman"])
                    self.assertLessEqual(deadline - now[0], 2)
                    self.assertLessEqual(deadline, 14.3)
                    calls.append(("cgroup", deadline))
                    now[0] = deadline
                    interrupted[0] = cancel
                    return HELPER._context_unknown()[:2]

                def source(_container, _run, _mode, *, deadline):
                    self.assertLessEqual(deadline - now[0], 2)
                    self.assertLessEqual(deadline, 14.3)
                    calls.append(("source", deadline))
                    now[0] = deadline
                    return HELPER._unknown("identity")

                with patch.object(HELPER.INSPECTION, "diagnose", side_effect=cgroup), patch.object(
                    HELPER, "diagnose", side_effect=source
                ):
                    records = HELPER.batch(CONTAINER, RUN, "rootless", 14.3,
                                           clock=lambda: now[0], monotonic=lambda: now[0],
                                           euid=lambda: 0, alarm=alarms.append,
                                           interrupted=lambda: interrupted[0], lane="upstream-rootless")
                self.assertEqual([name for name, _ in calls],
                                 ["cgroup"] if elapsed or cancel else ["cgroup", "source"])
                self.assertEqual(alarms[-1], 0)
                self.assertLessEqual(max(alarms), 1.8)
                self.assertLessEqual(now[0], 14.3)
                if cancel or elapsed:
                    self.assertEqual(records, HELPER._context_unknown())
        with patch.object(HELPER.INSPECTION, "diagnose") as cgroup:
            self.assertEqual(HELPER.batch(CONTAINER, RUN, "rootless", 9,
                                         clock=lambda: 10, euid=lambda: 0, lane="upstream-rootless"), HELPER._context_unknown())
            self.assertEqual(HELPER.batch(CONTAINER, RUN, "rootless", 15,
                                         clock=lambda: 10, euid=lambda: 1000, lane="upstream-rootless"),
                             HELPER._context_unknown("privilege"))
            cgroup.assert_not_called()

    def test_supplied_device_deadline_is_not_restarted(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            self.assert_unknown(fixture.diagnose(clock=lambda: 10, deadline=9), "budget")
            self.assertEqual(fixture.inspect_calls, [])
            records = fixture.diagnose(clock=lambda: 10, deadline=11)
            self.assertEqual([row[1] for row in fixture.inspect_calls], [11, 11])
            self.assertEqual(records[0]["node"], "null")
            fixture.inspect_calls.clear()
            fixture.diagnose(clock=lambda: 10, deadline=100)
            self.assertEqual([row[1] for row in fixture.inspect_calls], [15, 15])

    def test_phase_boot_clock_offset_converts_to_reader_monotonic_deadlines(self):
        boot, mono = [100.0], [10.0]
        deadlines = []

        def reader(*args, deadline, **kwargs):
            deadlines.append(deadline)
            boot[0] += 2
            mono[0] += 2
            return HELPER._context_unknown()[:2]

        with patch.object(HELPER.INSPECTION, "diagnose", side_effect=reader), patch.object(
            HELPER, "diagnose", side_effect=reader
        ):
            HELPER.batch(CONTAINER, RUN, "rootless", 104.3, clock=lambda: boot[0],
                         monotonic=lambda: mono[0], euid=lambda: 0, alarm=lambda _: None, lane="upstream-rootless")
        self.assertEqual(deadlines, [12, 14])
        calls = []

        def capture(command, deadline, **kwargs):
            calls.append((command, deadline, kwargs))
            return HELPER._format_context(HELPER._context_unknown()).encode()

        HELPER.context(CONTAINER, RUN, "rootless", "1", deadline=109,
                       clock=lambda: 104, monotonic=lambda: 14, runner=capture, lane="upstream-rootless")
        command, deadline, options = calls[0]
        self.assertEqual(command[-2:], ["108.300000", "upstream-rootless"])
        self.assertEqual(deadline, 19)
        self.assertEqual(options["elevated_until"], 18.8)

    def test_delayed_root_bootstrap_never_reads_after_absolute_cutoff(self):
        now = [100.0]
        alarm = unittest.mock.Mock()
        with patch.object(HELPER.INSPECTION, "diagnose") as cgroup, patch.object(
            HELPER, "diagnose"
        ) as source:
            # The root child starts after caller/interpreter/sudo delay. Its
            # absolute deadline is stale; it must not start a fresh2s slice.
            self.assertEqual(HELPER.batch(CONTAINER, RUN, "rootless", 99,
                                         clock=lambda: now[0], monotonic=lambda: 10,
                                         euid=lambda: 0, alarm=alarm, lane="upstream-rootless"), HELPER._context_unknown())
            cgroup.assert_not_called()
            source.assert_not_called()
            alarm.assert_not_called()
        with patch.object(HELPER, "phase_clock", return_value=100), patch.object(
            sys, "argv", ["helper", "--context", CONTAINER, RUN, "rootless", "1", "99.0", "upstream-rootless"]
        ), patch.object(HELPER, "context") as context, patch("builtins.print") as output:
            HELPER.main()
            context.assert_not_called()
            self.assertNotIn(CONTAINER, str(output.call_args))

        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "unexpected-read"
            done = Path(directory) / "bootstrap-complete"
            original = HELPER.INSPECTION.bounded_command
            program = """import importlib.util, sys, time
from pathlib import Path
time.sleep(1)
spec = importlib.util.spec_from_file_location('helper', sys.argv[1])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
def unexpected(*args, **kwargs):
    Path(sys.argv[3]).write_text('unexpected-read')
    return helper._unknown('identity')
helper.diagnose = unexpected
helper.INSPECTION.diagnose = unexpected
records = helper.batch('dl-native-Ab12Cd34', 'Ab12Cd34', 'rootless', float(sys.argv[2]), lane='upstream-rootless',
                       euid=lambda: 0, alarm=lambda _: None)
Path(sys.argv[4]).write_text('done')
print(helper._format_context(records), end='')
"""

            def delayed(command, deadline, **kwargs):
                # Simulate sudo/root interpreter startup exceeding the already
                # forwarded work cutoff; no actual elevation/runtime is used.
                return original([sys.executable, "-c", program,
                                 str(ROOT / "scripts/native-device-source.py"),
                                 command[-2], str(marker), str(done)], deadline, **kwargs)

            with patch.object(HELPER, "SECONDS", 2), patch.object(HELPER, "PHASE_RESERVE", 1.2):
                self.assertEqual(HELPER.context(CONTAINER, RUN, "rootless", "1", runner=delayed, lane="upstream-rootless"),
                                 HELPER._context_unknown())
            self.assertTrue(done.exists())
            self.assertFalse(marker.exists())

    def test_context_monitor_kill_permission_failure_is_private_unknown(self):
        original_popen = subprocess.Popen
        original_capture = HELPER.INSPECTION.bounded_command
        processes = []

        def spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            process.wait(timeout=1)
            process.wait = unittest.mock.Mock(side_effect=subprocess.TimeoutExpired("protected-secret", 1))
            process.kill = unittest.mock.Mock(side_effect=PermissionError("protected-secret"))
            processes.append(process)
            return process

        def capture(_command, deadline, **kwargs):
            return original_capture([sys.executable, "-c", "pass"], deadline, **kwargs)

        with patch.object(HELPER, "SECONDS", 0.8), patch.object(HELPER, "PHASE_RESERVE", 0.3), patch.object(
            HELPER.INSPECTION.subprocess, "Popen", side_effect=spawn
        ):
            self.assertEqual(HELPER.context(CONTAINER, RUN, "rootless", "1",
                                           euid=lambda: 1000, runner=capture, lane="upstream-rootless"), HELPER._context_unknown())
        self.assertEqual(len(processes), 1)
        processes[0].kill.assert_called_once()
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

    def test_batch_lifeline_requires_open_empty_fifo(self):
        read_fd, write_fd = os.pipe()
        try:
            self.assertTrue(HELPER._caller_alive(read_fd))
            os.write(write_fd, b"protected-secret")
            self.assertFalse(HELPER._caller_alive(read_fd))
        finally:
            os.close(read_fd)
            os.close(write_fd)
        read_fd, write_fd = os.pipe()
        try:
            os.close(write_fd)
            self.assertFalse(HELPER._caller_alive(read_fd))
        finally:
            os.close(read_fd)
        with patch.object(HELPER.INSPECTION, "diagnose") as cgroup, patch.object(
            HELPER, "diagnose"
        ) as source:
            self.assertEqual(HELPER.batch(CONTAINER, RUN, "rootless", 14,
                                         clock=lambda: 10, euid=lambda: 0,
                                         lifeline=lambda: False, lane="upstream-rootless"), HELPER._context_unknown())
            cgroup.assert_not_called()
            source.assert_not_called()

    def test_context_cancellation_lifeline_reaches_separate_root_timer_group(self):
        with tempfile.TemporaryDirectory() as directory:
            started_path = Path(directory) / "first-reader-started"
            source_path = Path(directory) / "second-reader-started"
            root_program = """import functools, importlib.util, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location('helper', sys.argv[1])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
deadline, started, source_path = sys.argv[2:]
def cgroup(*args, **kwargs):
    Path(started).write_text('started')
    time.sleep(0.4)
    return helper._context_unknown()[:2]
def source(*args, **kwargs):
    Path(source_path).write_text('unexpected')
    return helper._unknown('identity')
helper.INSPECTION.diagnose = cgroup
helper.diagnose = source
helper.batch = functools.partial(helper.batch, euid=lambda: 0)
sys.argv = ['helper', '--batch', 'dl-native-Ab12Cd34', 'Ab12Cd34', 'rootless', deadline, 'upstream-rootless']
helper.main()
"""
            program = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('helper', sys.argv[1])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
helper.SECONDS = 2
original = helper.INSPECTION.bounded_command
helper_path = sys.argv[1]
root_program, started, source_path = sys.argv[2:]
def capture(command, deadline, **kwargs):
    # Retain actual GNU timeout/process-group/pipe behavior; replace only the
    # root Python bootstrap with synthetic readers, never a runtime request.
    command = command[:4] + [sys.executable, '-c', root_program, helper_path,
                            command[-2], started, source_path]
    return original(command, deadline, **kwargs)
helper.INSPECTION.bounded_command = capture
sys.argv = ['helper', '--context', 'dl-native-Ab12Cd34', 'Ab12Cd34', 'rootless', '0', 'upstream-rootless']
helper.main()
"""
            process = subprocess.Popen([sys.executable, "-c", program,
                                        str(ROOT / "scripts/native-device-source.py"), root_program,
                                        str(started_path), str(source_path)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 2
                while not started_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(started_path.exists())
                process.terminate()
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(stderr, "")
                self.assertEqual(HELPER._parse_context(stdout.encode()), HELPER._context_unknown())
                self.assertFalse(source_path.exists())
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3)



    def test_batch_cancellation_reaps_private_child_and_does_not_start_device_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "private-child-pid"
            source_path = Path(directory) / "source-invoked"
            program = """import functools, importlib.util, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location('helper', sys.argv[1])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
pid_path, source_path = sys.argv[2:]
child = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(10)"
def cgroup(*args, deadline, **kwargs):
    helper.INSPECTION.bounded_command([sys.executable, '-c', child, pid_path], deadline)
def source(*args, **kwargs):
    Path(source_path).write_text('unexpected')
    return helper._unknown('identity')
helper.INSPECTION.diagnose = cgroup
helper.diagnose = source
helper.batch = functools.partial(helper.batch, euid=lambda: 0)
sys.argv = ['helper', '--batch', 'dl-native-Ab12Cd34', 'Ab12Cd34', 'rootless',
            f'{helper.phase_clock() + 4:.6f}', 'upstream-rootless']
helper.main()
"""
            process = subprocess.Popen([sys.executable, "-c", program,
                                        str(ROOT / "scripts/native-device-source.py"),
                                        str(pid_path), str(source_path)],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
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
                self.assertEqual(HELPER._parse_context(stdout.encode()), HELPER._context_unknown())
                self.assertFalse(source_path.exists())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=2)

            # A slice alarm is not whole-phase cancellation: after reaping the
            # first private command, the second optional slice may still run.
            timer_pid = Path(directory) / "timer-child-pid"
            timer_source = Path(directory) / "timer-source-invoked"
            timed = program.replace("helper.main()", "helper.SLICE_SECONDS = 0.7\nhelper.main()")
            timed = timed.replace("helper.main()", "helper._caller_alive = lambda: True\nhelper.main()")
            result = subprocess.run([sys.executable, "-c", timed,
                                     str(ROOT / "scripts/native-device-source.py"),
                                     str(timer_pid), str(timer_source)],
                                    capture_output=True, text=True, timeout=2, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertEqual(HELPER._parse_context(result.stdout.encode()),
                             HELPER._context_unknown()[:2] + HELPER._unknown("identity"))
            self.assertTrue(timer_source.exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(int(timer_pid.read_text()), 0)

    def test_context_private_overflow_and_cancellation_wait_for_root_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            for cause in ("overflow", "cancel"):
                with self.subTest(cause=cause):
                    pid_path = Path(directory) / cause
                    program = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('helper', sys.argv[1])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
helper.SECONDS = 1
helper.PHASE_RESERVE = 0.3
pid_path, cause = sys.argv[2:]
original = helper.INSPECTION.bounded_command
child = ("import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); "
         + ("print('protected-secret'*300, flush=True); " if cause == 'overflow' else '')
         + "time.sleep(0.3)")
def capture(command, deadline, **kwargs):
    return original([sys.executable, '-c', child, pid_path], deadline, **kwargs)
helper.INSPECTION.bounded_command = capture
sys.argv = ['helper', '--context', 'dl-native-Ab12Cd34', 'Ab12Cd34', 'rootless', '1', 'upstream-rootless']
helper.main()
"""
                    started = time.monotonic()
                    process = subprocess.Popen([sys.executable, "-c", program,
                                                str(ROOT / "scripts/native-device-source.py"),
                                                str(pid_path), cause],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        deadline = started + 1
                        while not pid_path.exists() and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertTrue(pid_path.exists())
                        if cause == "cancel":
                            process.terminate()
                        stdout, stderr = process.communicate(timeout=2)
                        elapsed = time.monotonic() - started
                        self.assertGreaterEqual(elapsed, 0.8)
                        self.assertLess(elapsed, 1.8)
                        self.assertEqual(process.returncode, 0)
                        self.assertEqual(stderr, "")
                        self.assertEqual(HELPER._parse_context(stdout.encode()), HELPER._context_unknown())
                        self.assertNotIn("protected-secret", stdout)
                        with self.assertRaises(ProcessLookupError):
                            os.kill(int(pid_path.read_text()), 0)
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.communicate(timeout=2)

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
