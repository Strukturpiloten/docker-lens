"""Fake-only hosted prerequisite collection; never execute host/package/native tools."""

from contextlib import redirect_stderr, redirect_stdout
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hosted_diagnostic", ROOT / "scripts/native-outer-runtime-profile.py")
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)
SECRET = "private-host-source-user-stderr-canary"
HEAD = "a" * 40
CI = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
      "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "ImageVersion": "20261021.1.0",
      "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens", "GITHUB_EVENT_NAME": "workflow_dispatch",
      "GITHUB_REF": "refs/heads/main", "GITHUB_WORKFLOW": "Check", "GITHUB_WORKFLOW_REF": PROFILE.WORKFLOW,
      "GITHUB_WORKFLOW_SHA": HEAD, "GITHUB_SHA": HEAD, "GITHUB_JOB": PROFILE.JOB,
      "GITHUB_RUN_ID": "123456789", "GITHUB_RUN_ATTEMPT": "2"}


def package_fixture():
    return "".join(name + "\tinstall ok installed\t1.2.3-1ubuntu1\tamd64\n"
                   for name in PROFILE.PACKAGES).encode()


def owner_fixture():
    return "".join(("dpkg" if name in {"dpkg-query", "start-stop-daemon"} else
                    "systemd" if name == "systemctl" else "init-system-helpers") + ": " + path + "\n"
                   for name, path in PROFILE.HELPERS.items()).encode()


def unit_fixture():
    return "\n".join("Id=" + name + "\nLoadState=loaded\nActiveState=active\nSubState=" +
                     ("listening" if name.endswith("socket") else "running") +
                     "\nUnitFileState=enabled\nFragmentPath=/lib/systemd/system/" + name + "\nDropInPaths=\n"
                     for name in PROFILE.UNITS).encode()


class HostedDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dl-diagnostic-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.host = self.base / "host"
        self.host.mkdir(mode=0o700)
        self.raw = self.base / "private"
        self.raw.mkdir(mode=0o700)
        for source_id, path in PROFILE.SOURCE_PATHS.items():
            target = self.host / path.lstrip("/")
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if source_id in PROFILE.DIRECTORY_IDS:
                target.mkdir(mode=0o700)
            else:
                target.write_text('ID=ubuntu\nVERSION_ID="24.04"\nIGNORED=' + SECRET + "\n"
                                  if source_id == "os-release" else SECRET + "\n")
                target.chmod(0o644)
        self.addCleanup(patch.stopall)
        patch.object(PROFILE, "EXPECTED_UID", os.geteuid()).start()
        patch.object(PROFILE, "SOURCE_ROOT", str(self.host)).start()
        original = tempfile.mkdtemp
        patch.object(PROFILE.tempfile, "mkdtemp", side_effect=lambda **kw: original(dir=self.raw, **kw)).start()

    def execute(self, environment=None, replacements=None, statuses=None, missing=None):
        outputs = {PROFILE.CHECKOUT: (HEAD + "\n").encode(), PROFILE.PACKAGE_QUERY: package_fixture(),
                   PROFILE.OWNER_QUERY: owner_fixture(), PROFILE.UNIT_QUERY: unit_fixture()}
        outputs.update(replacements or {})
        statuses = statuses or {}
        calls, children, sizes = [], [], []
        real_popen, real_discard = subprocess.Popen, PROFILE.RawFiles.discard

        def fake(command, **kwargs):
            self.assertIn(command, PROFILE.COMMANDS)
            calls.append(command)
            self.assertEqual(kwargs["env"], PROFILE.ENVIRONMENT)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["cwd"], ROOT)
            for directory in self.raw.iterdir():
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual({item.name for item in directory.iterdir()}, set(PROFILE.RAW_NAMES))
                for item in directory.iterdir():
                    self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)
            if command == missing:
                raise FileNotFoundError(SECRET)
            data = outputs[command]
            expression = repr(data) if len(data) < 4096 else "b'X' * " + str(len(data))
            program = ("import sys; sys.stdout.buffer.write(" + expression + "); sys.stdout.flush(); "
                       "sys.stderr.buffer.write(" + repr(SECRET.encode()) + "); sys.exit(" +
                       str(statuses.get(command, 0)) + ")")
            child = real_popen([sys.executable, "-c", program], **kwargs)
            children.append(child)
            return child

        def discard(files):
            sizes.extend(os.fstat(fd).st_size for fd in files.values())
            real_discard(files)

        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            with patch.object(PROFILE.subprocess, "Popen", side_effect=fake), \
                    patch.object(PROFILE.RawFiles, "discard", discard), redirect_stdout(stdout), redirect_stderr(stderr):
                result = PROFILE.sample(CI if environment is None else environment)
        finally:
            for child in children:
                child.wait(timeout=2)
        self.assertEqual(list(self.raw.iterdir()), [])
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
        self.assertTrue(all(size <= PROFILE.LIMIT for size in sizes))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(result["admission"], "unadmitted")
        return result, calls

    def test_fixed_commands_bound_identity_hashes_and_no_native_query(self):
        result, calls = self.execute(environment=CI | {"GITHUB_TOKEN": SECRET, "DOCKER_HOST": SECRET,
                                                       "GITHUB_ACTOR": SECRET, "CONTAINER_HOST": SECRET})
        self.assertEqual(calls, list(PROFILE.COMMANDS))
        self.assertEqual((result["status"], result["reason"]), ("observed", "complete"))
        self.assertEqual(result["binding"]["checkout_sha"], HEAD)
        self.assertEqual(result["binding"]["workflow_ref"], PROFILE.WORKFLOW)
        self.assertEqual(result["observations"]["files"]["helper:invoke-rc.d"]["sha256"],
                         hashlib.sha256((SECRET + "\n").encode()).hexdigest())
        self.assertEqual(result["observations"]["units"]["docker.service"]["fragment"], "vendor")
        self.assertEqual(result["observations"]["trigger_execution_set"], "not_established")
        for command in PROFILE.COMMANDS:
            self.assertEqual(command[:4], ("/usr/bin/timeout", "--signal=TERM", "--kill-after=1s", "2s"))
            self.assertNotIn(command[4], {"/usr/bin/docker", "/usr/bin/podman", "/usr/bin/sudo"})
            self.assertNotIn("start", command)
            self.assertNotIn("restart", command)
            self.assertNotIn("install", command)
        self.assertIn("--show", PROFILE.PACKAGE_QUERY)
        self.assertIn("--search", PROFILE.OWNER_QUERY)
        self.assertIn("show", PROFILE.UNIT_QUERY)
        self.assertLess(len(json.dumps(result).encode()), PROFILE.LIMIT)

    def test_capture_rejects_nonallowlisted_command_before_any_child(self):
        with PROFILE.private_outputs() as files, patch.object(PROFILE.subprocess, "Popen") as native:
            for command in (("docker", "info"), ("podman", "info"), ("sudo", "systemctl", "restart", "docker"),
                            ("dpkg", "--install", SECRET), ("sh", "-c", SECRET)):
                with self.assertRaises(PROFILE.Unavailable):
                    PROFILE.capture(command, files, "command", time.monotonic() + 1)
            native.assert_not_called()
        self.assertNotIn("control:docker-ce:arm64:postinst", PROFILE.SOURCE_IDS)

    def test_dispatch_provenance_refuses_before_any_host_query(self):
        for key in CI:
            with self.subTest(key=key):
                result, calls = self.execute(environment=CI | {key: SECRET})
                self.assertEqual((result["status"], result["reason"]), ("unavailable", "ci_identity_unavailable"))
                self.assertEqual(calls, [])
        for update in ({"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_REF": "refs/heads/feature"},
                       {"GITHUB_RUN_ID": "01"}, {"GITHUB_SHA": "b" * 40}):
            self.assertEqual(self.execute(environment=CI | update)[1], [])
        result, calls = self.execute(replacements={PROFILE.CHECKOUT: b"b" * 40 + b"\n"})
        self.assertEqual(result["reason"], "checkout_unavailable")
        self.assertEqual(calls, [PROFILE.CHECKOUT])

    def test_short_staged_stdout_cannot_become_false_package_absence(self):
        result, _ = self.execute()
        self.assertEqual(result["status"], "observed")
        self.assertTrue(all(record["status"] == "reported"
                            for record in result["observations"]["packages"].values()))
        original_read = os.read
        injected = []

        def short_read(descriptor, count):
            raw = original_read(descriptor, count)
            if (count == PROFILE.LIMIT + 1 and stat.S_ISREG(os.fstat(descriptor).st_mode)
                    and raw == package_fixture()):
                injected.append(True)
                return raw.splitlines(keepends=True)[0]
            return raw

        with patch.object(PROFILE.os, "read", side_effect=short_read):
            result, _ = self.execute()
        self.assertEqual(injected, [True])
        self.assertEqual((result["status"], result["reason"]),
                         ("unavailable", "collector_io_failure"))
        self.assertIsNone(result["observations"])

    def test_missing_tools_invalid_and_oversize_command_output_are_explicit(self):
        result, _ = self.execute(missing=PROFILE.CHECKOUT)
        self.assertEqual(result["reason"], "tool_unavailable")
        for data in (b"", b"garbage\n", package_fixture() + package_fixture(), b"foreign\tinstalled\t1\tamd64\n"):
            result, _ = self.execute(replacements={PROFILE.PACKAGE_QUERY: data})
            # Empty is a complete absence observation; malformed data is not.
            self.assertEqual(result["status"], "observed" if data == b"" else "partial")
        result, _ = self.execute(replacements={PROFILE.UNIT_QUERY: SECRET.encode()})
        self.assertEqual(result["status"], "partial")
        result, _ = self.execute(replacements={PROFILE.OWNER_QUERY: b"X" * 65537})
        self.assertEqual(result["reason"], "output_overflow")

    def test_package_states_arch_aliases_and_owner_records_are_closed(self):
        raw = b"docker-ce\tdeinstall ok config-files\t5:29.8.1-1~ubuntu.24.04~noble\tamd64\n"
        records = PROFILE.package_metadata(raw)
        self.assertEqual(records["docker-ce"]["package_status"], "deinstall ok config-files")
        self.assertEqual(records["containerd.io"]["status"], "missing")
        for raw in (b"docker-ce\tinstall ok installed\tsecret/version\tamd64\n",
                    b"docker-ce\tinstall ok installed\t1\tarm64\n", b"docker-ce\tbad\t1\tamd64\n"):
            with self.assertRaises(PROFILE.Unavailable):
                PROFILE.package_metadata(raw)
        owners = PROFILE.owner_metadata(b"dpkg:amd64: /sbin/start-stop-daemon\nsystemd: /bin/systemctl\n")
        self.assertEqual(owners["start-stop-daemon"]["packages"], ["dpkg:amd64"])
        self.assertEqual(owners["systemctl"]["packages"], ["systemd"])
        with self.assertRaises(PROFILE.Unavailable):
            PROFILE.owner_metadata(("dpkg: /" + SECRET + "\n").encode())

    def source(self, source_id="helper:invoke-rc.d"):
        return self.host / PROFILE.SOURCE_PATHS[source_id].lstrip("/")

    def read(self, source_id="helper:invoke-rc.d"):
        with PROFILE.private_outputs() as files:
            return PROFILE.read_source(source_id, files, time.monotonic() + 2)

    def test_missing_symlink_fifo_mode_owner_and_oversize_source_outcomes(self):
        source = self.source()
        source.unlink()
        self.assertEqual(self.read(), {"status": "missing"})
        source.symlink_to("/" + SECRET)
        self.assertEqual(self.read()["status"], "symlink")
        source.unlink()
        os.mkfifo(source, 0o600)
        with self.assertRaises(PROFILE.Unavailable): self.read()
        source.unlink()
        source.write_bytes(b"private")
        source.chmod(0o666)
        with self.assertRaises(PROFILE.Unavailable): self.read()
        source.chmod(0o644)
        with patch.object(PROFILE, "EXPECTED_UID", os.geteuid() + 1):
            with self.assertRaises(PROFILE.Unavailable): self.read()
        with source.open("wb") as stream: stream.truncate(PROFILE.FILE_LIMIT + 1)
        with self.assertRaises(PROFILE.Unavailable) as caught: self.read()
        self.assertEqual(caught.exception.reason, "output_overflow")

    def test_masks_override_presence_and_bounded_directory_roster(self):
        source = self.source("etc:docker.service")
        source.unlink()
        source.symlink_to("/dev/null")
        self.assertEqual(self.read("etc:docker.service")["mask"], True)
        directory = self.source("etc:docker.service.d")
        (directory / SECRET).write_bytes(b"private")
        record = self.read("etc:docker.service.d")
        self.assertEqual(record["entries"], 1)
        self.assertNotIn(SECRET, json.dumps(record))
        for index in range(16): (directory / str(index)).touch()
        with self.assertRaises(PROFILE.Unavailable) as caught: self.read("etc:docker.service.d")
        self.assertEqual(caught.exception.reason, "output_overflow")

    def test_source_replacement_during_held_read_is_refused_and_preserved(self):
        source = self.source()
        real_read = os.read
        changed = False
        def race(descriptor, count):
            nonlocal changed
            value = real_read(descriptor, count)
            if not changed:
                changed = True
                source.unlink()
                source.write_bytes(b"replacement")
            return value
        with patch.object(PROFILE.os, "read", side_effect=race):
            with self.assertRaises(PROFILE.Unavailable) as caught: self.read()
        self.assertEqual(caught.exception.reason, "custody_failure")
        self.assertEqual(caught.exception.failure_detail,
                         {"guard": "stability", "component": "leaf", "category": "check_failed"})
        self.assertEqual(source.read_bytes(), b"replacement")

    def test_unknown_source_ids_and_standard_os_symlink_are_not_followed(self):
        with self.assertRaises(PROFILE.Unavailable): self.read("/" + SECRET)
        etc = self.host / "etc/os-release"
        etc.parent.mkdir(mode=0o700, exist_ok=True)
        etc.symlink_to("../usr/lib/os-release")
        self.assertEqual(self.read("os-release")["distribution"], "ubuntu")

    def test_malformed_os_data_and_symlink_ancestors_are_refused(self):
        source = self.source("os-release")
        for raw in (b"", b'ID=""ubuntu""\nVERSION_ID="24.04"\n',
                    b'ID=ubuntu\nID=ubuntu\nVERSION_ID="24.04"\n', b"\xff"):
            with self.subTest(raw=raw):
                source.write_bytes(raw)
                with self.assertRaises(PROFILE.Unavailable): self.read("os-release")
        directory = self.host / "usr/sbin"
        moved = self.host / "usr/held-sbin"
        directory.rename(moved)
        directory.symlink_to("held-sbin", target_is_directory=True)
        with self.assertRaises(PROFILE.Unavailable): self.read()
        self.assertTrue(directory.is_symlink())

    def test_total_source_budget_cancellation_and_expired_deadline_refuse(self):
        with PROFILE.private_outputs() as files:
            files.used = PROFILE.TOTAL_SOURCE
            with self.assertRaises(PROFILE.Unavailable) as caught:
                PROFILE.read_source("helper:invoke-rc.d", files, time.monotonic() + 2)
            self.assertEqual(caught.exception.reason, "output_overflow")
            with self.assertRaises(PROFILE.Unavailable) as caught:
                PROFILE.read_source("helper:invoke-rc.d", files, time.monotonic() - 1)
            self.assertEqual(caught.exception.reason, "timeout")
            cancellation = PROFILE.Cancellation()
            cancellation.request(signal.SIGTERM)
            with self.assertRaises(PROFILE.Cancelled):
                PROFILE.read_source("helper:invoke-rc.d", files, time.monotonic() + 2, cancellation)

    def test_programming_error_is_nonpositive_and_still_cleans_raw_files(self):
        with patch.object(PROFILE, "package_metadata", side_effect=TypeError(SECRET)):
            with self.assertRaisesRegex(TypeError, SECRET):
                self.execute()
        self.assertEqual(list(self.raw.iterdir()), [])

    def test_cleanup_failure_is_closed_and_owned_replacements_are_preserved(self):
        with patch.object(PROFILE.os, "unlink", side_effect=OSError(SECRET)):
            with self.assertRaises(PROFILE.Unavailable) as caught:
                with PROFILE.private_outputs():
                    pass
        self.assertEqual(caught.exception.reason, "cleanup_failure")
        self.assertEqual(len(list(self.raw.iterdir())), 1)

    def test_raw_file_replacement_is_not_deleted_or_claimed_clean(self):
        with self.assertRaises(PROFILE.Unavailable) as caught:
            with PROFILE.private_outputs() as files:
                os.unlink("command.stdout", dir_fd=files.held)
                replacement = os.open("command.stdout", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=files.held)
                os.write(replacement, b"foreign-replacement")
                os.close(replacement)
        self.assertEqual(caught.exception.reason, "cleanup_failure")
        directory = next(self.raw.iterdir())
        self.assertEqual((directory / "command.stdout").read_bytes(), b"foreign-replacement")

    def test_caller_exception_is_not_operation_cleanup_state(self):
        try:
            raise LookupError("unrelated")
        except LookupError:
            with PROFILE.private_outputs():
                pass
        self.assertEqual(list(self.raw.iterdir()), [])

    def test_main_schema_and_argument_refusal_are_value_free(self):
        for argv in (["diagnostic", "--path", SECRET], ["diagnostic"]):
            output, errors = io.StringIO(), io.StringIO()
            with patch.object(PROFILE.sys, "argv", argv), patch.dict(os.environ, {}, clear=True), \
                    redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(PROFILE.main(), 2)
            self.assertNotIn(SECRET, output.getvalue() + errors.getvalue())
            if len(argv) == 1:
                record = json.loads(output.getvalue())
                self.assertEqual(record["schema_version"], 3)
                self.assertEqual(record["purpose"], "hosted_prerequisite_diagnostic")
                self.assertEqual(record["admission"], "unadmitted")

    def test_failure_detail_constructor_is_closed_immutable_and_value_free(self):
        package = {"field": "version", "category": "empty", "row": 1}
        source = {"guard": "mode", "component": "ancestor_2", "category": "check_failed"}
        for reason, detail in (("invalid_metadata", package), ("custody_failure", source)):
            error = PROFILE.Unavailable(reason, detail)
            self.assertEqual(error.failure_detail, detail)
            self.assertEqual(str(error), reason)
            returned = error.failure_detail
            returned["category"] = SECRET
            self.assertEqual(error.failure_detail, detail)
        error = PROFILE.Unavailable("invalid_metadata", package)
        package["field"] = SECRET
        self.assertEqual(error.failure_detail["field"], "version")
        invalid = [({}, "invalid_metadata"), ({"field": SECRET, "category": "empty", "row": 1}, "invalid_metadata"),
                   ({"field": "version", "category": SECRET, "row": 1}, "invalid_metadata"),
                   ({"field": "version", "category": "empty", "row": True}, "invalid_metadata"),
                   ({"field": "version", "category": "empty", "row": -1}, "invalid_metadata"),
                   ({"field": "version", "category": "empty", "row": 12}, "invalid_metadata"),
                   ({"field": "version", "category": "empty", "row": 1, "raw": SECRET}, "invalid_metadata"),
                   ({"guard": SECRET, "component": "leaf", "category": "check_failed"}, "custody_failure"),
                   ({"guard": "owner", "component": SECRET, "category": "check_failed"}, "custody_failure"),
                   ({"guard": "owner", "component": "ancestor_5", "category": "check_failed"}, "custody_failure"),
                   ({"guard": "owner", "component": "leaf", "category": SECRET}, "custody_failure"),
                   ({"guard": "owner", "component": "leaf", "category": []}, "custody_failure"),
                   (source, "invalid_metadata"), (source, "command_failed"), (SECRET, "custody_failure")]
        for detail, reason in invalid:
            with self.subTest(reason=reason, detail_type=type(detail).__name__):
                with self.assertRaises(ValueError) as caught: PROFILE.Unavailable(reason, detail)
                self.assertNotIn(SECRET, str(caught.exception))

    def test_package_failure_fields_categories_order_and_row_are_closed(self):
        good = b"docker-ce\tinstall ok installed\t1.2.3\tamd64\n"
        cases = [(b"\xff", "encoding", "invalid_encoding", 0),
                 (b"x" * (PROFILE.LIMIT + 1), "framing", "oversize", 0),
                 (b"garbage", "framing", "missing_terminator", 0),
                 (b"garbage\n", "columns", "invalid_count", 1),
                 (b"\tbad\tbad\tbad\n", "package", "empty", 1),
                 ((SECRET + "\tbad\tbad\tbad\n").encode(), "package", "unrecognized", 1),
                 (good + good, "package", "duplicate", 2),
                 (b"docker-ce\t\tbad\tbad\n", "status", "empty", 1),
                 (("docker-ce\t" + SECRET + "\tbad\tbad\n").encode(), "status", "invalid_syntax", 1),
                 (b"docker-ce\tinstall ok installed\t\tbad\n", "version", "empty", 1),
                 (("docker-ce\tinstall ok installed\t" + SECRET + "\tbad\n").encode(), "version", "invalid_syntax", 1),
                 (b"docker-ce\tinstall ok installed\t1\t\n", "architecture", "empty", 1),
                 (("docker-ce\tinstall ok installed\t1\t" + SECRET + "\n").encode(), "architecture", "unrecognized", 1),
                 (package_fixture() + good, "package", "duplicate", 11)]
        for raw, field, category, row in cases:
            with self.subTest(field=field, category=category, row=row):
                with self.assertRaises(PROFILE.Unavailable) as caught: PROFILE.package_metadata(raw)
                self.assertEqual(caught.exception.reason, "invalid_metadata")
                expected = {"field": field, "category": category, "row": row}
                if field in {"version", "architecture"}:
                    expected["validated_dpkg_state"] = "installed"
                self.assertEqual(caught.exception.failure_detail, expected)
                self.assertNotIn(SECRET, json.dumps(caught.exception.failure_detail))
                self.assertNotIn(SECRET, str(caught.exception))

    def test_schema3_failure_details_propagate_without_salvage_or_private_bytes(self):
        raw = b"docker-ce\tinstall ok installed\t1\tamd64\n" + (SECRET + "\tbad\tbad\tbad\n").encode()
        copyright = self.source("copyright:dpkg")
        copyright.chmod(0o666)
        result, calls = self.execute(replacements={PROFILE.PACKAGE_QUERY: raw})
        self.assertEqual(result["schema_version"], 3)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(calls, list(PROFILE.COMMANDS))
        self.assertEqual(result["observations"]["packages"], {"status": "unavailable", "reason": "invalid_metadata",
                         "failure_detail": {"field": "package", "category": "unrecognized", "row": 2}})
        self.assertEqual(result["observations"]["files"]["copyright:dpkg"],
                         {"status": "unavailable", "reason": "custody_failure", "failure_detail":
                          {"guard": "mode", "component": "leaf", "category": "check_failed"}})
        self.assertEqual(list(self.raw.iterdir()), [])

    def test_source_owner_mode_kind_and_link_guards_have_only_fixed_components(self):
        def failure(guard, component):
            with self.assertRaises(PROFILE.Unavailable) as caught: self.read()
            self.assertEqual(caught.exception.failure_detail,
                             {"guard": guard, "component": component, "category": "check_failed"})
        self.host.chmod(0o722)
        failure("mode", "root")
        self.host.chmod(0o700)
        with patch.object(PROFILE, "EXPECTED_UID", os.geteuid() + 1): failure("owner", "root")
        directory = self.host / "usr/sbin"
        directory.chmod(0o777)
        failure("mode", "ancestor_2")
        directory.chmod(0o700)
        source = self.source()
        source.chmod(0o666)
        failure("mode", "leaf")
        source.chmod(0o644)
        link = self.base / "linked"
        link.hardlink_to(source)
        failure("links", "leaf")
        link.unlink()
        source.unlink()
        os.mkfifo(source, 0o600)
        failure("kind", "leaf")
        source.unlink()
        source.write_bytes(b"private")
        original_stat = os.stat
        def foreign(path, *args, **kwargs):
            return SimpleNamespace(st_uid=os.geteuid() + 1) if path == source.name else original_stat(path, *args, **kwargs)
        with patch.object(PROFILE.os, "stat", side_effect=foreign): failure("owner", "leaf")

    def test_source_open_and_metadata_io_details_never_echo_exception_values(self):
        original_open = os.open
        for code, category in ((errno.EACCES, "permission_denied"), (errno.EPERM, "permission_denied"),
                               (errno.ELOOP, "symlink_refused"), (errno.ENOTDIR, "not_directory"),
                               (errno.EIO, "io_error"), (errno.EBADF, "other_io")):
            def fault(path, *args, **kwargs):
                if path == "sbin": raise OSError(code, SECRET, "/" + SECRET)
                return original_open(path, *args, **kwargs)
            with self.subTest(category=category), patch.object(PROFILE.os, "open", side_effect=fault):
                with self.assertRaises(PROFILE.Unavailable) as caught: self.read()
                self.assertEqual(caught.exception.failure_detail,
                                 {"guard": "open", "component": "ancestor_2", "category": category})
                self.assertNotIn(SECRET, str(caught.exception))
        original_stat = os.stat
        def metadata(path, *args, **kwargs):
            if path == "invoke-rc.d": raise OSError(errno.EIO, SECRET)
            return original_stat(path, *args, **kwargs)
        with patch.object(PROFILE.os, "stat", side_effect=metadata):
            with self.assertRaises(PROFILE.Unavailable) as caught: self.read()
        self.assertEqual(caught.exception.failure_detail,
                         {"guard": "metadata", "component": "leaf", "category": "io_error"})

    def test_source_close_failure_is_fixed_detail_and_retains_original_io_context(self):
        original_close, original_read = os.close, os.read
        source_inode = self.source().stat().st_ino
        for primary in (False, True):
            attempted = []
            def close(descriptor):
                target = os.fstat(descriptor).st_ino == source_inode
                original_close(descriptor)
                if target:
                    attempted.append(descriptor)
                    raise OSError(errno.EIO, SECRET)
            def read(descriptor, count):
                if primary and os.fstat(descriptor).st_ino == source_inode: raise OSError(errno.EIO, SECRET)
                return original_read(descriptor, count)
            with self.subTest(primary=primary), patch.object(PROFILE.os, "close", side_effect=close), \
                    patch.object(PROFILE.os, "read", side_effect=read):
                with self.assertRaises(PROFILE.Unavailable) as caught: self.read()
            self.assertEqual(len(attempted), 1)
            self.assertEqual(caught.exception.failure_detail,
                             {"guard": "metadata" if primary else "close", "component": "leaf", "category": "io_error"})

    def test_schema3_success_has_no_failure_detail_and_preserves_observations(self):
        result, calls = self.execute()
        self.assertEqual((result["schema_version"], result["status"], result["reason"]), (3, "observed", "complete"))
        self.assertNotIn("failure_detail", json.dumps(result))
        self.assertEqual(calls, list(PROFILE.COMMANDS))
        self.assertEqual(PROFILE.package_metadata(b""), {name: {"status": "missing"} for name in PROFILE.PACKAGES})
        self.assertEqual((PROFILE.LIMIT, PROFILE.FILE_LIMIT, PROFILE.TOTAL_SOURCE), (65536, 2097152, 8388608))

    def test_schema3_only_reports_validated_final_state_for_later_failures(self):
        states = ("not-installed", "config-files", "half-installed", "unpacked", "half-configured",
                  "triggers-awaited", "triggers-pending", "installed")
        self.assertEqual(PROFILE.VALIDATED_DPKG_STATES, frozenset(states))
        for state in states:
            for field, version, architecture, category in (("version", "", "amd64", "empty"),
                                                           ("architecture", "1", SECRET, "unrecognized")):
                with self.subTest(state=state, field=field):
                    raw = ("docker-ce\tunknown reinstreq " + state + "\t" + version + "\t" + architecture + "\n").encode()
                    with self.assertRaises(PROFILE.Unavailable) as caught: PROFILE.package_metadata(raw)
                    self.assertEqual(caught.exception.reason, "invalid_metadata")
                    self.assertEqual(caught.exception.failure_detail,
                                     {"field": field, "category": category, "row": 1, "validated_dpkg_state": state})
                    self.assertNotIn(SECRET, json.dumps(caught.exception.failure_detail))
            # A fully accepted row retains its original reported fields; final
            # tokens never become inferred package-presence classifications.
            valid = ("docker-ce\tunknown reinstreq " + state + "\t1\tamd64\n").encode()
            self.assertEqual(PROFILE.package_metadata(valid)["docker-ce"]["package_status"], "unknown reinstreq " + state)

    def test_status_context_is_omitted_before_or_at_full_status_validation(self):
        good = b"docker-ce\tinstall ok installed\t1\tamd64\n"
        cases = [(b"\xff", "encoding"), (b"missing terminator", "framing"), (b"bad\n", "columns"),
                 ((SECRET + "\tinstall ok installed\t\tamd64\n").encode(), "package"),
                 (good + good, "package")]
        for state in ("", "Install ok installed", "install  ok installed", "install ok installed ",
                      "install " + SECRET + " installed", "install ok " + SECRET):
            cases.append((("docker-ce\t" + state + "\t\tamd64\n").encode(), "status"))
        for raw, field in cases:
            with self.subTest(field=field):
                with self.assertRaises(PROFILE.Unavailable) as caught: PROFILE.package_metadata(raw)
                self.assertEqual(caught.exception.failure_detail["field"], field)
                self.assertNotIn("validated_dpkg_state", caught.exception.failure_detail)
                self.assertNotIn(SECRET, json.dumps(caught.exception.failure_detail))

    def test_schema3_status_context_is_row_local_and_whole_parse_stays_unavailable(self):
        raw = (b"docker-ce\tinstall ok installed\t1\tamd64\n"
               b"docker-ce-cli\tdeinstall ok config-files\t\tamd64\n")
        result, calls = self.execute(replacements={PROFILE.PACKAGE_QUERY: raw})
        self.assertEqual((result["schema_version"], result["status"], result["admission"]), (3, "partial", "unadmitted"))
        self.assertEqual(calls, list(PROFILE.COMMANDS))
        self.assertEqual(result["observations"]["packages"],
                         {"status": "unavailable", "reason": "invalid_metadata", "failure_detail":
                          {"field": "version", "category": "empty", "row": 2, "validated_dpkg_state": "config-files"}})
        self.assertNotIn("docker-ce", result["observations"]["packages"])
        duplicate = b"docker-ce\tdeinstall ok config-files\t1\tamd64\n" + raw.splitlines(keepends=True)[0]
        with self.assertRaises(PROFILE.Unavailable) as caught: PROFILE.package_metadata(duplicate)
        self.assertNotIn("validated_dpkg_state", caught.exception.failure_detail)

    def test_status_context_constructor_rejects_unvalidated_or_misplaced_values(self):
        base = {"field": "version", "category": "empty", "row": 1, "validated_dpkg_state": "installed"}
        error = PROFILE.Unavailable("invalid_metadata", base)
        base["validated_dpkg_state"] = SECRET
        self.assertEqual(error.failure_detail["validated_dpkg_state"], "installed")
        for value in (SECRET, "unknown", "", " installed", "installed\n", True, None, []):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ValueError) as caught:
                    PROFILE.Unavailable("invalid_metadata", base | {"validated_dpkg_state": value})
                self.assertNotIn(SECRET, str(caught.exception))
        base["validated_dpkg_state"] = "installed"
        for field in ("encoding", "framing", "columns", "package", "status"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                PROFILE.Unavailable("invalid_metadata", base | {"field": field})
        with self.assertRaises(ValueError): PROFILE.Unavailable("invalid_metadata", base | {"row": 0})
        with self.assertRaises(ValueError):
            PROFILE.Unavailable("custody_failure", {"guard": "mode", "component": "ancestor_2",
                                                     "category": "check_failed", "validated_dpkg_state": "installed"})


    def test_duplex_stderr_cap_and_hard_deadline_do_not_call_kill_or_communicate(self):
        real_popen = subprocess.Popen
        children = []
        for program, seconds, expected in (("import sys; sys.stderr.buffer.write(b'X'*65537)", 2, "output_overflow"),
                                           ("import sys; sys.stdout.buffer.write(b'X'*65537); sys.stderr.buffer.write(b'X'*65537)", 2, "output_overflow"),
                                           ("import time; time.sleep(0.15)", 0.03, "completion_unknown")):
            def fake(_command, **kwargs):
                child = real_popen([sys.executable, "-c", program], **kwargs)
                children.append(child)
                return child
            with PROFILE.private_outputs() as files, patch.object(PROFILE.subprocess, "Popen", side_effect=fake):
                began = time.monotonic()
                with self.assertRaises(PROFILE.Unavailable) as caught:
                    PROFILE.capture(PROFILE.CHECKOUT, files, "command", began + seconds)
                self.assertEqual(caught.exception.reason, expected)
                self.assertLess(time.monotonic() - began, seconds + 0.25)
                self.assertTrue(all(os.fstat(fd).st_size <= 65536 for fd in files.values()))
                if expected == "completion_unknown":
                    self.assertEqual(dict(files), {})
                    self.assertIsNone(children[-1].poll())
            for child in children:
                child.wait(timeout=1)
        source = (ROOT / "scripts/native-outer-runtime-profile.py").read_text()
        for forbidden in (".communicate(", ".kill(", ".terminate(", "shell=True", "shutil.rmtree"):
            self.assertNotIn(forbidden, source)


    def test_active_child_io_failure_interruption_and_signal_cleanup_before_reap(self):
        real_popen = subprocess.Popen
        for failure in (OSError(SECRET), KeyboardInterrupt(), TypeError(SECRET), "cancel", "cancel_unknown", "io_unknown"):
            cancellation = PROFILE.Cancellation()
            children, reaped, raw_removed = [], [], []
            with PROFILE.private_outputs() as files:
                def fake(_command, **kwargs):
                    child = real_popen([sys.executable, "-c", "import time; time.sleep(0.15)"], **kwargs)
                    children.append(child)
                    real_wait = child.wait

                    def wait(**options):
                        raw_removed.append(not files and not os.listdir(files.held))
                        result = real_wait(**options)
                        reaped.append(True)
                        return result

                    child.wait = wait
                    return child

                def select(_timeout):
                    if failure in ("cancel", "cancel_unknown"):
                        os.write(files["command.stdout"], SECRET.encode())
                        os.kill(os.getpid(), signal.SIGTERM)
                        return []
                    if failure == "io_unknown":
                        raise OSError(SECRET)
                    raise failure

                with patch.object(PROFILE.subprocess, "Popen", side_effect=fake), \
                     patch.object(PROFILE.selectors.DefaultSelector, "select", side_effect=select):
                    expected = PROFILE.Cancelled if failure in ("cancel", "cancel_unknown") else (PROFILE.Unavailable if isinstance(failure, OSError) or failure == "io_unknown" else type(failure))
                    previous = signal.signal(signal.SIGTERM, cancellation.request)
                    try:
                        with self.assertRaises(expected) as caught:
                            PROFILE.capture(PROFILE.CHECKOUT, files, "command", time.monotonic() + (0.03 if failure in ("cancel_unknown", "io_unknown") else 1), cancellation)
                    finally:
                        signal.signal(signal.SIGTERM, previous)
                self.assertEqual(dict(files), {})
                self.assertTrue(raw_removed and all(raw_removed))
                if failure in ("cancel_unknown", "io_unknown"):
                    self.assertEqual(caught.exception.reason, "cancelled_completion_unknown" if failure == "cancel_unknown" else "completion_unknown")
                    self.assertFalse(reaped)
                    self.assertIsNone(children[0].returncode)
                    # Test-fixture cleanup only, not evidence that capture reaped it.
                    children[0].wait(timeout=1)
                else:
                    self.assertTrue(reaped)
                    self.assertIsNotNone(children[0].returncode)


    def test_cancellation_main_is_closed_nonzero_and_restores_signal_handlers(self):
        for number in (signal.SIGTERM, signal.SIGINT):
            previous = signal.getsignal(number)
            output = io.StringIO()

            def cancelled(_environment, cancellation):
                os.kill(os.getpid(), number)
                cancellation.check()

            with patch.object(PROFILE, "sample", side_effect=cancelled), \
                 patch.object(PROFILE.sys, "argv", ["native-outer-runtime-profile.py"]), redirect_stdout(output):
                self.assertEqual(PROFILE.main(), 128 + number)
            self.assertEqual(json.loads(output.getvalue())["status"], "cancelled")
            self.assertNotIn(SECRET, output.getvalue())
            self.assertEqual(signal.getsignal(number), previous)



if __name__ == "__main__":
    unittest.main()
