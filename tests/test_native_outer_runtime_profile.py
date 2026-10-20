"""Fake-only CI profile diagnostics; never query sudo, Podman or a runtime."""

from contextlib import redirect_stderr, redirect_stdout
import io
import importlib.util
import json
import os
from pathlib import Path
import stat
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("outer_profile", ROOT / "scripts/native-outer-runtime-profile.py")
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)
SECRET = "private-host-path-user-stderr-canary"
HEAD = "a" * 40
CI = {"GITHUB_RUN_ID": "39173069422", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_JOB": "scaffold"}


def fixture(runtime="crun"):
    return {"version": {"Version": "4.9.3", "GitCommit": "b" * 40},
            "host": {"os": "linux", "cgroupManager": "systemd", "cgroupVersion": "v2", "serviceIsRemote": False,
                     "security": {"rootless": False}, "hostname": SECRET,
                     "ociRuntime": {"name": runtime, "version": runtime + " version 1.14.1\ncommit: " + SECRET,
                                    "package": runtime + "_1.14.1-1build2_amd64", "path": "/" + SECRET}}}


class OuterRuntimeProfileTests(unittest.TestCase):
    def execute(self, value=None, raw=None, status=0, missing=False, bad_custody=False,
                environment=None, git_output=None, git_status=0, programming_error=False,
                package_output=b"podman\t4.9.3+ds1-1ubuntu0.1\tamd64\ncrun\t1.14.1-1build2\tamd64\n", package_status=0,
                package_delay=0):
        output = json.dumps(fixture() if value is None else value).encode() if raw is None else raw
        real_popen, real_mkdtemp = subprocess.Popen, tempfile.mkdtemp
        real_discard = PROFILE.RawFiles.discard
        calls, children, sizes = [], [], []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def directory(**kwargs):
                result = real_mkdtemp(dir=root, **kwargs)
                if bad_custody:
                    Path(result).chmod(0o755)
                return result

            def fake(command, **kwargs):
                calls.append(tuple(command))
                self.assertEqual(kwargs["env"], {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
                self.assertEqual(kwargs["cwd"], ROOT)
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                for directory in root.iterdir():
                    self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                    self.assertEqual(set(item.name for item in directory.iterdir()), set(PROFILE.RAW_NAMES))
                    for item in directory.iterdir():
                        info = item.lstat()
                        self.assertTrue(stat.S_ISREG(info.st_mode))
                        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                        self.assertEqual(info.st_nlink, 1)
                if command == PROFILE.CHECKOUT:
                    data, code = (HEAD + "\n").encode() if git_output is None else git_output, git_status
                elif command == PROFILE.PACKAGES:
                    data, code = package_output, package_status
                else:
                    self.assertEqual(command, PROFILE.PODMAN)
                    if missing:
                        raise FileNotFoundError(SECRET)
                    data, code = output, status
                expression = repr(data) if len(data) <= 4096 else f"b'X' * {len(data)}"
                delay = package_delay if command == PROFILE.PACKAGES else 0
                program = ("import sys,time; sys.stdout.buffer.write(" + expression + "); sys.stdout.flush(); "
                           "sys.stderr.buffer.write(" + repr(SECRET.encode()) + "); "
                           "time.sleep(" + str(delay) + "); sys.exit(" + str(code) + ")")
                child = real_popen([sys.executable, "-c", program], **kwargs)
                children.append(child)
                return child

            real_capture = PROFILE.capture

            def capture(*args):
                if package_delay and args[0] == PROFILE.PACKAGES:
                    args = (*args[:3], min(args[3], time.monotonic() + 0.1), *args[4:])
                try:
                    return real_capture(*args)
                finally:
                    sizes.extend(os.fstat(descriptor).st_size for descriptor in args[1].values())

            stdout, stderr = io.StringIO(), io.StringIO()
            def discard(files):
                sizes.extend(os.fstat(descriptor).st_size for descriptor in files.values())
                real_discard(files)
            try:
                with patch.object(PROFILE.tempfile, "mkdtemp", side_effect=directory), \
                     patch.object(PROFILE.subprocess, "Popen", side_effect=fake), \
                     patch.object(PROFILE, "capture", side_effect=capture), \
                     patch.object(PROFILE.RawFiles, "discard", discard), \
                     redirect_stdout(stdout), redirect_stderr(stderr):
                    if programming_error:
                        with patch.object(PROFILE, "profile", side_effect=TypeError(SECRET)):
                            with self.assertRaisesRegex(TypeError, SECRET):
                                PROFILE.sample(CI)
                        result = None
                    else:
                        result = PROFILE.sample(CI if environment is None else environment)
            finally:
                for child in children:
                    child.wait(timeout=2)
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(all(size <= 65536 for size in sizes))
        if package_delay:
            self.assertIn(65536, sizes, "combined case must actually reach the output cap")
        if result is not None:
            self.assertNotIn(SECRET, json.dumps(result))
            self.assertIn(result["reason"], PROFILE.REASONS)
        return result, calls

    def test_exact_command_minimal_environment_and_actual_merge_checkout_binding(self):
        self.assertEqual(PROFILE.PODMAN, ("/usr/bin/sudo", "-n", "/usr/bin/timeout", "--signal=TERM",
                                         "--kill-after=2s", "10s", "/usr/bin/podman", "--remote=false", "info", "--format", "json"))
        self.assertEqual(PROFILE.PACKAGES, ("/usr/bin/timeout", "--signal=TERM", "--kill-after=1s", "2s",
                                          "/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${Version}\t${Architecture}\n",
                                          "podman", "crun", "runc"))
        environment = {**CI, "CONTAINER_HOST": SECRET, "CONTAINER_CONNECTION": SECRET,
                       "DOCKER_HOST": SECRET, "GITHUB_SHA": "c" * 40, "GITHUB_HEAD_REF": SECRET}
        result, calls = self.execute(environment=environment)
        self.assertEqual(calls, [PROFILE.CHECKOUT, PROFILE.PODMAN, PROFILE.PACKAGES])
        self.assertEqual(result["binding"], {"run_id": CI["GITHUB_RUN_ID"], "run_attempt": "2",
                                           "job": "scaffold", "checkout_sha": HEAD})
        self.assertEqual((result["schema_version"], result["purpose"], result["status"], result["reason"]),
                         (1, "ci_job_outer_runtime_identity_sample", "observed", "complete"))
        self.assertEqual(result["profile"]["runtime_package"],
                         {"status": "reported", "name": "crun", "version": "1.14.1-1build2", "architecture": "amd64"})
        self.assertEqual(result["profile"]["binary_ownership"], "unverified")
        self.assertEqual(result["profile"]["podman_package"], {"status": "reported", "name": "podman", "version": "4.9.3+ds1-1ubuntu0.1", "architecture": "amd64"})

    def test_missing_tools_status_timeout_and_overflow_are_closed_and_clean(self):
        for kwargs, reason in (({"missing": True}, "tool_unavailable"),
                               ({"status": 127}, "tool_unavailable"), ({"status": 126}, "tool_unavailable"),
                               ({"status": 124}, "timeout"), ({"status": 137}, "timeout"),
                               ({"status": 1}, "command_failed"),
                               ({"raw": b"X" * 65537}, "output_overflow"),
                               ({"bad_custody": True}, "custody_failure")):
            with self.subTest(reason=reason, kwargs=list(kwargs)):
                result, _ = self.execute(**kwargs)
                self.assertEqual((result["status"], result["reason"], result["profile"]), ("unavailable", reason, None))

    def test_malformed_truncated_duplicate_and_unknown_metadata_never_leak(self):
        for raw in (b"", b"{", b"[]", b"null", b'{"host":{},"host":{}}',
                    json.dumps(fixture()).encode()[:-1], b'{"value":NaN}'):
            result, _ = self.execute(raw=raw)
            self.assertEqual(result["status"], "unavailable")
        changes = [(("host", "ociRuntime", "name"), SECRET, "unknown_runtime"),
                   (("host", "os"), None, "invalid_profile"),
                   (("host", "os"), "windows", "invalid_profile"),
                   (("host", "ociRuntime"), None, "runtime_unavailable"),
                   (("host", "security", "rootless"), True, "unexpected_rootless"),
                   (("host", "security", "rootless"), "false", "invalid_profile"),
                   (("host", "serviceIsRemote"), True, "unexpected_remote"),
                   (("host", "serviceIsRemote"), None, "invalid_profile"),
                   (("host", "cgroupManager"), SECRET, "invalid_profile"),
                   (("host", "cgroupVersion"), "2", "invalid_profile"),
                   (("version", "Version"), "4.9", "invalid_profile"),
                   (("version", "Version"), True, "invalid_profile")]
        for route, invalid, reason in changes:
            value = fixture()
            selected = value
            for key in route[:-1]:
                selected = selected[key]
            selected[route[-1]] = invalid
            result, _ = self.execute(value=value)
            self.assertEqual(result["reason"], reason)

    def test_version_is_first_exact_name_bound_line_and_package_is_only_reported(self):
        for runtime in ("crun", "runc"):
            value = fixture(runtime)
            value["host"]["ociRuntime"]["version"] = runtime + " version 1.1.12-0ubuntu3.4\ncommit: " + SECRET
            value["host"]["cgroupManager"] = "cgroupfs"
            value["host"]["cgroupVersion"] = "v1"
            result, _ = self.execute(value=value)
            self.assertEqual(result["profile"]["runtime_version"], "1.1.12-0ubuntu3.4")
        for text in ("runc version 1.14.1", "crun version 1.14", "crun version 01.14.1",
                     " crun version 1.14.1", "crun version 1.14.1 ", "crun version 1.14.1\r\n",
                     SECRET + "\ncrun version 1.14.1"):
            value = fixture()
            value["host"]["ociRuntime"]["version"] = text
            self.assertEqual(self.execute(value=value)[0]["reason"], "invalid_profile")
        for package in (SECRET, "crun_1." + SECRET + "_amd64", "runc_1.14.1-1_amd64", {}, None):
            value = fixture()
            value["host"]["ociRuntime"]["package"] = package
            result, _ = self.execute(value=value)
            self.assertEqual(result["status"], "observed")
            self.assertEqual(result["profile"]["runtime_package"], {"status": "unrecognized"})
        value = fixture()
        del value["host"]["ociRuntime"]["package"]
        value["version"]["GitCommit"] = SECRET
        result, _ = self.execute(value=value)
        self.assertEqual(result["profile"]["runtime_package"], {"status": "unavailable"})
        self.assertEqual(result["profile"]["podman_git_commit"], {"status": "unrecognized"})

    def test_binding_refuses_unknown_ci_tokens_and_bad_git_without_podman(self):
        for environment in ({}, {**CI, "GITHUB_JOB": SECRET}, {**CI, "GITHUB_RUN_ID": "01"},
                            {**CI, "GITHUB_RUN_ATTEMPT": SECRET}):
            result, calls = self.execute(environment=environment)
            self.assertEqual(result["reason"], "ci_identity_unavailable")
            self.assertEqual(calls, [])
        for output, status in ((SECRET.encode(), 0), ((HEAD + "\n").encode(), 128), (b"f" * 64 + b"\n", 0)):
            result, calls = self.execute(git_output=output, git_status=status)
            self.assertEqual(result["reason"], "checkout_unavailable")
            self.assertEqual(calls, [PROFILE.CHECKOUT])

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
                    PROFILE.capture(PROFILE.PODMAN, files, "podman", began + seconds)
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

    def test_optional_package_overflow_cannot_hide_unknown_completion(self):
        result, calls = self.execute(package_output=b"X" * 65537, package_delay=0.3)
        self.assertEqual(calls, [PROFILE.CHECKOUT, PROFILE.PODMAN, PROFILE.PACKAGES])
        self.assertEqual((result["status"], result["reason"], result["profile"]),
                         ("unavailable", "completion_unknown", None))

    def test_programming_errors_are_not_normalized_and_cleanup_still_runs(self):
        self.execute(programming_error=True)

    def test_distro_package_records_are_bounded_closed_and_optional(self):
        for output in (b"", SECRET.encode(), b"podman\t4.9.3\tamd64\npodman\t4.9.3\tamd64\n",
                       b"podman\t4.9.3\ts390x\n", b"other\t4.9.3\tamd64\n",
                       b"podman\t4.9.3\tamd64", b"podman\t4.9.3;secret\tamd64\n"):
            result, _ = self.execute(package_output=output)
            self.assertEqual(result["status"], "observed")
            self.assertEqual(result["profile"]["podman_package"], {"status": "unavailable"})
        result, _ = self.execute(package_status=1)
        self.assertEqual(result["profile"]["podman_package"]["version"], "4.9.3+ds1-1ubuntu0.1")
        self.assertEqual(result["profile"]["runtime_distro_package"]["name"], "crun")
        self.assertEqual(result["profile"]["binary_ownership"], "unverified")
        result, _ = self.execute(package_status=2)
        self.assertEqual(result["profile"]["podman_package"], {"status": "unavailable"})
        self.assertEqual(PROFILE.package_metadata(b"podman\t5:4.9.3+ds1-1ubuntu0.1\tarm64\n")["podman"]["version"],
                         "5:4.9.3+ds1-1ubuntu0.1")
        value = fixture()
        del value["host"]["os"]
        self.assertEqual(self.execute(value=value)[0]["reason"], "invalid_profile")

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
                        os.write(files["podman.stdout"], SECRET.encode())
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
                            PROFILE.capture(PROFILE.PODMAN, files, "podman", time.monotonic() + (0.03 if failure in ("cancel_unknown", "io_unknown") else 1), cancellation)
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

    def test_cleanup_failure_is_closed_and_not_success(self):
        real_mkdtemp = tempfile.mkdtemp
        with tempfile.TemporaryDirectory() as temporary:
            def directory(**kwargs):
                return real_mkdtemp(dir=temporary, **kwargs)

            with patch.object(PROFILE.tempfile, "mkdtemp", side_effect=directory), \
                 patch.object(PROFILE.os, "unlink", side_effect=OSError(SECRET)):
                with self.assertRaises(PROFILE.Unavailable) as caught:
                    with PROFILE.private_outputs():
                        pass
                self.assertEqual(caught.exception.reason, "cleanup_failure")
            # Fake filesystem failures can leave private files: no false cleanup claim.
            self.assertEqual(len(list(Path(temporary).iterdir())), 1)

    def test_workflow_keeps_all_gates_and_adds_only_post_gate_scaffold_sample(self):
        source = (ROOT / ".github/workflows/check.yml").read_text()
        scaffold = source.split("  scaffold:\n", 1)[1].split("\n  native-conformance:", 1)[0]
        self.assertEqual(scaffold.count("run: ./scripts/check-all.sh --check"), 1)
        self.assertEqual(scaffold.count("run: python3 scripts/native-outer-runtime-profile.py"), 1)
        self.assertLess(scaffold.index("run: ./scripts/check-all.sh --check"), scaffold.index("run: python3 scripts/native-outer-runtime-profile.py"))
        self.assertNotIn("continue-on-error", source)
        self.assertNotIn("upload-artifact", scaffold)
        self.assertIn("needs: [scaffold, native-conformance]", source)
        self.assertIn('test "$SCAFFOLD_RESULT" = success', source)
        self.assertIn('test "$NATIVE_RESULT" = success', source)
        self.assertIn("lane: [debian11-rootful, debian11-rootless, upstream-rootful, upstream-rootless]", source)


if __name__ == "__main__":
    unittest.main()
