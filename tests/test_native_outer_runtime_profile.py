"""Fake-only hosted prerequisite collection; never execute host/package/native tools."""

from contextlib import redirect_stderr, redirect_stdout
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
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
UNPRIVILEGED_CONTEXT = PROFILE.unprivileged_context
SECRET = "private-host-source-user-stderr-canary"
HEAD = "a" * 40
CI = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
      "RUNNER_ARCH": "X64", "ImageOS": "ubuntu26", "ImageVersion": "20261122.9.1",
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
        for source_id, path in (PROFILE.SOURCE_PATHS | PROFILE.APPARMOR_PATHS | PROFILE.PROVENANCE_PATHS).items():
            target = self.host / path.lstrip("/")
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if source_id in PROFILE.DIRECTORY_IDS:
                target.mkdir(mode=0o700)
            else:
                target.write_text('ID=ubuntu\nVERSION_ID="26.04"\nIGNORED=' + SECRET + "\n"
                                  if source_id == "os-release" else SECRET + "\n")
                target.chmod(0o644)
                if source_id in PROFILE.FEATURE_VALUES:
                    target.write_bytes(PROFILE.FEATURE_VALUES[source_id][0] + b"\n")
        self.source("parser").chmod(0o755)
        for key, path in PROFILE.PROVENANCE_PATHS.items():
            target = self.host / path.lstrip("/")
            if key.startswith(":amd64"):
                target.unlink()
            else:
                target.write_text("" if key == "diversions" else
                                  "/usr/sbin/apparmor_parser\n" if key == ":list" else
                                  hashlib.md5((SECRET + "\n").encode()).hexdigest() + "  usr/sbin/apparmor_parser\n")
        self.addCleanup(patch.stopall)
        patch.object(PROFILE, "EXPECTED_UID", os.geteuid()).start()
        patch.object(PROFILE, "SOURCE_ROOT", str(self.host)).start()
        patch.object(PROFILE, "unprivileged_context", return_value=True).start()
        original = tempfile.mkdtemp
        patch.object(PROFILE.tempfile, "mkdtemp", side_effect=lambda **kw: original(dir=self.raw, **kw)).start()

    def execute(self, environment=None, replacements=None, statuses=None, missing=None,
                version_output=b"AppArmor parser version 5.0.2\n", on_version=None, cancellation=None):
        outputs = {PROFILE.CHECKOUT: (HEAD + "\n").encode(), PROFILE.PACKAGE_QUERY: package_fixture(),
                   PROFILE.OWNER_QUERY: owner_fixture(), PROFILE.UNIT_QUERY: unit_fixture(),
                   PROFILE.APPARMOR_QUERY: b"apparmor\tinstall ok installed\t4.0.1-0ubuntu1\tamd64\n"}
        outputs.update(replacements or {})
        statuses = statuses or {}
        calls, children, sizes = [], [], []
        real_popen, real_discard = subprocess.Popen, PROFILE.RawFiles.discard

        def fake(command, **kwargs):
            parser = bool(kwargs.get("pass_fds"))
            if parser:
                fd, = kwargs["pass_fds"]
                self.assertEqual(command, PROFILE.bounded_command("/proc/self/fd/" + str(fd), "--version"))
                self.assertEqual(kwargs["preexec_fn"], PROFILE.no_new_privileges)
                if on_version is not None: on_version(fd)
            else:
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
            data = version_output if parser else outputs[command]
            expression = repr(data) if parser or len(data) < 4096 else "b'X' * " + str(len(data))
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
                result = PROFILE.sample(CI if environment is None else environment, cancellation)
        finally:
            for child in children:
                child.wait(timeout=2)
        self.assertEqual(list(self.raw.iterdir()), [])
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
        self.assertTrue(all(size <= PROFILE.LIMIT for size in sizes))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(result["admission"], "unadmitted")
        return result, calls

    def test_check_workflow_runner_reaches_complete_receipt(self):
        workflow = (ROOT / ".github/workflows/check.yml").read_text()
        job = workflow.split("  hosted-prerequisite-diagnostic:\n", 1)[1]
        job = re.split(r"\n  [a-z][a-z-]*:\n", job, maxsplit=1)[0]
        self.assertIn("python3 -B scripts/native-outer-runtime-profile.py", job)
        label, = re.findall(r"^    runs-on: ([a-z0-9.-]+)$", job, re.MULTILINE)
        # The workflow selects a provider label, not a collector constant.
        # ImageOS is the provider's build variable, not the workflow label.
        metadata = {"ubuntu-24.04": ("ubuntu24", "24.04"), "ubuntu-26.04": ("ubuntu26", "26.04")}
        self.assertIn(label, metadata)
        image_os, version_id = metadata[label]
        for version in (version_id, f'"{version_id}"'):
            with self.subTest(label=label, version=version):
                self.source("os-release").write_text(f'ID="ubuntu"\nVERSION_ID={version}\n')
                result, calls = self.execute(environment=CI | {"ImageOS": image_os})
                self.assertEqual((result["status"], result["reason"]), ("observed", "complete"))
                self.assertEqual(calls, list(PROFILE.COMMANDS))
                self.assertEqual((result["binding"]["image_os"], result["binding"]["image_version"]),
                                 (image_os, CI["ImageVersion"]))
                release = result["observations"]["files"]["os-release"]
                self.assertEqual((release["distribution"], release["version_id"]), ("ubuntu", version_id))

    def test_check_refuses_wrong_runner_image_before_collection(self):
        for update in ({"ImageOS": "ubuntu24"},
                       {"ImageOS": "ubuntu26-arm64", "RUNNER_ARCH": "ARM64"},
                       {"ImageOS": "ubuntu-26.04"}, {"ImageOS": ""},
                       {"ImageVersion": "20261122.9"}, {"ImageVersion": "20261122.9.1\n"}):
            with self.subTest(update=update):
                result, calls = self.execute(environment=CI | update)
                self.assertEqual((result["status"], result["reason"]), ("unavailable", "ci_identity_unavailable"))
                self.assertIsNone(result["binding"])
                self.assertIsNone(result["observations"])
                self.assertEqual(calls, [])

    def test_current_runner_metadata_requires_matching_os_release(self):
        for release in ('ID=ubuntu\nVERSION_ID="24.04"\n', 'ID=ubuntu\nVERSION_ID="26.04.1"\n',
                        'ID=debian\nVERSION_ID="26.04"\n'):
            with self.subTest(release=release):
                self.source("os-release").write_text(release)
                result, calls = self.execute()
                self.assertEqual((result["status"], result["reason"]), ("unavailable", "invalid_metadata"))
                self.assertIsNone(result["observations"])
                self.assertEqual(calls, list(PROFILE.COMMANDS))

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

    def test_apparmor_positive_facts_survive_original_partial_inventory(self):
        result, _ = self.execute(replacements={PROFILE.PACKAGE_QUERY:
                                b"docker-ce\tunknown ok not-installed\t\t\n"})
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["observations"]["packages"]["failure_detail"],
                         {"field": "version", "category": "empty", "row": 1,
                          "validated_dpkg_state": "not-installed"})
        facts = result["observations"]["apparmor"]
        for name, value in {"enabled": "Y", "restrict_unprivileged_userns": "1",
                            "namespace_mask": "present", "policy_v9": "yes"}.items():
            self.assertEqual(facts[name], {"status": "observed", "value": value})
        for name in ("parser", "abi_4_0"):
            self.assertEqual(facts[name]["sha256"], hashlib.sha256((SECRET + "\n").encode()).hexdigest())
            self.assertEqual(facts[name]["kind"], "regular")
        self.assertEqual(facts["parser_package_version"], {
            "status": "reported", "version": "4.0.1-0ubuntu1", "architecture": "amd64",
            "provenance": "installed_apparmor_package_metadata"})

    def test_version_and_local_database_facts_are_independent(self):
        md5 = self.host / PROFILE.PROVENANCE_PATHS[":md5sums"].lstrip("/")
        md5.write_text("0" * 32 + "  usr/sbin/apparmor_parser\n")
        result, _ = self.execute(replacements={PROFILE.APPARMOR_QUERY: b""})
        facts = result["observations"]["apparmor"]
        self.assertEqual(facts["parser_version"]["version"], "5.0.2")
        self.assertEqual(facts["parser_package_checksum"]["comparison"], "mismatch")
        self.assertEqual(facts["parser_package_owner"]["owner"], "apparmor")
        self.assertEqual(facts["parser_package_version"]["status"], "unavailable")
        self.assertEqual(facts["parser_diversion"]["registration"], "none")
        result, _ = self.execute(version_output=b"unparsed private output\n")
        self.assertEqual(result["observations"]["apparmor"]["parser_version"]["reason"], "invalid_metadata")
        self.assertEqual(result["observations"]["apparmor"]["parser_package_checksum"]["comparison"], "mismatch")

    def test_version_execution_uses_the_held_inert_executable(self):
        # Execute a private inert fixture through the actual fd/timeout path;
        # never invoke the system parser or a command selected by input.
        self.source("parser").write_text("#!/usr/bin/python3\nimport os\n"
            "assert os.environ == {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}\n"
            "assert 'NoNewPrivs:\\t1' in open('/proc/self/status').read()\n"
            "print('AppArmor parser version 5.0.2')\n")
        with PROFILE.private_outputs() as files:
            record = PROFILE.read_source("parser", files, time.monotonic() + 4,
                inspect=lambda fd, raw, metadata: dict(metadata,
                    version=PROFILE.parser_version(fd, files, time.monotonic() + 3, None)))
        self.assertEqual(record["version"]["version"], "5.0.2")
        self.assertEqual(record["sha256"], hashlib.sha256(self.source("parser").read_bytes()).hexdigest())

    def test_version_unsafe_modes_root_and_capabilities_refuse_without_child(self):
        for mode in (0o4755, 0o2755, 0o644):
            self.source("parser").chmod(mode)
            result, _ = self.execute()
            self.assertEqual(result["observations"]["apparmor"]["parser_version"]["reason"], "custody_failure")
        self.source("parser").chmod(0o755)
        for replacement in (patch.object(PROFILE, "unprivileged_context", return_value=False),
                            patch.object(PROFILE.os, "getxattr", return_value=b"capability")):
            with replacement:
                result, _ = self.execute()
            self.assertEqual(result["observations"]["apparmor"]["parser_version"]["status"], "unavailable")

    def test_privilege_context_refuses_root_identity_drift_and_process_capabilities(self):
        for uid, uids, gids in ((0, (0, 0, 0), (1, 1, 1)),
                                (1, (1, 0, 1), (1, 1, 1)), (1, (1, 1, 1), (1, 0, 1))):
            with patch.object(PROFILE.os, "getuid", return_value=uid), \
                 patch.object(PROFILE.os, "getresuid", return_value=uids), \
                 patch.object(PROFILE.os, "getresgid", return_value=gids), \
                 patch.object(PROFILE.ctypes, "CDLL") as libc:
                self.assertFalse(UNPRIVILEGED_CONTEXT())
                libc.assert_not_called()
        for field in (None, "effective", "permitted", "inheritable"):
            def capget(_header, caps):
                if field is not None:
                    setattr(caps[1], field, 1)
                return 0
            with patch.object(PROFILE.os, "getuid", return_value=1), \
                 patch.object(PROFILE.os, "getresuid", return_value=(1, 1, 1)), \
                 patch.object(PROFILE.os, "getresgid", return_value=(1, 1, 1)), \
                 patch.object(PROFILE.ctypes, "CDLL", return_value=SimpleNamespace(capget=capget)):
                self.assertEqual(UNPRIVILEGED_CONTEXT(), field is None)

    def test_version_change_refuses_hash_and_version_together(self):
        def replace(_fd):
            self.source("parser").unlink()
            self.source("parser").write_text("replacement")
        result, _ = self.execute(on_version=replace)
        facts = result["observations"]["apparmor"]
        self.assertEqual(facts["parser"]["status"], "unavailable")
        self.assertEqual(facts["parser_version"]["status"], "unavailable")
        self.assertEqual(facts["parser_package_checksum"]["status"], "unavailable")

    def test_local_database_aliases_and_diversions_are_closed(self):
        for suffix in ("list", "md5sums"):
            path = self.host / PROFILE.PROVENANCE_PATHS[":" + suffix].lstrip("/")
            path.write_text(path.read_text().replace("usr/sbin/", "sbin/"))
        path = self.host / PROFILE.PROVENANCE_PATHS["diversions"].lstrip("/")
        path.write_text("/sbin/apparmor_parser\n/private/" + SECRET + "\nlocal-package\n")
        result, _ = self.execute()
        facts = result["observations"]["apparmor"]
        self.assertEqual(facts["parser_package_owner"]["owner"], "apparmor")
        self.assertEqual(facts["parser_package_checksum"]["comparison"], "match")
        self.assertEqual(facts["parser_diversion"]["registration"], "package")

    def test_version_malformed_and_byte_limit_refusals_preserve_hash(self):
        for raw in (b"", b"AppArmor parser version 5.0.2", b"AppArmor parser version 5.x\n",
                    b"AppArmor parser version 5.0.2\n\x00", b"x" * (PROFILE.LIMIT + 1)):
            result, _ = self.execute(version_output=raw)
            facts = result["observations"]["apparmor"]
            self.assertEqual(facts["parser_version"]["status"], "unavailable")
            self.assertEqual(facts["parser"]["status"], "observed")

    def test_provenance_complete_package_lists_preserve_valid_rows_and_refuse_bad_rows(self):
        path = self.host / PROFILE.PROVENANCE_PATHS[":list"].lstrip("/")
        harmless = b"/.\n/usr\n/path with spaces\n"
        for target in (b"", b"/usr/sbin/apparmor_parser\n", b"/sbin/apparmor_parser\n"):
            with self.subTest(valid_target=target):
                path.write_bytes(harmless + target)
                result, _ = self.execute()
                facts = result["observations"]["apparmor"]
                self.assertEqual(facts["parser_package_owner"]["owner"], "apparmor" if target else "not_recorded")
                self.assertEqual(facts["parser_version"]["version"], "5.0.2")
                self.assertEqual(facts["parser_package_checksum"]["comparison"], "match")
        for bad in (b"/bad\x00name\n", b"relative/path\n", b"/bad\r\n", b"\n", b"/bad\x7f\n"):
            for target in (b"", b"/usr/sbin/apparmor_parser\n"):
                for first in (True, False):
                    with self.subTest(bad=bad, target=target, first=first):
                        path.write_bytes(harmless + (target + bad if first else bad + target))
                        result, _ = self.execute()
                        facts = result["observations"]["apparmor"]
                        self.assertEqual(facts["parser_package_owner"], {
                            "status": "unavailable", "reason": "invalid_metadata"})
                        self.assertEqual(facts["parser_version"]["version"], "5.0.2")
                        self.assertEqual(facts["parser_package_checksum"]["comparison"], "match")

    def test_provenance_complete_checksums_preserve_relative_paths_and_refuse_bad_rows(self):
        path = self.host / PROFILE.PROVENANCE_PATHS[":md5sums"].lstrip("/")
        target = path.read_bytes()
        harmless = b"0" * 32 + b"  usr/share/path with spaces\n"
        path.write_bytes(harmless + target.replace(b"usr/sbin/", b"sbin/"))
        result, _ = self.execute()
        self.assertEqual(result["observations"]["apparmor"]["parser_package_checksum"]["comparison"], "match")
        for bad in (b"usr/bad\x00name", b"/absolute/path", b"usr/bad\r", b"usr/bad\x7f"):
            for first in (True, False):
                with self.subTest(bad=bad, first=first):
                    malformed = b"0" * 32 + b"  " + bad + b"\n"
                    path.write_bytes(target + malformed if first else malformed + target)
                    result, _ = self.execute()
                    facts = result["observations"]["apparmor"]
                    self.assertEqual(facts["parser_package_checksum"], {
                        "status": "unavailable", "reason": "invalid_metadata"})
                    self.assertEqual(facts["parser_version"]["version"], "5.0.2")
                    self.assertEqual(facts["parser_package_owner"]["owner"], "apparmor")

    def test_provenance_complete_diversions_preserve_local_marker_and_refuse_bad_rows(self):
        path = self.host / PROFILE.PROVENANCE_PATHS["diversions"].lstrip("/")
        for package, expected in ((b":", "local"), (b"local-package", "package"),
                                  (b"local-package:amd64", "package")):
            with self.subTest(package=package):
                path.write_bytes(b"/sbin/apparmor_parser\n/path with spaces\n" + package + b"\n")
                result, _ = self.execute()
                self.assertEqual(result["observations"]["apparmor"]["parser_diversion"]["registration"], expected)
        target = b"/usr/sbin/apparmor_parser\n/diverted\n:\n"
        for malformed in (b"/other\n/destination\nnot a package\n", b"relative\n/destination\nvalid-package\n",
                          b"/other\n/dest\x00ination\nvalid-package\n", b"/other\n/destination\nPACKAGE\n",
                          b"/other\r\n/destination\nvalid-package\n"):
            for present in (False, True):
                with self.subTest(malformed=malformed, present=present):
                    path.write_bytes((target if present else b"") + malformed)
                    result, _ = self.execute()
                    facts = result["observations"]["apparmor"]
                    self.assertEqual(facts["parser_diversion"], {
                        "status": "unavailable", "reason": "invalid_metadata"})
                    self.assertEqual(facts["parser_version"]["version"], "5.0.2")
                    self.assertEqual(facts["parser_package_owner"]["owner"], "apparmor")
                    self.assertEqual(facts["parser_package_checksum"]["comparison"], "match")

    def test_parser_capture_terminal_failures_stop_sample_and_clean_outputs(self):
        real_capture = PROFILE.capture
        for reason in ("completion_unknown", "collector_io_failure", "cleanup_failure"):
            captured = []
            def fail_parser(command, files, *args, **kwargs):
                captured.append(command)
                if kwargs.get("parser_fd") is not None:
                    files.discard()
                    raise PROFILE.Unavailable(reason)
                return real_capture(command, files, *args, **kwargs)
            with self.subTest(reason=reason), patch.object(PROFILE, "capture", side_effect=fail_parser):
                result, calls = self.execute()
                self.assertEqual(result, {
                    "schema_version": 5, "purpose": PROFILE.PURPOSE, "admission": "unadmitted",
                    "provenance": "unverified_installed_observation", "status": "unavailable",
                    "reason": reason, "binding": PROFILE.binding(CI), "observations": None})
                self.assertEqual(calls, list(PROFILE.COMMANDS[:-1]))
                self.assertEqual(len(captured), len(PROFILE.COMMANDS))
                self.assertEqual(captured[-1][-1], "--version")
                self.assertNotIn(PROFILE.APPARMOR_QUERY, captured)
                self.assertEqual(list(self.raw.iterdir()), [])

    def test_parser_capture_recoverable_failures_preserve_independent_facts(self):
        real_capture = PROFILE.capture
        for reason in ("tool_unavailable", "command_failed", "timeout", "output_overflow", "invalid_metadata"):
            def fail_parser(command, files, *args, **kwargs):
                if kwargs.get("parser_fd") is not None:
                    raise PROFILE.Unavailable(reason)
                return real_capture(command, files, *args, **kwargs)
            with self.subTest(reason=reason), patch.object(PROFILE, "capture", side_effect=fail_parser):
                result, calls = self.execute()
            self.assertEqual((result["status"], result["reason"]), ("partial", "complete"))
            facts = result["observations"]["apparmor"]
            self.assertEqual(facts["parser_version"], {"status": "unavailable", "reason": reason})
            self.assertEqual(facts["parser"]["status"], "observed")
            self.assertEqual(facts["parser_package_version"]["status"], "reported")
            self.assertEqual(facts["parser_package_checksum"]["comparison"], "match")
            self.assertEqual(calls, list(PROFILE.COMMANDS))
            self.assertEqual(list(self.raw.iterdir()), [])

    def test_version_exact_stream_limit_and_cancellation_cleanup(self):
        prefix = b"AppArmor parser version 5.0.2\n"
        # Bounded printable lines make the first output exactly 64 KiB.
        remaining = PROFILE.LIMIT - len(prefix)
        raw = prefix + (b"x" * 127 + b"\n") * (remaining // 128)
        raw += b"x" * (remaining % 128 - 1) + b"\n"
        self.assertEqual(len(raw), PROFILE.LIMIT)
        result, _ = self.execute(version_output=raw)
        self.assertEqual(result["observations"]["apparmor"]["parser_version"]["version"], "5.0.2")
        cancellation = PROFILE.Cancellation()
        with self.assertRaises(PROFILE.Cancelled):
            self.execute(cancellation=cancellation,
                         on_version=lambda _fd: cancellation.request(signal.SIGTERM))
        self.assertEqual(list(self.raw.iterdir()), [])

    def test_database_missing_malformed_and_duplicate_records_are_independent(self):
        md5 = self.host / PROFILE.PROVENANCE_PATHS[":md5sums"].lstrip("/")
        md5.unlink()
        diversion = self.host / PROFILE.PROVENANCE_PATHS["diversions"].lstrip("/")
        diversion.write_bytes(b"incomplete\n")
        result, _ = self.execute()
        facts = result["observations"]["apparmor"]
        self.assertEqual(facts["parser_version"]["version"], "5.0.2")
        self.assertEqual(facts["parser_package_checksum"]["reason"], "source_missing")
        self.assertEqual(facts["parser_diversion"]["reason"], "invalid_metadata")
        alternate = self.host / PROFILE.PROVENANCE_PATHS[":amd64:list"].lstrip("/")
        alternate.write_text("/usr/sbin/apparmor_parser\n")
        alternate.chmod(0o644)
        result, _ = self.execute()
        self.assertEqual(result["observations"]["apparmor"]["parser_package_owner"]["reason"], "invalid_metadata")

    def test_apparmor_missing_unexpected_and_negative_fields_are_independent(self):
        self.source("parser").unlink()
        self.source("namespace_mask").write_bytes(b"malformed/" + SECRET.encode())
        self.source("enabled").write_bytes(b"N\n")
        self.source("restrict_unprivileged_userns").write_bytes(b"0\n")
        self.source("policy_v9").write_bytes(b"no\n")
        result, _ = self.execute()
        facts = result["observations"]["apparmor"]
        self.assertEqual(result["status"], "partial")
        self.assertEqual(facts["parser"], {"status": "unavailable", "reason": "source_missing"})
        self.assertEqual(facts["namespace_mask"], {"status": "unavailable", "reason": "invalid_metadata"})
        for name, value in (("enabled", "N"), ("restrict_unprivileged_userns", "0"), ("policy_v9", "no")):
            self.assertEqual(facts[name], {"status": "observed", "value": value})
        self.assertEqual(facts["abi_4_0"]["status"], "observed")

    def test_apparmor_package_version_unavailable_does_not_hide_features(self):
        for raw in (b"", b"apparmor\tdeinstall ok config-files\t4.0.1\tamd64\n",
                    b"apparmor\tinstall ok installed\t\tamd64\n", b"private\n",
                    b"docker-ce\tinstall ok installed\t1\tamd64\n"):
            with self.subTest(raw=raw):
                result, _ = self.execute(replacements={PROFILE.APPARMOR_QUERY: raw})
                facts = result["observations"]["apparmor"]
                self.assertEqual(facts["parser_package_version"]["status"], "unavailable")
                self.assertEqual(facts["enabled"]["value"], "Y")
        for options in ({"missing": PROFILE.APPARMOR_QUERY}, {"statuses": {PROFILE.APPARMOR_QUERY: 124}}):
            result, _ = self.execute(**options)
            self.assertEqual(result["observations"]["apparmor"]["parser_package_version"]["status"], "unavailable")

    def test_apparmor_fixed_files_reject_links_permissions_and_arbitrary_access(self):
        for name in PROFILE.APPARMOR_PATHS:
            target = self.source(name)
            original = target.read_bytes()
            target.unlink()
            target.symlink_to("/" + SECRET)
            with self.subTest(name=name), self.assertRaises(PROFILE.Unavailable):
                self.read(name)
            target.unlink()
            target.write_bytes(original)
            target.chmod(0o666)
            with self.assertRaises(PROFILE.Unavailable): self.read(name)
            target.chmod(0o644)
        with PROFILE.private_outputs() as files, patch.object(PROFILE.os, "open") as opened:
            with self.assertRaises(PROFILE.Unavailable):
                PROFILE.read_source("/etc/" + SECRET, files, time.monotonic() + 2)
            opened.assert_not_called()
        real_open = os.open
        def denied(path, flags, *args, **kwargs):
            if path == "v9": raise PermissionError(errno.EACCES, SECRET)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(PROFILE.os, "open", side_effect=denied):
            result, _ = self.execute()
        self.assertEqual(result["observations"]["apparmor"]["policy_v9"], {
            "status": "unavailable", "reason": "custody_failure", "failure_detail":
            {"guard": "open", "component": "leaf", "category": "permission_denied"}})

    def test_apparmor_feature_caps_framing_and_pseudo_file_sizes(self):
        for raw in (b"", b"Y\n\n", b" Y\n", b"Y\x00", b"\xff", b"X" * 129):
            self.source("enabled").write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(PROFILE.Unavailable): self.read("enabled")
        self.source("enabled").write_bytes(b"Y\n")
        original_stat, original_fstat = os.stat, os.fstat
        inode = self.source("enabled").stat().st_ino
        def pseudo(info):
            if info.st_ino != inode: return info
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            fields["st_size"] = 4096
            return SimpleNamespace(**fields)
        with patch.object(PROFILE.os, "stat", side_effect=lambda *a, **kw: pseudo(original_stat(*a, **kw))), \
             patch.object(PROFILE.os, "fstat", side_effect=lambda *a: pseudo(original_fstat(*a))):
            self.assertEqual(self.read("enabled"), {"status": "observed", "value": "Y"})

    def test_apparmor_descriptor_custody_and_replacement_refusal(self):
        real_open, real_read, real_close = os.open, os.read, os.close
        for name in ("parser", "abi_4_0", "policy_v9"):
            opened, closed = [], []
            source = self.source(name)
            inode = source.stat().st_ino
            changed = []
            def held_open(path, flags, *args, **kwargs):
                self.assertTrue(flags & os.O_NOFOLLOW)
                if path != str(self.host): self.assertIn("dir_fd", kwargs)
                fd = real_open(path, flags, *args, **kwargs)
                opened.append(fd)
                return fd
            def held_close(fd):
                closed.append(fd)
                return real_close(fd)
            def replace(fd, count):
                raw = real_read(fd, count)
                if os.fstat(fd).st_ino == inode and not changed:
                    source.unlink()
                    source.write_bytes(b"replacement")
                    changed.append(True)
                return raw
            with PROFILE.private_outputs() as files, \
                 patch.object(PROFILE.os, "open", side_effect=held_open), \
                 patch.object(PROFILE.os, "close", side_effect=held_close), \
                 patch.object(PROFILE.os, "read", side_effect=replace):
                with self.subTest(name=name), self.assertRaises(PROFILE.Unavailable) as caught:
                    PROFILE.read_source(name, files, time.monotonic() + 2)
                self.assertEqual(caught.exception.reason, "custody_failure")
                self.assertEqual(sorted(opened), sorted(closed))

    def test_namespace_mask_projects_only_exact_token_membership(self):
        cases = [(b"userns_create", "present"), (b"userns_create\n", "present"),
                 (b"userns_create other_feature\n", "present"),
                 (b"other_feature userns_create\n", "present"),
                 (b"userns_create\tother_feature\n", "present"),
                 (b"other_feature\tuserns_create\n", "present"),
                 (b" \tother_feature\t  userns_create \t\n", "present"),
                 (b"other_feature\n", "absent"),
                 (b"userns_create_extra userns_creat xuserns_create\n", "absent")]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.source("namespace_mask").write_bytes(raw)
                self.assertEqual(self.read("namespace_mask"), {"status": "observed", "value": expected})
        self.source("namespace_mask").write_bytes(("userns_create " + SECRET.replace("-", "_") + "\n").encode())
        result, _ = self.execute()
        self.assertEqual(result["observations"]["apparmor"]["namespace_mask"],
                         {"status": "observed", "value": "present"})
        self.assertNotIn(SECRET.replace("-", "_"), json.dumps(result))

    def test_namespace_mask_refuses_malformed_or_ambiguous_lists(self):
        for raw in (b"", b" \t\n", b"userns_create\n\n", b"userns_create\nother_feature\n",
                    b"userns_create\r\n", b"userns_create\vother_feature\n",
                    b"userns_create\fother_feature\n", b"userns_create\x00other_feature\n",
                    b"userns_create \xff\n", b"userns_create other-feature\n",
                    b"userns_create other/feature\n", b"userns_create OTHER\n", b"x" * 129):
            with self.subTest(raw=raw):
                self.source("namespace_mask").write_bytes(raw)
                with self.assertRaises(PROFILE.Unavailable): self.read("namespace_mask")
                result, _ = self.execute()
                record = result["observations"]["apparmor"]["namespace_mask"]
                self.assertEqual(record["status"], "unavailable")
                self.assertEqual(set(record), {"status", "reason"})
                self.assertEqual(record["reason"], "output_overflow" if len(raw) > 128 else "invalid_metadata")

    def test_feature_overflow_is_independent_but_total_exhaustion_stops_collection(self):
        self.source("enabled").write_bytes(b"X" * 129)
        result, calls = self.execute()
        self.assertEqual(calls, list(PROFILE.COMMANDS))
        self.assertEqual(result["observations"]["apparmor"]["enabled"],
                         {"status": "unavailable", "reason": "output_overflow"})
        self.assertEqual(result["observations"]["apparmor"]["policy_v9"]["value"], "yes")
        self.source("enabled").write_bytes(b"Y\n")
        real_read = PROFILE.read_source
        for exact in (True, False):
            visited = []
            def exhaust(source_id, files, *args, **kwargs):
                visited.append(source_id)
                if source_id == "parser":
                    files.used = PROFILE.TOTAL_SOURCE - (self.source("parser").stat().st_size if exact else 1)
                return real_read(source_id, files, *args, **kwargs)
            with self.subTest(exact=exact), patch.object(PROFILE, "read_source", side_effect=exhaust):
                result, calls = self.execute()
                self.assertEqual(visited, ["parser"])
                self.assertEqual(calls, list(PROFILE.COMMANDS[:-1]))
                self.assertEqual((result["status"], result["reason"], result["observations"]),
                                 ("unavailable", "output_overflow", None))

    def test_exact_total_allows_the_last_source_to_finish(self):
        with PROFILE.private_outputs() as files:
            size = self.source("helper:invoke-rc.d").stat().st_size
            files.used = PROFILE.TOTAL_SOURCE - size
            record = PROFILE.read_source("helper:invoke-rc.d", files, time.monotonic() + 2)
            self.assertEqual(record["status"], "observed")
            self.assertEqual(files.used, PROFILE.TOTAL_SOURCE)

    def test_exceeded_budget_refuses_before_new_read_or_child(self):
        with PROFILE.private_outputs() as files:
            files.used = PROFILE.TOTAL_SOURCE + 1
            with patch.object(PROFILE.os, "read") as read, \
                 patch.object(PROFILE.os, "open") as opened, \
                 patch.object(PROFILE.subprocess, "Popen") as child:
                with self.assertRaises(PROFILE.Unavailable):
                    PROFILE.read_source("parser", files, time.monotonic() + 2)
                with self.assertRaises(PROFILE.Unavailable):
                    PROFILE.capture(PROFILE.APPARMOR_QUERY, files, "command", time.monotonic() + 2)
                read.assert_not_called()
                opened.assert_not_called()
                child.assert_not_called()

    def test_older_scalar_features_still_have_closed_exact_framing(self):
        for name, values in (("enabled", (b"Y", b"N")),
                             ("restrict_unprivileged_userns", (b"1", b"0")),
                             ("policy_v9", (b"yes", b"no"))):
            for value in values:
                for suffix in (b"", b"\n"):
                    self.source(name).write_bytes(value + suffix)
                    self.assertEqual(self.read(name), {"status": "observed", "value": value.decode()})
                for raw in (b" " + value, value + b" other", value + b"\n\n", value + b"\r\n"):
                    self.source(name).write_bytes(raw)
                    with self.assertRaises(PROFILE.Unavailable): self.read(name)

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
        return self.host / (PROFILE.SOURCE_PATHS | PROFILE.APPARMOR_PATHS | PROFILE.PROVENANCE_PATHS)[source_id].lstrip("/")

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
        for raw in (b"", b'ID=""ubuntu""\nVERSION_ID="26.04"\n',
                    b'ID=ubuntu\nID=ubuntu\nVERSION_ID="26.04"\n', b"\xff"):
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
                self.assertEqual(record["schema_version"], 5)
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
                   ({"guard": "owner", "component": "ancestor_8", "category": "check_failed"}, "custody_failure"),
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
        self.assertEqual(result["schema_version"], 5)
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
        self.assertEqual((result["schema_version"], result["status"], result["reason"]), (5, "observed", "complete"))
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
        self.assertEqual((result["schema_version"], result["status"], result["admission"]), (5, "partial", "unadmitted"))
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
