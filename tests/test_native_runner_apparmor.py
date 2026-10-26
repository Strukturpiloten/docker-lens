"""Hermetic profile controls: no parser, runtime, /run, or policy operations."""

import contextlib
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_native_hostname_wiring import assert_current_cohort

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("runner_apparmor", ROOT / "scripts/native-runner-apparmor.py")
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)
SOURCE = (ROOT / "scripts/native-conformance.sh").read_text()
RUNTIME = (ROOT / "scripts/native-outer-runtime.sh").read_text()
NONCE = "a" * 32
CID = "b" * 64
PIN = "example.invalid/engine:29@sha256:" + "c" * 64
HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
          "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
          "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens", "GITHUB_JOB": "native-conformance",
          "GITHUB_WORKFLOW_REF": "Strukturpiloten/docker-lens/.github/workflows/native-validation.yml@refs/heads/main",
          "GITHUB_RUN_ID": "127", "GITHUB_RUN_ATTEMPT": "1", "ImageOS": "ubuntu24",
          "ImageVersion": "20261020.1.0", "DOCKERLENS_NATIVE_CANDIDATE_SHA": "d" * 40}
BOX_HOSTED = HOSTED | {
    "GITHUB_REPOSITORY": "Strukturpiloten/boxferry", "GITHUB_JOB": "lanes",
    "GITHUB_WORKFLOW_REF": "Strukturpiloten/boxferry/.github/workflows/reviewed-docker-consumer-validation.yml@refs/heads/main",
}


# Independent behavioral expectations for AppArmor v4.0.1, not a real parser.
# Exact source b0eb95457bc2de401920308869d016e696c73664, parser.h warning
# categories/defaults and parser_main.c's separate warn/Werror options; ABI and
# downgrade pwarn sites gate on warn, while common_warn_once's rule-not-enforced
# fatal path is independent of its reporting mask. No upstream code is copied.
WARNING_BITS_401 = {"rule-not-enforced": 1, "rule-downgraded": 2, "abi": 4,
                    "config": 16, "cache": 32, "jobs": 128, "unexpected": 512, "override": 4096}
DEFAULT_WARNING_MASK_401 = 16 | 32 | 128 | 512 | 4096


def warning_masks_401(arguments):
    reporting, severity = DEFAULT_WARNING_MASK_401, 0
    for argument in arguments:
        option, separator, category = argument.partition("=")
        if separator and option in ("--warn", "--Werror"):
            if category not in WARNING_BITS_401:
                raise AssertionError("unsupported synthetic warning category")
            if option == "--warn":
                reporting |= WARNING_BITS_401[category]
            else:
                severity |= WARNING_BITS_401[category]
    return reporting, severity


def warning_effect_401(arguments, category):
    reporting, severity = warning_masks_401(arguments)
    selected = WARNING_BITS_401[category]
    reported = bool(reporting & selected)
    fatal = bool(severity & selected) and (reported or category == "rule-not-enforced")
    return reported, fatal


class WarningContract401Tests(unittest.TestCase):
    def test_default_masks_do_not_enable_abi_or_downgrade_by_severity(self):
        # Literal old severity-only configuration is the counterexample: an
        # ABI/downgrade site is invisible, so checking stderr cannot catch it.
        old = ("--Werror=rule-not-enforced", "--Werror=rule-downgraded", "--Werror=abi")
        self.assertEqual(warning_masks_401(old), (4784, 7))
        self.assertEqual(warning_effect_401(old, "abi"), (False, False))
        self.assertEqual(warning_effect_401(old, "rule-downgraded"), (False, False))
        self.assertEqual(warning_effect_401(old, "rule-not-enforced"), (False, True))

    def test_reporting_and_fatal_severity_are_independent_for_pwarn_sites(self):
        for category in ("abi", "rule-downgraded"):
            with self.subTest(category=category):
                self.assertEqual(warning_effect_401(("--warn=" + category,), category), (True, False))
                self.assertEqual(warning_effect_401(("--warn=" + category, "--Werror=" + category), category), (True, True))

    def test_rule_not_enforced_preserves_its_separate_fatal_path(self):
        self.assertEqual(warning_effect_401((), "rule-not-enforced"), (False, False))
        self.assertEqual(warning_effect_401(("--Werror=rule-not-enforced",), "rule-not-enforced"), (False, True))
        self.assertEqual(warning_effect_401(("--warn=rule-not-enforced",), "rule-not-enforced"), (True, False))


def definition(name, source=SOURCE):
    start = source.index("\n" + name + "() {") + 1
    return source[start:source.index("\n}\n", start) + 3]


def private_run(*, box=False):
    # Match the coordinator's alphanumeric mktemp suffix, not tempfile's
    # additional leading-underscore possibility (native run labels forbid it).
    # Production custody requires a direct /tmp child, even under gate TMPDIR.
    while True:
        directory = tempfile.TemporaryDirectory(prefix="boxferry-docker-core." if box else "dockerlens-native.", dir="/tmp")
        suffix = Path(directory.name).name.rsplit(".", 1)[1]
        acceptable = suffix.isalnum() if box else suffix[0].isalnum()
        if acceptable:
            return directory
        directory.cleanup()


class AdmissionTests(unittest.TestCase):
    def test_existing_workflow_consumers_keep_admission_and_success_only_artifacts(self):
        for name in ("check", "native-validation", "release-validation"):
            workflow = (ROOT / f".github/workflows/{name}.yml").read_text()
            native = workflow.split("  native-conformance:\n", 1)[1].split("  native-gate:\n", 1)[0]
            native = native.split("\n  check-gate:", 1)[0].split("\n  release-gate:", 1)[0]
            self.assertIn("DOCKERLENS_OUTER_ENGINE: docker", native)
            self.assertIn("DOCKERLENS_NATIVE_CANDIDATE_SHA:", native)
            self.assertIn("./scripts/native-conformance.sh", native)
            self.assertIn("if-no-files-found: error", native)
            self.assertNotIn("continue-on-error", native)
            self.assertNotIn("if: always()", native.split("actions/upload-artifact", 1)[1])
            self.assertIn('test "$NATIVE_RESULT" = success', workflow)
            if name == "check":
                self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", native)
                self.assertIn("${{ github.sha }}", native)
            elif name == "native-validation":
                self.assertLess(native.index("ref: main"), native.index("scripts/native-dispatch-admission.py"))
                self.assertLess(native.index("scripts/native-dispatch-admission.py"),
                                native.index("ref: ${{ inputs.expected_sha }}"))
                self.assertEqual(workflow.count("run: python3 scripts/native-dispatch-admission.py"), 3)
            else:
                self.assertNotIn("workflow_call:", workflow)
                self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"', native)
                self.assertIn('test "$(git rev-parse origin/main)" = "$EXPECTED_SHA"', native)

    def test_receipt_schema_and_all_projected_values_are_closed(self):
        receipt = {"schema": 1, "prerequisite": "github_runner_userns_v1", "outcome": "incomplete",
                   "candidate": "d" * 40, "label": "unverified", "profile_sha256": "a" * 64,
                   "parser_sha256": "b" * 64, "abi_sha256": "c" * 64,
                   "parser_version": "4.0.1", "cleanup": "removed"}
        APP.validate_receipt(receipt, "d" * 40)
        with self.assertRaises(APP.Refused):
            APP.validate_receipt(receipt, "d" * 40, require_verified=True)
        accepted = receipt | {"label": "verified", "outcome": "verified"}
        APP.validate_receipt(accepted, "d" * 40, require_verified=True)
        record = "DOCKERLENS_NATIVE_APPARMOR_PROFILE: " + json.dumps(accepted)
        APP.validate_cleanup_record(record, "d" * 40)
        wrong = [None, [], receipt | {"unknown": "private"}, receipt | {"schema": True},
                 receipt | {"outcome": "verified"}, accepted | {"outcome": "incomplete"},
                 receipt | {"label": "verified", "cleanup": "not_loaded"},
                 receipt | {"parser_version": "unverified"}, receipt | {"candidate": "e" * 40}]
        for key in receipt:
            wrong.extend((receipt | {key: "private\nraw"}, receipt | {key: None},
                          {other: value for other, value in receipt.items() if other != key}))
        for value in wrong:
            with self.subTest(value=value), self.assertRaises(APP.Refused):
                APP.validate_receipt(value, "d" * 40)
        for raw in (record + "extra", record.replace('"schema": 1', '"schema":1,"schema":1'),
                    "DOCKERLENS_NATIVE_APPARMOR_EXPERIMENT: " + json.dumps(accepted),
                    "DOCKERLENS_NATIVE_APPARMOR_PROFILE: " + json.dumps(receipt), "x" * 8193):
            with self.subTest(raw=raw), self.assertRaises((APP.Refused, ValueError)):
                APP.validate_cleanup_record(raw, "d" * 40)
        with self.assertRaises(APP.Refused):
            APP.validate_cleanup_record(record, "e" * 40)

    def test_read_only_receipt_validation_needs_no_runner_or_privileged_io(self):
        accepted = {"schema": 1, "prerequisite": "github_runner_userns_v1", "outcome": "verified",
                    "candidate": "d" * 40, "label": "verified", "profile_sha256": "a" * 64,
                    "parser_sha256": "b" * 64, "abi_sha256": "c" * 64,
                    "parser_version": "4.0.1", "cleanup": "removed"}
        record = "DOCKERLENS_NATIVE_APPARMOR_PROFILE: " + json.dumps(accepted)
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(APP, "RunnerProfile") as profile, \
                mock.patch.object(APP.sys, "stdin", io.StringIO(record)):
            self.assertEqual(APP.main(["validate-receipt", "d" * 40]), 0)
            profile.assert_not_called()

    def test_failure_stage_output_is_closed_and_does_not_echo_evidence(self):
        for stage in (*sorted(APP.STAGES), "private/path\nraw parser diagnostic"):
            with self.subTest(stage=stage):
                profile = mock.Mock(stage=stage)
                profile.prepare.side_effect = APP.Refused("private/raw evidence")
                output = io.StringIO()
                with mock.patch.object(APP, "RunnerProfile", return_value=profile), contextlib.redirect_stderr(output):
                    self.assertEqual(APP.main(["prepare", "directory", "upstream-rootless", NONCE, "name", "run", PIN]), 2)
                expected = stage if stage in APP.STAGES else "admission"
                self.assertEqual(output.getvalue(), "DOCKERLENS_NATIVE_APPARMOR_PROFILE: "
                                 f"operation=prepare stage={expected} outcome=refused cleanup=retained\n")

    def test_completed_query_rejects_stderr_and_nonzero_without_echo(self):
        with private_run() as run, mock.patch.object(APP, "OWNER", os.geteuid()):
            profile = APP.RunnerProfile(run, "upstream-rootless", NONCE, HOSTED, APP.Cancellation())
            for code in ("import sys; sys.stderr.write('private evidence')", "raise SystemExit(42)"):
                with self.subTest(code=code), self.assertRaises(APP.Refused):
                    profile.query((sys.executable, "-c", code))

    def test_exact_context_and_every_forbidden_selection_refuse_before_io(self):
        self.assertTrue(APP.admitted(HOSTED))
        for workflow, event in (("check", "push"), ("native-validation", "workflow_dispatch"),
                                ("release-validation", "workflow_dispatch")):
            context = HOSTED | {"GITHUB_WORKFLOW_REF": f"Strukturpiloten/docker-lens/.github/workflows/{workflow}.yml@refs/heads/main",
                                "GITHUB_EVENT_NAME": event}
            self.assertTrue(APP.admitted(context))
            for forbidden in ("pull_request", "pull_request_target", "workflow_call", "schedule",
                              "workflow_dispatch" if event == "push" else "push"):
                self.assertFalse(APP.admitted(context | {"GITHUB_EVENT_NAME": forbidden}))
        for key in HOSTED:
            with self.subTest(key=key):
                self.assertFalse(APP.admitted(HOSTED | {key: "wrong"}))
        for key in APP.SELECTORS:
            self.assertFalse(APP.admitted(HOSTED | {key: "ambient"}))
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(APP.os, "mkdir") as mkdir:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(APP.main(["prepare", "/tmp/dockerlens-native.abcdefgh", "upstream-rootless", NONCE, "name", "run", PIN]), 2)
            mkdir.assert_not_called()
        with mock.patch.object(APP, "OWNER", os.geteuid()):
            for lane in ("debian11-rootless", "upstream-rootful", "debian11-rootful", ""):
                with self.assertRaises(APP.Refused):
                    APP.RunnerProfile("/tmp/dockerlens-native.abcdefgh", lane, NONCE, HOSTED, APP.Cancellation())

    def test_fixed_profile_has_no_attachment_includes_or_other_rules(self):
        name = "dockerlens-127-upstream-rootless-127-1-" + NONCE
        text = APP.profile_bytes(name).decode()
        self.assertEqual(text, f"abi <abi/4.0>,\nprofile {name} flags=(unconfined) {{\n  userns,\n}}\n")
        for bad in ("unconfined", "docker-default", name + "\n", "/bin/rootlesskit", "../profile"):
            with self.assertRaises(APP.Refused):
                APP.profile_bytes(bad)

    def test_fixed_subprocess_environment_ignores_ambient_parser_configuration(self):
        with private_run() as run, \
                mock.patch.object(APP, "OWNER", os.geteuid()), \
                mock.patch.dict(os.environ, {"APPARMOR_CONFIG": "/private/ambient"}), \
                mock.patch.object(APP.CaptureContext, "capture", return_value=b"") as capture:
            profile = APP.RunnerProfile(run, "upstream-rootless", NONCE, HOSTED, APP.Cancellation())
            profile.query((str(APP.PARSER), *APP.COMMON, "--version"))
            command = capture.call_args.args[0]
            files = capture.call_args.args[1]
            self.assertEqual(command, (str(APP.PARSER), *APP.COMMON, "--version"))
            self.assertNotIn("timeout", command)
            self.assertNotIn("APPARMOR_CONFIG", files.context.environment)
            self.assertNotIn("HOME", files.context.environment)

    def test_source_selector_is_closed_and_checks_exact_clean_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            tools = Path(temporary)
            (tools / "timeout").symlink_to("/usr/bin/timeout")
            git = tools / "git"
            git.write_text("#!/bin/sh\ncase \" $* \" in *' rev-parse '*) printf '%s\\n' \"$MOCK_HEAD\";; *' status '*) printf '%s' \"$MOCK_DIRTY\";; *) exit 9;; esac\n")
            git.chmod(0o700)
            env = HOSTED | {"PATH": temporary, "MOCK_HEAD": "d" * 40, "MOCK_DIRTY": ""}
            body = ("set -euo pipefail\n" + definition("native_outer_policy", RUNTIME)
                    + definition("select_apparmor_profile")
                    + "\nlane=$1; native_outer_engine=$2; script_dir=/reviewed/scripts\n"
                    + "select_apparmor_profile; printf '%s' \"$apparmor_profile\"\n")
            def invoke(lane="upstream-rootless", engine="docker", changes=None):
                return subprocess.run(["/bin/bash", "-c", body, "test", lane, engine],
                                      env=env | (changes or {}), capture_output=True, timeout=3)
            self.assertEqual(invoke().stdout, b"github_runner_userns_v1")
            for lane in ("debian11-rootless", "upstream-rootful", "debian11-rootful"):
                self.assertEqual(invoke(lane=lane).stdout, b"")
            for changes in ({"MOCK_DIRTY": " M source"}, {"MOCK_HEAD": "e" * 40},
                            {"GITHUB_EVENT_NAME": "push"}, {"GITHUB_JOB": "other"},
                            {"RUNNER_ENVIRONMENT": "self-hosted"}, {"DOCKER_HOST": "tcp://remote"}):
                self.assertEqual(invoke(changes=changes).returncode, 2)
            self.assertEqual(invoke(engine="podman").returncode, 2)
            for workflow, event in (("check", "push"), ("release-validation", "workflow_dispatch")):
                changes = {"GITHUB_WORKFLOW_REF": f"Strukturpiloten/docker-lens/.github/workflows/{workflow}.yml@refs/heads/main",
                           "GITHUB_EVENT_NAME": event}
                self.assertEqual(invoke(changes=changes).stdout, b"github_runner_userns_v1")
                for wrong in ({"GITHUB_REF": "refs/pull/128/merge"}, {"GITHUB_JOB": "candidate"},
                              {"GITHUB_REPOSITORY": "fork/docker-lens"}, {"MOCK_HEAD": "e" * 40},
                              {"MOCK_DIRTY": " M source"}, {"DOCKERLENS_NATIVE_CANDIDATE_SHA": ""},
                              {"GITHUB_EVENT_NAME": "pull_request"}, {"RUNNER_ENVIRONMENT": "self-hosted"}):
                    self.assertEqual(invoke(changes=changes | wrong).returncode, 2)


class BoxAdmissionTests(unittest.TestCase):
    def test_only_literal_box_context_is_admitted_and_no_lane_or_directory_is_selected_by_caller(self):
        self.assertTrue(APP.admitted(BOX_HOSTED))
        self.assertEqual(APP.consumer_mode(BOX_HOSTED), APP.BOX_CONSUMER)
        self.assertEqual(APP.consumer_mode(HOSTED), APP.NATIVE_CONSUMER)
        wrong = [BOX_HOSTED | {key: "wrong"} for key in BOX_HOSTED]
        wrong += [BOX_HOSTED | {key: "ambient"} for key in APP.SELECTORS]
        wrong += [BOX_HOSTED | change for change in (
            {"GITHUB_REF": "refs/pull/469/merge"}, {"GITHUB_EVENT_NAME": "push"},
            {"GITHUB_EVENT_NAME": "workflow_call"}, {"RUNNER_ENVIRONMENT": "self-hosted"},
            {"GITHUB_JOB": "native-conformance"}, {"GITHUB_REPOSITORY": "Strukturpiloten/docker-lens"},
            {"GITHUB_WORKFLOW_REF": HOSTED["GITHUB_WORKFLOW_REF"]},
            {"GITHUB_WORKFLOW_REF": BOX_HOSTED["GITHUB_WORKFLOW_REF"].replace("refs/heads/main", "refs/heads/nonce")},
            {"GITHUB_RUN_ID": "0"}, {"GITHUB_RUN_ATTEMPT": "01"}, {"GITHUB_RUN_ID": "1" * 21},
            {"DOCKERLENS_NATIVE_CANDIDATE_SHA": "e" * 39},
        )]
        for environment in wrong:
            with self.subTest(environment=environment):
                self.assertFalse(APP.admitted(environment))
        with mock.patch.object(APP, "OWNER", os.geteuid()), mock.patch.object(APP.os, "mkdir") as mkdir:
            valid = "/tmp/boxferry-docker-core.Ab12Cd34"
            for directory in ("/tmp/dockerlens-native.Ab12Cd34", valid + "/child", valid + "x",
                              "/elsewhere/boxferry-docker-core.Ab12Cd34", valid.replace("Ab", "_b")):
                with self.subTest(directory=directory), self.assertRaises(APP.Refused):
                    APP.RunnerProfile(directory, "upstream-rootless", NONCE, BOX_HOSTED, APP.Cancellation())
            for lane in ("debian11-rootless", "upstream-rootful", "debian11-rootful", ""):
                with self.subTest(lane=lane), self.assertRaises(APP.Refused):
                    APP.RunnerProfile(valid, lane, NONCE, BOX_HOSTED, APP.Cancellation())
            for nonce in ("", "a" * 31, "A" * 32, NONCE + "/path", "docker-default"):
                with self.subTest(nonce=nonce), self.assertRaises(APP.Refused):
                    APP.RunnerProfile(valid, "upstream-rootless", nonce, BOX_HOSTED, APP.Cancellation())
            with self.assertRaises(APP.Refused):
                APP.RunnerProfile(valid, "upstream-rootless", NONCE, HOSTED, APP.Cancellation())
            mkdir.assert_not_called()

    def test_box_receipt_is_pure_closed_and_current_attempt_bound_without_native_reuse(self):
        receipt = {"schema": 1, "prerequisite": "github_runner_userns_v1", "outcome": "verified",
                   "candidate": "d" * 40, "label": "verified", "profile_sha256": "a" * 64,
                   "parser_sha256": "b" * 64, "abi_sha256": "c" * 64,
                   "parser_version": "4.0.1", "cleanup": "removed", "consumer": APP.BOX_CONSUMER,
                   "workflow_run": "127", "attempt": "1"}
        record = "DOCKERLENS_NATIVE_APPARMOR_PROFILE: " + json.dumps(receipt)
        APP.validate_box_cleanup_record(record, "d" * 40, "127", "1")
        native = {key: value for key, value in receipt.items() if key in APP.RECEIPT_KEYS}
        APP.validate_cleanup_record("DOCKERLENS_NATIVE_APPARMOR_PROFILE: " + json.dumps(native), "d" * 40)
        with self.assertRaises(APP.Refused):
            APP.validate_cleanup_record(record, "d" * 40)
        with self.assertRaises(APP.Refused):
            APP.validate_box_cleanup_record("DOCKERLENS_NATIVE_APPARMOR_PROFILE: " + json.dumps(native), "d" * 40, "127", "1")
        wrong = [receipt | {key: value} for key, value in (
            ("consumer", APP.NATIVE_CONSUMER), ("workflow_run", "128"), ("attempt", "2"),
            ("workflow_run", 127), ("attempt", True), ("outcome", "incomplete"), ("label", "unverified"),
            ("cleanup", "not_loaded"), ("candidate", "e" * 40), ("schema", True),
            ("parser_version", "4.0.2"), ("profile_sha256", "private/raw"), ("unknown", "extra"))]
        wrong += [{other: value for other, value in receipt.items() if other != key} for key in receipt]
        for value in wrong:
            with self.subTest(value=value), self.assertRaises(APP.Refused):
                APP.validate_box_cleanup_record("DOCKERLENS_NATIVE_APPARMOR_PROFILE: " + json.dumps(value), "d" * 40, "127", "1")
        for run, attempt in (("128", "1"), ("127", "2"), (127, "1"), ("127", 1), ("0", "1"), ("127", "01")):
            with self.subTest(run=run, attempt=attempt), self.assertRaises(APP.Refused):
                APP.validate_box_cleanup_record(record, "d" * 40, run, attempt)
        for raw in (record + "extra", record.replace('"attempt": "1"', '"attempt":"1","attempt":"1"'), "x" * 8193):
            with self.subTest(raw=raw), self.assertRaises((APP.Refused, ValueError)):
                APP.validate_box_cleanup_record(raw, "d" * 40, "127", "1")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(APP, "RunnerProfile") as profile, \
                mock.patch.object(APP.sys, "stdin", io.StringIO(record)):
            self.assertEqual(APP.main(["validate-box-consumer-receipt", "d" * 40, "127", "1"]), 0)
            profile.assert_not_called()


class LifecycleTests(unittest.TestCase):
    environment = HOSTED
    box = False

    def setUp(self):
        self.run = private_run(box=self.box)
        self.root = tempfile.TemporaryDirectory(prefix="dl-fake-apparmor-root-")
        self.addCleanup(self.run.cleanup)
        self.addCleanup(self.root.cleanup)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(APP, "ROOT", Path(self.root.name)))
        self.stack.enter_context(mock.patch.object(APP, "OWNER", os.geteuid()))
        self.stack.enter_context(mock.patch.object(APP, "trusted_file", return_value={
            "sha256": "f" * 64, "identity": [1, 2, os.geteuid()], "size": 10, "mtime_ns": 1, "ctime_ns": 1}))
        self.read = self.stack.enter_context(mock.patch.object(APP, "read_path", side_effect=self.fake_read))
        self.query = self.stack.enter_context(mock.patch.object(APP.RunnerProfile, "query", autospec=True, side_effect=self.fake_query))
        self.profile_loaded = False
        self.parser_failure = None
        self.compiler_warning = None
        self.version = b"AppArmor parser version 4.0.1\nCopyright test\n"
        self.missing_feature = None
        self.absence = True
        self.commands = []
        self.snapshot_override = None
        self.profile = APP.RunnerProfile(self.run.name, "upstream-rootless", NONCE, self.environment, APP.Cancellation())
        self.run_id = Path(self.run.name).name.rsplit(".", 1)[1]
        self.name = self.profile.name_prefix + self.run_id

    def fake_read(self, path, _limit=65536):
        if path == self.missing_feature:
            raise FileNotFoundError
        if path == APP.PROFILES:
            return ((self.profile.profile_name() + " (unconfined)\n").encode()
                    if self.profile_loaded else b"other (enforce)\n")
        if str(path).endswith("/enabled"):
            return b"Y\n"
        if str(path).endswith("/apparmor_restrict_unprivileged_userns"):
            return b"1\n"
        if str(path).endswith("/namespaces/mask"):
            return b"userns_create\n"
        if str(path).endswith("/versions/v9"):
            return b"yes\n"
        raise AssertionError(path)

    def fake_query(self, _profile, argv, *, statuses=(0,)):
        self.commands.append(tuple(argv))
        if argv[0] == str(APP.PARSER):
            self.assertEqual(argv[1:1 + len(APP.COMMON)], APP.COMMON)
            operation = argv[1 + len(APP.COMMON)]
            if self.parser_failure == operation:
                raise APP.Refused("completion_unknown")
            if operation == "--version":
                return self.version
            self.assertEqual(Path(argv[-1]).read_bytes(), APP.profile_bytes(self.profile.state["profile"]))
            if self.compiler_warning is not None and operation in ("--skip-kernel-load", "--add"):
                reported, fatal = warning_effect_401(argv[1:1 + len(APP.COMMON)], self.compiler_warning)
                # The real query refuses both nonzero parser status and any
                # stderr; an unreported masked warning supplies neither.
                if reported or fatal:
                    raise APP.Refused("synthetic_compiler_warning")
            if operation == "--add":
                self.assertFalse(self.profile_loaded)
                self.assertEqual(self.state()["load"], "intent")
                self.profile_loaded = True
            elif operation == "--remove":
                self.assertTrue(self.profile_loaded)
                self.assertEqual(self.state()["load"], "unload_intent")
                self.profile_loaded = False
            else:
                self.assertEqual(operation, "--skip-kernel-load")
            return b""
        if "apparmor-presence" in argv:
            self.assertEqual(statuses, (0,))
            if not self.absence:
                raise APP.Refused("unknown")
            return b""
        if "snapshot" in argv:
            value = {"Id": CID, "Name": self.name, "ImageDigest": PIN.rsplit("@", 1)[1],
                     "Config": {"Image": PIN, "Labels": {self.profile.owner_key: self.run_id}},
                     "State": {"Running": True, "Pid": 1234, "StartedAt": "started"},
                     "HostConfig": {"Privileged": True}}
            value.update(self.snapshot_override or {})
            return json.dumps(value).encode()
        raise AssertionError(argv)

    def state(self):
        return json.loads((self.profile.path / "state.json").read_text())

    def prepare(self):
        self.profile.prepare(self.name, self.run_id, PIN)

    def start(self):
        self.prepare()
        self.profile.load()
        name = self.profile.begin(self.name, self.run_id, PIN)
        self.assertEqual(name, self.state()["profile"])
        self.profile.created(CID)

    def test_fixed_parser_argv_and_full_profile_lifecycle(self):
        self.start()
        receipt = self.profile.cleanup()
        self.assertEqual((receipt["outcome"], receipt["cleanup"], receipt["label"]),
                         ("incomplete", "removed", "unverified"))
        self.assertFalse(self.profile_loaded)
        parser = [argv for argv in self.commands if argv[0] == str(APP.PARSER)]
        self.assertEqual([argv[1 + len(APP.COMMON)] for argv in parser],
                         ["--version", "--skip-kernel-load", "--add", "--remove"])
        self.assertEqual(list(self.profile.path.iterdir()), [])
        for forbidden in ("--replace", "--reload", "--purge-cache", "--write-cache", "--readimpliesX", "--namespace"):
            self.assertNotIn(forbidden, repr(parser))

    def test_missing_feature_unsupported_parser_and_existing_profile_never_load(self):
        for failure in ("feature", "version", "collision"):
            with self.subTest(failure=failure):
                self.missing_feature = Path("/sys/kernel/security/apparmor/features/namespaces/mask") if failure == "feature" else None
                self.version = b"AppArmor parser version 4.0.2\n" if failure == "version" else b"AppArmor parser version 4.0.1\n"
                self.profile_loaded = failure == "collision"
                with self.assertRaises((APP.Refused, OSError)):
                    self.prepare()
                self.assertEqual(self.state()["load"], "never")
                self.profile.cleanup()
                self.profile.path.rmdir()
        self.assertFalse(any("--add" in argv or "--remove" in argv for argv in self.commands))

    def test_compile_failure_never_loads_and_can_discard_only_unmutated_state(self):
        self.parser_failure = "--skip-kernel-load"
        with self.assertRaises(APP.Refused):
            self.prepare()
        self.assertEqual(self.profile.stage, "compile")
        self.assertEqual(self.profile.cleanup()["cleanup"], "not_loaded")

    def test_compile_and_add_use_enabled_fatal_masks_without_changing_other_defaults(self):
        self.prepare()
        self.profile.load()
        selected = [argv for argv in self.commands if argv[0] == str(APP.PARSER)
                    and argv[1 + len(APP.COMMON)] in ("--skip-kernel-load", "--add")]
        self.assertEqual(len(selected), 2)
        for argv in selected:
            reporting, severity = warning_masks_401(argv[1:1 + len(APP.COMMON)])
            self.assertEqual((reporting, severity), (4791, 7))
            for category in ("abi", "rule-downgraded", "rule-not-enforced"):
                self.assertEqual(warning_effect_401(argv[1:1 + len(APP.COMMON)], category), (True, True))
        self.assertEqual(self.profile.cleanup()["cleanup"], "removed")

    def test_abi_and_downgrade_diagnostics_refuse_during_compile_before_load(self):
        for category in ("abi", "rule-downgraded"):
            with self.subTest(category=category):
                self.compiler_warning = category
                with self.assertRaises(APP.Refused):
                    self.prepare()
                self.assertEqual(self.profile.stage, "compile")
                self.assertEqual(self.state()["load"], "never")
                self.assertFalse(self.profile_loaded)
                self.assertFalse(any("--add" in argv for argv in self.commands))
                self.assertEqual(self.profile.cleanup()["cleanup"], "not_loaded")
                self.profile.path.rmdir()

    def test_severity_only_counterexample_would_allow_masked_abi_and_downgrade(self):
        old = ("--config-file=/dev/null", "--skip-cache", "--jobs=0", "--Werror=rule-not-enforced",
               "--Werror=rule-downgraded", "--Werror=abi")
        for category in ("abi", "rule-downgraded"):
            with self.subTest(category=category), mock.patch.object(APP, "COMMON", old):
                self.compiler_warning = category
                self.prepare()
                self.assertEqual(self.state()["load"], "prepared")
                self.profile.load()
                self.assertTrue(self.profile_loaded)
                self.assertEqual(self.profile.cleanup()["cleanup"], "removed")
                self.profile.path.rmdir()

    def test_rule_not_enforced_remains_fatal_even_without_report_enablement(self):
        old = ("--config-file=/dev/null", "--skip-cache", "--jobs=0", "--Werror=rule-not-enforced",
               "--Werror=rule-downgraded", "--Werror=abi")
        self.compiler_warning = "rule-not-enforced"
        with mock.patch.object(APP, "COMMON", old), self.assertRaises(APP.Refused):
            self.prepare()
        self.assertEqual(self.profile.stage, "compile")
        self.assertEqual(self.state()["load"], "never")
        self.assertFalse(any("--add" in argv for argv in self.commands))
        self.assertEqual(self.profile.cleanup()["cleanup"], "not_loaded")

    def test_prerequisite_refusal_has_only_the_expected_fixed_stage(self):
        for path, stage in (("/sys/module/apparmor/parameters/enabled", "kernel_enabled"),
                            ("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "userns_restriction"),
                            ("/sys/kernel/security/apparmor/features/namespaces/mask", "kernel_features"),
                            ("/sys/kernel/security/apparmor/features/policy/versions/v9", "kernel_features")):
            with self.subTest(stage=stage):
                self.missing_feature = Path(path)
                with self.assertRaises(FileNotFoundError):
                    self.prepare()
                self.assertEqual(self.profile.stage, stage)
                self.assertEqual(self.state()["load"], "never")
                self.profile.cleanup()
                self.profile.path.rmdir()

    def test_absence_accepts_only_complete_exact_negative_rows_for_both_id_and_name(self):
        self.start()
        for raw in (b"", b"other\n", b"other\nother\n"):
            with self.subTest(raw=raw), mock.patch.object(self.profile, "bridge", return_value=raw) as bridge:
                self.profile.absent()
                self.assertEqual(bridge.call_args_list, [mock.call("apparmor-presence", "id", CID),
                                                        mock.call("apparmor-presence", "name", self.name)])
        for raw in (b"present\n", b"present\npresent\n", b"other\npresent\n", b"other", b"other\r\n",
                    b"other\npartial", b"\n", b"absent\n", b"private evidence\n"):
            with self.subTest(raw=raw), mock.patch.object(self.profile, "bridge", return_value=raw), self.assertRaises(APP.Refused):
                self.profile.absent()
        with mock.patch.object(self.profile, "bridge", side_effect=APP.Refused("command_failed")), self.assertRaises(APP.Refused):
            self.profile.absent()
        self.assertEqual(self.profile.stage, "absence")

    def test_name_collision_between_compile_and_load_never_removes_existing_profile(self):
        self.prepare()
        self.profile_loaded = True
        with self.assertRaises(APP.Refused):
            self.profile.load()
        self.assertEqual(self.profile.cleanup()["cleanup"], "not_loaded")
        self.assertTrue(self.profile_loaded)
        self.assertFalse(any("--add" in argv or "--remove" in argv for argv in self.commands))

    def test_add_failure_timeout_and_interrupted_create_are_sticky(self):
        self.prepare()
        self.parser_failure = "--add"
        with self.assertRaises(APP.Refused):
            self.profile.load()
        self.assertEqual(self.state()["load"], "intent")
        with self.assertRaises(APP.Refused):
            self.profile.cleanup()
        self.assertTrue((self.profile.path / "profile").exists())
        self.assertFalse(any("--remove" in argv for argv in self.commands))

    def test_created_never_attempted_allows_loaded_profile_removal(self):
        self.prepare()
        self.profile.load()
        self.assertEqual(self.profile.cleanup()["cleanup"], "removed")
        self.assertFalse(any("apparmor-presence" in argv for argv in self.commands))

    def test_creation_intent_without_recorded_cid_refuses_unload(self):
        self.prepare()
        self.profile.load()
        self.profile.begin(self.name, self.run_id, PIN)
        with self.assertRaises(APP.Refused):
            self.profile.cleanup()
        self.assertTrue(self.profile_loaded)
        self.assertEqual(self.state()["create"], "intent")

    def test_unknown_daemon_absence_and_unknown_remove_preserve_state(self):
        self.start()
        self.absence = False
        with self.assertRaises(APP.Refused):
            self.profile.cleanup()
        self.assertEqual(self.state()["load"], "loaded")
        self.absence = True
        self.parser_failure = "--remove"
        with self.assertRaises(APP.Refused):
            self.profile.cleanup()
        self.assertEqual(self.state()["load"], "unload_intent")
        self.parser_failure = None
        with self.assertRaises(APP.Refused):
            self.profile.cleanup()

    def test_actual_creation_binding_is_saved_before_later_label_refusal(self):
        self.start()
        self.assertEqual(self.state()["create"], "recorded")
        with mock.patch.object(APP.RunnerProfile, "snapshot", side_effect=APP.Refused("label_unavailable")):
            with self.assertRaises(APP.Refused):
                self.profile.verify()
        self.assertEqual(self.state()["create"], "recorded")
        self.assertEqual(self.profile.cleanup()["cleanup"], "removed")

    def test_unbound_actual_creation_never_becomes_known_from_cid_alone(self):
        self.prepare()
        self.profile.load()
        self.profile.begin(self.name, self.run_id, PIN)
        self.snapshot_override = {"Name": "foreign"}
        with self.assertRaises(ValueError):
            self.profile.created(CID)
        self.assertEqual(self.state()["create"], "intent")
        with self.assertRaises(APP.Refused):
            self.profile.cleanup()

    def test_run_directory_replacement_and_original_identity_mismatch_refuse(self):
        self.prepare()
        original = Path(self.run.name)
        moved = original.with_name(original.name + ".held")
        original.rename(moved)
        self.addCleanup(lambda: moved.rename(original))
        original.mkdir(mode=0o700)
        self.addCleanup(original.rmdir)
        with self.assertRaises(APP.Refused):
            self.profile.load()
        self.assertFalse(self.profile_loaded)

    def test_symlink_hardlink_mode_and_nonce_directory_reuse_refuse(self):
        self.prepare()
        with self.assertRaises(FileExistsError):
            self.prepare()
        profile = self.profile.path / "profile"
        content = profile.read_bytes()
        profile.chmod(0o644)
        with self.assertRaises(APP.Refused):
            self.profile.load()
        profile.chmod(0o600)
        extra = self.profile.path / "extra"
        os.link(profile, extra)
        with self.assertRaises(APP.Refused):
            self.profile.load()
        extra.unlink()
        profile.unlink()
        extra.write_bytes(content)
        profile.symlink_to(extra)
        with self.assertRaises(OSError):
            self.profile.load()

    def test_state_custody_and_candidate_rebinding_refuse_without_policy_contact(self):
        self.prepare()
        for key, wrong in (("candidate", "e" * 40), ("run_identity", [0, 1, 2]), ("attempt", "2"), ("lane", "debian11-rootless")):
            with self.subTest(key=key):
                state = self.state()
                path = self.profile.path / "state.json"
                path.write_text(json.dumps(state | {key: wrong}))
                with self.assertRaises(APP.Refused):
                    self.profile.load()
                path.write_text(json.dumps(state))
        self.assertFalse(self.profile_loaded)
        state = self.profile.path / "state.json"
        alias = self.profile.path / "alias"
        os.link(state, alias)
        with self.assertRaises(APP.Refused):
            self.profile.load()

    def test_malformed_state_never_authorizes_any_lifecycle_operation_or_receipt(self):
        self.prepare()
        original = self.state()
        path = self.profile.path / "state.json"
        values = [None, [], original | {"unknown": "private"}, original | {"schema": True},
                  original | {"schema": 1.0}, original | {"load": "arbitrary"},
                  original | {"create": "recorded", "cid": CID},
                  original | {"load": "loaded", "label": "verified"},
                  original | {"load": "unload_intent", "create": "intent"},
                  original | {"load": "never"}, original | {"profile_sha256": "0" * 64},
                  original | {"profile": original["profile"].replace(NONCE, "b" * 32)},
                  original | {"image": "unreviewed/image:latest"},
                  original | {"parser_version": "4.0.2"},
                  original | {"name": "foreign"}, original | {"run": "foreign"},
                  original | {"parser": original["parser"] | {"extra": "private"}},
                  original | {"abi": original["abi"] | {"identity": [1, True, os.geteuid()]}},
                  original | {"parser": original["parser"] | {"sha256": "arbitrary"}}]
        for key in original:
            values.extend((original | {key: None}, original | {key: []},
                           {other: value for other, value in original.items() if other != key}))
        encoded = [json.dumps(value) for value in values]
        encoded.extend((json.dumps(original)[:-1] + ', "load": "prepared"}',
                        json.dumps(original).replace('"size": 10', '"size": 10, "size": 10', 1),
                        '{"incomplete":'))
        operations = (("load", ()), ("begin", (self.name, self.run_id, PIN)), ("created", (CID,)),
                      ("verify", ()), ("cleanup", ()))
        commands = len(self.commands)
        policy_reads = self.read.call_count
        for index, raw in enumerate(encoded):
            path.write_text(raw)
            for operation, args in operations:
                with self.subTest(index=index, operation=operation), self.assertRaises((APP.Refused, ValueError)):
                    getattr(self.profile, operation)(*args)
                self.assertEqual(path.read_text(), raw)
                self.assertEqual((len(self.commands), self.read.call_count), (commands, policy_reads))
        path.write_text(json.dumps(original))
        self.profile.load()
        self.assertTrue(self.profile_loaded)

    def test_cancellation_before_parser_mutation_refuses_acceptance(self):
        self.prepare()
        # Cancellation at the actual parser transport edge, not a fake signal
        # to a real child. Intent was saved before entering this edge.
        with mock.patch.object(APP.RunnerProfile, "parser", side_effect=APP.Cancelled(15)):
            with self.assertRaises(APP.Cancelled):
                self.profile.load()
        self.assertEqual(self.state()["load"], "intent")
        with self.assertRaises(APP.Refused):
            self.profile.cleanup()

    def test_effective_label_is_exact_and_creation_bound_with_pid_start_brackets(self):
        self.start()
        expected = (self.state()["profile"] + " (unconfined)\n").encode()
        # /proc is replaced by a held temporary directory; no real process read.
        process = os.open(self.run.name, os.O_RDONLY | os.O_DIRECTORY)
        real_open = os.open
        def fake_open(path, flags, *args, **kwargs):
            return os.dup(process) if path == "/proc/1234" else real_open(path, flags, *args, **kwargs)
        try:
            with mock.patch.object(APP.os, "open", side_effect=fake_open), \
                    mock.patch.object(APP.RunnerProfile, "snapshot", return_value=(1234, "started")) as snapshot, \
                    mock.patch.object(APP, "process_ticks", return_value=99) as ticks, \
                    mock.patch.object(APP, "process_read", return_value=f"0::/system.slice/docker-{CID}.scope\n".encode()) as cgroup, \
                    mock.patch.object(APP, "process_label", return_value=expected) as label:
                self.profile.verify()
                self.assertEqual(self.state()["label"], "verified")
                self.assertEqual((snapshot.call_count, ticks.call_count, label.call_count), (2, 2, 2))
                for wrong in (b"unconfined\n", expected.replace(b"unconfined", b"enforce"), expected + b"stacked", b""):
                    label.return_value = wrong
                    with self.assertRaises(APP.Refused):
                        self.profile.verify()
                label.return_value = expected
                ticks.side_effect = [99, 100]
                with self.assertRaises(APP.Refused):
                    self.profile.verify()
                ticks.side_effect = None
                snapshot.side_effect = [(1234, "started"), (1234, "restarted")]
                with self.assertRaises(APP.Refused):
                    self.profile.verify()
                snapshot.side_effect = None
                for wrong in (b"0::/system.slice/other.scope\n", f"0::/docker/{CID}\n".encode(),
                              f"0::/system.slice/docker-{CID}.scope/child\n".encode()):
                    cgroup.return_value = wrong
                    with self.assertRaises(APP.Refused):
                        self.profile.verify()
                cgroup.side_effect = [f"0::/system.slice/docker-{CID}.scope\n".encode(), b"changed\n"]
                with self.assertRaises(APP.Refused):
                    self.profile.verify()
                cgroup.side_effect = None
                cgroup.return_value = f"0::/system.slice/docker-{CID}.scope\n".encode()
                self.profile.verify()
            receipt = self.profile.cleanup()
            context = ({"consumer": APP.BOX_CONSUMER, "workflow_run": self.environment["GITHUB_RUN_ID"],
                        "attempt": self.environment["GITHUB_RUN_ATTEMPT"]} if self.box else {})
            APP.validate_receipt(receipt, self.environment["DOCKERLENS_NATIVE_CANDIDATE_SHA"], require_verified=True, **context)
            self.assertEqual((receipt["outcome"], receipt["label"], receipt["cleanup"]),
                             ("verified", "verified", "removed"))
            self.assertFalse(self.profile_loaded)
        finally:
            os.close(process)


class BoxLifecycleTests(LifecycleTests):
    """Run the same custody, parser, cancellation, label/cgroup and cleanup refusals in Box mode."""
    environment = BOX_HOSTED
    box = True

    def test_distinct_state_and_profile_cannot_be_rebound_to_native_or_another_attempt(self):
        self.prepare()
        original = self.state()
        self.assertEqual(original["consumer"], APP.BOX_CONSUMER)
        self.assertTrue(self.profile.path.name.startswith("boxferry-apparmor."))
        self.assertEqual(self.profile.profile_name(), "boxferry-343-upstream-rootless-127-1-" + NONCE)
        self.assertEqual(APP.profile_bytes(self.profile.profile_name()),
                         f"abi <abi/4.0>,\nprofile {self.profile.profile_name()} flags=(unconfined) {{\n  userns,\n}}\n".encode())
        path = self.profile.path / "state.json"
        wrong = [original | {"consumer": APP.NATIVE_CONSUMER},
                 {key: value for key, value in original.items() if key != "consumer"},
                 original | {"profile": original["profile"].replace("boxferry-343", "dockerlens-127")},
                 original | {"name": "dl-native-" + self.run_id},
                 original | {"workflow_run": "128"}, original | {"attempt": "2"}]
        commands = len(self.commands)
        reads = self.read.call_count
        for value in wrong:
            path.write_text(json.dumps(value))
            for method, args in ((self.profile.load, ()), (self.profile.begin, (self.name, self.run_id, PIN)),
                                 (self.profile.created, (CID,)), (self.profile.verify, ()), (self.profile.cleanup, ())):
                with self.subTest(value=value, method=method.__name__), self.assertRaises(APP.Refused):
                    method(*args)
                self.assertEqual((len(self.commands), self.read.call_count), (commands, reads))
        path.write_text(json.dumps(original))
        self.profile.load()
        self.assertTrue(self.profile_loaded)

    def test_box_creation_requires_box_owner_even_with_correct_id_and_name(self):
        self.prepare()
        self.profile.load()
        self.profile.begin(self.name, self.run_id, PIN)
        self.snapshot_override = {"Config": {"Image": PIN, "Labels": {"io.dockerlens.native-run": self.run_id}}}
        with self.assertRaises(ValueError):
            self.profile.created(CID)
        self.assertEqual(self.state()["create"], "intent")
        with self.assertRaises(APP.Refused):
            self.profile.cleanup()


class ShellCreationTests(unittest.TestCase):
    def test_only_exact_selected_profile_calls_extend_explicit_context(self):
        base = ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "GITHUB_REF", "GITHUB_EVENT_NAME",
                "GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "ImageOS", "ImageVersion", "DOCKER_HOST",
                "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION",
                "CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINER_SSHKEY", "PODMAN_CONNECTIONS_CONF")
        extra = ("GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "DOCKERLENS_NATIVE_CANDIDATE_SHA")
        directory = "/tmp/dockerlens-native.abcdefgh"
        body = ("set -euo pipefail\n" + definition("native_outer_bridge_command", RUNTIME)
                + "\nnative_outer_engine=$1; native_outer_directory=$2; apparmor_profile=$3; shift 3\n"
                + "native_outer_privilege=(); native_outer_script_dir=/reviewed/scripts\n"
                + "timeout() { printf '%s\\0' \"$@\"; }\n"
                + "native_outer_bridge_command 30 \"$@\"\n")

        def check(args, extended=False, engine="docker", flag="github_runner_userns_v1"):
            # Capture explicit assignments only. Existing ambient inheritance is
            # unchanged; this fake does not claim to sanitize an environment.
            result = subprocess.run(["/bin/bash", "-c", body, "test", engine, directory, flag, *args],
                                    env=HOSTED | {"PATH": "/unavailable", "PRIVATE_CANARY": "not-forwarded"},
                                    capture_output=True, timeout=3)
            self.assertEqual((result.returncode, result.stderr), (0, b""))
            keys = base + extra if extended else base
            expected = ["--signal=TERM", "--kill-after=2s", "30s", "env",
                        *(key + "=" + HOSTED.get(key, "") for key in keys), "bash",
                        "/reviewed/scripts/native-outer-command.sh", "--engine", engine,
                        "--directory", directory, *args]
            self.assertEqual(result.stdout.decode().split("\0"), [*expected, ""])

        prepare = ["apparmor", "prepare", "upstream-rootless", NONCE, "owned", "run", PIN]
        phases = [["apparmor", phase, "upstream-rootless", NONCE] for phase in ("load", "verify", "cleanup")]
        create = ["create-daemon", "owned", "run", "io.dockerlens.native-run", "network", "volume",
                  "/private/socket", "/dockerlens-native", "upstream-rootless", PIN, "/private/log", NONCE]
        for args in (prepare, *phases, create):
            with self.subTest(args=args):
                check(args, extended=True)
                check(args, engine="podman")
                check(args, flag="")
                check(args, flag="github_runner_userns_v2")
                check(args + ["extra"])
                check(args[:-1])
                if args[0] == "create-daemon":
                    wrong_fields = ((8, "upstream-rootful"), (3, "io.boxferry.docker-core-run"),
                                    (7, "/boxferry-native"), (11, "docker-default"), (11, "A" * 32))
                else:
                    wrong_fields = ((1, "begin"), (1, "created"), (1, "unknown"),
                                    (2, "debian11-rootless"), (3, "docker-default"), (3, "A" * 32))
                for index, wrong in wrong_fields:
                    malformed = args.copy()
                    malformed[index] = wrong
                    check(malformed)
        for args in ([], ["check-context"], ["snapshot", CID], ["presence", "container", CID],
                     ["apparmor-presence", "id", CID], ["exec", CID, "id", "-u"], create[:-1]):
            with self.subTest(ordinary=args):
                check(args)
                check(args, engine="podman")

    def test_raw_absence_projection_matches_normal_container_listing_vector(self):
        with private_run() as run:
            private = Path(run)
            (private / "docker-client").mkdir(mode=0o700)
            tools = private / "bin"
            tools.mkdir(mode=0o700)
            for name, path in (("python3", sys.executable), ("dirname", "/usr/bin/dirname"), ("env", "/usr/bin/env")):
                (tools / name).symlink_to(path)
            client = tools / "docker"
            client.write_text(f"#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n")
            client.chmod(0o700)
            for kind, value in (("id", CID), ("name", "dl-native-abcdefgh")):
                with self.subTest(kind=kind):
                    field = "ID" if kind == "id" else "Names"
                    expected = ["container", "ls", "-a", "--no-trunc", "--filter", f"{kind}={value}",
                                "--format", f'{{{{if eq .{field} "{value}"}}}}present{{{{else}}}}other{{{{end}}}}']
                    raw = subprocess.run(["/bin/bash", str(ROOT / "scripts/native-outer-command.sh"),
                                          "--engine", "docker", "--directory", run, "apparmor-presence", kind, value],
                                         env=HOSTED | {"PATH": str(tools)}, capture_output=True, timeout=3)
                    self.assertEqual((raw.returncode, raw.stderr), (0, b""))
                    self.assertEqual(json.loads(raw.stdout), ["--config", str(private / "docker-client"),
                                                              "--host", "unix:///var/run/docker.sock", *expected])
                    body = (RUNTIME + "\nnative_outer_engine=docker; native_outer_cmd=(docker); native_outer_script_dir=/fake\n"
                            "timeout() { printf '%s\\0' \"$@\" >\"$trace\"; printf 'absent\\n'; return 1; }\n"
                            "trace=$1; native_outer_presence container \"$2\" \"$3\"\n")
                    normal = subprocess.run(["/bin/bash", "-c", body, "test", str(private / "normal-argv"), value, run],
                                            env={"PATH": str(tools)}, capture_output=True, timeout=3)
                    self.assertEqual((normal.returncode, normal.stdout, normal.stderr), (1, b"", b""))
                    argv = (private / "normal-argv").read_bytes().decode().rstrip("\0").split("\0")
                    self.assertEqual(argv[argv.index("--") + 1:], ["docker", *expected])
            for kind, value in (("id", "partial"), ("name", "bad/name"), ("volume", "owned")):
                bad = subprocess.run(["/bin/bash", str(ROOT / "scripts/native-outer-command.sh"),
                                      "--engine", "docker", "--directory", run, "apparmor-presence", kind, value],
                                     env=HOSTED | {"PATH": str(tools)}, capture_output=True, timeout=3)
                self.assertEqual((bad.returncode, bad.stdout), (2, b""))

    def test_owned_optional_nonce_keeps_original_launch_and_failure_status(self):
        for status, binding_status in ((0, 0), (0, 2), (0, 130), (0, 143), (42, 2), (130, 2), (143, 2)):
            with self.subTest(status=status, binding_status=binding_status), tempfile.TemporaryDirectory(prefix="dl-fake-create-") as temporary:
                private = Path(temporary)
                (private / "python3").symlink_to(sys.executable)
                profile = "dockerlens-127-upstream-rootless-127-1-" + NONCE
                body = ("set -euo pipefail\n" + definition("native_outer_create_daemon", RUNTIME) + "\n"
                        + "native_outer_engine=docker; native_outer_directory=$1; native_outer_script_dir=$2\n"
                        + "declare -A held=([name]=owned [run]=run [owner_key]=io.dockerlens.native-run "
                        + "[network]=network [volume]=volume [socket_dir]=/private/socket [guest_dir]=/dockerlens-native "
                        + "[lane]=upstream-rootless [image]=$3 [log_path]=/private/log [apparmor_nonce]=$4)\n"
                        + "native_outer_apparmor() { printf '%s\\n' \"$1\" >>\"$native_outer_directory/operations\"; "
                        + f"if [[ $1 == begin ]]; then printf '%s\\n' {profile}; else return {binding_status}; fi; }}\n"
                        + "native_outer_command() { printf '%s\\n' \"$@\" >\"$native_outer_directory/argv\"; "
                        + f"printf '%s' {CID} >\"$native_outer_directory/outer-create.cid\"; return {status}; }}\n"
                        + "native_outer_create_daemon held\n")
                result = subprocess.run(["/bin/bash", "-c", body, "test", temporary,
                                         str(ROOT / "scripts"), PIN, NONCE], env={"PATH": temporary},
                                        capture_output=True, text=True, timeout=3)
                self.assertEqual((result.returncode, result.stdout), (status or binding_status, CID + "\n"), result.stderr)
                argv = (private / "argv").read_text().splitlines()
                self.assertEqual(argv[:4], ["120", "run", "--pull=never", "-d"])
                self.assertEqual(argv[argv.index("--security-opt") + 1], "apparmor=" + profile)
                self.assertIn("--privileged", argv)
                self.assertEqual(argv[-2:], ["/usr/local/bin/start-dockerd", "--host=unix:///dockerlens-native/docker.sock"])
                self.assertEqual((private / "operations").read_text(), "begin\ncreated\n")

    def test_optional_bridge_nonce_does_not_accept_policy_name_path_or_extra_arguments(self):
        # Only attach validation is reached, using an empty private config. No
        # runtime binary is present on PATH; every invalid nonce must stop first.
        with tempfile.TemporaryDirectory(prefix="dl-fake-bridge-") as temporary:
            private = Path(temporary)
            (private / "docker-client").mkdir(mode=0o700)
            tools = private / "bin"
            tools.mkdir(mode=0o700)
            for name, target in (("python3", sys.executable), ("dirname", "/usr/bin/dirname")):
                (tools / name).symlink_to(target)
            args = ["owned", "run", "io.dockerlens.native-run", "network", "volume", "/private/socket",
                    "/dockerlens-native", "upstream-rootless", PIN, "/private/log"]
            for extra in (["docker-default"], ["/run/profile"], [NONCE + "/x"], [NONCE, "extra"]):
                result = subprocess.run(["/bin/bash", str(ROOT / "scripts/native-outer-command.sh"),
                                         "--engine", "docker", "--directory", temporary, "create-daemon", *args, *extra],
                                        env=HOSTED | {"PATH": str(tools)}, capture_output=True, timeout=3)
                self.assertEqual((result.returncode, result.stdout), (2, b""))


@unittest.skipUnless(sys.platform == "linux", "Linux original-owner process contract")
class ProcessLifetimeTests(unittest.TestCase):
    def test_original_bridge_owner_keeps_direct_child_descendant_and_early_eof_contained(self):
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        try:
            for mode, create in (("direct", False), ("descendant", False),
                                 ("soft-deadline", False), ("descendant", True), ("late-begin", True)):
                with self.subTest(mode=mode, create=create), private_run() as temporary:
                    self.owner_case(Path(temporary), mode, create)
        finally:
            self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0)

    def owner_case(self, run, mode, create):
        scripts = run / "scripts"
        scripts.mkdir(mode=0o700)
        tools = run / "bin"
        tools.mkdir(mode=0o700)
        (run / "docker-client").mkdir(mode=0o700)
        # Exact reviewed bridge/runtime/observation source; only the terminal
        # client and helper's privileged frontend are fakes. The frontend calls
        # the actual new query implementation, never parser or policy methods.
        for name in ("native-outer-command.sh", "native-outer-runtime.sh", "native-outer-observation.py"):
            (scripts / name).write_bytes((ROOT / "scripts" / name).read_bytes())
        for name, path in (("python3", sys.executable), ("dirname", "/usr/bin/dirname"),
                           ("sleep", "/bin/sleep"), ("env", "/usr/bin/env")):
            (tools / name).symlink_to(path)
        (run / "mode").write_text(mode)
        frontend = f'''import importlib.util, os, signal, sys, time
from pathlib import Path
sys.path.insert(0, {str(ROOT / "scripts")!r})
spec=importlib.util.spec_from_file_location("actual_query", {str(ROOT / "scripts/native-runner-apparmor.py")!r})
app=importlib.util.module_from_spec(spec); spec.loader.exec_module(app)
operation, directory, lane, nonce = sys.argv[1:5]
run=Path(directory); mode=(run/"mode").read_text()
app.OWNER=os.geteuid(); app.SCRIPTS=Path(__file__).parent
app.ENV={{"PATH":str(run/"bin"),"LANG":"C","LC_ALL":"C"}}
cancellation=app.Cancellation()
for number in (signal.SIGHUP,signal.SIGINT,signal.SIGTERM): signal.signal(number,cancellation.request)
profile=app.RunnerProfile(directory,lane,nonce,os.environ,cancellation)
if mode == "late-begin":
    signal.signal(signal.SIGTERM, lambda *_: None)
    (run/"frontend-ready").write_text(str(os.getpid()))
    while not (run/"release").exists(): time.sleep(.01)
    print("dockerlens-127-upstream-rootless-127-1-"+nonce, flush=True)
    raise SystemExit(0)
if mode == "soft-deadline": profile.deadline=time.monotonic()+.15
profile.bridge("apparmor-presence", "id", {CID!r})
raise SystemExit("unexpected fake query completion")
'''
        (scripts / "native-runner-apparmor.py").write_text(frontend)
        client = f'''#!{sys.executable}
import json, os, signal, sys, time
from pathlib import Path
run=Path(sys.argv[2]).parent
if "run" in sys.argv[1:]:
    (run/"FORBIDDEN-CREATE").write_text("resumed")
    raise SystemExit(99)
mode=(run/"mode").read_text()
def record():
    with (run/"pids").open("a") as output:
        output.write(json.dumps([os.getpid(),os.getpgrp()])+"\\n"); output.flush()
record()
if mode == "descendant":
    if os.fork() == 0:
        signal.signal(signal.SIGTERM,signal.SIG_IGN)
        record(); os.close(1); os.close(2)
        while True: time.sleep(1)
else:
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    os.close(1); os.close(2)
while True: time.sleep(1)
'''
        (tools / "docker").write_text(client)
        (tools / "docker").chmod(0o700)
        args = ["create-daemon", "owned", "run", "io.dockerlens.native-run", "network", "volume",
                str(run / "socket"), "/dockerlens-native", "upstream-rootless", PIN, str(run / "log"), NONCE] if create else [
                "apparmor", "load", "upstream-rootless", NONCE]
        command = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=0.3s", "2s", "/bin/bash",
                   str(scripts / "native-outer-command.sh"), "--engine", "docker", "--directory", str(run), *args]
        owner = subprocess.Popen(command, env=HOSTED | {"PATH": str(tools)}, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        pids = []
        try:
            deadline = time.monotonic() + 1.7
            ready = run / ("frontend-ready" if mode == "late-begin" else "pids")
            expected = 2 if mode == "descendant" else 1
            while time.monotonic() < deadline:
                if ready.exists() and len(ready.read_text().splitlines()) >= expected:
                    break
                time.sleep(.01)
            self.assertTrue(ready.exists(), "fake child must start before the original deadline")
            if mode == "late-begin":
                pids = [int(ready.read_text())]
                os.kill(owner.pid, signal.SIGTERM)
                (run / "release").write_text("release after cancellation")
            else:
                rows = [json.loads(row) for row in ready.read_text().splitlines()]
                self.assertEqual(len(rows), expected)
                pids = [pid for pid, _group in rows]
                self.assertTrue(all(group == owner.pid for _pid, group in rows))
                if mode == "descendant":
                    os.kill(owner.pid, signal.SIGTERM)
            # Observe owner exit WITHOUT reaping its identity before cleanup.
            deadline = time.monotonic() + 4
            while os.waitid(os.P_PID, owner.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                self.assertLess(time.monotonic(), deadline, "original hard owner did not finish")
                time.sleep(.01)
            delivered_by = time.monotonic() + .5
            for pid in pids:
                path = Path(f"/proc/{pid}/stat")
                # SIGKILL targets the timeout itself and all recorded children;
                # owner exit can be observed before another CPU schedules their
                # fatal-signal transition. Observe that transition without any
                # test-issued signal; a continuing live survivor still fails.
                while True:
                    try:
                        state = path.read_text().rsplit(") ", 1)[1].split()[0]
                    except FileNotFoundError:
                        break
                    if state in ("Z", "X"):
                        break
                    self.assertLess(time.monotonic(), delivered_by,
                                    "owned child remained live after original owner exit: " + state)
                    time.sleep(.01)
            self.assertFalse((run / "FORBIDDEN-CREATE").exists())
        finally:
            # Exact unreaped owner identity, never a PID-prefix or broad sweep.
            try:
                os.killpg(owner.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            owner.communicate(timeout=3)
            for pid in pids:
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass


class PublicationBudgetTests(unittest.TestCase):
    def run_wrapper(self, body):
        return subprocess.run(["/bin/bash", "-c", "set -euo pipefail\n"
                               + definition("native_publication_command") + body],
                              env={"PATH": "/unavailable"}, capture_output=True, text=True, timeout=3)

    def test_every_phase_recomputes_remaining_original_budget(self):
        result = self.run_wrapper("\nSECONDS=1700\n"
                                  + "timeout() { printf '%s\\n' \"$3\"; SECONDS=$((SECONDS + 11)); }\n"
                                  + "native_publication_command first\n"
                                  + "native_publication_command second\n"
                                  + "native_publication_command third\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["97s", "86s", "75s"])

    def test_expired_budget_never_starts_child_and_late_zero_is_refused(self):
        for elapsed in (1797, 1799, 1800, 1801):
            with self.subTest(elapsed=elapsed):
                result = self.run_wrapper(f"\nSECONDS={elapsed}\n"
                                          + "timeout() { printf 'FORBIDDEN CHILD'; }\n"
                                          + "native_publication_command child\n")
                self.assertEqual((result.returncode, result.stdout), (124, ""))
        result = self.run_wrapper("\nSECONDS=1790\n"
                                  + "timeout() { SECONDS=1800; return 0; }\n"
                                  + "native_publication_command child\n")
        self.assertEqual(result.returncode, 124)

    def test_child_failure_and_cancellation_cannot_become_success(self):
        for status in (17, 124, 130, 137, 143):
            with self.subTest(status=status):
                result = self.run_wrapper("\nSECONDS=1700\n"
                                          + f"timeout() {{ return {status}; }}\n"
                                          + "native_publication_command child\n")
                self.assertEqual(result.returncode, status)

    def test_real_publication_git_and_python_hangs_are_bounded_by_original_cutoff(self):
        with tempfile.TemporaryDirectory(prefix="dl-fake-publication-") as temporary:
            tools = Path(temporary)
            (tools / "timeout").symlink_to("/usr/bin/timeout")
            git = tools / "git"
            git.write_text("#!/bin/sh\ncase \" $* \" in\n"
                           + "*' rev-parse '*) phase=head;; *' status '*) phase=status;; *) exit 9;; esac\n"
                           + "printf '%s\\n' \"$phase\" >>\"$TRACE\"\n"
                           + "if [ \"$HANG\" = \"$phase\" ]; then /bin/sleep 20; fi\n"
                           + "if [ \"$phase\" = head ]; then printf '%s\\n' \"$CANDIDATE\"; fi\n")
            git.chmod(0o700)
            publisher = tools / "python3"
            publisher.write_text("#!/bin/sh\nprintf 'publisher\\n' >>\"$TRACE\"\n"
                                 + "if [ \"$HANG\" = publisher ]; then trap '' TERM; /bin/sleep 20; fi\n"
                                 + "printf 'ordinary-receipt-published\\n'\n")
            publisher.chmod(0o700)
            values = {"script_dir": "/reviewed/scripts", "run_dir": "/private/run", "lane": "upstream-rootless",
                      "image": PIN, "expected_mode": "rootless", "installed_docker_package": "", "run_id": "run",
                      "DOCKERLENS_NATIVE_EVIDENCE_DIR": "/private/evidence",
                      "DOCKERLENS_NATIVE_CANDIDATE_SHA": "d" * 40}
            for key in ("NATIVE_SHAPES_PATH", "NATIVE_SOURCE_PROBES_PATH", "NATIVE_NETWORK_PROBES_PATH",
                        "NATIVE_VOLUME_PROBES_PATH", "NATIVE_VOLUME_LABEL_PROBES_PATH", "NATIVE_IDENTITY_PROBES_PATH",
                        "NATIVE_PORT_PROBES_PATH", "NATIVE_HEALTH_METADATA_PROOF_PATH",
                        "NATIVE_NETWORK_ATTACHMENT_PROOF_PATH", "NATIVE_BIND_RELABEL_PROOF_PATH"):
                values[key] = "/private/proof"
            body = ("set -euo pipefail\n" + definition("native_publication_command")
                    + definition("publish_native_evidence")
                    + "\n" + "\n".join(key + "=" + shlex.quote(value) for key, value in values.items())
                    + "\nSECONDS=1796\npublish_native_evidence\nprintf 'PUBLICATION ACCEPTED\\n'\n")
            for phase, expected in (("none", ["head", "status", "publisher"]),
                                    ("head", ["head"]), ("status", ["head", "status"]),
                                    ("publisher", ["head", "status", "publisher"])):
                trace = tools / (phase + ".trace")
                # The positive arm checks throughput under its existing <5s
                # bound. Real hangs and deterministic expired/late controls
                # retain the original cutoff proof, without a one-tick race
                # between three successful child launches in this arm.
                phase_body = body
                if phase == "none":
                    phase_body = body.replace("\nSECONDS=1796\n", "\nSECONDS=1790\n", 1)
                with self.subTest(phase=phase):
                    started = time.monotonic()
                    result = subprocess.run(["/bin/bash", "-c", phase_body],
                                            env={"PATH": temporary, "HANG": phase, "TRACE": str(trace),
                                                 "CANDIDATE": "d" * 40},
                                            capture_output=True, text=True, timeout=7)
                    self.assertLess(time.monotonic() - started, 5)
                    self.assertEqual(trace.read_text().splitlines(), expected)
                    if phase == "none":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn("PUBLICATION ACCEPTED", result.stdout)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn("ordinary-receipt-published", result.stdout)
                        self.assertNotIn("PUBLICATION ACCEPTED", result.stdout)


class ShellFinalizationTests(unittest.TestCase):
    def cleanup(self, original=0, helper=0, network=0, containers=0, completed=1,
                retained=0, receipt=None, publisher=0, elapsed=0, publisher_elapsed=None):
        if receipt is None:
            receipt = {"schema": 1, "prerequisite": "github_runner_userns_v1", "outcome": "verified",
                       "candidate": HOSTED["DOCKERLENS_NATIVE_CANDIDATE_SHA"], "label": "verified",
                       "profile_sha256": "a" * 64, "parser_sha256": "b" * 64,
                       "abi_sha256": "c" * 64, "parser_version": "4.0.1", "cleanup": "removed"}
        record = receipt if isinstance(receipt, str) else (
            "DOCKERLENS_NATIVE_APPARMOR_PROFILE: " + json.dumps(receipt))
        with tempfile.TemporaryDirectory(prefix="dl-fake-cleanup-") as temporary:
            (Path(temporary) / "timeout").symlink_to("/usr/bin/timeout")
            (Path(temporary) / "python3").symlink_to(sys.executable)
            # Only the existing EXIT owner and real read-only receipt validator.
            # PATH cannot resolve a runtime, parser, sudo or cleanup executable.
            body = ("set -euo pipefail\n" + definition("native_publication_command")
                    + definition("cleanup") + "\n" + f"SECONDS={elapsed}\n"
                    + "watchdog_pid=; container=daemon; sidecar=sidecar; outer_network=network; volume=volume\n"
                    + "outer_container_id=; sidecar_container_id=; outer_attempted=0; sidecar_attempted=0\n"
                    + "apparmor_profile=github_runner_userns_v1; apparmor_attempted=1; apparmor_nonce=" + NONCE + "\n"
                    + f"apparmor_native_completed={completed}; native_success_summary='ORDINARY SUCCESS'; lane=upstream-rootless\n"
                    + f"preserve_run_dir={retained}; run_dir=" + shlex.quote(temporary) + "\n"
                    + "script_dir=" + shlex.quote(str(ROOT / "scripts")) + "\n"
                    + "DOCKERLENS_NATIVE_CANDIDATE_SHA=" + HOSTED["DOCKERLENS_NATIVE_CANDIDATE_SHA"] + "\n"
                    + f"cleanup_container() {{ printf 'container-cleanup-called\\n'; return {containers}; }}\n"
                    + f"cleanup_network() {{ printf 'network-cleanup-called\\n'; return {network}; }}\n"
                    + "cleanup_volume() { printf 'volume-cleanup-called\\n'; return 0; }\n"
                    + "cleanup_refuse() { status=1; preserve_run_dir=1; return 1; }\n"
                    + f"native_outer_bridge_command() {{ printf '%s\\n' {shlex.quote(record)}; "
                    + f"printf 'profile-cleanup-called\\n' >&2; return {helper}; }}\n"
                    + "publish_native_evidence() { printf 'ordinary-receipt-published\\n'; "
                    + (f"SECONDS={publisher_elapsed}; " if publisher_elapsed is not None else "")
                    + f"return {publisher}; }}\n"
                    + f"trap cleanup EXIT\nexit {original}\n")
            return subprocess.run(["/bin/bash", "-c", body], env={"PATH": temporary},
                                  capture_output=True, text=True, timeout=3)

    def test_native_success_and_verified_profile_cleanup_allow_ordinary_receipt(self):
        result = self.cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("outcome=verified native_completed=1", result.stderr)
        self.assertEqual(result.stdout.count("container-cleanup-called"), 2)
        for marker in ("container-cleanup-called", "network-cleanup-called", "volume-cleanup-called"):
            self.assertLess(result.stdout.index(marker), result.stdout.index("APPARMOR_PROFILE:"))
        self.assertLess(result.stdout.index("APPARMOR_PROFILE:"), result.stdout.index("ordinary-receipt-published"))
        self.assertLess(result.stdout.index("ordinary-receipt-published"), result.stdout.index("ORDINARY SUCCESS"))

    def test_native_failure_cancellation_cleanup_failure_and_retention_never_publish(self):
        for original in (0, 17, 130, 143):
            for failure in ({"helper": 2}, {"network": 1}, {"containers": 1},
                            {"completed": 0}, {"retained": 1}):
                with self.subTest(original=original, failure=failure):
                    result = self.cleanup(original=original, **failure)
                    self.assertEqual(result.returncode, original or 1, result.stderr)
                    self.assertIn("outcome=refused", result.stderr)
                    self.assertNotIn("ordinary-receipt-published", result.stdout)
                    self.assertNotIn("ORDINARY SUCCESS", result.stdout)
                    self.assertIn("profile-cleanup-called", result.stderr)
        result = self.cleanup(publisher=9)
        self.assertEqual(result.returncode, 9)
        self.assertNotIn("ORDINARY SUCCESS", result.stdout)

    def test_unproved_or_malformed_cleanup_receipt_cannot_publish(self):
        base = {"schema": 1, "prerequisite": "github_runner_userns_v1", "outcome": "verified",
                "candidate": HOSTED["DOCKERLENS_NATIVE_CANDIDATE_SHA"], "label": "verified",
                "profile_sha256": "a" * 64, "parser_sha256": "b" * 64,
                "abi_sha256": "c" * 64, "parser_version": "4.0.1", "cleanup": "removed"}
        for receipt in ("", "profile-cleanup-called", "DOCKERLENS_NATIVE_APPARMOR_PROFILE: {}",
                        'DOCKERLENS_NATIVE_APPARMOR_PROFILE: {"schema":1,"schema":1}',
                        base | {"label": "unverified", "outcome": "incomplete"},
                        base | {"cleanup": "not_loaded", "label": "unverified", "outcome": "incomplete"},
                        base | {"candidate": "e" * 40}, base | {"profile_sha256": ""}):
            with self.subTest(receipt=receipt):
                result = self.cleanup(receipt=receipt)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("ordinary-receipt-published", result.stdout)
                self.assertNotIn("ORDINARY SUCCESS", result.stdout)

    def test_expired_original_budget_cannot_validate_or_publish_after_cleanup(self):
        result = self.cleanup(elapsed=1800)
        self.assertEqual(result.returncode, 1)
        self.assertIn("profile-cleanup-called", result.stderr)
        self.assertNotIn("ordinary-receipt-published", result.stdout)
        self.assertNotIn("ORDINARY SUCCESS", result.stdout)

    def test_exact_native_sequence_and_launch_remain_mandatory(self):
        self.assertLess(SOURCE.index('30 apparmor verify "$lane" "$apparmor_nonce"'), SOURCE.index('/run-exact-native-test.sh"'))
        self.assertLess(SOURCE.rindex('/run-exact-native-test.sh"'), SOURCE.index("  apparmor_native_completed=1"))
        self.assertEqual(SOURCE.count('/run-exact-native-test.sh"'), 27)
        assert_current_cohort(self, SOURCE)
        self.assertIn('--privileged --pids-limit=512 --memory=4g', RUNTIME)
        self.assertIn('start=(/usr/local/bin/start-dockerd', RUNTIME)
        helper = (ROOT / "scripts/native-runner-apparmor.py").read_text()
        self.assertNotIn('"/usr/bin/git"', helper)
        self.assertNotIn("safe.directory", helper)

    def test_late_zero_publisher_cannot_emit_ordinary_success(self):
        result = self.cleanup(publisher_elapsed=1800)
        self.assertEqual(result.returncode, 124)
        self.assertIn("outcome=refused", result.stderr)
        self.assertNotIn("ORDINARY SUCCESS", result.stdout)

if __name__ == "__main__":
    unittest.main()
