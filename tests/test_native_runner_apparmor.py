"""Hermetic experiment controls: no parser, runtime, /run, or policy operations."""

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


def definition(name, source=SOURCE):
    start = source.index("\n" + name + "() {") + 1
    return source[start:source.index("\n}\n", start) + 3]


def private_run():
    # Match the coordinator's alphanumeric mktemp suffix, not tempfile's
    # additional leading-underscore possibility (native run labels forbid it).
    # Production custody requires a direct /tmp child, even under gate TMPDIR.
    while True:
        directory = tempfile.TemporaryDirectory(prefix="dockerlens-native.", dir="/tmp")
        if Path(directory.name).name.rsplit(".", 1)[1][0].isalnum():
            return directory
        directory.cleanup()


class AdmissionTests(unittest.TestCase):
    def test_receipt_schema_and_all_projected_values_are_closed(self):
        receipt = {"schema": 1, "experiment": "issue127_userns_v1", "outcome": "unadmitted",
                   "candidate": "d" * 40, "label": "unverified", "profile_sha256": "a" * 64,
                   "parser_sha256": "b" * 64, "abi_sha256": "c" * 64,
                   "parser_version": "4.0.1", "cleanup": "removed"}
        APP.validate_receipt(receipt, "d" * 40)
        wrong = [None, [], receipt | {"unknown": "private"}, receipt | {"schema": True},
                 receipt | {"label": "verified", "cleanup": "not_loaded"},
                 receipt | {"parser_version": "unverified"}, receipt | {"candidate": "e" * 40}]
        for key in receipt:
            wrong.extend((receipt | {key: "private\nraw"}, receipt | {key: None},
                          {other: value for other, value in receipt.items() if other != key}))
        for value in wrong:
            with self.subTest(value=value), self.assertRaises(APP.Refused):
                APP.validate_receipt(value, "d" * 40)

    def test_failure_stage_output_is_closed_and_does_not_echo_evidence(self):
        for stage in (*sorted(APP.STAGES), "private/path\nraw parser diagnostic"):
            with self.subTest(stage=stage):
                experiment = mock.Mock(stage=stage)
                experiment.prepare.side_effect = APP.Refused("private/raw evidence")
                output = io.StringIO()
                with mock.patch.object(APP, "Experiment", return_value=experiment), contextlib.redirect_stderr(output):
                    self.assertEqual(APP.main(["prepare", "directory", "upstream-rootless", NONCE, "name", "run", PIN]), 2)
                expected = stage if stage in APP.STAGES else "admission"
                self.assertEqual(output.getvalue(), "DOCKERLENS_NATIVE_APPARMOR_EXPERIMENT: "
                                 f"operation=prepare stage={expected} outcome=unadmitted cleanup=retained\n")

    def test_completed_query_rejects_stderr_and_nonzero_without_echo(self):
        with private_run() as run, mock.patch.object(APP, "OWNER", os.geteuid()):
            experiment = APP.Experiment(run, "upstream-rootless", NONCE, HOSTED, APP.Cancellation())
            for code in ("import sys; sys.stderr.write('private evidence')", "raise SystemExit(42)"):
                with self.subTest(code=code), self.assertRaises(APP.Refused):
                    experiment.query((sys.executable, "-c", code))

    def test_exact_context_and_every_forbidden_selection_refuse_before_io(self):
        self.assertTrue(APP.admitted(HOSTED))
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
                    APP.Experiment("/tmp/dockerlens-native.abcdefgh", lane, NONCE, HOSTED, APP.Cancellation())

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
            experiment = APP.Experiment(run, "upstream-rootless", NONCE, HOSTED, APP.Cancellation())
            experiment.query((str(APP.PARSER), *APP.COMMON, "--version"))
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
                    + definition("select_apparmor_experiment")
                    + "\nlane=$1; native_outer_engine=$2; script_dir=/reviewed/scripts\n"
                    + "select_apparmor_experiment; printf '%s' \"$apparmor_experiment\"\n")
            def invoke(lane="upstream-rootless", engine="docker", changes=None):
                return subprocess.run(["/bin/bash", "-c", body, "test", lane, engine],
                                      env=env | (changes or {}), capture_output=True, timeout=3)
            self.assertEqual(invoke().stdout, b"issue127_userns_v1")
            for lane in ("debian11-rootless", "upstream-rootful", "debian11-rootful"):
                self.assertEqual(invoke(lane=lane).stdout, b"")
            for changes in ({"MOCK_DIRTY": " M source"}, {"MOCK_HEAD": "e" * 40},
                            {"GITHUB_EVENT_NAME": "push"}, {"GITHUB_JOB": "other"},
                            {"RUNNER_ENVIRONMENT": "self-hosted"}, {"DOCKER_HOST": "tcp://remote"}):
                self.assertEqual(invoke(changes=changes).returncode, 2)
            self.assertEqual(invoke(engine="podman").returncode, 2)
            for workflow in ("check", "release-validation"):
                self.assertEqual(invoke(changes={"GITHUB_WORKFLOW_REF": f"Strukturpiloten/docker-lens/.github/workflows/{workflow}.yml@refs/heads/main"}).stdout, b"")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.run = private_run()
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
        self.query = self.stack.enter_context(mock.patch.object(APP.Experiment, "query", autospec=True, side_effect=self.fake_query))
        self.profile_loaded = False
        self.parser_failure = None
        self.version = b"AppArmor parser version 4.0.1\nCopyright test\n"
        self.missing_feature = None
        self.absence = True
        self.commands = []
        self.snapshot_override = None
        self.experiment = APP.Experiment(self.run.name, "upstream-rootless", NONCE, HOSTED, APP.Cancellation())
        self.run_id = Path(self.run.name).name.rsplit(".", 1)[1]
        self.name = "dl-native-" + self.run_id

    def fake_read(self, path, _limit=65536):
        if path == self.missing_feature:
            raise FileNotFoundError
        if path == APP.PROFILES:
            return (("dockerlens-127-upstream-rootless-127-1-" + NONCE + " (unconfined)\n").encode()
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

    def fake_query(self, _experiment, argv, *, statuses=(0,)):
        self.commands.append(tuple(argv))
        if argv[0] == str(APP.PARSER):
            self.assertEqual(argv[1:1 + len(APP.COMMON)], APP.COMMON)
            operation = argv[1 + len(APP.COMMON)]
            if self.parser_failure == operation:
                raise APP.Refused("completion_unknown")
            if operation == "--version":
                return self.version
            self.assertEqual(Path(argv[-1]).read_bytes(), APP.profile_bytes(self.experiment.state["profile"]))
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
                     "Config": {"Image": PIN, "Labels": {"io.dockerlens.native-run": self.run_id}},
                     "State": {"Running": True, "Pid": 1234, "StartedAt": "started"},
                     "HostConfig": {"Privileged": True}}
            value.update(self.snapshot_override or {})
            return json.dumps(value).encode()
        raise AssertionError(argv)

    def state(self):
        return json.loads((self.experiment.path / "state.json").read_text())

    def prepare(self):
        self.experiment.prepare(self.name, self.run_id, PIN)

    def start(self):
        self.prepare()
        self.experiment.load()
        name = self.experiment.begin(self.name, self.run_id, PIN)
        self.assertEqual(name, self.state()["profile"])
        self.experiment.created(CID)

    def test_fixed_parser_argv_and_full_profile_lifecycle(self):
        self.start()
        receipt = self.experiment.cleanup()
        self.assertEqual((receipt["outcome"], receipt["cleanup"], receipt["label"]),
                         ("unadmitted", "removed", "unverified"))
        self.assertFalse(self.profile_loaded)
        parser = [argv for argv in self.commands if argv[0] == str(APP.PARSER)]
        self.assertEqual([argv[1 + len(APP.COMMON)] for argv in parser],
                         ["--version", "--skip-kernel-load", "--add", "--remove"])
        self.assertEqual(list(self.experiment.path.iterdir()), [])
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
                self.experiment.cleanup()
                self.experiment.path.rmdir()
        self.assertFalse(any("--add" in argv or "--remove" in argv for argv in self.commands))

    def test_compile_failure_never_loads_and_can_discard_only_unmutated_state(self):
        self.parser_failure = "--skip-kernel-load"
        with self.assertRaises(APP.Refused):
            self.prepare()
        self.assertEqual(self.experiment.stage, "compile")
        self.assertEqual(self.experiment.cleanup()["cleanup"], "not_loaded")

    def test_prerequisite_refusal_has_only_the_expected_fixed_stage(self):
        for path, stage in (("/sys/module/apparmor/parameters/enabled", "kernel_enabled"),
                            ("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "userns_restriction"),
                            ("/sys/kernel/security/apparmor/features/namespaces/mask", "kernel_features"),
                            ("/sys/kernel/security/apparmor/features/policy/versions/v9", "kernel_features")):
            with self.subTest(stage=stage):
                self.missing_feature = Path(path)
                with self.assertRaises(FileNotFoundError):
                    self.prepare()
                self.assertEqual(self.experiment.stage, stage)
                self.assertEqual(self.state()["load"], "never")
                self.experiment.cleanup()
                self.experiment.path.rmdir()

    def test_absence_accepts_only_complete_exact_negative_rows_for_both_id_and_name(self):
        self.start()
        for raw in (b"", b"other\n", b"other\nother\n"):
            with self.subTest(raw=raw), mock.patch.object(self.experiment, "bridge", return_value=raw) as bridge:
                self.experiment.absent()
                self.assertEqual(bridge.call_args_list, [mock.call("apparmor-presence", "id", CID),
                                                        mock.call("apparmor-presence", "name", self.name)])
        for raw in (b"present\n", b"present\npresent\n", b"other\npresent\n", b"other", b"other\r\n",
                    b"other\npartial", b"\n", b"absent\n", b"private evidence\n"):
            with self.subTest(raw=raw), mock.patch.object(self.experiment, "bridge", return_value=raw), self.assertRaises(APP.Refused):
                self.experiment.absent()
        with mock.patch.object(self.experiment, "bridge", side_effect=APP.Refused("command_failed")), self.assertRaises(APP.Refused):
            self.experiment.absent()
        self.assertEqual(self.experiment.stage, "absence")

    def test_name_collision_between_compile_and_load_never_removes_existing_profile(self):
        self.prepare()
        self.profile_loaded = True
        with self.assertRaises(APP.Refused):
            self.experiment.load()
        self.assertEqual(self.experiment.cleanup()["cleanup"], "not_loaded")
        self.assertTrue(self.profile_loaded)
        self.assertFalse(any("--add" in argv or "--remove" in argv for argv in self.commands))

    def test_add_failure_timeout_and_interrupted_create_are_sticky(self):
        self.prepare()
        self.parser_failure = "--add"
        with self.assertRaises(APP.Refused):
            self.experiment.load()
        self.assertEqual(self.state()["load"], "intent")
        with self.assertRaises(APP.Refused):
            self.experiment.cleanup()
        self.assertTrue((self.experiment.path / "profile").exists())
        self.assertFalse(any("--remove" in argv for argv in self.commands))

    def test_created_never_attempted_allows_loaded_profile_removal(self):
        self.prepare()
        self.experiment.load()
        self.assertEqual(self.experiment.cleanup()["cleanup"], "removed")
        self.assertFalse(any("apparmor-presence" in argv for argv in self.commands))

    def test_creation_intent_without_recorded_cid_refuses_unload(self):
        self.prepare()
        self.experiment.load()
        self.experiment.begin(self.name, self.run_id, PIN)
        with self.assertRaises(APP.Refused):
            self.experiment.cleanup()
        self.assertTrue(self.profile_loaded)
        self.assertEqual(self.state()["create"], "intent")

    def test_unknown_daemon_absence_and_unknown_remove_preserve_state(self):
        self.start()
        self.absence = False
        with self.assertRaises(APP.Refused):
            self.experiment.cleanup()
        self.assertEqual(self.state()["load"], "loaded")
        self.absence = True
        self.parser_failure = "--remove"
        with self.assertRaises(APP.Refused):
            self.experiment.cleanup()
        self.assertEqual(self.state()["load"], "unload_intent")
        self.parser_failure = None
        with self.assertRaises(APP.Refused):
            self.experiment.cleanup()

    def test_actual_creation_binding_is_saved_before_later_label_refusal(self):
        self.start()
        self.assertEqual(self.state()["create"], "recorded")
        with mock.patch.object(APP.Experiment, "snapshot", side_effect=APP.Refused("label_unavailable")):
            with self.assertRaises(APP.Refused):
                self.experiment.verify()
        self.assertEqual(self.state()["create"], "recorded")
        self.assertEqual(self.experiment.cleanup()["cleanup"], "removed")

    def test_unbound_actual_creation_never_becomes_known_from_cid_alone(self):
        self.prepare()
        self.experiment.load()
        self.experiment.begin(self.name, self.run_id, PIN)
        self.snapshot_override = {"Name": "foreign"}
        with self.assertRaises(ValueError):
            self.experiment.created(CID)
        self.assertEqual(self.state()["create"], "intent")
        with self.assertRaises(APP.Refused):
            self.experiment.cleanup()

    def test_run_directory_replacement_and_original_identity_mismatch_refuse(self):
        self.prepare()
        original = Path(self.run.name)
        moved = original.with_name(original.name + ".held")
        original.rename(moved)
        self.addCleanup(lambda: moved.rename(original))
        original.mkdir(mode=0o700)
        self.addCleanup(original.rmdir)
        with self.assertRaises(APP.Refused):
            self.experiment.load()
        self.assertFalse(self.profile_loaded)

    def test_symlink_hardlink_mode_and_nonce_directory_reuse_refuse(self):
        self.prepare()
        with self.assertRaises(FileExistsError):
            self.prepare()
        profile = self.experiment.path / "profile"
        content = profile.read_bytes()
        profile.chmod(0o644)
        with self.assertRaises(APP.Refused):
            self.experiment.load()
        profile.chmod(0o600)
        extra = self.experiment.path / "extra"
        os.link(profile, extra)
        with self.assertRaises(APP.Refused):
            self.experiment.load()
        extra.unlink()
        profile.unlink()
        extra.write_bytes(content)
        profile.symlink_to(extra)
        with self.assertRaises(OSError):
            self.experiment.load()

    def test_state_custody_and_candidate_rebinding_refuse_without_policy_contact(self):
        self.prepare()
        for key, wrong in (("candidate", "e" * 40), ("run_identity", [0, 1, 2]), ("attempt", "2"), ("lane", "debian11-rootless")):
            with self.subTest(key=key):
                state = self.state()
                path = self.experiment.path / "state.json"
                path.write_text(json.dumps(state | {key: wrong}))
                with self.assertRaises(APP.Refused):
                    self.experiment.load()
                path.write_text(json.dumps(state))
        self.assertFalse(self.profile_loaded)
        state = self.experiment.path / "state.json"
        alias = self.experiment.path / "alias"
        os.link(state, alias)
        with self.assertRaises(APP.Refused):
            self.experiment.load()

    def test_malformed_state_never_authorizes_any_lifecycle_operation_or_receipt(self):
        self.prepare()
        original = self.state()
        path = self.experiment.path / "state.json"
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
                    getattr(self.experiment, operation)(*args)
                self.assertEqual(path.read_text(), raw)
                self.assertEqual((len(self.commands), self.read.call_count), (commands, policy_reads))
        path.write_text(json.dumps(original))
        self.experiment.load()
        self.assertTrue(self.profile_loaded)

    def test_cancellation_before_parser_mutation_stays_unadmitted(self):
        self.prepare()
        # Cancellation at the actual parser transport edge, not a fake signal
        # to a real child. Intent was saved before entering this edge.
        with mock.patch.object(APP.Experiment, "parser", side_effect=APP.Cancelled(15)):
            with self.assertRaises(APP.Cancelled):
                self.experiment.load()
        self.assertEqual(self.state()["load"], "intent")
        with self.assertRaises(APP.Refused):
            self.experiment.cleanup()

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
                    mock.patch.object(APP.Experiment, "snapshot", return_value=(1234, "started")) as snapshot, \
                    mock.patch.object(APP, "process_ticks", return_value=99) as ticks, \
                    mock.patch.object(APP, "process_read", return_value=f"0::/system.slice/docker-{CID}.scope\n".encode()) as cgroup, \
                    mock.patch.object(APP, "process_label", return_value=expected) as label:
                self.experiment.verify()
                self.assertEqual(self.state()["label"], "verified")
                self.assertEqual((snapshot.call_count, ticks.call_count, label.call_count), (2, 2, 2))
                for wrong in (b"unconfined\n", expected.replace(b"unconfined", b"enforce"), expected + b"stacked", b""):
                    label.return_value = wrong
                    with self.assertRaises(APP.Refused):
                        self.experiment.verify()
                label.return_value = expected
                ticks.side_effect = [99, 100]
                with self.assertRaises(APP.Refused):
                    self.experiment.verify()
                ticks.side_effect = None
                snapshot.side_effect = [(1234, "started"), (1234, "restarted")]
                with self.assertRaises(APP.Refused):
                    self.experiment.verify()
                snapshot.side_effect = None
                for wrong in (b"0::/system.slice/other.scope\n", f"0::/docker/{CID}\n".encode(),
                              f"0::/system.slice/docker-{CID}.scope/child\n".encode()):
                    cgroup.return_value = wrong
                    with self.assertRaises(APP.Refused):
                        self.experiment.verify()
                cgroup.side_effect = [f"0::/system.slice/docker-{CID}.scope\n".encode(), b"changed\n"]
                with self.assertRaises(APP.Refused):
                    self.experiment.verify()
        finally:
            os.close(process)


class ShellCreationTests(unittest.TestCase):
    def test_only_exact_selected_experimental_calls_extend_explicit_context(self):
        base = ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "GITHUB_REF", "GITHUB_EVENT_NAME",
                "GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "ImageOS", "ImageVersion", "DOCKER_HOST",
                "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION",
                "CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINER_SSHKEY", "PODMAN_CONNECTIONS_CONF")
        extra = ("GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "DOCKERLENS_NATIVE_CANDIDATE_SHA")
        directory = "/tmp/dockerlens-native.abcdefgh"
        body = ("set -euo pipefail\n" + definition("native_outer_bridge_command", RUNTIME)
                + "\nnative_outer_engine=$1; native_outer_directory=$2; apparmor_experiment=$3; shift 3\n"
                + "native_outer_privilege=(); native_outer_script_dir=/reviewed/scripts\n"
                + "timeout() { printf '%s\\0' \"$@\"; }\n"
                + "native_outer_bridge_command 30 \"$@\"\n")

        def check(args, extended=False, engine="docker", flag="issue127_userns_v1"):
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
                check(args, flag="issue127_userns_v2")
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
experiment=app.Experiment(directory,lane,nonce,os.environ,cancellation)
if mode == "late-begin":
    signal.signal(signal.SIGTERM, lambda *_: None)
    (run/"frontend-ready").write_text(str(os.getpid()))
    while not (run/"release").exists(): time.sleep(.01)
    print("dockerlens-127-upstream-rootless-127-1-"+nonce, flush=True)
    raise SystemExit(0)
if mode == "soft-deadline": experiment.deadline=time.monotonic()+.15
experiment.bridge("apparmor-presence", "id", {CID!r})
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


class ShellFinalizationTests(unittest.TestCase):
    def cleanup(self, original=0, helper=0, network=0, containers=0):
        with tempfile.TemporaryDirectory(prefix="dl-fake-cleanup-") as temporary:
            # Extract only the existing EXIT owner. PATH cannot resolve engines,
            # parser, sudo, or any external cleanup implementation.
            body = ("set -euo pipefail\n" + definition("cleanup") + "\n"
                    + "watchdog_pid=; container=daemon; sidecar=sidecar; outer_network=network; volume=volume\n"
                    + "outer_container_id=; sidecar_container_id=; outer_attempted=0; sidecar_attempted=0\n"
                    + "apparmor_experiment=issue127_userns_v1; apparmor_attempted=1; apparmor_nonce=" + NONCE + "\n"
                    + "apparmor_native_completed=1; native_success_summary='FORBIDDEN SUCCESS'; lane=upstream-rootless\n"
                    + "preserve_run_dir=1; run_dir=" + shlex.quote(temporary) + "\n"
                    + f"cleanup_container() {{ return {containers}; }}\n"
                    + f"cleanup_network() {{ return {network}; }}\ncleanup_volume() {{ return 0; }}\n"
                    + "cleanup_refuse() { status=1; preserve_run_dir=1; return 1; }\n"
                    + f"native_outer_bridge_command() {{ printf 'profile-cleanup-called\\n'; return {helper}; }}\n"
                    + f"trap cleanup EXIT\nexit {original}\n")
            return subprocess.run(["/bin/bash", "-c", body], env={"PATH": temporary},
                                  capture_output=True, text=True, timeout=3)

    def test_experiment_never_succeeds_and_preserves_native_and_cancel_failure(self):
        for original in (0, 17, 130, 143):
            for helper in (0, 2):
                result = self.cleanup(original=original, helper=helper, network=1)
                self.assertEqual(result.returncode, original or 1)
                self.assertIn("outcome=unadmitted", result.stderr)
                self.assertNotIn("FORBIDDEN SUCCESS", result.stdout)
                self.assertIn("profile-cleanup-called", result.stdout)

    def test_cleanup_still_checks_profile_when_guest_cleanup_was_unknown(self):
        result = self.cleanup(containers=1, helper=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("profile-cleanup-called", result.stdout)

    def test_standard_receipt_block_is_unreachable_after_experiment_native_checks(self):
        barrier = SOURCE.index("  apparmor_native_completed=1")
        receipt = SOURCE.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]')
        self.assertIn("exit 0", SOURCE[barrier:receipt])
        self.assertLess(SOURCE.index('30 apparmor verify "$lane" "$apparmor_nonce"'), SOURCE.index('/run-exact-native-test.sh"'))
        self.assertEqual(SOURCE.count('/run-exact-native-test.sh"'), 19)
        self.assertIn('--privileged --pids-limit=512 --memory=4g', RUNTIME)
        self.assertIn('start=(/usr/local/bin/start-dockerd', RUNTIME)
        helper = (ROOT / "scripts/native-runner-apparmor.py").read_text()
        self.assertNotIn('"/usr/bin/git"', helper)
        self.assertNotIn("safe.directory", helper)


if __name__ == "__main__":
    unittest.main()
