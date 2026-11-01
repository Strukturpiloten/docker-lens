"""Real attach-only UID command path with fake clients, never a native runtime."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("uid_bridge", ROOT / "scripts/native-daemon-uid.py")
UID = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UID)
CID = "a" * 64
HOSTED = {
    "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
    "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens",
    "GITHUB_WORKFLOW_REF": "Strukturpiloten/docker-lens/.github/workflows/native-validation.yml@refs/heads/main",
    "ImageOS": "ubuntu24", "ImageVersion": "20261020.1.0",
}


class DaemonUidBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dl-uid-bridge-")
        self.addCleanup(self.temporary.cleanup)
        self.private = Path(self.temporary.name)
        self.private.chmod(0o700)
        self.tools = self.private / "tools"
        self.tools.mkdir(mode=0o700)
        # No ambient runtime can be found even in the missing-client controls.
        for tool in ("timeout", "env", "bash", "python3", "dirname"):
            (self.tools / tool).symlink_to(Path(shutil.which(tool)).resolve())
        self.run = self.private / "held;not-shell"
        self.run.mkdir(mode=0o700)
        self.client = self.run / "docker-client"
        self.client.mkdir(mode=0o700)
        self.trace = self.private / "trace.json"
        sudo = self.tools / "sudo"
        sudo.write_text('#!/bin/sh\n[ "$1" = -n ] || exit 97\nshift\nexec env -i PATH="$PATH" "$@"\n')
        sudo.chmod(0o700)
        self.environment = {"PATH": str(self.tools), **HOSTED,
                            "DOCKER_CONFIG": "private-config-must-not-reach-docker",
                            "UNREVIEWED_CONTEXT": "must-not-cross-sudo"}

    def clients(self, stdout="0\n", stderr="", status=0):
        for engine in ("podman", "docker"):
            path = self.tools / engine
            path.write_text("#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\n"
                f"Path({str(self.trace)!r}).write_text(json.dumps({{'engine':{engine!r},'argv':sys.argv[1:],"
                "'docker_config_present':'DOCKER_CONFIG' in os.environ,"
                "'unreviewed_context_present':'UNREVIEWED_CONTEXT' in os.environ}))\n"
                f"sys.stdout.write({stdout!r})\nsys.stderr.write({stderr!r})\nraise SystemExit({status})\n")
            path.chmod(0o700)

    def observe(self, engine, caller_uid, mode="rootful", changes=None, directory=None):
        environment = {**self.environment, **(changes or {})}
        with patch.dict(os.environ, environment, clear=True), patch.object(UID.os, "geteuid", return_value=caller_uid):
            return UID.observe(CID, mode, engine, str(directory or self.run))

    def test_complete_backend_privilege_and_uid_command_matrix(self):
        for engine in ("podman", "docker"):
            for caller_uid in (0, 1000):
                for mode, observed in (("rootful", 0), ("rootless", 1000), ("rootless", 4294967295)):
                    with self.subTest(engine=engine, caller_uid=caller_uid, mode=mode, observed=observed):
                        self.clients(f"{observed}\n")
                        self.assertEqual(self.observe(engine, caller_uid, mode), observed)
                        trace = json.loads(self.trace.read_text())
                        self.assertEqual(trace["engine"], engine)
                        prefix = ["--config", str(self.client), "--host", "unix:///var/run/docker.sock"] if engine == "docker" else ["--remote=false"]
                        self.assertEqual(trace["argv"], prefix + ["exec", CID, "sh", "-ec", UID.QUERY])
                        if engine == "docker":
                            self.assertFalse(trace["docker_config_present"])
                        if caller_uid != 0:
                            self.assertFalse(trace["unreviewed_context_present"])
                        self.assertEqual(list(self.client.iterdir()), [])
                        self.assertEqual(list(self.run.iterdir()), [self.client])

    def test_policy_context_survives_scrubbed_sudo_and_rejects_selectors_without_client_contact(self):
        self.clients()
        for engine, changes in (
            ("docker", {"DOCKER_HOST": "unix:///private-canary.sock"}),
            ("docker", {"DOCKER_CONTEXT": "private-context"}),
            ("docker", {"GITHUB_REF": "refs/heads/untrusted"}),
            ("docker", {"GITHUB_WORKFLOW_REF": "private-workflow"}),
            ("docker", {"ImageVersion": "unknown"}),
            ("podman", {"CONTAINER_HOST": "unix:///private-canary.sock"}),
            ("podman", {"PODMAN_CONNECTIONS_CONF": "/private/config"}),
        ):
            for caller_uid in (0, 1000):
                with self.subTest(engine=engine, caller_uid=caller_uid, keys=tuple(changes)):
                    with self.assertRaisesRegex(ValueError, "^invalid daemon UID evidence$"):
                        self.observe(engine, caller_uid, changes=changes)
                    self.assertFalse(self.trace.exists())

    def test_missing_selected_client_never_falls_back(self):
        ambient = self.private / "ambient-host"
        ambient.mkdir(mode=0o700)
        sentinel = self.private / "ambient-client-called"
        for engine in ("podman", "docker"):
            path = ambient / engine
            path.write_text(f"#!/bin/sh\nprintf invoked > {str(sentinel)!r}\nexit 97\n")
            path.chmod(0o700)
        for engine in ("podman", "docker"):
            for caller_uid in (0, 1000):
                with self.subTest(engine=engine, caller_uid=caller_uid):
                    self.clients()
                    (self.tools / engine).unlink()
                    self.assertIsNone(shutil.which(engine, path=self.environment["PATH"]))
                    self.assertEqual(shutil.which(engine, path=str(ambient)), str(ambient / engine))
                    with patch.dict(os.environ, {"PATH": str(ambient)}):
                        with self.assertRaisesRegex(ValueError, "^invalid daemon UID evidence$"):
                            self.observe(engine, caller_uid)
                    self.assertFalse(self.trace.exists())
                    self.assertFalse(sentinel.exists())

    def test_attach_refuses_missing_nonempty_wrongmode_and_symlink_configuration_without_creation(self):
        self.clients()
        for fault in ("missing", "nonempty", "mode", "symlink", "parent-mode", "parent-symlink"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir=self.private) as directory:
                run = Path(directory)
                client = run / "docker-client"
                if fault != "missing":
                    client.mkdir(mode=0o700)
                if fault == "nonempty":
                    (client / "config.json").write_text("{}")
                elif fault == "mode":
                    client.chmod(0o755)
                elif fault == "symlink":
                    client.rmdir()
                    client.symlink_to(self.client, target_is_directory=True)
                elif fault == "parent-mode":
                    run.chmod(0o755)
                elif fault == "parent-symlink":
                    link = self.private / "run-link"
                    link.symlink_to(run, target_is_directory=True)
                    self.addCleanup(link.unlink)
                    run = link
                with self.assertRaisesRegex(ValueError, "^invalid daemon UID evidence$"):
                    self.observe("docker", 1000, directory=run)
                self.assertFalse(self.trace.exists())
                if fault == "missing":
                    self.assertFalse(client.exists())

    def test_real_bridge_result_does_not_bypass_uid_oracle_on_error_or_wrong_mode(self):
        for stdout, stderr, status, mode in (
            ("1000\n", "", 0, "rootful"), ("0\n", "", 0, "rootless"),
            ("0\n", "private-canary", 0, "rootful"), ("0\n", "", 125, "rootful"),
            ("00\n", "", 0, "rootful"), ("4294967296\n", "", 0, "rootless"),
        ):
            for engine in ("podman", "docker"):
                with self.subTest(engine=engine, status=status, mode=mode):
                    self.clients(stdout, stderr, status)
                    with self.assertRaisesRegex(ValueError, "^invalid daemon UID evidence$"):
                        self.observe(engine, 1000, mode)

    def test_canonical_policy_input_allowlist_and_direct_caller_are_exact(self):
        source = (ROOT / "scripts/native-outer-runtime.sh").read_text()
        keys = source.split("for key in ", 1)[1].split("; do context+=", 1)[0].replace("\\\n", " ").split()
        self.assertEqual(list(UID.CONTEXT), keys)
        caller = (ROOT / "scripts/native-conformance.sh").read_text()
        self.assertTrue('"$script_dir/native-daemon-uid.py" "$outer_container_id" "$expected_mode" ' + "\\\n" +
                        '  "$native_outer_engine" "$run_dir"' in caller)

    def test_cli_missing_backend_context_and_invalid_inputs_refuse_without_native_contact(self):
        self.clients()
        for args in ((CID, "rootful"), (CID, "rootful", "auto", str(self.run)),
                     (CID, "rootful", "docker", "relative"),
                     ("not-an-id", "rootful", "docker", str(self.run))):
            with self.subTest(argument_count=len(args)):
                result = subprocess.run([sys.executable, str(ROOT / "scripts/native-daemon-uid.py"), *args],
                    env=self.environment, capture_output=True, text=True, timeout=2)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "native daemon UID evidence rejected\n")
                self.assertFalse(self.trace.exists())
