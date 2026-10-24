"""External argv/normalization controls with fake clients; never an Engine."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "scripts/native-outer-command.sh"
SPEC = importlib.util.spec_from_file_location("outer_bridge_observation", ROOT / "scripts/native-outer-observation.py")
OBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBS)
ID = "a" * 64
DIGEST = "sha256:" + "b" * 64
IMAGE_ID = "sha256:" + "c" * 64
PIN = "example.invalid:5000/engine:1@" + DIGEST
HOSTED = {
    "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
    "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push",
    "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens",
    "GITHUB_WORKFLOW_REF": "Strukturpiloten/docker-lens/.github/workflows/check.yml@refs/heads/main",
    "ImageOS": "ubuntu24", "ImageVersion": "20261020.1.0",
}


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory(prefix="dl-bridge-")
        self.addCleanup(self.private.cleanup)
        self.directory = Path(self.private.name)
        self.directory.chmod(0o700)
        self.client = self.directory / "docker-client"
        self.client.mkdir(mode=0o700)
        self.tools = self.directory / "tools"
        self.tools.mkdir(mode=0o700)
        self.trace = self.directory / "trace"
        script = '''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
with open(os.environ["MOCK_TRACE"], "a") as stream:
    stream.write(json.dumps(args) + "\\n")
if args[:1] == ["--config"]:
    args = args[4:]
if args[:1] == ["--remote=false"]:
    args = args[1:]
if args[:2] == ["container", "inspect"]:
    print(os.environ["MOCK_CONTAINER"])
elif args[:2] == ["image", "inspect"]:
    print(os.environ["MOCK_IMAGE"])
elif args[:1] == ["save"]:
    Path(args[args.index("--output") + 1]).write_bytes(b"authored-archive")
elif args[:1] == ["run"]:
    if os.environ.get("MOCK_NO_CID") != "1":
        Path(args[args.index("--cidfile") + 1]).write_text(os.environ.get("MOCK_CID", "a" * 64))
    sys.exit(int(os.environ.get("MOCK_RUN_STATUS", "0")))
elif "slow" in args:
    time.sleep(3)
else:
    print(json.dumps(args))
'''
        for name in ("docker", "podman"):
            path = self.tools / name
            path.write_text(script)
            path.chmod(0o700)
        self.container = {"Id": ID, "Name": "/owned", "Image": IMAGE_ID,
                          "Config": {"Image": PIN, "Labels": {"io.boxferry.docker-core-run": "run"}}, "State": {"Running": True},
                          "HostConfig": {"NanoCpus": 0, "CpuQuota": 200000, "CpuPeriod": 100000}}
        self.image = {"Id": IMAGE_ID, "RepoDigests": ["example.invalid:5000/engine@" + DIGEST],
                      "Os": "linux", "Architecture": "amd64"}

    def invoke(self, *args, engine="docker", changes=None, timeout=None):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("DOCKER_", "DOCKERLENS_", "CONTAINER_", "GITHUB_", "RUNNER_", "Image"))
               and key not in {"PODMAN_CONNECTIONS_CONF"}}
        env.update(HOSTED)
        env.update({"PATH": str(self.tools) + ":" + os.environ["PATH"], "MOCK_TRACE": str(self.trace),
                    "MOCK_CONTAINER": json.dumps(self.container), "MOCK_IMAGE": json.dumps(self.image)})
        env.update(changes or {})
        command = ["bash", str(BRIDGE), "--engine", engine, "--directory", str(self.directory), *args]
        if timeout:
            command = ["timeout", "--signal=TERM", "--kill-after=0.2s", timeout, *command]
        return subprocess.run(command, env=env, capture_output=True, timeout=5)

    def calls(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()] if self.trace.exists() else []

    def test_docker_snapshot_binds_actual_image_and_declared_manifest_before_normalizing(self):
        result = self.invoke("inspect", "--format", "{{json .}}", ID)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["Name"], "owned")
        self.assertEqual(value["ImageDigest"], DIGEST)
        for key in ("Id", "Image", "Config", "State", "HostConfig"):
            self.assertEqual(value[key], self.container[key])
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.calls()[1][-1], PIN)
        self.assertFalse((self.directory / "outer-runtime.json").exists())

    def test_wrong_image_id_manifest_repository_and_missing_digest_never_supply_snapshot(self):
        for replacement in ({"Id": "sha256:" + "d" * 64}, {"RepoDigests": []},
                            {"RepoDigests": ["other.invalid/engine@" + DIGEST]},
                            {"RepoDigests": ["example.invalid:5000/engine@sha256:" + "e" * 64]}):
            with self.subTest(replacement=replacement):
                result = self.invoke("snapshot", ID, changes={"MOCK_IMAGE": json.dumps(self.image | replacement)})
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(PIN.encode(), result.stderr)

    def test_failed_start_cleanup_binding_requires_actual_id_name_owner_and_image(self):
        args = [ID, "owned", "io.boxferry.docker-core-run", "run", PIN]
        result = self.invoke("daemon-binding", *args)
        self.assertEqual((result.returncode, result.stdout), (0, (ID + "|owned|run\n").encode()), result.stderr)
        for offset, replacement in ((0, "d" * 64), (1, "foreign"), (3, "other-run"),
                                    (4, "other.invalid/engine:1@" + DIGEST),
                                    (4, "example.invalid:5000/engine:1@sha256:" + "e" * 64)):
            changed = list(args)
            changed[offset] = replacement
            result = self.invoke("daemon-binding", *changed)
            self.assertEqual((result.returncode, result.stdout), (2, b""))

    def test_podman_snapshot_remains_native_and_does_not_inspect_an_image(self):
        self.container["Name"] = "owned"
        self.container["ImageDigest"] = DIGEST
        result = self.invoke("snapshot", ID, engine="podman")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.container)
        self.assertEqual(len(self.calls()), 1)

    def test_exec_preserves_literal_inner_output_and_original_caller_timer(self):
        result = self.invoke("exec", "--user", "1000", ID, "docker", "inspect", "inner")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ["exec", "--user", "1000", ID, "docker", "inspect", "inner"])
        result = self.invoke("exec", ID, "slow", timeout="0.25s")
        self.assertEqual(result.returncode, 124)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(list(self.client.iterdir()), [])
        self.assertFalse((self.directory / "outer-runtime.json").exists())

    def test_attach_rejects_wrong_mode_symlink_nonempty_config_and_ambient_selector(self):
        self.assertEqual(self.invoke("check-context").returncode, 0)
        self.assertEqual(self.calls(), [])
        self.client.chmod(0o755)
        self.assertEqual(self.invoke("exec", ID, "true").returncode, 2)
        self.client.chmod(0o700)
        (self.client / "config.json").write_text("{}")
        self.assertEqual(self.invoke("exec", ID, "true").returncode, 2)
        (self.client / "config.json").unlink()
        self.assertEqual(self.invoke("exec", ID, "true", changes={"DOCKER_HOST": "tcp://remote"}).returncode, 2)
        self.client.rmdir()
        self.client.symlink_to(self.tools, target_is_directory=True)
        self.assertEqual(self.invoke("exec", ID, "true").returncode, 2)
        self.assertEqual(self.calls(), [])

    def test_volume_path_is_an_owned_local_bound_observation_not_discovery(self):
        value = {"Name": "owned-data", "Driver": "local", "CreatedAt": "observed",
                 "Mountpoint": "/var/lib/docker/volumes/owned-data/_data",
                 "Labels": {"io.boxferry.docker-core-run": "run"}}
        args = ("owned-data", "io.boxferry.docker-core-run", "run")
        self.assertEqual(OBS.volume_path(value, *args), value["Mountpoint"])
        for update in ({"Name": "foreign"}, {"Driver": "remote"}, {"Labels": {}},
                       {"Mountpoint": "/var/../foreign"}, {"Mountpoint": "/"}):
            with self.subTest(update=update), self.assertRaises(OBS.Refused):
                OBS.volume_path(value | update, *args)

    def test_closed_consumer_routes_keep_fixed_output_and_refuse_foreign_archive(self):
        for operation, args in (("pull", [PIN]), ("logs", [ID]),
                                ("volume-create", ["owned-data", "io.boxferry.docker-core-run", "run"])):
            result = self.invoke(operation, *args)
            self.assertEqual(result.returncode, 0, result.stderr)
        result = self.invoke("image-info", PIN)
        self.assertEqual(json.loads(result.stdout), {"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64"})
        self.assertEqual(self.invoke("image-save", PIN, "/tmp/foreign.tar").returncode, 2)
        self.assertEqual(self.invoke("context", "use", "remote").returncode, 2)
        archive = self.directory / "busybox.tar"
        for engine in ("podman", "docker"):
            result = self.invoke("image-save", PIN, str(archive), engine=engine)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(archive.read_bytes(), b"authored-archive")
            archive.unlink()

    def test_complete_rust_native_inventory_uses_one_literal_test_only_boundary(self):
        # These exact pure forms select data, never an executable. Retain every
        # other byte of the unit control under the blanket literal prohibition.
        selector = '''impl SourceOuterBackend {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "podman" => Some(Self::Podman),
            "docker" => Some(Self::Docker),
            _ => None,
        }
    }
'''
        pure_control = '''#[test]
fn source_backend_accounting_is_closed_and_does_not_charge_io() {
    let podman = SourceOuterBackend::parse("podman").unwrap();
    let docker = SourceOuterBackend::parse("docker").unwrap();
'''
        pure_podman = '    let podman = SourceOuterBackend::parse("podman").unwrap();\n'

        def checked_source(source, filename):
            self.assertIn("crate::native_outer_test_command::prefix()", source)
            scanned = source
            if filename == "native_lifecycle_tests.rs":
                # Require exactly one canonical parser with both closed cases
                # and explicit None refusal: no fallback or arbitrary stripping.
                self.assertEqual(source.count("impl SourceOuterBackend {"), 1)
                self.assertEqual(source.count("    fn parse(value: &str) -> Option<Self> {"), 1)
                self.assertEqual(source.count(selector), 1)
                self.assertEqual(source.count("fn source_backend_accounting_is_closed_and_does_not_charge_io() {"), 1)
                self.assertEqual(source.count(pure_control), 1)
                self.assertEqual(source.count(pure_podman), 1)
                scanned = source.replace(selector, "", 1).replace(pure_podman, "", 1)
            self.assertNotIn('"podman"', scanned)
            self.assertNotIn('"--remote=false"', scanned)

        modules = ["native_target_tests", "native_network_tests", "native_network_attachment_tests",
                   "native_bind_relabel_tests", "native_external_network_tests", "native_identity_tests",
                   "native_port_tests", "native_volume_tests", "native_volume_label_tests",
                   "native_health_metadata_tests", "native_stop_signal_tests", "native_lifecycle_tests"]
        paths = [ROOT / "src" / (name + ".rs") for name in modules]
        paths.append(ROOT / "tests/native_selection.rs")
        for path in paths:
            with self.subTest(path=path.name):
                source = path.read_text()
                checked_source(source, path.name)
        lifecycle = (ROOT / "src/native_lifecycle_tests.rs").read_text()
        injected = '    Command::new("podman");\n'
        for mutation in (
            lifecycle.replace("        match value {\n", injected + "        match value {\n", 1),
            lifecycle.replace(pure_control, pure_control + injected, 1),
            lifecycle.replace(pure_control, pure_control.replace(pure_podman, injected + pure_podman), 1),
            lifecycle + '\n["sudo", "-n", "podman"];\n',
            lifecycle.replace("            _ => None,\n", "            _ => Some(Self::Podman),\n", 1),
            lifecycle + selector,
        ):
            with self.subTest(mutation="closed selector boundary"), self.assertRaises(AssertionError):
                checked_source(mutation, "native_lifecycle_tests.rs")
        for path in [*ROOT.glob("src/*.rs"), *ROOT.glob("tests/*.rs")]:
            if path.name == "native_outer_test_command.rs":
                continue
            self.assertNotIn('Command::new("podman")', path.read_text())
            self.assertNotIn('["sudo", "-n", "podman"]', path.read_text())
        coordinator = (ROOT / "scripts/native-conformance.sh").read_text()
        self.assertIn('NATIVE_OUTER_ENGINE="$native_outer_engine"', coordinator)
        self.assertIn('NATIVE_OUTER_RUN_DIRECTORY="$run_dir"', coordinator)
        self.assertIn("#[cfg(test)]\nmod native_outer_test_command;", (ROOT / "src/lib.rs").read_text())
        for name in ("native_bind_relabel_tests", "native_network_attachment_tests", "native_external_network_tests"):
            source = (ROOT / "src" / (name + ".rs")).read_text()
            self.assertIn("snapshot_extra_calls()", source)
            self.assertIn("extra * 65536", source)
        self.assertIn("charge_outer_snapshot", (ROOT / "src/native_health_metadata_tests.rs").read_text())
        self.assertIn("charge_outer_snapshot(false)", (ROOT / "src/native_lifecycle_tests.rs").read_text())
        self.assertIn("charge_outer_snapshot(cleanup)", (ROOT / "src/native_stop_signal_tests.rs").read_text())

    def test_created_cid_survives_failed_run_without_hiding_original_status(self):
        args = ["owned", "run", "io.boxferry.docker-core-run", "bridge", "owned-data",
                str(self.directory / "socket"), "/boxferry-core", "upstream-rootful", PIN,
                str(self.directory / "daemon.log")]
        cidfile = self.directory / "outer-create.cid"
        for status in (0, 42, 124, 137, 130, 143):
            result = self.invoke("create-daemon", *args, changes={"MOCK_RUN_STATUS": str(status)})
            self.assertEqual((result.returncode, result.stdout), (status, (ID + "\n").encode()), result.stderr)
            cidfile.unlink()
        for changes in ({"MOCK_NO_CID": "1"}, {"MOCK_CID": "bad"}):
            for status in (0, 124, 143):
                result = self.invoke("create-daemon", *args, changes=changes | {"MOCK_RUN_STATUS": str(status)})
                self.assertEqual(result.returncode, status or 2)
                self.assertEqual(result.stdout, b"")
                if cidfile.exists():
                    cidfile.unlink()
        cidfile.write_text(ID)
        count = len(self.calls())
        self.assertEqual(self.invoke("create-daemon", *args).returncode, 2)
        self.assertEqual(len(self.calls()), count)

    def test_cid_file_refuses_symlink_links_wrong_mode_size_and_private_parent(self):
        path = self.directory / "outer-create.cid"
        for raw in (ID, ID + "\n"):
            path.write_text(raw)
            path.chmod(0o600)
            self.assertEqual(OBS.created_cid(str(path)), ID)
            path.unlink()
        for raw in ("bad", ID + "\n\n", "g" * 64):
            path.write_text(raw)
            with self.assertRaises(OBS.Refused):
                OBS.created_cid(str(path))
            path.unlink()
        path.symlink_to(self.trace)
        with self.assertRaises(OSError):
            OBS.created_cid(str(path))
        path.unlink()
        path.write_text(ID)
        path.chmod(0o666)
        with self.assertRaises(OBS.Refused):
            OBS.created_cid(str(path))
        path.chmod(0o600)
        link = self.directory / "other-link"
        os.link(path, link)
        with self.assertRaises(OBS.Refused):
            OBS.created_cid(str(path))
        link.unlink()
        self.directory.chmod(0o755)
        with self.assertRaises(OBS.Refused):
            OBS.created_cid(str(path))
        self.directory.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
