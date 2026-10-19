"""Authored Podman-shaped inputs only; no runtime or host observation."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import fcntl
import os
from pathlib import Path
import secrets
import subprocess
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from native_outer_bootstrap import build_bootstrap_argv
from native_outer_lifecycle import LifecycleError
from native_outer_launch import derive_launch
from native_outer_runtime import BoundImageObservation, config_semantic_sha256, config_semantics, normalize_image, normalize_inspect, zero_time
import native_outer_runtime as runtime_module
from native_outer_runtime import BoundedNativeProcess, FixedPodmanRuntime, NativeExecutable, normalize_profile
from native_outer_coordinator import Allowance, CoordinationError, Reservation, ReservedBudget
import test_native_outer_launch


class RuntimeNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.launch = derive_launch(*test_native_outer_launch.LaunchTests().inputs())
        self.identifier = "9" * 64
        self.image = BoundImageObservation(self.launch.image_ref, self.launch.image_digest, "sha256:" + "7" * 64,
                                          "sha256:" + "6" * 64, "amd64", "", "6" * 64,
                                          "sha256:" + "7" * 64, "selected_platform", "sha256:" + "5" * 64,
                                          ("sha256:" + "4" * 64,), b"{}")
        self.log = "/private/run/diagnostics/daemon.log"
        argv = build_bootstrap_argv(self.launch.nonce, list(self.launch.original_argv))
        self.observation = {
            "Id": self.identifier, "Name": self.launch.name, "ImageDigest": self.image.native_digest,
            "Image": self.image.native_id,
            "OCIRuntime": "crun", "Path": argv[0], "Args": argv[1:], "RestartCount": 0,
            "OCIConfigPath": "/owned/runtime/config.json",
            "Config": {"Labels": {"io.dockerlens.native-run": self.launch.owner},
                       "Entrypoint": "/bin/sh", "Env": list(reversed(self.launch.environment)),
                       "WorkingDir": "/", "Tty": False},
            "HostConfig": {"Privileged": True, "Memory": 4294967296, "CpuPeriod": 100000,
                           "CpuQuota": 200000, "PidsLimit": 512,
                           "LogConfig": {"Type": "k8s-file", "Path": self.log, "Size": "0B"},
                           "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
            "State": {"Status": "initialized", "Running": False, "Paused": False, "Restarting": False,
                      "OOMKilled": False, "Dead": False, "Error": "", "ExitCode": 0, "Pid": 2345,
                      "StartedAt": "0001-01-01T00:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z"}}

    def parse(self, value=None):
        return normalize_inspect(json.dumps([self.observation if value is None else value]).encode(),
                                 self.launch, self.identifier, self.log, self.image)

    def test_initialized_is_not_storage_created_and_omitted_false_is_supported(self):
        snapshot = self.parse()
        self.assertEqual((snapshot.state, snapshot.started_at, snapshot.pid), ("created", None, 2345))
        self.observation["State"]["Status"] = "created"
        with self.assertRaises(LifecycleError):
            self.parse()

    def test_running_retains_all_nine_timestamp_digits(self):
        self.observation["State"].update(Status="running", Running=True, StartedAt="2026-10-19T12:00:00.000000001Z")
        self.assertEqual(self.parse().started_at, "2026-10-19T12:00:00.000000001Z")
        for started in ("0001-01-01T00:00:00Z", "", None):
            self.observation["State"]["StartedAt"] = started
            with self.assertRaises(LifecycleError):
                self.parse()

    def test_zero_instant_not_shape_or_microsecond_truncation(self):
        self.assertTrue(zero_time("0001-01-01T01:00:00+01:00"))
        self.assertFalse(zero_time("0001-01-01T00:00:00.000000001Z"))
        for value in (None, "", "0001-01-01T00:00:00", "0001-01-01T00:00:00.Z"):
            with self.assertRaises(LifecycleError):
                zero_time(value)

    def test_identity_and_restart_drift_refuse(self):
        edits = [("Id", "8" * 64), ("Name", "other"), ("ImageDigest", "sha256:" + "0" * 64),
                 ("OCIRuntime", "other"), ("Path", "/bin/other"), ("RestartCount", True)]
        for key, changed in edits:
            value = deepcopy(self.observation)
            value[key] = changed
            with self.assertRaises(LifecycleError):
                self.parse(value)
        for key, changed in (("Restored", True), ("Checkpointed", True), ("Pid", 0),
                             ("Running", True), ("Restarting", True), ("ExitCode", False)):
            value = deepcopy(self.observation)
            value["State"][key] = changed
            with self.assertRaises(LifecycleError):
                self.parse(value)

    def test_index_and_selected_native_digest_are_not_blind_aliases(self):
        self.assertEqual(self.parse().image_digest, self.launch.image_digest)
        self.observation["ImageDigest"] = self.launch.image_digest
        with self.assertRaises(LifecycleError):
            self.parse()
        self.image = replace(self.image, native_digest=self.launch.image_digest, native_digest_kind="index")
        self.assertEqual(self.parse().image_digest, self.launch.image_digest)
        self.observation["Image"] = "0" * 64
        with self.assertRaises(LifecycleError):
            self.parse()


class PrivateNativeProcessTests(unittest.TestCase):
    def budget(self, byte_limit=1024):
        deadline = time.monotonic_ns() + 5_000_000_000
        return ReservedBudget(Reservation(secrets.token_hex(32), 1, "runtime", "test", Allowance(1, byte_limit, 1000), deadline),
                              time.monotonic_ns, lambda: False)

    def run_child(self, code, budget=None, **limits):
        budget = self.budget() if budget is None else budget
        result = BoundedNativeProcess(budget).run((sys.executable, "-c", code), time.monotonic() + 4,
                                                 {"PATH": "/usr/bin:/bin"}, seconds=2, **limits)
        return result, budget

    def test_actual_child_gets_devnull_stdin_and_no_control_descriptors(self):
        read, write = os.pipe()
        inherited = fcntl.fcntl(read, fcntl.F_DUPFD, 100)
        os.set_inheritable(inherited, True)
        try:
            code = ("import os,sys; assert sys.stdin.buffer.read()==b''; "
                    "\ntry: os.fstat(" + str(inherited) + ")"
                    "\nexcept OSError: sys.stdout.buffer.write(b'closed')"
                    "\nelse: raise SystemExit(9)")
            result, budget = self.run_child(code)
            self.assertEqual(result, (b"closed", 0))
            self.assertEqual(budget.used.native_calls, 1)
            self.assertEqual(budget.used.source_bytes, 6)
        finally:
            for descriptor in (read, write, inherited):
                os.close(descriptor)

    def test_fragmented_output_and_overflow_lookahead_are_charged(self):
        result, budget = self.run_child("import os,time; os.write(1,b'abc'); time.sleep(.02); os.write(1,b'def')", stdout_limit=6)
        self.assertEqual(result, (b"abcdef", 0))
        self.assertEqual(budget.used.source_bytes, 6)
        budget = self.budget()
        with self.assertRaises(LifecycleError):
            self.run_child("import os;\nwhile True: os.write(1,b'x'*4096)", budget, stdout_limit=16)
        self.assertEqual(budget.used.source_bytes, 17)

    def test_stderr_warning_nonzero_and_deadline_fail_closed(self):
        for code in ("import os;os.write(2,b'private warning')", "raise SystemExit(3)"):
            with self.assertRaises(LifecycleError):
                self.run_child(code)
        with self.assertRaises(LifecycleError):
            BoundedNativeProcess(self.budget()).run((sys.executable, "-c", "pass"), time.monotonic() + .5,
                                                    {"PATH": "/usr/bin:/bin"})

    def traced_child(self, code, byte_limit):
        budget = self.budget(byte_limit)
        descriptors, reads = set(), []
        original_read = os.read
        def spawn(*arguments, **keywords):
            process = subprocess.Popen(*arguments, **keywords)
            descriptors.update((process.stdout.fileno(), process.stderr.fileno()))
            return process
        def read(descriptor, maximum):
            raw = original_read(descriptor, maximum)
            if descriptor in descriptors:
                reads.append((maximum, len(raw)))
            return raw
        with patch.object(runtime_module.os, "read", read):
            try:
                result = BoundedNativeProcess(budget, spawn=spawn).run(
                    (sys.executable, "-c", code), time.monotonic() + 4, {"PATH": "/usr/bin:/bin"}, seconds=2)
            except LifecycleError:
                result = None
        self.assertEqual(sum(size for _maximum, size in reads), budget.used.source_bytes)
        self.assertLessEqual(budget.used.source_bytes, byte_limit)
        self.assertTrue(all(size <= maximum <= byte_limit for maximum, size in reads))
        self.assertFalse(budget._source_claims)
        return result, budget, reads

    def test_aggregate_zero_one_exact_and_dual_stream_overflow_are_prebounded(self):
        for remaining in (0, 1, 8):
            with self.subTest(remaining=remaining):
                result, budget, reads = self.traced_child(
                    "import os;os.write(1,b'x'*32);os.write(2,b'y'*32)", remaining)
                self.assertIsNone(result)
                self.assertEqual(budget.used.source_bytes, remaining)
                self.assertEqual(bool(reads), remaining != 0)

    def test_unused_eof_claim_does_not_block_below_cap_output_or_erase_failed_output(self):
        result, budget, _reads = self.traced_child("import os;os.write(1,b'abcdef')", 7)
        self.assertEqual(result, (b"abcdef", 0))
        self.assertEqual(budget.used.source_bytes, 6)
        result, budget, _reads = self.traced_child(
            "import os;os.write(1,b'abc');os.write(2,b'warn');raise SystemExit(3)", 64)
        self.assertIsNone(result)
        self.assertEqual(budget.used.source_bytes, 7)


class FixedRuntimeVocabularyTests(unittest.TestCase):
    def runtime(self, responses):
        intent, image, account, defaults = test_native_outer_launch.LaunchTests().inputs()
        account = replace(account, canonical_reference=intent.image_ref)
        calls = []
        class Executable:
            def __init__(self, path):
                self.chain = SimpleNamespace(path=path)
            def recheck(self):
                pass
            def recovery_recheck(self, _budget, _deadline):
                pass
            def close(self):
                pass
        class Process:
            budget = SimpleNamespace()
            def run(self, argv, deadline, environment, **options):
                calls.append((argv, deadline, environment, options))
                return responses.pop(0)
        config = SimpleNamespace(recheck=lambda: None, recovery_recheck=lambda _budget, _deadline: None, close=lambda: None)
        runtime = FixedPodmanRuntime(intent, account, Process(), Process(),
                                     {"PATH": "/usr/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C",
                                      "CONTAINERS_CONF": "/owned/runtime.conf"},
                                     "/owned/runtime.conf", "/owned/mounts.conf", "/owned/hooks",
                                     [Executable(path) for path in ("/usr/bin/podman", "/usr/bin/crun", "/usr/bin/timeout")], config)
        runtime.image = BoundImageObservation(intent.image_ref, account.image_digest, account.platform_digest,
                                              account.config_digest, "amd64", "", account.config_digest[7:],
                                              account.platform_digest, "selected_platform", "sha256:" + "a" * 64, (), b"{}")
        runtime.profile = SimpleNamespace()
        return runtime, derive_launch(intent, image, account, defaults), calls

    def test_create_uses_fixed_recipe_and_two_original_mounts(self):
        runtime, expected, calls = self.runtime([(b"9" * 64 + b"\n", 0)])
        self.assertEqual(runtime.create(expected, "/private/run/diagnostics/daemon.log", 123), "9" * 64)
        argv, deadline, environment, _options = calls[0]
        self.assertEqual(deadline, 123)
        self.assertEqual(argv[:2], ("/usr/bin/podman", "--remote=false"))
        self.assertEqual(len([item for item in argv if item.startswith("--volume=")]), 2)
        for flag in ("--memory-swap=8g", "--transient-store=false", "--unsetenv-all", "--env-host=false", "--http-proxy=false",
                     "--passwd-entry=", "--group-entry=", "--image-volume=ignore", "--userns=host"):
            self.assertIn(flag, argv)
        self.assertEqual(set(environment), {"PATH", "HOME", "LANG", "LC_ALL", "CONTAINERS_CONF"})
        with self.assertRaises(LifecycleError):
            runtime.create(expected, "/private/run/diagnostics/daemon.log", 124)

    def test_malformed_create_never_recovers_an_id_from_a_name(self):
        runtime, expected, calls = self.runtime([(b"not-an-id\n", 0)])
        with self.assertRaises(LifecycleError):
            runtime.create(expected, "/private/run/diagnostics/daemon.log", 123)
        self.assertTrue(runtime.create_attempted)
        self.assertIsNone(runtime.container_id)
        self.assertEqual(len(calls), 1)


class ExecutableCustodyTests(unittest.TestCase):
    def budget(self):
        return ReservedBudget(Reservation(secrets.token_hex(32), 1, "executable", "test", Allowance(0, 0, 2000),
                                         time.monotonic_ns() + 5_000_000_000), time.monotonic_ns, lambda: False)

    def exercise(self, mutation=None, *, mode=0o755, link=False):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            path = parent / "fixed-runtime"
            path.write_bytes(b"authored executable fixture")
            path.chmod(mode)
            if link:
                os.link(path, parent / "second-link")
            real_fstat, real_stat = os.fstat, os.stat
            registered = {(info.st_dev, info.st_ino) for info in (real_stat(parent), real_stat(path))}
            def project(info):
                if (info.st_dev, info.st_ino) not in registered:
                    return info
                values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                values["st_uid"] = 0
                return SimpleNamespace(**values)
            class TemporaryChain:
                # Real _Chain ancestor-custody controls live in the lifecycle
                # suite. This scope projects UID0 ONLY for registered fixtures.
                def __init__(self, owner, value):
                    self.owner, self.path, self.leaf = owner, value, Path(value).name
                    self.parent = owner._open(str(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    self.original = real_fstat(self.parent)
                    self.entries = [(None, self.parent, ())]
                def recheck(self):
                    held, named = real_fstat(self.parent), real_stat(parent, follow_symlinks=False)
                    runtime_module.require((held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
                                           == (self.original.st_dev, self.original.st_ino))
            with patch.object(runtime_module, "_Chain", TemporaryChain), \
                    patch.object(os, "fstat", side_effect=lambda fd: project(real_fstat(fd))), \
                    patch.object(os, "stat", side_effect=lambda *a, **k: project(real_stat(*a, **k))):
                owner = NativeExecutable(str(path), self.budget(), time.monotonic() + 4, time.monotonic, lambda: False)
                try:
                    owner.recheck()
                    if mutation:
                        mutation(path)
                        with self.assertRaises(LifecycleError):
                            owner.recheck()
                    held = owner.fd
                finally:
                    owner.close()
                with self.assertRaises(OSError):
                    real_fstat(held)

    def test_original_leaf_metadata_and_close(self):
        self.exercise()

    def test_replacement_content_mode_and_hardlink_refuse(self):
        def replace_leaf(path):
            path.rename(path.with_name("old-runtime"))
            path.write_bytes(b"authored executable fixture")
            path.chmod(0o755)
        self.exercise(replace_leaf)
        self.exercise(lambda path: path.write_bytes(b"changed"))
        self.exercise(lambda path: path.chmod(0o777))
        for arguments in ({"mode": 0o777}, {"mode": 0o644}, {"link": True}):
            with self.assertRaises(LifecycleError):
                self.exercise(**arguments)


class RuntimeProfileTests(unittest.TestCase):
    def test_exact_profile_and_no_remote_rootless_version_aliases(self):
        value = {"host": {"os": "linux", "security": {"rootless": False}, "serviceIsRemote": False,
                          "ociRuntime": {"name": "crun", "path": "/usr/bin/crun", "version": "crun version 1.14.1\ncommit: source"},
                          "cgroupManager": "systemd", "cgroupVersion": "v2"}, "version": {"Version": "4.9.3"}}
        self.assertEqual(normalize_profile(json.dumps(value).encode()).podman_version, "4.9.3")
        for route, changed in ((["host", "security", "rootless"], True), (["host", "serviceIsRemote"], True),
                               (["host", "ociRuntime", "path"], "/other/crun"), (["version", "Version"], "4.9.4"),
                               (["host", "cgroupVersion"], "v1")):
            edited, selected = deepcopy(value), None
            selected = edited
            for key in route[:-1]:
                selected = selected[key]
            selected[route[-1]] = changed
            with self.assertRaises(LifecycleError):
                normalize_profile(json.dumps(edited).encode())


class ImageSemanticTests(unittest.TestCase):
    def inputs(self):
        intent, image, account, _ = test_native_outer_launch.LaunchTests().inputs()
        config = {"User": "docker", "Env": ["PATH=/image/bin", "VALUE=image"], "WorkingDir": "/"}
        account = replace(account, canonical_reference="example.invalid/image:1@" + account.image_digest,
                          config_semantic_sha256=config_semantic_sha256(config),
                          ordered_layer_diff_ids=("sha256:" + "8" * 64,))
        native = {"Id": account.config_digest[7:], "Digest": account.platform_digest,
                  "RepoDigests": ["example.invalid/image@" + account.image_digest],
                  "Architecture": "amd64", "Os": "linux", "User": "docker", "Config": config,
                  "RootFS": {"Type": "layers", "Layers": list(account.ordered_layer_diff_ids)}}
        return account, native

    def parse(self, account, native):
        return normalize_image(json.dumps([native]).encode(), account)

    def test_independent_typed_projection_includes_every_exposed_field(self):
        expected = {"config": {"User": "", "ExposedPorts": {}, "Env": [], "Entrypoint": [], "Cmd": [],
                               "Volumes": {}, "WorkingDir": "", "Labels": {}, "StopSignal": "", "ArgsEscaped": False},
                    "healthcheck": None}
        self.assertEqual(config_semantics({}), expected)
        expected_hash = "sha256:" + hashlib.sha256(json.dumps(expected, sort_keys=True, ensure_ascii=True,
                                                              separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(config_semantic_sha256({}), expected_hash)
        for source in ({}, {"Env": None}, {"Env": []}, {"User": ""}, {"Volumes": {}}):
            self.assertEqual(config_semantic_sha256(source, audited_raw=True), expected_hash)
        for key, invalid in (("User", None), ("Env", []), ("Volumes", {}), ("ArgsEscaped", False),
                             ("Env", "wrong"), ("Labels", {"key": None}), ("NewUnknown", "value")):
            with self.assertRaises(LifecycleError):
                config_semantics({key: invalid})
        first = {"Env": ["A=1", "A=2"]}
        self.assertEqual(config_semantics(first)["config"]["Env"], ["A=1", "A=2"])
        self.assertNotEqual(config_semantic_sha256(first), config_semantic_sha256({"Env": ["A=2", "A=1"]}))

    def test_index_and_platform_are_distinct_composite_binding_forms_not_aliases(self):
        account, native = self.inputs()
        observed = self.parse(account, native)
        self.assertEqual((observed.native_digest, observed.native_digest_kind), (account.platform_digest, "selected_platform"))
        self.assertEqual(observed.launch_image()["config"]["Env"], ["PATH=/image/bin", "VALUE=image"])
        native["Digest"] = account.image_digest
        self.assertEqual(self.parse(account, native).native_digest_kind, "index")

    def test_every_composite_identity_and_configuration_predicate_is_required(self):
        account, original = self.inputs()
        edits = [("Id", "0" * 64), ("Digest", "sha256:" + "0" * 64), ("Digest", None),
                 ("Architecture", "arm64"), ("Os", "windows"), ("RepoDigests", []),
                 ("RepoDigests", ["other.invalid/image@" + account.image_digest]),
                 ("Healthcheck", None), ("Config", {"User": "docker", "Env": ["PATH=/other"], "WorkingDir": "/"}),
                 ("RootFS", {"Type": "layers", "Layers": ["sha256:" + "0" * 64]})]
        for key, changed in edits:
            native = deepcopy(original)
            native[key] = changed
            with self.assertRaises(LifecycleError):
                self.parse(account, native)


if __name__ == "__main__":
    unittest.main()
