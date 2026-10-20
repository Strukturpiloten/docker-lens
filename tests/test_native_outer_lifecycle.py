"""Synthetic representatives, NOT actual pinned-image defaults or native evidence.

Only temporary-file IO and FakeRuntimeOps are used. UID0 is projected narrowly
for explicitly registered synthetic OCI inodes; no chown or privilege bypass.
"""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError, replace
import io
import json
import os
import secrets
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from native_outer_bootstrap import BOOTSTRAP
import native_outer_lifecycle as lifecycle
from native_outer_lifecycle import (CandidateContext, CleanupIdentity, InspectSnapshot, LaunchExpectation,
                                    CallerLogCustody, LifecycleCustody, LifecycleError, MountExpectation,
                                    RootOCICustody, RuntimeProfile, State)
from native_outer_coordinator import Allowance, ReservationBook, ReservedBudget

ID = "a" * 64
DIGEST = "sha256:" + "b" * 64
NONCE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CANARY = "PRIVATE_LIFECYCLE_CANARY_/host/private"
STARTED = "2026-10-19T12:34:56.123456789Z"
PROFILE = RuntimeProfile("linux", False, False, "4.9.3", "crun", "1.14.1", "systemd", "v2")


def literal_frame(uid=0):
    # Literal facts, independent of the coordinator and its receipt dataclasses.
    return (b'2026-10-19T12:34:56Z stdout F DOCKERLENS_OUTER_BOOTSTRAP_V1 '
            b'{"contract":"outer-bootstrap-v1",'
            b'"nonce":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",'
            b'"pid":1,"proc_pid":1,"nspid":[1],"start":123456,"uid":' + str(uid).encode() +
            b',"namespaces":[4026533001,4026533002,4026533003],"membership":"0::/",'
            b'"mount":[101,99,"0:28","/","/sys/fs/cgroup"],"controller":[28,2,512,4294967296]}\n')


def expected_launch(lane):
    rootless = lane.endswith("rootless")
    argv = ("/usr/local/bin/start-dockerd", "--host=unix:///dockerlens-native/docker.sock")
    if lane == "debian11-rootless":
        argv += ("--storage-driver=vfs",)
    # These are authored synthetic representatives, not queried image defaults.
    standard = (MountExpectation("/proc", "proc", "proc", ("nosuid", "noexec", "nodev")),
                MountExpectation("/sys/fs/cgroup", "cgroup", "cgroup", ("ro", "nosuid", "noexec", "nodev")))
    storage = "/home/docker/.local/share/docker" if rootless else "/var/lib/docker"
    user = (MountExpectation(storage, "bind", "/synthetic/owned-volume/data", ("rbind", "rw")),
            MountExpectation("/dockerlens-native", "bind", "/synthetic/owned-socket", ("rbind", "rw")))
    return LaunchExpectation(lane, "synthetic-outer", "example.invalid/outer@" + DIGEST, DIGEST,
                             "synthetic-owned-run", NONCE, argv,
                             ("PATH=/usr/bin:/bin", "HOME=" + ("/home/docker" if rootless else "/root")),
                             1000 if rootless else 0, 1000 if rootless else 0, (),
                             "/home/docker" if rootless else "/", standard, user)


def oci_fixture(expectation):
    # Explicit slot/key ordering, without asking the validator for an expected spec.
    return {"ociVersion": "1.0.2", "process": {
        "terminal": False,
        "args": ["/bin/sh", "-c", BOOTSTRAP, "dl-outer-bootstrap", NONCE, *expectation.original_argv],
        "env": list(expectation.environment), "cwd": expectation.cwd,
        "user": {"uid": expectation.uid, "gid": expectation.gid, "additionalGids": []}},
        "linux": {"cgroupsPath": "machine.slice:libpod:" + ID,
                  "namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "cgroup"}, {"type": "uts"}],
                  "resources": {"pids": {"limit": 512}, "memory": {"limit": 4294967296},
                                "cpu": {"period": 100000, "quota": 200000}}},
        "annotations": {"run.oci.systemd.subgroup": "container", "run.oci.delegate-cgroup": "",
                        "io.kubernetes.cri.container-type": "sandbox"},
        "mounts": [{"destination": mount.destination, "type": mount.kind, "source": mount.source,
                    "options": list(mount.options)} for mount in expectation.standard_mounts + expectation.user_mounts]}


class FakeRuntimeOps:
    def __init__(self, fixture):
        self.fixture = fixture
        self.calls = []
        self.hooks = {}
        self.running = False
        self.snapshot_override = {}
        self.create_result = ID
        self.log_bytes = literal_frame(fixture.expectation.uid)

    def _hit(self, name, identity, deadline):
        self.calls.append((name, identity, deadline))
        if name in self.hooks:
            self.hooks[name](self)

    def create(self, expectation, log_path, deadline):
        assert expectation is self.fixture.expectation and log_path == str(self.fixture.log)
        self._hit("create", None, deadline)
        return self.create_result

    def initialize(self, container_id, deadline):
        self._hit("initialize", container_id, deadline)

    def inspect(self, container_id, deadline):
        self._hit("inspect", container_id, deadline)
        expected = self.fixture.expectation
        snapshot = InspectSnapshot(ID, expected.name, DIGEST, expected.owner, "k8s-file", str(self.fixture.log),
                                   str(self.fixture.oci), "running" if self.running else "created", 12345,
                                   STARTED if self.running else None, 0, False, False, "no")
        return replace(snapshot, **self.snapshot_override)

    def start(self, container_id, deadline):
        self._hit("start", container_id, deadline)
        self.running = True
        self.fixture.log.write_bytes(self.log_bytes)

    def cleanup(self, identity, deadline):
        expected = self.fixture.expectation
        assert identity == CleanupIdentity(ID, expected.name, DIGEST, expected.owner)
        self._hit("cleanup", identity, deadline)


class Fixture:
    def __init__(self, root, lane="debian11-rootful", raw=None, mode=0o640):
        self.expectation = expected_launch(lane)
        self.run = root / "run"
        self.run.mkdir(mode=0o700)
        self.diagnostics = self.run / "diagnostics"
        self.diagnostics.mkdir(mode=0o700)
        self.log = self.diagnostics / "outer.log"
        self.bundle = root / "bundle"
        self.bundle.mkdir(mode=0o700)
        self.oci = self.bundle / "config.json"
        self.root_inodes = set()
        self.write_oci(json.dumps(oci_fixture(self.expectation), separators=(",", ":")).encode() if raw is None else raw, mode)
        self.now = 0.0
        self.cancelled = False
        self.projected_uid = 0
        self.ops = FakeRuntimeOps(self)

    def write_oci(self, raw, mode=0o640):
        fd = os.open(self.oci, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            os.write(fd, raw)
        finally:
            os.close(fd)
        info = self.oci.stat()
        self.root_inodes.add((info.st_dev, info.st_ino))

    def project(self, info):
        if (info.st_dev, info.st_ino) not in self.root_inodes:
            return info
        values = {name: getattr(info, name) for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
        return SimpleNamespace(**values, st_uid=self.projected_uid)

    @contextmanager
    def ownership(self):
        real_stat, real_fstat = os.stat, os.fstat
        with patch.object(lifecycle.os, "stat", side_effect=lambda *args, **kwargs: self.project(real_stat(*args, **kwargs))), \
             patch.object(lifecycle.os, "fstat", side_effect=lambda *args, **kwargs: self.project(real_fstat(*args, **kwargs))):
            yield

    def owner(self, **kwargs):
        return LifecycleCustody(self.expectation, PROFILE, self.ops, str(self.log),
                                kwargs.pop("startup_deadline", 100.0), kwargs.pop("custody_deadline", 300.0),
                                kwargs.pop("cleanup_deadline", 400.0), lambda: self.now, lambda: self.cancelled, **kwargs)


class OuterLifecycleTests(unittest.TestCase):
    def assert_closed(self, operation, owner=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        held = list(owner._fds) if owner is not None else []
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(LifecycleError) as caught:
                operation()
        self.assertEqual(str(caught.exception), "outer lifecycle custody refused")
        self.assertEqual(repr(caught.exception), "LifecycleError('outer lifecycle custody refused')")
        self.assertNotIn(CANARY, repr(caught.exception))
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        if owner is not None:
            self.assertEqual(owner.state, State.POISONED)
            self.assertEqual(owner._fds, [])
            for descriptor in held:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def through(self, owner, state=State.FINALIZED):
        for method, result in ((owner.create, State.CREATED), (owner.initialize, State.INITIALIZED),
                               (owner.arm, State.ARMED), (owner.start, State.STARTED),
                               (owner.capture_frame, State.FRAMED), (owner.final_recheck, State.FINALIZED)):
            if owner.state == state:
                break
            method()
            self.assertEqual(owner.state, result)

    def test_four_literal_launch_representatives_private_immutable_context_and_live_fds(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary), lane)
                with fixture.ownership(), fixture.owner() as owner:
                    self.through(owner)
                    candidate = owner.candidate_context()
                    self.assertIs(type(candidate), CandidateContext)
                    self.assertEqual(candidate.identity, CleanupIdentity(ID, "synthetic-outer", DIGEST, "synthetic-owned-run"))
                    self.assertEqual((candidate.init_pid, candidate.started_at), (12345, STARTED))
                    self.assertEqual((candidate.frame.start, candidate.frame.namespaces), (123456, (4026533001, 4026533002, 4026533003)))
                    self.assertEqual(candidate.frame.controller, (28, 2, 512, 4294967296))
                    self.assertEqual(candidate.frame_prefix, literal_frame(fixture.expectation.uid))
                    self.assertEqual(candidate.oci_raw, fixture.oci.read_bytes())
                    self.assertEqual(candidate.oci.uid, 0)
                    self.assertEqual(len(candidate.oci_sha256), 64)
                    self.assertNotIn("synthetic", repr(candidate))
                    self.assertNotIn(str(fixture.oci), repr(candidate))
                    with self.assertRaises(FrozenInstanceError):
                        candidate.init_pid = 5
                    for descriptor in owner._fds:
                        os.fstat(descriptor)
                    self.assertTrue(all(call[1] == ID for call in fixture.ops.calls if call[0] not in ("create", "cleanup")))
                    self.assertTrue(all(call[2] == 100.0 for call in fixture.ops.calls[:6]))
                    self.assertLessEqual(owner.runtime_calls, 16)
                    self.assertGreater(owner.source_bytes, len(candidate.oci_raw))
                self.assertEqual(fixture.ops.calls[-1][0], "cleanup")
                self.assertEqual(fixture.ops.calls[-1][2], 400.0)

    def test_unknown_profile_and_nonfinite_or_reset_deadlines_refuse_before_ops(self):
        changes = {"operating_system": "freebsd", "rootless": True, "remote": True, "podman_version": "4.9.4",
                   "runtime_name": "runc", "runtime_version": "1.14.2", "cgroup_manager": "cgroupfs", "cgroup_version": "v1"}
        for key, value in list(changes.items()) + [("rootless", 0), ("remote", None)]:
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                self.assert_closed(lambda: LifecycleCustody(fixture.expectation, replace(PROFILE, **{key: value}), fixture.ops,
                                                           str(fixture.log), 100, 300, 400, lambda: 0, lambda: False))
                self.assertEqual(fixture.ops.calls, [])
        for startup, custody, cleanup, now in ((121, 300, 400, 0), (0, 300, 400, 0), (100, 99, 400, 0),
                                                (100, 300, 300, 0), (100, 300, 1801, 0), (100, 1801, 1900, 0),
                                                (float("nan"), 300, 400, 0),
                                                (100, float("inf"), 400, 0), (100, 300, 400, float("nan"))):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                self.assert_closed(lambda: LifecycleCustody(fixture.expectation, PROFILE, fixture.ops, str(fixture.log),
                                                           startup, custody, cleanup, lambda: now, lambda: False))

    def test_wrong_identity_state_restore_restart_and_zero_count_restart_refuse(self):
        changes = {"container_id": "c" * 64, "name": CANARY, "image_digest": "sha256:" + "d" * 64,
                   "owner": CANARY, "log_driver": "journald", "log_path": "/" + CANARY,
                   "pid": 0, "started_at": STARTED, "restart_count": 1, "restarting": True,
                   "restored": True, "restart_policy": "always", "state": "running"}
        for key, replacement in changes.items():
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                fixture.ops.snapshot_override[key] = replacement
                with fixture.ownership():
                    owner = fixture.owner()
                    owner.create()
                    self.assert_closed(owner.initialize, owner)
                    self.assertEqual(fixture.ops.calls[-1][0], "cleanup")
        for change in ({"pid": 12346}, {"started_at": "2026-10-19T12:34:57Z"},
                       {"oci_config_path": "/" + CANARY}, {"state": "created"}):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                with fixture.ownership():
                    owner = fixture.owner()
                    self.through(owner, State.FRAMED)
                    fixture.ops.snapshot_override.update(change)
                    self.assert_closed(owner.final_recheck, owner)

    def test_every_phase_cancel_poisons_once_and_never_emits_context(self):
        states = (State.NEW, State.CREATED, State.INITIALIZED, State.ARMED, State.STARTED, State.FRAMED, State.FINALIZED)
        next_methods = ("create", "initialize", "arm", "start", "capture_frame", "final_recheck", "candidate_context")
        for state, method in zip(states, next_methods):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                with fixture.ownership():
                    owner = fixture.owner()
                    self.through(owner, state)
                    before = len(fixture.ops.calls)
                    fixture.cancelled = True
                    self.assert_closed(getattr(owner, method), owner)
                    after = fixture.ops.calls[before:]
                    self.assertEqual([call[0] for call in after], [] if state is State.NEW else ["cleanup"])
                    self.assert_closed(owner.create, owner)
                    self.assertEqual(len(fixture.ops.calls), before + len(after))

    def test_mid_operation_cancel_unknown_create_and_cleanup_reserve(self):
        for operation in ("create", "initialize", "inspect", "start"):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                with fixture.ownership():
                    owner = fixture.owner()
                    if operation != "create":
                        owner.create()
                    if operation == "start":
                        owner.initialize()
                        owner.arm()
                    fixture.ops.hooks[operation] = lambda _ops: setattr(fixture, "cancelled", True)
                    target = owner.create if operation == "create" else (owner.start if operation == "start" else owner.initialize)
                    self.assert_closed(target, owner)
                    self.assertEqual(fixture.ops.calls[-1][0], "cleanup")
                    self.assertEqual(owner.cleanup_calls, 1)
        for unknown in ("exception", "invalid_id"):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                if unknown == "exception":
                    def fail(_ops):
                        raise RuntimeError(CANARY)
                    fixture.ops.hooks["create"] = fail
                else:
                    fixture.ops.create_result = CANARY
                with fixture.ownership():
                    owner = fixture.owner()
                    self.assert_closed(owner.create, owner)
                    self.assertEqual(owner.cleanup_obligation, "unknown_create")
                    self.assertEqual([call[0] for call in fixture.ops.calls], ["create"])
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            with fixture.ownership():
                owner = fixture.owner()
                owner.create()
                fixture.now = 101
                self.assert_closed(owner.initialize, owner)
                self.assertEqual(fixture.ops.calls[-1][0:1], ("cleanup",))
                self.assertEqual(fixture.ops.calls[-1][2], 400)

    def test_startup_clock_never_resets_custody_survives_then_expires(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            with fixture.ownership():
                owner = fixture.owner()
                self.through(owner, State.FRAMED)
                fixture.now = 150
                owner.final_recheck()
                self.assertEqual(fixture.ops.calls[-1][2], 300)
                fixture.now = 301
                self.assert_closed(owner.candidate_context, owner)
                self.assertEqual(fixture.ops.calls[-1][2], 400)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            fixture.ops.hooks["initialize"] = lambda _ops: setattr(fixture, "now", 100)
            with fixture.ownership():
                owner = fixture.owner()
                owner.create()
                self.assert_closed(owner.initialize, owner)
                self.assertEqual([call[2] for call in fixture.ops.calls], [100, 100, 400])

    def test_owned_file_birth_modes_links_uid_size_and_symlinks(self):
        for mutation in ("uid", "writable", "hardlink", "oversize", "empty", "symlink_leaf", "symlink_parent"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary), raw=b"X" * 65537 if mutation == "oversize" else (b"" if mutation == "empty" else None),
                                  mode=0o660 if mutation == "writable" else 0o640)
                if mutation == "uid":
                    fixture.projected_uid = 1234
                elif mutation == "writable":
                    fixture.oci.chmod(0o660)  # Defeat the test process umask, fixture only.
                elif mutation == "hardlink":
                    os.link(fixture.oci, fixture.bundle / "linked.json")
                elif mutation == "symlink_leaf":
                    moved = fixture.bundle / "actual.json"
                    fixture.oci.rename(moved)
                    fixture.oci.symlink_to(moved)
                elif mutation == "symlink_parent":
                    moved = Path(temporary) / "actual-bundle"
                    fixture.bundle.rename(moved)
                    fixture.bundle.symlink_to(moved, target_is_directory=True)
                with fixture.ownership():
                    owner = fixture.owner()
                    owner.create()
                    self.assert_closed(owner.initialize, owner)
        for mutation in ("existing_log", "directory_mode", "diagnostics_symlink"):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                if mutation == "existing_log":
                    fixture.log.write_bytes(b"")
                elif mutation == "directory_mode":
                    fixture.diagnostics.chmod(0o750)
                else:
                    moved = fixture.run / "actual-diagnostics"
                    fixture.diagnostics.rename(moved)
                    fixture.diagnostics.symlink_to(moved, target_is_directory=True)
                with fixture.ownership():
                    owner = fixture.owner()
                    self.assert_closed(owner.create, owner)
                    self.assertEqual(fixture.ops.calls, [])

    def test_samebytes_oci_replacement_mutation_parent_replacement_and_sibling_writes(self):
        for mutation in ("replacement", "content", "parent"):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                with fixture.ownership():
                    owner = fixture.owner()
                    self.through(owner, State.INITIALIZED)
                    original = fixture.oci.read_bytes()
                    if mutation == "replacement":
                        fixture.oci.rename(fixture.bundle / "old.json")
                        fixture.write_oci(original)
                    elif mutation == "content":
                        fixture.write_oci(original.replace(b'"ociVersion":"1.0.2"', b'"ociVersion":"1.0.3"'))
                    else:
                        fixture.bundle.rename(Path(temporary) / "old-bundle")
                        fixture.bundle.mkdir(mode=0o700)
                        fixture.write_oci(original)
                    self.assert_closed(owner.arm, owner)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            with fixture.ownership(), fixture.owner() as owner:
                self.through(owner, State.INITIALIZED)
                (fixture.bundle / "legitimate-runtime-sibling").write_bytes(b"new runtime data")
                owner.arm()
                self.assertEqual(owner.state, State.ARMED)

    def test_oci_exact_independent_launch_hooks_annotations_unified_namespaces_and_limits(self):
        mutations = []
        for hook in ("prestart", "createRuntime", "createContainer", "startContainer", "poststart", "poststop"):
            mutations.append(lambda value, hook=hook: value.update(hooks={hook: [{"path": "/" + CANARY}]}))
        for key, replacement in (("run.oci.systemd.subgroup", "other"), ("run.oci.delegate-cgroup", "child"),
                                 ("io.kubernetes.cri.container-type", "container"), ("io.kubernetes.cri.container-type", None)):
            mutations.append(lambda value, key=key, replacement=replacement: value["annotations"].update({key: replacement}))
        mutations.extend([
            lambda value: value["annotations"].pop("io.kubernetes.cri.container-type"),
            lambda value: value["linux"]["resources"].update(unified={"pids.max": "512"}),
            lambda value: value["linux"].update(cgroupsPath="machine.slice:libpod:" + "d" * 64),
            lambda value: value["linux"]["namespaces"][0].update(path="/synthetic/ns"),
            lambda value: value["linux"]["namespaces"].append({"type": "cgroup"}),
            lambda value: value["linux"]["namespaces"].pop(1),
            lambda value: value["linux"]["resources"]["pids"].update(limit=True),
            lambda value: value["linux"]["resources"]["memory"].update(limit=4294967295),
            lambda value: value["linux"]["resources"]["cpu"].update(quota=199999),
            lambda value: value["process"]["args"].append(CANARY),
            lambda value: value["process"]["env"].append("CANARY=" + CANARY),
            lambda value: value["process"].update(cwd="/" + CANARY),
            lambda value: value["process"]["user"].update(uid=True),
            lambda value: value["process"]["user"].update(gid=1000),
            lambda value: value["mounts"][-1].update(source="/" + CANARY),
            lambda value: value["mounts"][-1]["options"].append("ro"),
            lambda value: value["mounts"].append(dict(value["mounts"][0])),
        ])
        for mutation in mutations:
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                value = oci_fixture(fixture.expectation)
                mutation(value)
                fixture.write_oci(json.dumps(value).encode())
                with fixture.ownership():
                    owner = fixture.owner()
                    owner.create()
                    self.assert_closed(owner.initialize, owner)

    def test_independent_complete_resource_fields_accept_only_exact_typed_values(self):
        # Authored metadata, not a claim these are actual image/runtime defaults.
        extras = (("memory", (("swap", 8589934592), ("disableOOMKiller", False))),
                  ("cpu", (("cpus", "0-1"),)))
        for mutation in (None, "missing", "wrong_value", "wrong_type", "extra", "bool_as_int"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                fixture.expectation = replace(fixture.expectation, resource_extras=extras)
                value = oci_fixture(fixture.expectation)
                resources = value["linux"]["resources"]
                resources["memory"].update(swap=8589934592, disableOOMKiller=False)
                resources["cpu"]["cpus"] = "0-1"
                if mutation == "missing":
                    del resources["memory"]["swap"]
                elif mutation == "wrong_value":
                    resources["memory"]["swap"] = 8589934591
                elif mutation == "wrong_type":
                    resources["memory"]["swap"] = "8589934592"
                elif mutation == "extra":
                    resources["memory"]["reservation"] = 1024
                elif mutation == "bool_as_int":
                    resources["memory"]["disableOOMKiller"] = 0
                fixture.write_oci(json.dumps(value).encode())
                with fixture.ownership():
                    owner = fixture.owner()
                    if mutation is None:
                        with owner:
                            self.through(owner)
                            owner.candidate_context()
                    else:
                        owner.create()
                        self.assert_closed(owner.initialize, owner)

    def test_resource_expectations_refuse_collisions_duplicates_mutability_and_unbounded_scalars(self):
        invalid = (
            [], (("unified", ()),), (("memory", (("limit", 4294967296),)),),
            (("cpu", (("quota", 200000),)),), (("memory", ()), ("memory", ())),
            (("memory", (("swap", 1), ("swap", 2))),),
            (("memory", [("swap", 1)]),), (("memory", (("swap", []),)),),
            (("memory", (("swap", {}),)),), (("memory", (("swap", 1.0),)),),
            (("memory", (("swap", None),)),),
            (("memory", (("swap", -(1 << 63) - 1),)),),
            (("memory", (("swap", 1 << 64),)),),
            (("memory", (("swap", "x" * 4097),)),),
            (("memory", (("swap", "private\0value"),)),),
            (("memory", tuple(("field" + str(index), index) for index in range(33))),),
        )
        for extras in invalid:
            with self.subTest(extras=extras), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                fixture.expectation = replace(fixture.expectation, resource_extras=extras)
                with fixture.ownership():
                    self.assert_closed(fixture.owner)
                self.assertEqual(fixture.ops.calls, [])

    def test_oci_duplicate_keys_nonfinite_and_malformed_bytes_refuse(self):
        for kind in ("duplicate", "annotation_duplicate", "nan", "truncated", "utf8"):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                raw = fixture.oci.read_bytes()
                if kind == "duplicate":
                    raw = raw.replace(b'"ociVersion":"1.0.2"', b'"ociVersion":"1.0.2","ociVersion":"1.0.2"')
                elif kind == "annotation_duplicate":
                    raw = raw.replace(b'"io.kubernetes.cri.container-type":"sandbox"', b'"io.kubernetes.cri.container-type":"sandbox","io.kubernetes.cri.container-type":"sandbox"')
                elif kind == "nan":
                    raw = raw.replace(b'"limit":512', b'"limit":NaN')
                elif kind == "truncated":
                    raw = raw[:-1]
                else:
                    raw = b"\xff" + CANARY.encode()
                fixture.write_oci(raw)
                with fixture.ownership():
                    owner = fixture.owner()
                    owner.create()
                    self.assert_closed(owner.initialize, owner)

    def test_append_allowed_shrink_prefix_inode_and_log_metadata_changes_refuse(self):
        for mutation in ("shrink", "prefix", "replacement", "hardlink", "mode"):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                with fixture.ownership():
                    owner = fixture.owner()
                    self.through(owner)
                    candidate = owner.candidate_context()
                    with fixture.log.open("ab") as stream:
                        stream.write(b"2026-10-19T12:34:57Z stdout F ordinary log append\n")
                    owner.final_recheck()
                    self.assertEqual(owner.candidate_context(), candidate)
                    if mutation == "shrink":
                        fixture.log.write_bytes(candidate.frame_prefix)
                    elif mutation == "prefix":
                        fixture.log.write_bytes(fixture.log.read_bytes().replace(b"123456", b"123457", 1))
                    elif mutation == "replacement":
                        raw = fixture.log.read_bytes()
                        fixture.log.rename(fixture.diagnostics / "old.log")
                        fd = os.open(fixture.log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        os.write(fd, raw)
                        os.close(fd)
                    elif mutation == "hardlink":
                        os.link(fixture.log, fixture.diagnostics / "linked.log")
                    else:
                        fixture.log.chmod(0o640)
                    self.assert_closed(owner.final_recheck, owner)

    def test_partial_wrong_first_nonce_duplicate_and_oversized_initial_frame_refuse(self):
        for raw in (literal_frame()[:-1], b"", b"2026-10-19T12:34:56Z stdout F preceding\n" + literal_frame(),
                    literal_frame().replace(NONCE.encode(), b"c" * 64),
                    literal_frame()[:-1] + b" DOCKERLENS_OUTER_BOOTSTRAP_V1 {}\n",
                    literal_frame().replace(b'"uid":0', b'"uid":1000'),
                    b"2026-10-19T12:34:56Z stderr F " + b"x" * 2000 + b"\n" + literal_frame()):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                fixture.ops.log_bytes = raw
                with fixture.ownership():
                    owner = fixture.owner()
                    self.through(owner, State.STARTED)
                    self.assert_closed(owner.capture_frame, owner)

    def test_retained_first_frame_ignores_unrelated_later_daemon_records(self):
        for tail in (b"2026-10-19T12:34:57Z stdout P partial daemon\n",
                     b"unfinished daemon output", literal_frame(), b"arbitrary later bytes\n"):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                fixture.ops.log_bytes += tail
                with fixture.ownership(), fixture.owner() as owner:
                    self.through(owner)
                    self.assertEqual(owner.candidate_context().frame_prefix, literal_frame())
                    # No global duplicate-frame claim outside the selected prefix.
                    with fixture.log.open("ab") as stream:
                        stream.write(b"more arbitrary partial output")
                    owner.final_recheck()

    def test_started_at_zero_sentinel_and_typed_pid_rejection(self):
        for value in ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00.000000000Z", "0001-01-01T00:00:00+00:00",
                      "0001-01-01T01:00:00+01:00", "0001-01-01T23:59:00.000000000+23:59"):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                with fixture.ownership():
                    owner = fixture.owner()
                    self.through(owner, State.ARMED)
                    fixture.ops.hooks["start"] = lambda ops: ops.snapshot_override.update(started_at=value)
                    self.assert_closed(owner.start, owner)

    def test_nonzero_started_at_nanoseconds_survive_timezone_zero_comparison(self):
        for value in ("0001-01-01T00:00:00.000000001Z", "0001-01-01T01:00:00.000000001+01:00", STARTED):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                fixture.ops.hooks["start"] = lambda ops: ops.snapshot_override.update(started_at=value)
                with fixture.ownership(), fixture.owner() as owner:
                    self.through(owner)
                    self.assertEqual(owner.candidate_context().started_at, value)

    def test_defensive_caps_refuse_before_next_runtime_open_or_read_and_cleanup_owned_id(self):
        for counter, limit, primitive in (("runtime_calls", 16, None), ("io_calls", 4096, "open"),
                                          ("source_bytes", 1048576, "pread")):
            with self.subTest(counter=counter), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                with fixture.ownership():
                    owner = fixture.owner()
                    owner.create()
                    setattr(owner, counter, limit)
                    if primitive is None:
                        self.assert_closed(owner.initialize, owner)
                        self.assertFalse(any(call[0] == "initialize" for call in fixture.ops.calls))
                    else:
                        with patch.object(lifecycle.os, primitive, wraps=getattr(os, primitive)) as operation:
                            self.assert_closed(owner.initialize, owner)
                            operation.assert_not_called()
                    self.assertEqual(owner.cleanup_calls, 1)
                    self.assertEqual(fixture.ops.calls[-1][0], "cleanup")

    def test_out_of_order_repeated_start_and_no_early_context(self):
        for state in (State.NEW, State.CREATED, State.INITIALIZED, State.ARMED, State.STARTED, State.FRAMED):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                with fixture.ownership():
                    owner = fixture.owner()
                    self.through(owner, state)
                    self.assert_closed(owner.candidate_context, owner)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            with fixture.ownership():
                owner = fixture.owner()
                self.through(owner, State.STARTED)
                self.assert_closed(owner.start, owner)
                self.assertEqual([call[0] for call in fixture.ops.calls].count("start"), 1)

    def test_fd_adopted_before_post_open_cancel_and_cleanup_failure_stays_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            with fixture.ownership():
                owner = fixture.owner()
                real_open = os.open
                descriptors = []

                def cancelled_open(*args, **kwargs):
                    descriptor = real_open(*args, **kwargs)
                    descriptors.append(descriptor)
                    fixture.cancelled = True
                    return descriptor

                with patch.object(lifecycle.os, "open", side_effect=cancelled_open):
                    self.assert_closed(owner.create, owner)
                self.assertTrue(descriptors)
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            with fixture.ownership():
                owner = fixture.owner()
                owner.create()

                def bad_cleanup(_ops):
                    raise RuntimeError(CANARY)

                fixture.ops.hooks["cleanup"] = bad_cleanup
                fixture.cancelled = True
                self.assert_closed(owner.initialize, owner)
                self.assertEqual(owner.cleanup_obligation, "unverified")
                self.assertEqual(owner.cleanup_calls, 1)
                owner.close()
                self.assertEqual(owner.cleanup_calls, 1)


class SplitCustodyTests(unittest.TestCase):
    def budgets(self, fixture):
        book = ReservationBook(secrets.token_hex(32), {"lane": Allowance(16, 1048576, 4096)}, {"lane": 400_000_000_000})
        root = book.claim_before_spawn(book.reserve("root", "lane", Allowance(16, 1000000, 3600)))
        caller = book.claim_before_spawn(book.reserve("caller", "lane", Allowance(0, 48576, 496)))
        return (ReservedBudget(root, lambda: int(fixture.now * 1e9), lambda: fixture.cancelled),
                ReservedBudget(caller, lambda: int(fixture.now * 1e9), lambda: fixture.cancelled))

    def test_initialize_holds_original_before_binding_and_replacement_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            root_budget, _caller_budget = self.budgets(fixture)
            with fixture.ownership():
                root = RootOCICustody(fixture.expectation, PROFILE, fixture.ops, str(fixture.log), root_budget,
                                      100.0, 300.0, 400.0, lambda: fixture.now, lambda: fixture.cancelled)
                root.create()
                root.initialize()
                self.assertFalse(root._bound)
                original = os.fstat(root._oci.fd)
                self.assertEqual(original.st_ino, fixture.oci.stat().st_ino)
                fixture.oci.rename(fixture.oci.with_name("old-config.json"))
                fixture.oci.write_bytes(root._oci.raw)
                fixture.oci.chmod(0o600)
                with self.assertRaises(LifecycleError):
                    root.bind_expectation(fixture.expectation)
                self.assertEqual(root.state, State.POISONED)
                self.assertEqual(root._fds, [])

    def test_unbound_oci_is_not_returned_or_started(self):
        for action in ("original_oci", "arm"):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                root_budget, _caller_budget = self.budgets(fixture)
                with fixture.ownership():
                    root = RootOCICustody(fixture.expectation, PROFILE, fixture.ops, str(fixture.log), root_budget,
                                          100.0, 300.0, 400.0, lambda: fixture.now, lambda: fixture.cancelled)
                    root.create()
                    root.initialize()
                    with self.assertRaises(LifecycleError):
                        getattr(root, action)()
                    self.assertNotIn("start", [call[0] for call in fixture.ops.calls])

    def test_root_never_creates_or_holds_caller_log_and_disposal_is_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            root_budget, caller_budget = self.budgets(fixture)
            with fixture.ownership():
                root = RootOCICustody(fixture.expectation, PROFILE, fixture.ops, str(fixture.log), root_budget,
                                      100.0, 300.0, 400.0, lambda: fixture.now, lambda: fixture.cancelled)
                root.create()
                self.assertFalse(fixture.log.exists())
                root.initialize()
                root.bind_expectation(fixture.expectation)
                raw, info, pid = root.original_oci()
                self.assertEqual((raw, info.uid, pid), (fixture.oci.read_bytes(), 0, 12345))
                caller = CallerLogCustody(fixture.expectation, str(fixture.log), caller_budget,
                                          100.0, 300.0, lambda: fixture.now, lambda: fixture.cancelled)
                try:
                    caller.empty()
                    root.arm()
                    caller.empty()
                    self.assertEqual(root.start(), (12345, STARTED))
                    caller.capture()
                    original_log = os.fstat(caller._log.fd)
                    self.assertNotIn(caller._log.fd, root._fds)
                    self.assertFalse(hasattr(root, "_log"))
                    root.recheck()
                    self.assertEqual(caller.recheck()[2].start, 123456)
                    held = list(root._fds)
                    root.close()
                    for descriptor in held:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    self.assertEqual(os.fstat(caller._log.fd).st_ino, original_log.st_ino)
                    self.assertEqual(fixture.ops.calls[-1][0], "cleanup")
                    self.assertGreater(root_budget.used.source_bytes, len(raw))
                    self.assertGreater(caller_budget.used.source_bytes, 0)
                finally:
                    root.close()
                    caller.close()

    def test_caller_log_replacement_cannot_be_hidden_by_root_custody(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            root_budget, caller_budget = self.budgets(fixture)
            with fixture.ownership():
                root = RootOCICustody(fixture.expectation, PROFILE, fixture.ops, str(fixture.log), root_budget,
                                      100.0, 300.0, 400.0, lambda: fixture.now, lambda: fixture.cancelled)
                caller = CallerLogCustody(fixture.expectation, str(fixture.log), caller_budget,
                                          100.0, 300.0, lambda: fixture.now, lambda: fixture.cancelled)
                try:
                    root.create()
                    root.initialize()
                    root.bind_expectation(fixture.expectation)
                    root.arm()
                    root.start()
                    caller.capture()
                    fixture.log.rename(fixture.diagnostics / "old-log")
                    fixture.log.write_bytes(literal_frame())
                    fixture.log.chmod(0o600)
                    root.recheck()  # Root does not assert caller-log custody.
                    with self.assertRaises(LifecycleError):
                        caller.recheck()
                    self.assertEqual(caller._fds, [])
                finally:
                    root.close()
                    caller.close()

    def test_runtime_mount_hierarchy_and_env_map_order_do_not_create_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            value = oci_fixture(fixture.expectation)
            value["mounts"].reverse()
            value["process"]["env"].reverse()
            fixture.write_oci(json.dumps(value).encode())
            with fixture.ownership(), fixture.owner() as owner:
                OuterLifecycleTests().through(owner)
                self.assertEqual(owner.candidate_context().frame.start, 123456)


if __name__ == "__main__":
    unittest.main()
