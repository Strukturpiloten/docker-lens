"""Independent private configured-retention controls; these are not native evidence."""
import copy
import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("bind_proof", Path(__file__).resolve().parents[1] / "scripts/native_bind_relabel_proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)
SHAPES = ("BindMountSharedRelabelReadWrite", "BindMountSharedRelabelReadOnly",
          "BindMountPrivateRelabelReadWrite", "BindMountPrivateRelabelReadOnly")
CASES = ("shared-rw", "shared-ro", "private-rw", "private-ro")
CHECKS = ("source_boundary", "literal_bind", "native_mount", "running", "capture", "decoded_mount")
RUN = "Ab12Cd34"
FILENAME = "bind-relabel-config-v1.json"
SECRET = "private-source-do-not-disclose"


def fixture(lane="upstream-rootful"):
    debian = lane.startswith("debian11-")
    rootless = lane.endswith("-rootless")
    storage = "/home/docker/.local/share/docker" if rootless else "/var/lib/docker"
    context = {
        "candidate_sha": "a" * 40, "run_id": RUN, "lane": lane,
        "engine_release": "20.10.5" if debian else "29.8.1",
        "rendering_api": "1.41" if debian else "1.56", "acquisition_api": "1.41" if debian else "1.49",
        "mode": "rootless" if rootless else "rootful", "docker_package": "20.10.5+dfsg1-1+deb11u2" if debian else "",
        "fixture_image": "private.test/fixture:1@sha256:" + "b" * 64,
        "outer": {"id": "f" * 64, "name": f"dl-native-{RUN}", "owner": RUN,
                  "image": "private.test/outer:1@sha256:" + "c" * 64,
                  "data_volume": f"dl-native-data-{RUN}", "socket_source": "/private/capture/socket",
                  "privileged": True, "memory_bytes": 4294967296, "cpu_quota": 200000,
                  "cpu_period": 100000, "pids_limit": 512},
        "source_boundary": {"kind": "owned_data_volume", "volume": f"dl-native-data-{RUN}",
                            "storage_root": storage, "root": f"{storage}/dl-bind-relabel-{RUN}",
                            "owner": RUN, "owner_uid": 1000 if rootless else 0, "mode": "0700"},
    }
    cases = []
    for index, (case, shape) in enumerate(zip(CASES, SHAPES)):
        roles = []
        for role_index, role in enumerate(("oracle", "rendered")):
            roles.append({"role": role, "request_check": "independent_cli" if role == "oracle" else "literal_rendered",
                          "id": f"{index * 2 + role_index + 1:064x}", "name": f"dl-br-{RUN}-{case}-{role}",
                          "owner": RUN, "image": context["fixture_image"], "source_leaf": f"{case}-{role}",
                          "checks": dict.fromkeys(CHECKS, "passed"), "container_cleanup": "absent", "source_cleanup": "absent"})
        cases.append({"case": case, "shape": shape, "roles": roles})
    return {"schema_version": 1, "contract": "bind-relabel-config-v1", "context": context,
            "shapes": list(SHAPES), "cases": cases, "selinux_effect": "unverified",
            "cleanup": {"containers": "absent", "sources": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}


def object_paths(value, path=()):
    if isinstance(value, dict):
        yield path
        for key, child in value.items():
            yield from object_paths(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from object_paths(child, (*path, index))


def at(value, path):
    for part in path:
        value = value[part]
    return value


class ClosedProofTests(unittest.TestCase):
    def rejected(self, value, context=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaisesRegex(ValueError, "^incomplete bind relabel proof$") as failure:
                PROOF.validate_bind_relabel_proof(value, fixture()["context"] if context is None else context)
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        self.assertNotIn(SECRET, str(failure.exception))

    def test_four_exact_lanes_return_only_shapes(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            value = fixture(lane)
            self.assertEqual(PROOF.validate_bind_relabel_proof(value, copy.deepcopy(value["context"])), SHAPES)
            if lane.startswith("debian11-"):
                value["context"]["engine_release"] = "20.10.5+dfsg1"
                self.assertEqual(PROOF.validate_bind_relabel_proof(value, value["context"]), SHAPES)

    def test_every_object_requires_exact_keys_and_values(self):
        good = fixture()
        for path in object_paths(good):
            for key in at(good, path):
                for remove in (False, True):
                    changed = copy.deepcopy(good)
                    target = at(changed, path)
                    if remove:
                        del target[key]
                    else:
                        target[key] = SECRET
                    self.rejected(changed)
            changed = copy.deepcopy(good)
            at(changed, path)["private_inspect"] = SECRET
            self.rejected(changed)

    def test_matching_wrong_context_never_authorizes_api_or_host_source(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            good = fixture(lane)
            wrong_api = "1.56" if lane.startswith("upstream-") else "1.49"
            for path, wrong in ((('acquisition_api',), wrong_api), (('candidate_sha',), "a" * 39),
                                (('source_boundary', 'root'), "/dockerlens-native/native-bind"),
                                (('source_boundary', 'root'), "/var/lib/docker/dl-bind-relabel-foreign"),
                                (('source_boundary', 'kind'), "host_bind"),
                                (('source_boundary', 'volume'), "shared-volume"),
                                (('source_boundary', 'owner_uid'), True),
                                (('source_boundary', 'owner_uid'), 0 if lane.endswith("rootless") else 1000),
                                (('source_boundary', 'mode'), "0777"),
                                (('outer', 'pids_limit'), 512.0)):
                changed = copy.deepcopy(good)
                at(changed["context"], path[:-1])[path[-1]] = wrong
                self.rejected(changed, copy.deepcopy(changed["context"]))
            expected = copy.deepcopy(good["context"])
            expected["source_boundary"]["owner"] = "foreign"
            self.rejected(good, expected)

    def test_case_role_shape_order_identity_and_partial_checks_reject(self):
        good = fixture()
        for path in (("shapes",), ("cases",), ("cases", 0, "roles")):
            for operation in ("reverse", "empty", "duplicate"):
                changed = copy.deepcopy(good)
                values = at(changed, path)
                at(changed, path[:-1])[path[-1]] = (list(reversed(values)) if operation == "reverse" else
                                                   [] if operation == "empty" else [values[0]] * len(values))
                self.rejected(changed)
        for path, wrong in ((('cases', 0, 'roles', 0, 'id'), "f" * 64),
                            (('cases', 1, 'roles', 1, 'id'), good["cases"][0]["roles"][0]["id"]),
                            (('cases', 0, 'roles', 0, 'id'), "A" * 64),
                            (('cases', 0, 'roles', 0, 'checks', 'running'), "timeout"),
                            (('cleanup', 'uncertain'), True), (('cleanup', 'rounds'), True),
                            (('selinux_effect',), "enforced")):
            changed = copy.deepcopy(good)
            at(changed, path[:-1])[path[-1]] = wrong
            self.rejected(changed)


class PrivateFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        self.path = self.directory / FILENAME
        self.value = fixture()
        self.path.write_text(json.dumps(self.value), encoding="utf-8")
        self.path.chmod(0o600)

    def read(self):
        return PROOF.read_bind_relabel_proof(self.path, self.directory, self.value["context"])

    def rejected(self):
        with self.assertRaisesRegex(ValueError, "^invalid private bind relabel proof$") as failure:
            self.read()
        self.assertIsNone(failure.exception.__cause__)

    def test_private_regular_proof_returns_only_shapes(self):
        self.assertEqual(self.read(), SHAPES)

    def test_permission_special_bits_and_hardlinks_reject(self):
        for mode in (0o644, 0o400, 0o660, 0o4600, 0o2600):
            self.path.chmod(mode)
            self.rejected()
        self.path.chmod(0o600)
        os.link(self.path, self.directory / "other")
        self.rejected()

    def test_symlink_nonregular_and_untrusted_parent_reject(self):
        real = self.directory / "real"
        self.path.rename(real)
        self.path.symlink_to(real)
        self.rejected()
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        self.rejected()
        self.path.unlink()
        real.rename(self.path)
        for mode in (0o755, 0o770, 0o1700):
            self.directory.chmod(mode)
            self.rejected()
        self.directory.chmod(0o700)

    def test_duplicate_truncated_oversize_and_wrong_location_reject(self):
        for payload in ('{"schema_version":1,"schema_version":1}', '{', '', SECRET * 2048):
            self.path.write_text(payload, encoding="utf-8")
            self.rejected()
        self.path.write_text(json.dumps(self.value), encoding="utf-8")
        with self.assertRaises(ValueError):
            PROOF.read_bind_relabel_proof(self.path.with_name("foreign.json"), self.directory, self.value["context"])

    def test_short_read_owner_and_inode_drift_reject(self):
        original = os.read
        with patch.object(PROOF.os, "read", side_effect=lambda fd, size: original(fd, size)[:-1]):
            self.rejected()
        with patch.object(PROOF.os, "geteuid", return_value=os.geteuid() + 1):
            self.rejected()
        original_stat = os.stat
        def drift(path, *args, **kwargs):
            if path == FILENAME:
                return original_stat(self.directory / "foreign", *args, **kwargs)
            return original_stat(path, *args, **kwargs)
        (self.directory / "foreign").write_bytes(b"unrelated")
        with patch.object(PROOF.os, "stat", side_effect=drift):
            self.rejected()

    def test_symlinked_ancestor_and_directory_swap_reject(self):
        real_directory = self.directory / "private"
        real_directory.mkdir(mode=0o700)
        nested = real_directory / FILENAME
        nested.write_bytes(self.path.read_bytes())
        nested.chmod(0o600)
        alias = self.directory / "alias"
        alias.symlink_to(real_directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "^invalid private bind relabel proof$"):
            PROOF.read_bind_relabel_proof(alias / FILENAME, alias, self.value["context"])
        original_read = os.read
        old_directory = self.directory.with_name(self.directory.name + "-old")
        def swap(fd, size):
            payload = original_read(fd, size)
            self.directory.rename(old_directory)
            self.directory.mkdir(mode=0o700)
            self.path.write_bytes(payload)
            self.path.chmod(0o600)
            return payload
        try:
            with patch.object(PROOF.os, "read", side_effect=swap):
                self.rejected()
        finally:
            # Only the isolated test fixture's exact known files are removed.
            self.path.unlink()
            self.directory.rmdir()
            old_directory.rename(self.directory)


if __name__ == "__main__":
    unittest.main()
