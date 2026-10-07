"""Independent closed-schema, private-file, and privacy controls; no native claims."""

import contextlib
import copy
import importlib.util
import io
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_network_attachment_proof", ROOT / "scripts/native_network_attachment_proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)

# Expectations deliberately do not use the validator's shape/slot constants.
SHAPES = ("NetworkCreateLabels", "NetworkPrimaryAliases",
          "NetworkSecondaryAliases", "NetworkSecondaryConnect")
SLOTS = ("primary_network", "secondary_network", "server", "primary_peer", "secondary_peer")
CHECKS = ("primary_only", "secondary_connected", "labels", "aliases", "running", "membership")
EFFECTS = ("unique_dns", "shared_dns", "named_http", "shared_http", "direct_http")
FILENAME = "network-attachments-v1.json"
SECRET = "protected-network-value-do-not-print"
RUN = "Ab12Cd34"
FIXTURE = "private.test/fixture:1@sha256:" + "b" * 64
OUTER_IMAGE = "private.test/engine:1@sha256:" + "c" * 64


def fixture(lane="upstream-rootful", acquisition=None):
    debian = lane.startswith("debian11-")
    context = {
        "candidate_sha": "a" * 40, "run_id": RUN, "lane": lane,
        "engine_release": "20.10.5" if debian else "29.8.1",
        "rendering_api": "1.41" if debian else "1.56",
        "acquisition_api": acquisition or ("1.41" if debian else "1.49"),
        "mode": lane.rsplit("-", 1)[1],
        "docker_package": "20.10.5+dfsg1-1+deb11u2" if debian else "",
        "fixture_image": FIXTURE,
        "outer": {
            "id": "f" * 64, "name": f"dl-native-{RUN}", "owner": RUN,
            "image": OUTER_IMAGE, "data_volume": f"dl-native-data-{RUN}",
            "socket_source": "/private/native/socket", "privileged": True,
            "memory_bytes": 4294967296, "cpu_quota": 200000,
            "cpu_period": 100000, "pids_limit": 512,
        },
    }
    roles = []
    for role_index, role in enumerate(("oracle", "rendered")):
        resources = []
        for index, slot in enumerate(SLOTS):
            network = index < 2
            resource = {
                "slot": slot, "kind": "network" if network else "container",
                "id": f"{role_index * 5 + index + 1:064x}",
                "name": f"dl-na-{RUN}-{role}-{slot.replace('_', '-')}",
                "owner": RUN, "configured": "passed", "cleanup": "absent",
            }
            if not network:
                resource["image"] = FIXTURE
            resources.append(resource)
        roles.append({
            "role": role,
            "request_check": "independent_cli" if role == "oracle" else "literal_rendered",
            "resources": resources,
            "checks": {**dict.fromkeys(CHECKS, "passed"),
                       "primary": dict.fromkeys(EFFECTS, "passed"),
                       "secondary": dict.fromkeys(EFFECTS, "passed")},
            "cleanup": "absent",
        })
    return {
        "schema_version": 1, "contract": "network-attachments-v1",
        "context": context, "roles": roles, "shapes": list(SHAPES),
        "cleanup": {"outcome": "absent", "rounds": 2, "outstanding": 0, "uncertain": False},
    }


def at(value, path):
    for part in path:
        value = value[part]
    return value


def object_paths(value, path=()):
    if isinstance(value, dict):
        yield path
        for key, child in value.items():
            yield from object_paths(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from object_paths(child, (*path, index))


def changed_stat(info, **changes):
    fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
              "st_mtime_ns", "st_ctime_ns")
    return types.SimpleNamespace(**{**{field: getattr(info, field) for field in fields}, **changes})


class ClosedSchemaTests(unittest.TestCase):
    def rejected(self, value, expected=None):
        expected = fixture()["context"] if expected is None else expected
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(ValueError) as failure:
                PROOF.validate_network_attachment_proof(value, expected)
        self.assertEqual(str(failure.exception), "incomplete network attachment proof")
        self.assertIsNone(failure.exception.__cause__)
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        self.assertNotIn(SECRET, str(failure.exception))

    def test_all_four_lanes_return_only_four_closed_shapes(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            for acquisition in (("1.41",) if lane.startswith("debian") else ("1.49",)):
                with self.subTest(lane=lane, acquisition=acquisition):
                    value = fixture(lane, acquisition)
                    self.assertEqual(PROOF.validate_network_attachment_proof(
                        value, copy.deepcopy(value["context"])), SHAPES)
                    if lane.startswith("debian"):
                        value["context"]["engine_release"] = "20.10.5+dfsg1"
                        self.assertEqual(PROOF.validate_network_attachment_proof(
                            value, copy.deepcopy(value["context"])), SHAPES)

    def test_every_object_has_exact_required_fields(self):
        good = fixture()
        for path in object_paths(good):
            obj = at(good, path)
            for key in obj:
                for operation in ("remove", "replace"):
                    with self.subTest(path=path, field=key, operation=operation):
                        changed = copy.deepcopy(good)
                        target = at(changed, path)
                        if operation == "remove":
                            del target[key]
                        else:
                            target[key] = SECRET
                        self.rejected(changed)
            with self.subTest(path=path, operation="extra_private_field"):
                changed = copy.deepcopy(good)
                at(changed, path)["raw_private_inspect"] = SECRET
                self.rejected(changed)

    def test_acquisition_api_is_exact_even_when_harness_and_proof_agree(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            expected_api = "1.41" if lane.startswith("debian11-") else "1.49"
            for wrong_api in ("", "1.40", "1.41", "1.48", "1.49", "1.50", "1.56"):
                if wrong_api == expected_api:
                    continue
                with self.subTest(lane=lane, acquisition=wrong_api):
                    value = fixture(lane)
                    value["context"]["acquisition_api"] = wrong_api
                    self.rejected(value, copy.deepcopy(value["context"]))

    def test_shape_role_resource_sets_are_exact_unique_and_ordered(self):
        good = fixture()
        paths = (("shapes",), ("roles",), ("roles", 0, "resources"), ("roles", 1, "resources"))
        for path in paths:
            source = at(good, path)
            replacements = (source[:-1], [*source, copy.deepcopy(source[0])],
                            [copy.deepcopy(source[0])] * len(source), list(reversed(source)),
                            [], {}, None)
            for replacement in replacements:
                with self.subTest(path=path, replacement_type=type(replacement).__name__):
                    changed = copy.deepcopy(good)
                    at(changed, path[:-1])[path[-1]] = replacement
                    self.rejected(changed)

    def test_context_is_independently_bound_and_requires_exact_native_setup(self):
        good = fixture()
        for key in good["context"]:
            expected = copy.deepcopy(good["context"])
            expected[key] = SECRET
            with self.subTest(mismatched_harness_context=key):
                self.rejected(good, expected)
        invalid = {
            "candidate_sha": ("a" * 39, "A" * 40, "b" * 64, True),
            "run_id": ("short", "Ab12Cd3-", "Ab12Cd345"),
            "lane": ("docker-rootful", "debian11-rootful"),
            "engine_release": ("29.8.0", "20.10.5"),
            "rendering_api": ("1.41", "1.49", "1.55", "1.57"),
            "acquisition_api": ("1.41", "1.44", "1.55", "1.56", "1.57"),
            "mode": ("unknown", "rootless"),
            "docker_package": ("29.8.1", "20.10.5+dfsg1-1+deb11u2"),
            "fixture_image": ("private/image:latest", "image@sha256:" + "a" * 64),
        }
        for key, values in invalid.items():
            for replacement in values:
                changed = copy.deepcopy(good)
                changed["context"][key] = replacement
                with self.subTest(invalid_context=key, replacement=replacement):
                    self.rejected(changed, copy.deepcopy(changed["context"]))
        invalid_outer = {
            "id": ("f" * 63, "F" * 64), "name": ("dl-native-foreign",),
            "owner": ("foreign",), "image": ("image:latest",),
            "data_volume": ("dl-native-data-foreign",),
            "socket_source": ("relative/socket", "/private/native/not-socket"),
            "privileged": (False, 1), "memory_bytes": (4294967295, 4294967296.0),
            "cpu_quota": (100000, 200000.0), "cpu_period": (99999, 100000.0),
            "pids_limit": (513, 512.0),
        }
        for key, values in invalid_outer.items():
            for replacement in values:
                changed = copy.deepcopy(good)
                changed["context"]["outer"][key] = replacement
                with self.subTest(invalid_outer=key):
                    self.rejected(changed, copy.deepcopy(changed["context"]))

    def test_foreign_reused_noncanonical_resources_and_partial_effects_reject(self):
        good = fixture()
        for role_index in range(2):
            for index in range(5):
                for replacement in ("x" * 64, "A" * 64, "a" * 63,
                                    good["context"]["outer"]["id"], good["roles"][0]["resources"][0]["id"]):
                    if replacement == good["roles"][role_index]["resources"][index]["id"]:
                        continue
                    changed = copy.deepcopy(good)
                    changed["roles"][role_index]["resources"][index]["id"] = replacement
                    self.rejected(changed)
                for key, replacement in (("owner", "foreign"), ("name", "dl-na-stale"),
                                         ("configured", "not_run"), ("cleanup", "unknown")):
                    changed = copy.deepcopy(good)
                    changed["roles"][role_index]["resources"][index][key] = replacement
                    self.rejected(changed)
            for side in ("primary", "secondary"):
                for effect in EFFECTS:
                    for status in ("timeout", "NXDOMAIN", "failed_exec", "not_run", True):
                        changed = copy.deepcopy(good)
                        changed["roles"][role_index]["checks"][side][effect] = status
                        self.rejected(changed)

    def test_cleanup_types_and_incomplete_outcomes_reject(self):
        for key, values in {
            "outcome": ("unknown", "present"), "rounds": (0, 1, 3, 2.0, True),
            "outstanding": (1, False, 0.0), "uncertain": (True, 0),
        }.items():
            for replacement in values:
                changed = fixture()
                changed["cleanup"][key] = replacement
                self.rejected(changed)
        for key, replacement in (("schema_version", True), ("schema_version", 1.0),
                                 ("schema_version", 2), ("contract", "network-attachments-v2")):
            changed = fixture()
            changed[key] = replacement
            self.rejected(changed)


class PrivateReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.directory = self.root / "capture"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / FILENAME
        self.good = fixture()
        self.expected = copy.deepcopy(self.good["context"])
        self.write(json.dumps(self.good).encode())

    def write(self, payload):
        self.path.write_bytes(payload)
        self.path.chmod(0o600)

    def read(self, path=None, directory=None):
        return PROOF.read_network_attachment_proof(
            self.path if path is None else path,
            self.directory if directory is None else directory, self.expected)

    def rejected(self, path=None, directory=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(ValueError) as failure:
                self.read(path, directory)
        self.assertEqual(str(failure.exception), "invalid private network attachment proof")
        self.assertIsNone(failure.exception.__cause__)
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        self.assertNotIn(SECRET, str(failure.exception))

    def test_private_direct_child_returns_no_resource_or_context_values(self):
        result = self.read()
        self.assertEqual(result, SHAPES)
        self.assertIsInstance(result, tuple)
        for private in (RUN, FIXTURE, OUTER_IMAGE, "candidate_sha", "resources", "outer"):
            self.assertNotIn(private, repr(result))

    def test_missing_wrong_child_and_nested_paths_reject(self):
        self.rejected(self.directory / "missing.json")
        self.rejected(self.root / FILENAME)
        nested = self.directory / "nested"
        nested.mkdir(mode=0o700)
        child = nested / FILENAME
        child.write_bytes(self.path.read_bytes())
        child.chmod(0o600)
        self.rejected(child)
        self.path.unlink()
        self.rejected()

    def test_file_directory_and_ancestor_symlink_aliases_reject(self):
        held = self.directory / "held.json"
        self.path.rename(held)
        self.path.symlink_to(held)
        self.rejected()
        self.path.unlink()
        held.rename(self.path)
        alias = self.root / "capture-alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        self.rejected(alias / FILENAME, alias)
        ancestor = self.root / "ancestor-alias"
        ancestor.symlink_to(self.root, target_is_directory=True)
        self.rejected(ancestor / "capture" / FILENAME, ancestor / "capture")

    def test_modes_special_bits_and_hardlinks_reject(self):
        for mode in (0o644, 0o400, 0o660, 0o1600, 0o2600, 0o4600):
            with self.subTest(file_mode=oct(mode)):
                self.path.chmod(mode)
                self.rejected()
        self.path.chmod(0o600)
        for mode in (0o755, 0o500, 0o770, 0o1700, 0o2700, 0o4700):
            with self.subTest(directory_mode=oct(mode)):
                self.directory.chmod(mode)
                self.rejected()
        self.directory.chmod(0o700)
        os.link(self.path, self.directory / "second-link")
        self.rejected()

    def test_nonregular_file_is_rejected_without_blocking(self):
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        self.rejected()
        self.path.unlink()
        self.path.mkdir(mode=0o600)
        self.rejected()

    def test_wrong_directory_or_file_owner_rejects(self):
        original_lstat = os.lstat
        with patch.object(PROOF.os, "lstat", side_effect=lambda path, *a, **kw:
                          changed_stat(original_lstat(path, *a, **kw), st_uid=os.geteuid() + 1)):
            self.rejected()
        original_fstat = os.fstat
        def foreign_file(fd):
            info = original_fstat(fd)
            return changed_stat(info, st_uid=os.geteuid() + 1) if info.st_ino == self.path.stat().st_ino else info
        with patch.object(PROOF.os, "fstat", side_effect=foreign_file):
            self.rejected()

    def test_size_json_duplicate_keys_and_private_errors_are_closed(self):
        payload = json.dumps(self.good).encode()
        invalid = (
            b"", b" " * (16 * 1024 + 1), payload[:-1], b"\xff" + SECRET.encode(),
            b'{"secret":"' + SECRET.encode() + b'",',
            payload.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'),
            payload.replace(b'"unique_dns": "passed"', b'"unique_dns": "passed", "unique_dns": "passed"', 1),
            ("[" * 1500 + '"' + SECRET + '"' + "]" * 1500).encode(),
        )
        for value in invalid:
            with self.subTest(size=len(value)):
                self.write(value)
                self.rejected()

    def test_metadata_and_named_inode_drift_rejects(self):
        original_fstat = os.fstat
        file_inode = self.path.stat().st_ino
        for field in ("st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"):
            seen = 0
            def drift(fd):
                nonlocal seen
                info = original_fstat(fd)
                if info.st_ino == file_inode:
                    seen += 1
                    if seen == 2:
                        return changed_stat(info, **{field: getattr(info, field) + 1})
                return info
            with self.subTest(field=field), patch.object(PROOF.os, "fstat", side_effect=drift):
                self.rejected()
        original_stat = os.stat
        def named_drift(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path == FILENAME and kwargs.get("dir_fd") is not None:
                return changed_stat(info, st_ino=info.st_ino + 1)
            return info
        with patch.object(PROOF.os, "stat", side_effect=named_drift):
            self.rejected()

    def test_content_truncation_replacement_and_parent_replacement_during_read_reject(self):
        original_read = os.read
        for change in ("truncate", "replace", "parent"):
            def raced(fd, count):
                data = original_read(fd, count)
                if change == "truncate":
                    self.path.write_bytes(b"{}")
                elif change == "replace":
                    self.path.unlink()
                    self.write(json.dumps(self.good).encode())
                else:
                    self.directory.rename(self.root / "old-capture")
                    self.directory.mkdir(mode=0o700)
                    self.write(json.dumps(self.good).encode())
                return data
            with self.subTest(change=change), patch.object(PROOF.os, "read", side_effect=raced):
                self.rejected()
            self.write(json.dumps(self.good).encode())

    def test_short_read_and_transport_exception_do_not_disclose_canary(self):
        original_read = os.read
        with patch.object(PROOF.os, "read", side_effect=lambda fd, count: original_read(fd, count)[:-1]):
            self.rejected()
        with patch.object(PROOF.os, "read", side_effect=OSError(SECRET)):
            self.rejected()


if __name__ == "__main__":
    unittest.main()
