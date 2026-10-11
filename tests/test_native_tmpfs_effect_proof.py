"""Tiny offline controls only; synthetic objects are not native proof."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/native_tmpfs_effect_proof.py"
SPEC = importlib.util.spec_from_file_location("tmpfs_preparation", SOURCE)
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


def fixture(lane="debian11-rootful"):
    debian = lane.startswith("debian11-")
    mode = lane.rsplit("-", 1)[1]
    context = {
        "candidate_sha": "a" * 40, "run_id": "Ab12Cd34", "lane": lane,
        "engine_release": "20.10.5" if debian else "29.8.1", "rendering_api": "1.41" if debian else "1.56",
        "acquisition_api": "1.41" if debian else "1.49", "mode": mode,
        "docker_package": "20.10.5+dfsg1-1+deb11u2" if debian else "",
        "fixture_image": "docker.io/library/busybox:synthetic@sha256:" + "b" * 64,
        "daemon_uid": 0 if mode == "rootful" else 1000,
        "outer": {"id": "f" * 64, "name": "dl-native-Ab12Cd34", "owner": "Ab12Cd34",
                  "image": "synthetic:only@sha256:" + "c" * 64,
                  "data_volume": "dl-native-data-Ab12Cd34", "socket_source": "/synthetic/socket",
                  "privileged": True, "memory_bytes": 4294967296,
                  "cpu_quota": 200000, "cpu_period": 100000, "pids_limit": 512},
    }
    cases = []
    # Independent literal expectations, not values imported from CASES.
    for number, (size, permissions, readonly) in enumerate(
            ((1048576, 448, False), (1048576, 448, True),
             (2097152, 488, False), (2097152, 488, True))):
        containers = []
        for role_number, role in enumerate(("oracle", "rendered")):
            index = 2 * number + role_number
            containers.append({"role": role, "id": f"{index + 1:064x}",
                               "name": f"dl-tmpfs-Ab12Cd34-{index}", "owner": "Ab12Cd34",
                               "image_id": "sha256:" + "d" * 64,
                               "configuration": {"type": "tmpfs", "target": "/dl-tmpfs",
                                                 "size_bytes": size, "mode": permissions,
                                                 "read_only": readonly},
                               "effect": {"filesystem": "tmpfs", "capacity_bytes": size,
                                          "mode": permissions, "mount_access": "ro" if readonly else "rw",
                                          "write_outcome": "refused" if readonly else "written_then_enospc",
                                          "saturation_bytes": 0 if readonly else size}})
        cases.append({"size_bytes": size, "mode": permissions, "read_only": readonly,
                      "containers": containers})
    value = {"schema_version": 1, "contract": "tmpfs-effect-v1", "admission": "unadmitted",
             "context": copy.deepcopy(context),
             "apis": {"fixture_cli": context["rendering_api"], "renderer": context["rendering_api"],
                      "request": context["rendering_api"]},
             "borrowed_image": {"id": "sha256:" + "d" * 64, "identity": "unchanged", "removal": "not_owned"},
             "cases": cases, "limits": {"containers": 8, "deadline_seconds": 180, "retries": 0},
             "coverage": "explicit_1MiB_0700_and_2MiB_0750_rw_ro_only",
             "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}
    return value, context


class ProofControls(unittest.TestCase):
    def refuse(self, value, context):
        with self.assertRaises(PROOF.ContractError):
            PROOF.validate(value, context)

    def test_four_independent_lane_contexts_remain_unadmitted(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            value, context = fixture(lane)
            result = PROOF.validate(value, context)
            self.assertEqual(result["admission"], "unadmitted")
            self.assertEqual(set(result), {"contract", "admission", "coverage"})

    def test_closed_objects_reject_unknown_and_missing_fields(self):
        paths = ((), ("context",), ("context", "outer"), ("apis",), ("borrowed_image",),
                 ("limits",), ("cleanup",), ("cases", 0), ("cases", 0, "containers", 0),
                 ("cases", 0, "containers", 0, "configuration"),
                 ("cases", 0, "containers", 0, "effect"))
        for path in paths:
            for unknown in (True, False):
                value, context = fixture()
                item = value
                for key in path:
                    item = item[key]
                if unknown:
                    item["unknown"] = True
                else:
                    del item[next(iter(item))]
                self.refuse(value, context)

    def test_every_context_mismatch_refuses(self):
        for key in ("candidate_sha", "run_id", "lane", "engine_release", "fixture_image", "daemon_uid"):
            value, context = fixture()
            value["context"][key] = {"candidate_sha": "e" * 40, "run_id": "Other123",
                                     "lane": "upstream-rootful", "engine_release": "other",
                                     "fixture_image": "docker.io/library/busybox:synthetic@sha256:" + "e" * 64,
                                     "daemon_uid": 1}[key]
            self.refuse(value, context)

    def test_outer_context_mismatch_refuses(self):
        value, context = fixture()
        value["context"]["outer"]["id"] = "e" * 64
        self.refuse(value, context)

    def test_wrong_api_and_package_dimensions_refuse(self):
        for key, wrong in (("rendering_api", "1.49"), ("acquisition_api", "1.56"),
                           ("docker_package", ""), ("mode", "rootless")):
            value, context = fixture()
            value["context"][key] = wrong
            self.refuse(value, context)

    def test_effect_is_not_configuration_only(self):
        for key, wrong in (("filesystem", "ext4"), ("capacity_bytes", 2097152), ("mode", 511),
                           ("mount_access", "ro"), ("write_outcome", "refused"), ("saturation_bytes", 0)):
            value, context = fixture()
            value["cases"][0]["containers"][0]["effect"][key] = wrong
            self.refuse(value, context)

    def test_readonly_effect_requires_refused_write_and_zero_saturation(self):
        for key, wrong in (("mount_access", "rw"), ("write_outcome", "written_then_enospc"),
                           ("saturation_bytes", 1048576)):
            value, context = fixture()
            value["cases"][1]["containers"][0]["effect"][key] = wrong
            self.refuse(value, context)

    def test_duplicate_and_outer_container_ids_refuse(self):
        for duplicate in ("f" * 64, f"{2:064x}"):
            value, context = fixture()
            value["cases"][0]["containers"][0]["id"] = duplicate
            self.refuse(value, context)

    def test_missing_reordered_and_extra_cases_refuse(self):
        for action in ("missing", "reordered", "extra"):
            value, context = fixture()
            if action == "missing":
                value["cases"].pop()
            elif action == "extra":
                value["cases"].append(copy.deepcopy(value["cases"][0]))
            else:
                value["cases"].reverse()
            self.refuse(value, context)

    def test_role_order_refuses(self):
        value, context = fixture()
        value["cases"][0]["containers"].reverse()
        self.refuse(value, context)

    def test_boolean_integer_confusion_refuses(self):
        for key in ("schema_version",):
            value, context = fixture()
            value[key] = True
            self.refuse(value, context)
        value, context = fixture()
        value["cases"][0]["containers"][0]["configuration"]["read_only"] = 0
        self.refuse(value, context)

    def test_cleanup_ambiguity_and_budget_reset_refuse(self):
        for group, key, wrong in (("cleanup", "uncertain", True), ("cleanup", "rounds", 1),
                                  ("cleanup", "outstanding", 1), ("limits", "retries", 1),
                                  ("limits", "deadline_seconds", 181), ("limits", "containers", 9)):
            value, context = fixture()
            value[group][key] = wrong
            self.refuse(value, context)

    def test_unproved_numeric_domain_and_admission_refuse(self):
        value, context = fixture()
        value["cases"][0]["mode"] = 4095
        self.refuse(value, context)
        value, context = fixture()
        value["admission"] = "admitted"
        self.refuse(value, context)

    def test_null_wrong_types_and_malformed_ids_refuse(self):
        for malformed in (None, [], "not-a-proof", 1, True):
            self.refuse(malformed, fixture()[1])
        value, context = fixture()
        value["cases"][0]["containers"][0]["id"] = "A" * 64
        self.refuse(value, context)

    def test_private_reader_refuses_missing_malformed_duplicate_and_oversize(self):
        with tempfile.TemporaryDirectory(prefix="dl-tmpfs-synthetic-") as directory:
            path = Path(directory) / "tmpfs-effect-v1.json"
            with self.assertRaises(PROOF.ContractError):
                PROOF.read_proof(str(path))
            for data in (b"{", b'{"x":1,"x":2}', b"x" * 16385, b"NaN"):
                path.write_bytes(data)
                path.chmod(0o600)
                with self.assertRaises(PROOF.ContractError):
                    PROOF.read_proof(str(path))

    def test_private_reader_refuses_mode_symlink_hardlink_and_directory(self):
        with tempfile.TemporaryDirectory(prefix="dl-tmpfs-synthetic-") as directory:
            path = Path(directory) / "tmpfs-effect-v1.json"
            other = Path(directory) / "synthetic-only"
            other.write_bytes(b"{}")
            other.chmod(0o600)
            path.symlink_to(other)
            with self.assertRaises(PROOF.ContractError):
                PROOF.read_proof(str(path))
            path.unlink()
            os.link(other, path)
            with self.assertRaises(PROOF.ContractError):
                PROOF.read_proof(str(path))
            path.unlink()
            path.mkdir(mode=0o600)
            with self.assertRaises(PROOF.ContractError):
                PROOF.read_proof(str(path))
            path.rmdir()
            path.write_bytes(b"{}")
            path.chmod(0o644)
            with self.assertRaises(PROOF.ContractError):
                PROOF.read_proof(str(path))

    def test_private_reader_valid_synthetic_bytes(self):
        with tempfile.TemporaryDirectory(prefix="dl-tmpfs-synthetic-") as directory:
            path = Path(directory) / "tmpfs-effect-v1.json"
            value, context = fixture()
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o600)
            result = PROOF.validate(PROOF.read_proof(str(path)), context)
            self.assertEqual(result["admission"], "unadmitted")

    def test_private_reader_refuses_unprivate_or_symlinked_ancestry(self):
        with tempfile.TemporaryDirectory(prefix="dl-tmpfs-synthetic-") as directory:
            owned = Path(directory) / "owned"
            owned.mkdir(mode=0o700)
            path = owned / "tmpfs-effect-v1.json"
            path.write_bytes(b"{}")
            path.chmod(0o600)
            owned.chmod(0o755)
            with self.assertRaises(PROOF.ContractError):
                PROOF.read_proof(str(path))
            owned.chmod(0o700)
            link = Path(directory) / "linked"
            link.symlink_to(owned, target_is_directory=True)
            with self.assertRaises(PROOF.ContractError):
                PROOF.read_proof(str(link / "tmpfs-effect-v1.json"))


if __name__ == "__main__":
    unittest.main()
