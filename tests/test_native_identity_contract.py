"""Independent completion/privacy controls for parameterized raw identity proof."""

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import test_native_evidence as legacy

IDENTITY_PROBES = legacy.IDENTITY_PROBES
ROOT, RUN_ID, SHA, SCRIPT = legacy.ROOT, legacy.RUN_ID, legacy.SHA, legacy.SCRIPT


CASES = (
    "inherit", "numeric_uid_gid", "numeric_uid", "named_user", "named_user_group",
    "named_user_numeric_group", "numeric_user_named_group", "missing_user",
    "missing_group", "nondirectory_workdir",
)
OUTCOMES = ("exited_zero",) * 7 + ("missing_user", "missing_group", "workdir_not_directory")
VERSION = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}


def proof_v2(lane="upstream-rootful", mode="rootful", api="1.56"):
    cases = []
    for index, (name, outcome) in enumerate(zip(CASES, OUTCOMES)):
        positive = index < 7
        records = []
        for role_index, role in enumerate(("oracle", "rendered")):
            records.append({
                "role": role, "id": f"{2 * index + role_index + 1:064x}",
                "name": f"dl-identity-{RUN_ID}-{name}-{role}", "owner": RUN_ID,
                "configured": "passed", "outcome": outcome,
                "rejection_phase": None if positive else "start",
                "runtime_uid": "passed" if positive else "not_started",
                "runtime_gid": "passed" if positive else "not_started",
                "runtime_workdir": "passed" if positive else "not_started", "cleanup": "absent",
            })
        cases.append({"case": name, "expected_outcome": outcome, "wire": "passed", "containers": records})
    return {"schema_version": 2, "candidate_sha": SHA, "lane": lane, "mode": mode,
            "rendering_api": api, "run_id": RUN_ID, "identity_contract": "container-identity-v1",
            "cases": cases, "probes": IDENTITY_PROBES}


class ParameterizedIdentityTests(unittest.TestCase):
    # Reuse input-file setup only; expected contracts above are independent of
    # the product validator, and no inherited tests execute twice.
    run_emit = legacy.NativeEvidenceTests.run_emit

    def rejected(self, proof):
        result, destination = self.run_emit(VERSION, identity=proof)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertEqual(result.stderr.strip(), "native evidence rejected")
        self.assertEqual(result.stdout, "")

    def test_all_four_lanes_map_only_complete_parameterized_raw_identity(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane):
                debian = lane.startswith("debian11")
                mode = lane.rsplit("-", 1)[1]
                api = "1.41" if debian else "1.56"
                version = {"Version": "20.10.5" if debian else "29.8.1",
                           "ApiVersion": api, "MinAPIVersion": "1.12" if debian else "1.44"}
                image = f"ghcr.io/strukturpiloten/docker-{'debian-11' if debian else '29'}-{mode}:v1.0.0@sha256:" + "b" * 64
                result, destination = self.run_emit(
                    version, lane=lane, mode=mode, image=image,
                    package="20.10.5+dfsg1-1+deb11u2" if debian else "",
                    identity=proof_v2(lane, mode, api))
                self.assertEqual(result.returncode, 0, result.stderr)
                evidence = json.loads(destination.read_text())
                self.assertEqual(evidence["identity_contract"], "container-identity-v1")
                self.assertEqual(evidence["identity_cases"], list(CASES))
                self.assertEqual(evidence["identity_probes"], IDENTITY_PROBES)
                for capability in ("ContainerUser", "ContainerWorkdir"):
                    self.assertEqual(evidence["admitted_shapes"][capability], [capability])
                    self.assertEqual(evidence["capability_outcome"][capability], "available")
                self.assertNotIn("SupplementaryGroups", evidence["admitted_shapes"])
                for private in ("dl-identity", RUN_ID, "runtime_uid", "rejection_phase", "configured"):
                    self.assertNotIn(private, destination.read_text())
                for case in proof_v2()["cases"]:
                    for record in case["containers"]:
                        self.assertNotIn(record["id"], destination.read_text())

    def test_legacy_numeric_proof_never_maps_identity_capabilities(self):
        result, destination = self.run_emit(VERSION)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(destination.read_text())
        for name in ("ContainerUser", "ContainerWorkdir"):
            self.assertNotIn(name, evidence["admitted_shapes"])
            self.assertNotIn(name, evidence["capability_outcome"])
        self.assertNotIn("identity_contract", evidence)
        self.assertNotIn("identity_cases", evidence)

    def test_v2_cannot_map_identity_on_an_unproved_rendering_api(self):
        for api in ("1.41", "1.49", "1.52", "1.57"):
            version = {**VERSION, "ApiVersion": api, "MinAPIVersion": "1.12"}
            result, destination = self.run_emit(version, identity=proof_v2(api=api))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(destination.exists())
            self.assertEqual(result.stderr.strip(), "native evidence rejected")

    def test_every_binding_case_and_record_is_required_closed_and_ordered(self):
        good = proof_v2()
        for key in good:
            for remove in (False, True):
                changed = copy.deepcopy(good)
                if remove:
                    del changed[key]
                else:
                    changed[key] = "protected-secret"
                with self.subTest(top=key, remove=remove):
                    self.rejected(changed)
        for index, case in enumerate(good["cases"]):
            changed = copy.deepcopy(good)
            del changed["cases"][index]
            self.rejected(changed)
            for key in case:
                for remove in (False, True):
                    changed = copy.deepcopy(good)
                    if remove:
                        del changed["cases"][index][key]
                    else:
                        changed["cases"][index][key] = "protected-secret"
                    self.rejected(changed)
            for role_index, record in enumerate(case["containers"]):
                for key in record:
                    for remove in (False, True):
                        changed = copy.deepcopy(good)
                        if remove:
                            del changed["cases"][index]["containers"][role_index][key]
                        else:
                            changed["cases"][index]["containers"][role_index][key] = "protected-secret"
                        with self.subTest(case=index, role=role_index, field=key, remove=remove):
                            self.rejected(changed)
        for path in ((), ("cases",), ("cases", 0), ("cases", 0, "containers"), ("cases", 0, "containers", 0)):
            changed = copy.deepcopy(good)
            node = changed
            for key in path:
                node = node[key]
            if isinstance(node, list):
                node.append(copy.deepcopy(node[0]))
            else:
                node["protected-secret"] = "protected-secret"
            self.rejected(changed)
        for key in ("cases", "probes"):
            changed = copy.deepcopy(good)
            changed[key].reverse()
            self.rejected(changed)
        changed = copy.deepcopy(good)
        changed["schema_version"] = True
        self.rejected(changed)

    def test_negative_creation_requires_attribution_and_exact_absence(self):
        good = proof_v2()
        for case in good["cases"][7:]:
            for record in case["containers"]:
                record.update(id=None, configured="not_created", rejection_phase="create")
        result, destination = self.run_emit(VERSION, identity=good)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(destination.exists())
        for index in range(10):
            for role in range(2):
                changed = proof_v2()
                changed["cases"][index]["containers"][role]["id"] = None
                self.rejected(changed)
        for index in range(7, 10):
            changed = proof_v2()
            for record in changed["cases"][index]["containers"]:
                record["rejection_phase"] = "create"
            self.rejected(changed)
            for role in range(2):
                for field, value in (("cleanup", "uncertain"), ("outcome", "timeout"),
                                     ("configured", "passed"), ("rejection_phase", "start"),
                                     ("runtime_uid", "passed")):
                    changed = copy.deepcopy(good)
                    changed["cases"][index]["containers"][role][field] = value
                    self.rejected(changed)
            changed = proof_v2()
            changed["cases"][index]["containers"][0]["rejection_phase"] = "create"
            self.rejected(changed)

    def test_ids_are_globally_distinct_not_merely_distinct_within_pairs(self):
        for case_index in range(10):
            for role in range(2):
                if (case_index, role) == (0, 0):
                    continue
                changed = proof_v2()
                changed["cases"][case_index]["containers"][role]["id"] = changed["cases"][0]["containers"][0]["id"]
                self.rejected(changed)

    def test_v2_private_file_rejects_duplicates_links_modes_and_overflow(self):
        for failure in ("oversized", "hardlink", "public", "readonly", "executable", "symlink", "fifo", "duplicate_top", "duplicate_record"):
            result, destination = self.run_emit(VERSION, identity=proof_v2())
            self.assertEqual(result.returncode, 0, result.stderr)
            root = destination.parent.parent
            path = root / "identity.json"
            destination.unlink()
            if failure == "oversized":
                path.write_bytes(b" " * 16385)
            elif failure == "hardlink":
                os.link(path, root / "alias")
            elif failure == "public":
                path.chmod(0o640)
            elif failure == "readonly":
                path.chmod(0o400)
            elif failure == "executable":
                path.chmod(0o700)
            elif failure in ("symlink", "fifo"):
                path.unlink()
                if failure == "symlink":
                    path.symlink_to(root / "version.json")
                else:
                    os.mkfifo(path, 0o600)
            else:
                content = path.read_text()
                content = content.replace('"schema_version": 2', '"schema_version": 1, "schema_version": 2') if failure == "duplicate_top" else content.replace('"configured": "passed"', '"configured": "failed", "configured": "passed"', 1)
                path.write_text(content)
            command = ["python3", str(SCRIPT), *[str(root / name) for name in (
                "version.json", "shapes.json", "source.json", "network.json", "volume.json", "volume-label.json", "identity.json")],
                str(destination), "upstream-rootful",
                "ghcr.io/strukturpiloten/docker-29-rootful:v29.8.1@sha256:" + "b" * 64,
                "rootful", "", SHA, RUN_ID]
            rejected = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(destination.exists())
            self.assertEqual(rejected.stderr.strip(), "native evidence rejected")

    def test_metadata_stability_and_owner_are_checked_on_the_open_descriptor(self):
        spec = importlib.util.spec_from_file_location("identity_emitter", SCRIPT)
        emitter = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            spec.loader.exec_module(emitter)
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "proof.json"
            path.write_text(json.dumps(proof_v2()))
            path.chmod(0o600)
            original = os.stat(path)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
            for field in fields:
                changed = types.SimpleNamespace(**{name: getattr(original, name) for name in fields})
                setattr(changed, field, getattr(changed, field) + 1)
                with self.subTest(changed=field), patch.object(emitter.os, "fstat", side_effect=[original, changed]):
                    with self.assertRaises(ValueError):
                        emitter.read_identity_proof(path, "upstream-rootful", "rootful", "1.56", SHA, RUN_ID)
            changed = types.SimpleNamespace(**{name: getattr(original, name) for name in fields})
            changed.st_uid = os.geteuid() + 1
            with patch.object(emitter.os, "fstat", return_value=changed):
                with self.assertRaises(ValueError):
                    emitter.read_identity_proof(path, "upstream-rootful", "rootful", "1.56", SHA, RUN_ID)

    def test_schema_v2_has_fixed_case_and_outcome_pairs_without_root_admission(self):
        schema = json.loads((ROOT / "docs/native-evidence.schema.json").read_text())
        definition = schema["$defs"]["native_identity_proof_v2"]
        cases = definition["properties"]["cases"]
        self.assertFalse(cases["items"])
        self.assertEqual(cases["minItems"], 10)
        self.assertEqual(cases["maxItems"], 10)
        expected = [item["allOf"][1]["properties"] for item in cases["prefixItems"]]
        self.assertEqual([item["case"]["const"] for item in expected], list(CASES))
        self.assertEqual([item["expected_outcome"]["const"] for item in expected], list(OUTCOMES))
        self.assertNotIn("identity_contract", schema["properties"])
        self.assertNotIn("identity_cases", schema["properties"])


if __name__ == "__main__":
    unittest.main()
