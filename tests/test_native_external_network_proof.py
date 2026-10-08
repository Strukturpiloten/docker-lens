"""Independent private external-network controls, never native qualification."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("external_proof", ROOT / "scripts/native_external_network_proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)
RUN = "Ab12Cd34"
FILENAME = "external-network-internal-v1.json"
SHAPES = ("ExternalNetworkInternalFalse", "ExternalNetworkInternalTrue")
CHECKS = ("independent_cli", "direct_inspect", "fresh_acquisition", "selected_root",
          "schema3_empty_requests", "expected_assessment", "opposite_assessment", "identity_unchanged")
SECRET = "PRIVATE_EXTERNAL_NETWORK_CANARY"


def fixture(lane="upstream-rootful"):
    debian = lane.startswith("debian11-")
    rootless = lane.endswith("-rootless")
    context = {
        "candidate_sha": "a" * 40, "run_id": RUN, "lane": lane,
        "engine_release": "20.10.5+dfsg1" if debian else "29.8.1",
        "rendering_api": "1.41" if debian else "1.56",
        "acquisition_api": "1.41" if debian else "1.49",
        "mode": "rootless" if rootless else "rootful",
        "docker_package": "20.10.5+dfsg1-1+deb11u2" if debian else "",
        "fixture_image": "private.test/fixture:1@sha256:" + "b" * 64,
        "daemon_uid": 1000 if rootless else 0,
        "outer": {"id": "f" * 64, "name": f"dl-native-{RUN}", "owner": RUN,
                  "image": "private.test/engine:1@sha256:" + "c" * 64,
                  "data_volume": f"dl-native-data-{RUN}", "socket_source": "/private/capture/socket",
                  "privileged": True, "memory_bytes": 4294967296,
                  "cpu_quota": 200000, "cpu_period": 100000, "pids_limit": 512},
    }
    networks = []
    for internal, case, shape, native_id in zip((False, True), ("ordinary", "internal"), SHAPES,
                                               ("1" * 64, "2" * 64)):
        networks.append({"case": case, "shape": shape, "id": native_id, "name": f"dl-ext-{RUN}-{case}",
                         "owner": RUN, "internal": internal, "checks": dict.fromkeys(CHECKS, "passed"),
                         "cleanup": "absent"})
    return {"schema_version": 1, "contract": "external-network-internal-v1", "context": context,
            "shapes": list(SHAPES), "networks": networks,
            "cleanup": {"networks": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}


class ExternalNetworkProofTests(unittest.TestCase):
    def rejected(self, proof, context=None):
        with self.assertRaisesRegex(ValueError, "^invalid private external network proof$") as caught:
            PROOF.validate_external_network_proof(proof, fixture()["context"] if context is None else context)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_all_exact_lanes_require_complete_two_shape_group(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            proof = fixture(lane)
            self.assertEqual(PROOF.validate_external_network_proof(proof, proof["context"]), SHAPES)
        proof = fixture()
        proof["networks"][0]["id"] = proof["context"]["outer"]["id"]
        self.assertEqual(PROOF.validate_external_network_proof(proof, proof["context"]), SHAPES,
                         "different resource kinds may share native ID spelling")

    def test_every_required_check_and_cleanup_is_nonoptional(self):
        for index in range(2):
            for check in CHECKS:
                for replacement in (False, "failed", "unknown", SECRET):
                    proof = fixture()
                    proof["networks"][index]["checks"][check] = replacement
                    self.rejected(proof)
            proof = fixture()
            proof["networks"][index]["cleanup"] = "unknown"
            self.rejected(proof)
        for field, replacements in {
            "networks": ["unknown", SECRET], "rounds": [1, True, 2.0],
            "outstanding": [1, False, 0.0], "uncertain": [True, 0],
        }.items():
            for replacement in replacements:
                proof = fixture()
                proof["cleanup"][field] = replacement
                self.rejected(proof)

    def test_no_partial_reordered_duplicate_or_wrong_internal_shape(self):
        for mutate in range(9):
            proof = fixture()
            if mutate == 0:
                proof["networks"].pop()
            elif mutate == 1:
                proof["networks"].reverse()
            elif mutate == 2:
                proof["shapes"].reverse()
            elif mutate == 3:
                proof["networks"][1]["id"] = proof["networks"][0]["id"]
            elif mutate == 4:
                proof["networks"][0]["internal"] = None
            elif mutate == 5:
                proof["networks"][0]["internal"] = 0
            elif mutate == 6:
                proof["networks"][1]["internal"] = False
            elif mutate == 7:
                proof["networks"][0]["name"] = SECRET
            else:
                proof["networks"][0]["owner"] = SECRET
            self.rejected(proof)

    def test_independent_context_cannot_be_supplied_by_proof(self):
        for field in fixture()["context"]:
            proof = fixture()
            proof["context"][field] = SECRET
            self.rejected(proof)
        for field in fixture()["context"]["outer"]:
            proof = fixture()
            proof["context"]["outer"][field] = SECRET
            self.rejected(proof)
        for mutate in (False, 1, -1, 4294967296):
            proof = fixture()
            proof["context"]["daemon_uid"] = mutate
            self.rejected(proof, proof["context"])
        proof = fixture()
        proof["context"]["acquisition_api"] = "1.56"
        self.rejected(proof, proof["context"])

    def test_unknown_fields_and_duplicate_json_keys_refuse(self):
        for path in ((), ("context",), ("context", "outer"), ("cleanup",),
                     ("networks", 0), ("networks", 0, "checks")):
            proof = fixture()
            obj = proof
            for key in path:
                obj = obj[key]
            obj[SECRET] = SECRET
            self.rejected(proof)
        payload = json.dumps(fixture())
        for key in ("schema_version", "candidate_sha", "owner", "internal"):
            duplicate = payload.replace(f'"{key}":', f'"{key}": null, "{key}":', 1)
            with self.assertRaises(ValueError) as caught:
                json.loads(duplicate, object_pairs_hook=PROOF.unique_object)
            self.assertNotIn(SECRET, str(caught.exception))

    def test_private_file_identity_bounds_and_symlinks_refuse(self):
        for mutation in ("good", "missing", "mode", "directory", "symlink", "hardlink",
                         "oversize", "empty", "duplicate", "file_drift", "parent_drift", "owner"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                path = root / FILENAME
                proof = fixture()
                proof["context"]["outer"]["socket_source"] = str(root / "socket")
                path.write_text(json.dumps(proof))
                path.chmod(0o600)
                original_fstat = os.fstat
                if mutation == "missing":
                    path.unlink()
                elif mutation == "mode":
                    path.chmod(0o644)
                elif mutation == "directory":
                    root.chmod(0o755)
                elif mutation == "symlink":
                    path.rename(root / "original")
                    path.symlink_to(root / "original")
                elif mutation == "hardlink":
                    os.link(path, root / "second")
                elif mutation == "oversize":
                    path.write_bytes(b"x" * (16 * 1024 + 1))
                elif mutation == "empty":
                    path.write_bytes(b"")
                elif mutation == "duplicate":
                    path.write_text(path.read_text().replace('"schema_version": 1',
                                    '"schema_version": 0, "schema_version": 1'))

                def drift(fd):
                    info = original_fstat(fd)
                    selected = os.path.isfile(f"/proc/self/fd/{fd}")
                    if (mutation == "file_drift" and selected) or (mutation == "parent_drift" and not selected):
                        fields = list(info)
                        fields[1] += 1
                        return os.stat_result(fields)
                    return info

                with patch.object(PROOF.os, "fstat", side_effect=drift), \
                     patch.object(PROOF.os, "geteuid", return_value=os.geteuid() + 1 if mutation == "owner" else os.geteuid()):
                    if mutation == "good":
                        self.assertEqual(PROOF.read_external_network_proof(path, root, proof["context"]), SHAPES)
                    else:
                        with self.assertRaisesRegex(ValueError, "^invalid private external network proof$"):
                            PROOF.read_external_network_proof(path, root, proof["context"])


if __name__ == "__main__":
    unittest.main()
