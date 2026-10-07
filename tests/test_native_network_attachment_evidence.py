"""Independent whole-manifest boundary for attachment/alias/label proof."""

import json
import os
import subprocess
import unittest

import test_native_evidence as legacy


class NetworkAttachmentEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit

    def emit(self, lane="upstream-rootful", **options):
        debian = lane.startswith("debian11-")
        mode = lane.rsplit("-", 1)[1]
        version = {"Version": "20.10.5+dfsg1" if debian else "29.8.1",
                   "ApiVersion": "1.41" if debian else "1.56",
                   "MinAPIVersion": "1.12" if debian else "1.40"}
        image = (f"ghcr.io/strukturpiloten/docker-debian-11-{mode}:v1.0.0" if debian else
                 f"ghcr.io/strukturpiloten/docker-29-{mode}:v29.8.1") + "@sha256:" + "b" * 64
        return self.run_emit(version, lane=lane, mode=mode, image=image,
                             package="20.10.5+dfsg1-1+deb11u2" if debian else "", **options)

    def test_complete_native_groups_project_only_closed_markers_for_all_lanes(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane):
                result, path = self.emit(lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(path.read_text())
                self.assertEqual(record["network_attachment_contract"], "network-attachments-v1")
                self.assertEqual(record["network_attachment_probes"], ["NetworkCreateLabels", "NetworkPrimaryAliases",
                                                                      "NetworkSecondaryAliases", "NetworkSecondaryConnect"])
                for capability, shapes in (("NetworkLabels", ["NetworkCreateLabels"]),
                                            ("NetworkAliases", ["NetworkPrimaryAliases", "NetworkSecondaryAliases"]),
                                            ("NetworkMultipleAttachment", ["NetworkSecondaryConnect"])):
                    self.assertEqual(record["admitted_shapes"][capability], shapes)
                    self.assertEqual(record["capability_outcome"][capability], "available")
                self.assertEqual(record["network_probes"], legacy.NETWORK_PROBES)
                for private in ("socket_source", "data_volume", "outer", "roles", "dl-na-", "Ab12Cd34"):
                    self.assertNotIn(private, record)
                    if private != "outer":
                        self.assertNotIn(private, path.read_text())

    def test_old_static_network_markers_cannot_replace_missing_new_proof(self):
        result, path = self.emit(network_attachment_missing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())
        self.assertIn("native evidence rejected", result.stderr)

    def test_effect_cleanup_context_or_acquisition_failures_refuse_entire_manifest(self):
        for mutation in ("effect", "cleanup", "context", "api", "private"):
            with self.subTest(mutation=mutation):
                result, path = self.emit()
                self.assertEqual(result.returncode, 0, result.stderr)
                proof_path = path.parent.parent / "network-attachments-v1.json"
                proof = json.loads(proof_path.read_text())
                if mutation == "effect":
                    proof["roles"][1]["checks"]["secondary"]["shared_dns"] = "failed"
                elif mutation == "cleanup":
                    proof["cleanup"]["uncertain"] = True
                elif mutation == "context":
                    proof["context"]["outer"]["id"] = "c" * 64
                elif mutation == "api":
                    proof["context"]["acquisition_api"] = "1.56"
                else:
                    proof["PRIVATE_ATTACHMENT_CANARY"] = "PRIVATE_ATTACHMENT_CANARY"
                proof_path.write_text(json.dumps(proof))
                path.unlink()
                rejected = subprocess.run(result.args, capture_output=True, text=True, check=False, timeout=5,
                                          env={**os.environ, "NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                                               "NATIVE_OUTER_CONTAINER_ID": "f" * 64})
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(path.exists())
                self.assertIn("native evidence rejected", rejected.stderr)
                self.assertNotIn("PRIVATE_ATTACHMENT_CANARY", rejected.stdout + rejected.stderr)
