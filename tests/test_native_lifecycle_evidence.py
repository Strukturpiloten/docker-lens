"""Whole-manifest lifecycle source observations, never capability admission."""

import copy
import json
import unittest

import test_native_external_network_evidence as external


class LifecycleEvidenceTests(unittest.TestCase):
    run_emit = external.ExternalNetworkEvidenceTests.run_emit
    emit = external.ExternalNetworkEvidenceTests.emit
    rerun = external.ExternalNetworkEvidenceTests.rerun

    def test_four_lanes_publish_only_unadmitted_closed_outcomes(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane):
                result, path = self.emit(lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                raw = path.read_text()
                record = json.loads(raw)
                debian = lane.startswith("debian11-")
                self.assertEqual(record["lifecycle_contract"], "lifecycle-v1")
                self.assertEqual(record["lifecycle_outcomes"], {
                    "admission": "unadmitted",
                    "probes": ["stop_timeout_effective", "health_start_interval_" + (
                        "not_effective_on_selected_api" if debian else "effective")],
                })
                for field in ("StopTimeout", "HealthStartInterval"):
                    self.assertNotIn(field, record["capability_outcome"])
                    self.assertNotIn(field, record["admitted_shapes"])
                self.assertEqual(len(record["capability_outcome"]), 31 if debian else 32)
                self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 48 if debian else 50)
                for private in ("lifecycle-term", "lifecycle-health-failure", "StartedAt", "FinishedAt",
                                "outer_before", "image_before", "cleanup", "owner",
                                "a" * 64, "f" * 64):
                    self.assertNotIn(private, raw)
                self.assertNotIn('"stop_timeout":', raw)

    def test_missing_proof_refuses_every_lane(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane):
                result, path = self.emit(lane, lifecycle_missing=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual(result.stderr.strip(), "native evidence rejected")

    def test_partial_stale_wrong_context_and_private_fields_refuse_manifest(self):
        result, path = self.emit()
        self.assertEqual(result.returncode, 0, result.stderr)
        proof_path = path.parent.parent / "lifecycle-v1.json"
        original = json.loads(proof_path.read_text())
        path.unlink()
        for mutation in ("partial", "candidate", "run", "lane", "api", "outer", "private"):
            with self.subTest(mutation=mutation):
                proof = copy.deepcopy(original)
                if mutation == "partial":
                    proof["stop_timeout"].pop()
                elif mutation == "private":
                    proof["private"] = "PRIVATE_LIFECYCLE_CANARY"
                elif mutation == "outer":
                    proof["context"]["outer"]["id"] = "e" * 64
                else:
                    key = {"candidate": "candidate_sha", "run": "run_id", "lane": "lane",
                           "api": "acquisition_api"}[mutation]
                    proof["context"][key] = {"candidate": "b" * 40, "run": "Stale001",
                                             "lane": "upstream-rootless", "api": "1.55"}[mutation]
                proof_path.write_text(json.dumps(proof))
                self.rerun(result, path)


if __name__ == "__main__":
    unittest.main()
