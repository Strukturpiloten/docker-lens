"""Emitter admission requires the entire independent health protocol."""

import copy
import json
import unittest

import test_native_evidence as legacy
from test_native_health_metadata_proof import proof


class HealthMetadataEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit

    def version(self, lane):
        return {"Version": "20.10.5+dfsg1" if lane.startswith("debian") else "29.8.1",
                "ApiVersion": "1.41" if lane.startswith("debian") else "1.56",
                "MinAPIVersion": "1.12" if lane.startswith("debian") else "1.44"}

    def emit(self, lane="upstream-rootful", health=None):
        mode = lane.rsplit("-", 1)[1]
        image = (f"ghcr.io/strukturpiloten/docker-debian-11-{mode}:v1.0.0" if lane.startswith("debian") else
                 f"ghcr.io/strukturpiloten/docker-29-{mode}:v29.8.1") + "@sha256:" + "b" * 64
        return self.run_emit(self.version(lane), lane=lane, mode=lane.rsplit("-", 1)[1],
                             image=image,
                             package="20.10.5+dfsg1-1+deb11u2" if lane.startswith("debian") else "",
                             health_metadata=health)

    def test_complete_groups_and_only_closed_projection_for_all_lanes(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane):
                result, destination = self.emit(lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(destination.read_text())
                self.assertEqual(record["candidate_sha"], legacy.SHA)
                self.assertEqual(record["health_metadata_contract"], "health-metadata-v1")
                self.assertEqual(record["health_metadata_probes"], ["ContainerCreateLabels", "ShellHealthcheck",
                                                                   "HealthStartPeriodPositive", "HealthStartPeriodZero"])
                for capability, shapes in (("ContainerLabels", ["ContainerCreateLabels"]),
                                            ("HealthShell", ["ShellHealthcheck"]),
                                            ("HealthStartPeriod", ["HealthStartPeriodZero", "HealthStartPeriodPositive"])):
                    self.assertEqual(record["admitted_shapes"][capability], shapes)
                    self.assertEqual(record["capability_outcome"][capability], "available")
                self.assertNotIn("HealthDisabled", record["admitted_shapes"])
                self.assertNotIn("HealthStartInterval", record["admitted_shapes"])
                for private in ("StartedAt", "started_at", "regression_observed_at", "dl-health-",
                                "inherited_failure", "disabled_gap_ns", "initial_attempts", "Ab12Cd34"):
                    self.assertNotIn(private, destination.read_text())

    def test_partial_foreign_or_late_only_health_proof_refuses_entire_manifest(self):
        original = proof()
        invalid = [{}, {**original, "private-canary": "PRIVATE_HEALTH_CANARY"}]
        foreign = copy.deepcopy(original)
        foreign["candidate_sha"] = "c" * 40
        invalid.append(foreign)
        partial = copy.deepcopy(original)
        partial["shapes"].pop()
        invalid.append(partial)
        late = copy.deepcopy(original)
        late["cases"][0]["containers"][0]["regression_observed_at"] = "2026-10-07T00:00:21.000000000Z"
        invalid.append(late)
        for value in invalid:
            with self.subTest():
                result, destination = self.emit(health=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())
                self.assertNotIn("PRIVATE_HEALTH_CANARY", result.stderr + result.stdout)
                self.assertIn("native evidence rejected", result.stderr)

    def test_omitted_mandatory_file_refuses_whole_manifest(self):
        result, destination = self.run_emit(self.version("upstream-rootful"), health_metadata_missing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(destination.exists())

    def test_other_api_profile_cannot_borrow_health_qualification(self):
        version = self.version("upstream-rootful")
        version["ApiVersion"] = "1.52"
        result, destination = self.run_emit(version)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(destination.exists())
