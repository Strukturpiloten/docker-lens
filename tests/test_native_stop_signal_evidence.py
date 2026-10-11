"""Whole-manifest refusal and reviewed StopSignal singleton admission only."""
import json
import unittest
import test_native_evidence as legacy
import test_native_external_network_evidence as external_evidence
import test_reviewed_catalog as reviewed


class StopSignalEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit
    emit = external_evidence.ExternalNetworkEvidenceTests.emit

    def test_complete_effect_group_on_every_lane(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            result, path = self.emit(lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads(path.read_text())
            self.assertEqual(record["stop_signal_contract"], "stop-signal-v1")
            self.assertEqual(record["stop_signal_probes"], ["StopSignal"])
            self.assertEqual(record["admitted_shapes"]["StopSignal"], ["StopSignal"])
            self.assertEqual(record["capability_outcome"]["StopSignal"], "available")
            for private in ("dl-stop-", "pid1-traps-ready", "started_at", "finished_at", "borrowed_image", "exit_code", "Ab12Cd34"):
                self.assertNotIn(private, path.read_text())

    def test_missing_partial_or_foreign_proof_refuses_manifest(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            for options in ({"stop_signal_missing": True}, {"stop_signal": {}}, {"stop_signal": "PRIVATE_CANARY"}):
                result, path = self.emit(lane, **options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual(result.stderr.strip(), "native evidence rejected")
                self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)

    def test_every_sealed_profile_binds_reviewed_complete_stop_signal_group_only(self):
        source = (legacy.ROOT / "src/reviewed_catalog.rs").read_text()
        for prefix in ("REVIEWED", "UPSTREAM"):
            capabilities = source.split(f"const {prefix}_CAPABILITIES:", 1)[1].split("];", 1)[0]
            shapes = source.split(f"const {prefix}_SHAPES:", 1)[1].split("];", 1)[0]
            self.assertIn("Capability::StopSignal,", capabilities)
            self.assertIn("NativeCapabilityShape::StopSignal,", shapes)
            self.assertNotIn("Capability::HealthStartInterval,", capabilities)
            self.assertNotIn("Capability::StopTimeout,", capabilities)
        records = reviewed.bind_cohorts(reviewed.hashed_json("reviewed"),
                                       reviewed.hashed_json("native"), reviewed.COHORTS)
        for lane, (_, record) in records[reviewed.STOP_SIGNAL_CANDIDATE, reviewed.STOP_SIGNAL_RUN].items():
            groups = {entry["name"]: entry["admitted_shapes"] for entry in record["capabilities"]}
            prior = reviewed.EXTERNAL_SHAPES if lane.startswith("debian11-") else reviewed.EXTERNAL_UPSTREAM_SHAPES
            self.assertEqual(groups.pop("StopSignal"), ["StopSignal"])
            self.assertEqual(groups, prior)


if __name__ == "__main__":
    unittest.main()
