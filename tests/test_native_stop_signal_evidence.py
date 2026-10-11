"""Whole-manifest refusal and closed projection without changing admission."""
import json
import unittest
import test_native_evidence as legacy
import test_native_external_network_evidence as external_evidence


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

    def test_every_sealed_profile_still_withholds_stop_signal(self):
        catalogue = (legacy.ROOT / "src/reviewed_catalog.rs").read_text()
        self.assertNotIn("Capability::StopSignal", catalogue)
        self.assertNotIn("NativeCapabilityShape::StopSignal", catalogue)


if __name__ == "__main__":
    unittest.main()
