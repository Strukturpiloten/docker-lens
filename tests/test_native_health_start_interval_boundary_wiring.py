"""Exact invocation and whole-emitter boundary controls; no Docker runtime."""

import copy
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import test_native_external_network_evidence as external

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_health_start_interval_boundary"
TEST = "live_health_start_interval_boundary_matches_engine"
SELECTED = f"native_health_metadata_tests::lifecycle::health_start_interval_boundary::{TEST}"
SUMMARY = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
HANDOFF = "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"
SECRET = "PRIVATE_BOUNDARY_CANARY"


class HealthBoundaryWiringTests(unittest.TestCase):
    def wrapper(self, output=SUMMARY, status=0, listing=None):
        with tempfile.TemporaryDirectory(prefix="dl-boundary-wiring-") as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            calls = root / "calls.jsonl"
            cargo.write_text('''#!/usr/bin/python3
import json, os, sys
keys = ["NATIVE_HEALTH_START_INTERVAL_BOUNDARY_DEADLINE_EPOCH",
        "NATIVE_LIFECYCLE_DEADLINE_EPOCH", "NATIVE_LIFECYCLE_CLEANUP_OWNER"]
with open(os.environ["CALLS"], "a") as stream:
    stream.write(json.dumps({"argv": sys.argv[1:], "context": {key: os.environ.get(key) for key in keys}}) + "\\n")
if "--list" in sys.argv:
    print(os.environ["LIST"])
    sys.exit(0)
print(os.environ["OUTPUT"])
sys.exit(int(os.environ["STATUS"]))
''')
            cargo.chmod(0o700)
            began = time.time()
            result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, TEST],
                capture_output=True, text=True, timeout=5,
                env={**os.environ, "PATH": f"{root}:/usr/bin:/bin", "CALLS": str(calls),
                     "LIST": SELECTED + ": test" if listing is None else listing,
                     "OUTPUT": output, "STATUS": str(status),
                     "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1"})
            ended = time.time()
            return result, [json.loads(line) for line in calls.read_text().splitlines()], began, ended

    def test_exact_twentieth_invocation_has_one_original_deadline(self):
        result, calls, began, ended = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all("--lib" in call["argv"] and "--test" not in call["argv"] for call in calls))
        self.assertEqual(calls[-1]["argv"][-4:], ["--", "--ignored", "--exact", SELECTED])
        self.assertIn(SELECTED, calls[-1]["argv"])
        self.assertIn("--exact", calls[-1]["argv"])
        context = calls[-1]["context"]
        deadline = int(context["NATIVE_HEALTH_START_INTERVAL_BOUNDARY_DEADLINE_EPOCH"])
        self.assertEqual(deadline, int(context["NATIVE_LIFECYCLE_DEADLINE_EPOCH"]))
        self.assertTrue(int(began) + 180 <= deadline <= int(ended) + 180)
        self.assertEqual(context["NATIVE_LIFECYCLE_CLEANUP_OWNER"], "native_conformance_outer_v1")

    def test_absent_duplicate_zero_two_and_failed_selections_refuse(self):
        for listing in ("", SELECTED + ": test\n" + SELECTED + ": test"):
            result, calls, _, _ = self.wrapper(listing=listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 1)
        for output, status in ((SUMMARY.replace("1 passed", "0 passed"), 0),
                               (SUMMARY.replace("1 passed", "2 passed"), 0), (FAILED, 101)):
            result, calls, _, _ = self.wrapper(output, status)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 2)

    def test_private_output_is_closed_and_cleanup_handoff_is_not_success(self):
        output = ("DOCKERLENS_NATIVE_CHECK: health_start_interval_boundary_configuration\n"
            f"thread '{SELECTED}' panicked at src/native_health_start_interval_boundary_tests.rs:123:4:\n{SECRET}\n"
            "DOCKERLENS_NATIVE_CHECK: health_start_interval_boundary_cleanup\n"
            "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + HANDOFF + "\n" + FAILED)
        result, _, _, _ = self.wrapper(output, 101)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source=native_health_start_interval_boundary_tests line=123 column=4", result.stderr)
        self.assertIn("health_start_interval_boundary_configuration", result.stderr)
        self.assertIn(HANDOFF, result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        for handoff in (HANDOFF, "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified"):
            result, _, _, _ = self.wrapper(handoff + "\n" + SUMMARY)
            self.assertNotEqual(result.returncode, 0)
        result, _, _, _ = self.wrapper(HANDOFF + " " + SECRET + "\n" + FAILED, 101)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertNotIn(HANDOFF, result.stderr)


class HealthBoundaryEvidenceTests(unittest.TestCase):
    run_emit = external.ExternalNetworkEvidenceTests.run_emit
    emit = external.ExternalNetworkEvidenceTests.emit
    rerun = external.ExternalNetworkEvidenceTests.rerun

    def test_all_lanes_emit_only_closed_unadmitted_configuration_outcomes(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            result, path = self.emit(lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads(path.read_text())
            debian = lane.startswith("debian11-")
            self.assertEqual(record["health_start_interval_boundary_contract"], "health-start-interval-boundary-v1")
            self.assertEqual(record["health_start_interval_boundary_outcomes"], {
                "admission": "unadmitted", "scope": "created_configuration_only",
                "probes": ["omission_configured_absent", "literal_zero_configured_absent",
                           "cli_zero_client_unknown_flag" if debian else "cli_zero_configured_absent"],
            })
            self.assertEqual(len(record["capability_outcome"]), 30 if debian else 31)
            self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 47 if debian else 49)
            self.assertNotIn("HealthStartInterval", record["capability_outcome"])
            self.assertNotIn("HealthStartInterval", record["admitted_shapes"])
            for private in ("dl-hsi-", "StartInterval", "StartedAt", "client_exit", '"configured":', '"cleanup":', SECRET):
                self.assertNotIn(private, path.read_text())

    def test_missing_proof_refuses_all_lanes_without_publishing(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            result, path = self.emit(lane, health_boundary_missing=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(path.exists())
            self.assertEqual(result.stderr.strip(), "native evidence rejected")

    def test_partial_context_readback_and_cleanup_mutations_refuse_whole_emitter(self):
        result, path = self.emit()
        self.assertEqual(result.returncode, 0, result.stderr)
        proof_path = path.parent.parent / "health-start-interval-boundary-v1.json"
        original = json.loads(proof_path.read_text())
        path.unlink()
        for mutation in ("partial", "candidate", "outer", "readback", "request", "cleanup", "private"):
            proof = copy.deepcopy(original)
            if mutation == "partial":
                proof["cases"].pop()
            elif mutation == "candidate":
                proof["context"]["candidate_sha"] = "b" * 40
            elif mutation == "outer":
                proof["context"]["outer"]["id"] = "e" * 64
            elif mutation == "readback":
                proof["cases"][0]["records"][0]["configured"]["Config"]["Healthcheck"]["StartInterval"] = 0
            elif mutation == "request":
                proof["cases"][1]["records"][1]["request_member"] = "absent"
            elif mutation == "cleanup":
                proof["cleanup"]["outstanding"] = 1
            else:
                proof["private"] = SECRET
            proof_path.write_text(json.dumps(proof))
            self.rerun(result, path)


if __name__ == "__main__":
    unittest.main()
