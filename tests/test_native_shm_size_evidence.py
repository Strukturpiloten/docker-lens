"""Three mandatory private families add observations, never admission."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import unittest

import test_native_evidence as legacy
import test_native_external_network_evidence as canonical

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = ("shm_size", "supplementary_groups", "kernel_settings")
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SECRET = "PRIVATE_NEW_FAMILY_CANARY"


class SourceFamilyEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit
    emit = canonical.ExternalNetworkEvidenceTests.emit

    def rerun(self, result, destination, backend):
        environment = {**os.environ, "NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                       "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                       "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if destination.stem.endswith("-rootless") else "0"}
        environment.pop("NATIVE_OUTER_ENGINE", None)
        if backend is not None:
            environment["NATIVE_OUTER_ENGINE"] = backend
        return subprocess.run(result.args, env=environment, capture_output=True, text=True, timeout=5, check=False)

    def test_all_four_lanes_and_both_backends_keep_admission_maps_unchanged(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                with self.subTest(lane=lane, backend=backend):
                    result, path = self.emit(lane, outer_backend=backend)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(result.args) - 2, 19)
                    record = json.loads(path.read_text())
                    self.assertEqual(len(record["capability_outcome"]), 31 if lane.startswith("debian11-") else 32)
                    self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 48 if lane.startswith("debian11-") else 50)
                    for family in FAMILIES:
                        self.assertEqual(record[family + "_contract"], family.replace("_", "-") + "-v1")
                        self.assertEqual(record[family + "_outcomes"]["admission"], "unadmitted")
                        self.assertEqual(set(record[family + "_outcomes"]), {"admission", "scope", "outcome"})
                    for capability in ("ShmSize", "SupplementaryGroups", "SecurityOptions", "Sysctls", "SysctlIpv4Forward", "PidsLimit", "UlimitNofile"):
                        self.assertNotIn(capability, record["capability_outcome"])
                        self.assertNotIn(capability, record["admitted_shapes"])
                    for protected in ("daemon_uid", "ordinary_calls", "ordinary_bytes", "dl-shm-", "dl-sg-", "dl-ks-", "ipc_namespace", "writer_pid"):
                        self.assertNotIn(protected, path.read_text())

    def test_each_fixed_proof_is_mandatory_before_any_manifest(self):
        for family in FAMILIES:
            for backend in ("podman", "docker"):
                result, path = self.emit(outer_backend=backend, **{family + "_missing": True})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual(result.stderr.strip(), "native evidence rejected")

    def test_stale_or_partial_family_refuses_the_whole_manifest(self):
        for family in FAMILIES:
            result, destination = self.emit()
            self.assertEqual(result.returncode, 0, result.stderr)
            path = destination.parent.parent / (family.replace("_", "-") + "-v1.json")
            original = json.loads(path.read_text())
            destination.unlink()
            for mutation in ("scope", "partial", "calls", "byte_floor", "cleanup", "private"):
                proof = deepcopy(original)
                if mutation == "scope":
                    proof["context"]["outer"]["id"] = "e" * 64
                elif mutation == "partial":
                    proof["cases"].pop()
                elif mutation == "calls":
                    proof["accounting"]["ordinary_calls"] += 2
                elif mutation == "byte_floor":
                    proof["accounting"]["ordinary_bytes"] = 524288
                elif mutation == "cleanup":
                    proof["cleanup"]["uncertain"] = True
                else:
                    proof[SECRET] = SECRET
                path.write_text(json.dumps(proof))
                rejected = self.rerun(result, destination, "podman")
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(destination.exists())
                self.assertEqual(rejected.stderr.strip(), "native evidence rejected")
                self.assertNotIn(SECRET, rejected.stdout + rejected.stderr)

    def test_emitter_backend_is_independent_required_and_not_a_podman_fallback(self):
        result, path = self.emit()
        self.assertEqual(result.returncode, 0, result.stderr)
        path.unlink()
        for backend in (None, "", "Docker", "unknown", "docker"):
            # Docker is canonical but these private counters are Podman-authored.
            rejected = self.rerun(result, path, backend)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(path.exists())
            self.assertEqual(rejected.stderr.strip(), "native evidence rejected")

    def test_every_new_reader_runs_immediately_and_before_apparmor_nonacceptance(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        for family, test in (("shm_size", "live_shm_size_effects_match_engine"),
                             ("supplementary_groups", "live_supplementary_groups_match_engine"),
                             ("kernel_settings", "live_kernel_settings_match_engine")):
            child = source.index('"$(dirname "$0")/run-exact-native-test.sh" native_' + family + " " + test)
            reader = source.index('python3 "$script_dir/native_' + family + '_proof.py"', child)
            between = source[child:reader]
            self.assertNotIn("run-exact-native-test.sh", between.split("\n", 1)[1])
            self.assertNotIn("DOCKERLENS_NATIVE_EVIDENCE_DIR", between)
            self.assertIn("\n)\n", between)
            self.assertLess(reader, source.index('if [[ -n ${apparmor_profile:-} ]]; then', reader))


if __name__ == "__main__":
    unittest.main()
