"""PIDs27 raw publication requires a real private file re-read, never admission."""

import hashlib
import json
import unittest

import test_native_evidence as legacy
import test_native_external_network_evidence as canonical
from test_native_pids_proof import fixture as pids_fixture, reader

LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SECRET = "PRIVATE_PIDS_CANARY"
OUTCOMES = {
    "admission": "unadmitted", "scope": "controlled_live_leaf_enforcement_only",
    "outcome": "leaf_enforcement_with_higher_capacity_controls",
    "qualification": "requires_complete_lane_exit_and_fresh_aggregate",
}


def change_proof(root, change):
    path = root / "pids-v1.json"
    proof = json.loads(path.read_text())
    change(proof)
    path.write_text(json.dumps(proof))


def rebind_artifact(root, change):
    """Keep both recorded copies consistent to test independent disk/source checks."""
    path = root / "socket/pids-worker/native-pids-worker.json"
    manifest = json.loads(path.read_text())
    change(manifest)
    path.write_text(json.dumps(manifest))
    change_proof(root, lambda proof: proof.update(artifact=manifest))


class PidsEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit
    emit = canonical.ExternalNetworkEvidenceTests.emit

    def reject(self, mutate=None, **options):
        result, destination = self.emit(pids_mutate=mutate, **options)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertFalse(destination.parent.exists())
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "native evidence rejected\n")
        self.assertNotIn(SECRET, result.stderr)

    def test_four_lanes_and_both_backends_add_only_closed_unadmitted_metadata(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                with self.subTest(lane=lane, backend=backend):
                    result, path = self.emit(lane, outer_backend=backend)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(result.args) - 2, 19)
                    record = json.loads(path.read_text())
                    self.assertEqual(record["pids_contract"], "pids-v1")
                    self.assertEqual(record["pids_outcomes"], OUTCOMES)
                    self.assertEqual(len(record["capability_outcome"]), 31 if lane.startswith("debian11-") else 32)
                    self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 48 if lane.startswith("debian11-") else 50)
                    for capability in ("PidsLimit", "UlimitNofile"):
                        self.assertNotIn(capability, record["capability_outcome"])
                        self.assertNotIn(capability, record["admitted_shapes"])
                    for private in (legacy.RUN_ID, "dl-pids-", "socket/pids-worker", "0123456789abcdef", "build_tools", "source_samples", "artifact_copy"):
                        self.assertNotIn(private, path.read_text())
                    self.assertEqual(record["rendering_api"], "1.41" if lane.startswith("debian11-") else "1.56")
                    self.assertEqual(record["acquisition_api"], "1.41" if lane.startswith("debian11-") else "1.49")

    def test_missing_proof_rejects_legacy_twenty_six_family_evidence(self):
        self.reject(pids_missing=True)

    def test_context_replay_and_forged_admission_refuse_the_whole_manifest(self):
        for key, value in (("candidate_sha", "e" * 40), ("run_id", "Stale123"),
                           ("lane", "upstream-rootless"), ("engine_release", "29.7.0"),
                           ("api_version", "1.49"), ("mode", "rootless"), ("outer_backend", "docker"),
                           ("outer_id", "e" * 64), ("fixture_image", "docker.io/library/busybox:replayed@sha256:" + "e" * 64)):
            with self.subTest(context=key):
                self.reject(lambda root: change_proof(root, lambda proof: proof["context"].update({key: value})))
        for change in (lambda proof: proof.update(capability_admission=["PidsLimit"]),
                       lambda proof: proof.update(catalogue_admission=True),
                       lambda proof: proof.update(private=SECRET),
                       lambda proof: proof["cases"].pop(),
                       lambda proof: proof["cases"][0]["worker_events"][3].update(errno=12),
                       lambda proof: proof["context"]["outer"].update(image=SECRET)):
            with self.subTest(change=change):
                self.reject(lambda root: change_proof(root, change))

    def test_internally_valid_other_run_and_backend_proofs_are_not_their_own_oracle(self):
        for replay in ("run", "backend", "engine", "outer"):
            def mutate(root):
                path = root / "pids-v1.json"
                original = json.loads(path.read_text())
                context = original["context"]
                if replay == "run":
                    context["run_id"] = "Stale123"
                    context["outer"].update(name="dl-native-Stale123", owner="Stale123",
                                            data_volume="dl-native-data-Stale123")
                elif replay == "backend":
                    context["outer_backend"] = "docker"
                elif replay == "engine":
                    context["engine_release"] = "29.7.0"
                else:
                    context["outer_id"] = "e" * 64
                    context["outer"]["id"] = "e" * 64
                proof = pids_fixture(expected_context=context)
                proof["artifact"] = original["artifact"]
                proof["measured"]["artifact_copy"]["sha256"] = original["artifact"]["sha256"]
                self.assertEqual(reader.validate_pids_proof(proof, context),
                                 {"contract": "pids-v1", "capability_admission": [], "catalogue_admission": False})
                path.write_text(json.dumps(proof))
            with self.subTest(replay=replay):
                self.reject(mutate)

    def test_proof_custody_and_malformed_bytes_are_rechecked(self):
        for fault in ("mode", "symlink", "hardlink", "truncated", "oversize"):
            def mutate(root):
                path = root / "pids-v1.json"
                if fault == "mode":
                    path.chmod(0o644)
                elif fault in ("symlink", "hardlink"):
                    moved = root / "replayed-private.json"
                    path.rename(moved)
                    if fault == "symlink":
                        path.symlink_to(moved)
                    else:
                        path.hardlink_to(moved)
                else:
                    path.write_bytes(b"{" + SECRET.encode() if fault == "truncated" else b" " * 131073)
            with self.subTest(fault=fault):
                self.reject(mutate)

    def test_real_artifact_and_every_raw_receipt_are_mandatory(self):
        for name in ("native-pids-worker", "native-pids-worker.json", "native-pids-worker-build.log",
                     "native-pids-worker-driver.py", "native-pids-worker-ld.py",
                     "native-pids-worker-link.json", "native-pids-worker-link.d"):
            for fault in ("missing", "tampered"):
                def mutate(root):
                    path = root / "socket/pids-worker" / name
                    if fault == "missing":
                        path.unlink()
                    else:
                        path.write_bytes(path.read_bytes() + SECRET.encode())
                with self.subTest(name=name, fault=fault):
                    self.reject(mutate)

    def test_matching_forged_source_receipts_cannot_replace_current_sources(self):
        for field in ("source_sha256", "controller_source_sha256", "cargo_lock_sha256", "cargo_manifest_sha256"):
            with self.subTest(field=field):
                self.reject(lambda root: rebind_artifact(root, lambda manifest: manifest.update({field: "0" * 64})))

    def test_rehashed_non_elf_is_rejected_by_actual_binary_inspection(self):
        def mutate(root):
            path = root / "socket/pids-worker/native-pids-worker"
            data = b"BAD!" + path.read_bytes()[4:]
            path.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            def change(manifest):
                manifest["sha256"] = digest
                manifest["build_tools"]["invocation"]["output_sha256"] = digest
            rebind_artifact(root, change)
            change_proof(root, lambda proof: proof["measured"]["artifact_copy"].update(sha256=digest))
        self.reject(mutate)

    def test_valid_private_build_log_never_reaches_public_output(self):
        def mutate(root):
            data = SECRET.encode()
            (root / "socket/pids-worker/native-pids-worker-build.log").write_bytes(data)
            rebind_artifact(root, lambda manifest: manifest.update(
                build_log_size=len(data), build_log_sha256=hashlib.sha256(data).hexdigest()))
        result, destination = self.emit(pids_mutate=mutate)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(SECRET, destination.read_text() + result.stdout + result.stderr)

    def test_schema_documents_only_the_optional_raw_projection(self):
        schema = json.loads((legacy.ROOT / "docs/native-evidence.schema.json").read_text())
        projection = schema["$defs"]["pids_native_source_projection"]
        self.assertFalse(projection["additionalProperties"])
        self.assertEqual(set(projection["required"]), {"pids_contract", "pids_outcomes"})
        self.assertEqual(projection["properties"]["pids_contract"], {"const": "pids-v1"})
        outcomes = schema["$defs"]["pids_native_source_outcomes"]
        self.assertFalse(outcomes["additionalProperties"])
        self.assertEqual(set(outcomes["required"]), set(OUTCOMES))
        self.assertEqual(outcomes["properties"], {key: {"const": value} for key, value in OUTCOMES.items()})
        self.assertNotIn("pids_contract", schema["properties"])
        self.assertNotIn("pids_outcomes", schema["required"])


if __name__ == "__main__":
    unittest.main()
