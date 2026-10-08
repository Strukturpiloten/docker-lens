"""Independent whole-manifest boundary for conditional configured binds."""

import json
import os
import subprocess
import unittest

import test_native_evidence as legacy


class BindRelabelEvidenceTests(unittest.TestCase):
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

    def test_all_four_lanes_project_complete_configured_groups_only(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane):
                result, path = self.emit(lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(path.read_text())
                self.assertEqual(record["bind_relabel_contract"], "bind-relabel-config-v1")
                self.assertEqual(record["bind_relabel_selinux_effect"], "unverified")
                self.assertEqual(record["bind_relabel_probes"], [
                    "BindMountSharedRelabelReadWrite", "BindMountSharedRelabelReadOnly",
                    "BindMountPrivateRelabelReadWrite", "BindMountPrivateRelabelReadOnly",
                ])
                for capability, shapes in (
                    ("BindRelabelShared", ["BindMountSharedRelabelReadWrite", "BindMountSharedRelabelReadOnly"]),
                    ("BindRelabelPrivate", ["BindMountPrivateRelabelReadWrite", "BindMountPrivateRelabelReadOnly"]),
                ):
                    self.assertEqual(record["admitted_shapes"][capability], shapes)
                    self.assertEqual(record["capability_outcome"][capability], "available")
                for private in ("source_boundary", "owner_uid", "source_leaf", "dl-br-", "dl-bind-relabel-"):
                    self.assertNotIn(private, path.read_text())

    def test_missing_or_incomplete_bind_proof_refuses_entire_manifest(self):
        result, path = self.emit(bind_relabel_missing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())
        self.assertEqual(result.stderr.strip(), "native evidence rejected")
        for mutation in ("effect", "cleanup", "uid", "partial", "api", "private"):
            with self.subTest(mutation=mutation):
                result, path = self.emit()
                self.assertEqual(result.returncode, 0, result.stderr)
                proof_path = path.parent.parent / "bind-relabel-config-v1.json"
                proof = json.loads(proof_path.read_text())
                if mutation == "effect":
                    proof["selinux_effect"] = "passed"
                elif mutation == "cleanup":
                    proof["cases"][2]["roles"][1]["source_cleanup"] = "unknown"
                elif mutation == "uid":
                    proof["context"]["source_boundary"]["owner_uid"] = 1
                elif mutation == "partial":
                    proof["cases"] = proof["cases"][:-1]
                elif mutation == "api":
                    proof["context"]["acquisition_api"] = "1.56"
                else:
                    proof["PRIVATE_BIND_CANARY"] = "PRIVATE_BIND_CANARY"
                proof_path.write_text(json.dumps(proof))
                path.unlink()
                rejected = subprocess.run(result.args, capture_output=True, text=True, check=False, timeout=5,
                                          env={**os.environ, "NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                                               "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                                               "NATIVE_BIND_RELABEL_DAEMON_UID": "0"})
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual(rejected.stderr.strip(), "native evidence rejected")
                self.assertNotIn("PRIVATE_BIND_CANARY", rejected.stdout + rejected.stderr)

    def test_rootless_proof_cannot_supply_its_own_expected_uid(self):
        result, path = self.emit("upstream-rootless")
        self.assertEqual(result.returncode, 0, result.stderr)
        proof_path = path.parent.parent / "bind-relabel-config-v1.json"
        proof = json.loads(proof_path.read_text())
        proof["context"]["source_boundary"]["owner_uid"] = 1001
        proof_path.write_text(json.dumps(proof))
        path.unlink()
        rejected = subprocess.run(result.args, capture_output=True, text=True, check=False, timeout=5,
                                  env={**os.environ, "NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                                       "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                                       "NATIVE_BIND_RELABEL_DAEMON_UID": "1000"})
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse(path.exists())
