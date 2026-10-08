"""Whole-manifest external network proof controls; no native qualification."""

import copy
import json
import os
import subprocess
import unittest

import test_native_evidence as legacy
from test_native_identity_contract import proof_v2

SHAPES = ["ExternalNetworkInternalFalse", "ExternalNetworkInternalTrue"]
SECRET = "PRIVATE_EXTERNAL_NETWORK_CANARY"


class ExternalNetworkEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit

    def emit(self, lane="upstream-rootful", **options):
        debian = lane.startswith("debian11-")
        mode = lane.rsplit("-", 1)[1]
        api = "1.41" if debian else "1.56"
        version = {"Version": "20.10.5+dfsg1" if debian else "29.8.1", "ApiVersion": api,
                   "MinAPIVersion": "1.12" if debian else "1.40"}
        image = (f"ghcr.io/strukturpiloten/docker-debian-11-{mode}:v1.0.0" if debian else
                 f"ghcr.io/strukturpiloten/docker-29-{mode}:v29.8.1") + "@sha256:" + "b" * 64
        # Canonical producer uses parameterized identity-v2. Preserve the separate
        # legacy identity-v1 fixture and its narrower group counts elsewhere.
        options.setdefault("identity", proof_v2(lane, mode, api))
        if debian:
            # Canonical Debian has a prescribed IPv6 boundary, unlike the port
            # suite's separate synthetic all-lanes fully observed controls.
            options.setdefault("port_probes", {
                "schema_version": 1,
                "positive": [shape for shape in legacy.PORT_SHAPES
                             if shape not in ("FixedIpv6HostPort", "EphemeralIpv6HostPort")],
                "expected_negative": [
                    {"shape": "FixedIpv6HostPort", "reason": "nested_default_bridge_ipv6_unavailable"},
                    {"shape": "EphemeralIpv6HostPort", "reason": "nested_default_bridge_ipv6_runtime_binding_absent"},
                ],
            })
        return self.run_emit(version, lane=lane, mode=mode, image=image,
                             package="20.10.5+dfsg1-1+deb11u2" if debian else "", **options)

    def rerun(self, result, destination):
        lane = destination.stem
        output = subprocess.run(result.args, capture_output=True, text=True, check=False, timeout=5,
                                env={**os.environ, "NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                                     "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                                     "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if lane.endswith("-rootless") else "0"})
        self.assertNotEqual(output.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertEqual(output.stderr.strip(), "native evidence rejected")
        self.assertNotIn(SECRET, output.stdout + output.stderr)

    def test_all_four_canonical_lanes_emit_only_complete_group_and_closed_projection(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane):
                result, path = self.emit(lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(path.read_text())
                self.assertEqual(record["external_network_contract"], "external-network-internal-v1")
                self.assertEqual(record["external_network_probes"], SHAPES)
                self.assertEqual(record["capability_outcome"]["NetworkExternalInternalExpectation"], "available")
                self.assertEqual(record["admitted_shapes"]["NetworkExternalInternalExpectation"], SHAPES)
                self.assertEqual(record["admitted_shapes"]["NetworkInternal"], ["InternalBridgeNetworkCreate"])
                self.assertEqual(len(record["capability_outcome"]), 29 if lane.startswith("debian11-") else 30)
                self.assertEqual(sum(map(len, record["admitted_shapes"].values())),
                                 46 if lane.startswith("debian11-") else 48)
                for key, expected in (
                    ("source_probes", legacy.SOURCE_PROBES), ("network_probes", legacy.NETWORK_PROBES),
                    ("volume_probes", legacy.VOLUME_PROBES), ("volume_label_probes", legacy.VOLUME_LABEL_PROBES),
                ):
                    self.assertEqual(record[key], expected)
                for private in ("daemon_uid", "dl-ext-", "owner", "cleanup", "private.test/", "checks"):
                    self.assertNotIn(private, path.read_text())

    def test_missing_proof_is_mandatory_on_every_lane(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            result, path = self.emit(lane, external_network_missing=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(path.exists())
            self.assertEqual(result.stderr.strip(), "native evidence rejected")

    def test_incomplete_stale_cross_context_and_unknown_fields_never_emit(self):
        result, path = self.emit()
        self.assertEqual(result.returncode, 0, result.stderr)
        proof_path = path.parent.parent / "external-network-internal-v1.json"
        original = json.loads(proof_path.read_text())
        path.unlink()
        for mutation in ("partial", "shape", "cleanup", "opposite", "case", "duplicate_id",
                         "candidate", "run", "lane", "mode", "uid", "api", "outer", "private"):
            with self.subTest(mutation=mutation):
                proof = copy.deepcopy(original)
                if mutation == "partial":
                    proof["networks"].pop()
                elif mutation == "shape":
                    proof["shapes"].reverse()
                elif mutation == "cleanup":
                    proof["cleanup"]["rounds"] = 1
                elif mutation == "opposite":
                    proof["networks"][0]["checks"]["opposite_assessment"] = "unknown"
                elif mutation == "case":
                    proof["networks"][0]["internal"] = None
                elif mutation == "duplicate_id":
                    proof["networks"][1]["id"] = proof["networks"][0]["id"]
                elif mutation in ("candidate", "run", "lane", "mode", "uid", "api"):
                    field = {"candidate": "candidate_sha", "run": "run_id", "lane": "lane",
                             "mode": "mode", "uid": "daemon_uid", "api": "acquisition_api"}[mutation]
                    proof["context"][field] = {"candidate": "b" * 40, "run": "Stale001",
                                               "lane": "upstream-rootless", "mode": "rootless",
                                               "uid": 1, "api": "1.56"}[mutation]
                elif mutation == "outer":
                    proof["context"]["outer"]["id"] = "e" * 64
                else:
                    proof[SECRET] = SECRET
                proof_path.write_text(json.dumps(proof))
                self.rerun(result, path)

    def test_private_file_custody_and_duplicate_keys_refuse_entire_manifest(self):
        for mutation in ("mode", "symlink", "hardlink", "duplicate_outer", "duplicate_nested", "empty", "oversize"):
            with self.subTest(mutation=mutation):
                result, path = self.emit()
                self.assertEqual(result.returncode, 0, result.stderr)
                proof_path = path.parent.parent / "external-network-internal-v1.json"
                path.unlink()
                if mutation == "mode":
                    proof_path.chmod(0o644)
                elif mutation == "symlink":
                    original = proof_path.with_name("original-private-proof")
                    proof_path.rename(original)
                    proof_path.symlink_to(original)
                elif mutation == "hardlink":
                    os.link(proof_path, proof_path.with_name("second-private-proof"))
                elif mutation.startswith("duplicate"):
                    key = "schema_version" if mutation == "duplicate_outer" else "internal"
                    proof_path.write_text(proof_path.read_text().replace(f'"{key}":', f'"{key}": null, "{key}":', 1))
                elif mutation == "empty":
                    proof_path.write_bytes(b"")
                else:
                    proof_path.write_bytes(b"x" * (16 * 1024 + 1))
                self.rerun(result, path)

    def test_disconnected_projection_schema_preserves_reviewed_root(self):
        schema = json.loads((legacy.ROOT / "docs/native-evidence.schema.json").read_text())
        probes = schema["$defs"]["external_network_probes"]
        self.assertEqual([item["const"] for item in probes["prefixItems"]], SHAPES)
        self.assertEqual((probes["minItems"], probes["maxItems"]), (2, 2))
        self.assertFalse(probes["items"])
        projection = schema["$defs"]["external_network_projection"]
        self.assertFalse(projection["additionalProperties"])
        self.assertEqual(projection["required"], ["external_network_contract", "external_network_probes"])
        root = dict(schema)
        del root["$defs"]
        self.assertNotIn("#/$defs/external_network", json.dumps(root, sort_keys=True))
        self.assertNotIn("external_network_contract", schema["properties"])
        self.assertNotIn("external_network_probes", schema["properties"])


if __name__ == "__main__":
    unittest.main()
