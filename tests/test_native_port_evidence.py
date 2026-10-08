"""Independent complete-group expectations for future native port manifests."""

import copy
import json
import re
import unittest

import test_native_evidence as legacy
from test_native_identity_contract import proof_v2


PORT_GROUPS = {
    "PortHostIpv4": ["FixedIpv4HostPort", "EphemeralIpv4HostPort"],
    "PortHostIpv6": ["FixedIpv6HostPort", "EphemeralIpv6HostPort"],
    "PortMultipleBindings": ["MultipleFixedPortBindings", "MultipleEphemeralPortBindings"],
    "PortExposeOnly": ["ExposedOnlyPort"],
    "PortEphemeral": ["EphemeralHostPort"],
}
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
IPV6_SHAPES = ("FixedIpv6HostPort", "EphemeralIpv6HostPort")
DEBIAN_REASONS = (
    "nested_default_bridge_ipv6_unavailable",
    "nested_default_bridge_ipv6_runtime_binding_absent",
)


class PortCapabilityEvidenceTests(unittest.TestCase):
    # Reuse private input setup only, never the producer's mapping or validator.
    run_emit = legacy.NativeEvidenceTests.run_emit

    def emit_lane(self, lane, identity_version, probes=None, proof_override=None):
        debian = lane.startswith("debian11-")
        mode = lane.rsplit("-", 1)[1]
        api = "1.41" if debian else "1.56"
        release = "20.10.5+dfsg1" if debian else "29.8.1"
        version = {"Version": release, "ApiVersion": api,
                   "MinAPIVersion": "1.12" if debian else "1.44"}
        image = (f"ghcr.io/strukturpiloten/docker-{'debian-11' if debian else '29'}-{mode}:"
                 "v1.0.0@sha256:" + "b" * 64)
        identity = (proof_v2(lane, mode, api) if identity_version == 2 else
                    legacy.identity_proof(lane, mode, api, legacy.SHA))
        return self.run_emit(version, lane=lane, mode=mode, image=image,
                             package="20.10.5+dfsg1-1+deb11u2" if debian else "",
                             identity=identity, port_probes=probes,
                             port_proof_override=proof_override)

    def expected_groups(self, identity_version, ipv6=True):
        groups = {**legacy.EXPECTED_RAW_SHAPES, **PORT_GROUPS}
        if not ipv6:
            del groups["PortHostIpv6"]
        if identity_version == 2:
            groups.update({"ContainerUser": ["ContainerUser"],
                           "ContainerWorkdir": ["ContainerWorkdir"]})
        return groups

    def assert_groups(self, destination, identity_version, ipv6=True):
        record = json.loads(destination.read_text(encoding="utf-8"))
        expected = self.expected_groups(identity_version, ipv6)
        self.assertEqual(record["admitted_shapes"], expected)
        self.assertEqual(record["capability_outcome"], {name: "available" for name in expected})
        self.assertEqual(len(expected), (30 if identity_version == 2 else 28) - (not ipv6))
        self.assertEqual(sum(map(len, expected.values())),
                         (48 if identity_version == 2 else 46) - (0 if ipv6 else 2))
        self.assertEqual("identity_contract" in record, identity_version == 2)
        self.assertEqual("identity_cases" in record, identity_version == 2)
        for private in (legacy.RUN_ID, "dl-identity-", "configured_user", "cleanup"):
            self.assertNotIn(private, destination.read_text(encoding="utf-8"))
        return record

    def assert_rejected(self, result, destination):
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr.strip(), "native evidence rejected")

    def test_observed_port_groups_are_exact_for_every_lane_and_both_identity_versions(self):
        for lane in LANES:
            for identity_version in (1, 2):
                with self.subTest(lane=lane, identity_version=identity_version):
                    result, destination = self.emit_lane(lane, identity_version)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    record = self.assert_groups(destination, identity_version)
                    self.assertEqual(record["port_probes"], [
                        {"shape": shape, "outcome": "observed"} for shape in legacy.PORT_SHAPES
                    ])

    def test_each_prescribed_debian_negative_withholds_only_the_complete_ipv6_group(self):
        for lane in LANES[:2]:
            for identity_version in (1, 2):
                for reason in DEBIAN_REASONS:
                    for negatives in ((IPV6_SHAPES[0],), (IPV6_SHAPES[1],), IPV6_SHAPES):
                        with self.subTest(lane=lane, identity_version=identity_version,
                                          reason=reason, negatives=negatives):
                            probes = {"schema_version": 1,
                                      "positive": [s for s in legacy.PORT_SHAPES if s not in negatives],
                                      "expected_negative": [
                                          {"shape": s, "reason": reason} for s in negatives
                                      ]}
                            result, destination = self.emit_lane(lane, identity_version, probes)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            record = self.assert_groups(destination, identity_version, ipv6=False)
                            self.assertEqual(record["port_probes"], [
                                {"shape": s, "outcome": "expected_negative", "reason": reason}
                                if s in negatives else {"shape": s, "outcome": "observed"}
                                for s in legacy.PORT_SHAPES
                            ])

    def test_missing_or_duplicate_group_member_rejects_the_whole_manifest(self):
        for lane in LANES:
            for identity_version in (1, 2):
                for group, required in PORT_GROUPS.items():
                    for member in required:
                        for invalid in ([s for s in legacy.PORT_SHAPES if s != member],
                                        [*legacy.PORT_SHAPES, member]):
                            with self.subTest(lane=lane, identity_version=identity_version,
                                              group=group, member=member, invalid=invalid):
                                probes = {"schema_version": 1, "positive": invalid,
                                          "expected_negative": []}
                                self.assert_rejected(*self.emit_lane(lane, identity_version, probes))

    def test_noncanonical_or_unrecognized_outcomes_reject_all_groups(self):
        malformed = [
            {"schema_version": 1, "positive": legacy.PORT_SHAPES[::-1], "expected_negative": []},
            {"schema_version": 1, "positive": [*legacy.PORT_SHAPES, "private-canary"], "expected_negative": []},
            {"schema_version": 1, "positive": [42, *legacy.PORT_SHAPES[1:]], "expected_negative": []},
            {"schema_version": True, "positive": legacy.PORT_SHAPES, "expected_negative": []},
            {**legacy.PORT_PROBES, "private-canary": "secret"},
            {"schema_version": 1, "positive": [], "expected_negative": []},
        ]
        for lane in LANES:
            for identity_version in (1, 2):
                for probes in malformed:
                    with self.subTest(lane=lane, identity_version=identity_version, probes=probes):
                        self.assert_rejected(*self.emit_lane(lane, identity_version, probes))

    def test_unprescribed_negative_cannot_be_a_partial_positive_manifest(self):
        for lane in LANES:
            for identity_version in (1, 2):
                for member in legacy.PORT_SHAPES:
                    reason = "private-canary" if member in IPV6_SHAPES else DEBIAN_REASONS[0]
                    probes = {"schema_version": 1,
                              "positive": [s for s in legacy.PORT_SHAPES if s != member],
                              "expected_negative": [{"shape": member, "reason": reason}]}
                    with self.subTest(lane=lane, identity_version=identity_version, member=member):
                        self.assert_rejected(*self.emit_lane(lane, identity_version, probes))
        for lane in LANES[2:]:
            for reason in DEBIAN_REASONS:
                probes = {"schema_version": 1,
                          "positive": [s for s in legacy.PORT_SHAPES if s not in IPV6_SHAPES],
                          "expected_negative": [{"shape": s, "reason": reason} for s in IPV6_SHAPES]}
                self.assert_rejected(*self.emit_lane(lane, 2, probes))

    def test_port_bindings_cleanup_and_identity_still_gate_all_groups(self):
        for lane in LANES:
            mode = lane.rsplit("-", 1)[1]
            debian = lane.startswith("debian11-")
            proof = legacy.port_proof(lane, mode, "1.41" if debian else "1.56",
                                      legacy.SHA, "20.10.5+dfsg1" if debian else "29.8.1")
            for identity_version in (1, 2):
                for field in ("candidate_sha", "lane", "engine_release", "rendering_api",
                              "daemon_mode", "run_id", "cleanup", "kind"):
                    invalid = copy.deepcopy(proof)
                    invalid[field] = "private-canary"
                    with self.subTest(lane=lane, identity_version=identity_version, field=field):
                        self.assert_rejected(*self.emit_lane(lane, identity_version, proof_override=invalid))

    def test_independent_port_groups_match_required_for_and_exact_lane_admission(self):
        source = (legacy.ROOT / "src/version.rs").read_text(encoding="utf-8")
        for capability, expected in PORT_GROUPS.items():
            match = re.search(rf"Capability::{capability}\s*=>\s*(?:\{{\s*)?Some\(&\[(.*?)\]\)",
                              source, re.DOTALL)
            self.assertIsNotNone(match, capability)
            self.assertEqual(re.findall(r"Self::(\w+)", match.group(1)), expected)
        self.assertEqual(len(legacy.SHAPES), 10)
        self.assertEqual(len(legacy.EXPECTED_RAW_SHAPES), 23)
        catalogue = (legacy.ROOT / "src/reviewed_catalog.rs").read_text(encoding="utf-8")
        capabilities = catalogue.split("const REVIEWED_CAPABILITIES:", 1)[1].split("];", 1)[0]
        shapes = catalogue.split("const REVIEWED_SHAPES:", 1)[1].split("];", 1)[0]
        common_names = re.findall(r"Capability::(\w+)", capabilities)
        common_shapes = re.findall(r"NativeCapabilityShape::(\w+)", shapes)
        self.assertEqual(len(common_names), 29)
        self.assertEqual(len(common_shapes), 46)
        self.assertEqual(set(PORT_GROUPS) - set(common_names), {"PortHostIpv6"})
        self.assertNotIn("FixedIpv6HostPort", common_shapes)
        self.assertNotIn("EphemeralIpv6HostPort", common_shapes)
        for name, required in PORT_GROUPS.items():
            if name != "PortHostIpv6":
                self.assertTrue(set(required).issubset(common_shapes))
        upstream = catalogue.split("const UPSTREAM_CAPABILITIES:", 1)[1].split("];", 1)[0]
        upstream_shapes = catalogue.split("const UPSTREAM_SHAPES:", 1)[1].split("];", 1)[0]
        upstream_names = re.findall(r"Capability::(\w+)", upstream)
        upstream_shape_names = re.findall(r"NativeCapabilityShape::(\w+)", upstream_shapes)
        self.assertEqual(len(upstream_names), 30)
        self.assertEqual(len(upstream_shape_names), 48)
        self.assertEqual(set(upstream_names), set(common_names) | {"PortHostIpv6"})
        self.assertEqual(set(upstream_shape_names), set(common_shapes) | set(PORT_GROUPS["PortHostIpv6"]))


if __name__ == "__main__":
    unittest.main()
