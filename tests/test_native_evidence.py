"""Closed native evidence cannot admit unreviewed identity or leak API bodies."""

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native-evidence.py"
SHA = "a" * 40
IMAGE = ("ghcr.io/strukturpiloten/docker-29-rootful:v29.8.1@sha256:"
         + "b" * 64)
SHAPES = {
    "StandaloneContainer": ["StandaloneCreate"],
    "NamedVolume": ["NamedVolumeCreate", "NamedVolumeMountReadWrite", "NamedVolumeMountReadOnly"],
    "BridgeNetwork": ["BridgeNetworkCreate", "BridgeNetworkAttach"],
    "PortPublish": ["FixedTcpPort", "FixedUdpPort"],
    "BindMount": ["BindMountReadWrite", "BindMountReadOnly"],
    "EnvironmentAssignment": ["EnvironmentValue", "EnvironmentEmptyValue"],
    "Command": ["ExecCommand"],
    "Entrypoint": ["ExecEntrypoint"],
    "Healthcheck": ["ExecHealthcheck"],
    "RestartPolicy": ["RestartNo", "RestartAlways", "RestartUnlessStopped",
                      "RestartOnFailureUnlimited", "RestartOnFailureLimited"],
}
SOURCE_PROBES = [
    "DiscoveryMetadata", "ExactContainerId", "ExactContainerName",
    "LiteralNamePrefix", "ExactLabel", "ExplicitAllContainers",
    "ExactNetworkRoot", "ExactVolumeRoot", "UnrelatedInspectExcluded",
    "IdentityFieldsOracle", "PortBindingsOracle",
    "MultipleHostIpBindingsOracle", "MountEnvironmentOracle",
    "HealthRestartOracle", "SelectedFieldOrigins",
    "NetworkActiveMembership", "NetworkStoppedMembershipBoundary",
    "ContainerInspectIdOracle",
]
NETWORK_PROBES = [
    "ExternalNetworkReference", "InternalBridgeNetworkCreate", "Ipv6BridgeNetworkCreate",
    "NetworkIpamV4", "NetworkIpamV6", "NetworkIpamGateway", "NetworkIpamRange",
    "NetworkIpamAuxiliary", "NetworkIpamDefaultDriver", "NetworkBridgeMtu",
    "NetworkBridgeIcc", "NetworkBridgeMasquerade", "NetworkBridgeHostBindingIp",
    "NetworkCreateLabels", "NetworkPrimaryAliases", "NetworkSecondaryAliases",
    "NetworkStaticIpv4", "NetworkStaticIpv6", "NetworkSecondaryConnect",
    "NetworkBridgeIccDisabled", "NetworkBridgeMasqueradeEnabled",
    "NetworkCreateLabelsValueDomain",
]
VOLUME_PROBES = [
    "ExistingVolumePrerequisite", "ExistingVolumeTargetIdentity",
    "ExistingVolumeReadOnlyData", "ExistingVolumeReadWriteData",
    "ExistingVolumePersistence", "MissingVolumePrecheck",
]
CONTAINER_PROBES = [
    "ExposedOnlyPort", "FixedIpv4HostPort", "FixedIpv6HostPort", "EphemeralIpv6HostPort",
    "EphemeralIpv4HostPort", "MultipleFixedPortBindings", "MultipleEphemeralPortBindings", "EphemeralHostPort",
    "ClearCommand", "ClearEntrypoint", "ShellHealthcheck", "DisabledHealthcheck",
    "HealthStartPeriodPositive", "HealthStartPeriodZero",
    "HealthStartIntervalPositive", "HealthStartIntervalZero", "ContainerCreateLabels",
    "ContainerUser", "ContainerWorkdir", "ContainerHostname", "TmpfsMountReadWrite",
    "TmpfsMountReadOnly", "TmpfsMountOptions", "ReadOnlyRootfsTrue", "ReadOnlyRootfsFalse",
    "ContainerInitTrue", "ContainerInitFalse", "StopSignal", "StopTimeoutPositive",
    "StopTimeoutZero", "MemoryBytes", "MemoryUnlimited", "PidsCount", "PidsUnlimited",
    "ShmSize", "UlimitsFinite", "UlimitsUnlimited", "UlimitNofile", "DeviceMappings",
    "LinuxCapDrop", "LinuxCapAdd", "CapAddNetBindService", "CapDropSysAdmin",
    "NoNewPrivilegesEnabled", "NoNewPrivilegesDisabled", "Sysctls", "SysctlIpv4Forward",
    "SupplementaryGroups", "DnsIpv4", "DnsIpv6", "ExtraHostsIpv4", "ExtraHostsIpv6",
    "LogJsonFile", "LogLocal", "LogNone", "LogOptions", "LogOptionMaxSize",
]
UPSTREAM_CONTAINER = {"schema_version": 1, "positive": CONTAINER_PROBES,
                      "expected_negative": []}
INTERVAL_NEGATIVES = [
    {"shape": "HealthStartIntervalPositive", "reason": "api_1_41_no_start_interval"},
    {"shape": "HealthStartIntervalZero", "reason": "api_1_41_start_interval_zero_unobservable"},
]
IPV6_NEGATIVES = [
    {"shape": shape, "reason": "nested_default_bridge_ipv6_unavailable"}
    for shape in ("EphemeralIpv6HostPort", "FixedIpv6HostPort")
]
DEBIAN_NEGATIVES = IPV6_NEGATIVES + INTERVAL_NEGATIVES
DEBIAN_CONTAINER = {
    "schema_version": 1,
    "positive": [shape for shape in CONTAINER_PROBES
                 if shape not in {item["shape"] for item in DEBIAN_NEGATIVES}],
    "expected_negative": DEBIAN_NEGATIVES,
}
VOLUME_LABEL_PROBES = [
    "VolumeCreateLabels", "VolumeLabelInspect",
    "VolumeLabelPersistence", "VolumeLabelOwnershipCleanup",
]


class NativeEvidenceTests(unittest.TestCase):
    def test_container_shape_vocabulary_matches_native_rust(self) -> None:
        rust = (ROOT / "src/native_container_tests.rs").read_text(encoding="utf-8")
        match = re.search(r"const EXPECTED_SHAPES: &\[&str\] = &\[(.*?)\];", rust, re.S)
        self.assertIsNotNone(match)
        rust_shapes = re.findall(r'"([A-Za-z0-9]+)"', match.group(1))
        self.assertEqual(len(rust_shapes), len(set(rust_shapes)))
        self.assertEqual(rust_shapes, CONTAINER_PROBES)

    def test_reviewed_record_schema_names_exact_native_shapes(self) -> None:
        schema = json.loads((ROOT / "docs/native-evidence.schema.json").read_text(encoding="utf-8"))
        reviewed = schema["properties"]["capabilities"]["items"]["properties"]
        names = set(reviewed["name"]["enum"])
        shape_names = set(reviewed["admitted_shapes"]["items"]["enum"])
        self.assertTrue(set(SHAPES).issubset(names))
        self.assertEqual(shape_names, {shape for values in SHAPES.values() for shape in values})

    def test_acquisition_cap_matches_manifest_calculation(self) -> None:
        acquisition = (ROOT / "src/acquisition.rs").read_text(encoding="utf-8")
        evidence = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("const MAX_KNOWN_API_MINOR: u16 = 49;", acquisition)
        self.assertIn("selected = min(int(maximum.split(\".\")[1]), 49)", evidence)

    def run_emit(self, version: dict, image: str = IMAGE, sha: str = SHA,
                 lane: str = "upstream-rootful", mode: str = "rootful",
                 package: str = "", shapes: dict | None = None,
                 source_probes: list[str] | None = None,
                 network_probes: list[str] | None = None,
                 volume_probes: object = None,
                 volume_label_probes: object = None,
                 container_probes: object | None = None,
                 write_container: bool = True) -> tuple[subprocess.CompletedProcess[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        version_path = root / "version.json"
        shapes_path = root / "shapes.json"
        source_path = root / "source.json"
        network_path = root / "network.json"
        volume_path = root / "volume.json"
        container_path = root / "container.json"
        volume_label_path = root / "volume-label.json"
        destination = root / "out" / f"{lane}.json"
        version_path.write_text(json.dumps(version), encoding="utf-8")
        shapes_path.write_text(json.dumps(SHAPES if shapes is None else shapes), encoding="utf-8")
        source_path.write_text(json.dumps(SOURCE_PROBES if source_probes is None else source_probes), encoding="utf-8")
        network_path.write_text(json.dumps(NETWORK_PROBES if network_probes is None else network_probes), encoding="utf-8")
        volume_path.write_text(json.dumps(VOLUME_PROBES if volume_probes is None else volume_probes), encoding="utf-8")
        if container_probes is None:
            container_probes = (DEBIAN_CONTAINER if lane.startswith("debian11-")
                                else UPSTREAM_CONTAINER)
        if write_container:
            container_path.write_text(container_probes if isinstance(container_probes, str)
                                      else json.dumps(container_probes), encoding="utf-8")
        volume_label_path.write_text(json.dumps(VOLUME_LABEL_PROBES if volume_label_probes is None else volume_label_probes), encoding="utf-8")
        result = subprocess.run(
            ["python3", str(SCRIPT), str(version_path), str(shapes_path), str(source_path),
             str(network_path), str(volume_path), str(container_path), str(volume_label_path), str(destination),
             lane, image, mode, package, sha],
            capture_output=True, text=True, check=False,
        )
        return result, destination

    def test_advertised_and_negotiated_api_are_distinct(self) -> None:
        result, path = self.run_emit({
            "Version": "29.8.1", "ApiVersion": "1.56",
            "MinAPIVersion": "1.44", "Private": "protected-secret",
            "Components": [{"Name": "containerd", "Version": "2.3.5"},
                           {"Name": "runc", "Version": "1.5.1"}],
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["engine_api_max"], "1.56")
        self.assertEqual(evidence["engine_api_min"], "1.44")
        self.assertEqual(evidence["acquisition_api"], "1.49")
        self.assertEqual(evidence["rendering_api"], "1.56")
        self.assertEqual(evidence["runtime_components"], {"containerd": "2.3.5", "runc": "1.5.1"})
        self.assertEqual(len(evidence["capability_outcome"]), 10)
        self.assertEqual(set(evidence["capability_outcome"].values()), {"available"})
        self.assertEqual(evidence["admitted_shapes"], SHAPES)
        self.assertEqual(evidence["source_probes"], SOURCE_PROBES)
        self.assertEqual(evidence["network_probes"], NETWORK_PROBES)
        self.assertEqual(evidence["container_probes"], UPSTREAM_CONTAINER)
        self.assertTrue(set(NETWORK_PROBES).isdisjoint(
            shape for values in evidence["admitted_shapes"].values() for shape in values))
        self.assertEqual(evidence["volume_probes"], VOLUME_PROBES)
        self.assertEqual(evidence["volume_label_probes"], VOLUME_LABEL_PROBES)
        self.assertNotIn("protected-secret", path.read_text(encoding="utf-8"))

    def test_rejects_unreviewed_identity_and_unacquirable_api(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        cases = (
            {"image": IMAGE.replace("docker-29-rootful", "docker-29-rootless")},
            {"sha": "invalid"},
            {"mode": "rootless"},
            {"package": "unexpected"},
        )
        for options in cases:
            with self.subTest(options=options):
                result, path = self.run_emit(version, **options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
        result, path = self.run_emit({**version, "MinAPIVersion": "1.50"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())
        result, path = self.run_emit({**version, "ApiVersion": "1.52"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())

    def test_debian_package_is_exact_and_private_fields_stay_private(self) -> None:
        image = ("ghcr.io/strukturpiloten/docker-debian-11-rootless:v1.0.0@sha256:"
                 + "c" * 64)
        version = {"Version": "20.10.5+dfsg1", "ApiVersion": "1.41",
                   "MinAPIVersion": "1.12", "Private": "protected-secret"}
        result, path = self.run_emit(
            version, image=image, lane="debian11-rootless", mode="rootless",
            package="20.10.5+dfsg1-1+deb11u2",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["debian_docker_package"], "20.10.5+dfsg1-1+deb11u2")
        self.assertEqual(evidence["acquisition_api"], "1.41")
        self.assertEqual(evidence["container_probes"], DEBIAN_CONTAINER)
        self.assertNotIn("protected-secret", path.read_text(encoding="utf-8"))
        result, path = self.run_emit(
            version, image=image, lane="debian11-rootless", mode="rootless",
            package="20.10.5+dfsg1-1+deb11u4",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())

    def test_container_probes_are_exact_closed_lane_specific_evidence(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        invalid = [
            {**UPSTREAM_CONTAINER, "positive": CONTAINER_PROBES[:-1]},
            {**UPSTREAM_CONTAINER, "positive": CONTAINER_PROBES + ["private-canary"]},
            {**UPSTREAM_CONTAINER, "positive": CONTAINER_PROBES + [CONTAINER_PROBES[0]]},
            {**UPSTREAM_CONTAINER, "expected_negative": [
                {"shape": "HealthStartIntervalPositive", "reason": "api_1_41_no_start_interval"}]},
            {**UPSTREAM_CONTAINER, "expected_negative": [
                {"shape": "private-canary", "reason": "private-canary"}]},
            {**UPSTREAM_CONTAINER, "schema_version": 2},
            {**UPSTREAM_CONTAINER, "schema_version": True},
            {**UPSTREAM_CONTAINER, "private-canary": "protected-secret"},
            {**UPSTREAM_CONTAINER, "positive": "protected-secret"},
            '{"schema_version":1,"positive":[],"positive":[],"expected_negative":[]}',
            "protected-secret" * 400,
        ]
        for probes in invalid:
            with self.subTest(probes=str(probes)[:60]):
                result, path = self.run_emit(version, container_probes=probes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("protected-secret", result.stdout + result.stderr)
                self.assertNotIn("private-canary", result.stdout + result.stderr)
        result, path = self.run_emit(version, write_container=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())
        result, path = self.run_emit(version, container_probes=DEBIAN_CONTAINER)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())

    def test_debian_container_negative_requires_exact_reason_and_api(self) -> None:
        image = ("ghcr.io/strukturpiloten/docker-debian-11-rootful:v1.0.0@sha256:"
                 + "c" * 64)
        version = {"Version": "20.10.5", "ApiVersion": "1.41", "MinAPIVersion": "1.12"}
        options = {"image": image, "lane": "debian11-rootful", "mode": "rootful",
                   "package": "20.10.5+dfsg1-1+deb11u2"}
        for ipv6_shapes in ((), ("FixedIpv6HostPort",),
                            ("EphemeralIpv6HostPort",),
                            ("FixedIpv6HostPort", "EphemeralIpv6HostPort")):
            with self.subTest(ipv6_shapes=ipv6_shapes):
                negatives = sorted(INTERVAL_NEGATIVES + [
                    item for item in IPV6_NEGATIVES if item["shape"] in ipv6_shapes
                ], key=lambda item: item["shape"])
                probes = {
                    "schema_version": 1,
                    "positive": [shape for shape in CONTAINER_PROBES
                                 if shape not in {item["shape"] for item in negatives}],
                    "expected_negative": negatives,
                }
                result, path = self.run_emit(version, container_probes=probes, **options)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["container_probes"], probes)
        for probes in (
            UPSTREAM_CONTAINER,
            {**DEBIAN_CONTAINER, "expected_negative": [
                {**IPV6_NEGATIVES[0], "reason": "private-canary"},
                *DEBIAN_NEGATIVES[1:]]},
            {**DEBIAN_CONTAINER, "expected_negative": list(reversed(DEBIAN_NEGATIVES))},
            {**DEBIAN_CONTAINER, "expected_negative": [
                {"shape": "HealthStartIntervalPositive", "reason": "private-canary"}]},
            {**DEBIAN_CONTAINER, "expected_negative": [
                {"shape": "HealthStartIntervalPositive",
                 "reason": "api_1_41_no_start_interval"},
                {"shape": "HealthStartIntervalZero", "reason": "private-canary"}]},
            {**DEBIAN_CONTAINER, "expected_negative": [
                {"shape": "HealthStartIntervalPositive",
                 "reason": "api_1_41_start_interval_zero_unobservable"},
                {"shape": "HealthStartIntervalZero", "reason": "api_1_41_no_start_interval"}]},
            {**DEBIAN_CONTAINER, "expected_negative": DEBIAN_CONTAINER["expected_negative"] * 2},
            {**DEBIAN_CONTAINER, "positive": DEBIAN_CONTAINER["positive"] +
             ["HealthStartIntervalPositive"]},
            {**DEBIAN_CONTAINER, "positive": DEBIAN_CONTAINER["positive"] +
             ["HealthStartIntervalZero"]},
        ):
            with self.subTest(probes=probes):
                result, path = self.run_emit(version, container_probes=probes, **options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)
        result, path = self.run_emit({**version, "ApiVersion": "1.42"}, **options)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())

    def test_missing_or_extra_shape_never_creates_positive_manifest(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        for capability, shape in (("PortPublish", "FixedUdpPort"),
                                  ("NamedVolume", "NamedVolumeMountReadOnly"),
                                  ("RestartPolicy", "RestartOnFailureUnlimited")):
            partial = json.loads(json.dumps(SHAPES))
            partial[capability].remove(shape)
            with self.subTest(capability=capability, shape=shape):
                result, path = self.run_emit(version, shapes=partial)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
        private = json.loads(json.dumps(SHAPES))
        private["PortPublish"].append("protected-secret")
        result, path = self.run_emit(version, shapes=private)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())
        self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_source_probes_are_exact_closed_non_admission_evidence(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        self.assertEqual(len(SOURCE_PROBES), 18)
        self.assertEqual(SOURCE_PROBES[-3:], [
            "NetworkActiveMembership", "NetworkStoppedMembershipBoundary",
            "ContainerInspectIdOracle",
        ])
        for probes in (SOURCE_PROBES[:-1], SOURCE_PROBES + ["private-canary"],
                       SOURCE_PROBES[:-1] + [SOURCE_PROBES[0]]):
            with self.subTest(probes=probes):
                result, path = self.run_emit(version, source_probes=probes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_network_probes_are_exact_closed_non_admission_evidence(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        self.assertEqual(len(NETWORK_PROBES), 22)
        self.assertEqual(NETWORK_PROBES[19:], [
            "NetworkBridgeIccDisabled", "NetworkBridgeMasqueradeEnabled",
            "NetworkCreateLabelsValueDomain",
        ])
        for probes in (NETWORK_PROBES[:-1], NETWORK_PROBES + ["private-canary"],
                       NETWORK_PROBES[:-1] + [NETWORK_PROBES[0]],
                       NETWORK_PROBES[:19]):
            with self.subTest(probes=probes):
                result, path = self.run_emit(version, network_probes=probes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_volume_probes_are_exact_closed_non_admission_evidence(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        for probes in (VOLUME_PROBES[:-1], VOLUME_PROBES + ["private-canary"],
                       VOLUME_PROBES[:-1] + [VOLUME_PROBES[0]],
                       {"private-canary": VOLUME_PROBES}):
            with self.subTest(probes=probes):
                result, path = self.run_emit(version, volume_probes=probes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_volume_probe_input_must_be_bounded_regular_json(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        result, destination = self.run_emit(version)
        self.assertEqual(result.returncode, 0, result.stderr)
        root = destination.parent.parent
        probe_path = root / "volume.json"
        command = ["python3", str(SCRIPT), str(root / "version.json"), str(root / "shapes.json"),
                   str(root / "source.json"), str(root / "network.json"),
                   str(probe_path), str(root / "container.json"), str(root / "volume-label.json"), str(destination),
                   "upstream-rootful", IMAGE, "rootful", "", SHA]
        valid = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        destination.unlink()
        valid_volume = root / "volume-valid.json"
        valid_volume.write_bytes(probe_path.read_bytes())
        probe_path.write_bytes(b"[" + b"x" * 4096 + b"]")
        oversized = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(oversized.returncode, 0)
        self.assertFalse(destination.exists())
        probe_path.unlink()
        probe_path.symlink_to(valid_volume)
        symlink = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(symlink.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertNotIn("private", oversized.stdout + oversized.stderr + symlink.stdout + symlink.stderr)

    def test_container_probe_input_must_be_bounded_regular_json(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        result, destination = self.run_emit(version)
        self.assertEqual(result.returncode, 0, result.stderr)
        root = destination.parent.parent
        probe_path = root / "container.json"
        command = ["python3", str(SCRIPT), str(root / "version.json"), str(root / "shapes.json"),
                   str(root / "source.json"), str(root / "network.json"),
                   str(root / "volume.json"), str(probe_path), str(root / "volume-label.json"), str(destination),
                   "upstream-rootful", IMAGE, "rootful", "", SHA]
        valid = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        destination.unlink()
        valid_container = root / "container-valid.json"
        valid_container.write_bytes(probe_path.read_bytes())
        probe_path.write_bytes(b"[" + b"x" * 4096 + b"]")
        oversized = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(oversized.returncode, 0)
        self.assertFalse(destination.exists())
        probe_path.unlink()
        probe_path.symlink_to(valid_container)
        symlink = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(symlink.returncode, 0)
        self.assertFalse(destination.exists())
        probe_path.unlink()
        probe_path.mkdir()
        directory = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(directory.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertNotIn("private", oversized.stdout + oversized.stderr + symlink.stdout + symlink.stderr + directory.stdout + directory.stderr)

    def test_volume_label_probes_are_exact_closed_non_admission_evidence(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        for probes in (VOLUME_LABEL_PROBES[:-1], VOLUME_LABEL_PROBES + ["private-canary"],
                       VOLUME_LABEL_PROBES[:-1] + [VOLUME_LABEL_PROBES[0]],
                       {"private-canary": VOLUME_LABEL_PROBES}):
            with self.subTest(probes=probes):
                result, path = self.run_emit(version, volume_label_probes=probes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_volume_label_probe_input_must_be_bounded_regular_json(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        result, destination = self.run_emit(version)
        self.assertEqual(result.returncode, 0, result.stderr)
        root = destination.parent.parent
        probe_path = root / "volume-label.json"
        command = ["python3", str(SCRIPT), str(root / "version.json"), str(root / "shapes.json"),
                   str(root / "source.json"), str(root / "network.json"),
                   str(root / "volume.json"), str(root / "container.json"), str(probe_path), str(destination),
                   "upstream-rootful", IMAGE, "rootful", "", SHA]
        valid = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        destination.unlink()
        probe_path.write_bytes(b"[" + b"x" * 4096 + b"]")
        oversized = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(oversized.returncode, 0)
        self.assertFalse(destination.exists())
        probe_path.unlink()
        probe_path.symlink_to(root / "volume.json")
        symlink = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(symlink.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertNotIn("private", oversized.stdout + oversized.stderr + symlink.stdout + symlink.stderr)


if __name__ == "__main__":
    unittest.main()
