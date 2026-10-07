"""Closed native evidence cannot admit unreviewed identity or leak API bodies."""

import copy
import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_native_health_metadata_proof import IMAGE as HEALTH_FIXTURE_IMAGE, proof as health_metadata_proof
from test_native_network_attachment_proof import fixture as network_attachment_fixture

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native-evidence.py"
SHA = "a" * 40
RUN_ID = "Ab12Cd34"
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
PREREQUISITE_SHAPES = {
    "VolumeExternalReference": ["ExternalVolumeReference"],
    "VolumeLabels": ["VolumeCreateLabels"],
    "NetworkExternalReference": ["ExternalNetworkReference"],
}
EXPECTED_RAW_SHAPES = {
    **SHAPES, "NetworkInternal": ["InternalBridgeNetworkCreate"],
    **PREREQUISITE_SHAPES,
    "ContainerLabels": ["ContainerCreateLabels"],
    "HealthShell": ["ShellHealthcheck"],
    "HealthStartPeriod": ["HealthStartPeriodZero", "HealthStartPeriodPositive"],
    "NetworkLabels": ["NetworkCreateLabels"],
    "NetworkAliases": ["NetworkPrimaryAliases", "NetworkSecondaryAliases"],
    "NetworkMultipleAttachment": ["NetworkSecondaryConnect"],
}
EXPECTED_PORT_CAPABILITY_SHAPES = {
    "PortHostIpv4": ["FixedIpv4HostPort", "EphemeralIpv4HostPort"],
    "PortHostIpv6": ["FixedIpv6HostPort", "EphemeralIpv6HostPort"],
    "PortMultipleBindings": ["MultipleFixedPortBindings", "MultipleEphemeralPortBindings"],
    "PortExposeOnly": ["ExposedOnlyPort"],
    "PortEphemeral": ["EphemeralHostPort"],
}
EXPECTED_FUTURE_RAW_SHAPES = {**EXPECTED_RAW_SHAPES, **EXPECTED_PORT_CAPABILITY_SHAPES}
SOURCE_PROBES = [
    "DiscoveryMetadata", "ExactContainerId", "ExactContainerName",
    "LiteralNamePrefix", "ExactLabel", "ExplicitAllContainers",
    "ExactNetworkRoot", "ExactVolumeRoot", "UnrelatedInspectExcluded",
    "IdentityFieldsOracle", "PortBindingsOracle",
    "MultipleHostIpBindingsOracle", "MountEnvironmentOracle",
    "HealthRestartOracle", "SelectedFieldOrigins",
    "DaemonResourceSupportOracle",
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
NETWORK_PROOF = {
    "probes": NETWORK_PROBES,
    "internal_shape": {"InternalBridgeNetworkCreate": "passed"},
}
VOLUME_PROBES = [
    "ExistingVolumePrerequisite", "ExistingVolumeTargetIdentity",
    "ExistingVolumeReadOnlyData", "ExistingVolumeReadWriteData",
    "ExistingVolumePersistence", "MissingVolumePrecheck",
]
VOLUME_LABEL_PROBES = [
    "VolumeCreateLabels", "VolumeLabelInspect",
    "VolumeLabelPersistence", "VolumeLabelOwnershipCleanup",
]
IDENTITY_PROBES = [
    "ContainerUser", "ContainerWorkdir", "ContainerNumericUidGid",
    "ContainerProcessWorkingDirectory", "ContainerIdentityOwnershipCleanup",
]
PORT_SHAPES = [
    "FixedIpv4HostPort", "EphemeralIpv4HostPort", "FixedIpv6HostPort",
    "EphemeralIpv6HostPort", "MultipleFixedPortBindings",
    "MultipleEphemeralPortBindings", "ExposedOnlyPort", "EphemeralHostPort",
]
PORT_PROBES = {
    "schema_version": 1,
    "positive": PORT_SHAPES,
    "expected_negative": [],
}


def port_proof(lane: str, mode: str, api: str, sha: str, engine: str) -> dict:
    return {
        "schema_version": 1, "kind": "dockerlens-native-port-probes",
        "candidate_sha": sha, "lane": lane, "engine_release": engine,
        "rendering_api": api, "daemon_mode": mode, "run_id": RUN_ID,
        "cleanup": "absent", "probes": PORT_PROBES,
    }


def identity_proof(lane: str, mode: str, api: str, sha: str) -> dict:
    return {
        "schema_version": 1, "candidate_sha": sha, "lane": lane,
        "mode": mode, "rendering_api": api, "run_id": RUN_ID,
        "probes": IDENTITY_PROBES,
        "containers": [
            {"role": role, "id": digit * 64,
             "name": f"dl-identity-{RUN_ID}-{role}", "owner": RUN_ID,
             "configured_user": "passed", "configured_workdir": "passed",
             "runtime_uid": "passed", "runtime_gid": "passed",
             "runtime_workdir": "passed", "cleanup": "absent"}
            for role, digit in (("oracle", "c"), ("rendered", "d"))
        ],
    }


class NativeEvidenceTests(unittest.TestCase):
    def test_identity_schema_is_additive_not_reviewed_admission(self) -> None:
        schema = json.loads((ROOT / "docs/native-evidence.schema.json").read_text())
        defs = schema["$defs"]
        self.assertEqual([item["const"] for item in defs["identity_probes"]["prefixItems"]],
                         IDENTITY_PROBES)
        self.assertFalse(defs["identity_probes"]["items"])
        self.assertFalse(defs["native_identity_proof"]["additionalProperties"])
        self.assertEqual([item["allOf"][1]["properties"]["shape"]["const"]
                          for item in defs["port_probes"]["prefixItems"]], PORT_SHAPES)
        self.assertFalse(defs["port_probes"]["items"])
        self.assertFalse(defs["native_port_probe_proof"]["additionalProperties"])
        self.assertNotIn("identity_probes", schema["properties"])
        self.assertNotIn("identity_probes", schema["required"])
        self.assertEqual(set(defs), {"api_version", "identity_probes",
                                     "identity_container_proof", "native_identity_proof",
                                     "identity_container_v2", "identity_case_v2", "native_identity_proof_v2",
                                     "port_shape", "port_probe_entry", "port_probes",
                                     "native_port_probe_proof"})
        unchanged = copy.deepcopy(schema)
        for name in ("identity_probes", "identity_container_proof", "native_identity_proof",
                     "identity_container_v2", "identity_case_v2", "native_identity_proof_v2",
                     "port_shape", "port_probe_entry", "port_probes", "native_port_probe_proof"):
            del unchanged["$defs"][name]
        # Canonical reviewed-record contract from the #74 clean base 946abb3;
        # adding disconnected definitions cannot rewrite historical admission.
        self.assertEqual(hashlib.sha256(json.dumps(unchanged, sort_keys=True,
                                                   separators=(",", ":")).encode()).hexdigest(),
                         "2ec0167732b28c917ad75137b64874b4b0b1ba64a9905ea0435673d4f4d744d9")

    def test_identity_proof_requires_every_binding_check_and_owned_pair(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        good = identity_proof("upstream-rootful", "rootful", "1.56", SHA)
        cases = []
        for key, bad in (("schema_version", True), ("candidate_sha", "b" * 40),
                         ("lane", "upstream-rootless"), ("mode", "rootless"),
                         ("rendering_api", "1.41"), ("run_id", "Stale123"),
                         ("probes", IDENTITY_PROBES[:-1]), ("probes", IDENTITY_PROBES[::-1]),
                         ("probes", [*IDENTITY_PROBES, "protected-secret"]),
                         ("containers", good["containers"][:1])):
            changed = copy.deepcopy(good)
            changed[key] = bad
            cases.append(changed)
        for index in (0, 1):
            for key in good["containers"][index]:
                for missing in (False, True):
                    changed = copy.deepcopy(good)
                    if missing:
                        del changed["containers"][index][key]
                    else:
                        changed["containers"][index][key] = "protected-secret"
                    cases.append(changed)
        for key in good:
            changed = copy.deepcopy(good)
            del changed[key]
            cases.append(changed)
        for omitted in IDENTITY_PROBES:
            changed = copy.deepcopy(good)
            changed["probes"] = [probe for probe in IDENTITY_PROBES if probe != omitted]
            cases.append(changed)
        repeated = copy.deepcopy(good)
        repeated["containers"][1]["id"] = repeated["containers"][0]["id"]
        extra = copy.deepcopy(good)
        extra["protected-secret"] = "protected-secret"
        extra_record = copy.deepcopy(good)
        extra_record["containers"][0]["protected-secret"] = "protected-secret"
        cases.extend([repeated, extra, extra_record, [], {}, [good]])
        for index, proof in enumerate(cases):
            with self.subTest(case=index):
                result, path = self.run_emit(version, identity=proof)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual(result.stderr.strip(), "native evidence rejected")
                self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_identity_file_requires_private_bounded_regular_unique_json(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        for failure in ("missing", "empty", "partial", "oversized", "symlink", "fifo",
                        "hardlink", "public", "duplicate_outer", "duplicate_record"):
            with self.subTest(failure=failure):
                result, destination = self.run_emit(version)
                self.assertEqual(result.returncode, 0, result.stderr)
                root = destination.parent.parent
                proof = root / "identity.json"
                destination.unlink()
                if failure in ("missing", "symlink", "fifo"):
                    proof.unlink()
                    if failure == "symlink":
                        proof.symlink_to(root / "version.json")
                    elif failure == "fifo":
                        os.mkfifo(proof, 0o600)
                elif failure == "hardlink":
                    os.link(proof, root / "second-link")
                elif failure == "public":
                    proof.chmod(0o640)
                else:
                    content = proof.read_text()
                    invalid = {"empty": "", "partial": '{"schema_version":',
                               "oversized": "x" * 4097,
                               "duplicate_outer": content.replace('"schema_version": 1',
                                                                  '"schema_version": 0, "schema_version": 1'),
                               "duplicate_record": content.replace('"runtime_uid": "passed"',
                                                                    '"runtime_uid": "failed", "runtime_uid": "passed"')}
                    proof.write_text(invalid[failure])
                command = ["python3", str(SCRIPT), *[str(root / name) for name in
                           ("version.json", "shapes.json", "source.json", "network.json",
                            "volume.json", "volume-label.json", "identity.json", "port-probes.json", "health-metadata.json", "network-attachments-v1.json")],
                           str(root), str(destination), "upstream-rootful", IMAGE, "rootful", "", SHA, RUN_ID]
                rejected = subprocess.run(command, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True,
                                          timeout=5, check=False)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(destination.exists())
                self.assertEqual(rejected.stderr.strip(), "native evidence rejected")

    def test_reviewed_record_schema_recognizes_defined_vocabulary_without_admission(self) -> None:
        schema = json.loads((ROOT / "docs/native-evidence.schema.json").read_text(encoding="utf-8"))
        reviewed = schema["properties"]["capabilities"]["items"]["properties"]
        names = set(reviewed["name"]["enum"])
        shape_names = set(reviewed["admitted_shapes"]["items"]["enum"])
        version = (ROOT / "src/version.rs").read_text(encoding="utf-8")

        def variants(declaration: str) -> set[str]:
            body = version.split(declaration, 1)[1].split("\n}", 1)[0]
            return set(re.findall(r"^    ([A-Za-z0-9_]+),$", body, re.MULTILINE))

        self.assertEqual(names, variants("pub enum Capability {"))
        self.assertEqual(shape_names, variants("pub(crate) enum NativeCapabilityShape {"))
        self.assertEqual(len(SHAPES), 10)
        self.assertEqual(sum(map(len, SHAPES.values())), 20)
        self.assertTrue(set(SHAPES).issubset(names))
        self.assertTrue({shape for values in SHAPES.values() for shape in values}.issubset(shape_names))
        self.assertTrue(set(EXPECTED_RAW_SHAPES).issubset(names))
        self.assertTrue({shape for values in EXPECTED_RAW_SHAPES.values()
                         for shape in values}.issubset(shape_names))

    def test_acquisition_cap_matches_manifest_calculation(self) -> None:
        acquisition = (ROOT / "src/acquisition.rs").read_text(encoding="utf-8")
        evidence = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("const MAX_KNOWN_API_MINOR: u16 = 49;", acquisition)
        self.assertIn("selected = min(int(maximum.split(\".\")[1]), 49)", evidence)

    def run_emit(self, version: dict, image: str = IMAGE, sha: str = SHA,
                 lane: str = "upstream-rootful", mode: str = "rootful",
                 package: str = "", shapes: dict | None = None,
                 source_probes: list[str] | None = None,
                 network_probes: object = None,
                 volume_probes: object = None,
                 volume_label_probes: object = None,
                 identity: object = None,
                 port_probes: object = None,
                 health_metadata: object = None,
                 health_metadata_missing: bool = False,
                 network_attachment: object = None,
                 network_attachment_missing: bool = False,
                 port_proof_override: object = None) -> tuple[subprocess.CompletedProcess[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        version_path = root / "version.json"
        shapes_path = root / "shapes.json"
        source_path = root / "source.json"
        network_path = root / "network.json"
        volume_path = root / "volume.json"
        volume_label_path = root / "volume-label.json"
        identity_path = root / "identity.json"
        port_path = root / "port-probes.json"
        health_metadata_path = root / "health-metadata.json"
        network_attachment_path = root / "network-attachments-v1.json"
        destination = root / "out" / f"{lane}.json"
        version_path.write_text(json.dumps(version), encoding="utf-8")
        shapes_path.write_text(json.dumps(SHAPES if shapes is None else shapes), encoding="utf-8")
        source_path.write_text(json.dumps(SOURCE_PROBES if source_probes is None else source_probes), encoding="utf-8")
        network_path.write_text(json.dumps(NETWORK_PROOF if network_probes is None else network_probes), encoding="utf-8")
        volume_path.write_text(json.dumps(VOLUME_PROBES if volume_probes is None else volume_probes), encoding="utf-8")
        volume_label_path.write_text(json.dumps(VOLUME_LABEL_PROBES if volume_label_probes is None else volume_label_probes), encoding="utf-8")
        identity_path.write_text(json.dumps(identity_proof(lane, mode, version.get("ApiVersion"), sha)
                                            if identity is None else identity), encoding="utf-8")
        identity_path.chmod(0o600)
        proof = port_proof(lane, mode, version.get("ApiVersion"), sha, version.get("Version"))
        if port_probes is not None:
            proof["probes"] = port_probes
        if port_proof_override is not None:
            proof = port_proof_override
        port_path.write_text(json.dumps(proof), encoding="utf-8")
        port_path.chmod(0o600)
        health = health_metadata_proof(lane)
        health.update({"candidate_sha": sha, "engine_release": version.get("Version"),
                       "rendering_api": version.get("ApiVersion")})
        if not health_metadata_missing:
            health_metadata_path.write_text(json.dumps(health if health_metadata is None else health_metadata), encoding="utf-8")
            health_metadata_path.chmod(0o600)
        network = network_attachment_fixture(lane)
        network["context"].update({"candidate_sha": sha, "engine_release": version.get("Version"),
                                   "rendering_api": version.get("ApiVersion"), "fixture_image": HEALTH_FIXTURE_IMAGE})
        network["context"]["outer"].update({"image": image, "socket_source": str(root / "socket")})
        for role in network["roles"]:
            for resource in role["resources"]:
                if resource["kind"] == "container":
                    resource["image"] = HEALTH_FIXTURE_IMAGE
        if not network_attachment_missing:
            network_attachment_path.write_text(json.dumps(network if network_attachment is None else network_attachment), encoding="utf-8")
            network_attachment_path.chmod(0o600)
        result = subprocess.run(
            ["python3", str(SCRIPT), str(version_path), str(shapes_path), str(source_path),
             str(network_path), str(volume_path), str(volume_label_path), str(identity_path),
             str(port_path), str(health_metadata_path), str(network_attachment_path), str(root), str(destination), lane, image, mode, package, sha, RUN_ID],
            capture_output=True, text=True, check=False,
            env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64},
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
        self.assertEqual(len(evidence["capability_outcome"]), 25)
        self.assertEqual(set(evidence["capability_outcome"].values()), {"available"})
        self.assertEqual(evidence["admitted_shapes"], EXPECTED_FUTURE_RAW_SHAPES)
        self.assertEqual(evidence["source_probes"], SOURCE_PROBES)
        self.assertEqual(evidence["network_probes"], NETWORK_PROBES)
        self.assertEqual(evidence["capability_outcome"]["NetworkInternal"], "available")
        self.assertEqual(set(NETWORK_PROBES).intersection(
            shape for values in evidence["admitted_shapes"].values() for shape in values), {
                "InternalBridgeNetworkCreate", "ExternalNetworkReference", "NetworkCreateLabels",
                "NetworkPrimaryAliases", "NetworkSecondaryAliases", "NetworkSecondaryConnect",
            })
        self.assertEqual(evidence["network_attachment_contract"], "network-attachments-v1")
        self.assertEqual(evidence["network_attachment_probes"], [
            "NetworkCreateLabels", "NetworkPrimaryAliases", "NetworkSecondaryAliases", "NetworkSecondaryConnect",
        ])
        self.assertEqual(evidence["volume_probes"], VOLUME_PROBES)
        self.assertEqual(evidence["volume_label_probes"], VOLUME_LABEL_PROBES)
        self.assertEqual(evidence["identity_probes"], IDENTITY_PROBES)
        self.assertEqual(evidence["port_probes"], [
            {"shape": shape, "outcome": "observed"} for shape in PORT_SHAPES
        ])
        for private in (RUN_ID, "c" * 64, "d" * 64, "dl-identity-"):
            self.assertNotIn(private, path.read_text(encoding="utf-8"))
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
        self.assertNotIn("protected-secret", path.read_text(encoding="utf-8"))
        result, path = self.run_emit(
            version, image=image, lane="debian11-rootless", mode="rootless",
            package="20.10.5+dfsg1-1+deb11u4",
        )
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

        result, path = self.run_emit(version, shapes=EXPECTED_RAW_SHAPES)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())

    def test_source_probes_are_exact_closed_non_admission_evidence(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        self.assertEqual(len(SOURCE_PROBES), 19)
        self.assertEqual(SOURCE_PROBES[15], "DaemonResourceSupportOracle")
        self.assertEqual(SOURCE_PROBES[-3:], [
            "NetworkActiveMembership", "NetworkStoppedMembershipBoundary",
            "ContainerInspectIdOracle",
        ])
        historical_probes = [probe for probe in SOURCE_PROBES
                             if probe != "DaemonResourceSupportOracle"]
        for probes in (historical_probes, SOURCE_PROBES[:-1], SOURCE_PROBES + ["private-canary"],
                       SOURCE_PROBES[:-1] + [SOURCE_PROBES[0]]):
            with self.subTest(probes=probes):
                result, path = self.run_emit(version, source_probes=probes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_resource_report_marker_never_admits_resource_capabilities(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        result, path = self.run_emit(version)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("DaemonResourceSupportOracle", evidence["source_probes"])
        self.assertEqual(set(evidence["capability_outcome"]), set(EXPECTED_FUTURE_RAW_SHAPES))
        self.assertEqual(evidence["admitted_shapes"], EXPECTED_FUTURE_RAW_SHAPES)
        self.assertNotIn("MemoryLimit", evidence["capability_outcome"])
        self.assertNotIn("SwapLimit", evidence["capability_outcome"])
        self.assertNotIn("DaemonResourceSupportOracle", (
            shape for shapes in evidence["admitted_shapes"].values() for shape in shapes))

    def test_prerequisite_raw_groups_are_exact_on_all_four_lane_identities(self) -> None:
        self.assertEqual(len(EXPECTED_RAW_SHAPES), 20)
        self.assertEqual(sum(map(len, EXPECTED_RAW_SHAPES.values())), 32)
        for family, release, api, minimum, package in (
            ("upstream", "29.8.1", "1.56", "1.44", ""),
            ("debian11", "20.10.5+dfsg1", "1.41", "1.12", "20.10.5+dfsg1-1+deb11u2"),
        ):
            for mode in ("rootful", "rootless"):
                image_family, tag = ("29", "v29.8.1") if family == "upstream" else ("debian-11", "v1.0.0")
                image = f"ghcr.io/strukturpiloten/docker-{image_family}-{mode}:{tag}@sha256:" + "b" * 64
                lane = f"{family}-{mode}"
                with self.subTest(lane=lane):
                    result, path = self.run_emit({
                        "Version": release, "ApiVersion": api, "MinAPIVersion": minimum,
                    }, lane=lane, mode=mode, image=image, package=package)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    record = json.loads(path.read_text(encoding="utf-8"))
                    self.assertEqual(record["candidate_sha"], SHA)
                    self.assertEqual(record["lane"], lane)
                    self.assertEqual(record["expected_mode"], mode)
                    self.assertEqual(record["engine_version"], release)
                    self.assertEqual(record["rendering_api"], api)
                    self.assertEqual(record["capability_outcome"], {
                        capability: "available" for capability in EXPECTED_FUTURE_RAW_SHAPES
                    })
                    self.assertEqual(record["admitted_shapes"], EXPECTED_FUTURE_RAW_SHAPES)
                    self.assertEqual(record["source_probes"], SOURCE_PROBES)
                    self.assertEqual(record["identity_probes"], IDENTITY_PROBES)

    def test_every_prerequisite_probe_is_required_before_any_manifest(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        for option, required in (("volume_probes", VOLUME_PROBES),
                                 ("volume_label_probes", VOLUME_LABEL_PROBES),
                                 ("network_probes", NETWORK_PROBES)):
            for omitted in required:
                partial = [probe for probe in required if probe != omitted]
                payload = {**NETWORK_PROOF, "probes": partial} if option == "network_probes" else partial
                with self.subTest(group=option, omitted=omitted):
                    result, path = self.run_emit(version, **{option: payload})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(path.exists())
                    self.assertEqual(result.stderr.strip(), "native evidence rejected")

    def test_missing_failed_or_duplicate_proof_files_never_emit_manifest(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        for filename in ("volume.json", "volume-label.json", "network.json"):
            failures = ("missing", "failed", "duplicate")
            if filename == "network.json":
                failures += ("duplicate_outer",)
            for failure in failures:
                with self.subTest(file=filename, failure=failure):
                    result, destination = self.run_emit(version)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    root = destination.parent.parent
                    path = root / filename
                    destination.unlink()
                    if failure == "missing":
                        path.unlink()
                    elif failure == "duplicate_outer":
                        path.write_text('{"probes":[],"probes":' + json.dumps(NETWORK_PROBES)
                                        + ',"internal_shape":{"InternalBridgeNetworkCreate":"passed"}}',
                                        encoding="utf-8")
                    elif filename == "network.json":
                        status = '"failed"' if failure == "failed" else '"passed"'
                        # Duplicate keys at either depth must fail even when a
                        # subsequent value would hide failure or duplicate pass.
                        path.write_text('{"probes":' + json.dumps(NETWORK_PROBES)
                                        + ',"internal_shape":{"InternalBridgeNetworkCreate":'
                                        + status + ',"InternalBridgeNetworkCreate":"passed"}}',
                                        encoding="utf-8")
                    else:
                        probes = VOLUME_PROBES if filename == "volume.json" else VOLUME_LABEL_PROBES
                        invalid = [*probes[:-1], "failed" if failure == "failed" else probes[0]]
                        path.write_text(json.dumps(invalid), encoding="utf-8")
                    command = ["python3", str(SCRIPT), str(root / "version.json"),
                               str(root / "shapes.json"), str(root / "source.json"),
                               str(root / "network.json"), str(root / "volume.json"),
                               str(root / "volume-label.json"), str(root / "identity.json"),
                               str(root / "port-probes.json"), str(root / "health-metadata.json"), str(root / "network-attachments-v1.json"), str(root), str(destination),
                               "upstream-rootful", IMAGE, "rootful", "", SHA, RUN_ID]
                    rejected = subprocess.run(command, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True, check=False)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertFalse(destination.exists())
                    self.assertEqual(rejected.stderr.strip(), "native evidence rejected")

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
                result, path = self.run_emit(version, network_probes={
                    **NETWORK_PROOF, "probes": probes,
                })
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_internal_proof_is_required_and_closed(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        for proof in (
            NETWORK_PROBES,
            {"probes": NETWORK_PROBES},
            {**NETWORK_PROOF, "internal_shape": {}},
            {**NETWORK_PROOF, "internal_shape": {"InternalBridgeNetworkCreate": "failed"}},
            {**NETWORK_PROOF, "internal_shape": {"InternalBridgeNetworkCreate": True}},
            {**NETWORK_PROOF, "internal_shape": {"InternalBridgeNetworkCreate": "passed",
                                                   "private-canary": "passed"}},
            {**NETWORK_PROOF, "private-canary": "secret"},
        ):
            with self.subTest(proof=proof):
                result, path = self.run_emit(version, network_probes=proof)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_internal_proof_requires_bounded_regular_private_input(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        result, destination = self.run_emit(version)
        self.assertEqual(result.returncode, 0, result.stderr)
        root = destination.parent.parent
        probe_path = root / "network.json"
        command = ["python3", str(SCRIPT), str(root / "version.json"), str(root / "shapes.json"),
                   str(root / "source.json"), str(probe_path), str(root / "volume.json"),
                   str(root / "volume-label.json"), str(root / "identity.json"),
                   str(root / "port-probes.json"), str(root / "health-metadata.json"), str(root / "network-attachments-v1.json"), str(root), str(destination),
                   "upstream-rootful", IMAGE, "rootful", "", SHA, RUN_ID]
        destination.unlink()
        probe_path.write_bytes(b"[" + b"x" * 4096 + b"]")
        oversized = subprocess.run(command, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True, check=False)
        self.assertNotEqual(oversized.returncode, 0)
        self.assertFalse(destination.exists())
        probe_path.unlink()
        probe_path.symlink_to(root / "source.json")
        symlink = subprocess.run(command, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True, check=False)
        self.assertNotEqual(symlink.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertNotIn("private", oversized.stdout + oversized.stderr + symlink.stdout + symlink.stderr)

    def test_internal_raw_shape_is_bound_to_exact_modes_and_versions(self) -> None:
        for lane, mode, image, package, version in (
            ("upstream-rootful", "rootful", IMAGE, "",
             {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}),
            ("debian11-rootless", "rootless",
             "ghcr.io/strukturpiloten/docker-debian-11-rootless:v1.0.0@sha256:" + "c" * 64,
             "20.10.5+dfsg1-1+deb11u2",
             {"Version": "20.10.5+dfsg1", "ApiVersion": "1.41", "MinAPIVersion": "1.12"}),
        ):
            with self.subTest(lane=lane):
                result, path = self.run_emit(version, lane=lane, mode=mode, image=image, package=package)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(record["expected_mode"], mode)
                self.assertEqual(record["rendering_api"], version["ApiVersion"])
                self.assertEqual(record["admitted_shapes"]["NetworkInternal"],
                                 ["InternalBridgeNetworkCreate"])
                wrong_mode, absent = self.run_emit(version, lane=lane, mode="other", image=image,
                                                   package=package)
                self.assertNotEqual(wrong_mode.returncode, 0)
                self.assertFalse(absent.exists())

    def test_port_publication_outcomes_are_complete_closed_and_non_admitting(self) -> None:
        upstream = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        positive = [shape for shape in PORT_SHAPES if shape not in
                    ("FixedIpv6HostPort", "EphemeralIpv6HostPort")]
        negative = [
            {"shape": "FixedIpv6HostPort", "reason": "nested_default_bridge_ipv6_unavailable"},
            {"shape": "EphemeralIpv6HostPort", "reason": "nested_default_bridge_ipv6_runtime_binding_absent"},
        ]
        probes = {"schema_version": 1, "positive": positive, "expected_negative": negative}
        image = "ghcr.io/strukturpiloten/docker-debian-11-rootful:v1.0.0@sha256:" + "c" * 64
        version = {"Version": "20.10.5+dfsg1", "ApiVersion": "1.41", "MinAPIVersion": "1.12"}
        result, path = self.run_emit(version, lane="debian11-rootful", mode="rootful",
                                     image=image, package="20.10.5+dfsg1-1+deb11u2",
                                     port_probes=probes)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(record["port_probes"], [
            {"shape": shape, "outcome": (
                "expected_negative" if shape in ("FixedIpv6HostPort", "EphemeralIpv6HostPort")
                else "observed"), **({"reason": negative[0 if shape == "FixedIpv6HostPort" else 1]["reason"]}
                                     if shape in ("FixedIpv6HostPort", "EphemeralIpv6HostPort") else {})}
            for shape in PORT_SHAPES
        ])
        self.assertEqual(record["capability_outcome"]["PortPublish"], "available")
        self.assertEqual(record["admitted_shapes"]["PortPublish"], ["FixedTcpPort", "FixedUdpPort"])
        serialized = path.read_text(encoding="utf-8")
        self.assertNotIn(RUN_ID, serialized)

        bad = [
            {"schema_version": 1, "positive": positive[:-1], "expected_negative": negative},
            {"schema_version": 1, "positive": [*positive, positive[0]], "expected_negative": negative},
            {"schema_version": 1, "positive": PORT_SHAPES, "expected_negative": negative},
            {"schema_version": 1, "positive": positive, "expected_negative": [*negative, negative[0]]},
            {"schema_version": 1, "positive": positive[::-1], "expected_negative": negative},
            {"schema_version": 1, "positive": [*positive, "private-canary"], "expected_negative": negative},
            {"schema_version": 1, "positive": [s for s in PORT_SHAPES if s != "FixedIpv6HostPort"],
             "expected_negative": [dict(negative[0], reason="private-canary"), negative[1]]},
            {"schema_version": 1, "positive": [s for s in PORT_SHAPES if s != "FixedIpv4HostPort"],
             "expected_negative": [{"shape": "FixedIpv4HostPort", "reason": negative[0]["reason"]}]},
            {"schema_version": True, "positive": positive, "expected_negative": negative},
            {"schema_version": 1, "positive": positive, "expected_negative": negative,
             "private-canary": "secret"},
        ]
        for invalid in bad:
            with self.subTest(probes=invalid):
                rejected, absent = self.run_emit(version, lane="debian11-rootful", mode="rootful",
                                                 image=image, package="20.10.5+dfsg1-1+deb11u2",
                                                 port_probes=invalid)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(absent.exists())
                self.assertNotIn("private-canary", rejected.stdout + rejected.stderr)

        upstream_negative, absent = self.run_emit(upstream, port_probes={
            "schema_version": 1, "positive": positive, "expected_negative": negative,
        })
        self.assertNotEqual(upstream_negative.returncode, 0)
        self.assertFalse(absent.exists())

    def test_port_proof_requires_private_direct_capture_child(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        result, destination = self.run_emit(version)
        self.assertEqual(result.returncode, 0, result.stderr)
        root = destination.parent.parent
        proof = root / "port-probes.json"
        destination.unlink()
        command = ["python3", str(SCRIPT), *[str(root / name) for name in
                   ("version.json", "shapes.json", "source.json", "network.json", "volume.json",
                    "volume-label.json", "identity.json", "port-probes.json", "health-metadata.json", "network-attachments-v1.json")], str(root),
                   str(destination), "upstream-rootful", IMAGE, "rootful", "", SHA, RUN_ID]
        for failure in ("missing", "symlink", "hardlink", "public", "oversized", "notchild", "duplicate"):
            with self.subTest(failure=failure):
                if proof.exists() or proof.is_symlink():
                    proof.unlink()
                proof.write_text(json.dumps(port_proof("upstream-rootful", "rootful", "1.56", SHA, "29.8.1")))
                proof.chmod(0o600)
                alternate = root / "alternate"
                if alternate.exists():
                    alternate.unlink()
                args = list(command)
                if failure == "missing":
                    proof.unlink()
                elif failure == "symlink":
                    proof.unlink()
                    proof.symlink_to(root / "version.json")
                elif failure == "hardlink":
                    os.link(proof, root / "second-link")
                elif failure == "public":
                    proof.chmod(0o640)
                elif failure == "oversized":
                    proof.write_text("x" * 4097)
                elif failure == "notchild":
                    alternate.write_text(proof.read_text())
                    alternate.chmod(0o600)
                    args[9] = str(alternate)
                elif failure == "duplicate":
                    content = proof.read_text()
                    proof.write_text(content.replace('"schema_version": 1',
                                                     '"schema_version": 0, "schema_version": 1'))
                rejected = subprocess.run(args, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True, timeout=5, check=False)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(destination.exists())
                self.assertEqual(rejected.stderr.strip(), "native evidence rejected")

    def test_port_proof_binds_exact_context_and_rejects_extra_fields(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
        good = port_proof("upstream-rootful", "rootful", "1.56", SHA, "29.8.1")
        invalid = []
        for key, value in (("schema_version", True), ("kind", "other"),
                           ("candidate_sha", "b" * 40), ("lane", "upstream-rootless"),
                           ("engine_release", "29.8.0"), ("rendering_api", "1.55"),
                           ("daemon_mode", "rootless"), ("run_id", "Stale123"),
                           ("cleanup", "present")):
            changed = copy.deepcopy(good)
            changed[key] = value
            invalid.append(changed)
        extra = copy.deepcopy(good)
        extra["private-canary"] = "secret"
        invalid.append(extra)
        nested_extra = copy.deepcopy(good)
        nested_extra["probes"]["private-canary"] = "secret"
        invalid.append(nested_extra)
        for proof in invalid:
            with self.subTest(proof=proof):
                result, path = self.run_emit(version, port_proof_override=proof)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("secret", result.stdout + result.stderr)

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
                   str(probe_path), str(root / "volume-label.json"), str(root / "identity.json"),
                   str(root / "port-probes.json"), str(root / "health-metadata.json"), str(root / "network-attachments-v1.json"), str(root), str(destination),
                   "upstream-rootful", IMAGE, "rootful", "", SHA, RUN_ID]
        valid = subprocess.run(command, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True, check=False)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        destination.unlink()
        probe_path.write_bytes(b"[" + b"x" * 4096 + b"]")
        oversized = subprocess.run(command, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True, check=False)
        self.assertNotEqual(oversized.returncode, 0)
        self.assertFalse(destination.exists())
        probe_path.unlink()
        probe_path.symlink_to(root / "source.json")
        symlink = subprocess.run(command, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True, check=False)
        self.assertNotEqual(symlink.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertNotIn("private", oversized.stdout + oversized.stderr + symlink.stdout + symlink.stderr)

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
                   str(root / "volume.json"), str(probe_path), str(root / "identity.json"),
                   str(root / "port-probes.json"), str(root / "health-metadata.json"), str(root / "network-attachments-v1.json"), str(root), str(destination),
                   "upstream-rootful", IMAGE, "rootful", "", SHA, RUN_ID]
        valid = subprocess.run(command, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True, check=False)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        destination.unlink()
        probe_path.write_bytes(b"[" + b"x" * 4096 + b"]")
        oversized = subprocess.run(command, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True, check=False)
        self.assertNotEqual(oversized.returncode, 0)
        self.assertFalse(destination.exists())
        probe_path.unlink()
        probe_path.symlink_to(root / "volume.json")
        symlink = subprocess.run(command, env={**os.environ, "NATIVE_FIXTURE_IMAGE": HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64}, capture_output=True, text=True, check=False)
        self.assertNotEqual(symlink.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertNotIn("private", oversized.stdout + oversized.stderr + symlink.stdout + symlink.stderr)


if __name__ == "__main__":
    unittest.main()
