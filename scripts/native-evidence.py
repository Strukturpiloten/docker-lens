#!/usr/bin/env python3
"""Emit closed, reviewable native evidence only after all lane checks pass."""

import json
import os
import re
import stat
import sys
from pathlib import Path

from native_identity_proof import CASES as IDENTITY_CASES, CONTRACT as IDENTITY_CONTRACT, validate_identity_v2


CAPABILITIES = (
    "StandaloneContainer", "NamedVolume", "BridgeNetwork", "PortPublish",
    "BindMount", "EnvironmentAssignment", "Command", "Entrypoint",
    "Healthcheck", "RestartPolicy",
)
REQUIRED_SHAPES = {
    "StandaloneContainer": ("StandaloneCreate",),
    "NamedVolume": ("NamedVolumeCreate", "NamedVolumeMountReadWrite", "NamedVolumeMountReadOnly"),
    "BridgeNetwork": ("BridgeNetworkCreate", "BridgeNetworkAttach"),
    "PortPublish": ("FixedTcpPort", "FixedUdpPort"),
    "BindMount": ("BindMountReadWrite", "BindMountReadOnly"),
    "EnvironmentAssignment": ("EnvironmentValue", "EnvironmentEmptyValue"),
    "Command": ("ExecCommand",),
    "Entrypoint": ("ExecEntrypoint",),
    "Healthcheck": ("ExecHealthcheck",),
    "RestartPolicy": ("RestartNo", "RestartAlways", "RestartUnlessStopped",
                      "RestartOnFailureUnlimited", "RestartOnFailureLimited"),
}
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SOURCE_PROBES = (
    "DiscoveryMetadata", "ExactContainerId", "ExactContainerName",
    "LiteralNamePrefix", "ExactLabel", "ExplicitAllContainers",
    "ExactNetworkRoot", "ExactVolumeRoot", "UnrelatedInspectExcluded",
    "IdentityFieldsOracle", "PortBindingsOracle",
    "MultipleHostIpBindingsOracle", "MountEnvironmentOracle",
    "HealthRestartOracle", "SelectedFieldOrigins",
    "DaemonResourceSupportOracle",
    "NetworkActiveMembership", "NetworkStoppedMembershipBoundary",
    "ContainerInspectIdOracle",
)
NETWORK_PROBES = (
    "ExternalNetworkReference", "InternalBridgeNetworkCreate",
    "Ipv6BridgeNetworkCreate", "NetworkIpamV4", "NetworkIpamV6",
    "NetworkIpamGateway", "NetworkIpamRange", "NetworkIpamAuxiliary",
    "NetworkIpamDefaultDriver", "NetworkBridgeMtu", "NetworkBridgeIcc",
    "NetworkBridgeMasquerade", "NetworkBridgeHostBindingIp",
    "NetworkCreateLabels", "NetworkPrimaryAliases", "NetworkSecondaryAliases",
    "NetworkStaticIpv4", "NetworkStaticIpv6", "NetworkSecondaryConnect",
    "NetworkBridgeIccDisabled", "NetworkBridgeMasqueradeEnabled",
    "NetworkCreateLabelsValueDomain",
)
INTERNAL_PROOF = {"InternalBridgeNetworkCreate": "passed"}
VOLUME_PROBES = (
    "ExistingVolumePrerequisite", "ExistingVolumeTargetIdentity",
    "ExistingVolumeReadOnlyData", "ExistingVolumeReadWriteData",
    "ExistingVolumePersistence", "MissingVolumePrecheck",
)
VOLUME_LABEL_PROBES = (
    "VolumeCreateLabels", "VolumeLabelInspect",
    "VolumeLabelPersistence", "VolumeLabelOwnershipCleanup",
)
IDENTITY_PROBES = (
    "ContainerUser", "ContainerWorkdir", "ContainerNumericUidGid",
    "ContainerProcessWorkingDirectory", "ContainerIdentityOwnershipCleanup",
)


def identity_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate identity proof key")
        result[key] = value
    return result


def read_identity_proof(path: Path, lane: str, mode: str, api: str,
                        candidate: str, run_id: str) -> tuple[list[str], bool]:
    # Trusted harness provenance, not an attestation against a privileged writer.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 16384
                or before.st_uid != os.geteuid() or before.st_mode & 0o077
                or before.st_nlink != 1):
            raise ValueError("invalid private identity proof")
        payload = source.read(16385)
        after = os.fstat(source.fileno())
    if (len(payload) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns, before.st_mode, before.st_uid, before.st_nlink)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                after.st_ctime_ns, after.st_mode, after.st_uid, after.st_nlink)):
        raise ValueError("identity proof changed")
    proof = json.loads(payload, object_pairs_hook=identity_object)
    if isinstance(proof, dict) and type(proof.get("schema_version")) is int and proof["schema_version"] == 2:
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise ValueError("invalid v2 identity proof mode")
        validate_identity_v2(proof, lane, mode, api, candidate, run_id, IDENTITY_PROBES)
        return list(IDENTITY_PROBES), True
    if (not isinstance(proof, dict) or set(proof) != {
            "schema_version", "candidate_sha", "lane", "mode", "rendering_api",
            "run_id", "probes", "containers"}
            or len(payload) > 4096
            or type(proof["schema_version"]) is not int or proof["schema_version"] != 1
            or proof["candidate_sha"] != candidate or proof["lane"] != lane
            or proof["mode"] != mode or proof["rendering_api"] != api
            or proof["run_id"] != run_id or proof["probes"] != list(IDENTITY_PROBES)):
        raise ValueError("identity proof binding or completion mismatch")
    containers = proof["containers"]
    checks = ("configured_user", "configured_workdir", "runtime_uid", "runtime_gid", "runtime_workdir")
    if not isinstance(containers, list) or len(containers) != 2:
        raise ValueError("incomplete identity pair")
    ids = []
    for role, record in zip(("oracle", "rendered"), containers):
        if (not isinstance(record, dict) or set(record) != {"role", "id", "name", "owner", "cleanup", *checks}
                or record["role"] != role or not isinstance(record["id"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["id"])
                or record["name"] != f"dl-identity-{run_id}-{role}"
                or record["owner"] != run_id or record["cleanup"] != "absent"
                or any(record[check] != "passed" for check in checks)):
            raise ValueError("invalid identity ownership or check")
        ids.append(record["id"])
    if len(set(ids)) != 2:
        raise ValueError("identity containers must be distinct")
    return list(IDENTITY_PROBES), False


def read_volume_probes(path: Path) -> list[str]:
    # This is a test-owned private file. No symlinks, devices, directories or
    # unbounded reads may reach the sanitized lane manifest.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 4096:
            raise ValueError("invalid native volume probe file")
        payload = source.read(4097)
    if len(payload) != metadata.st_size:
        raise ValueError("native volume probe file changed")
    probes = json.loads(payload)
    if (not isinstance(probes, list) or len(probes) != len(VOLUME_PROBES)
            or any(not isinstance(probe, str) for probe in probes)
            or set(probes) != set(VOLUME_PROBES)):
        raise ValueError("native volume probe set is incomplete")
    return list(VOLUME_PROBES)


def read_volume_label_probes(path: Path) -> list[str]:
    # The ignored native test owns this private file. Bound and validate it
    # before allowing any of its contents into the sanitized manifest.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 4096:
            raise ValueError("invalid native volume label probe file")
        payload = source.read(4097)
    if len(payload) != metadata.st_size:
        raise ValueError("native volume label probe file changed")
    probes = json.loads(payload)
    if (not isinstance(probes, list) or len(probes) != len(VOLUME_LABEL_PROBES)
            or any(not isinstance(probe, str) for probe in probes)
            or set(probes) != set(VOLUME_LABEL_PROBES)):
        raise ValueError("native volume label probe set is incomplete")
    return list(VOLUME_LABEL_PROBES)


def unique_proof_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native proof field")
        result[key] = value
    return result


def read_network_proof(path: Path) -> list[str]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 4096:
            raise ValueError("invalid native network proof file")
        payload = source.read(4097)
    if len(payload) != metadata.st_size:
        raise ValueError("native network proof file changed")
    proof = json.loads(payload, object_pairs_hook=unique_proof_object)
    if not isinstance(proof, dict) or set(proof) != {"probes", "internal_shape"}:
        raise ValueError("native network proof is incomplete")
    probes = proof["probes"]
    if (not isinstance(probes, list) or len(probes) != len(NETWORK_PROBES)
            or any(not isinstance(probe, str) for probe in probes)
            or set(probes) != set(NETWORK_PROBES)
            or proof["internal_shape"] != INTERNAL_PROOF):
        raise ValueError("native internal network proof is incomplete")
    return list(NETWORK_PROBES)


def emit(version_path: Path, shapes_path: Path, source_path: Path, network_path: Path, volume_path: Path, volume_label_path: Path, identity_path: Path, destination: Path, lane: str, image: str,
         mode: str, package: str, candidate_sha: str, run_id: str) -> None:
    if lane not in LANES or mode != lane.rsplit("-", 1)[1]:
        raise ValueError("invalid native lane or mode")
    if not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
        raise ValueError("invalid candidate SHA")
    if not re.fullmatch(r"[a-zA-Z0-9]{8}", run_id):
        raise ValueError("invalid identity run token")
    if not re.fullmatch(
        r"ghcr\.io/strukturpiloten/docker-(?:debian-11|29)-(?:rootful|rootless):"
        r"v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}", image,
    ) or image.rsplit("/", 1)[1].split(":", 1)[0] != "docker-" + (
        "debian-11" if lane.startswith("debian11-") else "29"
    ) + "-" + mode:
        raise ValueError("invalid native image identity")
    if lane.startswith("debian11-"):
        if package != "20.10.5+dfsg1-1+deb11u2":
            raise ValueError("invalid Debian package revision")
    elif package:
        raise ValueError("upstream image has no Debian Engine package")

    version = json.loads(version_path.read_text(encoding="utf-8"))
    engine = version.get("Version")
    maximum = version.get("ApiVersion")
    minimum = version.get("MinAPIVersion")
    expected_engines = ("20.10.5", "20.10.5+dfsg1") if lane.startswith("debian11-") else ("29.8.1",)
    if engine not in expected_engines:
        raise ValueError("unexpected Engine release")
    if not all(isinstance(value, str) and re.fullmatch(r"1\.[0-9]{1,3}", value)
               for value in (maximum, minimum)):
        raise ValueError("invalid Engine API bounds")
    selected = min(int(maximum.split(".")[1]), 49)
    if selected < 41 or int(minimum.split(".")[1]) > selected:
        raise ValueError("Engine API cannot be acquired")

    components = version.get("Components", [])
    if not isinstance(components, list):
        raise ValueError("invalid runtime components")
    runtime_components = {}
    for name in ("containerd", "runc"):
        matches = [item.get("Version") for item in components
                   if isinstance(item, dict) and item.get("Name") == name]
        if len(matches) > 1:
            raise ValueError("duplicate runtime component")
        value = matches[0] if matches else None
        if value is not None and (not isinstance(value, str) or
                                  not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,79}", value)):
            raise ValueError("invalid runtime component version")
        runtime_components[name] = value

    if shapes_path.stat().st_size > 4096:
        raise ValueError("native shape evidence exceeds closed limit")
    shapes = json.loads(shapes_path.read_text(encoding="utf-8"))
    if not isinstance(shapes, dict) or set(shapes) != set(CAPABILITIES):
        raise ValueError("native capability shape set is incomplete")
    for name, expected in REQUIRED_SHAPES.items():
        actual = shapes[name]
        if (not isinstance(actual, list) or len(actual) != len(expected)
                or any(not isinstance(item, str) for item in actual)
                or set(actual) != set(expected)):
            raise ValueError("native capability shape is incomplete")

    if source_path.stat().st_size > 4096:
        raise ValueError("native source evidence exceeds closed limit")
    source_probes = json.loads(source_path.read_text(encoding="utf-8"))
    if (not isinstance(source_probes, list) or len(source_probes) != len(SOURCE_PROBES)
            or any(not isinstance(probe, str) for probe in source_probes)
            or set(source_probes) != set(SOURCE_PROBES)):
        raise ValueError("native source probe set is incomplete")
    volume_probes = read_volume_probes(volume_path)
    volume_label_probes = read_volume_label_probes(volume_label_path)
    identity_probes, parameterized_identity = read_identity_proof(
        identity_path, lane, mode, maximum, candidate_sha, run_id)

    network_probes = read_network_proof(network_path)

    # Only these closed mappings follow the complete, validated native proof
    # files above. They extend raw lane evidence, never the reviewed catalogue.
    # Other network probes and source daemon reports grant no capability here.
    proof_shapes = {
        "NetworkInternal": ["InternalBridgeNetworkCreate"],
        "VolumeExternalReference": ["ExternalVolumeReference"],
        "VolumeLabels": ["VolumeCreateLabels"],
        "NetworkExternalReference": ["ExternalNetworkReference"],
    }
    if parameterized_identity:
        proof_shapes.update({"ContainerUser": ["ContainerUser"],
                             "ContainerWorkdir": ["ContainerWorkdir"]})

    record = {
        "schema_version": 1,
        "lane": lane,
        "candidate_sha": candidate_sha,
        "outer_image": image,
        "expected_mode": mode,
        "engine_version": engine,
        "engine_api_max": maximum,
        "engine_api_min": minimum,
        "acquisition_api": f"1.{selected}",
        "rendering_api": maximum,
        "debian_docker_package": package or None,
        "runtime_components": runtime_components,
        "capability_version": maximum,
        "capability_outcome": {**{name: "available" for name in CAPABILITIES},
                               **{name: "available" for name in proof_shapes}},
        "admitted_shapes": {**{name: list(REQUIRED_SHAPES[name]) for name in CAPABILITIES},
                            **proof_shapes},
        "source_probes": list(SOURCE_PROBES),
        "network_probes": list(NETWORK_PROBES),
        "volume_probes": volume_probes,
        "volume_label_probes": volume_label_probes,
        "identity_probes": identity_probes,
    }
    if parameterized_identity:
        record["identity_contract"] = IDENTITY_CONTRACT
        record["identity_cases"] = list(IDENTITY_CASES)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 15:
        raise SystemExit("usage: native-evidence.py VERSION_JSON SHAPES_JSON SOURCE_JSON NETWORK_JSON VOLUME_JSON VOLUME_LABEL_JSON IDENTITY_JSON DESTINATION LANE IMAGE MODE PACKAGE SHA RUN_ID")
    try:
        emit(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]),
             Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]), Path(sys.argv[8]), *sys.argv[9:])
    except (ValueError, OSError, json.JSONDecodeError, RecursionError):
        raise SystemExit("native evidence rejected") from None
