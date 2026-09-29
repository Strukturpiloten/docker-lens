#!/usr/bin/env python3
"""Emit closed, reviewable native evidence only after all lane checks pass."""

import json
import os
import re
import stat
import sys
from pathlib import Path


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
VOLUME_PROBES = (
    "ExistingVolumePrerequisite", "ExistingVolumeTargetIdentity",
    "ExistingVolumeReadOnlyData", "ExistingVolumeReadWriteData",
    "ExistingVolumePersistence", "MissingVolumePrecheck",
)
VOLUME_LABEL_PROBES = (
    "VolumeCreateLabels", "VolumeLabelInspect",
    "VolumeLabelPersistence", "VolumeLabelOwnershipCleanup",
)

CONTAINER_PROBES = (
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
)
START_INTERVAL_NEGATIVES = [
    {"shape": "HealthStartIntervalPositive", "reason": "api_1_41_no_start_interval"},
    {"shape": "HealthStartIntervalZero", "reason": "api_1_41_start_interval_zero_unobservable"},
]
DEBIAN_IPV6_NEGATIVES = {
    "FixedIpv6HostPort": "nested_default_bridge_ipv6_unavailable",
    "EphemeralIpv6HostPort": "nested_default_bridge_ipv6_unavailable",
}


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native container evidence key")
        result[key] = value
    return result


def read_container_probes(path: Path, lane: str) -> dict:
    # Match the volume-probe boundary: only a bounded, regular, non-symlink
    # private test file can contribute to a sanitized lane manifest.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 4096:
            raise ValueError("invalid native container probe file")
        payload = source.read(4097)
    if len(payload) != metadata.st_size:
        raise ValueError("native container probe file changed")
    probes = json.loads(payload, object_pairs_hook=unique_object)
    if (not isinstance(probes, dict) or set(probes) !=
            {"schema_version", "positive", "expected_negative"}
            or type(probes["schema_version"]) is not int
            or probes["schema_version"] != 1):
        raise ValueError("invalid native container evidence schema")
    positive = probes["positive"]
    negative = probes["expected_negative"]
    if (not isinstance(positive, list) or not isinstance(negative, list)
            or any(not isinstance(shape, str) for shape in positive)
            or any(not isinstance(item, dict) or set(item) != {"shape", "reason"}
                   or not isinstance(item["shape"], str)
                   or not isinstance(item["reason"], str) for item in negative)):
        raise ValueError("invalid native container probe outcome")
    negatives = [item["shape"] for item in negative]
    if (len(positive) != len(set(positive)) or len(negatives) != len(set(negatives))
            or set(positive) & set(negatives)
            or set(positive) | set(negatives) != set(CONTAINER_PROBES)):
        raise ValueError("native container probe set is incomplete")
    expected_negative = []
    if lane.startswith("debian11-"):
        expected_negative = START_INTERVAL_NEGATIVES + [
            {"shape": shape, "reason": reason}
            for shape, reason in DEBIAN_IPV6_NEGATIVES.items()
            if shape in negatives
        ]
        expected_negative.sort(key=lambda item: item["shape"])
    if negative != expected_negative:
        raise ValueError("native container probe outcome contradicts exact lane boundary")
    negative_shapes = {item["shape"] for item in expected_negative}
    expected_positive = [shape for shape in CONTAINER_PROBES if shape not in negative_shapes]
    return {"schema_version": 1, "positive": expected_positive,
            "expected_negative": expected_negative}


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


def emit(version_path: Path, shapes_path: Path, source_path: Path, network_path: Path,
         volume_path: Path, container_path: Path, volume_label_path: Path,
         destination: Path, lane: str, image: str,
         mode: str, package: str, candidate_sha: str) -> None:
    if lane not in LANES or mode != lane.rsplit("-", 1)[1]:
        raise ValueError("invalid native lane or mode")
    if not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
        raise ValueError("invalid candidate SHA")
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
    if maximum != ("1.41" if lane.startswith("debian11-") else "1.56"):
        raise ValueError("unexpected exact lane API")
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

    if network_path.stat().st_size > 4096:
        raise ValueError("native network evidence exceeds closed limit")
    network_probes = json.loads(network_path.read_text(encoding="utf-8"))
    if (not isinstance(network_probes, list) or len(network_probes) != len(NETWORK_PROBES)
            or any(not isinstance(probe, str) for probe in network_probes)
            or set(network_probes) != set(NETWORK_PROBES)):
        raise ValueError("native network probe set is incomplete")

    container_probes = read_container_probes(container_path, lane)

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
        "capability_outcome": {name: "available" for name in CAPABILITIES},
        "admitted_shapes": {name: list(REQUIRED_SHAPES[name]) for name in CAPABILITIES},
        "source_probes": list(SOURCE_PROBES),
        "network_probes": list(NETWORK_PROBES),
        "volume_probes": volume_probes,
        "container_probes": container_probes,
        "volume_label_probes": volume_label_probes,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 14:
        raise SystemExit("usage: native-evidence.py VERSION_JSON SHAPES_JSON SOURCE_JSON NETWORK_JSON VOLUME_JSON CONTAINER_JSON VOLUME_LABEL_JSON DESTINATION LANE IMAGE MODE PACKAGE SHA")
    try:
        emit(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]),
             Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]), Path(sys.argv[8]), *sys.argv[9:])
    except (ValueError, OSError, json.JSONDecodeError):
        raise SystemExit("native evidence rejected") from None
