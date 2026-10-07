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
PORT_SHAPES = (
    "FixedIpv4HostPort", "EphemeralIpv4HostPort", "FixedIpv6HostPort",
    "EphemeralIpv6HostPort", "MultipleFixedPortBindings",
    "MultipleEphemeralPortBindings", "ExposedOnlyPort", "EphemeralHostPort",
)
IPV6_PORT_SHAPES = frozenset(("FixedIpv6HostPort", "EphemeralIpv6HostPort"))
PORT_NEGATIVE_REASONS = frozenset((
    "nested_default_bridge_ipv6_unavailable",
    "nested_default_bridge_ipv6_runtime_binding_absent",
))
PORT_CAPABILITY_SHAPES = {
    "PortHostIpv4": ("FixedIpv4HostPort", "EphemeralIpv4HostPort"),
    "PortHostIpv6": ("FixedIpv6HostPort", "EphemeralIpv6HostPort"),
    "PortMultipleBindings": ("MultipleFixedPortBindings", "MultipleEphemeralPortBindings"),
    "PortExposeOnly": ("ExposedOnlyPort",),
    "PortEphemeral": ("EphemeralHostPort",),
}


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


def read_port_proof(path: Path, capture_dir: Path, lane: str, engine: str,
                    api: str, mode: str, candidate: str, run_id: str) -> list[dict[str, str]]:
    # The proof is private harness input. Hold the capture directory and read
    # its one exact child through openat so path replacement cannot redirect it.
    capture_abs = Path(os.path.abspath(capture_dir))
    capture_real = capture_abs.resolve(strict=True)
    if capture_abs != capture_real or path.name != "port-probes.json":
        raise ValueError("invalid native port proof location")
    parent_info = os.lstat(capture_abs)
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
        raise ValueError("invalid native port proof directory")
    ancestor_fd = os.open(capture_abs.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory_fd = os.open(capture_abs, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        os.close(ancestor_fd)
        raise
    try:
        directory_before = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory_before.st_mode)
                or directory_before.st_uid != os.geteuid()
                or directory_before.st_mode & 0o077
                or (directory_before.st_dev, directory_before.st_ino) !=
                   (parent_info.st_dev, parent_info.st_ino)):
            raise ValueError("invalid private native port proof directory")
        ancestor_before = os.fstat(ancestor_fd)
        named_parent_before = os.stat(capture_abs.name, dir_fd=ancestor_fd,
                                      follow_symlinks=False)
        if ((directory_before.st_dev, directory_before.st_ino) !=
                (named_parent_before.st_dev, named_parent_before.st_ino)
                or not stat.S_ISDIR(named_parent_before.st_mode)):
            raise ValueError("native port capture directory changed")
        expected_path = capture_abs / "port-probes.json"
        if path != expected_path and Path(os.path.abspath(path)) != expected_path:
            raise ValueError("native port proof is not a direct capture child")
        descriptor = os.open("port-probes.json", os.O_RDONLY | os.O_NONBLOCK |
                             os.O_NOFOLLOW, dir_fd=directory_fd)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if (not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 4096
                    or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_nlink != 1):
                raise ValueError("invalid private native port proof")
            payload = source.read(4097)
            source.seek(0)
            repeated_payload = source.read(4097)
            after = os.fstat(source.fileno())
        current_parent = os.fstat(directory_fd)
        current_ancestor = os.fstat(ancestor_fd)
        current_path_parent = os.lstat(capture_abs)
        current_named_parent = os.stat(capture_abs.name, dir_fd=ancestor_fd,
                                       follow_symlinks=False)
        current_leaf = os.stat("port-probes.json", dir_fd=directory_fd,
                               follow_symlinks=False)
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_uid,
             before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
             after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or len(payload) != before.st_size
                or repeated_payload != payload
                or (before.st_dev, before.st_ino) !=
                   (current_leaf.st_dev, current_leaf.st_ino)
                or not stat.S_ISREG(current_leaf.st_mode)
                or (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                    before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                   (current_leaf.st_dev, current_leaf.st_ino, current_leaf.st_mode,
                    current_leaf.st_uid, current_leaf.st_nlink, current_leaf.st_size,
                    current_leaf.st_mtime_ns, current_leaf.st_ctime_ns)
                or (directory_before.st_dev, directory_before.st_ino) !=
                   (current_parent.st_dev, current_parent.st_ino)
                or (directory_before.st_dev, directory_before.st_ino,
                    directory_before.st_mode, directory_before.st_uid,
                    directory_before.st_nlink, directory_before.st_mtime_ns,
                    directory_before.st_ctime_ns) !=
                   (current_parent.st_dev, current_parent.st_ino,
                    current_parent.st_mode, current_parent.st_uid,
                    current_parent.st_nlink, current_parent.st_mtime_ns,
                    current_parent.st_ctime_ns)
                or current_parent.st_uid != os.geteuid()
                or current_parent.st_mode & 0o077
                or (directory_before.st_dev, directory_before.st_ino) !=
                   (current_named_parent.st_dev, current_named_parent.st_ino)
                or not stat.S_ISDIR(current_named_parent.st_mode)
                or (directory_before.st_dev, directory_before.st_ino) !=
                   (current_path_parent.st_dev, current_path_parent.st_ino)
                or not stat.S_ISDIR(current_path_parent.st_mode)
                or current_path_parent.st_uid != os.geteuid()
                or current_path_parent.st_mode & 0o077
                or capture_abs.resolve(strict=True) != capture_abs
                or (ancestor_before.st_dev, ancestor_before.st_ino) !=
                   (current_ancestor.st_dev, current_ancestor.st_ino)):
            raise ValueError("native port proof changed")
    finally:
        os.close(directory_fd)
        os.close(ancestor_fd)

    proof = json.loads(payload, object_pairs_hook=unique_proof_object)
    if (not isinstance(proof, dict) or set(proof) != {
            "schema_version", "kind", "candidate_sha", "lane", "engine_release",
            "rendering_api", "daemon_mode", "run_id", "cleanup", "probes"}
            or type(proof["schema_version"]) is not int or proof["schema_version"] != 1
            or proof["kind"] != "dockerlens-native-port-probes"
            or proof["candidate_sha"] != candidate or proof["lane"] != lane
            or proof["engine_release"] != engine or proof["rendering_api"] != api
            or proof["daemon_mode"] != mode or proof["run_id"] != run_id
            or proof["cleanup"] != "absent"):
        raise ValueError("native port proof binding mismatch")
    probes = proof["probes"]
    if (not isinstance(probes, dict) or set(probes) !=
            {"schema_version", "positive", "expected_negative"}
            or type(probes["schema_version"]) is not int or probes["schema_version"] != 1):
        raise ValueError("native port probe schema mismatch")
    positive = probes["positive"]
    negative = probes["expected_negative"]
    if not isinstance(positive, list) or not isinstance(negative, list):
        raise ValueError("native port outcomes are incomplete")
    positive_set = set()
    for shape in positive:
        if not isinstance(shape, str) or shape not in PORT_SHAPES or shape in positive_set:
            raise ValueError("invalid native positive port outcome")
        positive_set.add(shape)
    negative_by_shape = {}
    for outcome in negative:
        if not isinstance(outcome, dict) or set(outcome) != {"shape", "reason"}:
            raise ValueError("invalid native negative port outcome")
        shape, reason = outcome["shape"], outcome["reason"]
        if (not isinstance(shape, str) or shape not in PORT_SHAPES
                or shape in negative_by_shape or shape in positive_set
                or not isinstance(reason, str) or reason not in PORT_NEGATIVE_REASONS
                or not lane.startswith("debian11-") or shape not in IPV6_PORT_SHAPES):
            raise ValueError("unsupported native negative port outcome")
        negative_by_shape[shape] = reason
    if positive_set | set(negative_by_shape) != set(PORT_SHAPES) or \
            positive_set & set(negative_by_shape):
        raise ValueError("native port outcome coverage is incomplete")
    if positive != [shape for shape in PORT_SHAPES if shape in positive_set] or \
            [entry["shape"] for entry in negative] != [
                shape for shape in PORT_SHAPES if shape in negative_by_shape]:
        raise ValueError("native port outcomes are not canonical")
    return [
        ({"shape": shape, "outcome": "observed"} if shape in positive_set else
         {"shape": shape, "outcome": "expected_negative", "reason": negative_by_shape[shape]})
        for shape in PORT_SHAPES
    ]


def emit(version_path: Path, shapes_path: Path, source_path: Path, network_path: Path, volume_path: Path, volume_label_path: Path, identity_path: Path, port_path: Path, capture_dir: Path, destination: Path, lane: str, image: str,
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
    port_probes = read_port_proof(port_path, capture_dir, lane, engine,
                                  maximum, mode, candidate_sha, run_id)

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
    # read_port_proof has already required all eight ordered, bound outcomes.
    # Map only complete positive groups, matching NativeCapabilityShape::required_for.
    # A prescribed Debian IPv6 boundary withholds that whole group, not the others.
    observed_port_shapes = {entry["shape"] for entry in port_probes
                            if entry["outcome"] == "observed"}
    for capability, required in PORT_CAPABILITY_SHAPES.items():
        if all(shape in observed_port_shapes for shape in required):
            proof_shapes[capability] = list(required)

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
        "port_probes": port_probes,
    }
    if parameterized_identity:
        record["identity_contract"] = IDENTITY_CONTRACT
        record["identity_cases"] = list(IDENTITY_CASES)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 17:
        raise SystemExit("usage: native-evidence.py VERSION_JSON SHAPES_JSON SOURCE_JSON NETWORK_JSON VOLUME_JSON VOLUME_LABEL_JSON IDENTITY_JSON PORT_JSON CAPTURE_DIR DESTINATION LANE IMAGE MODE PACKAGE SHA RUN_ID")
    try:
        emit(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]),
             Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]), Path(sys.argv[8]),
             Path(sys.argv[9]), Path(sys.argv[10]), *sys.argv[11:])
    except (ValueError, OSError, json.JSONDecodeError, RecursionError):
        raise SystemExit("native evidence rejected") from None
