"""Closed network-attachments-v1 proof; never catalogue admission or attestation."""
import json
import os
import re
import stat
from pathlib import Path

CONTRACT = "network-attachments-v1"
FILENAME = "network-attachments-v1.json"
LIMIT = 16 * 1024
SHAPES = ("NetworkCreateLabels", "NetworkPrimaryAliases", "NetworkSecondaryAliases", "NetworkSecondaryConnect")
SLOTS = ("primary_network", "secondary_network", "server", "primary_peer", "secondary_peer")
CONTEXT_KEYS = frozenset(("candidate_sha", "run_id", "lane", "engine_release", "rendering_api",
                          "acquisition_api", "mode", "docker_package", "fixture_image", "outer"))
OUTER_KEYS = frozenset(("id", "name", "owner", "image", "data_volume", "socket_source",
                        "privileged", "memory_bytes", "cpu_quota", "cpu_period", "pids_limit"))
CHECKS = ("primary_only", "secondary_connected", "labels", "aliases", "running", "membership")
EFFECTS = ("unique_dns", "shared_dns", "named_http", "shared_http", "direct_http")


def fail():
    raise ValueError("incomplete network attachment proof")


def canonical(value, length=64):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None


def pinned(value):
    return isinstance(value, str) and re.fullmatch(r"[^\s@]+:[^/@\s]+@sha256:[0-9a-f]{64}", value) is not None


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        fail()


def validate_context(context):
    keys(context, CONTEXT_KEYS)
    lane = context["lane"]
    if lane not in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
        fail()
    debian = lane.startswith("debian11-")
    if (not canonical(context["candidate_sha"], 40)
            or not isinstance(context["run_id"], str) or re.fullmatch(r"[A-Za-z0-9]{8}", context["run_id"]) is None
            or context["mode"] != lane.rsplit("-", 1)[1]
            or context["rendering_api"] != ("1.41" if debian else "1.56")
            or context["acquisition_api"] != ("1.41" if debian else "1.49")
            or context["engine_release"] not in (("20.10.5", "20.10.5+dfsg1") if debian else ("29.8.1",))
            or context["docker_package"] != ("20.10.5+dfsg1-1+deb11u2" if debian else "")
            or not pinned(context["fixture_image"])):
        fail()
    outer = context["outer"]
    keys(outer, OUTER_KEYS)
    run = context["run_id"]
    if (not canonical(outer["id"]) or outer["name"] != f"dl-native-{run}"
            or outer["owner"] != run or not pinned(outer["image"])
            or outer["data_volume"] != f"dl-native-data-{run}"
            or not isinstance(outer["socket_source"], str) or not outer["socket_source"].startswith("/")
            or not outer["socket_source"].endswith("/socket")
            or outer["privileged"] is not True):
        fail()
    for key, expected in (("memory_bytes", 4294967296), ("cpu_quota", 200000),
                          ("cpu_period", 100000), ("pids_limit", 512)):
        if type(outer[key]) is not int or outer[key] != expected:
            fail()


def validate_network_attachment_proof(proof, expected_context):
    """Require independently supplied harness context; return only closed shapes.

    Private provenance and trusted-harness completion are not authentication
    against a privileged writer and cannot grant a sealed capability.
    """
    validate_context(expected_context)
    keys(proof, ("schema_version", "contract", "context", "roles", "shapes", "cleanup"))
    if (type(proof["schema_version"]) is not int or proof["schema_version"] != 1
            or proof["contract"] != CONTRACT or proof["context"] != expected_context
            or proof["shapes"] != list(SHAPES)
            or not isinstance(proof["roles"], list) or len(proof["roles"]) != 2):
        fail()
    validate_context(proof["context"])
    keys(proof["cleanup"], ("outcome", "rounds", "outstanding", "uncertain"))
    cleanup = proof["cleanup"]
    if (cleanup["outcome"] != "absent" or type(cleanup["rounds"]) is not int or cleanup["rounds"] != 2
            or type(cleanup["outstanding"]) is not int or cleanup["outstanding"] != 0
            or cleanup["uncertain"] is not False):
        fail()
    ids = {expected_context["outer"]["id"]}
    run = expected_context["run_id"]
    for role, record in zip(("oracle", "rendered"), proof["roles"]):
        keys(record, ("role", "request_check", "resources", "checks", "cleanup"))
        if (record["role"] != role
                or record["request_check"] != ("independent_cli" if role == "oracle" else "literal_rendered")
                or record["cleanup"] != "absent" or not isinstance(record["resources"], list)
                or len(record["resources"]) != len(SLOTS)):
            fail()
        for slot, resource in zip(SLOTS, record["resources"]):
            network = slot.endswith("network")
            resource_keys = {"slot", "kind", "id", "name", "owner", "configured", "cleanup"}
            if not network:
                resource_keys.add("image")
            keys(resource, resource_keys)
            if (resource["slot"] != slot or resource["kind"] != ("network" if network else "container")
                    or not canonical(resource["id"]) or resource["id"] in ids
                    or resource["name"] != f"dl-na-{run}-{role}-{slot.replace('_', '-')}"
                    or resource["owner"] != run or resource["configured"] != "passed"
                    or resource["cleanup"] != "absent"
                    or (not network and resource["image"] != expected_context["fixture_image"])):
                fail()
            ids.add(resource["id"])
        checks = record["checks"]
        keys(checks, (*CHECKS, "primary", "secondary"))
        if any(checks[key] != "passed" for key in CHECKS):
            fail()
        for side in ("primary", "secondary"):
            keys(checks[side], EFFECTS)
            if any(checks[side][key] != "passed" for key in EFFECTS):
                fail()
    return SHAPES


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_network_attachment_proof(path, capture_dir, expected_context):
    return read_private_proof(path, capture_dir, FILENAME, expected_context, validate_network_attachment_proof)


def read_private_proof(path, capture_dir, filename, expected_context, validator):
    """Read one stable, bounded, exclusive caller-private direct child."""
    directory = Path(os.path.abspath(capture_dir))
    path = Path(path)
    descriptors = []
    try:
        if (type(filename) is not str or not filename or filename in (".", "..") or Path(filename).name != filename
                or directory.resolve(strict=True) != directory or path != directory / filename):
            fail()
        parent = os.lstat(directory)
        uid = os.geteuid()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid
                or stat.S_IMODE(parent.st_mode) != 0o700):
            fail()
        ancestor = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(ancestor)
        held = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ancestor)
        descriptors.append(held)
        if fingerprint(os.fstat(held)) != fingerprint(parent):
            fail()
        source = os.open(filename, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=held)
        descriptors.append(source)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= LIMIT):
            fail()
        payload = os.read(source, LIMIT + 1)
        if (len(payload) != before.st_size or len(payload) > LIMIT
                or fingerprint(os.fstat(source)) != fingerprint(before)
                or fingerprint(os.stat(filename, dir_fd=held, follow_symlinks=False)) != fingerprint(before)
                or fingerprint(os.stat(directory.name, dir_fd=ancestor, follow_symlinks=False)) != fingerprint(parent)
                or fingerprint(os.lstat(directory)) != fingerprint(parent)
                or directory.resolve(strict=True) != directory):
            fail()
        proof = json.loads(payload, object_pairs_hook=unique_object)
        return validator(proof, expected_context)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError("invalid private network attachment proof") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
