"""Private configured-bind retention proof; no SELinux effects or admission."""
import json
import os
import re
import stat
from pathlib import Path

CONTRACT = "bind-relabel-config-v1"
FILENAME = "bind-relabel-config-v1.json"
LIMIT = 16 * 1024
SHAPES = ("BindMountSharedRelabelReadWrite", "BindMountSharedRelabelReadOnly",
          "BindMountPrivateRelabelReadWrite", "BindMountPrivateRelabelReadOnly")
CASES = ("shared-rw", "shared-ro", "private-rw", "private-ro")
CHECKS = ("source_boundary", "literal_bind", "native_mount", "running", "capture", "decoded_mount")
CONTEXT_KEYS = ("candidate_sha", "run_id", "lane", "engine_release", "rendering_api",
                "acquisition_api", "mode", "docker_package", "fixture_image", "outer", "source_boundary")
OUTER_KEYS = ("id", "name", "owner", "image", "data_volume", "socket_source", "privileged",
              "memory_bytes", "cpu_quota", "cpu_period", "pids_limit")


def fail():
    raise ValueError("incomplete bind relabel proof")


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        fail()


def canonical(value, length=64):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None


def pinned(value):
    return isinstance(value, str) and re.fullmatch(r"[^\s@]+:[^/@\s]+@sha256:[0-9a-f]{64}", value) is not None


def validate_context(context):
    keys(context, CONTEXT_KEYS)
    lane = context["lane"]
    if lane not in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
        fail()
    debian = lane.startswith("debian11-")
    rootless = lane.endswith("-rootless")
    run = context["run_id"]
    if (not canonical(context["candidate_sha"], 40)
            or not isinstance(run, str) or re.fullmatch(r"[A-Za-z0-9]{8}", run) is None
            or context["mode"] != ("rootless" if rootless else "rootful")
            or context["rendering_api"] != ("1.41" if debian else "1.56")
            or context["acquisition_api"] != ("1.41" if debian else "1.49")
            or context["engine_release"] not in (("20.10.5", "20.10.5+dfsg1") if debian else ("29.8.1",))
            or context["docker_package"] != ("20.10.5+dfsg1-1+deb11u2" if debian else "")
            or not pinned(context["fixture_image"])):
        fail()
    outer = context["outer"]
    keys(outer, OUTER_KEYS)
    if (not canonical(outer["id"]) or outer["name"] != f"dl-native-{run}"
            or outer["owner"] != run or not pinned(outer["image"])
            or outer["data_volume"] != f"dl-native-data-{run}"
            or not isinstance(outer["socket_source"], str)
            or not outer["socket_source"].startswith("/") or not outer["socket_source"].endswith("/socket")
            or outer["privileged"] is not True):
        fail()
    for key, expected in (("memory_bytes", 4294967296), ("cpu_quota", 200000),
                          ("cpu_period", 100000), ("pids_limit", 512)):
        if type(outer[key]) is not int or outer[key] != expected:
            fail()
    boundary = context["source_boundary"]
    keys(boundary, ("kind", "volume", "storage_root", "root", "owner", "owner_uid", "mode"))
    storage = "/home/docker/.local/share/docker" if rootless else "/var/lib/docker"
    if (boundary["kind"] != "owned_data_volume" or boundary["volume"] != outer["data_volume"]
            or boundary["storage_root"] != storage or boundary["root"] != f"{storage}/dl-bind-relabel-{run}"
            or boundary["owner"] != run or type(boundary["owner_uid"]) is not int
            or not 0 <= boundary["owner_uid"] <= 4294967295
            or (boundary["owner_uid"] != 0) != rootless or boundary["mode"] != "0700"):
        fail()


def validate_bind_relabel_proof(proof, expected_context):
    """Require independent harness context; disclose only the four fixed shapes."""
    validate_context(expected_context)
    keys(proof, ("schema_version", "contract", "context", "shapes", "cases", "cleanup", "selinux_effect"))
    if (type(proof["schema_version"]) is not int or proof["schema_version"] != 1
            or proof["contract"] != CONTRACT or proof["context"] != expected_context
            or proof["shapes"] != list(SHAPES) or proof["selinux_effect"] != "unverified"
            or not isinstance(proof["cases"], list) or len(proof["cases"]) != 4):
        fail()
    validate_context(proof["context"])
    cleanup = proof["cleanup"]
    keys(cleanup, ("containers", "sources", "rounds", "outstanding", "uncertain"))
    if (cleanup["containers"] != "absent" or cleanup["sources"] != "absent"
            or type(cleanup["rounds"]) is not int or cleanup["rounds"] != 2
            or type(cleanup["outstanding"]) is not int or cleanup["outstanding"] != 0
            or cleanup["uncertain"] is not False):
        fail()
    ids = {expected_context["outer"]["id"]}
    run = expected_context["run_id"]
    for case, shape, record in zip(CASES, SHAPES, proof["cases"]):
        keys(record, ("case", "shape", "roles"))
        if (record["case"] != case or record["shape"] != shape
                or not isinstance(record["roles"], list) or len(record["roles"]) != 2):
            fail()
        for role, result in zip(("oracle", "rendered"), record["roles"]):
            keys(result, ("role", "request_check", "id", "name", "owner", "image", "source_leaf",
                          "checks", "container_cleanup", "source_cleanup"))
            if (result["role"] != role
                    or result["request_check"] != ("independent_cli" if role == "oracle" else "literal_rendered")
                    or not canonical(result["id"]) or result["id"] in ids
                    or result["name"] != f"dl-br-{run}-{case}-{role}" or result["owner"] != run
                    or result["image"] != expected_context["fixture_image"]
                    or result["source_leaf"] != f"{case}-{role}"
                    or result["container_cleanup"] != "absent" or result["source_cleanup"] != "absent"):
                fail()
            ids.add(result["id"])
            keys(result["checks"], CHECKS)
            if any(result["checks"][check] != "passed" for check in CHECKS):
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


def read_bind_relabel_proof(path, capture_dir, expected_context):
    """Read a stable 0600 direct child of a canonical owner-private 0700 directory."""
    directory = Path(os.path.abspath(capture_dir))
    descriptors = []
    try:
        if directory.resolve(strict=True) != directory or Path(path) != directory / FILENAME:
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
        source = os.open(FILENAME, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=held)
        descriptors.append(source)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= LIMIT):
            fail()
        payload = os.read(source, LIMIT + 1)
        if (len(payload) != before.st_size or len(payload) > LIMIT
                or fingerprint(os.fstat(source)) != fingerprint(before)
                or fingerprint(os.stat(FILENAME, dir_fd=held, follow_symlinks=False)) != fingerprint(before)
                or fingerprint(os.stat(directory.name, dir_fd=ancestor, follow_symlinks=False)) != fingerprint(parent)
                or fingerprint(os.lstat(directory)) != fingerprint(parent)
                or directory.resolve(strict=True) != directory):
            fail()
        return validate_bind_relabel_proof(json.loads(payload, object_pairs_hook=unique_object), expected_context)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError("invalid private bind relabel proof") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
