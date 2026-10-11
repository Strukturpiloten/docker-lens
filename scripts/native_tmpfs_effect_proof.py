"""Prepared closed tmpfs-effect-v1 reader; no runtime calls or admission."""

import json
import os
import re
import stat

CONTRACT = "tmpfs-effect-v1"
FILENAME = "tmpfs-effect-v1.json"
COVERAGE = "explicit_1MiB_0700_and_2MiB_0750_rw_ro_only"
CASES = ((1048576, 0o700, False), (1048576, 0o700, True),
         (2097152, 0o750, False), (2097152, 0o750, True))
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
HEX = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
RUN = re.compile(r"[a-zA-Z0-9]{8}\Z")


class ContractError(ValueError):
    """Value-free refusal, not a native unsupported-effect result."""


def require(condition):
    if not condition:
        raise ContractError("tmpfs proof refused")


def fields(value, keys):
    require(type(value) is dict and set(value) == set(keys.split()))


def exact(actual, expected):
    """Recursive equality that does not confuse bool with integers."""
    require(type(actual) is type(expected))
    if type(expected) is dict:
        require(set(actual) == set(expected))
        for key in expected:
            exact(actual[key], expected[key])
    elif type(expected) is list:
        require(len(actual) == len(expected))
        for left, right in zip(actual, expected):
            exact(left, right)
    else:
        require(actual == expected)


def hexadecimal(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def image_id(value):
    return type(value) is str and value.startswith("sha256:") and hexadecimal(value[7:])


def context(value):
    fields(value, "candidate_sha run_id lane engine_release rendering_api acquisition_api mode docker_package fixture_image daemon_uid outer")
    require(type(value["candidate_sha"]) is str and SHA.fullmatch(value["candidate_sha"]))
    require(type(value["run_id"]) is str and RUN.fullmatch(value["run_id"]))
    require(value["lane"] in LANES)
    debian = value["lane"].startswith("debian11-")
    exact(value["mode"], value["lane"].rsplit("-", 1)[1])
    exact(value["rendering_api"], "1.41" if debian else "1.56")
    exact(value["acquisition_api"], "1.41" if debian else "1.49")
    exact(value["docker_package"], "20.10.5+dfsg1-1+deb11u2" if debian else "")
    require(value["engine_release"] in (("20.10.5", "20.10.5+dfsg1") if debian else ("29.8.1",)))
    require(type(value["daemon_uid"]) is int and value["daemon_uid"] >= 0)
    require((value["daemon_uid"] == 0) == (value["mode"] == "rootful"))
    fixture = value["fixture_image"]
    require(type(fixture) is str and len(fixture) <= 256 and not any(c.isspace() for c in fixture))
    require(fixture.startswith("docker.io/library/busybox:") and "@" in fixture)
    require(image_id(fixture.rsplit("@", 1)[1]))
    outer = value["outer"]
    fields(outer, "id name owner image data_volume socket_source privileged memory_bytes cpu_quota cpu_period pids_limit")
    require(hexadecimal(outer["id"]))
    exact(outer["name"], "dl-native-" + value["run_id"])
    exact(outer["owner"], value["run_id"])
    exact(outer["data_volume"], "dl-native-data-" + value["run_id"])
    require(type(outer["image"]) is str and len(outer["image"]) <= 256 and "@" in outer["image"])
    require(image_id(outer["image"].rsplit("@", 1)[1]))
    require(type(outer["socket_source"]) is str and outer["socket_source"].startswith("/") and len(outer["socket_source"]) <= 4096)
    for key, expected in (("privileged", True), ("memory_bytes", 4294967296),
                          ("cpu_quota", 200000), ("cpu_period", 100000), ("pids_limit", 512)):
        exact(outer[key], expected)


def validate(proof, expected_context):
    """Expected context MUST come independently from the trusted harness.

    This is one lane, not four-lane qualification. Returned values deliberately
    contain no capabilities/shapes and cannot admit the numeric option domain.
    """
    context(expected_context)
    fields(proof, "schema_version contract admission context apis borrowed_image cases limits coverage cleanup")
    exact(proof["schema_version"], 1)
    exact(proof["contract"], CONTRACT)
    exact(proof["admission"], "unadmitted")
    context(proof["context"])
    exact(proof["context"], expected_context)
    api = expected_context["rendering_api"]
    exact(proof["apis"], {"fixture_cli": api, "renderer": api, "request": api})
    borrowed = proof["borrowed_image"]
    fields(borrowed, "id identity removal")
    require(image_id(borrowed["id"]))
    exact(borrowed["identity"], "unchanged")
    exact(borrowed["removal"], "not_owned")
    exact(proof["limits"], {"containers": 8, "deadline_seconds": 180, "retries": 0})
    exact(proof["coverage"], COVERAGE)
    exact(proof["cleanup"], {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False})
    require(type(proof["cases"]) is list and len(proof["cases"]) == 4)
    seen = {expected_context["outer"]["id"]}
    for number, (size, mode, read_only) in enumerate(CASES):
        case = proof["cases"][number]
        fields(case, "size_bytes mode read_only containers")
        for key, expected in (("size_bytes", size), ("mode", mode), ("read_only", read_only)):
            exact(case[key], expected)
        require(type(case["containers"]) is list and len(case["containers"]) == 2)
        for role_number, role in enumerate(("oracle", "rendered")):
            item = case["containers"][role_number]
            fields(item, "role id name owner image_id configuration effect")
            exact(item["role"], role)
            require(hexadecimal(item["id"]) and item["id"] not in seen)
            seen.add(item["id"])
            exact(item["name"], f"dl-tmpfs-{expected_context['run_id']}-{2 * number + role_number}")
            exact(item["owner"], expected_context["run_id"])
            exact(item["image_id"], borrowed["id"])
            exact(item["configuration"], {"type": "tmpfs", "target": "/dl-tmpfs",
                  "size_bytes": size, "mode": mode, "read_only": read_only})
            exact(item["effect"], {"filesystem": "tmpfs", "capacity_bytes": size,
                  "mode": mode, "mount_access": "ro" if read_only else "rw",
                  "write_outcome": "refused" if read_only else "written_then_enospc",
                  "saturation_bytes": 0 if read_only else size})
    return {"contract": CONTRACT, "admission": "unadmitted", "coverage": COVERAGE}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def identity(metadata):
    # Reading may change atime; it is not an identity or content guard.
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def read_proof(path):
    """Read a bounded owner-private regular file, never a symlink or hardlink.

    Caller supplies an already authenticated private directory, not an arbitrary
    path from the proof. No CLI/runtime/emitter registration is provided here.
    """
    descriptor = directory_fd = None
    try:
        directory = os.path.dirname(path)
        require(os.path.isabs(path) and os.path.basename(path) == FILENAME)
        require(os.path.realpath(directory) == directory)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        held = os.fstat(directory_fd)
        require(held.st_uid == os.getuid() and stat.S_IMODE(held.st_mode) == 0o700)
        descriptor = os.open(FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory_fd)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600)
        require(0 < before.st_size <= 16384)
        data = os.read(descriptor, 16385)
        after = os.fstat(descriptor)
        named = os.stat(FILENAME, dir_fd=directory_fd, follow_symlinks=False)
        directory_now = os.stat(directory, follow_symlinks=False)
        require(len(data) == before.st_size and identity(before) == identity(after)
                and identity(after) == identity(named))
        require(directory_now.st_dev == held.st_dev and directory_now.st_ino == held.st_ino
                and stat.S_IMODE(directory_now.st_mode) == 0o700
                and directory_now.st_uid == os.getuid()
                and os.path.realpath(directory) == directory)
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: require(False))
    except (OSError, UnicodeError, ValueError, RecursionError, TypeError):
        raise ContractError("tmpfs proof refused") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)
