"""Closed private device proof: configured mapping and bounded char read only."""
from hashlib import sha256
from pathlib import Path
import os
import re
import sys
from native_external_network_proof import validate_context
from native_network_attachment_proof import canonical, keys, read_private_proof
from native_shm_size_proof import exact, integer
from native_source_accounting import outer_snapshot_cost

CONTRACT = "device-mapping-v1"
FILENAME = CONTRACT + ".json"
MAPPING = [{"PathOnHost": "/dev/null", "PathInContainer": "/dev/native-null", "CgroupPermissions": "r"}]
RESULT = {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}


def fail():
    raise ValueError("invalid private device mapping proof")


def validate_effect(effect):
    keys(effect, ("report", "report_sha256", "nonsymlink", "kind", "rdev", "read", "binding"))
    exact(effect["nonsymlink"], True)
    exact(effect["kind"], "character")
    exact(effect["rdev"], {"major": 1, "minor": 3})
    exact(effect["read"], {"exit": 0, "max_bytes": 1, "bytes": 0})
    exact(effect["binding"], "held_fd_same_inode_before_after")
    report = effect["report"]
    if type(report) is not str or not 0 < len(report.encode()) <= 1024:
        fail()
    exact(effect["report_sha256"], sha256(report.encode()).hexdigest())
    # A rebound digest never establishes report semantics. Parse independent
    # expected source/null identity and all held-descriptor readback fields.
    lines = report.splitlines(keepends=True)
    if len(lines) != 5 or lines[0] != "source 1 3\n" or lines[3] != "read 0\n":
        fail()
    match = re.fullmatch(r"target (0|[1-9][0-9]{0,19}) ([1-9][0-9]{0,19}) 1 3\n", lines[1])
    if match is None:
        fail()
    integer(int(match[1]), 0, 2**64 - 1)
    integer(int(match[2]), 1, 2**64 - 1)
    suffix = f"{match[1]} {match[2]} 1 3\n"
    exact(lines[2], "opened " + suffix)
    exact(lines[4], "after " + suffix)


def validate_device_mapping_proof(proof, expected_context, *, outer_backend):
    """Require caller-bound context/backend; never infer authority from proof."""
    try:
        extra_calls, extra_bytes = outer_snapshot_cost(outer_backend)
        validate_context(expected_context)
        if not expected_context["fixture_image"].startswith("docker.io/library/busybox:"):
            fail()
        keys(proof, ("schema_version", "contract", "capability_admission", "catalogue_admission", "scope", "outer_backend",
                     "context", "borrowed_image", "containers", "daemon_health", "accounting", "cleanup"))
        for key, value in (("schema_version", 1), ("contract", CONTRACT), ("capability_admission", []),
                           ("catalogue_admission", False), ("scope", "configured_mapping_and_character_read_only"),
                           ("outer_backend", outer_backend), ("context", expected_context),
                           ("daemon_health", "version_matches_after_controls"),
                           ("cleanup", {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False})):
            exact(proof[key], value)
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        if type(proof["containers"]) is not list or len(proof["containers"]) != 2:
            fail()
        ids = {expected_context["outer"]["id"]}
        for item, role in zip(proof["containers"], ("oracle", "rendered")):
            keys(item, ("role", "id", "name", "owner", "image_id", "wire", "configured", "effect", "cleanup"))
            if not canonical(item["id"]) or item["id"] in ids:
                fail()
            ids.add(item["id"])
            for key, value in (("role", role), ("name", f"dl-device-{expected_context['run_id']}-{role}"),
                               ("owner", expected_context["run_id"]), ("image_id", image["id"]),
                               ("wire", "independent_cli" if role == "oracle" else "literal_rendered"), ("cleanup", "absent")):
                exact(item[key], value)
            configured = item["configured"]
            keys(configured, ("devices", "process", "running", "pid", "restarts"))
            for key, value in (("devices", MAPPING), ("process", "owned_pid1_loop"), ("running", True), ("restarts", 0)):
                exact(configured[key], value)
            integer(configured["pid"], 1, 2**31 - 1)
            validate_effect(item["effect"])
        a = proof["accounting"]
        keys(a, ("context_calls", "slot_calls", "daemon_health_calls", "final_readback_calls", "ordinary_calls", "ordinary_bytes",
                 "cleanup_calls", "cleanup_bytes", "deadline_seconds", "cleanup_reserve_seconds", "ordinary_elapsed_ns",
                 "cleanup_elapsed_ns", "elapsed_ns", "initial_context_acquisition"))
        context_calls = (9 if expected_context["lane"].startswith("debian11-") else 8) + extra_calls
        for key, value in (("context_calls", context_calls), ("slot_calls", [8, 8]), ("daemon_health_calls", 1),
                           ("final_readback_calls", 2 + extra_calls), ("ordinary_calls", context_calls + 19 + extra_calls),
                           ("cleanup_calls", 18), ("deadline_seconds", 180), ("cleanup_reserve_seconds", 46),
                           ("initial_context_acquisition", {"max_requests": 16, "max_total_bytes": 2097152,
                            "max_elapsed_seconds": 15, "accounting": "separate_existing_bound"})):
            exact(a[key], value)
        integer(a["ordinary_bytes"], 1 + 2 * extra_bytes, 2097152)
        integer(a["cleanup_bytes"], 1, 18 * (8192 + 2048))
        work = integer(a["ordinary_elapsed_ns"], 1, 134 * 10**9)
        cleanup = integer(a["cleanup_elapsed_ns"], 1, 46 * 10**9)
        total = integer(a["elapsed_ns"], 1, 180 * 10**9)
        if work + cleanup > total:
            fail()
        return dict(RESULT)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, IndexError, AttributeError):
        fail()


def read_device_mapping_proof(path, capture_dir, expected_context, *, outer_backend):
    try:
        outer_snapshot_cost(outer_backend)
        return read_private_proof(path, capture_dir, FILENAME, expected_context,
                                  lambda value, context: validate_device_mapping_proof(value, context, outer_backend=outer_backend))
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()


def main(arguments):
    if len(arguments) != 12:
        fail()
    directory, candidate, run, lane, engine, api, mode, package, fixture, image, outer_id, daemon_uid = arguments
    if re.fullmatch(r"0|[1-9][0-9]{0,9}", daemon_uid) is None:
        fail()
    context = {"candidate_sha": candidate, "run_id": run, "lane": lane, "engine_release": engine,
               "rendering_api": api, "acquisition_api": "1.41" if lane.startswith("debian11-") else "1.49",
               "mode": mode, "docker_package": package, "fixture_image": fixture, "daemon_uid": int(daemon_uid),
               "outer": {"id": outer_id, "name": "dl-native-" + run, "owner": run, "image": image,
                         "data_volume": "dl-native-data-" + run, "socket_source": str(Path(directory) / "socket"),
                         "privileged": True, "memory_bytes": 4294967296, "cpu_quota": 200000,
                         "cpu_period": 100000, "pids_limit": 512}}
    read_device_mapping_proof(Path(directory) / FILENAME, directory, context, outer_backend=os.environ.get("NATIVE_OUTER_ENGINE"))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise SystemExit("invalid private device mapping proof") from None
