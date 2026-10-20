"""Closed private shm-size-v1 proof reader; no runtime calls or admission."""

import re
import sys
from pathlib import Path

from native_external_network_proof import validate_context
from native_network_attachment_proof import canonical, keys, read_private_proof

CONTRACT = "shm-size-v1"
FILENAME = "shm-size-v1.json"
SCOPE = "explicit_1MiB_2MiB_with_observed_omission_only"
CASES = (("omitted", None), ("one_mib", 1048576), ("two_mib", 2097152))
SECOND = 1_000_000_000
CONTROL_BYTES = 3145728
ACQUISITION_BYTES = 512 * 1024
WORK_BYTES = 2 * 1024 * 1024
RECORD_FIELDS = (
    "role", "id", "name", "owner", "image_id", "wire", "configured_size_bytes",
    "filesystem", "mount_access", "ipc_mode", "ipc_namespace", "statfs_unit",
    "statfs_blocks", "capacity_bytes", "canary", "payload_bytes", "write_outcome",
    "running_after", "restart_count", "oom_killed", "cleanup",
)


def fail():
    raise ValueError("invalid private shm size proof")


def exact(value, expected):
    """Typed recursive equality: true must never satisfy an integer witness."""
    if type(value) is not type(expected):
        fail()
    if isinstance(expected, dict):
        keys(value, expected)
        for key, child in expected.items():
            exact(value[key], child)
    elif isinstance(expected, list):
        if len(value) != len(expected):
            fail()
        for child, other in zip(value, expected):
            exact(child, other)
    elif value != expected:
        fail()


def integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        fail()
    return value


def validate_shm_size_proof(proof, expected_context):
    """Caller supplies independently bound context, never values from the proof."""
    try:
        validate_context(expected_context)
        if not expected_context["fixture_image"].startswith("docker.io/library/busybox:"):
            fail()
        keys(proof, ("schema_version", "contract", "capability_admission", "catalogue_admission",
                     "scope", "context", "borrowed_image", "cases", "acquisition", "accounting", "cleanup"))
        for key, value in (("schema_version", 1), ("contract", CONTRACT), ("scope", SCOPE),
                           ("capability_admission", []), ("catalogue_admission", False),
                           ("context", expected_context)):
            exact(proof[key], value)
        validate_context(proof["context"])
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        exact(proof["cleanup"], {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False})
        acquisition = proof["acquisition"]
        keys(acquisition, ("route", "selected_ids", "requested_api", "reserved_calls", "reserved_bytes",
                           "actual_requests", "actual_response_bytes", "decoded", "limits", "byte_scope", "separate_transport_bounds",
                           "daemon_mode_evidence"))
        for key, value in (("route", "explicit_unix_socket"), ("selected_ids", 6),
                           ("requested_api", expected_context["acquisition_api"]),
                           ("reserved_calls", 16), ("reserved_bytes", ACQUISITION_BYTES),
                           ("byte_scope", "decoded_response_bodies_only"),
                           ("decoded", "present_effective_exact_sizes")):
            exact(acquisition[key], value)
        exact(acquisition["separate_transport_bounds"], {"response_header_bytes": 16384, "chunk_line_bytes": 64,
              "chunk_payload_crlf_bytes": 2, "final_trailer_line_bytes": 16384, "actual_wire_bytes": "not_measured"})
        modes = ("rootless_observed",) if expected_context["mode"] == "rootless" else (
            "rootful_observed", "unknown_with_independent_rootful_context")
        if acquisition["daemon_mode_evidence"] not in modes:
            fail()
        exact(acquisition["limits"], {"max_requests": 16, "max_selected_resources": 6, "max_expansions": 8,
                                     "max_response_bytes": 128 * 1024, "max_total_bytes": ACQUISITION_BYTES,
                                     "max_elapsed_seconds": 10})
        integer(acquisition["actual_requests"], 8, 16)
        integer(acquisition["actual_response_bytes"], 1, ACQUISITION_BYTES)
        accounting = proof["accounting"]
        keys(accounting, ("ordinary_calls", "ordinary_bytes", "cleanup_calls", "cleanup_bytes",
                          "deadline_seconds", "cleanup_reserve_seconds", "ordinary_elapsed_ns",
                          "cleanup_elapsed_ns", "elapsed_ns", "initial_context_acquisition"))
        exact(accounting["ordinary_calls"], 75 if expected_context["lane"].startswith("debian11-") else 74)
        integer(accounting["ordinary_bytes"], ACQUISITION_BYTES + 1, WORK_BYTES)
        exact(accounting["cleanup_calls"], 54)
        integer(accounting["cleanup_bytes"], 1, 54 * (8192 + 2048))
        exact(accounting["deadline_seconds"], 180)
        exact(accounting["cleanup_reserve_seconds"], 46)
        ordinary = integer(accounting["ordinary_elapsed_ns"], 1, 134 * SECOND)
        cleanup = integer(accounting["cleanup_elapsed_ns"], 1, 46 * SECOND)
        total = integer(accounting["elapsed_ns"], 1, 180 * SECOND)
        if ordinary + cleanup > total:
            fail()
        exact(accounting["initial_context_acquisition"], {
            "max_requests": 16, "max_total_bytes": WORK_BYTES, "max_elapsed_seconds": 15,
            "accounting": "separate_existing_bound",
        })
        if type(proof["cases"]) is not list or len(proof["cases"]) != len(CASES):
            fail()
        ids = {expected_context["outer"]["id"]}
        namespaces = set()
        defaults = []
        for case, (name, authored) in zip(proof["cases"], CASES):
            keys(case, ("case", "authored_size_bytes", "containers"))
            exact(case["case"], name)
            exact(case["authored_size_bytes"], authored)
            if type(case["containers"]) is not list or len(case["containers"]) != 2:
                fail()
            for item, role in zip(case["containers"], ("oracle", "rendered")):
                keys(item, RECORD_FIELDS)
                if not canonical(item["id"]) or item["id"] in ids:
                    fail()
                ids.add(item["id"])
                for key, value in (("role", role), ("name", f"dl-shm-{expected_context['run_id']}-{name}-{role}"),
                                   ("owner", expected_context["run_id"]), ("image_id", image["id"]),
                                   ("wire", "independent_cli" if role == "oracle" else "literal_rendered"),
                                   ("filesystem", "tmpfs"), ("mount_access", "rw"), ("ipc_mode", "private"),
                                   ("canary", "own_value_retained_after_all_six_seeds"), ("running_after", True),
                                   ("restart_count", 0), ("oom_killed", False), ("cleanup", "absent")):
                    exact(item[key], value)
                namespace = integer(item["ipc_namespace"], 1, 2**64 - 1)
                if namespace in namespaces:
                    fail()
                namespaces.add(namespace)
                capacity = integer(item["capacity_bytes"], 1, 2**63 - 1)
                exact(item["configured_size_bytes"], capacity)
                unit = integer(item["statfs_unit"], 4096, 65536)
                blocks = integer(item["statfs_blocks"], 1, 2**63 - 1)
                if unit & (unit - 1) or unit * blocks != capacity:
                    fail()
                if authored is None:
                    if capacity < CONTROL_BYTES:
                        fail()
                    defaults.append(capacity)
                    exact(item["payload_bytes"], CONTROL_BYTES)
                    exact(item["write_outcome"], "three_mib_written_readback")
                else:
                    exact(capacity, authored)
                    exact(item["payload_bytes"], authored)
                    exact(item["write_outcome"], "exact_saturation_native_enospc")
        if defaults[0] != defaults[1]:
            fail()
        return {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, IndexError):
        fail()


def read_shm_size_proof(path, capture_dir, expected_context):
    """Borrow the stable no-follow/single-link/0600 direct-child reader."""
    try:
        return read_private_proof(path, capture_dir, FILENAME, expected_context, validate_shm_size_proof)
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
                         "privileged": True, "memory_bytes": 4294967296,
                         "cpu_quota": 200000, "cpu_period": 100000, "pids_limit": 512}}
    read_shm_size_proof(Path(directory) / FILENAME, directory, context)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise SystemExit("invalid private shm size proof") from None
