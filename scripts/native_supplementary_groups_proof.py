"""Strict private supplementary-groups-v1 reader; never admission or I/O oracle."""

from pathlib import Path
import re
import sys
import os

from native_source_accounting import outer_snapshot_cost
from native_external_network_proof import validate_context
from native_network_attachment_proof import canonical, keys, read_private_proof

CONTRACT = "supplementary-groups-v1"
FILENAME = "supplementary-groups-v1.json"
SCOPE = "numeric_nonroot_omitted_one_pair_dac_only"
CASES = (("omitted", []), ("one", [23456]), ("pair", [23456, 34567]))
SECOND = 1_000_000_000
BODY_ALLOWANCE = 524288


def fail():
    raise ValueError("invalid private supplementary groups proof")


def exact(value, expected):
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


def validate_supplementary_groups_proof(proof, expected_context, *, outer_backend):
    try:
        extra_calls, extra_bytes = outer_snapshot_cost(outer_backend)
        validate_context(expected_context)
        if not expected_context["fixture_image"].startswith("docker.io/library/busybox:"):
            fail()
        keys(proof, ("schema_version", "contract", "scope", "capability_admission", "catalogue_admission",
                     "context", "borrowed_image", "cases", "acquisition", "accounting", "cleanup"))
        for key, value in (("schema_version", 1), ("contract", CONTRACT), ("scope", SCOPE),
                           ("capability_admission", []), ("catalogue_admission", False), ("context", expected_context)):
            exact(proof[key], value)
        validate_context(proof["context"])
        borrowed = proof["borrowed_image"]
        keys(borrowed, ("id", "identity", "removal"))
        if type(borrowed["id"]) is not str or not borrowed["id"].startswith("sha256:") or not canonical(borrowed["id"][7:]):
            fail()
        exact(borrowed["identity"], "unchanged")
        exact(borrowed["removal"], "not_owned")
        exact(proof["cleanup"], {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False})
        acquired = proof["acquisition"]
        keys(acquired, ("selected_ids", "route", "api", "daemon_mode_evidence", "reserved_calls", "reserved_body_bytes",
                        "actual_requests", "actual_body_bytes", "decoded", "byte_scope", "limits", "separate_transport_bounds"))
        for key, value in (("selected_ids", 6), ("route", "explicit_unix_socket"), ("api", expected_context["acquisition_api"]),
                           ("reserved_calls", 16), ("reserved_body_bytes", BODY_ALLOWANCE),
                           ("decoded", "effective_user_and_groupadd_agree"), ("byte_scope", "decoded_response_bodies_only")):
            exact(acquired[key], value)
        modes = ("rootless_observed",) if expected_context["mode"] == "rootless" else (
            "rootful_observed", "unknown_with_independent_rootful_context")
        if acquired["daemon_mode_evidence"] not in modes:
            fail()
        integer(acquired["actual_requests"], 8, 16)
        integer(acquired["actual_body_bytes"], 1, BODY_ALLOWANCE)
        exact(acquired["limits"], {"max_requests": 16, "max_selected_resources": 6, "max_expansions": 8,
              "max_response_bytes": 131072, "max_total_body_bytes": BODY_ALLOWANCE, "max_elapsed_seconds": 10})
        exact(acquired["separate_transport_bounds"], {"response_header_bytes": 16384, "chunk_line_bytes": 64,
              "chunk_payload_crlf_bytes": 2, "final_trailer_line_bytes": 16384, "actual_wire_bytes": "not_measured"})
        budget = proof["accounting"]
        keys(budget, ("ordinary_calls", "ordinary_bytes", "cleanup_calls", "cleanup_bytes", "ordinary_elapsed_ns",
                      "cleanup_elapsed_ns", "elapsed_ns", "deadline_seconds", "cleanup_reserve_seconds", "initial_context_acquisition"))
        exact(budget["ordinary_calls"], (75 if expected_context["lane"].startswith("debian11-") else 74) + 2 * extra_calls)
        integer(budget["ordinary_bytes"], 524289 + 2 * extra_bytes, 2097152)
        exact(budget["cleanup_calls"], 54)
        integer(budget["cleanup_bytes"], 1, 54 * 10240)
        ordinary = integer(budget["ordinary_elapsed_ns"], 1, 134 * SECOND)
        cleanup = integer(budget["cleanup_elapsed_ns"], 1, 46 * SECOND)
        elapsed = integer(budget["elapsed_ns"], 1, 180 * SECOND)
        if ordinary + cleanup > elapsed:
            fail()
        exact(budget["deadline_seconds"], 180)
        exact(budget["cleanup_reserve_seconds"], 46)
        exact(budget["initial_context_acquisition"], {"max_requests": 16, "max_body_bytes": 2097152,
              "max_elapsed_seconds": 15, "accounting": "separate_existing_bound"})
        if type(proof["cases"]) is not list or len(proof["cases"]) != 3:
            fail()
        ids = {expected_context["outer"]["id"]}
        for case, (name, groups) in zip(proof["cases"], CASES):
            keys(case, ("case", "authored_groups", "containers"))
            exact(case["case"], name)
            exact(case["authored_groups"], groups)
            if type(case["containers"]) is not list or len(case["containers"]) != 2:
                fail()
            for item, role in zip(case["containers"], ("oracle", "rendered")):
                keys(item, ("role", "id", "name", "owner", "image_id", "wire", "configured_availability", "effect",
                            "running_after", "restart_count", "oom_killed", "cleanup"))
                if not canonical(item["id"]) or item["id"] in ids:
                    fail()
                ids.add(item["id"])
                for key, value in (("role", role), ("name", f"dl-sg-{expected_context['run_id']}-{name}-{role}"),
                                   ("owner", expected_context["run_id"]), ("image_id", borrowed["id"]),
                                   ("wire", "independent_cli" if role == "oracle" else "literal_rendered"),
                                   ("running_after", True), ("restart_count", 0), ("oom_killed", False), ("cleanup", "absent")):
                    exact(item[key], value)
                allowed = ("present",) if groups else ("missing", "null", "empty")
                if item["configured_availability"] not in allowed:
                    fail()
                effect = item["effect"]
                keys(effect, ("pid", "uid", "primary_gid", "kernel_groups", "primary_gid_in_groups", "effective_capabilities",
                              "kernel_pre_post_root_agree", "writer", "root_exec_scope", "files"))
                for key, value in (("pid", 1), ("uid", 12345), ("primary_gid", 3456), ("effective_capabilities", "0000000000000000"),
                                   ("kernel_pre_post_root_agree", True), ("writer", "nonroot_pid1"), ("root_exec_scope", "setup_and_readback_only")):
                    exact(effect[key], value)
                kernel = effect["kernel_groups"]
                if type(kernel) is not list:
                    fail()
                for gid in kernel:
                    integer(gid, 0, 4294967295)
                if kernel != sorted(set(kernel)) or [gid for gid in kernel if gid != 3456] != groups:
                    fail()
                exact(effect["primary_gid_in_groups"], 3456 in kernel)
                if type(effect["files"]) is not list or len(effect["files"]) != 2:
                    fail()
                for file, gid in zip(effect["files"], (23456, 34567)):
                    keys(file, ("owner_uid", "group_gid", "mode", "write_exit", "outcome", "readback"))
                    for key, value in (("owner_uid", 0), ("group_gid", gid), ("mode", 432)):
                        exact(file[key], value)
                    if gid in groups:
                        exact(file["write_exit"], 0)
                        exact(file["outcome"], "worker_written")
                        exact(file["readback"], "worker_canary")
                    else:
                        integer(file["write_exit"], 1, 255)
                        exact(file["outcome"], "native_permission_denied")
                        exact(file["readback"], "baseline_unchanged")
        return {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, IndexError):
        fail()


def read_supplementary_groups_proof(path, capture_dir, expected_context, *, outer_backend):
    try:
        outer_snapshot_cost(outer_backend)
        return read_private_proof(
            path, capture_dir, FILENAME, expected_context,
            lambda proof, context: validate_supplementary_groups_proof(proof, context, outer_backend=outer_backend))
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()


def main(arguments):
    if len(arguments) != 12:
        fail()
    directory, candidate, run, lane, engine, api, mode, package, fixture, image, outer_id, uid = arguments
    if re.fullmatch(r"0|[1-9][0-9]{0,9}", uid) is None:
        fail()
    context = {"candidate_sha": candidate, "run_id": run, "lane": lane, "engine_release": engine, "rendering_api": api,
               "acquisition_api": "1.41" if lane.startswith("debian11-") else "1.49", "mode": mode, "docker_package": package,
               "fixture_image": fixture, "daemon_uid": int(uid),
               "outer": {"id": outer_id, "name": "dl-native-" + run, "owner": run, "image": image,
                         "data_volume": "dl-native-data-" + run, "socket_source": str(Path(directory) / "socket"),
                         "privileged": True, "memory_bytes": 4294967296, "cpu_quota": 200000, "cpu_period": 100000, "pids_limit": 512}}
    read_supplementary_groups_proof(Path(directory) / FILENAME, directory, context,
                           outer_backend=os.environ.get("NATIVE_OUTER_ENGINE"))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise SystemExit("invalid private supplementary groups proof") from None
