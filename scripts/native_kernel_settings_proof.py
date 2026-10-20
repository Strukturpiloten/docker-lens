"""Closed diagonal kernel-settings-v1 private proof; no runtime or admission."""

from pathlib import Path
import re
import sys

from native_external_network_proof import validate_context
from native_network_attachment_proof import canonical, keys, read_private_proof

CONTRACT = "kernel-settings-v1"
FILENAME = "kernel-settings-v1.json"
CASES = (("omitted", None), ("false_zero", False), ("true_one", True))
SECOND = 1_000_000_000


def fail():
    raise ValueError("invalid private kernel settings proof")


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


def validate_kernel_settings_proof(proof, expected_context):
    try:
        validate_context(expected_context)
        if not expected_context["fixture_image"].startswith("docker.io/library/busybox:"):
            fail()
        keys(proof, ("schema_version", "contract", "scope", "capability_admission", "catalogue_admission", "context",
                     "borrowed_image", "outer_namespaces", "cases", "acquisition", "accounting", "cleanup"))
        for key, value in (("schema_version", 1), ("contract", CONTRACT), ("scope", "diagonal_omitted_false0_true1_only"),
                           ("capability_admission", []), ("catalogue_admission", False), ("context", expected_context)):
            exact(proof[key], value)
        validate_context(proof["context"])
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        exact(proof["cleanup"], {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False})
        outer = proof["outer_namespaces"]
        keys(outer, ("net", "pid", "unchanged"))
        exact(outer["unchanged"], True)
        nets = {integer(outer["net"], 1, 2**64 - 1)}
        pids = {integer(outer["pid"], 1, 2**64 - 1)}
        acquired = proof["acquisition"]
        keys(acquired, ("selected_ids", "route", "api", "daemon_mode_evidence", "reserved_calls", "reserved_body_bytes",
                        "actual_requests", "actual_body_bytes", "decoded", "byte_scope", "limits", "separate_transport_bounds"))
        for key, value in (("selected_ids", 6), ("route", "explicit_unix_socket"), ("api", expected_context["acquisition_api"]),
                           ("reserved_calls", 16), ("reserved_body_bytes", 524288), ("decoded", "effective_security_and_sysctls_agree"),
                           ("byte_scope", "decoded_response_bodies_only")):
            exact(acquired[key], value)
        modes = ("rootless_observed",) if expected_context["mode"] == "rootless" else (
            "rootful_observed", "unknown_with_independent_rootful_context")
        if acquired["daemon_mode_evidence"] not in modes:
            fail()
        integer(acquired["actual_requests"], 8, 16)
        integer(acquired["actual_body_bytes"], 1, 524288)
        exact(acquired["limits"], {"max_requests": 16, "max_selected_resources": 6, "max_expansions": 8,
              "max_response_bytes": 131072, "max_total_body_bytes": 524288, "max_elapsed_seconds": 10})
        exact(acquired["separate_transport_bounds"], {"response_header_bytes": 16384, "chunk_line_bytes": 64,
              "chunk_payload_crlf_bytes": 2, "final_trailer_line_bytes": 16384, "actual_wire_bytes": "not_measured"})
        budget = proof["accounting"]
        keys(budget, ("ordinary_calls", "ordinary_bytes", "cleanup_calls", "cleanup_bytes", "ordinary_elapsed_ns", "cleanup_elapsed_ns",
                      "elapsed_ns", "deadline_seconds", "cleanup_reserve_seconds", "initial_context_acquisition"))
        exact(budget["ordinary_calls"], 71 if expected_context["lane"].startswith("debian11-") else 70)
        integer(budget["ordinary_bytes"], 524289, 2097152)
        exact(budget["cleanup_calls"], 54)
        integer(budget["cleanup_bytes"], 1, 552960)
        ordinary = integer(budget["ordinary_elapsed_ns"], 1, 134 * SECOND)
        cleanup = integer(budget["cleanup_elapsed_ns"], 1, 46 * SECOND)
        total = integer(budget["elapsed_ns"], 1, 180 * SECOND)
        if ordinary + cleanup > total:
            fail()
        exact(budget["deadline_seconds"], 180)
        exact(budget["cleanup_reserve_seconds"], 46)
        exact(budget["initial_context_acquisition"], {"max_requests": 16, "max_body_bytes": 2097152,
              "max_elapsed_seconds": 15, "accounting": "separate_existing_bound"})
        if type(proof["cases"]) is not list or len(proof["cases"]) != 3:
            fail()
        ids = {expected_context["outer"]["id"]}
        for case, (name, flag) in zip(proof["cases"], CASES):
            keys(case, ("case", "authored_nnp", "authored_forwarding", "containers"))
            exact(case["case"], name)
            exact(case["authored_nnp"], flag)
            exact(case["authored_forwarding"], None if flag is None else int(flag))
            if type(case["containers"]) is not list or len(case["containers"]) != 2:
                fail()
            for item, role in zip(case["containers"], ("oracle", "rendered")):
                keys(item, ("role", "id", "name", "owner", "image_id", "wire", "security_availability", "sysctls_availability",
                            "effect", "running_after", "restart_count", "oom_killed", "cleanup"))
                if not canonical(item["id"]) or item["id"] in ids:
                    fail()
                ids.add(item["id"])
                for key, value in (("role", role), ("name", f"dl-ks-{expected_context['run_id']}-{name}-{role}"),
                                   ("owner", expected_context["run_id"]), ("image_id", image["id"]),
                                   ("wire", "independent_cli" if role == "oracle" else "literal_rendered"),
                                   ("running_after", True), ("restart_count", 0), ("oom_killed", False), ("cleanup", "absent")):
                    exact(item[key], value)
                available = ("present",) if flag is not None else ("missing", "null", "empty")
                if item["security_availability"] not in available or item["sysctls_availability"] not in available:
                    fail()
                effect = item["effect"]
                keys(effect, ("parent_pid", "parent_ppid", "child_pid", "child_ppid", "parent_nnp", "child_nnp", "forwarding",
                              "net_namespace", "pid_namespace", "parent_pre_post_agree", "exec_binding", "root_corroboration"))
                for key, value in (("parent_pid", 1), ("parent_ppid", 0), ("child_ppid", 1), ("parent_pre_post_agree", True),
                                   ("exec_binding", "background_pid_argv_exe_inode_and_proc"), ("root_corroboration", "same_live_pids_and_namespaces")):
                    exact(effect[key], value)
                integer(effect["child_pid"], 2, 4194304)
                nnp = integer(effect["parent_nnp"], 0, 1)
                exact(effect["child_nnp"], nnp)
                forwarding = integer(effect["forwarding"], 0, 1)
                if flag is not None:
                    # An inherited one is never successful explicit false or a
                    # manufactured unsupported outcome. The whole proof refuses.
                    exact(nnp, int(flag))
                    exact(forwarding, int(flag))
                net = integer(effect["net_namespace"], 1, 2**64 - 1)
                pid = integer(effect["pid_namespace"], 1, 2**64 - 1)
                if net in nets or pid in pids:
                    fail()
                nets.add(net)
                pids.add(pid)
        return {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, IndexError):
        fail()


def read_kernel_settings_proof(path, capture_dir, expected_context):
    try:
        return read_private_proof(path, capture_dir, FILENAME, expected_context, validate_kernel_settings_proof)
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
    read_kernel_settings_proof(Path(directory) / FILENAME, directory, context)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise SystemExit("invalid private kernel settings proof") from None
