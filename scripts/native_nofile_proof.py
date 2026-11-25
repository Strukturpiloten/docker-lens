"""Closed nofile-v1 schema-2 reader; no runtime calls or admission."""

from pathlib import Path
from copy import deepcopy
import json
import os
import re
import sys

from native_external_network_proof import validate_context
from native_network_attachment_proof import canonical, keys, read_private_proof
from native_shm_size_proof import exact, integer
from native_source_accounting import outer_snapshot_cost

CONTRACT = "nofile-v1"
FILENAME = "nofile-v1.json"
SCHEMA_VERSION = 2
PROOF_LIMIT = 512 * 1024
METADATA_LIMIT = 64 * 1024
U64 = 2**64 - 1
CASES = (("soft64_hard128", 64, 128), ("soft128_hard128", 128, 128),
         ("soft64_hard_unlimited", 64, -1), ("both_unlimited", -1, -1))
SAMPLES = ("parent_pre", "parent_post", "bound_pre", "bound_post", "self_pre", "self_post", "root_parent", "root_worker")
PHASES = ("base", "base_repeat", "saturated", "saturated_repeat", "restored")
REFUSAL = re.compile(r"(?:^|: )error setting rlimit type 7: operation not permitted(?:: unknown)?$")
NETWORK_AUDIENCES = ([0, 1, 2, 3], [4, 5], [6, 7])
ORDINARY_CAPTURE_BYTES = 65550 + 8192
CLEANUP_CAPTURE_BYTES = 8192 + 2048
IDENTITY_OBJECT_BYTES = 73  # Compact {"Id":"<64 hex>"}; necessary, not a full body.


def fail():
    raise ValueError("invalid private nofile proof")


def actual_limit(value):
    if type(value) is str:
        exact(value, "unlimited")
    else:
        integer(value, 1, 2**31 - 1)


def validate_witness(witness, soft, hard):
    keys(witness, ("outcome", "kernel", "samples", "nr_open", "owned_files", "descriptors",
                   "retained_count", "failure", "reuse_count", "phases", "exec_binding"))
    keys(witness["kernel"], ("soft", "hard"))
    kernel = witness["kernel"]
    ceiling = integer(witness["nr_open"], 128, 2**31 - 1)
    for name, authored in (("soft", soft), ("hard", hard)):
        actual_limit(kernel[name])
        if authored != -1:
            exact(kernel[name], authored)
        elif type(kernel[name]) is int and kernel[name] > ceiling:
            fail()
    if kernel["soft"] == "unlimited":
        exact(kernel["hard"], "unlimited")
    elif type(kernel["hard"]) is int and kernel["soft"] > kernel["hard"]:
        fail()
    keys(witness["samples"], SAMPLES)
    child = integer(witness["samples"]["self_pre"]["pid"], 2, 2**31 - 1)
    for name, sample in witness["samples"].items():
        keys(sample, ("soft", "hard", "pid", "ppid"))
        parent = name.startswith("parent") or name == "root_parent"
        exact(sample, {"soft": kernel["soft"], "hard": kernel["hard"],
                       "pid": 1 if parent else child, "ppid": 0 if parent else 1})
    owners = witness["owned_files"]
    controls = tuple("/tmp/dl-nf/" + name for name in ("gate", "report", "error"))
    paths = tuple(f"/tmp/dl-nf/f{i}" for i in range(1, 257))
    keys(owners, controls + paths)
    nodes = set()
    for path, node in owners.items():
        keys(node, ("device", "inode"))
        pair = (integer(node["device"], 0, U64), integer(node["inode"], 1, U64))
        if pair in nodes:
            fail()
        nodes.add(pair)
    keys(witness["descriptors"], PHASES)
    observed = {}
    for phase, items in witness["descriptors"].items():
        if type(items) is not list or not 3 <= len(items) <= 208:
            fail()
        observed[phase] = {}
        previous = -1
        for item in items:
            keys(item, ("fd", "target", "device", "inode"))
            fd = integer(item["fd"], 0, 2**31 - 1)
            if fd <= previous or type(item["target"]) is not str or item["target"] not in owners:
                fail()
            previous = fd
            node = owners[item["target"]]
            exact(item["device"], node["device"])
            exact(item["inode"], node["inode"])
            observed[phase][fd] = item
    base = observed["base"]
    if not 3 <= len(base) <= 16 or any(item["target"] not in controls for item in base.values()):
        fail()
    for fd, path in enumerate(controls):
        exact(base[fd]["target"], path)
    for phase in ("base_repeat", "restored"):
        exact(observed[phase], base)
    saturation = observed["saturated"]
    exact(observed["saturated_repeat"], saturation)
    count = integer(witness["retained_count"], 1, 192)
    if len(saturation) != len(base) + count:
        fail()
    actual_paths = set()
    for fd, item in saturation.items():
        if fd in base:
            exact(item, base[fd])
        else:
            if item["target"] in actual_paths:
                fail()
            actual_paths.add(item["target"])
    exact(actual_paths, set(paths[:count]))
    finite = type(kernel["soft"]) is int and kernel["soft"] <= 192
    if finite:
        # Bind every occupied numeric slot; capacity is not guessed as soft-3.
        exact(set(saturation), set(range(kernel["soft"])))
        exact(witness["failure"], {"getline_return": -1, "errno": 24, "attempt": count + 1})
    else:
        exact(count, 192)
        exact(witness["failure"], None)
    exact(witness["reuse_count"], 256)
    exact(witness["phases"], ["base", "held", "done"])
    exact(witness["exec_binding"], "retained_background_pid_exact_nul_argv_exe_inode_and_proc")
    if hard != -1:
        outcome = "exact_finite_emfile"
    elif kernel["hard"] != "unlimited" or soft == -1 and kernel["soft"] != "unlimited":
        outcome = "finite_kernel_normalization"
    elif soft != -1:
        outcome = "exact_hard_unlimited_finite_soft_emfile"
    else:
        outcome = "exact_both_unlimited_bounded_success"
    exact(witness["outcome"], outcome)
    return kernel, count, ceiling


def validate_networks(proof, context, container_ids):
    """Bind the selected design independently of optional active membership."""
    topology = proof["network_topology"]
    keys(topology, ("default", "owned"))
    default = topology["default"]
    keys(default, ("id", "name", "driver", "ownership", "container_indices"))
    if type(topology["owned"]) is not list or len(topology["owned"]) != 2:
        fail()
    networks = [default] + topology["owned"]
    identities = {context["outer"]["id"], *container_ids}
    setup_calls = setup_bytes = cleanup_calls = cleanup_bytes = 0
    for index, network in enumerate(networks):
        if index != 0 or network["id"] is not None:
            if not canonical(network["id"]) or network["id"] in identities:
                fail()
            identities.add(network["id"])
        exact(network["driver"], "bridge")
        exact(network["container_indices"], NETWORK_AUDIENCES[index])
        if index == 0:
            exact(network["name"], "bridge")
            exact(network["ownership"], "not_owned")
        else:
            keys(network, ("case", "id", "name", "owner", "driver", "container_indices",
                           "setup_calls", "setup_bytes", "cleanup_calls", "cleanup_bytes", "cleanup", "absence_rounds"))
            case = CASES[index + 1][0]
            exact(network["case"], case)
            exact(network["name"], f"dl-nf-{context['run_id']}-net-{case}")
            exact(network["owner"], context["run_id"])
            exact(network["setup_calls"], 3)
            exact(network["cleanup_calls"], 6)
            exact(network["cleanup"], "absent")
            exact(network["absence_rounds"], 2)
            setup_calls += network["setup_calls"]
            setup_bytes += integer(network["setup_bytes"], 1, 3 * ORDINARY_CAPTURE_BYTES)
            cleanup_calls += network["cleanup_calls"]
            cleanup_bytes += integer(network["cleanup_bytes"], 1, 6 * CLEANUP_CAPTURE_BYTES)
    acquired = proof["acquisition"]
    if type(acquired["networks"]) is not list or len(acquired["networks"]) > 3:
        fail()
    captured = {}
    previous = -1
    for observed in acquired["networks"]:
        keys(observed, ("id", "name", "driver", "ownership", "owner", "container_indices", "lookup",
                        "active_membership_availability", "active_selected_ids", "active_unselected_count"))
        group = [i for i, network in enumerate(networks) if observed["name"] == network["name"]]
        if len(group) != 1 or group[0] <= previous or not canonical(observed["id"]):
            fail()
        index = previous = group[0]
        network = networks[index]
        captured[index] = observed
        for name in ("id", "name", "driver", "container_indices"):
            exact(observed[name], network[name])
        exact(observed["ownership"], "owned" if index else "not_owned")
        exact(observed["owner"], context["run_id"] if index else None)
        if type(observed["lookup"]) is not str or observed["lookup"] not in ("id", "name"):
            fail()
        members = observed["active_selected_ids"]
        if type(members) is not list:
            fail()
        audience = [container_ids[i] for i in NETWORK_AUDIENCES[index]]
        # This also refuses duplicates, foreign selected IDs and changed order.
        exact(members, [value for value in audience if value in members])
        state = observed["active_membership_availability"]
        if type(state) is not str:
            fail()
        if state in ("missing", "null", "redacted"):
            exact(members, [])
            exact(observed["active_unselected_count"], None)
        elif state == "empty":
            exact(members, [])
            exact(observed["active_unselected_count"], 0)
        elif state == "present":
            others = integer(observed["active_unselected_count"], 0, 4096)
            if not 1 <= len(members) + others <= 4096 or index and others:
                fail()
        else:
            fail()
    bindings = acquired["container_networks"]
    if type(bindings) is not list or len(bindings) != 8:
        fail()
    supported = set()
    for index, binding in enumerate(bindings):
        keys(binding, ("container_id", "endpoint_map_availability", "network_id", "network_id_availability", "name", "lookup"))
        network_index = 0 if index < 4 else index // 2 - 1
        network = networks[network_index]
        exact(binding["container_id"], container_ids[index])
        whole_map = binding["endpoint_map_availability"]
        if type(whole_map) is not str:
            fail()
        if whole_map in ("missing", "null", "empty", "redacted"):
            for name in ("network_id", "network_id_availability", "name", "lookup"):
                exact(binding[name], None)
            continue
        if whole_map != "present" or network_index not in captured:
            fail()
        supported.add(network_index)
        exact(binding["name"], network["name"])
        state = binding["network_id_availability"]
        if type(state) is not str:
            fail()
        if state == "present":
            if not canonical(binding["network_id"]):
                fail()
            exact(binding["network_id"], network["id"])
            lookup = "id"
        elif state == "empty":
            exact(binding["network_id"], "")
            lookup = "name"
        elif state in ("missing", "null", "redacted"):
            exact(binding["network_id"], None)
            lookup = "name"
        else:
            fail()
        exact(binding["lookup"], lookup)
        # One actual GET per network excludes mixed ID/name aliases, including
        # two individually valid keys that would resolve to the same native ID.
        exact(captured[network_index]["lookup"], lookup)
    if supported != set(captured) or (default["id"] is None) != (0 not in captured):
        fail()
    return setup_calls, setup_bytes, cleanup_calls, cleanup_bytes, len(captured)


def validate_nofile_proof(proof, expected_context, *, outer_backend):
    """Independent external context is mandatory, even without public evidence."""
    try:
        extra_calls, extra_bytes = outer_snapshot_cost(outer_backend)
        validate_context(expected_context)
        if not expected_context["fixture_image"].startswith("docker.io/library/busybox:"):
            fail()
        keys(proof, ("schema_version", "contract", "capability_admission", "catalogue_admission", "scope",
                     "context", "borrowed_image", "network_topology", "cases", "acquisition", "daemon_health", "accounting", "cleanup"))
        for name, expected in (("schema_version", SCHEMA_VERSION), ("contract", CONTRACT), ("capability_admission", []),
                               ("catalogue_admission", False), ("scope", "four_diagonal_nofile_cases_source_only"),
                               ("context", expected_context), ("daemon_health", "version_matches_after_all_cases")):
            exact(proof[name], expected)
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        exact(proof["cleanup"], {"containers": "absent", "networks": "absent", "owned_networks": 2,
                                 "rounds": 2, "outstanding": 0, "uncertain": False})
        if type(proof["cases"]) is not list or len(proof["cases"]) != 4:
            fail()
        ids, counts, ceilings, slot_calls = {expected_context["outer"]["id"]}, [], set(), []
        container_ids = []
        for case, (name, soft, hard) in zip(proof["cases"], CASES):
            keys(case, ("case", "containers"))
            exact(case["case"], name)
            if type(case["containers"]) is not list or len(case["containers"]) != 2:
                fail()
            pair = []
            for item, role in zip(case["containers"], ("oracle", "rendered")):
                keys(item, ("role", "id", "name", "owner", "image_id", "wire", "configured", "effect", "cleanup"))
                if not canonical(item["id"]) or item["id"] in ids:
                    fail()
                ids.add(item["id"])
                container_ids.append(item["id"])
                for field, value in (("role", role), ("name", f"dl-nf-{expected_context['run_id']}-{name}-{role}"),
                                     ("owner", expected_context["run_id"]), ("image_id", image["id"]),
                                     ("wire", "independent_cli" if role == "oracle" else "literal_rendered"),
                                     ("configured", {"soft": soft, "hard": hard}), ("cleanup", "absent")):
                    exact(item[field], value)
                effect = item["effect"]
                keys(effect, ("stage", "cli_exit", "http_status", "diagnostic", "witness"))
                refused = effect["stage"] == "start_refused"
                exact(effect["stage"], "start_refused" if refused else "running")
                exact(effect["cli_exit"], (1 if refused else 0) if role == "oracle" else None)
                exact(effect["http_status"], (500 if refused else 204) if role == "rendered" else None)
                if refused:
                    diagnostic = effect["diagnostic"]
                    if (hard != -1 or type(diagnostic) is not str or len(diagnostic.encode()) > 8192
                            or any(not 32 <= ord(c) <= 126 for c in diagnostic) or REFUSAL.search(diagnostic) is None):
                        fail()
                    exact(effect["witness"], {"outcome": "specific_nofile_start_refusal", "status": "created", "pid": 0,
                                             "never_started": True, "terminal_unchanged": True,
                                             "error": "setting_rlimit_nofile_eperm"})
                    pair.append(("start_refused", None, None))
                    slot_calls.append(7)
                else:
                    exact(effect["diagnostic"], None)
                    kernel, count, ceiling = validate_witness(effect["witness"], soft, hard)
                    pair.append((effect["witness"]["outcome"], kernel, count))
                    ceilings.add(ceiling)
                    slot_calls.append(8)
            exact(pair[0], pair[1])
            counts.append(pair[0][2])
        if len(ceilings) != 1 or counts[0] is None or counts[1] is None or counts[1] <= counts[0]:
            fail()
        acquired = proof["acquisition"]
        keys(acquired, ("route", "selected_ids", "requested_api", "reserved_calls", "reserved_bytes", "actual_requests",
                        "actual_response_bytes", "actual_expansions", "actual_elapsed_ns", "networks", "container_networks",
                        "decoded", "daemon_mode_evidence", "byte_scope", "separate_transport_bounds", "limits"))
        for field, value in (("route", "explicit_unix_socket"), ("selected_ids", 8), ("requested_api", expected_context["acquisition_api"]),
                             ("reserved_calls", 20), ("reserved_bytes", 524288), ("decoded", "present_effective_exact_nofile_values"),
                             ("byte_scope", "decoded_response_bodies_only"),
                             ("limits", {"max_requests": 20, "max_selected_resources": 8, "max_expansions": 11,
                                         "max_response_bytes": 131072, "max_total_bytes": 524288, "max_elapsed_seconds": 10}),
                             ("separate_transport_bounds", {"response_header_bytes": 16384, "chunk_line_bytes": 64,
                                                            "chunk_payload_crlf_bytes": 2, "final_trailer_line_bytes": 16384,
                                                            "actual_wire_bytes": "not_measured"})):
            exact(acquired[field], value)
        acquisition_elapsed = integer(acquired["actual_elapsed_ns"], 1, 10 * 10**9)
        setup_calls, setup_bytes, network_cleanup_calls, network_cleanup_bytes, captured_networks = validate_networks(
            proof, expected_context, container_ids)
        # Each inspected identity requires at least its compact Id-only object.
        # The producer must still measure the authentic sum over all bodies.
        identity_floor = IDENTITY_OBJECT_BYTES * (len(container_ids) + captured_networks)
        integer(acquired["actual_response_bytes"], identity_floor, 524288)
        exact(acquired["actual_requests"], 10 + captured_networks)
        exact(acquired["actual_expansions"], 8 + captured_networks)
        modes = ("rootless_observed",) if expected_context["mode"] == "rootless" else ("rootful_observed", "unknown_with_independent_rootful_context")
        if type(acquired["daemon_mode_evidence"]) is not str or acquired["daemon_mode_evidence"] not in modes:
            fail()
        accounting = proof["accounting"]
        keys(accounting, ("context_calls", "slot_calls", "daemon_health_calls", "acquisition_reserved_calls", "final_readback_calls",
                          "network_setup_calls", "network_setup_bytes", "container_cleanup_calls", "container_cleanup_bytes",
                          "network_cleanup_calls", "network_cleanup_bytes",
                          "ordinary_calls", "ordinary_bytes", "cleanup_calls", "cleanup_bytes", "deadline_seconds", "cleanup_reserve_seconds",
                          "ordinary_elapsed_ns", "cleanup_elapsed_ns", "elapsed_ns", "initial_context_acquisition"))
        context_calls = (9 if expected_context["lane"].startswith("debian11-") else 8) + extra_calls
        final_readback_calls = 2 + extra_calls
        for field, value in (("context_calls", context_calls), ("slot_calls", slot_calls), ("daemon_health_calls", 1),
                             ("acquisition_reserved_calls", 20), ("final_readback_calls", final_readback_calls),
                             ("network_setup_calls", setup_calls), ("network_setup_bytes", setup_bytes),
                             ("container_cleanup_calls", 72), ("network_cleanup_calls", network_cleanup_calls),
                             ("network_cleanup_bytes", network_cleanup_bytes),
                             ("ordinary_calls", context_calls + setup_calls + sum(slot_calls) + 1 + 20 + final_readback_calls),
                             ("cleanup_calls", 72 + network_cleanup_calls),
                             ("deadline_seconds", 180), ("cleanup_reserve_seconds", 46),
                             ("initial_context_acquisition", {"max_requests": 16, "max_total_bytes": 2097152,
                                                              "max_elapsed_seconds": 15, "accounting": "separate_existing_bound"})):
            exact(accounting[field], value)
        integer(accounting["ordinary_calls"], 1, 300)
        integer(accounting["cleanup_calls"], 1, 100)
        ordinary_bytes = integer(accounting["ordinary_bytes"], 524289 + setup_bytes + 2 * extra_bytes, 2097152)
        container_cleanup_bytes = integer(accounting["container_cleanup_bytes"], 1, 72 * CLEANUP_CAPTURE_BYTES)
        exact(accounting["cleanup_bytes"], container_cleanup_bytes + network_cleanup_bytes)
        cleanup_bytes = integer(accounting["cleanup_bytes"], 1, 2097152)
        if ordinary_bytes + cleanup_bytes > 4194304:
            fail()
        work = integer(accounting["ordinary_elapsed_ns"], 1, 134 * 10**9)
        cleanup = integer(accounting["cleanup_elapsed_ns"], 1, 46 * 10**9)
        total = integer(accounting["elapsed_ns"], 1, 180 * 10**9)
        if acquisition_elapsed > work or work + cleanup > total:
            fail()
        if metadata_size(proof) > METADATA_LIMIT:
            fail()
        return {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, IndexError, AttributeError):
        fail()


def metadata_size(proof):
    metadata = deepcopy(proof)
    for case in metadata["cases"]:
        for item in case["containers"]:
            if item["effect"]["stage"] == "running":
                del item["effect"]["witness"]["owned_files"]
                del item["effect"]["witness"]["descriptors"]
    return len(json.dumps(metadata, ensure_ascii=False, separators=(",", ":")).encode())


def read_nofile_proof(path, capture_dir, expected_context, *, outer_backend):
    """Shared held no-follow custody; only this new protocol opts into 512KiB."""
    try:
        outer_snapshot_cost(outer_backend)
        return read_private_proof(path, capture_dir, FILENAME, expected_context,
                                  lambda value, context: validate_nofile_proof(
                                      value, context, outer_backend=outer_backend),
                                  max_bytes=PROOF_LIMIT)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()


def main(arguments):
    if len(arguments) != 12:
        fail()
    outer_backend = os.environ.get("NATIVE_OUTER_ENGINE")
    try:
        outer_snapshot_cost(outer_backend)
    except ValueError:
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
    read_nofile_proof(Path(directory) / FILENAME, directory, context, outer_backend=outer_backend)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise SystemExit("invalid private nofile proof") from None
