"""Private pids-limit-v1 reader; synthetic checks never establish native support."""

from pathlib import Path, PurePosixPath
import re
import sys

from native_external_network_proof import validate_context
from native_network_attachment_proof import canonical, keys, read_private_proof

CONTRACT = "pids-limit-v1"
FILENAME = "pids-limit-v1.json"
SCOPE = "finite16_finite64_unlimited_32_child_attempts_only"
CASES = (("finite16", 16), ("finite64", 64), ("unlimited", -1))
SECOND = 1_000_000_000
MAX_PID = 4194304
PROOF_BYTES = 16384
ACQUISITION_BYTES = 524288


def fail():
    raise ValueError("invalid private pids limit proof")


def number(value, lower=0, upper=2**64 - 1):
    if type(value) is not int or not lower <= value <= upper:
        fail()
    return value


def same(value, expected):
    if type(value) is not type(expected):
        fail()
    if isinstance(expected, dict):
        keys(value, expected)
        for key, child in expected.items():
            same(value[key], child)
    elif isinstance(expected, list):
        if len(value) != len(expected):
            fail()
        for child, other in zip(value, expected):
            same(child, other)
    elif value != expected:
        fail()


def path(value):
    if (not isinstance(value, str) or not value.startswith("/") or len(value) > 512
            or str(PurePosixPath(value)) != value or ".." in PurePosixPath(value).parts
            or any(character.isspace() for character in value)):
        fail()
    return PurePosixPath(value)


def mapped_path(mapping, kind):
    keys(mapping, ("kind", "mount_id", "root", "mountpoint", "membership", "path",
                   "outer_membership", "outer_path", "inode", "device"))
    same(mapping["kind"], kind)
    number(mapping["mount_id"], 1)
    number(mapping["inode"], 1)
    number(mapping["device"], 1)
    root, point = path(mapping["root"]), path(mapping["mountpoint"])
    for membership, selected in (("membership", "path"), ("outer_membership", "outer_path")):
        member = path(mapping[membership])
        if not member.is_relative_to(root):
            fail()
        same(str(point / member.relative_to(root)), mapping[selected])
    if (mapping["path"] == mapping["outer_path"]
            or not path(mapping["path"]).is_relative_to(path(mapping["outer_path"]))):
        fail()


def rows(value, count, identity):
    if not isinstance(value, list) or len(value) != count:
        fail()
    outer, inner = set(), set()
    expanded = []
    for row in value:
        if not isinstance(row, list) or len(row) != 5:
            fail()
        for item in row:
            if type(item) is not int:
                fail()
        pid, private, parent, started, actual_uid = row
        pid += identity["nspid"][0]
        parent += identity["nspid"][0]
        started += identity["start"]
        actual_uid += identity["outer_uid"]
        number(pid, 1, MAX_PID)
        number(private, 1, MAX_PID)
        number(parent, 0, MAX_PID)
        number(started, 1)
        same(actual_uid, identity["outer_uid"])
        if pid in outer or private in inner:
            fail()
        outer.add(pid)
        inner.add(private)
        expanded.append([pid, private, parent, started, actual_uid])
    if value != sorted(value, key=lambda item: item[1]):
        fail()
    return expanded


def snapshot(value, count, identity, limit):
    keys(value, ("rows", "members", "pids_current", "pids_max", "denials", "oom_kills",
                 "outer_pids", "outer_memory", "ancestor_headroom", "phase"))
    same(value["pids_current"], count)
    same(value["pids_max"], "max" if limit == -1 else limit)
    expanded = rows(value["rows"], count, identity)
    members = value["members"]
    if not isinstance(members, list) or any(type(item) is not int for item in members):
        fail()
    same([item + identity["nspid"][0] for item in members], sorted(row[0] for row in expanded))
    number(value["denials"])
    number(value["oom_kills"])
    number(value["outer_pids"], count, 384)
    number(value["outer_memory"], 1, 3221225472)
    number(value["ancestor_headroom"], 128)
    return expanded


def case(value, expected, role, context, image, observer):
    name, limit = expected
    keys(value, ("case", "role", "id", "name", "wire", "image_id", "configured_limit",
                 "identity", "pids_mapping", "memory_mapping", "event_source", "nproc",
                 "preflight", "baseline", "held", "restored", "work", "elapsed_ns", "cleanup"))
    same(value["case"], name)
    same(value["role"], role)
    if not canonical(value["id"]):
        fail()
    same(value["name"], f"dl-pids-{context['run_id']}-{name}-{role}")
    same(value["wire"], "independent_cli" if role == "oracle" else "literal_rendered")
    same(value["image_id"], image)
    same(value["configured_limit"], limit)
    same(value["cleanup"], "absent")
    number(value["elapsed_ns"], 1, 15 * SECOND)
    keys(value["preflight"], ("outer_pids", "outer_memory"))
    number(value["preflight"]["outer_pids"], 1, 384)
    number(value["preflight"]["outer_memory"], 1, 3221225472)
    identity = value["identity"]
    keys(identity, ("private_pid", "private_uid", "start", "pid_namespace", "state_pid",
                    "nspid", "uid_map", "outer_uid", "worker_private", "worker_start"))
    same(identity["private_pid"], 1)
    same(identity["private_uid"], 0)
    number(identity["start"], 1)
    number(identity["pid_namespace"], 1)
    if identity["pid_namespace"] in (observer["daemon_pid_namespace"], observer["pid_namespace"]):
        fail()
    chain = identity["nspid"]
    depth = observer["daemon_depth"]
    if not isinstance(chain, list) or not depth < len(chain) <= 8:
        fail()
    for item in chain:
        number(item, 1, MAX_PID)
    same(chain[-1], 1)
    same(identity["state_pid"], chain[depth - 1])
    number(identity["outer_uid"], 0, 4294967295)
    mapping = identity["uid_map"]
    if not isinstance(mapping, list) or len(mapping) != 3:
        fail()
    inside, outside, length = mapping
    number(inside, 0, 4294967295)
    number(outside, 0, 4294967295)
    number(length, 1, 4294967295)
    if not inside <= identity["private_uid"] < inside + length:
        fail()
    same(identity["outer_uid"], outside + identity["private_uid"] - inside)
    number(identity["worker_private"], 2, MAX_PID)
    number(identity["worker_start"], identity["start"])
    for mapped in (value["pids_mapping"], value["memory_mapping"]):
        mapped_path(mapped, observer["cgroup_kind"])
    if observer["cgroup_kind"] == "v2":
        same(value["pids_mapping"], value["memory_mapping"])
    if value["event_source"] not in ("pids.events.local", "pids.events_exclusive_leaf"):
        fail()
    nproc = value["nproc"]
    if not isinstance(nproc, list) or len(nproc) != 2:
        fail()
    for item in nproc:
        if item != "unlimited":
            number(item, 35)
    soft, hard = nproc
    if hard != "unlimited" and (soft == "unlimited" or soft > hard):
        fail()
    baseline, held, restored = (value[key] for key in ("baseline", "held", "restored"))
    baseline_rows = snapshot(baseline, 2, identity, limit)
    held_rows = snapshot(held, 16 if limit == 16 else 34, identity, limit)
    restored_rows = snapshot(restored, 1, identity, limit)
    same(baseline["phase"], "ready")
    same(held["phase"], "exit_barrier")
    same(restored["phase"], "idle")
    init = baseline_rows[0]
    worker = baseline_rows[1]
    same(init[0], chain[0])
    same(init[1], 1)
    same(init[3], identity["start"])
    same(worker[1], identity["worker_private"])
    same(worker[2], init[0])
    same(worker[3], identity["worker_start"])
    same(held_rows[:2], baseline_rows)
    same(restored_rows, [init])
    for child in held_rows[2:]:
        same(child[2], worker[0])
        if child[3] < worker[3]:
            fail()
    same(held["oom_kills"], baseline["oom_kills"])
    same(restored["oom_kills"], baseline["oom_kills"])
    same(held["denials"], baseline["denials"] + (1 if limit == 16 else 0))
    same(restored["denials"], held["denials"])
    same(value["work"], {"attempts": 15 if limit == 16 else 32,
                         "successes": 14 if limit == 16 else 32,
                         "exit_status": 2 if limit == 16 else 0,
                         "diagnostic": "native_c_eagain_fork" if limit == 16 else "none",
                         "held_barrier": True, "release": "all_children_gone"})
    return value["id"], identity["pid_namespace"]


def validate_pids_limit_proof(proof, expected_context):
    try:
        validate_context(expected_context)
        keys(proof, ("schema_version", "contract", "context", "capability_admission",
                     "catalogue_admission", "scope", "borrowed_image", "observer", "cases",
                     "acquisition", "accounting", "cleanup"))
        same(proof["schema_version"], 1)
        same(proof["contract"], CONTRACT)
        same(proof["context"], expected_context)
        same(proof["capability_admission"], [])
        same(proof["catalogue_admission"], False)
        same(proof["scope"], SCOPE)
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if not isinstance(image["id"], str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image["id"]):
            fail()
        same(image["identity"], "unchanged")
        same(image["removal"], "not_owned")
        observer = proof["observer"]
        keys(observer, ("pid_namespace", "mount_namespace", "cgroup_namespace", "daemon_pid_namespace",
                        "daemon_depth", "daemon_uid", "cgroup_kind", "outer_process_ceiling"))
        for key in ("pid_namespace", "mount_namespace", "cgroup_namespace", "daemon_pid_namespace"):
            number(observer[key], 1)
        number(observer["daemon_depth"], 1, 7)
        if ((observer["daemon_depth"] == 1)
                != (observer["daemon_pid_namespace"] == observer["pid_namespace"])):
            fail()
        same(observer["daemon_uid"], expected_context["daemon_uid"])
        same(observer["outer_process_ceiling"], 512)
        if observer["cgroup_kind"] not in ("v1", "v2"):
            fail()
        cases = proof["cases"]
        if not isinstance(cases, list) or len(cases) != 6:
            fail()
        identities, namespaces = set(), set()
        outer_bindings = {}
        leaf_identities = {controller: set() for controller in ("pids_mapping", "memory_mapping")}
        leaf_paths = {controller: set() for controller in leaf_identities}
        for index, value in enumerate(cases):
            identity, namespace = case(value, CASES[index // 2], ("oracle", "rendered")[index % 2],
                                       expected_context, image["id"], observer)
            if identity in identities or namespace in namespaces:
                fail()
            identities.add(identity)
            namespaces.add(namespace)
            for controller in leaf_identities:
                mapping = value[controller]
                binding = tuple(mapping[key] for key in ("kind", "mount_id", "root", "mountpoint",
                                                         "outer_membership", "outer_path", "device"))
                if controller in outer_bindings and outer_bindings[controller] != binding:
                    fail()
                outer_bindings[controller] = binding
                leaf = (mapping["device"], mapping["inode"])
                if leaf in leaf_identities[controller] or mapping["path"] in leaf_paths[controller]:
                    fail()
                leaf_identities[controller].add(leaf)
                leaf_paths[controller].add(mapping["path"])
        acquisition = proof["acquisition"]
        keys(acquisition, ("route", "selected_ids", "requested_api", "reserved_calls", "reserved_bytes",
                           "actual_requests", "actual_response_bytes", "decoded", "max_elapsed_ns"))
        for key, expected in (("route", "explicit_unix_socket"), ("selected_ids", 6),
                              ("requested_api", expected_context["acquisition_api"]),
                              ("reserved_calls", 16), ("reserved_bytes", ACQUISITION_BYTES),
                              ("decoded", "present_effective_exact_pids_limits")):
            same(acquisition[key], expected)
        number(acquisition["actual_requests"], 1, 16)
        number(acquisition["actual_response_bytes"], 1, ACQUISITION_BYTES)
        number(acquisition["max_elapsed_ns"], 1, 10 * SECOND)
        accounting = proof["accounting"]
        keys(accounting, ("ordinary_calls", "ordinary_bytes", "cleanup_calls", "cleanup_bytes",
                          "ordinary_elapsed_ns", "cleanup_elapsed_ns", "elapsed_ns",
                          "deadline_seconds", "cleanup_reserve_seconds"))
        same(accounting["ordinary_calls"], 124 if expected_context["lane"].startswith("debian11-") else 123)
        number(accounting["ordinary_bytes"], ACQUISITION_BYTES, 2097152)
        same(accounting["cleanup_calls"], 54)
        number(accounting["cleanup_bytes"], 1, 2 * 1024 * 1024)
        number(accounting["ordinary_elapsed_ns"], 1, 134 * SECOND)
        number(accounting["cleanup_elapsed_ns"], 1, 46 * SECOND)
        number(accounting["elapsed_ns"], accounting["ordinary_elapsed_ns"] + accounting["cleanup_elapsed_ns"],
               180 * SECOND)
        same(accounting["deadline_seconds"], 180)
        same(accounting["cleanup_reserve_seconds"], 46)
        same(proof["cleanup"], {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False})
        return {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False, "scope": SCOPE}
    except (KeyError, IndexError, TypeError, ValueError, OverflowError, RecursionError):
        fail()


def read_pids_limit_proof(proof_path, capture_dir, expected_context):
    try:
        return read_private_proof(proof_path, capture_dir, FILENAME, expected_context, validate_pids_limit_proof)
    except (OSError, KeyError, IndexError, TypeError, ValueError, OverflowError, RecursionError):
        fail()


def main(arguments):
    if len(arguments) != 12:
        fail()
    directory, candidate, run, lane, engine, api, mode, package, fixture, image, outer_id, uid = arguments
    if re.fullmatch(r"0|[1-9][0-9]{0,9}", uid) is None:
        fail()
    context = {"candidate_sha": candidate, "run_id": run, "lane": lane, "engine_release": engine,
               "rendering_api": api, "acquisition_api": "1.41" if lane.startswith("debian11-") else "1.49",
               "mode": mode, "docker_package": package, "fixture_image": fixture, "daemon_uid": int(uid),
               "outer": {"id": outer_id, "name": "dl-native-" + run, "owner": run, "image": image,
                         "data_volume": "dl-native-data-" + run,
                         "socket_source": str(Path(directory) / "socket"), "privileged": True,
                         "memory_bytes": 4294967296, "cpu_quota": 200000, "cpu_period": 100000, "pids_limit": 512}}
    read_pids_limit_proof(Path(directory) / FILENAME, directory, context)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError):
        raise SystemExit("invalid private pids limit proof") from None
