"""Independent, closed PIDs27 private reader. It never runs a native command.

Caller-private proof custody is not authentication against a privileged writer.
Successful reading is source-only: whole-lane cleanup and fresh qualification
remain separate requirements, and no capability/catalogue entry is admitted.
"""

import os
import hashlib
from pathlib import Path
import re
import stat
import struct
import sys

from native_network_attachment_proof import fingerprint, read_private_proof, unique_object

CONTRACT = "pids-v2"
FILENAME = "pids-v2.json"
LIMIT = 128 * 1024
SLOTS = ("cli16", "cli64", "cli_unlimited", "rendered16", "rendered64", "rendered_unlimited")
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
U64 = 2**64 - 1


def fail():
    raise ValueError("invalid private pids proof")


def keys(value, names):
    if type(value) is not dict or set(value) != set(names):
        fail()


def exact(value, expected):
    if type(value) is not type(expected):
        fail()
    if type(value) is dict:
        keys(value, expected)
        for name in expected:
            exact(value[name], expected[name])
    elif type(value) is list:
        if len(value) != len(expected):
            fail()
        for left, right in zip(value, expected):
            exact(left, right)
    elif value != expected:
        fail()


def integer(value, minimum=0, maximum=U64):
    if type(value) is not int or not minimum <= value <= maximum:
        fail()
    return value


def text(value, maximum=256):
    if type(value) is not str or not 0 < len(value.encode()) <= maximum or "\0" in value:
        fail()
    return value


def digest(value, size=64):
    if type(value) is not str or re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is None:
        fail()
    return value


def sequence(value, minimum, maximum=None):
    if type(value) is not list or not minimum <= len(value) <= (minimum if maximum is None else maximum):
        fail()
    return value


def identity(value, count):
    sequence(value, count)
    return tuple(integer(number, 0 if offset == 0 else 1) for offset, number in enumerate(value))


def cgroup_type(value):
    if type(value) is not str or value not in ("domain", "domain threaded", "threaded"):
        fail()
    return value


def validate_context(context):
    keys(context, ("candidate_sha", "run_id", "lane", "engine_release", "api_version", "mode",
                   "outer_backend", "outer_id", "fixture_image", "outer"))
    digest(context["candidate_sha"], 40)
    digest(context["outer_id"])
    if context["lane"] not in LANES or context["outer_backend"] not in ("docker", "podman"):
        fail()
    exact(context["mode"], "rootless" if context["lane"].endswith("rootless") else "rootful")
    if re.fullmatch(r"[A-Za-z0-9]{8}", text(context["run_id"], 8)) is None:
        fail()
    # Match native_engine_release_matches' exact Debian source suffix policy.
    # Keep the actual reported release in every context comparison; do not
    # normalize +dfsg1 away or accept it on an upstream Engine lane.
    release_pattern = r"[0-9]+\.[0-9]+\.[0-9]+" + (r"(?:\+dfsg1)?" if context["lane"].startswith("debian11-") else "")
    if re.fullmatch(release_pattern, text(context["engine_release"], 64)) is None:
        fail()
    exact(context["api_version"], "1.41" if context["lane"].startswith("debian11-") else "1.56")
    if re.fullmatch(r"docker.io/library/busybox:[^@\s]+@sha256:[0-9a-f]{64}", text(context["fixture_image"], 256)) is None:
        fail()
    outer = context["outer"]
    keys(outer, ("id", "name", "owner", "image", "data_volume", "socket_source", "privileged", "memory_bytes", "cpu_quota", "cpu_period", "pids_limit"))
    for field, value in (("id", context["outer_id"]), ("name", "dl-native-" + context["run_id"]),
                         ("owner", context["run_id"]), ("data_volume", "dl-native-data-" + context["run_id"]),
                         ("privileged", True), ("memory_bytes", 4294967296), ("cpu_quota", 200000), ("cpu_period", 100000), ("pids_limit", 512)):
        exact(outer[field], value)
    if re.fullmatch(r"ghcr.io/strukturpiloten/docker-[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}", text(outer["image"], 512)) is None:
        fail()
    socket = Path(text(outer["socket_source"], 4096))
    if not socket.is_absolute() or socket.name != "socket" or any(part == ".." for part in socket.parts):
        fail()


def validate_copy_receipt(receipt, size):
    chunks = (integer(size, 1, 8 * 1024 * 1024) + 65535) // 65536
    exact(receipt, {"schema": "dockerlens-pids-copy-io-v1", "chunk_bytes": 65536,
                    "reserved_bytes": 3 * size + 2, "reserved_operations": 3 * chunks + 2,
                    "read_bytes": 2 * size, "write_bytes": size,
                    "read_operations": 2 * chunks + 2, "write_operations": chunks, "eof_probes": 2})


def validate_worker_events(events, slot, nonce):
    sequence(events, 7)
    finite = slot.endswith("16")
    phases = ("identity", "baseline", "attempt", "hold-failure" if finite else "hold-control",
              "release", "reuse", "finished")
    identities = []
    for index, (event, phase) in enumerate(zip(events, phases)):
        common = ("schema", "case", "nonce", "phase", "pid", "threads")
        keys(event, (*common, *(('rlimit_nproc_soft', 'rlimit_nproc_hard', 'kernel_sysname',
                                'kernel_release', 'kernel_version', 'kernel_machine') if index == 0 else
                               ('children', 'child_count', 'fork_return', 'errno', 'eagain'))))
        for field, value in (("schema", "dockerlens-pids-worker-v1"), ("case", slot), ("nonce", nonce),
                             ("phase", phase), ("pid", 1), ("threads", 1)):
            exact(event[field], value)
        if index == 0:
            exact(event["kernel_sysname"], "Linux")
            for field in ("kernel_release", "kernel_version", "kernel_machine"):
                text(event[field])
            integer(event["rlimit_nproc_soft"])
            integer(event["rlimit_nproc_hard"])
            continue
        exact(event["eagain"], 11)  # Linux EAGAIN, independently authored errno oracle.
        count = (15 if finite else 32) if index in (2, 3) else 0
        exact(event["child_count"], count)
        children = sequence(event["children"], count)
        if len(set(integer(pid, 2, 2**31 - 1) for pid in children)) != count:
            fail()
        identities.append({1, *children})
        if index == 3 and finite:
            exact(event["fork_return"], -1)
            exact(event["errno"], 11)
        elif index == 5:
            integer(event["fork_return"], 2, 2**31 - 1)
            exact(event["errno"], 0)
        else:
            exact(event["fork_return"], None)
            exact(event["errno"], None)
    if events[2]["children"] != events[3]["children"]:
        fail()
    return ({1}, identities[1], identities[2], {1})


def validate_case(case, slot, nonce):
    keys(case, ("slot", "worker_events", "source_samples", "controlled_limit", "effect", "definition"))
    exact(case["slot"], slot)
    exact(case["effect"], "enforced_with_controls_unadmitted")
    maximum = 16 if slot.endswith("16") else (64 if slot.endswith("64") else "max")
    exact(case["controlled_limit"], maximum)
    members = validate_worker_events(case["worker_events"], slot, nonce)
    samples = sequence(case["source_samples"], 4)
    all_tasks = []
    last_rows = None
    first_attr = None
    first_globals = None
    for phase, (sample, expected_members) in enumerate(zip(samples, members)):
        keys(sample, ("maximum", "current", "events_max", "tasks", "task_namespace_ids", "attribution", "globals", "cgroup_type"))
        cgroup_type(sample["cgroup_type"])
        exact(sample["maximum"], maximum)
        exact(sample["current"], len(expected_members))
        integer(sample["events_max"])
        tasks = sequence(sample["tasks"], len(expected_members))
        task_set = {identity(row, 2) for row in tasks}
        if len(task_set) != len(tasks) or any(tid == 0 for tid, _ in task_set):
            fail()
        coordinates = sequence(sample["task_namespace_ids"], len(tasks))
        tids, namespace_members = set(), set()
        for row in coordinates:
            sequence(row, 3)
            tid = integer(row[0], 1, 2**31 - 1)
            pids = tuple(integer(pid, 1, 2**31 - 1) for pid in sequence(row[1], 3, 32))
            exact(row[2], row[1])
            if tid in tids or pids[0] != tid or pids[-1] in namespace_members:
                fail()
            tids.add(tid)
            namespace_members.add(pids[-1])
        if tids != {tid for tid, _ in task_set} or namespace_members != expected_members:
            fail()
        all_tasks.append(task_set)
        attr = sample["attribution"]
        keys(attr, ("event_semantics", "pids_localevents", "complete_chain", "outer_index",
                    "reader_cgroup_namespace", "hierarchy_root", "controllers", "candidate_membership"))
        exact(attr["candidate_membership"], "typed_procs_local_membership_v1")
        exact(attr["event_semantics"], "hierarchical_with_local_enforcer")
        exact(attr["pids_localevents"], False)
        exact(attr["complete_chain"], True)
        identity(attr["reader_cgroup_namespace"], 2)
        root = attr["hierarchy_root"]
        keys(root, ("identity", "pids_max_present", "cgroup_type_present", "cgroup_events_present",
                    "available_pids", "mount_root_is_slash", "qualification"))
        root_identity = identity(root["identity"], 3)
        for field, value in (("pids_max_present", False), ("cgroup_type_present", False),
                             ("cgroup_events_present", False), ("available_pids", True),
                             ("mount_root_is_slash", True), ("qualification", "root_exempt")):
            exact(root[field], value)
        rows = sequence(attr["controllers"], 2, 32)
        outer = integer(attr["outer_index"], 1, len(rows) - 1)
        exact(rows[outer]["maximum"], 512)
        exact(rows[0]["maximum"], maximum)
        exact(rows[0]["current"], sample["current"])
        exact(rows[0]["events_max"], sample["events_max"])
        exact(rows[0]["cgroup_type"], sample["cgroup_type"])
        if cgroup_type(rows[outer]["cgroup_type"]) == "threaded":
            fail()
        groups = set()
        for index, row in enumerate(rows):
            keys(row, ("identity", "maximum", "current", "events_max", "events_local_max",
                       "current_samples", "events_samples", "events_local_samples", "cgroup_type"))
            kind = cgroup_type(row["cgroup_type"])
            if index + 1 < len(rows):
                parent_kind = cgroup_type(rows[index + 1]["cgroup_type"])
                allowed_children = {"domain": ("domain", "domain threaded"),
                                    "domain threaded": ("threaded",), "threaded": ("threaded",)}
                if kind not in allowed_children[parent_kind]:
                    fail()
            # The final row's parent is the independently qualified genuine
            # hierarchy root above, whose mixed-child exception is not a type.
            group = identity(row["identity"], 3)
            if group in groups or group == root_identity or (group[0], group[2]) != (root_identity[0], root_identity[2]):
                fail()
            groups.add(group)
            for pair_key, scalar in (("current_samples", "current"), ("events_samples", "events_max"),
                                     ("events_local_samples", "events_local_max")):
                pair = sequence(row[pair_key], 2)
                before, after = (integer(value) for value in pair)
                exact(row[scalar], max(before, after) if pair_key == "current_samples" else after)
                if (index == 0 and before != after) or (pair_key != "current_samples" and after < before):
                    fail()
            if row["maximum"] != "max":
                limit = integer(row["maximum"], 1)
                if index and limit - integer(row["current"]) < (len(members[1]) if phase == 0 else 1):
                    fail()
            if last_rows is not None:
                previous = last_rows[index]
                exact(row["identity"], previous["identity"])
                exact(row["maximum"], previous["maximum"])
                exact(row["cgroup_type"], previous["cgroup_type"])
                delta = integer(row["events_max"]) - integer(previous["events_max"])
                local_delta = integer(row["events_local_max"]) - integer(previous["events_local_max"])
                causal = int(maximum == 16 and phase == 2)
                if local_delta != (causal if index == 0 else 0) or delta < 0:
                    fail()
                if index == 0 and delta != causal or 0 < index <= outer and delta < causal:
                    fail()
        if first_attr is not None:
            for field in ("outer_index", "reader_cgroup_namespace", "hierarchy_root"):
                exact(attr[field], first_attr[field])
            if len(rows) != len(last_rows):
                fail()
        else:
            first_attr = attr
        last_rows = rows
        globals_ = sample["globals"]
        keys(globals_, ("threads_max", "pid_max", "total_tasks", "total_tasks_samples", "sched_policy",
                        "nproc_soft", "nproc_hard", "kernel_release", "kernel_version", "kernel_machine"))
        exact(globals_["sched_policy"], 0)
        integer(globals_["pid_max"], 33)
        total = max(integer(value, 1) for value in sequence(globals_["total_tasks_samples"], 2))
        exact(globals_["total_tasks"], total)
        if integer(globals_["threads_max"], 1) - total < (len(members[1]) if phase == 0 else 1):
            fail()
        for field in ("kernel_release", "kernel_version", "kernel_machine"):
            exact(globals_[field], case["worker_events"][0][field])
        for field in ("soft", "hard"):
            value = case["worker_events"][0]["rlimit_nproc_" + field]
            exact(globals_["nproc_" + field], "unlimited" if value == U64 else value)
        static = {name: value for name, value in globals_.items() if name not in ("total_tasks", "total_tasks_samples")}
        if first_globals is not None:
            exact(static, first_globals)
        first_globals = static
    if all_tasks[0] != all_tasks[3] or all_tasks[1] != all_tasks[2] or not all_tasks[0] < all_tasks[1]:
        fail()


def validate_shared_topology(cases):
    """Bind all 24 observations to one identity/kind/parent measurement scope."""
    bindings = {}
    leaves = set()
    ancestor_groups = set()
    common = None
    for case in cases:
        first = case["source_samples"][0]["attribution"]
        leaf = identity(first["controllers"][0]["identity"], 3)
        if leaf in leaves:
            fail()
        leaves.add(leaf)
        for sample in case["source_samples"]:
            attr = sample["attribution"]
            rows = attr["controllers"]
            root = identity(attr["hierarchy_root"]["identity"], 3)
            selected = (identity(rows[attr["outer_index"]]["identity"], 3), root,
                        identity(attr["reader_cgroup_namespace"], 2))
            if common is None:
                common = selected
            elif selected != common:
                fail()
            for index, row in enumerate(rows):
                group = identity(row["identity"], 3)
                parent = identity(rows[index + 1]["identity"], 3) if index + 1 < len(rows) else root
                binding = (row["cgroup_type"], parent)
                if group in bindings and bindings[group] != binding:
                    fail()
                bindings[group] = binding
                if index:
                    ancestor_groups.add(group)
    if leaves & ancestor_groups:
        fail()


def validate_budget(budget, root):
    keys(budget, ("parent_calls", "parent_captured_and_reserved_bytes", "max_calls", "max_bytes",
                  "cleanup_calls_reserved", "cleanup_bytes_reserved", "terminal_monotonic_ns", "external_source_reserved",
                  "root_output_bytes", "root_input_bytes", "native_effect_admission"))
    for field, value in (("max_calls", 400), ("max_bytes", 4194304), ("cleanup_calls_reserved", 100),
                         ("cleanup_bytes_reserved", 2097152),
                         ("native_effect_admission", "requires_complete_lane_exit_and_fresh_aggregate")):
        exact(budget[field], value)
    integer(budget["parent_calls"], 1, 400)
    integer(budget["parent_captured_and_reserved_bytes"], 1, 4194304)
    integer(budget["terminal_monotonic_ns"], 1)
    integer(budget["root_input_bytes"], 1, 8192)
    output = integer(budget["root_output_bytes"], 1, 65536)
    keys(root, ("api", "source", "captured_output_bytes"))
    exact(root["captured_output_bytes"], output)
    exact(root["api"], {"inspect_calls_reserved": 18, "inspect_body_bytes_reserved": 589824,
                        "runtime_probe_calls_reserved": 1, "runtime_probe_body_bytes_reserved": 4096})
    source = root["source"]
    keys(source, ("external_reserved", "root_reserved", "total_reserved", "limits", "fds", "output_reserved_before_final"))
    exact(source["limits"], {"bytes": 33554432, "reads": 65536, "output_bytes": 65536,
                              "live_fd_reservations": 256, "fd_opens": 32768})
    exact(source["external_reserved"], budget["external_source_reserved"])
    for part in ("external_reserved", "root_reserved", "total_reserved"):
        keys(source[part], ("bytes", "reads"))
        integer(source[part]["bytes"], 1, 33554432)
        integer(source[part]["reads"], 1, 65536)
    for field in ("bytes", "reads"):
        exact(source["total_reserved"][field], source["external_reserved"][field] + source["root_reserved"][field])
    integer(source["output_reserved_before_final"], 1, output - 1)
    fds = source["fds"]
    keys(fds, ("peak_reservations", "open_reservations", "fixed_overhead_reservations", "source_owned_remaining"))
    integer(fds["peak_reservations"], 16, 256)
    integer(fds["open_reservations"], 1, 32768)
    exact(fds["fixed_overhead_reservations"], 16)
    exact(fds["source_owned_remaining"], 0)


def native_gnu_target(value, cpu):
    if type(value) is not str or len(value) > 128 or cpu not in ("x86_64", "aarch64"):
        return False
    if value in (f"{cpu}-linux-gnu", f"{cpu}-suse-linux", f"{cpu}-redhat-linux"):
        return True
    match = re.fullmatch(re.escape(cpu) + r"-([A-Za-z0-9_.+]+)-linux-gnu", value)
    return match is not None and not any(abi in match[1].lower() for abi in ("musl", "uclibc", "android"))


def validate_artifact(artifact, context):
    keys(artifact, ("schema", "candidate", "toolchain", "compiler", "target", "flags", "profile", "binary", "size", "sha256",
                    "elf", "source_sha256", "controller_source_sha256", "cargo_lock_sha256", "cargo_manifest_sha256",
                    "build_log_sha256", "build_log_size", "original_deadline_ns", "build_tools"))
    exact(artifact["schema"], "dockerlens-pids-worker-build-v1")
    exact(artifact["candidate"], context["candidate_sha"])
    exact(artifact["binary"], "native-pids-worker")
    if artifact["target"] not in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
        fail()
    cpu = artifact["target"].split("-")[0]
    toolchain = text(artifact["toolchain"], 32)
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchain) is None:
        fail()
    flags = "-C target-feature=+crt-static -C panic=abort -C strip=symbols -C linker-flavor=gcc"
    exact(artifact["flags"], flags + (" -C linker-features=-lld" if cpu == "x86_64" else ""))
    exact(artifact["profile"], {"name": "release", "opt-level": "z", "lto": "fat", "codegen-units": 1})
    exact(artifact["elf"], {"class": 64, "endianness": "little", "machine": 62 if cpu == "x86_64" else 183,
                            "pt_interp": False, "dt_needed": False})
    compiler = artifact["compiler"]
    keys(compiler, ("release", "host", "commit_hash", "commit_date", "llvm_version"))
    exact(compiler["release"], toolchain)
    exact(compiler["host"], artifact["target"])
    digest(compiler["commit_hash"], 40)
    for field in ("commit_date", "llvm_version"):
        text(compiler[field], 64)
    for field in ("sha256", "source_sha256", "controller_source_sha256", "cargo_lock_sha256", "cargo_manifest_sha256", "build_log_sha256"):
        digest(artifact[field])
    integer(artifact["size"], 1, 8 * 1024 * 1024)
    integer(artifact["build_log_size"], 1, 1024 * 1024)
    integer(artifact["original_deadline_ns"], 1)
    tools = artifact["build_tools"]
    keys(tools, ("schema", "policy", "driver", "linker", "wrappers", "invocation", "dependencies", "crt",
                 "hashed_input_bytes", "scope", "implementation_closure"))
    for field, expected in (("schema", "dockerlens-pids-build-tools-v1"), ("policy", "native-gcc-bfd-v1"),
                            ("scope", "installed-tools-and-consumed-crt-only-v1"), ("implementation_closure", "unresolved")):
        exact(tools[field], expected)
    keys(tools["wrappers"], ("driver_sha256", "linker_sha256"))
    for value in tools["wrappers"].values():
        digest(value)
    invocation = tools["invocation"]
    keys(invocation, ("count", "size", "sha256", "output_size", "output_sha256"))
    exact(invocation["count"], 1)
    exact(invocation["output_size"], artifact["size"])
    exact(invocation["output_sha256"], artifact["sha256"])
    integer(invocation["size"], 1, 65536)
    digest(invocation["sha256"])
    keys(tools["dependencies"], ("size", "sha256"))
    integer(tools["dependencies"]["size"], 1, 131072)
    digest(tools["dependencies"]["sha256"])
    rows = [("driver", tools["driver"]), ("linker", tools["linker"])]
    crt = sequence(tools["crt"], 6, 8)
    roles = set()
    for row in crt:
        role = row["role"]
        if role not in ("start", "init", "fini", "begin", "end", "libc", "gcc-runtime", "gcc-eh") or role in roles:
            fail()
        roles.add(role)
        rows.append(("crt", row))
    if not {"start", "init", "fini", "begin", "end", "libc"} <= roles:
        fail()
    paths, total = set(), 0
    for kind, row in rows:
        fields = ("path", "size", "sha256", "identity", "package", "file_kind")
        keys(row, (*fields, *(("role",) if kind == "crt" else ("version",)), *(("native_target",) if kind == "driver" else ())))
        path = text(row["path"], 4096)
        if not path.startswith("/") or path in paths:
            fail()
        paths.add(path)
        total += integer(row["size"], 1, 32 * 1024 * 1024)
        digest(row["sha256"])
        if kind != "crt":
            text(row["version"], 8192)
            if row["file_kind"] not in ("elf", "script"):
                fail()
        else:
            exact(row["file_kind"], "archive" if row["role"] in ("libc", "gcc-runtime", "gcc-eh") else "elf")
        if kind == "driver" and not native_gnu_target(row["native_target"], cpu):
            fail()
        info = row["identity"]
        keys(info, ("device", "inode", "uid", "gid", "mode", "links", "mtime_ns", "ctime_ns"))
        for field, value in info.items():
            integer(value, 1 if field in ("inode", "links") else 0)
        if info["mode"] & 0o170000 != 0o100000:
            fail()
        package = row["package"]
        keys(package, ("status", "reason", "unverified_path_hint"))
        exact(package["status"], "unavailable")
        exact(package["reason"], "os-bootstrap-not-queried")
        if package["unverified_path_hint"] is not None:
            text(package["unverified_path_hint"], 255)
    integer(total, 1, 128 * 1024 * 1024)
    integer(tools["hashed_input_bytes"], 2 * total, 256 * 1024 * 1024)


def validate_measured(proof, context):
    measured = proof["measured"]
    keys(measured, ("daemon", "artifact_copy", "decoded"))
    daemon = measured["daemon"]
    keys(daemon, ("release", "advertised_api", "mode", "reported_pids", "cgroup_driver", "cgroup_version", "kernel_identity_source"))
    for field, expected in (("release", context["engine_release"]), ("advertised_api", context["api_version"]),
                            ("mode", context["mode"]), ("reported_pids", True), ("cgroup_version", "2"),
                            ("kernel_identity_source", "held_peer_and_live_worker")):
        exact(daemon[field], expected)
    if daemon["cgroup_driver"] not in (("systemd",) if context["mode"] == "rootless" else ("systemd", "cgroupfs")):
        fail()
    copy = measured["artifact_copy"]
    keys(copy, ("path", "size", "sha256", "io", "source", "copy", "directory_uid", "directory_mode"))
    uid = 1000 if context["mode"] == "rootless" else 0
    exact(copy["path"], "/tmp/dockerlens-pids-worker-" + context["run_id"] + "/native-pids-worker")
    exact(copy["size"], proof["artifact"]["size"])
    exact(copy["sha256"], proof["artifact"]["sha256"])
    exact(copy["directory_uid"], uid)
    exact(copy["directory_mode"], 448)
    for field in ("source", "copy"):
        row = copy[field]
        keys(row, ("device", "inode", "uid", "gid", "mode", "links"))
        for name, value in row.items():
            integer(value, 1 if name in ("inode", "links") else 0)
        exact(row["links"], 1)
        exact(row["mode"], 448)
        if field == "copy":
            exact(row["uid"], uid)
            exact(row["gid"], uid)
    validate_copy_receipt(copy["io"], copy["size"])
    decoded = measured["decoded"]
    keys(decoded, ("route", "selected_ids", "reserved_calls", "reserved_body_bytes", "reserved_transport_bytes", "actual_requests",
                   "actual_body_bytes", "limits", "decoded_limits", "origin", "scope"))
    for field, value in (("route", "explicit_unix_socket"), ("selected_ids", 6), ("reserved_calls", 16),
                         ("reserved_body_bytes", 262144), ("reserved_transport_bytes", 278528),
                         ("origin", "effective"), ("scope", "actual_readonly_product_acquisition")):
        exact(decoded[field], value)
    exact(decoded["limits"], {"max_requests": 16, "max_selected_resources": 6, "max_expansions": 8,
                             "max_response_bytes": 32768, "max_total_bytes": 262144, "max_elapsed_seconds": 10})
    integer(decoded["actual_requests"], 8, 16)
    integer(decoded["actual_body_bytes"], 1, 262144)
    ids = {context["outer_id"]}
    expected_decoded = {}
    for slot, case in zip(SLOTS, proof["cases"]):
        definition = case["definition"]
        keys(definition, ("slot", "id", "name", "pids_limit", "definition"))
        cid = digest(definition["id"])
        if cid in ids:
            fail()
        ids.add(cid)
        maximum = 16 if slot.endswith("16") else (64 if slot.endswith("64") else -1)
        exact(definition["slot"], slot)
        name = f"dl-pids-{context['run_id']}-{slot}"
        exact(definition["name"], name)
        exact(definition["pids_limit"], maximum)
        expected_decoded[cid] = maximum
        document = definition["definition"]
        if slot.startswith("cli"):
            exact(document, {"oracle": "independently_authored_cli", "pids_limit": maximum,
                             "entrypoint": "/dl-pids-worker", "fixed_mounts": 2})
        else:
            # The producer compares the renderer to this independently authored
            # complete request; the reader repeats that contract from literals.
            keys(document, ("schema_version", "context", "requests", "prerequisites"))
            exact(document["context"], {"kind": "observed", "provenance": "process_local_only",
                  "engine_release": context["engine_release"], "api_version": context["api_version"], "daemon_mode": context["mode"]})
            prerequisites = []
            if context["mode"] == "rootless" and maximum > 0:
                prerequisites = [{"kind": "rootless_pids", "reference": "1", "identity": name, "pids_limit": str(maximum),
                                  "required_cgroup_driver": "systemd", "required_cgroup_version": "2", "required_pids_report": True,
                                  "delegation": "unverified", "enforcement": "unverified"}]
            exact(document["schema_version"], 4 if prerequisites else 1)
            exact(document["prerequisites"], prerequisites)
            exact(document["requests"], [{"method": "POST", "path": f"/v{context['api_version']}/containers/create?name={name}",
                "body": {"Image": context["fixture_image"], "Entrypoint": ["/dl-pids-worker"],
                    "Cmd": [slot, proof["nonce"], str(proof["budgets"]["terminal_monotonic_ns"])],
                    "Labels": {"io.dockerlens.native-run": context["run_id"], "io.dockerlens.native-pids": context["run_id"],
                               "io.dockerlens.native-pids-slot": slot},
                    "HostConfig": {"Init": False, "PidsLimit": maximum, "Mounts": [
                        {"Type": "bind", "Source": copy["path"], "Target": "/dl-pids-worker", "ReadOnly": True},
                        {"Type": "bind", "Source": f"/dockerlens-native/pids-control/{slot}",
                         "Target": "/dl-pids-control", "ReadOnly": False}]}}}])
    exact(decoded["decoded_limits"], expected_decoded)


def validate_pids_proof(proof, expected_context):
    try:
        validate_context(expected_context)
        keys(proof, ("schema_version", "contract", "scope", "capability_admission", "catalogue_admission", "context", "nonce",
                     "outer_before", "outer_after_confirmation", "outer_final", "artifact", "measured", "cases", "root", "cleanup", "budgets"))
        for field, value in (("schema_version", 2), ("contract", CONTRACT), ("scope", "controlled_live_leaf_enforcement_only"),
                             ("capability_admission", []), ("catalogue_admission", False), ("context", expected_context)):
            exact(proof[field], value)
        digest(proof["nonce"], 32)
        outer = proof["outer_before"]
        keys(outer, ("context", "id", "pid", "start_ticks", "runtime_started_at", "restart_count", "cgroup_namespace_mode"))
        exact(outer["id"], expected_context["outer_id"])
        exact(outer["context"], expected_context["outer"])
        integer(outer["pid"], 1, 2**31 - 1)
        integer(outer["start_ticks"], 1)
        text(outer["runtime_started_at"], 64)
        exact(outer["restart_count"], 0)
        exact(outer["cgroup_namespace_mode"], "private")
        exact(proof["outer_after_confirmation"], outer)
        exact(proof["outer_final"], outer)
        validate_budget(proof["budgets"], proof["root"])
        exact(proof["cleanup"], {"containers": "absent", "absence_rounds": 2,
              "worker_exits": "finished_then_owner_term_zero", "controller": "closed_and_reaped", "guest_copy": "removed",
              "source_handles": "closed_before_final_ack", "outer": "retained_for_lane_finalizer",
              "outer_teardown_owner": "native_conformance_outer_v1"})
        cases = sequence(proof["cases"], 6)
        for case, slot in zip(cases, SLOTS):
            validate_case(case, slot, proof["nonce"])
        validate_shared_topology(cases)
        # Other proof sections are validated below against independent context
        # and literal request/evidence expectations; none select their reader.
        validate_artifact(proof["artifact"], expected_context)
        validate_measured(proof, expected_context)
        return {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError, AttributeError):
        fail()


def read_pids_proof(path, capture_dir, expected_context):
    try:
        def validate(proof, context):
            result = validate_pids_proof(proof, context)
            verify_artifact_files(proof["artifact"], capture_dir)
            return result
        return read_private_proof(path, capture_dir, FILENAME, expected_context, validate, max_bytes=LIMIT)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()


def verify_artifact_files(manifest, capture_dir):
    """Separate bounded reader I/O, never charged as original live root I/O.

    The producer's native experiment already validated its own retained handles.
    This repeats the immutable prebuild/source binding independently, retaining
    directories and checking before/after versions. No binary is executed.
    """
    import json
    import tomllib
    descriptors = []
    try:
        directory = Path(capture_dir)
        if directory.resolve(strict=True) != directory:
            fail()
        capture = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(capture)
        socket = os.open("socket", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=capture)
        descriptors.append(socket)
        artifact = os.open("pids-worker", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=socket)
        descriptors.append(artifact)
        before = os.fstat(artifact)
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o700:
            fail()

        def read(name, maximum, mode, parent):
            held_parents = []
            parts = name.split("/")
            try:
                for component in parts[:-1]:
                    parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    held_parents.append(parent)
                source = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
                held_parents.append(source)
                info = os.fstat(source)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                        or not 0 < info.st_size <= maximum or mode is not None and stat.S_IMODE(info.st_mode) != mode):
                    fail()
                data = bytearray()
                while len(data) < info.st_size:
                    requested = min(65536, info.st_size - len(data))
                    part = os.read(source, requested)
                    if len(part) != requested:
                        fail()
                    data.extend(part)
                if os.read(source, 1) or fingerprint(os.fstat(source)) != fingerprint(info):
                    fail()
                if fingerprint(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) != fingerprint(info):
                    fail()
                return bytes(data)
            finally:
                for descriptor in reversed(held_parents):
                    os.close(descriptor)

        recorded = json.loads(read("native-pids-worker.json", 32768, 0o600, artifact), object_pairs_hook=unique_object)
        exact(recorded, manifest)
        tools = manifest["build_tools"]
        for name, maximum, size, expected in (
                ("native-pids-worker", 8 * 1024 * 1024, manifest["size"], manifest["sha256"]),
                ("native-pids-worker-build.log", 1024 * 1024, manifest["build_log_size"], manifest["build_log_sha256"]),
                ("native-pids-worker-driver.py", 16384, None, tools["wrappers"]["driver_sha256"]),
                ("native-pids-worker-ld.py", 16384, None, tools["wrappers"]["linker_sha256"]),
                ("native-pids-worker-link.json", 65536, tools["invocation"]["size"], tools["invocation"]["sha256"]),
                ("native-pids-worker-link.d", 131072, tools["dependencies"]["size"], tools["dependencies"]["sha256"])):
            data = read(name, maximum, 0o700 if name == "native-pids-worker" else 0o600, artifact)
            if size is not None and size != len(data) or hashlib.sha256(data).hexdigest() != expected:
                fail()
            if name == "native-pids-worker":
                validate_static_elf(data, manifest["elf"]["machine"])
        source_root = Path(__file__).resolve().parents[1]
        source = os.open(source_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(source)
        channel = tomllib.loads(read("rust-toolchain.toml", 4096, None, source).decode())["toolchain"]["channel"]
        exact(channel, manifest["toolchain"])
        for name, maximum, field in (("examples/native-pids-worker.rs", 131072, "source_sha256"),
                ("examples/native-pids-controller/mod.rs", 131072, "controller_source_sha256"),
                ("Cargo.toml", 65536, "cargo_manifest_sha256"), ("Cargo.lock", 1048576, "cargo_lock_sha256")):
            data = read(name, maximum, None, source)
            if hashlib.sha256(data).hexdigest() != manifest[field]:
                fail()
        if fingerprint(os.fstat(artifact)) != fingerprint(before) or fingerprint(os.stat("pids-worker", dir_fd=socket, follow_symlinks=False)) != fingerprint(before):
            fail()
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def validate_static_elf(data, machine):
    """Independent ELF64 program-header oracle: no interpreter or dependency."""
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        fail()
    if struct.unpack_from("<HHI", data, 16) not in ((2, machine, 1), (3, machine, 1)):
        fail()
    offset = struct.unpack_from("<Q", data, 32)[0]
    header_size, entry_size, entries = struct.unpack_from("<HHH", data, 52)
    if header_size != 64 or entry_size != 56 or not 1 <= entries <= 128 or offset < 64 or offset + entries * 56 > len(data):
        fail()
    loads, dynamic = 0, 0
    for number in range(entries):
        kind, _, start, _, _, size, memory, _ = struct.unpack_from("<IIQQQQQQ", data, offset + number * 56)
        if start > len(data) or size > len(data) - start or memory < size or kind == 3:
            fail()
        loads += kind == 1
        if kind == 2:
            dynamic += 1
            if dynamic > 1 or not 0 < size <= 65536 or size % 16:
                fail()
            terminated = False
            for position in range(start, start + size, 16):
                tag = struct.unpack_from("<q", data, position)[0]
                if tag == 1:
                    fail()
                if tag == 0:
                    terminated = True
                    break
            if not terminated:
                fail()
    if not loads:
        fail()


def main(arguments):
    if len(arguments) != 10:
        fail()
    directory, candidate, run, lane, engine, api, mode, fixture, outer_id, image = arguments
    context = {"candidate_sha": candidate, "run_id": run, "lane": lane, "engine_release": engine,
               "api_version": api, "mode": mode, "outer_backend": os.environ.get("NATIVE_OUTER_ENGINE"),
               "outer_id": outer_id, "fixture_image": fixture,
               "outer": {"id": outer_id, "name": "dl-native-" + run, "owner": run, "image": image,
                         "data_volume": "dl-native-data-" + run, "socket_source": str(Path(directory) / "socket"),
                         "privileged": True, "memory_bytes": 4294967296, "cpu_quota": 200000, "cpu_period": 100000, "pids_limit": 512}}
    read_pids_proof(Path(directory) / FILENAME, directory, context)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise SystemExit("invalid private pids proof") from None
