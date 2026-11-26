"""Strict private namespace-local named-capability proof, without admission."""
from hashlib import sha256
import os
from pathlib import Path
import re
import sys
from native_external_network_proof import validate_context
from native_health_metadata_proof import timestamp_ns
from native_network_attachment_proof import canonical, keys, read_private_proof
from native_shm_size_proof import exact, integer
from native_source_accounting import outer_snapshot_cost

CONTRACT = "named-capabilities-v1"
FILENAME = CONTRACT + ".json"
LIMIT = 65536
RESULT = {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}
ROLES = ("default-cli", "add-cli", "add-rendered", "drop-cli", "drop-rendered", "both-cli", "both-rendered", "drop-all-cli", "netbind-only-cli", "all-cli", "all-minus-sysadmin-cli")
# Independent native configuration expectations, never derived from rendered data.
CAPS = (((), ()), (("NET_BIND_SERVICE",), ()), (("NET_BIND_SERVICE",), ()), ((), ("SYS_ADMIN",)), ((), ("SYS_ADMIN",)), (("NET_BIND_SERVICE",), ("SYS_ADMIN",)), (("NET_BIND_SERVICE",), ("SYS_ADMIN",)), ((), ("ALL",)), (("NET_BIND_SERVICE",), ("ALL",)), (("ALL",), ()), (("ALL",), ("SYS_ADMIN",)))
MASK_KEYS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
ZERO_TIME = "0001-01-01T00:00:00Z"


def fail():
    raise ValueError("invalid private named capabilities proof")


def number(text, low=0):
    if type(text) is not str or re.fullmatch(r"0|[1-9][0-9]{0,19}", text) is None:
        fail()
    return integer(int(text), low, 2**64 - 1)


def cap_mask(text):
    # Linux proc status prints exactly sixteen lower-case hex digits for u64.
    if type(text) is not str or re.fullmatch(r"[0-9a-f]{16}", text) is None:
        fail()
    return integer(int(text, 16), 0, 2**64 - 1)


def effect(packet, container_id):
    keys(packet, ("raw", "sha256"))
    text = packet["raw"]
    if type(text) is not str or not 0 < len(text.encode()) <= 4096 or not text.endswith("\n") or "\r" in text:
        fail()
    exact(packet["sha256"], sha256(text.encode()).hexdigest())
    rows = [line.split(" ") for line in text.splitlines()]
    if len(rows) != 16 or rows[0] != [CONTRACT] or rows[1] != ["hostname", container_id[:12]]:
        fail()
    samples = []
    for offset, phase in ((2, "before"), (9, "after")):
        identity = rows[offset]
        if len(identity) != 9 or identity[0] != phase or identity[1] != "1" or identity[-1] != "sleep":
            fail()
        for i in (2, 3, 4):
            number(identity[i], 0 if i == 3 else 1)
        if re.fullmatch(r"user:\[[1-9][0-9]{0,19}\]", identity[5]) is None:
            fail()
        number(identity[5][6:-1], 1)
        exact(identity[6], identity[5])
        # Held proc object must still identify the current /proc/1 directory.
        exact(identity[7], "held_current_pid1")
        exact(rows[offset + 1], ["uid", "0", "0", "0", "0"])
        masks = []
        for row, name in zip(rows[offset + 2:offset + 7], MASK_KEYS):
            if len(row) != 2 or row[0] != name:
                fail()
            masks.append(cap_mask(row[1]))
        if masks[2] & ~masks[1] or masks[2] & ~masks[3]:
            fail()
        samples.append((identity[1:], masks))
    exact(samples[1], samples[0])
    return samples[0][1][2]


def retained(raw, expected, lane):
    # Closed normalization for the four named profiles: Engine/CLI may retain
    # named capabilities with CAP_ prefix. ALL is only literal ALL, never CAP_ALL.
    if lane not in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
        fail()
    if not expected:
        if raw not in (None, []):
            fail()
    elif (type(raw) is not list or len(raw) != 1 or type(raw[0]) is not str
          or raw[0] not in (expected[0], "CAP_" + expected[0])
          or expected[0] == "ALL" and raw[0] != "ALL"):
        fail()


def configured(item, record, image, context, live, caps):
    keys(item, ("id", "name", "image", "config_image", "owner", "hostname", "cmd", "entrypoint", "user", "init", "running", "pid", "started_at", "finished_at", "oom", "exit", "status", "restarts", "error", "restarting", "paused", "dead", "privileged", "cap_add", "cap_drop", "mounts", "devices", "ports"))
    for key, value in (("id", record["id"]), ("name", "/" + record["name"]), ("image", image), ("config_image", context["fixture_image"]), ("owner", context["run_id"]), ("hostname", record["id"][:12]), ("cmd", ["sleep", "180"]), ("running", live), ("oom", False), ("exit", 0), ("status", "running" if live else "created"), ("restarts", 0), ("error", ""), ("restarting", False), ("paused", False), ("dead", False), ("privileged", False), ("mounts", []), ("finished_at", ZERO_TIME)):
        exact(item[key], value)
    if item["entrypoint"] not in (None, []) or item["user"] not in ("", "0", "0:0"):
        fail()
    if type(item["init"]) not in (type(None), bool) or item["init"] not in (None, False):
        fail()
    if item["devices"] not in (None, []) or item["ports"] not in (None, {}):
        fail()
    retained(item["cap_add"], caps[0], context["lane"])
    retained(item["cap_drop"], caps[1], context["lane"])
    if live:
        integer(item["pid"], 1, 2**31 - 1)
        timestamp_ns(item["started_at"])
    else:
        exact(item["pid"], 0)
        exact(item["started_at"], ZERO_TIME)


def validate_capabilities_proof(proof, expected_context, *, outer_backend):
    try:
        extra_calls, extra_bytes = outer_snapshot_cost(outer_backend)
        validate_context(expected_context)
        if not expected_context["fixture_image"].startswith("docker.io/library/busybox:"):
            fail()
        keys(proof, ("schema_version", "contract", "context", "outer_backend", "capability_admission", "catalogue_admission", "scope", "normalization", "borrowed_image", "containers", "accounting", "cleanup", "daemon_health"))
        for key, value in (("schema_version", 1), ("contract", CONTRACT), ("context", expected_context), ("outer_backend", outer_backend), ("capability_admission", []), ("catalogue_admission", False), ("scope", "cli_causal_transitions_and_rendered_retention_namespace_local"), ("normalization", "four_profiles_named_optional_CAP_prefix_ALL_literal"), ("cleanup", {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}), ("daemon_health", "version_matches_after_controls")):
            exact(proof[key], value)
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        if type(proof["containers"]) is not list or len(proof["containers"]) != 11:
            fail()
        ids = {expected_context["outer"]["id"]}
        masks = []
        for record, role, caps in zip(proof["containers"], ROLES, CAPS):
            keys(record, ("role", "id", "name", "owner", "wire", "created", "running", "after", "effect", "cleanup"))
            if not canonical(record["id"]) or record["id"] in ids:
                fail()
            ids.add(record["id"])
            for key, value in (("role", role), ("name", f"dl-cap-{expected_context['run_id']}-{role}"), ("owner", expected_context["run_id"]), ("wire", "literal_rendered" if role.endswith("-rendered") else "independent_cli"), ("cleanup", "absent")):
                exact(record[key], value)
            for phase in ("created", "running", "after"):
                configured(record[phase], record, image["id"], expected_context, phase != "created", caps)
            exact(record["after"], record["running"])
            masks.append(effect(record["effect"], record["id"]))
        default, all_mask = masks[0], masks[9]
        if default & 1024 != 1024 or default & 2097152 or all_mask & 2097152 != 2097152:
            fail()
        exact(masks[1:7], [default] * 6)
        exact(masks[7], 0)
        exact(masks[8], 1024)
        exact(masks[10], all_mask & ~2097152)
        a = proof["accounting"]
        keys(a, ("context_calls", "slot_calls", "daemon_health_calls", "final_readback_calls", "ordinary_calls", "ordinary_bytes", "small_calls", "small_bytes", "cleanup_calls", "cleanup_bytes", "deadline_seconds", "cleanup_reserve_seconds", "ordinary_elapsed_ns", "cleanup_elapsed_ns", "elapsed_ns", "initial_context_acquisition"))
        context_calls = (9 if expected_context["lane"].startswith("debian11-") else 8) + extra_calls
        for key, value in (("context_calls", context_calls), ("slot_calls", [8] * 11), ("daemon_health_calls", 1), ("final_readback_calls", 2 + extra_calls), ("ordinary_calls", context_calls + 91 + extra_calls), ("small_calls", 88), ("cleanup_calls", 99), ("deadline_seconds", 180), ("cleanup_reserve_seconds", 46), ("initial_context_acquisition", {"max_requests": 16, "max_total_bytes": 2097152, "max_elapsed_seconds": 15, "accounting": "separate_existing_bound"})):
            exact(a[key], value)
        integer(a["small_bytes"], 1, 88 * 8192)
        full = 12 if expected_context["lane"].startswith("debian11-") else 11
        integer(a["ordinary_bytes"], a["small_bytes"] + 2 * extra_bytes, full * 73742 + 88 * 8192 + 2 * extra_bytes)
        integer(a["cleanup_bytes"], 1, 99 * 10240)
        work = integer(a["ordinary_elapsed_ns"], 1, 134 * 10**9)
        cleanup = integer(a["cleanup_elapsed_ns"], 1, 46 * 10**9)
        if work + cleanup > integer(a["elapsed_ns"], 1, 180 * 10**9):
            fail()
        return dict(RESULT)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, IndexError, AttributeError):
        fail()


def read_capabilities_proof(path, capture_dir, context, *, outer_backend):
    try:
        outer_snapshot_cost(outer_backend)
        return read_private_proof(path, capture_dir, FILENAME, context, lambda p, c: validate_capabilities_proof(p, c, outer_backend=outer_backend), max_bytes=LIMIT)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()


def main(arguments):
    if len(arguments) != 12:
        fail()
    directory, candidate, run, lane, engine, api, mode, package, fixture, image, outer_id, uid = arguments
    if re.fullmatch(r"0|[1-9][0-9]{0,9}", uid) is None:
        fail()
    context = {"candidate_sha": candidate, "run_id": run, "lane": lane, "engine_release": engine, "rendering_api": api, "acquisition_api": "1.41" if lane.startswith("debian11-") else "1.49", "mode": mode, "docker_package": package, "fixture_image": fixture, "daemon_uid": int(uid), "outer": {"id": outer_id, "name": "dl-native-" + run, "owner": run, "image": image, "data_volume": "dl-native-data-" + run, "socket_source": str(Path(directory) / "socket"), "privileged": True, "memory_bytes": 4294967296, "cpu_quota": 200000, "cpu_period": 100000, "pids_limit": 512}}
    read_capabilities_proof(Path(directory) / FILENAME, directory, context, outer_backend=os.environ.get("NATIVE_OUTER_ENGINE"))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise SystemExit("invalid private named capabilities proof") from None
