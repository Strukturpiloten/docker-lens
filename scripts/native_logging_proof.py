"""Closed logging-v1 private source reader; configured retention/read only."""
from hashlib import sha256
from pathlib import Path
import json
import os
import re
import sys
from native_external_network_proof import validate_context
from native_health_metadata_proof import timestamp_ns
from native_network_attachment_proof import canonical, keys, read_private_proof
from native_shm_size_proof import exact, integer
from native_source_accounting import outer_snapshot_cost

CONTRACT = "logging-v1"
FILENAME = CONTRACT + ".json"
LIMIT = 16384
FULL = 73742
SMALL = 9216
CLEANUP = 552960
PROCESS = 'test "$$" = 1 || exit 61; printf "%s\\n" "$1"'
REFUSAL = "Error response from daemon: configured logging driver does not support reading\n"
DELIMITER = "\nDOCKERLENS_LOG_EXIT:"
DRIVERS = ("json-file", "local", "none")
ROLES = ("oracle", "rendered")
SLOTS = tuple((driver, role) for driver in DRIVERS for role in ROLES)


def fail():
    raise ValueError("invalid private logging proof")


def expected_config(driver):
    if driver not in DRIVERS:
        fail()
    return {"Type": driver, "Config": {"max-size": "1m"} if driver == "json-file" else {}}


def expected_token(context, driver, role):
    if driver not in DRIVERS or role not in ROLES:
        fail()
    token = f"dockerlens-log-v1:{context['run_id']}:{driver}:{role}"
    if re.fullmatch(r"dockerlens-log-v1:[A-Za-z0-9]{8}:(?:json-file|local|none):(?:oracle|rendered)", token) is None or len(token.encode()) + 1 > 96:
        fail()
    return token


def parse_frame(frame):
    """Preserve every original output byte; no command-substitution LF loss."""
    if type(frame) is not str or not 0 < len(frame.encode()) <= 1024 or not frame.endswith("\n") or "\0" in frame:
        fail()
    prefix, marker, status = frame[:-1].rpartition(DELIMITER)
    if not marker or "DOCKERLENS_LOG_EXIT:" in prefix or status not in ("0", "1"):
        fail()
    return int(status), prefix


def validate_read(value, context, driver, role, ident):
    keys(value, ("target", "argv", "status", "raw", "raw_sha256", "frame", "frame_sha256"))
    exact(value["target"], ident)
    exact(value["argv"], ["logs", "--tail", "1", "--timestamps=false", ident])
    status, raw = parse_frame(value["frame"])
    exact(value["status"], status)
    exact(value["raw"], raw)
    exact(value["frame_sha256"], sha256(value["frame"].encode()).hexdigest())
    exact(value["raw_sha256"], sha256(raw.encode()).hexdigest())
    exact(status, 1 if driver == "none" else 0)
    exact(raw, REFUSAL if driver == "none" else expected_token(context, driver, role) + "\n")


def configured(value, context, driver, role, terminal):
    keys(value, ("log_config", "cmd", "tty", "entrypoint", "init", "status", "pid", "running", "exit", "oom", "restarts", "error_empty", "started_at", "finished_at"))
    config = expected_config(driver)
    for key, expected in (("log_config", config), ("cmd", ["sh", "-c", PROCESS, "dl-log", expected_token(context, driver, role)]),
                          ("tty", False), ("entrypoint", "empty_inherited"), ("init", "not_inserted"),
                          ("status", "exited" if terminal else "created"), ("pid", 0), ("running", False),
                          ("exit", 0), ("oom", False), ("restarts", 0), ("error_empty", True)):
        exact(value[key], expected)
    if terminal:
        start, finish = timestamp_ns(value["started_at"]), timestamp_ns(value["finished_at"])
        if not 0 < start <= finish:
            fail()
    else:
        exact(value["started_at"], "0001-01-01T00:00:00Z")
        exact(value["finished_at"], "0001-01-01T00:00:00Z")


def validate_logging_proof(proof, expected_context, *, outer_backend):
    try:
        delta, extra = outer_snapshot_cost(outer_backend)
        validate_context(expected_context)
        if not expected_context["fixture_image"].startswith("docker.io/library/busybox:"):
            fail()
        keys(proof, ("schema_version", "contract", "capability_admission", "catalogue_admission", "scope", "context", "outer_backend", "borrowed_image", "containers", "daemon_health", "accounting", "cleanup"))
        for key, value in (("schema_version", 1), ("contract", CONTRACT), ("capability_admission", []), ("catalogue_admission", False),
                           ("scope", "explicit_drivers_configured_one_line_read_only"), ("context", expected_context), ("outer_backend", outer_backend),
                           ("daemon_health", "version_matches_after_controls"), ("cleanup", {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False})):
            exact(proof[key], value)
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        if type(proof["containers"]) is not list or len(proof["containers"]) != 6:
            fail()
        ids = {expected_context["outer"]["id"]}
        for item, (driver, role) in zip(proof["containers"], SLOTS):
            keys(item, ("driver", "role", "id", "name", "owner", "image_id", "wire", "requested", "before", "after", "wait_exit", "read", "cleanup"))
            if not canonical(item["id"]) or item["id"] in ids:
                fail()
            ids.add(item["id"])
            for key, value in (("driver", driver), ("role", role), ("name", f"dl-log-{expected_context['run_id']}-{driver}-{role}"),
                               ("owner", expected_context["run_id"]), ("image_id", image["id"]),
                               ("wire", "independent_cli" if role == "oracle" else "literal_rendered"),
                               ("requested", expected_config(driver)), ("wait_exit", 0), ("cleanup", "absent")):
                exact(item[key], value)
            configured(item["before"], expected_context, driver, role, False)
            configured(item["after"], expected_context, driver, role, True)
            validate_read(item["read"], expected_context, driver, role, item["id"])
        a = proof["accounting"]
        keys(a, ("context_calls", "context_bytes", "slot_calls", "slot_bytes", "daemon_health_calls", "daemon_health_bytes",
                 "before_cleanup_calls", "before_cleanup_bytes", "ordinary_calls", "ordinary_bytes", "cleanup_calls", "cleanup_bytes",
                 "final_readback_calls", "final_readback_bytes", "reservation", "deadline_seconds", "cleanup_reserve_seconds",
                 "ordinary_elapsed_ns", "cleanup_elapsed_ns", "elapsed_ns", "initial_context_acquisition"))
        context_calls = (9 if expected_context["lane"].startswith("debian11-") else 8) + delta
        slot_limits = [193564, 322616] * 3
        pending = 1769766 + extra
        for key, value in (("context_calls", context_calls), ("slot_calls", [7] * 6), ("daemon_health_calls", 1),
                           ("before_cleanup_calls", context_calls + 43), ("ordinary_calls", context_calls + 45 + delta),
                           ("cleanup_calls", 54), ("final_readback_calls", 2 + delta), ("deadline_seconds", 180), ("cleanup_reserve_seconds", 46),
                           ("reservation", {"pending_ordinary_bytes": pending, "slot_byte_limits": slot_limits,
                                            "cleanup_calls": 54, "cleanup_bytes": 552960, "final_calls": 2 + delta,
                                            "final_bytes": 147484 + extra, "byte_scope": "captured_stdout_stderr_not_wire"}),
                           ("initial_context_acquisition", {"max_requests": 16, "max_total_bytes": 2097152, "max_elapsed_seconds": 15, "accounting": "separate_existing_bound"})):
            exact(a[key], value)
        context_bytes = integer(a["context_bytes"], 1 + extra, 2097152 - pending)
        if type(a["slot_bytes"]) is not list or len(a["slot_bytes"]) != 6:
            fail()
        slot_bytes = sum(integer(value, 1, bound) for value, bound in zip(a["slot_bytes"], slot_limits))
        health_bytes = integer(a["daemon_health_bytes"], 1, FULL)
        before = integer(a["before_cleanup_bytes"], 1, 2097152)
        exact(before, context_bytes + slot_bytes + health_bytes)
        # Shared capture_room sees cumulative cleanup, not a reset ordinary ledger.
        if before + CLEANUP + 147484 + extra > 2097152:
            fail()
        final = integer(a["final_readback_bytes"], 1 + extra, 147484 + extra)
        exact(a["ordinary_bytes"], before + final)
        integer(a["ordinary_bytes"], 1 + 2 * extra, 2097152)
        integer(a["cleanup_bytes"], 1, CLEANUP)
        work = integer(a["ordinary_elapsed_ns"], 1, 134 * 10**9)
        cleanup = integer(a["cleanup_elapsed_ns"], 1, 46 * 10**9)
        if work + cleanup > integer(a["elapsed_ns"], 1, 180 * 10**9):
            fail()
        if len(json.dumps(proof, separators=(",", ":"), ensure_ascii=False).encode()) > LIMIT:
            fail()
        return {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, IndexError, AttributeError):
        fail()


def read_logging_proof(path, capture_dir, expected_context, *, outer_backend):
    try:
        outer_snapshot_cost(outer_backend)
        return read_private_proof(path, capture_dir, FILENAME, expected_context,
                                  lambda value, context: validate_logging_proof(value, context, outer_backend=outer_backend))
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
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
                         "data_volume": "dl-native-data-" + run, "socket_source": str(Path(directory) / "socket"),
                         "privileged": True, "memory_bytes": 4294967296, "cpu_quota": 200000, "cpu_period": 100000, "pids_limit": 512}}
    read_logging_proof(Path(directory) / FILENAME, directory, context, outer_backend=os.environ.get("NATIVE_OUTER_ENGINE"))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise SystemExit("invalid private logging proof") from None
