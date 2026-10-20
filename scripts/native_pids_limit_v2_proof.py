"""Strict private PIDs-v2 coordinates and compact phases, never native admission.

The live CLI requires anonymous context stdin and independently reconstructs its
source/OCI/log boundary before stable v2 custody and historical pure semantic
expansion. Historical pure v2 fixtures remain callable without live authority;
they cannot enter the live CLI or admit capability/compatibility evidence.
The 1 KiB reserve carries the independently validated compact original boundary.
"""

import json
import os
from pathlib import Path
import re
import sys

from native_network_attachment_proof import read_private_proof
from native_external_network_proof import validate_context
from native_pids_limit_proof import same, validate_pids_limit_proof

CONTRACT = "pids-limit-v2"
FILENAME = "pids-limit-v2.json"
SCOPE = "finite16_finite64_unlimited_32_child_attempts_only"
PROOF_BYTES = 16384
SERIALIZED_BYTES = 15360
MAX_PID = 4194304
PHASE_FIELDS = ("rows", "members", "pids_current", "pids_max", "denials", "oom_kills",
                "outer_pids", "outer_memory", "ancestor_headroom", "phase")
ROOT_FIELDS = ("schema_version", "contract", "context", "capability_admission",
               "catalogue_admission", "scope", "borrowed_image", "observer", "cases",
               "acquisition", "accounting", "cleanup", "coordinates")
OBSERVER_FIELDS = ("pid_namespace", "mount_namespace", "cgroup_namespace", "daemon_pid_namespace",
                   "daemon_depth", "daemon_uid", "cgroup_kind", "outer_process_ceiling")


def fail():
    raise ValueError("invalid private pids limit proof")


def integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        fail()
    return value


def exact_keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        fail()


def validate_coordinates(coordinates, observer):
    exact_keys(observer, OBSERVER_FIELDS)
    for key in ("pid_namespace", "mount_namespace", "cgroup_namespace", "daemon_pid_namespace"):
        integer(observer[key], 1, 2**64 - 1)
    if type(coordinates) is not list or len(coordinates) != 37:
        fail()
    # Fixed positions are context, then six cases, each with baseline/held/
    # restored scan+controller records. No uniqueness or time ordering is implied.
    for witness in coordinates:
        if type(witness) is not list or len(witness) != 6:
            fail()
        shell = integer(witness[0], 1, MAX_PID)
        proc = shell + integer(witness[1], 0, 0)
        chain = witness[2]
        if type(chain) is not list or len(chain) != 1:
            fail()
        nspid = shell + integer(chain[0], 0, 0)
        if not (1 <= proc <= MAX_PID and proc == nspid == shell):
            fail()
        for delta, key in zip(witness[3:], ("pid_namespace", "mount_namespace", "cgroup_namespace")):
            namespace = observer[key] + integer(delta, 0, 0)
            if namespace != observer[key]:
                fail()


def validate_pids_limit_v2_proof(proof, expected_context, outer_context=None, budget=None):
    """Validate original v2 shape/size, then every unchanged v1 semantic predicate."""
    try:
        if outer_context is not None:
            from native_outer_coordinator import derive_consumer_authority
            boundary = derive_consumer_authority(outer_context, expected_context, budget=budget)
            if type(proof) is not dict or proof.get("boundary") != boundary:
                fail()
            if type(proof.get("observer")) is not dict or any(
                    proof["observer"].get(key) != boundary[2][position]
                    for position, key in enumerate(("pid_namespace", "mount_namespace", "cgroup_namespace"))):
                fail()
            if proof["observer"].get("cgroup_kind") != "v2" or type(proof.get("cases")) is not list:
                fail()
            for case in proof["cases"]:
                for key in ("pids_mapping", "memory_mapping"):
                    mapping = case.get(key) if type(case) is dict else None
                    if (type(mapping) is not dict or mapping.get("device") != boundary[4][0]
                            or mapping.get("mount_id") != boundary[3][0] or mapping.get("root") != "/"
                            or mapping.get("mountpoint") != "/sys/fs/cgroup"
                            or mapping.get("outer_membership") != "/" or mapping.get("outer_path") != "/sys/fs/cgroup"):
                        fail()
            if len(json.dumps(proof, separators=(",", ":"), ensure_ascii=False,
                              allow_nan=False).encode("utf-8")) > PROOF_BYTES:
                fail()
            proof = {key: value for key, value in proof.items() if key != "boundary"}
        if len(json.dumps(proof, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")) > SERIALIZED_BYTES:
            fail()
        exact_keys(proof, ROOT_FIELDS)
        integer(proof["schema_version"], 2, 2)
        if type(proof["contract"]) is not str or proof["contract"] != CONTRACT:
            fail()
        validate_context(expected_context)
        same(proof["context"], expected_context)
        validate_coordinates(proof["coordinates"], proof["observer"])
        if type(proof["cases"]) is not list or len(proof["cases"]) != 6:
            fail()
        expanded = {key: value for key, value in proof.items() if key != "coordinates"}
        expanded["schema_version"] = 1
        expanded["contract"] = "pids-limit-v1"
        expanded["cases"] = []
        for case in proof["cases"]:
            if type(case) is not dict:
                fail()
            record = dict(case)
            for phase in ("baseline", "held", "restored"):
                packed = case[phase]
                if type(packed) is not list or len(packed) != len(PHASE_FIELDS):
                    fail()
                record[phase] = dict(zip(PHASE_FIELDS, packed))
            expanded["cases"].append(record)
        outcome = validate_pids_limit_proof(expanded, expected_context)
        exact_keys(outcome, ("contract", "capability_admission", "catalogue_admission", "scope"))
        if (type(outcome["contract"]) is not str or outcome["contract"] != "pids-limit-v1"
                or type(outcome["capability_admission"]) is not list or outcome["capability_admission"]
                or type(outcome["catalogue_admission"]) is not bool or outcome["catalogue_admission"]
                or type(outcome["scope"]) is not str or outcome["scope"] != SCOPE):
            fail()
        return {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False, "scope": SCOPE}
    except (KeyError, IndexError, TypeError, ValueError, OverflowError, RecursionError):
        fail()


def read_pids_limit_v2_proof(proof_path, capture_dir, expected_context, outer_context=None, budget=None):
    try:
        if budget is not None:
            budget.debit(source_bytes=PROOF_BYTES + 1, io_calls=64)
        return read_private_proof(proof_path, capture_dir, FILENAME, expected_context,
                                  lambda value, expected: validate_pids_limit_v2_proof(value, expected, outer_context, budget),
                                  max_bytes=PROOF_BYTES)
    except (OSError, KeyError, IndexError, TypeError, ValueError, OverflowError, RecursionError):
        fail()


def main(arguments):
    from native_outer_coordinator import metered_source_reads, read_consumer_input
    outer_context, budget = read_consumer_input(sys.stdin.buffer, "reader")
    if str(outer_context["pids"]["deadline_epoch"]) != os.environ.get("NATIVE_PIDS_LIMIT_DEADLINE_EPOCH"):
        fail()
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
    with metered_source_reads(budget):
        read_pids_limit_v2_proof(Path(directory) / FILENAME, directory, context, outer_context)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError):
        raise SystemExit("invalid private pids limit proof") from None
