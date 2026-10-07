"""Private health-metadata-v1 completion protocol, not catalogue admission."""

import datetime
import json
import os
import re
import stat
from pathlib import Path


CONTRACT = "health-metadata-v1"
SHAPES = ("ContainerCreateLabels", "ShellHealthcheck",
          "HealthStartPeriodPositive", "HealthStartPeriodZero")
CASES = ("grace_positive", "period_zero", "inherited_failure", "disabled")
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
LIMIT = 16384
SECOND = 1_000_000_000


def require(condition):
    if not condition:
        raise ValueError("health metadata proof rejected")


def timestamp_ns(value):
    require(type(value) is str)
    match = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z", value)
    require(match is not None)
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    require(1970 <= year <= 9999 and hour < 24 and minute < 60 and second < 60)
    try:
        days = (datetime.date(year, month, day) - datetime.date(1970, 1, 1)).days
    except ValueError:
        raise ValueError("health metadata proof rejected") from None
    fraction = int((match.group(7) or "").ljust(9, "0"))
    return ((days * 24 + hour) * 3600 + minute * 60 + second) * SECOND + fraction


def attempt(record, started, exit_code, lower):
    require(type(record) is dict and record.keys() == {"start", "end", "exit_code"})
    require(type(record["exit_code"]) is int and record["exit_code"] == exit_code)
    start, end = timestamp_ns(record["start"]), timestamp_ns(record["end"])
    require(start >= started and start >= lower and start < end <= started + 180 * SECOND)
    return start, end


def failed_pair(records, started, lower, upper=None):
    require(type(records) is list and len(records) == 2)
    first = attempt(records[0], started, 1, lower)
    second = attempt(records[1], started, 1, first[1])
    require(first != second)
    if upper is not None:
        require(first[1] < upper and second[1] < upper)
    return second[1]


def validate_health_metadata_proof(proof, lane, engine, api, mode, candidate, run_id, base_image):
    """Return only the four closed shapes, never IDs, labels, paths or health logs.

    The producer is a trusted isolated harness, not an attestation against a
    privileged writer. The caller supplies independently admitted run context.
    Native timestamps remain in this private input only.
    """
    require(lane in LANES and mode == lane.rsplit("-", 1)[1])
    debian = lane.startswith("debian11-")
    require(engine in (("20.10.5", "20.10.5+dfsg1") if debian else ("29.8.1",)))
    require(api == ("1.41" if debian else "1.56"))
    require(type(candidate) is str and re.fullmatch(r"[0-9a-f]{40}", candidate))
    require(type(run_id) is str and re.fullmatch(r"[A-Za-z0-9]{8}", run_id))
    require(type(base_image) is str and re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", base_image))
    require(type(proof) is dict and proof.keys() == {
        "schema_version", "kind", "contract", "candidate_sha", "lane", "engine_release",
        "rendering_api", "acquisition_api", "daemon_mode", "base_image", "base_health_start_period_ns", "debian_package",
        "run_id", "cleanup", "shapes", "cases", "derived_image", "seed_container"})
    require(type(proof["schema_version"]) is int and proof["schema_version"] == 1)
    require(proof["kind"] == "dockerlens-native-health-metadata-proof" and proof["contract"] == CONTRACT)
    for key, expected in (("candidate_sha", candidate), ("lane", lane), ("engine_release", engine),
                          ("rendering_api", api), ("daemon_mode", mode), ("run_id", run_id),
                          ("base_image", base_image), ("cleanup", "absent"),
                          ("acquisition_api", "1.41" if debian else "1.49"),
                          ("debian_package", "20.10.5+dfsg1-1+deb11u2" if debian else None)):
        require(proof[key] == expected)
    require(proof["shapes"] == list(SHAPES))
    require(type(proof["base_health_start_period_ns"]) is int and proof["base_health_start_period_ns"] == 0)
    derived = proof["derived_image"]
    require(type(derived) is dict and derived.keys() == {"id", "tag", "owner", "configured", "cleanup"})
    require(type(derived["id"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", derived["id"]))
    require(derived["tag"] == f"dl-health-{run_id.lower()}:inherited" and derived["owner"] == run_id
            and derived["configured"] == "passed" and derived["cleanup"] == "absent")
    seed = proof["seed_container"]
    require(type(seed) is dict and seed.keys() == {"id", "name", "owner", "image", "cleanup"})
    require(type(seed["id"]) is str and re.fullmatch(r"[0-9a-f]{64}", seed["id"]))
    require(seed["name"] == f"dl-health-{run_id}-seed" and seed["owner"] == run_id
            and seed["image"] == base_image and seed["cleanup"] == "absent")
    ids = {seed["id"]}
    require(type(proof["cases"]) is list and len(proof["cases"]) == 4)
    for name, case in zip(CASES, proof["cases"]):
        require(type(case) is dict and case.keys() == {"case", "wire", "containers"})
        require(case["case"] == name and case["wire"] == "passed")
        require(type(case["containers"]) is list and len(case["containers"]) == 2)
        for role, record in zip(("oracle", "rendered"), case["containers"]):
            require(type(record) is dict and record.keys() == {
                "role", "id", "name", "owner", "image", "labels", "health_config", "running",
                "started_at", "initial_state", "initial_streak", "initial_attempts",
                "recovery_attempt", "recovery", "regression", "regression_attempts",
                "regression_streak", "regression_observed_at", "health_sentinel", "disabled_gap_ns", "cleanup"})
            identifier = record["id"]
            require(type(identifier) is str and re.fullmatch(r"[0-9a-f]{64}", identifier)
                    and identifier not in ids)
            ids.add(identifier)
            require(record["role"] == role and record["name"] == f"dl-health-{run_id}-{name}-{role}"
                    and record["owner"] == run_id and record["cleanup"] == "absent")
            require(record["image"] == (base_image if name in CASES[:2] else derived["id"]))
            require(all(record[key] == "passed" for key in ("labels", "health_config", "running")))
            started = timestamp_ns(record["started_at"])
            require(type(record["initial_streak"]) is int and type(record["regression_streak"]) is int)
            if name == "disabled":
                require(record["initial_state"] == "disabled" and record["initial_streak"] == 0
                        and record["initial_attempts"] == [] and record["health_sentinel"] == "absent")
                require(type(record["disabled_gap_ns"]) is int and
                        2 * SECOND <= record["disabled_gap_ns"] <= 135 * SECOND)
                last_failure = started
            else:
                require(record["health_sentinel"] == "present" and record["disabled_gap_ns"] is None)
                last_failure = failed_pair(record["initial_attempts"], started, started,
                                           started + 20 * SECOND if name == "grace_positive" else None)
                require(record["initial_state"] == ("starting" if name == "grace_positive" else "unhealthy"))
                require(record["initial_streak"] == 0 if name == "grace_positive" else
                        2 <= record["initial_streak"] <= 400)
            if name in CASES[:2]:
                recovery = attempt(record["recovery_attempt"], started, 0, last_failure)
                if name == "grace_positive":
                    require(recovery[1] < started + 20 * SECOND)
                require(record["recovery"] == "healthy" and record["regression"] == "unhealthy"
                        and 2 <= record["regression_streak"] <= 400)
                last_regression = failed_pair(record["regression_attempts"], started, recovery[1],
                                              started + 20 * SECOND if name == "grace_positive" else None)
                observed = timestamp_ns(record["regression_observed_at"])
                require(last_regression <= observed <= started + 180 * SECOND)
                if name == "grace_positive":
                    require(observed < started + 20 * SECOND)
            else:
                require(record["recovery_attempt"] is None and record["recovery"] == "not_applicable"
                        and record["regression"] == "not_applicable" and record["regression_attempts"] == []
                        and record["regression_streak"] == 0 and record["regression_observed_at"] is None)
    return list(SHAPES)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def read_health_metadata_proof(path, capture_dir, lane, engine, api, mode, candidate, run_id, base_image):
    """Read one stable mode-0600 direct child of a held private directory."""
    directory = Path(os.path.abspath(capture_dir))
    path = Path(path)
    require(directory == directory.resolve(strict=True))
    require(path == directory / "health-metadata.json")
    named_directory = os.lstat(directory)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before_directory = os.fstat(directory_fd)
        require(stat.S_ISDIR(before_directory.st_mode) and before_directory.st_uid == os.geteuid()
                and stat.S_IMODE(before_directory.st_mode) == 0o700
                and fingerprint(named_directory) == fingerprint(before_directory))
        descriptor = os.open("health-metadata.json", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                             dir_fd=directory_fd)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                    and 0 < before.st_size <= LIMIT)
            payload = source.read(LIMIT + 1)
            source.seek(0)
            repeated = source.read(LIMIT + 1)
            after = os.fstat(source.fileno())
        require(len(payload) == before.st_size and payload == repeated
                and fingerprint(before) == fingerprint(after)
                and fingerprint(before) == fingerprint(os.stat("health-metadata.json", dir_fd=directory_fd,
                                                               follow_symlinks=False))
                and fingerprint(before_directory) == fingerprint(os.fstat(directory_fd))
                and fingerprint(before_directory) == fingerprint(os.lstat(directory))
                and directory == directory.resolve(strict=True))
    finally:
        os.close(directory_fd)
    proof = json.loads(payload, object_pairs_hook=unique_object,
                       parse_constant=lambda _value: require(False))
    return validate_health_metadata_proof(proof, lane, engine, api, mode, candidate, run_id, base_image)
