"""Private lifecycle-v1 observations; never capability admission or attestation."""

from native_external_network_proof import validate_context
from native_health_metadata_proof import timestamp_ns
from native_network_attachment_proof import canonical, keys, read_private_proof

CONTRACT = "lifecycle-v1"
FILENAME = "lifecycle-v1.json"
SECOND = 1_000_000_000
COMMON = frozenset(("role", "id", "name", "owner", "image", "image_id", "wire", "cleanup"))
STOP_FIELDS = COMMON | frozenset((
    "configured_seconds", "readiness", "term_marker", "running_before_stop", "started_at",
    "ready_observed_at", "stop_requested_at", "finished_at", "stopped_observed_at",
    "timeout_override", "signal_override", "stop_elapsed_ns", "exit_code", "state", "running",
    "pid", "oom_killed", "restarting", "restart_count", "paused", "dead", "state_error_empty",
    "ready_clock", "request_clock", "observed_clock"))
HEALTH_FIELDS = COMMON | frozenset((
    "start_interval_request", "start_interval_readback_ns", "request_accepted", "started_at", "early", "late"))
STOP_CASES = ((1, 137, 800_000_000, 2_500_000_000), (5, 41, 2_800_000_000, 5_500_000_000))


def fail():
    raise ValueError("invalid private lifecycle proof")


def exact(value, expected):
    if type(value) is not type(expected) or value != expected:
        fail()


def integer(value, lower, upper):
    if type(value) is not int or not lower <= value < upper:
        fail()
    return value


def clock_sample(value, native):
    """Caller UTC brackets and monotonic RTT bound clock disagreement explicitly."""
    if type(value) is not list or len(value) != 3:
        fail()
    before, after, elapsed = (integer(item, 0, 2 ** 64) for item in value)
    if not (before <= after <= before + 500_000_000 and elapsed <= 500_000_000
            and abs(after - before - elapsed) <= 50_000_000
            and before - 250_000_000 <= native <= after + 250_000_000):
        fail()


def owned(record, role, suffix, context, image_id, seen):
    if not canonical(record["id"]) or record["id"] in seen:
        fail()
    seen.add(record["id"])
    for key, value in (("role", role), ("name", f"dl-life-{context['run_id']}-{suffix}"),
                       ("owner", context["run_id"]), ("image", context["fixture_image"]),
                       ("image_id", image_id), ("cleanup", "absent"),
                       ("wire", "independent_cli" if role == "oracle" else "literal_rendered")):
        exact(record[key], value)


def snapshot(value, started, early):
    keys(value, ("before", "after", "before_clock", "after_clock", "status", "failing_streak", "running", "restart_count", "attempts"))
    for key, expected in (("status", "starting"), ("failing_streak", 0), ("running", True), ("restart_count", 0)):
        exact(value[key], expected)
    before, after = (timestamp_ns(value[key]) for key in ("before", "after"))
    clock_sample(value["before_clock"], before)
    clock_sample(value["after_clock"], after)
    lower, upper = (3_300_000_000, 4 * SECOND) if early else (9 * SECOND, 12 * SECOND)
    if not started + lower <= before <= after < started + upper:
        fail()
    attempts = value["attempts"]
    if type(attempts) is not list or len(attempts) > 5:
        fail()
    previous = started
    for attempt in attempts:
        keys(attempt, ("start", "end", "exit_code", "marker"))
        exact(attempt["exit_code"], 1)
        exact(attempt["marker"], "lifecycle-health-failure")
        start, end = (timestamp_ns(attempt[key]) for key in ("start", "end"))
        if not previous <= start < end <= after or end - start >= SECOND:
            fail()
        previous = end
    return before, after


def validate_lifecycle_proof(proof, expected_context):
    """Return only two closed outcomes after all six owned fixtures are verified."""
    try:
        validate_context(expected_context)
        keys(proof, ("schema_version", "contract", "context", "apis", "borrowed_image", "stop_timeout",
                     "health_start_interval", "cleanup"))
        exact(proof["schema_version"], 1)
        exact(proof["contract"], CONTRACT)
        exact(proof["context"], expected_context)
        validate_context(proof["context"])
        keys(proof["apis"], ("fixture_cli", "stop_renderer", "health_renderer", "request", "health_probe"))
        for key in ("fixture_cli", "stop_renderer", "health_renderer", "request"):
            exact(proof["apis"][key], expected_context["rendering_api"])
        exact(proof["apis"]["health_probe"], "test_local_unadmitted")
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        keys(proof["cleanup"], ("containers", "rounds", "outstanding", "uncertain"))
        for key, value in (("containers", "absent"), ("rounds", 2), ("outstanding", 0), ("uncertain", False)):
            exact(proof["cleanup"][key], value)
        seen = {expected_context["outer"]["id"]}
        cases = proof["stop_timeout"]
        if type(cases) is not list or len(cases) != 2:
            fail()
        for case, (seconds, exit_code, lower, upper) in zip(cases, STOP_CASES):
            keys(case, ("configured_seconds", "expected_exit_code", "containers"))
            exact(case["configured_seconds"], seconds)
            exact(case["expected_exit_code"], exit_code)
            if type(case["containers"]) is not list or len(case["containers"]) != 2:
                fail()
            for record, role in zip(case["containers"], ("oracle", "rendered")):
                keys(record, STOP_FIELDS)
                owned(record, role, f"timeout-{seconds}-{role}", expected_context, image["id"], seen)
                for key, value in (("configured_seconds", seconds), ("readiness", "pid1-term-ready"),
                                   ("term_marker", True), ("running_before_stop", True), ("timeout_override", False),
                                   ("signal_override", False), ("exit_code", exit_code), ("state", "exited"),
                                   ("running", False), ("pid", 0), ("oom_killed", False), ("restarting", False),
                                   ("restart_count", 0), ("paused", False), ("dead", False), ("state_error_empty", True)):
                    exact(record[key], value)
                elapsed = integer(record["stop_elapsed_ns"], lower, upper)
                started, ready, requested, finished, observed = (
                    timestamp_ns(record[key]) for key in ("started_at", "ready_observed_at", "stop_requested_at",
                                                          "finished_at", "stopped_observed_at"))
                for field, native in (("ready_clock", ready), ("request_clock", requested), ("observed_clock", observed)):
                    clock_sample(record[field], native)
                if not (started <= ready <= requested < finished <= observed <= started + 180 * SECOND
                        and lower <= finished - requested < upper
                        and abs(elapsed - (finished - requested)) <= 500_000_000):
                    fail()
        health = proof["health_start_interval"]
        keys(health, ("outcome", "interval_ns", "start_period_ns", "start_interval_ns", "timeout_ns", "retries", "containers"))
        for key, value in (("interval_ns", 8 * SECOND), ("start_period_ns", 30 * SECOND),
                           ("start_interval_ns", SECOND), ("timeout_ns", SECOND), ("retries", 3)):
            exact(health[key], value)
        outcome = health["outcome"]
        if outcome not in ("effective", "not_effective_on_selected_api"):
            fail()
        if outcome != "effective" and not expected_context["lane"].startswith("debian11-"):
            fail()
        if type(health["containers"]) is not list or len(health["containers"]) != 2:
            fail()
        for record, role, suffix in zip(health["containers"], ("oracle", "rendered"), ("health-control", "health-candidate")):
            keys(record, HEALTH_FIELDS)
            owned(record, role, suffix, expected_context, image["id"], seen)
            exact(record["request_accepted"], True)
            candidate = role == "rendered"
            exact(record["start_interval_request"], SECOND if candidate else "omitted")
            exact(record["start_interval_readback_ns"], SECOND if candidate and outcome == "effective" else 0)
            started = timestamp_ns(record["started_at"])
            _, early_after = snapshot(record["early"], started, True)
            snapshot(record["late"], started, False)
            count = len(record["early"]["attempts"])
            if (candidate and outcome == "effective" and count < 3) or (not (candidate and outcome == "effective") and count != 0):
                fail()
            if not any(timestamp_ns(attempt["start"]) >= early_after for attempt in record["late"]["attempts"]):
                fail()
        return ("stop_timeout_effective", "health_start_interval_" + outcome)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError("invalid private lifecycle proof") from None


def read_lifecycle_proof(path, capture_dir, expected_context):
    try:
        return read_private_proof(path, capture_dir, FILENAME, expected_context, validate_lifecycle_proof)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError("invalid private lifecycle proof") from None
