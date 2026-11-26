"""Closed private default/zero effects; never compatibility admission."""

from native_external_network_proof import validate_context
from native_health_metadata_proof import timestamp_ns
from native_network_attachment_proof import canonical, keys, read_private_proof

CONTRACT = "lifecycle-default-effects-v1"
FILENAME = "lifecycle-default-effects-v1.json"
ERROR = "invalid private lifecycle default effect proof"
SECOND = 1_000_000_000
COMMON = frozenset(("role", "id", "name", "owner", "image", "image_id", "wire", "cleanup"))
STOP_FIELDS = COMMON | frozenset((
    "timeout_request", "raw_timeout", "readiness", "term_log", "running_before_stop", "started_at",
    "ready_observed_at", "stop_requested_at", "finished_at", "stopped_observed_at", "ready_clock",
    "request_clock", "observed_clock", "timeout_override", "signal_override", "stop_elapsed_ns",
    "exit_code", "state", "running", "pid", "oom_killed", "restarting", "restart_count", "paused",
    "dead", "state_error_empty"))
HEALTH_FIELDS = COMMON | frozenset((
    "start_interval_request", "raw_start_interval", "request_accepted", "started_at", "early", "late"))


def fail():
    raise ValueError(ERROR)


def exact(value, expected):
    if type(value) is not type(expected) or value != expected:
        fail()


def integer(value, lower, upper):
    if type(value) is not int or not lower <= value < upper:
        fail()
    return value


def clock_sample(value, native):
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
    for key, value in (("role", role), ("name", f"dl-def-{context['run_id']}-{suffix}"),
                       ("owner", context["run_id"]), ("image", context["fixture_image"]),
                       ("image_id", image_id), ("cleanup", "absent"),
                       ("wire", "independent_cli" if role == "oracle" else "literal_rendered")):
        exact(record[key], value)


def snapshot(value, started, raw, early, debian):
    keys(value, ("before", "after", "before_clock", "after_clock", "raw_start_interval", "status",
                 "failing_streak", "running", "restart_count", "attempts"))
    for key, expected in (("raw_start_interval", raw), ("status", "starting"), ("failing_streak", 0),
                          ("running", True), ("restart_count", 0)):
        exact(value[key], expected)
    before, after = (timestamp_ns(value[key]) for key in ("before", "after"))
    lower, upper = (6_000_000_000, 7_200_000_000) if early else (11_200_000_000, 13_000_000_000)
    if not started + lower <= before <= after < started + upper:
        fail()
    clock_sample(value["before_clock"], before)
    clock_sample(value["after_clock"], after)
    ages = (() if early else (8,)) if debian else ((5,) if early else (5, 10))
    observations = value["attempts"]
    if type(observations) is not list or len(observations) != len(ages):
        fail()
    previous = started
    for attempt, age in zip(observations, ages):
        keys(attempt, ("start", "end", "exit_code", "marker"))
        exact(attempt["exit_code"], 1)
        exact(attempt["marker"], "lifecycle-health-failure")
        start, end = (timestamp_ns(attempt[key]) for key in ("start", "end"))
        if not (previous <= start < end <= after and end - start < SECOND
                and started + age * SECOND <= start < started + age * SECOND + 1_200_000_000):
            fail()
        previous = end
    return after


def validate_lifecycle_default_effect_proof(proof, expected_context):
    """Verify all six actual fixtures and independent exact-lane expectations."""
    try:
        validate_context(expected_context)
        keys(proof, ("schema_version", "contract", "context", "apis", "borrowed_image", "legacy_zero_cli",
                     "stop_timeout", "health_start_interval", "cleanup", "accounting"))
        exact(proof["schema_version"], 1)
        exact(proof["contract"], CONTRACT)
        exact(proof["context"], expected_context)
        validate_context(proof["context"])
        debian = expected_context["lane"].startswith("debian11-")
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
        accounting = proof["accounting"]
        keys(accounting, ("ordinary_calls", "cleanup_calls", "ordinary_bytes", "cleanup_bytes", "deadline_seconds", "renewed"))
        integer(accounting["ordinary_calls"], 1, 301)
        # Complete six-slot cleanup requires 54 calls, plus two distinct
        # legacy-refusal-name absence reads. Never invent cleanup from a flag.
        exact(accounting["cleanup_calls"], 56 if debian else 54)
        integer(accounting["ordinary_bytes"], 1, 2 * 1024 * 1024 + 1)
        integer(accounting["cleanup_bytes"], 1, 2 * 1024 * 1024 + 1)
        exact(accounting["deadline_seconds"], 180)
        exact(accounting["renewed"], False)
        refusal = proof["legacy_zero_cli"]
        keys(refusal, ("name", "outcome", "exit_code", "stdout_empty", "stderr_signature", "absence_reads", "started"))
        for key, value in (("name", f"dl-def-{expected_context['run_id']}-zero-cli-refusal"),
                           ("outcome", "unknown_flag" if debian else "not_applicable"),
                           ("exit_code", 125 if debian else None), ("stdout_empty", True),
                           ("stderr_signature", "unknown_health_start_interval" if debian else "not_applicable"),
                           ("absence_reads", 2 if debian else 0), ("started", False)):
            exact(refusal[key], value)
        seen = {expected_context["outer"]["id"]}
        stops = proof["stop_timeout"]
        if type(stops) is not list or len(stops) != 4:
            fail()
        for index, record in enumerate(stops):
            keys(record, STOP_FIELDS)
            omitted = index < 2
            role = "oracle" if index % 2 == 0 else "rendered"
            case = "omitted" if omitted else "zero"
            owned(record, role, f"timeout-{case}-{role}", expected_context, image["id"], seen)
            for key, value in (("timeout_request", "omitted" if omitted else 0),
                               ("raw_timeout", "absent" if omitted else "present_zero"),
                               ("readiness", "pid1-term-ready"), ("running_before_stop", True),
                               ("timeout_override", False), ("signal_override", False),
                               ("exit_code", 41 if omitted else 137), ("state", "exited"),
                               ("running", False), ("pid", 0), ("oom_killed", False),
                               ("restarting", False), ("restart_count", 0), ("paused", False),
                               ("dead", False), ("state_error_empty", True)):
                exact(record[key], value)
            if type(record["term_log"]) is not str or record["term_log"] not in (
                    ("single_term",) if omitted else ("empty", "single_term")):
                fail()
            lower, upper = (2_800_000_000, 5_500_000_000) if omitted else (0, 800_000_000)
            elapsed = integer(record["stop_elapsed_ns"], lower, upper)
            started, ready, requested, finished, observed = (
                timestamp_ns(record[key]) for key in ("started_at", "ready_observed_at", "stop_requested_at",
                                                      "finished_at", "stopped_observed_at"))
            for field, native in (("ready_clock", ready), ("request_clock", requested), ("observed_clock", observed)):
                clock_sample(record[field], native)
            if not (started <= ready <= requested <= finished <= observed <= started + 180 * SECOND
                    and lower <= finished - requested < upper
                    and abs(elapsed - (finished - requested)) <= 500_000_000):
                fail()
        health = proof["health_start_interval"]
        keys(health, ("outcome", "source_scope", "interval_ns", "start_period_ns", "start_interval_request", "timeout_ns", "retries", "containers"))
        outcome = "unsupported_legacy_field" if debian else "default_equivalent"
        scope = "accepted_unknown_member_legacy_schedule_only" if debian else "supported_field_zero_default_schedule"
        for key, value in (("outcome", outcome), ("source_scope", scope), ("interval_ns", 8 * SECOND),
                           ("start_period_ns", 30 * SECOND), ("start_interval_request", 0),
                           ("timeout_ns", SECOND), ("retries", 3)):
            exact(health[key], value)
        records = health["containers"]
        if type(records) is not list or len(records) != 2:
            fail()
        for record, role, suffix in zip(records, ("oracle", "rendered"), ("health-control", "health-candidate")):
            keys(record, HEALTH_FIELDS)
            owned(record, role, suffix, expected_context, image["id"], seen)
            exact(record["start_interval_request"], "omitted" if role == "oracle" else 0)
            exact(record["request_accepted"], True)
            raw = record["raw_start_interval"]
            if type(raw) is not str or raw not in ("absent", "present_zero"):
                fail()
            if debian:
                exact(raw, "absent")
            started = timestamp_ns(record["started_at"])
            early_after = snapshot(record["early"], started, raw, True, debian)
            snapshot(record["late"], started, raw, False, debian)
            early, late = record["early"]["attempts"], record["late"]["attempts"]
            if late[:len(early)] != early or not any(timestamp_ns(attempt["start"]) >= early_after for attempt in late):
                fail()
        return ("stop_timeout_omitted_graceful_zero_forced", "health_start_interval_" + outcome)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, AttributeError):
        raise ValueError(ERROR) from None


def read_lifecycle_default_effect_proof(path, capture_dir, expected_context):
    try:
        return read_private_proof(path, capture_dir, FILENAME, expected_context, validate_lifecycle_default_effect_proof)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, AttributeError):
        raise ValueError(ERROR) from None
