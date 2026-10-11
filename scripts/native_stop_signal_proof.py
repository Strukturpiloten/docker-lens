"""Private stop-signal-v1 effect proof, never catalogue admission or attestation."""

from native_external_network_proof import validate_context
from native_health_metadata_proof import timestamp_ns
from native_network_attachment_proof import canonical, keys, read_private_proof

CONTRACT = "stop-signal-v1"
FILENAME = "stop-signal-v1.json"
SHAPES = ("StopSignal",)
CASES = (("SIGTERM", "term", 41), ("SIGINT", "int", 42))
SECOND = 1_000_000_000
FIELDS = frozenset(("role", "id", "name", "owner", "image", "image_id", "configured_signal", "wire",
                    "readiness", "running_before_stop", "started_at", "ready_observed_at", "stop_requested_at",
                    "finished_at", "stopped_observed_at", "stop_timeout_seconds", "signal_override", "stop_elapsed_ns",
                    "exit_code", "state", "running", "pid", "oom_killed", "restarting", "restart_count", "cleanup"))


def fail():
    raise ValueError("invalid private stop signal proof")


def exact(value, expected):
    if type(value) is not type(expected) or value != expected:
        fail()


def validate_stop_signal_proof(proof, expected_context):
    """Require both configured spellings and their distinct actual trap exits."""
    try:
        validate_context(expected_context)
        keys(proof, ("schema_version", "contract", "context", "shapes", "borrowed_image", "cases", "cleanup"))
        exact(proof["schema_version"], 1)
        exact(proof["contract"], CONTRACT)
        exact(proof["context"], expected_context)
        validate_context(proof["context"])
        exact(proof["shapes"], list(SHAPES))
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        cleanup = proof["cleanup"]
        keys(cleanup, ("containers", "rounds", "outstanding", "uncertain"))
        for key, value in (("containers", "absent"), ("rounds", 2), ("outstanding", 0), ("uncertain", False)):
            exact(cleanup[key], value)
        if type(proof["cases"]) is not list or len(proof["cases"]) != 2:
            fail()
        seen = set()
        for case, (signal, name, expected_exit) in zip(proof["cases"], CASES):
            keys(case, ("signal", "expected_exit_code", "containers"))
            exact(case["signal"], signal)
            exact(case["expected_exit_code"], expected_exit)
            if type(case["containers"]) is not list or len(case["containers"]) != 2:
                fail()
            for record, role in zip(case["containers"], ("oracle", "rendered")):
                keys(record, FIELDS)
                if not canonical(record["id"]) or record["id"] in seen:
                    fail()
                seen.add(record["id"])
                for key, value in (("role", role), ("name", f"dl-stop-{expected_context['run_id']}-{name}-{role}"),
                                   ("owner", expected_context["run_id"]), ("image", expected_context["fixture_image"]),
                                   ("image_id", image["id"]), ("configured_signal", signal), ("wire", "passed"),
                                   ("readiness", "pid1-traps-ready"), ("running_before_stop", True),
                                   ("stop_timeout_seconds", 3), ("signal_override", False), ("exit_code", expected_exit),
                                   ("state", "exited"), ("running", False), ("pid", 0), ("oom_killed", False),
                                   ("restarting", False), ("restart_count", 0), ("cleanup", "absent")):
                    exact(record[key], value)
                elapsed = record["stop_elapsed_ns"]
                if type(elapsed) is not int or not 0 < elapsed < 5 * SECOND:
                    fail()
                started, ready, requested, finished, observed = (
                    timestamp_ns(record[key]) for key in ("started_at", "ready_observed_at", "stop_requested_at",
                                                          "finished_at", "stopped_observed_at"))
                if not (started <= ready <= requested < finished <= observed <= started + 180 * SECOND
                        and finished - requested < 5 * SECOND):
                    fail()
        return SHAPES
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError("invalid private stop signal proof") from None


def read_stop_signal_proof(path, capture_dir, expected_context):
    try:
        return read_private_proof(path, capture_dir, FILENAME, expected_context, validate_stop_signal_proof)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError("invalid private stop signal proof") from None
