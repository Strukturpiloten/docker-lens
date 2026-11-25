"""Private omitted/zero representation proof; no health effect or admission.

Request provenance is independent of configured readback. In particular, an
absent StartInterval never becomes an observed integer zero. Historical client
refusal is distinct from server rejection and from a successful API request.
"""

from native_external_network_proof import validate_context
from native_network_attachment_proof import canonical, keys, read_private_proof

CONTRACT = "health-start-interval-boundary-v1"
FILENAME = "health-start-interval-boundary-v1.json"
SECOND = 1_000_000_000
# Pinned Debian CLI parser-only observation by the primary, 2026-10-11:
# /tmp/dockerlens114-cli-signature-20261011.py; stdout empty, exact unknown-flag
# stderr, exit125. Genuine four-lane source execution is still required.
LEGACY_CLIENT_EXIT = 125
CASES = ("omitted", "zero")
FIELDS = ("role", "name", "owner", "image", "wire", "request_intent",
          "request_member", "result", "client_exit", "server_status", "id",
          "image_id", "configured", "readback_state", "state", "restart_count",
          "cleanup")
HEALTH = {"Test": ["CMD-SHELL", "exit 1"], "Interval": 8 * SECOND,
          "Timeout": SECOND, "Retries": 3, "StartPeriod": 30 * SECOND}
CREATED = {"Status": "created", "Running": False, "Pid": 0,
           "StartedAt": "0001-01-01T00:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z",
           "OOMKilled": False, "Restarting": False, "Paused": False,
           "Dead": False, "ExitCode": 0, "Error": ""}


def fail():
    raise ValueError("invalid private health start interval boundary proof")


def exact(value, expected):
    """Type-sensitive recursive equality, including nested bool-versus-int."""
    if type(value) is not type(expected):
        fail()
    if type(expected) is dict:
        keys(value, expected)
        for key in expected:
            exact(value[key], expected[key])
    elif type(expected) is list:
        if len(value) != len(expected):
            fail()
        for actual, wanted in zip(value, expected):
            exact(actual, wanted)
    elif value != expected:
        fail()


def classify_start_interval(value):
    """Keep raw states distinct; malformed/missing parent objects refuse.

    This classifier is not a native acceptance policy. The fixed native cohort
    below requires absent readback, even for the explicit-zero request intent.
    """
    try:
        if type(value) is not dict or type(value.get("Config")) is not dict:
            fail()
        health = value["Config"].get("Healthcheck")
        if type(health) is not dict:
            fail()
        if "StartInterval" not in health:
            return "absent"
        interval = health["StartInterval"]
        if interval is None:
            return "null"
        if type(interval) is int and 0 <= interval < 2 ** 64:
            return "present_zero" if interval == 0 else "present_positive"
        return "wrong_type"
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()


def validate_health_start_interval_boundary_proof(proof, expected_context):
    """Return only closed source outcomes after four slots and cleanup checks."""
    try:
        validate_context(expected_context)
        keys(proof, ("schema_version", "contract", "context", "admission", "scope",
                     "apis", "borrowed_image", "budget", "cases", "cleanup"))
        for field, expected in (("schema_version", 1), ("contract", CONTRACT),
                                ("context", expected_context), ("admission", "unadmitted"),
                                ("scope", "created_configuration_only")):
            exact(proof[field], expected)
        validate_context(proof["context"])
        exact(proof["apis"], {"fixture_cli": expected_context["rendering_api"],
                              "renderer": expected_context["rendering_api"],
                              "request": expected_context["rendering_api"],
                              "health_probe": "test_local_unadmitted"})
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        budget = proof["budget"]
        keys(budget, ("limit_seconds", "cleanup_reserve_seconds", "elapsed_ns"))
        exact(budget["limit_seconds"], 180)
        exact(budget["cleanup_reserve_seconds"], 46)
        if type(budget["elapsed_ns"]) is not int or not 0 < budget["elapsed_ns"] <= 180 * SECOND:
            fail()
        exact(proof["cleanup"], {"containers": "absent", "rounds": 2, "ledger_slots": 4,
                                 "outstanding": 0, "uncertain": False})
        cases = proof["cases"]
        if type(cases) is not list or len(cases) != 2:
            fail()
        seen = {expected_context["outer"]["id"]}
        debian = expected_context["lane"].startswith("debian11-")
        for case, name in zip(cases, CASES):
            keys(case, ("case", "records"))
            exact(case["case"], name)
            if type(case["records"]) is not list or len(case["records"]) != 2:
                fail()
            for record, role in zip(case["records"], ("oracle", "rendered")):
                keys(record, FIELDS)
                cli = role == "oracle"
                for field, expected in (("role", role),
                        ("name", f"dl-hsi-{expected_context['run_id']}-{name}-{role}"),
                        ("owner", expected_context["run_id"]), ("image", expected_context["fixture_image"]),
                        ("wire", "independent_cli" if cli else "literal_rendered"),
                        ("request_intent", "omitted" if name == "omitted" else "explicit_zero"),
                        ("request_member", "not_observed" if cli else "absent" if name == "omitted" else "integer_zero"),
                        ("cleanup", "absent")):
                    exact(record[field], expected)
                refused = debian and name == "zero" and cli
                if refused:
                    exact(record["result"], "client_unknown_flag")
                    # The precise legacy exit is independently observed before
                    # source integration; no arbitrary nonzero is accepted.
                    exact(record["client_exit"], LEGACY_CLIENT_EXIT)
                    for field in ("server_status", "id", "image_id", "configured",
                                  "readback_state", "state", "restart_count"):
                        exact(record[field], None)
                    continue
                exact(record["result"], "accepted")
                exact(record["client_exit"], 0 if cli else None)
                exact(record["server_status"], None if cli else 201)
                if not canonical(record["id"]) or record["id"] in seen:
                    fail()
                seen.add(record["id"])
                exact(record["image_id"], image["id"])
                exact(record["readback_state"], classify_start_interval(record["configured"]))
                exact(record["readback_state"], "absent")
                exact(record["configured"], {"Config": {"Healthcheck": HEALTH}})
                exact(record["state"], CREATED)
                exact(record["restart_count"], 0)
        return {"contract": CONTRACT, "admission": "unadmitted",
                "outcomes": ["omission_configured_absent", "literal_zero_configured_absent",
                             "cli_zero_client_unknown_flag" if debian else "cli_zero_configured_absent"]}
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()


def read_health_start_interval_boundary_proof(path, capture_dir, expected_context):
    """Use the stable bounded owner-private direct-child reader without changes."""
    try:
        return read_private_proof(path, capture_dir, FILENAME, expected_context,
                                  validate_health_start_interval_boundary_proof)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()
