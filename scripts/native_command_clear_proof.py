"""Strict private command-clear-v1 source proof; no public projection or admission."""

from native_external_network_proof import validate_context
from native_network_attachment_proof import canonical, keys, read_private_proof

CONTRACT = "command-clear-v1"
FILENAME = "command-clear-v1.json"
SHAPES = ("ClearCommand", "ClearEntrypoint")
CASES = ("image_defaults", "entrypoint_inherit", "command_clear", "entrypoint_clear")
IMAGE_ENTRY = "/dl-image-entrypoint"
EXPLICIT_ENTRY = "/dl-explicit-entrypoint"
COMMAND = "/dl-command-process"
FIELDS = ("role", "id", "name", "owner", "image", "wire", "entrypoint", "command",
          "entrypoint_variant", "command_variant", "path", "args", "process_argv", "marker",
          "state", "running", "restart_count", "cleanup")


def fail():
    raise ValueError("invalid private command clear proof")


def exact(value, expected):
    # Deep exact types: bool is never an integer field or an array member.
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


def image_id(value):
    return type(value) is str and value.startswith("sha256:") and canonical(value[7:])


def vectors(case):
    if case == "image_defaults":
        return [IMAGE_ENTRY], ["image-command"]
    if case in ("entrypoint_inherit", "command_clear"):
        return [EXPLICIT_ENTRY], []
    return [], [COMMAND, "explicit-command"]


def effective(value, variant, expected):
    if expected:
        exact(value, expected)
        exact(variant, "exec")
    elif variant == "null":
        exact(value, None)
    elif variant == "empty_array":
        exact(value, [])
    else:
        fail()


def validate_command_clear_proof(proof, expected_context):
    """Require defaults, entrypoint-only control, both clear effects and owned cleanup."""
    try:
        validate_context(expected_context)
        keys(proof, ("schema_version", "contract", "context", "shapes", "borrowed_image",
                     "derived_image", "seed", "cases", "cleanup"))
        exact(proof["schema_version"], 1)
        exact(proof["contract"], CONTRACT)
        exact(proof["context"], expected_context)
        validate_context(proof["context"])
        exact(proof["shapes"], list(SHAPES))
        borrowed = proof["borrowed_image"]
        keys(borrowed, ("id", "identity", "removal"))
        if not image_id(borrowed["id"]):
            fail()
        exact(borrowed["identity"], "unchanged")
        exact(borrowed["removal"], "not_owned")
        run = expected_context["run_id"]
        derived = proof["derived_image"]
        keys(derived, ("id", "tag", "owner", "entrypoint", "command", "cleanup"))
        if not image_id(derived["id"]) or derived["id"] == borrowed["id"]:
            fail()
        for field, value in (("tag", f"dl-command-clear-{run.lower()}:fixture"), ("owner", run),
                             ("entrypoint", [IMAGE_ENTRY]), ("command", ["image-command"]),
                             ("cleanup", "absent")):
            exact(derived[field], value)
        seed = proof["seed"]
        keys(seed, ("id", "name", "owner", "image", "exit_code", "cleanup"))
        if not canonical(seed["id"]) or seed["id"] == expected_context["outer"]["id"]:
            fail()
        for field, value in (("name", f"dl-command-{run}-seed"), ("owner", run),
                             ("image", expected_context["fixture_image"]), ("exit_code", 0),
                             ("cleanup", "absent")):
            exact(seed[field], value)
        exact(proof["cleanup"], {"containers": "absent", "images": "absent", "rounds": 2,
                                 "outstanding": 0, "uncertain": False})
        seen = {seed["id"], expected_context["outer"]["id"]}
        if type(proof["cases"]) is not list or len(proof["cases"]) != len(CASES):
            fail()
        for case, name in zip(proof["cases"], CASES):
            keys(case, ("case", "containers"))
            exact(case["case"], name)
            if type(case["containers"]) is not list or len(case["containers"]) != 2:
                fail()
            entrypoint, command = vectors(name)
            argv = entrypoint + command
            for record, role in zip(case["containers"], ("oracle", "rendered")):
                keys(record, FIELDS)
                if not canonical(record["id"]) or record["id"] in seen:
                    fail()
                seen.add(record["id"])
                effective(record["entrypoint"], record["entrypoint_variant"], entrypoint)
                effective(record["command"], record["command_variant"], command)
                for field, value in (("role", role), ("name", f"dl-command-{run}-{name}-{role}"),
                                     ("owner", run), ("image", derived["id"]), ("wire", "passed"),
                                     ("path", argv[0]), ("args", argv[1:]),
                                     ("process_argv", ["/bin/sh"] + argv),
                                     ("marker", "\n".join(argv) + "\n"), ("state", "running"),
                                     ("running", True), ("restart_count", 0), ("cleanup", "absent")):
                    exact(record[field], value)
        return SHAPES
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()


def read_command_clear_proof(path, capture_dir, expected_context):
    try:
        return read_private_proof(path, capture_dir, FILENAME, expected_context, validate_command_clear_proof)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()
