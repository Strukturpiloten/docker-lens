"""Closed external-network-internal-v1 proof, not sealed admission or attestation."""

import json
import os
import stat
from pathlib import Path

from native_network_attachment_proof import (
    CONTEXT_KEYS, canonical, fingerprint, keys, validate_context as validate_base_context,
)

CONTRACT = "external-network-internal-v1"
FILENAME = "external-network-internal-v1.json"
LIMIT = 16 * 1024
SHAPES = ("ExternalNetworkInternalFalse", "ExternalNetworkInternalTrue")
CASES = ("ordinary", "internal")
CHECKS = ("independent_cli", "direct_inspect", "fresh_acquisition", "selected_root",
          "schema3_empty_requests", "expected_assessment", "opposite_assessment", "identity_unchanged")


def fail():
    raise ValueError("invalid private external network proof")


def validate_context(context):
    keys(context, {*CONTEXT_KEYS, "daemon_uid"})
    validate_base_context({key: context[key] for key in CONTEXT_KEYS})
    uid = context["daemon_uid"]
    if (type(uid) is not int or not 0 <= uid <= 4294967295
            or (uid != 0) != (context["mode"] == "rootless")):
        fail()


def validate_external_network_proof(proof, expected_context):
    """Both independently created bridge cases, all checks and verified cleanup."""
    try:
        validate_context(expected_context)
        keys(proof, ("schema_version", "contract", "context", "shapes", "networks", "cleanup"))
        if (type(proof["schema_version"]) is not int or proof["schema_version"] != 1
                or proof["contract"] != CONTRACT or proof["context"] != expected_context
                or proof["shapes"] != list(SHAPES)
                or not isinstance(proof["networks"], list) or len(proof["networks"]) != 2):
            fail()
        validate_context(proof["context"])
        keys(proof["cleanup"], ("networks", "rounds", "outstanding", "uncertain"))
        cleanup = proof["cleanup"]
        if (cleanup["networks"] != "absent" or type(cleanup["rounds"]) is not int
                or cleanup["rounds"] != 2 or type(cleanup["outstanding"]) is not int
                or cleanup["outstanding"] != 0 or cleanup["uncertain"] is not False):
            fail()
        native_ids = set()
        run = expected_context["run_id"]
        for internal, case, shape, network in zip((False, True), CASES, SHAPES, proof["networks"]):
            keys(network, ("case", "shape", "id", "name", "owner", "internal", "checks", "cleanup"))
            if (network["case"] != case or network["shape"] != shape
                    or not canonical(network["id"]) or network["id"] in native_ids
                    or network["name"] != f"dl-ext-{run}-{case}" or network["owner"] != run
                    or type(network["internal"]) is not bool or network["internal"] is not internal
                    or network["cleanup"] != "absent"):
                fail()
            native_ids.add(network["id"])  # Same-kind networks only, not outer container IDs.
            keys(network["checks"], CHECKS)
            if any(network["checks"][check] != "passed" for check in CHECKS):
                fail()
        return SHAPES
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def read_external_network_proof(path, capture_dir, expected_context):
    """Stable bounded single-link 0600 direct child, canonical owner-private 0700 parent."""
    directory = Path(os.path.abspath(capture_dir))
    descriptors = []
    try:
        if directory.resolve(strict=True) != directory or Path(path) != directory / FILENAME:
            fail()
        parent = os.lstat(directory)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) != 0o700):
            fail()
        ancestor = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(ancestor)
        held = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ancestor)
        descriptors.append(held)
        if fingerprint(os.fstat(held)) != fingerprint(parent):
            fail()
        source = os.open(FILENAME, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=held)
        descriptors.append(source)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                or not 0 < before.st_size <= LIMIT):
            fail()
        payload = os.read(source, LIMIT + 1)
        if (len(payload) != before.st_size or len(payload) > LIMIT
                or fingerprint(os.fstat(source)) != fingerprint(before)
                or fingerprint(os.stat(FILENAME, dir_fd=held, follow_symlinks=False)) != fingerprint(before)
                or fingerprint(os.stat(directory.name, dir_fd=ancestor, follow_symlinks=False)) != fingerprint(parent)
                or fingerprint(os.lstat(directory)) != fingerprint(parent)
                or directory.resolve(strict=True) != directory):
            fail()
        return validate_external_network_proof(json.loads(payload, object_pairs_hook=unique_object), expected_context)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
