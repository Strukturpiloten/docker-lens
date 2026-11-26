"""Strict private hostname source proof; no raw or catalogue admission."""

import re
import sys
from pathlib import Path

from native_external_network_proof import validate_context
from native_health_metadata_proof import timestamp_ns
from native_network_attachment_proof import canonical, keys, read_private_proof

# Semantic/public projection is deliberately independent of private versioning.
CONTRACT = "hostname-v1"
PRIVATE_SCHEMA_VERSION = 2
FILENAME = "hostname-v2.json"
RESOLVER_CONTRACT = "resolver-files-v1"
ERROR = "invalid private hostname proof"
CASES = ("omitted", "explicit")
FIELDS = ("role", "id", "name", "owner", "image", "image_id", "wire", "cli_api",
          "request_hostname", "configured_hostname", "process_hostname", "started_at",
          "running_before", "running_after", "restart_count", "cleanup")


RESOLVER_FIELDS = ("role", "id", "name", "owner", "image", "image_id", "wire", "cli_api",
                   "configured_dns", "configured_extra_hosts", "nameservers", "host_matches",
                   "started_at", "running_before", "running_after", "restart_count", "cleanup")
RESOLVER_CASES = (
    ("ipv4", "192.0.2.53", "fixture-v4.local", "192.0.2.10"),
    ("ipv6", "2001:4860:4860::8888", "fixture-v6.local", "2001:db8::10"),
)


def fail():
    raise ValueError(ERROR)


def exact(value, expected):
    if type(value) is not type(expected) or value != expected:
        fail()


def validate_resolver(section, context, image, seen):
    """Finite observed records with independently authored expected values."""
    keys(section, ("contract", "cases"))
    exact(section["contract"], RESOLVER_CONTRACT)
    if type(section["cases"]) is not list or len(section["cases"]) != 2:
        fail()
    for case, (family, dns, host, address) in zip(section["cases"], RESOLVER_CASES):
        keys(case, ("case", "containers"))
        exact(case["case"], family)
        if type(case["containers"]) is not list or len(case["containers"]) != 2:
            fail()
        for record, role in zip(case["containers"], ("oracle", "rendered")):
            keys(record, RESOLVER_FIELDS)
            if not canonical(record["id"]) or record["id"] in seen:
                fail()
            seen.add(record["id"])
            for key, value in (
                ("role", role), ("name", f'dl-resolver-{context["run_id"]}-{family}-{role}'),
                ("owner", context["run_id"]), ("image", context["fixture_image"]),
                ("image_id", image["id"]),
                ("wire", "independent_cli" if role == "oracle" else "literal_rendered"),
                ("cli_api", context["rendering_api"]),
                ("configured_dns", [dns]), ("configured_extra_hosts", [f"{host}:{address}"]),
                ("nameservers", [dns]), ("host_matches", [{"address": address, "names": [host]}]),
                ("running_before", True), ("running_after", True),
                ("restart_count", 0), ("cleanup", "absent"),
            ):
                exact(record[key], value)
            if timestamp_ns(record["started_at"]) <= 0:
                fail()


def validate_hostname_proof(proof, expected_context):
    """Bind independently supplied harness facts and all eight finite fixtures.

    The omitted request retains no authored hostname. Its generated short-ID
    hostname is checked as a daemon default, never portable configured intent.
    """
    try:
        validate_context(expected_context)
        keys(proof, ("schema_version", "contract", "context", "capability_admission",
                     "catalogue_admission", "borrowed_image", "cases", "resolver", "cleanup"))
        for key, value in (("schema_version", PRIVATE_SCHEMA_VERSION), ("contract", CONTRACT),
                           ("context", expected_context), ("capability_admission", []),
                           ("catalogue_admission", False)):
            exact(proof[key], value)
        validate_context(proof["context"])
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        keys(proof["cleanup"], ("containers", "rounds", "outstanding", "uncertain"))
        for key, value in (("containers", "absent"), ("rounds", 2),
                           ("outstanding", 0), ("uncertain", False)):
            exact(proof["cleanup"][key], value)
        if type(proof["cases"]) is not list or len(proof["cases"]) != 2:
            fail()
        seen = {expected_context["outer"]["id"]}
        for case, name in zip(proof["cases"], CASES):
            keys(case, ("case", "authored_hostname", "containers"))
            exact(case["case"], name)
            authored = None if name == "omitted" else f'dl-hostname-{expected_context["run_id"]}'
            exact(case["authored_hostname"], authored)
            if type(case["containers"]) is not list or len(case["containers"]) != 2:
                fail()
            for record, role in zip(case["containers"], ("oracle", "rendered")):
                keys(record, FIELDS)
                if not canonical(record["id"]) or record["id"] in seen:
                    fail()
                seen.add(record["id"])
                expected = record["id"][:12] if authored is None else authored
                for key, value in (
                    ("role", role), ("name", f'dl-host-{expected_context["run_id"]}-{name}-{role}'),
                    ("owner", expected_context["run_id"]), ("image", expected_context["fixture_image"]),
                    ("image_id", image["id"]),
                    ("wire", "independent_cli" if role == "oracle" else "literal_rendered"),
                    ("cli_api", expected_context["rendering_api"]),
                    ("request_hostname", "omitted" if authored is None else authored),
                    ("configured_hostname", expected), ("process_hostname", expected),
                    ("running_before", True), ("running_after", True),
                    ("restart_count", 0), ("cleanup", "absent"),
                ):
                    exact(record[key], value)
                if timestamp_ns(record["started_at"]) <= 0:
                    fail()
        validate_resolver(proof["resolver"], expected_context, image, seen)
        return {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, AttributeError):
        raise ValueError(ERROR) from None


def read_hostname_proof(path, capture_dir, expected_context):
    try:
        return read_private_proof(path, capture_dir, FILENAME, expected_context, validate_hostname_proof)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, AttributeError):
        raise ValueError(ERROR) from None


def main(arguments):
    # All facts come from canonical harness variables, never proof self-context.
    if len(arguments) != 12:
        fail()
    (directory, candidate, run, lane, engine, api, mode, package,
     fixture, outer_image, outer_id, uid) = arguments
    if re.fullmatch(r"0|[1-9][0-9]{0,9}", uid) is None:
        fail()
    context = {
        "candidate_sha": candidate, "run_id": run, "lane": lane,
        "engine_release": engine, "rendering_api": api,
        "acquisition_api": "1.41" if lane.startswith("debian11-") else "1.49",
        "mode": mode, "docker_package": package, "fixture_image": fixture,
        "daemon_uid": int(uid), "outer": {
            "id": outer_id, "name": f"dl-native-{run}", "owner": run,
            "image": outer_image, "data_volume": f"dl-native-data-{run}",
            "socket_source": str(Path(directory) / "socket"), "privileged": True,
            "memory_bytes": 4294967296, "cpu_quota": 200000,
            "cpu_period": 100000, "pids_limit": 512,
        },
    }
    read_hostname_proof(Path(directory) / FILENAME, Path(directory), context)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, AttributeError):
        raise SystemExit("native hostname proof rejected") from None
