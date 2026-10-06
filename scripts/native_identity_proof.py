"""Closed v2 identity semantics. No values or resource identifiers are emitted."""

import re


CONTRACT = "container-identity-v1"
CASES = (
    "inherit", "numeric_uid_gid", "numeric_uid", "named_user",
    "named_user_group", "named_user_numeric_group", "numeric_user_named_group",
    "missing_user", "missing_group", "nondirectory_workdir",
)
OUTCOMES = ("exited_zero",) * 7 + (
    "missing_user", "missing_group", "workdir_not_directory",
)


def validate_identity_v2(proof, lane, mode, api, candidate, run_id, probes):
    """Validate a complete twenty-record proof; caller verifies private-file provenance.

    This checks trusted-harness completion, not attestation against a privileged
    writer. A valid proof can extend raw evidence only, never the sealed catalogue.
    """
    if (lane not in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
            or mode != lane.rsplit("-", 1)[1]
            or api != ("1.41" if lane.startswith("debian11-") else "1.56")
            or not isinstance(proof, dict) or set(proof) != {
            "schema_version", "candidate_sha", "lane", "mode", "rendering_api",
            "run_id", "identity_contract", "cases", "probes"}
            or type(proof["schema_version"]) is not int or proof["schema_version"] != 2
            or proof["candidate_sha"] != candidate or proof["lane"] != lane
            or proof["mode"] != mode or proof["rendering_api"] != api
            or proof["run_id"] != run_id or proof["identity_contract"] != CONTRACT
            or proof["probes"] != list(probes)
            or not isinstance(proof["cases"], list) or len(proof["cases"]) != len(CASES)):
        raise ValueError("identity contract binding or completion mismatch")
    ids = set()
    for name, outcome, case in zip(CASES, OUTCOMES, proof["cases"]):
        if (not isinstance(case, dict) or set(case) != {
                "case", "expected_outcome", "wire", "containers"}
                or case["case"] != name or case["expected_outcome"] != outcome
                or case["wire"] != "passed" or not isinstance(case["containers"], list)
                or len(case["containers"]) != 2):
            raise ValueError("incomplete identity contract case")
        positive = outcome == "exited_zero"
        phases = []
        for role, record in zip(("oracle", "rendered"), case["containers"]):
            if (not isinstance(record, dict) or set(record) != {
                    "role", "id", "name", "owner", "configured", "outcome",
                    "rejection_phase", "runtime_uid", "runtime_gid", "runtime_workdir", "cleanup"}
                    or record["role"] != role
                    or record["name"] != f"dl-identity-{run_id}-{name}-{role}"
                    or record["owner"] != run_id or record["outcome"] != outcome
                    or record["cleanup"] != "absent"
                    or any(record[key] != ("passed" if positive else "not_started")
                           for key in ("runtime_uid", "runtime_gid", "runtime_workdir"))):
                raise ValueError("invalid identity contract ownership or check")
            phase = record["rejection_phase"]
            if (positive and phase is not None) or (not positive and phase not in ("create", "start")):
                raise ValueError("invalid identity rejection phase")
            phases.append(phase)
            identifier = record["id"]
            if identifier is None:
                if positive or phase != "create" or record["configured"] != "not_created":
                    raise ValueError("unproved identity creation absence")
            else:
                if (phase == "create" or not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{64}", identifier)
                        or identifier in ids or record["configured"] != "passed"):
                    raise ValueError("invalid or repeated identity container")
                ids.add(identifier)
        if phases[0] != phases[1]:
            raise ValueError("identity oracle and renderer rejection disagree")
