#!/usr/bin/env python3
"""Gate one reviewed development API break using the canonical Git comparison."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from boxferry_ci import api_baselines as api
from boxferry_ci import cargo_tools
from boxferry_ci.contracts import ContractError
from boxferry_ci.release import unique_object

REPOSITORY = "Strukturpiloten/docker-lens"
PACKAGE = "docker-lens"
RECORD = "scripts/development-api-intent.json"
LINT = "constructible_struct_adds_field"
FIELDS = sorted(
    f"{structure}.{field}"
    for structure in ("ResourceSupportObservation", "ResourceSupportAssessment")
    for field in ("pids_limit", "cgroup_driver", "cgroup_version")
)


def record_blob(root: Path, revision: str) -> str:
    entry = api.git(root, "ls-tree", revision, "--", RECORD)
    if not entry:
        return ""
    match = re.fullmatch(r"100644 blob ([0-9a-f]{40})\t" + re.escape(RECORD), entry)
    if match is None:
        raise ContractError("development API intent must be a regular, nonexecutable Git blob")
    return match[1]


def approved_delta(root: Path, context: api.Context, base: str) -> dict[str, Any] | None:
    blob = record_blob(root, base)
    if not blob:
        return None
    parent = api.git(root, "rev-parse", "--verify", f"{base}^")
    if record_blob(root, parent):
        return None  # A record authorizes only the transition from its introducing baseline.
    if int(api.git(root, "cat-file", "-s", blob)) > 4096:
        raise ContractError("development API intent exceeds its byte bound")
    record = json.loads(api.git(root, "cat-file", "blob", blob), object_pairs_hook=unique_object)
    if (
        not isinstance(record, dict)
        or set(record) != {"schema", "previous_main", "delta_sha256", "candidate_version"}
        or type(record["schema"]) is not int
        or record["schema"] != 1
        or record["previous_main"] != parent
        or not isinstance(record["delta_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", record["delta_sha256"]) is None
        or record["candidate_version"] != "0.2.0"
    ):
        raise ContractError("malformed trusted development API intent record")
    if api.dirty(root) or record_blob(root, context.candidate) != blob:
        return None
    manifest = ".github/automation.json"
    if api.git(root, "rev-parse", f"{base}:{manifest}") != api.git(
        root, "rev-parse", f"{context.candidate}:{manifest}"
    ):
        return None
    delta = api.command(
        root,
        (
            "git",
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "diff-tree",
            "-r",
            "--no-commit-id",
            "--raw",
            "--no-renames",
            "--no-abbrev",
            "-z",
            base,
            context.candidate,
        ),
    )
    if not delta or hashlib.sha256(delta).hexdigest() != record["delta_sha256"]:
        return None
    return record


def matches_comparison(
    report: dict[str, Any],
    context: api.Context,
    selection: tuple[str, dict[str, str]],
    fingerprint: str,
    version: str,
    allowance: str,
) -> bool:
    base, authority = selection
    return (
        report.get("context") == vars(context)
        and report.get("authority") == authority
        and report.get("source_fingerprint") == fingerprint
        and report.get("checks")
        == [
            {
                "package": PACKAGE,
                "candidate_version": version,
                "kind": "git",
                "baseline_rev": base,
                "baseline_version": "",
                "release_type": allowance,
            }
        ]
    )


def expected_minor_failure(
    report: dict[str, Any],
    context: api.Context,
    selection: tuple[str, dict[str, str]],
    fingerprint: str,
    version: str,
) -> bool:
    base, _ = selection
    if type(report.get("schema")) is not int or report["schema"] != 1:
        return False
    if report.get("status") != "failure" or not matches_comparison(
        report, context, selection, fingerprint, version, "minor"
    ):
        return False
    failure = report.get("command_failure", {})
    command = [
        "cargo",
        "semver-checks",
        "check-release",
        "--manifest-path",
        "<repository>/Cargo.toml",
        "--package",
        PACKAGE,
        "--all-features",
        "--baseline-rev",
        base,
        "--release-type",
        "minor",
    ]
    if (
        failure.get("status") != "failed"
        or failure.get("returncode") != 100
        or failure.get("argv") != command
        or failure.get("abort_hook_failure")
    ):
        return False
    stdout, stderr = failure["stdout"], failure["stderr"]
    diagnostic = re.fullmatch(
        rf"--- failure {LINT}: struct exhaustively constructible through public API adds field ---\n"
        r"\nDescription:\n"
        r"A pub struct that could be exhaustively constructed with a literal using only public API "
        r"has a new pub field, breaking existing exhaustive literals\.\n"
        r" +ref: https://doc\.rust-lang\.org/reference/expressions/struct-expr\.html\n"
        r" +impl: https://github\.com/obi1kenobi/cargo-semver-checks/tree/"
        rf"v{re.escape(report['tool']['version'])}/src/lints/{LINT}\.ron\n"
        r"\nFailed in:\n"
        r"((?:  field [A-Za-z_.]+ in [^\n]+/src/resource_support\.rs:\d+\n?){6})",
        stdout.strip(),
    )
    if diagnostic is None:
        return False
    witnesses = re.findall(r"(?m)^  field (\S+) in ", diagnostic[1])
    summary = re.fullmatch(
        rf" +Cloning {base}\n"
        + rustdoc_progress("current", version)
        + rustdoc_progress("baseline", "0.1.0")
        + rf" +Checking {PACKAGE} v0\.1\.0 -> v{re.escape(version)} \(assume minor change\)\n"
        r" +Checked \[ *\d+\.\d+s\] (\d+) checks: (\d+) pass, 1 fail, 0 warn, \d+ skip\n"
        r"\n +Summary semver requires new major version: 1 major and 0 minor checks failed\n"
        rf" +Finished \[ *\d+\.\d+s\] {PACKAGE}",
        stderr.strip("\n"),
    )
    return (
        sorted(witnesses) == FIELDS
        and summary is not None
        and int(summary[1]) == int(summary[2]) + 1
    )


def rustdoc_progress(role: str, version: str) -> str:
    """The pinned checker either builds rustdoc or reads a complete cached result."""
    package = rf"{PACKAGE} v{re.escape(version)}"
    elapsed = r"\[ *\d+\.\d+s\]"
    return (
        rf"(?: +Building {package} \({role}\)\n"
        rf" +Built {elapsed} \({role}\)\n"
        rf" +Parsing {package} \({role}\)\n"
        rf"| +Parsing {package} \({role}, cached\)\n)"
        rf" +Parsed {elapsed} \({role}\)\n"
    )


def context_for(root: Path, hosted: bool) -> tuple[api.Context, dict[str, Any]]:
    event = os.environ["GITHUB_EVENT_NAME"] if hosted else "local"
    payload = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()) if hosted else {}
    candidate = api.git(root, "rev-parse", "HEAD")
    if hosted and (
        payload["repository"]["full_name"] != REPOSITORY or candidate != os.environ["GITHUB_SHA"]
    ):
        raise ContractError("development API checkout does not match the exact caller event")
    policy = candidate
    if event == "pull_request":
        policy = payload["pull_request"]["base"]["sha"]
    elif event == "merge_group":
        policy = payload["merge_group"]["base_sha"]
    identity = api.automation_identity(root, None, allow_dirty_self=False)
    return api.Context(
        "development", event, candidate, policy, identity["revision"], REPOSITORY
    ), payload


def run_api(root: Path, context: api.Context, report: Path, allowance: str = "") -> int:
    return api.main(
        [
            "run",
            "--repository-root",
            str(root),
            "--repository",
            REPOSITORY,
            "--package",
            PACKAGE,
            "--api-purpose",
            "development",
            "--event",
            context.event,
            "--candidate-sha",
            context.candidate,
            "--policy-sha",
            context.policy,
            "--automation-sha",
            context.automation,
            "--release-type",
            allowance,
            "--report-json",
            str(report),
        ]
    )


def write_output(name: str, value: str) -> None:
    api.write_outputs(Path(os.environ["GITHUB_OUTPUT"]), {name: value})


def held_fingerprint(root: Path, candidate: str) -> str:
    """Verify the working bytes against the approved Git tree, including ignored index flags."""
    paths = sorted(api.git(root, "ls-tree", "-r", "--name-only", "-z", candidate).split("\0")[:-1])
    with api.snapshot(root, candidate) as immutable:
        if any(not (immutable / path).is_file() for path in paths):
            raise ContractError("development API intent requires a complete tested tree")
        expected = api.fingerprint(immutable, paths)
    if api.fingerprint(root) != expected:
        raise ContractError("development API working bytes differ from the reviewed Git tree")
    return expected


def check(root: Path, hosted: bool, evidence: Path) -> int:
    context, payload = context_for(root, hosted)
    selection = api.select_git(root, context, payload)
    base, authority = selection
    intent = approved_delta(root, context, base)
    normal_report = evidence / "api-baseline-local.json"
    if not hosted and authority.get("advertised_default_sha") not in {base, context.candidate}:
        intent = None
    if intent is None:
        return 0 if hosted else run_api(root, context, normal_report)

    held = held_fingerprint(root, context.candidate)
    if hosted:
        tool = cargo_tools.select(root, "cargo-semver-checks")
        installation = cargo_tools.install(tool, evidence / "cargo-tools", root)
        os.environ["CARGO_HOME"] = installation["CARGO_HOME"]
        os.environ["PATH"] = installation["bin_directory"] + os.pathsep + os.environ["PATH"]
        write_output("minor_evidence", "true")
    if api.dirty(root):
        raise ContractError("development API intent requires clean held source")
    os.environ["CARGO_TERM_COLOR"] = "never"
    minor_report = evidence / "api-baseline-minor.json"
    status = run_api(root, context, minor_report)
    if status == 0:
        if not hosted:
            minor_report.replace(normal_report)
        return 0
    if (
        status != 1
        or not expected_minor_failure(
            json.loads(minor_report.read_text()),
            context,
            selection,
            held,
            intent["candidate_version"],
        )
        or api.fingerprint(root) != held
        or api.dirty(root)
        or api.select_git(root, context, payload) != selection
    ):
        raise ContractError("minor comparison differs from the reviewed development API intent")
    if hosted:
        write_output("release_type", "major")
        return 0

    status = run_api(root, context, normal_report, "major")
    if status == 0:
        result = json.loads(normal_report.read_text())
        if (
            result["status"] != "success"
            or not matches_comparison(
                result, context, selection, held, intent["candidate_version"], "major"
            )
            or api.fingerprint(root) != held
            or api.dirty(root)
            or api.select_git(root, context, payload) != selection
        ):
            result["status"] = "failure"
            normal_report.write_text(json.dumps(result, indent=2) + "\n")
            raise ContractError(
                "major comparison differs from the reviewed minor source and baseline"
            )
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    parser.add_argument("--hosted", type=Path, metavar="EVIDENCE_DIRECTORY")
    args = parser.parse_args()
    root = args.repository_root.resolve(strict=True)
    try:
        if args.hosted is None:
            return check(root, False, root / "target")
        # Keep the original minor receipt independent of the subsequently compiled checkout.
        args.hosted.mkdir(exist_ok=False)
        return check(root, True, args.hosted)
    except (ContractError, OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Development API validation failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
