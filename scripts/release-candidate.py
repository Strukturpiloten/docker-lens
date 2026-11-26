"""Bind the reviewed DockerLens version and release notes to the exact live main."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path

SHA = re.compile(r"[a-f0-9]{40}")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}")


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], timeout=30).decode("utf-8")


def release_notes(changelog: str, version: str) -> str:
    headings = list(re.finditer(r"(?m)^## (.+)$", changelog))
    title = re.compile(
        rf"(?:{re.escape(version)}|\[{re.escape(version)}\])(?: - [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})?"
    )
    matching = [i for i, heading in enumerate(headings) if title.fullmatch(heading[1].strip())]
    if len(matching) != 1:
        raise ValueError("expected one finalized changelog section for the crate version")
    index = matching[0]
    end = headings[index + 1].start() if index + 1 < len(headings) else len(changelog)
    notes = changelog[headings[index].end() : end]
    if not re.search(r"(?m)^[-*] \S", notes):
        raise ValueError("the finalized release notes must contain at least one entry")
    return notes


def verify_candidate(environment: Mapping[str, str]) -> tuple[str, str, str]:
    candidate = environment.get("EXPECTED_SHA", "")
    version = environment.get("EXPECTED_VERSION", "")
    if (
        not SHA.fullmatch(candidate)
        or environment.get("GITHUB_REPOSITORY") != "Strukturpiloten/docker-lens"
        or environment.get("GITHUB_RUN_ATTEMPT") != "1"
        or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_SHA") != candidate
        or environment.get("VALIDATED_SHA") != candidate
    ):
        raise ValueError("the release requires the exact validated main dispatch")
    if not VERSION.fullmatch(version):
        raise ValueError("the expected crate version must be stable and exact")
    if git("rev-parse", "HEAD").strip() != candidate or git("status", "--porcelain"):
        raise ValueError("the release checkout is dirty or does not match the candidate")
    package = tomllib.loads(git("show", "HEAD:Cargo.toml"))["package"]
    if (
        not isinstance(package, dict)
        or package.get("name") != "docker-lens"
        or package.get("version") != version
    ):
        raise ValueError("the expected version does not match the candidate manifest")
    notes = release_notes(git("show", "HEAD:CHANGELOG.md"), version)
    if git("ls-remote", "--exit-code", "origin", "refs/heads/main") != (
        f"{candidate}\trefs/heads/main\n"
    ):
        raise ValueError("origin/main moved since this release candidate was selected")
    return candidate, version, notes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--after-approval", action="store_true")
    arguments = parser.parse_args()
    try:
        candidate, version, notes = verify_candidate(os.environ)
        digest = hashlib.sha256(notes.encode("utf-8")).hexdigest()
        if arguments.after_approval:
            if (
                os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
                or os.environ.get("PREPARED_VERSION") != version
                or os.environ.get("PREPARED_NOTES_SHA256") != digest
            ):
                raise ValueError("the approved version and notes must match this first attempt")
        else:
            approval_comment = ""
            if (
                os.environ.get("VALIDATION_ONLY") == "false"
                and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
            ):
                run_id = os.environ["GITHUB_RUN_ID"]
                if not re.fullmatch(r"[1-9][0-9]*", run_id):
                    raise ValueError("the release approval requires a valid workflow run ID")
                approval_comment = (
                    f"Approve docker-lens {version} at {candidate} with notes SHA-256 {digest} "
                    f"for release run {run_id} attempt 1"
                )
            with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
                summary.write(
                    f"## DockerLens {version}\n\nCommit `{candidate}`\n\n{notes.strip()}\n"
                )
                if approval_comment:
                    summary.write(
                        f"\nRelease approval comment:\n\n```text\n{approval_comment}\n```\n"
                    )
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
                output.write(f"notes_sha256={digest}\n")
                if approval_comment:
                    output.write(f"approval_comment={approval_comment}\n")
    except (OSError, KeyError, UnicodeError, tomllib.TOMLDecodeError, subprocess.SubprocessError):
        print("DockerLens release candidate evidence could not be read.", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"DockerLens release candidate refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
