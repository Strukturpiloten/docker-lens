#!/usr/bin/env python3
"""Fail-closed admission for a manually reviewed, exact-PR-head native run."""

import http.client
import json
import os
import re
import sys
from collections.abc import Callable
from urllib.parse import quote

REPOSITORY = "Strukturpiloten/docker-lens"
BOXFERRY_REPOSITORY = "Strukturpiloten/boxferry"
TRUSTED_REPOSITORIES = frozenset({REPOSITORY, BOXFERRY_REPOSITORY})
ALLOWED_ROLES = frozenset({"write", "maintain", "admin"})
ACTOR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
PR_RE = re.compile(r"[1-9][0-9]{0,8}\Z")
ID_RE = re.compile(r"[1-9][0-9]*\Z")


class AdmissionError(Exception):
    """A closed, value-free rejection reason."""


def allowed_api_path(path: str, expected_repository: str) -> bool:
    if expected_repository not in TRUSTED_REPOSITORIES:
        return False
    prefix = f"/repos/{expected_repository}/"
    if not path.startswith(prefix):
        return False
    suffix = path[len(prefix):]
    if suffix.startswith("pulls/"):
        return bool(PR_RE.fullmatch(suffix.removeprefix("pulls/")))
    if suffix.startswith("collaborators/") and suffix.endswith("/permission"):
        actor = suffix[len("collaborators/"):-len("/permission")]
        return bool(ACTOR_RE.fullmatch(actor))
    return False


def fetch_json(path: str, token: str, expected_repository: str = REPOSITORY) -> dict:
    if not allowed_api_path(path, expected_repository):
        raise AdmissionError("invalid-api-path")
    connection = http.client.HTTPSConnection("api.github.com", timeout=10)
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "docker-lens-native-admission",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise AdmissionError("api-unavailable")
        body = response.read(65_537)
        if len(body) > 65_536:
            raise AdmissionError("api-response-too-large")
        value = json.loads(body)
        if not isinstance(value, dict):
            raise AdmissionError("api-invalid-response")
        return value
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise AdmissionError("api-unavailable") from error
    finally:
        connection.close()


def expected_repository_from_env(env: dict[str, str]) -> str:
    """Only a trusted workflow literal may select the shared consumer policy."""
    repository = env.get("EXPECTED_REPOSITORY", REPOSITORY)
    if repository not in TRUSTED_REPOSITORIES:
        raise AdmissionError("invalid-repository-policy")
    return repository


def admit(
    env: dict[str, str], get: Callable[[str], dict], expected_repository: str = REPOSITORY
) -> None:
    if expected_repository not in TRUSTED_REPOSITORIES:
        raise AdmissionError("invalid-repository-policy")
    if (
        env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or env.get("GITHUB_REF") != "refs/heads/main"
        or env.get("GITHUB_REPOSITORY") != expected_repository
    ):
        raise AdmissionError("untrusted-dispatch-ref")
    repo_id = env.get("GITHUB_REPOSITORY_ID", "")
    pr_number = env.get("PR_NUMBER", "")
    expected_sha = env.get("EXPECTED_SHA", "")
    actors = (env.get("GITHUB_ACTOR", ""), env.get("GITHUB_TRIGGERING_ACTOR", ""))
    if not (ID_RE.fullmatch(repo_id) and PR_RE.fullmatch(pr_number) and SHA_RE.fullmatch(expected_sha)):
        raise AdmissionError("invalid-input")
    if not all(ACTOR_RE.fullmatch(actor) for actor in actors):
        raise AdmissionError("unknown-actor")

    for actor in set(actors):
        permission = get(f"/repos/{expected_repository}/collaborators/{quote(actor, safe='')}/permission")
        role = permission.get("permission") if isinstance(permission, dict) else None
        if not isinstance(role, str) or role not in ALLOWED_ROLES:
            raise AdmissionError("insufficient-actor-permission")

    pull = get(f"/repos/{expected_repository}/pulls/{pr_number}")
    if not isinstance(pull, dict):
        raise AdmissionError("invalid-pull-response")
    head = pull.get("head")
    base = pull.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        raise AdmissionError("invalid-pull-response")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    if not isinstance(head_repo, dict) or not isinstance(base_repo, dict):
        raise AdmissionError("invalid-pull-response")
    if not (
        type(pull.get("number")) is int
        and pull["number"] == int(pr_number)
        and pull.get("state") == "open"
        and base.get("ref") == "main"
        and head.get("sha") == expected_sha
        and type(head_repo.get("id")) is int
        and type(base_repo.get("id")) is int
        and head_repo["id"] == int(repo_id)
        and base_repo["id"] == int(repo_id)
        and head_repo.get("full_name") == expected_repository
        and base_repo.get("full_name") == expected_repository
    ):
        raise AdmissionError("pull-head-mismatch")


def main(args: list[str] | None = None) -> int:
    try:
        if (sys.argv[1:] if args is None else args):
            raise AdmissionError("invalid-repository-policy")
        expected_repository = expected_repository_from_env(os.environ)
    except AdmissionError as error:
        print(f"native dispatch denied: {error}", file=sys.stderr)
        return 1
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("native dispatch denied: missing-token", file=sys.stderr)
        return 1
    try:
        admit(os.environ, lambda path: fetch_json(path, token, expected_repository), expected_repository)
    except AdmissionError as error:
        print(f"native dispatch denied: {error}", file=sys.stderr)
        return 1
    if expected_repository == REPOSITORY:
        print("reviewed exact PR head admitted for native validation only")
    else:
        print("reviewed exact PR head admitted for application validation only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
