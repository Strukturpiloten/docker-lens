"""Offline contracts for the DockerLens publishing workflow and its guards."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_candidate", ROOT / "scripts/release-candidate.py"
)
assert SPEC is not None and SPEC.loader is not None
CANDIDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANDIDATE)

SHA = "a" * 40
VERSION = "0.2.0"
PUBLISHER = (ROOT / ".github/workflows/release.yml").read_text()
VALIDATION = (ROOT / ".github/workflows/release-validation.yml").read_text()
NOTES = "\n\n- Verified release note.\n\n"
DIGEST = hashlib.sha256(NOTES.encode()).hexdigest()
CONTEXT = {
    "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_SHA": SHA,
    "GITHUB_RUN_ID": "123",
    "GITHUB_RUN_ATTEMPT": "1",
    "EXPECTED_SHA": SHA,
    "EXPECTED_VERSION": VERSION,
    "VALIDATED_SHA": SHA,
}


def step_script(source: str, name: str) -> str:
    step = re.split(r"(?m)^      - ", source.split(f"      - name: {name}\n", 1)[1], maxsplit=1)[0]
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


class PublicationTests(unittest.TestCase):
    def test_workflows_keep_validation_and_publication_permissions_separate(self):
        inventory, publisher = PUBLISHER.split("  publish:\n", 1)
        self.assertIn("default: true", inventory)
        self.assertIn("uses: ./.github/workflows/release-validation.yml", inventory)
        self.assertIn('validation-only: "true"', inventory)
        for prohibited in ("environment:", "id-token:", "contents: write"):
            self.assertNotIn(prohibited, inventory)
        self.assertIn("needs: [validation, inventory]", publisher)
        for requirement in (
            "github.ref == 'refs/heads/main'",
            "github.run_attempt == 1",
            "inputs.validation_only == false",
            "needs.validation.result == 'success'",
            "needs.validation.outputs.candidate_sha == inputs.expected_sha",
            "needs.inventory.result == 'success'",
            "needs.inventory.outputs.version == inputs.expected_version",
            "needs.inventory.outputs.notes_sha256 != ''",
            "environment: release",
            "id-token: write",
        ):
            self.assertIn(requirement, publisher)
        self.assertNotIn("contents: write", publisher)
        self.assertNotIn("bootstrap-token:", publisher)
        self.assertEqual(
            PUBLISHER.count("uses: ./_automation/.github/actions/shared-crate-publish"), 2
        )
        self.assertEqual(publisher.count('validation-only: "false"'), 1)
        self.assertLess(
            publisher.index("scripts/release-candidate.py --after-approval"),
            publisher.index("uses: ./_automation/.github/actions/shared-crate-publish"),
        )
        self.assertLess(
            publisher.index("Verify the release environment and the maintainer's approval"),
            publisher.index("scripts/release-candidate.py --after-approval"),
        )
        for prohibited in ("id-token:", "environment:", "shared-crate-publish", "cargo publish"):
            self.assertNotIn(prohibited, VALIDATION)
        self.assertIn("workflow_dispatch:", VALIDATION)
        self.assertIn("value: ${{ jobs.release-gate.outputs.candidate_sha }}", VALIDATION)

    def test_candidate_admission_refuses_non_main_even_at_the_expected_sha(self):
        guard = step_script(VALIDATION, "Require an exact main dispatch before checking out code")
        self.assertLess(
            VALIDATION.index(guard.splitlines()[0]), VALIDATION.index("actions/checkout")
        )
        for context in (
            {},
            {"GITHUB_REF": "refs/tags/main"},
            {"GITHUB_REF": "refs/heads/topic"},
            {"EXPECTED_SHA": ""},
            {"GITHUB_EVENT_NAME": "push"},
            {"GITHUB_REPOSITORY": "Strukturpiloten/other"},
        ):
            with self.subTest(context=context):
                run = subprocess.run(
                    ["bash", "-c", guard],
                    env=dict(os.environ, **CONTEXT) | context,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(run.returncode == 0, not context, run.stderr)

    def test_final_validation_only_exports_the_shared_candidate_at_current_main(self):
        guard = step_script(VALIDATION, "Recheck current main after all lanes")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git = root / "git"
            git.write_text(
                '#!/bin/bash\ncase "$*" in "fetch --no-tags origin main") exit "$FETCH_EXIT";; '
                '"rev-parse HEAD") printf "%s\\n" "$GIT_HEAD";; '
                '"rev-parse origin/main") printf "%s\\n" "$GIT_MAIN";; *) exit 2;; esac\n'
            )
            git.chmod(0o700)
            output = root / "output"
            environment = dict(
                os.environ,
                PATH=f"{root}:{os.environ['PATH']}",
                EXPECTED_SHA=SHA,
                GITHUB_OUTPUT=str(output),
                GIT_HEAD=SHA,
                GIT_MAIN=SHA,
                FETCH_EXIT="0",
                SHARED_CANDIDATE_SHA=SHA,
            )
            for change in (
                {},
                {"SHARED_CANDIDATE_SHA": ""},
                {"SHARED_CANDIDATE_SHA": "b" * 40},
                {"FETCH_EXIT": "1"},
                {"GIT_MAIN": "b" * 40},
                {"GIT_HEAD": "b" * 40},
            ):
                with self.subTest(change=change):
                    output.unlink(missing_ok=True)
                    run = subprocess.run(
                        ["bash", "-c", guard],
                        env=environment | change,
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    if change:
                        self.assertNotEqual(run.returncode, 0)
                        self.assertFalse(output.exists())
                    else:
                        self.assertEqual(run.returncode, 0, run.stderr)
                        self.assertEqual(output.read_text(), f"candidate_sha={SHA}\n")

    def test_personal_approval_is_required_even_if_the_environment_can_be_bypassed(self):
        guard = step_script(
            PUBLISHER, "Verify the release environment and the maintainer's approval"
        )
        reviewer = {"login": "TheRealBecks", "id": 1497405}
        environment = {
            "name": "release",
            "id": 222,
            "can_admins_bypass": False,
            "deployment_branch_policy": {"custom_branch_policies": True},
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "reviewers": [{"type": "User", "reviewer": reviewer}],
                },
            ],
        }
        branches = {"total_count": 1, "branch_policies": [{"type": "branch", "name": "main"}]}
        approved = {
            "state": "approved",
            "user": reviewer,
            "environments": [{"name": "release", "id": 222}],
        }
        failures = (
            {"APPROVALS": []},
            {"APPROVALS": {"row": approved}},
            {"APPROVALS": [approved | {"state": "rejected"}]},
            {"APPROVALS": [approved | {"user": {"login": "someone-else", "id": 2}}]},
            {"APPROVALS": [approved | {"user": reviewer | {"id": 2}}]},
            {"APPROVALS": [approved | {"environments": [{"name": "release", "id": 333}]}]},
            {"APPROVALS": [approved, approved]},
            {"ENVIRONMENT": environment | {"can_admins_bypass": True}},
            {"ENVIRONMENT": environment | {"protection_rules": []}},
            {
                "BRANCHES": {
                    "total_count": 2,
                    "branch_policies": [
                        {"type": "branch", "name": "main"},
                        {"type": "tag", "name": "v*"},
                    ],
                }
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gh = root / "gh"
            gh.write_text(
                '#!/bin/bash\n[[ "$1" == api ]] || exit 2\ncase "$2" in\n'
                'repos/Strukturpiloten/docker-lens/environments/release) printf "%s\\n" "$ENVIRONMENT";;\n'
                "repos/Strukturpiloten/docker-lens/environments/release/deployment-branch-policies) "
                'printf "%s\\n" "$BRANCHES";;\n'
                "repos/Strukturpiloten/docker-lens/actions/runs/123/approvals) "
                '[[ "$API_EXIT" == 0 ]] && printf "%s\\n" "$APPROVALS";;\n'
                "*) exit 2;; esac\n"
            )
            gh.chmod(0o700)
            for change in (
                {},
                *(
                    {key: json.dumps(value) for key, value in failure.items()}
                    for failure in failures
                ),
                {"GITHUB_RUN_ATTEMPT": "2"},
                {"API_EXIT": "1"},
            ):
                with self.subTest(change=change):
                    run = subprocess.run(
                        ["bash", "-c", guard],
                        env=dict(os.environ, **CONTEXT)
                        | {
                            "PATH": f"{root}:{os.environ['PATH']}",
                            "ENVIRONMENT": json.dumps(environment),
                            "BRANCHES": json.dumps(branches),
                            "APPROVALS": json.dumps([approved]),
                            "API_EXIT": "0",
                        }
                        | change,
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(run.returncode == 0, not change, run.stderr)

    def test_notes_and_version_are_bound_before_and_after_approval(self):
        values = {
            ("rev-parse", "HEAD"): SHA + "\n",
            ("status", "--porcelain"): "",
            ("show", "HEAD:Cargo.toml"): f'[package]\nname="docker-lens"\nversion="{VERSION}"\n',
            (
                "show",
                "HEAD:CHANGELOG.md",
            ): f"## Unreleased\n\n- Work\n\n## [{VERSION}]{NOTES}## 0.1.0\n",
            ("ls-remote", "--exit-code", "origin", "refs/heads/main"): f"{SHA}\trefs/heads/main\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary, output = root / "summary", root / "output"
            environment = CONTEXT | {
                "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(summary),
                "PREPARED_VERSION": VERSION,
                "PREPARED_NOTES_SHA256": DIGEST,
            }
            cases = (
                ([], {}, {}, True),
                (["--after-approval"], {}, {}, True),
                (["--after-approval"], {"PREPARED_NOTES_SHA256": ""}, {}, False),
                (["--after-approval"], {"PREPARED_NOTES_SHA256": "0" * 64}, {}, False),
                (["--after-approval"], {"PREPARED_VERSION": "0.3.0"}, {}, False),
                (["--after-approval"], {"VALIDATED_SHA": ""}, {}, False),
                (["--after-approval"], {"VALIDATED_SHA": "b" * 40}, {}, False),
                (["--after-approval"], {"GITHUB_REF": "refs/tags/v0.2.0"}, {}, False),
                (["--after-approval"], {"GITHUB_RUN_ATTEMPT": "2"}, {}, False),
                (
                    ["--after-approval"],
                    {},
                    {("ls-remote", "--exit-code", "origin", "refs/heads/main"): "moved"},
                    False,
                ),
                ([], {"EXPECTED_VERSION": "0.3.0"}, {}, False),
                ([], {}, {("show", "HEAD:CHANGELOG.md"): "## Unreleased\n\n- Work\n"}, False),
            )
            for args, env_edit, git_edit, success in cases:
                with (
                    self.subTest(args=args, env_edit=env_edit, git_edit=git_edit),
                    patch.dict(os.environ, environment | env_edit, clear=True),
                    patch.object(sys, "argv", ["release-candidate.py", *args]),
                    patch.object(
                        CANDIDATE,
                        "git",
                        side_effect=lambda *key, responses=values | git_edit: responses[key],
                    ),
                ):
                    self.assertEqual(CANDIDATE.main(), 0 if success else 1)
            self.assertEqual(output.read_text(), f"notes_sha256={DIGEST}\n")
            self.assertIn(SHA, summary.read_text())
            self.assertIn(NOTES.strip(), summary.read_text())

    def test_requires_one_nonempty_final_notes_section(self):
        for changelog in (
            "## Unreleased\n\n- Unversioned change\n",
            "## [0.2.0]\n\n### Features\n",
            "## 0.2.0\n\n- One\n## [0.2.0] - 2026-11-21\n\n- Two\n",
        ):
            with self.subTest(changelog=changelog), self.assertRaises(ValueError):
                CANDIDATE.release_notes(changelog, VERSION)


if __name__ == "__main__":
    unittest.main()
