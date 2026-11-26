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

import yaml
from boxferry_ci import release as shared_release

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
APPROVAL_GUARD = ROOT / "scripts/release-approval.sh"
NOTES = "\n\n- Verified release note.\n\n"
DIGEST = hashlib.sha256(NOTES.encode()).hexdigest()
APPROVAL = (
    f"Approve docker-lens {VERSION} at {SHA} with notes SHA-256 {DIGEST} "
    "for release run 123 attempt 1"
)
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
    step = re.split(
        r"(?m)^      - |^  [\w-]+:\n", source.split(f"      - name: {name}\n", 1)[1], maxsplit=1
    )[0]
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


class PublicationTests(unittest.TestCase):
    def test_workflow_grants_oidc_only_to_approved_publication(self):
        inventory, approval = PUBLISHER.split("  approval:\n", 1)
        self.assertIn("default: true", inventory)
        self.assertIn("needs: admission", inventory)
        self.assertIn("timeout-minutes: 45", approval)
        self.assertIn("uses: ./.github/workflows/release-validation.yml", inventory)
        self.assertIn('validation-only: "true"', inventory)
        for prohibited in ("environment:", "id-token:", "contents: write"):
            self.assertNotIn(prohibited, inventory)
        self.assertIn("needs: [validation, inventory]", approval)
        for requirement in (
            "github.ref == 'refs/heads/main'",
            "github.run_attempt == 1",
            "inputs.validation_only == false",
            "needs.validation.result == 'success'",
            "needs.validation.outputs.candidate_sha == inputs.expected_sha",
            "needs.inventory.result == 'success'",
            "needs.inventory.outputs.version == inputs.expected_version",
            "needs.inventory.outputs.notes_sha256 != ''",
            "needs.inventory.outputs.approval_comment != ''",
            "needs.inventory.outputs.environment_id != ''",
            "environment: release",
            "actions: read",
        ):
            self.assertIn(requirement, approval)
        for prohibited in ("contents: write", "bootstrap-token:"):
            self.assertNotIn(prohibited, PUBLISHER)
        self.assertEqual(PUBLISHER.count("id-token: write"), 1)
        self.assertEqual(
            inventory.count("uses: ./_automation/.github/actions/shared-crate-publish"), 1
        )
        self.assertIn("if: inputs.validation_only == false", inventory)
        self.assertIn("scripts/release-approval.sh --preflight", inventory)
        self.assertIn('run: test "${INVENTORY_VERSION}" = "${EXPECTED_VERSION}"', inventory)
        self.assertEqual(
            approval.count("uses: ./_automation/.github/actions/shared-crate-publish"), 1
        )
        self.assertIn('validation-only: "false"', approval)
        self.assertIn("validation-sha: ${{ needs.validation.outputs.candidate_sha }}", approval)
        self.assertIn("validation-result: ${{ needs.validation.result }}", approval)
        self.assertLess(
            approval.index("scripts/release-approval.sh --review"),
            approval.index("scripts/release-candidate.py --after-approval"),
        )
        self.assertLess(
            approval.index("scripts/release-candidate.py --after-approval"),
            approval.index("uses: ./_automation/.github/actions/shared-crate-publish"),
        )
        for prohibited in ("id-token:", "environment:", "shared-crate-publish", "cargo publish"):
            self.assertNotIn(prohibited, VALIDATION)
        self.assertIn("workflow_dispatch:", VALIDATION)
        self.assertIn("value: ${{ jobs.release-gate.outputs.candidate_sha }}", VALIDATION)

    def test_release_admission_binds_both_modes_before_expensive_validation(self):
        workflow = yaml.safe_load(PUBLISHER)
        self.assertEqual(workflow["jobs"]["validation"]["needs"], "admission")
        admission = workflow["jobs"]["admission"]
        self.assertEqual(admission["permissions"], {"contents": "read"})
        self.assertNotIn("environment", admission)
        self.assertNotIn("if", admission)
        script = step_script(PUBLISHER, "Require the exact protected main before validation")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gh = root / "gh"
            gh.write_text(
                '#!/bin/bash\n[[ "$*" == "api repos/Strukturpiloten/docker-lens/branches/main" ]] || exit 2\n'
                '[[ "$API_EXIT" == 0 ]] || exit 1\nprintf "%s\\n" "$MAIN"\n'
            )
            gh.chmod(0o700)
            main = {"name": "main", "protected": True, "commit": {"sha": SHA}}
            for mode in ("true", "false"):
                for change in (
                    {},
                    {"MAIN": json.dumps(main | {"protected": False})},
                    {"MAIN": json.dumps(main | {"commit": {"sha": "b" * 40}})},
                    {"MAIN": json.dumps(main | {"name": "topic"})},
                    {"MAIN": "{}"},
                    {"MAIN": json.dumps(main) + "\n" + json.dumps(main)},
                    {"API_EXIT": "1"},
                    {"GITHUB_REF": "refs/tags/v0.2.0"},
                    {"GITHUB_RUN_ATTEMPT": "2"},
                    {"GITHUB_SHA": "b" * 40},
                    {"EXPECTED_SHA": "short"},
                ):
                    with self.subTest(mode=mode, change=change):
                        result = subprocess.run(
                            ["bash", "-c", script],
                            env=dict(os.environ, **CONTEXT)
                            | {
                                "PATH": f"{root}:{os.environ['PATH']}",
                                "MAIN": json.dumps(main),
                                "API_EXIT": "0",
                                "VALIDATION_ONLY": mode,
                            }
                            | change,
                            capture_output=True,
                            timeout=10,
                            check=False,
                        )
                        self.assertEqual(result.returncode == 0, not change, result.stderr)

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

    def test_preflight_and_personal_approval_refuse_unsafe_environment_or_history(self):
        reviewer = {"login": "TheRealBecks", "id": 1497405, "type": "User"}
        environment = {
            "name": "release",
            "id": 22952362673,
            "can_admins_bypass": True,
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "reviewers": [{"type": "User", "reviewer": reviewer}],
                },
            ],
        }
        branches = {
            "total_count": 2,
            "branch_policies": [{"type": "branch", "name": "main"}, {"type": "tag", "name": "v*"}],
        }
        main = {"name": "main", "protected": True, "commit": {"sha": SHA}}
        approved = {
            "state": "approved",
            "user": reviewer,
            "environments": [{"name": "release", "id": environment["id"]}],
            "comment": APPROVAL,
        }
        invalid_protection = (
            {"MAIN": main | {"protected": False}},
            {"MAIN": main | {"commit": {"sha": "b" * 40}}},
            {"ENVIRONMENT": environment | {"id": 333}},
            {"ENVIRONMENT": environment | {"protection_rules": []}},
            {"BRANCHES": {"total_count": 1, "branch_policies": [{"type": "tag", "name": "main"}]}},
        )
        invalid_reviews = (
            {"APPROVALS": []},
            {"APPROVALS": {"row": approved}},
            {"APPROVALS": [approved, {"state": "approved"}]},
            {"APPROVALS": [approved, {"environments": [{}]}]},
            {"APPROVALS": [approved, {"environments": [{"name": "other"}]}]},
            {"APPROVALS": [approved, {"environments": [{"id": 333}]}]},
            {"APPROVALS": [approved, {"environments": [{"name": "", "id": 333}]}]},
            {"APPROVALS": [approved, {"environments": [{"name": "other", "id": "333"}]}]},
            {"APPROVALS": [approved, {"environments": [{"name": "other", "id": 333.5}]}]},
            {"APPROVALS": [approved | {"state": "rejected"}]},
            {"APPROVALS": [approved | {"state": "pending"}]},
            {"APPROVALS": [approved | {"state": "bypassed"}]},
            {"APPROVALS": [approved | {"comment": None}]},
            {"APPROVALS": [approved | {"comment": "Bypass protection and start waiting jobs"}]},
            {"APPROVALS": [approved | {"comment": APPROVAL.replace("run 123", "run 122")}]},
            {"APPROVALS": [approved | {"comment": APPROVAL.replace(SHA, "b" * 40)}]},
            {"APPROVALS": [approved | {"comment": APPROVAL.replace(DIGEST, "0" * 64)}]},
            {"APPROVALS": [approved | {"user": {"login": "someone-else", "id": 2}}]},
            {"APPROVALS": [approved | {"user": reviewer | {"id": 2}}]},
            {"APPROVALS": [approved | {"user": reviewer | {"type": "Bot"}}]},
            {"APPROVALS": [approved | {"environments": [{"name": "release", "id": 333}]}]},
            {"APPROVALS": [approved, approved]},
            {
                "APPROVALS": [
                    approved,
                    approved | {"environments": [{"name": "release", "id": 333}]},
                ]
            },
            {
                "APPROVALS": [
                    approved,
                    approved
                    | {"state": "rejected", "environments": [{"name": "Release", "id": 333}]},
                ]
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gh = root / "gh"
            gh.write_text(
                '#!/bin/bash\n[[ "$1" == api ]] || exit 2\ncase "$2" in\n'
                'repos/Strukturpiloten/docker-lens/branches/main) printf "%s\\n" "$MAIN";;\n'
                'repos/Strukturpiloten/docker-lens/environments/release) printf "%s\\n" "$ENVIRONMENT";;\n'
                "repos/Strukturpiloten/docker-lens/environments/release/deployment-branch-policies) "
                'printf "%s\\n" "$BRANCHES";;\n'
                "repos/Strukturpiloten/docker-lens/actions/runs/123/approvals) "
                '[[ "$API_EXIT" == 0 ]] && printf "%s\\n" "$APPROVALS";;\n'
                "*) exit 2;; esac\n"
            )
            gh.chmod(0o700)
            output = root / "output"
            fixture = dict(os.environ, **CONTEXT) | {
                "PATH": f"{root}:{os.environ['PATH']}",
                "MAIN": json.dumps(main),
                "ENVIRONMENT": json.dumps(environment),
                "BRANCHES": json.dumps(branches),
                "APPROVALS": json.dumps([approved]),
                "APPROVAL_COMMENT": APPROVAL,
                "API_EXIT": "0",
                "GITHUB_OUTPUT": str(output),
                "PREPARED_ENVIRONMENT_ID": str(environment["id"]),
            }
            invalid_context = (
                {"GITHUB_RUN_ATTEMPT": "2"},
                {"GITHUB_REF": "refs/tags/v0.2.0"},
                {"GITHUB_RUN_ID": "invalid"},
            )
            for mode, cases in (
                (
                    "--preflight",
                    (
                        # A preflight needs no review history.
                        {"API_EXIT": "1"},
                        *(
                            {key: json.dumps(value) for key, value in case.items()}
                            for case in invalid_protection
                        ),
                        *invalid_context,
                    ),
                ),
                (
                    "--review",
                    (
                        {},
                        *(
                            {key: json.dumps(value) for key, value in case.items()}
                            for case in (*invalid_protection, *invalid_reviews)
                        ),
                        *invalid_context,
                        {
                            "APPROVALS": json.dumps([approved, approved])
                            + "\n"
                            + json.dumps([approved])
                        },
                        {"APPROVAL_COMMENT": ""},
                        {"API_EXIT": "1"},
                        {"PREPARED_ENVIRONMENT_ID": "333"},
                    ),
                ),
            ):
                for index, change in enumerate(cases):
                    with self.subTest(mode=mode, change=change):
                        output.unlink(missing_ok=True)
                        run = subprocess.run(
                            ["bash", str(APPROVAL_GUARD), mode],
                            env=fixture | change,
                            capture_output=True,
                            timeout=10,
                            check=False,
                        )
                        self.assertEqual(run.returncode == 0, index == 0, run.stderr)
                        if mode == "--preflight" and index == 0:
                            self.assertEqual(
                                output.read_text(), f"environment_id={environment['id']}\n"
                            )
                        else:
                            self.assertFalse(output.exists())

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
                ([], {"VALIDATION_ONLY": "true"}, {}, True),
                ([], {"VALIDATION_ONLY": "false"}, {}, True),
                ([], {"VALIDATION_ONLY": "false", "GITHUB_RUN_ATTEMPT": "2"}, {}, False),
                ([], {"VALIDATION_ONLY": "false", "GITHUB_RUN_ID": "invalid"}, {}, False),
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
                    output.unlink(missing_ok=True)
                    summary.unlink(missing_ok=True)
                    self.assertEqual(CANDIDATE.main(), 0 if success else 1)
                    if success and not args:
                        show_approval = (
                            env_edit.get("VALIDATION_ONLY") == "false"
                            and env_edit.get("GITHUB_RUN_ATTEMPT", "1") == "1"
                        )
                        expected = f"notes_sha256={DIGEST}\n"
                        if show_approval:
                            expected += f"approval_comment={APPROVAL}\n"
                        self.assertEqual(output.read_text(), expected)
                        self.assertIn(SHA, summary.read_text())
                        self.assertIn(NOTES.strip(), summary.read_text())
                        self.assertEqual(APPROVAL in summary.read_text(), show_approval)
                    else:
                        self.assertFalse(output.exists())
                        self.assertFalse(summary.exists())

    def test_normal_shared_prepare_and_publish_interface_without_credentials(self):
        # Exercise the real pinned producer, observing its final upload boundary.
        # No credential value or network operation is supplied by this harness.
        workflow = yaml.safe_load(PUBLISHER)
        publish_job = workflow["jobs"]["approval"]
        caller = publish_job["steps"][-1]
        self.assertEqual(caller["uses"], "./_automation/.github/actions/shared-crate-publish")
        self.assertEqual(caller["with"]["package"], "docker-lens")
        self.assertEqual(caller["with"]["candidate-sha"], "${{ inputs.expected_sha }}")
        self.assertEqual(
            caller["with"]["release-config"],
            "${{ github.workspace }}/source/scripts/release-policy.json",
        )
        inventory = workflow["jobs"]["inventory"]["steps"]
        prepare_call = next(step for step in inventory if step.get("uses") == caller["uses"])
        for call, mode in ((prepare_call, "true"), (caller, "false")):
            self.assertEqual(call["with"]["validation-only"], mode)
            self.assertEqual(call["with"]["package"], "docker-lens")
            self.assertEqual(
                call["with"]["validation-sha"], "${{ needs.validation.outputs.candidate_sha }}"
            )
            self.assertEqual(call["with"]["validation-result"], "${{ needs.validation.result }}")
            self.assertEqual(
                call["with"]["automation-sha"],
                json.loads((ROOT / ".github/automation.json").read_text())["revision"],
            )
        revision = json.loads((ROOT / ".github/automation.json").read_text())["revision"]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            manifest = source / "Cargo.toml"
            manifest.write_text('[package]\nname="docker-lens"\nversion="0.2.0"\n')
            metadata = {
                "workspace_members": ["fixture"],
                "packages": [
                    {
                        "id": "fixture",
                        "name": "docker-lens",
                        "version": VERSION,
                        "manifest_path": str(manifest),
                        "publish": None,
                        "dependencies": [],
                    }
                ],
            }
            output = Path(directory) / "output"
            argv = [
                "--repository-root",
                str(source),
                "--config",
                str(ROOT / "scripts/release-policy.json"),
                "--package",
                "docker-lens",
                "--candidate-sha",
                SHA,
                "--automation-sha",
                revision,
                "--validation-sha",
                SHA,
                "--validation-result",
                "success",
            ]
            with (
                patch.dict(
                    os.environ,
                    CONTEXT | {"BOXFERRY_DEFAULT_BRANCH": "main", "GITHUB_OUTPUT": str(output)},
                    clear=True,
                ),
                patch.object(
                    shared_release.subprocess,
                    "check_output",
                    side_effect=lambda args, **kwargs: (
                        json.dumps(metadata)
                        if args[0] == "cargo"
                        else SHA
                        if args[2] == str(source)
                        else revision
                    ),
                ) as cargo,
                patch.object(shared_release, "registry_status", return_value=404) as registry,
                patch.object(shared_release, "publish_crate") as upload,
            ):
                self.assertEqual(
                    shared_release.main(["prepare-crate", *argv, "--validation-only", "true"]), 0
                )
                registry.assert_not_called()
                upload.assert_not_called()
                self.assertIn("version=0.2.0", output.read_text())
                self.assertEqual(
                    shared_release.main(["prepare-crate", *argv, "--validation-only", "false"]), 0
                )
                registry.assert_called_once_with("docker-lens", VERSION)
                self.assertEqual(cargo.call_args.kwargs["cwd"], source)
                for mode in ("true", "false"):
                    with self.assertRaises(SystemExit):
                        shared_release.main(["publish-crate", *argv, "--validation-only", mode])
                upload.assert_not_called()
                # The producer's credential-presence check is the only substituted
                # authentication boundary; the fixture never creates a token.
                original_get = os.environ.get
                with patch.object(
                    os.environ,
                    "get",
                    side_effect=lambda key, *default: (
                        True if key == "CARGO_REGISTRY_TOKEN" else original_get(key, *default)
                    ),
                ):
                    self.assertEqual(
                        shared_release.main(["publish-crate", *argv, "--validation-only", "false"]),
                        0,
                    )
                upload.assert_called_once_with(source, "docker-lens", VERSION)

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
