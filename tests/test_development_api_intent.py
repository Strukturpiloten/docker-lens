"""Development API intent is limited to a trusted Git transition and six witnesses."""

from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from boxferry_ci import api_baselines as api
from boxferry_ci import cargo_tools
from boxferry_ci.contracts import ContractError

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/development-api-intent.py"
SUBJECT = runpy.run_path(str(GUARD))
AUTHORIZE = SUBJECT["approved_delta"]
CHECK = SUBJECT["check"]
RECORD = SUBJECT["RECORD"]
AUTOMATION = "a" * 40


class DevelopmentAPIIntentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.git("init", "-q")
        self.git("config", "user.name", "Intent test")
        self.git("config", "user.email", "test@example.invalid")
        (self.root / "src").mkdir()
        (self.root / "scripts").mkdir()
        (self.root / ".github").mkdir()
        (self.root / ".github/automation.json").write_text("{}\n")
        self.source = self.root / "src/resource_support.rs"
        self.source.write_text("pub struct Test;\n")
        self.previous = self.commit("previous trusted main")
        self.source.write_text("pub struct Test { pub field: u32 }\n")
        prototype = self.commit("prototype")
        delta = subprocess.check_output(
            [
                "git",
                "diff-tree",
                "-r",
                "--no-commit-id",
                "--raw",
                "--no-renames",
                "--no-abbrev",
                "-z",
                self.previous,
                prototype,
            ],
            cwd=self.root,
            timeout=10,
        )
        self.git("reset", "--hard", self.previous)
        self.record = {
            "schema": 1,
            "previous_main": self.previous,
            "delta_sha256": hashlib.sha256(delta).hexdigest(),
            "candidate_version": "0.2.0",
        }
        (self.root / RECORD).write_text(json.dumps(self.record))
        self.base = self.commit("prepared trusted main")
        self.source.write_text("pub struct Test { pub field: u32 }\n")
        self.candidate = self.commit("approved product")

    def git(self, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=self.root, text=True, timeout=10).strip()

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def context(self, event: str, candidate: str, policy: str) -> api.Context:
        return api.Context(
            "development", event, candidate, policy, AUTOMATION, SUBJECT["REPOSITORY"]
        )

    def test_existing_selector_uses_each_real_event_base_with_distinct_tested_commits(self) -> None:
        tree = self.git("rev-parse", f"{self.candidate}^{{tree}}")
        pr = self.git("commit-tree", tree, "-p", self.base, "-p", self.candidate, "-m", "PR test")
        group = self.git("commit-tree", tree, "-p", self.base, "-m", "Queue candidate")
        self.assertEqual(len({pr, group, self.candidate}), 3)
        events = (
            ("pull_request", pr, self.base, {"pull_request": {"base": {"sha": self.base}}}),
            ("merge_group", group, self.base, {"merge_group": {"base_sha": self.base}}),
            (
                "push",
                group,
                group,
                {
                    "repository": {"default_branch": "main"},
                    "before": self.base,
                    "ref": "refs/heads/main",
                },
            ),
            ("local", self.candidate, self.candidate, {}),
        )
        for event, candidate, policy, payload in events:
            with self.subTest(event=event):
                self.git("checkout", "-q", "--detach", candidate)
                context = self.context(event, candidate, policy)
                with patch.object(api, "default_authority", return_value=("main", self.base)):
                    selected, _ = api.select_git(self.root, context, payload)
                self.assertEqual(selected, self.base)
                self.assertEqual(AUTHORIZE(self.root, context, selected), self.record)

    def test_preparation_candidate_owned_record_and_later_baseline_do_not_authorize(self) -> None:
        self.git("checkout", "-q", "--detach", self.base)
        context = self.context("pull_request", self.base, self.previous)
        payload = {"pull_request": {"base": {"sha": self.previous}}}
        selected, _ = api.select_git(self.root, context, payload)
        self.assertIsNone(AUTHORIZE(self.root, context, selected))

        self.git("checkout", "-q", "--detach", self.candidate)
        self.source.write_text("pub struct Later;\n")
        later = self.commit("later main")
        self.assertIsNone(AUTHORIZE(self.root, self.context("push", later, later), self.candidate))

    def test_preparation_workflow_uses_baseline_guard_even_with_candidate_override_input(
        self,
    ) -> None:
        execution = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (execution / "source").symlink_to(self.root, target_is_directory=True)
        subprocess.run(
            ["git", "clone", "-q", "--no-hardlinks", str(self.root), str(execution / "_policy")],
            check=True,
            timeout=10,
        )
        subprocess.run(
            ["git", "-C", str(execution / "_policy"), "checkout", "-q", "--detach", self.previous],
            check=True,
            timeout=10,
        )
        (self.root / "scripts/development-api-intent.py").write_text(
            "raise SystemExit('candidate-only guard was executed')\n"
        )
        self.commit("candidate-only guard")
        workflow = (ROOT / ".github/workflows/check.yml").read_text()
        step = re.search(
            r"(?ms)^      - name: Verify development API intent from the trusted baseline\n"
            r".*?^        run: \|\n(.*?)(?=^      - name:)",
            workflow,
        )
        assert step is not None
        output = execution / "outputs"
        result = subprocess.run(
            ["bash", "-c", textwrap.dedent(step[1])],
            cwd=execution,
            env={
                **os.environ,
                "AUTHORITY_SHA": self.previous,
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_OUTPUT": str(output),
                "RUNNER_TEMP": str(execution),
                "RELEASE_TYPE": "major",
            },
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())

    def test_extra_path_dirty_source_and_modified_record_refuse_the_intent(self) -> None:
        context = self.context("local", self.candidate, self.candidate)
        self.source.write_text("pub struct Test { pub field: u32, pub extra: u32 }\n")
        self.assertIsNone(AUTHORIZE(self.root, context, self.base))
        extra = self.commit("one additional field")
        self.assertIsNone(AUTHORIZE(self.root, self.context("local", extra, extra), self.base))
        self.git("reset", "--hard", self.candidate)
        (self.root / "extra.txt").write_text("extra\n")
        extra = self.commit("one additional path")
        self.assertIsNone(AUTHORIZE(self.root, self.context("local", extra, extra), self.base))
        self.git("reset", "--hard", self.candidate)
        (self.root / RECORD).write_text(json.dumps({**self.record, "delta_sha256": "b" * 64}))
        replaced = self.commit("attempt to supply candidate intent")
        self.assertIsNone(
            AUTHORIZE(self.root, self.context("local", replaced, replaced), self.base)
        )

    def test_hidden_working_difference_cannot_match_the_approved_tree(self) -> None:
        self.git("update-index", "--assume-unchanged", "src/resource_support.rs")
        self.source.write_text("pub struct Unexpected;\n")
        self.assertFalse(api.dirty(self.root))
        with self.assertRaises(ContractError):
            SUBJECT["held_fingerprint"](self.root, self.candidate)

    def minor_report(self, context: api.Context) -> dict:
        version = "0.50.0"
        return {
            "schema": 1,
            "status": "failure",
            "context": vars(context),
            "authority": (
                {"default_branch": "main", "advertised_default_sha": self.base}
                if context.event == "local"
                else {"event_base": self.base}
            ),
            "source_fingerprint": api.fingerprint(self.root),
            "tool": {
                "package": "cargo-semver-checks",
                "version": version,
                "rust_channel": "1.98.1",
            },
            "checks": [
                {
                    "package": "docker-lens",
                    "candidate_version": "0.2.0",
                    "kind": "git",
                    "baseline_rev": self.base,
                    "baseline_version": "",
                    "release_type": "minor",
                }
            ],
            "command_failure": {
                "status": "failed",
                "returncode": 100,
                "argv": [
                    "cargo",
                    "semver-checks",
                    "check-release",
                    "--manifest-path",
                    "<repository>/Cargo.toml",
                    "--package",
                    "docker-lens",
                    "--all-features",
                    "--baseline-rev",
                    self.base,
                    "--release-type",
                    "minor",
                ],
                "stdout": "--- failure constructible_struct_adds_field: struct exhaustively "
                "constructible through public API adds field ---\n\nDescription:\n"
                "A pub struct that could be exhaustively constructed with a literal using only "
                "public API has a new pub field, breaking existing exhaustive literals.\n"
                "        ref: https://doc.rust-lang.org/reference/expressions/struct-expr.html\n"
                f"       impl: https://github.com/obi1kenobi/cargo-semver-checks/tree/v{version}"
                "/src/lints/constructible_struct_adds_field.ron\n\nFailed in:\n"
                + "".join(
                    f"  field {witness} in /held/src/resource_support.rs:1\n"
                    for witness in SUBJECT["FIELDS"]
                ),
                "stderr": f"     Cloning {self.base}\n"
                "    Building docker-lens v0.2.0 (current)\n"
                "       Built [   1.854s] (current)\n"
                "     Parsing docker-lens v0.2.0 (current)\n"
                "      Parsed [   0.018s] (current)\n"
                "     Parsing docker-lens v0.1.0 (baseline, cached)\n"
                "      Parsed [   0.014s] (baseline)\n"
                "    Checking docker-lens v0.1.0 -> v0.2.0 (assume minor change)\n"
                "     Checked [   0.016s] 196 checks: 195 pass, 1 fail, 0 warn, 58 skip\n\n"
                "     Summary semver requires new major version: 1 major and 0 minor checks failed\n"
                "    Finished [   4.247s] docker-lens\n",
            },
        }

    def test_only_exact_minor_outcome_allows_major_on_the_same_context(self) -> None:
        context = self.context("local", self.candidate, self.candidate)
        evidence = Path(self.enterContext(tempfile.TemporaryDirectory()))
        report = self.minor_report(context)
        cases = (
            ("all expected witnesses", lambda _: None),
            (
                "additional witness",
                lambda item: item["command_failure"].update(
                    stdout=item["command_failure"]["stdout"]
                    + "  field ResourceSupportObservation.extra in /held/src/resource_support.rs:1\n"
                ),
            ),
            (
                "another lint",
                lambda item: item["command_failure"].update(
                    stdout=item["command_failure"]["stdout"] + "--- failure another_lint: ---\n"
                ),
            ),
            (
                "extra warning",
                lambda item: item["command_failure"].update(
                    stdout=item["command_failure"]["stdout"] + "--- warning other_lint: ---\n"
                ),
            ),
            (
                "clipped transcript",
                lambda item: item["command_failure"].update(
                    stderr=item["command_failure"]["stderr"].split("    Finished")[0]
                ),
            ),
            (
                "clipped progress",
                lambda item: item["command_failure"].update(
                    stderr=item["command_failure"]["stderr"].split("\n", 1)[1]
                ),
            ),
            (
                "different clone",
                lambda item: item["command_failure"].update(
                    stderr=item["command_failure"]["stderr"].replace(self.base, self.previous)
                ),
            ),
            (
                "extra error",
                lambda item: item["command_failure"].update(
                    stderr="error: incomplete git baseline\n" + item["command_failure"]["stderr"]
                ),
            ),
            (
                "wrong receipt authority",
                lambda item: item["authority"].update(advertised_default_sha=self.previous),
            ),
            ("missing command identity", lambda item: item["command_failure"].pop("argv")),
            ("tool error", lambda item: item["command_failure"].update(returncode=1)),
            ("failed baseline", lambda item: item["checks"][0].update(baseline_rev=self.previous)),
        )
        for label, modify in cases:
            with self.subTest(label=label):
                actual = json.loads(json.dumps(report))
                modify(actual)
                calls = []

                def run_api(
                    root: Path,
                    current: api.Context,
                    path: Path,
                    allowance: str = "",
                    outcome: dict = actual,
                    call_log: list[str] = calls,
                ) -> int:
                    self.assertEqual(root, self.root)
                    self.assertEqual(current, context)
                    call_log.append(allowance)
                    if not allowance:
                        path.write_text(json.dumps(outcome))
                        return 1
                    accepted = json.loads(json.dumps(outcome))
                    accepted["status"] = "success"
                    accepted["checks"][0]["release_type"] = allowance
                    path.write_text(json.dumps(accepted))
                    return 0

                with (
                    patch.object(api, "default_authority", return_value=("main", self.base)),
                    patch.dict(
                        CHECK.__globals__,
                        {"context_for": lambda *_: (context, {}), "run_api": run_api},
                    ),
                ):
                    if label == "all expected witnesses":
                        self.assertEqual(CHECK(self.root, False, evidence), 0)
                        self.assertEqual(calls, ["", "major"])
                        self.assertTrue((evidence / "api-baseline-minor.json").is_file())
                    else:
                        with self.assertRaises(ContractError):
                            CHECK(self.root, False, evidence)
                        self.assertEqual(calls, [""])

    def test_major_receipt_cannot_substitute_the_observed_local_authority(self) -> None:
        context = self.context("local", self.candidate, self.candidate)
        evidence = Path(self.enterContext(tempfile.TemporaryDirectory()))

        def run_api(_: Path, __: api.Context, path: Path, allowance: str = "") -> int:
            report = self.minor_report(context)
            if allowance == "major":
                report["status"] = "success"
                report["checks"][0]["release_type"] = allowance
                report["authority"]["advertised_default_sha"] = self.previous
            path.write_text(json.dumps(report))
            return 0 if allowance else 1

        with (
            patch.object(api, "default_authority", return_value=("main", self.base)),
            patch.dict(
                CHECK.__globals__,
                {"context_for": lambda *_: (context, {}), "run_api": run_api},
            ),
            self.assertRaisesRegex(ContractError, "major comparison differs"),
        ):
            CHECK(self.root, False, evidence)
        self.assertEqual(
            json.loads((evidence / "api-baseline-local.json").read_text())["status"], "failure"
        )

    def test_local_default_tip_must_still_hold_the_prepared_transition(self) -> None:
        self.git("checkout", "-q", "--detach", self.base)
        (self.root / "new-main.txt").write_text("main advanced\n")
        new_tip = self.commit("new canonical main")
        self.git("checkout", "-q", "--detach", self.candidate)
        context = self.context("local", self.candidate, self.candidate)
        evidence = Path(self.enterContext(tempfile.TemporaryDirectory()))
        current_tip = new_tip

        def authority(_: Path, __: api.Context) -> tuple[str, str]:
            return "main", current_tip

        def minor(root: Path, observed: api.Context, path: Path, allowance: str = "") -> int:
            nonlocal current_tip
            self.assertEqual(root, self.root)
            self.assertEqual(observed, context)
            self.assertEqual(allowance, "")
            path.write_text(json.dumps(self.minor_report(context)))
            current_tip = new_tip
            return 1

        with (
            patch.object(api, "default_authority", side_effect=authority),
            patch.dict(
                CHECK.__globals__,
                {"context_for": lambda *_: (context, {}), "run_api": minor},
            ),
        ):
            self.assertEqual(CHECK(self.root, False, evidence), 1)
            self.assertFalse((evidence / "api-baseline-minor.json").exists())
            current_tip = self.base
            with self.assertRaisesRegex(ContractError, "minor comparison differs"):
                CHECK(self.root, False, evidence)
            self.assertTrue((evidence / "api-baseline-minor.json").is_file())

    def test_hosted_release_type_is_issued_only_after_the_reviewed_minor_failure(self) -> None:
        context = self.context("merge_group", self.candidate, self.base)
        payload = {"merge_group": {"base_sha": self.base}}
        evidence = Path(self.enterContext(tempfile.TemporaryDirectory()))
        outputs = evidence / "workflow-output"
        report = self.minor_report(context)

        def minor(root: Path, observed: api.Context, path: Path, allowance: str = "") -> int:
            self.assertEqual(root, self.root)
            self.assertEqual(observed, context)
            self.assertEqual(allowance, "")
            self.assertNotIn("release_type", outputs.read_text())
            path.write_text(json.dumps(report))
            return 1

        with (
            patch.dict(os.environ, {"GITHUB_OUTPUT": str(outputs), "RELEASE_TYPE": "major"}),
            patch.dict(
                CHECK.__globals__,
                {"context_for": lambda *_: (context, payload), "run_api": minor},
            ),
            patch.object(cargo_tools, "select"),
            patch.object(
                cargo_tools,
                "install",
                return_value={
                    "CARGO_HOME": str(evidence / "cargo"),
                    "bin_directory": str(evidence / "bin"),
                },
            ),
        ):
            self.assertEqual(CHECK(self.root, True, evidence), 0)
        self.assertEqual(outputs.read_text(), "minor_evidence=true\nrelease_type=major\n")
        self.assertEqual(json.loads((evidence / "api-baseline-minor.json").read_text()), report)


if __name__ == "__main__":
    unittest.main()
