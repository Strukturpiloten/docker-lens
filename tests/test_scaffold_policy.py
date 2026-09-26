"""Bounded bootstrap and release policy invariants."""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ScaffoldPolicyTests(unittest.TestCase):
    def test_release_gate_is_exact_candidate_and_native_required(self) -> None:
        workflow = (ROOT / ".github/workflows/release-validation.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"', workflow)
        self.assertIn('test "$(git rev-parse origin/main)" = "$EXPECTED_SHA"', workflow)
        self.assertIn("needs: candidate", workflow)
        self.assertIn("./scripts/native-conformance.sh", workflow)
        self.assertNotIn("continue-on-error", workflow)
        self.assertNotIn("cargo publish", workflow)

    def test_action_pins_and_renovate_ownership(self) -> None:
        renovate = json.loads((ROOT / "renovate.json").read_text())
        self.assertEqual(
            renovate["enabledManagers"],
            ["cargo", "github-actions", "custom.regex"],
        )
        self.assertEqual(len(renovate["customManagers"]), 1)
        manager = renovate["customManagers"][0]
        self.assertEqual(manager["datasourceTemplate"], "github-tags")
        extractor = manager["matchStrings"][0].replace("(?<currentValue>", "(?P<currentValue>")
        self.assertRegex((ROOT / "rust-toolchain.toml").read_text(), extractor)
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            text = workflow.read_text()
            for action in re.findall(r"uses: (.+)", text):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$")

    def test_scripts_have_distinct_scope(self) -> None:
        fast = (ROOT / "scripts/format-lint.sh").read_text()
        complete = (ROOT / "scripts/check-all.sh").read_text()
        native = (ROOT / "scripts/native-conformance.sh").read_text()
        self.assertNotIn("cargo test", fast)
        self.assertIn("cargo test --all-targets --locked", complete)
        self.assertIn("python3 -m unittest discover", complete)
        self.assertIn("exit 1", native)

    def test_manual_native_dispatch_is_trusted_exact_head_and_validation_only(self) -> None:
        workflow = (ROOT / ".github/workflows/native-validation.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("draft is allowed", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertNotIn("push:", workflow)
        self.assertIn("pull-requests: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertEqual(workflow.count("ref: ${{ inputs.expected_sha }}"), 2)
        self.assertEqual(workflow.count("python3 scripts/native-dispatch-admission.py"), 3)
        self.assertIn("if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'", workflow)
        native_job = workflow.split("  native-conformance:\n", 1)[1].split("  native-gate:\n", 1)[0]
        trusted_checkout = native_job.index("ref: main")
        actor_check = native_job.index("run: python3 scripts/native-dispatch-admission.py")
        candidate_checkout = native_job.index("ref: ${{ inputs.expected_sha }}")
        native_execution = native_job.index("./scripts/native-conformance.sh")
        self.assertLess(trusted_checkout, actor_check)
        self.assertLess(actor_check, candidate_checkout)
        self.assertLess(candidate_checkout, native_execution)
        self.assertEqual(native_job.count("GITHUB_TOKEN: ${{ github.token }}"), 1)
        self.assertIn("needs: [admission, candidate, native-conformance]", workflow)
        self.assertIn('test "$ADMISSION_RESULT" = success', workflow)
        self.assertIn('test "$CANDIDATE_RESULT" = success', workflow)
        self.assertIn('test "$NATIVE_RESULT" = success', workflow)
        self.assertIn("[debian11-rootful, debian11-rootless, upstream-rootful, upstream-rootless]", workflow)
        self.assertNotIn("cargo publish", workflow)
        self.assertNotIn("gh release", workflow)
        self.assertIn("A draft PR stays unmergeable during validation", (ROOT / "docs/verification.md").read_text())


if __name__ == "__main__":
    unittest.main()
