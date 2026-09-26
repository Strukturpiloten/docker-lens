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


if __name__ == "__main__":
    unittest.main()
