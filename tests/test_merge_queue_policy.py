"""Merge queue candidates require the same complete offline evidence as PRs."""

import os
import subprocess
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MergeQueuePolicyTests(unittest.TestCase):
    def test_queue_runs_complete_gate_at_the_event_candidate(self) -> None:
        workflow = (ROOT / ".github/workflows/check.yml").read_text()
        self.assertIn("  merge_group:\n    types: [checks_requested]\n", workflow)
        self.assertIn("candidate-sha: ${{ github.sha }}", workflow)
        self.assertIn("github.event.merge_group.base_sha", workflow)
        self.assertIn("--tested-sha", workflow)
        self.assertIn("--needs-json", workflow)
        self.assertNotIn("continue-on-error", workflow)

    def test_queue_gate_rejects_incomplete_unplanned_or_unknown_outcomes(self) -> None:
        workflow = (ROOT / ".github/workflows/check.yml").read_text()
        gate = workflow.split("      - name: Fail on skipped, cancelled, or failed validation\n", 1)[1].split("        run: |\n", 1)[1]
        script = textwrap.dedent(gate)
        for event, ref, offline, native, expected in (
            (
                "merge_group",
                "refs/heads/gh-readonly-queue/main/pr-1",
                "success",
                "skipped",
                True,
            ),
            (
                "merge_group",
                "refs/heads/gh-readonly-queue/main/pr-1",
                "failure",
                "skipped",
                False,
            ),
            (
                "merge_group",
                "refs/heads/gh-readonly-queue/main/pr-1",
                "cancelled",
                "skipped",
                False,
            ),
            (
                "merge_group",
                "refs/heads/gh-readonly-queue/main/pr-1",
                "skipped",
                "skipped",
                False,
            ),
            (
                "merge_group",
                "refs/heads/gh-readonly-queue/main/pr-1",
                "success",
                "success",
                False,
            ),
            (
                "merge_group",
                "refs/heads/gh-readonly-queue/main/pr-1",
                "success",
                "failure",
                False,
            ),
            ("pull_request", "refs/pull/1/merge", "success", "skipped", True),
            ("push", "refs/heads/main", "success", "success", True),
            ("push", "refs/heads/main", "success", "skipped", False),
            ("unknown", "refs/heads/main", "success", "skipped", False),
        ):
            with self.subTest(event=event, offline=offline, native=native):
                result = subprocess.run(
                    ["bash", "-e", "-o", "pipefail", "-c", script],
                    env=dict(
                        os.environ,
                        EVENT_NAME=event,
                        EVENT_REF=ref,
                        SCAFFOLD_RESULT=offline,
                        NATIVE_RESULT=native,
                    ),
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                self.assertEqual(result.returncode == 0, expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
