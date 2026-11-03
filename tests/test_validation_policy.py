"""The trusted seed preserves offline suites before workflow adoption."""

import json
import shlex
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ValidationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = json.loads((ROOT / "scripts/validation-policy.json").read_text())
        self.aliases = tomllib.loads((ROOT / ".cargo/config.toml").read_text())["alias"]

    def test_complete_profiles_keep_the_current_gate(self) -> None:
        self.assertEqual(self.policy["schema"], 2)
        self.assertEqual(self.policy["repository"], "Strukturpiloten/docker-lens")
        self.assertEqual(
            set(self.policy["jobs"]),
            {
                "rust",
                "msrv",
                "dependencies",
                "api",
                "documentation",
                "lockfile-release-age",
            },
        )
        self.assertEqual(
            set(self.policy["profile_jobs"]["executable-docs"]),
            set(self.policy["jobs"]),
        )
        complete = [["bash", "scripts/check-all.sh", "--check"]]
        self.assertEqual(self.policy["local_commands"]["full"], complete)
        self.assertEqual(self.policy["local_commands"]["executable-docs"], complete)

    def test_prose_uses_policy_tests_without_rust_or_runtime_contact(self) -> None:
        self.assertEqual(self.policy["profile_jobs"]["prose"], ["documentation"])
        expected = [
            ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
            ["git", "diff", "--check"],
        ]
        self.assertEqual(self.policy["local_commands"]["prose"], expected)
        self.assertEqual(self.policy["tasks"]["documentation"]["commands"], expected)
        self.assertEqual(self.policy["public_documentation_root"], "docs/")
        self.assertEqual(
            self.policy["full_documentation_roots"],
            ["docs/decisions/", "docs/evidence/"],
        )
        self.assertEqual(self.policy["executable_documentation_paths"], ["README.md"])
        self.assertIsNone(self.policy["documentation_examples_manifest"])

    def test_shared_rust_tasks_preserve_locked_scope_and_diagnostics(self) -> None:
        expected = {
            "ci-check": ["check", "--all-targets", "--locked"],
            "ci-clippy": [
                "clippy",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
            "ci-test": ["test", "--all-targets", "--locked"],
            "ci-doctest": ["test", "--doc", "--locked"],
            "ci-doc": ["doc", "--no-deps", "--locked"],
        }
        self.assertEqual(
            {name: shlex.split(value) for name, value in self.aliases.items()}, expected
        )
        self.assertEqual(
            self.policy["tasks"]["rust-quality"]["commands"],
            [
                ["cargo", "fmt", "--all", "--", "--check"],
                *[["cargo", name] for name in expected],
            ],
        )
        self.assertEqual(
            self.policy["tasks"]["msrv"]["commands"], [["cargo", "ci-check"]]
        )
        for task in self.policy["tasks"].values():
            self.assertGreater(task["timeout_seconds"], 0)
            self.assertLessEqual(task["timeout_seconds"], 1800)


if __name__ == "__main__":
    unittest.main()
