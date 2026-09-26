"""Repository-local agent roles and scaffold policy contracts."""

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AgentConfigurationTests(unittest.TestCase):
    def test_primary_and_bounded_defaults(self) -> None:
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
        self.assertEqual(config["model"], "gpt-6-sol")
        self.assertEqual(config["model_reasoning_effort"], "xhigh")
        self.assertTrue(config["agents"]["enabled"])
        self.assertEqual(config["agents"]["max_concurrent_threads_per_session"], 9)
        self.assertEqual(config["agents"]["default_subagent_model"], "gpt-6-sol")
        self.assertEqual(config["agents"]["default_subagent_reasoning_effort"], "medium")

    def test_explicit_roles_and_permissions(self) -> None:
        for role, model, effort, sandbox in (
            ("implementation-worker", "gpt-6-sol", "high", "workspace-write"),
            ("specification-researcher", "gpt-6-sol", "high", "read-only"),
            ("reviewer", "gpt-6-sol", "high", "read-only"),
            ("verifier", "gpt-6-luna", "high", "workspace-write"),
        ):
            with self.subTest(role=role):
                config = tomllib.loads(
                    (ROOT / f".codex/agents/{role}.toml").read_text(encoding="utf-8")
                )
                self.assertEqual(config["name"], role.replace("-", "_"))
                self.assertEqual(config["model"], model)
                self.assertEqual(config["model_reasoning_effort"], effort)
                self.assertEqual(config["sandbox_mode"], sandbox)
                instructions = config["developer_instructions"]
                self.assertIn("AGENTS.md", instructions)
                self.assertIn("GitHub writes", instructions)
                if role == "reviewer":
                    self.assertIn("original user requirements", instructions)
                    self.assertIn("independent expected results", instructions)
                if role == "verifier":
                    self.assertIn("./scripts/check-all.sh --check", instructions)
                    self.assertIn(
                        "Escalate complex failure diagnosis to a Sol agent",
                        instructions,
                    )
                    self.assertIn("never run the default formatting gate", instructions)

    def test_workspace_authorization_and_agent_limits_are_bounded(self) -> None:
        instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        authorization = instructions.split(
            "## Workspace scope and standing GitHub authorization", 1
        )[1].split("\n## ", 1)[0]
        repositories = [line for line in authorization.splitlines() if line.startswith("- ")]
        self.assertEqual(
            repositories,
            [
                "- `Strukturpiloten/boxferry`",
                "- `Strukturpiloten/compose-lens`",
                "- `Strukturpiloten/podman-lens`",
                "- `Strukturpiloten/quadlet-lens`",
                "- `Strukturpiloten/boxferry-website`",
                "- `Strukturpiloten/docker-lens`",
            ],
        )
        flattened = " ".join(instructions.split())
        for required in (
            "The primary manager always uses `gpt-6-sol` with `xhigh` reasoning",
            "reserve Astra at `xhigh` for particularly difficult architectural questions",
            "up to nine concurrent subagents plus the primary manager",
            "subject to the session's actual runtime limit",
            "Nine is a ceiling, not a target or nine distinct roles",
            "Do not create nested agents to evade the limit",
            "Never run two writers in one checkout",
            "at most one complete gate or heavy runtime suite at a time across this workspace",
            "Do not work on or modify any repository outside this explicit allowlist",
            "For user-requested work within this scope",
            "may create issues, branches, commits, pushes, and pull requests and merge verified "
            "task-related pull requests without asking for renewed approval",
            "does not authorize unrelated backlog work, implementation of "
            "discussion-only proposals",
            "A later user instruction may narrow or revoke this permission",
            "ready, mergeable, independently reviewed, and has every required check successful",
            "exact-head safeguard; never bypass branch protection or use an administrator override",
            "synchronize local `main` with `origin/main`",
            "does not authorize releases, publication, deployment operations, or "
            "merging release/publication/deployment pull requests",
            "Subagents remain within their assigned task and checkout "
            "and must not perform those writes",
        ):
            self.assertIn(required, flattened)
        for obsolete in (
            "Use at most three subagents",
            "does not authorize a merge",
            "Merge only when the user explicitly authorizes",
        ):
            self.assertNotIn(obsolete, flattened)
