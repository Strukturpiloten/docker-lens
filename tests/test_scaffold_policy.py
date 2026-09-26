"""Bounded bootstrap and release policy invariants."""

import json
import os
import re
import subprocess
import textwrap
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
        self.assertEqual(len(renovate["customManagers"]), 2)
        manager = renovate["customManagers"][0]
        self.assertEqual(manager["datasourceTemplate"], "github-tags")
        extractor = manager["matchStrings"][0].replace("(?<currentValue>", "(?P<currentValue>")
        self.assertRegex((ROOT / "rust-toolchain.toml").read_text(), extractor)
        native_manager = renovate["customManagers"][1]
        self.assertEqual(native_manager["managerFilePatterns"], ["/^scripts\\/native-conformance\\.sh$/"])
        native_extractor = re.sub(
            r"\(\?<(\w+)>", r"(?P<\1>", native_manager["matchStrings"][0]
        )
        native_script = (ROOT / "scripts/native-conformance.sh").read_text()
        pins = list(re.finditer(native_extractor, native_script))
        self.assertEqual(len(pins), 4)
        self.assertEqual({pin.group("datasource") for pin in pins}, {"docker"})
        self.assertEqual(
            {pin.group("currentValue") for pin in pins},
            {"28.5.1-dind", "28.5.1-dind-rootless", "11.11-slim", "1.37.0"},
        )
        self.assertTrue(all(re.fullmatch(r"sha256:[0-9a-f]{64}", pin.group("currentDigest")) for pin in pins))
        for package, revision in (
            ("DOCKER", "20.10.5+dfsg1-1+deb11u4"),
            ("CA_CERTIFICATES", "20250419~deb12u1~deb11u1"),
            ("ROOTLESSKIT", "0.14.2-1+b3"),
            ("SLIRP4NETNS", "1.0.1-2"),
            ("UIDMAP", "1:4.8.1-1+deb11u1"),
            ("FUSE_OVERLAYFS", "1.4.0-1"),
        ):
            self.assertIn(f"DEBIAN_{package}_PACKAGE='{revision}'", native_script)
        self.assertIn("manual check of these six pins before every native release", (ROOT / "docs/dependency-policy.md").read_text())
        self.assertEqual(native_script.count('"ca-certificates=$DEBIAN_CA_CERTIFICATES_PACKAGE"'), 4)
        self.assertIn('test -w /home/rootless', native_script)
        self.assertIn('test -w /run/user/1000', native_script)
        self.assertIn('rootless_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', native_script)
        self.assertIn('command -v dockerd', native_script)
        self.assertIn('/usr/bin/env PATH=$rootless_path XDG_RUNTIME_DIR=/run/user/1000', native_script)
        self.assertIn('chown -R rootless:rootless /home/rootless/.local/share/docker', native_script)
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
        self.assertIn("podman_cmd=(sudo -n podman)", native)
        self.assertIn('"${podman_cmd[@]}" volume rm "$volume"', native)
        self.assertIn("run-exact-native-test.sh\" acquisition live_read_only_acquisition_matches_oracle", native)
        self.assertIn("run-exact-native-test.sh\" native_target live_target_render_matches_engine", native)
        exact = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        self.assertIn("-- --ignored --list", exact)
        self.assertIn("1 passed; 0 failed; 0 ignored", exact)
        self.assertNotIn("system prune", native)
        self.assertNotIn("volume prune", native)

    def test_native_lanes_and_release_aggregate_remain_required(self) -> None:
        check = (ROOT / ".github/workflows/check.yml").read_text()
        release = (ROOT / ".github/workflows/release-validation.yml").read_text()
        lanes = "[debian11-rootful, debian11-rootless, upstream-rootful, upstream-rootless]"
        self.assertIn(lanes, check)
        self.assertIn(lanes, release)
        self.assertIn("needs: [scaffold, native-conformance]", check)
        native_job = check.split("  native-conformance:\n", 1)[1].split("  check-gate:\n", 1)[0]
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", native_job)
        self.assertEqual(check.count("./scripts/native-conformance.sh"), 1)
        self.assertNotIn("pull_request_target:", check)
        self.assertIn('test "$NATIVE_RESULT" = skipped', check)
        self.assertIn('test "$NATIVE_RESULT" = success', check)
        self.assertIn("fail-fast: false", release)
        self.assertIn("if: always()", release)
        self.assertIn("needs: [candidate, native-conformance]", release)
        self.assertIn('test "$NATIVE_RESULT" = success', release)
        self.assertIn('git fetch --no-tags origin main', release)

    def test_pr_gate_is_offline_only_and_main_requires_native(self) -> None:
        check = (ROOT / ".github/workflows/check.yml").read_text()
        gate = check.split("  check-gate:\n", 1)[1].split("        run: |\n", 1)[1]
        script = textwrap.dedent(gate)
        for scenario, event, ref, native, should_pass in (
            ("fork code", "pull_request", "refs/pull/1/merge", "skipped", True),
            ("same-repo code", "pull_request", "refs/pull/2/merge", "skipped", True),
            ("fork prose", "pull_request", "refs/pull/3/merge", "skipped", True),
            ("PR claimed native", "pull_request", "refs/pull/4/merge", "success", False),
            ("main native", "push", "refs/heads/main", "success", True),
            ("main skipped", "push", "refs/heads/main", "skipped", False),
            ("unknown push", "push", "refs/heads/other", "skipped", False),
        ):
            with self.subTest(scenario=scenario):
                env = dict(os.environ, EVENT_NAME=event, EVENT_REF=ref,
                           SCAFFOLD_RESULT="success", NATIVE_RESULT=native)
                result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], env=env,
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode == 0, should_pass)
                if event == "pull_request" and should_pass:
                    self.assertIn("offline-only", result.stdout)

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
