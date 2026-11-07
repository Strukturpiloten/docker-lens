"""Bounded bootstrap and release policy invariants."""

import json
import os
import re
import subprocess
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class ScaffoldPolicyTests(unittest.TestCase):
    def workflow_flow_list(self, source: str, key: str) -> list[str]:
        match = re.search(r"(?m)^\s*" + re.escape(key) + r":\s*(\[[^\]]*\])", source)
        self.assertIsNotNone(match, f"missing {key} flow-list")
        assert match is not None
        return [item.strip() for item in match[1][1:-1].split(",") if item.strip()]

    def test_rust_minimum_and_development_toolchain_contract(self) -> None:
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
        minimum = manifest["package"]["rust-version"]
        self.assertEqual(minimum, "1.98.1")
        self.assertEqual(manifest["package"]["edition"], "2024")
        self.assertRegex(minimum, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        channel = toolchain["toolchain"]["channel"]
        self.assertRegex(channel, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertGreaterEqual(tuple(map(int, channel.split("."))),
                                tuple(map(int, minimum.split("."))))
        self.assertTrue({"clippy", "rustfmt"}.issubset(toolchain["toolchain"]["components"]))
        # Clippy uses Cargo's rust-version unless an explicit override is added.
        for name in ("clippy.toml", ".clippy.toml"):
            path = ROOT / name
            if path.exists():
                config = tomllib.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(config.get("msrv", minimum), minimum)
        for name in ("README.md", "AGENTS.md", "docs/dependency-policy.md", "docs/verification.md"):
            with self.subTest(document=name):
                self.assertIn(f"Rust {minimum}", (ROOT / name).read_text(encoding="utf-8"))

    def test_release_gate_is_exact_candidate_and_native_required(self) -> None:
        workflow = (ROOT / ".github/workflows/release-validation.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"', workflow)
        self.assertIn('test "$(git rev-parse origin/main)" = "$EXPECTED_SHA"', workflow)
        self.assertIn("needs: candidate", workflow)
        self.assertIn("./scripts/native-conformance.sh", workflow)
        self.assertNotIn("continue-on-error", workflow)
        self.assertNotIn("cargo publish", workflow)
        api = workflow.split("  api:\n", 1)[1].split("  shared-release-gate:\n", 1)[0]
        self.assertIn("api_purpose: published", api)
        self.assertIn('release_type: ""', api)
        self.assertIn("PUBLISHED_API_CANDIDATE_SHA: ${{ needs.api.outputs.published_api_candidate_sha }}", workflow)
        self.assertIn('test "$PUBLISHED_API_CANDIDATE_SHA" = "$EXPECTED_SHA"', workflow)

    def assert_action_reference(self, action: str, *, nested: bool = False) -> None:
        if not nested and action in {
            "./.github/actions/setup-node",
            "./source/.github/actions/setup-node",
        }:
            composite = (ROOT / ".github/actions/setup-node/action.yml").read_text()
            references = re.findall(r"(?m)^\s*(?:- )?uses: (.+)", composite)
            self.assertTrue(references, "the owned composite must retain its pinned external Action")
            for reference in references:
                self.assert_action_reference(reference, nested=True)
        elif not nested and action.startswith("./_automation/.github/actions/"):
            self.assertIn(action, {
                "./_automation/.github/actions/shared-source",
                "./_automation/.github/actions/shared-python",
            })
        elif not nested and action.startswith("Strukturpiloten/boxferry/.github/workflows/shared-"):
            self.assertRegex(action, r"^Strukturpiloten/boxferry/\.github/workflows/shared-[a-z-]+\.yml@[0-9a-f]{40} # automation-v1 interface v1$")
        else:
            self.assertFalse(action.startswith("./"), "unknown local Action path")
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$")

    def test_only_owned_local_composites_can_expand_to_pinned_actions(self) -> None:
        for action in ("./.github/actions/setup-node", "./source/.github/actions/setup-node"):
            self.assert_action_reference(action)
        invalid = (
            "./.github/actions/unknown",
            "./source/.github/actions/setup-node-extra",
            "./.github/actions/setup-node@" + "a" * 40 + " # v7.1.0",
            "actions/setup-node@main # v7.1.0",
            "actions/setup-node@" + "a" * 40,
        )
        for action in invalid:
            with self.subTest(action=action), self.assertRaises(AssertionError):
                self.assert_action_reference(action)
        for action in ("actions/setup-node@main # v7.1.0", "./_automation/.github/actions/shared-python"):
            with patch.object(Path, "read_text", return_value="  - uses: " + action), self.assertRaises(AssertionError):
                self.assert_action_reference("./.github/actions/setup-node")

    def test_action_pins_and_renovate_ownership(self) -> None:
        renovate = json.loads((ROOT / "renovate.json").read_text())
        self.assertEqual(renovate["enabledManagers"],
                         ["cargo", "github-actions", "rust-toolchain", "custom.regex"])
        self.assertEqual(len(renovate["customManagers"]), 1)
        self.assertEqual(len(renovate["extends"]), 2)
        for reference in renovate["extends"]:
            self.assertRegex(reference, r"^github>Strukturpiloten/boxferry//renovate-presets/(common|rust)#[0-9a-f]{40}$")
        native_manager = renovate["customManagers"][0]
        self.assertEqual(native_manager["managerFilePatterns"], ["/^scripts\\/native-conformance\\.sh$/"])
        native_extractor = re.sub(
            r"\(\?<(\w+)>", r"(?P<\1>", native_manager["matchStrings"][0]
        )
        native_script = (ROOT / "scripts/native-conformance.sh").read_text()
        pins = list(re.finditer(native_extractor, native_script))
        self.assertEqual(len(pins), 5)
        self.assertEqual({pin.group("datasource") for pin in pins}, {"docker"})
        self.assertEqual(
            {pin.group("depName") for pin in pins},
            {
                "ghcr.io/strukturpiloten/docker-debian-11-rootful",
                "ghcr.io/strukturpiloten/docker-debian-11-rootless",
                "ghcr.io/strukturpiloten/docker-29-rootful",
                "ghcr.io/strukturpiloten/docker-29-rootless",
                "docker.io/library/busybox",
            },
        )
        self.assertEqual(
            {pin.group("currentValue") for pin in pins},
            {"v1.0.0", "v29.8.1", "1.37.0"},
        )
        self.assertTrue(all(re.fullmatch(r"sha256:[0-9a-f]{64}", pin.group("currentDigest")) for pin in pins))
        self.assertIn("DEBIAN_DOCKER_PACKAGE='20.10.5+dfsg1-1+deb11u2'", native_script)
        self.assertIn("--image-volume=ignore", native_script)
        self.assertIn("--oom-score-adj=0", native_script)
        self.assertIn("start=(/usr/local/bin/start-dockerd", native_script)
        self.assertNotIn("apt-get", native_script)
        self.assertNotIn("native-apt-install.sh", native_script)
        self.assertNotIn("native-debian-snapshot.sh", native_script)
        self.assertIn('"$volume" >/dev/null', native_script)
        self.assertIn('"$volume"', native_script)
        self.assertIn("five distinct version-tag", (ROOT / "docs/dependency-policy.md").read_text())
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            for action in re.findall(r"(?m)^\s*(?:- )?uses: (.+)", workflow.read_text()):
                self.assert_action_reference(action)
        for name in ("check.yml", "release-validation.yml", "native-validation.yml"):
            workflow = (ROOT / ".github/workflows" / name).read_text()
            self.assertIn("name: dockerlens-native-${{ matrix.lane }}", workflow)
            self.assertIn("if-no-files-found: error", workflow)
            self.assertIn("DOCKERLENS_NATIVE_CANDIDATE_SHA:", workflow)

    def test_scripts_have_distinct_scope(self) -> None:
        fast = (ROOT / "scripts/format-lint.sh").read_text()
        complete = (ROOT / "scripts/check-all.sh").read_text()
        native = (ROOT / "scripts/native-conformance.sh").read_text()
        self.assertNotIn("cargo test", fast)
        self.assertIn("cargo test --all-targets --locked", complete)
        self.assertIn("scripts/validation-plan.py run --task documentation", complete)
        self.assertIn("scripts/validation-plan.py run --task api-development", complete)
        self.assertNotIn("cargo semver-checks", complete)
        api = (ROOT / ".github/workflows/check.yml").read_text().split("  api:\n", 1)[1].split("  documentation:\n", 1)[0]
        self.assertIn("api_purpose: development", api)
        self.assertIn("initial_api_contract: false", api)
        self.assertIn("exit 1", native)
        self.assertIn("podman_cmd=(sudo -n podman)", native)
        self.assertIn('timeout --signal=TERM --kill-after=2s 8s "${podman_cmd[@]}" "$@"', native)
        self.assertIn('"${podman_cmd[@]:0:2}" timeout --signal=TERM --kill-after=2s 8s "${podman_cmd[@]:2}" "$@"', native)
        for owned_cleanup in (
            'cleanup_container "$container" container "$outer_container_id" "$outer_attempted"',
            'cleanup_container "$sidecar" sidecar "$sidecar_container_id" "$sidecar_attempted"',
            'cleanup_remove "$role" rm --force --time 0 "$id"',
            'cleanup_remove network network rm "$outer_network"',
            'cleanup_remove volume volume rm "$volume"',
        ):
            self.assertIn(owned_cleanup, native)
        self.assertNotIn('cleanup_remove "$role" rm --force --time 0 "$name"', native)
        self.assertIn("run-exact-native-test.sh\" acquisition live_read_only_acquisition_matches_oracle", native)
        self.assertIn("run-exact-native-test.sh\" native_target live_target_render_matches_engine", native)
        exact = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        self.assertIn("-- --ignored --list", exact)
        self.assertIn("1 passed; 0 failed; 0 ignored", exact)
        self.assertNotIn("system prune", native)
        self.assertNotIn("volume prune", native)

    def test_complete_gate_checks_declared_msrv_and_propagates_failure(self) -> None:
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        minimum = manifest["package"]["rust-version"]
        complete = (ROOT / "scripts/check-all.sh").read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", complete)
        self.assertIn('\n"$(dirname "$0")/check-msrv.sh"\n', complete)
        self.assertLess(complete.index("check-msrv.sh"), complete.index("cargo test --all-targets"))
        for workflow in ("native-validation.yml", "release-validation.yml"):
            self.assertIn("./scripts/check-all.sh --check",
                          (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "rustup"
            trace = Path(temporary) / "trace"
            cargo_trace = Path(temporary) / "cargo-trace"
            fake.write_text("#!/usr/bin/env bash\n"
                            "printf '%s\\n' \"$*\" >> \"$MSRV_TRACE\"\n"
                            "if [[ $1 == run ]]; then exit 37; fi\n", encoding="utf-8")
            fake.chmod(0o755)
            cargo = Path(temporary) / "cargo"
            cargo.write_text("#!/usr/bin/env bash\n"
                             "printf '%s\\n' \"$*\" >> \"$CARGO_TRACE\"\n", encoding="utf-8")
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=f"{temporary}:{os.environ['PATH']}",
                       MSRV_TRACE=str(trace), CARGO_TRACE=str(cargo_trace))
            result = subprocess.run([str(ROOT / "scripts/check-all.sh"), "--check"], env=env,
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 37)
            self.assertEqual(trace.read_text(encoding="utf-8").splitlines(), [
                f"toolchain install {minimum} --profile minimal --no-self-update",
                f"run {minimum} cargo check --all-targets --locked",
            ])
            self.assertEqual(cargo_trace.read_text(encoding="utf-8").splitlines(), [
                "fmt --all -- --check", "clippy --all-targets --locked -- -D warnings",
            ])

    def test_msrv_check_uses_manifest_and_refuses_invalid_or_failed_toolchains(self) -> None:
        script = (ROOT / "scripts/check-msrv.sh").read_text(encoding="utf-8")
        for minimum, install_exit, run_exit, expected_exit, expected_calls in (
            ("1.99.2", 0, 0, 0, 2),
            ("1.99.2", 31, 0, 31, 1),
            ("1.99.2", 0, 37, 37, 2),
            ("1.98", 0, 0, 1, 0),
            ("stable", 0, 0, 1, 0),
        ):
            with self.subTest(minimum=minimum, install_exit=install_exit, run_exit=run_exit):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    scripts = root / "scripts"
                    scripts.mkdir()
                    check = scripts / "check-msrv.sh"
                    check.write_text(script, encoding="utf-8")
                    (root / "Cargo.toml").write_text(
                        f'[package]\nrust-version = "{minimum}"\n', encoding="utf-8")
                    trace = root / "trace"
                    rustup = root / "rustup"
                    rustup.write_text(
                        '#!/usr/bin/env bash\n'
                        'printf \'%s\\n\' "$*" >> "$MSRV_TRACE"\n'
                        'if [[ $1 == toolchain ]]; then exit "$INSTALL_EXIT"; fi\n'
                        'exit "$RUN_EXIT"\n', encoding="utf-8")
                    rustup.chmod(0o755)
                    env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                               MSRV_TRACE=str(trace), INSTALL_EXIT=str(install_exit),
                               RUN_EXIT=str(run_exit))
                    result = subprocess.run(["bash", str(check)], env=env,
                                            capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, expected_exit)
                    calls = trace.read_text(encoding="utf-8").splitlines() if trace.exists() else []
                    self.assertEqual(calls, [
                        f"toolchain install {minimum} --profile minimal --no-self-update",
                        f"run {minimum} cargo check --all-targets --locked",
                    ][:expected_calls])
                    if expected_calls == 0:
                        self.assertIn("must be an exact Rust release", result.stderr)

    def test_native_lanes_and_release_aggregate_remain_required(self) -> None:
        check = (ROOT / ".github/workflows/check.yml").read_text()
        release = (ROOT / ".github/workflows/release-validation.yml").read_text()
        expected_lanes = ["debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"]
        self.assertEqual(self.workflow_flow_list(check, "lane"), expected_lanes)
        self.assertEqual(self.workflow_flow_list(release, "lane"), expected_lanes)
        self.assertEqual(self.workflow_flow_list(check.split("  check-gate:\n", 1)[1], "needs"),
                         ["validation-plan", "rust", "msrv", "dependencies", "api", "documentation",
                          "lockfile-release-age", "native-conformance"])
        native_job = check.split("  native-conformance:\n", 1)[1].split("  check-gate:\n", 1)[0]
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", native_job)
        self.assertEqual(check.count("./scripts/native-conformance.sh"), 1)
        self.assertNotIn("pull_request_target:", check)
        self.assertIn('test "$NATIVE_RESULT" = skipped', check)
        self.assertIn('test "$NATIVE_RESULT" = success', check)
        self.assertIn("fail-fast: false", release)
        self.assertIn("if: always()", release)
        self.assertEqual(self.workflow_flow_list(release.split("  release-gate:\n", 1)[1], "needs"),
                         ["candidate", "native-conformance", "dependencies", "api", "shared-release-gate"])
        self.assertIn('test "$NATIVE_RESULT" = success', release)
        self.assertIn('git fetch --no-tags origin main', release)

    def test_hosted_diagnostic_dispatch_is_closed_and_does_not_replace_required_ci(self) -> None:
        check = (ROOT / ".github/workflows/check.yml").read_text()
        diagnostic = check.split("  hosted-prerequisite-diagnostic:\n", 1)[1].split("  validation-plan:\n", 1)[0]
        scaffold = check.split("  validation-plan:\n", 1)[1].split("  native-conformance:\n", 1)[0]
        aggregate = check.split("  check-gate:\n", 1)[1]
        self.assertIn("  workflow_dispatch:\n", check)
        self.assertNotIn("inputs:", check)
        self.assertIn("if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'", diagnostic)
        self.assertIn("ref: ${{ github.sha }}", diagnostic)
        self.assertIn("persist-credentials: false", diagnostic)
        self.assertIn("timeout-minutes: 5", diagnostic)
        self.assertIn("--kill-after=2s 55s python3 -B scripts/native-outer-runtime-profile.py", diagnostic)
        self.assertIn("set -o noclobber", diagnostic)
        self.assertIn("umask 077", diagnostic)
        self.assertIn("dockerlens-hosted-prerequisite.json", diagnostic)
        self.assertIn("if-no-files-found: error", diagnostic)
        self.assertNotIn("sudo", diagnostic)
        self.assertNotIn("native-conformance.sh", diagnostic)
        self.assertNotIn("check-all.sh", diagnostic)
        self.assertNotIn("continue-on-error", diagnostic)
        self.assertIn("if: github.event_name != 'workflow_dispatch'", scaffold)
        self.assertIn("name: Required CI\n", aggregate)
        self.assertIn("if: always() && !(github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main')", aggregate)
        self.assertEqual(self.workflow_flow_list(aggregate, "needs"),
                         ["validation-plan", "rust", "msrv", "dependencies", "api", "documentation",
                          "lockfile-release-age", "native-conformance"])
        self.assertEqual(check.count("name: Required CI"), 1)
        self.assertIn("permissions:\n  contents: read", check)
        self.assertNotIn("write", check)
        for name in ("native-validation.yml", "release-validation.yml"):
            self.assertNotIn("native-outer-runtime-profile.py", (ROOT / ".github/workflows" / name).read_text())

    def test_hosted_diagnostic_event_ref_job_selection(self) -> None:
        workflow = (ROOT / ".github/workflows/check.yml").read_text()
        job_names = ("hosted-prerequisite-diagnostic", "validation-plan", "native-conformance", "check-gate")
        conditions = {}
        for name in job_names:
            body = workflow.split("  " + name + ":\n", 1)[1]
            body = re.split(r"\n  [a-z][a-z-]*:\n", body, maxsplit=1)[0]
            conditions[name] = re.search(r"^    if: (.+)$", body, re.MULTILINE).group(1)
        for event, ref, expected in (
            ("workflow_dispatch", "refs/heads/main", (True, False, False, False)),
            ("workflow_dispatch", "refs/heads/feature", (False, False, False, True)),
            ("pull_request", "refs/pull/1/merge", (False, True, False, True)),
            ("merge_group", "refs/heads/gh-readonly-queue/main/pr-1", (False, True, False, True)),
            ("push", "refs/heads/main", (False, True, True, True)),
            ("push", "refs/heads/feature", (False, True, False, True)),
        ):
            with self.subTest(event=event, ref=ref):
                actual = []
                for name in job_names:
                    # These closed job predicates use the shared boolean/string
                    # subset of Actions expressions and Bash conditional syntax.
                    expression = (conditions[name].replace("github.event_name", '"$EVENT_NAME"')
                                  .replace("github.ref", '"$EVENT_REF"')
                                  .replace("always()", "true").replace("!(", "! ("))
                    result = subprocess.run(["bash", "-c", "[[ " + expression + " ]]"],
                                            env=dict(os.environ, EVENT_NAME=event, EVENT_REF=ref),
                                            capture_output=True, text=True, check=False)
                    self.assertIn(result.returncode, (0, 1), result.stderr)
                    actual.append(result.returncode == 0)
                self.assertEqual(tuple(actual), expected)

    def test_diagnostic_pins_have_existing_unique_renovate_ownership(self) -> None:
        workflow = (ROOT / ".github/workflows/check.yml").read_text()
        canonical = (ROOT / ".github/workflows/native-validation.yml").read_text()
        configuration = (ROOT / "renovate.json").read_text()

        def check_pins(workflow: str, canonical: str, configuration: str) -> tuple[str, str]:
            renovate = json.loads(configuration)
            self.assertEqual(renovate["enabledManagers"].count("github-actions"), 1)
            self.assertEqual(len(renovate["customManagers"]), 1)
            self.assertEqual(
                renovate["customManagers"][0]["managerFilePatterns"],
                [r"/^scripts\/native-conformance\.sh$/"],
            )
            # Local manual native-image rules cannot override inherited Action policy.
            for rule in renovate["packageRules"]:
                self.assertEqual(rule["matchManagers"], ["custom.regex"])
                self.assertEqual(rule["matchFileNames"], ["scripts/native-conformance.sh"])
                self.assertNotIn("automerge", rule)
                self.assertNotIn("dependencyDashboardApproval", rule)

            references = re.findall(r"(?m)^\s*(?:- )?uses: (.+)$", canonical)
            expected = []
            for action in ("actions/checkout", "actions/upload-artifact"):
                pins = [ref for ref in references if ref.split("@", 1)[0] == action]
                self.assertTrue(pins, f"canonical native workflow must declare {action}")
                for pin in pins:
                    self.assert_action_reference(pin)
                self.assertEqual(len(set(pins)), 1, f"conflicting canonical {action} pins")
                expected.append(pins[0])
            diagnostic = workflow.split("  hosted-prerequisite-diagnostic:\n", 1)[1].split(
                "  validation-plan:\n", 1
            )[0]
            self.assertEqual(re.findall(r"uses: (.+)", diagnostic), expected)
            return expected[0], expected[1]

        checkout, artifact = check_pins(workflow, canonical, configuration)
        # A coherent Renovate upgrade changes declarations, not a version literal in this test.
        updated_checkout = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0"
        check_pins(
            workflow.replace(checkout, updated_checkout),
            canonical.replace(checkout, updated_checkout),
            configuration,
        )
        digest = checkout.split("@", 1)[1].split(" ", 1)[0]
        other_digest = ("0" if digest[0] != "0" else "1") + digest[1:]
        other_checkout = "actions/checkout@" + other_digest + " # v99.0.0"
        mutations = [
            (
                "diagnostic divergence",
                workflow.replace(checkout, other_checkout),
                canonical,
                configuration,
            ),
            (
                "missing canonical declaration",
                workflow,
                canonical.replace("uses: " + checkout, "run: true"),
                configuration,
            ),
            (
                "conflicting canonical pins",
                workflow,
                canonical.replace(checkout, other_checkout, 1),
                configuration,
            ),
            (
                "unexpected diagnostic Action",
                workflow.replace(
                    artifact, artifact + "\n      - uses: actions/cache@" + "a" * 40 + " # v1.2.3"
                ),
                canonical,
                configuration,
            ),
        ]
        for invalid in (
            "actions/checkout@main # v4.4.0",
            "actions/checkout@" + "a" * 39 + " # v4.4.0",
            "actions/checkout@" + "a" * 40,
            "actions/checkout@" + "a" * 40 + " # v4.4",
        ):
            mutations.append(
                (
                    invalid,
                    workflow.replace(checkout, invalid),
                    canonical.replace(checkout, invalid),
                    configuration,
                )
            )
        action_extractor = (
            r"uses: (?<depName>actions/checkout)@(?<currentDigest>[0-9a-f]{40})"
            r" # (?<currentValue>v[0-9]+\.[0-9]+\.[0-9]+)"
        )
        for mutation in (
            "missing manager",
            "duplicate manager",
            "overlapping custom owner",
            "duplicate custom owner",
            "Action group override",
            "Action approval override",
        ):
            changed = json.loads(configuration)
            if mutation == "missing manager":
                changed["enabledManagers"].remove("github-actions")
            elif mutation == "duplicate manager":
                changed["enabledManagers"].append("github-actions")
            elif mutation == "overlapping custom owner":
                changed["customManagers"][0]["managerFilePatterns"].append(
                    "/^\\.github/workflows/check\\.yml$/"
                )
                changed["customManagers"][0]["matchStrings"].append(action_extractor)
                changed["customManagers"][0]["datasourceTemplate"] = "github-tags"
            elif mutation == "duplicate custom owner":
                changed["customManagers"].append(
                    {
                        "customType": "regex",
                        "datasourceTemplate": "github-tags",
                        "managerFilePatterns": ["/^\\.github/workflows/check\\.yml$/"],
                        "matchStrings": [action_extractor],
                    }
                )
            else:
                field = (
                    "groupName"
                    if mutation == "Action group override"
                    else "dependencyDashboardApproval"
                )
                changed["packageRules"].append(
                    {
                        "matchManagers": ["github-actions"],
                        field: "unreviewed group" if field == "groupName" else True,
                    }
                )
            mutations.append((mutation, workflow, canonical, json.dumps(changed)))
        for label, changed_workflow, changed_canonical, changed_configuration in mutations:
            with self.subTest(mutation=label), self.assertRaises(AssertionError):
                check_pins(changed_workflow, changed_canonical, changed_configuration)
        self.assertEqual(
            len(
                [
                    name
                    for name in (ROOT / ".github/workflows").glob("*.yml")
                    if "native-outer-runtime-profile.py" in name.read_text()
                ]
            ),
            1,
        )

    def test_pr_gate_is_offline_only_and_main_requires_native(self) -> None:
        check = (ROOT / ".github/workflows/check.yml").read_text()
        gate = check.split("      - name: Fail on skipped, cancelled, or failed validation\n", 1)[1].split("        run: |\n", 1)[1]
        script = textwrap.dedent(gate)
        for scenario, event, ref, native, should_pass in (
            ("fork code", "pull_request", "refs/pull/1/merge", "skipped", True),
            ("same-repo code", "pull_request", "refs/pull/2/merge", "skipped", True),
            ("fork prose", "pull_request", "refs/pull/3/merge", "skipped", True),
            ("PR claimed native", "pull_request", "refs/pull/4/merge", "success", False),
            ("main native", "push", "refs/heads/main", "success", True),
            ("main skipped", "push", "refs/heads/main", "skipped", False),
            ("unknown push", "push", "refs/heads/other", "skipped", False),
            ("non-main diagnostic", "workflow_dispatch", "refs/heads/feature", "skipped", False),
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
        self.assertEqual(self.workflow_flow_list(native_job, "lane"), [
            "debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless",
        ])
        self.assertNotIn("cargo publish", workflow)
        self.assertNotIn("gh release", workflow)
        self.assertIn("A draft PR stays unmergeable during validation", (ROOT / "docs/verification.md").read_text())


    def test_native_lane_order_and_membership_survive_only_format_changes(self) -> None:
        expected = ["debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"]
        for source in ("lane: [" + ", ".join(expected) + "]", "lane:\n  [\n    " + ",\n    ".join(expected) + ",\n  ]"):
            self.assertEqual(self.workflow_flow_list(source, "lane"), expected)
        for changed in (expected[:-1], list(reversed(expected)), [*expected, "unreviewed"]):
            self.assertNotEqual(self.workflow_flow_list("lane: [" + ", ".join(changed) + "]", "lane"), expected)


if __name__ == "__main__":
    unittest.main()
