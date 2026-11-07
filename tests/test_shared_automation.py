"""DockerLens-specific selection, admission, release and native-owner regressions."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import patch

import boxferry_ci
from boxferry_ci import eligibility, planner
from boxferry_ci.contracts import ContractError
from boxferry_ci.gate import GateFailure, verify_gate
from boxferry_ci.policy import load_policy
from boxferry_ci.release import ReleaseError
from boxferry_ci.release import load_policy as load_release
from boxferry_ci.release import verify_gate as verify_release

ROOT = Path(__file__).resolve().parents[1]
SHARED = Path(boxferry_ci.__file__).resolve().parents[3]
SHA = "a" * 40


class SharedAutomationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy(ROOT / "scripts/validation-policy.json")

    def classify(self, paths: list[str]) -> tuple[str, ...]:
        comparison = planner.Comparison("pull_request", "a" * 40, "b" * 40, "c" * 40)
        with (
            patch.object(planner, "changes_between", return_value=[("M", (p,)) for p in paths]),
            patch.object(planner, "regular_contents", return_value=b"# Plain prose\n"),
        ):
            return planner.classify(ROOT, comparison, self.policy)[0]

    def test_prose_targeted_tests_mixed_unknown_policy_and_main_selection(self) -> None:
        for paths, expected in (
            (["docs/guide.md"], ("prose",)),
            (["tests/decoder.rs"], ("rust-tests",)),
            (["docs/guide.md", "tests/decoder.rs"], ("prose", "rust-tests")),
            (["src/lib.rs"], ("full",)),
            (["docs/evidence/new.md"], ("full",)),
            (["scripts/validation-policy.json"], ("full",)),
            (["unknown.file"], ("full",)),
        ):
            with self.subTest(paths=paths):
                self.assertEqual(self.classify(paths), expected)
        for event in ("push", "workflow_dispatch", "workflow_call"):
            plan = planner.make_plan(ROOT, self.policy, event=event, tested_sha=SHA)
            self.assertEqual(plan["profile"], "full")
            jobs = plan["jobs"]
            assert isinstance(jobs, dict)
            self.assertTrue(all(jobs.values()))
        self.assertEqual(
            self.policy.selected_jobs(("rust-tests",)),
            {"rust", "documentation", "lockfile-release-age"},
        )

    def test_aggregate_rejects_failed_cancelled_missing_and_unexpected_skips(self) -> None:
        plan = planner.make_plan(ROOT, self.policy, event="push", tested_sha=SHA)
        comparison = planner.Comparison("push", SHA, SHA, SHA)
        needs = {job: {"result": "success"} for job in ("validation-plan", *self.policy.jobs)}
        verify_gate(plan, needs, self.policy, comparison, expected_plan=plan)
        for job in self.policy.jobs:
            for result in ("failure", "cancelled", "skipped"):
                candidate = deepcopy(needs)
                candidate[job]["result"] = result
                with self.subTest(job=job, result=result), self.assertRaises(GateFailure):
                    verify_gate(plan, candidate, self.policy, comparison, expected_plan=plan)
        with self.assertRaises(ContractError):
            verify_gate(plan, {}, self.policy, comparison, expected_plan=plan)
        narrowed = deepcopy(plan)
        narrowed.update(event="pull_request", profile="prose", profiles=["prose"])
        narrowed["jobs"] = {job: job == "documentation" for job in self.policy.jobs}
        intended = {
            job: {"result": "success" if job in {"validation-plan", "documentation"} else "skipped"}
            for job in needs
        }
        verify_gate(
            narrowed,
            intended,
            self.policy,
            planner.Comparison("pull_request", SHA, SHA, SHA),
            expected_plan=narrowed,
        )

    def assert_shared_pin_identity(
        self,
        manifest: dict[str, object],
        renovate: dict[str, object],
        workflows: dict[str, str],
    ) -> None:
        revision = manifest["revision"]
        self.assertIsInstance(revision, str)
        assert isinstance(revision, str)
        self.assertRegex(revision, r"^[a-f0-9]{40}$")
        self.assertEqual(
            renovate["extends"],
            [
                f"github>Strukturpiloten/boxferry//renovate-presets/{name}#{revision}"
                for name in ("common", "rust")
            ],
        )

        def one_pin(source: str, field: str, label: str) -> None:
            values = re.findall(rf"(?m)^\s*{field}:\s*([^\s#]+)", source)
            self.assertEqual([value.strip("\"'") for value in values], [revision], label)

        calls_found = 0
        for filename, source in workflows.items():
            jobs = re.findall(r"(?ms)^  [\w-]+:\n.*?(?=^  [\w-]+:\n|\Z)", source)
            for job in jobs:
                calls = re.findall(
                    r"Strukturpiloten/boxferry/\.github/workflows/shared-[a-z-]+\.yml@([^\s]+)",
                    job,
                )
                if calls or re.search(r"(?m)^      automation[_-]sha:", job):
                    self.assertEqual(calls, [revision], filename)
                    field = (
                        "automation-sha"
                        if "shared-dependency-eligibility.yml@" in job
                        else "automation_sha"
                    )
                    one_pin(job, field, filename)
                    one_pin(job, "automation[_-]sha", filename)
                    calls_found += 1
            steps = re.findall(r"(?ms)^      - .*?(?=^      - |^  [\w-]+:\n|\Z)", source)
            for step in steps:
                if re.search(r"(?m)^\s+repository: Strukturpiloten/boxferry\s*$", step):
                    one_pin(step, "ref", filename)
                    self.assertEqual(
                        step.count(
                            "# renovate: datasource=github-digest depName=Strukturpiloten/boxferry "
                            "currentValue=automation-v1"
                        ),
                        1,
                        filename,
                    )
                if "./_automation/.github/actions/shared-source" in step or re.search(
                    r"(?m)^\s+automation-sha:", step
                ):
                    self.assertEqual(step.count("./_automation/.github/actions/shared-source"), 1)
                    one_pin(step, "automation-sha", filename)
                if "${AUTOMATION_SHA}" in step or re.search(r"(?m)^\s+AUTOMATION_SHA:", step):
                    one_pin(step, "AUTOMATION_SHA", filename)
        self.assertGreater(calls_found, 0, "shared reusable calls must not disappear")

    def test_shared_pin_coupling_rejects_each_independent_drift_or_missing_owner(self) -> None:
        manifest = json.loads((ROOT / ".github/automation.json").read_text())
        renovate = json.loads((ROOT / "renovate.json").read_text())
        workflows = {
            path.name: path.read_text() for path in (ROOT / ".github/workflows").glob("*.yml")
        }
        revision = manifest["revision"]
        other = ("a" if revision != "a" * 40 else "b") * 40
        self.assert_shared_pin_identity(manifest, renovate, workflows)
        for index in (0, 1):
            for replacement in (other, "main"):
                proposed = deepcopy(renovate)
                proposed["extends"][index] = proposed["extends"][index].replace(
                    revision, replacement
                )
                with (
                    self.subTest(preset=index, replacement=replacement),
                    self.assertRaises(AssertionError),
                ):
                    self.assert_shared_pin_identity(manifest, proposed, workflows)
            for owners in (
                [value for position, value in enumerate(renovate["extends"]) if position != index],
                [*renovate["extends"], renovate["extends"][index]],
            ):
                with self.subTest(preset=index, owners=owners), self.assertRaises(AssertionError):
                    self.assert_shared_pin_identity(
                        manifest, {**renovate, "extends": owners}, workflows
                    )
        source = workflows["check.yml"]
        for pattern in (
            r"(?m)^    uses: Strukturpiloten/boxferry/\.github/workflows/shared-[a-z-]+\.yml@[^\n]+$",
            r"(?m)^      automation_sha: [^\n]+$",
            r"(?m)^          automation-sha: [^\n]+$",
            r"(?m)^          AUTOMATION_SHA: [^\n]+$",
            r"(?m)^          ref: " + revision + r"$",
        ):
            match = re.search(pattern, source)
            assert match is not None, pattern
            original = match[0]
            for replacement in (original.replace(revision, other), "", original + "\n" + original):
                proposed = {**workflows, "check.yml": source.replace(original, replacement, 1)}
                with (
                    self.subTest(pattern=pattern, replacement=replacement),
                    self.assertRaises(AssertionError),
                ):
                    self.assert_shared_pin_identity(manifest, renovate, proposed)

        service = workflows["dependency-eligibility.yml"]
        match = re.search(r"(?m)^      automation-sha: [^\n]+$", service)
        assert match is not None
        original = match[0]
        for replacement in (
            original.replace(revision, other),
            original.replace(revision, "main"),
            "",
            original + "\n" + original,
            original + "\n" + original.replace("automation-sha", "automation_sha"),
        ):
            proposed = {
                **workflows,
                "dependency-eligibility.yml": service.replace(original, replacement, 1),
            }
            with self.subTest(service=replacement), self.assertRaises(AssertionError):
                self.assert_shared_pin_identity(manifest, renovate, proposed)
        self.assert_shared_pin_identity(
            {**manifest, "revision": other},
            {
                **renovate,
                "extends": [value.replace(revision, other) for value in renovate["extends"]],
            },
            {name: source.replace(revision, other) for name, source in workflows.items()},
        )

    def test_stable_frontloader_and_all_shared_pins_are_one_immutable_identity(self) -> None:
        manifest = json.loads((ROOT / ".github/automation.json").read_text())
        self.assertRegex(manifest["revision"], r"^[a-f0-9]{40}$")
        self.assertEqual(manifest["repository"], "Strukturpiloten/boxferry")
        self.assertEqual(manifest["interface"], 1)
        self.assert_shared_pin_identity(
            manifest,
            json.loads((ROOT / "renovate.json").read_text()),
            {path.name: path.read_text() for path in (ROOT / ".github/workflows").glob("*.yml")},
        )
        service = (ROOT / ".github/workflows/dependency-eligibility.yml").read_text()
        self.assertIn("workflows: [Check]", service)
        self.assertIn("cancel-in-progress: false", service)
        check = (ROOT / ".github/workflows/check.yml").read_text()
        self.assertEqual(check.count("name: Required CI"), 1)
        self.assertIn(
            "group: check-${{ github.event_name == 'workflow_dispatch' && 'diagnostic' || 'validation' }}-${{ github.ref }}",
            check,
        )
        self.assertNotIn("contents: write", check)
        self.assertNotIn("statuses: write", check)
        self.assertIn("shared-dependency-wait.yml@", check)
        self.assertIn(
            "github.event.pull_request.base.sha || github.event.merge_group.base_sha", check
        )
        self.assertIn("--needs-json", check)
        self.assertNotIn("initial_api_contract: true", check)

    def test_shared_source_upgrade_retry_owns_every_caller_pin(self) -> None:
        before = (ROOT / ".github/workflows/check.yml").read_bytes()
        current = json.loads((ROOT / ".github/automation.json").read_text())["revision"]
        next_source = "b" * 40
        proposed = before.replace(current.encode(), next_source.encode())
        self.assertEqual(eligibility.expected_ci_upgrade(before, current, next_source), proposed)

    def test_interface_one_loader_delegates_raw_argv_and_labels_development_override(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "dockerlens_frontloader", ROOT / "scripts/validation-plan.py"
        )
        assert spec is not None and spec.loader is not None
        loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loader)
        manifest = loader.load_config(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            project = base / "automation"
            bootstrap = project / "src/boxferry_ci/bootstrap.py"
            bootstrap.parent.mkdir(parents=True)
            (project / "pyproject.toml").write_text("[project]\nname='fixture'\n")
            (project / "uv.lock").write_text("version = 1\n")
            record = base / "argv.json"
            bootstrap.write_text(
                "import json\nfrom pathlib import Path\n"
                "def run_project(root, project, arguments):\n"
                f"    Path({str(record)!r}).write_text(json.dumps(arguments))\n"
                "    return 39\n",
            )
            raw = ["future-command", "--candidate-sha", "b" * 40, "--event", "merge_group"]
            with patch.object(loader, "prepare_implementation", return_value=project) as prepare:
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(loader.main(raw), 39)
                prepare.assert_called_once_with(ROOT, manifest["revision"])
            self.assertEqual(json.loads(record.read_text()), raw)
            captured = io.StringIO()
            with contextlib.redirect_stderr(captured):
                self.assertEqual(loader.main(["--implementation-checkout", str(base), *raw]), 39)
            self.assertIn("mutable development implementation override", captured.getvalue())
            self.assertEqual(json.loads(record.read_text()), raw)

    def test_actual_prose_documentation_task_is_cold_without_node_or_candidate_caches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            candidate = base / "source"
            shared = base / "_automation"
            binary = base / "bin"
            startup = base / "startup"
            for directory in (
                candidate / "scripts",
                candidate / ".github",
                candidate / "tests",
                binary,
                startup,
            ):
                directory.mkdir(parents=True)
            for name in (
                "scripts/setup-ci-tools.py",
                "scripts/validation-policy.json",
                ".github/automation.json",
            ):
                shutil.copyfile(ROOT / name, candidate / name)
            shutil.copyfile(Path(__file__), candidate / "tests/shared_node_contract.py")
            shutil.copytree(
                SHARED / "automation",
                shared / "automation",
                ignore=shutil.ignore_patterns(".venv", "__pycache__", ".ruff_cache"),
            )
            (shared / ".devcontainer").mkdir()
            shutil.copyfile(
                SHARED / ".devcontainer/Dockerfile", shared / ".devcontainer/Dockerfile"
            )
            entry = candidate / "tests/test_prose_phase.py"
            entry.write_text(
                textwrap.dedent("""\
                import unittest
                import shared_node_contract as contracts
                from boxferry_ci import bootstrap, renovate_runtime, tooling
                def forbidden(*args, **kwargs):
                    raise AssertionError("cold prose attempted tool or runtime acquisition")
                bootstrap.prepare_implementation = forbidden
                renovate_runtime.prepare_runtime = forbidden
                tooling.install = forbidden
                def load_tests(loader, suite, pattern):
                    result = loader.loadTestsFromTestCase(contracts.NodeSetupTests)
                    result.addTests(loader.loadTestsFromName(
                        "SharedAutomationTests.test_real_renovate_extraction_and_effective_update_policy",
                        contracts,
                    ))
                    return result
                """)
            )
            (binary / "python3").symlink_to(sys.executable)
            (binary / "git").write_text(
                "#!/bin/sh\n"
                'if [ "$#" = 2 ] && [ "$1" = diff ] && [ "$2" = --check ]; then exit 0; fi\n'
                "exit 97\n"
            )
            (binary / "git").chmod(0o755)
            (startup / "sitecustomize.py").write_text(
                "import urllib.request\n"
                "def forbidden(*args, **kwargs): raise AssertionError('unexpected network acquisition')\n"
                "urllib.request.build_opener = forbidden\n"
            )
            compile((startup / "sitecustomize.py").read_text(), "network denial", "exec")
            environment = {
                **os.environ,
                "PATH": str(binary),
                "PYTHONPATH": os.pathsep.join((str(startup), str(shared / "automation/src"))),
                "DOCKERLENS_METADATA_UNCHANGED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            for name in (
                "CARGO_TARGET_DIR",
                "GITHUB_PATH",
                "GITHUB_OUTPUT",
                "BOXFERRY_RENOVATE_PACKAGE",
            ):
                environment.pop(name, None)
            self.assertIsNone(shutil.which("node", path=str(binary)))
            policy = json.loads((candidate / "scripts/validation-policy.json").read_text())
            self.assertEqual(
                policy["tasks"]["documentation"]["commands"][0],
                [
                    "python3",
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "tests",
                    "-v",
                ],
            )
            self.assertIn("DOCKERLENS_METADATA_UNCHANGED=1", policy["local_commands"]["prose"][0])
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "boxferry_ci",
                    "run",
                    "--task",
                    "documentation",
                    "--repository-root",
                    str(candidate),
                    "--config",
                    str(candidate / "scripts/validation-policy.json"),
                ],
                cwd=candidate,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
            )
            captured = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, captured)
            self.assertNotIn("Error in sitecustomize", captured)
            self.assertIn("skipped=3", captured)
            for pure in (
                "test_node_authority_binds_both_immutable_contexts_and_checks_before_read",
                "test_cold_wrong_failed_or_command_shaped_node_stops_every_provisioning_operation",
                "test_absolute_node_callback_preserves_all_other_argv_and_timeouts",
            ):
                self.assertRegex(captured, pure + r"[^\n]*\.\.\. ok")
            self.assertFalse((candidate / "target/boxferry-automation").exists())
            self.assertFalse((candidate / "target/tools/renovate").exists())
            self.assertIn(
                "unset DOCKERLENS_METADATA_UNCHANGED", (ROOT / "scripts/check-all.sh").read_text()
            )
            environment.pop("DOCKERLENS_METADATA_UNCHANGED")
            probe = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    "import shared_node_contract as c; "
                    "names=['test_actual_frontloader_selects_node_on_cold_path_without_automation_checkout',"
                    "'test_actual_composite_and_three_callers_order_cold_node_setup_before_provisioning']; "
                    "assert all(not getattr(getattr(c.NodeSetupTests,n),'__unittest_skip__',False) for n in names)",
                ],
                cwd=candidate,
                env={
                    **environment,
                    "PYTHONPATH": environment["PYTHONPATH"] + os.pathsep + str(candidate / "tests"),
                },
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)

    def test_archive_shaped_cold_bootstrap_retains_canonical_cargo_tool_data(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "dockerlens_archive_loader", ROOT / "scripts/validation-plan.py"
        )
        assert spec is not None and spec.loader is not None
        loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loader)
        setup_spec = importlib.util.spec_from_file_location(
            "dockerlens_archive_setup", ROOT / "scripts/setup-ci-tools.py"
        )
        assert setup_spec is not None and setup_spec.loader is not None
        setup = importlib.util.module_from_spec(setup_spec)
        setup_spec.loader.exec_module(setup)
        stream = io.BytesIO()
        inventory = (SHARED / ".devcontainer/Dockerfile").read_bytes()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, data in {
                "automation/pyproject.toml": b"[project]\nname='fixture'\n",
                "automation/uv.lock": b"version = 1\n",
                "automation/renovate-runtime.json": (
                    SHARED / "automation/renovate-runtime.json"
                ).read_bytes(),
                "renovate-presets/common.json": b"{}\n",
                ".devcontainer/Dockerfile": inventory,
            }.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))

        def read_git(directory: Path, *arguments: str, binary: bool = False) -> bytes | str:
            if arguments[0] == "archive":
                self.assertIn(".devcontainer/Dockerfile", arguments)
                return stream.getvalue()
            return SHA if arguments[0] == "rev-parse" else ""

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            objects = base / "target/boxferry-automation" / f"{SHA}.git"
            objects.mkdir(parents=True)
            (objects / "config").write_text(loader.BARE_CONFIG)
            with patch.object(loader, "run_git", side_effect=read_git):
                project = loader.prepare_implementation(base, SHA)
            self.assertEqual((project.parent / ".devcontainer/Dockerfile").read_bytes(), inventory)
            self.assertFalse((project.parent / "templates").exists())
            with (
                patch.object(
                    setup.tooling, "__file__", str(project / "src/boxferry_ci/tooling.py")
                ),
                patch.object(
                    setup, "node_preflight", return_value=("/selected/node", "24.21.0", SHA)
                ),
                patch.object(setup.tooling, "install"),
                patch.object(setup.renovate_runtime, "prepare_runtime"),
                patch.object(setup.subprocess, "run") as cargo,
            ):
                self.assertEqual(setup.main(["--engine", "podman", "--cargo-tools"]), 0)
            self.assertEqual(cargo.call_count, 2)

    def test_release_is_validation_only_with_every_exact_native_prerequisite(self) -> None:
        policy = load_release(ROOT / "scripts/release-policy.json", "Strukturpiloten/docker-lens")
        self.assertFalse(policy["publication_enabled"])
        needs: dict[str, Any] = {
            job: {"result": "success", "outputs": {"candidate_sha": SHA}}
            for job in policy["required_jobs"]
        }
        needs["api"]["outputs"]["published_api_candidate_sha"] = SHA
        verify_release(policy, needs, SHA)
        for job in policy["required_jobs"]:
            invalid = deepcopy(needs)
            outputs = invalid[job]["outputs"]
            assert isinstance(outputs, dict)
            outputs["candidate_sha"] = "b" * 40
            with self.subTest(job=job), self.assertRaises(ReleaseError):
                verify_release(policy, invalid, SHA)
        for filename in ("release-validation.yml", "native-validation.yml"):
            source = (ROOT / ".github/workflows" / filename).read_text()
            self.assertIn("./scripts/native-conformance.sh", source)
            self.assertNotIn("cargo publish", source)
        self.assertIn(
            "podman_cmd=(sudo -n podman)", (ROOT / "scripts/native-conformance.sh").read_text()
        )

    def test_setup_uses_canonical_tool_metadata_and_explicit_outer_engine(self) -> None:
        setup = (ROOT / "scripts/setup-ci-tools.py").read_text()
        self.assertIn('choices=("podman", "docker")', setup)
        self.assertIn("tooling.install", setup)
        self.assertIn("renovate_runtime.prepare_runtime", setup)
        self.assertNotIn("curl", setup)
        self.assertIsNone(re.search(r"sha256:[a-f0-9]{64}", setup))
        for task, engine in (("setup-tools", "podman"), ("setup-tools-hosted", "docker")):
            self.assertIn(engine, self.policy.tasks[task].commands[0])

    def test_only_the_five_qualified_native_fixture_tuples_are_excluded(self) -> None:
        rules = json.loads((ROOT / "renovate.json").read_text())["packageRules"]
        self.assertEqual(len(rules), 1)
        fixed = rules[0]
        self.assertFalse(fixed["enabled"])
        self.assertNotIn("automerge", fixed)
        self.assertNotIn("dependencyDashboardApproval", fixed)
        self.assertEqual(fixed["matchFileNames"], ["scripts/native-conformance.sh"])
        self.assertEqual(
            set(fixed["matchPackageNames"]),
            {
                "ghcr.io/strukturpiloten/docker-29-rootful",
                "ghcr.io/strukturpiloten/docker-29-rootless",
                "ghcr.io/strukturpiloten/docker-debian-11-rootful",
                "ghcr.io/strukturpiloten/docker-debian-11-rootless",
                "docker.io/library/busybox",
            },
        )
        self.assertEqual(fixed["matchDatasources"], ["docker"])
        self.assertEqual(fixed["matchManagers"], ["custom.regex"])

    def test_local_prose_and_rust_test_feedback_handles_cold_operational_cache(self) -> None:
        from boxferry_ci import __main__ as cli

        for profile in ("prose", "rust-tests"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:

                def execute(args: object, calls: tuple[tuple[str, ...], ...], timeout: int) -> int:
                    wrapped = next(call for call in calls if "-m" in call and "unittest" in call)
                    self.assertEqual(wrapped[:2], ("env", "DOCKERLENS_METADATA_UNCHANGED=1"))
                    environment = dict(os.environ)
                    environment.pop("DOCKERLENS_METADATA_UNCHANGED", None)
                    environment["BOXFERRY_RENOVATE_PACKAGE"] = str(Path(temporary) / "cold-cache")
                    environment["PYTHONPATH"] = (
                        str(ROOT / "tests")
                        + os.pathsep
                        + str(Path(boxferry_ci.__file__).resolve().parents[1])
                    )
                    result = subprocess.run(
                        [
                            *wrapped[:2],
                            sys.executable,
                            "-m",
                            "unittest",
                            "test_shared_automation.SharedAutomationTests.test_real_renovate_extraction_and_effective_update_policy",
                        ],
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=15,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("skipped=1", result.stderr)
                    self.assertFalse((Path(temporary) / "cold-cache").exists())
                    return result.returncode

                with (
                    patch.object(cli, "_plan", return_value={"profiles": [profile]}),
                    patch.object(cli, "_execute", side_effect=execute),
                ):
                    self.assertEqual(
                        cli.main(
                            [
                                "run-local",
                                "--repository-root",
                                str(ROOT),
                                "--config",
                                str(ROOT / "scripts/validation-policy.json"),
                            ]
                        ),
                        0,
                    )
        self.assertIn(
            "unset DOCKERLENS_METADATA_UNCHANGED", (ROOT / "scripts/check-all.sh").read_text()
        )

    def test_local_api_gate_uses_canonical_leaf_and_preserves_environment(self) -> None:
        gate = (ROOT / "scripts/check-all.sh").read_text()
        self.assertIn("run --task api-development", gate)
        self.assertNotIn("cargo semver-checks", gate)
        self.assertNotIn("cargo-tools verify", gate)
        self.assertNotIn("--implementation-checkout", gate)
        self.assertLess(gate.index("cargo deny"), gate.index("run --task api-development"))
        for api_exit in (0, 1, 41, 130):
            with self.subTest(api_exit=api_exit), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                scripts, tools = root / "scripts", root / "bin"
                scripts.mkdir()
                tools.mkdir()
                (scripts / "check-all.sh").write_text(gate)
                for name in ("format-lint.sh", "check-msrv.sh"):
                    path = scripts / name
                    path.write_text("#!/usr/bin/env bash\nexit 0\n")
                    path.chmod(0o755)
                stub = (
                    f"#!{sys.executable}\n"
                    + r"""
import json, os, sys
from pathlib import Path
name, arguments = Path(sys.argv[0]).name, sys.argv[1:]
with Path(os.environ['TRACE']).open('a') as output:
    output.write(json.dumps({'name': name, 'argv': arguments,
        'cargo_home': os.environ.get('CARGO_HOME'), 'path': os.environ['PATH'],
        'target': os.environ.get('CARGO_TARGET_DIR'),
        'compiler': os.environ.get('RUSTUP_TOOLCHAIN'),
        'metadata_skip': os.environ.get('DOCKERLENS_METADATA_UNCHANGED')}) + '\n')
if name == 'python3' and arguments[1:4] == ['run', '--task', 'api-development']:
    raise SystemExit(int(os.environ['API_EXIT']))
"""
                )
                for name in ("python3", "cargo", "git"):
                    path = tools / name
                    path.write_text(stub)
                    path.chmod(0o755)
                trace = root / "trace.jsonl"
                environment = dict(
                    os.environ,
                    PATH=str(tools) + os.pathsep + os.environ["PATH"],
                    CARGO_HOME=str(root / "cargo-home"),
                    CARGO_TARGET_DIR=str(root / "target"),
                    RUSTUP_TOOLCHAIN="ambient-forwarded-to-shared-helper",
                    DOCKERLENS_METADATA_UNCHANGED="1",
                    API_EXIT=str(api_exit),
                    TRACE=str(trace),
                )
                result = subprocess.run(
                    ["bash", str(scripts / "check-all.sh"), "--check"],
                    cwd=root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, api_exit, result.stdout + result.stderr)
                events = [json.loads(line) for line in trace.read_text().splitlines()]
                api = [
                    event
                    for event in events
                    if event["name"] == "python3"
                    and event["argv"][1:4] == ["run", "--task", "api-development"]
                ]
                self.assertEqual(len(api), 1)
                self.assertEqual(
                    api[0]["argv"],
                    [
                        "scripts/validation-plan.py",
                        "run",
                        "--task",
                        "api-development",
                        "--report-json",
                        "target/api-development-task.json",
                    ],
                )
                self.assertEqual(api[0]["cargo_home"], environment["CARGO_HOME"])
                self.assertEqual(api[0]["target"], environment["CARGO_TARGET_DIR"])
                self.assertEqual(api[0]["compiler"], environment["RUSTUP_TOOLCHAIN"])
                self.assertIsNone(api[0]["metadata_skip"])
                self.assertEqual(
                    api[0]["path"],
                    str(root / "target/shared-tools/bin") + os.pathsep + environment["PATH"],
                )
                self.assertFalse(
                    any(
                        event["name"] == "cargo" and event["argv"][:1] == ["semver-checks"]
                        for event in events
                    )
                )
                self.assertEqual(
                    any(
                        event["name"] == "git" and event["argv"] == ["diff", "--check"]
                        for event in events
                    ),
                    api_exit == 0,
                )

    def test_api_leaf_is_one_canonical_development_call_without_identity_or_baseline_copy(
        self,
    ) -> None:
        task = self.policy.tasks["api-development"]
        self.assertEqual(
            task.commands,
            (
                (
                    "python",
                    "-m",
                    "boxferry_ci.api_baselines",
                    "run",
                    "--repository-root",
                    ".",
                    "--repository",
                    "Strukturpiloten/docker-lens",
                    "--api-purpose",
                    "development",
                    "--event",
                    "local",
                    "--package",
                    "docker-lens",
                    "--report-json",
                    "target/api-baseline-local.json",
                ),
            ),
        )
        self.assertEqual(task.timeout_seconds, 1200)
        for copied_policy in (
            "--automation-sha",
            "--baseline-rev",
            "--baseline-version",
            "--allow-initial",
            "--release-type",
        ):
            self.assertNotIn(copied_policy, task.commands[0])

    def test_release_requires_distinct_published_api_output_beyond_generic_shared_gate(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/release-validation.yml").read_text()
        api_job = workflow.split("  api:\n", 1)[1].split("  shared-release-gate:\n", 1)[0]
        self.assertIn("api_purpose: published", api_job)
        self.assertIn('release_type: ""', api_job)
        self.assertIn("initial_api_contract: false", api_job)
        guard_step = workflow.split(
            "      - name: Fail on skipped, cancelled, or failed validation\n", 1
        )[1].split("      - uses:", 1)[0]
        self.assertIn(
            "PUBLISHED_API_CANDIDATE_SHA: ${{ needs.api.outputs.published_api_candidate_sha }}",
            guard_step,
        )
        self.assertIn("EXPECTED_SHA: ${{ inputs.expected_sha }}", guard_step)
        guard = textwrap.dedent(guard_step.split("        run: |\n", 1)[1])
        policy = load_release(ROOT / "scripts/release-policy.json", "Strukturpiloten/docker-lens")
        needs: dict[str, Any] = {
            job: {"result": "success", "outputs": {"candidate_sha": SHA}}
            for job in policy["required_jobs"]
        }
        needs["api"]["outputs"]["published_api_candidate_sha"] = SHA
        # The shared gate requires one published proof alongside every generic binding;
        # the caller's final guard also binds that proof to the successful API job.
        self.assertEqual(verify_release(policy, needs, SHA), SHA)
        generic_only = deepcopy(needs)
        del generic_only["api"]["outputs"]["published_api_candidate_sha"]
        with self.assertRaisesRegex(ReleaseError, "exactly one explicit published API"):
            verify_release(policy, generic_only, SHA)
        for published in ("b" * 40, "malformed", "", None, True):
            invalid = deepcopy(needs)
            invalid["api"]["outputs"]["published_api_candidate_sha"] = published
            with (
                self.subTest(published=published),
                self.assertRaisesRegex(ReleaseError, "invalid published API binding: api"),
            ):
                verify_release(policy, invalid, SHA)
        duplicate = deepcopy(needs)
        duplicate["candidate"]["outputs"]["published_api_candidate_sha"] = SHA
        with self.assertRaisesRegex(ReleaseError, "exactly one explicit published API"):
            verify_release(policy, duplicate, SHA)
        for output, api_result, expected, success in (
            (SHA, "success", SHA, True),
            ("", "success", SHA, False),
            ("b" * 40, "success", SHA, False),
            ("malformed", "success", SHA, False),
            (SHA, "failure", SHA, False),
            (SHA, "cancelled", SHA, False),
            (SHA, "skipped", SHA, False),
            ("", "success", "", False),
        ):
            environment = dict(
                os.environ,
                EXPECTED_SHA=expected,
                PUBLISHED_API_CANDIDATE_SHA=output,
                CANDIDATE_RESULT="success",
                NATIVE_RESULT="success",
                DEPENDENCIES_RESULT="success",
                API_RESULT=api_result,
                SHARED_RESULT="success",
            )
            with self.subTest(output=output, api_result=api_result, expected=expected):
                result = subprocess.run(
                    ["bash", "-c", guard],
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        for prerequisite in (
            "CANDIDATE_RESULT",
            "NATIVE_RESULT",
            "DEPENDENCIES_RESULT",
            "API_RESULT",
            "SHARED_RESULT",
        ):
            for outcome in ("failure", "cancelled", "skipped", ""):
                environment = dict(
                    os.environ,
                    EXPECTED_SHA=SHA,
                    PUBLISHED_API_CANDIDATE_SHA=SHA,
                    CANDIDATE_RESULT="success",
                    NATIVE_RESULT="success",
                    DEPENDENCIES_RESULT="success",
                    API_RESULT="success",
                    SHARED_RESULT="success",
                )
                environment[prerequisite] = outcome
                with self.subTest(prerequisite=prerequisite, outcome=outcome):
                    result = subprocess.run(
                        ["bash", "-c", guard],
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=5,
                    )
                    self.assertNotEqual(result.returncode, 0)

    def test_setup_executes_only_reviewed_canonical_operations(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "dockerlens_setup", ROOT / "scripts/setup-ci-tools.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with (
            patch.object(module, "node_preflight", return_value=("/selected/node", "24.22.1", SHA)),
            patch.object(module.tooling, "install") as install,
            patch.object(module.renovate_runtime, "prepare_runtime") as prepare,
            patch.object(module.subprocess, "run") as cargo,
        ):
            self.assertEqual(module.main(["--engine", "docker", "--cargo-tools"]), 0)
        self.assertEqual(install.call_args.args[1], ("actionlint", "shfmt", "shellcheck"))
        self.assertEqual(prepare.call_args.kwargs["engine"], "docker")
        self.assertTrue(callable(prepare.call_args.kwargs["command"]))
        self.assertEqual(prepare.call_args.args[0], SHARED / "automation/renovate-runtime.json")
        self.assertEqual(cargo.call_count, 2)
        for call in cargo.call_args_list:
            self.assertEqual(call.args[0][:4], ["cargo", "install", "--locked", "--version"])
            self.assertRegex(call.args[0][4], r"^[0-9]+\.[0-9]+\.[0-9]+$")
            self.assertIn(call.args[0][5], {"cargo-deny", "cargo-semver-checks"})
            self.assertEqual(call.kwargs, {"check": True, "timeout": 900})

    @unittest.skipIf(
        os.environ.get("DOCKERLENS_METADATA_UNCHANGED") == "1",
        "trusted prose plan does not alter dependency definitions",
    )
    def test_real_renovate_extraction_and_effective_update_policy(self) -> None:
        runtime = Path(os.environ.get("BOXFERRY_RENOVATE_PACKAGE", ROOT / "target/tools/renovate"))
        self.assertEqual(
            (runtime / "source-image.txt").read_text().strip(),
            json.loads((SHARED / "automation/renovate-runtime.json").read_text())["image"],
        )
        script = r"""
(async()=>{
const fs=require('fs'),assert=require('assert/strict'),base=process.argv[1]+'/dist/';
await require(base+'logger/index.js').init();
assert.equal(require(base+'util/regex.js').regexEngineStatus.type,'available');
const root=process.argv[2],shared=process.argv[3];
const local=JSON.parse(fs.readFileSync(root+'/renovate.json'));
const common=JSON.parse(fs.readFileSync(shared+'/renovate-presets/common.json'));
const rust=JSON.parse(fs.readFileSync(shared+'/renovate-presets/rust.json'));
const effective={...common,...rust,...local,
 customManagers:[...common.customManagers,...(rust.customManagers||[]),...local.customManagers],
 packageRules:[...common.packageRules,...rust.packageRules,...local.packageRules]};
const {extractPackageFile:extract}=require(base+'modules/manager/custom/regex/index.js');
const {applyPackageRules}=require(base+'util/package-rules/index.js');
const files=['.github/automation.json','.github/workflows/check.yml',
 '.github/workflows/dependency-eligibility.yml','scripts/native-conformance.sh'];
let pins=0;
for(const file of files){
 const content=fs.readFileSync(root+'/'+file,'utf8');
 const dependencies=effective.customManagers.flatMap(manager=>
 manager.managerFilePatterns.some(p=>new RegExp(p.slice(1,-1)).test(file))?
 (extract(content,file,manager)||{deps:[]}).deps:[]);
 if(file==='scripts/native-conformance.sh')assert.equal(dependencies.length,5);
 if(file==='.github/automation.json')assert.equal(dependencies.length,1);
 pins+=dependencies.length;
}
const {validateConfig}=require(base+'config/validation.js');
const validation=await validateConfig('repository',local);
assert.deepEqual(validation.errors,[]);
const {GlobalConfig}=require(base+'config/global.js');GlobalConfig.set({localDir:root});
const {extractPackageFile:extractActions}=require(base+'modules/manager/github-actions/extract.js');
const actionFile='.github/actions/setup-node/action.yml';
const actionSource=fs.readFileSync(root+'/'+actionFile,'utf8');
const extracted=await extractActions(actionSource,actionFile,{});
const actionPins=extracted.deps.filter(dep=>dep.depName==='actions/setup-node');
assert.equal(actionPins.length,1);
const action=actionPins[0];
assert.match(action.currentDigest,/^[a-f0-9]{40}$/);
assert.match(action.currentValue,/^v?[0-9]+\.[0-9]+\.[0-9]+$/);
const customActionPins=effective.customManagers.flatMap(manager=>
 manager.managerFilePatterns.some(p=>new RegExp(p.slice(1,-1)).test(actionFile))?
 (extract(actionSource,actionFile,manager)||{deps:[]}).deps:[]);
assert.equal(customActionPins.length,0,'native github-actions is the sole composite Action owner');
for(const source of [actionSource,actionSource.replace(action.currentDigest,'f'.repeat(40))]){
 const independent=(await extractActions(source,actionFile,{})).deps.find(dep=>dep.depName==='actions/setup-node');
 const policy=await applyPackageRules({...effective,...independent,manager:'github-actions',
  datasource:'github-tags',packageName:'actions/setup-node',depName:'actions/setup-node',
  packageFile:actionFile,updateType:'digest'});
 assert.equal(policy.minimumReleaseAge,'3 days');
 assert.equal(policy.automerge,true);assert.equal(policy.dependencyDashboardApproval,false);
 assert.notEqual(policy.enabled,false);
}
for(const [datasource,name,file] of [['node-version','node','.github/workflows/ci.yml'],
 ['docker','docker.io/library/node','.devcontainer/Dockerfile']]){
 const policy=await applyPackageRules({...effective,manager:'custom.regex',datasource,
  depName:name,packageName:name,packageFile:file,updateType:'minor'});
 assert.equal(policy.minimumReleaseAge,'3 days','standalone Node tools never inherit source age exemption');
}
for(const [dep,age] of [[{manager:'cargo',datasource:'crate',packageName:'serde_json'},'3 days'],
 [{manager:'cargo',datasource:'crate',packageName:'compose-lens'},'0 days'],
 [{manager:'github-actions',datasource:'github-tags',packageName:'actions/checkout'},'3 days']]){
 const policy=await applyPackageRules({...effective,...dep,depName:dep.packageName,updateType:'minor'});
 assert.equal(policy.automerge,true);assert.equal(policy.dependencyDashboardApproval,false);
 assert.equal(policy.minimumReleaseAge,age);
}
const native=await applyPackageRules({...effective,manager:'regex',datasource:'docker',
 depName:'ghcr.io/strukturpiloten/docker-29-rootful',packageName:'ghcr.io/strukturpiloten/docker-29-rootful',
 packageFile:'scripts/native-conformance.sh',updateType:'digest'});
assert.equal(native.enabled,false);
for (const [name,file] of [
 ['ghcr.io/strukturpiloten/docker-29-rootful-extra','scripts/native-conformance.sh'],
 ['ghcr.io/strukturpiloten/docker-29-rootful','scripts/other-tool.sh'],
 ['ghcr.io/renovatebot/renovate','automation/renovate-runtime.json'],
 ['docker.io/library/alpine','scripts/native-conformance.sh']]) {
 const policy=await applyPackageRules({...effective,manager:'regex',datasource:'docker',
 depName:name,packageName:name,packageFile:file,updateType:'digest'});
 assert.notEqual(policy.enabled,false);assert.equal(policy.automerge,true);
}
console.log('native extraction and effective policy passed: '+pins);
})().catch(error=>{console.error(error);process.exit(1)});
"""
        result = subprocess.run(
            ["node", "-e", script, str(runtime), str(ROOT), str(SHARED)],
            capture_output=True,
            text=True,
            check=False,
            timeout=90,
        )
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-6000:])
        self.assertIn("native extraction and effective policy passed", result.stdout)


class NodeSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "dockerlens_node_setup", ROOT / "scripts/setup-ci-tools.py"
        )
        assert spec is not None and spec.loader is not None
        self.setup = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.setup)
        self.documents = {
            ".github/workflows/ci.yml": b"jobs:\n  tools:\n    node-version: 24.22.1\n",
            ".devcontainer/Dockerfile": (
                "FROM docker.io/library/node:24.21.0-bookworm-slim@sha256:"
                + "d" * 64
                + " AS node_toolchain\n"
            ).encode(),
        }

    @contextlib.contextmanager
    def authority(
        self, *, kind: str = "git-checkout", fault: str = ""
    ) -> Iterator[list[tuple[str, ...]]]:
        calls: list[tuple[str, ...]] = []
        objects = {hashlib.sha1(data).hexdigest(): data for data in self.documents.values()}

        def read_git(repository: Path, *argv: str, binary: bool = False) -> bytes | str:
            calls.append(argv)
            expected = (
                ROOT / "target/boxferry-automation" / f"{SHA}.git"
                if kind == "interface-1-archive"
                else SHARED
            )
            self.assertEqual(repository, expected)
            if argv[0] == "ls-tree":
                self.assertEqual(argv[2], SHA)
                relative = argv[-1]
                if fault == "missing":
                    return b""
                mode = "120000" if fault == "mode" else "100644"
                oid = hashlib.sha1(self.documents[relative]).hexdigest()
                return f"{mode} blob {oid}\t{relative}\0".encode()
            if argv[1] == "-t":
                return "tree" if fault == "type" else "blob"
            if argv[1] == "-s":
                if fault == "size":
                    return "65537"
                if fault == "bad-size":
                    return "-1; private-command"
                return str(len(objects[argv[-1]]))
            self.assertEqual(argv[:2], ("cat-file", "blob"))
            self.assertTrue(binary)
            data = objects[argv[-1]]
            return data + b"changed" if fault == "changed" else data

        with (
            patch.object(self.setup.bootstrap, "load_config", return_value={"revision": SHA}),
            patch.object(
                self.setup.bootstrap,
                "automation_identity",
                return_value={"revision": SHA, "kind": kind},
            ) as identity,
            patch.object(self.setup.bootstrap, "run_git", side_effect=read_git),
        ):
            yield calls
            identity.assert_called_once_with(ROOT, SHA)

    def test_node_authority_binds_both_immutable_contexts_and_checks_before_read(self) -> None:
        for kind in ("git-checkout", "interface-1-archive"):
            with self.subTest(kind=kind), self.authority(kind=kind) as calls:
                self.assertEqual(self.setup.canonical_nodes(), (SHA, "24.22.1", "24.21.0"))
            self.assertEqual(
                [argv[:2] for argv in calls],
                [
                    ("ls-tree", "-z"),
                    ("cat-file", "-t"),
                    ("cat-file", "-s"),
                    ("cat-file", "blob"),
                    ("ls-tree", "-z"),
                    ("cat-file", "-t"),
                    ("cat-file", "-s"),
                    ("cat-file", "blob"),
                ],
            )
        for fault in ("missing", "mode", "type", "size", "bad-size"):
            with self.subTest(fault=fault), self.authority(fault=fault) as calls:
                with self.assertRaises(self.setup.SetupError):
                    self.setup.canonical_nodes()
            self.assertNotIn(("cat-file", "blob"), [argv[:2] for argv in calls])
        with self.authority(fault="changed"), self.assertRaises(self.setup.SetupError):
            self.setup.canonical_nodes()

    def test_metadata_is_unambiguous_bounded_utf8_and_never_a_command(self) -> None:
        original = self.documents.copy()
        cases = (
            (".github/workflows/ci.yml", b"no version\n"),
            (".github/workflows/ci.yml", b"node-version: 24.22.1\nnode-version: 24.21.0\n"),
            (".github/workflows/ci.yml", b"node-version: 24.22.1; echo private\n"),
            (".github/workflows/ci.yml", b"node-version: $(private)\n"),
            (
                ".github/workflows/ci.yml",
                b"node-version: 24.22.1\nnode-version-file: unreviewed\n",
            ),
            (".github/workflows/ci.yml", b"node-version: 24.22.1\xff\n"),
            (".devcontainer/Dockerfile", b"FROM node:latest AS node_toolchain\n"),
            (".devcontainer/Dockerfile", original[".devcontainer/Dockerfile"] * 2),
        )
        for relative, document in cases:
            self.documents = {**original, relative: document}
            with self.subTest(relative=relative, document=document), self.authority():
                with self.assertRaises(self.setup.SetupError):
                    self.setup.canonical_nodes()
        for kind in ("producer-working-tree", "unknown"):
            with self.authority(kind=kind), self.assertRaises(self.setup.SetupError):
                self.setup.canonical_nodes()
        with (
            patch.object(self.setup.bootstrap, "load_config", side_effect=ValueError("PRIVATE")),
            self.assertRaises(self.setup.SetupError) as caught,
        ):
            self.setup.canonical_nodes()
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_hosted_selection_needs_no_node_and_hands_off_only_a_numeric_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            stdout = io.StringIO()
            with (
                self.authority(),
                patch.object(self.setup.shutil, "which") as which,
                patch.object(self.setup.tooling, "install") as install,
                patch.object(self.setup.renovate_runtime, "prepare_runtime") as prepare,
                patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                contextlib.redirect_stdout(stdout),
            ):
                self.assertEqual(self.setup.main(["--node-version", "--node-context", "hosted"]), 0)
            self.assertEqual(stdout.getvalue(), "24.22.1\n")
            self.assertEqual(output.read_text(), "node_version=24.22.1\n")
            which.assert_not_called()
            install.assert_not_called()
            prepare.assert_not_called()

    def test_failed_metadata_query_never_writes_a_version_handoff(self) -> None:
        self.documents[".github/workflows/ci.yml"] = b"node-version: $(PRIVATE-COMMAND)\\n"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            stderr = io.StringIO()
            with (
                self.authority(),
                patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                patch.object(self.setup.shutil, "which") as which,
                patch.object(self.setup.tooling, "install") as install,
                patch.object(self.setup.renovate_runtime, "prepare_runtime") as prepare,
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(self.setup.main(["--node-version", "--node-context", "hosted"]), 2)
            self.assertFalse(output.exists())
            self.assertNotIn("PRIVATE", stderr.getvalue())
            which.assert_not_called()
            install.assert_not_called()
            prepare.assert_not_called()

    def test_metadata_exact_size_boundary_and_independent_producer_action(self) -> None:
        authority = self.documents[".github/workflows/ci.yml"]
        self.documents[".github/workflows/ci.yml"] = (
            authority + b"#" + b"x" * (65536 - len(authority) - 1)
        )
        with self.authority():
            self.assertEqual(self.setup.canonical_nodes()[1:], ("24.22.1", "24.21.0"))
        self.documents[".github/workflows/ci.yml"] = (
            authority + b"    uses: actions/setup-node@" + b"a" * 40 + b" # v7.0.0\\n"
        )
        with self.authority():
            self.assertEqual(self.setup.canonical_nodes()[1:], ("24.22.1", "24.21.0"))

    @unittest.skipIf(
        os.environ.get("DOCKERLENS_METADATA_UNCHANGED") == "1",
        "trusted prose plan does not provision the immutable object cache",
    )
    def test_actual_frontloader_selects_node_on_cold_path_without_automation_checkout(self) -> None:
        revision = json.loads((ROOT / ".github/automation.json").read_text())["revision"]
        expected = self.setup.canonical_nodes()[1]
        objects = ROOT / "target/boxferry-automation" / f"{revision}.git"
        git = shutil.which("git")
        assert git is not None
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            candidate = base / "candidate"
            binary = base / "bin"
            binary.mkdir()
            (candidate / "scripts").mkdir(parents=True)
            (candidate / ".github").mkdir()
            for name in (
                "scripts/validation-plan.py",
                "scripts/setup-ci-tools.py",
                "scripts/validation-policy.json",
                ".github/automation.json",
            ):
                shutil.copyfile(ROOT / name, candidate / name)
            cache = candidate / "target/boxferry-automation"
            cache.mkdir(parents=True)
            shutil.copytree(objects, cache / f"{revision}.git")
            (binary / "git").symlink_to(git)
            (binary / "python3").symlink_to(sys.executable)
            (binary / "uv").write_text(
                f"#!{sys.executable}\n"
                + textwrap.dedent("""\
                    import os,sys
                    from pathlib import Path
                    args=sys.argv[1:]
                    if args==['--version']:
                        print('uv 0.13.6');raise SystemExit(0)
                    assert args[:2]==['run','--locked']
                    project=Path(args[args.index('--project')+1])
                    os.chdir(args[args.index('--directory')+1])
                    os.environ['PYTHONPATH']=str(project/'src')
                    os.execv(sys.executable,[sys.executable,*args[args.index('python')+1:]])
                """)
            )
            (binary / "uv").chmod(0o755)
            startup = base / "startup"
            startup.mkdir()
            (startup / "sitecustomize.py").write_text(
                "import urllib.request\n"
                "def forbidden(*args, **kwargs): raise AssertionError('unexpected uv network acquisition')\n"
                "urllib.request.build_opener = forbidden\n"
            )
            compile((startup / "sitecustomize.py").read_text(), "network-denial fixture", "exec")
            output = base / "outputs"
            result = subprocess.run(
                [
                    sys.executable,
                    str(candidate / "scripts/validation-plan.py"),
                    "run",
                    "--task",
                    "node-toolchain",
                ],
                cwd=candidate,
                env={
                    **os.environ,
                    "PATH": str(binary),
                    "PYTHONPATH": str(startup),
                    "GITHUB_OUTPUT": str(output),
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("Error in sitecustomize", result.stderr)
            self.assertEqual(output.read_text(), f"node_version={expected}\n")
            self.assertFalse((candidate / "_automation").exists())
            self.assertFalse((candidate / "target/tools/renovate").exists())

    def test_preflight_accepts_only_the_exact_context_versions(self) -> None:
        for context in ("hosted", "local"):
            for version in ("24.22.1", "24.21.0", "24.23.0", "22.20.0", "20.19.0"):
                accepted = version == "24.22.1" or (context == "local" and version == "24.21.0")
                with (
                    self.subTest(context=context, version=version),
                    patch.object(
                        self.setup, "canonical_nodes", return_value=(SHA, "24.22.1", "24.21.0")
                    ),
                    patch.object(self.setup.shutil, "which", return_value=sys.executable),
                    patch.object(
                        self.setup.renovate_runtime,
                        "run_command",
                        return_value="v" + version + "\n",
                    ) as run,
                ):
                    if accepted:
                        self.assertEqual(
                            self.setup.node_preflight(context),
                            (str(Path(sys.executable).resolve()), version, SHA),
                        )
                    else:
                        with self.assertRaises(self.setup.SetupError):
                            self.setup.node_preflight(context)
                self.assertEqual(
                    run.call_args.args, ((str(Path(sys.executable).resolve()), "--version"), 10)
                )

    def test_cold_wrong_failed_or_command_shaped_node_stops_every_provisioning_operation(
        self,
    ) -> None:
        for outcome in (
            None,
            "v22.20.0\n",
            "v24.22.1; private\n",
            "v24.22.1\nprivate\n",
            "$(private)",
            self.setup.renovate_runtime.RenovateRuntimeError("PRIVATE-TIMEOUT"),
        ):
            stderr = io.StringIO()
            with (
                self.subTest(outcome=type(outcome).__name__),
                patch.object(
                    self.setup, "canonical_nodes", return_value=(SHA, "24.22.1", "24.21.0")
                ),
                patch.object(
                    self.setup.shutil,
                    "which",
                    return_value=None if outcome is None else sys.executable,
                ),
                patch.object(self.setup.renovate_runtime, "run_command") as run,
                patch.object(self.setup.tooling, "install") as install,
                patch.object(self.setup.renovate_runtime, "prepare_runtime") as prepare,
                patch.object(self.setup.subprocess, "run") as cargo,
                contextlib.redirect_stderr(stderr),
            ):
                if isinstance(outcome, Exception):
                    run.side_effect = outcome
                else:
                    run.return_value = outcome
                self.assertEqual(
                    self.setup.main(
                        ["--engine", "docker", "--node-context", "hosted", "--cargo-tools"]
                    ),
                    2,
                )
            self.assertIn("Node", stderr.getvalue())
            self.assertNotIn("private", stderr.getvalue())
            self.assertNotIn("PRIVATE", stderr.getvalue())
            self.assertLess(len(stderr.getvalue()), 600)
            install.assert_not_called()
            prepare.assert_not_called()
            cargo.assert_not_called()
            if outcome is None:
                run.assert_not_called()

    def test_absolute_node_callback_preserves_all_other_argv_and_timeouts(self) -> None:
        for argv in (
            ["node", "--input-type=module", "-e", "native-RE2", "/runtime"],
            ["podman", "cp", "node", "/target"],
            ["docker", "pull", "image"],
            ["nodejs", "--version"],
            ["/different/node", "--version"],
        ):
            held = list(argv)
            with patch.object(
                self.setup.renovate_runtime, "run_command", return_value="evidence"
            ) as run:
                self.assertEqual(
                    self.setup._runtime_command("/verified/node", argv, 17.25), "evidence"
                )
            self.assertEqual(argv, held)
            expected = ("/verified/node", *argv[1:]) if argv[0] == "node" else argv
            self.assertEqual(run.call_args.args, (expected, 17.25))
            if argv[0] != "node":
                self.assertIs(run.call_args.args[0], argv)

    def test_actual_setup_preflights_before_downloads_and_safely_reports_re2_failure(self) -> None:
        trace: list[str] = []
        stderr = io.StringIO()

        def selected(context: str) -> tuple[str, str, str]:
            self.assertEqual(context, "hosted")
            trace.append("preflight")
            return "/verified/node", "24.22.1", SHA

        def prepare(*args: object, **kwargs: object) -> None:
            trace.append("prepare")
            self.assertEqual(kwargs["engine"], "docker")
            callback = kwargs["command"]
            assert callable(callback)
            with patch.object(
                self.setup.renovate_runtime, "run_command", return_value="native-re2-available"
            ) as run:
                callback(["node", "-e", "RE2"], 30)
            self.assertEqual(run.call_args.args, (("/verified/node", "-e", "RE2"), 30))
            raise self.setup.renovate_runtime.RenovateRuntimeError("PRIVATE-CHILD-ERROR")

        with (
            patch.object(self.setup, "node_preflight", side_effect=selected),
            patch.object(
                self.setup.tooling, "install", side_effect=lambda *args: trace.append("download")
            ),
            patch.object(self.setup.renovate_runtime, "prepare_runtime", side_effect=prepare),
            patch.object(self.setup.subprocess, "run") as cargo,
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(
                self.setup.main(
                    ["--engine", "docker", "--node-context", "hosted", "--cargo-tools"]
                ),
                2,
            )
        self.assertEqual(trace, ["preflight", "download", "prepare"])
        self.assertIn("preparation/native RE2", stderr.getvalue())
        self.assertIn("Node 24.22.1, engine docker", stderr.getvalue())
        self.assertIn("ghcr.io/renovatebot/renovate:", stderr.getvalue())
        self.assertIn("child failure reason is unavailable", stderr.getvalue())
        self.assertNotIn("PRIVATE", stderr.getvalue())
        cargo.assert_not_called()

    @unittest.skipIf(
        os.environ.get("DOCKERLENS_METADATA_UNCHANGED") == "1",
        "trusted prose plan does not provision the native Renovate YAML runtime",
    )
    def test_actual_composite_and_three_callers_order_cold_node_setup_before_provisioning(
        self,
    ) -> None:
        runtime = ROOT / "target/tools/renovate"
        script = r"""
const fs=require('fs'),yaml=require(process.argv[1]+'/node_modules/yaml'),root=process.argv[2];
const read=name=>yaml.parse(fs.readFileSync(root+'/'+name,'utf8'));
const action=read('.github/actions/setup-node/action.yml');
const check=read('.github/workflows/check.yml').jobs.documentation;
const native=read('.github/workflows/native-validation.yml').jobs.candidate;
const release=read('.github/workflows/release-validation.yml').jobs.candidate;
process.stdout.write(JSON.stringify({action,check,native,release}));
"""
        parsed = subprocess.run(
            ["node", "-e", script, str(runtime), str(ROOT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        documents = json.loads(parsed.stdout)
        steps = documents["action"]["runs"]["steps"]
        self.assertEqual(len(steps), 3)
        self.assertIn("--task node-toolchain", steps[0]["run"])
        self.assertRegex(steps[1]["uses"], r"^actions/setup-node@[a-f0-9]{40}$")
        self.assertEqual(
            steps[1]["with"]["node-version"], "${{ steps.canonical-node.outputs.node_version }}"
        )
        self.assertFalse(steps[1]["with"]["package-manager-cache"])
        self.assertIn("--task node-preflight", steps[2]["run"])
        for name, action_path, last_step in (
            (
                "check",
                "./source/.github/actions/setup-node",
                "Set up canonical tools and the real Renovate engine",
            ),
            ("native", "./.github/actions/setup-node", "Complete offline gate"),
            ("release", "./.github/actions/setup-node", "Complete scaffold gate"),
        ):
            caller_steps = documents[name]["steps"]
            action_index = next(
                i for i, step in enumerate(caller_steps) if step.get("uses") == action_path
            )
            gate_index = next(
                i for i, step in enumerate(caller_steps) if step.get("name") == last_step
            )
            self.assertLess(action_index, gate_index)
            if name == "check":
                self.assertEqual(caller_steps[action_index]["if"], caller_steps[gate_index]["if"])
                self.assertEqual(caller_steps[action_index]["with"]["repository-root"], "source")
                self.assertIn("--node-context hosted", caller_steps[gate_index]["run"])
            else:
                self.assertIn("Verify exact", caller_steps[action_index - 1]["name"])
        check_steps = documents["check"]["steps"]
        setup_step = next(
            step
            for step in check_steps
            if step["name"] == "Set up canonical tools and the real Renovate engine"
        )
        policy_step = next(
            step for step in check_steps if "--task documentation" in step.get("run", "")
        )
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "bin"
            candidate = base / "source"
            binary.mkdir()
            candidate.mkdir()
            trace = base / "trace"
            handoff = base / "output"
            wrapper = binary / "python3"
            wrapper.write_text(
                f"#!{sys.executable}\n"
                + textwrap.dedent(f"""\
                import importlib.util,json,os,sys
                from pathlib import Path
                root=Path({str(ROOT)!r})
                def record(value):
                    with Path(os.environ['NODE_TEST_TRACE']).open('a') as stream:stream.write(value+'\\n')
                args=sys.argv[1:]
                if Path(sys.argv[0]).name=='uv':
                    if '--task' in args and args[args.index('--task')+1]=='documentation':
                        record('policy');raise SystemExit(0)
                    args=args[args.index('python')+1:]
                if args[0].endswith('validation-plan.py'):
                    task=args[args.index('--task')+1]
                    args=json.loads((root/'scripts/validation-policy.json').read_text())['tasks'][task]['commands'][0][2:]
                else:args=args[1:]
                spec=importlib.util.spec_from_file_location('node_setup_fixture',root/'scripts/setup-ci-tools.py')
                module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                module.canonical_nodes=lambda:({SHA!r},'24.22.1','24.21.0')
                original=module.node_preflight
                def preflight(context):record('verify');return original(context)
                module.node_preflight=preflight
                module.tooling.install=lambda *args:record('tools')
                module.renovate_runtime.prepare_runtime=lambda *args,**kwargs:record('prepare')
                if '--node-version' in args:record('select')
                raise SystemExit(module.main(args))
            """)
            )
            wrapper.chmod(0o755)
            (binary / "uv").symlink_to(wrapper)
            bash = shutil.which("bash")
            assert bash is not None
            environment = {
                **os.environ,
                "PATH": str(binary),
                "GITHUB_OUTPUT": str(handoff),
                "NODE_TEST_TRACE": str(trace),
                "EVENT_NAME": "pull_request",
                "BASE_SHA": SHA,
                "HEAD_SHA": SHA,
                "POLICY_SHA": SHA,
                "GITHUB_SHA": SHA,
                "AUTOMATION_SHA": SHA,
                "POLICY_CONFIG": "policy.json",
            }
            for installed, accepted in (("24.22.1", True), ("24.21.0", False)):
                trace.unlink(missing_ok=True)
                handoff.unlink(missing_ok=True)
                (binary / "node").unlink(missing_ok=True)
                result = subprocess.run(
                    [bash, "-euc", steps[0]["run"]],
                    cwd=candidate,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(handoff.read_text(), "node_version=24.22.1\n")
                with trace.open("a") as stream:
                    stream.write("install\n")
                (binary / "node").write_text("#!/bin/sh\nprintf 'v" + installed + "\\n'\n")
                (binary / "node").chmod(0o755)
                result = subprocess.run(
                    [bash, "-euc", steps[2]["run"]],
                    cwd=candidate,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if accepted:
                    for step in (setup_step, policy_step):
                        result = subprocess.run(
                            [bash, "-euc", step["run"]],
                            cwd=base,
                            env=environment,
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        trace.read_text().splitlines(),
                        ["select", "install", "verify", "verify", "tools", "prepare", "policy"],
                    )
                else:
                    self.assertEqual(
                        trace.read_text().splitlines(), ["select", "install", "verify"]
                    )


if __name__ == "__main__":
    unittest.main()
