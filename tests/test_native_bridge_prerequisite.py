"""Offline host bridge preflight tests; no module is loaded by this suite."""

import importlib.util
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "scripts/native-bridge-prerequisite.py"
SPEC = importlib.util.spec_from_file_location("native_bridge_prerequisite", SOURCE)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)

HOSTED = {
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "Linux",
    "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens",
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_JOB": "native-conformance",
}


class NativeBridgePrerequisiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.module = root / "br_netfilter"
        self.iptables = root / "bridge-nf-call-iptables"
        self.ip6tables = root / "bridge-nf-call-ip6tables"

    def check(self, environment: dict[str, str], run: object) -> str:
        return bridge.ensure_bridge_prerequisite(
            environment, module=self.module, iptables=self.iptables,
            ip6tables=self.ip6tables, run=run,
        )

    def ready(self) -> None:
        self.module.mkdir()
        self.iptables.write_text("1\n")
        self.ip6tables.write_text("1\n")

    def test_already_ready_never_loads_even_on_hosted_runner(self) -> None:
        self.ready()
        for environment in ({}, HOSTED):
            with self.subTest(environment=environment), mock.patch.object(bridge.subprocess, "run") as run:
                marker = self.check(environment, run)
                self.assertIn("module_load=not-needed", marker)
                run.assert_not_called()

    def test_local_and_unknown_never_load_when_missing_or_disabled(self) -> None:
        for environment in ({}, {"GITHUB_ACTIONS": "true"}):
            with self.subTest(environment=environment), mock.patch.object(bridge.subprocess, "run") as run:
                with self.assertRaisesRegex(bridge.BridgePrerequisiteError, "read-only"):
                    self.check(environment, run)
                run.assert_not_called()
        self.ready()
        self.ip6tables.write_text("0\n")
        with mock.patch.object(bridge.subprocess, "run") as run:
            with self.assertRaisesRegex(bridge.BridgePrerequisiteError, "read-only"):
                self.check({}, run)
            run.assert_not_called()

    def test_every_hosted_guard_field_is_required(self) -> None:
        self.assertTrue(bridge.hosted_main_native_job(HOSTED))
        for field in HOSTED:
            changed = dict(HOSTED)
            changed.pop(field)
            with self.subTest(field=field), mock.patch.object(bridge.subprocess, "run") as run:
                self.assertFalse(bridge.hosted_main_native_job(changed))
                with self.assertRaises(bridge.BridgePrerequisiteError):
                    self.check(changed, run)
                run.assert_not_called()
        for field, value in (
            ("RUNNER_ENVIRONMENT", "self-hosted"), ("RUNNER_OS", "Windows"),
            ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/tags/v1"),
            ("GITHUB_REPOSITORY", "attacker/docker-lens"), ("GITHUB_JOB", "candidate"),
        ):
            changed = dict(HOSTED, **{field: value})
            with self.subTest(field=field, value=value), mock.patch.object(bridge.subprocess, "run") as run:
                self.assertFalse(bridge.hosted_main_native_job(changed))
                with self.assertRaises(bridge.BridgePrerequisiteError):
                    self.check(changed, run)
                run.assert_not_called()
        self.assertTrue(bridge.hosted_main_native_job(dict(HOSTED, GITHUB_EVENT_NAME="workflow_dispatch")))

    def test_hosted_missing_module_loads_exact_command_then_checks_both_sysctls(self) -> None:
        def loaded(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            self.assertEqual(command, ["sudo", "-n", "timeout", "--signal=TERM",
                                       "--kill-after=2s", "10s", "modprobe", "br_netfilter"])
            self.assertEqual(kwargs["timeout"], 15)
            self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
            self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
            self.ready()
            return subprocess.CompletedProcess(command, 0)
        marker = self.check(HOSTED, loaded)
        self.assertIn("module_load=hosted-only", marker)

    def test_present_but_disabled_never_calls_modprobe(self) -> None:
        self.ready()
        self.ip6tables.write_text("0\n")
        with mock.patch.object(bridge.subprocess, "run") as run:
            with self.assertRaisesRegex(bridge.BridgePrerequisiteError, "not enabled"):
                self.check(HOSTED, run)
            run.assert_not_called()

    def test_hosted_load_error_timeout_and_bad_readback_fail_closed(self) -> None:
        failures = (
            lambda _command, **_kwargs: subprocess.CompletedProcess([], 1, b"private", b"private"),
            mock.Mock(side_effect=subprocess.TimeoutExpired(["sudo"], 10, b"private", b"private")),
            mock.Mock(side_effect=FileNotFoundError("private path")),
        )
        for runner in failures:
            with self.subTest(runner=runner):
                with self.assertRaises(bridge.BridgePrerequisiteError) as failure:
                    self.check(HOSTED, runner)
                self.assertNotIn("private", str(failure.exception))
        def incomplete(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            self.module.mkdir()
            self.iptables.write_text("1\n")
            self.ip6tables.write_text("0\n")
            return subprocess.CompletedProcess(command, 0)
        with self.assertRaisesRegex(bridge.BridgePrerequisiteError, "post-load readback"):
            self.check(HOSTED, incomplete)

    def test_sysctl_values_are_closed_and_bounded(self) -> None:
        self.assertEqual(bridge.sysctl_state(self.iptables), "unavailable")
        for value, expected in (("1\n", "enabled"), ("0\n", "disabled"),
                                ("2\n", "invalid"), ("1\nprivate", "invalid")):
            with self.subTest(value=value):
                self.iptables.write_text(value)
                self.assertEqual(bridge.sysctl_state(self.iptables), expected)

    def test_timed_out_module_command_kills_spawned_child_group(self) -> None:
        marker = Path(self.temporary.name) / "late-child-marker"
        started = Path(self.temporary.name) / "child-started"
        child = f"import pathlib,time;time.sleep(1);pathlib.Path({str(marker)!r}).write_text('late')"
        parent = ("import pathlib,subprocess,sys;"
                  f"child=subprocess.Popen([{sys.executable!r},'-c',{child!r}]);"
                  f"pathlib.Path({str(started)!r}).write_text('started');"
                  "child.wait()")
        def fake_popen(_command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
            return subprocess.Popen([sys.executable, "-c", parent], **kwargs)
        with self.assertRaises(subprocess.TimeoutExpired):
            bridge.bounded_module_command(
                list(bridge.LOAD), check=False, timeout=0.3,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                popen=fake_popen,
            )
        self.assertTrue(started.exists(), "fake child was not started before timeout")
        time.sleep(1.1)
        self.assertFalse(marker.exists(), "timed-out child continued after group kill")

    def test_outer_timeout_handles_unprivileged_signal_denial_without_leak(self) -> None:
        class FakeRootProcess:
            pid = 123456

            def wait(self, timeout: float) -> int:
                raise subprocess.TimeoutExpired(list(bridge.LOAD), timeout, b"private-output")

        with mock.patch.object(bridge.os, "killpg", side_effect=PermissionError("private-path")):
            with self.assertRaises(subprocess.TimeoutExpired):
                bridge.bounded_module_command(
                    list(bridge.LOAD), check=False, timeout=15,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    popen=lambda _command, **_kwargs: FakeRootProcess(),
                )


if __name__ == "__main__":
    unittest.main()
