"""Hermetic kernel-window contracts: never contact a runtime or host journal."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from test_native_hostname_wiring import assert_current_cohort

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("kernel_window", ROOT / "scripts/native-rootless-kernel-window.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
import native_outer_diagnostic_capture as capture_module

SOURCE = (ROOT / "scripts/native-conformance.sh").read_text()
RUNTIME = (ROOT / "scripts/native-outer-runtime.sh").read_text()
CANARY = "private-canary /secret/profile pid=98765"
EVENT = 'audit: type=1400 audit(10.005:12): apparmor="DENIED" operation="userns_create" comm="rootlesskit"'
HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
          "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
          "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens", "ImageOS": "ubuntu24",
          "ImageVersion": "20261020.1.0", "GITHUB_WORKFLOW_REF":
          "Strukturpiloten/docker-lens/.github/workflows/native-validation.yml@refs/heads/main"}


def row(message=EVENT, timestamp="10000001", **extra):
    return (json.dumps({"__REALTIME_TIMESTAMP": timestamp, "MESSAGE": message, **extra}) + "\n").encode()


def definition(name, source=SOURCE):
    start = source.index("\n" + name + "() {") + 1
    return source[start:source.index("\n}\n", start) + 3]


class ParserTests(unittest.TestCase):
    def observed(self, payload):
        return MODULE.observe(payload, 10000000, 20000000)

    def test_exact_denial_and_explicit_errno_are_independent(self):
        for suffix, expected in (("", "absent"), (" error=-13", "permission_denied"),
                                 (" error=-1", "operation_not_permitted"), (" errno=EACCES", "permission_denied"),
                                 (" errno=EPERM", "operation_not_permitted"), (" errno=5", "other")):
            self.assertEqual(self.observed(row(EVENT + suffix)), ("observed", "userns_create", expected))

    def test_operations_and_missing_operation_are_closed(self):
        for operation, expected in (("exec", "exec"), ("open", "other"), ("", "unknown")):
            message = EVENT.replace('operation="userns_create"', f'operation="{operation}"')
            self.assertEqual(self.observed(row(message)), ("observed", expected, "absent"))

    def test_comm_comes_only_from_message_not_journal_comm(self):
        self.assertEqual(self.observed(row(_COMM="kernel")), ("observed", "userns_create", "absent"))
        self.assertEqual(self.observed(row(EVENT.replace('comm="rootlesskit"', 'comm="other"'), _COMM="rootlesskit")),
                         ("unobserved", "unknown", "absent"))

    def test_near_misses_are_not_observed(self):
        for message in (EVENT.replace("DENIED", "ALLOWED"),
                        EVENT.replace('comm="rootlesskit"', 'comm="rootlesskit2"'),
                        'apparmor="DENIED" comm="other" name="rootlesskit"', "ordinary kernel message"):
            self.assertEqual(self.observed(row(message)), ("unobserved", "unknown", "absent"))

    def test_raw_literal_unquoted_authority_fields_cannot_observe_or_prove_absence(self):
        for payload in (
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=DENIED comm=\\"rootlesskit\\""}\n',
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=\\"DENIED\\" comm=rootlesskit"}\n',
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=DENIED comm=rootlesskit"}\n',
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=DENIED comm=\\"other\\""}\n',
        ):
            with self.subTest(payload=payload):
                self.assertEqual(self.observed(payload), MODULE.AMBIGUOUS)

    def test_raw_literal_incomplete_denied_comm_never_proves_absence(self):
        for payload in (
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=\\"DENIED\\" operation=\\"exec\\""}\n',
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=\\"DENIED\\" comm=\\"\\""}\n',
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=\\"DENIED\\" comm=unknown"}\n',
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=\\"DENIED\\" comm=\\"?\\""}\n',
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=\\"DENIED\\" comm=\\"rootlesskit"}\n',
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=\\"DENIED\\" comm=\\"rootlesskit-extra\\""}\n',
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=\\"denied\\" comm=\\"rootlesskit\\""}\n',
            b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"audit: type=1400 audit(10.005:12): comm=\\"rootlesskit\\" operation=\\"exec\\""}\n',
        ):
            with self.subTest(payload=payload):
                self.assertEqual(self.observed(payload), MODULE.AMBIGUOUS)
        other = b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=\\"DENIED\\" comm=\\"other\\""}\n'
        self.assertEqual(self.observed(other), ("unobserved", "unknown", "absent"))
        exact = b'{"__REALTIME_TIMESTAMP":"10000001","MESSAGE":"apparmor=\\"DENIED\\" comm=\\"rootlesskit\\" operation=\\"exec\\""}\n'
        self.assertEqual(self.observed(exact), ("observed", "exec", "absent"))

    def test_quoted_payload_is_not_token_authority(self):
        self.assertEqual(self.observed(row('apparmor="DENIED" comm="other" info="comm=rootlesskit"')),
                         ("unobserved", "unknown", "absent"))
        self.assertEqual(self.observed(row(EVENT + ' info="permission denied"')),
                         ("observed", "userns_create", "absent"))

    def test_conflicting_or_malformed_events_are_ambiguous(self):
        for payload in (row() + row(EVENT.replace("userns_create", "exec")),
                        row(EVENT + ' comm="rootlesskit"'), row(EVENT + " error=-13 errno=EPERM"),
                        row(EVENT + ' name="unterminated'), row("prefix " + EVENT)):
            self.assertEqual(self.observed(payload), MODULE.AMBIGUOUS)
        self.assertEqual(self.observed(row() + row()), ("observed", "userns_create", "absent"))

    def test_complete_empty_query_is_unobserved(self):
        self.assertEqual(self.observed(b""), ("unobserved", "unknown", "absent"))

    def test_strict_framing_duplicates_types_and_window(self):
        malformed = [row()[:-1], row() + b"\n", b"[]\n", b"{} {}\n", b"\xff\n",
                     b'{"MESSAGE":"x","MESSAGE":"y","__REALTIME_TIMESTAMP":"10000001"}\n',
                     row(timestamp="9999999"), row(timestamp="20000001"), row(timestamp=10000001),
                     row(timestamp=["10000001"]), row(message=None), row(message=[1, 2]),
                     row(message="x\n"), row(message="\ud800"), b'{"MESSAGE":NaN}\n',
                     row() + b'{"unfinished":', b" " + row(), row() * 1000]
        for payload in malformed:
            with self.subTest(payload=payload[:50]), self.assertRaises(MODULE.Unavailable):
                self.observed(payload)

    def test_inclusive_window_boundaries(self):
        for timestamp in ("10000000", "20000000"):
            self.assertEqual(self.observed(row(timestamp=timestamp))[0], "observed")

    def test_parser_rechecks_budget_without_refund(self):
        with self.assertRaises(MODULE.Unavailable):
            MODULE.observe(row(), 10000000, 20000000,
                           lambda: (_ for _ in ()).throw(MODULE.Unavailable("budget")))


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kernel-fake-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.real_popen = subprocess.Popen
        self.real_mkdtemp = tempfile.mkdtemp

    def fake_collect(self, code, cancellation=None):
        commands = []

        def popen(argv, **kwargs):
            commands.append((argv, kwargs))
            return self.real_popen([sys.executable, "-c", code], **kwargs)

        with patch.object(MODULE, "CaptureContext", wraps=MODULE.CaptureContext) as context, \
                patch.object(capture_module.subprocess, "Popen", popen), \
                patch.object(capture_module.tempfile, "mkdtemp",
                             lambda **kwargs: self.real_mkdtemp(dir=self.directory, **kwargs)):
            result = MODULE.collect(self.directory, 10000000, 20000000, time.monotonic() + 0.8,
                                    cancellation or MODULE.Cancellation(), lambda: None)
        self.assertEqual(context.call_args.kwargs["stream_limit"], 32768)
        self.assertEqual(context.call_args.kwargs["total_source_limit"], 65536)
        self.assertIs(context.call_args.kwargs["reuse_outputs"], False)
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertEqual(len(commands), 1)
        argv, options = commands[0]
        self.assertEqual(argv, MODULE.command(10000000, 20000000, os.geteuid()))
        self.assertEqual(dict(options["env"]), MODULE.ENVIRONMENT)
        self.assertEqual(options["cwd"], self.directory)
        return result

    def test_fixed_argv_root_owned_timeout_and_no_comm_filter(self):
        for euid in (0, 1000):
            argv = MODULE.command(10000001, 20000002, euid)
            privilege = () if euid == 0 else ("/usr/bin/sudo", "-n")
            self.assertEqual(argv[:len(privilege) + 5], privilege + (
                "/usr/bin/timeout", "--signal=TERM", "--kill-after=0.25s", "2s", "/usr/bin/journalctl"))
            self.assertIn("--boot=0", argv)
            self.assertIn("--dmesg", argv)
            self.assertIn("--since=@10.000001", argv)
            self.assertIn("--until=@20.000002", argv)
            self.assertNotIn("_COMM", " ".join(argv))

    def test_private_complete_capture_and_no_raw_artifacts(self):
        self.assertEqual(self.fake_collect(f"import sys;sys.stdout.buffer.write({row()!r})"),
                         ("observed", "userns_create", "absent"))

    def test_warnings_status_overflow_and_truncation_never_become_absence(self):
        cases = ["import sys;sys.stderr.write('access denied')", "raise SystemExit(1)",
                 "raise SystemExit(124)", "raise SystemExit(127)",
                 "import sys;sys.stdout.write('x'*32769)", "import sys;sys.stderr.write('x'*32769)",
                 "import sys;sys.stdout.write('x'*33000);sys.stderr.write('x'*33000)",
                 f"import sys;sys.stdout.buffer.write({row()[:-1]!r})"]
        for code in cases:
            with self.subTest(code=code), self.assertRaises(MODULE.Unavailable):
                self.fake_collect(code)
            self.assertEqual(list(self.directory.iterdir()), [])

    def test_missing_tool_and_cancellation_clean_private_outputs(self):
        with patch.object(capture_module.subprocess, "Popen", side_effect=FileNotFoundError), \
                self.assertRaises(MODULE.Unavailable):
            MODULE.collect(self.directory, 1, 2, time.monotonic() + 0.2, MODULE.Cancellation(), lambda: None)
        for number in (signal.SIGINT, signal.SIGTERM):
            cancellation = MODULE.Cancellation()
            cancellation.request(number)
            with self.assertRaises(MODULE.Cancelled) as caught:
                self.fake_collect("raise AssertionError('must not spawn')", cancellation)
            self.assertEqual(caught.exception.signum, number)
            self.assertEqual(list(self.directory.iterdir()), [])

    def test_failed_cleanup_does_not_release_an_observation(self):
        with patch.object(capture_module.Path, "rmdir", side_effect=OSError), self.assertRaises(MODULE.Unavailable):
            self.fake_collect("pass")

    def test_cancellation_after_spawn_discards_private_bytes(self):
        for number in (signal.SIGINT, signal.SIGTERM):
            class AfterSpawn(MODULE.Cancellation):
                checks = 0

                def check(self):
                    self.checks += 1
                    if self.checks >= 2:
                        self.request(number)
                    super().check()

            with self.assertRaises(MODULE.Cancelled) as caught:
                self.fake_collect(f"import sys;sys.stdout.write({CANARY!r})", AfterSpawn())
            self.assertEqual(caught.exception.signum, number)
            self.assertEqual(list(self.directory.iterdir()), [])

    def test_original_capture_deadline_cannot_be_renewed(self):
        processes = []

        def popen(_argv, **kwargs):
            process = self.real_popen([sys.executable, "-c", "import time;time.sleep(0.08)"], **kwargs)
            processes.append(process)
            return process

        try:
            with patch.object(capture_module.subprocess, "Popen", popen), \
                    patch.object(capture_module.tempfile, "mkdtemp",
                                 lambda **kwargs: self.real_mkdtemp(dir=self.directory, **kwargs)), \
                    self.assertRaises(MODULE.Unavailable):
                MODULE.collect(self.directory, 1, 2, time.monotonic() + 0.02, MODULE.Cancellation(), lambda: None)
            self.assertEqual(list(self.directory.iterdir()), [])
            self.assertEqual(len(processes), 1)
        finally:
            # Test-only fake child join; production never claims it reaped an
            # unknown privileged child and has no second capture deadline.
            for process in processes:
                process.wait(timeout=1)

    def test_helper_rejects_local_and_invalid_budget_before_capture(self):
        for engine, mode, remaining in (("podman", "rootless", "1800"), ("docker", "rootful", "1800"),
                                        ("docker", "rootless", "4")):
            with patch.object(MODULE, "collect") as collect, contextlib.redirect_stdout(io.StringIO()) as output:
                status = MODULE.main([engine, mode, str(self.directory), "1", "1", "1", remaining, "2"])
            collect.assert_not_called()
            self.assertEqual(status, 0)
            self.assertIn("observation=unavailable", output.getvalue())

    def test_helper_cancellation_status_and_closed_output(self):
        for number in (signal.SIGINT, signal.SIGTERM):
            with patch.dict(os.environ, HOSTED, clear=True), \
                    patch.object(MODULE, "collect", side_effect=MODULE.Cancelled(number)), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                status = MODULE.main(["docker", "rootless", str(self.directory), str(time.time_ns() // 1000),
                                      str(time.clock_gettime_ns(time.CLOCK_BOOTTIME)),
                                      str(int(time.clock_gettime(time.CLOCK_BOOTTIME) * 100)), "5", str(os.getpid())])
            self.assertEqual(status, 128 + number)
            self.assertIn("observation=unavailable", output.getvalue())
            self.assertNotIn(str(self.directory), output.getvalue())

    def test_direct_cli_accident_guard_has_no_local_fallback(self):
        for changes in ({}, {"RUNNER_ENVIRONMENT": "self-hosted"}, {"GITHUB_REF": "refs/pull/1/merge"},
                        {"GITHUB_WORKFLOW_REF": "unreviewed"}, {"DOCKER_HOST": "secret"}):
            environment = HOSTED | changes if changes else {}
            with patch.dict(os.environ, environment, clear=True), patch.object(MODULE, "collect") as collect, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                MODULE.main(["docker", "rootless", str(self.directory), "1", "1", "1", "5", str(os.getpid())])
            collect.assert_not_called()
            self.assertIn("observation=unavailable", output.getvalue())
        self.assertTrue(MODULE.admitted(HOSTED))


class ClockMappingTests(unittest.TestCase):
    def invoke(self, samples):
        with patch.dict(os.environ, HOSTED, clear=True), \
                patch.object(MODULE, "sample_clocks", side_effect=samples), \
                patch.object(MODULE.time, "clock_gettime", return_value=500.0), \
                patch.object(MODULE.os, "kill"), patch.object(MODULE.signal, "setitimer"), \
                patch.object(MODULE, "collect", return_value=("unobserved", "unknown", "absent")) as collect, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            status = MODULE.main(["docker", "rootless", "/tmp", "1000000000", "495000000000",
                                  "50000", "1795", "4242"])
        self.assertEqual(status, 0)
        return collect, output.getvalue()

    def test_forward_and_backward_steps_inside_sanity_window_refuse_before_query(self):
        for current_us in (1100000000, 1001000000):
            collect, output = self.invoke([(current_us, 500000000000)])
            collect.assert_not_called()
            self.assertIn("observation=unavailable", output)

    def test_forward_and_backward_steps_during_collection_suppress_observation(self):
        for final_us in (1105000000, 1001000000):
            collect, output = self.invoke([(1005000000, 500000000000), (final_us, 500100000000)])
            collect.assert_called_once()
            self.assertEqual(collect.call_args.args[1:3], (1000000000, 1005000000))
            self.assertIn("observation=unavailable", output)

    def test_consistent_pairs_keep_original_query_end(self):
        collect, output = self.invoke([(1005000000, 500000000000), (1005150000, 500150000000)])
        collect.assert_called_once()
        self.assertEqual(collect.call_args.args[1:3], (1000000000, 1005000000))
        self.assertIn("observation=unobserved", output)

    def test_fixed_mapping_tolerance_does_not_expand(self):
        self.assertEqual(MODULE.CLOCK_MAPPING_TOLERANCE_NS, 100000000)
        for offset_us in (-100000, 100000):
            MODULE.verify_clock_mapping(1000000000, 495000000000, 1005000000 + offset_us, 500000000000)
        for offset_us in (-100001, 100001):
            with self.assertRaises(MODULE.Unavailable):
                MODULE.verify_clock_mapping(1000000000, 495000000000, 1005000000 + offset_us, 500000000000)

    def test_clock_sampling_is_bracketed_and_refuses_slow_or_reversed_samples(self):
        with patch.object(MODULE.time, "clock_gettime_ns", side_effect=[495000000000, 495002000000]), \
                patch.object(MODULE.time, "time_ns", return_value=1000000000000):
            self.assertEqual(MODULE.sample_clocks(), (1000000000, 495001000000))
        for after in (495010000001, 494999999999):
            with patch.object(MODULE.time, "clock_gettime_ns", side_effect=[495000000000, after]), \
                    patch.object(MODULE.time, "time_ns", return_value=1000000000000), \
                    self.assertRaises(MODULE.Unavailable):
                MODULE.sample_clocks()

    def test_startup_pair_is_sampled_once_without_journal_authority(self):
        with patch.dict(os.environ, HOSTED, clear=True), \
                patch.object(MODULE, "sample_clocks", return_value=(1000000000, 495000000000)) as clocks, \
                patch.object(MODULE, "collect") as collect, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(MODULE.main(["startup-clock"]), 0)
        self.assertEqual(output.getvalue(), "1000000000 495000000000\n")
        clocks.assert_called_once()
        collect.assert_not_called()
        with patch.dict(os.environ, {}, clear=True), patch.object(MODULE, "sample_clocks") as clocks:
            self.assertEqual(MODULE.main(["startup-clock"]), 1)
        clocks.assert_not_called()


class ShellTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kernel-shell-fake-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.trace = self.directory / "trace"
        self.environment = {"PATH": str(self.directory), "TRACE": str(self.trace),
                            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                            "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
                            "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens", "ImageOS": "ubuntu24",
                            "ImageVersion": "20261020.1.0", "GITHUB_WORKFLOW_REF":
                            "Strukturpiloten/docker-lens/.github/workflows/native-validation.yml@refs/heads/main"}
        # Deliberately no journalctl, runtime, env or Python executable in PATH.
        # Both root and non-root vectors terminate at this fake first process.
        for name in ("sudo", "timeout"):
            executable = self.directory / name
            executable.write_text(f"#!{sys.executable}\nimport json,os,sys\n"
                                  "with open(os.environ['TRACE'],'a') as f: f.write(json.dumps(sys.argv)+'\\n')\n"
                                  f"print(os.environ.get('REPLY', '{MODULE.PREFIX} observation=unobserved operation=unknown errno=absent'))\n"
                                  "raise SystemExit(int(os.environ.get('STATUS','0')))\n")
            executable.chmod(0o700)

    def shell(self, setup="", invocation="permission_denied", changes=None):
        body = ("set -euo pipefail\n" + definition("native_outer_policy", RUNTIME)
                + definition("rootless_kernel_window_diagnostic")
                + "native_outer_engine=docker; expected_mode=rootless; rootless_startup_us=10000000;rootless_startup_boot_ns=495000000000\n"
                + f"script_dir={str(ROOT / 'scripts')!r};run_dir={str(self.directory)!r}\n"
                + "main_pid=$$;watchdog_pid=$$;SECONDS=0\ntrap 'exit 130' INT\ntrap 'exit 143' TERM\n"
                + setup + "\nrootless_kernel_window_diagnostic " + invocation + "\n"
                + "rootless_kernel_window_diagnostic " + invocation + "\nexit 23\n")
        return subprocess.run(["/bin/bash", "-c", body], env=self.environment | (changes or {}),
                              capture_output=True, text=True, timeout=2)

    def test_once_only_privileged_whole_helper_timer_and_preserved_failure(self):
        result = self.shell()
        self.assertEqual(result.returncode, 23)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr.count("observation=unobserved"), 1)
        commands = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.assertEqual(len(commands), 1)
        argv = commands[0]
        start = 1 if os.geteuid() == 0 else 3
        if os.geteuid() != 0:
            self.assertEqual(argv[1:3], ["-n", "timeout"])
        self.assertEqual(argv[start:start + 8], ["--signal=TERM", "--kill-after=0.5s", "3s", "env", "-i",
                                                "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"])
        self.assertEqual(set(argv[start + 8:start + 17]), {key + "=" + value for key, value in HOSTED.items()})
        self.assertEqual(argv[start + 17], "python3")
        self.assertIn("10000000", argv)
        self.assertIn("495000000000", argv)

    def test_local_rootful_and_unobserved_skip_before_any_process(self):
        for setup, observation in (("native_outer_engine=podman", "permission_denied"),
                                   ("expected_mode=rootful", "ambiguous"), ("", "unobserved"), ("", "unavailable")):
            self.trace.unlink(missing_ok=True)
            result = self.shell(setup, observation)
            self.assertEqual(result.returncode, 23)
            self.assertEqual(result.stderr, "")
            self.assertFalse(self.trace.exists())

    def test_admission_budget_and_watchdog_refuse_before_any_process(self):
        for setup in ("SECONDS=1796", "watchdog_pid=", "watchdog_pid=999999999", "rootless_startup_us=", "rootless_startup_boot_ns=",
                      "RUNNER_ENVIRONMENT=self-hosted", "DOCKER_HOST=private-canary"):
            self.trace.unlink(missing_ok=True)
            result = self.shell(setup)
            self.assertEqual(result.returncode, 23)
            self.assertIn("observation=unavailable", result.stderr)
            self.assertFalse(self.trace.exists())

    def test_exact_five_seconds_is_admitted(self):
        result = self.shell("SECONDS=1795", "operation_not_permitted")
        self.assertEqual(result.returncode, 23)
        self.assertTrue(self.trace.exists())

    def test_uncertain_status_and_untrusted_output_are_closed(self):
        for changes in ({"STATUS": "124"}, {"STATUS": "137"}, {"STATUS": "1"}, {"REPLY": CANARY}):
            result = self.shell(changes=changes)
            self.assertEqual(result.returncode, 23)
            self.assertIn("observation=unavailable", result.stderr)
            self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_cancellation_propagates_original_signal_status(self):
        for status in (130, 143):
            result = self.shell(changes={"STATUS": str(status)})
            self.assertEqual(result.returncode, status)

    def test_boundary_precedes_actual_create_and_native_cohort_is_unchanged(self):
        boundary = SOURCE.index('rootless_startup_pair=$(python3 "$script_dir/native-rootless-kernel-window.py" startup-clock')
        self.assertLess(boundary, SOURCE.index("outer_container_id=$(native_outer_bridge_command 120 create-daemon"))
        self.assertEqual(SOURCE.count('rootless_startup_pair=$(python3 "$script_dir/native-rootless-kernel-window.py" startup-clock'), 1)
        self.assertEqual(SOURCE.count('/run-exact-native-test.sh"'), 27)
        assert_current_cohort(self, SOURCE)
        self.assertIn('rootless_kernel_window_diagnostic "${diagnosis##* rootlesskit_self_reexec=}"', SOURCE)


if __name__ == "__main__":
    unittest.main()
