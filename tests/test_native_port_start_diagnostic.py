"""Independent failed-start observations: private, closed, bounded, never proof."""

import importlib.util
import json
import os
import shlex
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_port_start_diagnostic", ROOT / "scripts/native-port-start-diagnostic.py")
assert SPEC is not None and SPEC.loader is not None
DIAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAG)

RUN = "Ab12Cd34"
CANDIDATE = "b" * 40
OUTER = "a" * 64
CREATED = "c" * 64
CANARY = "protected-secret native-ID 18113 /private/path"


class FakeCollector:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls = []

    def check(self):
        pass

    def query(self, arguments):
        self.calls.append(arguments)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class NativePortStartDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dockerlens-start-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        (self.root / "diagnostics").mkdir(mode=0o700)
        self.path = self.root / "diagnostics" / "port-start-window.json"
        self.end = time.time_ns() - 1_000_000_000
        self.start = self.end - 8_000_000_000
        self.invocation = (self.start - 1_000_000_000) // 1000
        self.record = {
            "schemaVersion": 1, "phase": "multi_dynamic_oracle_start", "status": "timeout",
            "runId": RUN, "lane": "debian11-rootless", "candidateSha": CANDIDATE,
            "outerId": OUTER, "outerName": f"dl-native-{RUN}", "createdId": CREATED,
            "createdName": f"dl-port-{RUN}-multi-dynamic-oracle", "apiVersion": "1.41",
            "startRealtimeNs": self.start, "endRealtimeNs": self.end,
            "cutoffEpoch": self.end // 1_000_000_000 + 60,
        }
        self.write()

    def write(self, record=None):
        self.path.write_text(json.dumps(self.record if record is None else record))
        self.path.chmod(0o600)

    def inspect(self, **changes):
        value = {"Id": OUTER, "Name": f"dl-native-{RUN}",
                 "Config": {"Labels": {"io.dockerlens.native-run": RUN}}}
        value.update(changes)
        return json.dumps(value).encode(), b""

    def line(self, instant, text):
        return f"{DIAG.timestamp_arg(instant)} {text}\n".encode()

    def observe(self, collector):
        result = DIAG.observe(self.root, os.getuid(), RUN, "debian11-rootless", CANDIDATE,
                              self.invocation, collector)
        for forbidden in (CANARY, OUTER, CREATED, "18113", "/private/path", "2026-"):
            self.assertNotIn(forbidden, result)
        return result

    def test_actual_window_only_rootless_trace_survives_as_closed_category(self):
        logs = (self.line(self.start - 1, "permission denied " + CANARY)
                + self.line(self.start, "DOCKERLENS_ROOTLESS_TRACE: rootlesskit " + CANARY)
                + self.line(self.end, "DOCKERLENS_ROOTLESS_TRACE: slirp4netns " + CANARY)
                + self.line(self.end + 1, "cleanup runc " + CANARY))
        collector = FakeCollector([self.inspect(), self.inspect(), (logs, b"")])
        self.assertEqual(self.observe(collector), DIAG.closed(
            "complete", "rootless_trace", "rootless_network"))
        self.assertEqual(collector.calls[:2], [
            ["inspect", "--format", "{{json .}}", OUTER],
            ["inspect", "--format", "{{json .}}", f"dl-native-{RUN}"],
        ])
        self.assertEqual(collector.calls[2], [
            "logs", "--timestamps", "--since", DIAG.timestamp_arg(self.start),
            "--until", DIAG.timestamp_arg(self.end), "--tail", "80", OUTER,
        ])

    def test_log_stderr_is_timestamp_filtered_and_raw_lines_never_classified(self):
        stdout = self.line(self.start, "docker-proxy bind: " + CANARY)
        stderr = (self.line(self.end, "address already in use " + CANARY)
                  + b"permission denied protected-secret\n"
                  + self.line(self.end + 1, "cleanup rootlesskit"))
        self.assertEqual(DIAG.classify(stdout, stderr, self.start, self.end),
                         ("daemon", "port_proxy"))
        self.assertEqual(DIAG.classify(b"rootlesskit\n", b"", self.start, self.end),
                         ("none", "unclassified"))
        self.assertEqual(DIAG.classify(self.line(self.start, "runc permission denied"),
                                       b"", self.start, self.end), ("daemon", "ambiguous"))

    def test_missing_window_other_stage_pending_success_stale_run_never_query(self):
        mutations = (
            {"phase": "cleanup"}, {"status": "pending"}, {"status": "pass"},
            {"runId": "Stale001"}, {"lane": "upstream-rootless"},
            {"candidateSha": "d" * 40}, {"apiVersion": "1.56"},
            {"createdName": f"dl-port-{RUN}-multi-dynamic-rendered"},
            {"outerName": "foreign"}, {"createdId": "short"}, {"outerId": "A" * 64},
            {"schemaVersion": True}, {"unexpected": CANARY},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.write(self.record | mutation)
                collector = FakeCollector()
                self.assertEqual(self.observe(collector), DIAG.closed("window_unavailable"))
                self.assertEqual(collector.calls, [])
        self.path.unlink()
        collector = FakeCollector()
        self.assertEqual(self.observe(collector), DIAG.closed("window_unavailable"))
        self.assertEqual(collector.calls, [])

    def test_duplicate_oversize_wrong_owner_mode_symlink_and_path_reject_before_io(self):
        self.path.write_text(json.dumps(self.record)[:-1] + ', "status":"timeout"}')
        self.assertEqual(self.observe(FakeCollector()), DIAG.closed("window_unavailable"))
        self.path.write_bytes(b"x" * 4097)
        self.assertEqual(self.observe(FakeCollector()), DIAG.closed("window_unavailable"))
        self.write()
        for mode in (0o644, 0o400, 0o660, 0o4600):
            self.path.chmod(mode)
            self.assertEqual(self.observe(FakeCollector()), DIAG.closed("window_unavailable"))
        self.write()
        for location in (self.root, self.root / "diagnostics"):
            location.chmod(0o755)
            self.assertEqual(self.observe(FakeCollector()), DIAG.closed("window_unavailable"))
            location.chmod(0o700)
        self.assertEqual(DIAG.observe(self.root, os.getuid() + 1, RUN,
                                     "debian11-rootless", CANDIDATE, self.invocation, FakeCollector()),
                         DIAG.closed("window_unavailable"))
        saved = self.path.with_name("original")
        self.path.rename(saved)
        self.path.symlink_to(saved)
        self.assertEqual(self.observe(FakeCollector()), DIAG.closed("window_unavailable"))
        self.path.unlink()
        saved.rename(self.path)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(DIAG.observe(alias, os.getuid(), RUN, "debian11-rootless",
                                     CANDIDATE, self.invocation, FakeCollector()),
                         DIAG.closed("window_unavailable"))

    def test_hardlink_and_directory_symlink_reject_without_query(self):
        os.link(self.path, self.root / "linked")
        self.assertEqual(self.observe(FakeCollector()), DIAG.closed("window_unavailable"))
        (self.root / "linked").unlink()
        diagnostics = self.root / "diagnostics"
        diagnostics.rename(self.root / "elsewhere")
        diagnostics.symlink_to(self.root / "elsewhere", target_is_directory=True)
        self.assertEqual(self.observe(FakeCollector()), DIAG.closed("window_unavailable"))

    def test_future_reversal_stale_and_original_cutoff_reject_without_query(self):
        mutations = (
            {"startRealtimeNs": self.end + 1},
            {"endRealtimeNs": time.time_ns() + 10_000_000_000},
            {"startRealtimeNs": self.start - 200_000_000_000,
             "endRealtimeNs": self.end - 200_000_000_000},
            {"startRealtimeNs": self.end - 12_000_000_000},
            {"cutoffEpoch": self.start // 1_000_000_000 - 1},
            {"cutoffEpoch": self.end // 1_000_000_000 + 181},
            {"startRealtimeNs": True}, {"endRealtimeNs": -1},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.write(self.record | mutation)
                collector = FakeCollector()
                self.assertEqual(self.observe(collector), DIAG.closed("window_unavailable"))
                self.assertEqual(collector.calls, [])
        self.write()
        collector = FakeCollector()
        self.assertEqual(DIAG.observe(self.root, os.getuid(), RUN, "debian11-rootless",
                                     CANDIDATE, self.end // 1000, collector),
                         DIAG.closed("window_unavailable"))
        self.assertEqual(collector.calls, [])

    def test_immutable_id_and_current_named_outer_both_require_owner(self):
        foreign = (
            self.inspect(Id="e" * 64), self.inspect(Name="foreign"),
            self.inspect(Config={"Labels": {"io.dockerlens.native-run": "Stale001"}}),
            (self.inspect()[0], b"warning " + CANARY.encode()),
        )
        for bad in foreign:
            for stage in (0, 1):
                with self.subTest(stage=stage, bad=bad):
                    collector = FakeCollector([self.inspect()] * stage + [bad])
                    self.assertEqual(self.observe(collector), DIAG.closed("ownership_unverified"))
                    self.assertEqual(len(collector.calls), stage + 1)

    def test_file_content_metadata_or_inode_drift_suppresses_result(self):
        for fault in ("content", "mode", "inode"):
            with self.subTest(fault=fault):
                self.write()
                collector = FakeCollector([self.inspect(), self.inspect(), (b"", b"")])
                original = collector.query

                def drift(arguments):
                    result = original(arguments)
                    if fault == "content":
                        self.path.write_bytes(self.path.read_bytes().replace(b'"timeout"', b'"pending"'))
                    elif fault == "mode":
                        self.path.chmod(0o644)
                    else:
                        data = self.path.read_bytes()
                        self.path.rename(self.path.with_name("old"))
                        self.path.write_bytes(data)
                        self.path.chmod(0o600)
                    return result

                collector.query = drift
                self.assertEqual(self.observe(collector), DIAG.closed("window_unavailable"))
                self.assertEqual(len(collector.calls), 1)
                old = self.path.with_name("old")
                if old.exists():
                    old.unlink()

    def test_timeout_cancel_nonzero_and_overflow_never_accept_partial_observation(self):
        for category in ("timeout", "cancelled", "query_failed", "output_limit", "unavailable"):
            collector = FakeCollector([self.inspect(), self.inspect(), DIAG.Unavailable(category)])
            self.assertEqual(self.observe(collector), DIAG.closed(category))

    def collector(self, remaining=100):
        return DIAG.Collector(int(time.clock_gettime(time.CLOCK_BOOTTIME) * 100),
                              remaining, os.getpid())

    def test_total_allowance_uses_boot_and_monotonic_not_realtime_and_no_budget_extension(self):
        boot = time.clock_gettime(time.CLOCK_BOOTTIME)
        for remaining in (0, 1, 3, 4):
            with self.subTest(remaining=remaining), self.assertRaises(DIAG.Unavailable) as caught:
                DIAG.Collector(int(boot * 100), remaining, os.getpid())
            self.assertEqual(caught.exception.collector, "budget")
        with self.assertRaises(DIAG.Unavailable):
            DIAG.Collector(int((boot - 4) * 100), 100, os.getpid())
        with self.assertRaises(DIAG.Unavailable):
            DIAG.Collector(int((boot + 2) * 100), 100, os.getpid())
        collector = self.collector()
        self.assertLessEqual(collector.deadline - time.monotonic(), 3)
        with patch.object(DIAG.time, "time_ns", return_value=0):
            collector.check()
        with patch.object(DIAG.time, "clock_gettime", return_value=collector.boot_deadline):
            with self.assertRaises(DIAG.Unavailable) as caught:
                collector.check()
            self.assertEqual(caught.exception.collector, "timeout")
        collector = self.collector()
        collector.cancel(signal.SIGTERM, None)
        with self.assertRaises(DIAG.Unavailable) as caught:
            collector.check()
        self.assertEqual(caught.exception.collector, "cancelled")
        with self.assertRaises(DIAG.Unavailable):
            DIAG.Collector(int(boot * 100), 100, 1)

    def tool(self, name, content):
        path = self.root / name
        path.write_text(content)
        path.chmod(0o755)
        return path

    def test_real_process_nonzero_valid_stdout_warning_timeout_and_combined_cap(self):
        # Uses only fake Podman and the installed timeout; no native runtime.
        for script, category in (
            ("printf '%s' '{\"Id\":\"valid\"}'; exit 42", "query_failed"),
            ("printf 'protected-secret'; printf 'warning' >&2; exit 125", "query_failed"),
            ("sleep 10", "timeout"),
            (f"{shlex.quote(os.sys.executable)} -c 'import os; os.write(1,b\"x\"*40000); os.write(2,b\"y\"*40000)'",
             "output_limit"),
        ):
            with self.subTest(category=category):
                self.tool("podman", "#!/bin/sh\n" + script + "\n")
                collector = self.collector()
                started = time.monotonic()
                with patch.dict(os.environ, {"PATH": str(self.root) + ":" + os.environ["PATH"]}):
                    with self.assertRaises(DIAG.Unavailable) as caught:
                        collector.query(["logs", OUTER])
                self.assertEqual(caught.exception.collector, category)
                self.assertLess(time.monotonic() - started, 4)
                self.assertLessEqual(collector.bytes, DIAG.OUTPUT_LIMIT + 4096)

    def shell_function(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        return "port_start_failure_diagnostic() {" + source.split(
            "port_start_failure_diagnostic() {", 1)[1].split(
                '\n"$(dirname "$0")/run-exact-native-test.sh" native_capture', 1)[0]

    def test_parent_original_failure_cleanup_even_diagnostic_failure_and_no_query_pass(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        block = 'port_invocation_us=${EPOCHREALTIME/./}' + source.split(
            'port_invocation_us=${EPOCHREALTIME/./}', 1)[1].split(
                '\nif [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR', 1)[0]
        block = block.replace('"$(dirname "$0")/run-exact-native-test.sh"', "exact_wrapper")
        for status in (0, 37):
            script = ("set -euo pipefail\n"
                      "trap 'printf cleanup >> \"$calls\"' EXIT\n"
                      f"exact_wrapper() {{ return {status}; }}\n"
                      "port_start_failure_diagnostic() { printf diagnostic >> \"$calls\"; return 91; }\n"
                      + block + "\nprintf evidence >> \"$calls\"\n")
            calls = self.root / "calls"
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                    env=os.environ | {"calls": str(calls)})
            self.assertEqual(result.returncode, status)
            self.assertEqual(calls.read_text(), "evidencecleanup" if status == 0 else "diagnosticcleanup")
            calls.unlink()

    def test_parent_root_budget_guard_and_helper_status_are_closed(self):
        # Exercise root control flow with fake tools regardless of test UID;
        # the real non-root subprocess refusal is verified separately below.
        function = self.shell_function().replace("EUID", "observer_test_euid")
        for seconds, helper_status, expected in (
            (0, 0, "complete"), (1796, 0, "budget"), (0, 42, "unavailable"),
        ):
            with self.subTest(seconds=seconds, helper_status=helper_status):
                calls = self.root / "helper-calls"
                self.tool("timeout", '#!/bin/sh\nprintf "%s\\n" "$*" >> "$calls"\nshift 3\nexec "$@"\n')
                self.tool("python3", '#!/bin/sh\nprintf "%s\\n" "$*" >> "$calls"\n'
                          + f"printf '%s\\n' '{DIAG.closed('complete', 'rootless_trace', 'rootless_network')}'\n"
                          + f"exit {helper_status}\n")
                script = ("set -euo pipefail\n" + function + "\n"
                          + f"SECONDS={seconds}; watchdog_pid=$$; observer_test_euid=0; "
                          + "podman_cmd=(podman); "
                          + "script_dir=/private; run_dir=/private; run_id=Ab12Cd34; lane=debian11-rootless; "
                          + f"NATIVE_PORT_CANDIDATE_SHA={CANDIDATE}; port_invocation_us=1234567890123456; "
                          + "port_start_failure_diagnostic\n")
                result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                    env=os.environ | {"PATH": str(self.root) + ":" + os.environ["PATH"], "calls": str(calls)})
                self.assertEqual(result.returncode, 0)
                self.assertIn("collector=" + expected, result.stderr)
                self.assertNotIn(CANARY, result.stderr)
                if seconds == 1796:
                    self.assertFalse(calls.exists())
                else:
                    self.assertIn("--signal=TERM --kill-after=0.25s 3.5s", calls.read_text())
                    calls.unlink()

    def test_nonroot_observer_refuses_before_stalled_sudo_or_any_query(self):
        # Use an actual unprivileged Bash, dropping only the test child UID if
        # this offline suite itself runs as root. No sudo is used for the test.
        self.root.chmod(0o755)
        calls = self.root / "refused-calls"
        calls.touch()
        calls.chmod(0o666)
        for name in ("sudo", "timeout", "python3", "podman"):
            self.tool(name, '#!/bin/sh\nprintf "%s\\n" "$0" >> "$calls"\nsleep 30\n')
        script = ("set -euo pipefail\n" + self.shell_function() + "\n"
                  + "(( EUID != 0 )) || exit 99\n"
                  + "SECONDS=0; watchdog_pid=$$; podman_cmd=(sudo -n podman); "
                  + "script_dir=/private; run_dir=/private; run_id=Ab12Cd34; lane=debian11-rootless; "
                  + f"NATIVE_PORT_CANDIDATE_SHA={CANDIDATE}; port_invocation_us=1234567890123456; "
                  + "port_start_failure_diagnostic\n")
        identity = {"user": 65534, "group": 65534} if os.geteuid() == 0 else {}
        started = time.monotonic()
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=1,
            env=os.environ | {"PATH": str(self.root) + ":" + os.environ["PATH"], "calls": str(calls)},
            **identity)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), DIAG.closed("unavailable"))
        self.assertEqual(result.stdout, "")
        self.assertEqual(calls.read_text(), "")

    def test_helper_nonroot_entrypoint_refuses_without_initialization_or_query(self):
        with patch.object(DIAG.os, "geteuid", return_value=1000), \
                patch.object(DIAG, "Collector") as collector, \
                patch.object(DIAG.subprocess, "Popen") as popen, \
                patch("builtins.print") as output:
            self.assertEqual(DIAG.main(["private"] * 9), 0)
            output.assert_called_once_with(DIAG.closed("unavailable"))
            collector.assert_not_called()
            popen.assert_not_called()

    def test_parent_final_boot_handoff_rejects_late_reversed_and_raw_results(self):
        function = self.shell_function().replace("EUID", "observer_test_euid")
        for end, output, expected in (
            ("103.98", DIAG.closed("complete", "daemon", "port_proxy"), "complete"),
            ("103.99", DIAG.closed("complete", "daemon", "port_proxy"), "timeout"),
            ("104.01", DIAG.closed("complete", "daemon", "port_proxy"), "timeout"),
            ("99.00", DIAG.closed("complete", "daemon", "port_proxy"), "timeout"),
            ("100.00", CANARY, "unavailable"),
            ("100.00", DIAG.closed("complete", "daemon", "port_proxy") + CANARY, "unavailable"),
        ):
            with self.subTest(end=end, output=output):
                self.tool("timeout", '#!/bin/sh\nshift 3\nexec "$@"\n')
                self.tool("python3", "#!/bin/sh\nprintf '%s\\n' " + shlex.quote(output) + "\n")
                script = ("set -euo pipefail\n" + function + "\n"
                          + "read_count=0\nread() { read_count=$((read_count + 1)); "
                          + f"if (( read_count == 1 )); then builtin read \"$@\" <<< '100.00 0'; "
                          + f"else builtin read \"$@\" <<< '{end} 0'; fi; }}\n"
                          + "SECONDS=0; watchdog_pid=$$; observer_test_euid=0; podman_cmd=(podman); script_dir=/private; "
                          + "run_dir=/private; run_id=Ab12Cd34; lane=debian11-rootless; "
                          + f"NATIVE_PORT_CANDIDATE_SHA={CANDIDATE}; port_invocation_us=1234567890123456; "
                          + "port_start_failure_diagnostic\n")
                result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                    env=os.environ | {"PATH": str(self.root) + ":" + os.environ["PATH"]})
                self.assertEqual(result.returncode, 0)
                self.assertIn("collector=" + expected, result.stderr)
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_timestamp_fraction_offset_and_malformed_window_filter(self):
        self.assertEqual(DIAG.timestamp_ns(b"1970-01-01T00:00:00.000000001Z"), 1)
        self.assertEqual(DIAG.timestamp_ns(b"1970-01-01T01:00:00.000000001+01:00"), 1)
        for invalid in (b"2026-13-01T00:00:00Z", b"2026-01-01T24:00:00Z",
                        b"2026-01-01T00:00:00.1234567890Z", b"2026-01-01T00:00:00"):
            self.assertIsNone(DIAG.timestamp_ns(invalid))

    def test_watchdog_dead_cancellation_and_clock_expiry_prevent_new_query(self):
        for category in ("watchdog", "cancelled", "timeout"):
            collector = self.collector()
            if category == "watchdog":
                collector.watchdog = 1
            elif category == "cancelled":
                collector.cancel(signal.SIGINT, None)
            else:
                collector.deadline = time.monotonic() - 1
            with patch.object(DIAG.subprocess, "Popen") as popen:
                with self.assertRaises(DIAG.Unavailable) as caught:
                    collector.query(["inspect", OUTER])
                self.assertEqual(caught.exception.collector, category)
                popen.assert_not_called()

    def test_rust_and_evidence_boundaries_remain_explicit(self):
        source = (ROOT / "src/native_port_tests.rs").read_text()
        wrapper = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        evidence = (ROOT / "scripts/native-evidence.py").read_text()
        self.assertIn('Some(28 | 124)', source)
        self.assertIn('start_window_identity(method, path, cleanup)', source)
        self.assertIn('"NATIVE_PORT_START_DIAGNOSTIC_PATH"', source)
        self.assertIn('let directory = capture.join("diagnostics")', source)
        self.assertIn('if cleanup || method != "POST"', source)
        self.assertIn('canonical_id(id)', source.split('fn start_window_identity', 1)[1].split('fn api_with_cleanup', 1)[0])
        self.assertIn('let Some(total) = start_diagnostic_budget(self.remaining())', source)
        self.assertIn('Some(Duration::from_secs(4))', source)
        self.assertIn('remaining > if cleanup { 1 } else { 40 }', source)
        self.assertIn('const EXPECTED_SHAPES: [&str; 8]', source)
        self.assertIn('run_deadline_epoch=$(( $(date +%s) + 180 ))', wrapper)
        self.assertIn('timeout 180 cargo', wrapper)
        self.assertNotIn('port-start-window', evidence)
        self.assertNotIn('START_DIAGNOSTIC', evidence)
        self.assertLess(harness.index('port_start_failure_diagnostic || true'),
                        harness.index('python3 "$script_dir/native-evidence.py"'))


if __name__ == "__main__":
    unittest.main()
