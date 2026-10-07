"""Independent private-file diagnostics; no daemon or privileged query."""
import importlib.util
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/native-port-start-diagnostic.py"
SPEC = importlib.util.spec_from_file_location("port_start_diagnostic", HELPER)
assert SPEC is not None and SPEC.loader is not None
DIAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAG)
RUN, OUTER, CREATED, CANDIDATE = "Ab12Cd34", "a" * 64, "c" * 64, "b" * 40
IMAGE = "registry.invalid/native:1.0.0@sha256:" + "d" * 64
CANARY = "protected-secret native-ID 18113 /private/path"


class NativePortStartDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dockerlens-start-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.diag = self.root / "diagnostics"
        self.diag.mkdir(mode=0o700)
        DIAG.prepare(self.root, RUN, "debian11-rootless")
        self.log = self.diag / DIAG.LOG_FILE
        self.registration = self.diag / DIAG.REGISTRATION_FILE
        self.window = self.diag / DIAG.WINDOW_FILE
        self.fd = os.open(self.log, os.O_RDONLY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.fd)
        self.end = time.time_ns() - 10**9
        self.start = self.end - 8 * 10**9
        self.invocation = (self.start - 10**9) // 1000
        self.prefix = self.line(self.start - 10, "startup " + CANARY)
        self.log.write_bytes(self.prefix)
        self.native = {
            "Id": OUTER, "Name": f"dl-native-{RUN}", "ImageName": "normalized-display-name",
            "ImageDigest": DIAG.image_digest(IMAGE),
            "Config": {"Labels": {"io.dockerlens.native-run": RUN}},
            "HostConfig": {"LogConfig": {"Type": "k8s-file", "Path": str(self.log)}},
        }
        DIAG.register(self.root, RUN, "debian11-rootless", IMAGE, OUTER, self.fd, self.native)
        self.record = {
            "schemaVersion": 1, "phase": "multi_dynamic_oracle_start", "status": "timeout",
            "runId": RUN, "lane": "debian11-rootless", "candidateSha": CANDIDATE,
            "outerId": OUTER, "outerName": f"dl-native-{RUN}", "createdId": CREATED,
            "createdName": f"dl-port-{RUN}-multi-dynamic-oracle", "apiVersion": "1.41",
            "startRealtimeNs": self.start, "endRealtimeNs": self.end,
            "cutoffEpoch": self.end // 10**9 + 60,
        }
        self.write(self.window, self.record)

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def line(self, instant, payload, stream="stdout", flag="F"):
        return f"{DIAG.timestamp_arg(instant)} {stream} {flag} {payload}\n".encode()

    def append(self, data):
        with self.log.open("ab") as output:
            output.write(data)

    def collector(self, remaining=100):
        return DIAG.Collector(int(time.clock_gettime(time.CLOCK_BOOTTIME) * 100), remaining, os.getpid())

    def observe(self, collector=None):
        result = DIAG.observe(self.root, os.geteuid(), RUN, "debian11-rootless", CANDIDATE,
                              self.invocation, collector or self.collector(), self.fd, IMAGE)
        for secret in (CANARY, OUTER, CREATED, "18113", "/private/path", "2026-"):
            self.assertNotIn(secret, result)
        return result

    def test_exclusive_private_setup_and_digest_normalization(self):
        value = json.loads(self.registration.read_bytes())
        self.assertEqual(value["status"], "registered")
        self.assertEqual(value["imageDigest"], DIAG.image_digest(IMAGE))
        self.assertEqual(value["prefixBytes"], len(self.prefix))
        for path in (self.log, self.registration):
            self.assertEqual(path.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(self.diag.stat().st_mode & 0o7777, 0o700)
        with self.assertRaises(FileExistsError):
            DIAG.prepare(self.root, RUN, "debian11-rootless")

    def test_registration_rejects_id_name_label_digest_driver_path_and_empty_prefix(self):
        prepared = json.loads(self.registration.read_bytes())
        prepared.update(status="prepared", outerId=None, image=None, imageDigest=None,
                        prefixBytes=0, prefixSha256=None)
        for change in (
            {"Id": "e" * 64}, {"Name": "foreign"}, {"ImageDigest": None},
            {"ImageDigest": "sha256:" + "e" * 64},
            {"Config": {"Labels": {"io.dockerlens.native-run": "Stale001"}}},
            {"HostConfig": {"LogConfig": {"Type": "journald", "Path": str(self.log)}}},
            {"HostConfig": {"LogConfig": {"Type": "k8s-file", "Path": "/foreign"}}},
        ):
            with self.subTest(change=change):
                self.write(self.registration, prepared)
                with self.assertRaises(DIAG.Unavailable):
                    DIAG.register(self.root, RUN, "debian11-rootless", IMAGE, OUTER,
                                  self.fd, self.native | change)
        self.write(self.registration, prepared)
        self.log.write_bytes(b"")
        with self.assertRaises(DIAG.Unavailable):
            DIAG.register(self.root, RUN, "debian11-rootless", IMAGE, OUTER, self.fd, self.native)

    def test_only_actual_window_complete_rootless_stdout_stderr_are_classified(self):
        self.append(self.line(self.start, "DOCKERLENS_ROOTLESS_TRACE: rootlesskit " + CANARY)
                    + self.line(self.end, "DOCKERLENS_ROOTLESS_TRACE: slirp4netns " + CANARY, "stderr")
                    + self.line(self.end + 1, "cleanup permission denied " + CANARY))
        self.assertEqual(self.observe(), DIAG.closed("complete", "rootless_trace", "rootless_network"))

    def test_eighty_records_preserve_the_first_error_and_overflow_refuses(self):
        self.append(self.line(self.start, "permission denied " + CANARY)
                    + b"".join(self.line(self.start + index, "benign " + CANARY) for index in range(79)))
        self.assertEqual(self.observe(), DIAG.closed("complete", "daemon", "permission"))
        self.append(self.line(self.start + 80, "benign " + CANARY))
        self.assertEqual(self.observe(), DIAG.closed("output_limit"))

    def test_missing_other_stage_pending_stale_wrong_api_and_clock_windows_do_not_read_log(self):
        for mutation in (
            {"phase": "cleanup"}, {"status": "pending"}, {"status": "pass"},
            {"runId": "Stale001"}, {"lane": "upstream-rootless"}, {"candidateSha": "e" * 40},
            {"createdId": "short"}, {"outerId": "A" * 64}, {"apiVersion": "1.56"},
            {"createdName": f"dl-port-{RUN}-multi-dynamic-rendered"}, {"schemaVersion": True},
            {"startRealtimeNs": self.end + 1}, {"endRealtimeNs": time.time_ns() + 10**10},
            {"startRealtimeNs": self.start - 200 * 10**9, "endRealtimeNs": self.end - 200 * 10**9},
            {"cutoffEpoch": self.start // 10**9 - 1}, {"unexpected": CANARY},
        ):
            with self.subTest(mutation=mutation):
                self.write(self.window, self.record | mutation)
                with patch.object(DIAG.os, "pread") as read:
                    self.assertEqual(self.observe(), DIAG.closed("window_unavailable"))
                    read.assert_not_called()
        self.window.unlink()
        self.assertEqual(self.observe(), DIAG.closed("window_unavailable"))

    def test_context_duplicate_key_oversize_owner_mode_symlink_and_drift(self):
        for path in (self.window, self.registration):
            baseline = path.read_bytes()
            path.write_bytes(baseline[:-1] + b',"schemaVersion":1}')
            self.assertNotIn("collector=complete", self.observe())
            path.write_bytes(b"x" * 4097)
            self.assertNotIn("collector=complete", self.observe())
            path.write_bytes(baseline)
            path.chmod(0o644)
            self.assertNotIn("collector=complete", self.observe())
            path.chmod(0o600)
            saved = path.with_name(path.name + ".saved")
            path.rename(saved)
            path.symlink_to(saved)
            self.assertNotIn("collector=complete", self.observe())
            path.unlink()
            saved.rename(path)
        self.root.chmod(0o755)
        self.assertEqual(self.observe(), DIAG.closed("window_unavailable"))
        self.root.chmod(0o700)
        with patch.object(DIAG, "classify", side_effect=lambda *args: (
                self.window.chmod(0o644) or "daemon", "permission")):
            self.assertNotIn("collector=complete", self.observe())

    def test_only_exact_debian_rootless_oracle_window_allows_twenty_seven_seconds(self):
        for duration, accepted in ((27 * 10**9, True), (27 * 10**9 + 1, False)):
            record = self.record | {"startRealtimeNs": self.end - duration}
            self.write(self.window, record)
            held = DIAG.Window(self.root, os.geteuid())
            try:
                invocation = (record["startRealtimeNs"] - 10**9) // 1000
                if accepted:
                    self.assertEqual(held.validate(RUN, "debian11-rootless", CANDIDATE, invocation,
                                                   time.time_ns()), record)
                else:
                    with self.assertRaises(DIAG.Unavailable):
                        held.validate(RUN, "debian11-rootless", CANDIDATE, invocation, time.time_ns())
            finally:
                held.close()

    def test_other_profile_windows_keep_eleven_seconds_and_mismatches_never_gain_allowance(self):
        for lane, api in (("debian11-rootful", "1.41"), ("upstream-rootful", "1.56"),
                          ("upstream-rootless", "1.56")):
            for duration, accepted in ((11 * 10**9, True), (11 * 10**9 + 1, False)):
                record = self.record | {"lane": lane, "apiVersion": api,
                                        "startRealtimeNs": self.end - duration}
                self.write(self.window, record)
                held = DIAG.Window(self.root, os.geteuid())
                try:
                    invocation = (record["startRealtimeNs"] - 10**9) // 1000
                    if accepted:
                        self.assertEqual(held.validate(RUN, lane, CANDIDATE, invocation,
                                                       time.time_ns()), record)
                    else:
                        with self.assertRaises(DIAG.Unavailable):
                            held.validate(RUN, lane, CANDIDATE, invocation, time.time_ns())
                finally:
                    held.close()
        for change in ({"lane": "upstream-rootless"}, {"apiVersion": "1.56"},
                       {"createdName": f"dl-port-{RUN}-multi-dynamic-rendered"}, {"phase": "cleanup"}):
            record = self.record | {"startRealtimeNs": self.end - 27 * 10**9} | change
            self.write(self.window, record)
            held = DIAG.Window(self.root, os.geteuid())
            try:
                with self.assertRaises(DIAG.Unavailable):
                    held.validate(RUN, "debian11-rootless", CANDIDATE,
                                  (record["startRealtimeNs"] - 10**9) // 1000, time.time_ns())
            finally:
                held.close()

    def test_context_identity_digest_and_metadata_must_match_original_source(self):
        baseline = json.loads(self.registration.read_bytes())
        for mutation in ({"outerId": "e" * 64}, {"runId": "Stale001"},
                         {"imageDigest": "sha256:" + "e" * 64}, {"logDriver": "journald"},
                         {"uid": os.geteuid() + 1}, {"inode": baseline["inode"] + 1},
                         {"mode": 0o644}, {"prefixSha256": "f" * 64}, {"prefixBytes": 0}):
            with self.subTest(mutation=mutation):
                self.write(self.registration, baseline | mutation)
                self.assertEqual(self.observe(), DIAG.closed("ownership_unverified"))

    def test_rotation_never_reads_replacement_or_fixes_mode(self):
        replacement = self.log.with_name("replacement")
        replacement.write_bytes(self.prefix + self.line(self.start, "permission denied " + CANARY))
        replacement.chmod(0o640)
        self.log.unlink()
        replacement.rename(self.log)
        with patch.object(DIAG.os, "pread") as read:
            self.assertEqual(self.observe(), DIAG.closed("ownership_unverified"))
            read.assert_not_called()
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o640)

    def test_source_symlink_hardlink_and_mode_refuse_before_read(self):
        for fault in ("symlink", "hardlink", "mode"):
            with self.subTest(fault=fault):
                saved = self.log.with_name("saved")
                if fault == "symlink":
                    self.log.rename(saved)
                    self.log.symlink_to(saved)
                elif fault == "hardlink":
                    os.link(self.log, saved)
                else:
                    self.log.chmod(0o644)
                with patch.object(DIAG.os, "pread") as read:
                    self.assertEqual(self.observe(), DIAG.closed("ownership_unverified"))
                    read.assert_not_called()
                if fault == "symlink":
                    self.log.unlink()
                    saved.rename(self.log)
                elif fault == "hardlink":
                    saved.unlink()
                else:
                    self.log.chmod(0o600)
        original = os.fstat

        def wrong_owner(descriptor):
            info = original(descriptor)
            if descriptor != self.fd:
                return info
            fields = list(info)
            fields[4] = info.st_uid + 1
            return os.stat_result(fields)

        with patch.object(DIAG.os, "fstat", side_effect=wrong_owner), patch.object(DIAG.os, "pread") as read:
            self.assertEqual(self.observe(), DIAG.closed("ownership_unverified"))
            read.assert_not_called()

    def test_truncate_prefix_drift_oversize_partial_malformed_and_reversed_cri_refuse(self):
        for data, category in (
            (b"", "output_limit"), (b"x" * (DIAG.OUTPUT_LIMIT + 1), "output_limit"),
            (self.prefix.replace(b"startup", b"forged!") + self.line(self.start, "runc"), "ownership_unverified"),
            (self.prefix + self.line(self.start, "runc")[:-1], "unavailable"),
            (self.prefix + self.line(self.start, "runc", flag="P"), "unavailable"),
            (self.prefix + self.line(self.start, "runc", stream="unknown"), "unavailable"),
            (self.prefix + b"malformed timestamp stdout F private\n", "unavailable"),
            (self.prefix + self.line(self.start, "runc") + self.line(self.start - 1, "runc"), "unavailable"),
        ):
            with self.subTest(category=category):
                self.log.write_bytes(data)
                collector = self.collector()
                self.assertEqual(self.observe(collector), DIAG.closed(category))
                self.assertLessEqual(collector.bytes, DIAG.OUTPUT_LIMIT)

    def test_append_race_during_snapshot_suppresses_result(self):
        original = os.pread

        def race(*args):
            data = original(*args)
            self.append(self.line(self.end + 1, "cleanup " + CANARY))
            return data

        with patch.object(DIAG.os, "pread", side_effect=race):
            self.assertEqual(self.observe(), DIAG.closed("ownership_unverified"))

    def test_timeout_cancel_watchdog_budget_and_boottime_bound_new_io(self):
        for reason in ("timeout", "cancelled", "watchdog"):
            collector = self.collector()
            if reason == "timeout":
                collector.deadline = time.monotonic() - 1
            elif reason == "cancelled":
                collector.cancel(signal.SIGTERM, None)
            else:
                collector.watchdog = 1
            with patch.object(DIAG.os, "pread") as read:
                self.assertEqual(self.observe(collector), DIAG.closed(reason))
                read.assert_not_called()
        for remaining in (0, 3, 4):
            with self.assertRaises(DIAG.Unavailable):
                self.collector(remaining)
        collector = self.collector()
        self.assertLessEqual(collector.deadline - time.monotonic(), 3)
        with patch.object(DIAG.time, "time_ns", return_value=0):
            collector.check()
        with patch.object(DIAG.time, "clock_gettime", return_value=collector.boot_deadline):
            with self.assertRaises(DIAG.Unavailable):
                collector.check()

    def shell_function(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        return "port_start_failure_diagnostic() {" + source.split(
            "port_start_failure_diagnostic() {", 1)[1].split(
                '\n"$(dirname "$0")/run-exact-native-test.sh" native_capture', 1)[0]

    def test_original_wrapper_status_cleanup_and_no_observer_on_pass(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        block = 'port_invocation_us=${EPOCHREALTIME/./}' + source.split(
            'port_invocation_us=${EPOCHREALTIME/./}', 1)[1].split(
                '\nif [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR', 1)[0]
        block = block.replace('"$(dirname "$0")/run-exact-native-test.sh"', "exact_wrapper")
        calls = self.root / "calls"
        for status in (0, 37):
            script = ("set -euo pipefail\ntrap 'printf cleanup >> \"$calls\"' EXIT\n"
                      + f"exact_wrapper() {{ return {status}; }}\n"
                      + "port_start_failure_diagnostic() { printf diagnostic >> \"$calls\"; return 91; }\n"
                      + block + "\nprintf evidence >> \"$calls\"\n")
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                    env=os.environ | {"calls": str(calls)})
            self.assertEqual(result.returncode, status)
            self.assertEqual(calls.read_text(), "evidencecleanup" if status == 0 else "diagnosticcleanup")
            calls.unlink()

    def tool(self, name, content):
        path = self.root / name
        path.write_text(content)
        path.chmod(0o755)

    def test_parent_budget_late_boottime_raw_and_nonzero_helpers_are_closed(self):
        for seconds, end, status, output, expected in (
            (0, "103.98", 0, DIAG.closed("complete", "daemon", "port_proxy"), "complete"),
            (0, "103.99", 0, DIAG.closed("complete", "daemon", "port_proxy"), "timeout"),
            (0, "99.00", 0, DIAG.closed("complete", "daemon", "port_proxy"), "timeout"),
            (1796, "100.00", 0, "ignored", "budget"),
            (0, "100.00", 42, "ignored", "unavailable"),
            (0, "100.00", 0, CANARY, "unavailable"),
        ):
            with self.subTest(expected=expected, end=end):
                self.tool("timeout", '#!/bin/sh\nshift 3\nexec "$@"\n')
                self.tool("python3", "#!/bin/sh\nprintf '%s\\n' " + shlex.quote(output) + f"\nexit {status}\n")
                script = ("set -euo pipefail\n" + self.shell_function() + "\n"
                          + "read_count=0\nread() { read_count=$((read_count+1)); "
                          + f"if (( read_count == 1 )); then builtin read \"$@\" <<< '100.00 0'; "
                          + f"else builtin read \"$@\" <<< '{end} 0'; fi; }}\n"
                          + f"SECONDS={seconds}; watchdog_pid=$$; script_dir=/private; run_dir=/private; "
                          + f"run_id={RUN}; lane=debian11-rootless; NATIVE_PORT_CANDIDATE_SHA={CANDIDATE}; "
                          + f"port_invocation_us=1234567890123456; port_start_log_fd=9; image={shlex.quote(IMAGE)}; "
                          + "port_start_failure_diagnostic\n")
                result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                    env=os.environ | {"PATH": str(self.root) + ":" + os.environ["PATH"]})
                self.assertEqual(result.returncode, 0)
                self.assertIn("collector=" + expected, result.stderr)
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_actual_nonroot_helper_reads_held_fd_without_stalled_sudo_or_podman(self):
        self.append(self.line(self.start, "DOCKERLENS_ROOTLESS_TRACE: rootlesskit " + CANARY))
        marker = self.root / "queried"
        marker.touch()
        marker.chmod(0o666)
        for name in ("sudo", "podman"):
            self.tool(name, '#!/bin/sh\nprintf queried >> "$marker"\nsleep 30\n')
        uid = 65534 if os.geteuid() == 0 else os.geteuid()
        if os.geteuid() == 0:
            value = json.loads(self.registration.read_bytes())
            value["uid"] = uid
            self.write(self.registration, value)
            for path in (self.root, self.diag, self.log, self.registration, self.window):
                os.chown(path, uid, 65534)
        args = [str(self.root), str(uid), RUN, "debian11-rootless", CANDIDATE,
                str(self.invocation), str(int(time.clock_gettime(time.CLOCK_BOOTTIME) * 100)),
                "100", str(os.getpid()), str(self.fd), IMAGE]
        identity = {"user": uid, "group": 65534} if os.geteuid() == 0 else {}
        started = time.monotonic()
        child = ('import os,runpy,sys; sys.argv=sys.argv[1:]; '
                 'sys.argv[9]=str(os.getpid()); runpy.run_path(sys.argv[0],run_name="__main__")')
        result = subprocess.run([sys.executable, "-c", child, str(HELPER), *args], capture_output=True,
            text=True, timeout=2, pass_fds=(self.fd,), **identity,
            env=os.environ | {"PATH": str(self.root) + ":" + os.environ["PATH"], "marker": str(marker)})
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), DIAG.closed("complete", "rootless_trace", "rootless_network"))
        self.assertEqual(result.stderr, "")
        self.assertEqual(marker.read_text(), "")

    def test_actual_nonroot_bash_timeout_python_chain_preserves_held_fd(self):
        self.append(self.line(self.start, "DOCKERLENS_ROOTLESS_TRACE: rootlesskit " + CANARY))
        marker = self.root / "queried"
        marker.touch()
        marker.chmod(0o666)
        for name in ("sudo", "podman"):
            self.tool(name, '#!/bin/sh\nprintf queried >> "$marker"\nsleep 30\n')
        uid = 65534 if os.geteuid() == 0 else os.geteuid()
        if os.geteuid() == 0:
            value = json.loads(self.registration.read_bytes())
            value["uid"] = uid
            self.write(self.registration, value)
            for path in (self.root, self.diag, self.log, self.registration, self.window):
                os.chown(path, uid, 65534)
        script = (self.shell_function()
                  + f"\nscript_dir={shlex.quote(str(HELPER.parent))}; "
                  + f"run_dir={shlex.quote(str(self.root))}; run_id={RUN}; "
                  + f"lane=debian11-rootless; NATIVE_PORT_CANDIDATE_SHA={CANDIDATE}; "
                  + f"port_invocation_us={self.invocation}; port_start_log_fd={self.fd}; "
                  + f"image={shlex.quote(IMAGE)}; "
                  + "sleep 20 & watchdog_pid=$!; "
                  + "trap 'kill \"$watchdog_pid\" 2>/dev/null || true; "
                  + "wait \"$watchdog_pid\" 2>/dev/null || true' EXIT; "
                  + "port_start_failure_diagnostic\n")
        identity = {"user": uid, "group": 65534} if os.geteuid() == 0 else {}
        started = time.monotonic()
        result = subprocess.run(["bash", "--noprofile", "--norc", "-c", script],
            capture_output=True, text=True, timeout=4, pass_fds=(self.fd,), **identity,
            env=os.environ | {"PATH": str(self.root) + ":" + os.environ["PATH"], "marker": str(marker)})
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), DIAG.closed("complete", "rootless_trace", "rootless_network"))
        self.assertEqual(result.stdout, "")
        self.assertEqual(marker.read_text(), "")

    def test_definition_and_proof_boundaries(self):
        source = (ROOT / "src/native_port_tests.rs").read_text()
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        helper = HELPER.read_text()
        wrapper = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        emitter = (ROOT / "scripts/native-evidence.py").read_text()
        self.assertIn('--log-driver=k8s-file --log-opt "path=$run_dir/diagnostics/daemon.log" --log-opt max-size=1048576', harness)
        self.assertIn("inspect --format '{{json .}}'", harness)
        self.assertNotIn("{{json .Id}}", harness)
        self.assertNotIn("subprocess", helper)
        observer = self.shell_function()
        self.assertNotIn("sudo", observer)
        self.assertNotIn("podman", observer)
        self.assertIn("--kill-after=0.25s 3.5s", observer)
        self.assertIn("Some(28 | 124)", source)
        self.assertIn("Some(Duration::from_secs(4))", source)
        self.assertIn("remaining > if cleanup { 1 } else { 40 }", source)
        self.assertIn("const EXPECTED_SHAPES: [&str; 8]", source)
        self.assertIn("run_deadline_epoch=$(( $(date +%s) + 180 ))", wrapper)
        for private in (DIAG.REGISTRATION_FILE, DIAG.LOG_FILE, DIAG.WINDOW_FILE):
            self.assertNotIn(private, emitter)


if __name__ == "__main__":
    unittest.main()
