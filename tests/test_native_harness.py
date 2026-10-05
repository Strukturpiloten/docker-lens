"""Fault injection for exact resource cleanup and ignored native test selection."""

import importlib.util
import json
import os
import re
import shlex
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeHarnessTests(unittest.TestCase):
    def test_identity_is_independent_eleventh_mandatory_check_before_manifest(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        invocations = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$',
                                 source, re.MULTILINE)
        self.assertEqual(invocations, [
            ("native_capture", "live_engine_capture_decodes"),
            ("acquisition", "live_read_only_acquisition_matches_oracle"),
            ("native_selection", "live_native_selection_and_source_observations"),
            ("native_selection", "live_network_membership_matches_engine"),
            ("native_target", "live_target_render_matches_engine"),
            ("native_network", "live_network_render_matches_engine"),
            ("native_network", "live_internal_network_blocks_external_egress"),
            ("native_volume", "live_existing_volume_prerequisite_matches_engine"),
            ("native_container", "live_container_settings_match_engine"),
            ("native_volume_label", "live_created_volume_labels_match_engine"),
            ("native_identity", "live_container_process_identity_matches_engine"),
        ])
        self.assertLess(source.index('native_identity live_container_process_identity_matches_engine'),
                        source.index('python3 "$script_dir/native-evidence.py"'))
        self.assertIn('export NATIVE_IDENTITY_PROBES_PATH="$run_dir/identity-probes.json"', source)

    def test_identity_source_requires_pid1_owned_id_cleanup_and_positive_absence(self) -> None:
        source = (ROOT / "src/native_identity_tests.rs").read_text()
        self.assertIn('set -eu; id -u; id -g; pwd -P', source)
        self.assertIn('--user=1000:1000', source)
        self.assertIn('--workdir=/tmp', source)
        self.assertNotIn('exec --user', source)
        self.assertIn('"State"]["ExitCode"], 0', source)
        self.assertIn('"State"]["Status"], "exited"', source)
        self.assertIn('"State"]["Running"], false', source)
        self.assertIn('if !self.attempted[index]', source)
        bind = source.split('fn bind(', 1)[1].split('fn cleanup(', 1)[0]
        self.assertLess(bind.index('self.inspect(&self.names[index]'), bind.index('self.ids[index] ='))
        self.assertIn('registered != id', bind)
        cleanup = source.split('fn cleanup(', 1)[1].split('fn facts(', 1)[0]
        self.assertIn('owned(&before, Some(&id), &name, &self.run)', cleanup)
        self.assertIn('containers/{id}?force=1', cleanup)
        self.assertNotIn('containers/{name}?force=1', cleanup)
        self.assertIn('!= 204', cleanup)
        self.assertIn('for _ in 0..2', cleanup)
        self.assertIn('self.inspect(&self.names[index], true).0 != 404', cleanup)
        self.assertIn('self.inspect(id, true).0 != 404', cleanup)
        self.assertLess(source.index('assert!(passed && cleaned'), source.index('create_new(true)'))
        self.assertIn('mode(0o600)', source)

    def test_identity_exact_selection_and_closed_failure_privacy(self) -> None:
        selected = "native_identity_tests::live_container_process_identity_matches_engine"
        for mode in ("pass", "absent", "duplicate", "zero", "fail"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._tool(root, "cargo", '''#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$FAKE_NATIVE_INVOCATIONS"
if [[ $* == *--list* ]]; then
  [[ $FAKE_MODE != absent ]] || exit 0
  echo 'native_identity_tests::live_container_process_identity_matches_engine: test'
  if [[ $FAKE_MODE == duplicate ]]; then
    echo 'native_identity_tests::live_container_process_identity_matches_engine: test'
  fi
elif [[ $FAKE_MODE == fail ]]; then
  echo 'DOCKERLENS_NATIVE_CHECK: identity_render protected-secret'
  echo 'DOCKERLENS_NATIVE_CHECK: identity_private'
  echo 'DOCKERLENS_NATIVE_CHECK: identity_cleanup_unverified'
  echo "thread 'protected-secret' panicked at src/native_identity_tests.rs:123:4:"
  echo 'protected-secret raw-native-ID'
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 42
elif [[ $FAKE_MODE == zero ]]; then
  echo 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
else
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
''')
                calls = root / "calls"
                env = os.environ.copy()
                env.update(PATH=f"{root}:{env['PATH']}", FAKE_MODE=mode,
                           FAKE_NATIVE_INVOCATIONS=str(calls))
                result = subprocess.run([str(ROOT / "scripts/run-exact-native-test.sh"),
                                         "native_identity", "live_container_process_identity_matches_engine"],
                                        env=env, capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode == 0, mode == "pass")
                invocations = calls.read_text().splitlines()
                self.assertTrue(all('--lib' in call and '--test' not in call for call in invocations))
                if mode not in ("absent", "duplicate"):
                    self.assertIn(f'--ignored --exact {selected}', invocations[1])
                self.assertNotIn('protected-secret', result.stdout + result.stderr)
                self.assertNotIn('identity_private', result.stderr)
                self.assertNotIn('identity_render', result.stderr)
                if mode == "fail":
                    self.assertIn('DOCKERLENS_NATIVE_CHECK: identity_cleanup_unverified', result.stderr)
                    self.assertIn('DOCKERLENS_NATIVE_PANIC: source=native_identity_tests line=123 column=4', result.stderr)

    @staticmethod
    def _cgroup_helper():
        spec = importlib.util.spec_from_file_location(
            "native_cgroup_diagnostic", ROOT / "scripts/native-cgroup-diagnostic.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_cgroup_classification_is_closed_private_and_fail_closed(self) -> None:
        helper = self._cgroup_helper()
        payload = b"outer\ncpu memory pids\npids\n4294967296\nmax\ndaemon\nmemory\n\nmissing\nprotected-secret\n"
        records = helper.classify(payload)
        self.assertEqual(records[0], {
            "scope": "outer", "outcome": "observed",
            "memory_controller": "present", "pids_controller": "present",
            "memory_delegated": "absent", "pids_delegated": "present",
            "memory_max": "finite", "swap_max": "max",
        })
        self.assertEqual(records[1]["memory_max"], "missing")
        self.assertEqual(records[1]["swap_max"], "unknown")
        self.assertNotIn("protected-secret", str(records))
        self.assertNotIn("4294967296", str(records))
        unknown = b"outer\nunknown\nunknown\nunknown\nunknown\ndaemon\nunknown\nunknown\nunknown\nunknown\n"
        self.assertEqual(helper.classify(unknown), [helper.unknown("outer"), helper.unknown("daemon")])
        for malformed in (payload + b"raw=protected-secret\n", b"\xff", b"x" * 8193):
            with self.assertRaises(helper.Unavailable):
                helper.classify(malformed)
        for invalid in ("memory-private", "memory\nprivate", "protected-secret", "memory protectedsecret", "memory memory"):
            self.assertEqual(helper.controller_state(invalid, "memory"), "unknown")

    def test_cgroup_caller_deadline_is_shared_clamped_and_not_restarted(self) -> None:
        helper = self._cgroup_helper()
        identity = ("a" * 64 + '|dl-native-Ab12Cd34|true|Ab12Cd34|123|"2026-10-02T12:00:00Z"\n').encode()
        payload = b"outer\nmemory pids\nmemory\n1234\nmax\ndaemon\nunknown\nunknown\nunknown\nunknown\n"
        for supplied, expected in ((9, None), (11, 11), (100, 15)):
            calls = []

            def runner(command, deadline):
                calls.append((command, deadline))
                return payload if command[1] == "exec" else identity

            with patch.object(helper.time, "monotonic", return_value=10):
                records = helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", "rootful", ["podman"],
                                         runner, deadline=supplied, lane="upstream-rootful")
            if expected is None:
                self.assertEqual(calls, [])
                self.assertEqual(records, [helper.unknown("outer"), helper.unknown("daemon")])
            else:
                self.assertEqual([deadline for _, deadline in calls], [expected] * 3)
                self.assertEqual(records[0]["outcome"], "observed")
                self.assertLessEqual(float(calls[1][0][6]) + 0.75, expected - 10)

    def test_shared_context_runner_is_optional_bounded_and_has_four_closed_defaults(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        block = source.split("# One five-second context phase,", 1)[1].split(
            "if [[ $expected_mode == rootless ]]; then", 1
        )[0]
        block = "# One five-second context phase," + block
        for sudo, expired, failed in ((False, False, False), (True, False, False),
                                      (False, True, False), (True, False, True)):
            with self.subTest(sudo=sudo, expired=expired, failed=failed):
                fake = f'''python3() {{
  if [[ $2 == --validate-context ]]; then
    command python3 {shlex.quote(str(ROOT / "scripts/native-device-source.py"))} "$2" "$3"
    return
  fi
  [[ $1 == /owned/native-device-source.py && $2 == --context &&
     $3 == dl-native-Ab12Cd34 && $4 == Ab12Cd34 && $5 == rootless && $6 == {int(sudo)} &&
     $8 == upstream-rootless ]] || exit 42
  [[ {int(expired)} == 0 ]] || exit 43
  if [[ {int(failed)} == 1 ]]; then
    echo "DOCKERLENS_NATIVE_CGROUP_DIAG: scope=outer outcome=unavailable memory_controller=unknown pids_controller=unknown memory_delegated=unknown pids_delegated=unknown memory_max=unknown swap_max=unknown"
    echo protected-secret >&2
    return 1
  fi
  for role in outer daemon; do
    echo "DOCKERLENS_NATIVE_CGROUP_DIAG: scope=$role outcome=unavailable memory_controller=unknown pids_controller=unknown memory_delegated=unknown pids_delegated=unknown memory_max=unknown swap_max=unknown"
  done
  for role in host-null renamed-null; do
    echo "DOCKERLENS_NATIVE_DEVICE_SOURCE: role=$role scope=daemon-view view=different_mount node=other uncertainty=none runtime_source=unknown permissions=unknown"
  done
}}
export -f python3
'''
                setup = ("set -euo pipefail\nscript_dir=/owned\ncontainer=dl-native-Ab12Cd34\n"
                         "run_id=Ab12Cd34\nexpected_mode=rootless\nlane=upstream-rootless\n"
                         + ("podman_cmd=(sudo -n podman)\n" if sudo else "podman_cmd=(podman)\n")
                         + f"SECONDS={1800 if expired else 0}\n")
                result = subprocess.run(["bash", "-c", setup + fake + block + "false\n"],
                                        capture_output=True, text=True, timeout=2, check=False)
                self.assertEqual(result.returncode, 1)  # The original assertion still fails.
                self.assertEqual(result.stderr, "")
                self.assertEqual(len(result.stdout.splitlines()), 4)
                self.assertEqual(result.stdout.count("DOCKERLENS_NATIVE_DEVICE_SOURCE:"), 2)
                self.assertEqual("node=other uncertainty=none" in result.stdout, not (failed or expired))
                self.assertNotIn("protected-secret", result.stdout)
                self.assertNotIn("Ab12Cd34", result.stdout)
        self.assertNotIn("run-exact-native-test", block)
        self.assertNotIn("native-evidence", block)
        self.assertNotIn(" exec ", block)

    def test_shared_context_does_not_swallow_whole_lane_cancellation(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        block = "# One five-second context phase," + source.split(
            "# One five-second context phase,", 1
        )[1].split("if [[ $expected_mode == rootless ]]; then", 1)[0]
        setup = ("set -euo pipefail\ntrap 'echo cleanup; exit 143' TERM\n"
                 "script_dir=/owned\ncontainer=dl-native-Ab12Cd34\nrun_id=Ab12Cd34\n"
                 "expected_mode=rootless\nlane=upstream-rootless\npodman_cmd=(podman)\nSECONDS=0\n"
                 "export native_parent=$BASHPID\n"
                 "python3() { kill -TERM \"$native_parent\"; return 143; }\nexport -f python3\n")
        result = subprocess.run(["bash", "-c", setup + block + "echo after\n"],
                                capture_output=True, text=True, timeout=2, check=False)
        self.assertEqual(result.returncode, 143)
        self.assertEqual(result.stdout, "cleanup\n")
        self.assertEqual(result.stderr, "")

    def test_shared_context_outer_timer_bounds_stalled_initial_interpreter(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        block = "# One five-second context phase," + source.split(
            "# One five-second context phase,", 1
        )[1].split("if [[ $expected_mode == rootless ]]; then", 1)[0]
        self.assertIn("timeout --signal=TERM --kill-after=0.2 4.8 bash -c", block)
        block = block.replace("--kill-after=0.2 4.8", "--kill-after=0.2 0.3")
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "local-interpreter-pid"
            setup = ("set -euo pipefail\nscript_dir=/owned\ncontainer=dl-native-Ab12Cd34\n"
                     "run_id=Ab12Cd34\nexpected_mode=rootless\nlane=upstream-rootless\npodman_cmd=(sudo -n podman)\n"
                     "SECONDS=0\n")
            fake = f'''python3() {{
  if [[ $2 == --validate-context ]]; then
    command python3 {shlex.quote(str(ROOT / "scripts/native-device-source.py"))} "$2" "$3"
    return
  fi
  trap '' TERM
  echo "$BASHPID" > {shlex.quote(str(marker))}
  sleep 10
}}
export -f python3
'''
            started = time.monotonic()
            result = subprocess.run(["bash", "-c", setup + fake + block], capture_output=True,
                                    text=True, timeout=2, check=False)
            self.assertGreaterEqual(time.monotonic() - started, 0.3)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertEqual(len(result.stdout.splitlines()), 4)
            self.assertTrue(marker.exists())
            self._assert_process_not_live(int(marker.read_text()))

    def test_cgroup_identity_requires_json_serialization_not_go_display(self) -> None:
        helper = self._cgroup_helper()
        prefix = "a" * 64 + "|dl-native-Ab12Cd34|true|Ab12Cd34|123|"
        # Independently authored realistic examples of time.Time's display and
        # MarshalJSON boundaries, with no actual container identity or time.
        display = "2031-04-05 06:07:08.123456789 +0000 UTC"
        timestamp = "2031-04-05T06:07:08.123456789Z"
        serialized = json.dumps(timestamp)
        parsed = helper.inspect_identity((prefix + serialized + "\n").encode(), "dl-native-Ab12Cd34", "Ab12Cd34")
        self.assertEqual(parsed[-1], timestamp)
        for unsupported in (display, json.dumps(display), timestamp):
            with self.assertRaises(helper.Unavailable):
                helper.inspect_identity((prefix + unsupported + "\n").encode(), "dl-native-Ab12Cd34", "Ab12Cd34")
        payload = b"outer\nmemory pids\nmemory\n1234\nmax\ndaemon\nunknown\nunknown\nunknown\nunknown\n"
        before = (prefix + serialized + "\n").encode()
        changed = (prefix + json.dumps(timestamp.replace("123456789", "123456788")) + "\n").encode()
        replies = iter((before, payload, changed))
        self.assertEqual(helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", "rootful", ["podman"],
                                        lambda *_args: next(replies), lane="upstream-rootful"), [helper.unknown("outer"), helper.unknown("daemon")])

    def test_cgroup_timestamp_json_is_bounded_typed_and_private(self) -> None:
        helper = self._cgroup_helper()
        prefix = "a" * 64 + "|dl-native-Ab12Cd34|true|Ab12Cd34|123|"
        invalid = ("", '"unterminated-private-canary', "null", "true", "42",
                   '["private-canary"]', '{"secret":"private-canary"}',
                   json.dumps("private-canary"), json.dumps("2031-13-05T06:07:08Z"),
                   json.dumps("2031-04-05T06:07:08+99:00"), json.dumps("private-canary" * 30))
        for value in invalid:
            calls = []

            def runner(command, deadline):
                calls.append(command)
                return (prefix + value + "\n").encode()

            records = helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", "rootful", ["podman"], runner, lane="upstream-rootful")
            self.assertEqual(records, [helper.unknown("outer"), helper.unknown("daemon")])
            self.assertEqual(len(calls), 1)
            self.assertNotIn("private-canary", json.dumps(records))
        with self.assertRaises(helper.Unavailable):
            helper.inspect_identity(b"a" * 8193, "dl-native-Ab12Cd34", "Ab12Cd34")

    def test_cgroup_read_requires_same_owned_identity_and_shared_deadline(self) -> None:
        helper = self._cgroup_helper()
        identity = ("a" * 64 + '|dl-native-Ab12Cd34|true|Ab12Cd34|123|"2026-10-02T12:00:00Z"\n').encode()
        payload = b"outer\nmemory pids\nmemory\n1234\nmax\ndaemon\nunknown\nunknown\nunknown\nunknown\n"
        for changed in (identity.replace(b"123|", b"124|"), identity.replace(b"|true|", b"|false|"),
                        identity.replace(b"12:00:00", b"12:00:01")):
            commands = []

            def runner(command, deadline):
                commands.append((command, deadline))
                return (identity, payload, changed)[len(commands) - 1]

            records = helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", "rootful", ["podman"], runner, lane="upstream-rootful")
            self.assertEqual(records, [helper.unknown("outer"), helper.unknown("daemon")])
            self.assertEqual(len({deadline for _, deadline in commands}), 1)
            self.assertIn("{{json .State.StartedAt}}", commands[0][0][3])
            self.assertEqual(commands[1][0][2], "a" * 64)
            self.assertEqual(commands[1][0][4:6], ["-k", "0.2"])
            self.assertIn("timeout", commands[1][0])
        commands = []

        def wrong_owner(command, deadline):
            commands.append(command)
            return identity.replace(b"|Ab12Cd34|", b"|wrong-owner|")

        self.assertEqual(helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", "rootful", ["podman"], wrong_owner, lane="upstream-rootful"),
                         [helper.unknown("outer"), helper.unknown("daemon")])
        self.assertEqual(len(commands), 1)
        # Names or Podman commands outside the closed run scope never execute.
        def forbidden(*_args):
            self.fail("unscoped command executed")
        self.assertEqual(helper.diagnose("ambient", "Ab12Cd34", "rootful", ["podman"], forbidden, lane="upstream-rootful"),
                         [helper.unknown("outer"), helper.unknown("daemon")])
        self.assertEqual(helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", "rootful", ["podman", "--remote"], forbidden, lane="upstream-rootful"),
                         [helper.unknown("outer"), helper.unknown("daemon")])
        replies = iter((identity, payload, identity))
        self.assertEqual(helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", "rootless", ["podman"],
                                        lambda *_args: next(replies), lane="upstream-rootless"), helper.classify(payload))

    def test_cgroup_lane_selects_only_canonical_account_and_uid(self) -> None:
        helper = self._cgroup_helper()
        identity = ("a" * 64 + '|dl-native-Ab12Cd34|true|Ab12Cd34|123|"2031-04-05T06:07:08Z"\n').encode()
        payload = b"outer\nmemory pids\nmemory\n1234\nmax\ndaemon\nunknown\nunknown\nunknown\nunknown\n"
        for lane, mode, account, uid in (
            ("debian11-rootless", "rootless", "dockertest", "1000"),
            ("upstream-rootless", "rootless", "docker", "1000"),
            ("debian11-rootful", "rootful", "root", "0"),
            ("upstream-rootful", "rootful", "root", "0"),
        ):
            commands = []

            def runner(command, _deadline):
                commands.append(command)
                return payload if command[1] == "exec" else identity

            records = helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", mode,
                                      ["podman"], runner, lane=lane)
            self.assertEqual(records, helper.classify(payload))
            self.assertEqual(commands[1][-3:], [mode, account, uid])
        for lane, mode in ((None, "rootless"), ("unknown", "rootless"),
                           ("debian11-rootless", "rootful"), ("upstream-rootful", "rootless")):
            runner = unittest.mock.Mock()
            self.assertEqual(helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", mode,
                                            ["podman"], runner, lane=lane),
                             [helper.unknown("outer"), helper.unknown("daemon")])
            runner.assert_not_called()

    def test_cgroup_guest_timer_uses_short_options_and_propagates_failure(self) -> None:
        helper = self._cgroup_helper()
        identity = ("a" * 64 + '|dl-native-Ab12Cd34|true|Ab12Cd34|123|"2031-04-05T06:07:08Z"\n').encode()
        payload = b"outer\nmemory pids\nmemory\n1234\nmax\ndaemon\nunknown\nunknown\nunknown\nunknown\n"
        # Independently authored short-option-only contract fake. It executes
        # only a synthetic shell reply, never the guest script or runtime tools.
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            self._tool(fixture, "timeout", f"#!{sys.executable}\n" + '''import subprocess
import sys
args = sys.argv[1:]
if (len(args) != 10 or args[:2] != ["-k", "0.2"]
        or args[3:5] != ["sh", "-c"] or args[6] != "diagnostic"
        or args[7] not in ("rootful", "rootless")
        or args[8:] != (["root", "0"] if args[7] == "rootful" else ["docker", "1000"])):
    sys.exit(64)
try:
    if not 0.2 < float(args[2]) <= 3.0:
        sys.exit(65)
except ValueError:
    sys.exit(65)
sys.exit(subprocess.run(args[3:], check=False).returncode)
''')
            timer = fixture / "timeout"
            former = subprocess.run([str(timer), "--kill-after=0.2", "3.000", "sh", "-c",
                                     "exit 0", "diagnostic", "rootful"],
                                    capture_output=True, timeout=2, check=False)
            self.assertEqual(former.returncode, 64)
            self.assertEqual(former.stdout, b"")
            for mode in ("rootful", "rootless"):
                for status in (0, 71):
                    with self.subTest(mode=mode, status=status):
                        commands = []

                        def runner(command, deadline):
                            commands.append((command, deadline))
                            if command[1] == "inspect":
                                return identity
                            self.assertEqual(command[:6], ["podman", "exec", "a" * 64,
                                                           "timeout", "-k", "0.2"])
                            self.assertEqual(command[7:], ["sh", "-c", helper.GUEST_SCRIPT,
                                                           "diagnostic", mode,
                                                           "root" if mode == "rootful" else "docker",
                                                           "0" if mode == "rootful" else "1000"])
                            synthetic = "printf '%s' " + shlex.quote(payload.decode()) + f"; exit {status}"
                            result = helper.bounded_command(
                                [str(timer), *command[4:9], synthetic, *command[10:]], deadline)
                            return result

                        records = helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", mode, ["podman"], runner, lane="upstream-" + mode)
                        expected = helper.classify(payload) if status == 0 else [helper.unknown("outer"), helper.unknown("daemon")]
                        self.assertEqual(records, expected)
                        self.assertEqual(len(commands), 3 if status == 0 else 2)
                        self.assertEqual(len({deadline for _, deadline in commands}), 1)

    def test_cgroup_read_errors_and_expired_deadline_remain_unavailable(self) -> None:
        helper = self._cgroup_helper()
        identity = ("a" * 64 + '|dl-native-Ab12Cd34|true|Ab12Cd34|123|"2026-10-02T12:00:00Z"\n').encode()
        expected = [helper.unknown("outer"), helper.unknown("daemon")]
        for failure in (helper.Unavailable(), OSError("protected-secret"),
                        subprocess.TimeoutExpired("protected-secret", 5)):
            def runner(*_args):
                raise failure
            self.assertEqual(helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", "rootless", ["podman"], runner, lane="upstream-rootless"), expected)
        with patch.object(helper.time, "monotonic", side_effect=[0, 5]):
            self.assertEqual(helper.diagnose("dl-native-Ab12Cd34", "Ab12Cd34", "rootless", ["podman"],
                                            lambda *_args: identity, lane="upstream-rootless"), expected)

    def test_cgroup_guest_requires_namespace_mapping_and_closed_reads(self) -> None:
        helper = self._cgroup_helper()
        # Only synthetic files are read. No daemon, host cgroup, or runtime
        # namespace is contacted by this guest-script regression.
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            proc = fixture / "proc"
            root = fixture / "sys/fs/cgroup"
            daemon = root / "slice/daemon"
            daemon.mkdir(parents=True)
            for path in (proc / "self/ns", proc / "123/ns"):
                path.mkdir(parents=True)
                (path / "cgroup").symlink_to("cgroup:[100]")
                (path / "mnt").symlink_to("mnt:[200]")
            (proc / "self/mountinfo").write_text(f"1 0 0:1 / {root} rw - cgroup2 cgroup rw\n")
            (proc / "123/comm").write_text("dockerd\n")
            (proc / "123/status").write_text("Name:\tdockerd\nUid:\t0\t0\t0\t0\n")
            passwd = fixture / "passwd"
            passwd.write_text("docker:x:1000:1000:fixture:/home/docker:/bin/sh\n")
            # Field 22 is the stable process start identity.
            (proc / "123/stat").write_text("123 (dockerd) S " + " ".join(["0"] * 18 + ["1234"]) + "\n")
            (proc / "123/cgroup").write_text("0::/slice/daemon\n")
            for path in (root, daemon):
                (path / "cgroup.controllers").write_text("cpu memory pids\n")
                (path / "cgroup.subtree_control").write_text("memory\n")
                (path / "memory.max").write_text("1234\n")
                (path / "memory.swap.max").write_text("max\n")
            script = helper.GUEST_SCRIPT.replace("/proc/", str(proc) + "/").replace("/sys/fs/cgroup", str(root)).replace("/etc/passwd", str(passwd))

            def read_guest(mode="rootful", env=None, lane=None):
                contract = helper.fixture_contract(lane or "upstream-" + mode, mode)
                return subprocess.run(["sh", "-c", script, "diagnostic", mode,
                                       contract.account, str(contract.uid)],
                                      capture_output=True, timeout=2, check=False, env=env)

            observed = read_guest()
            self.assertEqual(observed.returncode, 0, observed.stderr)
            self.assertEqual([record["outcome"] for record in helper.classify(observed.stdout)], ["observed", "observed"])
            (proc / "123/ns/mnt").unlink()
            (proc / "123/ns/mnt").symlink_to("mnt:[201]")
            mismatched = read_guest()
            self.assertEqual(mismatched.returncode, 0)
            self.assertEqual(helper.classify(mismatched.stdout)[1], helper.unknown("daemon"))
            (proc / "123/ns/mnt").unlink()
            (proc / "123/ns/mnt").symlink_to("mnt:[200]")
            for member in ("0::/../private", "0::/slice/./daemon", "0::/slice//daemon", "1:memory:/private"):
                (proc / "123/cgroup").write_text(member + "\n")
                self.assertNotEqual(read_guest().returncode, 0)
            (proc / "123/cgroup").write_text("0::/slice/daemon\n")
            secret = fixture / "protected-secret"
            secret.write_text("protected-secret\n")
            (daemon / "memory.max").unlink()
            (daemon / "memory.max").symlink_to(secret)
            protected = read_guest()
            self.assertEqual(protected.returncode, 0)
            self.assertNotIn(b"protected-secret", protected.stdout + protected.stderr)
            self.assertEqual(helper.classify(protected.stdout)[1]["memory_max"], "unknown")
            (proc / "123/status").write_text("Uid:\t1732\t1732\t1732\t1732\n")
            self.assertNotEqual(read_guest("rootful").returncode, 0)
            self.assertNotEqual(read_guest("rootless").returncode, 0)
            (proc / "123/status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
            self.assertEqual(read_guest("rootless").returncode, 0)
            # Both names exist, but only the selected lane's canonical account
            # and UID may establish daemon identity. The other account is not a
            # fallback, and an arbitrary positive UID is not acceptable.
            for lane, selected, other in (("debian11-rootless", "dockertest", "docker"),
                                          ("upstream-rootless", "docker", "dockertest")):
                passwd.write_text(f"{selected}:x:1000:1000:fixture:/home/docker:/bin/sh\n"
                                  f"{other}:x:1732:1732:fixture:/home/docker:/bin/sh\n")
                self.assertEqual(read_guest("rootless", lane=lane).returncode, 0)
                passwd.write_text(f"{selected}:x:1732:1732:fixture:/home/docker:/bin/sh\n"
                                  f"{other}:x:1000:1000:fixture:/home/docker:/bin/sh\n")
                self.assertNotEqual(read_guest("rootless", lane=lane).returncode, 0)
            for accounts in ("", "docker:x:0:0:fixture:/home/docker:/bin/sh\n",
                             "docker:x:1000:1000:fixture:/home/docker:/bin/sh\n" * 2,
                             "docker:x:1000:1000:fixture:/home/docker:/bin/sh:extra\n"):
                passwd.write_text(accounts)
                self.assertNotEqual(read_guest("rootless").returncode, 0)
            passwd.write_text("docker:x:1000:1000:fixture:/home/docker:/bin/sh\n")
            bin_dir = fixture / "bin"
            bin_dir.mkdir()
            self._tool(bin_dir, "head", """#!/usr/bin/env python3
import os, sys
from pathlib import Path
if sys.argv[-1] == os.environ['TEST_CGROUP_UID_FILE']:
    counter = Path(os.environ['TEST_CGROUP_UID_COUNTER'])
    reads = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(reads))
    if reads == 2:
        if os.environ['TEST_CGROUP_UID_ROLE'] == 'status':
            print('Uid:\\t1733\\t1733\\t1733\\t1733')
        else:
            print('docker:x:1733:1733:fixture:/home/docker:/bin/sh')
        raise SystemExit(0)
os.execv(os.environ['TEST_CGROUP_REAL_HEAD'], ['head', *sys.argv[1:]])
""")
            for role, target in (("status", proc / "123/status"), ("account", passwd)):
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}", TEST_CGROUP_UID_ROLE=role,
                           TEST_CGROUP_UID_FILE=str(target), TEST_CGROUP_UID_COUNTER=str(fixture / role),
                           TEST_CGROUP_REAL_HEAD=shutil.which("head"))
                self.assertNotEqual(read_guest("rootless", env).returncode, 0)
            valid_mount = f"1 0 0:1 / {root} rw - cgroup2 cgroup rw\n"
            for stacked in (valid_mount, f"2 0 0:2 / {root} rw - tmpfs tmpfs rw\n"):
                (proc / "self/mountinfo").write_text(valid_mount + stacked)
                self.assertNotEqual(read_guest("rootless").returncode, 0)
            # The first 8193 bytes end in a newline; command substitution must
            # not strip it and admit a prefix hiding a later stacked mount.
            padding = "2 0 0:2 / /padding rw - tmpfs "
            prefix = valid_mount + padding + "x" * (8192 - len(valid_mount.encode()) - len(padding)) + "\n"
            self.assertEqual(len(prefix.encode()), 8193)
            (proc / "self/mountinfo").write_text(prefix + f"3 0 0:3 / {root} rw - tmpfs tmpfs rw\n")
            self.assertNotEqual(read_guest("rootless").returncode, 0)
            utf8_env = dict(os.environ, LC_ALL="C.UTF-8")
            ascii_control = valid_mount + padding + "x" * (8191 - len(valid_mount.encode()) - len(padding)) + "\n"
            self.assertEqual(len(ascii_control.encode()), 8192)
            (proc / "self/mountinfo").write_text(ascii_control)
            ascii_result = subprocess.run(["bash", "-c", script, "diagnostic", "rootless", "docker", "1000"],
                                          env=utf8_env, capture_output=True, timeout=2, check=False)
            self.assertEqual(ascii_result.returncode, 0, ascii_result.stderr)
            self.assertEqual(helper.classify(ascii_result.stdout)[0]["outcome"], "observed")
            unicode_bytes = 8192 - len(valid_mount.encode()) - len(padding)
            unicode_prefix = valid_mount + padding + "é" * (unicode_bytes // 2) + "x" * (unicode_bytes % 2) + "\n"
            self.assertEqual(len(unicode_prefix.encode()), 8193)
            self.assertLessEqual(len(unicode_prefix), 8192)
            (proc / "self/mountinfo").write_text(unicode_prefix + f"3 0 0:3 / {root} rw - tmpfs tmpfs rw\n")
            unprotected = script.replace("LC_ALL=C\nexport LC_ALL\n", "", 1)
            without_c = subprocess.run(["bash", "-c", unprotected, "diagnostic", "rootless", "docker", "1000"],
                                       env=utf8_env, capture_output=True, timeout=2, check=False)
            self.assertEqual(without_c.returncode, 0, without_c.stderr)
            self.assertEqual(helper.classify(without_c.stdout)[0]["outcome"], "observed")
            with_c = subprocess.run(["bash", "-c", script, "diagnostic", "rootless", "docker", "1000"],
                                    env=utf8_env, capture_output=True, timeout=2, check=False)
            self.assertNotEqual(with_c.returncode, 0)
            (proc / "self/mountinfo").write_text(f"1 0 0:1 /private {root} rw - cgroup2 cgroup rw\n")
            self.assertNotEqual(read_guest("rootless").returncode, 0)

    @staticmethod
    def _assert_process_not_live(pid):
        status = Path(f"/proc/{pid}/stat")
        if status.exists():
            # A killed orphan can briefly await PID 1's reaper; it cannot run.
            assert status.read_text().rsplit(")", 1)[1].split()[0] == "Z"

    def test_cgroup_capture_bounds_both_streams_and_reaps_children(self) -> None:
        helper = self._cgroup_helper()
        with tempfile.TemporaryDirectory() as directory:
            for cause in ("stdout", "stderr", "timeout"):
                pid_path = Path(directory) / cause
                program = """import os, subprocess, sys, time
from pathlib import Path
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
Path(sys.argv[1]).write_text(str(child.pid))
if sys.argv[2] != 'timeout':
    os.write(1 if sys.argv[2] == 'stdout' else 2, b'protected-secret' * 1000)
time.sleep(60)
"""
                with self.assertRaises(helper.Unavailable):
                    helper.bounded_command([sys.executable, "-c", program, str(pid_path), cause], time.monotonic() + 0.6)
                self.assertTrue(pid_path.exists())
                self._assert_process_not_live(int(pid_path.read_text()))
            budget = {"total": 8190}
            with self.assertRaises(helper.Unavailable):
                helper.bounded_command([sys.executable, "-c", "print('secret')"], time.monotonic() + 1, budget)
            self.assertLessEqual(budget["total"], helper.CAPTURE_LIMIT)

    def test_cgroup_capture_combines_alternating_streams_across_commands(self) -> None:
        helper = self._cgroup_helper()
        deadline = time.monotonic() + 2
        budget = {"total": 0}
        helper.bounded_command([sys.executable, "-c", "import os; os.write(1, b'a'*3000); os.write(2, b'b'*3000)"], deadline, budget)
        self.assertEqual(budget["total"], 6000)
        with self.assertRaises(helper.Unavailable):
            helper.bounded_command([sys.executable, "-c", "import os; os.write(2, b'c'*1200); os.write(1, b'd'*1200)"], deadline, budget)
        self.assertLessEqual(budget["total"], helper.CAPTURE_LIMIT)

    def test_cgroup_elevated_commands_have_root_owned_timeout_and_teardown_margin(self) -> None:
        helper = self._cgroup_helper()
        for operation in ("inspect", "exec", "inspect"):
            with patch.object(helper.time, "monotonic", return_value=10):
                command, elevated_until = helper.command_with_timeout(["sudo", "-n", "podman", operation], 15)
            self.assertEqual(command[:5], ["sudo", "-n", "timeout", "--signal=TERM", "--kill-after=0.2"])
            self.assertEqual(command[6:], ["podman", operation])
            self.assertLessEqual(10 + float(command[5]) + helper.TEARDOWN_SECONDS, elevated_until)
            self.assertLess(elevated_until, 15)
        with patch.object(helper.time, "monotonic", return_value=14.2):
            command, elevated_until = helper.command_with_timeout(["sudo", "-n", "podman", "inspect"], 15)
        self.assertLess(elevated_until, 15)
        with patch.object(helper.time, "monotonic", return_value=14.9):
            with self.assertRaises(helper.Unavailable):
                helper.command_with_timeout(["sudo", "-n", "podman", "inspect"], 15)

    def test_cgroup_cleanup_closes_pipes_on_signal_permission_and_wait_errors(self) -> None:
        helper = self._cgroup_helper()
        real_popen = subprocess.Popen
        for wait_error in (False, True):
            processes = []

            def spawn(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                process.wait(timeout=1)
                if wait_error:
                    def fail_wait(**_kwargs):
                        raise subprocess.TimeoutExpired("protected-secret", 1)
                    process.wait = fail_wait
                processes.append(process)
                return process

            with patch.object(helper.subprocess, "Popen", side_effect=spawn), \
                 patch.object(helper.os, "killpg", side_effect=PermissionError("protected-secret")):
                with self.assertRaises((helper.Unavailable, subprocess.TimeoutExpired)):
                    helper.bounded_command([sys.executable, "-c", "raise SystemExit(7)"], time.monotonic() + 2)
            self.assertTrue(processes[0].stdout.closed)
            self.assertTrue(processes[0].stderr.closed)

    def test_cgroup_helper_cancellation_reaps_its_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            pid_path = bin_dir / "child.pid"
            self._tool(bin_dir, "podman", """#!/usr/bin/env python3
import os, subprocess, sys, time
from pathlib import Path
if sys.argv[1] == 'inspect':
    print('a' * 64 + '|dl-native-Ab12Cd34|true|Ab12Cd34|123|"2026-10-02T12:00:00Z"')
else:
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    Path(os.environ['TEST_CGROUP_CHILD']).write_text(str(child.pid))
    time.sleep(60)
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["TEST_CGROUP_CHILD"] = str(pid_path)
            process = subprocess.Popen([sys.executable, str(ROOT / "scripts/native-cgroup-diagnostic.py"),
                                        "dl-native-Ab12Cd34", "Ab12Cd34", "rootful", "0", "upstream-rootful"],
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 3
                while not pid_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pid_path.exists())
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=2)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(stdout.count(b"outcome=unavailable"), 2)
                self.assertEqual(stderr, b"")
                self._assert_process_not_live(int(pid_path.read_text()))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=2)

    def test_cgroup_elevated_timer_bounds_cancellation_and_overflow(self) -> None:
        # Fake sudo forwards into the real timer without gaining privilege.
        # Construction proves timer ownership ordering; these processes prove
        # cancellation never relies on the Python process killing that timer.
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "sudo", """#!/usr/bin/env bash
set -eu
[[ $1 == -n ]]
shift
printf '%s\n' "${*:1:7}" >> "$TEST_CGROUP_TIMER_TRACE"
exec "$@"
""")
            self._tool(bin_dir, "podman", """#!/usr/bin/env python3
import os, subprocess, sys, time
from pathlib import Path
if sys.argv[1] == 'inspect':
    print('a' * 64 + '|dl-native-Ab12Cd34|true|Ab12Cd34|123|"2026-10-02T12:00:00Z"')
elif os.environ['TEST_CGROUP_CAUSE'] == 'ready':
    print('outer\\nmemory pids\\nmemory\\n1234\\nmax\\ndaemon\\nunknown\\nunknown\\nunknown\\nunknown')
else:
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    Path(os.environ['TEST_CGROUP_CHILD']).write_text(str(child.pid))
    if os.environ['TEST_CGROUP_CAUSE'] == 'overflow':
        os.write(2, b'protected-secret' * 1000)
    time.sleep(60)
""")
            for cause in ("ready", "cancel", "overflow"):
                pid_path = bin_dir / f"{cause}.pid"
                trace = bin_dir / f"{cause}.trace"
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}", TEST_CGROUP_CAUSE=cause,
                           TEST_CGROUP_CHILD=str(pid_path), TEST_CGROUP_TIMER_TRACE=str(trace))
                started = time.monotonic()
                process = subprocess.Popen([sys.executable, str(ROOT / "scripts/native-cgroup-diagnostic.py"),
                                            "dl-native-Ab12Cd34", "Ab12Cd34", "rootful", "1", "upstream-rootful"],
                                           env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    if cause in ("cancel", "overflow"):
                        while not pid_path.exists() and time.monotonic() - started < 2:
                            time.sleep(0.01)
                        self.assertTrue(pid_path.exists())
                        if cause == "overflow":
                            # Overflow already entered reserved teardown; a
                            # cancellation there must not abandon its timer.
                            time.sleep(0.1)
                        process.send_signal(signal.SIGTERM)
                        time.sleep(0.05)
                        process.send_signal(signal.SIGTERM)
                    stdout, stderr = process.communicate(timeout=5.2)
                    self.assertEqual(process.returncode, 0)
                    self.assertLess(time.monotonic() - started, 5.2)
                    self.assertEqual(stderr, b"")
                    self.assertNotIn(b"protected-secret", stdout)
                    commands = trace.read_text().splitlines()
                    self.assertTrue(all(command.startswith("timeout --signal=TERM --kill-after=0.2 ") for command in commands))
                    if cause == "ready":
                        self.assertEqual(len(commands), 3)
                        self.assertIn(" podman inspect ", commands[0])
                        self.assertIn(" podman inspect ", commands[-1])
                        self.assertIn(b"scope=outer outcome=observed", stdout)
                    else:
                        self.assertEqual(stdout.count(b"outcome=unavailable"), 2)
                        self.assertTrue(pid_path.exists())
                        self._assert_process_not_live(int(pid_path.read_text()))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=2)
    def test_cleanup_timeout_runs_with_the_podman_clients_privileges(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        helpers = "cleanup_podman() {" + source.split("cleanup_podman() {", 1)[1].split(
            "\ncleanup() {", 1
        )[0] + "\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._tool(root, "sudo", '#!/bin/sh\nprintf "%s\\n" "$*" > "$FAKE_SUDO_ARGS"\n'
                       '[ "$1" = -n ] || exit 42\nshift\nexec "$@"\n')
            self._tool(root, "timeout", '#!/bin/sh\nprintf "%s\\n" "$*" > "$FAKE_TIMEOUT_ARGS"\n'
                       '[ "$1" = --signal=TERM ] && [ "$2" = --kill-after=2s ] '
                       '&& [ "$3" = 8s ] || exit 43\nshift 3\nexec "$@"\n')
            self._tool(root, "podman", '#!/bin/sh\nprintf "%s\\n" "$*"\n'
                       'echo "private-canary native failure" >&2\n')
            env = os.environ.copy()
            env.update(PATH=f"{root}:{env['PATH']}", FAKE_SUDO_ARGS=str(root / "sudo-args"),
                       FAKE_TIMEOUT_ARGS=str(root / "timeout-args"))
            for elevated in (False, True):
                with self.subTest(elevated=elevated):
                    (root / "sudo-args").unlink(missing_ok=True)
                    prefix = "sudo -n podman" if elevated else "podman"
                    result = subprocess.run(
                        ["bash", "-c", f"podman_cmd=({prefix})\n" + helpers
                         + "cleanup_podman inspect exact-task-name\n"],
                        env=env, capture_output=True, text=True, timeout=5, check=False,
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "inspect exact-task-name\n")
                    self.assertEqual(result.stderr, "")
                    self.assertEqual((root / "sudo-args").exists(), elevated)
                    if elevated:
                        self.assertEqual(
                            (root / "sudo-args").read_text().strip(),
                            "-n timeout --signal=TERM --kill-after=2s 8s podman inspect exact-task-name",
                        )
                    self.assertEqual(
                        (root / "timeout-args").read_text().strip(),
                        "--signal=TERM --kill-after=2s 8s podman inspect exact-task-name",
                    )

    def test_cleanup_immediate_stop_preserves_ownership_and_absence_checks(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        helpers = "cleanup_podman() {" + source.split("cleanup_podman() {", 1)[1].split(
            "\ncleanup() {", 1
        )[0] + "\n"
        container_helper = "cleanup_container() {" + source.split("cleanup_container() {", 1)[1].split(
            "\ntrap cleanup EXIT", 1
        )[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._tool(root, "timeout", '#!/bin/sh\n[ "$3" = 8s ] || [ "$3" = 6.0s ] || exit 43\n'
                       'export FAKE_CLIENT_BOUND=8\nshift 3\nexec "$@"\n')
            self._tool(root, "podman", '''#!/usr/bin/env bash
set -eu
[[ $1 == container ]] || echo 'private-canary resource-id' >&2
case "$1" in
  container)
    if [[ $FAKE_MODE == query_error || ($FAKE_MODE == readback_error && ! -e $FAKE_RESOURCE) ]]; then
      exit 125
    fi
    [[ -e $FAKE_RESOURCE ]] ;;
  inspect)
    if [[ $FAKE_MODE == mismatched_owner ]]; then echo foreign-run; else echo owned-run; fi ;;
  rm)
    printf '%s\\n' "$*" > "$FAKE_REMOVE_ARGS"
    # Independent CLI semantics: default stop grace is ten seconds. A client
    # deadline of eight seconds cannot reach removal without explicit time 0.
    if [[ $* != 'rm --force --time 0 dl-native-synthetic' ]]; then
      (( FAKE_CLIENT_BOUND < 10 )) && exit 124
      exit 44
    fi
    case $FAKE_MODE in
      remove_error) exit 42 ;;
      remove_cancelled) exit 143 ;;
      leftover) exit 0 ;;
      *) rm -f "$FAKE_RESOURCE" ;;
    esac ;;
  *) exit 45 ;;
esac
''')
            env = os.environ.copy()
            env.update(PATH=f"{root}:{env['PATH']}", FAKE_RESOURCE=str(root / "resource"),
                       FAKE_REMOVE_ARGS=str(root / "remove-args"))
            for mode, original in (
                ("success", False), ("success", True), ("query_error", False),
                ("mismatched_owner", False), ("remove_error", False),
                ("remove_cancelled", False), ("leftover", False), ("readback_error", False),
            ):
                with self.subTest(mode=mode, original=original):
                    (root / "resource").touch()
                    (root / "remove-args").unlink(missing_ok=True)
                    env["FAKE_MODE"] = mode
                    selected = container_helper.replace("rm --force --time 0", "rm --force") \
                        if original else container_helper
                    result = subprocess.run(
                        ["bash", "-c", "set -euo pipefail\npodman_cmd=(podman)\n"
                         "run_id=owned-run\nstatus=0\npreserve_run_dir=0\n"
                         f"script_dir={shlex.quote(str(ROOT / 'scripts'))}\nrun_dir={shlex.quote(str(root))}\n"
                         + helpers + selected
                         + '\ncleanup_container dl-native-synthetic container\nexit "$status"\n'],
                        env=env, capture_output=True, text=True, timeout=5, check=False,
                    )
                    self.assertEqual(result.returncode, 0 if mode == "success" and not original else 1)
                    self.assertEqual(
                        (root / "resource").exists(),
                        original or mode in ("mismatched_owner", "remove_error", "remove_cancelled", "leftover"),
                    )
                    self.assertEqual((root / "remove-args").exists(), mode != "mismatched_owner")
                    if mode != "mismatched_owner" and not original:
                        self.assertEqual((root / "remove-args").read_text().strip(),
                                         "rm --force --time 0 dl-native-synthetic")
                    if original or mode in ("remove_error", "remove_cancelled"):
                        category = "timeout" if original else "cancelled" if mode == "remove_cancelled" else "error"
                        self.assertIn(
                            "DOCKERLENS_NATIVE_CLEANUP: role=container operation=remove "
                            f"category={category}", result.stderr,
                        )
                    self.assertNotIn("private-canary", result.stdout + result.stderr)
                    if mode in ("leftover", "readback_error"):
                        self.assertIn("owned container cleanup readback failed", result.stderr)

    def test_cleanup_success_summary_requires_dependency_cleanup(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        helpers = "cleanup_podman() {" + source.split("cleanup_podman() {", 1)[1].split(
            "\ntrap cleanup EXIT", 1
        )[0] + "\n"
        self.assertIn('native_success_summary="native conformance passed:', source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._tool(root, "timeout", '#!/bin/sh\n[ "$3" = 8s ] || [ "$3" = 6.0s ] || exit 43\nshift 3\nexec "$@"\n')
            self._tool(root, "podman", '''#!/usr/bin/env bash
set -eu
for name; do :; done
case "$name" in
  dl-native-synthetic) role=container ;;
  dl-native-egress-synthetic) role=sidecar ;;
  dl-native-net-synthetic) role=network ;;
  dl-native-data-synthetic) role=volume ;;
  *) exit 44 ;;
esac
[[ ${2:-} == exists ]] || echo 'private-canary native-resource-id' >&2
if [[ $1 == inspect || ${2:-} == inspect ]]; then echo synthetic; exit 0; fi
if [[ ${2:-} == exists ]]; then [[ -e $FAKE_STATE/$role ]]; exit; fi
if [[ $1 == rm || ${2:-} == rm ]]; then
  printf '%s\\n' "$*" >> "$FAKE_STATE/removals"
  case $role in
    container|sidecar)
      [[ $* == "rm --force --time 0 $name" ]] || exit 45
      [[ $FAKE_MODE != container_leftover || $role != container ]] || exit 0 ;;
    network)
      [[ $* == "network rm $name" ]] || exit 46
      [[ ! -e $FAKE_STATE/container && ! -e $FAKE_STATE/sidecar ]] || exit 47
      [[ $FAKE_MODE != network_error ]] || exit 42 ;;
    volume)
      [[ $* == "volume rm $name" ]] || exit 48
      [[ ! -e $FAKE_STATE/container ]] || exit 49 ;;
  esac
  rm -f "$FAKE_STATE/$role"
else exit 50; fi
''')
            env = os.environ.copy()
            env.update(PATH=f"{root}:{env['PATH']}", FAKE_STATE=str(root))
            for mode in ("success", "container_leftover", "network_error"):
                with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                    prefix="dockerlens-native.", dir="/tmp",
                ) as temporary:
                    for role in ("container", "sidecar", "network", "volume"):
                        (root / role).touch()
                    (root / "removals").unlink(missing_ok=True)
                    env["FAKE_MODE"] = mode
                    script = (
                        "set -euo pipefail\npodman_cmd=(podman)\nwatchdog_pid=\n"
                        "run_id=synthetic\nlane=debian11-rootful\n"
                        "container=dl-native-synthetic\nsidecar=dl-native-egress-synthetic\n"
                        "outer_network=dl-native-net-synthetic\nvolume=dl-native-data-synthetic\n"
                        "native_success_summary='native conformance passed: synthetic'\npreserve_run_dir=0\n"
                        f"script_dir={shlex.quote(str(ROOT / 'scripts'))}\n"
                        f"run_dir={shlex.quote(temporary)}\n"
                        + helpers + "cleanup\n"
                    )
                    result = subprocess.run(
                        ["bash", "-c", script], env=env, capture_output=True,
                        text=True, timeout=5, check=False,
                    )
                    self.assertEqual(result.returncode, 0 if mode == "success" else 1)
                    self.assertEqual(result.stdout, "native conformance passed: synthetic\n"
                                     if mode == "success" else "")
                    self.assertEqual(
                        (root / "removals").read_text().splitlines(),
                        ["rm --force --time 0 dl-native-synthetic",
                         "rm --force --time 0 dl-native-egress-synthetic",
                         "network rm dl-native-net-synthetic",
                         "volume rm dl-native-data-synthetic"],
                    )
                    self.assertNotIn("private-canary", result.stdout + result.stderr)
                    self.assertNotIn("native-resource-id", result.stdout + result.stderr)
                    self.assertFalse(Path(temporary).exists())
                    if mode == "network_error":
                        self.assertIn("role=network operation=remove category=error", result.stderr)
                    if mode == "container_leftover":
                        self.assertIn("owned container cleanup readback failed", result.stderr)

    def test_sidecar_failure_source_requires_successful_classification(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        helpers = "classify_sidecar_error() {" + source.split(
            "classify_sidecar_error() {", 1
        )[1].split("\n}\nwatchdog &", 1)[0] + "\n}\n"
        cases = (
            (
                "permission denied private-canary", 0,
                "bind: address already in use private-canary", 0, "permission", "logs_query",
                "private-canary", "private-canary", "bind_error",
            ),
            (
                "private-canary", 0,
                "bind: address already in use private-canary", 0,
                "permission", "logs_query",
                "permission denied private-canary", "private-canary", "bind_error",
            ),
            (
                "private-canary", 0,
                "bind: address already in use private-canary", 0, "bind_error", "state_error",
                "private-canary", "private-canary", "bind_error",
            ),
            (
                "permission denied private-canary", 42,
                "bind: address already in use private-canary", 0, "bind_error", "state_error",
                "private-canary", "private-canary", "bind_error",
            ),
            (
                "private-canary", 0,
                "permission denied private-canary", 0, "permission", "state_error",
                "private-canary", "private-canary", "permission",
            ),
            (
                "private-canary", 0, "private-canary", 0, "permission", "logs_query",
                "permission denied private-canary", "private-canary", "unknown",
            ),
            (
                "private-canary", 0, "private-canary", 0, "unknown", "none",
                "private-canary", "permission denied private-canary", "unknown",
            ),
            (
                "permission denied private-canary", 42,
                "private-canary", 0, "unknown", "none",
                "permission denied private-canary", "private-canary", "unknown",
            ),
            (
                "permission denied private-canary", 42,
                "bind: address already in use private-canary", 42, "unknown", "none",
                "permission denied private-canary", "permission denied private-canary", "unavailable",
            ),
            (
                "DOCKERLENS_SIDECAR_STAGE: write_ok", 0,
                "private-canary", 0, "unknown", "none",
                "private-canary", "private-canary", "unknown",
            ),
            (
                "private-canary", 0,
                "private-canary", 0, "unknown", "none",
                "DOCKERLENS_SIDECAR_STAGE: write_ok\nprivate-canary", "private-canary", "unknown",
            ),
            (
                "DOCKERLENS_SIDECAR_STAGE: write_failed", 0,
                "private-canary", 0, "unknown", "none",
                "private-canary", "private-canary", "unknown",
            ),
            (
                "DOCKERLENS_SIDECAR_STAGE: write_ok\nhttpd: permission denied private-canary", 0,
                "private-canary", 0, "permission", "logs_query",
                "private-canary", "private-canary", "unknown",
            ),
            (
                "DOCKERLENS_SIDECAR_STAGE: write_ok", 42,
                "private-canary", 0, "unknown", "none",
                "permission denied private-canary", "private-canary", "unknown",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "podman"
            fake.write_text(
                '#!/usr/bin/env bash\n'
                'case "$1" in\n'
                '  logs) printf "%s\\n" "$FAKE_LOGS"; '
                'printf "%s\\n" "$FAKE_LOGS_STDERR" >&2; exit "$FAKE_LOGS_STATUS" ;;\n'
                '  inspect) printf "%s\\n" "$FAKE_STATE_ERROR"; '
                'printf "%s\\n" "$FAKE_STATE_STDERR" >&2; exit "$FAKE_STATE_STATUS" ;;\n'
                '  *) exit 42 ;;\n'
                'esac\n',
                encoding="utf-8",
            )
            fake.chmod(0o755)
            script = (
                "set -euo pipefail\n"
                f"podman_cmd=({fake})\n"
                "sidecar=synthetic\n"
                + helpers
                + "sidecar_failure_diagnostic\n"
            )
            for (
                logs, logs_status, state, state_status,
                category, origin, logs_stderr, state_stderr, expected_state_error,
            ) in cases:
                with self.subTest(
                    category=category, source=origin,
                    logs_status=logs_status, state_status=state_status,
                ):
                    env = os.environ.copy()
                    env.update(
                        FAKE_LOGS=logs,
                        FAKE_LOGS_STATUS=str(logs_status),
                        FAKE_LOGS_STDERR=logs_stderr,
                        FAKE_STATE_ERROR=state,
                        FAKE_STATE_STATUS=str(state_status),
                        FAKE_STATE_STDERR=state_stderr,
                    )
                    result = subprocess.run(
                        ["bash", "-c", script], env=env, capture_output=True,
                        text=True, timeout=10, check=False,
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    if logs_status == 0:
                        logs_query_output = logs + "\n" + logs_stderr
                        if "DOCKERLENS_SIDECAR_STAGE: write_failed" in logs_query_output:
                            expected_stage = "write_failed"
                        elif "DOCKERLENS_SIDECAR_STAGE: write_ok" in logs_query_output:
                            expected_stage = "write_ok"
                        else:
                            expected_stage = "unknown"
                    else:
                        expected_stage = "unknown"
                    self.assertEqual(
                        result.stderr.strip(),
                        "DOCKERLENS_NATIVE_SIDECAR_SETUP: "
                        f"phase=sidecar_failure category={category} source={origin} "
                        f"write_stage={expected_stage} httpd_stage=unknown "
                        f"state_error={expected_state_error}",
                    )
                    self.assertNotIn("private-canary", result.stderr)

    def test_sidecar_failure_prefers_attributed_httpd_cause(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        helpers = "classify_sidecar_error() {" + source.split(
            "classify_sidecar_error() {", 1
        )[1].split("\n}\nwatchdog &", 1)[0] + "\n}\n"
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "podman"
            fake.write_text(
                '#!/bin/sh\n'
                'case "$1" in\n'
                '  logs) printf "%s\\n" "$FAKE_LOGS"; '
                'printf "permission denied private-canary\\n" >&2 ;;\n'
                '  inspect) printf "bind: address already in use private-canary\\n" ;;\n'
                '  *) exit 42 ;;\n'
                'esac\n',
                encoding="utf-8",
            )
            fake.chmod(0o755)
            script = (
                "set -euo pipefail\n"
                f"podman_cmd=({fake})\n"
                "sidecar=synthetic\n"
                + helpers
                + "sidecar_failure_diagnostic\n"
            )
            prefix = (
                "DOCKERLENS_SIDECAR_STAGE: write_ok\n"
                "DOCKERLENS_SIDECAR_HTTPD: invoked\n"
            )
            for marker, returned, expected, origin in (
                ("applet_missing", "returned_nonzero", "applet_missing", "httpd_stderr"),
                ("shell_error", "returned_nonzero", "shell_error", "httpd_stderr"),
                ("permission", "returned_nonzero", "permission", "httpd_stderr"),
                ("bind_error", "returned_nonzero", "bind_error", "httpd_stderr"),
                ("config_error", "returned_nonzero", "config_error", "httpd_stderr"),
                ("unknown", "returned_nonzero", "unknown", "httpd_stderr"),
                ("permission private-canary", "returned_nonzero", "unknown", "none"),
                ("permission\nDOCKERLENS_SIDECAR_HTTPD_CAUSE: permission",
                 "returned_nonzero", "unknown", "none"),
                ("permission private-canary\nDOCKERLENS_SIDECAR_HTTPD_CAUSE: permission",
                 "returned_nonzero", "unknown", "none"),
                ("permission", "returned_zero", "permission", "logs_query"),
            ):
                with self.subTest(marker=marker, returned=returned):
                    env = os.environ.copy()
                    env["FAKE_LOGS"] = (
                        prefix + f"DOCKERLENS_SIDECAR_HTTPD_CAUSE: {marker}\n"
                        + f"DOCKERLENS_SIDECAR_HTTPD: {returned}\n"
                    )
                    result = subprocess.run(
                        ["bash", "-c", script], env=env, capture_output=True,
                        text=True, timeout=10, check=False,
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr.strip(),
                        "DOCKERLENS_NATIVE_SIDECAR_SETUP: "
                        f"phase=sidecar_failure category={expected} source={origin} "
                        f"write_stage=write_ok httpd_stage={returned} "
                        "state_error=bind_error",
                    )
                    self.assertNotIn("private-canary", result.stderr)

    def test_sidecar_failure_categories_are_closed_and_hide_native_text(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        classifier = "classify_sidecar_error() {" + source.split(
            "classify_sidecar_error() {", 1
        )[1].split("\n}\nsidecar_failure_diagnostic()", 1)[0] + "\n}\n"
        cases = (
            ("sh: httpd: not found private-canary", "applet_missing"),
            ("sh: syntax error: private-canary", "shell_error"),
            ("httpd: invalid option private-canary", "config_error"),
            ("httpd: can't bind to port private-canary", "bind_error"),
            ("permission denied private-canary", "permission"),
            ("no space left on device private-canary", "storage"),
            ("runtime error private-canary", "runtime_error"),
            ("private-canary", "unknown"),
            ("", "unknown"),
        )
        for native_text, expected in cases:
            with self.subTest(category=expected):
                result = subprocess.run(
                    ["bash", "-c", classifier + "classify_sidecar_error"],
                    input=native_text, capture_output=True, text=True, timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, expected + "\n")
                self.assertEqual(result.stderr, "")
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_sidecar_stage_classifier_is_bounded_and_requires_exact_marker(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        classifier = "classify_sidecar_error() {" + source.split(
            "classify_sidecar_error() {", 1
        )[1].split("\n}\nsidecar_failure_diagnostic()", 1)[0] + "\n}\n"
        cases = (
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\n", "write_ok|unknown|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_failed\n", "write_failed|unknown|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nhttpd: permission denied private-canary\n",
             "write_ok|unknown|permission|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n",
             "write_ok|invoked|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\nprivate-canary\n",
             "write_ok|returned_nonzero|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_zero\n", "write_ok|returned_zero|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n",
             "write_ok|unknown|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_failed\nDOCKERLENS_SIDECAR_HTTPD: invoked\n",
             "write_failed|unknown|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_zero\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n", "write_ok|unknown|unknown|absent"),
            ("prefix DOCKERLENS_SIDECAR_STAGE: write_ok\n", "unknown|unknown|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_STAGE: write_failed\n",
             "unknown|unknown|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\n" + "x" * 9000,
             "unknown|unknown|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD_CAUSE: permission\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n",
             "write_ok|returned_nonzero|unknown|permission"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD_CAUSE: bind_error\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n",
             "write_ok|returned_nonzero|unknown|bind_error"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD_CAUSE: config_error\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n",
             "write_ok|returned_nonzero|unknown|config_error"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD_CAUSE: unknown\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n",
             "write_ok|returned_nonzero|unknown|unknown"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD_CAUSE: permission\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_zero\n",
             "write_ok|returned_zero|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD_CAUSE: permission private-canary\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n",
             "write_ok|returned_nonzero|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD_CAUSE: permission\n"
             "DOCKERLENS_SIDECAR_HTTPD_CAUSE: permission\n"
             "DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n",
             "write_ok|returned_nonzero|unknown|absent"),
            ("DOCKERLENS_SIDECAR_STAGE: write_ok\nDOCKERLENS_SIDECAR_HTTPD: invoked\n"
             "DOCKERLENS_SIDECAR_HTTPD_CAUSE: permission\n" + "x" * 9000 +
             "DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n",
             "unknown|unknown|unknown|absent"),
        )
        for logs, expected in cases:
            with self.subTest(expected=expected, size=len(logs)):
                result = subprocess.run(
                    ["bash", "-c", classifier + "classify_sidecar_error --with-stage"],
                    input=logs, capture_output=True, text=True, timeout=5, check=False,
                )
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, expected + "\n")
                self.assertEqual(result.stderr, "")
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_sidecar_command_marks_write_stage_before_httpd(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        quoted_command = source.split('  "$FIXTURE_IMAGE" sh -c \\\n  ', 1)[1].split(
            " 2>&1 >/dev/null |", 1
        )[0]
        command = shlex.split(quoted_command)
        self.assertEqual(len(command), 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sidecar_tmp = root / "sidecar"
            httpd_root = sidecar_tmp / "public"
            target = httpd_root / "index.html"
            fake_httpd = root / "httpd"
            fake_mktemp = root / "mktemp"
            capture = sidecar_tmp / "httpd.stderr"
            invoked = root / "httpd-invoked"
            fake_httpd.write_text(
                '#!/bin/sh\nprintf "yes" > "$FAKE_HTTPD_INVOKED"\n'
                '[ "$(cat "$5/index.html")" = proof-egress ] || exit 43\n'
                'if [ "$FAKE_HTTPD_FAIL" = 1 ]; then '
                'printf "%s\\n" "$FAKE_HTTPD_ERROR" >&2; exit 42; fi\n',
                encoding="utf-8",
            )
            fake_httpd.chmod(0o755)
            fake_mktemp.write_text(
                '#!/bin/sh\n[ "$1" = -d ] || exit 42\n'
                'mkdir -p "$FAKE_SIDECAR_TMP"\nprintf "%s\\n" "$FAKE_SIDECAR_TMP"\n',
                encoding="utf-8",
            )
            fake_mktemp.chmod(0o755)
            env = os.environ.copy()
            env.update(PATH=f"{root}:{env['PATH']}", FAKE_HTTPD_INVOKED=str(invoked),
                       FAKE_SIDECAR_TMP=str(sidecar_tmp))
            for target_is_directory, httpd_error, expected_cause in (
                (False, None, None),
                (True, None, None),
                (False, "permission denied private-canary", "permission"),
                (False, "can't bind to port private-canary", "bind_error"),
                (False, "invalid option private-canary", "config_error"),
                (False, "httpd: applet not found private-canary", "applet_missing"),
                (False, "sh: httpd: not found private-canary", "applet_missing"),
                (False, "sh: syntax error private-canary", "shell_error"),
                (False, "private-canary", "unknown"),
                (False, "DOCKERLENS_SIDECAR_HTTPD_CAUSE: permission private-canary",
                 "unknown"),
            ):
                with self.subTest(write_failure=target_is_directory, httpd_error=httpd_error):
                    if target.exists():
                        if target.is_dir():
                            target.rmdir()
                        else:
                            target.unlink()
                    invoked.unlink(missing_ok=True)
                    capture.unlink(missing_ok=True)
                    if target_is_directory:
                        target.mkdir(parents=True)
                    env["FAKE_HTTPD_FAIL"] = "1" if httpd_error is not None else "0"
                    env["FAKE_HTTPD_ERROR"] = httpd_error or ""
                    result = subprocess.run(
                        ["sh", "-c", command[0]],
                        env=env, capture_output=True, text=True, timeout=5, check=False,
                    )
                    self.assertEqual(result.returncode, 1 if target_is_directory else
                                     42 if httpd_error is not None else 0)
                    expected_stage = "write_failed" if target_is_directory else "write_ok"
                    self.assertIn(f"DOCKERLENS_SIDECAR_STAGE: {expected_stage}\n", result.stderr)
                    if target_is_directory:
                        self.assertNotIn("DOCKERLENS_SIDECAR_HTTPD:", result.stderr)
                    else:
                        self.assertIn("DOCKERLENS_SIDECAR_HTTPD: invoked\n", result.stderr)
                        returned = "returned_nonzero" if httpd_error is not None else "returned_zero"
                        self.assertIn(f"DOCKERLENS_SIDECAR_HTTPD: {returned}\n", result.stderr)
                    if expected_cause is None:
                        self.assertNotIn("DOCKERLENS_SIDECAR_HTTPD_CAUSE:", result.stderr)
                    else:
                        self.assertIn(
                            f"DOCKERLENS_SIDECAR_HTTPD_CAUSE: {expected_cause}\n",
                            result.stderr,
                        )
                    self.assertEqual(invoked.exists(), not target_is_directory)
                    self.assertFalse(capture.exists())
                    self.assertNotIn("private-canary", result.stderr)
                    if not target_is_directory:
                        self.assertFalse(sidecar_tmp.exists())
                    else:
                        target.rmdir()
                        httpd_root.rmdir()
                        sidecar_tmp.rmdir()

    def test_sidecar_httpd_stderr_is_outside_served_root(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        quoted_command = source.split('  "$FIXTURE_IMAGE" sh -c \\\n  ', 1)[1].split(
            " 2>&1 >/dev/null |", 1
        )[0]
        command = shlex.split(quoted_command)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_httpd = root / "httpd"
            fake_mktemp = root / "mktemp"
            sidecar_tmp = root / "sidecar"
            record = root / "served-path"
            fake_mktemp.write_text(
                '#!/bin/sh\nmkdir "$FAKE_SIDECAR_TMP"\n'
                'printf "%s\\n" "$FAKE_SIDECAR_TMP"\n', encoding="utf-8",
            )
            fake_httpd.write_text(
                '#!/bin/sh\n'
                '[ "$1" = -f ] && [ "$2" = -p ] && [ "$3" = 18084 ] && '
                '[ "$4" = -h ] || exit 43\n'
                'printf "%s\\n" "$5" > "$FAKE_HTTPD_RECORD"\n'
                '[ "$(cat "$5/index.html")" = proof-egress ] || exit 44\n'
                'printf "permission denied private-canary\\n" >&2\n'
                '[ "$(stat -c %a "$FAKE_SIDECAR_TMP/httpd.stderr")" = 600 ] || exit 45\n'
                '[ "$(find "$5" -type f | wc -l)" = 1 ] || exit 46\n'
                'exit 42\n', encoding="utf-8",
            )
            fake_httpd.chmod(0o755)
            fake_mktemp.chmod(0o755)
            env = os.environ.copy()
            env.update(PATH=f"{root}:{env['PATH']}", FAKE_SIDECAR_TMP=str(sidecar_tmp),
                       FAKE_HTTPD_RECORD=str(record))
            result = subprocess.run(
                ["sh", "-c", command], env=env, capture_output=True, text=True,
                timeout=5, check=False,
            )
            self.assertEqual(result.returncode, 42)
            served = Path(record.read_text().strip()).resolve()
            capture = (sidecar_tmp / "httpd.stderr").resolve()
            self.assertFalse(capture.is_relative_to(served))
            self.assertEqual(served, (sidecar_tmp / "public").resolve())
            self.assertIn("DOCKERLENS_SIDECAR_HTTPD_CAUSE: permission\n", result.stderr)
            self.assertNotIn("private-canary", result.stdout + result.stderr)
            self.assertFalse(sidecar_tmp.exists())

    def test_sidecar_httpd_capture_limit_is_checked_and_bounds_overflow(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        quoted_command = source.split('  "$FIXTURE_IMAGE" sh -c \\\n  ', 1)[1].split(
            " 2>&1 >/dev/null |", 1
        )[0]
        command = shlex.split(quoted_command)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sidecar_tmp = root / "sidecar"
            capture_size = root / "capture-size"
            invoked = root / "httpd-invoked"
            fake_mktemp = root / "mktemp"
            fake_httpd = root / "httpd"
            fake_rm = root / "rm"
            fake_mktemp.write_text(
                '#!/bin/sh\nmkdir "$FAKE_SIDECAR_TMP"\n'
                'printf "%s\\n" "$FAKE_SIDECAR_TMP"\n', encoding="utf-8",
            )
            fake_httpd.write_text(
                '#!/bin/sh\n'
                'printf yes > "$FAKE_HTTPD_INVOKED"\n'
                'head -c 16384 /dev/zero | tr "\\000" x >&2\n'
                'exit 42\n', encoding="utf-8",
            )
            fake_rm.write_text(
                '#!/bin/sh\n'
                'if [ -f "$FAKE_SIDECAR_TMP/httpd.stderr" ]; then\n'
                '  wc -c < "$FAKE_SIDECAR_TMP/httpd.stderr" > "$FAKE_CAPTURE_SIZE"\n'
                'fi\nexec /usr/bin/rm "$@"\n', encoding="utf-8",
            )
            fake_mktemp.chmod(0o755)
            fake_httpd.chmod(0o755)
            fake_rm.chmod(0o755)
            env = os.environ.copy()
            env.update(PATH=f"{root}:{env['PATH']}", FAKE_SIDECAR_TMP=str(sidecar_tmp),
                       FAKE_CAPTURE_SIZE=str(capture_size), FAKE_HTTPD_INVOKED=str(invoked))
            for shell, limit_available in (
                ("sh", True), ("sh", False), ("bash", True), ("bash", False),
            ):
                with self.subTest(shell=shell, limit_available=limit_available):
                    capture_size.unlink(missing_ok=True)
                    invoked.unlink(missing_ok=True)
                    selected = command if limit_available else command.replace("ulimit -f 8", "false")
                    result = subprocess.run(
                        [shell, "-c", selected], env=env, capture_output=True, text=True,
                        timeout=5, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(invoked.exists(), limit_available)
                    size = int(capture_size.read_text())
                    if limit_available:
                        self.assertGreater(size, 0)
                        self.assertLessEqual(size, 8192)
                    else:
                        self.assertEqual(size, 0)
                    self.assertIn("DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n", result.stderr)
                    self.assertIn("DOCKERLENS_SIDECAR_HTTPD_CAUSE: unknown\n", result.stderr)
                    self.assertNotIn("x" * 100, result.stdout + result.stderr)
                    self.assertFalse(sidecar_tmp.exists())

    def test_outer_ipv4_diagnostics_are_closed_for_each_rejection(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        helper = source.split("validated_outer_ipv4() {", 1)[1].split(
            "\n}\nsidecar_setup_failed()", 1
        )[0]
        network = "dl-native-net-fixture"
        valid = {network: {"IPAddress": "10.89.0.2"}}
        fixtures = (
            ('{"private-canary":', "json_shape", "0"),
            (json.dumps([]), "json_shape", "0"),
            (json.dumps({}), "network_missing", "0"),
            (json.dumps({**valid, "unexpected": {"IPAddress": "10.89.0.3"}}), "network_extra", "0"),
            (json.dumps({network: {}}), "ipv4_missing", "0"),
            (json.dumps({network: {"IPAddress": "private-canary"}}), "ipv4_malformed", "0"),
            (json.dumps({network: {"IPAddress": 173604866}}), "ipv4_malformed", "0"),
            (json.dumps({network: {"IPAddress": "8.8.8.8"}}), "ipv4_nonprivate", "0"),
            (json.dumps(valid), "inspect_failed", "42"),
            ("private-canary" * 300, "output_limit", "0"),
        )
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "podman"
            fake.write_text(
                '#!/usr/bin/env bash\nprintf %s "$FAKE_NETWORKS"\nexit "$FAKE_PODMAN_STATUS"\n',
                encoding="utf-8",
            )
            fake.chmod(0o755)
            script = (
                'podman_cmd=("$FAKE_PODMAN")\n'
                f'outer_network={network}\n'
                f'validated_outer_ipv4() {{{helper}\n}}\n'
                'validated_outer_ipv4 "$FAKE_ROLE" dl-native-fixture\n'
            )
            for role in ("sidecar", "daemon"):
                for networks, category, status in fixtures:
                    with self.subTest(role=role, category=category, status=status):
                        env = os.environ.copy()
                        env.update(FAKE_PODMAN=str(fake), FAKE_ROLE=role,
                                   FAKE_NETWORKS=networks, FAKE_PODMAN_STATUS=status)
                        result = subprocess.run(
                            ["bash", "-c", script], env=env, capture_output=True,
                            text=True, timeout=15, check=False,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(
                            result.stderr.strip(),
                            f"DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=attachment role={role} category={category}",
                        )
                        self.assertNotIn("private-canary", result.stderr)
            env = os.environ.copy()
            env.update(FAKE_PODMAN=str(fake), FAKE_ROLE="sidecar",
                       FAKE_NETWORKS=json.dumps(valid), FAKE_PODMAN_STATUS="0")
            result = subprocess.run(
                ["bash", "-c", script], env=env, capture_output=True,
                text=True, timeout=15, check=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "10.89.0.2\n")
            self.assertEqual(result.stderr, "")

    def test_network_oracle_diagnostics_are_closed_and_do_not_hide_failure(self) -> None:
        source = (ROOT / "src/native_network_tests.rs").read_text(encoding="utf-8")
        negative_cli = source.split("fn cli(args:", 1)[1].split("fn network_cli_failure_category", 1)[0]
        self.assertNotIn("DOCKERLENS_NATIVE_NETWORK_CLI_DIAG", negative_cli)
        positive_cli = source.split("fn cli_ok(args:", 1)[1].split("struct BoundedDnsCliOutput", 1)[0]
        self.assertIn("DOCKERLENS_NATIVE_NETWORK_CLI_DIAG", positive_cli)
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_network_render_matches_engine: test'
else
  echo 'DOCKERLENS_NATIVE_CHECK: network_oracle_alternate_create' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_oracle_private' >&2
  echo 'DOCKERLENS_NATIVE_NETWORK_CLI_DIAG: exit=other category=bridge_filter' >&2
  echo 'DOCKERLENS_NATIVE_NETWORK_CLI_DIAG: exit=other category=private-canary' >&2
  echo 'private-canary raw native output' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 101
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                 "live_network_render_matches_engine"],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("network_oracle_alternate_create", result.stderr)
            self.assertIn("exit=other category=bridge_filter", result.stderr)
            self.assertNotIn("private-canary", result.stdout + result.stderr)
            self.assertNotIn("network_oracle_private", result.stdout + result.stderr)

    def test_host_network_prerequisite_runs_before_owned_resources(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        preflight = 'python3 "$script_dir/native-bridge-prerequisite.py"'
        self.assertIn(preflight, source)
        self.assertLess(source.index(preflight), source.index('run_dir=$(mktemp -d'))
        self.assertNotIn("sysctl -w", source)
        self.assertNotIn("DOCKER_IGNORE_BR_NETFILTER_ERROR", source)

    def test_failure_exposes_only_selected_native_panic_location(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_network_render_matches_engine: test'
else
  printf '%s\\n' "$TEST_PANIC"
  echo 'assertion contains protected-native-canary and private path' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 101
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            # Current libtest includes a numeric thread ID; older Rust omits it.
            # Observed independently in an actual local Rust panic, not inferred
            # from the extractor's synthetic fixture. Never disclose that ID.
            for location, thread_suffix, expected in (
                ("src/native_network_tests.rs:1931:5", "", True),
                ("src/native_network_tests.rs:1931:5", " (342)", True),
                ("src/native_network_tests.rs:1931:5", " (private)", False),
                ("src/native_network_tests.rs:1931:5", " (12345678901)", False),
                ("/private/source/native_network_tests.rs:1931:5", " (342)", False),
                ("src/native_target_tests.rs:1931:5", " (342)", False),
                ("src/native_network_tests.rs:private:5", "", False),
                ("src/native_network_tests.rs:1931:50000", "", False),
            ):
                with self.subTest(location=location, thread_suffix=thread_suffix):
                    env["TEST_PANIC"] = f"thread 'protected-name-canary'{thread_suffix} panicked at {location}:"
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                         "live_network_render_matches_engine"],
                        env=env, text=True, capture_output=True, timeout=10,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual("DOCKERLENS_NATIVE_PANIC:" in result.stderr, expected)
                    if expected:
                        self.assertIn("source=native_network_tests line=1931 column=5", result.stderr)
                    for private in ("protected-native-canary", "protected-name-canary", "/private/source", "(342)"):
                        self.assertNotIn(private, result.stdout + result.stderr)

    def test_failure_reports_first_panic_before_aggregate_panic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'DOCKERLENS_NATIVE_CHECK: container_resolver_logging_ipv6_rendered_create' >&2
  echo "thread 'protected-first-name' (342) panicked at src/native_container_tests.rs:4111:7:" >&2
  echo 'protected-first-message and native value' >&2
  echo "thread 'protected-aggregate-name' panicked at src/native_container_tests.rs:5527:9:" >&2
  echo 'protected-aggregate-message and private path' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 101
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, text=True, capture_output=True, timeout=10, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "DOCKERLENS_NATIVE_CHECK: container_resolver_logging_ipv6_rendered_create",
                result.stderr,
            )
            self.assertEqual(
                ["DOCKERLENS_NATIVE_PANIC: source=native_container_tests line=4111 column=7"],
                [line for line in result.stderr.splitlines()
                 if line.startswith("DOCKERLENS_NATIVE_PANIC:")],
            )
            for private in ("protected-first", "protected-aggregate", "native value",
                            "private path", "(342)"):
                self.assertNotIn(private, result.stdout + result.stderr)

    def test_isolation_positive_controls_query_ipv4_before_negative_controls(self) -> None:
        source = (ROOT / "src/native_network_tests.rs").read_text(encoding="utf-8")
        markers = [
            "network_isolation_edge_dns", "network_isolation_edge_http",
            "network_isolation_local_dns", "network_isolation_local_http",
            "network_isolation_collision_dns", "network_isolation_collision_http",
            "network_isolation_foreign_route",
        ]
        self.assertEqual([source.count(f'DOCKERLENS_NATIVE_CHECK: {marker}"')
                          for marker in markers], [1] * len(markers))
        self.assertEqual([source.index(f'DOCKERLENS_NATIVE_CHECK: {marker}')
                          for marker in markers],
                         sorted(source.index(f'DOCKERLENS_NATIVE_CHECK: {marker}')
                                for marker in markers))
        self.assertEqual(re.findall(r'"nslookup",\s*"-type=A",\s*"([^"]+)"', source),
                         ["edge-sentinel", "edge-sentinel", "edge-sentinel.",
                          "backend-app", "edge-sentinel.", "edge-sentinel."])
        edge_dns = source[source.index('let edge_dns_outcome ='):source.index('if let Err(category) = edge_dns_outcome')]
        self.assertTrue('exec nslookup -type=A edge-sentinel 127.0.0.11' in edge_dns)
        self.assertTrue('/etc/resolv.conf || exit 42;' in edge_dns)
        local_dns = source[source.index('network_isolation_local_dns"'):source.index('network_isolation_local_http"')]
        self.assertIsNotNone(re.search(
            r'"exec",\s*&backend_only,\s*"cat",\s*"/etc/resolv\.conf"', local_dns,
        ))
        self.assertIsNotNone(re.search(
            r'"backend-app",\s*EMBEDDED_DNS_SERVER,', local_dns,
        ))
        self.assertTrue('resolver_category(&backend_resolver.stdout)' in local_dns)
        collision_dns = source[source.index('network_isolation_collision_dns"'):source.index('network_isolation_collision_http"')]
        self.assertEqual(len(re.findall(r'"edge-sentinel\.",\s*EMBEDDED_DNS_SERVER,', collision_dns)), 2)
        self.assertTrue('nslookup_has_only_exact_named_a(&edge_collision.stdout, "edge-sentinel", edge_ip)' in collision_dns)
        self.assertTrue('nslookup_has_only_exact_named_a(' in collision_dns)
        self.assertTrue('backend_canary_ip,' in collision_dns)
        self.assertTrue('DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=edge' in collision_dns)
        self.assertTrue('DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=backend' in collision_dns)
        self.assertIsNotNone(re.search(r'assert!\(\s*edge_exact', collision_dns))
        self.assertIsNotNone(re.search(r'assert!\(\s*backend_exact', collision_dns))
        edge_http = source[source.index('network_isolation_edge_http"'):source.index('network_isolation_local_dns"')]
        local_http = source[source.index('network_isolation_local_http"'):source.index('network_isolation_collision_dns"')]
        collision_http = source[source.index('network_isolation_collision_http"'):source.index('network_isolation_foreign_route"')]
        self.assertTrue('"http://edge-sentinel:8080/"' in edge_http)
        self.assertTrue('"http://backend-app:8080/"' in local_http)
        self.assertEqual(collision_http.count('"http://edge-sentinel:8080/"'), 2)
        self.assertTrue('b"edge-canary"' in collision_http)
        self.assertTrue('b"backend-canary"' in collision_http)
        self.assertTrue('canonical_inspected_container_id(&edge_only_body)' in source)
        self.assertTrue('canonical_inspected_container_id(&isolated)' in source)
        self.assertIsNotNone(re.search(r'assert!\(\s*edge_id != backend_id', source))
        self.assertIsNotNone(re.search(r'assert!\(\s*edge_ip != backend_canary_ip', source))
        self.assertTrue('network_isolation_cleanup_unverified' in source)
        self.assertTrue('let backend_cleaned = backend_fixture.cleanup();' in source)
        self.assertTrue('let edge_cleaned = edge_fixture.cleanup();' in source)
        self.assertTrue('fn nslookup_exact_named_a_rejects_extra_foreign_and_malformed_answers()' in source)
        self.assertIn('let edge_dns_outcome = wait_for_exact_dns_answer(', source)
        self.assertIn('if category != "cli_lookup"', source)
        self.assertIn('edge_dns_outcome.is_ok()', source)
        self.assertIn('let edge_alias_present =', source)
        self.assertIn('aliases.iter().any(|alias| alias == "edge-sentinel")', source)
        self.assertTrue('nslookup_has_ipv4_answer(&backend_answer.stdout, "backend-app", backend_ip)' in local_dns)
        self.assertIn("fn nslookup_ipv4_answer_requires_exact_named_address_not_prefix_or_resolver()", source)
        self.assertIn('edge_only_body["State"]["Running"] != true', source)
        self.assertIn("fn edge_dns_failure_categories_are_closed_and_value_free()", source)
        self.assertIn("fn exact_dns_readiness_retries_only_transient_lookup_with_finite_budget()", source)
        self.assertIn("const LIMIT: usize = 8192;", source)
        self.assertIn("let stdout_reader = std::thread::spawn", source)
        self.assertIn("let stderr_reader = std::thread::spawn", source)
        self.assertIn('private_docker_command("8")', source)
        self.assertIn('api_with_timeout("GET", path, None, "3")', source)
        self.assertLess(source.index("match named_dns_answer_category"),
                        source.index('if message.contains("can\'t resolve")'))
        self.assertIn("mixed wrong answer must not be retried", source)
        failure = source.index('if let Err(category) = edge_dns_outcome')
        self.assertLess(failure, source.index('diagnose_edge_dns(&run_id', failure))
        self.assertLess(source.index('diagnose_edge_dns(&run_id', failure),
                        source.index('edge_dns_outcome.is_ok()', failure))
        self.assertIsNotNone(re.search(
            r'"--name",\s*&peer,\s*"--network",\s*edge,\s*image,\s*"sleep",\s*"120"',
            source,
        ))
        self.assertIsNotNone(re.search(
            r'api_with_timeout_and_cap\("GET",\s*&path,\s*None,\s*"3",\s*Some\(1024 \* 1024\)\)',
            source,
        ))
        self.assertTrue('NATIVE_NETWORK_TEST_DEADLINE_EPOCH' in source)
        self.assertTrue('DNS_CLI_HARD_LIMIT_SECS' in source)
        self.assertTrue('command.args(["--kill-after=1", seconds])' in source)
        self.assertIn('networks.len() == 1 && networks.contains_key(edge)', source)
        self.assertIn('summary.cleanup = if guard.cleanup()', source)

    def test_dns_diagnostic_summary_is_closed_and_surfaced_separately(self) -> None:
        valid = ("DOCKERLENS_NATIVE_DNS_DIAG: peer=ready resolver=embedded_search "
                 "default_a=fail explicit_a=pass dotted_a=pass name_http=pass "
                 "ip_http=pass edge_app=pass cleanup=pass")
        invalid = ("DOCKERLENS_NATIVE_DNS_DIAG: peer=ready resolver=protected-secret "
                   "default_a=pass explicit_a=pass dotted_a=pass name_http=pass "
                   "ip_http=pass edge_app=pass cleanup=pass")
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_network_render_matches_engine: test'
else
  [[ ${NATIVE_NETWORK_TEST_DEADLINE_EPOCH:-} =~ ^[0-9]+$ ]] || exit 24
  remaining=$((NATIVE_NETWORK_TEST_DEADLINE_EPOCH - $(date +%s)))
  (( remaining >= 170 && remaining <= 180 )) || exit 24
  echo 'protected native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_isolation_edge_dns_readiness_exhausted' >&2
  printf '%s\n' "$TEST_DIAG" >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for supplied, accepted in ((valid, True), (invalid, False),
                                       (valid + " raw=protected-secret", False)):
                with self.subTest(accepted=accepted, supplied=supplied):
                    env["TEST_DIAG"] = supplied
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                         "live_network_render_matches_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(valid in result.stderr, accepted)
                    self.assertIn("network_isolation_edge_dns_readiness_exhausted", result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)
                    self.assertNotIn("protected native response", result.stdout + result.stderr)

    def test_collision_dns_diagnostic_is_closed_and_keeps_failure(self) -> None:
        valid = ("DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=backend category=cli_unclassified "
                 "exit=other response=no_error_no_a")
        invalid = ("DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=protected-secret category=cli_unclassified "
                   "exit=other response=no_error_no_a")
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_network_render_matches_engine: test'
else
  echo 'protected native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_isolation_collision_dns' >&2
  printf '%s\n' "$TEST_DIAG" >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for supplied, accepted in ((valid, True), (invalid, False),
                                       (valid + " raw=protected-secret", False)):
                with self.subTest(accepted=accepted, supplied=supplied):
                    env["TEST_DIAG"] = supplied
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                         "live_network_render_matches_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(valid in result.stderr, accepted)
                    self.assertIn("network_isolation_collision_dns", result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)
                    self.assertNotIn("protected native response", result.stdout + result.stderr)

    def test_tmpfs_option_proof_precedes_positive_shape_recording(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text()
        effects = source.split("fn assert_tmpfs_effects(", 1)[1].split("fn assert_signal_effect(", 1)[0]
        self.assertIn("run.cli_with_timeout(", effects)
        self.assertIn("stat -f -c '%S %b'", effects)
        self.assertIn("stat -c '%a'", effects)
        self.assertIn("for path in /scratch /sealed", effects)
        self.assertIn("assert_tmpfs_options(&options);", effects)
        storage = source.split("fn probe_storage_and_lifecycle(", 1)[1].split(
            "fn assert_resource_effects(", 1
        )[0]
        before_positive = storage.split('"TmpfsMountOptions"', 1)[0]
        self.assertIn("assert_tmpfs_effects(run, &oracle_id);", before_positive)
        self.assertIn("assert_tmpfs_effects(run, &id);", before_positive)
        self.assertEqual(before_positive.count("assert_tmpfs_effects("), 2)

    def test_container_checkpoint_preserves_all_ten_existing_native_checks(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        calls = re.findall(
            r'^"\$\(dirname "\$0"\)/run-exact-native-test\.sh" ([a-z_]+) ([a-z_]+)$',
            source, re.MULTILINE,
        )
        # Independently reviewed baseline order; the new checkpoint may not
        # replace, duplicate or skip any prior native requirement.
        existing = [
            ("native_capture", "live_engine_capture_decodes"),
            ("acquisition", "live_read_only_acquisition_matches_oracle"),
            ("native_selection", "live_native_selection_and_source_observations"),
            ("native_selection", "live_network_membership_matches_engine"),
            ("native_target", "live_target_render_matches_engine"),
            ("native_network", "live_network_render_matches_engine"),
            ("native_network", "live_internal_network_blocks_external_egress"),
            ("native_volume", "live_existing_volume_prerequisite_matches_engine"),
            ("native_volume_label", "live_created_volume_labels_match_engine"),
            ("native_identity", "live_container_process_identity_matches_engine"),
        ]
        checkpoint = ("native_container", "live_container_settings_match_engine")
        self.assertEqual(calls, [*existing[:-2], checkpoint, *existing[-2:]])
        self.assertLess(source.index(checkpoint[1]), source.index('python3 "$script_dir/native-evidence.py"'))

    def test_container_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = '"$(dirname "$0")/run-exact-native-test.sh" native_container live_container_settings_match_engine'
        network = '"$(dirname "$0")/run-exact-native-test.sh" native_network live_network_render_matches_engine'
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertLess(source.index(network), source.index(selected))
        self.assertLess(source.index(selected), source.index(manifest))
        self.assertIn('export NATIVE_CONTAINER_PROBES_PATH="$run_dir/container-probes.json"', source)
        self.assertIn('"$NATIVE_CONTAINER_PROBES_PATH"', source)

    def test_container_failure_marker_is_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'protected native response' >&2
  echo "DOCKERLENS_NATIVE_CHECK: container_$TEST_MARKER" >&2
  echo 'DOCKERLENS_NATIVE_CHECK: container_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for marker in (
                "ports", "ports_ipv6", "identity_health", "health_disabled", "clear",
                "start_interval", "storage_lifecycle", "resources_security",
                "resolver_logging",
                "resources_security_oracle_inspect",
                "resources_security_oracle_memory",
                "resources_security_rendered_pids",
                "resources_security_rendered_shm",
            ):
                with self.subTest(marker=marker):
                    env["TEST_MARKER"] = marker
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                         "live_container_settings_match_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"DOCKERLENS_NATIVE_CHECK: container_{marker}", result.stderr)
                    self.assertNotIn("private", result.stdout + result.stderr)

    def test_port_failure_stage_and_categories_never_expose_native_details(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text(encoding="utf-8")
        for suffix in (
            "port-oracle", "port-rendered", "ipv6-oracle", "ipv6-rendered",
            "ipv6-dynamic-oracle", "ipv6-dynamic-rendered",
            "multi-dynamic-oracle", "multi-dynamic-rendered",
        ):
            self.assertIn(f'"{suffix}" =>', source)
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'protected-secret native response' >&2
  echo "DOCKERLENS_NATIVE_CHECK: container_port_$TEST_PORT_STAGE" >&2
  echo 'DOCKERLENS_NATIVE_CHECK: container_port_fixed_ipv6_rendered_protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_CLI_DIAG: exit=other stderr=address_family' >&2
  echo 'DOCKERLENS_NATIVE_CLI_DIAG: exit=other stderr=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_API_DIAG: operation=start status=conflict' >&2
  echo 'DOCKERLENS_NATIVE_API_DIAG: operation=protected-secret status=conflict' >&2
  echo 'DOCKERLENS_NATIVE_API_DIAG: operation=start status=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_API_DIAG: operation=start status=conflict raw=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_IPV6_BOUNDARY_DIAG: result=refused' >&2
  echo 'DOCKERLENS_NATIVE_IPV6_BOUNDARY_DIAG: result=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_PORT_BINDINGS_DIAG: key=array count=one ipv4=one ipv6=zero other=zero v4_port=nonzero v6_port=absent' >&2
  echo 'DOCKERLENS_NATIVE_PORT_BINDINGS_DIAG: key=array count=protected-secret ipv4=one ipv6=zero other=zero v4_port=nonzero v6_port=absent' >&2
  echo 'DOCKERLENS_NATIVE_PORT_BINDINGS_DIAG: key=array count=one ipv4=one ipv6=zero other=zero v4_port=nonzero v6_port=absent raw=protected-secret' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for stage in (
                "fixed_ipv4_oracle_cli_inspect", "fixed_ipv6_rendered_cli_http",
                "fixed_ipv6_rendered_tcp6_boundary",
                "fixed_ipv6_rendered_negative_recheck",
                "fixed_ipv6_rendered_runtime_absence",
                "dynamic_ipv6_oracle_dynamic_binding",
                "dynamic_ipv6_oracle_tcp6_boundary",
                "dynamic_ipv6_oracle_negative_recheck",
                "dynamic_ipv6_oracle_runtime_absence",
                "repeated_dynamic_ipv4_rendered_cli_http_secondary",
                "fixed_ipv4_rendered_udp_assert",
            ):
                with self.subTest(stage=stage):
                    env["TEST_PORT_STAGE"] = stage
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                         "live_container_settings_match_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"container_port_{stage}", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_CLI_DIAG: exit=other stderr=address_family", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_API_DIAG: observation=last operation=start status=conflict", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_IPV6_BOUNDARY_DIAG: result=refused", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_PORT_BINDINGS_DIAG: key=array count=one ipv4=one ipv6=zero other=zero v4_port=nonzero v6_port=absent", result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_command_clear_stages_and_diagnostic_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo "DOCKERLENS_NATIVE_CHECK: container_clear_$TEST_STAGE" >&2
  echo 'DOCKERLENS_NATIVE_CHECK: container_clear_protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_CLEAR_DIAG: phase=paired cmd=null entrypoint=shell path=shell args=empty' >&2
  echo 'DOCKERLENS_NATIVE_CLEAR_DIAG: phase=paired cmd=protected-secret entrypoint=shell path=shell args=empty' >&2
  echo 'DOCKERLENS_NATIVE_CLEAR_DIAG: phase=paired cmd=null entrypoint=shell path=shell args=empty raw=protected-secret' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for stage in ("baseline", "cmd_alone", "override_omit", "paired_literal",
                          "rendered", "entrypoint"):
                with self.subTest(stage=stage):
                    env["TEST_STAGE"] = stage
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                         "live_container_settings_match_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"container_clear_{stage}", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_CLEAR_DIAG: phase=paired cmd=null entrypoint=shell path=shell args=empty", result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_cap_drop_diagnostic_is_exact_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'DOCKERLENS_NATIVE_CHECK: container_resources_security' >&2
  echo 'DOCKERLENS_NATIVE_CAP_DROP_DIAG: phase=oracle state=array count=one spelling=cap_sys_admin' >&2
  echo 'DOCKERLENS_NATIVE_CAP_DROP_DIAG: phase=oracle state=array count=one spelling=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_CAP_DROP_DIAG: phase=oracle state=array count=one spelling=cap_sys_admin raw=protected-secret' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DOCKERLENS_NATIVE_CAP_DROP_DIAG: phase=oracle state=array count=one spelling=cap_sys_admin", result.stderr)
            self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_start_failure_body_diagnostic_is_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'DOCKERLENS_NATIVE_CHECK: container_resources_security_oracle_start' >&2
  echo 'DOCKERLENS_NATIVE_START_BODY_DIAG: shape=message cgroup_mention=present device_mention=absent sysctl_mention=absent ulimit_mention=absent apparmor_mention=absent permission_phrase=present errno_mention=absent controller_mention=absent bpf_mention=absent' >&2
  echo 'DOCKERLENS_NATIVE_START_BODY_DIAG: shape=message cgroup_mention=protected-secret device_mention=absent sysctl_mention=absent ulimit_mention=absent apparmor_mention=absent permission_phrase=present errno_mention=absent controller_mention=absent bpf_mention=absent' >&2
  echo 'DOCKERLENS_NATIVE_START_BODY_DIAG: shape=message cgroup_mention=present device_mention=absent sysctl_mention=absent ulimit_mention=absent apparmor_mention=absent permission_phrase=present errno_mention=absent controller_mention=absent bpf_mention=absent raw=protected-secret' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DOCKERLENS_NATIVE_START_BODY_DIAG: shape=message cgroup_mention=present device_mention=absent sysctl_mention=absent ulimit_mention=absent apparmor_mention=absent permission_phrase=present errno_mention=absent controller_mention=absent bpf_mention=absent", result.stderr)
            self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_resource_effect_guest_reads_only_bounded_synthetic_controller_files(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text()
        guest = source.split('const RESOURCE_EFFECT_GUEST: &str = r#"', 1)[1].split('"#;', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cgroup"
            root.mkdir()
            script = guest
            paths = [root / "memory.max", root / "pids.max"]

            def read(env=None):
                result = subprocess.run(["sh", "-c", script, "cgroup-read", *map(str, paths)], env=env, capture_output=True,
                                        text=True, timeout=2, check=False)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stderr, "")
                return result.stdout

            self.assertEqual(read(), "memory missing\npids missing\n")
            memory = root / "memory.max"
            pids = root / "pids.max"
            memory.write_text("67108864\n")
            pids.write_text("32\n")
            self.assertEqual(read(), "memory ok 67108864\npids ok 32\n")
            for value, category in (("max\n", "ok max"), ("protected-secret\n", "malformed"),
                                    ("12\n34\n", "malformed"), ("9" * 66, "oversized")):
                memory.write_text(value)
                self.assertEqual(read(), f"memory {category}\npids ok 32\n")
            memory.unlink()
            secret = Path(directory) / "secret"
            secret.write_text("protected-secret\n")
            memory.symlink_to(secret)
            self.assertEqual(read(), "memory invalid_file\npids ok 32\n")
            memory.unlink()
            memory.mkdir()
            self.assertEqual(read(), "memory invalid_file\npids ok 32\n")
            memory.rmdir()
            (root / "memory").mkdir()
            (root / "memory/memory.limit_in_bytes").write_text("67108864\n")
            # A fixed root fallback would read this file without an authenticated
            # mount/member mapping. Only an explicitly resolved leaf is accepted.
            self.assertEqual(read(), "memory missing\npids ok 32\n")
            paths[0] = root / "memory/memory.limit_in_bytes"
            self.assertEqual(read(), "memory ok 67108864\npids ok 32\n")
            (root / "memory.max").write_text("999999\n")
            (root / "pids.max").write_text("999\n")
            leaf = root / "leaf"
            leaf.mkdir()
            (leaf / "memory.max").write_text("67108864\n")
            (leaf / "pids.max").write_text("32\n")
            paths[:] = [leaf / "memory.max", leaf / "pids.max"]
            self.assertEqual(read(), "memory ok 67108864\npids ok 32\n")
            (leaf / "memory.max").write_text("67108864" + "\n" * 100)
            self.assertEqual(read(), "memory oversized\npids ok 32\n")
            (leaf / "memory.max").write_text("67108864\n")
            alias = root / "alias"
            alias.symlink_to(leaf, target_is_directory=True)
            paths[0] = alias / "memory.max"
            self.assertEqual(read(), "memory invalid_file\npids ok 32\n")
            paths[0] = leaf / "memory.max"
            bin_dir = Path(directory) / "bin"
            bin_dir.mkdir()
            self._tool(bin_dir, "head", "#!/bin/sh\nexit 1\n")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            self.assertEqual(read(env), "memory read_error\npids read_error\n")

    def test_resource_effect_diagnostics_are_closed_capped_and_never_enforcement(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text()
        control = source.split("fn resource_control_start(", 1)[1].split("fn namespace_probe(", 1)[0]
        self.assertIn("resource_control_may_continue(", control)
        self.assertIn("self.resource_effect_reads(id)", control)
        guest = source.split("fn resource_cgroup_guest(", 1)[1].split("fn namespace_probe(", 1)[0]
        self.assertIn('"1".into()', guest)
        self.assertIn('&args, "3"', guest)
        required = source.split("fn probe_resources_and_security(", 1)[1].split(
            "fn runtime_unlimited_cgroups(", 1
        )[0]
        self.assertIn("assert_native_api_status(NativeApiOperation::Start, oracle_start_status, 204);", required)
        self.assertIn('assert_resource_effects(run, &oracle_id, "oracle");', required)
        self.assertIn('assert_resource_effects(run, &id, "rendered");', required)
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  fields='memory_configured=finite memory_read=finite memory_effect=matches pids_configured=finite pids_read=finite pids_effect=matches enforcement=unknown'
  for control in baseline baseline baseline memory pids device device-same-path; do
    echo "DOCKERLENS_NATIVE_RESOURCE_EFFECT_DIAG: control=$control $fields" >&2
  done
  echo "DOCKERLENS_NATIVE_RESOURCE_EFFECT_DIAG: control=protected-secret $fields" >&2
  echo "DOCKERLENS_NATIVE_RESOURCE_EFFECT_DIAG: control=memory $fields raw=protected-secret" >&2
  echo "DOCKERLENS_NATIVE_RESOURCE_EFFECT_DIAG: control=memory ${fields/enforcement=unknown/enforcement=proven}" >&2
  echo "DOCKERLENS_NATIVE_RESOURCE_EFFECT_DIAG: control=memory ${fields/memory_configured=finite/memory_configured=67108864}" >&2
  echo "DOCKERLENS_NATIVE_RESOURCE_EFFECT_DIAG: control=memory ${fields/memory_read=finite/memory_read=controller_present}" >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"], env=env, capture_output=True,
                text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            records = [line for line in result.stderr.splitlines()
                       if line.startswith("DOCKERLENS_NATIVE_RESOURCE_EFFECT_DIAG:")]
            self.assertEqual(len(records), 5)
            self.assertEqual([line.split("control=", 1)[1].split(" ", 1)[0] for line in records],
                             ["baseline", "memory", "pids", "device", "device-same-path"])
            self.assertTrue(all(line.endswith("enforcement=unknown") for line in records))
            for private in ("protected-secret", "67108864", "controller_present", "enforcement=proven"):
                self.assertNotIn(private, result.stdout + result.stderr)

    def test_control_start_body_diagnostics_preserve_five_closed_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  body='shape=message cgroup_mention=present device_mention=absent sysctl_mention=absent ulimit_mention=absent apparmor_mention=absent permission_phrase=present errno_mention=absent controller_mention=present bpf_mention=absent'
  for control in baseline baseline baseline baseline memory pids device device-same-path; do
    echo "DOCKERLENS_NATIVE_RESOURCE_START_BODY_DIAG: control=$control $body" >&2
  done
  echo "DOCKERLENS_NATIVE_START_BODY_DIAG: $body" >&2
  echo "DOCKERLENS_NATIVE_RESOURCE_START_BODY_DIAG: control=protected-secret $body" >&2
  echo "DOCKERLENS_NATIVE_RESOURCE_START_BODY_DIAG: control=memory $body raw=protected-secret" >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr.count("DOCKERLENS_NATIVE_RESOURCE_START_BODY_DIAG:"), 5)
            for control in ("baseline", "memory", "pids", "device", "device-same-path"):
                self.assertIn(f"DOCKERLENS_NATIVE_RESOURCE_START_BODY_DIAG: control={control} shape=message", result.stderr)
            self.assertIn("DOCKERLENS_NATIVE_START_BODY_DIAG: shape=message", result.stderr)
            self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_resource_cgroup_snapshot_guest_requires_shared_namespaces_and_complete_caps(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text()
        guest = source.split('const RESOURCE_CGROUP_SNAPSHOT_GUEST: &str = r#"', 1)[1].split('"#;', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            for process in ("1", "17"):
                (proc / process / "ns").mkdir(parents=True)
                for kind, identity in (("pid", 11), ("mnt", 12), ("cgroup", 13)):
                    (proc / process / "ns" / kind).symlink_to(f"{kind}:[{identity}]")
            stat = "1 (sleep) S " + "0 " * 18 + "41\n"
            membership = "0::/parent/leaf\n"
            mounts = ("10 0 0:10 / / rw - tmpfs tmpfs rw\n"
                      "1 10 0:1 / /proc rw - proc proc rw\n2 10 0:2 / /cg rw - cgroup2 cgroup rw\n")
            for name, payload in (("stat", stat), ("cgroup", membership), ("mountinfo", mounts)):
                (proc / "1" / name).write_text(payload)
            (proc / "17" / "cgroup").write_text(membership)
            script = guest.replace("/proc", str(proc)).replace("helper_pid=$$", "helper_pid=17")

            def read():
                return subprocess.run(["sh", "-c", script], capture_output=True, text=True,
                                      timeout=2, check=False)

            result = read()
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertEqual(result.stdout, "helper\n17\nnamespaces\npid:[11]\nmnt:[12]\ncgroup:[13]\nstat\n" +
                             stat + "cgroup\n" + membership + "mountinfo\n" + mounts + "end\n")
            for name, limit, original in (("stat", 512, stat), ("cgroup", 1024, membership),
                                           ("mountinfo", 6144, mounts)):
                with self.subTest(name=name):
                    # Newlines must count toward the cap, even under cmdsub.
                    (proc / "1" / name).write_text("\n" * (limit + 1))
                    result = read()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("end\n", result.stdout)
                    self.assertEqual(result.stderr, "")
                    (proc / "1" / name).write_text(original)
            for kind in ("pid", "mnt", "cgroup"):
                with self.subTest(namespace=kind):
                    current = proc / "17" / "ns" / kind
                    previous = os.readlink(current)
                    current.unlink()
                    current.symlink_to(f"{kind}:[99]")
                    result = read()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("stat\n", result.stdout)
                    self.assertEqual(result.stderr, "")
                    current.unlink()
                    current.symlink_to(previous)
            (proc / "17" / "cgroup").write_text("0::/parent/foreign\n")
            result = read()
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("mountinfo\n", result.stdout)
            self.assertEqual(result.stderr, "")

    def test_device_body_diagnostics_are_bounded_private_and_non_admitting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  fields='host_path_mention=absent destination_path_mention=present errno_phrase=enoent namespace=unknown source_presence=unknown source_type=unknown'
  echo "DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG: control=device $fields" >&2
  echo "DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG: control=device $fields" >&2
  echo "DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG: control=device-same-path $fields" >&2
  echo "DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG: control=protected-secret $fields" >&2
  echo "DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG: control=device $fields raw=protected-secret" >&2
  echo 'DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG: control=device host_path_mention=present destination_path_mention=present errno_phrase=protected-secret namespace=unknown source_presence=unknown source_type=unknown' >&2
  echo 'DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG: control=device host_path_mention=present destination_path_mention=present errno_phrase=enoent namespace=daemon source_presence=present source_type=character' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=device-same-path phase=start outcome=started' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=device-same-path status=204' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_START_STATE: control=device-same-path state=running' >&2
  echo "DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=decision outcome=$TEST_FLOW_DECISION" >&2
  echo 'DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=resources_security checkpoint=probe outcome=unknown' >&2
  echo 'DOCKERLENS_NATIVE_GROUP_FAILURE: group=resources_security reason=probe' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for decision in ("probe_failed", "cleanup_unverified"):
                with self.subTest(decision=decision):
                    env["TEST_FLOW_DECISION"] = decision
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                         "live_container_settings_match_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stderr.count("DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG:"), 2)
                    for control in ("device", "device-same-path"):
                        self.assertIn(f"DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG: control={control} ", result.stderr)
                    self.assertIn("control=device-same-path status=204", result.stderr)
                    self.assertIn("control=device-same-path state=running", result.stderr)
                    self.assertIn(f"phase=decision outcome={decision}", result.stderr)
                    self.assertIn("group=resources_security reason=probe", result.stderr)
                    self.assertNotIn("namespace=daemon", result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)
                    self.assertNotIn("required native test passed", result.stdout + result.stderr)

    def _run_first_failure_fixture(self, records: list[str], exit_status: int = 101):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self._tool(root, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  cat "$TEST_FIRST_FAILURE_CAPTURE"
  if [[ $TEST_FIRST_FAILURE_EXIT == 0 ]]; then
    echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
  else
    echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  fi
  exit "$TEST_FIRST_FAILURE_EXIT"
fi
""")
        capture = root / "private-capture"
        capture.write_text("\n".join(records) + "\n")
        env = os.environ.copy()
        env.update(PATH=f"{root}:{env['PATH']}", TEST_FIRST_FAILURE_CAPTURE=str(capture),
                   TEST_FIRST_FAILURE_EXIT=str(exit_status))
        return subprocess.run(
            [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
             "live_container_settings_match_engine"],
            env=env, capture_output=True, text=True, timeout=10, check=False,
        )

    def test_first_failure_original_resource_start_survives_controls_and_port_timeout(self) -> None:
        original = "DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=oracle status=400 category=invalid_request"
        resource = "DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=resources_security checkpoint=resource_oracle_start outcome=http_status"
        port = "DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=ports checkpoint=api outcome=timeout"
        result = self._run_first_failure_fixture([
            original,
            "thread 'protected-first-name' panicked at src/native_container_tests.rs:73:4:",
            "protected-original-body and private/native-path",
            "DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=memory status=500",
            "DOCKERLENS_NATIVE_API_DIAG: operation=start status=server",
            "DOCKERLENS_NATIVE_GROUP_CLEANUP: group=resources_security outcome=verified",
            resource,
            "DOCKERLENS_NATIVE_GROUP_FAILURE: group=resources_security reason=probe",
            "DOCKERLENS_NATIVE_API_DIAG: transport=timeout",
            "thread 'protected-later-name' panicked at src/native_container_tests.rs:900:5:",
            port,
            "DOCKERLENS_NATIVE_GROUP_FAILURE: group=ports reason=mutation_uncertain",
            "thread 'protected-aggregate-name' panicked at src/native_container_tests.rs:999:6:",
        ])
        self.assertNotEqual(result.returncode, 0)
        for record in (original, resource, port):
            self.assertEqual(result.stderr.count(record), 1)
        self.assertLess(result.stderr.index(resource), result.stderr.index(port))
        self.assertIn("observation=last transport=timeout", result.stderr)
        self.assertIn("control=memory status=500", result.stderr)
        self.assertIn("source=native_container_tests line=73 column=4", result.stderr)
        self.assertNotIn("line=900", result.stderr)
        self.assertNotIn("line=999", result.stderr)
        self.assertNotIn("protected-", result.stdout + result.stderr)
        self.assertNotIn("private/native-path", result.stdout + result.stderr)

    def test_first_failure_two_groups_keep_unknown_context_and_cleanup_failure(self) -> None:
        first = "DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=resources_security checkpoint=probe outcome=unknown"
        for checkpoint, reason in (("probe", "probe"), ("cleanup", "cleanup_unverified")):
            second = f"DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=ports checkpoint={checkpoint} outcome=unknown"
            with self.subTest(reason=reason):
                result = self._run_first_failure_fixture([
                    "thread 'protected-name' panicked at src/native_container_tests.rs:91:2:",
                    first,
                    "DOCKERLENS_NATIVE_GROUP_FAILURE: group=resources_security reason=probe",
                    second,
                    f"DOCKERLENS_NATIVE_GROUP_FAILURE: group=ports reason={reason}",
                ])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr.count("DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE:"), 2)
                self.assertIn(second, result.stderr)
                self.assertIn(f"group=ports reason={reason}", result.stderr)
                self.assertIn("source=native_container_tests line=91 column=2", result.stderr)
                self.assertNotIn("protected-name", result.stdout + result.stderr)

    def test_first_failure_timeout_unknown_and_success_emit_no_inferred_cause(self) -> None:
        for checkpoint, outcome in (("api", "timeout"), ("cli", "timeout"), ("cli", "unknown"),
                                    ("probe", "unknown"), ("preflight", "unknown")):
            record = f"DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=ports checkpoint={checkpoint} outcome={outcome}"
            reason = "preflight" if checkpoint == "preflight" else "probe"
            with self.subTest(checkpoint=checkpoint, outcome=outcome):
                result = self._run_first_failure_fixture([
                    record, f"DOCKERLENS_NATIVE_GROUP_FAILURE: group=ports reason={reason}",
                ])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(record, result.stderr)
                self.assertNotIn("cause=", result.stderr)
        success = self._run_first_failure_fixture([
            "DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=oracle status=204 category=success",
            "protected-private-success-output",
        ], exit_status=0)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(success.stderr, "")
        self.assertNotIn("RESOURCE_START_HTTP", success.stdout)
        self.assertNotIn("FIRST_FAILURE", success.stdout)
        self.assertNotIn("protected-", success.stdout)

    def test_first_failure_records_reject_malformed_forged_duplicate_and_private_fields(self) -> None:
        original = "DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=oracle status=500 category=server"
        first = "DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=resources_security checkpoint=resource_oracle_start outcome=http_status"
        failed = "DOCKERLENS_NATIVE_GROUP_FAILURE: group=resources_security reason=probe"
        good = [original, first, failed]
        cases = [
            [*good, first], [*good, original], [*good, failed],
            [original, first + " raw=protected-secret", failed],
            [original, first + "\rprotected-secret", failed],
            [original, first + "\x00protected-secret", failed],
            [original, first.replace("resources_security", "protected-secret"), failed],
            [original, first.replace("http_status", "protected-secret"), failed],
            [original, first.replace("resource_oracle_start", "protected-secret"), failed],
            [original, " " + first, failed],
            [original, first.replace("FIRST_FAILURE:", "FIRST_FAILURE"), failed],
            [original + " raw=protected-secret", first, failed],
            [original.replace("status=500", "status=600"), first, failed],
            [original.replace("category=server", "category=success"), first, failed],
            [original.replace("control=oracle", "control=oracle-protected-secret"), first, failed],
            [original, first, failed.replace("resources_security", "ports")],
            [original, first, failed.replace("reason=probe", "reason=protected-secret")],
            [original, first], [first, failed], [original, failed],
            [first, original, failed], [original, failed, first],
            [original, first.replace("resources_security", "ports"),
             failed.replace("resources_security", "ports")],
            [original, first.replace("resource_oracle_start", "probe").replace("http_status", "unknown"), failed],
            ["DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=ports checkpoint=api outcome=server",
             "DOCKERLENS_NATIVE_GROUP_FAILURE: group=ports reason=probe"],
            ["DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=ports checkpoint=cleanup outcome=unknown",
             "DOCKERLENS_NATIVE_GROUP_FAILURE: group=ports reason=probe"],
            ["DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=ports checkpoint=preflight outcome=unknown",
             "DOCKERLENS_NATIVE_GROUP_FAILURE: group=ports reason=probe"],
            ["DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=ports checkpoint=probe outcome=unknown",
             "DOCKERLENS_NATIVE_GROUP_FAILURE: group=ports reason=probe", *good],
        ]
        for index, records in enumerate(cases):
            with self.subTest(case=index):
                result = self._run_first_failure_fixture(records)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr.strip(), "required native test rejected malformed first-failure diagnostics")
                self.assertNotIn("protected-secret", result.stdout + result.stderr)
                self.assertNotIn("required native test passed", result.stdout + result.stderr)
        for records in (good, [original.replace("status=500", "status=204").replace("server", "success"), first, failed]):
            success_forgery = self._run_first_failure_fixture(records, exit_status=0)
            self.assertNotEqual(success_forgery.returncode, 0)
            self.assertNotIn("required native test passed", success_forgery.stdout)
        unknown = self._run_first_failure_fixture([
            original.replace("status=500 category=server", "status=unknown category=unknown"), first,
            failed.replace("reason=probe", "reason=mutation_uncertain"),
        ])
        self.assertNotEqual(unknown.returncode, 0)
        self.assertIn("control=oracle status=unknown category=unknown", unknown.stderr)
        self.assertNotIn("rejected malformed", unknown.stderr)

    def test_first_failure_group_records_require_checkpoints_even_when_new_records_absent(self) -> None:
        failed = "DOCKERLENS_NATIVE_GROUP_FAILURE: group=ports reason=probe"
        first = "DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=ports checkpoint=probe outcome=unknown"
        for records, exit_status in (([failed], 101), ([failed, failed], 101),
                                     ([failed], 0), ([first, failed], 0),
                                     ([failed + " raw=protected-secret"], 101),
                                     ([failed.replace("GROUP_FAILURE:", "GROUP_FAILURE")], 0),
                                     ([failed.replace("ports", "protected-secret")], 101)):
            with self.subTest(records=records, exit_status=exit_status):
                result = self._run_first_failure_fixture(records, exit_status=exit_status)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr.strip(), "required native test rejected malformed first-failure diagnostics")
                self.assertNotIn("required native test passed", result.stdout)
                self.assertNotIn("protected-secret", result.stdout + result.stderr)
        for exit_status in (101, 124):
            abrupt = self._run_first_failure_fixture(["protected-private-compiler-or-abrupt-failure"],
                                                     exit_status=exit_status)
            self.assertNotEqual(abrupt.returncode, 0)
            self.assertNotIn("rejected malformed", abrupt.stderr)
            self.assertNotIn("protected-private", abrupt.stdout + abrupt.stderr)

    def test_first_failure_successful_resource_start_is_supplemental_to_later_group_failure(self) -> None:
        original = "DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=oracle status=204 category=success"
        port = "DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=ports checkpoint=api outcome=timeout"
        result = self._run_first_failure_fixture([
            original, "DOCKERLENS_NATIVE_API_DIAG: transport=timeout", port,
            "DOCKERLENS_NATIVE_GROUP_FAILURE: group=ports reason=mutation_uncertain",
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(original, result.stderr)
        self.assertIn(port, result.stderr)
        self.assertIn("observation=last transport=timeout", result.stderr)
        self.assertNotIn("rejected malformed", result.stderr)

    def test_first_failure_source_captures_resource_status_before_controls_and_cleanup(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text()
        oracle = source.split("fn probe_resources_and_security(", 1)[1].split(
            "let mut container = bare_container", 1
        )[0]
        capture = oracle.index("resource_oracle_start_diagnostic(oracle_start_status)")
        store_match = re.search(r'run\.first_failure\s*\.record\(\s*"resource_oracle_start",\s*"http_status"\)', oracle)
        self.assertIsNotNone(store_match)
        store = store_match.start()
        self.assertLess(capture, oracle.index("resource_start_control_matrix(run)"))
        self.assertLess(store, oracle.index("resource_start_control_matrix(run)"))
        self.assertLess(store, oracle.index("assert_native_api_status("))
        first = source.split("impl FirstGroupFailure", 1)[1].split("fn resource_oracle_start_diagnostic", 1)[0]
        self.assertIn("if self.checkpoint.get().is_none()", first)
        group = source.split("fn live_container_settings_match_engine()", 1)[1].split("type GroupProbe", 1)[0]
        self.assertLess(group.index('run.first_failure.record("probe", "unknown")'), group.index("run.cleanup_verified(name)"))
        self.assertIn("if decision != GroupDecision::Merge", group)
        self.assertIn('GroupDecision::Merge => evidence.merge(group_evidence)', group)

    def test_group_failures_are_closed_bounded_and_do_not_print_panic_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  for group in resources_security ports identity_health_clear storage_lifecycle resolver_logging; do
    echo "DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=$group checkpoint=probe outcome=unknown" >&2
    echo "DOCKERLENS_NATIVE_GROUP_FAILURE: group=$group reason=probe" >&2
  done
  echo 'thread protected-secret panicked at secret path and value' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr.count("DOCKERLENS_NATIVE_GROUP_FAILURE:"), 5)
            self.assertNotIn("protected-secret", result.stdout + result.stderr)
            self.assertNotIn("secret path", result.stdout + result.stderr)

    def test_resource_start_diagnostics_allow_only_closed_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=memory phase=start outcome=rejected' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=memory status=500' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_START_STATE: control=memory state=created' >&2
  echo 'DOCKERLENS_NATIVE_ORACLE_START_STATE: state=created' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=protected-secret phase=start outcome=rejected' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=memory status=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=memory status=500 raw=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_START_STATE: control=memory state=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_ORACLE_START_STATE: state=protected-secret' >&2
  echo 'protected-secret raw Engine response' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            for marker in (
                "DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=memory phase=start outcome=rejected",
                "DOCKERLENS_NATIVE_RESOURCE_START_HTTP: control=memory status=500",
                "DOCKERLENS_NATIVE_RESOURCE_START_STATE: control=memory state=created",
                "DOCKERLENS_NATIVE_ORACLE_START_STATE: state=created",
            ):
                self.assertEqual(result.stderr.count(marker), 1)
            self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_start_timeout_and_cleanup_diagnostics_are_closed_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'DOCKERLENS_NATIVE_START_TIMEOUT_DIAG: state=running reason=none' >&2
  echo 'DOCKERLENS_NATIVE_START_TIMEOUT_DIAG: state=unavailable reason=transport' >&2
  echo 'DOCKERLENS_NATIVE_START_TIMEOUT_DIAG: state=protected-secret reason=transport' >&2
  echo 'DOCKERLENS_NATIVE_START_TIMEOUT_DIAG: state=running reason=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_START_TIMEOUT_DIAG: state=running reason=transport' >&2
  echo 'DOCKERLENS_NATIVE_START_TIMEOUT_DIAG: state=unavailable reason=transport raw=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_CLEANUP_STEP: step=tracked_delete outcome=begin' >&2
  echo 'DOCKERLENS_NATIVE_CLEANUP_STEP: step=delete_inspect outcome=begin' >&2
  echo 'DOCKERLENS_NATIVE_CLEANUP_STEP: step=delete_request outcome=begin' >&2
  for ((i=0; i<40; i++)); do
    echo 'DOCKERLENS_NATIVE_CLEANUP_STEP: step=container_name_list outcome=begin' >&2
  done
  echo 'DOCKERLENS_NATIVE_CLEANUP_STEP: step=readback_stable outcome=begin' >&2
  echo 'DOCKERLENS_NATIVE_CLEANUP_STEP: step=protected-secret outcome=begin' >&2
  echo 'DOCKERLENS_NATIVE_CLEANUP_STEP: step=readback_stable outcome=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_CLEANUP_STEP: step=readback_stable outcome=begin raw=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_GROUP_CLEANUP: group=ports outcome=begin' >&2
  echo 'DOCKERLENS_NATIVE_CLEANUP_READBACK: group=ports phase=first containers=nonzero images=zero' >&2
  echo 'DOCKERLENS_NATIVE_GROUP_CLEANUP: group=ports outcome=unverified' >&2
  echo 'DOCKERLENS_NATIVE_GROUP_CLEANUP: group=protected-secret outcome=verified' >&2
  echo 'DOCKERLENS_NATIVE_CLEANUP_READBACK: group=ports phase=first containers=protected-secret images=zero' >&2
  echo 'DOCKERLENS_NATIVE_CLEANUP_READBACK: group=ports phase=first containers=nonzero images=zero raw=protected-secret' >&2
  echo 'protected-secret raw Engine response' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DOCKERLENS_NATIVE_START_TIMEOUT_DIAG: state=unavailable reason=transport", result.stderr)
            self.assertIn("DOCKERLENS_NATIVE_CLEANUP_STEP: step=readback_stable outcome=begin", result.stderr)
            self.assertIn(
                "DOCKERLENS_NATIVE_CLEANUP_READBACK: group=ports phase=first containers=nonzero images=zero",
                result.stderr,
            )
            self.assertIn("DOCKERLENS_NATIVE_GROUP_CLEANUP: group=ports outcome=unverified", result.stderr)
            self.assertEqual(result.stderr.count("DOCKERLENS_NATIVE_CLEANUP_STEP:"), 32)
            self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_resource_controls_resolver_subphases_and_cleanup_flow_are_closed(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text(encoding="utf-8")
        self.assertIn("if oracle_start_status != 204 {", source)
        self.assertIn("resource_start_control_matrix(run);", source)
        self.assertLess(source.index("resource_start_control_matrix(run);"),
                        source.index("assert_native_api_status(NativeApiOperation::Start, oracle_start_status, 204);"))
        self.assertIn('resource_control_may_continue(uncertain, resource_control_seconds_remaining())', source)
        self.assertLess(source.index('("resources_security", probe_resources_security_group)'),
                        source.index('("ports", probe_port_group)'))
        self.assertIn('const RESOURCE_START_CONTROLS: [&str; 5]', source)
        self.assertIn('"memory" => Some(&["--memory=67108864"])', source)
        self.assertIn('"pids" => Some(&["--pids-limit=32"])', source)
        self.assertIn('"device" => Some(&["--device=/dev/null:/dev/native-null:r"])', source)
        self.assertIn('"device-same-path" => Some(&["--device=/dev/null:/dev/null:r"])', source)
        self.assertNotIn('"--memory=67108864", "--pids-limit=32"', source)
        self.assertIn('self.cli_with_timeout(&args, "10")', source)
        self.assertIn('mark_container_flow("cleanup_readback",', source)
        runner = (ROOT / "scripts/run-exact-native-test.sh").read_text(encoding="utf-8")
        self.assertIn('control=(baseline|memory|pids|device|device-same-path)', runner)
        self.assertIn('"$capture_path" | tail -n 35', runner)
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'DOCKERLENS_NATIVE_CHECK: container_resolver_logging_ipv6_rendered_hosts' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: container_resolver_logging_ipv6_rendered_private' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=baseline phase=start outcome=started' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=memory phase=start outcome=started' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=pids phase=start outcome=uncertain' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=device phase=start outcome=timeout' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=resource phase=start outcome=started' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=private phase=start outcome=started' >&2
  echo 'DOCKERLENS_NATIVE_RESOURCE_CONTROL: control=device phase=start outcome=started raw=protected-secret' >&2
  echo 'DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=mutation outcome=timeout' >&2
  echo 'DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=cleanup_tracked outcome=begin' >&2
  echo 'DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=cleanup_tracked outcome=pass' >&2
  echo 'DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=cleanup_inventory outcome=begin' >&2
  echo 'DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=cleanup_inventory outcome=pass' >&2
  echo 'DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=cleanup_readback outcome=begin' >&2
  echo 'DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=cleanup_readback outcome=pass' >&2
  echo "DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=decision outcome=$TEST_FLOW_DECISION" >&2
  echo 'DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=decision outcome=pass' >&2
  echo 'DOCKERLENS_NATIVE_CONTAINER_FLOW: phase=cleanup_private outcome=pass' >&2
  echo 'DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=ports checkpoint=probe outcome=unknown' >&2
  echo "DOCKERLENS_NATIVE_GROUP_FAILURE: group=ports reason=$TEST_GROUP_REASON" >&2
  echo 'protected-secret raw native output' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 101
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for decision, reason in (("mutation_uncertain", "mutation_uncertain"),
                                     ("probe_failed", "probe")):
                with self.subTest(decision=decision):
                    env["TEST_FLOW_DECISION"] = decision
                    env["TEST_GROUP_REASON"] = reason
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                         "live_container_settings_match_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("container_resolver_logging_ipv6_rendered_hosts", result.stderr)
                    self.assertIn("control=memory phase=start outcome=started", result.stderr)
                    self.assertIn("control=pids phase=start outcome=uncertain", result.stderr)
                    self.assertIn("control=device phase=start outcome=timeout", result.stderr)
                    self.assertNotIn("control=resource phase=start", result.stderr)
                    self.assertIn("phase=mutation outcome=timeout", result.stderr)
                    self.assertIn("phase=cleanup_readback outcome=pass", result.stderr)
                    self.assertIn(f"phase=decision outcome={decision}", result.stderr)
                    self.assertNotIn("phase=decision outcome=pass", result.stderr)
                    self.assertIn(f"group=ports reason={reason}", result.stderr)
                    self.assertEqual(result.stderr.count("DOCKERLENS_NATIVE_CONTAINER_FLOW:"), 8)
                    self.assertNotIn("private", result.stdout + result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_ipv6_probe_name_and_repeated_ipv4_oracle_are_live_and_bounded(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text(encoding="utf-8")
        self.assertIn("byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'", source)
        self.assertIn('assert!(valid_container_suffix("ipv6-oracle"));', source)
        oracle_start = source.index('mark_port_stage("port-oracle", "oracle_start");')
        oracle_primary = source.index('assert_fixed_ipv4_http(run, &oracle_id, "port-oracle", false);')
        oracle_secondary = source.index('assert_fixed_ipv4_http(run, &oracle_id, "port-oracle", true);')
        oracle_cleanup = source.index('mark_port_stage("port-oracle", "oracle_cleanup");')
        rendered_start = source.index('mark_port_stage("port-rendered", "api_start");')
        self.assertLess(oracle_start, oracle_primary)
        self.assertLess(oracle_primary, oracle_secondary)
        self.assertLess(oracle_secondary, oracle_cleanup)
        self.assertLess(oracle_cleanup, rendered_start)
        self.assertIn('for attempt in 1 2 3 4 5;', source)
        self.assertIn('wget -qO- -T 2', source)
        self.assertIn('assert_fixed_ipv4_http(run, &id, "port-rendered", true);', source)

    def test_port_probes_use_outer_namespace_without_new_probe_containers(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text(encoding="utf-8")
        port_source = source.split("fn probe_ports(", 1)[1].split("fn probe_complementary_ports(", 1)[0]
        self.assertNotIn('"--network".into(),', port_source)
        self.assertIn('run.namespace_probe("tcp_refusal", None)', port_source)
        self.assertIn('isolated.status.success() && isolation_result == "refused"', port_source)
        self.assertIn('run.require_outer_identity();', port_source)
        self.assertIn('run.require_outer_curl();', port_source)
        self.assertIn('run.require_outer_bash();', port_source)
        self.assertIn('run.namespace_probe("udp", Some(&assigned))', port_source)
        self.assertIn('let assigned: u16 = assigned.parse()', port_source)
        self.assertIn('assert!(assigned > 0);', port_source)
        helper = (ROOT / "scripts/native-net-probe.py").read_text(encoding="utf-8")
        self.assertRegex(helper, r'"--noproxy",\s*"\*",\s*"--proxy",\s*""')
        self.assertRegex(helper, r'"--connect-timeout",\s*"2",\s*"--max-time",\s*"3"')
        self.assertIn('pass_fds=(net_fd,)', helper)
        self.assertIn('f"--net=/proc/self/fd/{net_fd}"', helper)

    def test_api_and_resolver_logs_failure_labels_are_closed(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text(encoding="utf-8")
        self.assertIn('DOCKERLENS_NATIVE_API_DIAG: operation={} status={}', source)
        self.assertIn('DOCKERLENS_NATIVE_RESOLVER_LOGS_DIAG: operation=logs outcome=cli_failure', source)
        self.assertIn('mark_ipv4_log_canary(side, canary_present);', source)
        self.assertIn('log_canary_ready(|| run.cli_with_timeout(&["logs".into(), id.into()], "3"))', source)
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'DOCKERLENS_NATIVE_API_DIAG: operation=inspect status=not_found' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: container_resolver_logging_ipv4_oracle_logs' >&2
  echo 'DOCKERLENS_NATIVE_RESOLVER_LOGS_DIAG: operation=logs outcome=cli_failure' >&2
  echo 'DOCKERLENS_NATIVE_RESOLVER_LOG_CANARY: side=oracle outcome=missing' >&2
  echo 'DOCKERLENS_NATIVE_RESOLVER_LOG_CANARY: side=private outcome=missing' >&2
  echo 'DOCKERLENS_NATIVE_RESOLVER_LOGS_DIAG: operation=private outcome=cli_failure' >&2
  echo 'DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE: group=resolver_logging checkpoint=cli outcome=unknown' >&2
  echo 'DOCKERLENS_NATIVE_GROUP_FAILURE: group=resolver_logging reason=probe' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: container_resolver_logging_local_rendered_create' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "DOCKERLENS_NATIVE_API_DIAG: observation=last operation=inspect status=not_found",
                result.stderr,
            )
            self.assertIn(
                "DOCKERLENS_NATIVE_RESOLVER_LOGS_DIAG: operation=logs outcome=cli_failure",
                result.stderr,
            )
            self.assertIn(
                "DOCKERLENS_NATIVE_RESOLVER_LOG_CANARY: side=oracle outcome=missing",
                result.stderr,
            )
            self.assertIn("DOCKERLENS_NATIVE_GROUP_FAILURE: group=resolver_logging reason=probe", result.stderr)
            self.assertNotIn("private", result.stdout + result.stderr)

    def test_container_http_and_health_diagnostics_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo 'DOCKERLENS_NATIVE_CHECK: container_health_disabled_rendered_wait'
  echo 'DOCKERLENS_NATIVE_CHECK: container_health_disabled_private'
  echo 'DOCKERLENS_NATIVE_HTTP_DIAG: exit=other category=connection_refused'
  echo 'DOCKERLENS_NATIVE_HTTP_DIAG: exit=other category=private'
  echo 'DOCKERLENS_NATIVE_IPV6_DIAG: local_service=fail inner_all=enabled inner_lo=disabled outer_tcp6=bind_unavailable curl_exit=7'
  echo 'DOCKERLENS_NATIVE_IPV6_DIAG: local_service=private inner_all=enabled inner_lo=disabled outer_tcp6=bind_unavailable curl_exit=7'
  echo 'DOCKERLENS_NATIVE_ISOLATION_DIAG: result=connected'
  echo 'DOCKERLENS_NATIVE_ISOLATION_DIAG: result=private'
  echo 'DOCKERLENS_NATIVE_NAMESPACE_DIAG: category=changed'
  echo 'DOCKERLENS_NATIVE_NAMESPACE_DIAG: category=private'
  echo 'private native response' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("container_health_disabled_rendered_wait", result.stderr)
            self.assertIn("exit=other category=connection_refused", result.stderr)
            self.assertIn(
                "local_service=fail inner_all=enabled inner_lo=disabled outer_tcp6=bind_unavailable curl_exit=7",
                result.stderr,
            )
            self.assertIn("DOCKERLENS_NATIVE_ISOLATION_DIAG: result=connected", result.stderr)
            self.assertIn("DOCKERLENS_NATIVE_NAMESPACE_DIAG: category=changed", result.stderr)
            self.assertNotIn("private", result.stdout + result.stderr)

    def test_health_image_uses_run_owned_create_commit_and_closed_stage(self) -> None:
        source = (ROOT / "src/native_container_tests.rs").read_text(encoding="utf-8")
        health = source.split("fn image_with_failing_health(", 1)[1].split("\n}\n", 1)[0]
        for token in (
            '"health-default-source"', '"--health-cmd=/bin/false"',
            '"--health-interval=1s"', '"--health-timeout=1s"',
            '"--health-retries=2"', '"commit".into()',
            '"Interval", "Timeout", "Retries"',
            '"io.dockerlens.native-run"', 'self.delete(&source_id);',
        ):
            self.assertIn(token, health)
        self.assertNotIn('"build".into()', health)
        self.assertNotIn("fn cli_with_stdin", source)
        self.assertIn('dockerlens-native-{role}:r{run_id}', source)
        self.assertNotIn('format!("{}:local", self.name(', source)
        runner = (ROOT / "scripts/run-exact-native-test.sh").read_text(encoding="utf-8")
        self.assertIn("health_disabled(_(source_(create|inspect|cleanup)|image_(commit|inspect)|", runner)
        self.assertNotIn("health_disabled(_(image_build|", runner)

    def test_health_substages_and_known_cli_categories_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  echo "DOCKERLENS_NATIVE_CHECK: container_health_disabled_$TEST_STAGE"
  echo 'DOCKERLENS_NATIVE_CHECK: container_health_disabled_private'
  echo "DOCKERLENS_NATIVE_CLI_DIAG: exit=other stderr=$TEST_CATEGORY"
  echo 'DOCKERLENS_NATIVE_CLI_DIAG: exit=other stderr=protected-secret'
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for stage in ("source_create", "source_inspect", "image_commit",
                          "image_inspect", "source_cleanup"):
                for category in ("storage_exhausted", "invalid_reference",
                                 "missing_resource", "image_storage", "unknown"):
                    with self.subTest(stage=stage, category=category):
                        env["TEST_STAGE"] = stage
                        env["TEST_CATEGORY"] = category
                        result = subprocess.run(
                            [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                             "live_container_settings_match_engine"],
                            env=env, capture_output=True, text=True, timeout=15, check=False,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(f"container_health_disabled_{stage}", result.stderr)
                        self.assertIn(f"stderr={category}", result.stderr)
                        self.assertNotIn("private", result.stdout + result.stderr)
                        self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_native_test_output_limit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  if [[ $TEST_PHASE == list ]]; then
    head -c 300000 /dev/zero
  else
    echo 'native_container_tests::live_container_settings_match_engine: test'
  fi
else
  head -c 300000 /dev/zero
fi
echo 'private-canary' >&2
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for phase in ("list", "run"):
                with self.subTest(phase=phase):
                    env["TEST_PHASE"] = phase
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                         "live_container_settings_match_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("output exceeded closed byte limit", result.stderr)
                    self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_native_test_output_limit_does_not_cap_build_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            artifact = bin_dir / "fake-build-artifact"
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_container_tests::live_container_settings_match_engine: test'
else
  head -c 300000 /dev/zero > "$TEST_ARTIFACT_PATH"
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["TEST_ARTIFACT_PATH"] = str(artifact)
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_container",
                 "live_container_settings_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(artifact.stat().st_size, 300000)

    def test_network_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = '"$(dirname "$0")/run-exact-native-test.sh" native_network live_network_render_matches_engine'
        internal = '"$(dirname "$0")/run-exact-native-test.sh" native_network live_internal_network_blocks_external_egress'
        target = '"$(dirname "$0")/run-exact-native-test.sh" native_target live_target_render_matches_engine'
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertEqual(source.count(internal), 1)
        self.assertLess(source.index(target), source.index(selected))
        self.assertLess(source.index(selected), source.index(internal))
        self.assertLess(source.index(internal), source.index(manifest))
        self.assertIn('"$NATIVE_NETWORK_PROBES_PATH"', source)

    def test_internal_network_failure_marker_is_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_internal_network_blocks_external_egress: test'
else
  echo 'protected native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_internal_blocked' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_internal_private-canary' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                 "live_internal_network_blocks_external_egress"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("network_internal_blocked", result.stderr)
            self.assertNotIn("private-canary", result.stdout + result.stderr)
            self.assertNotIn("protected native response", result.stdout + result.stderr)

    def test_internal_cleanup_diagnostics_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_internal_network_blocks_external_egress: test'
else
  echo 'protected native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_internal_sidecar' >&2
  printf '%s\n' "$TEST_ENDPOINT_DIAG" "$TEST_CLEANUP_DIAG" >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for cleanup, accepted in (
                ("DOCKERLENS_NATIVE_CLEANUP: internal_proof=pass", True),
                ("DOCKERLENS_NATIVE_CLEANUP: internal_proof=fail", True),
                ("DOCKERLENS_NATIVE_CLEANUP: internal_proof=private-canary", False),
            ):
                with self.subTest(accepted=accepted):
                    env["TEST_ENDPOINT_DIAG"] = "DOCKERLENS_NATIVE_ENDPOINT_DIAG: phase=create category=host_mode_unsupported exit=other"
                    env["TEST_CLEANUP_DIAG"] = cleanup
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                         "live_internal_network_blocks_external_egress"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(cleanup in result.stderr, accepted)
                    self.assertNotIn("DOCKERLENS_NATIVE_ENDPOINT_DIAG", result.stderr)
                    self.assertNotIn("private-canary", result.stdout + result.stderr)
                    self.assertNotIn("protected native response", result.stdout + result.stderr)

    def test_network_option_value_and_label_controls_are_closed(self) -> None:
        source = (ROOT / "src/native_network_tests.rs").read_text(encoding="utf-8")
        version = (ROOT / "src/version.rs").read_text(encoding="utf-8")
        self.assertIn('"NetworkBridgeIccDisabled"', source)
        self.assertIn('"NetworkBridgeMasqueradeEnabled"', source)
        self.assertIn('"NetworkCreateLabelsValueDomain"', source)
        self.assertIn('Self::NetworkBridgeIccDisabled,', version)
        self.assertIn('Self::NetworkBridgeMasqueradeEnabled,', version)
        self.assertIn('"com.docker.network.bridge.enable_icc=false"', source)
        self.assertIn('"com.docker.network.bridge.enable_ip_masquerade=true"', source)
        self.assertIn('NetworkLabel::new(EMPTY_LABEL_KEY.as_bytes().to_vec(), Vec::new())', source)
        self.assertIn('SPECIAL_LABEL_VALUE.as_bytes().to_vec()', source)
        self.assertIn('oracle_control_body["Labels"] == expected_labels', source)
        self.assertIn('control_request["body"] == expected_option_control_body(&control, false)', source)
        self.assertIn('enabled_request["body"] == expected_option_control_body(&control_enabled, true)', source)
        self.assertIn('matched["Options"]["com.docker.network.bridge.enable_icc"] = json!("true")', source)
        self.assertIn('control_body["Labels"] == expected_labels', source)
        enabled = source.index('backend_http.as_slice()')
        disabled = source.index('ICC-disabled control must block healthy same-bridge peers')
        self.assertLess(enabled, disabled)
        self.assertIn('"http://127.0.0.1:8080/"', source[enabled:disabled])
        self.assertIn('let cross_url = format!("http://{server_ip}:8080/")', source[enabled:disabled])
        self.assertIn('let enabled_cross_url = format!("http://{enabled_server_ip}:8080/")', source[enabled:disabled])
        self.assertIn('enabled_cross_success && enabled_cross_body.as_slice() == b"control-server"', source[enabled:disabled])
        self.assertIn('!cross_success && cross_body.is_empty()', source[enabled:disabled])

    def test_network_failure_marker_is_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_network_tests::live_network_render_matches_engine: test'
else
  echo 'protected native response' >&2
  echo "DOCKERLENS_NATIVE_CHECK: network_isolation_$TEST_MARKER" >&2
  echo 'DOCKERLENS_NATIVE_CHECK: network_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            for marker in (
                "edge_fixture_exited", "edge_alias_missing", "edge_dns",
                "edge_dns_fixture_exited", "edge_dns_readiness_exhausted",
                "edge_dns_output_limit",
                "edge_dns_cli_timeout", "edge_dns_cli_resolver", "edge_dns_cli_lookup",
                "edge_dns_cli_docker", "edge_dns_cli_exec",
                "edge_dns_cli_answer_present", "edge_dns_cli_unclassified",
                "edge_dns_answer_missing", "edge_dns_answer_wrong_ip",
                "edge_dns_answer_malformed", "edge_dns_answer_inconsistent",
                "edge_dns_alias_missing", "edge_http", "backend_alias_missing",
                "local_dns", "local_http", "collision_dns", "collision_http",
                "foreign_route", "cleanup_unverified",
            ):
                with self.subTest(marker=marker):
                    env["TEST_MARKER"] = marker
                    result = subprocess.run(
                        [str(ROOT / "scripts/run-exact-native-test.sh"), "native_network",
                         "live_network_render_matches_engine"],
                        env=env, capture_output=True, text=True, timeout=15, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"DOCKERLENS_NATIVE_CHECK: network_isolation_{marker}",
                                  result.stderr)
                    self.assertNotIn("private", result.stdout + result.stderr)

    def test_source_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = '"$(dirname "$0")/run-exact-native-test.sh" native_selection live_native_selection_and_source_observations'
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertLess(source.index(selected), source.index(manifest))
        self.assertIn('"$NATIVE_SOURCE_PROBES_PATH"', source)
        self.assertIn('io.dockerlens.fixture=decoy', source)

    def test_membership_probe_follows_source_and_precedes_manifest(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        baseline = 'native_selection live_native_selection_and_source_observations'
        membership = ('"$(dirname "$0")/run-exact-native-test.sh" native_selection '
                      'live_network_membership_matches_engine')
        self.assertEqual(source.count(membership), 1)
        self.assertLess(source.index(baseline), source.index(membership))
        self.assertLess(source.index(membership), source.index('python3 "$script_dir/native-evidence.py"'))

    def test_membership_failure_markers_remain_closed_and_private(self) -> None:
        for marker in ("source_network_membership", "membership_cleanup_unverified"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                bin_dir = Path(directory)
                self._tool(bin_dir, "cargo", f'''#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'live_network_membership_matches_engine: test'
else
  echo 'private native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: {marker}' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: membership_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
''')
                env = os.environ.copy()
                env["PATH"] = f"{bin_dir}:{env['PATH']}"
                result = subprocess.run(
                    [str(ROOT / "scripts/run-exact-native-test.sh"), "native_selection",
                     "live_network_membership_matches_engine"],
                    env=env, capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: {marker}", result.stderr)
                self.assertNotIn("private", result.stdout + result.stderr)

    def test_existing_volume_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = ('"$(dirname "$0")/run-exact-native-test.sh" native_volume '
                    'live_existing_volume_prerequisite_matches_engine')
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertLess(source.index(selected), source.index(manifest))
        self.assertIn('export NATIVE_VOLUME_PROBES_PATH="$run_dir/volume-probes.json"', source)
        self.assertIn('"$NATIVE_VOLUME_PROBES_PATH"', source)

    def test_created_volume_label_probe_is_exact_and_precedes_manifest_emission(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        selected = ('"$(dirname "$0")/run-exact-native-test.sh" native_volume_label '
                    'live_created_volume_labels_match_engine')
        manifest = 'python3 "$script_dir/native-evidence.py"'
        self.assertEqual(source.count(selected), 1)
        self.assertLess(source.index(selected), source.index(manifest))
        self.assertIn('export NATIVE_VOLUME_LABEL_PROBES_PATH="$run_dir/volume-label-probes.json"', source)
        self.assertIn('"$NATIVE_VOLUME_LABEL_PROBES_PATH"', source)

    def test_volume_label_failure_markers_remain_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_volume_label_tests::live_created_volume_labels_match_engine: test'
else
  echo 'private native volume label response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_labels_create' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_labels_private' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_labels_cleanup_unverified' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_volume_label",
                 "live_created_volume_labels_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DOCKERLENS_NATIVE_CHECK: volume_labels_cleanup_unverified", result.stderr)
            self.assertNotIn("private", result.stdout + result.stderr)

    def test_volume_failure_markers_remain_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'native_volume_tests::live_existing_volume_prerequisite_matches_engine: test'
else
  echo 'private native volume response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_missing_precheck' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_private' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: volume_cleanup_unverified' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_volume",
                 "live_existing_volume_prerequisite_matches_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DOCKERLENS_NATIVE_CHECK: volume_cleanup_unverified", result.stderr)
            self.assertNotIn("private", result.stdout + result.stderr)

    def test_source_failure_markers_remain_closed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo 'live_native_selection_and_source_observations: test'
else
  echo 'private native response' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: source_multiple_bindings' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: source_private' >&2
  echo 'DOCKERLENS_NATIVE_ERROR: selection' >&2
  echo 'DOCKERLENS_NATIVE_ERROR: private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 23
fi
""")
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_selection",
                 "live_native_selection_and_source_observations"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DOCKERLENS_NATIVE_CHECK: source_multiple_bindings", result.stderr)
            self.assertIn("DOCKERLENS_NATIVE_ERROR: selection", result.stderr)
            self.assertNotIn("private", result.stdout + result.stderr)

    def test_effective_storage_check_fails_closed_before_native_work(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        block = source.split("\n\napi_get() {", 1)[0].rsplit(
            "\nif [[ $lane == debian11-rootless ]]; then", 1
        )[1]
        block = "if [[ $lane == debian11-rootless ]]; then" + block
        destination = "/home/docker/.local/share/docker"
        valid = f"18 7 0:42 /private-source {destination} rw - ext4 /private-device rw"
        for lane, mountinfo, status, admitted in (
            ("debian11-rootless", valid, 0, True),
            ("debian11-rootless", valid.replace(" rw -", " rw,nosuid,nodev -"), 0, False),
            ("debian11-rootless", valid, 42, False),
            ("debian11-rootless", "", 0, False),
            ("upstream-rootless", "", 42, True),
        ):
            with self.subTest(lane=lane, mountinfo=mountinfo, status=status):
                env = os.environ.copy()
                env.update(lane=lane, script_dir=str(ROOT / "scripts"),
                           TEST_MOUNTINFO=mountinfo, TEST_STATUS=str(status))
                result = subprocess.run(
                    ["bash", "-c", "set -euo pipefail\n"
                     "timeout() { printf '%s\\n' \"$TEST_MOUNTINFO\"; "
                     "echo protected-secret >&2; return \"$TEST_STATUS\"; }\n"
                     "podman_cmd=(unused)\ncontainer=synthetic\n" + block
                     + "\nprintf 'native-work-admitted'\n"],
                    env=env, capture_output=True, text=True, timeout=5, check=False,
                )
                self.assertEqual(result.returncode == 0, admitted, result.stderr)
                self.assertEqual("native-work-admitted" in result.stdout, admitted)
                self.assertNotIn("protected-secret", result.stdout + result.stderr)
                self.assertNotIn("private-source", result.stdout + result.stderr)

    def test_storage_sampling_resamples_only_transient_descendant_loss(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        sampler = "sample_storage_kib() {" + source.split("sample_storage_kib() {", 1)[1].split(
            "\nmain_pid=$$", 1
        )[0]
        self.assertIn('ulimit -f 4; LC_ALL=C timeout --kill-after=1 10 "${du_cmd[@]}"', sampler)
        self.assertIn('timeout --kill-after=1 10 "${df_cmd[@]}" -Pk -- "$graph_root"', sampler)
        self.assertIn('timeout --kill-after=1 10 "${stat_cmd[@]}" -c', sampler)
        self.assertIn('stat_cmd=(sudo -n stat)', source)
        bash = """set -euo pipefail
volume_path=$TEST_VOLUME_PATH
run_dir=$TEST_RUN_DIR
graph_root=$run_dir
storage_root_identity='directory|1:1'
stat_cmd=(stat)
timeout() { shift 2; "$@"; }
sudo() { shift; "$@"; }
stat() {
  [[ -d $volume_path ]] || return 1
  if [[ $TEST_STORAGE_CASE == identity_change ]]; then printf 'directory|1:2'; else printf 'directory|1:1'; fi
}
df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\\nmock 9000000 0 8000000 0%% /\\n'; }
du() {
  mock_calls=$(<"$TEST_COUNT_FILE")
  mock_calls=$((mock_calls + 1))
  printf '%s' "$mock_calls" >"$TEST_COUNT_FILE"
  case $TEST_STORAGE_CASE in
    transient) if (( mock_calls == 1 )); then printf "du: cannot access '%s/vanished': No such file or directory\\n" "$volume_path" >&2; return 1; fi ;;
    unterminated) if (( mock_calls == 1 )); then printf "du: cannot access '%s/vanished': No such file or directory" "$volume_path" >&2; return 1; fi ;;
    persistent) printf "du: cannot access '%s/vanished': No such file or directory\\n" "$volume_path" >&2; return 1 ;;
    root_loss) rmdir "$volume_path"; printf "du: cannot access '%s': No such file or directory\\n" "$volume_path" >&2; return 1 ;;
    permission) printf "du: cannot read directory '%s/private': Permission denied\\n" "$volume_path" >&2; return 1 ;;
    stderr_overflow) head -c 100000 /dev/zero >&2; return 1 ;;
    timeout) return 124 ;;
    malformed) printf 'not-a-total\\t%s\\n' "$volume_path"; return 0 ;;
    large) printf '5000000\\t%s\\n' "$volume_path"; return 0 ;;
  esac
  printf '100\\t%s\\n' "$volume_path"
}
""" + sampler + """
if sample_storage_kib; then printf 'admitted:%s\\n' "$SAMPLED_STORAGE_KIB"; else printf 'rejected\\n'; fi
"""
        for case, admitted in (
            ("transient", True), ("unterminated", True), ("persistent", False),
            ("identity_change", False), ("root_loss", False),
            ("permission", False), ("stderr_overflow", False), ("timeout", False),
            ("malformed", False),
            ("large", False),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                volume = Path(directory) / "owned-volume"
                volume.mkdir()
                counter = Path(directory) / "du-calls"
                counter.write_text("0")
                env = os.environ.copy()
                env.update(TEST_VOLUME_PATH=str(volume), TEST_RUN_DIR=directory,
                           TEST_STORAGE_CASE=case, TEST_COUNT_FILE=str(counter))
                result = subprocess.run(
                    ["bash", "-c", bash], env=env, text=True,
                    capture_output=True, timeout=5, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "admitted:100" if admitted else "rejected")

    def test_read_only_volume_start_keeps_classified_failure_probe(self) -> None:
        source = (ROOT / "src/native_target_tests.rs").read_text(encoding="utf-8")
        start = source.split(
            'eprintln!("DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_inspected");', 1
        )[1].split(
            'eprintln!("DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_started");', 1
        )[0]
        self.assertIn("start_native_source(&volume_ro_id);", start)

    def test_synthetic_bind_fixture_is_writable_but_parent_stays_private(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
        fixture = source.split(
            "# A random directory, two containers, network, and volume belong to this lane.", 1
        )[1].split("\nwatchdog_pid=", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            env = os.environ.copy()
            env["TMPDIR"] = temporary
            result = subprocess.run(
                ["bash", "-c", "set -euo pipefail\numask 077\n" + fixture
                 + "\nprintf '%s\\n' \"$run_dir\""],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            run_dir = Path(result.stdout.strip())
            bind = run_dir / "socket/native-bind"
            self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((run_dir / "socket").stat().st_mode), 0o777)
            self.assertEqual(stat.S_IMODE(bind.stat().st_mode), 0o777)
            self.assertEqual(stat.S_IMODE((bind / "canary").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((bind / "index.html").stat().st_mode), 0o644)

    def test_runtime_package_versions_are_allowlisted(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        version_reader = "native_package_version() {" + source.split(
            "native_package_version() {", 1
        )[1].split("\necho \"DOCKERLENS_NATIVE_ENV:", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            self._tool(
                Path(temporary),
                "fake_package_query",
                "#!/bin/sh\ncase \"$*\" in *runc) printf '1.1.5+ds1-1+deb11u2' ;; "
                "*containerd) printf 'protected-secret value' ;; *) exit 1 ;; esac\n",
            )
            env = os.environ.copy()
            env["PATH"] = f"{temporary}:{env['PATH']}"
            result = subprocess.run(
                ["bash", "-c", "podman_cmd=(fake_package_query)\ncontainer=fake\n"
                 + version_reader
                 + "\nprintf '%s|%s|%s' "
                 "\"$(native_package_version runc)\" "
                 "\"$(native_package_version containerd)\" "
                 "\"$(native_package_version libseccomp2)\""],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "1.1.5+ds1-1+deb11u2|unavailable|unavailable")
            self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_probe_error_categories_never_echo_private_details(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        classifier = "classify_probe_error() {" + source.split(
            "classify_probe_error() {", 1
        )[1].split("\nexport -f classify_probe_error", 1)[0]
        cases = {
            "read init-p: connection reset by peer protected-secret": "init_pipe_eof",
            "state.json: no such file protected-secret": "runtime_state_missing",
            "invalid argument protected-secret": "invalid_argument",
            "failed to mount protected-secret": "mount",
            "cgroup protected-secret": "cgroup",
            "operation not permitted protected-secret": "permission",
            "OCI runtime create failed protected-secret": "oci",
            "protected-secret": "unclassified",
        }
        for detail, category in cases.items():
            with self.subTest(category=category):
                result = subprocess.run(
                    ["bash", "-c", classifier + "\nclassify_probe_error"],
                    input=detail,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), category)
                self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_both_inert_probe_modes_report_and_remove_exact_owned_containers(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        probe = "classify_probe_error() {" + source.split(
            "classify_probe_error() {", 1
        )[1].split("\nnetwork_id=", 1)[0]
        fake_docker = """#!/usr/bin/env bash
set -euo pipefail
state=$FAKE_PROBE_STATE
[[ $1 == container ]]
action=$2
shift 2
case $action in
  create)
    [[ $* == *'--entrypoint /bin/sh'* ]]
    [[ $* == *'-c exit 0'* ]]
    [[ $* == *'example.invalid/pinned:1@sha256:1234'* ]]
    if [[ $* == *'--network none'* ]]; then mode=none; else
      [[ $* == *'--network bridge'* ]]; mode=bridge
    fi
    touch "$state/$mode"
    printf '%s\\n' "$mode" >> "$state/created"
    if [[ $mode == "$FAKE_PROBE_CREATE_FAIL" ]]; then
      echo 'invalid argument protected-secret' >&2
      exit 42
    fi
    echo synthetic-id ;;
  start)
    mode=${1##*-}
    if [[ $mode == "$FAKE_PROBE_START_FAIL" ]]; then
      echo 'OCI runtime create failed: protected-secret' >&2
      exit 42
    fi
    echo synthetic-id ;;
  wait) echo 0 ;;
  inspect)
    mode=${*: -1}; mode=${mode##*-}
    [[ -f $state/$mode ]] || exit 1
    if [[ $* == *Config.Labels* ]]; then
      if [[ $mode == "$FAKE_PROBE_FOREIGN_LABEL" ]]; then echo foreign;
      else echo synthetic; fi
    elif [[ $* == *State.Error* ]]; then
      touch "$state/error_inspected-$mode"
      if [[ $mode == "$FAKE_PROBE_START_FAIL" ]]; then
        echo 'read init-p: connection reset by peer protected-secret'
      else echo; fi
    else echo 'exited|0'; fi ;;
  rm)
    mode=${*: -1}; mode=${mode##*-}
    [[ $mode != "$FAKE_PROBE_REMOVE_FAIL" ]] || exit 1
    rm "$state/$mode" ;;
  ls)
    if [[ $* == *probe-none* && -f $state/none ]]; then echo 'dl-synthetic-probe-none'; fi
    if [[ $* == *probe-bridge* && -f $state/bridge ]]; then echo 'dl-synthetic-probe-bridge'; fi ;;
  *) exit 2 ;;
esac
"""
        cases = (
            ("none", "", "", ""),
            ("", "bridge", "", ""),
            ("", "", "none", ""),
            ("", "", "", "bridge"),
        )
        for start_fail, remove_fail, create_fail, foreign_label in cases:
            with self.subTest(start_fail=start_fail, remove_fail=remove_fail,
                              create_fail=create_fail, foreign_label=foreign_label):
                with tempfile.TemporaryDirectory() as temporary:
                    state = Path(temporary)
                    self._tool(state, "fake_docker", fake_docker)
                    env = os.environ.copy()
                    env.update(
                        PATH=f"{state}:{env['PATH']}",
                        FAKE_PROBE_STATE=str(state),
                        FAKE_PROBE_START_FAIL=start_fail,
                        FAKE_PROBE_REMOVE_FAIL=remove_fail,
                        FAKE_PROBE_CREATE_FAIL=create_fail,
                        FAKE_PROBE_FOREIGN_LABEL=foreign_label,
                    )
                    result = subprocess.run(
                        ["bash", "-c", "set -euo pipefail\nrun_id=synthetic\n"
                         "FIXTURE_IMAGE=example.invalid/pinned:1@sha256:1234\n"
                         "inner_docker=(fake_docker)\n" + probe],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual((state / "created").read_text().splitlines(),
                                     ["none", "bridge"])
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)
                    if start_fail:
                        self.assertIn("none_start_init_pipe_eof", result.stderr)
                        self.assertIn("none_state_error_init_pipe_eof", result.stderr)
                        self.assertIn("bridge_start_ok", result.stderr)
                        self.assertFalse((state / "none").exists())
                        self.assertFalse((state / "bridge").exists())
                    elif create_fail:
                        self.assertIn("none_start_create_invalid_argument", result.stderr)
                        self.assertIn("bridge_start_ok", result.stderr)
                        self.assertFalse((state / "none").exists())
                        self.assertFalse((state / "bridge").exists())
                    elif remove_fail:
                        self.assertIn("bridge_cleanup_unverified", result.stderr)
                        self.assertFalse((state / "none").exists())
                        self.assertTrue((state / "bridge").exists())
                    else:
                        self.assertIn("bridge_cleanup_unverified", result.stderr)
                        self.assertFalse((state / "none").exists())
                        self.assertTrue((state / "bridge").exists())
                        self.assertFalse((state / "error_inspected-bridge").exists())

    def test_owned_resources_are_cleaned_after_early_failures(self) -> None:
        fake_podman = """#!/usr/bin/env bash
set -eu
state=$FAKE_NATIVE_STATE
command=$1; shift
case "$command" in
  info)
    case "$*" in
      *Rootless*) echo false ;;
      *GraphRoot*) echo "$state" ;;
      *) exit 3 ;;
    esac ;;
 container)
 if [[ $1 == exists && $FAKE_NATIVE_FAULT == container_query_error && -e $state/ran ]]; then exit 125; fi
 if [[ $1 != exists ]]; then exit 4; fi
 case $2 in
 dl-native-egress-*) [[ $FAKE_NATIVE_FAULT == sidecar_query_error && -e $state/sidecar ]] && exit 125
 [[ -e $state/sidecar ]] ;;
 *) [[ -e $state/container ]] ;;
 esac ;;
 network)
 action=$1; shift
 case $action in
 exists) [[ $FAKE_NATIVE_FAULT == network_query_error && -e $state/network ]] && exit 125
 [[ -e $state/network ]] ;;
 create) for name; do :; done
 printf '%s\n' "$name" > "$state/expected-network"
 touch "$state/network"
 [[ $FAKE_NATIVE_FAULT == network_create ]] && exit 42
 echo "$name" ;;
 inspect) for name; do :; done
 echo "$name" | sed 's/^dl-native-net-//'
 [[ $FAKE_NATIVE_FAULT == network_inspect_partial ]] && exit 42
 exit 0 ;;
 rm) for name; do :; done
 read -r expected < "$state/expected-network"
 [[ $name == "$expected" ]] || exit 66
 touch "$state/network_removal_attempted"
 [[ $FAKE_NATIVE_FAULT == network_remains ]] || rm -f "$state/network" ;;
 *) exit 4 ;;
 esac ;;
  volume)
    action=$1; shift
    case "$action" in
      exists)
        if [[ $FAKE_NATIVE_FAULT == volume_query_error && -e $state/ran ]]; then exit 125; fi
        [[ -e $state/volume ]] ;;
      create)
        for name; do :; done
        printf '%s\n' "$name" > "$state/expected-volume"
        touch "$state/volume"
        [[ $FAKE_NATIVE_FAULT == volume ]] && exit 42
        echo "$state/volume" ;;
      inspect)
        if [[ $* == *Labels* ]]; then
          for name; do :; done
          echo "$name" | sed 's/^dl-native-data-//'
          [[ $FAKE_NATIVE_FAULT == volume_inspect_partial ]] && exit 42
          true
        else echo "$state"; fi ;;
      rm)
        for name; do :; done
        read -r expected < "$state/expected-volume"
        [[ $name == "$expected" ]] || exit 66
        touch "$state/volume_removal_attempted"
        [[ $FAKE_NATIVE_FAULT == volume_remains ]] || rm -f "$state/volume" ;;
      *) exit 4 ;;
    esac ;;
  pull) [[ $FAKE_NATIVE_FAULT != pull ]] ;;
 run)
 prior=
 for item in "$@"; do
 if [[ $prior == --name ]]; then name=$item; fi
 prior=$item
 done
 if [[ $name == dl-native-egress-* ]]; then
   printf '%s\n' "$*" > "$state/sidecar-run-args"
   touch "$state/sidecar"
   if [[ $FAKE_NATIVE_FAULT == sidecar_start || $FAKE_NATIVE_FAULT == sidecar_start_classifier_failure ]]; then
     echo 'sh: syntax error private-canary' >&2
     exit 42
   fi
   if [[ $FAKE_NATIVE_FAULT == cancel_after_sidecar ]]; then sleep 2; fi
 else
   printf '%s\n' "$*" > "$state/run-args"
   printf '%s\n' "$name" > "$state/expected-container"
   touch "$state/ran" "$state/container"
   [[ $FAKE_NATIVE_FAULT == run ]] && exit 42
 fi
 exit 0 ;;
logs)
  if [[ $FAKE_NATIVE_FAULT == sidecar_exited_empty_ip ]]; then
    echo 'sh: httpd: not found private-canary' >&2
  elif [[ $FAKE_NATIVE_FAULT == sidecar_write_failed ]]; then
    echo 'DOCKERLENS_SIDECAR_STAGE: write_failed' >&2
  elif [[ $FAKE_NATIVE_FAULT == sidecar_httpd_failed ||
    $FAKE_NATIVE_FAULT == sidecar_conflicting_state_error ]]; then
    echo 'DOCKERLENS_SIDECAR_STAGE: write_ok' >&2
    echo 'DOCKERLENS_SIDECAR_HTTPD: invoked' >&2
    echo 'httpd: permission denied private-canary' >&2
    echo 'DOCKERLENS_SIDECAR_HTTPD: returned_nonzero' >&2
  elif [[ $FAKE_NATIVE_FAULT == sidecar_logs_query_error ]]; then
    echo 'DOCKERLENS_SIDECAR_STAGE: write_ok' >&2
    echo 'permission denied private-canary' >&2
    exit 42
  elif [[ $FAKE_NATIVE_FAULT == sidecar_state_error_field ]]; then
   :
 else
   echo 'private-canary' >&2
 fi ;;
 inspect)
 if [[ $* == *Labels* ]]; then
 for name; do :; done
 if [[ $name == dl-native-egress-* && $FAKE_NATIVE_FAULT == sidecar_inspect_hang ]]; then sleep 30; fi
 echo "$name" | sed -e 's/^dl-native-egress-//' -e 's/^dl-native-//'
 if [[ $name == dl-native-egress-* && $FAKE_NATIVE_FAULT == sidecar_inspect_partial ]]; then exit 42; fi
 if [[ $name == dl-native-* && $name != dl-native-egress-* && $FAKE_NATIVE_FAULT == container_inspect_partial ]]; then exit 42; fi
 elif [[ $* == *NetworkSettings.Networks* ]]; then
 for name; do :; done
 read -r network_name < "$state/expected-network"
 if [[ $name == dl-native-egress-* ]]; then ip=10.88.0.2; else ip=10.88.0.3; fi
 if [[ $name == dl-native-egress-* && $FAKE_NATIVE_FAULT == sidecar_running_empty_ip ]]; then ip=; fi
 if [[ $name == dl-native-egress-* && $FAKE_NATIVE_FAULT == sidecar_exited_empty_ip ]]; then ip=; fi
 printf '{"%s":{"IPAddress":"%s"}}\n' "$network_name" "$ip"
 elif [[ $* == *State.Running* ]]; then
 if [[ $FAKE_NATIVE_FAULT == sidecar_state_unavailable ]]; then exit 42; fi
    if [[ $FAKE_NATIVE_FAULT == sidecar_exited_empty_ip ||
      $FAKE_NATIVE_FAULT == sidecar_state_error_field ||
      $FAKE_NATIVE_FAULT == sidecar_write_failed ||
      $FAKE_NATIVE_FAULT == sidecar_httpd_failed ||
      $FAKE_NATIVE_FAULT == sidecar_conflicting_state_error ||
      $FAKE_NATIVE_FAULT == sidecar_logs_query_error ]]; then
   echo 'false|exited|127'
 else
   echo 'true|running|0'
 fi
 elif [[ $* == *State.Error* ]]; then
 if [[ $FAKE_NATIVE_FAULT == sidecar_state_error_field ||
   $FAKE_NATIVE_FAULT == sidecar_conflicting_state_error ]]; then
   touch "$state/state_error_inspected"
   echo 'bind: address already in use private-canary'
 fi
 elif [[ $* == *HostConfig.Privileged* ]]; then echo true
    elif [[ $* == *'.Mounts'* ]]; then echo unexpected:/var/lib/docker
 else exit 4; fi ;;
 exec)
 touch "$state/health-attempted"
 if [[ $FAKE_NATIVE_FAULT == sidecar_health_dead ]]; then exit 42; fi
 if [[ $FAKE_NATIVE_FAULT == sidecar_health_race && ! -e $state/health-first ]]; then
   touch "$state/health-first"; exit 42
 fi
 echo proof-egress ;;
 rm)
 for name; do :; done
 if [[ $name == dl-native-egress-* ]]; then
   touch "$state/sidecar_removal_attempted"
   [[ $FAKE_NATIVE_FAULT == sidecar_remains ]] || rm -f "$state/sidecar"
 else
   read -r expected < "$state/expected-container"
   [[ $name == "$expected" ]] || exit 66
   touch "$state/container_removal_attempted"
   [[ $FAKE_NATIVE_FAULT == container_remains ]] || rm -f "$state/container"
 fi ;;
  *) exit 4 ;;
esac
"""
        for lane, fault in (
            ("debian11-rootful", "volume"),
            ("debian11-rootful", "pull"),
            ("debian11-rootful", "network_create"),
            ("debian11-rootful", "sidecar_start"),
            ("debian11-rootful", "sidecar_start_classifier_failure"),
            ("debian11-rootful", "sidecar_health_dead"),
            ("debian11-rootful", "sidecar_health_race"),
            ("debian11-rootful", "sidecar_exited_empty_ip"),
            ("debian11-rootful", "sidecar_write_failed"),
            ("debian11-rootful", "sidecar_httpd_failed"),
            ("debian11-rootful", "sidecar_conflicting_state_error"),
            ("debian11-rootful", "sidecar_logs_query_error"),
            ("debian11-rootful", "sidecar_state_error_field"),
            ("debian11-rootful", "sidecar_running_empty_ip"),
            ("debian11-rootful", "sidecar_state_unavailable"),
            ("debian11-rootful", "cancel_after_sidecar"),
            ("debian11-rootful", "run"),
            ("debian11-rootless", "unexpected_mount"),
            ("upstream-rootful", "unexpected_mount"),
            ("upstream-rootless", "run"),
            ("debian11-rootful", "container_query_error"),
            ("debian11-rootless", "volume_query_error"),
            ("upstream-rootful", "container_remains"),
            ("upstream-rootless", "volume_remains"),
            ("upstream-rootful", "sidecar_remains"),
            ("upstream-rootless", "network_remains"),
            ("debian11-rootful", "sidecar_query_error"),
            ("debian11-rootless", "network_query_error"),
            ("debian11-rootful", "container_inspect_partial"),
            ("debian11-rootless", "sidecar_inspect_partial"),
            ("debian11-rootless", "sidecar_inspect_hang"),
            ("upstream-rootful", "network_inspect_partial"),
            ("upstream-rootless", "volume_inspect_partial"),
        ):
            with self.subTest(lane=lane, fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = root / "state"
                bin_dir = root / "bin"
                state.mkdir()
                (state / "foreign-resource").write_text("untouched")
                bin_dir.mkdir()
                self._tool(bin_dir, "sudo", "#!/bin/sh\n[ \"$1\" = -n ] && shift\nexec \"$@\"\n")
                self._tool(bin_dir, "df",
                           "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted\n'"
                           "\nprintf 'fake 100000000 1 100000000 1%% /tmp\n'\n")
                self._tool(bin_dir, "podman", fake_podman)
                # These cleanup fixtures do not test kernel preflight. Admit
                # that single helper in the fake PATH, leaving every other
                # Python helper on the real interpreter.
                self._tool(bin_dir, "python3", "#!/bin/sh\n"
                           "case \"$1\" in */native-bridge-prerequisite.py) "
                           "echo DOCKERLENS_NATIVE_HOST_NETWORK:bridge_filter=ready; exit 0;; esac\n"
                           "if [ \"${FAKE_NATIVE_FAULT:-}\" = sidecar_start_classifier_failure ] "
                           "&& [ \"$1\" = -c ]; then "
                           "echo private-canary; exit 87; fi\n"
                           f'exec "{sys.executable}" "$@"\n')
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}",
                           FAKE_NATIVE_STATE=str(state), FAKE_NATIVE_FAULT=fault)
                command = ["bash", str(ROOT / "scripts/native-conformance.sh"), lane]
                if fault == "cancel_after_sidecar":
                    process = subprocess.Popen(
                        command, env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True,
                    )
                    deadline = time.monotonic() + 5
                    while not (state / "sidecar").exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue((state / "sidecar").exists())
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=15)
                    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                else:
                    started = time.monotonic()
                    result = subprocess.run(
                        command, env=env, capture_output=True, text=True,
                        timeout=25 if fault == "sidecar_inspect_hang" else 15,
                        check=False,
                    )
                    if fault == "sidecar_inspect_hang":
                        self.assertLess(time.monotonic() - started, 18)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((state / "volume").exists(), fault in ("volume_remains", "volume_inspect_partial"))
                self.assertEqual((state / "container").exists(), fault in ("container_remains", "container_inspect_partial"))
                self.assertEqual((state / "sidecar").exists(), fault in ("sidecar_remains", "sidecar_inspect_partial", "sidecar_inspect_hang"))
                self.assertEqual((state / "network").exists(), fault in ("network_remains", "network_inspect_partial"))
                self.assertEqual((state / "foreign-resource").read_text(), "untouched")
                if fault in ("container_query_error", "container_remains"):
                    self.assertTrue((state / "container_removal_attempted").exists())
                if fault in ("volume_query_error", "volume_remains"):
                    self.assertTrue((state / "volume_removal_attempted").exists())
                if fault in ("sidecar_query_error", "sidecar_remains"):
                    self.assertTrue((state / "sidecar_removal_attempted").exists())
                if fault in ("network_query_error", "network_remains"):
                    self.assertTrue((state / "network_removal_attempted").exists())
                if fault == "container_query_error":
                    self.assertIn("could not verify whether owned container", result.stderr)
                if fault == "volume_query_error":
                    self.assertIn("could not verify whether owned volume", result.stderr)
                if fault == "container_remains":
                    self.assertIn("owned container cleanup readback failed", result.stderr)
                if fault == "volume_remains":
                    self.assertIn("owned volume cleanup readback failed", result.stderr)
                if fault == "sidecar_remains":
                    self.assertIn("owned sidecar cleanup readback failed", result.stderr)
                if fault == "sidecar_inspect_hang":
                    self.assertIn("refusing to remove sidecar", result.stderr)
                    self.assertFalse((state / "sidecar_removal_attempted").exists())
                    self.assertTrue((state / "network_removal_attempted").exists())
                    self.assertTrue((state / "volume_removal_attempted").exists())
                if fault == "network_remains":
                    self.assertIn("owned network cleanup readback failed", result.stderr)
                for role in ("container", "sidecar", "network", "volume"):
                    if fault == f"{role}_inspect_partial":
                        self.assertIn(f"refusing to remove {role}", result.stderr)
                        self.assertFalse((state / f"{role}_removal_attempted").exists())
                if fault == "sidecar_health_dead":
                    self.assertIn("DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=sidecar_health", result.stderr)
                if fault == "sidecar_health_race":
                    self.assertTrue((state / "health-first").exists())
                    self.assertNotIn("phase=sidecar_health", result.stderr)
                if fault == "sidecar_exited_empty_ip":
                    self.assertIn(
                        "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=sidecar_state category=exited exit=nonzero",
                        result.stderr,
                    )
                    self.assertNotIn("phase=attachment", result.stderr)
                    self.assertFalse((state / "health-attempted").exists())
                    self.assertIn("phase=sidecar_failure category=applet_missing source=logs_query", result.stderr)
                if fault == "sidecar_write_failed":
                    self.assertIn(
                        "phase=sidecar_failure category=unknown source=none write_stage=write_failed",
                        result.stderr,
                    )
                if fault == "sidecar_httpd_failed":
                    self.assertIn(
                        "phase=sidecar_failure category=unknown source=none write_stage=write_ok httpd_stage=returned_nonzero state_error=unknown",
                        result.stderr,
                    )
                if fault == "sidecar_conflicting_state_error":
                    self.assertIn(
                        "phase=sidecar_failure category=unknown source=none write_stage=write_ok httpd_stage=returned_nonzero state_error=bind_error",
                        result.stderr,
                    )
                    self.assertTrue((state / "state_error_inspected").exists())
                if fault == "sidecar_logs_query_error":
                    self.assertIn(
                        "phase=sidecar_failure category=unknown source=none write_stage=unknown",
                        result.stderr,
                    )
                if fault == "sidecar_state_error_field":
                    self.assertIn(
                        "phase=sidecar_failure category=bind_error source=state_error write_stage=unknown httpd_stage=unknown state_error=bind_error",
                        result.stderr,
                    )
                    self.assertFalse((state / "health-attempted").exists())
                if fault == "sidecar_start":
                    self.assertIn("phase=sidecar_failure category=shell_error", result.stderr)
                if fault == "sidecar_start_classifier_failure":
                    self.assertIn("phase=sidecar_failure category=unknown", result.stderr)
                    self.assertIn("phase=sidecar_start", result.stderr)
                    self.assertFalse((state / "sidecar").exists())
                    self.assertTrue((state / "sidecar_removal_attempted").exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)
                if fault == "sidecar_running_empty_ip":
                    self.assertTrue((state / "health-attempted").exists())
                    self.assertIn(
                        "phase=attachment role=sidecar category=ipv4_missing",
                        result.stderr,
                    )
                if fault == "sidecar_state_unavailable":
                    self.assertIn(
                        "phase=sidecar_state category=inspect_failed exit=unavailable",
                        result.stderr,
                    )
                    self.assertFalse((state / "health-attempted").exists())
                if (state / "sidecar-run-args").exists():
                    sidecar_args = (state / "sidecar-run-args").read_text()
                    self.assertIn("--network dl-native-net-", sidecar_args)
                    self.assertIn("--user=65534:65534", sidecar_args)
                    self.assertIn("--cap-drop=all", sidecar_args)
                    self.assertIn("--security-opt no-new-privileges", sidecar_args)
                    self.assertIn("--pids-limit=64", sidecar_args)
                    self.assertIn("--memory=128m", sidecar_args)
                if (state / "run-args").exists():
                    args = (state / "run-args").read_text()
                    self.assertIn("--image-volume=ignore", args)
                    self.assertEqual("--security-opt apparmor=unconfined" in args,
                                     lane == "debian11-rootless")
                    self.assertEqual("--oom-score-adj=0" in args, lane == "debian11-rootless")
                    self.assertIn("/usr/local/bin/start-dockerd", args)
                    self.assertIn("--host=unix:///dockerlens-native/docker.sock", args)
                    self.assertIn(":/dockerlens-native", args)
                    expected_store = (
                        "/home/docker/.local/share/docker:U,suid,dev"
                        if lane == "debian11-rootless"
                        else "/home/docker/.local/share/docker:U"
                        if lane == "upstream-rootless"
                        else "/var/lib/docker:U"
                    )
                    self.assertIn(expected_store, args)
                    if fault == "unexpected_mount":
                        self.assertIn("unexpected image or data-root volumes", result.stderr)

    def test_published_image_and_fixture_contracts_are_static(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        self.assertIn("DEBIAN_DOCKER_PACKAGE='20.10.5+dfsg1-1+deb11u2'", source)
        self.assertIn('storage_mount="$volume:', source)
        self.assertIn('rootless ]]; then printf /home/docker/.local/share/docker', source)
        self.assertIn('--user 0:0 --workdir /tmp --hostname dockerlens-native', source)
        self.assertIn('--label io.dockerlens.fixture=synthetic', source)
        self.assertNotIn('/run/dockerlens', source)
        self.assertIn('curl -fs --max-time 5 --unix-socket "$socket" http://localhost/_ping', source)
        self.assertNotIn('apt-get', source)
        self.assertFalse((ROOT / "scripts/native-apt-install.sh").exists())
        self.assertFalse((ROOT / "scripts/native-debian-snapshot.sh").exists())

    def test_engine_release_match_has_exact_boundaries(self) -> None:
        source = (ROOT / "scripts/native-version.sh").read_text()
        for lane, expected, actual, should_pass in (
            ("upstream-rootful", "29.8.1", "29.8.1", True),
            ("upstream-rootless", "29.8.1", "29.8.10", False),
            ("upstream-rootful", "29.8.1", "29.8.1+dfsg1", False),
            ("debian11-rootful", "20.10.5", "20.10.5", True),
            ("debian11-rootless", "20.10.5", "20.10.5+dfsg1", True),
            ("debian11-rootful", "20.10.5", "20.10.50", False),
            ("debian11-rootful", "20.10.5", "20.10.5+unexpected", False),
        ):
            with self.subTest(lane=lane, actual=actual):
                result = subprocess.run(
                    ["bash", "-c", f'source "{ROOT}/scripts/native-version.sh"; '
                     'native_engine_release_matches "$1" "$2" "$3"',
                     "native-test", lane, expected, actual],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode == 0, should_pass)

    def test_only_one_ignored_test_counts_as_native_success(self) -> None:
        for mode, expected_success in (
            ("ignored", True),
            ("nonignored", False),
            ("zero", False),
            ("runfail", False),
            ("acquirefail", False),
            ("uidfail", False),
            ("phasefail", False),
            ("shapefail", False),
            ("volumefail", False),
            ("startfail", False),
            ("listfail", False),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                bin_dir = Path(directory)
                self._tool(
                    bin_dir,
                    "cargo",
                    """#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  if [[ $FAKE_NATIVE_TEST_MODE == listfail ]]; then
    echo 'protected listing detail' >&2
    exit 23
  fi
  [[ $FAKE_NATIVE_TEST_MODE == nonignored ]] || echo 'live_check: test'
elif [[ $FAKE_NATIVE_TEST_MODE == zero ]]; then
  echo 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;'
elif [[ $FAKE_NATIVE_TEST_MODE == runfail ]]; then
  echo 'protected native secret and socket payload' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: capture_mounts' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: capture_protected_secret' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; trailing protected value'
  exit 7
elif [[ $FAKE_NATIVE_TEST_MODE == acquirefail ]]; then
  echo 'protected native response and secret' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: acquire_socket' >&2
  echo 'DOCKERLENS_NATIVE_ERROR: shape' >&2
  echo 'DOCKERLENS_NATIVE_ERROR: protected-secret' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 8
elif [[ $FAKE_NATIVE_TEST_MODE == uidfail ]]; then
  echo 'protected process details' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_uid_count' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_uid_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 9
elif [[ $FAKE_NATIVE_TEST_MODE == phasefail ]]; then
  echo 'protected network details' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_traffic_probe' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_traffic_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 10
elif [[ $FAKE_NATIVE_TEST_MODE == shapefail ]]; then
  echo 'protected native shape detail' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_shape_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 12
elif [[ $FAKE_NATIVE_TEST_MODE == volumefail ]]; then
  echo 'protected read-only volume detail' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_accessible' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_write_other' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_write_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 13
elif [[ $FAKE_NATIVE_TEST_MODE == startfail ]]; then
  echo 'protected daemon start detail' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_start_cgroup' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_start_private' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_start_reason_operation_not_permitted' >&2
  echo 'DOCKERLENS_NATIVE_CHECK: target_start_reason_private' >&2
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 11
else
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""",
                )
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}", FAKE_NATIVE_TEST_MODE=mode)
                result = subprocess.run(
                    [str(ROOT / "scripts/run-exact-native-test.sh"), "fixture", "live_check"],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, expected_success)
                self.assertNotIn("protected", result.stdout + result.stderr)
                if mode == "runfail":
                    self.assertIn("fixture::live_check failed (exit 7)", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: capture_mounts", result.stderr)
                    self.assertNotIn("capture_protected_secret", result.stderr)
                    self.assertIn("test result: FAILED. 0 passed; 1 failed;", result.stderr)
                elif mode == "acquirefail":
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: acquire_socket", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_ERROR: shape", result.stderr)
                    self.assertNotIn("protected-secret", result.stderr)
                elif mode == "uidfail":
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: target_uid_count", result.stderr)
                    self.assertNotIn("target_uid_private", result.stderr)
                elif mode == "phasefail":
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: target_traffic_probe", result.stderr)
                    self.assertNotIn("target_traffic_private", result.stderr)
                elif mode == "shapefail":
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro", result.stderr)
                    self.assertNotIn("target_shape_private", result.stderr)
                elif mode == "volumefail":
                    self.assertIn(
                        "DOCKERLENS_NATIVE_CHECK: target_shape_volume_ro_write_other",
                        result.stderr,
                    )
                    self.assertNotIn("target_shape_volume_ro_write_private", result.stderr)
                elif mode == "startfail":
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: target_start_cgroup", result.stderr)
                    self.assertIn(
                        "DOCKERLENS_NATIVE_CHECK: target_start_reason_operation_not_permitted",
                        result.stderr,
                    )
                    self.assertNotIn("target_start_private", result.stderr)
                    self.assertNotIn("target_start_reason_private", result.stderr)
                elif mode == "listfail":
                    self.assertIn("fixture::live_check (exit 23)", result.stderr)

    def test_native_target_uses_private_library_test_by_exact_name(self) -> None:
        for listed, expected_success in ((0, False), (1, True), (2, False)):
            with self.subTest(listed=listed), tempfile.TemporaryDirectory() as directory:
                bin_dir = Path(directory)
                self._tool(
                    bin_dir,
                    "cargo",
                    """#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$FAKE_NATIVE_INVOCATIONS"
if [[ $* == *--list* ]]; then
  for ((i=0; i<FAKE_NATIVE_LISTED; i++)); do
    echo 'native_target_tests::live_target_render_matches_engine: test'
  done
else
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""",
                )
                invocation = bin_dir / "invocations"
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}",
                           FAKE_NATIVE_INVOCATIONS=str(invocation),
                           FAKE_NATIVE_LISTED=str(listed))
                result = subprocess.run(
                    [str(ROOT / "scripts/run-exact-native-test.sh"),
                     "native_target", "live_target_render_matches_engine"],
                    env=env, capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertEqual(result.returncode == 0, expected_success)
                calls = invocation.read_text().splitlines()
                self.assertEqual(len(calls), 2 if expected_success else 1)
                self.assertTrue(all("--lib" in call and "--test" not in call for call in calls))
                if expected_success:
                    self.assertIn(
                        "--ignored --exact native_target_tests::live_target_render_matches_engine",
                        calls[1],
                    )

        invalid = subprocess.run(
            [str(ROOT / "scripts/run-exact-native-test.sh"),
             "native-target", "live_target_render_matches_engine"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(invalid.returncode, 2)

    def test_native_volume_uses_private_library_test_by_exact_name(self) -> None:
        selected = "native_volume_tests::live_existing_volume_prerequisite_matches_engine"
        for listed, expected_success in ((0, False), (1, True), (2, False)):
            with self.subTest(listed=listed), tempfile.TemporaryDirectory() as directory:
                bin_dir = Path(directory)
                self._tool(
                    bin_dir,
                    "cargo",
                    """#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$FAKE_NATIVE_INVOCATIONS"
if [[ $* == *--list* ]]; then
  for ((i=0; i<FAKE_NATIVE_LISTED; i++)); do
    echo 'native_volume_tests::live_existing_volume_prerequisite_matches_engine: test'
  done
else
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""",
                )
                invocation = bin_dir / "invocations"
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}",
                           FAKE_NATIVE_INVOCATIONS=str(invocation),
                           FAKE_NATIVE_LISTED=str(listed))
                result = subprocess.run(
                    [str(ROOT / "scripts/run-exact-native-test.sh"), "native_volume",
                     "live_existing_volume_prerequisite_matches_engine"],
                    env=env, capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertEqual(result.returncode == 0, expected_success)
                calls = invocation.read_text().splitlines()
                self.assertEqual(len(calls), 2 if expected_success else 1)
                self.assertTrue(all("--lib" in call and "--test" not in call for call in calls))
                if expected_success:
                    self.assertIn(f"--ignored --exact {selected}", calls[1])

        invalid = subprocess.run(
            [str(ROOT / "scripts/run-exact-native-test.sh"), "native-volume",
             "live_existing_volume_prerequisite_matches_engine"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(invalid.returncode, 2)

    def test_native_volume_label_uses_private_library_test_by_exact_name(self) -> None:
        selected = "native_volume_label_tests::live_created_volume_labels_match_engine"
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$FAKE_NATIVE_INVOCATIONS"
if [[ $* == *--list* ]]; then
  echo 'native_volume_label_tests::live_created_volume_labels_match_engine: test'
else
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""")
            invocation = bin_dir / "invocations"
            env = os.environ.copy()
            env.update(PATH=f"{bin_dir}:{env['PATH']}", FAKE_NATIVE_INVOCATIONS=str(invocation))
            result = subprocess.run(
                [str(ROOT / "scripts/run-exact-native-test.sh"), "native_volume_label",
                 "live_created_volume_labels_match_engine"],
                env=env, capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = invocation.read_text().splitlines()
            self.assertEqual(len(calls), 2)
            self.assertTrue(all("--lib" in call and "--test" not in call for call in calls))
            self.assertIn(f"--ignored --exact {selected}", calls[1])

    @staticmethod
    def _tool(directory: Path, name: str, content: str) -> None:
        path = directory / name
        path.write_text(content)
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
