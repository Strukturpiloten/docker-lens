"""Fault injection for exact resource cleanup and ignored native test selection."""

import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeHarnessTests(unittest.TestCase):
    def test_port_publication_is_independent_eleventh_mandatory_check_before_manifest(self) -> None:
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
            ("native_volume_label", "live_created_volume_labels_match_engine"),
            ("native_identity", "live_container_process_identity_matches_engine"),
            ("native_port", "live_port_publications_match_engine"),
            ("native_health_metadata", "live_health_metadata_matches_engine"),
            ("native_network_attachment", "live_network_attachments_match_engine"),
            ("native_bind_relabel", "live_bind_relabel_configuration_matches_engine"),
        ])
        self.assertLess(source.index('native_port live_port_publications_match_engine'),
                        source.index('python3 "$script_dir/native-evidence.py"'))
        self.assertIn('export NATIVE_IDENTITY_PROBES_PATH="$run_dir/identity-probes.json"', source)
        self.assertIn('export NATIVE_PORT_PROBES_PATH="$run_dir/port-probes.json"', source)
        self.assertIn('export NATIVE_PORT_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', source)

    def test_identity_source_requires_pid1_owned_id_cleanup_and_positive_absence(self) -> None:
        source = (ROOT / "src/native_identity_tests.rs").read_text()
        self.assertIn('set -eu; id -u; id -g; pwd -P', source)
        self.assertIn('Some("1000:1000".into())', source)
        self.assertIn('Some("/tmp".into())', source)
        self.assertIn('format!("--user={user}")', source)
        self.assertIn('format!("--workdir={workdir}")', source)
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
        self.assertIn('.0 == 204', cleanup)
        self.assertIn('for _ in 0..2', cleanup)
        self.assertIn('self.inspect(&self.names[index], true).0 == 404', cleanup)
        self.assertIn('self.inspect(id, true).0 == 404', cleanup)
        self.assertIn('name_absent && id_absent', cleanup)
        self.assertIn('None => self.create_rejected[index]', cleanup)
        self.assertIn('deleted && !self.create_rejected[index]', cleanup)
        self.assertIn('self.cleanup_uncertain |= !verified', cleanup)
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
 if [[ $item == path=* ]]; then log_path=${item#path=}; fi
 if [[ $item == *@sha256:* ]]; then daemon_image=$item; fi
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
   printf '%s\n' "$log_path" > "$state/daemon-log-path"
   printf '%s\n' "$daemon_image" > "$state/daemon-image"
   printf '1970-01-01T00:00:00.000000000Z stdout F private-startup-canary\n' >> "$log_path"
   printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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
 if [[ $* == *'{{json .Id}}'* ]]; then
  echo 'template: inspect: cannot evaluate field Id in type interface{}' >&2
  touch "$state/go-field-projection-rejected"
  exit 42
 fi
 if [[ $* == *'{{json .}}'* ]]; then
  read -r name < "$state/expected-container"
  read -r log_path < "$state/daemon-log-path"
  read -r daemon_image < "$state/daemon-image"
  outer_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  image_digest=${daemon_image##*@}
  [[ $FAKE_NATIVE_FAULT != log_registration_id ]] || outer_id=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
  [[ $FAKE_NATIVE_FAULT != log_registration_digest ]] || image_digest=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
  [[ $FAKE_NATIVE_FAULT != log_registration_path ]] || log_path=/foreign-private-path
  digest_json=$(printf '"%s"' "$image_digest")
  [[ $FAKE_NATIVE_FAULT != log_registration_missing_digest ]] || digest_json=null
  printf '{"Id":"%s","Name":"%s","ImageName":"normalized-display-name","ImageDigest":%s,"Config":{"Labels":{"io.dockerlens.native-run":"%s"}},"HostConfig":{"Privileged":true,"LogConfig":{"Type":"k8s-file","Path":"%s"}}}\n' \
    "$outer_id" "$name" "$digest_json" "${name#dl-native-}" "$log_path"
 elif [[ $* == *Labels* ]]; then
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
    elif [[ $* == *'.Mounts'* ]]; then
      read -r log_path < "$state/daemon-log-path"
      cp "${log_path%/*}/port-log-registration.json" "$state/registration-observed.json"
      echo unexpected:/var/lib/docker
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
            ("debian11-rootless", "log_registration_id"),
            ("debian11-rootless", "log_registration_digest"),
            ("debian11-rootless", "log_registration_path"),
            ("debian11-rootless", "log_registration_missing_digest"),
            ("upstream-rootful", "legacy_podman_json"),
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
                if fault in ("unexpected_mount", "legacy_podman_json", "log_registration_id", "log_registration_digest", "log_registration_missing_digest", "log_registration_path"):
                    observed = json.loads((state / "registration-observed.json").read_text())
                    self.assertEqual(observed["status"], "registered" if fault in ("unexpected_mount", "legacy_podman_json") else "prepared")
                    self.assertIn("outer container has unexpected image or data-root volumes", result.stderr)
                    self.assertFalse((state / "go-field-projection-rejected").exists())
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

    def test_native_curl_readiness_sites_keep_exact_argv_counts_and_final_fallback(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        self.assertEqual(len(re.findall(r"\bcurl\b", source)), 4)  # Preflight and three sites.
        readiness = "deadline=$((SECONDS + 360))" + source.split(
            "deadline=$((SECONDS + 360))", 1
        )[1].split("\nif [[ $lane == debian11-rootless ]]; then", 1)[0]
        cases = (
            ("ready", [0, 0], False, True, 2, 0, 0),
            ("poll-retry", [7, 0, 0], False, True, 3, 1, 0),
            ("final-failure", [0, 7], False, True, 2, 0, 1),
            ("deadline-fallback", [7, 7], True, True, 2, 1, 1),
            ("outer-exited", [7], False, False, 1, 0, 1),
        )
        for case, exits, expire, running, expected_count, sleep_count, status in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                socket_path = directory / "docker.sock"
                # Exercise the real -S guard without creating a transport or listener.
                os.mknod(socket_path, stat.S_IFSOCK | 0o600)
                calls, env = self._native_curl_client(directory, exits, "000")
                sleeps = directory / "sleep-calls"
                preface = f"""set -euo pipefail
SECONDS=0
socket=$1
container=synthetic-owned-daemon
podman_cmd=(podman)
chmod() {{ :; }}
sudo() {{ [[ $1 == -n ]]; shift; "$@"; }}
podman() {{ printf '%s\\n' {'true' if running else 'false'}; }}
sleep() {{ printf '%s\\n' "$*" >> {shlex.quote(str(sleeps))}; {'SECONDS=360' if expire else ':'}; }}
diagnose_native_startup() {{ printf '%s\\n' startup-diagnostic >&2; }}
"""
                result = subprocess.run(
                    ["bash", "-c", preface + readiness, "curl-readiness-test", str(socket_path)],
                    cwd=directory, env=env, capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertTrue(calls.exists())
                expected = ["-q", "--noproxy", "*", "-fs", "--max-time", "5", "--unix-socket",
                            str(socket_path), "http://localhost/_ping"]
                observed = [json.loads(line) for line in calls.read_text().splitlines()]
                self.assertEqual(observed, [{"argv": expected, "canary": "synthetic-client-boundary"}]
                                 * expected_count)
                self.assertEqual(sleeps.read_text().splitlines() if sleeps.exists() else [], ["2"] * sleep_count)
                self.assertEqual(result.stderr.count("startup-diagnostic"), status)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("synthetic-client-boundary", result.stderr)

    def test_native_curl_api_get_keeps_exact_argv_count_limits_and_failure_status(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        api_get = "api_get() {" + source.split("api_get() {", 1)[1].split("\njson_key() {", 1)[0]
        self.assertIn("status=$(timeout 20 curl -q --noproxy '*' -fsS --max-time 15", api_get)
        for http_status, native_exit, expected_exit in (("200", 0, 0), ("404", 0, 1),
                                                       ("000", 7, 7), ("404", 22, 22)):
            with self.subTest(http_status=http_status, native_exit=native_exit), \
                    tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                socket_path = directory / "docker.sock"
                target = directory / "container.json"
                calls, env = self._native_curl_client(directory, [native_exit], http_status)
                request = "/v1.41/containers/synthetic/json"
                script = 'set -euo pipefail\nsocket=$1\n' + api_get + '\napi_get "$2" "$3"'
                result = subprocess.run(
                    ["bash", "-c", script, "curl-api-test", str(socket_path), request, str(target)],
                    cwd=directory, env=env, capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                self.assertTrue(calls.exists())
                expected = ["-q", "--noproxy", "*", "-fsS", "--max-time", "15", "--unix-socket",
                            str(socket_path), "http://localhost" + request, "-o", str(target), "-w", "%{http_code}"]
                self.assertEqual([json.loads(line) for line in calls.read_text().splitlines()],
                                 [{"argv": expected, "canary": "synthetic-client-boundary"}])
                status_path = target.with_suffix(".status")
                if expected_exit == 0:
                    self.assertEqual(status_path.read_text(), "200\n")
                else:
                    self.assertFalse(status_path.exists())
                self.assertEqual(result.stdout, "")
                self.assertNotIn("synthetic-client-boundary", result.stderr)

    def _native_curl_client(self, directory: Path, exits: list[int], http_status: str) -> tuple[Path, dict[str, str]]:
        calls = directory / "curl-argv.jsonl"
        bin_dir = directory / "bin"
        bin_dir.mkdir()
        # A real glob match makes an unquoted --noproxy wildcard fail the argv check.
        (directory / "wildcard-expansion-canary").touch()
        self._tool(bin_dir, "curl", f"""#!{sys.executable}
import json
import os
import sys
from pathlib import Path

calls = Path({str(calls)!r})
previous = calls.read_text().splitlines() if calls.exists() else []
with calls.open('a') as output:
    output.write(json.dumps({{'argv': sys.argv[1:], 'canary': os.environ.get('DOCKERLENS_CURL_CANARY')}}) + '\\n')
exits = {exits!r}
sys.stdout.write({http_status!r})
sys.exit(exits[min(len(previous), len(exits) - 1)])
""")
        return calls, {"PATH": f"{bin_dir}:/usr/bin:/bin", "DOCKERLENS_CURL_CANARY": "synthetic-client-boundary"}

    def test_published_image_and_fixture_contracts_are_static(self) -> None:
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        self.assertIn("DEBIAN_DOCKER_PACKAGE='20.10.5+dfsg1-1+deb11u2'", source)
        self.assertIn('storage_mount="$volume:', source)
        self.assertIn('rootless ]]; then printf /home/docker/.local/share/docker', source)
        self.assertIn('--user 0:0 --workdir /tmp --hostname dockerlens-native', source)
        self.assertIn('--label io.dockerlens.fixture=synthetic', source)
        self.assertNotIn('/run/dockerlens', source)
        self.assertIn('curl -q --noproxy \'*\' -fs --max-time 5 --unix-socket "$socket" http://localhost/_ping', source)
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

    def test_native_port_uses_private_library_test_by_exact_name(self) -> None:
        selected = "native_port_tests::live_port_publications_match_engine"
        for listed, expected_success in ((0, False), (1, True), (2, False)):
            with self.subTest(listed=listed), tempfile.TemporaryDirectory() as directory:
                bin_dir = Path(directory)
                self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$FAKE_NATIVE_INVOCATIONS"
if [[ $* == *--list* ]]; then
  for ((i=0; i<FAKE_NATIVE_LISTED; i++)); do
    echo 'native_port_tests::live_port_publications_match_engine: test'
  done
else
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
fi
""")
                invocation = bin_dir / "invocations"
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}",
                           FAKE_NATIVE_INVOCATIONS=str(invocation),
                           FAKE_NATIVE_LISTED=str(listed))
                result = subprocess.run(
                    [str(ROOT / "scripts/run-exact-native-test.sh"), "native_port",
                     "live_port_publications_match_engine"],
                    env=env, capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertEqual(result.returncode == 0, expected_success)
                calls = invocation.read_text().splitlines()
                self.assertEqual(len(calls), 2 if expected_success else 1)
                self.assertTrue(all("--lib" in call and "--test" not in call for call in calls))
                if expected_success:
                    self.assertIn(f"--ignored --exact {selected}", calls[1])

    def test_native_port_failure_markers_are_closed(self) -> None:
        selected = "native_port_tests::live_port_publications_match_engine"
        for marker, accepted in (("port_fixed_ipv4_oracle_cli_create", True),
                                 ("port_context", True),
                                 ("container_port_fixed_ipv4_oracle_cli_create", False),
                                 ("port_private_canary", False)):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                bin_dir = Path(directory)
                self._tool(bin_dir, "cargo", f"""#!/usr/bin/env bash
set -eu
if [[ $* == *--list* ]]; then
  echo '{selected}: test'
else
  echo 'DOCKERLENS_NATIVE_CHECK: {marker}'
  echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;'
  exit 101
fi
""")
                env = os.environ.copy()
                env["PATH"] = f"{bin_dir}:{env['PATH']}"
                result = subprocess.run(
                    [str(ROOT / "scripts/run-exact-native-test.sh"), "native_port",
                     "live_port_publications_match_engine"],
                    env=env, capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((f"DOCKERLENS_NATIVE_CHECK: {marker}" in result.stderr), accepted)

    def _port_wrapper(self, output: str, status: int = 101, target: str = "native_port") -> subprocess.CompletedProcess[str]:
        test_name = "live_port_publications_match_engine"
        selected = f"{target}_tests::{test_name}"
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self._tool(bin_dir, "cargo", """#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$FAKE_NATIVE_INVOCATIONS"
if [[ $* == *--list* ]]; then
  printf '%s: test\\n' "$FAKE_NATIVE_SELECTED"
else
  printf '%s\\n' "$FAKE_NATIVE_OUTPUT"
  exit "$FAKE_NATIVE_STATUS"
fi
""")
            invocation = bin_dir / "invocations"
            env = os.environ.copy()
            env.update(PATH=f"{bin_dir}:{env['PATH']}", FAKE_NATIVE_INVOCATIONS=str(invocation),
                       FAKE_NATIVE_SELECTED=selected, FAKE_NATIVE_OUTPUT=output,
                       FAKE_NATIVE_STATUS=str(status))
            result = subprocess.run([str(ROOT / "scripts/run-exact-native-test.sh"), target, test_name],
                                    env=env, capture_output=True, text=True, timeout=15, check=False)
            calls = invocation.read_text().splitlines()
            self.assertEqual(len(calls), 2)
            self.assertIn(f"--ignored --exact {selected}", calls[1])
            return result

    def test_port_failure_preserves_pre_cleanup_stage_and_first_selected_panic(self) -> None:
        selected = "native_port_tests::live_port_publications_match_engine"
        for suffix in ("", " (123)"):
            for cleanup_outcome in ("pass", "fail", "panic"):
                with self.subTest(suffix=suffix, cleanup_outcome=cleanup_outcome):
                    result = self._port_wrapper("\n".join([
                        "DOCKERLENS_NATIVE_CHECK: port_fixed_ipv6_oracle_tcp6_boundary",
                        "DOCKERLENS_NATIVE_API_DIAG: transport=timeout",
                        "thread 'protected-secret' panicked at src/native_port_tests.rs:1:2:",
                        f"thread '{selected}'{suffix} panicked at src/native_port_tests.rs:205:9:",
                        "protected-secret compared runtime values",
                        "DOCKERLENS_NATIVE_CHECK: port_cleanup",
                        "DOCKERLENS_NATIVE_API_DIAG: transport=other",
                        f"DOCKERLENS_NATIVE_PORT_CLEANUP_DIAG: attempt=primary outcome={cleanup_outcome} reserve=low mutation=clear",
                        f"thread '{selected}' panicked at src/native_port_tests.rs:2883:5:",
                        "DOCKERLENS_NATIVE_CHECK: port_fixed_ipv4_rendered_cli_http",
                        "DOCKERLENS_NATIVE_PORT_CLEANUP_DIAG: attempt=drop outcome=panic reserve=exhausted mutation=uncertain",
                        "DOCKERLENS_NATIVE_CHECK: port_cleanup_unverified",
                        "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 130 filtered out;",
                    ]))
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: port_fixed_ipv6_oracle_tcp6_boundary", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_CHECK: port_cleanup_unverified", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_PANIC: source=native_port_tests line=205 column=9", result.stderr)
                    self.assertNotIn("line=2883", result.stderr)
                    self.assertNotIn("line=1 column=2", result.stderr)
                    self.assertNotIn("port_fixed_ipv4_rendered_cli_http", result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)
                    self.assertIn(f"attempt=primary outcome={cleanup_outcome}", result.stderr)
                    self.assertIn("attempt=drop outcome=panic", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_API_DIAG: transport=timeout", result.stderr)
                    self.assertNotIn("DOCKERLENS_NATIVE_API_DIAG: transport=other", result.stderr)

    def test_port_diagnostic_families_are_closed_and_target_scoped(self) -> None:
        valid = [
            "DOCKERLENS_NATIVE_API_DIAG: transport=timeout",
            "DOCKERLENS_NATIVE_PORT_API_DIAG: action=start phase=probe exit=curl_timeout",
            "DOCKERLENS_NATIVE_PORT_API_DIAG: action=inspect_name phase=cleanup exit=outer_timeout",
            "DOCKERLENS_NATIVE_PORT_START_DIAG: outcome=observed version=responsive object=timeout identity=unknown state=unknown primary=unknown secondary=unknown allocation_relation=unknown mutation=uncertain",
            "DOCKERLENS_NATIVE_API_DIAG: operation=start status=server",
            "DOCKERLENS_NATIVE_HTTP_DIAG: exit=other category=connection_refused",
            "DOCKERLENS_NATIVE_CLI_DIAG: exit=timeout stderr=permission",
            "DOCKERLENS_NATIVE_NAMESPACE_DIAG: category=identity",
            "DOCKERLENS_NATIVE_IPV6_DIAG: local_service=pass inner_all=disabled inner_lo=disabled outer_tcp6=available curl_exit=7",
            "DOCKERLENS_NATIVE_IPV6_BOUNDARY_DIAG: result=refused",
            "DOCKERLENS_NATIVE_ISOLATION_DIAG: result=other",
            "DOCKERLENS_NATIVE_PORT_BINDINGS_DIAG: key=array count=two ipv4=one ipv6=zero other=one v4_port=nonzero v6_port=absent",
            "DOCKERLENS_NATIVE_PORT_CLEANUP_DIAG: attempt=primary outcome=fail reserve=low mutation=clear",
            "DOCKERLENS_NATIVE_PORT_CLEANUP_DIAG: attempt=drop outcome=panic reserve=exhausted mutation=uncertain",
        ]
        summary = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 130 filtered out;"
        result = self._port_wrapper("\n".join(valid + [summary]))
        self.assertEqual(result.returncode, 1)
        for line in valid:
            self.assertEqual(result.stderr.splitlines().count(line), 1)
        non_port = self._port_wrapper("\n".join(valid + [summary]), target="native_identity")
        for line in valid:
            self.assertNotIn(line, non_port.stderr)
        malformed = []
        for line in valid:
            malformed.extend((line + " protected-secret", "protected-secret " + line,
                              line + "\r", line.replace("=", "=protected-secret", 1)))
            # Replace every individual enum independently, including bounded
            # numerical HTTP categories. A known field cannot rescue an unknown.
            for field in line.split()[1:]:
                key, value = field.split("=", 1)
                malformed.extend((line.replace(field, f"{key}=unknown_enum", 1),
                                  line.replace(field, f"{key}=protected\nsecret", 1)))
        rejected = self._port_wrapper("\n".join(malformed + [summary]))
        self.assertEqual(rejected.returncode, 1)
        self.assertNotIn("_DIAG:", rejected.stderr)
        self.assertNotIn("protected", rejected.stdout + rejected.stderr)
        self.assertNotIn("unknown_enum", rejected.stderr)

    def test_port_start_followup_observations_never_replace_failure_or_reveal_values(self) -> None:
        selected = "native_port_tests::live_port_publications_match_engine"
        observations = [
            "outcome=observed version=responsive object=timeout identity=unknown state=unknown primary=unknown secondary=unknown allocation_relation=unknown mutation=uncertain",
            "outcome=observed version=timeout object=timeout identity=unknown state=unknown primary=unknown secondary=unknown allocation_relation=unknown mutation=uncertain",
            "outcome=observed version=responsive object=responsive identity=same state=running primary=one secondary=one allocation_relation=same mutation=uncertain",
            "outcome=observed version=responsive object=responsive identity=same state=running primary=one secondary=one allocation_relation=different mutation=uncertain",
            "outcome=observed version=responsive object=responsive identity=mismatch state=unknown primary=unknown secondary=unknown allocation_relation=unknown mutation=uncertain",
            "outcome=skipped version=unknown object=unknown identity=unknown state=unknown primary=unknown secondary=unknown allocation_relation=unknown mutation=uncertain",
        ]
        for observation in observations:
            with self.subTest(observation=observation):
                result = self._port_wrapper("\n".join([
                    "DOCKERLENS_NATIVE_CHECK: port_repeated_dynamic_ipv4_oracle_oracle_start",
                    "DOCKERLENS_NATIVE_API_DIAG: transport=timeout",
                    "DOCKERLENS_NATIVE_PORT_API_DIAG: action=start phase=probe exit=curl_timeout",
                    "DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: begin",
                    f"thread '{selected}' panicked at src/native_port_tests.rs:505:9:",
                    "private-native-ID protected-secret 32000",
                    "DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: end",
                    f"DOCKERLENS_NATIVE_PORT_START_DIAG: {observation}",
                    f"thread '{selected}' panicked at src/native_port_tests.rs:415:9:",
                    "DOCKERLENS_NATIVE_CHECK: port_cleanup",
                    "DOCKERLENS_NATIVE_PORT_API_DIAG: action=delete phase=cleanup exit=outer_timeout",
                    "DOCKERLENS_NATIVE_CHECK: port_cleanup_unverified",
                    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 130 filtered out;",
                ]))
                self.assertEqual(result.returncode, 1)
                self.assertIn("line=415 column=9", result.stderr)
                self.assertNotIn("line=505", result.stderr)
                self.assertIn(f"DOCKERLENS_NATIVE_PORT_START_DIAG: {observation}", result.stderr)
                self.assertIn("action=start phase=probe exit=curl_timeout", result.stderr)
                self.assertIn("action=delete phase=cleanup exit=outer_timeout", result.stderr)
                for secret in ("private-native-ID", "protected-secret", "32000"):
                    self.assertNotIn(secret, result.stdout + result.stderr)

    def test_port_start_allocation_relation_requires_exact_finite_field(self) -> None:
        prefix = ("DOCKERLENS_NATIVE_PORT_START_DIAG: outcome=observed version=responsive "
                  "object=responsive identity=same state=created primary=one secondary=one ")
        summary = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 130 filtered out;"
        for relation in ("same", "different", "unknown"):
            line = f"{prefix}allocation_relation={relation} mutation=uncertain"
            result = self._port_wrapper("\n".join([line, summary]))
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr.splitlines().count(line), 1)
        invalid = [
            prefix + "mutation=uncertain",
            prefix + "allocation_relation=32000 mutation=uncertain",
            prefix + "allocation_relation=protected-secret mutation=uncertain",
            prefix + "allocation_relation=unknown_enum mutation=uncertain",
            prefix + "allocation_relation=same allocation_relation=different mutation=uncertain",
            prefix + "allocation_relation=same mutation=uncertain protected-secret",
            prefix + "allocation_relation=same mutation=uncertain\r",
            prefix + "allocation_relation=same extra=protected-secret mutation=uncertain",
        ]
        result = self._port_wrapper("\n".join(invalid + [summary]))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("DOCKERLENS_NATIVE_PORT_START_DIAG", result.stderr)
        for secret in ("32000", "protected-secret", "unknown_enum"):
            self.assertNotIn(secret, result.stdout + result.stderr)

    def test_port_start_followup_reuses_only_test_scoped_canonical_gets(self) -> None:
        source = (ROOT / "src/native_port_tests.rs").read_text()
        failure = source.split('let output = self.capture(&mut command, input.as_deref(), 131080);', 1)[1].split('let split = output', 1)[0]
        self.assertIn('if !cleanup && method == "POST" && start', failure)
        self.assertIn('self.name("multi-dynamic-oracle")', failure)
        self.assertIn('path == format!("{prefix}/containers/{id}/start")', failure)
        self.assertLess(failure.index('DIAGNOSTIC_SCOPE: begin'), failure.index('self.repeated_start_diagnostics('))
        self.assertLess(failure.index('self.repeated_start_diagnostics('), failure.index('DIAGNOSTIC_SCOPE: end'))
        followup = source.split('fn repeated_start_diagnostics(', 1)[1].split('fn api(', 1)[0]
        self.assertIn('self.known_id(id) != Some(name)', followup)
        self.assertLess(followup.index('start_diagnostic_budget('), followup.index('ReadRequest::DaemonVersion'))
        self.assertEqual(followup.count('ReadRequest::DaemonVersion'), 1)
        self.assertEqual(followup.count('ReadRequest::InspectContainer('), 1)
        for forbidden in ('self.capture(', 'self.api(', 'self.cleanup(', 'Command::new(',
                          'uncertain_mutation.set', 'thread::spawn', 'ReadRequest::List',
                          'self.calls.set', 'self.bytes.set'):
            self.assertNotIn(forbidden, followup)
        canonical = (ROOT / 'src/acquisition.rs').read_text()
        seam = canonical.split('pub(crate) fn diagnostic_get(', 1)[1].split('fn exchange', 1)[0]
        self.assertIn('diagnostic_request_allowed(request, api)', seam)
        self.assertEqual(seam.count('http_get('), 1)
        self.assertIn('remaining(budget.started, limit, cancelled)?', seam)
        self.assertNotIn('acquire(', seam)
        self.assertIn('#[cfg(test)]\npub(crate) fn diagnostic_get', canonical)

    def test_port_panic_projection_excludes_caught_ipv6_followups(self) -> None:
        selected = "native_port_tests::live_port_publications_match_engine"
        begin = "DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: begin"
        end = "DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: end"
        optional = f"thread '{selected}' panicked at src/native_port_tests.rs:1054:9:"
        primary = f"thread '{selected}' panicked at src/native_port_tests.rs:1080:9:"
        for count in (1, 2):
            with self.subTest(scopes=count):
                events = ["DOCKERLENS_NATIVE_CHECK: port_fixed_ipv6_rendered_cli_http",
                          "DOCKERLENS_NATIVE_HTTP_DIAG: exit=other category=no_route"]
                for _ in range(count):
                    events.extend([begin, optional, "protected-secret compared values", end])
                events.extend([primary, "DOCKERLENS_NATIVE_CHECK: port_cleanup",
                               f"thread '{selected}' panicked at src/native_port_tests.rs:3000:5:",
                               "DOCKERLENS_NATIVE_CHECK: port_cleanup_unverified"])
                result = self._port_wrapper("\n".join(events))
                self.assertEqual(result.returncode, 1)
                self.assertIn("DOCKERLENS_NATIVE_PANIC: source=native_port_tests line=1080 column=9", result.stderr)
                self.assertNotIn("line=1054", result.stderr)
                self.assertNotIn("line=3000", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_HTTP_DIAG: exit=other category=no_route", result.stderr)
                self.assertNotIn("DIAGNOSTIC_SCOPE", result.stdout + result.stderr)
                self.assertNotIn("PORT_SCOPE_DIAG", result.stderr)
                self.assertNotIn("protected-secret", result.stdout + result.stderr)
        # A timed-out stream with only caught follow-up panics has no eligible
        # source site even when its observed scope happened to finish.
        timeout = self._port_wrapper("\n".join([begin, optional, end]), status=124)
        self.assertEqual(timeout.returncode, 1)
        self.assertIn("failed (exit 124)", timeout.stderr)
        self.assertNotIn("DOCKERLENS_NATIVE_PANIC:", timeout.stderr)
        source = (ROOT / "src/native_port_tests.rs").read_text()
        invocation = source.split('if let Some((id, local_ipv6)) = local_ipv6 {', 1)[1].split(
            'panic!("closed published endpoint HTTP assertion failed")', 1)[0]
        self.assertLess(invocation.index(begin), invocation.index("best_effort_ipv6_diagnostics("))
        self.assertLess(invocation.index("best_effort_ipv6_diagnostics("), invocation.index(end))
        helper = source.split("fn best_effort_ipv6_diagnostics(", 1)[1].split("#[test]", 1)[0]
        self.assertNotIn("DIAGNOSTIC_SCOPE", helper)

    def test_port_panic_projection_invalid_scope_suppresses_all_sites(self) -> None:
        selected = "native_port_tests::live_port_publications_match_engine"
        begin = "DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: begin"
        end = "DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: end"
        optional = f"thread '{selected}' panicked at src/native_port_tests.rs:1054:9:"
        primary = f"thread '{selected}' panicked at src/native_port_tests.rs:1080:9:"
        malformed = [
            [begin, begin, optional, end, end, primary],
            [end, primary],
            [begin, optional, primary],
            [begin, optional, end + " protected-secret", primary],
            [begin, "DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: unknown_enum", end, primary],
            [begin, "DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: be\ngin", end, primary],
            [primary, begin, optional],
            [primary, end],
            [primary, " " + begin, end],
            [primary, begin + " protected-secret", end],
            [primary, begin + "\r", end],
        ]
        for index, events in enumerate(malformed):
            for status in (101, 124):
                with self.subTest(case=index, status=status):
                    result = self._port_wrapper("\n".join(events), status=status)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(f"failed (exit {status})", result.stderr)
                    self.assertIn("DOCKERLENS_NATIVE_PORT_SCOPE_DIAG: state=invalid", result.stderr)
                    self.assertNotIn("DOCKERLENS_NATIVE_PANIC:", result.stderr)
                    self.assertNotIn("DIAGNOSTIC_SCOPE", result.stdout + result.stderr)
                    self.assertNotIn("unknown_enum", result.stderr)
                    self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_port_panic_projection_rejects_other_sources_and_injected_locations(self) -> None:
        selected = "native_port_tests::live_port_publications_match_engine"
        invalid = [
            f"thread '{selected}' panicked at src/native_identity_tests.rs:205:9:",
            f"thread '{selected}' panicked at /protected-secret/src/native_port_tests.rs:205:9:",
            f"thread '{selected}' panicked at src/native_port_tests.rs:1234567:9:",
            f"thread '{selected}' panicked at src/native_port_tests.rs:205:12345:",
            f"thread '{selected}' panicked at src/native_port_tests.rs:205:9: protected-secret",
            f"thread '{selected}' panicked at src/native_port_tests.rs:205:protected-secret:",
            "thread 'other_test' panicked at src/native_port_tests.rs:205:9:",
        ]
        result = self._port_wrapper("\n".join(invalid))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("DOCKERLENS_NATIVE_PANIC:", result.stderr)
        self.assertNotIn("protected-secret", result.stdout + result.stderr)

    def test_port_diagnostics_never_turn_failure_timeout_or_zero_tests_into_success(self) -> None:
        diagnostic = "DOCKERLENS_NATIVE_API_DIAG: transport=timeout"
        for status, passed, failed, success in ((0, 1, 0, True), (0, 0, 0, False),
                                               (0, 2, 0, False), (101, 1, 0, False),
                                               (124, 0, 1, False), (137, 0, 1, False)):
            with self.subTest(status=status, passed=passed, failed=failed):
                summary = f"test result: {'ok' if failed == 0 else 'FAILED'}. {passed} passed; {failed} failed; 0 ignored; 0 measured; 130 filtered out;"
                result = self._port_wrapper(f"{diagnostic}\n{summary}", status=status)
                self.assertEqual(result.returncode == 0, success)
                if status != 0:
                    self.assertIn(f"failed (exit {status})", result.stderr)
                    self.assertIn(diagnostic, result.stderr)
                else:
                    self.assertNotIn(diagnostic, result.stdout + result.stderr)

    @staticmethod
    def _tool(directory: Path, name: str, content: str) -> None:
        path = directory / name
        path.write_text(content)
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
