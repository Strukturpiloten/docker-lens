"""Fault injection for exact resource cleanup and ignored native test selection."""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeHarnessTests(unittest.TestCase):
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
            "# A random directory, container, and volume belong to exactly this lane.", 1
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
    [[ $1 == exists && -e $state/container ]] ;;
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
    printf '%s\n' "$*" > "$state/run-args"
    prior=
    for item in "$@"; do
      if [[ $prior == --name ]]; then printf '%s\n' "$item" > "$state/expected-container"; fi
      prior=$item
    done
    touch "$state/ran"
    touch "$state/container"
    [[ $FAKE_NATIVE_FAULT == unexpected_mount ]] ;;
  inspect)
    if [[ $* == *Labels* ]]; then
      for name; do :; done
      echo "$name" | sed 's/^dl-native-//'
    elif [[ $* == *HostConfig.Privileged* ]]; then echo true
    elif [[ $* == *'.Mounts'* ]]; then echo unexpected:/var/lib/docker
    else exit 4; fi ;;
  rm)
    for name; do :; done
    read -r expected < "$state/expected-container"
    [[ $name == "$expected" ]] || exit 66
    touch "$state/container_removal_attempted"
    [[ $FAKE_NATIVE_FAULT == container_remains ]] || rm -f "$state/container" ;;
  *) exit 4 ;;
esac
"""
        for lane, fault in (
            ("debian11-rootful", "volume"),
            ("debian11-rootful", "pull"),
            ("debian11-rootful", "run"),
            ("debian11-rootless", "unexpected_mount"),
            ("upstream-rootful", "unexpected_mount"),
            ("upstream-rootless", "run"),
            ("debian11-rootful", "container_query_error"),
            ("debian11-rootless", "volume_query_error"),
            ("upstream-rootful", "container_remains"),
            ("upstream-rootless", "volume_remains"),
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
                env = os.environ.copy()
                env.update(PATH=f"{bin_dir}:{env['PATH']}",
                           FAKE_NATIVE_STATE=str(state), FAKE_NATIVE_FAULT=fault)
                result = subprocess.run(
                    ["bash", str(ROOT / "scripts/native-conformance.sh"), lane],
                    env=env, capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((state / "volume").exists(), fault == "volume_remains")
                self.assertEqual((state / "container").exists(), fault == "container_remains")
                self.assertEqual((state / "foreign-resource").read_text(), "untouched")
                if fault in ("container_query_error", "container_remains"):
                    self.assertTrue((state / "container_removal_attempted").exists())
                if fault in ("volume_query_error", "volume_remains"):
                    self.assertTrue((state / "volume_removal_attempted").exists())
                if fault == "container_query_error":
                    self.assertIn("could not verify whether owned container", result.stderr)
                if fault == "volume_query_error":
                    self.assertIn("could not verify whether owned volume", result.stderr)
                if fault == "container_remains":
                    self.assertIn("owned container cleanup readback failed", result.stderr)
                if fault == "volume_remains":
                    self.assertIn("owned volume cleanup readback failed", result.stderr)
                if (state / "run-args").exists():
                    args = (state / "run-args").read_text()
                    self.assertIn("--image-volume=ignore", args)
                    self.assertEqual("--oom-score-adj=0" in args, lane == "debian11-rootless")
                    self.assertIn("/usr/local/bin/start-dockerd", args)
                    self.assertIn("--host=unix:///dockerlens-native/docker.sock", args)
                    self.assertIn(":/dockerlens-native", args)
                    expected_store = ("/home/docker/.local/share/docker:U"
                                      if lane.endswith("rootless") else "/var/lib/docker:U")
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

    @staticmethod
    def _tool(directory: Path, name: str, content: str) -> None:
        path = directory / name
        path.write_text(content)
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
