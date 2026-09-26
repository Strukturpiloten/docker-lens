"""Fault injection for exact resource cleanup and ignored native test selection."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeHarnessTests(unittest.TestCase):
    def test_created_resources_are_removed_even_when_create_reports_failure(self) -> None:
        for fault in (
            "volume", "pull", "run", "run_exists_error", "pull_exists_error",
            "preflight_exists_error", "daemon_exit", "daemon_package_missing",
            "cleanup_container_remains",
            "cleanup_volume_remains", "cleanup_container_query_error",
            "cleanup_volume_query_error",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bin_dir = root / "bin"
                state = root / "state"
                bin_dir.mkdir()
                state.mkdir()
                self._tool(bin_dir, "sudo", "#!/bin/sh\n[ \"$1\" = -n ] && shift\nexec \"$@\"\n")
                self._tool(
                    bin_dir,
                    "df",
                    "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted\\n'"
                    "\nprintf 'fake 100000000 1 100000000 1%% /tmp\\n'\n",
                )
                self._tool(
                    bin_dir,
                    "podman",
                    """#!/usr/bin/env bash
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
    if [[ $1 == exists && $FAKE_NATIVE_FAULT == preflight_exists_error ]]; then exit 125; fi
    if [[ $1 == exists && $FAKE_NATIVE_FAULT == run_exists_error && -e $state/container ]]; then exit 125; fi
    if [[ $1 == exists && $FAKE_NATIVE_FAULT == cleanup_container_query_error && -e $state/container_removal_attempted ]]; then exit 125; fi
    [[ $1 == exists && -e $state/container ]] ;;
  volume)
    action=$1; shift
    case "$action" in
      exists)
        if [[ $FAKE_NATIVE_FAULT == pull_exists_error && -e $state/volume ]]; then exit 125; fi
        if [[ $FAKE_NATIVE_FAULT == cleanup_volume_query_error && -e $state/volume_removal_attempted ]]; then exit 125; fi
        [[ -e $state/volume ]] ;;
      create)
        touch "$state/volume"
        [[ $FAKE_NATIVE_FAULT == volume ]] && exit 42
        echo "$state/volume" ;;
      inspect)
        if [[ $* == *Labels* ]]; then
          name=${*: -1}; echo "${name#dl-native-data-}"
        else
          echo "$state"
        fi ;;
      rm)
        touch "$state/volume_removal_attempted"
        [[ $FAKE_NATIVE_FAULT == cleanup_volume_remains ]] || rm -f "$state/volume" ;;
      *) exit 4 ;;
    esac ;;
  pull)
    [[ $FAKE_NATIVE_FAULT == pull || $FAKE_NATIVE_FAULT == pull_exists_error ]] && exit 42
    exit 0 ;;
  run)
    touch "$state/container"
    [[ $FAKE_NATIVE_FAULT == run || $FAKE_NATIVE_FAULT == run_exists_error || $FAKE_NATIVE_FAULT == cleanup_* ]] && exit 42
    echo fake-id ;;
  inspect)
    if [[ $* == *Labels* ]]; then
      name=${*: -1}; echo "${name#dl-native-}"
    elif [[ $* == *State.Running* ]]; then
      [[ $FAKE_NATIVE_FAULT == daemon_* ]] && echo false || echo true
    elif [[ $* == *State.Status* ]]; then
      echo 'exited|42|false'
    else
      echo true
    fi ;;
  logs)
    if [[ $FAKE_NATIVE_FAULT == daemon_package_missing ]]; then
      echo "E: Version 'protected-secret' for 'docker.io' was not found"
    else
      echo 'newuidmap: protected-secret could not write uid_map'
    fi ;;
  rm)
    touch "$state/container_removal_attempted"
    [[ $FAKE_NATIVE_FAULT == cleanup_container_remains ]] || rm -f "$state/container" ;;
  *) exit 5 ;;
esac
""",
                )
                env = os.environ.copy()
                env.update(
                    PATH=f"{bin_dir}:{env['PATH']}",
                    TMPDIR=str(root),
                    FAKE_NATIVE_STATE=str(state),
                    FAKE_NATIVE_FAULT=fault,
                )
                result = subprocess.run(
                    ["bash", str(ROOT / "scripts/native-conformance.sh"),
                     "debian11-rootless" if fault == "daemon_exit"
                     else "debian11-rootful" if fault == "daemon_package_missing"
                     else "upstream-rootful"],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((state / "container").exists(), fault == "cleanup_container_remains")
                self.assertEqual((state / "volume").exists(), fault == "cleanup_volume_remains")
                if fault == "run_exists_error":
                    self.assertIn("could not verify whether owned container", result.stderr)
                elif fault == "pull_exists_error":
                    self.assertIn("could not verify whether owned volume", result.stderr)
                elif fault == "preflight_exists_error":
                    self.assertIn("could not verify generated native container name", result.stderr)
                elif fault == "daemon_exit":
                    self.assertIn("state=exited|42|false category=rootless_uidmap", result.stderr)
                    self.assertNotIn("protected-secret", result.stderr)
                elif fault == "daemon_package_missing":
                    self.assertIn("state=exited|42|false category=package_install", result.stderr)
                    self.assertNotIn("protected-secret", result.stderr)
                elif fault.startswith("cleanup_"):
                    resource = "container" if "container" in fault else "volume"
                    exit_status = 125 if fault.endswith("query_error") else 0
                    self.assertIn(
                        f"owned {resource} cleanup readback failed (exists exit {exit_status})",
                        result.stderr,
                    )

    def test_engine_release_match_has_exact_boundaries(self) -> None:
        helper = ROOT / "scripts/native-version.sh"
        for lane, expected, reported, allowed in (
            ("upstream-rootful", "28.5.1", "28.5.1", True),
            ("upstream-rootless", "28.5.1", "28.5.10", False),
            ("upstream-rootful", "28.5.1", "28.5.1+dfsg1", False),
            ("debian11-rootful", "20.10.5", "20.10.5", True),
            ("debian11-rootless", "20.10.5", "20.10.5+dfsg1", True),
            ("debian11-rootful", "20.10.5", "20.10.50", False),
            ("debian11-rootful", "20.10.5", "20.10.5+unexpected", False),
        ):
            with self.subTest(lane=lane, reported=reported):
                result = subprocess.run(
                    ["bash", "-c", 'source "$1"; native_engine_release_matches "$2" "$3" "$4"',
                     "native-version-test", str(helper), lane, expected, reported],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, allowed)

    def test_only_one_ignored_test_counts_as_native_success(self) -> None:
        for mode, expected_success in (
            ("ignored", True),
            ("nonignored", False),
            ("zero", False),
            ("runfail", False),
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
                elif mode == "listfail":
                    self.assertIn("fixture::live_check (exit 23)", result.stderr)

    @staticmethod
    def _tool(directory: Path, name: str, content: str) -> None:
        path = directory / name
        path.write_text(content)
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
