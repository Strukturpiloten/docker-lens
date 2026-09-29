"""Counterfactual storage samples without Podman or Docker resources."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
SAMPLER = "sample_storage_kib() {" + SOURCE.split("sample_storage_kib() {", 1)[1].split(
    "\nstorage_mount=", 1
)[0]


class NativeWatchdogTests(unittest.TestCase):
    def run_measurement(
        self, scenario: str, *, watchdog: bool = False, expired: bool = False
    ) -> tuple[subprocess.CompletedProcess[str], tuple[tuple[int, int, int], list[str], bool]]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("du", "df", "stat"):
                (root / f"{name}-count").write_text("0", encoding="utf-8")
            script = """set -euo pipefail
volume_path=/private/volume
graph_root=/private/storage
run_dir=$TEST_RUN_DIR
storage_root_identity='directory|1:2'
stat_cmd=(stat)
bump() {
  local name=$1 count
  count=$(<"$TEST_RUN_DIR/$name-count")
  count=$((count + 1))
  printf '%s' "$count" >"$TEST_RUN_DIR/$name-count"
  printf '%s' "$count"
}
stat() {
  local count
  count=$(bump stat)
  case $TEST_CASE in
    root_loss) return 1 ;;
    root_replace) if (( count > 1 )); then printf 'directory|1:3'; return; fi ;;
  esac
  printf 'directory|1:2'
}
df() {
  bump df >/dev/null
  case $TEST_CASE in
    free_limit|du_fail_free_limit) printf 'fs 1K-blocks Used Available Use%% Mounted\\nfs 9000000 0 2097151 1%% /private/storage\\n'; return ;;
    df_fail_used_limit) printf 'fs 1K-blocks Used Available Use%% Mounted\\nfs 9000000 0 2097152 1%% /private/storage\\n'; return 1 ;;
    df_persistent|df_permission) printf 'df: /private/storage: Permission denied\\n' >&2; return 1 ;;
    malformed_df) printf 'not a measurement\\n'; return ;;
  esac
  printf 'fs 1K-blocks Used Available Use%% Mounted\\nfs 9000000 0 8000000 1%% /private/storage\\n'
}
du() {
  local count
  count=$(bump du)
  case $TEST_CASE in
    transient|du_fail_free_limit|root_replace)
      if (( count == 1 )); then
        printf "du: cannot access '/private/volume/overlay/merged': No such file or directory\\n" >&2
        return 1
      fi ;;
    persistent)
      printf "du: cannot access '/private/volume/overlay/merged': No such file or directory\\n" >&2
      return 1 ;;
    du_partial_limit)
      printf '4194305\\t/private/volume\\n'
      printf "du: cannot access '/private/volume/overlay/merged': No such file or directory\\n" >&2
      return 1 ;;
    malformed) printf 'not-a-number\\t/private/volume\\n'; return ;;
    used_limit|df_fail_used_limit) printf '4194305\\t/private/volume\\n'; return ;;
    permission) printf "du: cannot read directory '/private/volume/private': Permission denied\\n" >&2; return 1 ;;
    timeout) return 124 ;;
  esac
  printf '1048576\\t/private/volume\\n'
}
timeout() { shift 2; "$@"; }
sudo() { if [[ $1 == -n ]]; then shift; fi; "$@"; }
sleep() { printf '%s\\n' "$1" >>"$TEST_RUN_DIR/sleeps"; }
""" + SAMPLER + """
trap 'touch "$TEST_RUN_DIR/cleanup"; exit 143' TERM
"""
            if expired:
                script += "SECONDS=1801\n"
            if watchdog:
                script += "watchdog & wait\n"
            else:
                script += "if sample_storage_kib; then echo measurement=pass; else echo measurement=fail; fi\n"
            env = os.environ.copy()
            env.update(TEST_RUN_DIR=str(root), TEST_CASE=scenario)
            result = subprocess.run(
                ["bash", "-c", script], env=env, text=True, capture_output=True,
                timeout=5, check=False,
            )
            counts = tuple(
                int((root / f"{name}-count").read_text(encoding="utf-8"))
                for name in ("du", "df", "stat")
            )
            sleeps = (root / "sleeps").read_text(encoding="utf-8").splitlines() if (
                root / "sleeps"
            ).exists() else []
            return result, (counts, sleeps, (root / "cleanup").exists())

    def test_disappearing_owned_descendant_retries_once(self) -> None:
        result, (counts, sleeps, _) = self.run_measurement("transient")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("measurement=pass", result.stdout)
        self.assertEqual(counts[:2], (2, 2))
        self.assertEqual(sleeps, ["0.2"])
        self.assertEqual(result.stderr, "")

    def test_persistent_descendant_loss_terminates_watchdog_and_runs_cleanup(self) -> None:
        result, (counts, sleeps, cleaned) = self.run_measurement("persistent", watchdog=True)
        self.assertEqual(result.returncode, 143)
        self.assertEqual(counts[:2], (3, 3))
        self.assertEqual(sleeps, ["5", "0.2", "0.2"])
        self.assertTrue(cleaned)
        self.assertIn("native lane storage measurement failed", result.stderr)
        self.assertNotIn("/private/", result.stdout + result.stderr)

    def test_observed_limits_fail_even_when_other_command_errors(self) -> None:
        for scenario in ("used_limit", "free_limit", "du_fail_free_limit",
                         "df_fail_used_limit", "du_partial_limit"):
            with self.subTest(scenario=scenario):
                result, (counts, sleeps, _) = self.run_measurement(scenario)
                self.assertIn("measurement=fail", result.stdout)
                self.assertEqual(counts[:2], (1, 1))
                self.assertEqual(sleeps, [])
                self.assertIn(
                    "native lane exceeded its storage, free-space, or 30-minute budget",
                    result.stderr,
                )
                self.assertNotIn("/private/", result.stdout + result.stderr)

    def test_non_descendant_errors_and_malformed_totals_fail_closed(self) -> None:
        for scenario in ("df_persistent", "df_permission", "malformed_df",
                         "malformed", "permission", "timeout", "root_replace", "root_loss"):
            with self.subTest(scenario=scenario):
                result, (counts, sleeps, _) = self.run_measurement(scenario)
                self.assertIn("measurement=fail", result.stdout)
                self.assertLessEqual(max(counts[:2]), 1)
                self.assertEqual(sleeps, [])
                self.assertIn("native lane storage measurement failed", result.stderr)
                self.assertNotIn("/private/", result.stdout + result.stderr)

    def test_deadline_fails_without_running_commands(self) -> None:
        result, (counts, sleeps, _) = self.run_measurement("transient", expired=True)
        self.assertIn("measurement=fail", result.stdout)
        self.assertEqual(counts, (0, 0, 0))
        self.assertEqual(sleeps, [])
        self.assertIn("native lane exceeded its storage, free-space, or 30-minute budget",
                      result.stderr)


if __name__ == "__main__":
    unittest.main()
