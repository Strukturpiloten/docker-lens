"""Counterfactual watchdog measurements without Podman or native Engine resources."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/native-conformance.sh").read_text(encoding="utf-8")
WATCHDOG = "watchdog_measure() {" + SOURCE.split("watchdog_measure() {", 1)[1].split(
    "\nstorage_mount=", 1
)[0]


class NativeWatchdogTests(unittest.TestCase):
    def run_measurement(
        self, scenario: str, *, watchdog: bool = False, expired: bool = False
    ) -> tuple[subprocess.CompletedProcess[str], tuple[tuple[int, int], list[str], bool]]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "sudo").write_text('#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n')
            (bin_dir / "du").write_text("""#!/bin/sh
count=$(cat "$WATCHDOG_STATE/du-count")
count=$((count + 1))
printf '%s' "$count" > "$WATCHDOG_STATE/du-count"
case "$WATCHDOG_CASE" in
  transient|du_fail_free_limit) if [ "$count" -eq 1 ]; then
    echo 'du: /private/overlay/merged: No such file' >&2; exit 1
  fi ;;
  persistent) echo 'du: /private/overlay/merged: No such file' >&2; exit 1 ;;
  du_partial_limit) if [ "$count" -eq 1 ]; then
    echo '4194305 /private/volume'
    echo 'du: /private/overlay/merged: No such file' >&2
    exit 1
  fi ;;
  malformed) echo 'not-a-number /private/volume'; exit 0 ;;
  used_limit|df_fail_used_limit) echo '4194305 /private/volume'; exit 0 ;;
esac
echo '1048576 /private/volume'
""")
            (bin_dir / "df").write_text("""#!/bin/sh
count=$(cat "$WATCHDOG_STATE/df-count")
count=$((count + 1))
printf '%s' "$count" > "$WATCHDOG_STATE/df-count"
case "$WATCHDOG_CASE" in
  free_limit|du_fail_free_limit) free=2097151 ;;
  df_persistent|df_fail_used_limit) echo 'df: /private/storage: unavailable' >&2; exit 1 ;;
  malformed_df) free=not-a-number ;;
  *) free=2097152 ;;
esac
printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n'
printf 'fake 10000000 1 %s 1%% /private/storage\n' "$free"
""")
            for tool in ("sudo", "du", "df"):
                (bin_dir / tool).chmod(0o755)
            for name in ("du-count", "df-count"):
                (root / name).write_text("0")
            script = f"""set -euo pipefail
volume_path=/private/volume
graph_root=/private/storage
{WATCHDOG}
sleep() {{ printf '%s\\n' "$1" >> "$WATCHDOG_STATE/sleeps"; }}
"""
            if expired:
                script += "SECONDS=1801\n"
            if watchdog:
                script += """main_pid=$$
trap 'printf cleaned > "$WATCHDOG_STATE/cleanup"; exit 143' TERM
watchdog &
wait $!
"""
            else:
                script += """if watchdog_measure; then echo measurement=pass; else echo measurement=fail; fi
"""
            env = os.environ.copy()
            env.update(
                PATH=f"{bin_dir}:{env['PATH']}",
                WATCHDOG_STATE=str(root),
                WATCHDOG_CASE=scenario,
            )
            result = subprocess.run(
                ["bash", "-c", script], env=env, capture_output=True,
                text=True, timeout=5, check=False,
            )
            counts = (int((root / "du-count").read_text()), int((root / "df-count").read_text()))
            sleeps = (root / "sleeps").read_text().splitlines() if (root / "sleeps").exists() else []
            cleaned = (root / "cleanup").exists()
            return result, (counts, sleeps, cleaned)

    def test_transient_du_error_retries_measurement_only(self) -> None:
        result, (counts, sleeps, _) = self.run_measurement("transient")
        self.assertIn("measurement=pass", result.stdout)
        self.assertEqual(counts, (2, 2))
        self.assertEqual(sleeps, ["1"])
        self.assertEqual(result.stderr, "")

    def test_persistent_error_terminates_lane_and_preserves_cleanup(self) -> None:
        for scenario in ("persistent", "df_persistent"):
            with self.subTest(scenario=scenario):
                result, (counts, sleeps, cleaned) = self.run_measurement(scenario, watchdog=True)
                self.assertEqual(result.returncode, 143)
                self.assertEqual(counts, (3, 3))
                self.assertEqual(sleeps, ["5", "1", "1"])
                self.assertTrue(cleaned)
                self.assertIn("native lane watchdog measurement failed", result.stderr)
                self.assertNotIn("/private/", result.stdout + result.stderr)

    def test_thresholds_fail_even_when_other_measurement_errors(self) -> None:
        for scenario in ("used_limit", "free_limit", "du_fail_free_limit", "df_fail_used_limit"):
            with self.subTest(scenario=scenario):
                result, (counts, sleeps, _) = self.run_measurement(scenario)
                self.assertIn("measurement=fail", result.stdout)
                self.assertEqual(counts, (1, 1))
                self.assertEqual(sleeps, [])
                self.assertIn("native lane exceeded its storage, free-space, or 30-minute budget", result.stderr)
                self.assertNotIn("/private/", result.stdout + result.stderr)

    def test_partial_du_total_above_limit_cannot_be_cleared_by_retry(self) -> None:
        result, (counts, sleeps, cleaned) = self.run_measurement("du_partial_limit", watchdog=True)
        self.assertEqual(result.returncode, 143)
        self.assertEqual(counts, (1, 1))
        self.assertEqual(sleeps, ["5"])
        self.assertTrue(cleaned)
        self.assertIn("native lane exceeded its storage, free-space, or 30-minute budget", result.stderr)
        self.assertNotIn("/private/", result.stdout + result.stderr)

    def test_malformed_measurement_fails_closed_without_retry(self) -> None:
        for scenario in ("malformed", "malformed_df"):
            with self.subTest(scenario=scenario):
                result, (counts, sleeps, _) = self.run_measurement(scenario)
                self.assertIn("measurement=fail", result.stdout)
                self.assertEqual(counts, (1, 1))
                self.assertEqual(sleeps, [])
                self.assertIn("native lane watchdog invalid measurement", result.stderr)
                self.assertNotIn("/private/", result.stdout + result.stderr)

    def test_expired_deadline_fails_before_measurement(self) -> None:
        result, (counts, sleeps, _) = self.run_measurement("transient", expired=True)
        self.assertIn("measurement=fail", result.stdout)
        self.assertEqual(counts, (0, 0))
        self.assertEqual(sleeps, [])
        self.assertIn("native lane exceeded its storage, free-space, or 30-minute budget", result.stderr)


if __name__ == "__main__":
    unittest.main()
