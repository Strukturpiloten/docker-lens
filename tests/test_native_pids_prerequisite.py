"""Early PIDs metadata refusals using real launcher code and inert query stubs."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/native-conformance.sh").read_text()
SUFFIX = ("; cgroup v2 required; rootless lanes require a systemd-backed fixture; "
          "rootful lanes require systemd or cgroupfs\n")


class PidsPrerequisiteTests(unittest.TestCase):
    def exercise(self, mode, version, driver, version_status=0, driver_status=0):
        start = SOURCE.index("inner_cgroup_status=0\n")
        end = SOURCE.index("\n[[ $inner_cgroup =~", start)
        body = r'''set -euo pipefail
cleanup() {
  local status=$?
  printf 'cleanup:%s\n' "$status" >> "$TRACE"
}
trap cleanup EXIT
timeout() {
  [[ $1 == 15 ]] || return 70
  shift
  "$@"
}
query() {
  [[ $# == 3 && $1 == info && $2 == --format ]] || return 70
  printf 'PRIVATE_QUERY_STDERR_CANARY\n' >&2
  case "$3" in
    '{{.CgroupVersion}}')
      printf 'query:version\n' >> "$TRACE"
      printf '%s' "$VERSION"
      return "$VERSION_STATUS"
      ;;
    '{{.CgroupDriver}}')
      printf 'query:driver\n' >> "$TRACE"
      printf '%s' "$DRIVER"
      return "$DRIVER_STATUS"
      ;;
    *) return 70 ;;
  esac
}
inner_docker=(query)
expected_mode=$MODE
'''
        body += SOURCE[start:end] + '\nprintf "workload\\n" >> "$TRACE"\n'
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            result = subprocess.run(
                ["/bin/bash", "-c", body], capture_output=True, text=True, timeout=3,
                env={"PATH": "/nonexistent", "TRACE": str(trace), "MODE": mode,
                     "VERSION": version, "DRIVER": driver,
                     "VERSION_STATUS": str(version_status), "DRIVER_STATUS": str(driver_status)},
            )
            return result, trace.read_text().splitlines()

    def test_literal_supported_fixture_matrix_continues_without_claiming_acceptance(self):
        for mode, version, driver in [
            ("rootful", "2", "systemd"),
            ("rootful", "2", "cgroupfs"),
            ("rootless", "2", "systemd"),
        ]:
            with self.subTest(mode=mode, version=version, driver=driver):
                result, trace = self.exercise(mode, version, driver)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")
                self.assertEqual(trace, ["query:version", "query:driver", "workload", "cleanup:0"])

    def test_literal_refusal_matrix_stops_work_and_preserves_exit_cleanup(self):
        # Independent fixture expectations, including failed queries with plausible
        # stdout. A command failure must never borrow successful-looking metadata.
        cases = [
            ("rootful", "1", "systemd", 0, 0, "cgroup_v2_required"),
            ("rootless", "1", "systemd", 0, 0, "cgroup_v2_required"),
            ("rootful", "2", "none", 0, 0, "rootful_cgroup_driver_required"),
            ("rootless", "2", "none", 0, 0, "rootless_systemd_fixture_required"),
            ("rootless", "2", "cgroupfs", 0, 0, "rootless_systemd_fixture_required"),
        ]
        for mode in ("rootful", "rootless"):
            cases.extend([
                (mode, "", "systemd", 0, 0, "cgroup_version_unavailable"),
                (mode, "2", "systemd", 124, 0, "cgroup_version_unavailable"),
                (mode, "2", "", 0, 0, "cgroup_driver_unavailable"),
                (mode, "2", "systemd", 0, 1, "cgroup_driver_unavailable"),
                (mode, "1.0", "systemd", 0, 0, "cgroup_version_malformed"),
                (mode, "3", "systemd", 0, 0, "cgroup_version_malformed"),
                (mode, " 2", "systemd", 0, 0, "cgroup_version_malformed"),
                (mode, "2\nPRIVATE_VERSION_CANARY", "systemd", 0, 0, "cgroup_version_malformed"),
                (mode, "2", "unknown", 0, 0, "cgroup_driver_malformed"),
                (mode, "2", "<no value>", 0, 0, "cgroup_driver_malformed"),
                (mode, "2", " systemd", 0, 0, "cgroup_driver_malformed"),
                (mode, "2", "systemd\nPRIVATE_DRIVER_CANARY", 0, 0, "cgroup_driver_malformed"),
            ])
        for mode, version, driver, version_status, driver_status, reason in cases:
            with self.subTest(mode=mode, version=version, driver=driver,
                              version_status=version_status, driver_status=driver_status):
                result, trace = self.exercise(mode, version, driver, version_status, driver_status)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "native PIDs prerequisite refused: " + reason + SUFFIX)
                self.assertEqual(trace, ["query:version", "query:driver", "cleanup:1"])

    def test_gate_follows_existing_queries_before_work_and_all_27_unchanged_calls(self):
        calls = re.findall(r'run-exact-native-test\.sh" ([a-z_0-9]+) ([a-z_0-9]+)', SOURCE)
        expected = """
native_capture live_engine_capture_decodes
acquisition live_read_only_acquisition_matches_oracle
native_selection live_native_selection_and_source_observations
native_selection live_network_membership_matches_engine
native_target live_target_render_matches_engine
native_network live_network_render_matches_engine
native_network live_internal_network_blocks_external_egress
native_volume live_existing_volume_prerequisite_matches_engine
native_volume_label live_created_volume_labels_match_engine
native_identity live_container_process_identity_matches_engine
native_port live_port_publications_match_engine
native_health_metadata live_health_metadata_matches_engine
native_network_attachment live_network_attachments_match_engine
native_bind_relabel live_bind_relabel_configuration_matches_engine
native_external_network live_external_network_internal_matches_engine
native_stop_signal live_stop_signal_matches_engine
native_lifecycle live_lifecycle_matches_engine
native_runtime_filesystem live_runtime_filesystem_matches_engine
native_tmpfs_effect live_tmpfs_effects_match_engine
native_health_start_interval_boundary live_health_start_interval_boundary_matches_engine
native_lifecycle_default_effect live_lifecycle_default_effects_match_engine
native_hostname live_hostname_matches_engine
native_command_clear live_command_clear_matches_engine
native_shm_size live_shm_size_effects_match_engine
native_supplementary_groups live_supplementary_groups_match_engine
native_kernel_settings live_kernel_settings_match_engine
native_pids live_pids_limits_and_effects_match_engine
"""
        self.assertEqual(calls, [tuple(row.split()) for row in expected.strip().splitlines()] + [
            ("native_nofile", "live_nofile_limits_and_effects_match_engine"),
        ])
        gate = SOURCE.index('\nnative_pids_prerequisite "$expected_mode"')
        self.assertEqual(SOURCE.count("info --format '{{.CgroupVersion}}'"), 1)
        self.assertEqual(SOURCE.count("info --format '{{.CgroupDriver}}'"), 1)
        self.assertLess(SOURCE.index("trap cleanup EXIT"), gate)
        self.assertLess(SOURCE.index("inner_cgroup_driver=$("), gate)
        self.assertLess(gate, SOURCE.index('"${inner_docker[@]}" pull "$FIXTURE_IMAGE"'))
        self.assertLess(gate, SOURCE.index('"$(dirname "$0")/run-exact-native-test.sh"'))
        self.assertLess(gate, SOURCE.index('python3 "$script_dir/build-native-pids-worker.py"'))


if __name__ == "__main__":
    unittest.main()
