"""Canonical nofile28 controls with inert native commands and the real private reader."""
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

from test_native_nofile_proof import fixture

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_nofile"
TEST = "live_nofile_limits_and_effects_match_engine"
SELECTED = f"native_health_metadata_tests::lifecycle::nofile::{TEST}"
SUCCESS = b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;\n"
HANDOFF = b"DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required\n"
SECRET = b"PRIVATE_NOFILE_WIRING_CANARY"
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
# Independent original invocation ledger, not parsed from production or older tests.
ORIGINAL27 = [
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
    ("native_external_network", "live_external_network_internal_matches_engine"),
    ("native_stop_signal", "live_stop_signal_matches_engine"),
    ("native_lifecycle", "live_lifecycle_matches_engine"),
    ("native_runtime_filesystem", "live_runtime_filesystem_matches_engine"),
    ("native_tmpfs_effect", "live_tmpfs_effects_match_engine"),
    ("native_health_start_interval_boundary", "live_health_start_interval_boundary_matches_engine"),
    ("native_lifecycle_default_effect", "live_lifecycle_default_effects_match_engine"),
    ("native_hostname", "live_hostname_matches_engine"),
    ("native_command_clear", "live_command_clear_matches_engine"),
    ("native_shm_size", "live_shm_size_effects_match_engine"),
    ("native_supplementary_groups", "live_supplementary_groups_match_engine"),
    ("native_kernel_settings", "live_kernel_settings_match_engine"),
    ("native_pids", "live_pids_limits_and_effects_match_engine"),
]


class NofileWiringTests(unittest.TestCase):
    def wrapper(self, output=SUCCESS, status=0, *, listing=None, list_status=0, name=TEST, cleanup_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cargo").write_text('''#!/usr/bin/python3
import base64, json, os, sys
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"argv": sys.argv[1:], "owner": os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER"),
        "deadline": os.environ.get("NATIVE_NOFILE_DEADLINE_EPOCH"),
        "shared": os.environ.get("NATIVE_LIFECYCLE_DEADLINE_EPOCH")}) + "\\n")
if "--list" in sys.argv:
    sys.stdout.buffer.write(base64.b64decode(os.environ["LISTING"]))
    sys.exit(int(os.environ["LIST_STATUS"]))
sys.stdout.buffer.write(open(os.environ["OUTPUT_PATH"], "rb").read())
sys.exit(int(os.environ["STATUS"]))
''')
            (root / "date").write_text('''#!/usr/bin/env bash
printf 'date\\n' >> "$DATES"
printf '2000\\n'
''')
            if cleanup_failure:
                (root / "rm").write_text('''#!/usr/bin/env bash
printf 'cleanup\\n' >> "$DATES"
exit 1
''')
                (root / "rm").chmod(0o700)
            for name_path in (root / "cargo", root / "date"):
                name_path.chmod(0o700)
            listing = (SELECTED + ": test\n").encode() if listing is None else listing
            (root / "output").write_bytes(output)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "TMPDIR": directory,
                   "TRACE": str(root / "trace"), "DATES": str(root / "dates"),
                   "OUTPUT_PATH": str(root / "output"), "STATUS": str(status),
                   "LISTING": base64.b64encode(listing).decode(), "LIST_STATUS": str(list_status),
                   "NATIVE_NOFILE_DEADLINE_EPOCH": "1",
                   "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1"}
            result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, name],
                                    env=env, capture_output=True, timeout=10, check=False)
            calls = [json.loads(line) for line in (root / "trace").read_text().splitlines()] if (root / "trace").exists() else []
            dates = (root / "dates").read_text().splitlines() if (root / "dates").exists() else []
            self.assertNotIn(SECRET, result.stdout + result.stderr)
            return result, calls, dates

    def test_only_exact_ignored_test_runs_with_original_once_only_deadline(self):
        result, calls, dates = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertIn("--lib", calls[0]["argv"])
        self.assertEqual(calls[1]["argv"][-4:], ["--", "--ignored", "--exact", SELECTED])
        self.assertEqual(calls[1]["deadline"], "2180")
        self.assertEqual(calls[1]["shared"], "2180")
        self.assertEqual(calls[1]["owner"], "native_conformance_outer_v1")
        self.assertEqual(dates, ["date"])
        result, calls, dates = self.wrapper(name="other_ignored_nofile_test")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertEqual(dates, [])

    def test_listing_execution_and_numeric_summary_cannot_silently_skip_work(self):
        for listing in (b"", b"foreign: test\n", (SELECTED + ": test\n").encode() * 2):
            with self.subTest(listing=listing):
                result, calls, dates = self.wrapper(listing=listing)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 1)
                self.assertEqual(dates, [])
        self.assertNotEqual(self.wrapper(list_status=7)[0].returncode, 0)
        for output, status in ((SUCCESS, 101), (SUCCESS.replace(b"1 passed", b"0 passed"), 0),
                               (SUCCESS.replace(b"1 passed", b"2 passed"), 0),
                               (SUCCESS.replace(b"0 ignored", b"1 ignored"), 0), (b"", 0)):
            with self.subTest(output=output, status=status):
                self.assertNotEqual(self.wrapper(output, status)[0].returncode, 0)

    def test_unverified_cleanup_handoff_and_capture_uncertainty_override_success(self):
        for output in (HANDOFF + SUCCESS, b"DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + SUCCESS,
                       SECRET + b"\0" + SUCCESS, b"x" * 1048577 + SUCCESS):
            with self.subTest(size=len(output)):
                self.assertNotEqual(self.wrapper(output)[0].returncode, 0)
        result, _calls, dates = self.wrapper(cleanup_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(dates, ["date", "cleanup"])
        self.assertEqual(result.stderr, b"required native test private capture cleanup unavailable\n")

    def test_first_causal_site_is_closed_and_private_panic_text_never_escapes(self):
        failure = (b"DOCKERLENS_NATIVE_CHECK: nofile_effects\n"
                   + f"thread '{SELECTED}' panicked at src/native_nofile_tests.rs:123:4:\n".encode()
                   + SECRET + b"\nDOCKERLENS_NATIVE_CHECK: nofile_cleanup\n"
                   + b"DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + HANDOFF)
        result, _calls, _dates = self.wrapper(failure, 101)
        for public in (b"(exit 101)", b"nofile_effects", b"lifecycle_cleanup_unverified",
                       b"source=native_nofile_tests line=123 column=4", HANDOFF.rstrip()):
            self.assertIn(public, result.stderr)
        result, _calls, _dates = self.wrapper(b"thread 'worker' panicked at /private/" + SECRET + b":1:1:\n" + failure, 101)
        self.assertIn(b"source=native_nofile_tests location=unavailable", result.stderr)
        self.assertNotIn(b"line=123", result.stderr)
        result, _calls, _dates = self.wrapper(b"DOCKERLENS_NATIVE_CHECK: nofile_secret_" + SECRET + b"\n", 101)
        self.assertNotIn(b"nofile_secret_", result.stderr)

    def test_original27_order_readers_and_separate_one_child_owner_are_preserved(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = re.findall(r'^[ \t]*"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)
        self.assertEqual(calls, ORIGINAL27 + [(TARGET, TEST)])
        owners = re.findall(r'^\(\n[ \t]+export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n(.*?)^\)', source, re.S | re.M)
        owned = [re.findall(r'run-exact-native-test.sh" (\w+) (\w+)', block) for block in owners]
        self.assertEqual(owned, [ORIGINAL27[16:21], [ORIGINAL27[21]], [ORIGINAL27[23]],
                                [ORIGINAL27[24]], [ORIGINAL27[25]], [ORIGINAL27[26]], [(TARGET, TEST)]])
        self.assertEqual(source.count("export NATIVE_LIFECYCLE_CLEANUP_OWNER="), 7)
        pids = source.index('python3 "$script_dir/native_pids_proof.py"')
        nofile = source.index('"$(dirname "$0")/run-exact-native-test.sh" native_nofile')
        reader = source.index('python3 "$script_dir/native_nofile_proof.py"')
        publication = source.index('publish_native_evidence() {')
        self.assertLess(pids, nofile)
        self.assertLess(nofile, reader)
        self.assertLess(reader, publication)
        command = shlex.split(source[reader:source.index('\n\n', reader)].replace('\\\n', ' '))
        self.assertEqual(command[2:], ["$run_dir", "$NATIVE_NOFILE_CANDIDATE_SHA", "$run_id", "$lane",
            "$server_version", "$api_version", "$expected_mode", "$installed_docker_package",
            "$NATIVE_FIXTURE_IMAGE", "$image", "$NATIVE_OUTER_CONTAINER_ID", "$NATIVE_BIND_RELABEL_DAEMON_UID"])
        self.assertIn('export NATIVE_NOFILE_PROOF_PATH="$run_dir/nofile-v1.json"', source)
        self.assertIn('export NATIVE_NOFILE_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', source)

    def tail(self, lane, backend, *, failure="", evidence=False, profile=False, proof_mutate=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            (root / "socket").mkdir(mode=0o700)
            payload = fixture(lane, outer_backend=backend)
            context = payload["context"]
            context["outer"]["socket_source"] = str(root / "socket")
            context = deepcopy(context)
            if proof_mutate is not None:
                proof_mutate(payload)
            proof_path = root / "nofile-v1.json"
            proof_path.write_text(json.dumps(payload))
            proof_path.chmod(0o600)
            (root / "python3").write_text('''#!/usr/bin/python3
import json, os, subprocess, sys
if sys.argv[1] == "-c":
    print("123456789")
    raise SystemExit(0)
name = sys.argv[1].rsplit("/", 1)[-1]
event = {"build-native-pids-worker.py":"prebuild", "native_pids_proof.py":"pids_reader", "native_nofile_proof.py":"nofile_reader"}[name]
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"event":event, "argv":sys.argv[2:], "backend":os.environ["NATIVE_OUTER_ENGINE"]}) + "\\n")
if os.environ["FAILURE"] == event:
    raise SystemExit(23)
if event == "nofile_reader":
    raise SystemExit(subprocess.run([sys.executable, *sys.argv[1:]], check=False).returncode)
''')
            (root / "run-exact-native-test.sh").write_text('''#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  'native_pids live_pids_limits_and_effects_match_engine') event=pids_child ;;
  'native_nofile live_nofile_limits_and_effects_match_engine') event=nofile_child ;;
  *) exit 97 ;;
esac
printf '{"event":"%s","owner":"%s"}\\n' "$event" "${NATIVE_LIFECYCLE_CLEANUP_OWNER:-}" >> "$TRACE"
if [[ $FAILURE == "$event" ]]; then exit 23; fi
''')
            for path in (root / "python3", root / "run-exact-native-test.sh"):
                path.chmod(0o700)
            source = (ROOT / "scripts/native-conformance.sh").read_text()
            start = source.index('# Build the fixed inert witness before invocation27')
            segment = source[start:source.index('\nnative_success_summary=', start)]
            (root / "tail.sh").write_text('''#!/usr/bin/env bash
set -euo pipefail
unset NATIVE_LIFECYCLE_CLEANUP_OWNER
native_publication_command() {
  if [[ $1 == git ]]; then
    if [[ $* == *'rev-parse HEAD' ]]; then printf '%s\\n' "$NATIVE_PIDS_CANDIDATE_SHA"; fi
  else printf '{"event":"emitter"}\\n' >> "$TRACE"; fi
}
cleanup() {
  local status=$?
  trap - EXIT
  printf '{"event":"teardown","status":%s}\\n' "$status" >> "$TRACE"
  if [[ -n $apparmor_profile && $status == 0 && ${apparmor_native_completed:-0} == 1 ]]; then
    publish_native_evidence || status=$?
  fi
  exit "$status"
}
trap cleanup EXIT
''' + segment + '\nprintf \'{"event":"complete","owner":"%s"}\\n\' "${NATIVE_LIFECYCLE_CLEANUP_OWNER:-}" >> "$TRACE"\n')
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "TRACE": str(root / "trace"),
                   "FAILURE": failure, "run_dir": directory, "script_dir": str(ROOT / "scripts"),
                   "run_id": context["run_id"], "lane": lane, "server_version": context["engine_release"],
                   "api_version": context["rendering_api"], "expected_mode": context["mode"],
                   "installed_docker_package": context["docker_package"], "image": context["outer"]["image"],
                   "NATIVE_FIXTURE_IMAGE": context["fixture_image"], "NATIVE_OUTER_IMAGE": context["outer"]["image"],
                   "NATIVE_OUTER_CONTAINER_ID": context["outer"]["id"], "NATIVE_OUTER_ENGINE": backend,
                   "NATIVE_BIND_RELABEL_DAEMON_UID": str(context["daemon_uid"]),
                   "NATIVE_PIDS_CANDIDATE_SHA": context["candidate_sha"], "NATIVE_NOFILE_CANDIDATE_SHA": context["candidate_sha"],
                   "DOCKERLENS_NATIVE_CANDIDATE_SHA": context["candidate_sha"],
                   "DOCKERLENS_NATIVE_EVIDENCE_DIR": "synthetic" if evidence else "", "apparmor_profile": "owned" if profile else ""}
            for name in ("SHAPES", "SOURCE_PROBES", "NETWORK_PROBES", "VOLUME_PROBES", "VOLUME_LABEL_PROBES",
                         "IDENTITY_PROBES", "PORT_PROBES", "HEALTH_METADATA_PROOF", "NETWORK_ATTACHMENT_PROOF", "BIND_RELABEL_PROOF"):
                env["NATIVE_" + name + "_PATH"] = "synthetic"
            result = subprocess.run(["bash", str(root / "tail.sh")], env=env, capture_output=True, timeout=10, check=False)
            events = [json.loads(line) for line in (root / "trace").read_text().splitlines()]
            return result, events, deepcopy(context)

    def test_actual_tail_always_runs_real_twelve_fact_reader_on_every_lane_and_backend(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                with self.subTest(lane=lane, backend=backend):
                    result, events, context = self.tail(lane, backend)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual([item["event"] for item in events],
                        ["prebuild", "pids_child", "pids_reader", "nofile_child", "nofile_reader", "complete", "teardown"])
                    reader = events[4]
                    self.assertEqual(reader["backend"], backend)
                    self.assertEqual(reader["argv"], [context["outer"]["socket_source"].removesuffix("/socket"),
                        context["candidate_sha"], context["run_id"], lane, context["engine_release"], context["rendering_api"],
                        context["mode"], context["docker_package"], context["fixture_image"], context["outer"]["image"],
                        context["outer"]["id"], str(context["daemon_uid"])])
                    self.assertEqual(events[1]["owner"], "native_conformance_outer_v1")
                    self.assertEqual(events[3]["owner"], "native_conformance_outer_v1")
                    self.assertEqual(events[-2]["owner"], "")
                    self.assertEqual(events[-1]["status"], 0)

    def test_each_required_failure_stops_before_later_work_and_original_exit_teardown_runs(self):
        sequence = ["prebuild", "pids_child", "pids_reader", "nofile_child", "nofile_reader"]
        for failure in sequence:
            for profile in (False, True):
                with self.subTest(failure=failure, profile=profile):
                    result, events, _context = self.tail("upstream-rootless", "docker", failure=failure, evidence=True, profile=profile)
                    expected_status = 1 if failure == "prebuild" else 23
                    self.assertEqual(result.returncode, expected_status, result.stderr)
                    self.assertEqual([item["event"] for item in events], sequence[:sequence.index(failure) + 1] + ["teardown"])
                    self.assertEqual(events[-1]["status"], expected_status)
        for profile in (False, True):
            result, events, _context = self.tail("upstream-rootful", "podman", evidence=True, profile=profile)
            self.assertEqual(result.returncode, 0, result.stderr)
            names = [item["event"] for item in events]
            self.assertLess(names.index("nofile_reader"), names.index("emitter"))
            if profile:
                self.assertLess(names.index("teardown"), names.index("emitter"))
            else:
                self.assertLess(names.index("emitter"), names.index("teardown"))

    def test_real_inline_reader_refuses_private_proof_even_without_emission(self):
        for mutate in (lambda value: value["context"].update(candidate_sha="f" * 40),
                       lambda value: value["accounting"].update(ordinary_calls=1),
                       lambda value: value["cleanup"].update(uncertain=True)):
            result, events, _context = self.tail("debian11-rootless", "docker", proof_mutate=mutate)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual([item["event"] for item in events][-2:], ["nofile_reader", "teardown"])
            self.assertEqual(result.stderr, b"invalid private nofile proof\n")


if __name__ == "__main__":
    unittest.main()
