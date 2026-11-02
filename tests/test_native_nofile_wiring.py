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
from test_native_device_mapping_proof import fixture as device_fixture
from test_native_memory_proof import fixture as memory_fixture, bind_context as bind_memory_context
from test_native_capabilities_proof import fixture as capabilities_fixture, bind_context as bind_capabilities_context
from test_native_logging_proof import fixture as logging_fixture, bind_context as bind_logging_context

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
    def test_actual_default_capture_libtest_preserves_marker_record_and_cleanup_order(self):
        # Execute the three production marker statements under ordinary capturing
        # libtest. Authored transcripts alone miss eprintln/direct-stderr reordering.
        source = (ROOT / "src/native_nofile_tests.rs").read_text()
        markers = {}
        for name in ("context", "effects", "cleanup"):
            matches = [line.strip() for line in source.splitlines()
                       if f'"DOCKERLENS_NATIVE_CHECK: nofile_{name}"' in line]
            self.assertEqual(len(matches), 1)
            markers[name] = matches[0]
        with tempfile.TemporaryDirectory(prefix="dl-nofile-libtest-") as directory:
            root = Path(directory)
            fixture = '''use std::io::Write;
mod native_health_metadata_tests { pub mod lifecycle { pub mod nofile {
use super::super::super::*;
#[test] #[ignore]
fn live_nofile_limits_and_effects_match_engine() {
    let mode = std::env::var("NOFILE_TRANSPORT_MODE").unwrap();
    let work = mode == "work" || mode == "both";
    let cleanup = mode == "cleanup" || mode == "both";
    let result = std::panic::catch_unwind(|| {
        CONTEXT
        EFFECTS
        if work { panic!("PRIVATE_NOFILE_WIRING_CANARY"); }
    });
    CLEANUP
    if cleanup { let _ = std::io::stderr().write_all(HANDOFF); }
    if work { let _ = std::io::stderr().write_all(WORK); }
    if cleanup { let _ = std::io::stderr().write_all(REFUSAL); }
    if let Err(error) = result { std::panic::resume_unwind(error); }
    assert!(!cleanup, "PRIVATE_NOFILE_WIRING_CANARY");
}
}}}
'''
            for token, value in (("CONTEXT", markers["context"]), ("EFFECTS", markers["effects"]),
                                 ("CLEANUP", markers["cleanup"]),
                                 ("HANDOFF", 'b"' + HANDOFF.decode().replace("\n", "\\n") + '"'),
                                 ("WORK", 'b"' + (self.failure_line(operation="observe", code="1").rstrip(b"\n") + b" observer_site=workerexe\n").decode().replace("\n", "\\n") + '"'),
                                 ("REFUSAL", 'b"' + self.cleanup_line(reason="ownership_guard", termination="unknown", code="none").decode().replace("\n", "\\n") + '"')):
                fixture = fixture.replace(token, value)
            (root / "transport.rs").write_text(fixture)
            built = subprocess.run(["rustc", "--edition=2024", "--test", str(root / "transport.rs"), "-o", str(root / "transport")],
                                   cwd=ROOT, capture_output=True, timeout=30, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            for mode in ("work", "cleanup", "both", "success"):
                captured = subprocess.run([str(root / "transport"), "--ignored", "--exact", SELECTED],
                                          env={**os.environ, "NOFILE_TRANSPORT_MODE": mode},
                                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5, check=False)
                self.assertEqual(captured.returncode, 0 if mode == "success" else 101)
                result, _calls, _dates = self.wrapper(captured.stdout, captured.returncode)
                self.assertEqual(result.returncode, 0 if mode == "success" else 1, result.stderr)
                output = result.stdout + result.stderr
                self.assertEqual(b"DOCKERLENS_NATIVE_NOFILE_FAILURE:" in output, mode in ("work", "both"))
                self.assertEqual(b" observer_site=workerexe" in output, mode in ("work", "both"))
                self.assertEqual(b"DOCKERLENS_NATIVE_NOFILE_CLEANUP_REFUSAL:" in output, mode in ("cleanup", "both"))
                self.assertEqual(HANDOFF.rstrip() in output, mode in ("cleanup", "both"))
                self.assertNotIn(SECRET, output)
                if mode == "both":
                    self.assertLess(output.index(b"DOCKERLENS_NATIVE_NOFILE_FAILURE:"), output.index(b"DOCKERLENS_NATIVE_NOFILE_CLEANUP_REFUSAL:"))

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
        self.assertEqual(calls, ORIGINAL27 + [(TARGET, TEST), ("native_device_mapping", "live_device_mapping_matches_engine"),
                                 ("native_memory", "live_memory_limits_and_effects_match_engine"), ("native_capabilities", "live_named_capabilities_match_engine"), ("native_logging", "live_logging_matches_engine")])
        owners = re.findall(r'^\(\n[ \t]+export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n(.*?)^\)', source, re.S | re.M)
        owned = [re.findall(r'run-exact-native-test.sh" (\w+) (\w+)', block) for block in owners]
        self.assertEqual(owned, [ORIGINAL27[16:21], [ORIGINAL27[21]], [ORIGINAL27[23]],
                                [ORIGINAL27[24]], [ORIGINAL27[25]], [ORIGINAL27[26]], [(TARGET, TEST)],
                                 [("native_device_mapping", "live_device_mapping_matches_engine")],
                          [("native_memory", "live_memory_limits_and_effects_match_engine")], [("native_capabilities", "live_named_capabilities_match_engine")], [("native_logging", "live_logging_matches_engine")]])
        self.assertEqual(source.count("export NATIVE_LIFECYCLE_CLEANUP_OWNER="), 11)
        pids = source.index('python3 "$script_dir/native_pids_proof.py"')
        nofile = source.index('"$(dirname "$0")/run-exact-native-test.sh" native_nofile')
        reader = source.index('python3 "$script_dir/native_nofile_proof.py"')
        publication = source.index('publish_native_evidence() {')
        self.assertLess(pids, nofile)
        self.assertLess(nofile, reader)
        self.assertLess(reader, publication)
        command = shlex.split(source[reader:source.index('\n# Invocation 29', reader)].replace('\\\n', ' '))
        self.assertEqual(command[2:], ["$run_dir", "$NATIVE_NOFILE_CANDIDATE_SHA", "$run_id", "$lane",
            "$server_version", "$api_version", "$expected_mode", "$installed_docker_package",
            "$NATIVE_FIXTURE_IMAGE", "$image", "$NATIVE_OUTER_CONTAINER_ID", "$NATIVE_BIND_RELABEL_DAEMON_UID"])
        self.assertIn('export NATIVE_NOFILE_PROOF_PATH="$run_dir/nofile-v1.json"', source)
        self.assertIn('export NATIVE_NOFILE_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', source)

    def tail(self, lane, backend, *, failure="", evidence=False, profile=False, proof_mutate=None, device_mutate=None, memory_mutate=None, capabilities_mutate=None, logging_mutate=None):
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
            device = device_fixture(lane, outer_backend=backend)
            device["context"] = deepcopy(context)
            if device_mutate is not None:
                device_mutate(device)
            memory = bind_memory_context(memory_fixture(lane, outer_backend=backend), context)
            if memory_mutate is not None:
                memory_mutate(memory)
            capabilities = bind_capabilities_context(capabilities_fixture(lane, outer_backend=backend), context)
            if capabilities_mutate is not None:
                capabilities_mutate(capabilities)
            logging = bind_logging_context(logging_fixture(lane, outer_backend=backend), context)
            if logging_mutate is not None:
                logging_mutate(logging)
            logging_path = root / "logging-v1.json"
            logging_path.write_text(json.dumps(logging, separators=(",", ":")))
            logging_path.chmod(0o600)
            cap_path = root / "named-capabilities-v1.json"
            cap_path.write_text(json.dumps(capabilities))
            cap_path.chmod(0o600)
            memory_path = root / "memory-limits-v1.json"
            memory_path.write_text(json.dumps(memory))
            memory_path.chmod(0o600)
            device_path = root / "device-mapping-v1.json"
            device_path.write_text(json.dumps(device))
            device_path.chmod(0o600)
            proof_path = root / "nofile-v1.json"
            proof_path.write_text(json.dumps(payload))
            proof_path.chmod(0o600)
            (root / "python3").write_text('''#!/usr/bin/python3
import json, os, subprocess, sys
if sys.argv[1] == "-c":
    print("123456789")
    raise SystemExit(0)
name = sys.argv[1].rsplit("/", 1)[-1]
event = {"build-native-pids-worker.py":"prebuild", "native_pids_proof.py":"pids_reader", "native_nofile_proof.py":"nofile_reader", "native_device_mapping_proof.py":"device_reader", "native_memory_proof.py":"memory_reader", "native_capabilities_proof.py":"capabilities_reader", "native_logging_proof.py":"logging_reader"}[name]
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"event":event, "argv":sys.argv[2:], "backend":os.environ["NATIVE_OUTER_ENGINE"]}) + "\\n")
if os.environ["FAILURE"] == event:
    raise SystemExit(23)
if event in ("nofile_reader", "device_reader", "memory_reader", "capabilities_reader", "logging_reader"):
    raise SystemExit(subprocess.run([sys.executable, *sys.argv[1:]], check=False).returncode)
''')
            (root / "run-exact-native-test.sh").write_text('''#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  'native_pids live_pids_limits_and_effects_match_engine') event=pids_child ;;
  'native_nofile live_nofile_limits_and_effects_match_engine') event=nofile_child ;;
  'native_device_mapping live_device_mapping_matches_engine') event=device_child ;;
  'native_memory live_memory_limits_and_effects_match_engine') event=memory_child ;;
  'native_capabilities live_named_capabilities_match_engine') event=capabilities_child ;;
  'native_logging live_logging_matches_engine') event=logging_child ;;
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
                   "NATIVE_PIDS_CANDIDATE_SHA": context["candidate_sha"], "NATIVE_NOFILE_CANDIDATE_SHA": context["candidate_sha"], "NATIVE_DEVICE_MAPPING_CANDIDATE_SHA": context["candidate_sha"], "NATIVE_MEMORY_CANDIDATE_SHA": context["candidate_sha"], "NATIVE_CAPABILITIES_CANDIDATE_SHA": context["candidate_sha"], "NATIVE_LOGGING_CANDIDATE_SHA": context["candidate_sha"],
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
                        ["prebuild", "pids_child", "pids_reader", "nofile_child", "nofile_reader", "device_child", "device_reader", "memory_child", "memory_reader", "capabilities_child", "capabilities_reader", "logging_child", "logging_reader", "complete", "teardown"])
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
        sequence = ["prebuild", "pids_child", "pids_reader", "nofile_child", "nofile_reader", "device_child", "device_reader", "memory_child", "memory_reader", "capabilities_child", "capabilities_reader", "logging_child", "logging_reader"]
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


    def test_actual_observer_program_reports_only_fixed_failing_site_with_inert_commands(self):
        source = (ROOT / "src/native_nofile_tests.rs").read_text()
        program = source.split('const OBSERVE: &str = r#"', 1)[1].split('"#;', 1)[0]
        # All existing commands are inert shell functions; no host/guest procfs or runtime is read.
        stubs = r'''test(){ if command test "$site" = "$FAIL_SITE";then return 1;fi;return 0; }
[(){ if command test "$1" = -f;then command test "$FAIL_SITE" != reportwait;else command test "$1" "$2" "$3";fi; }
id(){ printf '0\n'; }
seq(){ printf '1\n'; }
sleep(){ command test "$FAIL_SITE" != reportwait; }
awk(){ if command test "$site" = "$FAIL_SITE";then return 1;fi;printf '2\n'; }
cmp(){ command test "$FAIL_SITE" != workerargv; }
cat(){ command test "$FAIL_SITE" != transcript; }
'''
        sites = ("rootuid", "rootgid", "reportwait", "reportfile", "reportlink", "workererror",
                 "workerpid", "workerexe", "workerargv", "transcript", "parentlimits", "workerlimits")
        for site in (*sites, "none"):
            result = subprocess.run(["sh", "-c", stubs + program, "PRIVATE_NOFILE_WIRING_CANARY", "inert-worker"],
                                    env={**os.environ, "FAIL_SITE": site}, capture_output=True, timeout=3, check=False)
            with self.subTest(site=site):
                self.assertEqual(result.returncode, 0 if site == "none" else 1)
                self.assertEqual(result.stderr, b"" if site == "none" else
                                 f"DOCKERLENS_NATIVE_NOFILE_OBSERVER: site={site}\n".encode())

    def test_actual_rust_observer_parser_and_work_freezing_without_workspace_build(self):
        health = (ROOT / "src/native_health_metadata_tests.rs").read_text()
        nofile = (ROOT / "src/native_nofile_tests.rs").read_text()
        begin = health.index("#[derive(Clone, Copy, Debug, Eq, PartialEq)]\nenum NofileObserverSite")
        definitions = health[begin:health.index("struct HealthRun {", begin)]
        cases = nofile[nofile.index("const CASES:"):nofile.index("const REQUESTS:")]
        begin = nofile.index("#[derive(Clone, Copy, Debug, Eq, PartialEq)]\nenum NofileOperation")
        definitions += cases + nofile[begin:nofile.index("#[derive(Clone, Copy, Debug, Eq, PartialEq)]\nenum NofileCleanupRefusal", begin)]
        controls = r'''fn main() {
    use std::os::unix::process::ExitStatusExt;
    let failed = std::process::ExitStatus::from_raw(1 << 8);
    let run = HealthRun { nofile_command_observation: Some(NofileCommandObservation::default()) };
    let diagnostics = NofileDiagnostics::default();
    for site in NofileObserverSite::ALL {
        let record = format!("DOCKERLENS_NATIVE_NOFILE_OBSERVER: site={}\n", site.name());
        assert_eq!(NofileObserverSite::from_capture(record.as_bytes()), Some(site));
        for invalid in [record.repeat(2), record.trim_end().to_string(), record.replace(site.name(), "PRIVATE_CANARY"),
                        format!("{record}\0"), format!("{record}{}", "x".repeat(8192))] {
            assert_eq!(NofileObserverSite::from_capture(invalid.as_bytes()), None);
        }
        diagnostics.select(&run, 0, NofileRole::Oracle, NofileOperation::Observe);
        let observation = run.nofile_command_observation.as_ref().unwrap();
        observation.observe_stderr(failed, record.as_bytes());
        let frozen = diagnostics.failure(&run).unwrap();
        assert!(frozen.ends_with(&format!(" observed_termination=exit code=1 observer_site={}", site.name())));
        assert!(frozen.len() <= 256);
        observation.reset();
        assert!(observation.observer_site.get().is_none());
        assert!(observation.first_failure.get().is_none());
        assert!(!diagnostics.failure(&run).unwrap().contains("observer_site="));
        assert!(frozen.contains("observer_site="));
        observation.observe_stderr(std::process::ExitStatus::from_raw(0), record.as_bytes());
        assert!(observation.observer_site.get().is_none());
        diagnostics.select(&run, 0, NofileRole::Oracle, NofileOperation::Create);
        observation.observe_stderr(failed, record.as_bytes());
        assert!(!diagnostics.failure(&run).unwrap().contains("observer_site="));
        observation.begin_capture();
        assert!(observation.observer_site.get().is_none());
    }
}'''
        with tempfile.TemporaryDirectory(prefix="dl-nofile-observer-") as directory:
            root = Path(directory)
            (root / "observer.rs").write_text("use std::cell::Cell;\n" + definitions +
                "struct HealthRun { nofile_command_observation: Option<NofileCommandObservation> }\n" + controls)
            built = subprocess.run(["rustc", "--edition=2024", str(root / "observer.rs"), "-o", str(root / "observer")],
                                   cwd=ROOT, capture_output=True, timeout=30, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run([str(root / "observer")], capture_output=True, timeout=3, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_observer_suffix_projects_only_for_failed_observe_and_never_cleanup(self):
        original = self.failure_line(operation="observe", code="1")
        sites = ("rootuid", "rootgid", "reportwait", "reportfile", "reportlink", "workererror",
                 "workerpid", "workerexe", "workerargv", "transcript", "parentlimits", "workerlimits")
        for site in sites:
            work = original.rstrip(b"\n") + f" observer_site={site}\n".encode()
            cleanup = self.cleanup_line(termination="unknown", code="none")
            result, _calls, _dates = self.wrapper(self.failure_transcript(work, cleanup), 101)
            self.assertIn(work, result.stderr)
            self.assertIn(cleanup, result.stderr)
            self.assertNotIn(b"first_observed_termination=exit code=1", result.stderr)
        for work in (original.rstrip(b"\n") + b" observer_site=PRIVATE_NOFILE_WIRING_CANARY\n",
                     self.failure_line().rstrip(b"\n") + b" observer_site=workerexe\n",
                     self.failure_line(operation="observe", termination="unknown", code="none").rstrip(b"\n") + b" observer_site=workerexe\n"):
            result, _calls, _dates = self.wrapper(self.failure_transcript(work), 101)
            self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_FAILURE:", result.stderr)
            self.assertNotIn(SECRET, result.stderr)

    @staticmethod
    def failure_line(case="soft64_hard128", role="oracle", operation="create", termination="exit", code="125"):
        return (f"DOCKERLENS_NATIVE_NOFILE_FAILURE: caller_case={case} caller_role={role} caller_operation={operation} "
                f"observed_termination={termination} code={code}\n").encode()

    @staticmethod
    def cleanup_line(reason="inner_unverified", termination="exit", code="7"):
        return (f"DOCKERLENS_NATIVE_NOFILE_CLEANUP_REFUSAL: reason={reason} "
                f"first_observed_termination={termination} code={code}\n").encode()

    @staticmethod
    def failure_transcript(work=b"", cleanup=b""):
        prefix = b"DOCKERLENS_NATIVE_CHECK: nofile_context\nDOCKERLENS_NATIVE_CHECK: nofile_effects\n"
        panic = f"thread '{SELECTED}' panicked at src/native_health_metadata_tests.rs:541:9:\n".encode() + SECRET + b"\n"
        if work:
            prefix += panic
        else:
            prefix += b"DOCKERLENS_NATIVE_CHECK: nofile_capture\n"
        result = prefix + b"DOCKERLENS_NATIVE_CHECK: nofile_cleanup\n" + (HANDOFF if cleanup else b"") + work + cleanup
        if cleanup and not work:
            result += f"thread '{SELECTED}' panicked at src/native_lifecycle_tests.rs:212:5:\n".encode()
        return result

    def test_closed_work_and_cleanup_failures_remain_independent_and_in_order(self):
        work, cleanup = self.failure_line(), self.cleanup_line()
        for work_record, cleanup_record in ((work, b""), (b"", cleanup), (work, cleanup)):
            result, calls, dates = self.wrapper(self.failure_transcript(work_record, cleanup_record), 101)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 2)
            self.assertEqual(dates, ["date"])
            self.assertEqual(work in result.stderr, bool(work_record))
            self.assertEqual(cleanup in result.stderr, bool(cleanup_record))
            if work_record and cleanup_record:
                self.assertLess(result.stderr.index(work), result.stderr.index(cleanup))
        for termination, code in (("exit", "124"), ("exit", "130"), ("exit", "143"), ("signal", "9"), ("unknown", "none")):
            line = self.failure_line(termination=termination, code=code)
            result, _calls, _dates = self.wrapper(self.failure_transcript(line), 101)
            self.assertIn(line, result.stderr)
        line = self.cleanup_line("ownership_guard", "unknown", "none")
        result, _calls, _dates = self.wrapper(self.failure_transcript(cleanup=line), 101)
        self.assertIn(line, result.stderr)
        self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_FAILURE:", result.stderr)
        result, _calls, _dates = self.wrapper(self.failure_transcript(work, line), 101)
        self.assertIn(work, result.stderr)
        self.assertIn(line, result.stderr)
        self.assertNotIn(b"first_observed_termination=exit code=125", result.stderr)

    def test_handoff_requires_complete_pair_after_terminal_cleanup_before_projection(self):
        work, cleanup = self.failure_line(), self.cleanup_line()
        complete = self.failure_transcript(work, cleanup)
        # Cut on a complete work-record newline between the producer's two writes.
        # It is a valid work record in isolation, but the retained handoff proves
        # that cleanup refusal also exists and cannot be silently dropped.
        cut = complete[:complete.index(cleanup)]
        self.assertTrue(cut.endswith(work))
        impossible = (
            cut,
            complete.replace(HANDOFF + work, work + HANDOFF),
            cut + HANDOFF,
            self.failure_transcript(work) + HANDOFF,
        )
        for output in impossible:
            result, calls, dates = self.wrapper(output, 101)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 2)
            self.assertEqual(dates, ["date"])
            self.assertIn(b"(exit 101)", result.stderr)
            self.assertIn(HANDOFF.rstrip(), result.stderr)
            self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_FAILURE:", result.stdout + result.stderr)
            self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_CLEANUP_REFUSAL:", result.stdout + result.stderr)
        for work_record, cleanup_record in ((work, b""), (b"", cleanup), (work, cleanup)):
            result, _calls, _dates = self.wrapper(self.failure_transcript(work_record, cleanup_record), 101)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(work in result.stderr, bool(work_record))
            self.assertEqual(cleanup in result.stderr, bool(cleanup_record))
        # Context/preflight can fail before nofile_effects; verified cleanup
        # still permits its sole work record without an outer teardown handoff.
        context = self.failure_line("all", "none", "context", "unknown", "none")
        preflight = self.failure_transcript(context).replace(b"DOCKERLENS_NATIVE_CHECK: nofile_effects\n", b"")
        result, _calls, _dates = self.wrapper(preflight, 101)
        self.assertIn(context, result.stderr)
        self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_CLEANUP_REFUSAL:", result.stderr)

    def test_closed_case_roles_and_noncommand_boundaries_keep_unknown_termination(self):
        for case in ("soft64_hard128", "soft128_hard128", "soft64_hard_unlimited", "both_unlimited"):
            for role in ("oracle", "rendered"):
                line = self.failure_line(case, role, "observe", "exit", "1")
                result, _calls, _dates = self.wrapper(self.failure_transcript(line), 101)
                self.assertIn(line, result.stderr)
        for case, role, operation, termination, code in (
                ("all", "none", "context", "unknown", "none"),
                ("soft64_hard128", "pair", "pair_comparison", "unknown", "none"),
                ("all", "rendered", "capacity_comparison", "unknown", "none"),
                ("all", "none", "daemon_health", "exit", "7"),
                ("all", "none", "acquisition", "unknown", "none")):
            line = self.failure_line(case, role, operation, termination, code)
            result, _calls, _dates = self.wrapper(self.failure_transcript(line), 101)
            self.assertIn(line, result.stderr)
        from test_native_pids_wiring import PidsWiringTests
        line = self.failure_line()
        result, _trace = PidsWiringTests.wrapper(self, line.decode() + SUCCESS.decode(), status=0)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_", result.stdout + result.stderr)
        self.assertNotIn(b"required native test passed", result.stdout + result.stderr)

    def test_nofile_caller_context_rejects_malformed_stale_private_and_contradictory_records(self):
        work, cleanup = self.failure_line(), self.cleanup_line()
        invalid = [work + work, cleanup + work, work + cleanup + cleanup,
                   work.replace(b"caller_role=oracle", b"caller_role=pair"),
                   work.replace(b"caller_case=soft64_hard128", b"caller_case=all"),
                   work.replace(b"caller_operation=create", b"caller_operation=witness"),
                   work.replace(b"code=125", b"code=0"), work.replace(b"code=125", b"code=0125"),
                   self.failure_line(termination="signal", code="65"),
                   work.replace(b"code=125", b"code=256"), work.replace(b"observed_termination=exit", b"observed_termination=unknown"),
                   b"\x1b[31m" + work, work.replace(b"caller_role=oracle", b"caller_role=\x1b[31moracle"),
                   work.rstrip(b"\n") + b" " + SECRET + b"\n", work.replace(b"\n", b"\r\n"),
                   work.replace(b"\n", b"\0" + SECRET + b"\n"),
                   self.cleanup_line("ownership_guard", "exit", "125"),
                   b"DOCKERLENS_NATIVE_NOFILE_FAILURE: " + SECRET + b"\n",
                   work + b"DOCKERLENS_NATIVE_PIDS_MEASUREMENT_REFUSAL: code=pids-eof\n"]
        for records in invalid:
            result, _calls, _dates = self.wrapper(self.failure_transcript(records), 101)
            self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_", result.stdout + result.stderr)
        for output in (work, self.failure_transcript(cleanup=cleanup).replace(HANDOFF, b"") + HANDOFF,
                       self.failure_transcript(cleanup=cleanup) + HANDOFF,
                       self.failure_transcript(work).replace(b"DOCKERLENS_NATIVE_CHECK: nofile_cleanup\n", b""),
                       self.failure_transcript(cleanup=cleanup).replace(HANDOFF, b""),
                       self.failure_transcript(work).rstrip(b"\n")):
            result, _calls, _dates = self.wrapper(output, 101)
            self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_", result.stdout + result.stderr)
        for status in (0, 101):
            result, _calls, _dates = self.wrapper(self.failure_transcript(b"\x1b[31m" + work) + SUCCESS, status)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_", result.stdout + result.stderr)
            result, _calls, _dates = self.wrapper(self.failure_transcript(work) + SUCCESS, status)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_", result.stdout + result.stderr)
            self.assertNotIn(b"required native test passed", result.stdout + result.stderr)
        result, _calls, _dates = self.wrapper()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(b"DOCKERLENS_NATIVE_NOFILE_", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
