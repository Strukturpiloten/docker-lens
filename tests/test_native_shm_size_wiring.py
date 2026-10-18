"""Canonical source-contract wiring; synthetic controls do not qualify Docker."""

import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_shm_size"
TEST = "live_shm_size_effects_match_engine"
SELECTED = f"native_health_metadata_tests::lifecycle::shm_size::{TEST}"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
ORIGINAL_CALLS = [
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
]


class ShmSizeWiringTests(unittest.TestCase):
    def wrapper(self, output=SUCCESS, status=0, listing=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo, trace = root / "cargo", root / "trace"
            cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"args":sys.argv[1:],
        "deadline":os.environ.get("NATIVE_SHM_SIZE_DEADLINE_EPOCH"),
        "shared":os.environ.get("NATIVE_LIFECYCLE_DEADLINE_EPOCH"),
        "owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")}) + "\\n")
if "--list" in sys.argv:
    print(os.environ["LISTING"])
else:
    print(os.environ["OUTPUT"])
    sys.exit(int(os.environ["STATUS"]))
''')
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", TRACE=str(trace),
                       LISTING=f"{SELECTED}: test" if listing is None else listing,
                       OUTPUT=output, STATUS=str(status), NATIVE_LIFECYCLE_CLEANUP_OWNER="native_conformance_outer_v1")
            began = int(time.time())
            result = subprocess.run([str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, TEST],
                                    env=env, capture_output=True, text=True, timeout=10, check=False)
            ended = int(time.time())
            return result, [json.loads(line) for line in trace.read_text().splitlines()], began, ended

    def test_twenty_fourth_registration_preserves_first_twenty_three_and_six_child_block_bytes(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        call_prefix = '"$(dirname "$0")/run-exact-native-test.sh" '
        calls = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)
        self.assertEqual(calls, ORIGINAL_CALLS + [(TARGET, TEST)])
        scope_prefix = '(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n'
        old_block = scope_prefix + "\n".join(call_prefix + " ".join(call) for call in ORIGINAL_CALLS[16:22]) + '\n)'
        new_block = scope_prefix + call_prefix + f'{TARGET} {TEST}\n)'
        self.assertEqual(source.count(old_block), 1)
        self.assertEqual(source.count(new_block), 1)
        self.assertEqual(source.count(scope_prefix), 2)
        self.assertLess(source.index('COMMAND_CLEAR_PROOF\n\n'), source.index(new_block))
        reader = source.index('python3 "$script_dir/native_shm_size_proof.py"')
        self.assertLess(source.index(new_block), reader)
        self.assertLess(reader, source.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', reader))
        invocation = source[reader:source.index('\n\n', reader)].replace('\\\n', ' ')
        self.assertEqual(len(shlex.split(invocation)) - 2, 12)
        for independent in ('"$run_dir"', '"$NATIVE_SHM_SIZE_CANDIDATE_SHA"', '"$run_id"', '"$lane"',
                            '"$server_version"', '"$api_version"', '"$expected_mode"', '"$installed_docker_package"',
                            '"$NATIVE_FIXTURE_IMAGE"', '"$image"', '"$NATIVE_OUTER_CONTAINER_ID"', '"$NATIVE_BIND_RELABEL_DAEMON_UID"'):
            self.assertIn(independent, invocation)
        self.assertIn('export NATIVE_SHM_SIZE_PROOF_PATH="$run_dir/shm-size-v1.json"', source)
        self.assertIn('export NATIVE_SHM_SIZE_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', source)
        self.assertIn('#[path = "native_shm_size_tests.rs"]\nmod shm_size;',
                      (ROOT / "src/native_lifecycle_tests.rs").read_text())

    def test_exact_ignored_selection_shared_original_deadline_and_no_silent_skip(self):
        result, calls, began, ended = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertIn("--lib", calls[0]["args"])
        self.assertEqual(calls[1]["args"][-4:], ["--", "--ignored", "--exact", SELECTED])
        self.assertEqual(calls[1]["deadline"], calls[1]["shared"])
        self.assertTrue(began + 180 <= int(calls[1]["deadline"]) <= ended + 180)
        self.assertEqual(calls[1]["owner"], "native_conformance_outer_v1")
        for listing in ("", "foreign: test", f"{SELECTED}: test\n{SELECTED}: test"):
            result, calls, _, _ = self.wrapper(listing=listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 1)
        for output in (SUCCESS.replace("1 passed", "0 passed"), SUCCESS.replace("1 passed", "2 passed"),
                       'DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n' + SUCCESS,
                       'DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required\n' + SUCCESS):
            self.assertNotEqual(self.wrapper(output)[0].returncode, 0)

    def test_fixed_first_panic_and_causal_marker_preserve_failure_without_private_payload(self):
        output = (f"DOCKERLENS_NATIVE_CHECK: shm_size_effects\n"
                  f"thread '{SELECTED}' panicked at src/native_shm_size_tests.rs:123:4:\nPRIVATE_SHM_CANARY\n"
                  f"DOCKERLENS_NATIVE_CHECK: shm_size_cleanup\n"
                  f"DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n{FAILED}")
        result = self.wrapper(output, 101)[0]
        for fixed in ("(exit 101)", "shm_size_effects", "lifecycle_cleanup_unverified",
                      "source=native_shm_size_tests line=123 column=4"):
            self.assertIn(fixed, result.stderr)
        self.assertNotIn("PRIVATE_SHM_CANARY", result.stdout + result.stderr)
        result = self.wrapper("thread 'worker' panicked at /private/PRIVATE_SHM_CANARY:1:1:\n" + output, 101)[0]
        self.assertIn("source=native_shm_size_tests location=unavailable", result.stderr)
        self.assertNotIn("line=123", result.stderr)
        self.assertNotIn("PRIVATE_SHM_CANARY", result.stdout + result.stderr)

    def source(self):
        return re.sub(r"\s+", " ", (ROOT / "src/native_shm_size_tests.rs").read_text())

    def test_finite_cases_use_borrowed_six_slot_ownership_and_once_only_cleanup(self):
        source = self.source()
        self.assertRegex(source, r'\("omitted", None\).*\("one_mib", Some\(1_048_576\)\).*\("two_mib", Some\(2_097_152\)\)')
        for text in ('run.ids = vec![None; 6]', 'run.attempted = vec![false; 6]',
                     'let owner = BoundOuterCleanupOwner::bind(&run)', 'image_snapshot(&run)',
                     'outer_context(&run)', '!run.image_attempted && run.derived_id.is_none()'):
            self.assertIn(text, source)
        self.assertEqual(source.count('cleanup(&mut run)'), 1)
        self.assertNotIn('run.cleanup()', source)
        self.assertNotIn('derive_image(', source)
        self.assertNotIn('impl Drop', source)
        cleanup = source.index('cleanup(&mut run)')
        terminal = source.index('terminal_cleanup(&mut run, &owner, disposition)')
        verified = source.index('require_verified_result(result, disposition)')
        publication = source.index('target.publish(&proof)')
        self.assertLess(cleanup, terminal)
        self.assertLess(terminal, verified)
        self.assertLess(verified, source.index('image_snapshot(&run) == image'))
        self.assertLess(verified, publication)
        self.assertIn('CleanupDisposition::OuterTeardownRequired', source)
        self.assertIn('cleanup_calls == 54', source)

    def test_cli_and_literal_requests_keep_omission_separate_from_native_default(self):
        source = self.source()
        create = source.split('fn create_shm(', 1)[1].split('fn configured_shm(', 1)[0]
        self.assertIn('if let Some(size) = authored', create)
        self.assertIn('args.extend(["--shm-size".into(), size.to_string()])', create)
        self.assertIn('body["HostConfig"]["ShmSize"] = json!(size)', create)
        self.assertIn('"HostConfig":{}', create)
        self.assertNotIn('"IpcMode"', create)
        self.assertEqual(create.count('run.attempted[index] = true'), 2)
        self.assertLess(create.index('run.attempted[index] = true'), create.index('let bytes = docker(run, &args)'))
        self.assertIn('request == json!({"method":"POST","path":path,"body":body})', create)
        self.assertIn('measured[0].capacity == measured[1].capacity', source)
        self.assertIn('measured[0].capacity >= CONTROL_BYTES', source)
        self.assertIn('const CONTROL_BYTES: u64 = 3_145_728', source)
        self.assertNotIn('67_108_864', source)
        self.assertNotIn('67108864', source)

    def test_independent_effects_keep_all_six_canaries_and_private_ipc_live(self):
        source = self.source()
        for text in ('stat -f -c %T /dev/shm', 'stat -f -c %S /dev/shm', 'stat -f -c %b /dev/shm',
                     'readlink /proc/self/ns/ipc', 'namespaces.insert(observed.ipc)',
                     'value["HostConfig"]["IpcMode"] == "private"',
                     'No space left on device', 'cmp /dev/shm/dl-shm-payload -',
                     'stat -c %s /dev/shm/dl-shm-payload', 'own_value_retained_after_all_six_seeds'):
            self.assertIn(text, source)
        self.assertLess(source.index('measured.push(observed)'), source.index('effect_shm(&run, index, observed)'))
        self.assertIn('test ! -e /dev/shm/dl-shm-canary', source)
        self.assertIn('test ! -L /dev/shm/dl-shm-canary', source)
        self.assertIn('test ! -L /dev/shm/dl-shm-payload', source)
        self.assertIn('if failure=$(dd ', source)
        self.assertIn('if authored.is_some()', source)

    def test_one_batched_product_capture_charges_before_io_and_checks_decoded_evidence(self):
        source = self.source()
        capture = source.split('fn acquire_shm(', 1)[1].split('#[test]', 1)[0]
        self.assertEqual(capture.count('let capture = acquire('), 1)
        self.assertIn('const ACQUISITION_CALLS: usize = 16', source)
        self.assertIn('const ACQUISITION_BYTES: usize = 512 * 1024', source)
        for text in ('run.calls.set(calls)', 'run.bytes.set(bytes)'):
            self.assertLess(capture.index(text), capture.index('let capture = acquire('))
        for text in ('Selector::ContainerIds(selected)', 'max_selected_resources: 6', 'max_expansions: 8',
                     'max_response_bytes: 128 * 1024', 'max_total_bytes: ACQUISITION_BYTES',
                     'elapsed.min(Duration::from_secs(10))', 'checked_sub(Duration::from_secs(46))',
                     'capture.selected_roots().len() == 6', 'capture.route() == CaptureRoute::ExplicitUnixSocket',
                     'exchange.status().code() == 200', 'exchange.api_version()', 'decode_capture(&capture)',
                     'decoded.containers.len() == 6', 'seen.insert(index)', 'Availability::Present',
                     'Origin::Effective', 'Origin::RuntimeAssigned', 'measured[index].capacity',
                     'decoded.version.daemon.observation_id == capture.observation_id()'):
            self.assertIn(text, capture)
        self.assertIn('if run.lane.starts_with("debian11-") { 41 } else { 49 }', capture)
        self.assertIn('"byte_scope":"decoded_response_bodies_only"', capture)
        self.assertIn('"actual_wire_bytes":"not_measured"', capture)
        transport = (ROOT / "src/acquisition.rs").read_text()
        self.assertIn('const MAX_HEADER_BYTES: usize = 16 * 1024', transport)
        self.assertIn('wire.line(64)?', transport)
        self.assertIn('wire.line(MAX_HEADER_BYTES)?', transport)

    def test_original_budgets_remain_closed_and_initial_context_is_separate(self):
        source = self.source()
        parent = (ROOT / "src/native_health_metadata_tests.rs").read_text()
        for text in ('const MAX_CALLS: usize = 400', 'const MAX_BYTES: usize = 4 * 1024 * 1024',
                     'const CLEANUP_CALLS: usize = 100', 'const CLEANUP_BYTES: usize = 2 * 1024 * 1024'):
            self.assertIn(text, parent)
        self.assertIn('bytes + 2 * ORDINARY_ENVELOPE <= MAX_BYTES - CLEANUP_BYTES', source)
        self.assertIn('cleanup_elapsed <= Duration::from_secs(46)', source)
        self.assertIn('started.elapsed() <= Duration::from_secs(180)', source)
        self.assertIn('"accounting":"separate_existing_bound"', source)
        self.assertIn('"max_requests":16,"max_total_bytes":2*1024*1024,"max_elapsed_seconds":15', source)
        self.assertNotIn('run.calls.set(0)', source)
        self.assertNotIn('run.bytes.set(0)', source)
        self.assertNotIn('run.deadline =', source)

    def test_proof_is_private_source_only_and_closed_diagnostics_have_no_dynamic_payload(self):
        source = self.source()
        self.assertIn('ProofTarget::new_for("NATIVE_SHM_SIZE_PROOF_PATH", FILENAME)', source)
        self.assertIn('"NATIVE_SHM_SIZE_CANDIDATE_SHA", "NATIVE_SHM_SIZE_DEADLINE_EPOCH"', source)
        self.assertIn('"capability_admission":[],"catalogue_admission":false', source)
        markers = re.findall(r'eprintln!\("([^"]*)"\)', source)
        self.assertEqual(set(markers), {"DOCKERLENS_NATIVE_CHECK: shm_size_" + step
                                      for step in ("context", "seed", "effects", "capture", "cleanup", "proof")})
        self.assertEqual(source.count('eprintln!('), len(markers))
        self.assertNotIn('TargetCapabilityCatalog', source)
        self.assertIn('fn shm_measurement_refuses_partial_malformed_and_overflowing_effects()', source)
        reader = (ROOT / "scripts/native_shm_size_proof.py").read_text()
        self.assertIn('read_private_proof(path, capture_dir, FILENAME, expected_context, validate_shm_size_proof)', reader)
        self.assertNotIn('subprocess', reader)
        catalogue = (ROOT / "src/reviewed_catalog.rs").read_text()
        for prefix in ("REVIEWED", "UPSTREAM"):
            selected = catalogue.split(f"const {prefix}_CAPABILITIES:", 1)[1].split('];', 1)[0]
            self.assertNotIn('Capability::ShmSize,', selected)


if __name__ == "__main__":
    unittest.main()
