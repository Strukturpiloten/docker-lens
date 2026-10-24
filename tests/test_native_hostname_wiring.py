"""Mandatory hostname selection, private diagnostics and inert registration."""

import json
import os
import re
import shlex
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import test_native_external_network_evidence as external

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_hostname"
TEST = "live_hostname_matches_engine"
SELECTED = f"native_health_metadata_tests::lifecycle::hostname::{TEST}"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
SECRET = "PRIVATE_HOSTNAME_CANARY"
HANDOFF = "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"


def native_calls(source):
    return re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)


class HostnameWiringTests(unittest.TestCase):
    def wrapper(self, output=SUCCESS, status=0, listing=None, list_status=0):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            trace = root / "trace"
            cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["TRACE"], "a") as output:
    output.write(json.dumps({"args":sys.argv[1:],
        "deadline":os.environ.get("NATIVE_HOSTNAME_DEADLINE_EPOCH"),
        "owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER"),
        "shared_deadline":os.environ.get("NATIVE_HEALTH_METADATA_DEADLINE_EPOCH")}) + "\\n")
if "--list" in sys.argv:
    print(os.environ["LISTING"])
    sys.exit(int(os.environ["LIST_STATUS"]))
else:
    print(os.environ["OUTPUT"])
    sys.exit(int(os.environ["STATUS"]))
''')
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", TRACE=str(trace),
                       LISTING=f"{SELECTED}: test" if listing is None else listing,
                       OUTPUT=output, STATUS=str(status), LIST_STATUS=str(list_status),
                       NATIVE_HOSTNAME_DEADLINE_EPOCH="1", NATIVE_LIFECYCLE_CLEANUP_OWNER="native_conformance_outer_v1")
            began = int(time.time())
            result = subprocess.run([str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, TEST],
                                    env=env, capture_output=True, text=True, timeout=10, check=False)
            ended = int(time.time())
            calls = [json.loads(line) for line in trace.read_text().splitlines()]
            return result, calls, began, ended

    def test_twenty_second_registration_preserves_existing_protocol_and_private_reader(self):
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = native_calls(harness)
        self.assertEqual(len(calls), 23)
        self.assertEqual(calls[21], (TARGET, TEST))
        self.assertEqual(calls.count((TARGET, TEST)), 1)
        owner_marker = '(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n'
        original_owner = harness.index(owner_marker)
        original_end = harness.index('\n)\n', original_owner)
        self.assertEqual(native_calls(harness[original_owner:original_end]), calls[16:21])
        self.assertEqual(len(native_calls(harness[original_owner:original_end])), 5)
        owner = harness.index(owner_marker, original_end)
        end = harness.index('\n)\n', owner)
        self.assertEqual(native_calls(harness[owner:end]), [(TARGET, TEST)])
        self.assertEqual(harness.count(owner_marker), 2)
        reader = harness.index('python3 "$script_dir/native_hostname_proof.py"')
        emitter = harness.index('python3 "$script_dir/native-evidence.py"')
        self.assertLess(end, reader)
        self.assertLess(reader, harness.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', end))
        self.assertLess(reader, emitter)
        self.assertLess(reader, harness.index('if [[ -n ${apparmor_profile:-} ]]; then', end))
        self.assertIn('export NATIVE_HOSTNAME_PROOF_PATH="$run_dir/hostname-v1.json"', harness)
        self.assertIn('export NATIVE_HOSTNAME_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', harness)
        invocation = harness[reader:harness.index('\n\n', reader)]
        self.assertEqual(len(shlex.split(invocation.replace('\\\n', ' '))) - 2, 12)
        for independent in ('"$run_dir"', '"$NATIVE_HOSTNAME_CANDIDATE_SHA"', '"$run_id"', '"$lane"',
                            '"$server_version"', '"$api_version"', '"$expected_mode"', '"$installed_docker_package"',
                            '"$NATIVE_FIXTURE_IMAGE"', '"$image"', '"$NATIVE_OUTER_CONTAINER_ID"', '"$NATIVE_BIND_RELABEL_DAEMON_UID"'):
            self.assertIn(independent, invocation)
        self.assertNotIn('"$NATIVE_HOSTNAME_PROOF_PATH"', invocation)
        self.assertIn('#[path = "native_hostname_tests.rs"]\nmod hostname;',
                      (ROOT / "src/native_lifecycle_tests.rs").read_text())
        emitter_source = (ROOT / "scripts/native-evidence.py").read_text()
        self.assertIn('read_hostname_proof(capture_dir / HOSTNAME_FILENAME, capture_dir, external_context)', emitter_source)
        self.assertNotIn('"ContainerHostname": ["ContainerHostname"]', emitter_source)
        protocol = harness[emitter:harness.index('\n  fi\n}', emitter)].replace('\\\n', ' ')
        self.assertEqual(len(shlex.split(protocol)) - 2, 19)
        self.assertNotIn('"$NATIVE_HOSTNAME_PROOF_PATH"', protocol)
        self.assertIn('len(sys.argv) != 20', emitter_source)

    def test_exact_selection_one_deadline_and_no_silent_skip(self):
        result, calls, began, ended = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertIn("--lib", calls[0]["args"])
        self.assertIn("--list", calls[0]["args"])
        self.assertIn(SELECTED, calls[1]["args"])
        self.assertIn("--exact", calls[1]["args"])
        self.assertLessEqual(began + 179, int(calls[1]["deadline"]))
        self.assertLessEqual(int(calls[1]["deadline"]), ended + 180)
        self.assertEqual(calls[1]["owner"], "native_conformance_outer_v1")
        self.assertEqual(calls[1]["deadline"], calls[1]["shared_deadline"])
        wrapper = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        self.assertEqual(wrapper.count('run_deadline_epoch=$(( $(date +%s) + 180 ))'), 1)
        for listing in ("", f"foreign::{TEST}: test", f"{SELECTED}: test\n{SELECTED}: test"):
            result, calls, _, _ = self.wrapper(listing=listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 1)
        result, calls, _, _ = self.wrapper(listing=SECRET, list_status=17)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        for output, status in ((SUCCESS.replace("1 passed", "0 passed"), 0),
                               (SUCCESS.replace("1 passed", "2 passed"), 0), (FAILED, 1), (SUCCESS, 17),
                               (HANDOFF + "\n" + SUCCESS, 0),
                               ("DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + SUCCESS, 0),
                               (SUCCESS.replace("0 failed", "1 failed"), 0),
                               (SUCCESS.replace("0 ignored", "1 ignored"), 0)):
            result, _, _, _ = self.wrapper(output=output, status=status)
            self.assertNotEqual(result.returncode, 0)

    def test_actual_coordinator_fragment_always_reads_immediately_with_independent_arguments(self):
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        marker = '(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n'
        first = harness.index(marker)
        owner = harness.index(marker, first + len(marker))
        fragment = harness[owner:harness.index('"$(dirname "$0")/run-exact-native-test.sh" native_command_clear', owner)]
        for exact_status, reader_status in ((0, 0), (17, 0), (0, 23)):
            with self.subTest(exact=exact_status, reader=reader_status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                trace = root / "trace"
                exact = root / "run-exact-native-test.sh"
                exact.write_text('''#!/usr/bin/python3
import json,os,sys
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"kind":"exact", "args":sys.argv[1:],
        "owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")}) + "\\n")
sys.exit(int(os.environ["EXACT_STATUS"]))
''')
                exact.chmod(0o700)
                (root / "native_hostname_proof.py").write_text('''import json,os,sys
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"kind":"reader", "args":sys.argv[1:],
        "owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")}) + "\\n")
sys.exit(int(os.environ["READER_STATUS"]))
''')
                driver = root / "driver"
                driver.write_text("set -euo pipefail\n" + fragment + "printf 'continued\\n'\n")
                expected = [str(root / "capture"), "a" * 40, "Ab12Cd34", "upstream-rootless",
                            "29.8.1", "1.56", "rootless", "", "independent-fixture", "independent-outer",
                            "f" * 64, "1000"]
                env = {**os.environ, "TRACE": str(trace), "EXACT_STATUS": str(exact_status),
                       "READER_STATUS": str(reader_status), "script_dir": str(root),
                       "NATIVE_HOSTNAME_PROOF_PATH": SECRET,
                       **dict(zip(("run_dir", "NATIVE_HOSTNAME_CANDIDATE_SHA", "run_id", "lane", "server_version",
                                   "api_version", "expected_mode", "installed_docker_package", "NATIVE_FIXTURE_IMAGE",
                                   "image", "NATIVE_OUTER_CONTAINER_ID", "NATIVE_BIND_RELABEL_DAEMON_UID"), expected))}
                env.pop("NATIVE_LIFECYCLE_CLEANUP_OWNER", None)
                env.pop("DOCKERLENS_NATIVE_EVIDENCE_DIR", None)
                result = subprocess.run(["bash", str(driver)], env=env, capture_output=True, text=True, timeout=5)
                calls = [json.loads(line) for line in trace.read_text().splitlines()]
                self.assertEqual(calls[0], {"kind": "exact", "args": [TARGET, TEST],
                                           "owner": "native_conformance_outer_v1"})
                self.assertEqual(len(calls), 1 if exact_status else 2)
                if not exact_status:
                    self.assertEqual(calls[1], {"kind": "reader", "args": expected, "owner": None})
                self.assertEqual(result.returncode, exact_status or reader_status)
                self.assertEqual(result.stdout, "continued\n" if not (exact_status or reader_status) else "")
                self.assertEqual(result.stderr, "")

    def test_only_closed_markers_and_first_numeric_source_site_cross_boundary(self):
        output = (f"DOCKERLENS_NATIVE_CHECK: hostname_effects\n"
                  f"thread '{SELECTED}' panicked at src/native_hostname_tests.rs:123:4:\n{SECRET}\n"
                  f"DOCKERLENS_NATIVE_CHECK: hostname_cleanup\n{FAILED}")
        result, _, _, _ = self.wrapper(output, 1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source=native_hostname_tests line=123 column=4", result.stderr)
        self.assertIn("DOCKERLENS_NATIVE_CHECK: hostname_effects", result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        for private in (f"DOCKERLENS_NATIVE_CHECK: hostname_{SECRET}", f"hostname={SECRET}"):
            result, _, _, _ = self.wrapper(private + "\n" + SUCCESS)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_source_requires_real_hostname_and_preserves_scoped_cleanup(self):
        source = (ROOT / "src/native_hostname_tests.rs").read_text()
        self.assertIn("use super::super::ProofTarget;", source)
        self.assertIn('ProofTarget::new_for("NATIVE_HOSTNAME_PROOF_PATH", FILENAME)', source)
        self.assertIn("struct ProofTarget {", (ROOT / "src/native_health_metadata_tests.rs").read_text())
        self.assertNotIn("PrivateTarget", source)
        for required in ('"--hostname"', '"hostname".into()', 'process_hostname_matches(&output, &expected)',
                         'before["Config"]["Hostname"]', 'before["State"]["StartedAt"] == after["State"]["StartedAt"]',
                         'BoundOuterCleanupOwner::bind(&run)', 'cleanup(&mut run)', 'terminal_cleanup(&mut run, &owner, disposition)',
                         'require_verified_result(result, disposition)', 'image_snapshot(&run) == image && outer_context(&run) == outer'):
            self.assertIn(required, source)
        self.assertIn('body["Hostname"] = json!(hostname)', source)
        self.assertIn('if let Some(hostname) = authored', source)
        self.assertIn('"capability_admission":[]', source)
        self.assertIn('"catalogue_admission":false', source)
        self.assertNotIn("TargetCapabilityCatalog", source)
        self.assertNotIn("run.cleanup()", source)
        self.assertNotIn("run.image_for(", source)
        self.assertNotIn("Command::new(", source)

    def test_first_panic_and_exact_marker_privacy(self):
        for first in (f"thread '{SECRET}' panicked at private-worker.rs:8:2:",
                      f"thread '{SELECTED}' panicked at /private/{SECRET}/src/native_hostname_tests.rs:12:4:",
                      f"thread '{SELECTED}' panicked at src/native_hostname_tests.rs:1234567:4:"):
            output = (f"DOCKERLENS_NATIVE_CHECK: hostname_context\n{first}\n{SECRET}\n"
                      f"DOCKERLENS_NATIVE_CHECK: hostname_effects\n"
                      f"thread '{SELECTED}' panicked at src/native_hostname_tests.rs:999:8:\n"
                      f"DOCKERLENS_NATIVE_CHECK: hostname_cleanup\n{FAILED}")
            result, _, _, _ = self.wrapper(output, 101)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source=native_hostname_tests location=unavailable", result.stderr)
            self.assertNotIn("line=999", result.stderr)
            self.assertNotIn("DOCKERLENS_NATIVE_CHECK: hostname_effects", result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
        for marker in (f"DOCKERLENS_NATIVE_CHECK: hostname_context {SECRET}",
                       "DOCKERLENS_NATIVE_CHECK: hostname_effects\r", "\x1b[31mDOCKERLENS_NATIVE_CHECK: hostname_cleanup"):
            result, _, _, _ = self.wrapper(marker + "\n" + FAILED, 101)
            self.assertNotIn("DOCKERLENS_NATIVE_CHECK:", result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)


class HostnameEvidenceTests(unittest.TestCase):
    run_emit = external.ExternalNetworkEvidenceTests.run_emit
    emit = external.ExternalNetworkEvidenceTests.emit

    def test_all_lanes_emit_only_closed_unadmitted_observation(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            result, path = self.emit(lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout + result.stderr, "")
            raw = path.read_text()
            record = json.loads(raw)
            self.assertEqual(record["hostname_contract"], "hostname-v1")
            self.assertEqual(record["hostname_outcomes"], {
                "admission": "unadmitted", "outcome": "omitted_and_explicit_verified",
            })
            self.assertEqual(len(record["capability_outcome"]), 30 if lane.startswith("debian11-") else 31)
            self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 47 if lane.startswith("debian11-") else 49)
            self.assertNotIn("ContainerHostname", record["capability_outcome"])
            self.assertNotIn("ContainerHostname", record["admitted_shapes"])
            for private in ("dl-host-", "dl-hostname-", "configured_hostname", "process_hostname",
                            "daemon_uid", "a" * 64, "f" * 64, SECRET):
                self.assertNotIn(private, raw)

    def test_missing_hostname_never_publishes_on_any_lane(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            result, path = self.emit(lane, hostname_missing=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(path.exists())
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "native evidence rejected\n")

    def test_stale_partial_cross_context_effect_type_and_custody_refuse_before_publication(self):
        for fault in ("candidate", "outer", "uid", "path", "partial", "effect", "admission", "typed_flag",
                      "unknown", "malformed", "duplicate", "mode", "hardlink", "symlink"):
            with self.subTest(fault=fault):
                result, path = self.emit()
                self.assertEqual(result.returncode, 0, result.stderr)
                proof_path = path.parent.parent / "hostname-v1.json"
                proof = json.loads(proof_path.read_text())
                path.unlink()
                if fault == "candidate":
                    proof["context"]["candidate_sha"] = "e" * 40
                elif fault == "outer":
                    proof["context"]["outer"]["id"] = "e" * 64
                elif fault == "uid":
                    proof["context"]["daemon_uid"] = 1
                elif fault == "path":
                    proof["context"]["outer"]["socket_source"] = "/foreign/socket"
                elif fault == "partial":
                    proof["cases"].pop()
                elif fault == "effect":
                    proof["cases"][1]["containers"][0]["process_hostname"] = SECRET
                elif fault == "admission":
                    proof["capability_admission"] = ["ContainerHostname"]
                elif fault == "typed_flag":
                    proof["catalogue_admission"] = 0
                elif fault == "unknown":
                    proof[SECRET] = SECRET
                proof_path.write_text(json.dumps(proof))
                if fault == "malformed":
                    proof_path.write_text("{" + SECRET)
                elif fault == "duplicate":
                    proof_path.write_text(proof_path.read_text().replace('"schema_version": 1', '"schema_version": 0, "schema_version": 1', 1))
                elif fault == "mode":
                    proof_path.chmod(0o640)
                elif fault == "hardlink":
                    os.link(proof_path, proof_path.with_name("second-link"))
                elif fault == "symlink":
                    moved = proof_path.with_name("moved-private")
                    proof_path.rename(moved)
                    proof_path.symlink_to(moved)
                output = subprocess.run(result.args, capture_output=True, text=True, check=False, timeout=5,
                    env={**os.environ, "NATIVE_FIXTURE_IMAGE": external.legacy.HEALTH_FIXTURE_IMAGE,
                         "NATIVE_OUTER_CONTAINER_ID": "f" * 64, "NATIVE_BIND_RELABEL_DAEMON_UID": "0"})
                self.assertNotEqual(output.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual(output.stdout, "")
                self.assertEqual(output.stderr, "native evidence rejected\n")
                self.assertNotIn(SECRET, output.stdout + output.stderr)


if __name__ == "__main__":
    unittest.main()
