"""Mandatory hostname selection, private diagnostics and inert registration."""

import json
import os
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_hostname"
TEST = "live_hostname_matches_engine"
SELECTED = f"native_health_metadata_tests::lifecycle::hostname::{TEST}"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
SECRET = "PRIVATE_HOSTNAME_CANARY"
HANDOFF = "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"


class HostnameWiringTests(unittest.TestCase):
    def wrapper(self, output=SUCCESS, status=0, listing=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            trace = root / "trace"
            cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["TRACE"], "a") as output:
    output.write(json.dumps({"args":sys.argv[1:],
        "deadline":os.environ.get("NATIVE_HOSTNAME_DEADLINE_EPOCH"),
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
            calls = [json.loads(line) for line in trace.read_text().splitlines()]
            return result, calls, began, ended

    def test_twenty_second_registration_preserves_existing_protocol_and_private_reader(self):
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', harness, re.M)
        self.assertEqual(len(calls), 24)
        self.assertEqual(calls[21], (TARGET, TEST))
        self.assertEqual(calls.count((TARGET, TEST)), 1)
        owner = harness.index('(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n')
        end = harness.index('\n)\n', owner)
        self.assertIn(f"{TARGET} {TEST}", harness[owner:end])
        reader = harness.index('python3 "$script_dir/native_hostname_proof.py"')
        emitter = harness.index('python3 "$script_dir/native-evidence.py"')
        self.assertLess(end, reader)
        self.assertLess(reader, harness.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', end))
        self.assertLess(reader, emitter)
        self.assertIn('export NATIVE_HOSTNAME_PROOF_PATH="$run_dir/hostname-v1.json"', harness)
        self.assertIn('export NATIVE_HOSTNAME_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', harness)
        invocation = harness[reader:harness.index('\n\n', reader)]
        for independent in ('"$run_dir"', '"$NATIVE_HOSTNAME_CANDIDATE_SHA"', '"$run_id"', '"$lane"',
                            '"$server_version"', '"$api_version"', '"$expected_mode"', '"$installed_docker_package"',
                            '"$NATIVE_FIXTURE_IMAGE"', '"$image"', '"$NATIVE_OUTER_CONTAINER_ID"', '"$NATIVE_BIND_RELABEL_DAEMON_UID"'):
            self.assertIn(independent, invocation)
        self.assertNotIn('"$NATIVE_HOSTNAME_PROOF_PATH"', invocation)
        self.assertIn('#[path = "native_hostname_tests.rs"]\nmod hostname;',
                      (ROOT / "src/native_lifecycle_tests.rs").read_text())
        self.assertIn('"ContainerHostname": ["ContainerHostname"]', (ROOT / "scripts/native-evidence.py").read_text())

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
        for listing in ("", f"foreign::{TEST}: test", f"{SELECTED}: test\n{SELECTED}: test"):
            result, calls, _, _ = self.wrapper(listing=listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 1)
        for output, status in ((SUCCESS.replace("1 passed", "0 passed"), 0),
                               (SUCCESS.replace("1 passed", "2 passed"), 0), (FAILED, 1), (SUCCESS, 17),
                               (HANDOFF + "\n" + SUCCESS, 0)):
            result, _, _, _ = self.wrapper(output=output, status=status)
            self.assertNotEqual(result.returncode, 0)

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


if __name__ == "__main__":
    unittest.main()
