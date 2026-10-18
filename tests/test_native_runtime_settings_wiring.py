"""Exact two-family integration controls; no Cargo or native Engine execution."""

import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
import unittest

from test_native_shm_size_wiring import ORIGINAL_CALLS

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = ("supplementary_groups", "kernel_settings")
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
HANDOFF = "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"
SECRET = "PRIVATE_RUNTIME_SETTINGS_CANARY"


class RuntimeSettingsWiringTests(unittest.TestCase):
    def wrapper(self, family, output=SUCCESS, status=0, listing=None):
        selected = f"native_health_metadata_tests::lifecycle::{family}::live_{family}_match_engine"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo, trace = root / "cargo", root / "trace"
            cargo.write_text(r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"args":sys.argv[1:],
        "deadline":os.environ.get("NATIVE_" + os.environ["FAMILY"].upper() + "_DEADLINE_EPOCH"),
        "shared":os.environ.get("NATIVE_LIFECYCLE_DEADLINE_EPOCH"),
        "owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")}) + "\n")
if "--list" in sys.argv:
    print(os.environ["LISTING"])
else:
    print(os.environ["OUTPUT"])
    sys.exit(int(os.environ["STATUS"]))
''')
            cargo.chmod(0o700)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", TRACE=str(trace), FAMILY=family,
                       LISTING=f"{selected}: test" if listing is None else listing,
                       OUTPUT=output, STATUS=str(status),
                       NATIVE_LIFECYCLE_CLEANUP_OWNER="native_conformance_outer_v1")
            began = int(time.time())
            result = subprocess.run([str(ROOT / "scripts/run-exact-native-test.sh"),
                                     "native_" + family, "live_" + family + "_match_engine"],
                                    env=env, capture_output=True, text=True, timeout=10, check=False)
            ended = int(time.time())
            return result, [json.loads(line) for line in trace.read_text().splitlines()], began, ended

    def test_exact_26_calls_preserve_first_24_and_separate_owner_scopes(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)
        first24 = ORIGINAL_CALLS + [("native_shm_size", "live_shm_size_effects_match_engine")]
        self.assertEqual(calls[:26], first24 + [("native_" + family, "live_" + family + "_match_engine")
                                         for family in FAMILIES])
        self.assertEqual(calls[26:27], [("native_pids_limit", "live_pids_limit_effects_match_engine")])
        self.assertEqual(calls[27:], [("native_nofile", "live_nofile_limits_and_effects_match_engine")])
        prefix = '(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n'
        self.assertEqual(source.count(prefix), 6)
        previous = source.index('python3 "$script_dir/native_shm_size_proof.py"')
        for family in FAMILIES:
            call = f'"$(dirname "$0")/run-exact-native-test.sh" native_{family} live_{family}_match_engine'
            block = prefix + call + '\n)'
            self.assertEqual(source.count(block), 1)
            self.assertLess(previous, source.index(block))
            reader = source.index(f'python3 "$script_dir/native_{family}_proof.py"')
            self.assertLess(source.index(block), reader)
            invocation = source[reader:source.index('\n\n', reader)].replace('\\\n', ' ')
            expected = ['python3', f'$script_dir/native_{family}_proof.py', '$run_dir',
                        f'$NATIVE_{family.upper()}_CANDIDATE_SHA', '$run_id', '$lane', '$server_version',
                        '$api_version', '$expected_mode', '$installed_docker_package', '$NATIVE_FIXTURE_IMAGE',
                        '$image', '$NATIVE_OUTER_CONTAINER_ID', '$NATIVE_BIND_RELABEL_DAEMON_UID']
            self.assertEqual(shlex.split(invocation), expected)
            self.assertIn(f'export NATIVE_{family.upper()}_PROOF_PATH="$run_dir/{family.replace("_", "-")}-v1.json"', source)
            self.assertIn(f'export NATIVE_{family.upper()}_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', source)
            previous = reader
        self.assertLess(previous, source.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', previous))

    def test_exact_selection_single_deadline_and_fail_closed_summary(self):
        for family in FAMILIES:
            with self.subTest(family=family):
                selected = f"native_health_metadata_tests::lifecycle::{family}::live_{family}_match_engine"
                result, calls, began, ended = self.wrapper(family)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 2)
                self.assertIn("--lib", calls[0]["args"])
                self.assertEqual(calls[1]["args"][-4:], ["--", "--ignored", "--exact", selected])
                self.assertEqual(calls[1]["deadline"], calls[1]["shared"])
                self.assertTrue(began + 180 <= int(calls[1]["deadline"]) <= ended + 180)
                self.assertEqual(calls[1]["owner"], "native_conformance_outer_v1")
                for listing in ("", "foreign: test", f"{selected}: test\n{selected}: test"):
                    result, calls, _, _ = self.wrapper(family, listing=listing)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(len(calls), 1)
                for output in (SUCCESS.replace("1 passed", "0 passed"), SUCCESS.replace("1 passed", "2 passed"),
                               HANDOFF + "\n" + SUCCESS,
                               "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + SUCCESS):
                    self.assertNotEqual(self.wrapper(family, output)[0].returncode, 0)

    def test_first_causal_panic_cleanup_and_private_payloads(self):
        for family in FAMILIES:
            with self.subTest(family=family):
                selected = f"native_health_metadata_tests::lifecycle::{family}::live_{family}_match_engine"
                output = (f"DOCKERLENS_NATIVE_CHECK: {family}_effects\n"
                          f"thread '{selected}' panicked at src/native_{family}_tests.rs:123:4:\n{SECRET}\n"
                          f"DOCKERLENS_NATIVE_CHECK: {family}_cleanup\n"
                          f"thread '{selected}' panicked at src/native_{family}_tests.rs:456:8:\n"
                          "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + HANDOFF + "\n" + SUCCESS)
                result = self.wrapper(family, output, 101)[0]
                self.assertNotEqual(result.returncode, 0)
                for fixed in ("exit 101", f"{family}_effects", "lifecycle_cleanup_unverified", HANDOFF,
                              f"source=native_{family}_tests line=123 column=4"):
                    self.assertIn(fixed, result.stderr)
                for private in (SECRET, "line=456"):
                    self.assertNotIn(private, result.stdout + result.stderr)
                result = self.wrapper(family, f"thread 'worker' panicked at /private/{SECRET}:1:1:\n" + output, 101)[0]
                self.assertIn(f"source=native_{family}_tests location=unavailable", result.stderr)
                self.assertNotIn("line=123", result.stderr)
                self.assertNotIn(SECRET, result.stdout + result.stderr)
                result = self.wrapper(family, f"DOCKERLENS_NATIVE_CHECK: {family}_{SECRET}\n" + SUCCESS)[0]
                self.assertNotIn(SECRET, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
