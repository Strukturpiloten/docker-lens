"""Mocked canonical PIDs wiring and private custody; never native qualification."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import test_native_evidence as legacy
import test_native_external_network_evidence as canonical
from test_native_runtime_cohort_wiring import EXPECTED_CALLS

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_pids_limit"
TEST = "live_pids_limit_effects_match_engine"
SELECTED = f"native_health_metadata_tests::lifecycle::pids_limit::{TEST}"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SECRET = "PRIVATE_PIDS_WIRING_CANARY"


class PidsLimitWiringTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit

    def wrapper(self, output=SUCCESS, status=0, listing=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo, trace = root / "cargo", root / "trace"
            cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"args":sys.argv[1:],
        "deadline":os.environ.get("NATIVE_PIDS_LIMIT_DEADLINE_EPOCH"),
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
                       OUTPUT=output, STATUS=str(status),
                       NATIVE_LIFECYCLE_CLEANUP_OWNER="native_conformance_outer_v1")
            began = int(time.time())
            result = subprocess.run([str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, TEST],
                                    env=env, capture_output=True, text=True, timeout=10, check=False)
            ended = int(time.time())
            return result, [json.loads(line) for line in trace.read_text().splitlines()], began, ended

    def test_twenty_seventh_invocation_preserves_prior_calls_and_all_owner_blocks(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        prefix = '"$(dirname "$0")/run-exact-native-test.sh" '
        calls = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)
        self.assertEqual(calls[:26], EXPECTED_CALLS)
        self.assertEqual(calls[26:], [(TARGET, TEST)])
        scope = '(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n'
        old = scope + "\n".join(prefix + " ".join(call) for call in EXPECTED_CALLS[16:22]) + '\n)'
        self.assertEqual(source.count(old), 1)
        for call in EXPECTED_CALLS[23:26] + [(TARGET, TEST)]:
            self.assertEqual(source.count(scope + prefix + " ".join(call) + '\n)'), 1)
        self.assertEqual(source.count(scope), 5)
        kernel_reader = source.index('python3 "$script_dir/native_kernel_settings_proof.py"')
        child = source.index(scope + prefix + f'{TARGET} {TEST}\n)')
        reader = source.index('python3 "$script_dir/native_pids_limit_proof.py"')
        self.assertLess(kernel_reader, child)
        self.assertLess(child, reader)
        self.assertLess(reader, source.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', reader))
        invocation = source[reader:source.index('\n\n', reader)].replace('\\\n', ' ')
        self.assertEqual(len(shlex.split(invocation)) - 2, 12)
        for independent in ('"$run_dir"', '"$NATIVE_PIDS_LIMIT_CANDIDATE_SHA"', '"$run_id"', '"$lane"',
                            '"$server_version"', '"$api_version"', '"$expected_mode"', '"$installed_docker_package"',
                            '"$NATIVE_FIXTURE_IMAGE"', '"$image"', '"$NATIVE_OUTER_CONTAINER_ID"', '"$NATIVE_BIND_RELABEL_DAEMON_UID"'):
            self.assertIn(independent, invocation)
        self.assertIn('export NATIVE_PIDS_LIMIT_PROOF_PATH="$run_dir/pids-limit-v1.json"', source)
        self.assertIn('export NATIVE_PIDS_LIMIT_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', source)

    def test_exact_private_selection_original_deadline_and_numeric_summary_required(self):
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
        result = self.wrapper(SUCCESS, 53)[0]
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("(exit 53)", result.stderr)

    def test_only_actual_shared_diagnostics_and_first_panic_numeric_location_are_public(self):
        panic = f"thread '{SELECTED}' panicked at src/native_pids_limit_tests.rs:123:4:\n{SECRET}\n"
        output = ("DOCKERLENS_NATIVE_CHECK: health_metadata_context\n"
                  "DOCKERLENS_NATIVE_CHECK: pids_limit_context\n" + panic +
                  "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + FAILED)
        result = self.wrapper(output, 101)[0]
        self.assertNotEqual(result.returncode, 0)
        for fixed in ("(exit 101)", "lifecycle_cleanup_unverified", "source=native_pids_limit_tests line=123 column=4"):
            self.assertIn(fixed, result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertNotIn("pids_limit_context", result.stdout + result.stderr)
        for first in (f"thread 'worker' panicked at /private/{SECRET}:1:1:\n",
                      f"thread '{SELECTED}' panicked at /private/{SECRET}:1:1:\n",
                      f"thread '{SELECTED}' panicked at src/native_pids_limit_tests.rs:0:4:\n"):
            result = self.wrapper(first + output, 101)[0]
            self.assertIn("source=native_pids_limit_tests location=unavailable", result.stderr)
            self.assertNotIn("line=123", result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
        for basename in ("native_lifecycle_tests", "native_health_metadata_tests"):
            result = self.wrapper(panic.replace("native_pids_limit_tests", basename) + FAILED, 101)[0]
            self.assertIn(f"source={basename} line=123 column=4", result.stderr)
        result = self.wrapper("DOCKERLENS_NATIVE_CHECK: health_metadata_context\n" + FAILED, 101)[0]
        self.assertIn("DOCKERLENS_NATIVE_CHECK: health_metadata_context", result.stderr)
        wrapper = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        self.assertNotRegex(wrapper, r"pids_limit_(?:context|effects|capture|proof|cleanup|evidence)")

    def test_four_lanes_require_private_proof_without_public_projection_or_abi_changes(self):
        from test_reviewed_catalog import required_shapes

        # Existing native shapes are not new emitter or catalogue admissions.
        self.assertEqual(required_shapes()["PidsLimit"], ("PidsCount", "PidsUnlimited"))
        catalogue = (ROOT / "src/reviewed_catalog.rs").read_text()
        for prefix in ("REVIEWED", "UPSTREAM"):
            selected = catalogue.split(f"const {prefix}_CAPABILITIES:", 1)[1].split("];", 1)[0]
            self.assertNotIn("Capability::PidsLimit,", selected)
            shapes = catalogue.split(f"const {prefix}_SHAPES:", 1)[1].split("];", 1)[0]
            for shape in ("PidsCount", "PidsUnlimited"):
                self.assertNotIn("NativeCapabilityShape::" + shape + ",", shapes)
        schema = (ROOT / "docs/native-evidence.schema.json").read_text()
        self.assertNotIn("pids_limit", schema)
        for lane in LANES:
            with self.subTest(lane=lane):
                result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(result.args) - 2, 19)
                record = json.loads(destination.read_text())
                self.assertNotIn("PidsLimit", record["capability_outcome"])
                self.assertNotIn("PidsLimit", record["admitted_shapes"])
                self.assertNotIn("pids_limit", destination.read_text())
                self.assertEqual(len(record["capability_outcome"]), 43 if lane.startswith("debian11-") else 45)
                self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 66 if lane.startswith("debian11-") else 70)
                proof = destination.parent.parent / "pids-limit-v1.json"
                self.assertLessEqual(proof.stat().st_size, 16 * 1024)
                result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane, pids_limit_missing=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())

    def test_context_effect_cleanup_and_custody_failures_refuse_entire_output(self):
        for lane in LANES:
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            path = destination.parent.parent / "pids-limit-v1.json"
            original = json.loads(path.read_text())
            destination.unlink()
            for mutation in ("partial", "context", "effect", "cleanup", "typed", "extra", "oversize", "mode", "symlink"):
                with self.subTest(lane=lane, mutation=mutation):
                    proof = copy.deepcopy(original)
                    if mutation == "partial":
                        proof["cases"].pop()
                    elif mutation == "context":
                        proof["context"]["candidate_sha"] = "e" * 40
                    elif mutation == "effect":
                        proof["cases"][0]["work"]["successes"] = 13
                    elif mutation == "cleanup":
                        proof["cleanup"]["uncertain"] = True
                    elif mutation == "typed":
                        proof["catalogue_admission"] = 0
                    elif mutation == "extra":
                        proof[SECRET] = SECRET
                    path.write_text(json.dumps(proof, separators=(",", ":")))
                    if mutation == "oversize":
                        path.write_text(" " * (16 * 1024 + 1))
                    elif mutation == "mode":
                        path.chmod(0o644)
                    elif mutation == "symlink":
                        backing = path.with_name("private-backing.json")
                        path.rename(backing)
                        path.symlink_to(backing)
                    canonical.ExternalNetworkEvidenceTests.rerun(self, result, destination)
                    if path.is_symlink():
                        path.unlink()
                        backing.rename(path)
                    path.chmod(0o600)

    def test_exact_typed_four_key_reader_return_required_after_real_validation(self):
        spec = importlib.util.spec_from_file_location("pids_wiring_emitter", legacy.SCRIPT)
        emitter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(emitter)
        valid = {"contract": "pids-limit-v1", "capability_admission": [], "catalogue_admission": False,
                 "scope": emitter.PIDS_LIMIT_SCOPE}
        invalid = [None, [], False, {}, {key: value for key, value in valid.items() if key != "scope"},
                   {**valid, SECRET: SECRET}, {**valid, "contract": SECRET}, {**valid, "capability_admission": ()},
                   {**valid, "capability_admission": ["PidsLimit"]}, {**valid, "catalogue_admission": 0},
                   {**valid, "scope": SECRET}, {**valid, "scope": []}]
        for lane in LANES:
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            destination.unlink()
            paths, arguments = [Path(value) for value in result.args[2:15]], result.args[15:]
            real = emitter.read_pids_limit_proof
            for value in invalid:
                with self.subTest(lane=lane, value=value):
                    def wrong_return(*args):
                        self.assertEqual(real(*args), valid)
                        return copy.deepcopy(value)

                    with patch.dict(os.environ, {"NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                                                 "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                                                 "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if lane.endswith("rootless") else "0"}), \
                            patch.object(emitter, "read_pids_limit_proof", side_effect=wrong_return) as call:
                        with self.assertRaisesRegex(ValueError, "^incomplete pids-limit private qualification$"):
                            emitter.emit(*paths, *arguments)
                        self.assertEqual(call.call_count, 1)
                    self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
