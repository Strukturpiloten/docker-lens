"""Pure/mock nofile registration controls; never execute the native workload."""

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
from test_native_nofile_proof import fixture, refuse_case
from test_native_runtime_cohort_wiring import EXPECTED_CALLS

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_nofile"
TEST = "live_nofile_limits_and_effects_match_engine"
SELECTED = f"native_health_metadata_tests::lifecycle::nofile::{TEST}"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SECRET = "PRIVATE_NOFILE_WIRING_CANARY"


class NofileWiringTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit

    def wrapper(self, output=SUCCESS, status=0, listing=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo, trace = root / "cargo", root / "trace"
            cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"args":sys.argv[1:],
        "deadline":os.environ.get("NATIVE_NOFILE_DEADLINE_EPOCH"),
        "shared":os.environ.get("NATIVE_LIFECYCLE_DEADLINE_EPOCH"),
        "owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")}) + "\\n")
print(os.environ["LISTING"] if "--list" in sys.argv else os.environ["OUTPUT"])
sys.exit(0 if "--list" in sys.argv else int(os.environ["STATUS"]))
''')
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", TRACE=str(trace),
                       LISTING=f"{SELECTED}: test" if listing is None else listing,
                       OUTPUT=output, STATUS=str(status),
                       NATIVE_LIFECYCLE_CLEANUP_OWNER="native_conformance_outer_v1")
            began = int(time.time())
            result = subprocess.run([str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, TEST],
                                    env=env, capture_output=True, text=True, timeout=10, check=False)
            return result, [json.loads(line) for line in trace.read_text().splitlines()], began, int(time.time())

    def test_twenty_eighth_call_preserves_first_twenty_seven_and_five_owner_blocks(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)
        original = EXPECTED_CALLS + [("native_pids_limit", "live_pids_limit_effects_match_engine")]
        self.assertEqual(calls, original + [(TARGET, TEST)])
        prefix = '"$(dirname "$0")/run-exact-native-test.sh" '
        scope = '(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n'
        self.assertEqual(source.count(scope), 6)
        block = scope + "\n".join(prefix + " ".join(call) for call in original[16:22]) + '\n)'
        self.assertEqual(source.count(block), 1)
        for call in original[23:27] + [(TARGET, TEST)]:
            self.assertEqual(source.count(scope + prefix + " ".join(call) + '\n)'), 1)
        reader = source.index('python3 "$script_dir/native_nofile_proof.py"')
        self.assertLess(source.index('python3 "$script_dir/native_pids_limit_proof.py"'), reader)
        self.assertLess(reader, source.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', reader))
        invocation = source[reader:source.index('\n\n', reader)].replace('\\\n', ' ')
        self.assertEqual(len(shlex.split(invocation)) - 2, 12)
        for fact in ("run_dir", "NATIVE_NOFILE_CANDIDATE_SHA", "run_id", "lane", "server_version",
                     "api_version", "expected_mode", "installed_docker_package", "NATIVE_FIXTURE_IMAGE",
                     "image", "NATIVE_OUTER_CONTAINER_ID", "NATIVE_BIND_RELABEL_DAEMON_UID"):
            self.assertIn('"$' + fact + '"', invocation)
        self.assertIn('export NATIVE_NOFILE_PROOF_PATH="$run_dir/nofile-v1.json"', source)
        self.assertIn('export NATIVE_NOFILE_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', source)

    def test_exact_private_selection_original_deadline_and_failure_status_diagnostics(self):
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
        for count in ("0", "2"):
            self.assertNotEqual(self.wrapper(SUCCESS.replace("1 passed", count + " passed"))[0].returncode, 0)
        result = self.wrapper(SUCCESS, 53)[0]
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("(exit 53)", result.stderr)

    def test_actual_markers_handoff_and_first_panic_are_closed_and_private(self):
        producer = (ROOT / "src/native_nofile_tests.rs").read_text()
        for stage in ("context", "effects", "capture", "cleanup", "proof"):
            marker = "DOCKERLENS_NATIVE_CHECK: nofile_" + stage
            self.assertIn(marker, producer)
            self.assertIn(marker, self.wrapper(marker + "\n" + FAILED, 101)[0].stderr)
        panic = f"thread '{SELECTED}' panicked at src/native_nofile_tests.rs:123:4:\n{SECRET}\n"
        output = ("DOCKERLENS_NATIVE_CHECK: nofile_effects\n" + panic +
                  "DOCKERLENS_NATIVE_CHECK: nofile_cleanup\nDOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + FAILED)
        result = self.wrapper(output, 101)[0]
        for fixed in ("(exit 101)", "nofile_effects", "lifecycle_cleanup_unverified",
                      "source=native_nofile_tests line=123 column=4"):
            self.assertIn(fixed, result.stderr)
        for first in (f"thread 'worker' panicked at /private/{SECRET}:1:1:\n",
                      f"thread '{SELECTED}' panicked at /private/{SECRET}:1:1:\n",
                      f"thread '{SELECTED}' panicked at src/native_nofile_tests.rs:0:4:\n"):
            result = self.wrapper(first + output, 101)[0]
            self.assertIn("source=native_nofile_tests location=unavailable", result.stderr)
            self.assertNotIn("line=123", result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
        for basename in ("native_lifecycle_tests", "native_health_metadata_tests"):
            result = self.wrapper(panic.replace("native_nofile_tests", basename) + FAILED, 101)[0]
            self.assertIn(f"source={basename} line=123 column=4", result.stderr)
        for marker in ("DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified",
                       "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"):
            self.assertNotEqual(self.wrapper(marker + "\n" + SUCCESS)[0].returncode, 0)
        result = self.wrapper("DOCKERLENS_NATIVE_CHECK: nofile_invented\n" + panic + FAILED, 101)[0]
        self.assertNotIn("nofile_invented", result.stdout + result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        result = self.wrapper("DOCKERLENS_NATIVE_CHECK: health_metadata_context\n" + FAILED, 101)[0]
        self.assertIn("DOCKERLENS_NATIVE_CHECK: health_metadata_context", result.stderr)

    def test_actual_noemit_harness_tail_requires_reader_with_independent_context_on_all_lanes(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        tail = source[source.index('(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n'
                                   '"$(dirname "$0")/run-exact-native-test.sh" ' + TARGET):]
        tail = tail.split('\nif [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', 1)[0]
        tail = tail.replace('"$(dirname "$0")/run-exact-native-test.sh"', "fake_native")
        for lane in LANES:
            for fault in ("none", "missing", "context", "effect", "cleanup", "native_failure"):
                with self.subTest(lane=lane, fault=fault), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    root.chmod(0o700)
                    proof = fixture(lane)
                    context = copy.deepcopy(proof["context"])
                    context["outer"]["socket_source"] = str(root / "socket")
                    proof["context"] = copy.deepcopy(context)
                    if fault == "context":
                        proof["context"]["candidate_sha"] = "e" * 40
                    elif fault == "effect":
                        proof["cases"][0]["containers"][0]["effect"]["witness"]["reuse_count"] = 0
                    elif fault == "cleanup":
                        proof["cleanup"]["uncertain"] = True
                    if fault != "missing":
                        path = root / "nofile-v1.json"
                        path.write_text(json.dumps(proof, separators=(",", ":")))
                        path.chmod(0o600)
                    env = dict(os.environ, script_dir=str(ROOT / "scripts"), run_dir=str(root),
                               NATIVE_NOFILE_CANDIDATE_SHA=context["candidate_sha"], run_id=context["run_id"], lane=lane,
                               server_version=context["engine_release"], api_version=context["rendering_api"],
                               expected_mode=context["mode"], installed_docker_package=context["docker_package"],
                               NATIVE_FIXTURE_IMAGE=context["fixture_image"], image=context["outer"]["image"],
                               NATIVE_OUTER_CONTAINER_ID=context["outer"]["id"], NATIVE_BIND_RELABEL_DAEMON_UID=str(context["daemon_uid"]),
                               STATUS="53" if fault == "native_failure" else "0")
                    env.pop("NATIVE_LIFECYCLE_CLEANUP_OWNER", None)
                    env.pop("DOCKERLENS_NATIVE_EVIDENCE_DIR", None)
                    script = ('set -euo pipefail\nfake_native() { '
                              '[[ ${NATIVE_LIFECYCLE_CLEANUP_OWNER:-} == native_conformance_outer_v1 ]] || return 99; '
                              'return "$STATUS"; }\n' + tail + '\nprintf "public-boundary\\n"\n')
                    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=5, check=False)
                    self.assertEqual(result.returncode == 0, fault == "none", result.stderr)
                    self.assertEqual("public-boundary" in result.stdout, fault == "none")
                    if fault == "native_failure":
                        self.assertEqual(result.returncode, 53)

    def test_four_lane_private_qualification_keeps_counts_and_unlimited_dispositions_honest(self):
        for lane in LANES:
            for disposition in ("exact", "refused", "normalized"):
                result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                private = destination.parent.parent / "nofile-v1.json"
                proof = json.loads(private.read_text())
                for index in (2, 3):
                    if disposition == "refused":
                        refuse_case(proof, index)
                    elif disposition == "normalized":
                        for item in proof["cases"][index]["containers"]:
                            witness = item["effect"]["witness"]
                            witness["outcome"] = "finite_kernel_normalization"
                            witness["kernel"]["hard"] = 1048576
                            if index == 3:
                                witness["kernel"]["soft"] = 1048576
                            for sample in witness["samples"].values():
                                sample.update(witness["kernel"])
                destination.unlink()
                private.write_text(json.dumps(proof, separators=(",", ":")))
                result = subprocess.run(result.args, capture_output=True, text=True, check=False, timeout=5,
                                        env={**os.environ, "NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                                             "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                                             "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if lane.endswith("rootless") else "0"})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(result.args) - 2, 19)
                record = json.loads(destination.read_text())
                self.assertEqual(len(record["capability_outcome"]), 43 if lane.startswith("debian11-") else 45)
                self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 66 if lane.startswith("debian11-") else 70)
                for capability in ("Ulimits", "UlimitNofile"):
                    self.assertNotIn(capability, record["capability_outcome"])
                    self.assertNotIn(capability, record["admitted_shapes"])
                self.assertNotIn("nofile", destination.read_text())
                self.assertTrue(16 * 1024 < private.stat().st_size <= 512 * 1024)

    def test_actual_reader_context_effect_cleanup_custody_and_missing_refuse_whole_output(self):
        for lane in LANES:
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane, nofile_missing=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(destination.exists())
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            path = destination.parent.parent / "nofile-v1.json"
            original = json.loads(path.read_text())
            destination.unlink()
            for mutation in ("partial", "context", "effect", "cleanup", "mode", "oversize", "typed", "symlink"):
                proof = copy.deepcopy(original)
                if mutation == "partial":
                    proof["cases"].pop()
                elif mutation == "context":
                    proof["context"]["candidate_sha"] = "e" * 40
                elif mutation == "effect":
                    proof["cases"][0]["containers"][0]["effect"]["witness"]["failure"]["errno"] = 23
                elif mutation == "cleanup":
                    proof["cleanup"]["uncertain"] = True
                elif mutation == "typed":
                    proof["catalogue_admission"] = 0
                path.write_text(json.dumps(proof, separators=(",", ":")))
                if mutation == "mode":
                    path.chmod(0o644)
                elif mutation == "oversize":
                    path.write_text(" " * (512 * 1024 + 1))
                elif mutation == "symlink":
                    backing = path.with_name("nofile-private-backing.json")
                    path.rename(backing)
                    path.symlink_to(backing)
                canonical.ExternalNetworkEvidenceTests.rerun(self, result, destination)
                if path.is_symlink():
                    path.unlink()
                    backing.rename(path)
                path.chmod(0o600)

    def test_scoped_custody_and_unselected_catalogue_vocabulary_are_unchanged(self):
        from native_nofile_proof import PROOF_LIMIT, METADATA_LIMIT
        from test_reviewed_catalog import required_shapes

        self.assertEqual((PROOF_LIMIT, METADATA_LIMIT), (512 * 1024, 64 * 1024))
        self.assertEqual(required_shapes()["Ulimits"], ("UlimitsFinite", "UlimitsUnlimited"))
        self.assertEqual(required_shapes()["UlimitNofile"], ("UlimitNofile",))
        self.assertNotIn("nofile", (ROOT / "docs/native-evidence.schema.json").read_text())
        catalogue = (ROOT / "src/reviewed_catalog.rs").read_text()
        for prefix in ("REVIEWED", "UPSTREAM"):
            capabilities = catalogue.split(f"const {prefix}_CAPABILITIES:", 1)[1].split("];", 1)[0]
            shapes = catalogue.split(f"const {prefix}_SHAPES:", 1)[1].split("];", 1)[0]
            for capability in ("Ulimits", "UlimitNofile"):
                self.assertNotIn("Capability::" + capability + ",", capabilities)
            for shape in ("UlimitsFinite", "UlimitsUnlimited", "UlimitNofile"):
                self.assertNotIn("NativeCapabilityShape::" + shape + ",", shapes)

    def test_exact_typed_three_key_return_rejects_scope_extra_and_bool_integer_substitution(self):
        spec = importlib.util.spec_from_file_location("nofile_wiring_emitter", legacy.SCRIPT)
        emitter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(emitter)
        valid = {"contract": "nofile-v1", "capability_admission": [], "catalogue_admission": False}
        invalid = [None, {}, {**valid, "scope": "four_diagonal_nofile_cases_source_only"},
                   {**valid, "contract": SECRET}, {**valid, "capability_admission": ()},
                   {**valid, "capability_admission": ["Ulimits"]}, {**valid, "catalogue_admission": 0}]
        for lane in LANES:
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            destination.unlink()
            paths, arguments = [Path(value) for value in result.args[2:15]], result.args[15:]
            real = emitter.read_nofile_proof
            for value in invalid:
                def wrong_return(*args):
                    self.assertEqual(real(*args), valid)
                    return copy.deepcopy(value)

                with patch.dict(os.environ, {"NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                                             "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                                             "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if lane.endswith("rootless") else "0"}), \
                        patch.object(emitter, "read_nofile_proof", side_effect=wrong_return) as call:
                    with self.assertRaisesRegex(ValueError, "^incomplete nofile private qualification$"):
                        emitter.emit(*paths, *arguments)
                    self.assertEqual(call.call_count, 1)
                self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
