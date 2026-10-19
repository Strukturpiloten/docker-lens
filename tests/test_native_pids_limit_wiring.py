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
from native_harness_syntax import authored_emitter_authority, invocations, logical_owner_scopes, native_calls, emitter_cli, rerun_emitter
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
        calls = native_calls(source)
        self.assertEqual(calls[:26], EXPECTED_CALLS)
        self.assertEqual(calls[26:27], [(TARGET, TEST)])
        self.assertEqual(calls[27:], [("native_nofile", "live_nofile_limits_and_effects_match_engine")])
        scope = '(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n'
        old = scope + "\n".join(prefix + " ".join(call) for call in EXPECTED_CALLS[16:22]) + '\n)'
        self.assertEqual(source.count(old), 1)
        for call in EXPECTED_CALLS[23:26]:
            self.assertEqual(source.count(scope + prefix + " ".join(call) + '\n)'), 1)
        self.assertEqual(source.count(scope), 5)
        self.assertEqual(len(logical_owner_scopes(source)), 6)
        kernel_reader = source.index('python3 "$script_dir/native_kernel_settings_proof.py"')
        child = next(item.start for item in invocations(source) if (item.target, item.test) == (TARGET, TEST))
        reader = source.index('canonical_phase reader')
        self.assertLess(kernel_reader, child)
        self.assertLess(child, reader)
        self.assertLess(reader, source.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', reader))
        invocation = source[reader:source.index('\n\n', reader)].replace('\\\n', ' ')
        self.assertEqual(len(shlex.split(invocation)) - 2, 12)
        for independent in ('"$run_dir"', '"$NATIVE_PIDS_LIMIT_CANDIDATE_SHA"', '"$run_id"', '"$lane"',
                            '"$server_version"', '"$api_version"', '"$expected_mode"', '"$installed_docker_package"',
                            '"$NATIVE_FIXTURE_IMAGE"', '"$image"', '"$NATIVE_OUTER_CONTAINER_ID"', '"$NATIVE_BIND_RELABEL_DAEMON_UID"'):
            self.assertIn(independent, invocation)
        self.assertIn('export NATIVE_PIDS_LIMIT_PROOF_PATH="$run_dir/pids-limit-v2.json"', source)
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
        self.assertNotRegex(wrapper, r"DOCKERLENS_NATIVE_CHECK: pids_limit_(?:context|effects|capture|proof|cleanup|evidence)")

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
                self.assertEqual(len(emitter_cli(result)), 19)
                record = json.loads(destination.read_text())
                self.assertNotIn("PidsLimit", record["capability_outcome"])
                self.assertNotIn("PidsLimit", record["admitted_shapes"])
                self.assertNotIn("pids_limit", destination.read_text())
                self.assertEqual(len(record["capability_outcome"]), 43 if lane.startswith("debian11-") else 45)
                self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 66 if lane.startswith("debian11-") else 70)
                proof = destination.parent.parent / "pids-limit-v2.json"
                self.assertLessEqual(proof.stat().st_size, 16 * 1024)
                result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane, pids_limit_missing=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())

    def test_actual_stage_vocabulary_is_closed_and_covers_context_and_six_roles(self):
        context_stages = ("context", "image", "outer_observer", "daemon_identity", "outer_pids_resolve",
                          "outer_memory_resolve", "acquisition", "final_snapshots", "proof")
        case_stages = ("preflight", "create", "start", "inspect", "private_identity", "baseline_scan",
                       "leaf_pids_resolve", "leaf_memory_resolve", "baseline_controller", "work_start",
                       "held_scan", "held_controller", "release", "restored_scan", "restored_controller", "final_inspect")
        stages = [f"case=context role=observer stage={stage}" for stage in context_stages]
        stages += [f"case=finite16 role=oracle stage={stage}" for stage in case_stages]
        stages += [f"case={case} role={role} stage=leaf_memory_resolve"
                   for case in ("finite16", "finite64", "unlimited") for role in ("oracle", "rendered")]
        for fields in stages:
            with self.subTest(fields=fields):
                stage = "DOCKERLENS_NATIVE_PIDS_STAGE: " + fields
                result = self.wrapper(stage + "\n" + FAILED, 101)[0]
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(stage, result.stderr)
        source = (ROOT / "src/native_pids_limit_tests.rs").read_text()
        self.assertIn('"DOCKERLENS_NATIVE_PIDS_STAGE: case={case} role={role} stage={}"', source)
        self.assertIn('"DOCKERLENS_NATIVE_PIDS_RESOLVE: reason={}{}"', source)
        self.assertIn('"DOCKERLENS_NATIVE_PIDS_CONTROLLER: reason={reason}"', source)

    def test_last_pre_first_panic_stage_and_matching_resolution_survive_cleanup(self):
        reasons = ("no_controller_mount", "root_coordinate_mismatch", "multiple_eligible_mounts",
                   "outside_owned_descendant relation=equal_owner",
                   "outside_owned_descendant relation=outside_owner", "outside_owned_descendant relation=mixed")
        for fields in ("case=context role=observer stage=outer_pids_resolve",
                       "case=context role=observer stage=outer_memory_resolve",
                       "case=finite16 role=oracle stage=leaf_pids_resolve",
                       "case=unlimited role=rendered stage=leaf_memory_resolve"):
            for reason in reasons:
                with self.subTest(fields=fields, reason=reason):
                    stage = "DOCKERLENS_NATIVE_PIDS_STAGE: " + fields
                    classification = "DOCKERLENS_NATIVE_PIDS_RESOLVE: reason=" + reason
                    original = f"thread '{SELECTED}' panicked at src/native_health_metadata_tests.rs:542:9:\n{SECRET}\n"
                    later = "DOCKERLENS_NATIVE_PIDS_STAGE: case=context role=observer stage=proof"
                    output = ("DOCKERLENS_NATIVE_PIDS_STAGE: case=context role=observer stage=context\n" +
                              "DOCKERLENS_NATIVE_CHECK: health_metadata_context\n" + stage + "\n" + classification + "\n" +
                              original + "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + later + "\n" +
                              f"thread '{SELECTED}' panicked at src/native_pids_limit_tests.rs:999:1:\n" + FAILED)
                    result = self.wrapper(output, 101)[0]
                    for fixed in ("(exit 101)", stage, classification, "lifecycle_cleanup_unverified",
                                  "source=native_health_metadata_tests line=542 column=9"):
                        self.assertIn(fixed, result.stderr)
                    for absent in (SECRET, later, "line=999", "stage=context\n"):
                        self.assertNotIn(absent, result.stdout + result.stderr)
        stage = "DOCKERLENS_NATIVE_PIDS_STAGE: case=finite64 role=rendered stage=held_scan"
        later = "DOCKERLENS_NATIVE_PIDS_STAGE: case=context role=observer stage=proof"
        for boundary in (f"thread 'worker' panicked at /private/{SECRET}:1:1:",
                         "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup",
                         "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"):
            result = self.wrapper(stage + "\n" + boundary + "\n" + later + "\n" + FAILED, 101)[0]
            self.assertIn(stage, result.stderr)
            self.assertNotIn(later, result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_malformed_cross_phase_and_private_diagnostics_never_become_public(self):
        prefix = "DOCKERLENS_NATIVE_PIDS_STAGE: "
        actual = prefix + "case=context role=observer stage=outer_pids_resolve"
        classification = "DOCKERLENS_NATIVE_PIDS_RESOLVE: reason=root_coordinate_mismatch"
        malformed = [prefix + "case=context role=oracle stage=context",
                     prefix + "case=finite16 role=observer stage=preflight",
                     prefix + "case=context role=observer stage=create",
                     prefix + "case=finite64 role=rendered stage=outer_observer",
                     prefix + f"case={SECRET} role=oracle stage=inspect",
                     prefix + f"case=finite16 role=oracle stage={SECRET}",
                     actual + " " + SECRET, actual + "\r" + SECRET,
                     " " + actual, classification + " " + SECRET,
                     "DOCKERLENS_NATIVE_PIDS_RESOLVE: reason=" + SECRET]
        for line in malformed:
            with self.subTest(line=line):
                result = self.wrapper(actual + "\n" + line + "\n" + FAILED, 101)[0]
                self.assertIn(actual, result.stderr)
                self.assertNotIn(line + "\n", result.stderr)
                self.assertNotIn(SECRET, result.stdout + result.stderr)
        for output in (classification,
                       prefix + "case=finite16 role=oracle stage=preflight\n" + classification,
                       actual + "\n" + classification + "\n" + classification):
            result = self.wrapper(output + "\n" + FAILED, 101)[0]
            self.assertNotIn("DOCKERLENS_NATIVE_PIDS_RESOLVE:", result.stderr)

    def test_each_controller_conjunct_has_one_closed_pre_first_panic_classification(self):
        reasons = ("member_ids_mismatch", "current_count_mismatch", "members_and_current_mismatch")
        for phase in ("baseline_controller", "held_controller", "restored_controller"):
            for reason in reasons:
                with self.subTest(phase=phase, reason=reason):
                    stage = f"DOCKERLENS_NATIVE_PIDS_STAGE: case=finite16 role=oracle stage={phase}"
                    classification = "DOCKERLENS_NATIVE_PIDS_CONTROLLER: reason=" + reason
                    panic = f"thread '{SELECTED}' panicked at src/native_pids_limit_tests.rs:824:5:"
                    later = "DOCKERLENS_NATIVE_PIDS_CONTROLLER: reason=member_ids_mismatch"
                    output = "\n".join((stage, classification, panic, SECRET,
                                        "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified",
                                        "DOCKERLENS_NATIVE_PIDS_STAGE: case=context role=observer stage=proof",
                                        later, FAILED))
                    result = self.wrapper(output, 101)[0]
                    diagnostics = [line for line in result.stderr.splitlines()
                                   if line.startswith("DOCKERLENS_NATIVE_PIDS_")]
                    self.assertEqual(diagnostics, [stage, classification])
                    self.assertNotEqual(result.returncode, 0)
                    for expected in ("(exit 101)", "source=native_pids_limit_tests line=824 column=5"):
                        self.assertIn(expected, result.stderr)
                    self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_controller_refusals_require_exact_phase_and_no_duplicate_or_mixed_reason(self):
        prefix = "DOCKERLENS_NATIVE_PIDS_STAGE: case=finite64 role=rendered stage="
        stage = prefix + "held_controller"
        classification = "DOCKERLENS_NATIVE_PIDS_CONTROLLER: reason=current_count_mismatch"
        resolver = "DOCKERLENS_NATIVE_PIDS_RESOLVE: reason=root_coordinate_mismatch"
        for output in (classification,
                       prefix + "held_scan\n" + classification,
                       prefix + "leaf_pids_resolve\n" + classification,
                       stage + "\n" + resolver,
                       stage + "\n" + classification + "\n" + classification,
                       stage + "\n" + classification + "\n" + resolver,
                       stage + "\n" + resolver + "\n" + classification,
                       stage + "\n" + classification + "\n" + prefix + "restored_scan"):
            with self.subTest(output=output):
                result = self.wrapper(output + "\n" + FAILED, 101)[0]
                self.assertNotIn("DOCKERLENS_NATIVE_PIDS_CONTROLLER:", result.stderr)
                self.assertNotIn("DOCKERLENS_NATIVE_PIDS_RESOLVE:", result.stderr)
        # A new stage resets the single-classification slot instead of carrying
        # an earlier phase's valid observation into the next operation.
        next_stage = prefix + "restored_controller"
        next_reason = "DOCKERLENS_NATIVE_PIDS_CONTROLLER: reason=member_ids_mismatch"
        result = self.wrapper("\n".join((stage, classification, next_stage, next_reason, FAILED)), 101)[0]
        diagnostics = [line for line in result.stderr.splitlines() if line.startswith("DOCKERLENS_NATIVE_PIDS_")]
        self.assertEqual(diagnostics, [next_stage, next_reason])

    def test_new_diagnostics_never_expose_native_data_or_replace_first_panic(self):
        stage = "DOCKERLENS_NATIVE_PIDS_STAGE: case=finite16 role=oracle stage=baseline_controller"
        valid = "DOCKERLENS_NATIVE_PIDS_CONTROLLER: reason=members_and_current_mismatch"
        malformed = [valid + " " + SECRET, valid + "\r" + SECRET, " " + valid,
                     "DOCKERLENS_NATIVE_PIDS_CONTROLLER: reason=" + SECRET,
                     valid + " members=123 current=456",
                     "DOCKERLENS_NATIVE_PIDS_RESOLVE: reason=outside_owned_descendant",
                     "DOCKERLENS_NATIVE_PIDS_RESOLVE: reason=outside_owned_descendant relation=" + SECRET,
                     "DOCKERLENS_NATIVE_PIDS_RESOLVE: reason=outside_owned_descendant relation=equal_owner path=/" + SECRET]
        for invalid in malformed:
            with self.subTest(invalid=invalid):
                actual = ("DOCKERLENS_NATIVE_PIDS_STAGE: case=finite16 role=oracle stage=leaf_pids_resolve"
                          if invalid.startswith("DOCKERLENS_NATIVE_PIDS_RESOLVE:") else stage)
                result = self.wrapper("\n".join((actual, invalid, FAILED)), 101)[0]
                diagnostics = [line for line in result.stderr.splitlines() if line.startswith("DOCKERLENS_NATIVE_PIDS_")]
                self.assertEqual(diagnostics, [actual])
                self.assertNotIn(SECRET, result.stdout + result.stderr)
        for boundary in (f"thread 'worker' panicked at /private/{SECRET}:1:1:",
                         "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup",
                         "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"):
            result = self.wrapper("\n".join((stage, boundary, valid,
                                             f"thread '{SELECTED}' panicked at src/native_pids_limit_tests.rs:999:1:",
                                             FAILED)), 101)[0]
            diagnostics = [line for line in result.stderr.splitlines() if line.startswith("DOCKERLENS_NATIVE_PIDS_")]
            self.assertEqual(diagnostics, [stage])
            self.assertNotIn(SECRET, result.stdout + result.stderr)
            if boundary.startswith("thread"):
                self.assertNotIn("line=999", result.stderr)

    def test_context_effect_cleanup_and_custody_failures_refuse_entire_output(self):
        for lane in LANES:
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            path = destination.parent.parent / "pids-limit-v2.json"
            original = json.loads(path.read_text())
            destination.unlink()
            for mutation in ("partial", "context", "effect", "cleanup", "typed", "extra", "coordinate",
                             "multiview", "namespace", "tuple", "oversize", "mode", "symlink"):
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
                    elif mutation == "coordinate":
                        proof["coordinates"][6][1] = 1
                    elif mutation == "multiview":
                        proof["coordinates"][0][2] = [0, 1]
                    elif mutation == "namespace":
                        proof["coordinates"][9][3] = 1
                    elif mutation == "tuple":
                        proof["cases"][0]["held"].pop()
                    path.write_text(json.dumps(proof, separators=(",", ":")))
                    if mutation == "oversize":
                        path.write_text(" " * (16 * 1024 + 1))
                    elif mutation == "mode":
                        path.chmod(0o644)
                    elif mutation == "symlink":
                        backing = path.with_name("private-backing.json")
                        path.rename(backing)
                        path.symlink_to(backing)
                    rerun_emitter(self, result, destination)
                    if path.is_symlink():
                        path.unlink()
                        backing.rename(path)
                    path.chmod(0o600)

    def test_exact_typed_four_key_reader_return_required_after_real_validation(self):
        spec = importlib.util.spec_from_file_location("pids_wiring_emitter", legacy.SCRIPT)
        emitter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(emitter)
        valid = {"contract": "pids-limit-v2", "capability_admission": [], "catalogue_admission": False,
                 "scope": emitter.PIDS_LIMIT_SCOPE}
        invalid = [None, [], False, {}, {**valid, "contract": "pids-limit-v1"},
                   {key: value for key, value in valid.items() if key != "scope"},
                   {**valid, SECRET: SECRET}, {**valid, "contract": SECRET}, {**valid, "capability_admission": ()},
                   {**valid, "capability_admission": ["PidsLimit"]}, {**valid, "catalogue_admission": 0},
                   {**valid, "scope": SECRET}, {**valid, "scope": []}]
        for lane in LANES:
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            destination.unlink()
            paths, arguments = [Path(value) for value in emitter_cli(result)[:13]], emitter_cli(result)[13:]
            real = emitter.read_pids_limit_proof
            for value in invalid:
                with self.subTest(lane=lane, value=value):
                    def wrong_return(*args):
                        self.assertEqual(real(*args), valid)
                        return copy.deepcopy(value)

                    with authored_emitter_authority(emitter_cli(result)) as outer_context, \
                            patch.dict(os.environ, {"NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                                                 "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                                                 "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if lane.endswith("rootless") else "0"}), \
                            patch.object(emitter, "read_pids_limit_proof", side_effect=wrong_return) as call:
                        with self.assertRaisesRegex(ValueError, "^incomplete pids-limit private qualification$"):
                            emitter.emit(*paths, *arguments, outer_context=outer_context)
                        self.assertEqual(call.call_count, 1)
                    self.assertFalse(destination.exists())


    def test_current_consumers_require_v2_with_no_legacy_file_or_schema_fallback(self):
        from test_native_pids_limit_proof import fixture as historical_fixture
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        emitter = legacy.SCRIPT.read_text()
        self.assertIn('canonical_phase reader', harness)
        self.assertNotIn('python3 "$script_dir/native_pids_limit_proof.py"', harness)
        self.assertIn('from native_pids_limit_v2_proof import', emitter)
        self.assertNotIn('from native_pids_limit_proof import', emitter)
        for lane in LANES:
            with self.subTest(lane=lane):
                result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                current = destination.parent.parent / "pids-limit-v2.json"
                original = json.loads(current.read_text())
                self.assertEqual(original["schema_version"], 2)
                self.assertEqual(original["contract"], "pids-limit-v2")
                self.assertEqual(len(original["coordinates"]), 37)
                self.assertLessEqual(current.stat().st_size, 15 * 1024)
                destination.unlink()
                current.rename(current.with_name("pids-limit-v1.json"))
                rerun_emitter(self, result, destination)
                historical = historical_fixture(lane)
                historical["context"] = copy.deepcopy(original["context"])
                current.write_text(json.dumps(historical, separators=(",", ":")))
                current.chmod(0o600)
                rerun_emitter(self, result, destination)
                historical["schema_version"] = 2
                historical["contract"] = "pids-limit-v2"
                historical["coordinates"] = copy.deepcopy(original["coordinates"])
                current.write_text(json.dumps(historical, separators=(",", ":")))
                rerun_emitter(self, result, destination)


if __name__ == "__main__":
    unittest.main()
