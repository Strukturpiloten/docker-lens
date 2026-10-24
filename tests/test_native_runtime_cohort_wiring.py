"""Closed twenty-six-test recovery wiring; no real native calls."""

import copy
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
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
HANDOFF = "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"
CHILDREN = (
    ("native_runtime_filesystem", "live_runtime_filesystem_matches_engine", "runtime_filesystem"),
    ("native_tmpfs_effect", "live_tmpfs_effects_match_engine", "tmpfs_effect"),
)
EXPECTED_CALLS = [
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
]


class RuntimeCohortWiringTests(unittest.TestCase):
    def wrapper(self, child, output=SUCCESS, status=0, listing=None):
        target, name, module = child
        selected = f"native_health_metadata_tests::lifecycle::{module}::{name}"
        with tempfile.TemporaryDirectory(prefix="dl-cohort-synthetic-") as directory:
            root = Path(directory)
            cargo = root / "cargo"
            calls = root / "calls"
            cargo.write_text('''#!/usr/bin/python3
import json, os, sys
keys = ["NATIVE_LIFECYCLE_DEADLINE_EPOCH", "NATIVE_HEALTH_METADATA_DEADLINE_EPOCH",
        "NATIVE_RUNTIME_FILESYSTEM_DEADLINE_EPOCH", "NATIVE_TMPFS_EFFECT_DEADLINE_EPOCH",
        "NATIVE_LIFECYCLE_CLEANUP_OWNER"]
with open(os.environ["CALLS"], "a") as stream:
    stream.write(json.dumps({"argv":sys.argv[1:], "context":{key:os.environ.get(key) for key in keys}}) + "\\n")
if "--list" in sys.argv:
    print(os.environ["LIST"])
    sys.exit(0)
print(os.environ["OUTPUT"])
sys.exit(int(os.environ["STATUS"]))
''')
            cargo.chmod(0o700)
            started = time.time()
            result = subprocess.run([
                "bash", str(ROOT / "scripts/run-exact-native-test.sh"), target, name,
            ], capture_output=True, text=True, timeout=5,
                env={**os.environ, "PATH": f"{root}:/usr/bin:/bin", "CALLS": str(calls),
                     "LIST": selected + ": test" if listing is None else listing,
                     "OUTPUT": output, "STATUS": str(status),
                     "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1"})
            ended = time.time()
            return result, [json.loads(line) for line in calls.read_text().splitlines()], started, ended

    def test_original_nineteen_plus_recovered_two_have_exact_five_owner_scope(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)
        self.assertEqual(calls, EXPECTED_CALLS)
        owner = source.index('(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n')
        end = source.index('\n)\n', owner)
        scoped = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source[owner:end], re.M)
        self.assertEqual(scoped, EXPECTED_CALLS[16:21])
        self.assertEqual(source.count('export NATIVE_LIFECYCLE_CLEANUP_OWNER='), 5)
        self.assertLess(source.index('unset NATIVE_LIFECYCLE_CLEANUP_OWNER'), source.index('run-exact-native-test.sh" native_capture'))
        emission = source.index('python3 "$script_dir/native-evidence.py"')
        self.assertLess(end, emission)
        protocol = source[emission:source.index('\n  fi\n}', emission)].replace('\\\n', ' ')
        self.assertEqual(len(shlex.split(protocol)) - 2, 19)
        for prefix, filename in (("LIFECYCLE", "lifecycle-v1.json"),
                                 ("RUNTIME_FILESYSTEM", "runtime-filesystem-v1.json"),
                                 ("TMPFS_EFFECT", "tmpfs-effect-v1.json")):
            self.assertIn(f'export NATIVE_{prefix}_PROOF_PATH="$run_dir/{filename}"', source)
            self.assertIn(f'export NATIVE_{prefix}_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', source)
            self.assertNotIn(f'"$NATIVE_{prefix}_PROOF_PATH"', protocol)

    def test_children_execute_once_or_refuse_without_retry(self):
        for child in CHILDREN:
            selected = f"native_health_metadata_tests::lifecycle::{child[2]}::{child[1]}"
            for case in ("pass", "zero", "two", "absent", "duplicate", "failed"):
                with self.subTest(target=child[0], case=case):
                    listing = {"absent": "", "duplicate": selected + ": test\n" + selected + ": test"}.get(case)
                    output = SUCCESS.replace("1 passed", {"zero": "0 passed", "two": "2 passed"}.get(case, "1 passed"))
                    result, calls, _, _ = self.wrapper(child, output, 101 if case == "failed" else 0, listing)
                    self.assertEqual(result.returncode == 0, case == "pass")
                    self.assertEqual(len(calls), 1 if case in ("absent", "duplicate") else 2)
                    self.assertTrue(all("--lib" in item["argv"] and "--test" not in item["argv"] for item in calls))
                    if len(calls) == 2:
                        self.assertEqual(calls[1]["argv"][-3:], ["--ignored", "--exact", selected])

    def test_each_invocation_uses_one_original_deadline_and_scoped_owner(self):
        source = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        self.assertEqual(source.count('run_deadline_epoch=$(( $(date +%s) + 180 ))'), 1)
        for child in CHILDREN:
            result, calls, started, ended = self.wrapper(child)
            self.assertEqual(result.returncode, 0, result.stderr)
            context = calls[1]["context"]
            deadlines = [int(context[key]) for key in context if key.endswith("DEADLINE_EPOCH")]
            self.assertEqual(len(set(deadlines)), 1)
            self.assertGreaterEqual(deadlines[0], int(started) + 180)
            self.assertLessEqual(deadlines[0], int(ended) + 180)
            self.assertEqual(context["NATIVE_LIFECYCLE_CLEANUP_OWNER"], "native_conformance_outer_v1")

    def test_handoff_or_unverified_cleanup_never_passes_even_with_success_summary(self):
        for child in CHILDREN:
            for message in (HANDOFF, "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified"):
                result, calls, _, _ = self.wrapper(child, message + "\n" + SUCCESS)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 2)
                self.assertNotIn("required native test passed", result.stdout)
            for malformed in (HANDOFF + " PRIVATE_CANARY", HANDOFF.replace("state=required", "state=PRIVATE_CANARY")):
                result, _, _, _ = self.wrapper(child, malformed + "\n" + FAILED, 101)
                self.assertNotIn("DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP:", result.stderr)
                self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)

    def test_first_panic_privacy_and_child_source_allowlists_preserve_cause(self):
        for child in CHILDREN:
            selected = f"native_health_metadata_tests::lifecycle::{child[2]}::{child[1]}"
            source = child[0] + "_tests"
            for first in (f"thread '{selected}' panicked at src/{source}.rs:123:4:",
                          "thread 'PRIVATE_WORKER' panicked at src/private.rs:23:4:"):
                output = first + "\nPRIVATE_CANARY\n" + HANDOFF + "\n" + (
                    f"thread '{selected}' panicked at src/{source}.rs:456:8:\n" + FAILED)
                result, _, _, _ = self.wrapper(child, output, 101)
                self.assertIn("failed (exit 101)", result.stderr)
                self.assertIn("line=123 column=4" if "123:4" in first else "location=unavailable", result.stderr)
                self.assertNotIn("line=456", result.stderr)
                self.assertNotIn("PRIVATE_", result.stdout + result.stderr)
                self.assertIn(HANDOFF, result.stderr)
            for site in ("/PRIVATE_CANARY/src/" + source + ".rs:123:4:",
                         "src/" + source + ".rs:1234567:4:", "src/" + source + ".rs:123:12345:",
                         "src/private.rs:123:4:"):
                result, _, _, _ = self.wrapper(child, f"thread '{selected}' panicked at {site}\nPRIVATE_CANARY\n{FAILED}", 101)
                self.assertIn("location=unavailable", result.stderr)
                self.assertNotIn("line=", result.stderr)
                self.assertNotIn("PRIVATE_", result.stdout + result.stderr)

    def test_only_runtime_child_fixed_markers_are_projected(self):
        child = CHILDREN[0]
        output = ("DOCKERLENS_NATIVE_CHECK: runtime_filesystem_false\n"
                  "DOCKERLENS_NATIVE_CHECK: runtime_filesystem_PRIVATE_CANARY\n"
                  "DOCKERLENS_NATIVE_LIFECYCLE_STAGE: case=5 stage=early\n"
                  "DOCKERLENS_NATIVE_CHECK: runtime_filesystem_cleanup\n" + FAILED)
        result, _, _, _ = self.wrapper(child, output, 101)
        self.assertIn("DOCKERLENS_NATIVE_CHECK: runtime_filesystem_false", result.stderr)
        self.assertIn("DOCKERLENS_NATIVE_CHECK: runtime_filesystem_cleanup", result.stderr)
        self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)
        self.assertNotIn("DOCKERLENS_NATIVE_LIFECYCLE_STAGE:", result.stderr)
        result, _, _, _ = self.wrapper(CHILDREN[1], output, 101)
        self.assertNotIn("runtime_filesystem_", result.stderr)

    def test_parent_seams_have_dynamic_ledgers_and_ordinary_postcleanup_reads(self):
        lifecycle = (ROOT / "src/native_lifecycle_tests.rs").read_text()
        self.assertIn('#[path = "native_runtime_filesystem_tests.rs"]\nmod runtime_filesystem;', lifecycle)
        self.assertIn('#[path = "native_tmpfs_effect_tests.rs"]\nmod tmpfs_effect;', lifecycle)
        cleanup = lifecycle.split('fn cleanup(run:', 1)[1].split('fn create(', 1)[0]
        self.assertEqual(cleanup.count('0..run.names.len()'), 2)
        self.assertIn('for _ in 0..2', cleanup)
        self.assertNotIn('run.cleaned = true', cleanup)
        snapshot = lifecycle.split('fn image_snapshot(', 1)[1].split('fn utc_ns(', 1)[0]
        self.assertIn('false,', snapshot)
        self.assertNotIn('true,', snapshot)
        self.assertEqual(8 * (5 + 2 * 2), 72)
        for file, slots in (("native_runtime_filesystem_tests.rs", 6), ("native_tmpfs_effect_tests.rs", 8)):
            source = (ROOT / "src" / file).read_text()
            self.assertIn(f'run.ids = vec![None; {slots}]', source)
            self.assertIn(f'run.attempted = vec![false; {slots}]', source)
            facts = source.split('facts.capabilities =', 1)[1].split('.collect()', 1)[0]
            self.assertIn('Command', re.findall(r'Capability::(\w+)', facts))
            self.assertIn('ImageCommand::Exec', source)
            self.assertIn('terminal_cleanup(&mut run, &owner, disposition)', source)
            self.assertIn('require_verified_result(result, disposition)', source)
            self.assertNotIn('run.cleanup()', source)
            self.assertNotIn('run.image_for(', source)
            self.assertIn('assert_eq!(image_snapshot(&run),', source)
            self.assertIn('assert_eq!(outer_context(&run), outer)', source)


class RuntimeCohortEvidenceTests(unittest.TestCase):
    run_emit = external.ExternalNetworkEvidenceTests.run_emit
    emit = external.ExternalNetworkEvidenceTests.emit
    rerun = external.ExternalNetworkEvidenceTests.rerun

    def test_four_lanes_emit_only_closed_unadmitted_fields_and_existing_counts(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            result, path = self.emit(lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            raw = path.read_text()
            record = json.loads(raw)
            self.assertEqual(record["runtime_filesystem_contract"], "runtime-filesystem-v1")
            self.assertEqual(record["runtime_filesystem_outcomes"], {
                "admission": "unadmitted", "init_effect_scope": "pid1_indirection_only",
                "rootfs_effect_scope": "diagonal_omitted_false_true_only", "controls": ["omitted", "false", "true"],
            })
            self.assertEqual(record["tmpfs_effect_contract"], "tmpfs-effect-v1")
            self.assertEqual(record["tmpfs_effect_outcomes"], {
                "admission": "unadmitted", "coverage": "explicit_1MiB_0700_and_2MiB_0750_rw_ro_only",
            })
            self.assertEqual(len(record["capability_outcome"]), 30 if lane.startswith("debian11-") else 31)
            self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 47 if lane.startswith("debian11-") else 49)
            for forbidden in ("ContainerInit", "ReadOnlyRootfs", "TmpfsMount", "StopTimeout", "HealthStartInterval"):
                self.assertNotIn(forbidden, record["capability_outcome"])
                self.assertNotIn(forbidden, record["admitted_shapes"])
            for private in ("worker_pid", "daemon_uid", "capacity_bytes", "dl-runtime-", "dl-tmpfs-", "a" * 64, "f" * 64):
                self.assertNotIn(private, raw)

    def test_every_child_proof_is_mandatory_on_each_lane(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            for key in ("runtime_filesystem_missing", "tmpfs_effect_missing"):
                result, path = self.emit(lane, **{key: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual(result.stderr.strip(), "native evidence rejected")

    def test_context_cannot_validate_itself_and_unknown_effect_or_cleanup_refuses(self):
        for filename in ("runtime-filesystem-v1.json", "tmpfs-effect-v1.json"):
            result, path = self.emit()
            self.assertEqual(result.returncode, 0, result.stderr)
            proof_path = path.parent.parent / filename
            original = json.loads(proof_path.read_text())
            path.unlink()
            for mutation in ("candidate", "outer", "private", "cleanup", "effect", "partial"):
                value = copy.deepcopy(original)
                if mutation == "candidate":
                    value["context"]["candidate_sha"] = "e" * 40
                elif mutation == "outer":
                    value["context"]["outer"]["id"] = "e" * 64
                elif mutation == "private":
                    value["PRIVATE_CANARY"] = "PRIVATE_CANARY"
                elif mutation == "cleanup":
                    value["cleanup"]["uncertain"] = True
                elif mutation == "partial":
                    value["cases"].pop()
                elif filename.startswith("runtime"):
                    value["cases"][2]["containers"][0]["write_effect"] = "written"
                else:
                    value["cases"][0]["containers"][0]["effect"]["capacity_bytes"] = 1
                proof_path.write_text(json.dumps(value))
                self.rerun(result, path)

    def test_both_private_readers_refuse_malformed_files_and_custody(self):
        for filename in ("runtime-filesystem-v1.json", "tmpfs-effect-v1.json"):
            for mutation in ("duplicate", "malformed", "oversize", "mode", "symlink", "hardlink"):
                result, path = self.emit()
                self.assertEqual(result.returncode, 0, result.stderr)
                proof = path.parent.parent / filename
                path.unlink()
                if mutation == "duplicate":
                    proof.write_text('{"schema_version":1,"schema_version":1}')
                elif mutation == "malformed":
                    proof.write_text('{')
                elif mutation == "oversize":
                    proof.write_text('x' * 65537)
                elif mutation == "mode":
                    proof.chmod(0o644)
                elif mutation == "symlink":
                    target = proof.with_name("synthetic-original")
                    proof.rename(target)
                    proof.symlink_to(target)
                else:
                    os.link(proof, proof.with_name("synthetic-second-link"))
                self.rerun(result, path)


if __name__ == "__main__":
    unittest.main()
