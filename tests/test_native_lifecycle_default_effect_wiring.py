"""Independent exact-selection and whole-emitter controls; no Docker runtime."""

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
TARGET = "native_lifecycle_default_effect"
TEST = "live_lifecycle_default_effects_match_engine"
SELECTED = f"native_health_metadata_tests::lifecycle::default_effect::{TEST}"
SUMMARY = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
HANDOFF = "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"
SECRET = "PRIVATE_DEFAULT_WIRING_CANARY"
FILENAME = "lifecycle-default-effects-v1.json"


class DefaultEffectWiringTests(unittest.TestCase):
    def wrapper(self, output=SUMMARY, status=0, listing=None):
        with tempfile.TemporaryDirectory(prefix="dl-default-wiring-") as directory:
            root = Path(directory)
            cargo, calls = root / "cargo", root / "calls.jsonl"
            cargo.write_text('''#!/usr/bin/python3
import json, os, sys
keys = ["NATIVE_LIFECYCLE_DEFAULT_EFFECT_DEADLINE_EPOCH", "NATIVE_LIFECYCLE_DEADLINE_EPOCH",
        "NATIVE_HEALTH_START_INTERVAL_BOUNDARY_DEADLINE_EPOCH", "NATIVE_LIFECYCLE_CLEANUP_OWNER"]
with open(os.environ["CALLS"], "a") as stream:
    stream.write(json.dumps({"argv":sys.argv[1:], "context":{key:os.environ.get(key) for key in keys}}) + "\\n")
if "--list" in sys.argv:
    print(os.environ["LIST"])
    sys.exit(0)
print(os.environ["OUTPUT"])
sys.exit(int(os.environ["STATUS"]))
''')
            cargo.chmod(0o700)
            began = time.time()
            result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, TEST],
                capture_output=True, text=True, timeout=5,
                env={**os.environ, "PATH": f"{root}:/usr/bin:/bin", "CALLS": str(calls),
                     "LIST": SELECTED + ": test" if listing is None else listing,
                     "OUTPUT": output, "STATUS": str(status),
                     "NATIVE_LIFECYCLE_DEFAULT_EFFECT_DEADLINE_EPOCH": "1",
                     "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1"})
            ended = time.time()
            return result, [json.loads(line) for line in calls.read_text().splitlines()], began, ended

    def test_twenty_first_required_registration_preserves_protocol_and_five_owner_scope(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        invocation = f'"$(dirname "$0")/run-exact-native-test.sh" {TARGET} {TEST}'
        calls = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)
        self.assertEqual(len(calls), 21)
        self.assertEqual(calls[-1], (TARGET, TEST))
        self.assertEqual(source.count(invocation), 1)
        owner = source.index('(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n')
        end = source.index('\n)\n', owner)
        owned_calls = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source[owner:end], re.M)
        self.assertEqual(owned_calls, calls[-5:])
        self.assertEqual(source.count("export NATIVE_LIFECYCLE_CLEANUP_OWNER="), 1)
        self.assertLess(source.index("unset NATIVE_LIFECYCLE_CLEANUP_OWNER"), owner)
        for line in (f'export NATIVE_LIFECYCLE_DEFAULT_EFFECT_PROOF_PATH="$run_dir/{FILENAME}"',
                     'export NATIVE_LIFECYCLE_DEFAULT_EFFECT_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA'):
            self.assertIn(line, source)
        start = source.index('python3 "$script_dir/native-evidence.py"')
        self.assertLess(end, start)
        protocol = source[start:source.index('\nfi', start)].replace('\\\n', ' ')
        self.assertEqual(len(shlex.split(protocol)) - 2, 19)
        self.assertNotIn('"$NATIVE_LIFECYCLE_DEFAULT_EFFECT_PROOF_PATH"', protocol)
        emitter = (ROOT / "scripts/native-evidence.py").read_text()
        self.assertIn("capture_dir / LIFECYCLE_DEFAULT_EFFECT_FILENAME, capture_dir, external_context", emitter)
        self.assertIn("len(sys.argv) != 20", emitter)

    def test_exact_once_selection_and_original_deadline(self):
        result, calls, began, ended = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertIn("--lib", call["argv"])
            self.assertNotIn("--test", call["argv"])
        self.assertEqual(calls[-1]["argv"][-4:], ["--", "--ignored", "--exact", SELECTED])
        context = calls[-1]["context"]
        deadlines = [int(value) for key, value in context.items() if key.endswith("DEADLINE_EPOCH")]
        self.assertEqual(len(set(deadlines)), 1)
        self.assertTrue(int(began) + 180 <= deadlines[0] <= int(ended) + 180)
        self.assertEqual(context["NATIVE_LIFECYCLE_CLEANUP_OWNER"], "native_conformance_outer_v1")
        wrapper = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        self.assertEqual(wrapper.count('run_deadline_epoch=$(( $(date +%s) + 180 ))'), 1)

    def test_missing_duplicate_zero_two_and_failed_selections_are_not_success(self):
        for listing in ("", SELECTED + ": test\n" + SELECTED + ": test", SELECTED + SECRET + ": test"):
            result, calls, _, _ = self.wrapper(listing=listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 1)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
        for output, status in ((SUMMARY.replace("1 passed", "0 passed"), 0),
                               (SUMMARY.replace("1 passed", "2 passed"), 0), (FAILED, 101)):
            result, calls, _, _ = self.wrapper(output, status)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 2)
            self.assertNotIn("required native test passed", result.stdout)

    def test_outer_handoff_and_unverified_cleanup_refuse_numeric_success(self):
        for marker in (HANDOFF, "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified"):
            result, calls, _, _ = self.wrapper(marker + "\n" + SUMMARY)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 2)
            self.assertNotIn("required native test passed", result.stdout)

    def test_first_panic_exact_source_binding_and_privacy(self):
        first = f"thread '{SELECTED}' panicked at src/native_lifecycle_default_effect_tests.rs:123:4:"
        result, _, _, _ = self.wrapper(first + f"\n{SECRET}\n{HANDOFF}\n" +
            f"thread '{SELECTED}' panicked at src/native_lifecycle_tests.rs:456:8:\n{FAILED}", 101)
        self.assertIn("source=native_lifecycle_default_effect_tests line=123 column=4", result.stderr)
        self.assertIn(HANDOFF, result.stderr)
        self.assertNotIn("line=456", result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        for first in (f"thread '{SECRET}' panicked at src/native_lifecycle_default_effect_tests.rs:123:4:",
                      f"thread '{SELECTED}' panicked at /{SECRET}/src/native_lifecycle_default_effect_tests.rs:123:4:",
                      f"thread '{SELECTED}' panicked at src/native_health_start_interval_boundary_tests.rs:123:4:",
                      f"thread '{SELECTED}' panicked at src/native_lifecycle_default_effect_tests.rs:1234567:4:"):
            result, _, _, _ = self.wrapper(first + f"\n{SECRET}\n{FAILED}", 101)
            self.assertIn("source=native_lifecycle_default_effect_tests location=unavailable", result.stderr)
            self.assertNotIn("line=", result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
        result, _, _, _ = self.wrapper(HANDOFF + f" {SECRET}\n{FAILED}", 101)
        self.assertNotIn(HANDOFF, result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_shared_allowlist_failure_preserves_bound_source_and_private_request_suppression(self):
        output = (f"thread '{SELECTED}' panicked at src/native_health_metadata_tests.rs:543:9:\n"
                  f"allowlisted exact native request: /v1.41/containers/{SECRET}/json\n"
                  f"{HANDOFF}\n"
                  f"thread '{SELECTED}' panicked at src/native_lifecycle_default_effect_tests.rs:999:8:\n{FAILED}")
        result, calls, _, _ = self.wrapper(output, 101)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertIn("source=native_health_metadata_tests line=543 column=9", result.stderr)
        self.assertIn(HANDOFF, result.stderr)
        self.assertNotIn("line=999", result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertNotIn("/containers/", result.stdout + result.stderr)

    def test_composed_allowlist_controls_are_nonignored_inert_rust_unit_tests(self):
        # This checks registration of controls for the primary offline Rust gate,
        # not Rust semantics: the controls themselves call request_allowed(), the
        # actual predicate enforced by api(). Never substitute a Python model.
        source = (ROOT / "src/native_lifecycle_default_effect_tests.rs").read_text()
        names = (
            "legacy_absence_composed_allowlist_adds_only_the_exact_get",
            "legacy_absence_binding_refuses_other_invocations_and_changed_context",
            "legacy_absence_composition_preserves_the_six_owned_request_ledgers",
        )
        for name in names:
            self.assertIn(f"#[test]\nfn {name}()", source)
            self.assertNotRegex(source, r'#\[ignore[^\n]*\]\s*fn ' + name)
        controls = source.split("fn allowlist_fixture(", 1)[1]
        self.assertIn("cleaned: true", controls)
        self.assertNotIn("run.api(", controls)
        self.assertNotIn("run.inspect(", controls)
        self.assertNotIn("run.outer(", controls)


class DefaultEffectEvidenceTests(unittest.TestCase):
    # Use the central authored whole-emitter fixture, not isolated reader mocks.
    run_emit = external.ExternalNetworkEvidenceTests.run_emit
    emit = external.ExternalNetworkEvidenceTests.emit
    rerun = external.ExternalNetworkEvidenceTests.rerun

    def test_four_lanes_emit_only_closed_unadmitted_effects_without_catalogue_changes(self):
        for lane in ("upstream-rootful", "upstream-rootless", "debian11-rootful", "debian11-rootless"):
            result, path = self.emit(lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            raw = path.read_text()
            record = json.loads(raw)
            self.assertEqual(record["lifecycle_default_effect_contract"], "lifecycle-default-effects-v1")
            self.assertEqual(record["lifecycle_default_effect_outcomes"], {"admission": "raw_source_only", "catalogue_admission": "unadmitted",
                "probes": ["stop_timeout_omitted_graceful_zero_forced", "health_start_interval_unsupported_legacy_field"
                           if lane.startswith("debian11-") else "health_start_interval_default_equivalent"]})
            self.assertEqual(record["lifecycle_contract"], "lifecycle-v1")
            self.assertEqual(record["lifecycle_outcomes"], {"admission": "raw_source_only", "catalogue_admission": "unadmitted", "probes": [
                "stop_timeout_effective", "health_start_interval_not_effective_on_selected_api" if lane.startswith("debian11-")
                else "health_start_interval_effective"]})
            self.assertEqual(len(record["capability_outcome"]), 34 if lane.startswith("debian11-") else 36)
            self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 56 if lane.startswith("debian11-") else 60)
            for capability in ("StopTimeout", "HealthStartInterval"):
                positive = capability != "HealthStartInterval" or not lane.startswith("debian11-")
                self.assertEqual(capability in record["capability_outcome"], positive)
                self.assertEqual(capability in record["admitted_shapes"], positive)
            for private in ("dl-def-", "stop_elapsed_ns", "raw_timeout", "raw_start_interval", "started_at",
                            "stderr_signature", "daemon_uid", "sha256:" + "d" * 64, SECRET):
                self.assertNotIn(private, raw)

    def test_missing_private_proof_refuses_every_lane(self):
        for lane in ("upstream-rootful", "upstream-rootless", "debian11-rootful", "debian11-rootless"):
            result, path = self.emit(lane, lifecycle_default_effect_missing=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(path.exists())
            self.assertEqual(result.stderr.strip(), "native evidence rejected")

    def test_legacy_schedule_never_projects_a_supported_zero_claim(self):
        for lane in ("upstream-rootful", "upstream-rootless", "debian11-rootful", "debian11-rootless"):
            result, path = self.emit(lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            proof_path = path.parent.parent / FILENAME
            proof = json.loads(proof_path.read_text())
            path.unlink()
            if lane.startswith("debian11-"):
                proof["health_start_interval"]["outcome"] = "default_equivalent"
                proof["health_start_interval"]["source_scope"] = "supported_field_zero_default_schedule"
            else:
                proof["health_start_interval"]["outcome"] = "unsupported_legacy_field"
                proof["health_start_interval"]["source_scope"] = "accepted_unknown_member_legacy_schedule_only"
            proof_path.write_text(json.dumps(proof))
            self.rerun(result, path)

    def test_whole_emitter_rejects_self_bound_context_partial_effects_and_cleanup(self):
        result, path = self.emit()
        self.assertEqual(result.returncode, 0, result.stderr)
        proof_path = path.parent.parent / FILENAME
        original = json.loads(proof_path.read_text())
        path.unlink()
        for mutation in ("candidate", "outer", "run", "release", "api", "mode", "uid", "fixture_image",
                         "partial", "duplicate", "unknown", "raw", "graceful_zero", "scheduler", "cleanup", "renewed"):
            proof = copy.deepcopy(original)
            if mutation in ("candidate", "run", "release", "api", "mode", "uid", "fixture_image"):
                key = {"candidate": "candidate_sha", "run": "run_id", "release": "engine_release",
                       "api": "rendering_api", "mode": "mode", "uid": "daemon_uid", "fixture_image": "fixture_image"}[mutation]
                proof["context"][key] = 1000 if key == "daemon_uid" else SECRET
            elif mutation == "outer":
                proof["context"]["outer"]["id"] = "e" * 64
            elif mutation == "partial":
                proof["stop_timeout"].pop()
            elif mutation == "duplicate":
                proof["health_start_interval"]["containers"][1]["id"] = proof["stop_timeout"][0]["id"]
            elif mutation == "unknown":
                proof[SECRET] = SECRET
            elif mutation == "raw":
                proof["stop_timeout"][0]["raw_timeout"] = "present_zero"
            elif mutation == "graceful_zero":
                proof["stop_timeout"][2]["exit_code"] = 41
            elif mutation == "scheduler":
                proof["health_start_interval"]["containers"][1]["late"]["attempts"] = []
            elif mutation == "cleanup":
                proof["cleanup"]["uncertain"] = True
            else:
                proof["accounting"]["renewed"] = True
            proof_path.write_text(json.dumps(proof))
            self.rerun(result, path)

    def test_fixed_capture_child_ignores_untrusted_path_and_refuses_private_custody_failures(self):
        for mutation in ("renamed", "duplicate", "malformed", "oversize", "mode", "symlink", "hardlink"):
            result, path = self.emit()
            self.assertEqual(result.returncode, 0, result.stderr)
            proof = path.parent.parent / FILENAME
            path.unlink()
            alternate = proof.with_name(SECRET)
            if mutation == "renamed":
                proof.rename(alternate)
            elif mutation == "duplicate":
                proof.write_text('{"contract":"' + SECRET + '","contract":"duplicate"}')
            elif mutation == "malformed":
                proof.write_text('{"private":"' + SECRET + '"')
            elif mutation == "oversize":
                proof.write_text(SECRET * 2048)
            elif mutation == "mode":
                proof.chmod(0o644)
            elif mutation == "symlink":
                proof.rename(alternate)
                proof.symlink_to(alternate)
            else:
                os.link(proof, alternate)
            outcome = subprocess.run(result.args, capture_output=True, text=True, timeout=5,
                env={**os.environ, "NATIVE_FIXTURE_IMAGE": external.legacy.HEALTH_FIXTURE_IMAGE,
                     "NATIVE_OUTER_CONTAINER_ID": "f" * 64, "NATIVE_BIND_RELABEL_DAEMON_UID": "0",
                     "NATIVE_LIFECYCLE_DEFAULT_EFFECT_PROOF_PATH": str(alternate)})
            self.assertNotEqual(outcome.returncode, 0)
            self.assertFalse(path.exists())
            self.assertEqual(outcome.stderr.strip(), "native evidence rejected")
            self.assertNotIn(SECRET, outcome.stdout + outcome.stderr)


if __name__ == "__main__":
    unittest.main()
