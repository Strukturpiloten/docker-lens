"""Canonical process-source wiring; synthetic controls are not native evidence."""

import json
import os
import re
import shlex
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import importlib.util

import test_native_external_network_evidence as external
from test_native_command_clear_projection import OUTCOME, expected_shapes

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_command_clear"
TEST = "live_command_clear_matches_engine"
SELECTED = f"native_health_metadata_tests::command_clear::{TEST}"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
SECRET = "PRIVATE_COMMAND_CLEAR_CANARY"


def native_calls(source):
    return re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)


class CommandClearWiringTests(unittest.TestCase):
    def wrapper(self, output=SUCCESS, status=0, listing=None, list_status=0):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            trace = root / "trace"
            cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"args": sys.argv[1:],
        "deadline": os.environ.get("NATIVE_COMMAND_CLEAR_DEADLINE_EPOCH"),
        "shared_deadline": os.environ.get("NATIVE_HEALTH_METADATA_DEADLINE_EPOCH"),
        "owner": os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")}) + "\\n")
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
                       NATIVE_COMMAND_CLEAR_DEADLINE_EPOCH="1")
            env.pop("NATIVE_LIFECYCLE_CLEANUP_OWNER", None)
            began = int(time.time())
            result = subprocess.run([str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, TEST],
                                    env=env, capture_output=True, text=True, timeout=10, check=False)
            ended = int(time.time())
            calls = [json.loads(line) for line in trace.read_text().splitlines()]
            return result, calls, began, ended

    def test_twenty_third_registration_and_mandatory_independent_reader(self):
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = native_calls(harness)
        self.assertEqual(len(calls), 26)
        self.assertEqual(calls[21:23], [("native_hostname", "live_hostname_matches_engine"), (TARGET, TEST)])
        self.assertEqual(calls.count((TARGET, TEST)), 1)
        hostname_reader = harness.index('python3 "$script_dir/native_hostname_proof.py"')
        command = harness.index(f'"$(dirname "$0")/run-exact-native-test.sh" {TARGET} {TEST}')
        reader = harness.index("from native_command_clear_proof import read_command_clear_proof")
        emission_gate = harness.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', command)
        self.assertLess(hostname_reader, command)
        self.assertLess(command, reader)
        self.assertLess(reader, emission_gate)
        self.assertIn('export NATIVE_COMMAND_CLEAR_PROOF_PATH="$run_dir/command-clear-v1.json"', harness)
        self.assertIn('export NATIVE_COMMAND_CLEAR_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', harness)
        self.assertIn('read_command_clear_proof(Path(directory) / "command-clear-v1.json", Path(directory), context)', harness)
        owner = harness.index('(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n')
        self.assertLess(harness.index('\n)\n', owner), command)
        hostname_owner = harness.index('(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n', owner + 1)
        self.assertLess(harness.index('\n)\n', hostname_owner), command)
        self.assertEqual(harness.count('export NATIVE_LIFECYCLE_CLEANUP_OWNER='), 5)
        self.assertLess(reader, harness.index('if [[ -n ${apparmor_profile:-} ]]; then', reader))
        emitter = harness.index('python3 "$script_dir/native-evidence.py"')
        protocol = harness[emitter:harness.index('\n  fi\n}', emitter)].replace('\\\n', ' ')
        self.assertEqual(len(shlex.split(protocol)) - 2, 19)
        self.assertNotIn('"$NATIVE_COMMAND_CLEAR_PROOF_PATH"', protocol)
        self.assertIn('!= ("ClearCommand", "ClearEntrypoint")', harness)
        self.assertIn('!= ("ClearCommand", "ClearEntrypoint")', (ROOT / "scripts/native-evidence.py").read_text())

    def test_exact_selection_deadline_and_no_lifecycle_handoff(self):
        result, calls, began, ended = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["args"][-3:], ["--", "--ignored", "--list"])
        self.assertEqual(calls[1]["args"][-4:], ["--", "--ignored", "--exact", SELECTED])
        self.assertEqual(calls[1]["deadline"], calls[1]["shared_deadline"])
        self.assertTrue(began + 180 <= int(calls[1]["deadline"]) <= ended + 180)
        self.assertIsNone(calls[1]["owner"])
        self.assertEqual((ROOT / "scripts/run-exact-native-test.sh").read_text().count(
            'run_deadline_epoch=$(( $(date +%s) + 180 ))'), 1)
        for listing in ("", f"{SELECTED}: test\n{SELECTED}: test", "other: test"):
            result, calls, _, _ = self.wrapper(listing=listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 1)
        result, calls, _, _ = self.wrapper(listing=SECRET, list_status=17)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        for output in ("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;",
                       "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;",
                       SUCCESS.replace("0 failed", "1 failed"), SUCCESS.replace("0 ignored", "1 ignored"),
                       SUCCESS + "\nDOCKERLENS_NATIVE_CHECK: command_clear_cleanup_unverified"):
            self.assertNotEqual(self.wrapper(output)[0].returncode, 0)
        self.assertNotEqual(self.wrapper(SUCCESS, 17)[0].returncode, 0)
        for refused in ("DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified",
                        "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"):
            self.assertNotEqual(self.wrapper(refused + "\n" + SUCCESS)[0].returncode, 0)

    def test_fixed_causal_diagnostics_first_panic_and_cleanup_failure(self):
        output = (f"DOCKERLENS_NATIVE_CHECK: command_clear_derive\n"
                  f"DOCKERLENS_NATIVE_COMMAND_CLEAR_STAGE: case=command_clear role=rendered stage=effect\n"
                  f"thread '{SELECTED}' panicked at src/native_command_clear_tests.rs:123:4:\n{SECRET}\n"
                  f"DOCKERLENS_NATIVE_COMMAND_CLEAR_STAGE: case=image_defaults role=oracle stage=create\n"
                  f"DOCKERLENS_NATIVE_CHECK: command_clear_cleanup\n"
                  f"DOCKERLENS_NATIVE_CHECK: command_clear_cleanup_unverified\n{FAILED}")
        result = self.wrapper(output, 101)[0]
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("(exit 101)", result.stderr)
        for fixed in ("command_clear_derive", "command_clear_cleanup_unverified",
                      "case=command_clear role=rendered stage=effect",
                      "source=native_command_clear_tests line=123 column=4"):
            self.assertIn(fixed, result.stderr)
        self.assertNotIn("case=image_defaults", result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)

        for first in (f"thread 'worker' panicked at src/native_command_clear_tests.rs:1:1:\n{SECRET}\n",
                      f"thread '{SELECTED}' panicked at /private/{SECRET}.rs:1:1:\n"):
            result = self.wrapper(first + output, 101)[0]
            self.assertIn("source=native_command_clear_tests location=unavailable", result.stderr)
            self.assertNotIn("line=123", result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
        result = self.wrapper(f"DOCKERLENS_NATIVE_CHECK: command_clear_{SECRET}\n"
                              f"DOCKERLENS_NATIVE_COMMAND_CLEAR_STAGE: case={SECRET} role=oracle stage=create\n{FAILED}", 101)[0]
        self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_all_fixed_stages_and_malformed_marker_privacy(self):
        for case in ("image_defaults", "entrypoint_inherit", "command_clear", "entrypoint_clear"):
            for role in ("oracle", "rendered"):
                for stage in ("create", "effect"):
                    marker = f"DOCKERLENS_NATIVE_COMMAND_CLEAR_STAGE: case={case} role={role} stage={stage}"
                    result = self.wrapper(marker + "\n" + SECRET + "\n" + FAILED, 101)[0]
                    self.assertIn(marker, result.stderr)
                    self.assertNotIn(SECRET, result.stdout + result.stderr)
        for marker in ("DOCKERLENS_NATIVE_CHECK: command_clear_derive\r",
                       "\x1b[31mDOCKERLENS_NATIVE_CHECK: command_clear_context",
                       "DOCKERLENS_NATIVE_COMMAND_CLEAR_STAGE: case=command_clear role=rendered stage=effect " + SECRET):
            result = self.wrapper(marker + "\n" + FAILED, 101)[0]
            self.assertNotIn("DOCKERLENS_NATIVE_CHECK:", result.stderr)
            self.assertNotIn("DOCKERLENS_NATIVE_COMMAND_CLEAR_STAGE:", result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_child_has_exact_ignored_entry_and_dedicated_environment(self):
        parent = (ROOT / "src/native_health_metadata_tests.rs").read_text()
        child = (ROOT / "src/native_command_clear_tests.rs").read_text()
        self.assertIn('#[path = "native_command_clear_tests.rs"]\nmod command_clear;', parent)
        self.assertIn('fn live_command_clear_matches_engine()', child)
        self.assertIn('#[ignore = "requires isolated exact-profile Docker Engine and authenticated harness"]', child)
        for key in ("NATIVE_COMMAND_CLEAR_CANDIDATE_SHA", "NATIVE_COMMAND_CLEAR_DEADLINE_EPOCH",
                    "NATIVE_COMMAND_CLEAR_PROOF_PATH", "command-clear-v1.json"):
            self.assertIn(key, child)

    def test_inline_adapter_uses_independent_harness_facts_and_fixed_errors(self):
        from test_native_command_clear_proof import fixture

        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        adapter = harness.split("<<'COMMAND_CLEAR_PROOF'\n", 1)[1].split("\nCOMMAND_CLEAR_PROOF", 1)[0]
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                proof = fixture(lane)
                context = proof["context"]
                context["outer"]["socket_source"] = str(root / "socket")
                facts = [str(root), context["candidate_sha"], context["run_id"], lane,
                         context["engine_release"], context["rendering_api"], context["mode"],
                         context["docker_package"], context["fixture_image"], context["outer"]["image"],
                         context["outer"]["id"], str(context["daemon_uid"])]
                path = root / "command-clear-v1.json"

                def invoke(arguments, library=ROOT / "scripts"):
                    return subprocess.run(["python3", "-", str(library), *arguments],
                                          input=adapter, capture_output=True, text=True, timeout=5, check=False)

                path.write_text(json.dumps(proof))
                path.chmod(0o600)
                result = invoke(facts)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout + result.stderr, "")
                # Every independently supplied fact is required; proof self-context
                # cannot authorize a different lane/candidate/runtime/ownership.
                for index in range(len(facts)):
                    wrong = facts.copy()
                    wrong[index] = SECRET
                    result = invoke(wrong)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stderr.strip(), "native command-clear proof rejected")
                    self.assertEqual(result.stdout, "")
                for uid in ("00", "+0", "-1", "4294967296", " 0", "0\n"):
                    result = invoke(facts[:-1] + [uid])
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stderr.strip(), "native command-clear proof rejected")
                path.unlink()
                self.assertNotEqual(invoke(facts).returncode, 0)
                for wrong in (facts[:-1], [*facts, SECRET]):
                    self.assertNotEqual(invoke(wrong).returncode, 0)
                for returned in (["ClearCommand", "ClearEntrypoint"], ("ClearCommand",),
                                 ("ClearEntrypoint", "ClearCommand"), None):
                    (root / "native_command_clear_proof.py").write_text(
                        "def read_command_clear_proof(*arguments):\n    return " + repr(returned) + "\n")
                    result = invoke(facts, root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr.strip(), "native command-clear proof rejected")

    def test_actual_harness_tail_requires_both_readers_before_public_emission(self):
        from test_native_command_clear_proof import fixture as command_fixture
        from test_native_hostname_proof import fixture as hostname_fixture
        from test_native_shm_size_proof import fixture as shm_fixture
        from test_native_supplementary_groups_proof import fixture as groups_fixture
        from test_native_kernel_settings_proof import fixture as kernel_fixture

        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        start = harness.index('python3 "$script_dir/native_hostname_proof.py"')
        tail = harness[start:harness.index('publish_native_evidence() {', start)]
        tail = tail.replace('"$(dirname "$0")/run-exact-native-test.sh"', 'command_wrapper')
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            for fault in ("none", "hostname_missing", "hostname_context", "command_missing",
                          "command_effect", "command_cleanup", "native_failure",
                          "shm_size_missing", "supplementary_groups_missing", "kernel_settings_missing"):
                with self.subTest(lane=lane, fault=fault), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    hostname = hostname_fixture(lane)
                    context = hostname["context"]
                    context["outer"]["socket_source"] = str(root / "socket")
                    command = command_fixture(lane)
                    command["context"] = json.loads(json.dumps(context))
                    command["seed"]["image"] = context["fixture_image"]
                    trace = root / "trace"
                    env = dict(os.environ, script_dir=str(ROOT / "scripts"), run_dir=str(root),
                        run_id=context["run_id"], lane=lane, server_version=context["engine_release"],
                        api_version=context["rendering_api"], expected_mode=context["mode"],
                        installed_docker_package=context["docker_package"],
                        NATIVE_HOSTNAME_CANDIDATE_SHA=context["candidate_sha"],
                        NATIVE_COMMAND_CLEAR_CANDIDATE_SHA=context["candidate_sha"],
                        NATIVE_SHM_SIZE_CANDIDATE_SHA=context["candidate_sha"],
                        NATIVE_SUPPLEMENTARY_GROUPS_CANDIDATE_SHA=context["candidate_sha"],
                        NATIVE_KERNEL_SETTINGS_CANDIDATE_SHA=context["candidate_sha"],
                        NATIVE_OUTER_ENGINE="podman",
                        NATIVE_FIXTURE_IMAGE=context["fixture_image"], image=context["outer"]["image"],
                        NATIVE_OUTER_CONTAINER_ID=context["outer"]["id"],
                        NATIVE_BIND_RELABEL_DAEMON_UID=str(context["daemon_uid"]),
                        NATIVE_COMMAND_CLEAR_PROOF_PATH=SECRET, TRACE=str(trace),
                        STATUS="37" if fault == "native_failure" else "0")
                    env.pop("NATIVE_LIFECYCLE_CLEANUP_OWNER", None)
                    env.pop("DOCKERLENS_NATIVE_EVIDENCE_DIR", None)
                    if fault == "hostname_context":
                        hostname["context"]["candidate_sha"] = "e" * 40
                    elif fault == "command_effect":
                        command["cases"][2]["containers"][1]["marker"] = SECRET
                    elif fault == "command_cleanup":
                        command["cleanup"]["uncertain"] = True
                    for family, proof in (("hostname", hostname), ("command", command)):
                        if fault != family + "_missing":
                            path = root / ("hostname-v1.json" if family == "hostname" else "command-clear-v1.json")
                            path.write_text(json.dumps(proof))
                            path.chmod(0o600)
                    for family, fixture in (("shm_size", shm_fixture), ("supplementary_groups", groups_fixture),
                                            ("kernel_settings", kernel_fixture)):
                        if fault != family + "_missing":
                            proof = fixture(lane)
                            proof["context"] = json.loads(json.dumps(context))
                            path = root / (family.replace("_", "-") + "-v1.json")
                            path.write_text(json.dumps(proof))
                            path.chmod(0o600)
                    script = ('set -euo pipefail\ncommand_wrapper() {\n'
                              '  if [[ $1 == native_command_clear ]]; then\n'
                              '    [[ -z ${NATIVE_LIFECYCLE_CLEANUP_OWNER:-} ]] || return 98\n'
                              '  else\n'
                              '    [[ ${NATIVE_LIFECYCLE_CLEANUP_OWNER:-} == native_conformance_outer_v1 ]] || return 98\n'
                              '  fi\n'
                              '  printf "%s %s\\n" "$1" "$2" >> "$TRACE"\n'
                              '  return "$STATUS"\n}\n' + tail + 'printf "public\\n" >> "$TRACE"\n')
                    result = subprocess.run(["bash", "-c", script], env=env,
                                            capture_output=True, text=True, timeout=5)
                    events = trace.read_text().splitlines() if trace.exists() else []
                    expected = [] if fault.startswith("hostname_") else [f"{TARGET} {TEST}"]
                    if fault == "none" or fault in ("shm_size_missing", "supplementary_groups_missing", "kernel_settings_missing"):
                        for family, test in (("shm_size", "live_shm_size_effects_match_engine"),
                                             ("supplementary_groups", "live_supplementary_groups_match_engine"),
                                             ("kernel_settings", "live_kernel_settings_match_engine")):
                            expected.append("native_" + family + " " + test)
                            if fault == family + "_missing":
                                break
                    if fault == "none":
                        expected.append("public")
                    self.assertEqual(events, expected)
                    self.assertEqual(result.returncode == 0, fault == "none", result.stderr)
                    if fault == "native_failure":
                        self.assertEqual(result.returncode, 37)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn(SECRET, result.stderr)

    def test_cleanup_delegation_is_not_success_and_is_not_retried(self):
        parent = (ROOT / "src/native_health_metadata_tests.rs").read_text()
        child = (ROOT / "src/native_command_clear_tests.rs").read_text()
        self.assertIn("cleanup_delegated: false", parent)
        self.assertIn("if self.owns_drop_cleanup()", parent)
        self.assertIn("!self.cleaned && !self.cleanup_delegated", parent)
        self.assertIn("native.cleanup_delegated = true", child)
        self.assertNotIn(".cleaned =", child)
        self.assertIn("impl Drop for CommandRun", child)
        self.assertIn("self.cleanup_attempted = true", child)
        self.assertIn("command_clear_cleanup_unverified", child)
        self.assertIn("assert!(owned.cleanup_verified", child)
        acquire = child.split("fn new() -> Self", 1)[1].split("fn image_for", 1)[0]
        self.assertRegex(acquire, r"native\.cleanup_delegated = true;\s*let mut owned = Self \{")
        self.assertLess(acquire.index("let mut owned = Self"), acquire.index("run.names ="))
        cleanup = child.split("fn cleanup(&mut self)", 1)[1].split("impl Drop", 1)[0]
        self.assertLess(cleanup.index("if self.cleanup_attempted"), cleanup.index("self.cleanup_attempted = true"))
        self.assertLess(cleanup.index("self.cleanup_attempted = true"), cleanup.index("self.cleanup_inner()"))
        controls = (ROOT / "src/native_lifecycle_default_effect_tests.rs").read_text().split(
            "fn health_drop_cleanup_ownership_guard_is_hermetic_for_all_states()", 1)[1].split("#[test]", 1)[0]
        self.assertIn("for cleaned in [false, true]", controls)
        self.assertIn("for delegated in [false, true]", controls)
        self.assertLess(controls.index("let required = run.owns_drop_cleanup()"), controls.index("run.cleaned = true"))
        self.assertLess(controls.index("run.cleaned = true"), controls.index("assert_eq!"))
        self.assertNotIn(".cleanup(", controls)

    def test_selected_snapshot_prefix_retains_original_charge_before_io_and_both_backends(self):
        child = (ROOT / "src/native_command_clear_tests.rs").read_text()
        snapshot = child.split("fn outer_snapshot(", 1)[1].split("#[test]", 1)[0]
        ordered = ["run.charge_outer_snapshot(false)", "run.timer(false, elevated)",
                   "crate::native_outer_test_command::prefix()", "run.capture("]
        self.assertEqual([snapshot.index(item) for item in ordered], sorted(snapshot.index(item) for item in ordered))
        self.assertNotIn('["podman"', snapshot)
        self.assertNotIn('["docker"', snapshot)
        parent = (ROOT / "src/native_health_metadata_tests.rs").read_text()
        charge = parent.split("fn charge_outer_snapshot(", 1)[1].split("fn outer(", 1)[0]
        for required in ("snapshot_extra_calls()", "self.calls.get() + extra", "extra * 65536",
                         "capture_room(self.calls.get(), self.bytes.get(), cleanup)"):
            self.assertIn(required, charge)
        bridge = (ROOT / "src/native_outer_test_command.rs").read_text()
        self.assertIn('usize::from(std::env::var("NATIVE_OUTER_ENGINE").as_deref() == Ok("docker"))', bridge)
        self.assertIn('matches!(engine.as_str(), PODMAN_ENGINE | "docker")', bridge)
        for original in ('value["Id"] == id', 'value["Name"] == run.outer', 'value["ImageDigest"] == digest',
                         'mounts.len() == 2', 'networks.len() == 1', '4294967296_u64', '== 512'):
            self.assertIn(original, snapshot)

    def test_effect_and_image_mutations_stay_test_only_and_exact(self):
        source = (ROOT / "src/native_command_clear_tests.rs").read_text()
        for spelling in ("/proc/1/cmdline", '"commit"', '"--attach"', '"--change"',
                         "?force=0", "?force=1", "for _ in 0..2", "base_snapshot(run)",
                         "outer_snapshot(run)", "ImageCommand::Clear", "ImageCommand::Inherit"):
            self.assertIn(spelling, source)
        for forbidden in ('"pull"', '"build"', '"prune"', '"rmi"', "--privileged", "--volume"):
            self.assertNotIn(forbidden, source)
        lib = (ROOT / "src/lib.rs").read_text()
        self.assertIn("mod native_health_metadata_tests;", lib)
        self.assertNotIn("mod native_command_clear_tests;", lib)


class CommandClearEvidenceTests(unittest.TestCase):
    run_emit = external.ExternalNetworkEvidenceTests.run_emit
    emit = external.ExternalNetworkEvidenceTests.emit

    def test_all_lanes_project_only_guarded_raw_source_singleton_and_exact_baseline(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            result, path = self.emit(lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout + result.stderr, "")
            raw = path.read_text()
            record = json.loads(raw)
            self.assertEqual(record["command_clear_contract"], "command-clear-v1")
            self.assertEqual(record["command_clear_projection_contract"], "command-clear-native-source-v1")
            self.assertEqual(record["command_clear_outcomes"], OUTCOME)
            self.assertEqual(record["admitted_shapes"], expected_shapes(lane))
            self.assertEqual(record["capability_outcome"], dict.fromkeys(expected_shapes(lane), "available"))
            for forbidden in ("ContainerHostname", "EntrypointClear", "StopTimeout", "ShmSize"):
                self.assertNotIn(forbidden, record["capability_outcome"])
                self.assertNotIn(forbidden, record["admitted_shapes"])
            for private in ("process_argv", "dl-command-", "/dl-image-entrypoint", "image-command",
                            "daemon_uid", "f" * 64, SECRET):
                self.assertNotIn(private, raw)

    def test_emitter_requires_exact_ordered_two_shape_reader_return_before_publication(self):
        spec = importlib.util.spec_from_file_location("command_clear_emitter_test", ROOT / "scripts/native-evidence.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result, destination = self.emit()
        self.assertEqual(result.returncode, 0, result.stderr)
        destination.unlink()
        arguments = result.args[2:]
        for returned in (("ClearCommand",), ("ClearEntrypoint", "ClearCommand"),
                         ["ClearCommand", "ClearEntrypoint"], (), None):
            with self.subTest(returned=returned), patch.object(module, "read_command_clear_proof", return_value=returned), \
                    patch.dict(os.environ, {"NATIVE_OUTER_ENGINE": "podman", "NATIVE_FIXTURE_IMAGE": external.legacy.HEALTH_FIXTURE_IMAGE,
                                            "NATIVE_OUTER_CONTAINER_ID": "f" * 64, "NATIVE_BIND_RELABEL_DAEMON_UID": "0"}):
                with self.assertRaisesRegex(ValueError, "^invalid private command clear proof$"):
                    module.emit(*[Path(item) for item in arguments[:13]], *arguments[13:])
                self.assertFalse(destination.exists())

    def test_missing_either_proof_never_publishes_on_any_lane(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            for option in ("hostname_missing", "command_clear_missing"):
                result, path = self.emit(lane, **{option: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "native evidence rejected\n")

    def test_independent_context_defaults_effect_types_and_private_custody_refuse(self):
        for fault in ("candidate", "uid", "outer", "path", "missing_default", "missing_role", "reordered_controls", "empty_default", "partial",
                      "marker", "argv", "type", "cleanup", "unknown", "malformed", "duplicate", "mode", "hardlink", "symlink"):
            with self.subTest(fault=fault):
                result, path = self.emit()
                self.assertEqual(result.returncode, 0, result.stderr)
                proof_path = path.parent.parent / "command-clear-v1.json"
                proof = json.loads(proof_path.read_text())
                path.unlink()
                if fault == "candidate":
                    proof["context"]["candidate_sha"] = "e" * 40
                elif fault == "uid":
                    proof["context"]["daemon_uid"] = 1
                elif fault == "outer":
                    proof["context"]["outer"]["id"] = "e" * 64
                elif fault == "path":
                    proof["context"]["outer"]["socket_source"] = "/foreign/socket"
                elif fault == "missing_default":
                    proof["cases"].pop(0)
                elif fault == "missing_role":
                    proof["cases"][2]["containers"].pop()
                elif fault == "reordered_controls":
                    proof["cases"].reverse()
                elif fault == "empty_default":
                    proof["derived_image"]["command"] = []
                elif fault == "partial":
                    proof["shapes"].pop()
                elif fault == "marker":
                    proof["cases"][2]["containers"][1]["marker"] = SECRET
                elif fault == "argv":
                    proof["cases"][3]["containers"][1]["process_argv"].pop()
                elif fault == "type":
                    proof["cases"][0]["containers"][0]["restart_count"] = False
                elif fault == "cleanup":
                    proof["cleanup"]["uncertain"] = True
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
                    env={**os.environ, "NATIVE_OUTER_ENGINE": "podman", "NATIVE_FIXTURE_IMAGE": external.legacy.HEALTH_FIXTURE_IMAGE,
                         "NATIVE_OUTER_CONTAINER_ID": "f" * 64, "NATIVE_BIND_RELABEL_DAEMON_UID": "0"})
                self.assertNotEqual(output.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual(output.stdout, "")
                self.assertEqual(output.stderr, "native evidence rejected\n")
                self.assertNotIn(SECRET, output.stdout + output.stderr)


if __name__ == "__main__":
    unittest.main()
