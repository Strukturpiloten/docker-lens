"""Canonical process-source wiring; synthetic controls are not native evidence."""

import json
import os
import re
import subprocess
import tempfile
import time
import unittest
from native_harness_syntax import native_calls, shell_tail, bind_tail_pids_proof
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_command_clear"
TEST = "live_command_clear_matches_engine"
SELECTED = f"native_health_metadata_tests::command_clear::{TEST}"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
SECRET = "PRIVATE_COMMAND_CLEAR_CANARY"


class CommandClearWiringTests(unittest.TestCase):
    def wrapper(self, output=SUCCESS, status=0, listing=None):
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
else:
    print(os.environ["OUTPUT"])
    sys.exit(int(os.environ["STATUS"]))
''')
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", TRACE=str(trace),
                       LISTING=f"{SELECTED}: test" if listing is None else listing,
                       OUTPUT=output, STATUS=str(status))
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
        self.assertEqual(len(calls), 28)
        self.assertEqual(calls[26:27], [("native_pids_limit", "live_pids_limit_effects_match_engine")])
        self.assertEqual(calls[27:], [("native_nofile", "live_nofile_limits_and_effects_match_engine")])
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

    def test_exact_selection_deadline_and_no_lifecycle_handoff(self):
        result, calls, began, ended = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["args"][-3:], ["--", "--ignored", "--list"])
        self.assertEqual(calls[1]["args"][-4:], ["--", "--ignored", "--exact", SELECTED])
        self.assertEqual(calls[1]["deadline"], calls[1]["shared_deadline"])
        self.assertTrue(began + 180 <= int(calls[1]["deadline"]) <= ended + 180)
        self.assertIsNone(calls[1]["owner"])
        for listing in ("", f"{SELECTED}: test\n{SELECTED}: test", "other: test"):
            result, calls, _, _ = self.wrapper(listing=listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 1)
        for output in ("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;",
                       "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;",
                       SUCCESS + "\nDOCKERLENS_NATIVE_CHECK: command_clear_cleanup_unverified"):
            self.assertNotEqual(self.wrapper(output)[0].returncode, 0)

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

                def invoke(arguments):
                    return subprocess.run(["python3", "-", str(ROOT / "scripts"), *arguments],
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

    def test_actual_harness_tail_requires_both_readers_before_public_emission(self):
        from test_native_command_clear_proof import fixture as command_fixture
        from test_native_hostname_proof import fixture as hostname_fixture
        from test_native_shm_size_proof import fixture as shm_fixture
        from test_native_supplementary_groups_proof import fixture as supplementary_fixture
        from test_native_kernel_settings_proof import fixture as kernel_fixture
        from test_native_pids_limit_v2_proof import fixture as pids_fixture
        from test_native_nofile_proof import fixture as nofile_fixture

        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        tail = harness.split('python3 "$script_dir/native_hostname_proof.py"', 1)[1].split(
            '\nif [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', 1)[0]
        tail = 'python3 "$script_dir/native_hostname_proof.py"' + tail
        tail = shell_tail(tail, "command_wrapper")
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            for fault in ("none", "hostname_missing", "hostname_context", "command_missing",
                          "command_effect", "command_cleanup", "native_failure", "shm_missing",
                          "shm_context", "shm_effect", "shm_cleanup", "shm_native_failure",
                          "supplementary_missing", "supplementary_context", "supplementary_effect",
                          "supplementary_cleanup", "supplementary_native_failure",
                          "kernel_missing", "kernel_context", "kernel_false", "kernel_namespace",
                          "kernel_cleanup", "kernel_native_failure", "pids_missing", "pids_context",
                          "pids_effect", "pids_cleanup", "pids_native_failure"):
                with self.subTest(lane=lane, fault=fault), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    hostname = hostname_fixture(lane)
                    context = hostname["context"]
                    context["outer"]["socket_source"] = str(root / "socket")
                    # The independent outer-image authority now checks an
                    # actual repository/tag/digest shape, including a slash.
                    context["outer"]["image"] = "example.invalid/" + context["outer"]["image"]
                    command = command_fixture(lane)
                    command["context"] = json.loads(json.dumps(context))
                    command["seed"]["image"] = context["fixture_image"]
                    shm = shm_fixture(lane)
                    shm["context"] = json.loads(json.dumps(context))
                    supplementary = supplementary_fixture(lane)
                    supplementary["context"] = json.loads(json.dumps(context))
                    kernel = kernel_fixture(lane)
                    kernel["context"] = json.loads(json.dumps(context))
                    pids = pids_fixture(lane)
                    pids["context"] = json.loads(json.dumps(context))
                    bind_tail_pids_proof(pids, root, lane, context["outer"]["image"], context["candidate_sha"])
                    nofile = nofile_fixture(lane)
                    nofile["context"] = json.loads(json.dumps(context))
                    env = dict(os.environ, script_dir=str(ROOT / "scripts"), run_dir=str(root),
                               NATIVE_HOSTNAME_CANDIDATE_SHA=context["candidate_sha"],
                               NATIVE_COMMAND_CLEAR_CANDIDATE_SHA=context["candidate_sha"],
                               NATIVE_SHM_SIZE_CANDIDATE_SHA=context["candidate_sha"],
                               NATIVE_SUPPLEMENTARY_GROUPS_CANDIDATE_SHA=context["candidate_sha"],
                               NATIVE_KERNEL_SETTINGS_CANDIDATE_SHA=context["candidate_sha"],
                               NATIVE_PIDS_LIMIT_CANDIDATE_SHA=context["candidate_sha"],
                               NATIVE_NOFILE_CANDIDATE_SHA=context["candidate_sha"],
                               run_id=context["run_id"], lane=lane, server_version=context["engine_release"],
                               api_version=context["rendering_api"], expected_mode=context["mode"],
                               installed_docker_package=context["docker_package"],
                               NATIVE_FIXTURE_IMAGE=context["fixture_image"], image=context["outer"]["image"],
                               NATIVE_OUTER_CONTAINER_ID=context["outer"]["id"],
                               NATIVE_BIND_RELABEL_DAEMON_UID=str(context["daemon_uid"]),
                               TRACE=str(root / "trace"), STATUS="37" if fault == "native_failure" else "0",
                               SHM_STATUS="41" if fault == "shm_native_failure" else "0",
                               SUPPLEMENTARY_STATUS="43" if fault == "supplementary_native_failure" else "0",
                               KERNEL_STATUS="47" if fault == "kernel_native_failure" else "0",
                               PIDS_STATUS="53" if fault == "pids_native_failure" else "0")
                    env.pop("NATIVE_LIFECYCLE_CLEANUP_OWNER", None)
                    if fault == "hostname_context":
                        hostname["context"]["candidate_sha"] = "e" * 40
                    elif fault == "command_effect":
                        command["cases"][2]["containers"][1]["marker"] = SECRET
                    elif fault == "command_cleanup":
                        command["cleanup"]["uncertain"] = True
                    elif fault == "shm_context":
                        shm["context"]["candidate_sha"] = "e" * 40
                    elif fault == "shm_effect":
                        shm["cases"][1]["containers"][1]["write_outcome"] = SECRET
                    elif fault == "shm_cleanup":
                        shm["cleanup"]["uncertain"] = True
                    elif fault == "supplementary_context":
                        supplementary["context"]["candidate_sha"] = "e" * 40
                    elif fault == "supplementary_effect":
                        supplementary["cases"][0]["containers"][0]["effect"]["files"][0]["outcome"] = SECRET
                    elif fault == "supplementary_cleanup":
                        supplementary["cleanup"]["uncertain"] = True
                    elif fault == "kernel_context":
                        kernel["context"]["candidate_sha"] = "e" * 40
                    elif fault == "kernel_false":
                        kernel["cases"][1]["containers"][0]["effect"]["parent_nnp"] = 1
                    elif fault == "kernel_namespace":
                        kernel["cases"][0]["containers"][0]["effect"]["net_namespace"] = kernel["outer_namespaces"]["net"]
                    elif fault == "kernel_cleanup":
                        kernel["cleanup"]["uncertain"] = True
                    elif fault == "pids_context":
                        pids["context"]["candidate_sha"] = "e" * 40
                    elif fault == "pids_effect":
                        pids["cases"][0]["work"]["successes"] = 13
                    elif fault == "pids_cleanup":
                        pids["cleanup"]["uncertain"] = True
                    for family, proof in (("hostname", hostname), ("command", command), ("shm", shm),
                                          ("supplementary", supplementary), ("kernel", kernel), ("pids", pids), ("nofile", nofile)):
                        if fault != family + "_missing":
                            path = root / {"hostname": "hostname-v1.json", "command": "command-clear-v1.json",
                                           "shm": "shm-size-v1.json",
                                           "supplementary": "supplementary-groups-v1.json",
                                           "kernel": "kernel-settings-v1.json", "pids": "pids-limit-v2.json",
                                           "nofile": "nofile-v1.json"}[family]
                            serialization = {"separators": (",", ":")} if family == "pids" else {}
                            path.write_text(json.dumps(proof, **serialization))
                            path.chmod(0o600)
                    script = ('set -euo pipefail\ncommand_wrapper() {\n'
                              'if [[ $1 != native_command_clear ]]; then\n'
                              '  [[ ${NATIVE_LIFECYCLE_CLEANUP_OWNER:-} == native_conformance_outer_v1 ]] || return 99\n'
                              'else [[ -z ${NATIVE_LIFECYCLE_CLEANUP_OWNER:-} ]] || return 98; fi\n'
                              'printf "%s\\n" "$*" >> "$TRACE"\n'
                              'case $1 in native_shm_size) return "$SHM_STATUS";;\n'
                              'native_supplementary_groups) return "$SUPPLEMENTARY_STATUS";;\n'
                              'native_kernel_settings) return "$KERNEL_STATUS";;\n'
                              'native_pids_limit) return "$PIDS_STATUS";; native_nofile) return 0;; esac\nreturn "$STATUS"; }\n'
                              + tail + '\nprintf "public\\n" >> "$TRACE"\n')
                    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True,
                                            text=True, timeout=5, check=False)
                    trace = root / "trace"
                    events = trace.read_text().splitlines() if trace.exists() else []
                    expected = [] if fault.startswith("hostname_") else [f"{TARGET} {TEST}"]
                    if fault == "none" or fault.startswith(("shm_", "supplementary_", "kernel_", "pids_")):
                        expected.append("native_shm_size live_shm_size_effects_match_engine")
                    if fault == "none" or fault.startswith(("supplementary_", "kernel_", "pids_")):
                        expected.append("native_supplementary_groups live_supplementary_groups_match_engine")
                    if fault == "none" or fault.startswith(("kernel_", "pids_")):
                        expected.append("native_kernel_settings live_kernel_settings_match_engine")
                    if fault == "none" or fault.startswith("pids_"):
                        expected.append("native_pids_limit live_pids_limit_effects_match_engine")
                    if fault == "none":
                        expected.append("native_nofile live_nofile_limits_and_effects_match_engine")
                        expected.append("public")
                    self.assertEqual(events, expected)
                    self.assertEqual(result.returncode == 0, fault == "none", result.stderr)
                    if fault == "native_failure":
                        self.assertEqual(result.returncode, 37)
                    if fault == "shm_native_failure":
                        self.assertEqual(result.returncode, 41)
                    if fault == "supplementary_native_failure":
                        self.assertEqual(result.returncode, 43)
                    if fault == "kernel_native_failure":
                        self.assertEqual(result.returncode, 47)
                    if fault == "pids_native_failure":
                        self.assertEqual(result.returncode, 53)
                    self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_cleanup_delegation_is_not_success_and_is_not_retried(self):
        parent = (ROOT / "src/native_health_metadata_tests.rs").read_text()
        child = (ROOT / "src/native_command_clear_tests.rs").read_text()
        self.assertIn("cleanup_delegated: false", parent)
        self.assertIn("!self.cleaned && !self.cleanup_delegated", parent)
        self.assertIn("native.cleanup_delegated = true", child)
        self.assertNotIn(".cleaned =", child)
        self.assertIn("impl Drop for CommandRun", child)
        self.assertIn("self.cleanup_attempted = true", child)
        self.assertIn("command_clear_cleanup_unverified", child)
        self.assertIn("assert!(owned.cleanup_verified", child)

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


if __name__ == "__main__":
    unittest.main()
