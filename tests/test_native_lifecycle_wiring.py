"""Pure exact-selection, privacy, and teardown fault injection; no native runtime."""

import json
import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELECTED = "native_health_metadata_tests::lifecycle::live_lifecycle_matches_engine"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 100 filtered out;"
HANDOFF = "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"


class LifecycleWiringTests(unittest.TestCase):
    def wrapper(self, output=SUCCESS, status=0, listing=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo"
            cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                'case " $* " in *" --list "*) printf "%s\\n" "$LIST"; exit 0;; esac\n'
                'test "$NATIVE_LIFECYCLE_DEADLINE_EPOCH" = "$NATIVE_HEALTH_METADATA_DEADLINE_EPOCH" || exit 97\n'
                'test "$NATIVE_LIFECYCLE_CLEANUP_OWNER" = native_conformance_outer_v1 || exit 98\n'
                'printf "%s\\n" "$OUTPUT"; exit "$STATUS"\n')
            cargo.chmod(0o700)
            calls = root / "calls"
            result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                "native_lifecycle", "live_lifecycle_matches_engine"], capture_output=True, text=True, timeout=8,
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "CALLS": str(calls),
                     "LIST": f"{SELECTED}: test" if listing is None else listing, "OUTPUT": output,
                     "STATUS": str(status), "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1"})
            return result, calls.read_text().splitlines()

    def test_seventeenth_exact_test_retains_one_execution_and_original_deadline(self):
        for case in ("pass", "zero", "two", "absent", "duplicate", "failed"):
            listing = {"absent": "", "duplicate": f"{SELECTED}: test\n{SELECTED}: test"}.get(case)
            output = SUCCESS.replace("1 passed", {"zero": "0 passed", "two": "2 passed"}.get(case, "1 passed"))
            result, calls = self.wrapper(output, 101 if case == "failed" else 0, listing)
            self.assertEqual(result.returncode == 0, case == "pass")
            self.assertTrue(all("--lib" in call and "--test" not in call for call in calls))
            if len(calls) == 2:
                self.assertIn(f"--ignored --exact {SELECTED}", calls[-1])

    def test_original_failure_survives_cleanup_and_only_fixed_handoff_crosses_boundary(self):
        output = ("DOCKERLENS_NATIVE_CHECK: lifecycle_context\n"
            "DOCKERLENS_NATIVE_LIFECYCLE_STAGE: case=5 stage=early\n"
            f"thread '{SELECTED}' panicked at src/native_lifecycle_tests.rs:123:4:\nPRIVATE_CANARY\n"
            "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup\n"
            f"thread '{SELECTED}' panicked at src/native_lifecycle_tests.rs:456:8:\n"
            "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + HANDOFF + "\n" + FAILED)
        result, _ = self.wrapper(output, 101)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed (exit 101)", result.stderr)
        self.assertIn("source=native_lifecycle_tests line=123 column=4", result.stderr)
        self.assertIn("case=5 stage=early", result.stderr)
        self.assertIn(HANDOFF, result.stderr)
        self.assertNotIn("line=456", result.stderr)
        self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)
        for malformed in (HANDOFF + " PRIVATE_CANARY", HANDOFF + "\rPRIVATE_CANARY",
                          HANDOFF.replace("state=required", "state=PRIVATE_CANARY")):
            result, _ = self.wrapper(malformed + "\n" + FAILED, 101)
            self.assertNotIn("DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP:", result.stderr)
            self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)
        result, _ = self.wrapper(HANDOFF + "\n" + SUCCESS)
        self.assertNotEqual(result.returncode, 0, "handoff must not be accepted as completed cleanup")

    def test_owner_token_is_scoped_to_canonical_invocation_and_no_new_emitter_argument(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        invocations = re.findall(r'^"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)
        self.assertEqual(len(invocations), 24)
        self.assertEqual(invocations[16:22], [
            ("native_lifecycle", "live_lifecycle_matches_engine"),
            ("native_runtime_filesystem", "live_runtime_filesystem_matches_engine"),
            ("native_tmpfs_effect", "live_tmpfs_effects_match_engine"),
            ("native_health_start_interval_boundary", "live_health_start_interval_boundary_matches_engine"),
            ("native_lifecycle_default_effect", "live_lifecycle_default_effects_match_engine"),
            ("native_hostname", "live_hostname_matches_engine"),
        ])
        self.assertIn('unset NATIVE_LIFECYCLE_CLEANUP_OWNER', source)
        self.assertIn('(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1\n'
                      '"$(dirname "$0")/run-exact-native-test.sh" native_lifecycle live_lifecycle_matches_engine\n'
                      '"$(dirname "$0")/run-exact-native-test.sh" native_runtime_filesystem live_runtime_filesystem_matches_engine\n'
                      '"$(dirname "$0")/run-exact-native-test.sh" native_tmpfs_effect live_tmpfs_effects_match_engine\n'
                      '"$(dirname "$0")/run-exact-native-test.sh" native_health_start_interval_boundary live_health_start_interval_boundary_matches_engine\n'
                      '"$(dirname "$0")/run-exact-native-test.sh" native_lifecycle_default_effect live_lifecycle_default_effects_match_engine\n'
                      '"$(dirname "$0")/run-exact-native-test.sh" native_hostname live_hostname_matches_engine\n)', source)
        self.assertIn('export NATIVE_LIFECYCLE_PROOF_PATH="$run_dir/lifecycle-v1.json"', source)
        self.assertIn('export NATIVE_LIFECYCLE_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', source)
        self.assertNotIn('"$NATIVE_LIFECYCLE_PROOF_PATH"', source.split('python3 "$script_dir/native-evidence.py"', 1)[1])
        rust = (ROOT / "src/native_lifecycle_tests.rs").read_text()
        self.assertLess(rust.index('let cleanup_owner = BoundOuterCleanupOwner::bind(&run)'),
                        rust.index('let result = std::panic::catch_unwind', rust.index('fn live_lifecycle_matches_engine')))
        self.assertNotIn('run.cleaned = true', rust.split('fn cleanup(run:', 1)[1].split('fn create(', 1)[0])
        self.assertIn('mod lifecycle;', (ROOT / "src/native_health_metadata_tests.rs").read_text())


class LifecycleOuterCleanupTests(unittest.TestCase):
    def cleanup(self, fault="none", role="container", initial_status=0):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        helpers = source[source.index("cleanup_podman() {"):source.index("trap cleanup EXIT")]
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        run_dir = root / "dockerlens-native.fixture"
        run_dir.mkdir(mode=0o700)
        state = root / "state.json"
        objects = {"container": {"id": "a" * 64, "name": "dl-native-fixture", "present": True},
                   "sidecar": {"id": "b" * 64, "name": "dl-native-egress-fixture", "present": True},
                   "volume": {"name": "dl-native-data-fixture", "present": True},
                   "network": {"name": "dl-native-net-fixture", "present": True}}
        state.write_text(json.dumps(objects))
        calls = root / "calls"
        podman = root / "podman"
        podman.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]; path=Path(os.environ["STATE"]); objects=json.loads(path.read_text())
with open(os.environ["CALLS"], "a") as output: output.write(json.dumps(args)+"\\n")
fault=os.environ["FAULT"]; selected=os.environ["ROLE"]; key=args[-1]
matches=[(role,obj) for role,obj in objects.items() if key in (obj.get("id"),obj["name"])]
if not matches: sys.exit(125)
role,obj=matches[0]; active=role==selected
if "exists" in args:
    if active and (fault=="presence_unknown" or fault=="readback_unknown" and obj.get("removed")): sys.exit(125)
    if active and fault=="warning_presence": print("PRIVATE_CANARY",file=sys.stderr)
    sys.exit(0 if obj["present"] else 1)
if "inspect" in args:
    if active and fault=="inspect_unknown": sys.exit(125)
    if role in ("container","sidecar"):
        identifier=obj["id"] if not(active and fault=="id_changed") else "c"*64
        name=obj["name"] if not(active and fault=="name_changed") else "foreign"
        owner="fixture" if not(active and fault=="owner_changed") else "foreign"
        print(identifier+"|"+name+"|"+owner)
    elif role=="volume":
        created="2026-10-01T00:00:00Z" if not(active and fault=="created_changed") else "2026-10-02T00:00:00Z"
        mount="/private/data" if not(active and fault=="mount_changed") else "/private/other"
        owner="fixture" if not(active and fault=="owner_changed") else "foreign"
        print(obj["name"]+"|local|"+mount+"|"+created+"|"+owner)
    else: print("foreign" if active and fault=="owner_changed" else "fixture")
    sys.exit(0)
if "rm" in args:
    if active and fault=="remove_unknown": sys.exit(124)
    if not(active and fault=="leftover"): obj["present"]=False
    obj["removed"]=True; path.write_text(json.dumps(objects)); sys.exit(0)
sys.exit(125)
''')
        podman.chmod(0o700)
        bound_id = "" if fault == "unbound" and role == "container" else "a" * 64
        volume_identity = "" if fault == "unbound" and role == "volume" else "dl-native-data-fixture|local|/private/data|2026-10-01T00:00:00Z|fixture"
        setup = f'''set -euo pipefail
script_dir={shlex.quote(str(ROOT / "scripts"))}
run_dir={shlex.quote(str(run_dir))}; podman_cmd=({shlex.quote(str(podman))})
container=dl-native-fixture; sidecar=dl-native-egress-fixture; volume=dl-native-data-fixture; outer_network=dl-native-net-fixture
run_id=fixture; lane=synthetic; watchdog_pid=; preserve_run_dir=0; native_success_summary=passed
outer_container_id={shlex.quote(bound_id)}; sidecar_container_id={"b" * 64}
outer_attempted=1; sidecar_attempted=1; volume_attempted=1; network_attempted=1; network_created=1
volume_identity={shlex.quote(volume_identity)}
'''
        result = subprocess.run(["bash", "-c", setup + helpers + f'\ntrap cleanup EXIT\nexit {initial_status}\n'],
            env={**os.environ, "STATE": str(state), "CALLS": str(calls), "FAULT": fault, "ROLE": role,
                 "TMPDIR": str(root)}, capture_output=True, text=True, timeout=8)
        commands = [json.loads(line) for line in calls.read_text().splitlines()]
        return result, commands, json.loads(state.read_text()), run_dir.exists()

    def test_exact_ids_are_deleted_and_both_identity_forms_prove_absence(self):
        result, commands, objects, retained = self.cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(retained)
        self.assertEqual(result.stdout, "passed\n")
        self.assertTrue(all(not item["present"] for item in objects.values()))
        for role, identifier in (("container", "a" * 64), ("sidecar", "b" * 64)):
            self.assertIn(["rm", "--force", "--time", "0", identifier], commands)
            self.assertIn(["container", "exists", identifier], commands)
            self.assertEqual(commands.count(["container", "exists", objects[role]["name"]]), 2)
        result, _, _, _ = self.cleanup(initial_status=37)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("passed", result.stdout)

    def test_container_uncertainty_never_authorizes_removal_retry_or_storage_teardown(self):
        for fault in ("unbound", "presence_unknown", "warning_presence", "inspect_unknown", "id_changed", "name_changed", "owner_changed", "remove_unknown", "leftover", "readback_unknown"):
            result, commands, _, retained = self.cleanup(fault)
            self.assertNotEqual(result.returncode, 0, fault)
            self.assertTrue(retained, fault)
            deletes = [args for args in commands if "rm" in args and args[-1] == "a" * 64]
            self.assertLessEqual(len(deletes), 1)
            self.assertEqual(bool(deletes), fault in ("remove_unknown", "leftover", "readback_unknown"))
            self.assertFalse(any(args[:2] in (["volume", "rm"], ["network", "rm"]) for args in commands))
            self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)
            self.assertNotIn("passed", result.stdout)

    def test_volume_static_identity_and_transport_ambiguity_are_fail_closed(self):
        for fault in ("unbound", "presence_unknown", "inspect_unknown", "created_changed", "mount_changed", "owner_changed", "remove_unknown", "readback_unknown"):
            result, commands, _, retained = self.cleanup(fault, "volume")
            self.assertNotEqual(result.returncode, 0, fault)
            self.assertTrue(retained, fault)
            deletes = [args for args in commands if args[:2] == ["volume", "rm"]]
            self.assertLessEqual(len(deletes), 1)
            self.assertEqual(bool(deletes), fault in ("remove_unknown", "readback_unknown"))


if __name__ == "__main__":
    unittest.main()
