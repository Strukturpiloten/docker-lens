"""PIDs27 closed argv/caller/stream controls with inert runtime substitutes."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CID = "a" * 64
NONCE = "0123456789abcdef0123456789abcdef"
TEST = "live_pids_limits_and_effects_match_engine"
SELECTED = "native_health_metadata_tests::lifecycle::pids::" + TEST
HANDOFF = "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"


class PidsWiringTests(unittest.TestCase):
    def bridge(self, engine, arguments):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "native-outer-command.sh"
            script.write_bytes((ROOT / "scripts/native-outer-command.sh").read_bytes())
            (root / "native-outer-runtime.sh").write_text('''native_outer_attach() {
  [[ $1 == "$EXPECTED_ENGINE" && $2 == "$EXPECTED_DIRECTORY" ]] || return 1
  native_outer_cmd=("$FAKE_RUNTIME")
}
''')
            runtime = root / "inert-runtime"
            runtime.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
Path(os.environ["TRACE"]).write_text(json.dumps(sys.argv[1:]))
sys.stdout.buffer.write(sys.stdin.buffer.read())
''')
            runtime.chmod(0o700)
            result = subprocess.run(["bash", str(script), "--engine", engine, "--directory", directory, "pids-controller", *arguments],
                input=b"private literal stream\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                env={**os.environ, "EXPECTED_ENGINE": engine, "EXPECTED_DIRECTORY": directory,
                     "FAKE_RUNTIME": str(runtime), "TRACE": str(root / "trace")}, timeout=5)
            trace = json.loads((root / "trace").read_text()) if (root / "trace").exists() else None
            return result, trace

    def test_selected_backend_keeps_fixed_argv_and_interactive_bytes_without_host_runtime(self):
        for engine in ("podman", "docker"):
            for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
                args = [CID, "Ab12Cd34", lane, NONCE, "123456789"]
                result, trace = self.bridge(engine, args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(trace, ["exec", "-i", "--user", "0", CID,
                    "/dockerlens-native/pids-worker/native-pids-worker", "serve", *args[1:]])
                self.assertEqual(result.stdout, b"private literal stream\n")
                self.assertEqual(result.stderr, b"")

    def test_bridge_rejects_widening_ids_lanes_nonce_deadline_and_extra_arguments(self):
        args = [CID, "Ab12Cd34", "upstream-rootful", NONCE, "123456789"]
        for changed in [args + ["/bin/sh"], args[:-1], ["name", *args[1:]], [CID, "../run", *args[2:]],
                        [*args[:2], "foreign-rootful", *args[3:]], [*args[:3], "x" * 32, args[4]],
                        [*args[:4], "0"], [*args[:4], "123;id"]]:
            result, trace = self.bridge("podman", changed)
            self.assertEqual(result.returncode, 2)
            self.assertIsNone(trace)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"native outer command refused\n")

    def wrapper(self, output, status=0, listing=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cargo = root / "cargo"
            cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"argv":sys.argv[1:], "deadline":os.environ.get("NATIVE_PIDS_DEADLINE_EPOCH"),
                            "owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")}) + "\\n")
if "--list" in sys.argv:
    print(os.environ["LISTING"])
else:
    print(os.environ["OUTPUT"])
    sys.exit(int(os.environ["STATUS"]))
''')
            cargo.chmod(0o700)
            result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"), "native_pids", TEST],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "TRACE": str(root / "trace"),
                     "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1", "LISTING": SELECTED + ": test" if listing is None else listing,
                     "OUTPUT": output, "STATUS": str(status)})
            return result, [json.loads(row) for row in (root / "trace").read_text().splitlines()]

    def test_exact_selector_and_original_deadline_reject_zero_execution_and_cleanup_handoff(self):
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
        result, trace = self.wrapper(success)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(trace), 2)
        self.assertIn("--lib", trace[1]["argv"])
        self.assertIn(SELECTED, trace[1]["argv"])
        self.assertIn("--ignored", trace[1]["argv"])
        self.assertIn("--exact", trace[1]["argv"])
        self.assertRegex(trace[1]["deadline"], r"^[1-9][0-9]+$")
        self.assertEqual(trace[1]["owner"], "native_conformance_outer_v1")
        for output, status, listing in [(success, 0, ""), (success, 0, (SELECTED + ": test\n") * 2),
                (success.replace("1 passed", "0 passed"), 0, None), (success + "\n" + HANDOFF, 0, None),
                ("DOCKERLENS_NATIVE_CHECK: pids_context\nPRIVATE_PIDS_CANARY\n" + success, 1, None)]:
            result, _ = self.wrapper(output, status, listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"PRIVATE_PIDS_CANARY", result.stdout + result.stderr)

    def test_canonical27_is_after_kernel_reader_and_before_final_emission(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = re.findall(r'run-exact-native-test\.sh" ([a-z_0-9]+) ([a-z_0-9]+)', source)
        self.assertEqual(calls[-2:], [("native_kernel_settings", "live_kernel_settings_match_engine"), ("native_pids", TEST)])
        self.assertEqual(len(calls), 27)
        reader = source.index('python3 "$script_dir/native_pids_proof.py"')
        child = source.index('"$(dirname "$0")/run-exact-native-test.sh" native_pids')
        prebuild = source.index('python3 "$script_dir/build-native-pids-worker.py"')
        publication = source.index('publish_native_evidence() {')
        self.assertEqual(source.count('publish_native_evidence() {'), 1)
        self.assertLess(source.index('python3 "$script_dir/native_kernel_settings_proof.py"'), child)
        self.assertLess(prebuild, child)
        self.assertLess(child, reader)
        # The maintained-profile lane publishes only during EXIT after outer
        # teardown. Native work must complete before that deferred function is
        # even defined, irrespective of optional public evidence selection.
        for required_native_step in (prebuild, child, reader):
            self.assertLess(required_native_step, publication)
        self.assertLess(reader, source.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', reader))

    def test_required27_precedes_cleanup_and_failure_never_reaches_deferred_publication(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        # Execute the actual final coordinator segment with inert command
        # substitutes. Only publication is deferred; no runtime is contacted.
        start = source.index('# Build the fixed inert witness before invocation27')
        end = source.index('\nnative_success_summary=', start)
        segment = source[start:end]
        for profile in ("", "owned-profile"):
            for evidence in ("", "synthetic-evidence"):
                for failure in ("", "prebuild", "child", "reader"):
                    with self.subTest(profile=profile, evidence=bool(evidence), failure=failure), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / "socket").mkdir(mode=0o700)
                        (root / "python3").write_text('''#!/usr/bin/python3
import os, sys
if sys.argv[1] == "-c":
    print("123456789")
    raise SystemExit(0)
name = sys.argv[1].rsplit("/", 1)[-1]
event = {"build-native-pids-worker.py":"prebuild", "native_pids_proof.py":"reader"}[name]
with open(os.environ["TRACE"], "a") as stream:
    stream.write(event + "\\n")
raise SystemExit(int(os.environ["FAILURE"] == event))
''')
                        (root / "python3").chmod(0o700)
                        child = root / "run-exact-native-test.sh"
                        child.write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ $1 == native_pids && $2 == live_pids_limits_and_effects_match_engine ]]
printf 'child\\n' >> "$TRACE"
[[ $FAILURE != child ]]
''')
                        child.chmod(0o700)
                        harness = root / "coordinator-tail.sh"
                        harness.write_text('''#!/usr/bin/env bash
set -euo pipefail
native_publication_command() {
  if [[ $1 == git ]]; then
    if [[ $* == *'rev-parse HEAD' ]]; then printf '%s\\n' "$NATIVE_PIDS_CANDIDATE_SHA"; fi
  else
    printf 'emitter\\n' >> "$TRACE"
  fi
}
cleanup() {
  local status=$?
  trap - EXIT
  printf 'teardown\\n' >> "$TRACE"
  if [[ -n $apparmor_profile && $status == 0 && ${apparmor_native_completed:-0} == 1 ]]; then
    publish_native_evidence || status=$?
  fi
  exit "$status"
}
trap cleanup EXIT
''' + segment + '\nprintf "complete\\n" >> "$TRACE"\n')
                        variables = {name: "synthetic" for name in (
                            "run_id", "lane", "server_version", "api_version", "expected_mode", "image", "installed_docker_package",
                            "NATIVE_FIXTURE_IMAGE", "NATIVE_OUTER_CONTAINER_ID", "NATIVE_OUTER_IMAGE", "NATIVE_SHAPES_PATH",
                            "NATIVE_SOURCE_PROBES_PATH", "NATIVE_NETWORK_PROBES_PATH", "NATIVE_VOLUME_PROBES_PATH",
                            "NATIVE_VOLUME_LABEL_PROBES_PATH", "NATIVE_IDENTITY_PROBES_PATH", "NATIVE_PORT_PROBES_PATH",
                            "NATIVE_HEALTH_METADATA_PROOF_PATH", "NATIVE_NETWORK_ATTACHMENT_PROOF_PATH", "NATIVE_BIND_RELABEL_PROOF_PATH")}
                        result = subprocess.run(["bash", str(harness)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5,
                            env={**os.environ, **variables, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                                 "TRACE": str(root / "trace"), "FAILURE": failure, "run_dir": directory, "script_dir": directory,
                                 "NATIVE_PIDS_CANDIDATE_SHA": "a" * 40, "DOCKERLENS_NATIVE_CANDIDATE_SHA": "a" * 40,
                                 "apparmor_profile": profile, "DOCKERLENS_NATIVE_EVIDENCE_DIR": evidence})
                        trace = (root / "trace").read_text().splitlines()
                        expected = ["prebuild", "child", "reader"]
                        if failure:
                            self.assertNotEqual(result.returncode, 0)
                            self.assertEqual(trace, expected[:expected.index(failure) + 1] + ["teardown"])
                        else:
                            self.assertEqual(result.returncode, 0, result.stderr)
                            if evidence and not profile:
                                expected.append("emitter")
                            expected.extend(["complete", "teardown"])
                            if evidence and profile:
                                expected.append("emitter")
                            self.assertEqual(trace, expected)


if __name__ == "__main__":
    unittest.main()
