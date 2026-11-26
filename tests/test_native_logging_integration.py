"""Registered logging32: real shared wrapper, coordinator and emitter controls."""
from copy import deepcopy
import base64
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_native_evidence as legacy
import test_native_external_network_evidence as canonical
import test_native_nofile_wiring as previous
from test_native_command_clear_projection import expected_shapes
from test_native_logging_proof import LANES, rebind

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_logging"
TEST = "live_logging_matches_engine"
SELECTED = "native_health_metadata_tests::lifecycle::logging::" + TEST
SUCCESS = b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;\n"
HANDOFF = b"DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required\n"
SECRET = b"PRIVATE_LOGGING_INTEGRATION_CANARY"


class LoggingIntegrationTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit
    emit = canonical.ExternalNetworkEvidenceTests.emit
    tail = previous.NofileWiringTests.tail

    def wrapper(self, output=SUCCESS, status=0, *, listing=None, name=TEST, cleanup_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cargo").write_text('''#!/usr/bin/python3
import base64,json,os,sys
with open(os.environ["TRACE"],"a") as out:
 out.write(json.dumps({"argv":sys.argv[1:],"deadline":os.environ.get("NATIVE_LOGGING_DEADLINE_EPOCH"),"shared":os.environ.get("NATIVE_LIFECYCLE_DEADLINE_EPOCH"),"owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")})+"\\n")
if "--list" in sys.argv:sys.stdout.buffer.write(base64.b64decode(os.environ["LISTING"]))
else:sys.stdout.buffer.write(open(os.environ["OUTPUT"],"rb").read());sys.exit(int(os.environ["STATUS"]))
''')
            (root / "date").write_text('#!/bin/sh\nprintf "date\\n" >> "$DATES"\nprintf "2000\\n"\n')
            if cleanup_failure:
                (root / "rm").write_text('#!/bin/sh\nexit 1\n')
                (root / "rm").chmod(0o700)
            for path in (root / "cargo", root / "date"):
                path.chmod(0o700)
            (root / "output").write_bytes(output)
            environment = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "TMPDIR": directory,
                           "TRACE": str(root / "trace"), "DATES": str(root / "dates"), "OUTPUT": str(root / "output"),
                           "STATUS": str(status), "LISTING": base64.b64encode((SELECTED + ": test\n").encode() if listing is None else listing).decode(),
                           "NATIVE_LOGGING_DEADLINE_EPOCH": "1", "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1"}
            result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, name],
                                    env=environment, capture_output=True, timeout=10, check=False)
            calls = [json.loads(line) for line in (root / "trace").read_text().splitlines()] if (root / "trace").exists() else []
            dates = (root / "dates").read_text().splitlines() if (root / "dates").exists() else []
            self.assertNotIn(SECRET, result.stdout + result.stderr)
            return result, calls, dates

    def test_exact_registered_selection_one_deadline_and_private_failure_projection(self):
        result, calls, dates = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertIn("--lib", calls[1]["argv"])
        self.assertEqual(calls[1]["argv"][-4:], ["--", "--ignored", "--exact", SELECTED])
        self.assertEqual((calls[1]["deadline"], calls[1]["shared"], dates), ("2180", "2180", ["date"]))
        self.assertEqual(calls[1]["owner"], "native_conformance_outer_v1")
        for listing in (b"", b"foreign: test\n", (SELECTED + ": test\n").encode() * 2):
            result, calls, dates = self.wrapper(listing=listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((len(calls), dates), (1, []))
        result, calls, dates = self.wrapper(name="other_test")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((calls, dates), ([], []))
        for output, status in ((SUCCESS, 101), (SUCCESS, 124), (SUCCESS, 130), (SUCCESS, 143),
                               (SUCCESS.replace(b"1 passed", b"0 passed"), 0), (SUCCESS.replace(b"1 passed", b"2 passed"), 0),
                               (HANDOFF + SUCCESS, 0), (b"DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + SUCCESS, 0),
                               (SECRET + b"\0" + SUCCESS, 0), (b"x" * 1048577 + SUCCESS, 0)):
            self.assertNotEqual(self.wrapper(output, status)[0].returncode, 0)
        self.assertNotEqual(self.wrapper(cleanup_failure=True)[0].returncode, 0)
        failure = (b"DOCKERLENS_NATIVE_CHECK: logging_effects\n" + f"thread '{SELECTED}' panicked at src/native_logging_tests.rs:123:4:\n".encode()
                   + SECRET + b"\nDOCKERLENS_NATIVE_CHECK: logging_cleanup\n" + HANDOFF)
        result, _, _ = self.wrapper(failure, 101)
        self.assertIn(b"source=native_logging_tests line=123 column=4", result.stderr)
        self.assertIn(b"logging_effects", result.stderr)
        result, _, _ = self.wrapper(b"thread 'worker' panicked at /private/hidden:1:1:\n" + failure, 101)
        self.assertIn(b"source=native_logging_tests location=unavailable", result.stderr)
        self.assertNotIn(b"line=123", result.stderr)

    def test_exact32_eleven_owners_and_immediate_logging_reader_after_all_predecessors(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = re.findall(r'^[ \t]*"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)
        expected = previous.ORIGINAL27 + [("native_nofile", "live_nofile_limits_and_effects_match_engine"),
                    ("native_device_mapping", "live_device_mapping_matches_engine"), ("native_memory", "live_memory_limits_and_effects_match_engine"),
                    ("native_capabilities", "live_named_capabilities_match_engine"), (TARGET, TEST)]
        self.assertEqual(calls, expected)
        self.assertEqual(len(calls), 32)
        self.assertEqual(source.count("export NATIVE_LIFECYCLE_CLEANUP_OWNER="), 11)
        stages = ['run-exact-native-test.sh" native_pids ', 'python3 "$script_dir/native_pids_proof.py"',
                  'run-exact-native-test.sh" native_nofile ', 'python3 "$script_dir/native_nofile_proof.py"',
                  'run-exact-native-test.sh" native_device_mapping ', 'python3 "$script_dir/native_device_mapping_proof.py"',
                  'run-exact-native-test.sh" native_memory ', 'python3 "$script_dir/native_memory_proof.py"',
                  'run-exact-native-test.sh" native_capabilities ', 'python3 "$script_dir/native_capabilities_proof.py"',
                  'run-exact-native-test.sh" native_logging ', 'python3 "$script_dir/native_logging_proof.py"', 'publish_native_evidence() {']
        positions = [source.index(stage) for stage in stages]
        self.assertEqual(positions, sorted(positions))
        command = shlex.split(source[positions[-2]:source.index('\n\n', positions[-2])].replace('\\\n', ' '))
        self.assertEqual(command[2:], ["$run_dir", "$NATIVE_LOGGING_CANDIDATE_SHA", "$run_id", "$lane", "$server_version", "$api_version",
                                      "$expected_mode", "$installed_docker_package", "$NATIVE_FIXTURE_IMAGE", "$image", "$NATIVE_OUTER_CONTAINER_ID", "$NATIVE_BIND_RELABEL_DAEMON_UID"])
        self.assertIn('export NATIVE_LOGGING_PROOF_PATH="$run_dir/logging-v1.json"', source)
        lifecycle = (ROOT / "src/native_lifecycle_tests.rs").read_text()
        self.assertIn('#[path = "native_logging_tests.rs"]\nmod logging;', lifecycle)

    def test_real_reader_without_emission_all_profiles_backends_and_every_prefix_failure(self):
        sequence = ["prebuild", "pids_child", "pids_reader", "nofile_child", "nofile_reader", "device_child", "device_reader",
                    "memory_child", "memory_reader", "capabilities_child", "capabilities_reader", "logging_child", "logging_reader"]
        for lane in LANES:
            for backend in ("podman", "docker"):
                result, events, _ = self.tail(lane, backend)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([event["event"] for event in events], sequence + ["complete", "teardown"])
                self.assertEqual(events[11]["owner"], "native_conformance_outer_v1")
                self.assertEqual(events[12]["backend"], backend)
                def corrupt(proof):
                    value = proof["containers"][4]["read"]
                    value.update(raw="permission denied\n", frame="permission denied\n\nDOCKERLENS_LOG_EXIT:1\n")
                    rebind(proof)
                result, events, _ = self.tail(lane, backend, logging_mutate=corrupt)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([event["event"] for event in events][-2:], ["logging_reader", "teardown"])
                self.assertEqual(result.stderr, b"invalid private logging proof\n")
        for failure in sequence:
            result, events, _ = self.tail("upstream-rootless", "docker", failure=failure, evidence=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual([event["event"] for event in events], sequence[:sequence.index(failure) + 1] + ["teardown"])

    def rerun(self, result, lane, backend):
        return subprocess.run(result.args, env={**os.environ, "NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                              "NATIVE_OUTER_CONTAINER_ID": "f" * 64, "NATIVE_OUTER_ENGINE": backend,
                              "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if lane.endswith("-rootless") else "0"},
                              capture_output=True, text=True, timeout=10, check=False)

    def test_existing_emitter_revalidates_private_proof_without_public_admission(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                result, path = self.emit(lane, outer_backend=backend)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(result.args) - 2, 19)
                self.assertEqual(json.loads(path.read_text())["admitted_shapes"], expected_shapes(lane))
                for private in ("logging-v1", "dl-log-", "max-size", "frame_sha256", "ordinary_calls"):
                    self.assertNotIn(private, path.read_text())
                source = path.parent.parent / "logging-v1.json"
                proof = json.loads(source.read_text())
                value = proof["containers"][0]["read"]
                value.update(raw="wrong\n", frame="wrong\n\nDOCKERLENS_LOG_EXIT:0\n")
                rebind(proof)
                source.write_text(json.dumps(proof, separators=(",", ":")))
                path.unlink()
                rejected = self.rerun(result, lane, backend)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual((rejected.stdout, rejected.stderr), ("", "native evidence rejected\n"))
                missing, missing_path = self.emit(lane, outer_backend=backend, logging_missing=True)
                self.assertNotEqual(missing.returncode, 0)
                self.assertFalse(missing_path.exists())

    def test_emitter_independently_rejects_wrong_typed_reader_results_before_output(self):
        spec = importlib.util.spec_from_file_location("logging_emitter_control", ROOT / "scripts/native-evidence.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(len(inspect.signature(module.emit).parameters), 19)
        empty = {"contract": "logging-v1", "capability_admission": [], "catalogue_admission": False}
        for backend in ("podman", "docker"):
            result, path = self.emit("upstream-rootless", outer_backend=backend)
            self.assertEqual(result.returncode, 0, result.stderr)
            path.unlink()
            path.parent.rmdir()
            arguments = [Path(value) for value in result.args[2:15]] + result.args[15:]
            expected = json.loads((path.parent.parent / "logging-v1.json").read_text())["context"]
            environment = {"NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                           "NATIVE_BIND_RELABEL_DAEMON_UID": "1000", "NATIVE_OUTER_ENGINE": backend}
            for invalid in (None, [], {}, {**empty, "extra": SECRET.decode()}, {**empty, "contract": 1}, {**empty, "contract": "wrong"},
                            {**empty, "capability_admission": ()}, {**empty, "capability_admission": ["LogConfig"]},
                            {**empty, "catalogue_admission": True}, {**empty, "catalogue_admission": 0}):
                with patch.dict(os.environ, environment, clear=True), patch.object(module, "read_logging_proof", return_value=invalid) as held, self.assertRaises(ValueError):
                    module.emit(*arguments)
                self.assertFalse(path.parent.exists())
                held.assert_called_once_with(path.parent.parent / "logging-v1.json", path.parent.parent, expected, outer_backend=backend)
            with patch.dict(os.environ, environment, clear=True), patch.object(module, "read_logging_proof", wraps=module.read_logging_proof) as held:
                module.emit(*arguments)
            self.assertTrue(path.exists())
            held.assert_called_once_with(path.parent.parent / "logging-v1.json", path.parent.parent, expected, outer_backend=backend)


if __name__ == "__main__":
    unittest.main()
