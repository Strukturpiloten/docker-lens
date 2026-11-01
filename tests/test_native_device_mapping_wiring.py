"""Exact device29 selection/privacy/order using fake cargo and real readers."""
import base64
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
import test_native_nofile_wiring as nofile
from test_native_nofile_wiring import ORIGINAL27, SUCCESS, HANDOFF
from test_native_device_mapping_proof import LANES

ROOT = Path(__file__).resolve().parents[1]
TARGET = "native_device_mapping"
TEST = "live_device_mapping_matches_engine"
SELECTED = "native_health_metadata_tests::lifecycle::device_mapping::" + TEST
SECRET = b"PRIVATE_DEVICE_WIRING_CANARY"


class DeviceMappingWiringTests(unittest.TestCase):
    tail = nofile.NofileWiringTests.tail

    def wrapper(self, output=SUCCESS, status=0, *, listing=None, name=TEST):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cargo").write_text('''#!/usr/bin/python3
import base64, json, os, sys
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"argv":sys.argv[1:], "deadline":os.environ.get("NATIVE_DEVICE_MAPPING_DEADLINE_EPOCH"),
                             "shared":os.environ.get("NATIVE_LIFECYCLE_DEADLINE_EPOCH"),
                             "owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")}) + "\\n")
if "--list" in sys.argv:
    sys.stdout.buffer.write(base64.b64decode(os.environ["LISTING"]))
else:
    sys.stdout.buffer.write(open(os.environ["OUTPUT"], "rb").read())
    sys.exit(int(os.environ["STATUS"]))
''')
            (root / "date").write_text('#!/bin/sh\nprintf "date\\n" >> "$DATES"\nprintf "2000\\n"\n')
            for file in ("cargo", "date"):
                (root / file).chmod(0o700)
            (root / "output").write_bytes(output)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "TRACE": str(root / "trace"),
                   "DATES": str(root / "dates"), "OUTPUT": str(root / "output"), "STATUS": str(status),
                   "LISTING": base64.b64encode((SELECTED + ": test\n").encode() if listing is None else listing).decode(),
                   "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1", "TMPDIR": directory}
            result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"), TARGET, name],
                                    env=env, capture_output=True, timeout=10, check=False)
            calls = [json.loads(line) for line in (root / "trace").read_text().splitlines()] if (root / "trace").exists() else []
            dates = (root / "dates").read_text().splitlines() if (root / "dates").exists() else []
            self.assertNotIn(SECRET, result.stdout + result.stderr)
            return result, calls, dates

    def test_exact_selection_original_deadline_and_no_silent_skip(self):
        result, calls, dates = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1]["argv"][-4:], ["--", "--ignored", "--exact", SELECTED])
        self.assertIn("--lib", calls[1]["argv"])
        self.assertEqual((calls[1]["deadline"], calls[1]["shared"]), ("2180", "2180"))
        self.assertEqual(calls[1]["owner"], "native_conformance_outer_v1")
        self.assertEqual(dates, ["date"])
        result, calls, dates = self.wrapper(name="other_test")
        self.assertNotEqual(result.returncode, 0); self.assertEqual(calls, []); self.assertEqual(dates, [])
        for listing in (b"", b"foreign: test\n", (SELECTED + ": test\n").encode() * 2):
            result, calls, dates = self.wrapper(listing=listing)
            self.assertNotEqual(result.returncode, 0); self.assertEqual(len(calls), 1); self.assertEqual(dates, [])
        for output, status in ((SUCCESS, 101), (SUCCESS.replace(b"1 passed", b"0 passed"), 0),
                               (SUCCESS.replace(b"1 passed", b"2 passed"), 0), (HANDOFF + SUCCESS, 0),
                               (b"DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n" + SUCCESS, 0),
                               (SECRET + b"\0" + SUCCESS, 0), (b"x" * 1048577 + SUCCESS, 0)):
            self.assertNotEqual(self.wrapper(output, status)[0].returncode, 0)

    def test_closed_first_causal_panic_does_not_export_private_payload(self):
        output = (b"DOCKERLENS_NATIVE_CHECK: device_mapping_effects\n"
                  + f"thread '{SELECTED}' panicked at src/native_device_mapping_tests.rs:123:4:\n".encode()
                  + SECRET + b"\nDOCKERLENS_NATIVE_CHECK: device_mapping_cleanup\n" + HANDOFF)
        result, _, _ = self.wrapper(output, 101)
        self.assertIn(b"source=native_device_mapping_tests line=123 column=4", result.stderr)
        self.assertIn(b"device_mapping_effects", result.stderr)
        self.assertIn(HANDOFF.rstrip(), result.stderr)
        result, _, _ = self.wrapper(b"thread 'private' panicked at /private/hidden:1:1:\n" + output, 101)
        self.assertIn(b"source=native_device_mapping_tests location=unavailable", result.stderr)
        self.assertNotIn(b"line=123", result.stderr)

    def test_original28_order_and_exactly_one_immediate_device_reader(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = re.findall(r'^[ \t]*"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$', source, re.M)
        self.assertEqual(calls, ORIGINAL27 + [("native_nofile", "live_nofile_limits_and_effects_match_engine"), (TARGET, TEST), ("native_memory", "live_memory_limits_and_effects_match_engine"), ("native_capabilities", "live_named_capabilities_match_engine"), ("native_logging", "live_logging_matches_engine")])
        self.assertEqual(source.count("export NATIVE_LIFECYCLE_CLEANUP_OWNER="), 11)
        stages = ['run-exact-native-test.sh" native_pids ', 'python3 "$script_dir/native_pids_proof.py"',
                  'run-exact-native-test.sh" native_nofile ', 'python3 "$script_dir/native_nofile_proof.py"',
                  'run-exact-native-test.sh" native_device_mapping ', 'python3 "$script_dir/native_device_mapping_proof.py"',
                  'publish_native_evidence() {']
        positions = [source.index(stage) for stage in stages]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(source.count(stages[-2]), 1)
        reader = positions[-2]
        command = shlex.split(source[reader:source.index("\n\n",reader)].replace('\\\n', ' '))
        self.assertEqual(command[2:], ["$run_dir", "$NATIVE_DEVICE_MAPPING_CANDIDATE_SHA", "$run_id", "$lane",
                                      "$server_version", "$api_version", "$expected_mode", "$installed_docker_package",
                                      "$NATIVE_FIXTURE_IMAGE", "$image", "$NATIVE_OUTER_CONTAINER_ID", "$NATIVE_BIND_RELABEL_DAEMON_UID"])
        self.assertIn('export NATIVE_DEVICE_MAPPING_PROOF_PATH="$run_dir/device-mapping-v1.json"', source)
        self.assertIn('export NATIVE_DEVICE_MAPPING_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA', source)

    def test_real_reader_dominates_publication_and_failure_for_all_lanes_and_backends(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                result, events, _ = self.tail(lane, backend)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([item["event"] for item in events],
                                 ["prebuild", "pids_child", "pids_reader", "nofile_child", "nofile_reader", "device_child", "device_reader", "memory_child", "memory_reader", "capabilities_child", "capabilities_reader", "logging_child", "logging_reader", "complete", "teardown"])
                self.assertEqual(events[5]["owner"], "native_conformance_outer_v1")
                self.assertEqual(events[6]["backend"], backend)
                result, events, _ = self.tail(lane, backend, device_mutate=lambda p: p["cleanup"].update(uncertain=True))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([item["event"] for item in events][-2:], ["device_reader", "teardown"])
                self.assertEqual(result.stderr, b"invalid private device mapping proof\n")

    def test_source_has_fixed_read_mapping_liability_and_original_budget_owners(self):
        source = (ROOT / "src/native_device_mapping_tests.rs").read_text()
        self.assertIn('"/dev/null:/dev/native-null:r".into()', source)
        self.assertIn('"CgroupPermissions":"r"', source)
        self.assertIn('dd bs=1 count=1 <&3 >"$f"', source)
        self.assertIn('test ! -L "$p"; test -c "$p"', source)
        self.assertIn('"/proc/$$/fd/3"', source)
        self.assertLess(source.index('run.attempted[index] = true'), re.search(r'run\.api\(\s*"POST"', source).start())
        for required in ('BoundOuterCleanupOwner::bind', 'device_cleanup_with(&attempted', 'terminal_cleanup(&mut run',
                         'require_verified_result(result,disposition)', 'backend.final_snapshot_room', '18 * CLEANUP_ENVELOPE',
                         'Duration::from_secs(134)', 'Duration::from_secs(46)', 'Duration::from_secs(180)'):
            self.assertIn(re.sub(r"\s+", "", required), re.sub(r"\s+", "", source))
        for forbidden in ('run.cleanup()', 'run.calls.set(', 'run.bytes.set(', 'run.image_for(', 'image rm', '--privileged'):
            self.assertNotIn(forbidden, source)
        # Independent complete success-envelope arithmetic: 9 Debian context
        # captures, 11 inspect/API-create, 5 short captures, health and 2 final
        # reads, with two selected-Docker 65536-byte extras.
        self.assertEqual(23 * (65550 + 8192) + 5 * (1024 + 8192) + 2 * 65536, 1873218)
        self.assertLess(1873218, 2097152)
        self.assertEqual(18 * (8192 + 2048), 184320)
        self.assertEqual((8 + 16 + 1 + 2, 9 + 16 + 1 + 2, 9 + 16 + 1 + 3, 10 + 16 + 1 + 3), (27, 28, 29, 30))


if __name__ == "__main__":
    unittest.main()
