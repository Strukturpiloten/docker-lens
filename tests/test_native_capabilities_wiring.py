"""Capabilities31 exact selection, privacy, original30 dominance and reservations."""
import base64
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
import test_native_nofile_wiring as previous
from test_native_capabilities_proof import LANES, rebind

ROOT=Path(__file__).resolve().parents[1]
TARGET="native_capabilities"
TEST="live_named_capabilities_match_engine"
SELECTED="native_health_metadata_tests::lifecycle::capabilities::"+TEST
SUCCESS=b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;\n"
HANDOFF=b"DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required\n"
SECRET=b"PRIVATE_CAPABILITIES_WIRING_CANARY"
ORIGINAL30=previous.ORIGINAL27+[("native_nofile","live_nofile_limits_and_effects_match_engine"),("native_device_mapping","live_device_mapping_matches_engine"),("native_memory","live_memory_limits_and_effects_match_engine")]


class CapabilitiesWiringTests(unittest.TestCase):
    tail=previous.NofileWiringTests.tail

    def wrapper(self,output=SUCCESS,status=0,*,listing=None,name=TEST):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/"cargo").write_text('''#!/usr/bin/python3
import base64,json,os,sys
with open(os.environ["TRACE"],"a") as out:
    out.write(json.dumps({"argv":sys.argv[1:],"deadline":os.environ.get("NATIVE_CAPABILITIES_DEADLINE_EPOCH"),"shared":os.environ.get("NATIVE_LIFECYCLE_DEADLINE_EPOCH"),"owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")})+"\\n")
if "--list" in sys.argv:sys.stdout.buffer.write(base64.b64decode(os.environ["LISTING"]))
else:sys.stdout.buffer.write(open(os.environ["OUTPUT"],"rb").read());sys.exit(int(os.environ["STATUS"]))
''')
            (root/"date").write_text('#!/bin/sh\nprintf "date\\n" >> "$DATES"\nprintf "2000\\n"\n')
            for file in ("cargo","date"):(root/file).chmod(0o700)
            (root/"output").write_bytes(output)
            env={**os.environ,"PATH":str(root)+os.pathsep+os.environ["PATH"],"TMPDIR":directory,"TRACE":str(root/"trace"),"DATES":str(root/"dates"),"OUTPUT":str(root/"output"),"STATUS":str(status),
                 "LISTING":base64.b64encode((SELECTED+": test\n").encode() if listing is None else listing).decode(),"NATIVE_LIFECYCLE_CLEANUP_OWNER":"native_conformance_outer_v1"}
            result=subprocess.run(["bash",str(ROOT/"scripts/run-exact-native-test.sh"),TARGET,name],env=env,capture_output=True,timeout=10,check=False)
            calls=[json.loads(line) for line in (root/"trace").read_text().splitlines()] if (root/"trace").exists() else []
            dates=(root/"dates").read_text().splitlines() if (root/"dates").exists() else []
            self.assertNotIn(SECRET,result.stdout+result.stderr)
            return result,calls,dates

    def test_exact_ignored_selection_and_existing_once_created_deadline(self):
        result,calls,dates=self.wrapper();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(calls),2);self.assertEqual(calls[1]["argv"][-4:],["--","--ignored","--exact",SELECTED]);self.assertIn("--lib",calls[1]["argv"])
        self.assertEqual((calls[1]["deadline"],calls[1]["shared"]),("2180","2180"));self.assertEqual(calls[1]["owner"],"native_conformance_outer_v1");self.assertEqual(dates,["date"])
        for listing in (b"",b"foreign: test\n",(SELECTED+": test\n").encode()*2):
            result,calls,dates=self.wrapper(listing=listing);self.assertNotEqual(result.returncode,0);self.assertEqual(len(calls),1);self.assertEqual(dates,[])
        result,calls,dates=self.wrapper(name="other_test");self.assertNotEqual(result.returncode,0);self.assertEqual(calls,[]);self.assertEqual(dates,[])

    def test_failed_cancelled_uncertain_or_zero_work_results_never_pass(self):
        for output,status in ((SUCCESS,101),(SUCCESS,124),(SUCCESS,130),(SUCCESS,143),(SUCCESS.replace(b"1 passed",b"0 passed"),0),
                              (SUCCESS.replace(b"1 passed",b"2 passed"),0),(HANDOFF+SUCCESS,0),(b"DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n"+SUCCESS,0),
                              (SECRET+b"\0"+SUCCESS,0),(b"x"*1048577+SUCCESS,0)):
            self.assertNotEqual(self.wrapper(output,status)[0].returncode,0)
        output=(b"DOCKERLENS_NATIVE_CHECK: capabilities_effects\n"+f"thread '{SELECTED}' panicked at src/native_capabilities_tests.rs:123:4:\n".encode()+SECRET+b"\nDOCKERLENS_NATIVE_CHECK: capabilities_cleanup\n"+HANDOFF)
        result,_,_=self.wrapper(output,101);self.assertIn(b"source=native_capabilities_tests line=123 column=4",result.stderr);self.assertIn(b"capabilities_effects",result.stderr);self.assertIn(HANDOFF.rstrip(),result.stderr)
        result,_,_=self.wrapper(b"thread 'worker' panicked at /private/hidden:1:1:\n"+output,101);self.assertIn(b"source=native_capabilities_tests location=unavailable",result.stderr);self.assertNotIn(b"line=123",result.stderr)

    def test_original30_and_each_immediate_reader_precede_only_capabilities31(self):
        source=(ROOT/"scripts/native-conformance.sh").read_text()
        calls=re.findall(r'^[ \t]*"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$',source,re.M)
        self.assertEqual(calls,ORIGINAL30+[(TARGET,TEST),("native_logging","live_logging_matches_engine")])
        self.assertEqual(source.count("export NATIVE_LIFECYCLE_CLEANUP_OWNER="),11)
        stages=['run-exact-native-test.sh" native_pids ','python3 "$script_dir/native_pids_proof.py"','run-exact-native-test.sh" native_nofile ','python3 "$script_dir/native_nofile_proof.py"','run-exact-native-test.sh" native_device_mapping ','python3 "$script_dir/native_device_mapping_proof.py"','run-exact-native-test.sh" native_memory ','python3 "$script_dir/native_memory_proof.py"','run-exact-native-test.sh" native_capabilities ','python3 "$script_dir/native_capabilities_proof.py"','publish_native_evidence() {']
        positions=[source.index(stage) for stage in stages]
        self.assertEqual(positions,sorted(positions));self.assertEqual(source.count(stages[-2]),1)
        command=shlex.split(source[positions[-2]:source.index('\n\n',positions[-2])].replace('\\\n',' '))
        self.assertEqual(command[2:],["$run_dir","$NATIVE_CAPABILITIES_CANDIDATE_SHA","$run_id","$lane","$server_version","$api_version","$expected_mode","$installed_docker_package","$NATIVE_FIXTURE_IMAGE","$image","$NATIVE_OUTER_CONTAINER_ID","$NATIVE_BIND_RELABEL_DAEMON_UID"])
        self.assertIn('export NATIVE_CAPABILITIES_PROOF_PATH="$run_dir/named-capabilities-v1.json"',source)
        self.assertIn('export NATIVE_CAPABILITIES_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA',source)

    def test_real_capabilities_reader_is_required_without_public_emission(self):
        expected=["prebuild","pids_child","pids_reader","nofile_child","nofile_reader","device_child","device_reader","memory_child","memory_reader","capabilities_child","capabilities_reader", "logging_child", "logging_reader","complete","teardown"]
        for lane in LANES:
            for backend in ("podman","docker"):
                result,events,_=self.tail(lane,backend)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual([e["event"] for e in events],expected)
                self.assertEqual(events[9]["owner"],"native_conformance_outer_v1")
                self.assertEqual(events[10]["backend"],backend)
                def corrupt(p):
                    p['containers'][8]['effect']['raw']=p['containers'][8]['effect']['raw'].replace('0000000000000400','0000000000000401');rebind(p)
                result,events,_=self.tail(lane,backend,capabilities_mutate=corrupt)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual([e["event"] for e in events][-2:],["capabilities_reader","teardown"])
                self.assertEqual(result.stderr,b"invalid private named capabilities proof\n")

    def test_every_prefix_failure_and_capability_failure_retains_exit_teardown(self):
        sequence=["prebuild","pids_child","pids_reader","nofile_child","nofile_reader","device_child","device_reader","memory_child","memory_reader","capabilities_child","capabilities_reader", "logging_child", "logging_reader"]
        for failure in sequence:
            result,events,_=self.tail("upstream-rootless","docker",failure=failure,evidence=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual([e["event"] for e in events],sequence[:sequence.index(failure)+1]+["teardown"])

    def test_exact_small_accounting_and_unknown_id_guard(self):
        source=(ROOT/'src/native_capabilities_tests.rs').read_text()
        compact=re.sub(r'\s+','',source)
        for token in ('BoundOuterCleanupOwner::bind','terminal_cleanup(&mut run','require_verified_result(result,disposition)','publish_bounded(&proof,65536)','meter.calls.get()==88','cleanup_calls==99','99*(8192+2048)','88*SMALL+3*FULL+backend.snapshot_extra_bytes()'):
            self.assertIn(re.sub(r'\s+','',token),compact)
        self.assertLess(source.index('run.attempted[index] = true'),source.index('let (status, value) = small'))
        for forbidden in ('run.calls.set(','run.bytes.set(','"--privileged"','"setns"','"capsh"','run.cleanup()'):
            self.assertNotIn(forbidden,source)
        for lane in LANES:
            for backend in ('podman','docker'):
                extra=0 if backend=='podman' else 1
                context=(9 if lane.startswith('debian11-') else 8)+extra
                full=12 if lane.startswith('debian11-') else 11
                self.assertLessEqual(context+91+extra,300)
                # Even immediately before the final full capture there is room
                # for the generic capture precheck (full envelope).
                self.assertLessEqual(full*73742+88*8192+2*65536*extra,2097152)
        self.assertEqual(11*9,99);self.assertEqual(99*(8192+2048),1013760)

if __name__=='__main__':unittest.main()
