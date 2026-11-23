"""Memory30 exact selection, privacy, original29 dominance and reservations."""
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
import test_native_outer_bridge as outer_bridge
from test_native_memory_proof import LANES, rebind

ROOT=Path(__file__).resolve().parents[1]
TARGET="native_memory"
TEST="live_memory_limits_and_effects_match_engine"
SELECTED="native_health_metadata_tests::lifecycle::memory::"+TEST
SUCCESS=b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;\n"
HANDOFF=b"DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required\n"
SECRET=b"PRIVATE_MEMORY_WIRING_CANARY"
ORIGINAL29=previous.ORIGINAL27+[("native_nofile","live_nofile_limits_and_effects_match_engine"),("native_device_mapping","live_device_mapping_matches_engine")]


class MemoryWiringTests(unittest.TestCase):
    tail=previous.NofileWiringTests.tail

    def wrapper(self,output=SUCCESS,status=0,*,listing=None,name=TEST,target=TARGET,transport=None):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/"cargo").write_text('''#!/usr/bin/python3
import base64,json,os,sys
with open(os.environ["TRACE"],"a") as out:
    out.write(json.dumps({"argv":sys.argv[1:],"deadline":os.environ.get("NATIVE_MEMORY_DEADLINE_EPOCH"),"shared":os.environ.get("NATIVE_LIFECYCLE_DEADLINE_EPOCH"),"owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")})+"\\n")
if os.environ.get("MEMORY_TRANSPORT_BINARY"):
    args=sys.argv[sys.argv.index("--")+1:]
    binary=os.environ["MEMORY_TRANSPORT_BINARY"]
    os.execv(binary,[binary,*args])
if "--list" in sys.argv:sys.stdout.buffer.write(base64.b64decode(os.environ["LISTING"]))
else:sys.stdout.buffer.write(open(os.environ["OUTPUT"],"rb").read());sys.exit(int(os.environ["STATUS"]))
''')
            (root/"date").write_text('#!/bin/sh\nprintf "date\\n" >> "$DATES"\nprintf "2000\\n"\n')
            for file in ("cargo","date"):(root/file).chmod(0o700)
            (root/"output").write_bytes(output)
            env={**os.environ,"PATH":str(root)+os.pathsep+os.environ["PATH"],"TMPDIR":directory,"TRACE":str(root/"trace"),"DATES":str(root/"dates"),"OUTPUT":str(root/"output"),"STATUS":str(status),
                 "LISTING":base64.b64encode((SELECTED+": test\n").encode() if listing is None else listing).decode(),"NATIVE_LIFECYCLE_CLEANUP_OWNER":"native_conformance_outer_v1"}
            env.pop("MEMORY_TRANSPORT_BINARY", None)
            if transport is not None:
                binary, threads, handoff = transport
                env.update({"MEMORY_TRANSPORT_BINARY": str(binary), "RUST_TEST_THREADS": str(threads),
                            "MEMORY_TRANSPORT_HANDOFF": handoff})
            result=subprocess.run(["bash",str(ROOT/"scripts/run-exact-native-test.sh"),target,name],env=env,capture_output=True,timeout=10,check=False)
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
        output=(b"DOCKERLENS_NATIVE_CHECK: memory_effects\n"+f"thread '{SELECTED}' panicked at src/native_memory_tests.rs:123:4:\n".encode()+SECRET+b"\nDOCKERLENS_NATIVE_CHECK: memory_cleanup\n"+HANDOFF)
        result,_,_=self.wrapper(output,101);self.assertIn(b"source=native_memory_tests line=123 column=4",result.stderr);self.assertIn(b"memory_effects",result.stderr);self.assertIn(HANDOFF.rstrip(),result.stderr)
        result,_,_=self.wrapper(b"thread 'worker' panicked at /private/hidden:1:1:\n"+output,101);self.assertIn(b"source=native_memory_tests location=unavailable",result.stderr);self.assertNotIn(b"line=123",result.stderr)

    def test_original29_and_all_immediate_readers_precede_only_memory30(self):
        source=(ROOT/"scripts/native-conformance.sh").read_text()
        calls=re.findall(r'^[ \t]*"\$\(dirname "\$0"\)/run-exact-native-test.sh" (\w+) (\w+)$',source,re.M)
        self.assertEqual(calls,ORIGINAL29+[(TARGET,TEST),("native_capabilities","live_named_capabilities_match_engine"), ("native_logging", "live_logging_matches_engine")]);self.assertEqual(source.count("export NATIVE_LIFECYCLE_CLEANUP_OWNER="),11)
        stages=['run-exact-native-test.sh" native_pids ','python3 "$script_dir/native_pids_proof.py"','run-exact-native-test.sh" native_nofile ','python3 "$script_dir/native_nofile_proof.py"',
                'run-exact-native-test.sh" native_device_mapping ','python3 "$script_dir/native_device_mapping_proof.py"','run-exact-native-test.sh" native_memory ','python3 "$script_dir/native_memory_proof.py"','publish_native_evidence() {']
        positions=[source.index(stage) for stage in stages];self.assertEqual(positions,sorted(positions));self.assertEqual(source.count(stages[-2]),1)
        command=shlex.split(source[positions[-2]:source.index('\n\n',positions[-2])].replace('\\\n',' '))
        self.assertEqual(command[2:],["$run_dir","$NATIVE_MEMORY_CANDIDATE_SHA","$run_id","$lane","$server_version","$api_version","$expected_mode","$installed_docker_package","$NATIVE_FIXTURE_IMAGE","$image","$NATIVE_OUTER_CONTAINER_ID","$NATIVE_BIND_RELABEL_DAEMON_UID"])
        self.assertIn('export NATIVE_MEMORY_PROOF_PATH="$run_dir/memory-limits-v1.json"',source)
        self.assertIn('export NATIVE_MEMORY_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA',source)

    def test_real_memory_reader_is_required_without_public_emission_on_all_lanes(self):
        for lane in LANES:
            for backend in ("podman","docker"):
                result,events,_=self.tail(lane,backend);self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual([e["event"] for e in events],["prebuild","pids_child","pids_reader","nofile_child","nofile_reader","device_child","device_reader","memory_child","memory_reader","capabilities_child","capabilities_reader", "logging_child", "logging_reader","complete","teardown"])
                self.assertEqual(events[7]["owner"],"native_conformance_outer_v1");self.assertEqual(events[8]["backend"],backend)
                def corrupt(p):
                    raw=p["cases"][1]["containers"][0]["after"]["report"]
                    raw["raw"]=raw["raw"].replace("4194304 1 1 2","4194304 0 1 2");rebind(p)
                result,events,_=self.tail(lane,backend,memory_mutate=corrupt)
                self.assertNotEqual(result.returncode,0);self.assertEqual([e["event"] for e in events][-2:],["memory_reader","teardown"]);self.assertEqual(result.stderr,b"invalid private memory proof\n")

    def test_every_original_tail_failure_and_memory_failure_retains_exit_teardown(self):
        sequence=["prebuild","pids_child","pids_reader","nofile_child","nofile_reader","device_child","device_reader","memory_child","memory_reader","capabilities_child","capabilities_reader", "logging_child", "logging_reader"]
        for failure in sequence:
            result,events,_=self.tail("upstream-rootless","docker",failure=failure,evidence=True)
            self.assertNotEqual(result.returncode,0);self.assertEqual([e["event"] for e in events],sequence[:sequence.index(failure)+1]+["teardown"])

    def test_baseline_collector_uses_the_real_outer_bridge_uid_route(self):
        source = (ROOT / "src/native_memory_tests.rs").read_text()
        observe = source.split("fn observe(", 1)[1].split("fn event_clock(", 1)[0]
        user = re.search(r'command.args\(\[\s*"exec",\s*"--user",\s*"([^"]+)"', observe)[1]
        collector = re.search(r'const COLLECT: &str = r#"(.*?)"#;', source, re.S)[1]
        bridge = outer_bridge.BridgeTests()
        bridge.setUp()
        self.addCleanup(bridge.doCleanups)
        identity = ["-", "0", "0", "/", "0", "0", "baseline"]
        for engine, api in (("docker", "1.41"), ("podman", "1.56")):
            argv = [outer_bridge.ID, "sh", "-c", collector, "dl-memory-observe", "baseline", api, *identity]
            with self.subTest(engine=engine):
                result = bridge.invoke("exec", "--user", user, *argv, engine=engine)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), ["exec", "--user", "0", *argv])
                calls = bridge.calls()
                for rejected in ("0:0", "root", "1000:0"):
                    refused = bridge.invoke("exec", "--user", rejected, *argv, engine=engine)
                    self.assertEqual((refused.returncode, refused.stdout, refused.stderr),
                                     (2, b"", b"native outer command refused\n"))
                self.assertEqual(bridge.calls(), calls)

    def test_collector_still_requires_effective_uid_and_gid_zero(self):
        source = (ROOT / "src/native_memory_tests.rs").read_text()
        collector = re.search(r'const COLLECT: &str = r#"(.*?)"#;', source, re.S)[1]
        # Run the real identity preamble and stop before it touches procfs.
        checks = collector.split("\nsafe()", 1)[0]
        actor = 'id(){ case "$1" in -u) printf "%s\\n" "$TEST_UID";; -g) printf "%s\\n" "$TEST_GID";; esac; }\n'
        argv = ["sh", "-c", actor + checks + '\nprintf "accepted\\n"', "dl-memory-observe",
                "baseline", "1.41", "-", "0", "0", "/", "0", "0", "baseline"]
        for uid, gid, expected in (("0", "0", b"accepted\n"), ("1", "0", b""), ("0", "1", b""), ("0", "", b"")):
            with self.subTest(uid=uid, gid=gid):
                result = subprocess.run(argv, env={"TEST_UID": uid, "TEST_GID": gid},
                                        capture_output=True, timeout=3, check=False)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, expected, b"") if expected else
                                 (1, b"", b"DOCKERLENS_NATIVE_MEMORY_GUEST: site=identity\n"))

    def test_real_libtest_frames_context_with_one_or_two_threads_and_optional_handoff(self):
        import tomllib
        source = (ROOT / "src/native_memory_tests.rs").read_text()
        writes = re.findall(r'let _ = writeln!\(\s*std::io::stderr\(\),\s*"[^"]*DOCKERLENS_NATIVE_CHECK: memory_context"\s*,?\s*\);', source)
        self.assertEqual(len(writes), 1)
        record = b"DOCKERLENS_NATIVE_MEMORY_CONTEXT_FAILURE: operation=baseline result=nonzero termination=exit code=1 site=node_events"
        fixture = r'''use std::io::Write;
mod native_health_metadata_tests { pub mod lifecycle { pub mod memory {
    use super::super::super::*;
    #[test] #[ignore]
    fn live_memory_limits_and_effects_match_engine() {
        let failure = std::panic::catch_unwind(|| {
            CONTEXT_WRITE
            panic!("PRIVATE_MEMORY_WIRING_CANARY");
        });
        writeln!(std::io::stderr(), "DOCKERLENS_NATIVE_MEMORY_CONTEXT_FAILURE: operation=baseline result=nonzero termination=exit code=1 site=node_events").unwrap();
        writeln!(std::io::stderr(), "DOCKERLENS_NATIVE_CHECK: memory_cleanup").unwrap();
        if std::env::var("MEMORY_TRANSPORT_HANDOFF").unwrap() == "required" {
            writeln!(std::io::stderr(), "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified").unwrap();
            writeln!(std::io::stderr(), "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required").unwrap();
        }
        std::panic::resume_unwind(failure.unwrap_err());
    }
}}}
'''
        channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        with tempfile.TemporaryDirectory(prefix="dl-memory-transport-") as directory:
            root = Path(directory)
            rust = root / "transport.rs"
            binary = root / "transport"
            rust.write_text(fixture.replace("CONTEXT_WRITE", writes[0]))
            built = subprocess.run(["rustup", "run", channel, "rustc", "--edition=2024", "--test", str(rust), "-o", str(binary)],
                                   cwd=ROOT, capture_output=True, timeout=30, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            for threads in (1, 2):
                for handoff in ("absent", "required"):
                    with self.subTest(threads=threads, handoff=handoff):
                        result, calls, dates = self.wrapper(transport=(binary, threads, handoff))
                        self.assertEqual(result.returncode, 1)
                        self.assertIn(f"required native test {TARGET}::{TEST} failed (exit 101)".encode(), result.stderr)
                        self.assertIn(record, result.stderr)
                        self.assertIn(b"DOCKERLENS_NATIVE_CHECK: memory_context", result.stderr)
                        self.assertEqual(HANDOFF.rstrip() in result.stderr, handoff == "required")
                        self.assertEqual(b"lifecycle_cleanup_unverified" in result.stderr, handoff == "required")
                        self.assertEqual(len(calls), 2)
                        self.assertIn("--list", calls[0]["argv"])
                        self.assertEqual(calls[1]["argv"][-4:], ["--", "--ignored", "--exact", SELECTED])
                        self.assertEqual(dates, ["date"])

    def test_context_failure_projection_binds_operation_status_and_pre_cleanup_order(self):
        context = b"DOCKERLENS_NATIVE_CHECK: memory_context\n"
        cleanup = b"DOCKERLENS_NATIVE_CHECK: memory_cleanup\n"
        prefix = b"DOCKERLENS_NATIVE_MEMORY_CONTEXT_FAILURE: "
        baseline = prefix + b"operation=baseline result=nonzero termination=exit code=1 site=node_events\n"
        terminal = SUCCESS.replace(b"ok. 1 passed; 0 failed", b"FAILED. 0 passed; 1 failed")
        for line in (
            baseline,
            baseline.replace(b"nonzero termination=exit code=1 site=node_events",
                             b"stream_limit termination=exit code=0 site=none"),
            prefix + b"operation=version_cli result=nonzero termination=signal code=15 site=none\n",
            prefix + b"operation=package result=success termination=exit code=0 site=none\n",
            prefix + b"operation=acquire result=unobserved termination=unknown code=none site=none\n",
        ):
            result, _, _ = self.wrapper(context + line + cleanup + HANDOFF + terminal, 101)
            self.assertEqual(result.returncode, 1)
            self.assertIn(line.rstrip(), result.stderr)
            self.assertIn(HANDOFF.rstrip(), result.stderr)
        for wrong in (
            baseline + baseline,
            baseline.rstrip() + b" " + SECRET + b"\n",
            baseline.replace(b"baseline", b"info_get"),
            baseline.replace(b"code=1", b"code=0"),
            baseline.replace(b"site=node_events", b"site=bridge_refused"),
            baseline.replace(b"code=1", b"code=01"),
            baseline.replace(b"site=node_events", b"site=unknown_value"),
            baseline + b"DOCKERLENS_NATIVE_CHECK: memory_effects\n",
            baseline + b"DOCKERLENS_NATIVE_MEMORY_GUEST: site=node_events\n",
            baseline + b"DOCKERLENS_NATIVE_NOFILE_FAILURE: operation=foreign\n",
        ):
            result, _, _ = self.wrapper(context + wrong + cleanup + terminal, 101)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(prefix, result.stderr)
        for mixed in (context + cleanup + baseline + terminal, baseline + cleanup + terminal,
                      context + baseline + terminal, context + baseline + cleanup + SUCCESS):
            result, _, _ = self.wrapper(mixed, 101)
            self.assertNotIn(prefix, result.stderr)
        result, _, _ = self.wrapper(context + baseline + cleanup + SUCCESS, 0)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(prefix, result.stderr)

    def test_context_failure_rejects_impossible_summary_proof_and_cleanup_order(self):
        context = b"DOCKERLENS_NATIVE_CHECK: memory_context\n"
        record = b"DOCKERLENS_NATIVE_MEMORY_CONTEXT_FAILURE: operation=baseline result=nonzero termination=exit code=1 site=node_events\n"
        cleanup = b"DOCKERLENS_NATIVE_CHECK: memory_cleanup\n"
        unverified = b"DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n"
        failed = SUCCESS.replace(b"ok. 1 passed; 0 failed", b"FAILED. 0 passed; 1 failed")
        coherent = context + record + cleanup + unverified + HANDOFF + failed
        impossible = (
            failed + context + record + cleanup,
            context + failed + record + cleanup,
            context + record + failed + cleanup,
            context + record + cleanup + b"DOCKERLENS_NATIVE_CHECK: memory_proof\n" + failed,
            context + record + HANDOFF + cleanup + failed,
            context + record + unverified + cleanup + failed,
            context + record + cleanup + HANDOFF + unverified + failed,
            context + record + cleanup + failed + HANDOFF,
            coherent + failed,
            coherent.replace(HANDOFF, HANDOFF + HANDOFF),
            coherent.replace(unverified, unverified + unverified),
            coherent.replace(b"FAILED. 0 passed; 1 failed", b"FAILED. 0 passed; 0 failed"),
        )
        for index, output in enumerate(impossible):
            with self.subTest(index=index):
                result, _, _ = self.wrapper(output, 101)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"failed (exit 101)", result.stderr)
                self.assertNotIn(record.rstrip(), result.stderr)
                self.assertEqual(HANDOFF.rstrip() in result.stderr, HANDOFF in output)

    def test_context_failure_keeps_optional_cleanup_and_summary_free_timeout(self):
        context = b"DOCKERLENS_NATIVE_CHECK: memory_context\n"
        record = b"DOCKERLENS_NATIVE_MEMORY_CONTEXT_FAILURE: operation=baseline result=nonzero termination=exit code=1 site=node_events\n"
        cleanup = b"DOCKERLENS_NATIVE_CHECK: memory_cleanup\n"
        unverified = b"DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified\n"
        failed = SUCCESS.replace(b"ok. 1 passed; 0 failed", b"FAILED. 0 passed; 1 failed")
        for status in (101, 124, 143):
            for teardown in (b"", unverified, HANDOFF, unverified + HANDOFF):
                for summary in (b"", failed, failed.rstrip() + b" finished in 0.01s\n"):
                    with self.subTest(status=status, teardown=teardown, summary=summary):
                        result, _, _ = self.wrapper(context + record + cleanup + teardown + summary, status)
                        self.assertEqual(result.returncode, 1)
                        self.assertIn(f"failed (exit {status})".encode(), result.stderr)
                        self.assertIn(record.rstrip(), result.stderr)
                        self.assertEqual(HANDOFF.rstrip() in result.stderr, bool(HANDOFF in teardown))

    def test_other_selectors_keep_private_mentions_but_refuse_memory_records(self):
        record = b"DOCKERLENS_NATIVE_MEMORY_CONTEXT_FAILURE: operation=baseline result=nonzero termination=exit code=1 site=node_events\n"
        selectors = (
            ("native_target", "live_target_render_matches_engine", "native_target_tests::live_target_render_matches_engine"),
            ("native_capture", "live_engine_capture_decodes", "live_engine_capture_decodes"),
            ("native_pids", "live_pids_limits_and_effects_match_engine", "native_health_metadata_tests::lifecycle::pids::live_pids_limits_and_effects_match_engine"),
            ("native_nofile", "live_nofile_limits_and_effects_match_engine", "native_health_metadata_tests::lifecycle::nofile::live_nofile_limits_and_effects_match_engine"),
        )
        for target, name, selected in selectors:
            for note in (b"note: documentation names DOCKERLENS_NATIVE_MEMORY_EXAMPLE\n",
                         b"note: documentation names DOCKERLENS_NATIVE_MEMORY_CONTEXT_FAILURE\n"):
                with self.subTest(target=target, note=note):
                    result, _, _ = self.wrapper(note + SECRET + b"\n" + SUCCESS, target=target, name=name,
                                                listing=(selected + ": test\n").encode())
                    self.assertEqual(result.returncode, 0, result.stderr)
            for line in (record, b"DOCKERLENS_NATIVE_MEMORY_UNKNOWN: " + SECRET + b"\n"):
                result, _, _ = self.wrapper(line + SUCCESS, target=target, name=name,
                                            listing=(selected + ": test\n").encode())
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(b"DOCKERLENS_NATIVE_MEMORY_", result.stdout + result.stderr)

    def test_local_memory_event_parser_accepts_only_valid_known_counters(self):
        source = (ROOT / "src/native_memory_tests.rs").read_text()
        parser, = re.findall(r'^  (counters=\$\(awk .* "\$held/memory\.events\.local"\))$', source, re.M)
        older = b"low 1\nhigh 2\nmax 3\noom 5\noom_kill 7\noom_group_kill 0\n"
        optional = b"sock_throttled 11\n"
        with tempfile.TemporaryDirectory(prefix="dl-memory-events-") as directory:
            fixture = Path(directory) / "memory.events.local"
            command = ["sh", "-ec", f'held=$1\n{parser}\nprintf "%s\\n" "$counters"',
                       "memory-counter-control", directory]
            # Execute the exact collector assignment under its fail-fast shell.
            # A refused AWK process cannot publish a tuple through this boundary.
            for label, rows in (
                ("older", older),
                ("optional_after_required", older + optional),
                ("optional_before_required", optional + older),
                ("optional_zero", older + b"sock_throttled 0\n"),
                ("optional_twenty_digits", older + b"sock_throttled 18446744073709551615\n"),
            ):
                with self.subTest(layout=label):
                    fixture.write_bytes(rows)
                    result = subprocess.run(command, capture_output=True, timeout=3, check=False)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (0, b"5 7 3\n", b""))
            invalid = {
                "duplicate_optional": older + optional + optional,
                "duplicate_required": older + b"oom 5\n" + optional,
                "unknown": older + optional + b"sock_throttled_future 0\n",
                "missing_oom": older.replace(b"oom 5\n", b"") + optional,
                "missing_kill": older.replace(b"oom_kill 7\n", b"") + optional,
                "missing_max": older.replace(b"max 3\n", b"") + optional,
            }
            for value in (b"", b"-1", b"+1", b"01", b"1e1", b"no", b"1 2", b"1" * 21):
                invalid[f"malformed_{value!r}"] = older + b"sock_throttled " + value + b"\n"
            for label, rows in invalid.items():
                with self.subTest(layout=label):
                    fixture.write_bytes(rows)
                    result = subprocess.run(command, capture_output=True, timeout=3, check=False)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (1, b"", b""))

    def test_source_wires_counter_read_and_event_before_final_parent_release(self):
        source=(ROOT/"src/native_memory_tests.rs").read_text();compact=re.sub(r'\s+','',source)
        for token in ('BoundOuterCleanupOwner::bind','outer_context_observation','memory.events.local','memory.oom.group','COLLECT','terminal_cleanup(&mut run','require_verified_result(result, disposition)','publish_bounded(&proof, 65536)'):
            self.assertIn(re.sub(r'\s+','',token),compact)
        self.assertLess(source.index('run.attempted[index] = true'),source.index('let (status, v) = small'))
        self.assertLess(source.index('let (post_packet, post)'),source.index('"actual processed OOM event before parent release"'))
        self.assertLess(source.index('"actual processed OOM event before parent release"'),source.index('"release supervisor only after genuine live counter and event readback"'))
        for forbidden in ('run.calls.set(','run.bytes.set(','run.cleanup()','native_pids_boundary','native-pids-supervisor','oom_score_adj','OOMKillDisable'):
            self.assertNotIn(forbidden,source)
        self.assertIn('child_exec_semantics_not_post_exec_sampled',source);self.assertIn('supervisor_propagated_child_status',source)


if __name__=="__main__":unittest.main()
