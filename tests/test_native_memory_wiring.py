"""Memory30 exact selection, privacy, original29 dominance and reservations."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import tempfile
import unittest
import test_native_nofile_wiring as previous
import test_native_outer_bridge as outer_bridge
from test_native_memory_proof import LANES, ns, packet, reader, rebind

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

    def run_collector_tree(self, mode="baseline", *, node="/", kind=b"domain\n", fault=None, swap=b"0\n", child_status=137, check_root_lifetime=False):
        source = (ROOT / "src/native_memory_tests.rs").read_text()
        collector = re.search(r'const COLLECT: &str = r#"(.*?)"#;', source, re.S)[1]
        with tempfile.TemporaryDirectory(prefix="dl-memory-tree-") as directory:
            base = Path(directory)
            proc, mount = base / "proc", base / "cgroup"
            for pid, comm, start, pidns, cgroupns, membership, status in (
                ("1", "init", 100, 20, 21, "/init.scope", ""),
                ("101", "sh", 1000, 30, 31, "/group/workload", "NSpid:\t101 51 1\nPPid:\t1\n"),
                ("202", "sh", 2000, 30, 31, "/group/workload", "NSpid:\t202 52 2\nPPid:\t101\n"),
                ("self", "", 0, 20, 21, "", ""),
            ):
                process = proc / pid
                (process / "ns").mkdir(parents=True)
                (process / "ns/pid").symlink_to(f"pid:[{pidns}]")
                (process / "ns/cgroup").symlink_to(f"cgroup:[{cgroupns}]")
                (process / "stat").write_text(f"{pid} ({comm}) S " + "0 " * 18 + f"{start}\n")
                (process / "status").write_text(status)
                (process / "cgroup").write_text(f"0::{membership}\n")
            for path, limit in (("/", 4294967296), ("/group", 1073741824), ("/group/workload", 67108864)):
                directory = mount / path.removeprefix("/")
                directory.mkdir(exist_ok=True)
                if not (path == "/" and fault == "hierarchy_root"):
                    (directory / "memory.max").write_text(f"{limit}\n")
                    (directory / "memory.current").write_text("4096\n")
                    (directory / "memory.oom.group").write_text("0\n")
                    (directory / "memory.events.local").write_text("low 0\nhigh 0\nmax 3\noom 4\noom_kill 5\n")
                if path != node:
                    (directory / "cgroup.type").write_bytes(b"domain\n")
            target = mount / node.removeprefix("/") / "cgroup.type"
            if fault == "directory":
                target.mkdir()
            elif fault == "symlink":
                target.symlink_to(mount / "group/cgroup.type")
            elif fault == "dangling":
                target.symlink_to("absent")
            elif kind is not None:
                target.write_bytes(kind)
            (mount / "group/workload/cgroup.procs").write_text("202\n101\n")
            if mode == "post":
                # The actual post collector reads the supervisor's private
                # result after its child has gone and only PID1 remains.
                shutil.rmtree(proc / "202")
                result_dir = proc / "101/root/tmp/dl-memory"
                result_dir.mkdir(parents=True)
                (result_dir / "held").touch()
                (result_dir / "wait-error").write_text("")
                result = result_dir / "status"
                result.write_text(f"inert 2 {child_status}\n")
                result.chmod(0o600)
                (mount / "group/workload/cgroup.procs").write_text("101\n")
            dev = mount.stat().st_dev
            mount_root = "/delegated/subtree" if fault == "mount_root" else "/"
            (proc / "self/mountinfo").write_text(
                f"34 25 {os.major(dev)}:{os.minor(dev)} {mount_root} {mount} rw - cgroup2 cgroup rw\n"
            )
            if swap is not None:
                (mount / "memory.swap.max").write_bytes(swap)
            (proc / "meminfo").write_text("SwapTotal: 8388604 kB\n")
            # Redirect only the proc inputs. Keep the real held-FD lookup,
            # commands, identities, path walk, limits and status handling.
            collector = re.sub(r"/proc/(?!\$\$/fd/)", f"{proc}/", collector)
            final_walk = '\ndone\nif [ "$mode" != baseline ]; then'
            sabotage = {
                "closed_outer": 'eval "exec ${outer_held##*/}<&-"',
                "rebound_outer": 'eval "exec ${outer_held##*/}<\\\"$mount/group\\\""',
                "renamed_root": 'mv "$mount" "$mount.saved"; mkdir "$mount"',
            }
            if fault in sabotage:
                self.assertEqual(collector.count(final_walk), 1)
                collector = collector.replace(final_walk, '\ndone\n' + sabotage[fault] + '\nif [ "$mode" != baseline ]; then')
            shims = r'''id() { printf '0\n'; }
docker() {
  test "$DOCKER_API_VERSION" = 1.41
  test "$#" = 5; test "$1" = -H; test "$2" = unix:///dockerlens-native/docker.sock
  test "$3" = info; test "$4" = --format; test "$5" = '{{.SystemTime}}'
  printf '2026-09-01T10:00:00.000000000Z\n'
}
'''
            if check_root_lifetime:
                # Observe the real open descriptor at the second root readback
                # in node_readback: the first belongs to the ancestor loop and
                # the second is final verification after the walk. This does not
                # select a descriptor number or replace the collector's reads.
                shims += r'''
stat() {
  if [ "$#" = 3 ] && [ "$1" = -c ] && [ "$2" = '%d %i' ] &&
     [ "$3" = "$mount" ] && [ "$site" = node_readback ] && [ "$path" = / ]; then
    if [ -f ''' + str(base / "root_seen") + r''' ]; then
      observed=$(command stat -c '%d %i' "$outer_held/.") || return 1
      test "$observed" = "$outer_identity" || return 1
      printf 'held-root-verified\n' >>''' + str(base / "observations") + r'''
    else
      : >''' + str(base / "root_seen") + r'''
    fi
  fi
  command stat "$@"
}
'''
            if fault == "read":
                shims += r'''
cat() { printf 'domain\n'; printf 'PRIVATE_MEMORY_WIRING_CANARY\n' >&2; return 1; }
od() { printf ' 64 6f 6d 61 69 6e 0a\n'; printf 'PRIVATE_MEMORY_WIRING_CANARY\n' >&2; return 1; }
'''
            result = subprocess.run(
                ["sh", "-c", shims + collector, "dl-memory-observe", mode, "1.41",
                 "pid:[30]", "1000", "51", "/group/workload" if mode == "post" else "/", "2", "2000", "inert"],
                capture_output=True, timeout=3, check=False,
            )
            if check_root_lifetime:
                observations = base / "observations"
                self.assertEqual(observations.read_text() if observations.exists() else "",
                                 "held-root-verified\n", result.stderr.decode())
            return result

    @staticmethod
    def collected_sample(raw, mode):
        return reader.sample({"report": packet(raw.decode()),
                              "clock_bracket": [ns(0) - 1000000, ns(0) + 1000000, 2000000]}, mode)

    def test_collector_reads_namespace_root_leaf_and_immediate_ancestors(self):
        baseline = self.run_collector_tree()
        self.assertEqual((baseline.returncode, baseline.stderr), (0, b""))
        root = self.collected_sample(baseline.stdout, "baseline")
        self.assertEqual((root["leaf"], root["outer"][4]), ("/", "/init.scope"))
        self.assertEqual([node["path"] for node in root["nodes"]], ["/"])
        live = self.run_collector_tree("pre")
        self.assertEqual((live.returncode, live.stderr), (0, b""))
        sample = self.collected_sample(live.stdout, "pre")
        self.assertEqual(sample["members"], ["101", "202"])
        self.assertEqual(
            [(row["path"], row["limit"], row["oom"], row["kill"], row["maximum"], row["scope"])
             for row in sample["nodes"]],
            [(path, limit, 4, 5, 3, "v2_events_local") for path, limit in
             (("/group/workload", 67108864), ("/group", 1073741824), ("/", 4294967296))],
        )

    def test_swap_enabled_host_requires_actual_zero_at_bound_outer(self):
        # The synthetic procfs always reports positive host swap. Only the
        # held outer cgroup's actual swap maximum decides acceptance.
        for mode in ("baseline", "pre"):
            for value in (b"0\n", None, b"max\n", b"1\n", b"00\n", b"0\n0\n", b""):
                with self.subTest(mode=mode, value=value):
                    result = self.run_collector_tree(mode, swap=value)
                    if value == b"0\n":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.collected_sample(result.stdout, mode)
                    else:
                        self.assertNotEqual(result.returncode, 0)

    def test_post_result_read_keeps_outer_root_bound_through_final_verification(self):
        for mode, status in (("baseline", 137), ("pre", 137), ("post", 0), ("post", 137)):
            with self.subTest(mode=mode, status=status):
                result = self.run_collector_tree(mode, child_status=status, check_root_lifetime=True)
                self.assertEqual((result.returncode, result.stderr), (0, b""))
                sample = self.collected_sample(result.stdout, mode)
                if mode == "post":
                    self.assertEqual(sample["process"][5:], ["child_done", "2", str(status)])
                    self.assertEqual(sample["members"], ["101"])
                    self.assertEqual([node["path"] for node in sample["nodes"]],
                                     ["/group/workload", "/group", "/"])

    def test_final_root_verification_rejects_closed_rebound_or_replaced_root(self):
        for mode in ("baseline", "pre", "post"):
            for fault in ("closed_outer", "rebound_outer", "renamed_root"):
                with self.subTest(mode=mode, fault=fault):
                    result = self.run_collector_tree(mode, fault=fault)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn(b"clock ", result.stdout)

    def test_collector_classifies_root_type_failures_without_a_proof(self):
        cases = (
            ("hierarchy_root", None, "node_type_unavailable"),
            (None, None, "node_type_unavailable"),
            ("mount_root", b"domain\n", "mount"),
            ("directory", None, "node_type_object"),
            ("symlink", None, "node_type_object"),
            ("dangling", None, "node_type_object"),
            ("read", b"domain\n", "node_type_read"),
            (None, b"domain threaded\n", "node_type_domain_threaded"),
            (None, b"domain invalid\n", "node_type_domain_invalid"),
            (None, b"threaded\n", "node_type_threaded"),
            (None, b"domain (invalid)\n", "node_type_other"),
            (None, b"", "node_type_other"),
            (None, b"domain", "node_type_other"),
            (None, b"domain\0\n", "node_type_other"),
            (None, b"domain\n\n", "node_type_other"),
            (None, b"domain threaded\nx", "node_type_other"),
        )
        for fault, kind, site in cases:
            with self.subTest(fault=fault, kind=kind):
                result = self.run_collector_tree(kind=kind, fault=fault)
                self.assertEqual((result.returncode, result.stderr), (
                    1, f"DOCKERLENS_NATIVE_MEMORY_GUEST: site={site}\n".encode(),
                ))
                self.assertNotIn(b"\nnode ", result.stdout)
                self.assertNotIn(b"\nclock ", result.stdout)
                with self.assertRaises(ValueError):
                    self.collected_sample(result.stdout, "baseline")

    def test_collector_cannot_skip_unverified_leaf_ancestor_or_visible_root(self):
        for path, completed in (("/group/workload", []),
                                ("/group", [b"/group/workload"]),
                                ("/", [b"/group/workload", b"/group"])):
            for kind in (None, b"threaded\n", b"domain threaded\n", b"domain invalid\n"):
                with self.subTest(path=path, kind=kind):
                    result = self.run_collector_tree("pre", node=path, kind=kind)
                    self.assertEqual((result.returncode, result.stderr), (1, b""))
                    rows = [line.split(b" ")[1] for line in result.stdout.splitlines() if line.startswith(b"node ")]
                    self.assertEqual(rows, completed)
                    self.assertNotIn(b"\nclock ", result.stdout)
                    with self.assertRaises(ValueError):
                        self.collected_sample(result.stdout, "pre")

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
            *(baseline.replace(b"node_events", site) for site in (
                b"node_type", b"node_type_unavailable", b"node_type_object", b"node_type_read",
                b"node_type_domain_threaded", b"node_type_domain_invalid", b"node_type_threaded",
                b"node_type_other",
            )),
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
            baseline.replace(b"site=node_events", b"site=node_type_unknown"),
            baseline.replace(b"site=node_events", b"site=node_type_read role=leaf"),
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
