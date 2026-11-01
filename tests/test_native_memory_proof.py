"""Independent memory30 semantic/custody and real bounded barrier controls."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import native_memory_proof as reader
from test_native_external_network_proof import fixture as context_fixture
LANES=("debian11-rootful","debian11-rootless","upstream-rootful","upstream-rootless")
BARRIER = 'test "$$" = 1 || exit 61\nset -eu; umask 077; d=/tmp/dl-memory\ntest ! -e "$d"; test ! -L "$d"; mkdir "$d"\nreleased=0; trap \'released=1\' USR1\n(exec /bin/sh -c "$1" "$0-child") &\nchild=$!\nwhile [ ! -f "$d/child-bound" ]; do :; done\nIFS=\' \' read -r child_token child_ready <"$d/child-ready"\ntest "$child_token" = "$0-child"; test "$child_ready" = "$child"\nprintf \'%s %s\\n\' "$0" "$child" >"$d/ready.tmp"; mv "$d/ready.tmp" "$d/ready"\n: >"$d/bound"\nwhile [ "$released" = 0 ]; do :; done\ntrap \'\' USR1\nkill -USR1 "$child"\nset +e; wait "$child" 2>"$d/wait-error"; status=$?; set -e\ntrap \'exit "$status"\' USR2\nprintf \'%s %s %s\\n\' "$0" "$child" "$status" >"$d/status.tmp"\nmv "$d/status.tmp" "$d/status"\n: >"$d/held"\nwhile :; do :; done'
CHILD = 'test "$$" -gt 1 || exit 62\nset -eu; umask 077\ntrap \'exec dd if=/dev/zero of=/dev/null bs=100663296 count=1\' USR1\nprintf \'%s %s\\n\' "$0" "$$" >/tmp/dl-memory/child-ready.tmp\nmv /tmp/dl-memory/child-ready.tmp /tmp/dl-memory/child-ready\n: >/tmp/dl-memory/child-bound\nwhile :; do :; done'


def packet(text):return {"raw":text,"sha256":sha256(text.encode()).hexdigest()}
def stamp(second):return f"2026-09-01T10:{second//60:02d}:{second%60:02d}.000000000Z"
def ns(second):return 1788256800000000000+second*10**9

def report(mode,index=0,memory=None,second=0,*,root_membership="/init.scope",headroom_limit=167772160):
    leaf="/" if mode=="baseline" else f"/work/{index+1:064x}"
    pid=str(100+index);child=str(200+index);start=str(1000+index);cstart=str(2000+index)
    lines=["memory-source-v1","reader pid:[20] cgroup:[21]","mount 2 1 0:42 / /sys/fs/cgroup","kernel 6.12.0",
           f"outer / 50 42 100 {root_membership} cgroup:[21]","swap 0"]
    if mode=="baseline":lines += ["process baseline","members baseline"]
    elif mode=="pre":lines += [f"process {pid} {pid} {start} pid:[{300+index}] cgroup:[{400+index}] {child} 2 {cstart}",f"members {pid} {child}"]
    else:lines += [f"process {pid} {pid} {start} pid:[{300+index}] cgroup:[{400+index}] child_done 2 {137 if memory==67108864 else 0}",f"members {pid}"]
    lines += ["leaf "+leaf]
    if mode!="baseline":
        counters="1 1 2" if mode=="post" and memory==67108864 else "0 0 0"
        lines += [f"node {leaf} 42 {200+index} {67108864 if memory==67108864 else 'max'} 4194304 {counters} 0 v2_events_local",
                  f"node /work 42 101 {headroom_limit} 33554432 0 0 0 0 v2_events_local"]
    lines += ["node / 42 100 4294967296 67108864 0 0 0 0 v2_events_local","clock "+stamp(second)]
    return {"report":packet("\n".join(lines)+"\n"),"clock_bracket":[ns(second)-1000000,ns(second)+1000000,2000000]}


def fixture(lane="upstream-rootful",*,outer_backend="podman",headroom_limit=167772160):
    context=deepcopy(context_fixture(lane)["context"])
    context["fixture_image"]="docker.io/library/busybox:1.37.0@sha256:"+"b"*64
    image="sha256:"+"d"*64;cases=[]
    for case_index,(name,memory) in enumerate((("omitted",None),("finite64",67108864),("zero",0))):
        items=[]
        for offset,role in enumerate(("oracle","rendered")):
            i=case_index*2+offset;t=i*10;ident=f"{i+1:064x}";name_full=f"dl-memory-{context['run_id']}-{name}-{role}"
            configured={"id":ident,"name":"/"+name_full,"image":image,"config_image":context["fixture_image"],"owner":context["run_id"],
                        "cmd":["sh","-c",BARRIER,name_full,CHILD],"entrypoint":None,"user":"","init":None,"memory":memory or 0,
                        "memory_swap":134217728 if memory==67108864 else 0,"running":True,"pid":100+i,"started_at":stamp(t+1),
                        "finished_at":"0001-01-01T00:00:00Z","oom":False,"exit":0,"status":"running","restarts":0,"error":"",
                        "restarting":False,"paused":False,"dead":False,"privileged":False,"cap_add":None,"cap_drop":[],"mounts":[]}
            terminal=deepcopy(configured);terminal.update(running=False,pid=0,finished_at=stamp(t+7),oom=memory==67108864,exit=137 if memory==67108864 else 0,status="exited")
            ready=packet(f"ready {name_full} 2\npid:[{300+i}]\ncgroup:[{400+i}]\nparent_start {1000+i}\nchild_start {2000+i}\nchild_parent 1\nuid 0 0 0 0\nuid 0 0 0 0\n")
            event=json.dumps({"type":"container","action":"oom","id":ident,"owner":context["run_id"],"time_nano":ns(t+4)})+"\n" if memory==67108864 else ""
            items.append({"role":role,"id":ident,"name":name_full,"owner":context["run_id"],"wire":"independent_cli" if offset==0 else "literal_rendered","memory":memory,
                          "running":configured,"terminal":terminal,"readiness":ready,"before":report("pre",i,memory,t+3,headroom_limit=headroom_limit),"after":report("post",i,memory,t+5,headroom_limit=headroom_limit),
                          "child_wait_exit":137 if memory==67108864 else 0,"parent_wait_exit":137 if memory==67108864 else 0,"parent_exit_kind":"supervisor_propagated_child_status",
                          "logs":"" if memory==67108864 else "1+0 records in\n1+0 records out\n","events":event,"event_clock":{"time":stamp(t+6),"bracket":[ns(t+6)-1000000,ns(t+6)+1000000,2000000]},
                          "pid_continuity":"child_exec_semantics_not_post_exec_sampled","cleanup":"absent"})
        cases.append({"case":name,"containers":items})
    extra={"podman":0,"docker":1}[outer_backend];context_calls=(10 if lane.startswith("debian11-") else 9)+2*extra
    return {"schema_version":1,"contract":"memory-limits-v1","context":context,"outer_backend":outer_backend,
            "outer_source":{"id":context["outer"]["id"],"pid":99,"started_at":"2026-09-01T09:00:00Z","cgroupns":"private","pid_mode":"","restarts":0},
            "capability_admission":[],"catalogue_admission":False,"scope":"observed_local_pressure_and_bound_child_victim","hidden_ancestry":"unobserved_above_private_guest_root",
            "borrowed_image":{"id":image,"identity":"unchanged","removal":"not_owned"},"baseline":report("baseline"),"cases":cases,
            "daemon_health":"version_matches_after_controls","accounting":{"context_calls":context_calls,"baseline_calls":1,"slot_calls":[15]*6,"daemon_health_calls":1,
            "final_readback_calls":2+extra,"ordinary_calls":context_calls+94+extra,"ordinary_bytes":1000000+3*65536*extra,"small_calls":91,"small_bytes":200000,
            "cleanup_calls":36,"cleanup_bytes":100000,"deadline_seconds":180,"cleanup_reserve_seconds":46,"ordinary_elapsed_ns":5000000000,"cleanup_elapsed_ns":2000000000,"elapsed_ns":8000000000,
            "initial_context_acquisition":{"max_requests":16,"max_total_bytes":2097152,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"}},
            "cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":False}}


def rebind(value):
    if type(value) is dict:
        if set(value)=={"raw","sha256"}:value["sha256"]=sha256(value["raw"].encode()).hexdigest()
        for item in value.values():rebind(item)
    elif type(value) is list:
        for item in value:rebind(item)


def mutations():
    def raw_change(p,phase,old,new,case=1):
        item=p["cases"][case]["containers"][0][phase]["report"]
        item["raw"]=item["raw"].replace(old,new)
    return {
      "missing-role":lambda p:p["cases"][0]["containers"].pop(),"swapped-cases":lambda p:p["cases"].reverse(),
      "swapped-roles":lambda p:p["cases"][0]["containers"].reverse(),"duplicate-id":lambda p:p["cases"][0]["containers"][1].update(id=p["cases"][0]["containers"][0]["id"]),
      "context":lambda p:p["context"].update(candidate_sha="e"*40),"backend":lambda p:p.update(outer_backend="docker"),
      "outer-root":lambda p:p["outer_source"].update(cgroupns="host"),"hidden-claim":lambda p:p.update(hidden_ancestry="unbounded"),
      "wrong-kernel-limit":lambda p:raw_change(p,"before","67108864 4194304","33554432 4194304"),
      "missing-max-delta":lambda p:raw_change(p,"after","4194304 1 1 2","4194304 1 1 0"),
      "missing-oom-delta":lambda p:raw_change(p,"after","4194304 1 1 2","4194304 0 1 2"),
      "missing-victim-delta":lambda p:raw_change(p,"after","4194304 1 1 2","4194304 1 0 2"),
      "unexplained-victim":lambda p:raw_change(p,"after","4194304 1 1 2","4194304 1 2 2"),
      "counter-reset":lambda p:raw_change(p,"before","4194304 0 0 0","4194304 3 3 3"),
      "hierarchical":lambda p:raw_change(p,"after","v2_events_local","v2_events_hierarchical"),
      "group-oom":lambda p:raw_change(p,"after","1 1 2 0 v2","1 1 2 1 v2"),
      "ancestor-pressure":lambda p:raw_change(p,"after","33554432 0 0 0","33554432 1 1 1"),
      "low-headroom":lambda p:raw_change(p,"before","167772160 33554432","167772160 100663297"),
      "swap":lambda p:raw_change(p,"before","swap 0","swap 1"),
      "leaf-gone":lambda p:raw_change(p,"after","node /work/","gone /work/"),
      "stale-leaf":lambda p:raw_change(p,"after","42 202 ","42 999 "),
      "extra-member":lambda p:raw_change(p,"after","members 102\n","members 102 202\n"),
      "parent-died":lambda p:raw_change(p,"after","process 102 102","process 0 102"),
      "wrong-child":lambda p:raw_change(p,"before","202 2 2002","202 3 2002"),
      "false-child-parent":lambda p:p["cases"][1]["containers"][0]["readiness"].update(raw=p["cases"][1]["containers"][0]["readiness"]["raw"].replace("child_parent 1","child_parent 2")),
      "interrupted-wait":lambda p:raw_change(p,"after","child_done 2 137","child_done 2 138"),
      "false-child-exit":lambda p:p["cases"][1]["containers"][0].update(child_wait_exit=0),
      "wrong-exit-kind":lambda p:p["cases"][1]["containers"][0].update(parent_exit_kind="pid1_killed_by_oom"),
      "event-missing":lambda p:p["cases"][1]["containers"][0].update(events=""),
      "event-wrong-id":lambda p:p["cases"][1]["containers"][0].update(events=p["cases"][1]["containers"][0]["events"].replace(f'{3:064x}',"f"*64)),
      "event-early":lambda p:p["cases"][1]["containers"][0].update(events=p["cases"][1]["containers"][0]["events"].replace(str(ns(24)),str(ns(1)))),
      "event-after-release":lambda p:p["cases"][1]["containers"][0]["event_clock"].update(time=stamp(29)),
      "false-engine-flag":lambda p:p["cases"][1]["containers"][0]["terminal"].update(oom=False),
      "false-positive-flag":lambda p:p["cases"][0]["containers"][0]["terminal"].update(oom=True),
      "partial-record":lambda p:p["cases"][0]["containers"][0].update(logs="0+1 records in\n0+1 records out\n"),
      "marker-only":lambda p:p["cases"][0]["containers"][0].update(logs="memory-success\n"),
      "unbound-program":lambda p:p["cases"][0]["containers"][0]["running"]["cmd"].__setitem__(4,CHILD.replace("exec dd","dd")),
      "wrong-uid":lambda p:p["cases"][0]["containers"][0]["running"].update(user="1000"),
      "init-wrapper":lambda p:p["cases"][0]["containers"][0]["running"].update(init=True),
      "ordinary-calls":lambda p:p["accounting"].update(ordinary_calls=97),"bool-counters":lambda p:p["accounting"].update(cleanup_calls=True),
      "slot-calls":lambda p:p["accounting"].update(slot_calls=[14]*6),"byte-reserve":lambda p:p["accounting"].update(ordinary_bytes=2097152),
      "ordinary-time":lambda p:p["accounting"].update(ordinary_elapsed_ns=134000000001),"cleanup-time":lambda p:p["accounting"].update(cleanup_elapsed_ns=46000000001),
      "uncertain-cleanup":lambda p:p["cleanup"].update(uncertain=True),"borrowed-delete":lambda p:p["borrowed_image"].update(removal="deleted"),
      "admission":lambda p:p.update(capability_admission=["MemoryLimit"]),"private-extra":lambda p:p.update(PRIVATE_MEMORY_CANARY="PRIVATE_MEMORY_CANARY")}


class MemoryProofTests(unittest.TestCase):
    def test_all_four_profiles_and_both_backends_accept_real_visible_private_root_scope(self):
        for lane in LANES:
            for backend in ("podman","docker"):
                p=fixture(lane,outer_backend=backend)
                with self.subTest(lane=lane,backend=backend):
                    self.assertEqual(reader.validate_memory_proof(p,deepcopy(p["context"]),outer_backend=backend),{"contract":"memory-limits-v1","capability_admission":[],"catalogue_admission":False})
                    self.assertLess(len(json.dumps(p,separators=(",",":")).encode()),65536)
        # Available128MiB is sufficient for96MiB. No invented512MiB minimum.
        self.assertEqual(167772160-33554432,134217728)
        reader.validate_memory_proof(fixture(),fixture()["context"],outer_backend="podman")

    def test_false_semantics_still_fail_after_all_raw_hashes_are_rebound(self):
        original=fixture()
        for name,change in mutations().items():
            p=deepcopy(original);change(p);rebind(p)
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,"invalid private memory proof"):
                reader.validate_memory_proof(p,original["context"],outer_backend="podman")

    def test_v1_unknown_scopes_and_missing_live_files_never_pass_as_v2(self):
        for before,after in (("mount 2 ","mount 1 "),("v2_events_local","v1_oom_control_local"),("node / 42","gone / 42"),(" 1 1 2 "," 0 1 2 ")):
            p=fixture();sample=p["cases"][1]["containers"][0]["after"]["report"];sample["raw"]=sample["raw"].replace(before,after);rebind(p)
            with self.assertRaises(ValueError):reader.validate_memory_proof(p,p["context"],outer_backend="podman")

    def test_private_reader_requires_held_64k_custody_and_rejects_substitution(self):
        for fault in ("valid","malformed","duplicate","oversize","mode","directory-mode","symlink","hardlink","fifo"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);root.chmod(0o700);p=fixture();file=root/reader.FILENAME
                file.write_text(json.dumps(p));file.chmod(0o600)
                if fault=="malformed":file.write_text("{")
                elif fault=="duplicate":file.write_text('{"schema":1,"schema":1}')
                elif fault=="oversize":file.write_text("x"*65537)
                elif fault=="mode":file.chmod(0o644)
                elif fault=="directory-mode":root.chmod(0o755)
                elif fault=="symlink":file.rename(root/"original");file.symlink_to(root/"original")
                elif fault=="hardlink":os.link(file,root/"alias")
                elif fault=="fifo":file.unlink();os.mkfifo(file,0o600)
                if fault=="valid":self.assertEqual(reader.read_memory_proof(file,root,p["context"],outer_backend="podman"),reader.RESULT)
                else:
                    with self.assertRaises(ValueError):reader.read_memory_proof(file,root,p["context"],outer_backend="podman")
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700);p=fixture();file=root/reader.FILENAME;file.write_text(json.dumps(p));file.chmod(0o600)
            real_read=os.read
            def swap(fd,size):
                data=real_read(fd,size);file.unlink();file.write_text(json.dumps(p));file.chmod(0o600);return data
            with patch("native_network_attachment_proof.os.read",side_effect=swap),self.assertRaises(ValueError):
                reader.read_memory_proof(file,root,p["context"],outer_backend="podman")

    def test_exact_budget_arithmetic_and_both_program_identities(self):
        self.assertEqual(13*(65550+8192)+3*65536+91*8192,1900726)
        self.assertLess(1900726,2097152);self.assertEqual(36*(8192+2048),368640)
        self.assertEqual([(9+94),(10+94),(11+94+1),(12+94+1)],[103,104,106,107])
        source=(ROOT/"src/native_memory_tests.rs").read_text()
        for constant,literal,digest in (("BARRIER",BARRIER,reader.BARRIER_SHA256),("CHILD",CHILD,reader.CHILD_SHA256)):
            self.assertEqual(re.search(r'const '+constant+r': &str = r#"(.*?)"#;',source,re.S)[1],literal)
            self.assertEqual(sha256(literal.encode()).hexdigest(),digest)
        self.assertLess(BARRIER.index("trap '' USR1"),BARRIER.index('wait "$child"'))
        self.assertLess(BARRIER.index("trap 'exit"),BARRIER.index('status.tmp'))
        self.assertLess(CHILD.index("trap 'exec dd"),CHILD.index("child-ready.tmp"))
        self.assertIn(': >"$d/held"',BARRIER)
        for forbidden in ("oom_score_adj","OOMKillDisable",'"MemorySwap"',"native_pids_boundary","native-pids-supervisor"):
            self.assertNotIn(forbidden,source)


class MemoryBarrierTests(unittest.TestCase):
    def test_real_shell_two_barriers_repeated_release_and_actual_wait(self):
        # Run the actual reviewed programs with ONLY the PID1 guard and private
        # fixture path adapted. dd is a tiny explicit fake, never an allocator.
        # This tests shell wait/signal/publication semantics, not native cgroups.
        for child_result in (0,137):
            with self.subTest(child_result=child_result),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);d=root/"fixture";bin_dir=root/"bin";bin_dir.mkdir()
                fake=bin_dir/"dd";fake.write_text('''#!/usr/bin/python3
import os,signal,time
from pathlib import Path
root=Path(os.environ["MEMORY_TEST_ROOT"])
(root/"allocated").write_text(str(os.getpid()))
end=time.monotonic()+3
while not (root/"finish").exists():
    if time.monotonic()>end:raise SystemExit(73)
    time.sleep(0.005)
if os.environ["MEMORY_CHILD_RESULT"]=="137":os.kill(os.getpid(),signal.SIGKILL)
print("1+0 records in\\n1+0 records out",flush=True)
''');fake.chmod(0o700)
                parent=BARRIER.replace('test "$$" = 1','test "$$" -gt 1',1).replace('/tmp/dl-memory',str(d))
                child=CHILD.replace('/tmp/dl-memory',str(d))
                proc=subprocess.Popen(["/bin/sh","-c",parent,"synthetic",child],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                      env={**os.environ,"PATH":str(bin_dir)+os.pathsep+os.environ["PATH"],"MEMORY_TEST_ROOT":str(root),"MEMORY_CHILD_RESULT":str(child_result)},start_new_session=True)
                try:
                    def until(file):
                        end=time.monotonic()+3
                        while not file.exists():
                            if proc.poll() is not None:self.fail("supervisor ended before barrier")
                            if time.monotonic()>end:self.fail("synthetic barrier timed out")
                            time.sleep(0.005)
                    until(d/"bound");self.assertFalse((root/"allocated").exists())
                    ready_program=re.search(r'const READY: &str = r#"(.*?)"#;',(ROOT/"src/native_memory_tests.rs").read_text(),re.S)[1]
                    ready_program=ready_program.replace('/tmp/dl-memory',str(d)).replace('/proc/1/',f'/proc/{proc.pid}/')
                    observed=subprocess.run(["/bin/sh","-c",ready_program,"synthetic",child],capture_output=True,timeout=2,check=False)
                    self.assertEqual(observed.returncode,0,observed.stderr)
                    os.kill(proc.pid,signal.SIGUSR1);until(root/"allocated")
                    too_late=subprocess.run(["/bin/sh","-c",ready_program,"synthetic",child],capture_output=True,timeout=2,check=False)
                    self.assertNotEqual(too_late.returncode,0,"allocation already released cannot masquerade as ready child shell")
                    for _ in range(3):os.kill(proc.pid,signal.SIGUSR1);time.sleep(0.005)
                    self.assertIsNone(proc.poll());self.assertFalse((d/"held").exists())
                    (root/"finish").touch();until(d/"held")
                    token,pid,status=(d/"status").read_text().split();self.assertEqual(token,"synthetic");self.assertEqual(int(status),child_result)
                    self.assertEqual(pid,(root/"allocated").read_text());self.assertIsNone(proc.poll())
                    os.kill(proc.pid,signal.SIGUSR2);out,err=proc.communicate(timeout=3);self.assertEqual(proc.returncode,child_result);self.assertEqual(err,b"")
                    self.assertEqual(out,b"1+0 records in\n1+0 records out\n" if child_result==0 else b"")
                finally:
                    if proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.communicate(timeout=3)

    def test_premature_final_release_and_cancellation_cannot_publish_wait_success(self):
        for sig in (signal.SIGUSR2,signal.SIGTERM):
            with self.subTest(signal=sig),tempfile.TemporaryDirectory() as directory:
                d=Path(directory)/"fixture"
                parent=BARRIER.replace('test "$$" = 1','test "$$" -gt 1',1).replace('/tmp/dl-memory',str(d))
                child=CHILD.replace('/tmp/dl-memory',str(d))
                proc=subprocess.Popen(["/bin/sh","-c",parent,"synthetic",child],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                try:
                    deadline=time.monotonic()+2
                    while not (d/"bound").exists():
                        if time.monotonic()>deadline:self.fail("synthetic startup deadline")
                        time.sleep(0.005)
                    os.kill(proc.pid,sig);proc.wait(timeout=2)
                    self.assertEqual(proc.returncode,-sig)
                    self.assertFalse((d/"held").exists());self.assertFalse((d/"status").exists())
                finally:
                    try:os.killpg(proc.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    proc.communicate(timeout=2)


if __name__=="__main__":unittest.main()


def bind_context(proof, context):
    """Synthetic emitter fixture binding, retaining independently authored data."""
    old = proof["context"]
    serialized = json.dumps(proof).replace(old["run_id"], context["run_id"]).replace(old["fixture_image"], context["fixture_image"])
    bound = json.loads(serialized)
    bound["context"] = deepcopy(context)
    bound["outer_source"]["id"] = context["outer"]["id"]
    rebind(bound)
    return bound
