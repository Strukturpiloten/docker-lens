"""Private memory limits/read-only pressure proof; no runtime calls or admission."""
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from native_external_network_proof import validate_context
from native_health_metadata_proof import timestamp_ns
from native_network_attachment_proof import canonical, keys, read_private_proof, unique_object
from native_shm_size_proof import exact, integer
from native_source_accounting import outer_snapshot_cost

CONTRACT = "memory-limits-v1"
FILENAME = CONTRACT + ".json"
LIMIT = 65536
WITNESS = 100663296
FINITE = 67108864
CASES = (("omitted", None), ("finite64", FINITE), ("zero", 0))
RESULT = {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}
SMALL = 8192
FULL = 65550 + 8192


def fail():
    raise ValueError("invalid private memory proof")


def number(text, low=0):
    if type(text) is not str or re.fullmatch(r"0|[1-9][0-9]{0,19}", text) is None:
        fail()
    return integer(int(text), low, 2**64 - 1)


def path(text):
    if (type(text) is not str or not text.startswith("/") or len(text) > 256
            or re.fullmatch(r"[A-Za-z0-9_./:@+\-]+", text) is None
            or "//" in text or any(p in (".", "..") for p in text.split("/"))):
        fail()
    return text


def namespace(text, kind):
    if type(text) is not str or re.fullmatch(kind + r":\[[1-9][0-9]{0,19}\]", text) is None:
        fail()
    return text


def raw(packet):
    keys(packet, ("raw", "sha256"))
    text = packet["raw"]
    if type(text) is not str or not text.endswith("\n") or not 0 < len(text.encode()) <= 4096:
        fail()
    exact(packet["sha256"], sha256(text.encode()).hexdigest())
    return text


def clock_bracket(bracket, clock):
    if type(bracket) is not list or len(bracket)!=3: fail()
    before,after,elapsed=(integer(v,1,2**64-1) for v in bracket)
    if not (before<=after<=before+8_000_000_000 and elapsed<=8_000_000_000
            and abs(after-before-elapsed)<=50_000_000 and before-250_000_000<=clock<=after+250_000_000): fail()


def sample(packet, mode):
    keys(packet,("report","clock_bracket"));rows=[line.split(" ") for line in raw(packet["report"]).splitlines()]
    if not 11<=len(rows)<=18 or rows[0]!=["memory-source-v1"]:fail()
    for row,name in zip(rows[1:9],("reader","mount","kernel","outer","swap","process","members","leaf")):
        if row[0]!=name:fail()
    if len(rows[1])!=3 or len(rows[2])!=6 or len(rows[3])!=2 or len(rows[4])!=7 or rows[5]!=["swap","0"]:fail()
    reader=[namespace(rows[1][1],"pid"),namespace(rows[1][2],"cgroup")]
    version,mount_id,device,root,mount=rows[2][1:]
    exact(version,"2");number(mount_id,1);exact(root,"/");path(mount)
    if re.fullmatch(r"[0-9]+:[0-9]+",device) is None or re.fullmatch(r"[A-Za-z0-9._+\-]{1,128}",rows[3][1]) is None:fail()
    outer=rows[4][1:];exact(outer[0],"/");number(outer[1],1);number(outer[2]);number(outer[3],1);path(outer[4]);exact(outer[5],reader[1])
    process=rows[6][1:];members=rows[7][1:]
    if mode=="baseline":exact(process,["baseline"]);exact(members,["baseline"])
    else:
        if len(process)!=8:fail()
        number(process[0],1);number(process[1],1);number(process[2],1);namespace(process[3],"pid");namespace(process[4],"cgroup")
        if process[3]==reader[0]:fail()
        if mode=="pre":
            number(process[5],1);number(process[6],2);number(process[7],1)
            if process[0]==process[5]:fail()
            exact(members,[process[0],process[5]])
        else:
            exact(mode,"post");exact(process[5],"child_done");number(process[6],2)
            if process[7] not in ("0","137"):fail()
            exact(members,[process[0]])
    if len(rows[8])!=2:fail()
    leaf=path(rows[8][1]);nodes=[];expected=leaf
    for row in rows[9:-1]:
        if len(row)!=11 or row[0]!="node":fail()
        _,name,dev,inode,limit,usage,oom,kill,maximum,group,scope=row
        exact(name,expected);path(name);number(dev);number(inode,1)
        if limit!="max":number(limit,1)
        for n in (usage,oom,kill,maximum,group):number(n)
        if group not in ("0","1"):fail()
        exact(scope,"v2_events_local")
        d=int(dev);major=((d>>8)&0xfff)|((d>>32)&0xfffff000);minor=(d&0xff)|((d>>12)&0xffffff00)
        exact(device,f"{major}:{minor}")
        nodes.append({"path":name,"id":[dev,inode],"raw_limit":limit,"limit":None if limit=="max" else int(limit),
                      "usage":int(usage),"oom":int(oom),"kill":int(kill),"maximum":int(maximum),"group":int(group),"scope":scope})
        expected=str(PurePosixPath(expected).parent)
    if not 1<=len(nodes)<=8:fail()
    exact(nodes[-1]["path"],"/");exact(nodes[-1]["id"],outer[2:4]);exact(nodes[-1]["limit"],4294967296)
    if mode!="baseline" and len(nodes)<2:fail()
    if len(rows[-1])!=2 or rows[-1][0]!="clock":fail()
    clock=timestamp_ns(rows[-1][1]);clock_bracket(packet["clock_bracket"],clock)
    return {"version":"2","reader":reader,"mount":rows[2][1:],"kernel":rows[3][1],"outer":outer,
            "process":process,"members":members,"leaf":leaf,"nodes":nodes,"clock":clock,"clock_text":rows[-1][1]}


def ancestry(nodes):
    return [(n["path"], n["id"], n["raw_limit"], n["scope"]) for n in nodes]


def readiness(packet, name):
    lines=raw(packet).splitlines()
    if len(lines)!=8 or not lines[0].startswith("ready "+name+" ") or lines[5]!="child_parent 1" or lines[6:]!=["uid 0 0 0 0"]*2:fail()
    child=number(lines[0][len("ready "+name+" "):],2);namespace(lines[1],"pid");namespace(lines[2],"cgroup")
    if not lines[3].startswith("parent_start ") or not lines[4].startswith("child_start "):fail()
    return lines[1],lines[2],number(lines[3][13:],1),child,number(lines[4][12:],1)


def configured(item, expected, image, context):
    keys(item, ("id", "name", "image", "config_image", "owner", "cmd", "entrypoint", "user", "init", "memory", "memory_swap", "running", "pid", "started_at", "finished_at", "oom", "exit", "status", "restarts", "error", "restarting", "paused", "dead", "privileged", "cap_add", "cap_drop", "mounts"))
    for key, value in (("id", expected["id"]), ("name", "/" + expected["name"]), ("image", image),
                       ("config_image", context["fixture_image"]), ("owner", context["run_id"]),
                       ("memory", expected["memory"] or 0), ("restarts", 0), ("error", ""),
                       ("restarting", False), ("paused", False), ("dead", False), ("privileged", False), ("mounts", [])):
        exact(item[key], value)
    # The source binds the exact barrier bytes; private reader independently binds
    # its closed program digest and argv, not a caller-provided success token.
    if item["entrypoint"] not in (None, []) or item["init"] not in (None, False) or type(item["init"]) not in (type(None), bool):
        fail()
    if item["user"] not in ("", "0", "0:0") or item["cap_add"] not in (None, []) or item["cap_drop"] not in (None, []):
        fail()
    if type(item["cmd"]) is not list or len(item["cmd"]) != 5 or item["cmd"][:2] != ["sh", "-c"] or item["cmd"][3] != expected["name"]:
        fail()
    exact(sha256(item["cmd"][2].encode()).hexdigest(), BARRIER_SHA256)
    exact(sha256(item["cmd"][4].encode()).hexdigest(), CHILD_SHA256)
    integer(item["memory_swap"], -1, 2**63 - 1)


# Independently reviewed exact program identity; tests supply literal bytes and
# verify it against the Rust source rather than deriving this constant at import.
BARRIER_SHA256 = "60c40fd1b5cc867508fb64690fa96e1cc6b58ec063767f4f428fcc164839cdea"


CHILD_SHA256 = "45554395dfb9f8f955bcf3d8413f3175dda84fc924408152428a8630292bee1f"

def validate_memory_proof(proof, expected_context, *, outer_backend):
    try:
        extra_calls,extra_bytes=outer_snapshot_cost(outer_backend);validate_context(expected_context)
        if not expected_context["fixture_image"].startswith("docker.io/library/busybox:"):fail()
        keys(proof,("schema_version","contract","context","outer_backend","outer_source","capability_admission","catalogue_admission","scope","hidden_ancestry","borrowed_image","baseline","cases","accounting","cleanup","daemon_health"))
        for k,v in (("schema_version",1),("contract",CONTRACT),("context",expected_context),("outer_backend",outer_backend),("capability_admission",[]),("catalogue_admission",False),
                    ("scope","observed_local_pressure_and_bound_child_victim"),("hidden_ancestry","unobserved_above_private_guest_root"),
                    ("cleanup",{"containers":"absent","rounds":2,"outstanding":0,"uncertain":False}),("daemon_health","version_matches_after_controls")):
            exact(proof[k],v)
        outer=proof["outer_source"];keys(outer,("id","pid","started_at","cgroupns","pid_mode","restarts"))
        exact(outer["id"],expected_context["outer"]["id"]);integer(outer["pid"],1,2**31-1);timestamp_ns(outer["started_at"])
        exact(outer["cgroupns"],"private");exact(outer["restarts"],0)
        if type(outer["pid_mode"]) is not str or outer["pid_mode"] not in ("","private"):fail()
        image=proof["borrowed_image"];keys(image,("id","identity","removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):fail()
        exact(image["identity"],"unchanged");exact(image["removal"],"not_owned")
        baseline=sample(proof["baseline"],"baseline")
        if type(proof["cases"]) is not list or len(proof["cases"])!=3:fail()
        ids={expected_context["outer"]["id"]};common=None;unbounded=[]
        for case,(name,memory) in zip(proof["cases"],CASES):
            keys(case,("case","containers"));exact(case["case"],name)
            if type(case["containers"]) is not list or len(case["containers"])!=2:fail()
            for item,role in zip(case["containers"],("oracle","rendered")):
                keys(item,("role","id","name","owner","wire","memory","running","terminal","readiness","before","after","child_wait_exit","parent_wait_exit","parent_exit_kind","logs","events","event_clock","pid_continuity","cleanup"))
                if not canonical(item["id"]) or item["id"] in ids:fail()
                ids.add(item["id"])
                for k,v in (("role",role),("name",f"dl-memory-{expected_context['run_id']}-{name}-{role}"),("owner",expected_context["run_id"]),("wire","independent_cli" if role=="oracle" else "literal_rendered"),("memory",memory),
                            ("parent_exit_kind","supervisor_propagated_child_status"),("pid_continuity","child_exec_semantics_not_post_exec_sampled"),("cleanup","absent")):
                    exact(item[k],v)
                configured(item["running"],item,image["id"],expected_context);configured(item["terminal"],item,image["id"],expected_context)
                running,terminal=item["running"],item["terminal"]
                for k,v in (("status","running"),("running",True),("oom",False),("exit",0)):exact(running[k],v)
                integer(running["pid"],1,2**31-1)
                expected_exit=137 if memory==FINITE else 0
                for k,v in (("status","exited"),("running",False),("pid",0),("oom",memory==FINITE),("exit",expected_exit),("started_at",running["started_at"])):exact(terminal[k],v)
                exact(item["child_wait_exit"],expected_exit);exact(item["parent_wait_exit"],expected_exit)
                ns,cgns,start,child,child_start=readiness(item["readiness"],item["name"])
                pre,post=sample(item["before"],"pre"),sample(item["after"],"post")
                exact(pre["process"][1:5],[str(running["pid"]),str(start),ns,cgns]);exact(pre["process"][6:],[str(child),str(child_start)])
                exact(post["process"][:5],pre["process"][:5]);exact(post["process"][5:],["child_done",str(child),str(expected_exit)])
                for measured in (pre,post):
                    for k in ("version","reader","mount","kernel","outer"):exact(measured[k],baseline[k])
                exact(post["leaf"],pre["leaf"])
                if pre["leaf"]=="/":fail()
                a,b=pre["nodes"],post["nodes"];exact(ancestry(a),ancestry(b))
                strict=a[1:]
                if common is None:common=ancestry(strict)
                exact(ancestry(strict),common)
                for before,after in zip(strict,b[1:]):
                    for k in ("oom","kill","maximum"):exact(after[k],before[k])
                    if before["limit"] is not None and (before["usage"]>before["limit"] or before["limit"]-before["usage"]<WITNESS):fail()
                exact(a[0]["limit"],FINITE if memory==FINITE else None);exact(a[0]["group"],0);exact(b[0]["group"],0)
                for k in ("oom","kill","maximum"):
                    if memory==FINITE:
                        if (b[0][k]!=a[0][k]+1 if k=="kill" else b[0][k]<=a[0][k]):fail()
                    else:exact(b[0][k],a[0][k])
                if memory!=FINITE:unbounded.append((a[0]["raw_limit"],min((n["limit"] for n in strict if n["limit"] is not None),default=None)))
                event_clock=item["event_clock"];keys(event_clock,("time","bracket"));event_end=timestamp_ns(event_clock["time"]);clock_bracket(event_clock["bracket"],event_end)
                started=timestamp_ns(running["started_at"]);finished=timestamp_ns(terminal["finished_at"])
                if not started<=pre["clock"]<post["clock"]<=event_end<=finished:fail()
                log=item["logs"]
                if type(log) is not str or len(log.encode())>4096:fail()
                if memory==FINITE:exact(log,"")
                elif re.fullmatch(r"1\+0 records in\n1\+0 records out\n(?:100663296 bytes [ -~]{1,256}\n)?",log) is None:fail()
                events=item["events"]
                if type(events) is not str or len(events.encode())>4096:fail()
                parsed=[json.loads(line,object_pairs_hook=unique_object) for line in events.splitlines()]
                exact(len(parsed),1 if memory==FINITE else 0)
                for event in parsed:
                    keys(event,("type","action","id","owner","time_nano"))
                    for k,v in (("type","container"),("action","oom"),("id",item["id"]),("owner",expected_context["run_id"])):exact(event[k],v)
                    integer(event["time_nano"],pre["clock"],event_end)
        if len(set(unbounded))!=1:fail()
        a=proof["accounting"];keys(a,("context_calls","baseline_calls","slot_calls","daemon_health_calls","final_readback_calls","ordinary_calls","ordinary_bytes","small_calls","small_bytes","cleanup_calls","cleanup_bytes","deadline_seconds","cleanup_reserve_seconds","ordinary_elapsed_ns","cleanup_elapsed_ns","elapsed_ns","initial_context_acquisition"))
        context_calls=(10 if expected_context["lane"].startswith("debian11-") else 9)+2*extra_calls
        for k,v in (("context_calls",context_calls),("baseline_calls",1),("slot_calls",[15]*6),("daemon_health_calls",1),("final_readback_calls",2+extra_calls),("ordinary_calls",context_calls+94+extra_calls),
                    ("small_calls",91),("cleanup_calls",36),("deadline_seconds",180),("cleanup_reserve_seconds",46),
                    ("initial_context_acquisition",{"max_requests":16,"max_total_bytes":2097152,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"})):
            exact(a[k],v)
        integer(a["small_bytes"],1,91*SMALL)
        upper=(13 if expected_context["lane"].startswith("debian11-") else 12)*FULL+3*extra_bytes+91*SMALL
        integer(a["ordinary_bytes"],a["small_bytes"]+3*extra_bytes,upper);integer(a["cleanup_bytes"],1,36*10240)
        work=integer(a["ordinary_elapsed_ns"],1,134*10**9);cleanup=integer(a["cleanup_elapsed_ns"],1,46*10**9)
        if work+cleanup>integer(a["elapsed_ns"],1,180*10**9):fail()
        return dict(RESULT)
    except (ValueError,TypeError,KeyError,OverflowError,RecursionError,IndexError,AttributeError):fail()


def read_memory_proof(file,capture_dir,context,*,outer_backend):
    try:
        outer_snapshot_cost(outer_backend)
        return read_private_proof(file,capture_dir,FILENAME,context,lambda p,c:validate_memory_proof(p,c,outer_backend=outer_backend),max_bytes=LIMIT)
    except (OSError,ValueError,TypeError,KeyError,OverflowError,RecursionError):fail()


def main(arguments):
    if len(arguments)!=12:fail()
    directory,candidate,run,lane,engine,api,mode,package,fixture,image,outer_id,uid=arguments
    if re.fullmatch(r"0|[1-9][0-9]{0,9}",uid) is None:fail()
    context={"candidate_sha":candidate,"run_id":run,"lane":lane,"engine_release":engine,"rendering_api":api,
             "acquisition_api":"1.41" if lane.startswith("debian11-") else "1.49","mode":mode,"docker_package":package,
             "fixture_image":fixture,"daemon_uid":int(uid),"outer":{"id":outer_id,"name":"dl-native-"+run,"owner":run,"image":image,
             "data_volume":"dl-native-data-"+run,"socket_source":str(Path(directory)/"socket"),"privileged":True,
             "memory_bytes":4294967296,"cpu_quota":200000,"cpu_period":100000,"pids_limit":512}}
    read_memory_proof(Path(directory)/FILENAME,directory,context,outer_backend=os.environ.get("NATIVE_OUTER_ENGINE"))


if __name__=="__main__":
    try:main(sys.argv[1:])
    except (OSError,ValueError,TypeError,KeyError,OverflowError,RecursionError):
        raise SystemExit("invalid private memory proof") from None
