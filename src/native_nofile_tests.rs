//! Unregistered nofile-v1 source preparation; never capability admission.
//! Native programs below must run only in the independently owned native lanes.

use super::*;
use crate::observation::{Availability, Origin};
use crate::target::{ContainerToken, Ulimit, UlimitValue};
use std::collections::BTreeMap;

const CONTRACT: &str = "nofile-v1";
const FILENAME: &str = "nofile-v1.json";
const NOFILE_PROOF_MAX_BYTES: usize = 512 * 1024;
const METADATA_MAX_BYTES: usize = 64 * 1024;
const CASES: [(&str, i64, i64); 4] = [
    ("soft64_hard128", 64, 128),
    ("soft128_hard128", 128, 128),
    ("soft64_hard_unlimited", 64, -1),
    ("both_unlimited", -1, -1),
];
const REQUESTS: usize = 20;
const BODIES: usize = 512 * 1024;
const REFUSAL: &str = "error setting rlimit type 7: operation not permitted";

// Independently authored POSIX-awk program. No oracle implementation is copied.
// ERRNO is captured immediately: even close() may subsequently overwrite it.
const WORKER: &str = r#"function sample(tag, a,n,s,h,p,q,l){
while((getline l < "/proc/self/limits")>0){n=split(l,a);if(a[1]=="Max"&&a[2]=="open"&&a[3]=="files"){s=a[4];h=a[5]}}close("/proc/self/limits");
while((getline l < "/proc/self/status")>0){split(l,a);if(a[1]=="Pid:")p=a[2];if(a[1]=="PPid:")q=a[2]}close("/proc/self/status");
print tag,s,h,p,q;return s}
function gate(tag,g){print "phase",tag;fflush();if((getline g)!=1||g!=token " " tag)exit 81}
BEGIN{
s=sample("self_pre");gate("base");n=0;r=1;e=0;
for(i=1;i<=192;i++){f="/tmp/dl-nf/f" i;ERRNO=0;r=(getline v < f);e=ERRNO;if(r!=1)break;if(v!=token " " i)exit 82;n++}
if(r!=1&&(r!=-1||e!=24))exit 83;
if(r==1&&s!="unlimited"&&s<=192)exit 84;
print "held",n,r,e;gate("held");
for(i=1;i<=n;i++)if(close("/tmp/dl-nf/f" i)!=0)exit 85;
for(i=1;i<=256;i++){f="/tmp/dl-nf/f" i;if((getline v < f)!=1||v!=token " " i||close(f)!=0)exit 86}
print "reuse",256;sample("self_post");gate("done");exit 87
}"#;

const PARENT: &str = r#"test "$$" = 1 || exit 71
set -eu;LC_ALL=C;export LC_ALL;umask 077;d=/tmp/dl-nf
test ! -e "$d";test ! -L "$d";mkdir "$d";mkfifo "$d/gate";: >"$d/report";: >"$d/error"
for i in $(seq 1 256);do printf '%s %s\n' "$0-child" "$i" >"$d/f$i";done
exec 3<>"$d/gate"
s(){ printf '%s ' "$1";awk '/^Max open files /{printf "%s %s ",$4,$5}' /proc/"$2"/limits;awk '/^Pid:/{printf "%s ",$2}/^PPid:/{print $2}' /proc/"$2"/status;}
f(){ for p in /proc/$c/fd/*;do printf 'fd %s %s %s ' "$1" "${p##*/}" "$(readlink "$p")";stat -L -c '%d %i' "$p";done;}
w(){ for i in $(seq 1 80);do if grep -qx "phase $1" "$d/report";then return;fi;sleep 0.025;done;exit 72;}
b(){ test "/proc/$c/exe" -ef /bin/awk;printf '%s\000' /bin/awk -v "token=$0-child" "$1" | cmp "/proc/$c/cmdline" -;}
{
printf 'nr_open ';cat /proc/sys/fs/nr_open
stat -c 'own %n %d %i' "$d"/f* "$d/gate" "$d/report" "$d/error"
s parent_pre 1
(exec /bin/awk -v "token=$0-child" "$1" 3>&- <"$d/gate" >"$d/report" 2>"$d/error") &
c=$!;w base;b "$1";s bound_pre "$c";f base;f base_repeat
printf '%s base\n' "$0-child" >&3;w held;f saturated;f saturated_repeat
printf '%s held\n' "$0-child" >&3;w done;f restored;s bound_post "$c";s parent_post 1;b "$1"
test ! -s "$d/error"
} >"$d/parent.tmp"
mv "$d/parent.tmp" "$d/parent";wait "$c""#;

const OBSERVE: &str = r#"set -eu;LC_ALL=C;export LC_ALL;test "$(id -u)" = 0;test "$(id -g)" = 0;d=/tmp/dl-nf
for i in $(seq 1 100);do if [ -f "$d/parent" ];then break;fi;sleep 0.05;done
test -f "$d/parent";test ! -L "$d/parent";test ! -s "$d/error"
c=$(awk '$1=="bound_pre"{print $4}' "$d/parent");test -n "$c"
test "/proc/$c/exe" -ef /bin/awk;printf '%s\000' /bin/awk -v "token=$0-child" "$1" | cmp "/proc/$c/cmdline" -
cat "$d/parent" "$d/report"
s(){ printf '%s ' "$1";awk '/^Max open files /{printf "%s %s ",$4,$5}' /proc/"$2"/limits;awk '/^Pid:/{printf "%s ",$2}/^PPid:/{print $2}' /proc/"$2"/status;}
s root_parent 1;s root_worker "$c""#;

fn number(text: &str) -> u64 {
    assert!(
        !text.is_empty()
            && (text == "0" || !text.starts_with('0'))
            && text.bytes().all(|b| b.is_ascii_digit()),
        "canonical private nofile integer"
    );
    text.parse()
        .unwrap_or_else(|_| panic!("bounded private nofile integer"))
}

fn limit(text: &str) -> Value {
    if text == "unlimited" {
        json!("unlimited")
    } else {
        json!(number(text))
    }
}

fn entry(fd: u64, target: &str, device: u64, inode: u64) -> Value {
    json!({"fd":fd,"target":target,"device":device,"inode":inode})
}

fn witness(bytes: &[u8], expected: (i64, i64)) -> Value {
    let text = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("private nofile UTF8"));
    assert!(text.ends_with('\n'), "complete private nofile report");
    let mut samples = BTreeMap::new();
    let mut owners = BTreeMap::new();
    let mut descriptors: BTreeMap<String, BTreeMap<u64, Value>> = BTreeMap::new();
    let mut phases = Vec::new();
    let (mut nr_open, mut held, mut reuse) = (None, None, None);
    for line in text.lines() {
        let a: Vec<_> = line.split(' ').collect();
        match a.as_slice() {
            ["nr_open", value] => {
                assert!(
                    nr_open.replace(number(value)).is_none(),
                    "one owned kernel ceiling"
                );
            }
            ["own", path, device, inode] => {
                assert!(
                    owners
                        .insert(
                            (*path).to_owned(),
                            json!({"device":number(device),"inode":number(inode)})
                        )
                        .is_none(),
                    "unique owned stream manifest"
                );
            }
            ["fd", phase, fd, target, device, inode] => {
                let fd = number(fd);
                assert!(fd <= i32::MAX as u64, "Linux descriptor number range");
                assert!(
                    descriptors
                        .entry((*phase).to_owned())
                        .or_default()
                        .insert(fd, entry(fd, target, number(device), number(inode)))
                        .is_none(),
                    "unique live descriptor number"
                );
            }
            ["phase", name] => phases.push(*name),
            ["held", count, result, error] => {
                assert!(
                    held.replace((number(count), *result, number(error)))
                        .is_none(),
                    "one live held-open result"
                );
            }
            ["reuse", count] => {
                assert!(
                    reuse.replace(number(count)).is_none(),
                    "one close reuse result"
                );
            }
            [name, soft, hard, pid, ppid]
                if [
                    "parent_pre",
                    "parent_post",
                    "bound_pre",
                    "bound_post",
                    "self_pre",
                    "self_post",
                    "root_parent",
                    "root_worker",
                ]
                .contains(name) =>
            {
                assert!(samples.insert((*name).to_owned(),json!({"soft":limit(soft),"hard":limit(hard),"pid":number(pid),"ppid":number(ppid)})).is_none(), "one independently read process sample");
            }
            _ => panic!("closed private nofile report grammar"),
        }
    }
    assert!(
        samples.len() == 8 && phases == ["base", "held", "done"] && reuse == Some(256),
        "complete inherited worker phases"
    );
    let kernel = json!({"soft":samples["self_pre"]["soft"],"hard":samples["self_pre"]["hard"]});
    let child = samples["self_pre"]["pid"].as_u64().unwrap();
    assert!(
        (2..=i32::MAX as u64).contains(&child)
            && nr_open.is_some_and(|n| (128..=i32::MAX as u64).contains(&n)),
        "actual worker and readable kernel ceiling"
    );
    for (name, sample) in &samples {
        assert!(
            sample["soft"] == kernel["soft"]
                && sample["hard"] == kernel["hard"]
                && if name.starts_with("parent") || name == "root_parent" {
                    sample["pid"] == 1 && sample["ppid"] == 0
                } else {
                    sample["pid"] == child && sample["ppid"] == 1
                },
            "PID1 and inherited worker actual limits agree"
        );
    }
    for (name, wanted) in [("soft", expected.0), ("hard", expected.1)] {
        if wanted >= 0 {
            assert!(kernel[name] == json!(wanted), "finite authored limit exact");
        } else {
            assert!(
                kernel[name] == "unlimited"
                    || kernel[name]
                        .as_u64()
                        .is_some_and(|n| n > 0 && n <= nr_open.unwrap()),
                "truthful observed unlimited normalization"
            );
        }
    }
    if let (Some(soft), Some(hard)) = (kernel["soft"].as_u64(), kernel["hard"].as_u64()) {
        assert!(soft <= hard, "ordered actual limits");
    }
    assert!(
        kernel["soft"] != "unlimited" || kernel["hard"] == "unlimited",
        "unlimited soft requires unlimited hard"
    );
    assert!(
        owners.len() == 259 && descriptors.len() == 5,
        "complete owned file and live descriptor manifests"
    );
    let mut nodes = BTreeSet::new();
    for node in owners.values() {
        assert!(
            node["inode"].as_u64().is_some_and(|n| n > 0)
                && nodes.insert((
                    node["device"].as_u64().unwrap(),
                    node["inode"].as_u64().unwrap()
                )),
            "distinct owned regular/control stream inodes"
        );
    }
    for i in 1..=256 {
        assert!(
            owners.contains_key(&format!("/tmp/dl-nf/f{i}")),
            "complete numbered owned stream manifest"
        );
    }
    let base = &descriptors["base"];
    assert!(
        (3..=16).contains(&base.len())
            && base == &descriptors["base_repeat"]
            && base == &descriptors["restored"],
        "stable measured baseline restored after reuse"
    );
    for (fd, path) in [
        (0, "/tmp/dl-nf/gate"),
        (1, "/tmp/dl-nf/report"),
        (2, "/tmp/dl-nf/error"),
    ] {
        assert!(
            base[&fd]["target"] == path,
            "preopened standard descriptors"
        );
    }
    for value in base.values() {
        let path = value["target"].as_str().unwrap();
        assert!(
            ["/tmp/dl-nf/gate", "/tmp/dl-nf/report", "/tmp/dl-nf/error"].contains(&path)
                && value["device"] == owners[path]["device"]
                && value["inode"] == owners[path]["inode"],
            "unambiguous actually measured baseline"
        );
    }
    let (count, result, error) = held.unwrap();
    let sat = &descriptors["saturated"];
    assert!(
        sat == &descriptors["saturated_repeat"]
            && count <= 192
            && sat.len() == base.len() + count as usize,
        "stable actual live retained streams"
    );
    let mut actual = BTreeSet::new();
    for (fd, value) in sat {
        if let Some(original) = base.get(fd) {
            assert!(original == value, "baseline retained at saturation");
            continue;
        }
        let path = value["target"].as_str().unwrap();
        let i = number(
            path.strip_prefix("/tmp/dl-nf/f")
                .unwrap_or_else(|| panic!("owned retained stream target")),
        );
        assert!(
            (1..=count).contains(&i)
                && actual.insert(i)
                && value["device"] == owners[path]["device"]
                && value["inode"] == owners[path]["inode"],
            "distinct actual owned file streams not recycled"
        );
    }
    let finite = kernel["soft"].as_u64().is_some_and(|soft| soft <= 192);
    let failure = if finite {
        let soft = kernel["soft"].as_u64().unwrap();
        assert!(
            result == "-1"
                && error == 24
                && sat.len() as u64 == soft
                && sat.keys().copied().eq(0..soft),
            "actual EMFILE and live occupied descriptor range, not assumed minus three"
        );
        json!({"getline_return":-1,"errno":24,"attempt":count+1})
    } else {
        assert!(
            result == "1" && error == 0 && count == 192,
            "bounded successful opens beyond finite controls, never saturation/unlimited inference"
        );
        Value::Null
    };
    let outcome = if expected.1 >= 0 {
        "exact_finite_emfile"
    } else if kernel["hard"] != "unlimited" || (expected.0 < 0 && kernel["soft"] != "unlimited") {
        "finite_kernel_normalization"
    } else if expected.0 >= 0 {
        "exact_hard_unlimited_finite_soft_emfile"
    } else {
        "exact_both_unlimited_bounded_success"
    };
    json!({"outcome":outcome,"kernel":kernel,"samples":samples,"nr_open":nr_open.unwrap(),"owned_files":owners,
        "descriptors":descriptors.into_iter().map(|(name,items)|(name,items.into_values().collect::<Vec<_>>())).collect::<BTreeMap<_,_>>(),
        "retained_count":count,"failure":failure,"reuse_count":256,"phases":["base","held","done"],
        "exec_binding":"retained_background_pid_exact_nul_argv_exe_inode_and_proc"})
}

fn authored(run: &HealthRun, index: usize) -> Value {
    let (_, soft, hard) = CASES[index / 2];
    let value = |n: i64| {
        if n < 0 {
            UlimitValue::Unlimited
        } else {
            UlimitValue::Value(n as u64)
        }
    };
    let container = ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(run.names[index].as_bytes().to_vec()).unwrap(),
        image: ImageReference::new(run.base.as_bytes().to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Exec(
            ["sh", "-c", PARENT, run.names[index].as_str(), WORKER]
                .map(|t| Argument::new(t.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                    .unwrap(),
            ],
            ulimits: vec![Ulimit {
                name: ContainerToken::new(b"nofile".to_vec()).unwrap(),
                soft: value(soft),
                hard: value(hard),
            }],
            ..ContainerSettings::default()
        },
    };
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
    let graph = DockerPlanner
        .plan(
            &intent,
            &ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
    let request: Value =
        serde_json::from_slice(DockerApiRenderer.render(&graph).unwrap().bytes()).unwrap();
    let body = json!({"Image":run.base,"Cmd":["sh","-c",PARENT,run.names[index],WORKER],"Labels":{(OWNER):run.run},
        "HostConfig":{"Ulimits":[{"Name":"nofile","Soft":soft,"Hard":hard}]}});
    assert!(
        request
            == json!({"method":"POST","path":format!("/v{}/containers/create?name={}",run.api,run.names[index]),"body":body}),
        "complete independent literal nofile rendered request"
    );
    request
}

fn create_nofile(run: &mut HealthRun, index: usize) {
    assert!(
        run.inspect(&run.names[index], false).0 == 404,
        "fresh nofile name"
    );
    run.attempted[index] = true;
    if index.is_multiple_of(2) {
        let (_, soft, hard) = CASES[index / 2];
        let bytes = docker(
            run,
            &[
                "create".into(),
                "--name".into(),
                run.names[index].clone(),
                "--label".into(),
                format!("{OWNER}={}", run.run),
                "--ulimit".into(),
                format!("nofile={soft}:{hard}"),
                run.base.clone(),
                "sh".into(),
                "-c".into(),
                PARENT.into(),
                run.names[index].clone(),
                WORKER.into(),
            ],
        );
        let id = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed nofile CLI create ID"));
        bind(run, index, id);
    } else {
        let request = authored(run, index);
        let (status, value) = run.api(
            "POST",
            request["path"].as_str().unwrap(),
            Some(&request["body"]),
            false,
        );
        // Any create refusal without a canonical ID remains an unknown-owned
        // mutation: the nofile guard must require outer teardown before cleanup.
        assert!(
            status == 201 && (value["Warnings"].is_null() || value["Warnings"] == json!([])),
            "nofile create must yield known canonical ID"
        );
        bind(
            run,
            index,
            value["Id"]
                .as_str()
                .unwrap_or_else(|| panic!("closed nofile API create ID")),
        );
    }
}

fn configured(run: &HealthRun, index: usize, image: &Value, running: bool) -> Value {
    let id = run.ids[index].as_ref().unwrap();
    let (status, value) = run.inspect(id, false);
    let (_, soft, hard) = CASES[index / 2];
    assert!(
        status == 200
            && owned(run, &value, index, Some(id))
            && value["Image"] == image["id"]
            && value["Config"]["Cmd"] == json!(["sh", "-c", PARENT, run.names[index], WORKER])
            && (value["Config"]["Entrypoint"].is_null()
                || value["Config"]["Entrypoint"] == json!([]))
            && value["HostConfig"]["Ulimits"] == json!([{"Name":"nofile","Soft":soft,"Hard":hard}]),
        "owned exact configured nofile values and process"
    );
    assert!(
        value["HostConfig"]["Privileged"] == false
            && (value["HostConfig"]["CapAdd"].is_null()
                || value["HostConfig"]["CapAdd"] == json!([]))
            && (value["HostConfig"]["CapDrop"].is_null()
                || value["HostConfig"]["CapDrop"] == json!([]))
            && value["RestartCount"] == 0
            && value["State"]["OOMKilled"] == false
            && value["State"]["Running"] == running
            && value["State"]["Restarting"] == false
            && value["State"]["Paused"] == false
            && value["State"]["Dead"] == false
            && value["Mounts"].as_array().is_some_and(Vec::is_empty),
        "no caps, host mounts, restarts or unstable fixture"
    );
    value
}

// Only the existing independently implemented HTTP helper parses transport.
// This local frame retains non-2xx JSON which HealthRun::api intentionally drops.
fn start_http(run: &HealthRun, index: usize) -> (u16, Value) {
    let path = format!(
        "/v{}/containers/{}/start",
        run.api,
        run.ids[index].as_ref().unwrap()
    );
    assert!(
        run.request_allowed("POST", &path),
        "same exact nofile HTTP allowlist"
    );
    let mut command = run.timer(false, false);
    command.args([
        "python3",
        concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/native-unix-http.py"),
        "--timeout",
        "7",
        "--max-response-bytes",
        "65536",
        "--socket",
        &run.socket,
        "--method",
        "POST",
        "--max-request-bytes",
        "8388608",
        "--json-content-type",
        "--path",
        &path,
    ]);
    let bytes = run.capture(&mut command, None, false);
    let at = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .unwrap_or_else(|| panic!("closed nofile HTTP frame"));
    let status = std::str::from_utf8(&bytes[at + 1..])
        .ok()
        .filter(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("closed nofile HTTP status"));
    if status == 204 {
        assert!(at == 0, "empty successful nofile start body");
        (status, Value::Null)
    } else {
        let raw = std::str::from_utf8(&bytes[..at])
            .unwrap_or_else(|_| panic!("private nofile error UTF8"))
            .trim();
        let literal = raw
            .strip_prefix("{\"message\":")
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or_else(|| panic!("closed nofile HTTP message object"));
        // A single JSON string parser rejects trailing members and duplicate
        // message keys instead of collapsing a native object to its last key.
        let message: String = serde_json::from_str(literal)
            .unwrap_or_else(|_| panic!("single nofile HTTP error string"));
        (status, json!({"message":message}))
    }
}

fn start_cli(run: &HealthRun, index: usize) -> (u16, String) {
    let bytes=run.outer(&["sh".into(),"-c".into(),"output=$(\"$@\" 2>&1); status=$?; printf '%s\\nDOCKERLENS_NOFILE_EXIT:%s\\n' \"$output\" \"$status\"".into(),"dl-nofile-status".into(),
        "env".into(),"LC_ALL=C".into(),format!("DOCKER_API_VERSION={}",run.api),"docker".into(),"-H".into(),"unix:///dockerlens-native/docker.sock".into(),"start".into(),run.ids[index].as_ref().unwrap().clone()],false);
    let text = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| s.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("complete nofile CLI status frame"));
    let (output, status) = text
        .rsplit_once("\nDOCKERLENS_NOFILE_EXIT:")
        .unwrap_or_else(|| panic!("closed nofile CLI status delimiter"));
    let status = number(status);
    assert!(status <= 255, "bounded nofile CLI exit");
    (status as u16, output.to_owned())
}

fn refusal(error: &str) -> bool {
    error.len() <= 8192
        && error.bytes().all(|b| (32..=126).contains(&b))
        && (error == REFUSAL
            || error == format!("{REFUSAL}: unknown")
            || error.ends_with(&format!(": {REFUSAL}"))
            || error.ends_with(&format!(": {REFUSAL}: unknown")))
}

fn exercise(run: &HealthRun, index: usize, image: &Value) -> Value {
    let before = configured(run, index, image, false);
    assert!(
        before["State"]["Status"] == "created"
            && before["State"]["Pid"] == 0
            && before["State"]["StartedAt"] == "0001-01-01T00:00:00Z"
            && before["State"]["FinishedAt"] == "0001-01-01T00:00:00Z"
            && before["State"]["Error"] == ""
            && before["State"]["ExitCode"] == 0,
        "never-started exact create state"
    );
    let (status, reported) = if index.is_multiple_of(2) {
        let (s, t) = start_cli(run, index);
        (s, json!(t))
    } else {
        let (s, v) = start_http(run, index);
        (s, v)
    };
    let success = status == if index.is_multiple_of(2) { 0 } else { 204 };
    let current = configured(run, index, image, success);
    let (_, soft, hard) = CASES[index / 2];
    if success {
        if index.is_multiple_of(2) {
            assert!(
                reported == run.ids[index].as_ref().unwrap().as_str(),
                "exact nofile CLI started ID"
            );
        }
        assert!(
            current["State"]["Status"] == "running"
                && current["State"]["Pid"].as_u64().is_some_and(|n| n > 0),
            "actual live nofile PID1"
        );
        let bytes = docker(
            run,
            &[
                "exec".into(),
                "--user".into(),
                "0:0".into(),
                run.ids[index].as_ref().unwrap().clone(),
                "sh".into(),
                "-c".into(),
                OBSERVE.into(),
                run.names[index].clone(),
                WORKER.into(),
            ],
        );
        let value = witness(&bytes, (soft, hard));
        configured(run, index, image, true);
        json!({"stage":"running","cli_exit":if index.is_multiple_of(2){json!(0)}else{Value::Null},"http_status":if index.is_multiple_of(2){Value::Null}else{json!(204)},"diagnostic":Value::Null,"witness":value})
    } else {
        assert!(
            hard == -1 && status == if index.is_multiple_of(2) { 1 } else { 500 },
            "only specific unlimited START refusal eligible"
        );
        let error = current["State"]["Error"]
            .as_str()
            .unwrap_or_else(|| panic!("actual nofile start error"));
        assert!(
            refusal(error)
                && current["State"]["Status"] == "created"
                && current["State"]["Pid"] == 0
                && current["State"]["StartedAt"] == before["State"]["StartedAt"]
                && current["State"]["FinishedAt"] == before["State"]["FinishedAt"],
            "specific applying RLIMIT_NOFILE refusal and never-started facts"
        );
        if index.is_multiple_of(2) {
            let output = reported.as_str().unwrap();
            assert!(
                output
                    == format!(
                        "Error response from daemon: {error}\nError: failed to start containers: {}",
                        run.ids[index].as_ref().unwrap()
                    )
                    || output == format!("Error response from daemon: {error}"),
                "exact private CLI refusal corroborates inspected error"
            );
        } else {
            assert!(
                reported["message"] == error,
                "actual API error corroborates inspected error"
            );
        }
        let after = configured(run, index, image, false);
        assert!(
            after["State"] == current["State"],
            "stable never-started terminal failure"
        );
        json!({"stage":"start_refused","cli_exit":if index.is_multiple_of(2){json!(1)}else{Value::Null},"http_status":if index.is_multiple_of(2){Value::Null}else{json!(500)},"diagnostic":error,
            "witness":{"outcome":"specific_nofile_start_refusal","status":"created","pid":0,"never_started":true,"terminal_unchanged":true,"error":"setting_rlimit_nofile_eperm"}})
    }
}

fn acquisition(run: &HealthRun) -> Value {
    let calls = run.calls.get().checked_add(REQUESTS).unwrap();
    let bytes = run.bytes.get().checked_add(BODIES).unwrap();
    assert!(
        calls <= MAX_CALLS - CLEANUP_CALLS && bytes <= MAX_BYTES - CLEANUP_BYTES,
        "reserve one aggregate nofile acquisition"
    );
    let elapsed = run
        .remaining()
        .checked_sub(Duration::from_secs(46))
        .filter(|d| !d.is_zero())
        .unwrap_or_else(|| panic!("nofile acquisition cleanup reserve"));
    run.calls.set(calls);
    run.bytes.set(bytes);
    let selected = run
        .ids
        .iter()
        .map(|id| NativeId::new(id.as_ref().unwrap().clone()).unwrap())
        .collect();
    let capture = acquire(
        &Endpoint::unix_socket(PathBuf::from(&run.socket)),
        Selector::ContainerIds(selected),
        Limits {
            max_requests: REQUESTS,
            max_selected_resources: 8,
            max_expansions: 10,
            max_response_bytes: 131072,
            max_total_bytes: BODIES,
            max_elapsed: elapsed.min(Duration::from_secs(10)),
        },
        &AtomicBool::new(false),
    )
    .unwrap_or_else(|_| panic!("one actual eight-ID nofile acquisition"));
    let api = ApiVersion::new(
        NonZeroU16::new(1).unwrap(),
        if run.lane.starts_with("debian11-") {
            41
        } else {
            49
        },
    );
    assert!(
        capture.route() == CaptureRoute::ExplicitUnixSocket
            && capture.selected_roots().len() == 8
            && capture
                .exchanges()
                .iter()
                .all(|e| e.status().code() == 200 && e.api_version().is_none_or(|a| a == api)),
        "complete nofile acquisition and actual request API"
    );
    let decoded = decode_capture(&capture).unwrap_or_else(|_| panic!("actual nofile decode"));
    assert!(
        decoded.containers.len() == 8
            && decoded.version.requested_api_versions == vec![api]
            && decoded.version.daemon.observation_id == capture.observation_id()
            && decoded
                .version
                .daemon
                .release
                .as_ref()
                .is_some_and(|r| r.as_str() == run.engine),
        "actual bound nofile decoder context"
    );
    let mode = match (run.mode, decoded.version.daemon.mode) {
        (DaemonMode::Rootless, DaemonMode::Rootless) => "rootless_observed",
        (DaemonMode::Rootful, DaemonMode::Rootful) => "rootful_observed",
        (DaemonMode::Rootful, DaemonMode::Unknown) => "unknown_with_independent_rootful_context",
        _ => panic!("nonconflicting actual nofile mode"),
    };
    let mut seen = BTreeSet::new();
    for container in &decoded.containers {
        let id = container.id.value().unwrap().as_bytes();
        let index = run
            .ids
            .iter()
            .position(|other| other.as_ref().unwrap().as_bytes() == id)
            .unwrap_or_else(|| panic!("selected nofile decoded ID"));
        let values = container
            .runtime
            .ulimits
            .value()
            .unwrap_or_else(|| panic!("decoded nofile list present"));
        let (_, soft, hard) = CASES[index / 2];
        assert!(
            seen.insert(index)
                && container.id.availability == Availability::Present
                && container.id.origin == Origin::RuntimeAssigned
                && container.runtime.ulimits.availability == Availability::Present
                && container.runtime.ulimits.origin == Origin::Effective
                && values.len() == 1
                && values[0].name.availability == Availability::Present
                && values[0].name.origin == Origin::Effective
                && values[0]
                    .name
                    .value()
                    .is_some_and(|v| v.as_bytes() == b"nofile")
                && values[0].soft.availability == Availability::Present
                && values[0].soft.origin == Origin::Effective
                && values[0].hard.availability == Availability::Present
                && values[0].hard.origin == Origin::Effective
                && values[0].soft.value() == Some(&soft)
                && values[0].hard.value() == Some(&hard),
            "actual decoded configured nofile values, not inferred kernel support"
        );
    }
    let bodies: usize = capture
        .exchanges()
        .iter()
        .map(|e| e.body().as_bytes().len())
        .sum();
    assert!(
        capture.exchanges().len() <= REQUESTS && bodies <= BODIES,
        "bounded nofile response bodies"
    );
    json!({"route":"explicit_unix_socket","selected_ids":8,"requested_api":format!("{}.{}",api.major,api.minor),"reserved_calls":REQUESTS,"reserved_bytes":BODIES,"actual_requests":capture.exchanges().len(),"actual_response_bytes":bodies,"decoded":"present_effective_exact_nofile_values","daemon_mode_evidence":mode,
        "byte_scope":"decoded_response_bodies_only","separate_transport_bounds":{"response_header_bytes":16384,"chunk_line_bytes":64,"chunk_payload_crlf_bytes":2,"final_trailer_line_bytes":16384,"actual_wire_bytes":"not_measured"},
        "limits":{"max_requests":20,"max_selected_resources":8,"max_expansions":10,"max_response_bytes":131072,"max_total_bytes":BODIES,"max_elapsed_seconds":10}})
}

fn nofile_cleanup_with(
    attempted: &[bool],
    ids: &[Option<String>],
    inner: impl FnOnce() -> CleanupDisposition,
) -> CleanupDisposition {
    // Shared lifecycle cleanup can recover an unknown ID through its name.
    // Nofile does not authorize that recovery after an uncertain create.
    // Refuse the entire inner attempt before any read/name recovery/mutation.
    if attempted.len() != 8
        || ids.len() != 8
        || attempted
            .iter()
            .zip(ids)
            .any(|(attempted, id)| *attempted && !id.as_deref().is_some_and(identifier))
    {
        return CleanupDisposition::OuterTeardownRequired;
    }
    inner()
}

#[test]
fn nofile_unknown_create_id_never_invokes_inner_cleanup() {
    let attempted = vec![true; 8];
    let valid: Vec<_> = (1..=8).map(|n| Some(format!("{n:064x}"))).collect();
    for invalid in [
        None,
        Some("malformed".to_owned()),
        Some("a".repeat(63)),
        Some("A".repeat(64)),
    ] {
        let mut ids = valid.clone();
        ids[3] = invalid;
        let invoked = Cell::new(false);
        let disposition = nofile_cleanup_with(&attempted, &ids, || {
            invoked.set(true);
            CleanupDisposition::VerifiedAbsent
        });
        assert!(
            disposition == CleanupDisposition::OuterTeardownRequired && !invoked.get(),
            "unknown create ID must not permit name recovery or inner cleanup"
        );
    }
    let invoked = Cell::new(false);
    assert!(
        nofile_cleanup_with(&attempted, &valid, || {
            invoked.set(true);
            CleanupDisposition::VerifiedAbsent
        }) == CleanupDisposition::VerifiedAbsent
            && invoked.get(),
        "all bound canonical IDs permit normal cleanup"
    );
    assert!(
        nofile_cleanup_with(&attempted, &valid, || {
            CleanupDisposition::OuterTeardownRequired
        }) == CleanupDisposition::OuterTeardownRequired,
        "inner cleanup uncertainty remains unverified"
    );
    let invoked = Cell::new(false);
    assert!(
        nofile_cleanup_with(&attempted[..7], &valid, || {
            invoked.set(true);
            CleanupDisposition::VerifiedAbsent
        }) == CleanupDisposition::OuterTeardownRequired
            && !invoked.get(),
        "partial ownership ledger refuses cleanup"
    );
}

#[test]
#[ignore = "unregistered source preparation; requires exact isolated native lane and bound outer owner"]
fn live_nofile_limits_and_effects_match_engine() {
    let started = Instant::now();
    let target = ProofTarget::new_for("NATIVE_NOFILE_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_NOFILE_CANDIDATE_SHA",
        "NATIVE_NOFILE_DEADLINE_EPOCH",
    );
    run.names = CASES
        .into_iter()
        .flat_map(|(name, _, _)| {
            ["oracle", "rendered"].map(|role| format!("dl-nf-{}-{name}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 8];
    run.attempted = vec![false; 8];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: nofile_context");
        let uid = run.context();
        let image = image_snapshot(&run);
        assert!(
            image["config"]["Volumes"].is_null() || image["config"]["Volumes"] == json!({}),
            "no borrowed automatic volumes"
        );
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::Ulimits,
            Capability::UlimitNofile,
        ]
        .into_iter()
        .map(|capability| CapabilityFact {
            capability,
            state: CapabilityState::Available,
            provenance: FactProvenance::NativeConformance,
            scope: scope.clone(),
        })
        .collect();
        let context_calls = run.calls.get();
        assert!(
            context_calls
                == if run.lane.starts_with("debian11-") {
                    9
                } else {
                    8
                },
            "closed original context capture count"
        );
        let mut records = Vec::new();
        let mut slot_calls = Vec::new();
        eprintln!("DOCKERLENS_NATIVE_CHECK: nofile_effects");
        for index in 0..8 {
            let before = run.calls.get();
            create_nofile(&mut run, index);
            let effect = exercise(&run, index, &image);
            let expected = if effect["stage"] == "running" { 8 } else { 7 };
            assert!(
                run.calls.get() - before == expected,
                "closed outcome-derived nofile slot accounting"
            );
            slot_calls.push(expected);
            records.push(json!({"role":if index.is_multiple_of(2){"oracle"}else{"rendered"},"id":run.ids[index],"name":run.names[index],"owner":run.run,"image_id":image["id"],"wire":if index.is_multiple_of(2){"independent_cli"}else{"literal_rendered"},"configured":{"soft":CASES[index/2].1,"hard":CASES[index/2].2},"effect":effect,"cleanup":"absent"}));
        }
        let mut cases = Vec::new();
        for (i, (name, _, _)) in CASES.into_iter().enumerate() {
            let a = &records[2 * i]["effect"];
            let b = &records[2 * i + 1]["effect"];
            assert!(
                a["stage"] == b["stage"]
                    && a["witness"]["outcome"] == b["witness"]["outcome"]
                    && a["witness"]["kernel"] == b["witness"]["kernel"]
                    && a["witness"]["retained_count"] == b["witness"]["retained_count"],
                "independent matching CLI/API observed disposition"
            );
            cases.push(json!({"case":name,"containers":[records[2*i],records[2*i+1]]}));
        }
        for role in 0..2 {
            assert!(
                records[2 + role]["effect"]["witness"]["retained_count"]
                    .as_u64()
                    .unwrap()
                    > records[role]["effect"]["witness"]["retained_count"]
                        .as_u64()
                        .unwrap(),
                "greater live retained capacity at finite soft128 than64"
            );
        }
        let nr = records[0]["effect"]["witness"]["nr_open"].clone();
        for record in &records {
            if record["effect"]["stage"] == "running" {
                assert!(
                    record["effect"]["witness"]["nr_open"] == nr,
                    "same read-only kernel ceiling in owned contexts"
                );
            }
        }
        let (health_status, health) = run.api("GET", "/version", None, false);
        assert!(
            health_status == 200 && health["Version"] == run.engine,
            "post-case daemon health corroborated by finite controls"
        );
        eprintln!("DOCKERLENS_NATIVE_CHECK: nofile_capture");
        let acquired = acquisition(&run);
        (uid, image, cases, acquired, context_calls, slot_calls)
    }));
    let work_elapsed = started.elapsed();
    let before_calls = run.calls.get();
    let before_bytes = run.bytes.get();
    let cleanup_started = Instant::now();
    eprintln!("DOCKERLENS_NATIVE_CHECK: nofile_cleanup");
    // Bounded immutable ledger snapshots avoid borrowing the mutable runner in
    // the guard. Only the guarded callback can enter shared lifecycle cleanup.
    let attempted = run.attempted.clone();
    let ids = run.ids.clone();
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        nofile_cleanup_with(&attempted, &ids, || cleanup(&mut run))
    }))
    .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_calls = run.calls.get() - before_calls;
    let cleanup_bytes = run.bytes.get() - before_bytes;
    terminal_cleanup(&mut run, &owner, disposition);
    let (uid, image, cases, acquired, context_calls, slot_calls) =
        require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none() && image_snapshot(&run) == image,
        "borrowed image unchanged, never owned"
    );
    let outer = outer_context(&run);
    assert!(outer == owner.snapshot, "unchanged authenticated outer");
    let ordinary_calls = run.calls.get() - cleanup_calls;
    let ordinary_bytes = run.bytes.get() - cleanup_bytes;
    let ordinary_elapsed = started.elapsed().saturating_sub(cleanup_elapsed);
    assert!(
        ordinary_calls == context_calls + slot_calls.iter().sum::<usize>() + 1 + REQUESTS + 2
            && ordinary_bytes <= MAX_BYTES - CLEANUP_BYTES
            && cleanup_calls == 8 * 9
            && cleanup_bytes <= CLEANUP_BYTES,
        "derived closed nofile total accounting"
    );
    assert!(
        work_elapsed <= Duration::from_secs(134)
            && ordinary_elapsed <= Duration::from_secs(134)
            && cleanup_elapsed <= Duration::from_secs(46)
            && started.elapsed() <= Duration::from_secs(180),
        "original nofile absolute deadline and cleanup reserve"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"capability_admission":[],"catalogue_admission":false,"scope":"four_diagonal_nofile_cases_source_only","context":{"candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,"rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-"){ "1.41" }else{"1.49"},"mode":if run.mode==DaemonMode::Rootless{"rootless"}else{"rootful"},"docker_package":if run.lane.starts_with("debian11-"){"20.10.5+dfsg1-1+deb11u2"}else{""},"fixture_image":run.base,"daemon_uid":uid,"outer":outer},
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"cases":cases,"acquisition":acquired,"daemon_health":"version_matches_after_all_cases","accounting":{"context_calls":context_calls,"slot_calls":slot_calls,"daemon_health_calls":1,"acquisition_reserved_calls":REQUESTS,"final_readback_calls":2,"ordinary_calls":ordinary_calls,"ordinary_bytes":ordinary_bytes,"cleanup_calls":cleanup_calls,"cleanup_bytes":cleanup_bytes,"deadline_seconds":180,"cleanup_reserve_seconds":46,"ordinary_elapsed_ns":ordinary_elapsed.as_nanos(),"cleanup_elapsed_ns":cleanup_elapsed.as_nanos(),"elapsed_ns":started.elapsed().as_nanos(),"initial_context_acquisition":{"max_requests":16,"max_total_bytes":2097152,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"}},"cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    let mut metadata = proof.clone();
    for case in metadata["cases"].as_array_mut().unwrap() {
        for item in case["containers"].as_array_mut().unwrap() {
            if item["effect"]["stage"] == "running" {
                let witness = item["effect"]["witness"].as_object_mut().unwrap();
                witness.remove("owned_files");
                witness.remove("descriptors");
            }
        }
    }
    assert!(
        serde_json::to_vec(&metadata).unwrap().len() <= METADATA_MAX_BYTES,
        "bounded nofile metadata independent of inventories"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: nofile_proof");
    target.publish_bounded(&proof, NOFILE_PROOF_MAX_BYTES);
}
