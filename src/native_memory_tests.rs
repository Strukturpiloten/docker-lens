//! Six independent inner-memory pressure controls; private source only.
use super::*;
use crate::target::MemoryLimit;
use sha2::{Digest, Sha256};

const CONTRACT: &str = "memory-limits-v1";
const FILENAME: &str = "memory-limits-v1.json";
const FINITE: u64 = 67_108_864;
const WITNESS: u64 = 100_663_296;
const SMALL_BYTES: usize = 8192;
const FULL_BYTES: usize = 65_550 + 8192;
const CASES: [(&str, Option<u64>); 3] = [
    ("omitted", None),
    ("finite64", Some(FINITE)),
    ("zero", Some(0)),
];
const BARRIER: &str = r#"test "$$" = 1 || exit 61
set -eu; umask 077; d=/tmp/dl-memory
test ! -e "$d"; test ! -L "$d"; mkdir "$d"
released=0; trap 'released=1' USR1
(exec /bin/sh -c "$1" "$0-child") &
child=$!
while [ ! -f "$d/child-bound" ]; do :; done
IFS=' ' read -r child_token child_ready <"$d/child-ready"
test "$child_token" = "$0-child"; test "$child_ready" = "$child"
printf '%s %s\n' "$0" "$child" >"$d/ready.tmp"; mv "$d/ready.tmp" "$d/ready"
: >"$d/bound"
while [ "$released" = 0 ]; do :; done
trap '' USR1
kill -USR1 "$child"
set +e; wait "$child" 2>"$d/wait-error"; status=$?; set -e
trap 'exit "$status"' USR2
printf '%s %s %s\n' "$0" "$child" "$status" >"$d/status.tmp"
mv "$d/status.tmp" "$d/status"
: >"$d/held"
while :; do :; done"#;
const CHILD: &str = r#"test "$$" -gt 1 || exit 62
set -eu; umask 077
trap 'exec dd if=/dev/zero of=/dev/null bs=100663296 count=1' USR1
printf '%s %s\n' "$0" "$$" >/tmp/dl-memory/child-ready.tmp
mv /tmp/dl-memory/child-ready.tmp /tmp/dl-memory/child-ready
: >/tmp/dl-memory/child-bound
while :; do :; done"#;
const READY: &str = r#"set -eu; d=/tmp/dl-memory
test -f "$d/bound"; test ! -L "$d/bound"; test -f "$d/ready"; test ! -L "$d/ready"
IFS=' ' read -r token child <"$d/ready"; test "$token" = "$0"
printf 'ready %s %s\n' "$token" "$child"
readlink /proc/1/ns/pid; readlink /proc/1/ns/cgroup
awk '$2!="(sh)" || $22!~/^[1-9][0-9]*$/{exit 1}{print "parent_start",$22}' /proc/1/stat
awk '$2!="(sh)" || $22!~/^[1-9][0-9]*$/{exit 1}{print "child_start",$22}' /proc/"$child"/stat
awk '$1=="PPid:"{print "child_parent",$2}' /proc/"$child"/status
for pid in 1 "$child"; do
  awk '$1=="Uid:"{if(NF!=5)exit 1;print "uid",$2,$3,$4,$5;n++}END{if(n!=1)exit 1}' /proc/"$pid"/status
done
test /proc/"$child"/exe -ef /bin/sh
printf '%s\000' /bin/sh -c "$1" "$0-child" | cmp /proc/"$child"/cmdline -"#;
const COLLECT: &str = r#"set -eu; LC_ALL=C; export LC_ALL
mode=$1; api=$2; expected_ns=$3; parent_start=$4; daemon_pid=$5; saved_leaf=$6; child_inner=$7; child_start=$8; token=$9
test "$(id -u)" = 0; test "$(id -g)" = 0
safe() { case "$1" in *[!A-Za-z0-9_./:@+-]*|*//*|*/../*|*/./*|*/..|*/.) return 1;; esac; test "${#1}" -le 256; }
num() { awk 'NR!=1 || NF!=1 || $1 !~ /^(0|[1-9][0-9]*)$/ || length($1)>20 {exit 1} {v=$1} END{if(NR!=1)exit 1;print v}' "$1"; }
start() { awk 'NF>64 || $2!="(sh)" || $22 !~ /^[1-9][0-9]*$/ {exit 1} {print $22}' "$1/stat"; }
record() { awk -F: '$1=="0" && $2=="" {p=$3;n++} END{if(n!=1)exit 1;print p}' "$1/cgroup"; }
mounts=$(awk 'NF>64{exit 1}{for(i=7;i<=NF;i++)if($i=="-" && $(i+1)=="cgroup2"){print $1,$3,$4,$5;n++}}END{if(n!=1)exit 1}' /proc/self/mountinfo)
set -- $mounts; test "$#" = 4; mount_id=$1; device=$2; root=$3; mount=$4
test "$root" = /; safe "$mount"; test "$(readlink -f "$mount")" = "$mount"
reader_pidns=$(readlink /proc/self/ns/pid); reader_cgroupns=$(readlink /proc/self/ns/cgroup)
outer_cgroupns=$(readlink /proc/1/ns/cgroup); test "$reader_cgroupns" = "$outer_cgroupns"
outer_start=$(awk 'NF<=64 && $22 ~ /^[1-9][0-9]*$/ {print $22;ok=1}END{if(!ok)exit 1}' /proc/1/stat)
outer_membership=$(record /proc/1); safe "$outer_membership"
printf 'memory-source-v1\nreader %s %s\nmount 2 %s %s / %s\nkernel %s\n' "$reader_pidns" "$reader_cgroupns" "$mount_id" "$device" "$mount" "$(uname -r)"
printf 'outer / %s ' "$outer_start"; stat -c '%d %i' "$mount" | tr '\n' ' '; printf '%s %s\n' "$outer_membership" "$outer_cgroupns"
awk '$1=="SwapTotal:"{if(NF!=3 || $3!="kB" || $2!~/^(0|[1-9][0-9]*)$/)exit 1;print "swap",$2;n++}END{if(n!=1)exit 1}' /proc/meminfo
if [ "$mode" = baseline ]; then
  leaf=/; printf 'process baseline\nmembers baseline\n'
else
  parent=; child=; scanned=0
  for proc in /proc/[0-9]*; do
    scanned=$((scanned+1)); test "$scanned" -le 512
    ns=$(readlink "$proc/ns/pid" 2>/dev/null) || continue
    test "$ns" = "$expected_ns" || continue
    chain=$(awk '/^NSpid:/{if(NF<3 || NF>6)exit 1;print $(NF-1),$NF;n++}END{if(n!=1)exit 1}' "$proc/status") || continue
    if [ "$chain" = "$daemon_pid 1" ]; then test -z "$parent"; parent=$proc; fi
    inner=${chain##* }
    if [ "$inner" = "$child_inner" ]; then test -z "$child"; child=$proc; fi
  done
  test -n "$parent"; parent_pid=${parent##*/}; test "$(start "$parent")" = "$parent_start"
  cgroupns=$(readlink "$parent/ns/cgroup"); leaf=$(record "$parent"); safe "$leaf"; test "$leaf" != /
  if [ "$mode" = pre ]; then
    test -n "$child"; child_pid=${child##*/}; test "$(start "$child")" = "$child_start"
    test "$(record "$child")" = "$leaf"; test "$(readlink "$child/ns/cgroup")" = "$cgroupns"
    test "$(awk '/^PPid:/{print $2}' "$child/status")" = "$parent_pid"
    expected_members=$(printf '%s\n%s\n' "$parent_pid" "$child_pid" | sort -n)
    members=$(cat "$mount$leaf/cgroup.procs" | sort -n); test "$members" = "$expected_members"
    printf 'process %s %s %s %s %s %s %s %s\n' "$parent_pid" "$daemon_pid" "$parent_start" "$expected_ns" "$cgroupns" "$child_pid" "$child_inner" "$child_start"
    printf 'members %s %s\n' "$parent_pid" "$child_pid"
  else
    test "$mode" = post; test "$leaf" = "$saved_leaf"
    # Wait outside the workload: no observer can become an extra OOM victim.
    result=$parent/root/tmp/dl-memory/status
    for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
      if [ -f "$parent/root/tmp/dl-memory/held" ]; then break; fi; sleep 0.05
    done
    test -f "$parent/root/tmp/dl-memory/held"; test ! -L "$parent/root/tmp/dl-memory/held"; test -f "$result"; test ! -L "$result"; test ! -L "$parent/root/tmp/dl-memory/wait-error"; test "$(stat -c '%s' "$parent/root/tmp/dl-memory/wait-error")" -le 1024; test "$(stat -c '%a %h' "$result")" = '600 1'
    exec 4<"$result"; result_id=$(stat -L -c '%d %i' /proc/$$/fd/4)
    IFS=' ' read -r actual_token actual_child status <&4
    test "$actual_token" = "$token"; test "$actual_child" = "$child_inner"
    case "$status" in 0|137) :;; *) exit 1;; esac
    test "$(stat -c '%d %i' "$result")" = "$result_id"; exec 4<&-
    test "$(start "$parent")" = "$parent_start"
    members=$(cat "$mount$leaf/cgroup.procs"); test "$members" = "$parent_pid"
    printf 'process %s %s %s %s %s child_done %s %s\n' "$parent_pid" "$daemon_pid" "$parent_start" "$expected_ns" "$cgroupns" "$child_inner" "$status"
    printf 'members %s\n' "$parent_pid"
  fi
fi
printf 'leaf %s\n' "$leaf"
path=$leaf; count=0
while :; do
  count=$((count+1)); test "$count" -le 8
  dir=$mount$path; if [ "$path" = / ]; then dir=$mount; fi
  test "$(readlink -f "$dir")" = "$dir"; test ! -L "$dir"
  exec 3<"$dir"; held=/proc/$$/fd/3; identity=$(stat -L -c '%d %i' "$held")
  test "$(cat "$held/cgroup.type")" = domain
  IFS= read -r limit <"$held/memory.max"; usage=$(num "$held/memory.current"); group=$(num "$held/memory.oom.group")
  counters=$(awk 'NF!=2 || $2!~/^(0|[1-9][0-9]*)$/ || length($2)>20 || seen[$1]++{exit 1} $1=="oom"{o=$2;n++} $1=="oom_kill"{k=$2;n++} $1=="max"{m=$2;n++} $1!~/^(low|high|max|oom|oom_kill|oom_group_kill)$/{exit 1}END{if(n!=3)exit 1;print o,k,m}' "$held/memory.events.local")
  test "$(stat -c '%d %i' "$dir")" = "$identity"
  printf 'node %s %s %s %s %s %s v2_events_local\n' "$path" "$identity" "$limit" "$usage" "$counters" "$group"
  exec 3<&-
  test "$path" != / || break; path=${path%/*}; test -n "$path" || path=/
done
if [ "$mode" != baseline ]; then
  test "$(readlink "$parent/ns/pid")" = "$expected_ns"; test "$(start "$parent")" = "$parent_start"; test "$(record "$parent")" = "$leaf"
fi
printf 'clock '; DOCKER_API_VERSION="$api" docker -H unix:///dockerlens-native/docker.sock info --format '{{.SystemTime}}'"#;
const PROJECTION: &str = r#"{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"config_image":{{json .Config.Image}},"owner":{{json (index .Config.Labels "io.dockerlens.native-run")}},"cmd":{{json .Config.Cmd}},"entrypoint":{{json .Config.Entrypoint}},"user":{{json .Config.User}},"init":{{json .HostConfig.Init}},"memory":{{json .HostConfig.Memory}},"memory_swap":{{json .HostConfig.MemorySwap}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"started_at":{{json .State.StartedAt}},"finished_at":{{json .State.FinishedAt}},"oom":{{json .State.OOMKilled}},"exit":{{json .State.ExitCode}},"status":{{json .State.Status}},"restarts":{{json .RestartCount}},"error":{{json .State.Error}},"restarting":{{json .State.Restarting}},"paused":{{json .State.Paused}},"dead":{{json .State.Dead}},"privileged":{{json .HostConfig.Privileged}},"cap_add":{{json .HostConfig.CapAdd}},"cap_drop":{{json .HostConfig.CapDrop}},"mounts":{{json .Mounts}}}"#;
const EVENT: &str = r#"{"type":{{json .Type}},"action":{{json .Action}},"id":{{json .Actor.ID}},"owner":{{json (index .Actor.Attributes "io.dockerlens.native-run")}},"time_nano":{{json .TimeNano}}}"#;

#[derive(Default)]
struct SmallMeter {
    calls: Cell<usize>,
    bytes: Cell<usize>,
}
fn small<T>(run: &HealthRun, meter: &SmallMeter, action: impl FnOnce() -> T) -> T {
    let calls = run.calls.get();
    let bytes = run.bytes.get();
    let result = action();
    let captured = run.bytes.get().checked_sub(bytes).unwrap();
    assert!(
        run.calls.get() == calls + 1 && captured <= SMALL_BYTES,
        "closed memory small capture allowance"
    );
    meter.calls.set(meter.calls.get() + 1);
    meter.bytes.set(meter.bytes.get() + captured);
    result
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn packet(bytes: &[u8]) -> Value {
    assert!(bytes.len() <= 4096, "bounded memory report");
    let text = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("memory report UTF8"));
    assert!(text.ends_with('\n'), "complete memory report");
    json!({"raw":text,"sha256":hash(bytes)})
}
fn num(text: &str) -> u64 {
    assert!(
        !text.is_empty()
            && (text == "0" || !text.starts_with('0'))
            && text.bytes().all(|b| b.is_ascii_digit()),
        "canonical memory integer"
    );
    text.parse()
        .unwrap_or_else(|_| panic!("bounded memory integer"))
}
fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 256
        && !path.contains("//")
        && !path.split('/').any(|p| matches!(p, "." | ".."))
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:@+-".contains(&b))
}
fn namespace(text: &str, kind: &str) -> bool {
    text.strip_prefix(kind)
        .and_then(|s| s.strip_prefix(":["))
        .and_then(|s| s.strip_suffix(']'))
        .is_some_and(|s| num(s) > 0)
}
fn parent(path: &str) -> &str {
    path.rsplit_once('/')
        .map(|(p, _)| if p.is_empty() { "/" } else { p })
        .unwrap()
}
fn parse_sample(report: &Value, mode: &str) -> Value {
    let lines: Vec<Vec<&str>> = report["raw"]
        .as_str()
        .unwrap()
        .lines()
        .map(|s| s.split(' ').collect())
        .collect();
    assert!(
        (11..=18).contains(&lines.len()) && lines[0] == ["memory-source-v1"],
        "closed v2 memory grammar"
    );
    for (i, key) in [
        "reader", "mount", "kernel", "outer", "swap", "process", "members", "leaf",
    ]
    .iter()
    .enumerate()
    {
        assert!(lines[i + 1][0] == *key, "ordered v2 memory fields");
    }
    assert!(
        lines[1].len() == 3 && namespace(lines[1][1], "pid") && namespace(lines[1][2], "cgroup"),
        "actual reader namespaces"
    );
    assert!(
        lines[2].len() == 6
            && lines[2][1] == "2"
            && num(lines[2][2]) > 0
            && lines[2][4] == "/"
            && safe_path(lines[2][5]),
        "private guest cgroup2 root mount"
    );
    assert!(
        lines[3].len() == 2
            && lines[3][1].len() <= 128
            && lines[3][1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)),
        "observed kernel release"
    );
    assert!(
        lines[4].len() == 7
            && lines[4][1] == "/"
            && num(lines[4][2]) > 0
            && num(lines[4][4]) > 0
            && safe_path(lines[4][5])
            && lines[4][6] == lines[1][2],
        "bound private root object distinct from PID1 current membership"
    );
    num(lines[4][3]);
    assert!(lines[5] == ["swap", "0"], "actual global SwapTotal zero");
    if mode == "baseline" {
        assert!(
            lines[6] == ["process", "baseline"] && lines[7] == ["members", "baseline"],
            "baseline phase"
        );
    } else {
        assert!(
            lines[6].len() == 9
                && num(lines[6][1]) > 0
                && num(lines[6][2]) > 0
                && num(lines[6][3]) > 0
                && namespace(lines[6][4], "pid")
                && namespace(lines[6][5], "cgroup")
                && lines[6][4] != lines[1][1],
            "bound supervisor PID/start/namespaces"
        );
        if mode == "pre" {
            assert!(
                num(lines[6][6]) > 0
                    && num(lines[6][7]) > 1
                    && num(lines[6][8]) > 0
                    && lines[6][1] != lines[6][6]
                    && lines[7] == ["members", lines[6][1], lines[6][6]],
                "two independently bound members before allocation"
            );
        } else {
            assert!(
                mode == "post"
                    && lines[6][6] == "child_done"
                    && num(lines[6][7]) > 1
                    && matches!(lines[6][8], "0" | "137")
                    && lines[7] == ["members", lines[6][1]],
                "surviving parent after real child wait; no extra member"
            );
        }
    }
    assert!(
        lines[8].len() == 2 && safe_path(lines[8][1]),
        "closed visible memory leaf"
    );
    let leaf = lines[8][1];
    let mut expected = leaf;
    let mut nodes = Vec::new();
    for row in &lines[9..lines.len() - 1] {
        assert!(
            row.len() == 11
                && row[0] == "node"
                && row[1] == expected
                && safe_path(row[1])
                && num(row[3]) > 0
                && row[10] == "v2_events_local",
            "live held v2 memory node, never synthetic gone/root row"
        );
        let dev = num(row[2]);
        let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
        let minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
        assert!(
            lines[2][3] == format!("{major}:{minor}"),
            "node belongs to bound cgroup mount"
        );
        if row[4] != "max" {
            assert!(num(row[4]) > 0);
        }
        for n in &row[5..10] {
            num(n);
        }
        assert!(matches!(row[9], "0" | "1"), "observed OOM group mode");
        nodes.push(json!({"path":row[1],"id":[row[2],row[3]],"raw_limit":row[4],"limit":if row[4]=="max"{Value::Null}else{json!(num(row[4]))},"usage":num(row[5]),"oom":num(row[6]),"kill":num(row[7]),"maximum":num(row[8]),"group":num(row[9]),"scope":row[10]}));
        expected = parent(expected);
    }
    assert!(
        (1..=8).contains(&nodes.len())
            && nodes.last().unwrap()["path"] == "/"
            && nodes.last().unwrap()["id"] == json!([lines[4][3], lines[4][4]])
            && nodes.last().unwrap()["limit"] == 4294967296_u64,
        "actual bound private root has its real finite limit"
    );
    assert!(
        mode == "baseline" || nodes.len() >= 2,
        "workload is a descendant of owned private root"
    );
    let clock = lines.last().unwrap();
    assert!(
        clock.len() == 2 && clock[0] == "clock",
        "actual native sample clock"
    );
    let native = timestamp_ns(clock[1]).unwrap();
    json!({"version":"2","reader":lines[1][1..],"mount":lines[2][1..],"kernel":lines[3][1],"outer":lines[4][1..],"process":lines[6][1..],"members":lines[7][1..],"leaf":leaf,"nodes":nodes,"clock":u64::try_from(native).unwrap(),"clock_text":clock[1]})
}
fn ancestry(nodes: &[Value]) -> Value {
    json!(
        nodes
            .iter()
            .map(|n| json!([n["path"], n["id"], n["raw_limit"], n["scope"]]))
            .collect::<Vec<_>>()
    )
}
fn bracket(native: u64, begin: u64, end: u64, elapsed: u64) {
    assert!(
        end >= begin
            && end - begin <= 8_000_000_000
            && elapsed <= 8_000_000_000
            && (end - begin).abs_diff(elapsed) <= 50_000_000
            && native >= begin.saturating_sub(250_000_000)
            && native <= end + 250_000_000,
        "bounded native clock bracket without renewed timer"
    );
}
fn observe(run: &HealthRun, meter: &SmallMeter, mode: &str, identity: [&str; 7]) -> (Value, Value) {
    let [ns, start, pid, leaf, child, child_start, token] = identity;
    let begin = utc_ns();
    let monotonic = Instant::now();
    let bytes = small(run, meter, || {
        let elevated = match required("NATIVE_PODMAN_USE_SUDO").as_str() {
            "0" => false,
            "1" => true,
            _ => panic!("closed memory privilege selector"),
        };
        let mut command = run.timer(false, elevated);
        command.args(crate::native_outer_test_command::prefix());
        command.args([
            "exec",
            "--user",
            "0:0",
            &required("NATIVE_OUTER_CONTAINER_ID"),
            "sh",
            "-c",
            COLLECT,
            "dl-memory-observe",
            mode,
            &run.api,
            ns,
            start,
            pid,
            leaf,
            child,
            child_start,
            token,
        ]);
        run.capture(&mut command, None, false)
    });
    let end = utc_ns();
    let elapsed = u64::try_from(monotonic.elapsed().as_nanos()).unwrap();
    let report = packet(&bytes);
    let parsed = parse_sample(&report, mode);
    bracket(parsed["clock"].as_u64().unwrap(), begin, end, elapsed);
    (
        json!({"report":report,"clock_bracket":[begin,end,elapsed]}),
        parsed,
    )
}
fn event_clock(run: &HealthRun, meter: &SmallMeter) -> Value {
    let begin = utc_ns();
    let monotonic = Instant::now();
    let bytes = small(run, meter, || {
        docker(
            run,
            &["info".into(), "--format".into(), "{{.SystemTime}}".into()],
        )
    });
    let end = utc_ns();
    let elapsed = u64::try_from(monotonic.elapsed().as_nanos()).unwrap();
    let text = std::str::from_utf8(&bytes)
        .unwrap()
        .strip_suffix('\n')
        .unwrap();
    let native = u64::try_from(timestamp_ns(text).unwrap()).unwrap();
    bracket(native, begin, end, elapsed);
    json!({"time":text,"bracket":[begin,end,elapsed]})
}
fn projection(run: &HealthRun, meter: Option<&SmallMeter>, key: &str, cleanup: bool) -> Value {
    let action = || {
        let args = [
            "inspect".into(),
            "--format".into(),
            PROJECTION.into(),
            key.into(),
        ];
        if cleanup {
            let mut c = vec![
                "env".into(),
                format!("DOCKER_API_VERSION={}", run.api),
                "docker".into(),
                "-H".into(),
                "unix:///dockerlens-native/docker.sock".into(),
            ];
            c.extend(args);
            run.outer(&c, true)
        } else {
            docker(run, &args)
        }
    };
    let bytes = if let Some(meter) = meter {
        small(run, meter, action)
    } else {
        action()
    };
    assert!(bytes.len() <= 4096, "small exact memory inspect projection");
    serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("closed memory inspect JSON"))
}
fn check_config(run: &HealthRun, index: usize, image: &Value, v: &Value) {
    let memory = CASES[index / 2].1.unwrap_or(0);
    assert!(
        v["id"] == run.ids[index].as_ref().unwrap().as_str()
            && v["name"] == format!("/{}", run.names[index])
            && v["image"] == image["id"]
            && v["config_image"] == run.base
            && v["owner"] == run.run
            && v["cmd"] == json!(["sh", "-c", BARRIER, run.names[index], CHILD])
            && (v["entrypoint"].is_null() || v["entrypoint"] == json!([]))
            && matches!(v["user"].as_str(), Some("" | "0" | "0:0"))
            && (v["init"].is_null() || v["init"] == false)
            && v["memory"] == memory
            && v["memory_swap"].as_i64().is_some_and(|n| n >= -1)
            && v["restarts"] == 0
            && v["error"] == ""
            && v["restarting"] == false
            && v["paused"] == false
            && v["dead"] == false
            && v["privileged"] == false
            && (v["cap_add"].is_null() || v["cap_add"] == json!([]))
            && (v["cap_drop"].is_null() || v["cap_drop"] == json!([]))
            && v["mounts"] == json!([]),
        "owned exact memory config, empty entrypoint/init and no extra resource controls"
    );
}
fn authored(run: &HealthRun, index: usize) -> Value {
    let memory = CASES[index / 2].1;
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
            ["sh", "-c", BARRIER, run.names[index].as_str(), CHILD]
                .map(|v| Argument::new(v.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                    .unwrap(),
            ],
            memory_limit: memory.map(|n| {
                if n == 0 {
                    MemoryLimit::Unlimited
                } else {
                    MemoryLimit::Bytes(NonZeroU64::new(n).unwrap())
                }
            }),
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
    let mut body = json!({"Image":run.base,"Cmd":["sh","-c",BARRIER,run.names[index],CHILD],"Labels":{(OWNER):run.run}});
    if let Some(memory) = memory {
        body["HostConfig"] = json!({"Memory":memory});
    }
    assert!(
        request
            == json!({"method":"POST","path":format!("/v{}/containers/create?name={}",run.api,run.names[index]),"body":body}),
        "independent complete omitted/finite/zero memory request; no MemorySwap"
    );
    request
}
fn create_memory(run: &mut HealthRun, meter: &SmallMeter, index: usize, image: &Value) {
    assert!(
        small(run, meter, || run.inspect(&run.names[index], false)).0 == 404,
        "fresh memory fixture name"
    );
    let request = if index % 2 == 1 {
        Some(authored(run, index))
    } else {
        None
    };
    run.attempted[index] = true;
    let id = if let Some(request) = request {
        let (status, v) = small(run, meter, || {
            run.api(
                "POST",
                request["path"].as_str().unwrap(),
                Some(&request["body"]),
                false,
            )
        });
        assert!(
            status == 201 && (v["Warnings"].is_null() || v["Warnings"] == json!([])),
            "known memory API create"
        );
        v["Id"].as_str().unwrap().to_owned()
    } else {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
        ];
        if let Some(memory) = CASES[index / 2].1 {
            args.extend(["--memory".into(), memory.to_string()]);
        }
        args.extend([
            run.base.clone(),
            "sh".into(),
            "-c".into(),
            BARRIER.into(),
            run.names[index].clone(),
            CHILD.into(),
        ]);
        let bytes = small(run, meter, || docker(run, &args));
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed memory CLI ID"))
            .to_owned()
    };
    assert!(
        identifier(&id)
            && id != required("NATIVE_OUTER_CONTAINER_ID")
            && run.ids.iter().flatten().all(|other| other != &id),
        "unique canonical memory create ID"
    );
    // Store a known ID before readback; an unverified ID still stays uncertain.
    run.ids[index] = Some(id.clone());
    let v = projection(run, Some(meter), &run.names[index], false);
    check_config(run, index, image, &v);
    assert!(
        v["status"] == "created"
            && v["pid"] == 0
            && v["running"] == false
            && v["oom"] == false
            && v["exit"] == 0
            && v["started_at"] == "0001-01-01T00:00:00Z"
            && v["finished_at"] == "0001-01-01T00:00:00Z",
        "never-started memory fixture"
    );
}
fn compare_samples(
    pre: &Value,
    post: &Value,
    baseline: &Value,
    memory: Option<u64>,
    common: &mut Option<Value>,
) -> Value {
    for sample in [pre, post] {
        for field in ["version", "reader", "mount", "kernel", "outer"] {
            assert!(
                sample[field] == baseline[field],
                "same authenticated visible guest-root memory context"
            );
        }
    }
    assert!(
        pre["leaf"] != "/"
            && post["leaf"] == pre["leaf"]
            && pre["process"].as_array().unwrap()[..5] == post["process"].as_array().unwrap()[..5],
        "stable live parent and workload leaf"
    );
    let a = pre["nodes"].as_array().unwrap();
    let b = post["nodes"].as_array().unwrap();
    assert!(
        ancestry(a) == ancestry(b),
        "same live leaf and complete visible ancestor identities/limits"
    );
    let chain = ancestry(&a[1..]);
    if let Some(expected) = common.as_ref() {
        assert!(
            &chain == expected,
            "same visible inherited context for six controls"
        );
    } else {
        *common = Some(chain);
    }
    for (before, after) in a[1..].iter().zip(&b[1..]) {
        for k in ["oom", "kill", "maximum"] {
            assert!(
                before[k] == after[k],
                "no observed visible ancestor-local pressure/victim/reset"
            );
        }
    }
    assert!(
        a[0]["group"] == 0 && b[0]["group"] == 0,
        "actual memory.oom.group zero, never authored"
    );
    for k in ["oom", "kill", "maximum"] {
        if memory == Some(FINITE) {
            assert!(
                if k == "kill" {
                    a[0][k].as_u64().unwrap().checked_add(1) == b[0][k].as_u64()
                } else {
                    b[0][k].as_u64().unwrap() > a[0][k].as_u64().unwrap()
                },
                "real leaf-local pressure and exactly one bound child victim"
            );
        } else {
            assert!(
                a[0][k] == b[0][k],
                "positive controls have no local pressure or victims"
            );
        }
    }
    json!([
        a[0]["raw_limit"],
        a[1..].iter().filter_map(|n| n["limit"].as_u64()).min()
    ])
}
fn pressure_preconditions(sample: &Value, memory: Option<u64>) {
    let rows = sample["nodes"].as_array().unwrap();
    assert!(rows[0]["group"] == 0, "no group OOM; no protective writes");
    assert!(
        rows[0]["limit"]
            == if memory == Some(FINITE) {
                json!(FINITE)
            } else {
                Value::Null
            },
        "actual authored finite kernel limit or observed local unbounded form"
    );
    for row in &rows[1..] {
        if let Some(limit) = row["limit"].as_u64() {
            assert!(
                limit
                    .checked_sub(row["usage"].as_u64().unwrap())
                    .is_some_and(|available| available >= WITNESS),
                "sampled strict ancestor available headroom for the actual witness"
            );
        }
    }
}
fn cleanup_memory(run: &mut HealthRun, image: &Value, uncertain: &[bool]) -> CleanupDisposition {
    if uncertain.iter().any(|v| *v)
        || run
            .attempted
            .iter()
            .zip(&run.ids)
            .any(|(a, id)| *a && !id.as_deref().is_some_and(identifier))
    {
        return CleanupDisposition::OuterTeardownRequired;
    }
    let mut verified = true;
    for index in 0..6 {
        if run.attempted[index] {
            verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let id = run.ids[index].as_ref().unwrap().clone();
                let v = projection(run, None, &id, true);
                check_config(run, index, image, &v);
                let args = [
                    "env".into(),
                    format!("DOCKER_API_VERSION={}", run.api),
                    "docker".into(),
                    "-H".into(),
                    "unix:///dockerlens-native/docker.sock".into(),
                    "rm".into(),
                    "--force".into(),
                    id.clone(),
                ];
                run.outer(&args, true) == format!("{id}\n").as_bytes()
            }))
            .unwrap_or(false);
        }
    }
    for _ in 0..2 {
        for index in 0..6 {
            if run.attempted[index] {
                verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run.inspect(run.ids[index].as_ref().unwrap(), true).0 == 404
                        && run.inspect(&run.names[index], true).0 == 404
                }))
                .unwrap_or(false);
            }
        }
    }
    cleanup_disposition(verified)
}

#[test]
fn memory_supervisor_wait_is_not_interrupted_by_its_release_signal() {
    assert!(
        BARRIER.find("trap '' USR1").unwrap() < BARRIER.find("wait \"$child\"").unwrap()
            && BARRIER.find("trap 'exit").unwrap() < BARRIER.find("status.tmp").unwrap(),
        "two barriers prevent wait/publication races"
    );
    assert!(
        CHILD.contains("trap 'exec dd if=/dev/zero of=/dev/null bs=100663296 count=1' USR1")
            && !CHILD.contains("sleep"),
        "one exact bound allocator child"
    );
}

#[test]
#[ignore = "requires exact isolated lane, actual live memory pressure and child victim evidence"]
fn live_memory_limits_and_effects_match_engine() {
    let backend = source_outer_backend();
    let started = Instant::now();
    let target = ProofTarget::new_for("NATIVE_MEMORY_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_MEMORY_CANDIDATE_SHA",
        "NATIVE_MEMORY_DEADLINE_EPOCH",
    );
    run.names = CASES
        .iter()
        .flat_map(|(case, _)| {
            ["oracle", "rendered"].map(|role| format!("dl-memory-{}-{case}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 6];
    run.attempted = vec![false; 6];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let meter = SmallMeter::default();
    let mut uncertain = vec![false; 6];
    let mut borrowed = Value::Null;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: memory_context");
        let uid = run.context();
        let image = image_snapshot(&run);
        borrowed = image.clone();
        assert!(
            (image["config"]["Volumes"].is_null() || image["config"]["Volumes"] == json!({}))
                && (image["config"]["Entrypoint"].is_null()
                    || image["config"]["Entrypoint"] == json!([]))
                && matches!(image["config"]["User"].as_str(), Some("" | "0" | "0:0")),
            "borrowed image has no wrapper or altered UID"
        );
        let (outer_projection, raw_outer) = outer_context_observation(&run, false);
        assert!(
            outer_projection == owner.snapshot
                && raw_outer["HostConfig"]["CgroupnsMode"] == "private"
                && matches!(
                    raw_outer["HostConfig"]["PidMode"].as_str(),
                    Some("" | "private")
                )
                && raw_outer["State"]["Pid"].as_u64().is_some_and(|p| p > 0)
                && raw_outer["RestartCount"] == 0,
            "authenticated private outer namespace root"
        );
        let outer_source = json!({"id":required("NATIVE_OUTER_CONTAINER_ID"),"pid":raw_outer["State"]["Pid"],"started_at":raw_outer["State"]["StartedAt"],"cgroupns":"private","pid_mode":raw_outer["HostConfig"]["PidMode"],"restarts":0});
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::MemoryLimit,
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
                == (if run.lane.starts_with("debian11-") {
                    10
                } else {
                    9
                }) + 2 * backend.snapshot_extra_calls(),
            "closed memory context with separate raw-outer readback"
        );
        let pending = 91 * SMALL_BYTES + 3 * FULL_BYTES + backend.snapshot_extra_bytes();
        assert!(
            run.bytes
                .get()
                .checked_add(pending)
                .is_some_and(|n| n <= MAX_BYTES - CLEANUP_BYTES)
                && context_calls + 94 + backend.snapshot_extra_calls() <= MAX_CALLS - CLEANUP_CALLS
                && 36 * (8192 + 2048) <= CLEANUP_BYTES,
            "all memory barriers, small reads, final snapshots and cleanup reserved before mutation"
        );
        let (baseline_packet, baseline) = observe(
            &run,
            &meter,
            "baseline",
            ["-", "0", "0", "/", "0", "0", "baseline"],
        );
        let mut records = Vec::new();
        let mut common = None;
        let mut unbounded = None;
        eprintln!("DOCKERLENS_NATIVE_CHECK: memory_effects");
        for index in 0..6 {
            let before = run.calls.get();
            uncertain[index] = true;
            create_memory(&mut run, &meter, index, &image);
            let id = run.ids[index].as_ref().unwrap().clone();
            if index % 2 == 0 {
                assert!(
                    small(&run, &meter, || docker(&run, &["start".into(), id.clone()]))
                        == format!("{id}\n").as_bytes(),
                    "owned CLI start"
                );
            } else {
                assert!(
                    small(&run, &meter, || run.api(
                        "POST",
                        &format!("/v{}/containers/{id}/start", run.api),
                        None,
                        false
                    ))
                    .0 == 204,
                    "owned API start"
                );
            }
            let ready_bytes = small(&run, &meter, || {
                docker(
                    &run,
                    &[
                        "exec".into(),
                        "--user".into(),
                        "0:0".into(),
                        id.clone(),
                        "sh".into(),
                        "-c".into(),
                        READY.into(),
                        run.names[index].clone(),
                        CHILD.into(),
                    ],
                )
            });
            let readiness = packet(&ready_bytes);
            let ready: Vec<_> = readiness["raw"].as_str().unwrap().lines().collect();
            assert!(
                ready.len() == 8
                    && ready[0].starts_with(&format!("ready {} ", run.names[index]))
                    && namespace(ready[1], "pid")
                    && namespace(ready[2], "cgroup")
                    && ready[5] == "child_parent 1"
                    && ready[6] == "uid 0 0 0 0"
                    && ready[7] == "uid 0 0 0 0",
                "completed temporary readiness observer binds both root processes"
            );
            let child = ready[0].rsplit(' ').next().unwrap();
            assert!(num(child) > 1);
            let parent_start = ready[3].strip_prefix("parent_start ").unwrap();
            let child_start = ready[4].strip_prefix("child_start ").unwrap();
            assert!(num(parent_start) > 0 && num(child_start) > 0);
            let running = projection(&run, Some(&meter), &id, false);
            check_config(&run, index, &image, &running);
            assert!(
                running["running"] == true
                    && running["status"] == "running"
                    && running["pid"].as_u64().is_some_and(|p| p > 0)
                    && running["oom"] == false
                    && running["exit"] == 0,
                "actual live supervisor before pressure"
            );
            let daemon_pid = running["pid"].to_string();
            let name = run.names[index].clone();
            let args = [
                ready[1],
                parent_start,
                daemon_pid.as_str(),
                "/",
                child,
                child_start,
                name.as_str(),
            ];
            let (pre_packet, pre) = observe(&run, &meter, "pre", args);
            assert!(
                pre["process"][1] == daemon_pid
                    && pre["process"][2] == parent_start
                    && pre["process"][3] == ready[1]
                    && pre["process"][4] == ready[2]
                    && pre["process"][6] == child
                    && pre["process"][7] == child_start,
                "actual parent/child identities match readiness and exact two-member group"
            );
            let memory = CASES[index / 2].1;
            pressure_preconditions(&pre, memory);
            assert!(
                small(&run, &meter, || docker(
                    &run,
                    &["kill".into(), "--signal".into(), "USR1".into(), id.clone()]
                )) == format!("{id}\n").as_bytes(),
                "release allocation once outside workload"
            );
            let (post_packet, post) = observe(
                &run,
                &meter,
                "post",
                [
                    ready[1],
                    parent_start,
                    &daemon_pid,
                    pre["leaf"].as_str().unwrap(),
                    child,
                    child_start,
                    &name,
                ],
            );
            let expected = if memory == Some(FINITE) { 137 } else { 0 };
            assert!(
                post["process"][5] == "child_done"
                    && post["process"][6] == child
                    && post["process"][7].as_str()
                        == Some(if memory == Some(FINITE) { "137" } else { "0" }),
                "real child wait, not interrupted or propagated parent status"
            );
            let form = compare_samples(&pre, &post, &baseline, memory, &mut common);
            if memory != Some(FINITE) {
                if let Some(expected) = &unbounded {
                    assert!(
                        &form == expected,
                        "omitted and zero agree on observed local and visible inherited limits"
                    );
                } else {
                    unbounded = Some(form);
                }
            }
            let bytes = small(&run, &meter, || {
                run.outer(
                    &[
                        "sh".into(),
                        "-c".into(),
                        "exec \"$@\" 2>&1".into(),
                        "dl-memory-logs".into(),
                        "env".into(),
                        format!("DOCKER_API_VERSION={}", run.api),
                        "docker".into(),
                        "-H".into(),
                        "unix:///dockerlens-native/docker.sock".into(),
                        "logs".into(),
                        id.clone(),
                    ],
                    false,
                )
            });
            let logs = String::from_utf8(bytes).unwrap();
            if memory == Some(FINITE) {
                assert!(
                    logs.is_empty(),
                    "actual killed child cannot report full allocation"
                );
            } else {
                let l: Vec<_> = logs.lines().collect();
                assert!(
                    (2..=3).contains(&l.len())
                        && logs.ends_with('\n')
                        && l[0] == "1+0 records in"
                        && l[1] == "1+0 records out"
                        && (l.len() == 2 || l[2].starts_with("100663296 bytes ")),
                    "one full96MiB record, not exit0 alone"
                );
            }
            let event_clock = event_clock(&run, &meter);
            let until = event_clock["time"].as_str().unwrap();
            let until_ns = u64::try_from(timestamp_ns(until).unwrap()).unwrap();
            let bytes = small(&run, &meter, || {
                docker(
                    &run,
                    &[
                        "events".into(),
                        "--since".into(),
                        pre["clock_text"].as_str().unwrap().into(),
                        "--until".into(),
                        until.into(),
                        "--filter".into(),
                        "type=container".into(),
                        "--filter".into(),
                        format!("container={id}"),
                        "--filter".into(),
                        "event=oom".into(),
                        "--format".into(),
                        EVENT.into(),
                    ],
                )
            });
            let events = String::from_utf8(bytes).unwrap();
            let parsed: Vec<Value> = events
                .lines()
                .map(|line| {
                    serde_json::from_str(line)
                        .unwrap_or_else(|_| panic!("private OOM event projection"))
                })
                .collect();
            assert!(
                parsed.len() == usize::from(memory == Some(FINITE)),
                "actual processed OOM event before parent release"
            );
            for event in parsed {
                assert!(
                    event["type"] == "container"
                        && event["action"] == "oom"
                        && event["id"] == id
                        && event["owner"] == run.run
                        && event["time_nano"]
                            .as_u64()
                            .is_some_and(|t| t >= pre["clock"].as_u64().unwrap() && t <= until_ns),
                    "same-daemon owned-ID actual OOM event in fixed sampled window"
                );
            }
            assert!(
                small(&run, &meter, || docker(
                    &run,
                    &["kill".into(), "--signal".into(), "USR2".into(), id.clone()]
                )) == format!("{id}\n").as_bytes(),
                "release supervisor only after genuine live counter and event readback"
            );
            assert!(
                small(&run, &meter, || docker(&run, &["wait".into(), id.clone()]))
                    == format!("{expected}\n").as_bytes(),
                "actual supervisor propagated child status"
            );
            let terminal = projection(&run, Some(&meter), &id, false);
            check_config(&run, index, &image, &terminal);
            assert!(
                terminal["running"] == false
                    && terminal["status"] == "exited"
                    && terminal["pid"] == 0
                    && terminal["exit"] == expected
                    && terminal["oom"] == (memory == Some(FINITE))
                    && terminal["started_at"] == running["started_at"],
                "actual final Engine OOM flag and propagated terminal state"
            );
            assert!(
                run.calls.get() - before == 15,
                "exact two-barrier memory slot schedule"
            );
            uncertain[index] = false;
            records.push(json!({"role":if index%2==0{"oracle"}else{"rendered"},"id":id,"name":name,"owner":run.run,"wire":if index%2==0{"independent_cli"}else{"literal_rendered"},"memory":memory,"running":running,"terminal":terminal,"readiness":readiness,"before":pre_packet,"after":post_packet,"child_wait_exit":expected,"parent_wait_exit":expected,"parent_exit_kind":"supervisor_propagated_child_status","logs":logs,"events":events,"event_clock":event_clock,"pid_continuity":"child_exec_semantics_not_post_exec_sampled","cleanup":"absent"}));
        }
        assert!(
            meter.calls.get() == 91 && meter.bytes.get() <= 91 * SMALL_BYTES,
            "actual two-barrier small capture accounting"
        );
        assert!(
            run.api("GET", "/version", None, false).1["Version"] == run.engine,
            "final daemon health"
        );
        assert!(
            backend.final_snapshot_room(run.calls.get(), run.bytes.get(), 2),
            "final ordinary snapshot reserve"
        );
        let cases: Vec<_> = CASES
            .iter()
            .enumerate()
            .map(|(i, (name, _))| json!({"case":name,"containers":[records[2*i],records[2*i+1]]}))
            .collect();
        (
            uid,
            image,
            outer_source,
            baseline_packet,
            cases,
            context_calls,
        )
    }));
    let work_elapsed = started.elapsed();
    let before_calls = run.calls.get();
    let before_bytes = run.bytes.get();
    let cleanup_started = Instant::now();
    eprintln!("DOCKERLENS_NATIVE_CHECK: memory_cleanup");
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cleanup_memory(&mut run, &borrowed, &uncertain)
    }))
    .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_calls = run.calls.get() - before_calls;
    let cleanup_bytes = run.bytes.get() - before_bytes;
    terminal_cleanup(&mut run, &owner, disposition);
    let (uid, image, outer_source, baseline, cases, context_calls) =
        require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none() && image_snapshot(&run) == image,
        "borrowed image never removed or altered"
    );
    let outer = outer_context(&run);
    assert!(outer == owner.snapshot, "same authenticated outer");
    let ordinary_calls = run.calls.get() - cleanup_calls;
    let ordinary_bytes = run.bytes.get() - cleanup_bytes;
    let ordinary_elapsed = started.elapsed().saturating_sub(cleanup_elapsed);
    assert!(
        ordinary_calls == context_calls + 94 + backend.snapshot_extra_calls()
            && ordinary_bytes <= MAX_BYTES - CLEANUP_BYTES
            && cleanup_calls == 36
            && cleanup_bytes <= 368640,
        "all actual memory calls/bytes and cleanup accounted"
    );
    assert!(
        work_elapsed <= Duration::from_secs(134)
            && ordinary_elapsed <= Duration::from_secs(134)
            && cleanup_elapsed <= Duration::from_secs(46)
            && started.elapsed() <= Duration::from_secs(180),
        "original absolute deadline and46second reserve"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"capability_admission":[],"catalogue_admission":false,"scope":"observed_local_pressure_and_bound_child_victim","hidden_ancestry":"unobserved_above_private_guest_root","outer_source":outer_source,"outer_backend":if matches!(backend,SourceOuterBackend::Docker){"docker"}else{"podman"},"context":{"candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,"rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-"){"1.41"}else{"1.49"},"mode":if run.mode==DaemonMode::Rootless{"rootless"}else{"rootful"},"docker_package":if run.lane.starts_with("debian11-"){"20.10.5+dfsg1-1+deb11u2"}else{""},"fixture_image":run.base,"daemon_uid":uid,"outer":outer},"borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"baseline":baseline,"cases":cases,"daemon_health":"version_matches_after_controls","accounting":{"context_calls":context_calls,"baseline_calls":1,"slot_calls":[15,15,15,15,15,15],"daemon_health_calls":1,"final_readback_calls":2+backend.snapshot_extra_calls(),"ordinary_calls":ordinary_calls,"ordinary_bytes":ordinary_bytes,"small_calls":meter.calls.get(),"small_bytes":meter.bytes.get(),"cleanup_calls":cleanup_calls,"cleanup_bytes":cleanup_bytes,"deadline_seconds":180,"cleanup_reserve_seconds":46,"ordinary_elapsed_ns":ordinary_elapsed.as_nanos(),"cleanup_elapsed_ns":cleanup_elapsed.as_nanos(),"elapsed_ns":started.elapsed().as_nanos(),"initial_context_acquisition":{"max_requests":16,"max_total_bytes":2097152,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"}},"cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: memory_proof");
    target.publish_bounded(&proof, 65536);
}
