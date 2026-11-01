//! Registered diagonal kernel-settings-v1 source proof, canonical invocation 26.
//! No new APIs, capability admission, catalogue selection or host kernel mutation.

use super::*;
use crate::observation::{Availability, Origin};
use crate::target::SecurityOption;
use std::collections::BTreeMap;

const CONTRACT: &str = "kernel-settings-v1";
const FILENAME: &str = "kernel-settings-v1.json";
const CASES: [(&str, Option<bool>); 3] = [
    ("omitted", None),
    ("false_zero", Some(false)),
    ("true_one", Some(true)),
];
const BODY_ALLOWANCE: usize = 512 * 1024;
const CLEANUP_INSPECT_BODY_BYTES: usize = 65536;
const CLEANUP_PROJECTION_ENVELOPE: usize = 8192 + 2048;
const CHILD: &str = r#"test "$$" -gt 1 || exit 61
umask 077
{
  while read -r key value rest; do
    case "$key" in Pid:) printf 'child_pid %s\n' "$value";; PPid:) printf 'child_ppid %s\n' "$value";; NoNewPrivs:) printf 'child_nnp %s\n' "$value";; esac
  done </proc/self/status
  printf 'child_forward %s\n' "$(cat /proc/sys/net/ipv4/ip_forward)"
  printf 'child_net %s\n' "$(readlink /proc/self/ns/net)"
  printf 'child_pidns %s\n' "$(readlink /proc/self/ns/pid)"
} >/tmp/dl-ks/child.tmp
mv /tmp/dl-ks/child.tmp /tmp/dl-ks/child || exit 62
while :; do sleep 1; done"#;

const PARENT: &str = r#"test "$$" = 1 || exit 63
set -eu; LC_ALL=C; export LC_ALL; umask 077
test ! -e /tmp/dl-ks; test ! -L /tmp/dl-ks; mkdir /tmp/dl-ks
sample() {
  while read -r key value rest; do
    case "$key" in Pid:) printf '%s_pid %s\n' "$1" "$value";; PPid:) printf '%s_ppid %s\n' "$1" "$value";; NoNewPrivs:) printf '%s_nnp %s\n' "$1" "$value";; esac
  done </proc/1/status
  printf '%s_forward %s\n' "$1" "$(cat /proc/sys/net/ipv4/ip_forward)"
  printf '%s_net %s\n' "$1" "$(readlink /proc/1/ns/net)"
  printf '%s_pidns %s\n' "$1" "$(readlink /proc/1/ns/pid)"
}
sample pre >/tmp/dl-ks/parent.tmp
# A background fork followed by explicit exec, with PID retained and a later
# wait in PID1, cannot be replaced by a final-command shell optimization.
(exec /bin/sh -c "$1" "$0-child") &
child=$!
for n in $(seq 1 100); do if [ -f /tmp/dl-ks/child ]; then break; fi; sleep 0.05; done
test -f /tmp/dl-ks/child; test ! -L /tmp/dl-ks/child
test "/proc/$child/exe" -ef /bin/sh
printf '%s\000' /bin/sh -c "$1" "$0-child" | cmp "/proc/$child/cmdline" -
{
  printf 'spawned %s\n' "$child"
  cat /tmp/dl-ks/child
  while read -r key value rest; do
    case "$key" in Pid:) printf 'bound_pid %s\n' "$value";; PPid:) printf 'bound_ppid %s\n' "$value";; NoNewPrivs:) printf 'bound_nnp %s\n' "$value";; esac
  done <"/proc/$child/status"
  printf 'bound_net %s\n' "$(readlink /proc/$child/ns/net)"
  printf 'bound_pidns %s\n' "$(readlink /proc/$child/ns/pid)"
  sample post
} >>/tmp/dl-ks/parent.tmp
mv /tmp/dl-ks/parent.tmp /tmp/dl-ks/parent
wait "$child""#;

const OBSERVE: &str = r#"set -eu; test "$(id -u)" = 0; test "$(id -g)" = 0
for n in $(seq 1 100); do if [ -f /tmp/dl-ks/parent ]; then break; fi; sleep 0.05; done
test -f /tmp/dl-ks/parent; test ! -L /tmp/dl-ks/parent
cat /tmp/dl-ks/parent
child=; while read -r key value rest; do if [ "$key" = spawned ]; then child=$value; fi; done </tmp/dl-ks/parent
test -n "$child"; test "/proc/$child/exe" -ef /bin/sh
printf '%s\000' /bin/sh -c "$1" "$0-child" | cmp "/proc/$child/cmdline" -
for slot in root1 rootchild; do
  if [ "$slot" = root1 ]; then pid=1; else pid=$child; fi
  while read -r key value rest; do
    case "$key" in Pid:) printf '%s_pid %s\n' "$slot" "$value";; PPid:) printf '%s_ppid %s\n' "$slot" "$value";; NoNewPrivs:) printf '%s_nnp %s\n' "$slot" "$value";; esac
  done <"/proc/$pid/status"
  printf '%s_net %s\n' "$slot" "$(readlink /proc/$pid/ns/net)"
  printf '%s_pidns %s\n' "$slot" "$(readlink /proc/$pid/ns/pid)"
done
printf 'root_forward %s\n' "$(cat /proc/sys/net/ipv4/ip_forward)"
printf 'root_net %s\n' "$(readlink /proc/self/ns/net)"
printf 'root_pidns %s\n' "$(readlink /proc/self/ns/pid)""#;

#[derive(Clone, Copy, Eq, PartialEq)]
enum FieldState {
    Missing,
    Null,
    Empty,
    Present,
}
impl FieldState {
    fn name(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Null => "null",
            Self::Empty => "empty",
            Self::Present => "present",
        }
    }
    fn availability(self) -> Availability {
        match self {
            Self::Missing => Availability::Missing,
            Self::Null => Availability::Null,
            Self::Empty => Availability::Empty,
            Self::Present => Availability::Present,
        }
    }
}

fn namespace(value: &str, kind: &str) -> Option<u64> {
    let number = value
        .strip_prefix(kind)?
        .strip_prefix(":[")?
        .strip_suffix(']')?;
    if number.is_empty()
        || number.starts_with('0')
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    number.parse().ok()
}

fn outer_namespaces(run: &HealthRun) -> (u64, u64) {
    let bytes = run.outer(
        &[
            "sh".into(),
            "-ec".into(),
            "readlink /proc/self/ns/net; readlink /proc/self/ns/pid".into(),
        ],
        false,
    );
    let text =
        std::str::from_utf8(&bytes).unwrap_or_else(|_| panic!("closed outer namespace bytes"));
    let lines: Vec<_> = text.lines().collect();
    assert!(
        lines.len() == 2 && text.ends_with('\n'),
        "closed outer namespace pair"
    );
    (
        namespace(lines[0], "net").unwrap_or_else(|| panic!("outer network namespace")),
        namespace(lines[1], "pid").unwrap_or_else(|| panic!("outer PID namespace")),
    )
}

fn create_kernel_fixture(run: &mut HealthRun, index: usize) {
    assert!(
        run.inspect(&run.names[index], false).0 == 404,
        "fresh kernel fixture name"
    );
    let authored = CASES[index / 2].1;
    if index.is_multiple_of(2) {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
        ];
        if let Some(flag) = authored {
            args.extend([
                "--security-opt".into(),
                format!("no-new-privileges:{flag}"),
                "--sysctl".into(),
                format!("net.ipv4.ip_forward={}", u8::from(flag)),
            ]);
        }
        args.extend([
            run.base.clone(),
            "sh".into(),
            "-c".into(),
            PARENT.into(),
            run.names[index].clone(),
            CHILD.into(),
        ]);
        run.attempted[index] = true;
        let bytes = docker(run, &args);
        let id = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|value| value.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("canonical kernel CLI ID"));
        bind(run, index, id);
        return;
    }
    let mut settings = ContainerSettings {
        labels: vec![
            ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec()).unwrap(),
        ],
        ..ContainerSettings::default()
    };
    if let Some(flag) = authored {
        settings.security_options = vec![SecurityOption::NoNewPrivileges(flag)];
        settings.sysctls = vec![
            ContainerLabel::new(
                b"net.ipv4.ip_forward".to_vec(),
                if flag { b"1".to_vec() } else { b"0".to_vec() },
            )
            .unwrap(),
        ];
    }
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
            ["sh", "-c", PARENT, run.names[index].as_str(), CHILD]
                .map(|text| Argument::new(text.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck: None,
        restart: None,
        settings,
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
    let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
    let mut body = json!({"Image":run.base,"Cmd":["sh","-c",PARENT,run.names[index],CHILD],"Labels":{(OWNER):run.run},"HostConfig":{}});
    if let Some(flag) = authored {
        body["HostConfig"] = json!({"SecurityOpt":[format!("no-new-privileges:{flag}")],"Sysctls":{"net.ipv4.ip_forward":if flag {"1"} else {"0"}}});
    }
    assert!(
        request == json!({"method":"POST","path":path,"body":body}),
        "independent complete kernel literal request"
    );
    run.attempted[index] = true;
    let (status, created) = run.api("POST", &path, Some(&request["body"]), false);
    assert!(
        status == 201 && (created["Warnings"].is_null() || created["Warnings"] == json!([])),
        "kernel create without warnings"
    );
    bind(
        run,
        index,
        created["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical kernel rendered ID")),
    );
}

fn field_state(value: Option<&Value>, expected: Option<Value>, object: bool) -> FieldState {
    match (value, expected) {
        (None, None) => FieldState::Missing,
        (Some(Value::Null), None) => FieldState::Null,
        (Some(value), None)
            if if object {
                value.as_object().is_some_and(serde_json::Map::is_empty)
            } else {
                value.as_array().is_some_and(Vec::is_empty)
            } =>
        {
            FieldState::Empty
        }
        (Some(value), Some(expected)) if *value == expected => FieldState::Present,
        _ => panic!("exact native kernel setting representation"),
    }
}

fn configured(run: &HealthRun, index: usize, image: &Value) -> (FieldState, FieldState) {
    let id = run.ids[index].as_deref().unwrap();
    let (status, value) = run.inspect(id, false);
    assert!(
        status == 200
            && owned(run, &value, index, Some(id))
            && value["Image"] == image["id"]
            && running(&value),
        "owned live kernel fixture"
    );
    assert!(
        value["Config"]["Cmd"] == json!(["sh", "-c", PARENT, run.names[index], CHILD])
            && value["Path"] == "sh"
            && value["Args"] == json!(["-c", PARENT, run.names[index], CHILD]),
        "exact actual PID1 kernel argv"
    );
    assert!(
        value["Config"]["Entrypoint"].is_null() || value["Config"]["Entrypoint"] == json!([]),
        "borrowed kernel entrypoint"
    );
    assert!(
        value["Mounts"].as_array().is_some_and(Vec::is_empty)
            && matches!(
                value["HostConfig"]["NetworkMode"].as_str(),
                Some("default" | "bridge")
            ),
        "private container network without authored mounts"
    );
    let authored = CASES[index / 2].1;
    (
        field_state(
            value["HostConfig"].get("SecurityOpt"),
            authored.map(|flag| json!([format!("no-new-privileges:{flag}")])),
            false,
        ),
        field_state(
            value["HostConfig"].get("Sysctls"),
            authored.map(|flag| json!({"net.ipv4.ip_forward":if flag {"1"} else {"0"}})),
            true,
        ),
    )
}

fn receipt(bytes: &[u8]) -> Option<BTreeMap<String, String>> {
    if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        return None;
    }
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(bytes).ok()?.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 2
            || result
                .insert(fields[0].to_owned(), fields[1].to_owned())
                .is_some()
        {
            return None;
        }
    }
    let mut keys = vec![
        "spawned".to_owned(),
        "root_forward".to_owned(),
        "root_net".to_owned(),
        "root_pidns".to_owned(),
    ];
    for prefix in ["pre", "post", "child", "bound", "root1", "rootchild"] {
        for field in ["pid", "ppid", "nnp", "net", "pidns"] {
            keys.push(format!("{prefix}_{field}"));
        }
    }
    for prefix in ["pre", "post", "child"] {
        keys.push(format!("{prefix}_forward"));
    }
    if result.len() != keys.len() || keys.iter().any(|key| !result.contains_key(key)) {
        return None;
    }
    Some(result)
}

fn effect(run: &HealthRun, index: usize) -> Value {
    let id = run.ids[index].as_deref().unwrap();
    let bytes = docker(
        run,
        &[
            "exec".into(),
            "--user".into(),
            "0:0".into(),
            id.into(),
            "sh".into(),
            "-c".into(),
            OBSERVE.into(),
            run.names[index].clone(),
            CHILD.into(),
        ],
    );
    let value = receipt(&bytes).unwrap_or_else(|| panic!("closed actual worker kernel receipt"));
    let spawned = value["spawned"]
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 1 && *pid <= 4194304)
        .unwrap_or_else(|| panic!("genuine child PID"));
    let nnp = value["pre_nnp"]
        .parse::<u8>()
        .ok()
        .filter(|bit| *bit <= 1)
        .unwrap_or_else(|| panic!("kernel NNP bit"));
    let forward = value["pre_forward"]
        .parse::<u8>()
        .ok()
        .filter(|bit| *bit <= 1)
        .unwrap_or_else(|| panic!("namespaced forward bit"));
    let net =
        namespace(&value["pre_net"], "net").unwrap_or_else(|| panic!("kernel network namespace"));
    let pidns =
        namespace(&value["pre_pidns"], "pid").unwrap_or_else(|| panic!("kernel PID namespace"));
    for prefix in ["pre", "post", "child", "bound", "root1", "rootchild"] {
        let parent = matches!(prefix, "pre" | "post" | "root1");
        assert!(
            value[&format!("{prefix}_pid")]
                == if parent {
                    "1".to_owned()
                } else {
                    spawned.to_string()
                }
                && value[&format!("{prefix}_ppid")] == if parent { "0" } else { "1" },
            "independently bound PID and PPID"
        );
        assert!(
            value[&format!("{prefix}_nnp")] == nnp.to_string(),
            "NNP persists across actual exec and corroboration"
        );
        assert!(
            namespace(&value[&format!("{prefix}_net")], "net") == Some(net)
                && namespace(&value[&format!("{prefix}_pidns")], "pid") == Some(pidns),
            "actual child shares only its private container namespaces"
        );
    }
    for key in ["post_forward", "child_forward", "root_forward"] {
        assert!(
            value[key] == forward.to_string(),
            "consistent namespaced forwarding reads"
        );
    }
    assert!(
        namespace(&value["root_net"], "net") == Some(net)
            && namespace(&value["root_pidns"], "pid") == Some(pidns),
        "corroborating exec namespace identity"
    );
    if let Some(flag) = CASES[index / 2].1 {
        assert!(
            nnp == u8::from(flag),
            "explicit NNP false must be kernel zero; inherited one cannot count as false"
        );
        assert!(
            forward == u8::from(flag),
            "explicit finite forwarding effect"
        );
    }
    json!({"parent_pid":1,"parent_ppid":0,"child_pid":spawned,"child_ppid":1,"parent_nnp":nnp,"child_nnp":nnp,
        "forwarding":forward,"net_namespace":net,"pid_namespace":pidns,"parent_pre_post_agree":true,
        "exec_binding":"background_pid_argv_exe_inode_and_proc","root_corroboration":"same_live_pids_and_namespaces"})
}

fn acquisition(
    run: &HealthRun,
    states: &[(FieldState, FieldState)],
    outer_backend: SourceOuterBackend,
) -> Value {
    let calls = run.calls.get().checked_add(16).unwrap();
    let bytes = run.bytes.get().checked_add(BODY_ALLOWANCE).unwrap();
    assert!(
        outer_backend.final_snapshot_room(calls, bytes, 3),
        "charged kernel capture and final snapshots"
    );
    let elapsed = run
        .remaining()
        .checked_sub(Duration::from_secs(46))
        .filter(|left| !left.is_zero())
        .unwrap_or_else(|| panic!("kernel original cleanup cutoff"));
    run.calls.set(calls);
    run.bytes.set(bytes);
    let ids = run
        .ids
        .iter()
        .map(|id| NativeId::new(id.as_ref().unwrap().clone()).unwrap())
        .collect();
    let capture = acquire(
        &Endpoint::unix_socket(PathBuf::from(&run.socket)),
        Selector::ContainerIds(ids),
        Limits {
            max_requests: 16,
            max_selected_resources: 6,
            max_expansions: 8,
            max_response_bytes: 131072,
            max_total_bytes: BODY_ALLOWANCE,
            max_elapsed: elapsed.min(Duration::from_secs(10)),
        },
        &AtomicBool::new(false),
    )
    .unwrap_or_else(|_| panic!("actual kernel settings capture"));
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
            && capture.selected_roots().len() == 6
            && capture
                .exchanges()
                .iter()
                .all(|exchange| exchange.status().code() == 200)
            && capture
                .exchanges()
                .iter()
                .filter_map(|exchange| exchange.api_version())
                .all(|version| version == api),
        "exact six-ID kernel capture"
    );
    let decoded =
        decode_capture(&capture).unwrap_or_else(|_| panic!("actual kernel settings decode"));
    assert!(
        decoded.containers.len() == 6
            && decoded.version.requested_api_versions == vec![api]
            && decoded.version.daemon.observation_id == capture.observation_id()
            && decoded
                .version
                .daemon
                .release
                .as_ref()
                .is_some_and(|release| release.as_str() == run.engine),
        "exact decoded kernel context"
    );
    let mode = match (run.mode, decoded.version.daemon.mode) {
        (DaemonMode::Rootless, DaemonMode::Rootless) => "rootless_observed",
        (DaemonMode::Rootful, DaemonMode::Rootful) => "rootful_observed",
        (DaemonMode::Rootful, DaemonMode::Unknown) => "unknown_with_independent_rootful_context",
        _ => panic!("nonconflicting decoded kernel mode"),
    };
    let mut seen = BTreeSet::new();
    for container in &decoded.containers {
        let id = container
            .id
            .value()
            .unwrap_or_else(|| panic!("decoded kernel ID"))
            .as_bytes();
        let index = run
            .ids
            .iter()
            .position(|id_expected| id_expected.as_ref().unwrap().as_bytes() == id)
            .unwrap_or_else(|| panic!("selected kernel decoded ID"));
        let security = &container.runtime.security_options;
        let sysctls = &container.runtime.sysctls;
        assert!(
            seen.insert(index)
                && container.id.availability == Availability::Present
                && container.id.origin == Origin::RuntimeAssigned
                && security.origin == Origin::Effective
                && sysctls.origin == Origin::Effective
                && security.availability == states[index].0.availability()
                && sysctls.availability == states[index].1.availability(),
            "truthful kernel decoded availability"
        );
        let flag = CASES[index / 2].1;
        if let Some(options) = security.value() {
            let expected = flag.map(|flag| format!("no-new-privileges:{flag}"));
            assert!(
                options.len() == usize::from(flag.is_some())
                    && options
                        .iter()
                        .map(|item| item.as_bytes())
                        .eq(expected.iter().map(String::as_bytes)),
                "decoded exact security option bytes"
            );
        } else {
            assert!(flag.is_none(), "unavailable security only on omission");
        }
        if let Some(entries) = sysctls.value() {
            assert!(
                entries.len() == usize::from(flag.is_some()),
                "decoded finite sysctl count"
            );
            for entry in entries {
                assert!(
                    entry.key.as_bytes() == b"net.ipv4.ip_forward"
                        && entry.value.availability == Availability::Present
                        && entry.value.origin == Origin::Effective
                        && entry
                            .value
                            .value()
                            .is_some_and(|item| item.as_bytes()
                                == if flag == Some(true) { b"1" } else { b"0" }),
                    "decoded exact sysctl bytes"
                );
            }
        } else {
            assert!(flag.is_none(), "unavailable sysctl only on omission");
        }
    }
    let body_bytes: usize = capture
        .exchanges()
        .iter()
        .map(|exchange| exchange.body().as_bytes().len())
        .sum();
    assert!(
        (8..=16).contains(&capture.exchanges().len())
            && body_bytes > 0
            && body_bytes <= BODY_ALLOWANCE,
        "bounded kernel capture bodies"
    );
    json!({"selected_ids":6,"route":"explicit_unix_socket","api":format!("{}.{}",api.major,api.minor),"daemon_mode_evidence":mode,
        "reserved_calls":16,"reserved_body_bytes":BODY_ALLOWANCE,"actual_requests":capture.exchanges().len(),"actual_body_bytes":body_bytes,
        "decoded":"effective_security_and_sysctls_agree","byte_scope":"decoded_response_bodies_only",
        "limits":{"max_requests":16,"max_selected_resources":6,"max_expansions":8,"max_response_bytes":131072,"max_total_body_bytes":BODY_ALLOWANCE,"max_elapsed_seconds":10},
        "separate_transport_bounds":{"response_header_bytes":16384,"chunk_line_bytes":64,"chunk_payload_crlf_bytes":2,"final_trailer_line_bytes":16384,"actual_wire_bytes":"not_measured"}})
}

// Consume the same full bounded inspect body, without emitting Cmd/Args through
// cleanup's smaller stdout cap. This is kernel-local, not a transport change.
fn kernel_cleanup_room(calls: usize, bytes: usize) -> bool {
    calls < MAX_CALLS
        && bytes
            .checked_add(CLEANUP_INSPECT_BODY_BYTES)
            .and_then(|total| total.checked_add(CLEANUP_PROJECTION_ENVELOPE))
            .is_some_and(|total| total <= MAX_BYTES)
}

fn kernel_cleanup_charge(counted_with_reservation: usize, actual_body: usize) -> Option<usize> {
    let unused = CLEANUP_INSPECT_BODY_BYTES.checked_sub(actual_body)?;
    counted_with_reservation.checked_sub(unused)
}

fn kernel_cleanup_inspect(run: &HealthRun, key: &str) -> (u16, Value) {
    let path = format!("/v{}/containers/{key}/json", run.api);
    assert!(
        run.request_allowed("GET", &path),
        "original exact kernel cleanup GET authorization"
    );
    assert!(
        kernel_cleanup_room(run.calls.get(), run.bytes.get()),
        "full kernel cleanup body and stream capacity before I/O"
    );
    let reserved = run
        .bytes
        .get()
        .checked_add(CLEANUP_INSPECT_BODY_BYTES)
        .unwrap_or_else(|| panic!("bounded kernel cleanup body reservation"));
    run.bytes.set(reserved);
    let mut command = run.timer(true, false);
    command.args([
        "python3",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/native_kernel_cleanup.py"
        ),
        "--socket",
        &run.socket,
        "--path",
        &path,
    ]);
    // Failure retains the full body charge; capture separately charges actual
    // retained projection stdout/stderr, even when capture itself panics.
    let output = run.capture(&mut command, None, true);
    assert!(
        output.ends_with(b"\n"),
        "complete private kernel cleanup projection frame"
    );
    let frame: Value = serde_json::from_slice(&output)
        .unwrap_or_else(|_| panic!("closed private kernel cleanup projection JSON"));
    assert!(
        frame.as_object().is_some_and(|object| object.len() == 3
            && object.contains_key("status")
            && object.contains_key("body_bytes")
            && object.contains_key("object")),
        "closed kernel cleanup projection fields"
    );
    let status = match frame["status"].as_u64() {
        Some(200) => 200,
        Some(404) => 404,
        _ => panic!("closed actual kernel cleanup HTTP status"),
    };
    let body_bytes = frame["body_bytes"]
        .as_u64()
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| (1..=CLEANUP_INSPECT_BODY_BYTES).contains(count))
        .unwrap_or_else(|| panic!("actual bounded kernel cleanup body count"));
    let object = &frame["object"];
    assert!(
        if status == 404 {
            object.is_null()
        } else {
            object.as_object().is_some_and(|value| {
                value.len() == 3
                    && value.contains_key("Id")
                    && value.contains_key("Name")
                    && value.contains_key("Config")
            }) && object["Id"].as_str().is_some_and(identifier)
                && object["Name"].is_string()
                && object["Config"].as_object().is_some_and(|value| {
                    value.len() == 2 && value.contains_key("Image") && value.contains_key("Labels")
                })
                && object["Config"]["Image"].is_string()
                && object["Config"]["Labels"].as_object().is_some_and(|value| {
                    value.len() == 1 && value.get(OWNER).is_some_and(Value::is_string)
                })
        },
        "closed actual kernel cleanup ownership projection"
    );
    let charged = kernel_cleanup_charge(run.bytes.get(), body_bytes)
        .unwrap_or_else(|| panic!("checked kernel cleanup body accounting reconciliation"));
    assert!(
        charged <= MAX_BYTES,
        "unchanged aggregate kernel cleanup byte limit"
    );
    run.bytes.set(charged);
    (status, object.clone())
}

fn kernel_cleanup_with(
    attempted: &[bool],
    ids: &[Option<String>],
    inner: impl FnOnce() -> CleanupDisposition,
) -> CleanupDisposition {
    if attempted.len() != 6
        || ids.len() != 6
        || attempted
            .iter()
            .zip(ids)
            .any(|(attempted, id)| *attempted && !id.as_deref().is_some_and(identifier))
    {
        // No unknown-create name recovery or inner I/O is authorized here.
        return CleanupDisposition::OuterTeardownRequired;
    }
    inner()
}

fn remove_kernel_container(run: &HealthRun, index: usize) -> bool {
    let Some(id) = run.ids[index].as_deref().filter(|id| identifier(id)) else {
        return false;
    };
    let (status, value) = kernel_cleanup_inspect(run, &run.names[index]);
    if status == 404 {
        return true;
    }
    if status != 200 || !owned(run, &value, index, Some(id)) {
        return false;
    }
    if id == required("NATIVE_OUTER_CONTAINER_ID")
        || run
            .ids
            .iter()
            .enumerate()
            .any(|(other, registered)| other != index && registered.as_deref() == Some(id))
    {
        return false;
    }
    let (status, immediate) = kernel_cleanup_inspect(run, id);
    if status != 200 || !owned(run, &immediate, index, Some(id)) {
        return false;
    }
    run.api(
        "DELETE",
        &format!("/v{}/containers/{id}?force=1", run.api),
        None,
        true,
    )
    .0 == 204
        && run.inspect(id, true).0 == 404
        && run.inspect(&run.names[index], true).0 == 404
}

fn cleanup_kernel(run: &HealthRun) -> CleanupDisposition {
    kernel_cleanup_with(&run.attempted, &run.ids, || {
        let mut verified = true;
        for index in 0..run.names.len() {
            if run.attempted[index] {
                verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    remove_kernel_container(run, index)
                }))
                .unwrap_or(false);
            }
        }
        for _ in 0..2 {
            for index in 0..run.names.len() {
                if run.attempted[index] {
                    verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run.ids[index]
                            .as_ref()
                            .is_some_and(|id| run.inspect(id, true).0 == 404)
                            && run.inspect(&run.names[index], true).0 == 404
                    }))
                    .unwrap_or(false);
                }
            }
        }
        cleanup_disposition(verified)
    })
}

#[test]
fn kernel_cleanup_guard_and_body_accounting_controls_are_nonpositive_on_unknowns() {
    let attempted = vec![true; 6];
    let valid: Vec<_> = (1..=6).map(|value| Some(format!("{value:064x}"))).collect();
    for invalid in [None, Some("malformed".to_owned()), Some("A".repeat(64))] {
        let mut ids = valid.clone();
        ids[2] = invalid;
        let called = Cell::new(false);
        assert!(
            kernel_cleanup_with(&attempted, &ids, || {
                called.set(true);
                CleanupDisposition::VerifiedAbsent
            }) == CleanupDisposition::OuterTeardownRequired
                && !called.get(),
            "unknown kernel create ID forbids inner cleanup"
        );
    }
    let called = Cell::new(false);
    assert!(
        kernel_cleanup_with(&attempted, &valid, || {
            called.set(true);
            CleanupDisposition::VerifiedAbsent
        }) == CleanupDisposition::VerifiedAbsent
            && called.get(),
        "known canonical IDs allow ordinary cleanup"
    );
    let full = CLEANUP_INSPECT_BODY_BYTES + CLEANUP_PROJECTION_ENVELOPE;
    assert!(kernel_cleanup_room(MAX_CALLS - 1, MAX_BYTES - full));
    assert!(
        !kernel_cleanup_room(MAX_CALLS, 0)
            && !kernel_cleanup_room(0, MAX_BYTES - full + 1)
            && !kernel_cleanup_room(0, usize::MAX),
        "full body and stream reservation cannot overflow limits"
    );
    assert!(kernel_cleanup_charge(full, 8193) == Some(8193 + CLEANUP_PROJECTION_ENVELOPE));
    assert!(kernel_cleanup_charge(full, CLEANUP_INSPECT_BODY_BYTES) == Some(full));
    assert!(
        kernel_cleanup_charge(full, CLEANUP_INSPECT_BODY_BYTES + 1).is_none()
            && kernel_cleanup_charge(0, 1).is_none(),
        "unknown/oversize bodies cannot reconcile a reservation"
    );
}

#[test]
#[ignore = "requires exact disposable native harness"]
fn live_kernel_settings_match_engine() {
    let outer_backend = source_outer_backend();
    let started = Instant::now();
    let target = ProofTarget::new_for("NATIVE_KERNEL_SETTINGS_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_KERNEL_SETTINGS_CANDIDATE_SHA",
        "NATIVE_KERNEL_SETTINGS_DEADLINE_EPOCH",
    );
    run.names = CASES
        .into_iter()
        .flat_map(|(case, _)| {
            ["oracle", "rendered"].map(|role| format!("dl-ks-{}-{case}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 6];
    run.attempted = vec![false; 6];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: kernel_settings_context");
        let outer = owner.snapshot.clone();
        let daemon_uid = run.context();
        let image = image_snapshot(&run);
        let outer_ns = outer_namespaces(&run);
        assert!(
            image["config"]["Volumes"].is_null() || image["config"]["Volumes"] == json!({}),
            "no borrowed automatic mounts"
        );
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::SecurityOptions,
            Capability::Sysctls,
            Capability::SysctlIpv4Forward,
        ]
        .into_iter()
        .map(|capability| CapabilityFact {
            capability,
            state: CapabilityState::Available,
            provenance: FactProvenance::NativeConformance,
            scope: scope.clone(),
        })
        .collect();
        let mut cases = Vec::new();
        let mut states = Vec::new();
        let mut nets = BTreeSet::from([outer_ns.0]);
        let mut pids = BTreeSet::from([outer_ns.1]);
        eprintln!("DOCKERLENS_NATIVE_CHECK: kernel_settings_effects");
        for (case, (name, flag)) in CASES.into_iter().enumerate() {
            let mut containers = Vec::new();
            for (offset, role) in ["oracle", "rendered"].into_iter().enumerate() {
                let index = case * 2 + offset;
                create_kernel_fixture(&mut run, index);
                start(&run, index);
                let state = configured(&run, index, &image);
                let observed = effect(&run, index);
                assert!(
                    nets.insert(observed["net_namespace"].as_u64().unwrap())
                        && pids.insert(observed["pid_namespace"].as_u64().unwrap()),
                    "six private namespace identities apart from outer"
                );
                assert!(
                    configured(&run, index, &image) == state,
                    "stable configured kernel fields and live worker"
                );
                states.push(state);
                containers.push(json!({"role":role,"id":run.ids[index],"name":run.names[index],"owner":run.run,"image_id":image["id"],
                    "wire":if offset==0{"independent_cli"}else{"literal_rendered"},"security_availability":state.0.name(),"sysctls_availability":state.1.name(),
                    "effect":observed,"running_after":true,"restart_count":0,"oom_killed":false,"cleanup":"absent"}));
            }
            cases.push(json!({"case":name,"authored_nnp":flag,"authored_forwarding":flag.map(u8::from),"containers":containers}));
        }
        eprintln!("DOCKERLENS_NATIVE_CHECK: kernel_settings_capture");
        let captured = acquisition(&run, &states, outer_backend);
        (outer, daemon_uid, image, outer_ns, cases, captured)
    }));
    let before_calls = run.calls.get();
    let before_bytes = run.bytes.get();
    let cleanup_started = Instant::now();
    eprintln!("DOCKERLENS_NATIVE_CHECK: kernel_settings_cleanup");
    let disposition =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cleanup_kernel(&run)))
            .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_calls = run.calls.get() - before_calls;
    let cleanup_bytes = run.bytes.get() - before_bytes;
    terminal_cleanup(&mut run, &owner, disposition);
    let (outer, daemon_uid, image, outer_ns, cases, captured) =
        require_verified_result(result, disposition);
    assert!(
        !run.image_attempted
            && run.derived_id.is_none()
            && image_snapshot(&run) == image
            && outer_context(&run) == outer
            && outer_namespaces(&run) == outer_ns,
        "unchanged borrowed image outer and namespaces"
    );
    let ordinary_calls = run.calls.get() - cleanup_calls;
    let ordinary_bytes = run.bytes.get() - cleanup_bytes;
    let ordinary_elapsed = started.elapsed().saturating_sub(cleanup_elapsed);
    assert!(
        ordinary_calls
            == (if run.lane.starts_with("debian11-") {
                71
            } else {
                70
            }) + 2 * outer_backend.snapshot_extra_calls()
            && ordinary_bytes >= BODY_ALLOWANCE + 1 + 2 * outer_backend.snapshot_extra_bytes()
            && ordinary_bytes <= MAX_BYTES - CLEANUP_BYTES
            && cleanup_calls == 54
            && cleanup_bytes <= 54 * (8192 + 2048),
        "closed kernel accounting"
    );
    assert!(
        ordinary_elapsed <= Duration::from_secs(134)
            && cleanup_elapsed <= Duration::from_secs(46)
            && started.elapsed() <= Duration::from_secs(180),
        "original kernel deadline"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"scope":"diagonal_omitted_false0_true1_only","capability_admission":[],"catalogue_admission":false,
        "context":{"candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,"rendering_api":run.api,
            "acquisition_api":if run.lane.starts_with("debian11-"){"1.41"}else{"1.49"},"mode":if run.mode==DaemonMode::Rootless{"rootless"}else{"rootful"},
            "docker_package":if run.lane.starts_with("debian11-"){"20.10.5+dfsg1-1+deb11u2"}else{""},"fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"outer_namespaces":{"net":outer_ns.0,"pid":outer_ns.1,"unchanged":true},"cases":cases,"acquisition":captured,
        "accounting":{"ordinary_calls":ordinary_calls,"ordinary_bytes":ordinary_bytes,"cleanup_calls":cleanup_calls,"cleanup_bytes":cleanup_bytes,
            "ordinary_elapsed_ns":ordinary_elapsed.as_nanos(),"cleanup_elapsed_ns":cleanup_elapsed.as_nanos(),"elapsed_ns":started.elapsed().as_nanos(),"deadline_seconds":180,"cleanup_reserve_seconds":46,
            "initial_context_acquisition":{"max_requests":16,"max_body_bytes":2097152,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"}},
        "cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: kernel_settings_proof");
    target.publish(&proof);
}

#[test]
fn kernel_receipt_and_namespace_controls_refuse_partial_duplicate_and_wrong_kind() {
    assert!(receipt(b"pre_pid 1\n").is_none());
    assert!(receipt(b"pre_pid 1\npre_pid 1\n").is_none());
    assert!(namespace("net:[42]", "net") == Some(42));
    for value in [
        "net:[0]",
        "net:[01]",
        "net:[+1]",
        "pid:[42]",
        "net:[18446744073709551616]",
    ] {
        assert!(namespace(value, "net").is_none());
    }
}
