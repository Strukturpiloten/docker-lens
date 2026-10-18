//! Prepared source-only supplementary-groups-v1 lifecycle child.
//! Registration is primary-owned; no raw projection or catalogue admission.

use super::*;
use crate::observation::{Availability, Origin};
use crate::target::ContainerUser;
use std::collections::BTreeMap;

const CONTRACT: &str = "supplementary-groups-v1";
const FILENAME: &str = "supplementary-groups-v1.json";
const CASES: [(&str, &[u32]); 3] = [
    ("omitted", &[]),
    ("one", &[23456]),
    ("pair", &[23456, 34567]),
];
const BODY_ALLOWANCE: usize = 512 * 1024;
// Every redirect is executed by the nonroot PID1 shell itself. Braces do not
// fork a permission oracle; command substitution is only used to READ errors.
const GROUP_PROCESS: &str = r#"test "$$" = 1 || exit 61
LC_ALL=C; export LC_ALL
test "$(type printf)" = 'printf is a shell builtin' || exit 64
facts() {
  while read -r key rest; do
    case "$key" in
      Uid:) printf '%s_uid %s\n' "$1" "$rest";;
      Gid:) printf '%s_gid %s\n' "$1" "$rest";;
      Groups:) printf '%s_groups %s\n' "$1" "$rest";;
      CapEff:) printf '%s_cap %s\n' "$1" "$rest";;
    esac
  done </proc/1/status
}
for n in $(seq 1 200); do
  if [ -f /dl-sg/ready ]; then break; fi
  sleep 0.05
done
test -f /dl-sg/ready || exit 62
{
  printf 'pid %s\n' "$$"
  facts pre
  if { printf '%s' sg-worker-one >/dl-sg/first; } 2>/tmp/dl-sg-first-error; then
    first_code=0; first=written
  else
    first_code=$?; case "$(cat /tmp/dl-sg-first-error)" in *'Permission denied'*) first=denied;; *) first=other;; esac
  fi
  printf 'first %s %s\n' "$first_code" "$first"
  if { printf '%s' sg-worker-two >/dl-sg/second; } 2>/tmp/dl-sg-second-error; then
    second_code=0; second=written
  else
    second_code=$?; case "$(cat /tmp/dl-sg-second-error)" in *'Permission denied'*) second=denied;; *) second=other;; esac
  fi
  printf 'second %s %s\n' "$second_code" "$second"
  facts post
} >/tmp/dl-sg-report.tmp
mv /tmp/dl-sg-report.tmp /tmp/dl-sg-report || exit 63
while :; do sleep 1; done"#;

const PREPARE: &str = r#"set -eu; test "$(id -u)" = 0; test "$(id -g)" = 0
test ! -e /dl-sg; test ! -L /dl-sg
test ! -e /tmp/dl-sg-report; test ! -L /tmp/dl-sg-report
test ! -e /tmp/dl-sg-report.tmp; test ! -L /tmp/dl-sg-report.tmp
test ! -e /tmp/dl-sg-first-error; test ! -L /tmp/dl-sg-first-error
test ! -e /tmp/dl-sg-second-error; test ! -L /tmp/dl-sg-second-error
mkdir /dl-sg; chown 0:0 /dl-sg; chmod 0755 /dl-sg
printf '%s' sg-baseline-one >/dl-sg/first; printf '%s' sg-baseline-two >/dl-sg/second
chown 0:23456 /dl-sg/first; chown 0:34567 /dl-sg/second; chmod 0660 /dl-sg/first /dl-sg/second
test "$(stat -c %u:%g:%a /dl-sg/first)" = 0:23456:660
test "$(stat -c %u:%g:%a /dl-sg/second)" = 0:34567:660
printf '%s' ready >/dl-sg/ready"#;

const COLLECT: &str = r#"set -eu; test "$(id -u)" = 0; test "$(id -g)" = 0
for n in $(seq 1 100); do if [ -f /tmp/dl-sg-report ]; then break; fi; sleep 0.05; done
test -f /tmp/dl-sg-report; test ! -L /tmp/dl-sg-report
test "$(stat -c %u:%g:%a /dl-sg)" = 0:0:755
test "$(stat -c %u:%g:%a /dl-sg/first)" = 0:23456:660
test "$(stat -c %u:%g:%a /dl-sg/second)" = 0:34567:660
cat /tmp/dl-sg-report
while read -r key rest; do
  case "$key" in
    Uid:) printf 'root_uid %s\n' "$rest";; Gid:) printf 'root_gid %s\n' "$rest";;
    Groups:) printf 'root_groups %s\n' "$rest";; CapEff:) printf 'root_cap %s\n' "$rest";;
  esac
done </proc/1/status
printf 'root_first %s\n' "$(cat /dl-sg/first)"
printf 'root_second %s\n' "$(cat /dl-sg/second)""#;

#[derive(Clone, Copy, Eq, PartialEq)]
enum GroupState {
    Missing,
    Null,
    Empty,
    Present,
}

impl GroupState {
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

fn create_group_fixture(run: &mut HealthRun, index: usize) {
    assert!(
        run.inspect(&run.names[index], false).0 == 404,
        "fresh supplementary fixture name"
    );
    let groups = CASES[index / 2].1;
    if index.is_multiple_of(2) {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
            "--user".into(),
            "12345:3456".into(),
        ];
        for group in groups {
            args.extend(["--group-add".into(), group.to_string()]);
        }
        args.extend([
            run.base.clone(),
            "sh".into(),
            "-c".into(),
            GROUP_PROCESS.into(),
        ]);
        run.attempted[index] = true;
        let output = docker(run, &args);
        let id = std::str::from_utf8(&output)
            .ok()
            .and_then(|text| text.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("canonical supplementary CLI ID"));
        bind(run, index, id);
        return;
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
            ["sh", "-c", GROUP_PROCESS]
                .map(|text| Argument::new(text.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                    .unwrap(),
            ],
            user: Some(ContainerUser::new(b"12345:3456".to_vec()).unwrap()),
            group_add: groups
                .iter()
                .map(|group| ContainerUser::new(group.to_string().into_bytes()).unwrap())
                .collect(),
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
    let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
    let mut body = json!({"Image":run.base,"User":"12345:3456","Cmd":["sh","-c",GROUP_PROCESS],"Labels":{(OWNER):run.run},"HostConfig":{}});
    if !groups.is_empty() {
        body["HostConfig"]["GroupAdd"] =
            json!(groups.iter().map(u32::to_string).collect::<Vec<_>>());
    }
    assert!(
        request == json!({"method":"POST","path":path,"body":body}),
        "independent supplementary literal request"
    );
    run.attempted[index] = true;
    let (status, created) = run.api("POST", &path, Some(&request["body"]), false);
    assert!(
        status == 201 && (created["Warnings"].is_null() || created["Warnings"] == json!([])),
        "supplementary create accepted without warnings"
    );
    bind(
        run,
        index,
        created["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical supplementary rendered ID")),
    );
}

fn configured_groups(run: &HealthRun, index: usize, image: &Value) -> GroupState {
    let id = run.ids[index].as_deref().unwrap();
    let (status, value) = run.inspect(id, false);
    assert!(
        status == 200 && owned(run, &value, index, Some(id)),
        "owned supplementary inspect"
    );
    assert!(
        value["Image"] == image["id"]
            && value["Config"]["User"] == "12345:3456"
            && value["Config"]["Cmd"] == json!(["sh", "-c", GROUP_PROCESS]),
        "exact nonroot supplementary configuration"
    );
    assert!(
        value["Config"]["Entrypoint"].is_null() || value["Config"]["Entrypoint"] == json!([]),
        "borrowed empty entrypoint"
    );
    assert!(
        value["Path"] == "sh" && value["Args"] == json!(["-c", GROUP_PROCESS]) && running(&value),
        "actual live supplementary worker"
    );
    assert!(
        value["Mounts"].as_array().is_some_and(Vec::is_empty),
        "only internal supplementary files"
    );
    let groups = CASES[index / 2].1;
    match value["HostConfig"].get("GroupAdd") {
        None if groups.is_empty() => GroupState::Missing,
        Some(Value::Null) if groups.is_empty() => GroupState::Null,
        Some(Value::Array(items)) if groups.is_empty() && items.is_empty() => GroupState::Empty,
        Some(items)
            if !groups.is_empty()
                && *items == json!(groups.iter().map(u32::to_string).collect::<Vec<_>>()) =>
        {
            GroupState::Present
        }
        _ => panic!("exact native supplementary list with truthful omitted availability"),
    }
}

fn words(bytes: &[u8]) -> Option<BTreeMap<String, Vec<String>>> {
    if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let key = fields.next()?.to_owned();
        if result
            .insert(key, fields.map(str::to_owned).collect())
            .is_some()
        {
            return None;
        }
    }
    let expected = [
        "pid",
        "pre_uid",
        "pre_gid",
        "pre_groups",
        "pre_cap",
        "first",
        "second",
        "post_uid",
        "post_gid",
        "post_groups",
        "post_cap",
        "root_uid",
        "root_gid",
        "root_groups",
        "root_cap",
        "root_first",
        "root_second",
    ];
    if result.len() != expected.len() || expected.iter().any(|key| !result.contains_key(*key)) {
        return None;
    }
    Some(result)
}

fn decimal(text: &str) -> Option<u32> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
}

fn effect(run: &HealthRun, index: usize) -> Value {
    let id = run.ids[index].as_deref().unwrap();
    let prepared = docker(
        run,
        &[
            "exec".into(),
            "--user".into(),
            "0:0".into(),
            id.into(),
            "sh".into(),
            "-c".into(),
            PREPARE.into(),
        ],
    );
    assert!(prepared.is_empty(), "quiet root supplementary setup");
    let bytes = docker(
        run,
        &[
            "exec".into(),
            "--user".into(),
            "0:0".into(),
            id.into(),
            "sh".into(),
            "-c".into(),
            COLLECT.into(),
        ],
    );
    let record = words(&bytes).unwrap_or_else(|| panic!("closed worker supplementary receipt"));
    assert!(record["pid"] == ["1"], "actual nonroot PID1 writer");
    for prefix in ["pre", "post", "root"] {
        assert!(
            record[&format!("{prefix}_uid")] == ["12345"; 4]
                && record[&format!("{prefix}_gid")] == ["3456"; 4]
                && record[&format!("{prefix}_cap")] == ["0000000000000000"],
            "stable kernel nonroot IDs without effective capabilities"
        );
        assert!(
            record[&format!("{prefix}_groups")] == record["pre_groups"],
            "independently corroborated stable kernel groups"
        );
    }
    let kernel: Vec<u32> = record["pre_groups"]
        .iter()
        .map(|text| decimal(text).unwrap_or_else(|| panic!("closed kernel GID")))
        .collect();
    assert!(
        kernel.windows(2).all(|pair| pair[0] < pair[1]),
        "ordered unique actual kernel groups"
    );
    let extra: Vec<_> = kernel
        .iter()
        .copied()
        .filter(|group| *group != 3456)
        .collect();
    assert!(
        extra == CASES[index / 2].1,
        "exact finite supplementary membership apart from optional primary GID"
    );
    let mut files = Vec::new();
    for (name, gid, baseline, canary) in [
        ("first", 23456, "sg-baseline-one", "sg-worker-one"),
        ("second", 34567, "sg-baseline-two", "sg-worker-two"),
    ] {
        let observation = &record[name];
        assert!(observation.len() == 2, "closed permission observation");
        let code = decimal(&observation[0])
            .filter(|code| *code <= 255)
            .unwrap_or_else(|| panic!("closed permission exit"));
        let granted = extra.contains(&gid);
        assert!(
            if granted {
                code == 0 && observation[1] == "written"
            } else {
                code > 0 && observation[1] == "denied"
            },
            "native worker permission outcome"
        );
        assert!(
            record[&format!("root_{name}")] == [if granted { canary } else { baseline }],
            "root corroborates changed or unchanged file bytes"
        );
        files.push(
            json!({"owner_uid":0,"group_gid":gid,"mode":432,"write_exit":code,
            "outcome":if granted {"worker_written"} else {"native_permission_denied"},
            "readback":if granted {"worker_canary"} else {"baseline_unchanged"}}),
        );
    }
    json!({"pid":1,"uid":12345,"primary_gid":3456,"kernel_groups":kernel,"primary_gid_in_groups":kernel.contains(&3456),
        "effective_capabilities":"0000000000000000","kernel_pre_post_root_agree":true,"writer":"nonroot_pid1",
        "root_exec_scope":"setup_and_readback_only","files":files})
}

fn acquisition(run: &HealthRun, states: &[GroupState]) -> Value {
    let calls = run.calls.get().checked_add(16).unwrap();
    let bytes = run.bytes.get().checked_add(BODY_ALLOWANCE).unwrap();
    assert!(
        calls + 2 <= MAX_CALLS - CLEANUP_CALLS
            && bytes + 2 * (65550 + 8192) <= MAX_BYTES - CLEANUP_BYTES,
        "supplementary capture and final ordinary snapshots reserve"
    );
    let elapsed = run
        .remaining()
        .checked_sub(Duration::from_secs(46))
        .filter(|left| !left.is_zero())
        .unwrap_or_else(|| panic!("supplementary original cleanup cutoff"));
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
            max_response_bytes: 128 * 1024,
            max_total_bytes: BODY_ALLOWANCE,
            max_elapsed: elapsed.min(Duration::from_secs(10)),
        },
        &AtomicBool::new(false),
    )
    .unwrap_or_else(|_| panic!("actual six-ID supplementary capture"));
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
        "exact complete supplementary acquisition"
    );
    let decoded =
        decode_capture(&capture).unwrap_or_else(|_| panic!("supplementary product decoder"));
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
        "exact supplementary decoded context"
    );
    let mode = match (run.mode, decoded.version.daemon.mode) {
        (DaemonMode::Rootless, DaemonMode::Rootless) => "rootless_observed",
        (DaemonMode::Rootful, DaemonMode::Rootful) => "rootful_observed",
        (DaemonMode::Rootful, DaemonMode::Unknown) => "unknown_with_independent_rootful_context",
        _ => panic!("nonconflicting supplementary captured mode"),
    };
    let mut seen = BTreeSet::new();
    for container in &decoded.containers {
        let native = container
            .id
            .value()
            .unwrap_or_else(|| panic!("decoded supplementary ID"))
            .as_bytes();
        let index = run
            .ids
            .iter()
            .position(|id| id.as_ref().unwrap().as_bytes() == native)
            .unwrap_or_else(|| panic!("exact selected supplementary ID"));
        let groups = &container.runtime.supplementary_groups;
        assert!(
            seen.insert(index)
                && container.id.availability == Availability::Present
                && container.id.origin == Origin::RuntimeAssigned
                && groups.origin == Origin::Effective
                && groups.availability == states[index].availability(),
            "truthful decoded supplementary availability"
        );
        if let Some(values) = groups.value() {
            let expected: Vec<_> = CASES[index / 2].1.iter().map(u32::to_string).collect();
            assert!(
                values
                    .iter()
                    .map(|value| value.as_bytes())
                    .eq(expected.iter().map(String::as_bytes)),
                "decoded supplementary group bytes agree"
            );
        } else {
            assert!(
                CASES[index / 2].1.is_empty()
                    && matches!(states[index], GroupState::Missing | GroupState::Null),
                "only unavailable omission lacks group value"
            );
        }
        assert!(
            container.user.availability == Availability::Present
                && container.user.origin == Origin::Effective
                && container
                    .user
                    .value()
                    .is_some_and(|value| value.as_bytes() == b"12345:3456"),
            "decoded explicit nonroot user"
        );
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
        "bounded supplementary capture bodies"
    );
    json!({"selected_ids":6,"route":"explicit_unix_socket","api":format!("{}.{}",api.major,api.minor),"daemon_mode_evidence":mode,
        "reserved_calls":16,"reserved_body_bytes":BODY_ALLOWANCE,"actual_requests":capture.exchanges().len(),"actual_body_bytes":body_bytes,
        "decoded":"effective_user_and_groupadd_agree","byte_scope":"decoded_response_bodies_only",
        "limits":{"max_requests":16,"max_selected_resources":6,"max_expansions":8,"max_response_bytes":131072,"max_total_body_bytes":BODY_ALLOWANCE,"max_elapsed_seconds":10},
        "separate_transport_bounds":{"response_header_bytes":16384,"chunk_line_bytes":64,"chunk_payload_crlf_bytes":2,"final_trailer_line_bytes":16384,"actual_wire_bytes":"not_measured"}})
}

#[test]
#[ignore = "unregistered source preparation; requires exact disposable native harness"]
fn live_supplementary_groups_match_engine() {
    let started = Instant::now();
    let target = ProofTarget::new_for("NATIVE_SUPPLEMENTARY_GROUPS_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_SUPPLEMENTARY_GROUPS_CANDIDATE_SHA",
        "NATIVE_SUPPLEMENTARY_GROUPS_DEADLINE_EPOCH",
    );
    run.names = CASES
        .into_iter()
        .flat_map(|(case, _)| {
            ["oracle", "rendered"].map(|role| format!("dl-sg-{}-{case}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 6];
    run.attempted = vec![false; 6];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: supplementary_groups_context");
        let outer = owner.snapshot.clone();
        let daemon_uid = run.context();
        let image = image_snapshot(&run);
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
            Capability::ContainerUser,
            Capability::SupplementaryGroups,
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
        eprintln!("DOCKERLENS_NATIVE_CHECK: supplementary_groups_effects");
        for (case, (name, groups)) in CASES.into_iter().enumerate() {
            let mut containers = Vec::new();
            for (offset, role) in ["oracle", "rendered"].into_iter().enumerate() {
                let index = case * 2 + offset;
                create_group_fixture(&mut run, index);
                start(&run, index);
                let state = configured_groups(&run, index, &image);
                let observed = effect(&run, index);
                assert!(
                    configured_groups(&run, index, &image) == state,
                    "stable supplementary configuration and live worker"
                );
                states.push(state);
                containers.push(json!({"role":role,"id":run.ids[index],"name":run.names[index],"owner":run.run,"image_id":image["id"],
                    "wire":if offset==0 {"independent_cli"} else {"literal_rendered"},"configured_availability":state.name(),"effect":observed,
                    "running_after":true,"restart_count":0,"oom_killed":false,"cleanup":"absent"}));
            }
            cases.push(json!({"case":name,"authored_groups":groups,"containers":containers}));
        }
        eprintln!("DOCKERLENS_NATIVE_CHECK: supplementary_groups_capture");
        let captured = acquisition(&run, &states);
        (outer, daemon_uid, image, cases, captured)
    }));
    let before_calls = run.calls.get();
    let before_bytes = run.bytes.get();
    let cleanup_started = Instant::now();
    eprintln!("DOCKERLENS_NATIVE_CHECK: supplementary_groups_cleanup");
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cleanup(&mut run)))
        .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_calls = run.calls.get() - before_calls;
    let cleanup_bytes = run.bytes.get() - before_bytes;
    terminal_cleanup(&mut run, &owner, disposition);
    let (outer, daemon_uid, image, cases, captured) = require_verified_result(result, disposition);
    assert!(
        !run.image_attempted
            && run.derived_id.is_none()
            && image_snapshot(&run) == image
            && outer_context(&run) == outer,
        "unchanged borrowed image and outer"
    );
    let ordinary_calls = run.calls.get() - cleanup_calls;
    let ordinary_bytes = run.bytes.get() - cleanup_bytes;
    let ordinary_elapsed = started.elapsed().saturating_sub(cleanup_elapsed);
    assert!(
        ordinary_calls
            == if run.lane.starts_with("debian11-") {
                75
            } else {
                74
            }
            && ordinary_bytes <= MAX_BYTES - CLEANUP_BYTES
            && cleanup_calls == 54
            && cleanup_bytes <= 54 * (8192 + 2048),
        "closed supplementary accounting"
    );
    assert!(
        ordinary_elapsed <= Duration::from_secs(134)
            && cleanup_elapsed <= Duration::from_secs(46)
            && started.elapsed() <= Duration::from_secs(180),
        "original supplementary deadline"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"scope":"numeric_nonroot_omitted_one_pair_dac_only","capability_admission":[],"catalogue_admission":false,
        "context":{"candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,"rendering_api":run.api,
            "acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},"mode":if run.mode==DaemonMode::Rootless {"rootless"} else {"rootful"},
            "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},"fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"cases":cases,"acquisition":captured,
        "accounting":{"ordinary_calls":ordinary_calls,"ordinary_bytes":ordinary_bytes,"cleanup_calls":cleanup_calls,"cleanup_bytes":cleanup_bytes,
            "ordinary_elapsed_ns":ordinary_elapsed.as_nanos(),"cleanup_elapsed_ns":cleanup_elapsed.as_nanos(),"elapsed_ns":started.elapsed().as_nanos(),
            "deadline_seconds":180,"cleanup_reserve_seconds":46,"initial_context_acquisition":{"max_requests":16,"max_body_bytes":2097152,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"}},
        "cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: supplementary_groups_proof");
    target.publish(&proof);
}

#[test]
fn supplementary_worker_receipt_rejects_partial_duplicate_and_noncanonical_fields() {
    assert!(words(b"pid 1\n").is_none());
    assert!(words(b"pid 1\npid 1\n").is_none());
    for text in ["", "+1", "01", "-1", "1.0", "4294967296"] {
        assert!(decimal(text).is_none());
    }
    assert!(decimal("23456") == Some(23456));
}
