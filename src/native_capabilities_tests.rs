//! Eleven named-capability controls: CLI causality and unmodified artifact retention.
use super::*;
use crate::target::ContainerToken;
use crate::version::{EngineRelease, ObservationId};
use sha2::{Digest, Sha256};

const CONTRACT: &str = "named-capabilities-v1";
const FILENAME: &str = "named-capabilities-v1.json";
const ROLES: [&str; 11] = [
    "default-cli",
    "add-cli",
    "add-rendered",
    "drop-cli",
    "drop-rendered",
    "both-cli",
    "both-rendered",
    "drop-all-cli",
    "netbind-only-cli",
    "all-cli",
    "all-minus-sysadmin-cli",
];
const SMALL: usize = 8192;
const FULL: usize = 65550 + 8192;
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";
// Direct idle PID1, no shell wrapper/init. Exceeds the once-bound test deadline.
const COMMAND: [&str; 2] = ["sleep", "180"];
const PROJECTION: &str = r#"{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"config_image":{{json .Config.Image}},"owner":{{json (index .Config.Labels "io.dockerlens.native-run")}},"hostname":{{json .Config.Hostname}},"cmd":{{json .Config.Cmd}},"entrypoint":{{json .Config.Entrypoint}},"user":{{json .Config.User}},"init":{{json .HostConfig.Init}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"started_at":{{json .State.StartedAt}},"finished_at":{{json .State.FinishedAt}},"oom":{{json .State.OOMKilled}},"exit":{{json .State.ExitCode}},"status":{{json .State.Status}},"restarts":{{json .RestartCount}},"error":{{json .State.Error}},"restarting":{{json .State.Restarting}},"paused":{{json .State.Paused}},"dead":{{json .State.Dead}},"privileged":{{json .HostConfig.Privileged}},"cap_add":{{json .HostConfig.CapAdd}},"cap_drop":{{json .HostConfig.CapDrop}},"mounts":{{json .Mounts}},"devices":{{json .HostConfig.Devices}},"ports":{{json .HostConfig.PortBindings}}}"#;
// Regular, API-pinned exec, namespace-local root only. The held proc directory
// is checked against current PID1 before/after; read target status, never self.
const OBSERVE: &str = r#"set -eu; LC_ALL=C; export LC_ALL
exec 3</proc/1
p=/proc/$$/fd/3
sample() {
  test "$p" -ef /proc/1
  test "$(cat "$p/comm")" = sleep
  s=$(cat "$p/stat"); test "${s%% *}" = 1
  s=${s##*) }; start=$(printf '%s\n' "$s" | awk '{print $20}')
  ns=$(readlink "$p/ns/user"); own=$(readlink /proc/self/ns/user)
  test "$ns" = "$own"
  printf '%s 1 %s ' "$1" "$start"; stat -L -c '%d %i' "$p" | tr '\n' ' '
  printf '%s %s held_current_pid1 sleep\n' "$ns" "$own"
  awk '$1=="Uid:" {print "uid",$2,$3,$4,$5} $1=="CapInh:" {print "CapInh",$2} $1=="CapPrm:" {print "CapPrm",$2} $1=="CapEff:" {print "CapEff",$2} $1=="CapBnd:" {print "CapBnd",$2} $1=="CapAmb:" {print "CapAmb",$2}' "$p/status"
  test "$p" -ef /proc/1
}
printf 'named-capabilities-v1\nhostname '; cat /proc/sys/kernel/hostname
sample before; sample after
exec 3<&-"#;

#[derive(Default)]
struct SmallMeter {
    calls: Cell<usize>,
    bytes: Cell<usize>,
}
fn small<T>(run: &HealthRun, meter: &SmallMeter, action: impl FnOnce() -> T) -> T {
    let calls = run.calls.get();
    let bytes = run.bytes.get();
    let value = action();
    let delta = run.bytes.get().checked_sub(bytes).unwrap();
    assert!(
        run.calls.get() == calls + 1 && delta <= SMALL,
        "combined actual small capture allowance"
    );
    meter.calls.set(meter.calls.get() + 1);
    meter.bytes.set(meter.bytes.get() + delta);
    value
}
fn cap_lists(index: usize) -> (&'static [&'static str], &'static [&'static str]) {
    match index {
        0 => (&[], &[]),
        1 | 2 => (&["NET_BIND_SERVICE"], &[]),
        3 | 4 => (&[], &["SYS_ADMIN"]),
        5 | 6 => (&["NET_BIND_SERVICE"], &["SYS_ADMIN"]),
        7 => (&[], &["ALL"]),
        8 => (&["NET_BIND_SERVICE"], &["ALL"]),
        9 => (&["ALL"], &[]),
        10 => (&["ALL"], &["SYS_ADMIN"]),
        _ => panic!("closed capabilities role"),
    }
}
fn rendered(index: usize) -> bool {
    matches!(index, 2 | 4 | 6)
}
fn intent(
    name: &str,
    image: &str,
    owner: &str,
    add: &[&str],
    drop: &[&str],
) -> Result<TargetIntent, crate::target::IntentError> {
    let token = |v: &&str| ContainerToken::new(v.as_bytes().to_vec()).unwrap();
    TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(name.as_bytes().to_vec()).unwrap(),
        image: ImageReference::new(image.as_bytes().to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Exec(
            COMMAND
                .map(|v| Argument::new(v.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), owner.as_bytes().to_vec()).unwrap(),
            ],
            cap_add: add.iter().map(token).collect(),
            cap_drop: drop.iter().map(token).collect(),
            ..ContainerSettings::default()
        },
    }))])
}
fn authored(run: &HealthRun, index: usize) -> Value {
    assert!(rendered(index), "only three product shapes");
    let (add, drop) = cap_lists(index);
    let intent = intent(&run.names[index], &run.base, &run.run, add, drop).unwrap();
    let graph = DockerPlanner
        .plan(
            &intent,
            &ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
    let request: Value =
        serde_json::from_slice(DockerApiRenderer.render(&graph).unwrap().bytes()).unwrap();
    // Independently authored full request literals: neither ALL nor an empty
    // opposite field can be injected to create an artifact causal transition.
    let host = match index {
        2 => json!({"CapAdd":["NET_BIND_SERVICE"]}),
        4 => json!({"CapDrop":["SYS_ADMIN"]}),
        6 => json!({"CapAdd":["NET_BIND_SERVICE"],"CapDrop":["SYS_ADMIN"]}),
        _ => unreachable!(),
    };
    assert!(
        request
            == json!({"method":"POST","path":format!("/v{}/containers/create?name={}", run.api, run.names[index]),"body":{"Image":run.base,"Cmd":["sleep","180"],"Labels":{(OWNER):run.run},"HostConfig":host}}),
        "independent complete named-capability request literal"
    );
    request
}
fn projection(run: &HealthRun, meter: &SmallMeter, key: &str) -> Value {
    let bytes = small(run, meter, || {
        docker(
            run,
            &[
                "inspect".into(),
                "--format".into(),
                PROJECTION.into(),
                key.into(),
            ],
        )
    });
    assert!(bytes.len() <= 4096, "bounded capability inspect projection");
    serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("closed capability inspect JSON"))
}
fn retained(value: &Value, expected: &[&str]) -> bool {
    if expected.is_empty() {
        value.is_null() || value == &json!([])
    } else {
        value == &json!(expected)
            || expected[0] != "ALL" && value == &json!([format!("CAP_{}", expected[0])])
    }
}
fn check_config(run: &HealthRun, index: usize, image: &Value, v: &Value, live: bool) {
    let (add, drop) = cap_lists(index);
    assert!(
        v["id"] == run.ids[index].as_ref().unwrap().as_str()
            && v["name"] == format!("/{}", run.names[index])
            && v["image"] == image["id"]
            && v["config_image"] == run.base
            && v["owner"] == run.run
            && v["hostname"] == run.ids[index].as_ref().unwrap()[..12]
            && v["cmd"] == json!(COMMAND)
            && (v["entrypoint"].is_null() || v["entrypoint"] == json!([]))
            && matches!(v["user"].as_str(), Some("" | "0" | "0:0"))
            && (v["init"].is_null() || v["init"] == false)
            && v["privileged"] == false
            && v["mounts"] == json!([])
            && (v["devices"].is_null() || v["devices"] == json!([]))
            && (v["ports"].is_null() || v["ports"] == json!({}))
            && retained(&v["cap_add"], add)
            && retained(&v["cap_drop"], drop)
            && v["running"] == live
            && v["restarts"] == 0
            && v["oom"] == false
            && v["exit"] == 0
            && v["error"] == ""
            && v["restarting"] == false
            && v["paused"] == false
            && v["dead"] == false
            && v["finished_at"] == ZERO_TIME,
        "owned exact named capabilities and process disposition"
    );
    if live {
        assert!(
            v["status"] == "running"
                && v["pid"].as_u64().is_some_and(|n| n > 0)
                && v["started_at"].as_str().and_then(timestamp_ns).is_some(),
            "live capability PID and start"
        );
    } else {
        assert!(
            v["status"] == "created" && v["pid"] == 0 && v["started_at"] == ZERO_TIME,
            "unstarted capability container"
        );
    }
}
fn create_capabilities(run: &mut HealthRun, meter: &SmallMeter, index: usize) {
    assert!(
        small(run, meter, || run.inspect(&run.names[index], false)).0 == 404,
        "fresh capability name"
    );
    let request = rendered(index).then(|| authored(run, index));
    run.attempted[index] = true;
    let id = if let Some(request) = request {
        let (status, value) = small(run, meter, || {
            run.api(
                "POST",
                request["path"].as_str().unwrap(),
                Some(&request["body"]),
                false,
            )
        });
        assert!(
            status == 201 && (value["Warnings"].is_null() || value["Warnings"] == json!([])),
            "known capability API create"
        );
        value["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical capability API ID"))
            .to_owned()
    } else {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
        ];
        let (add, drop) = cap_lists(index);
        // In add-back control drop ALL is an oracle precondition, then named add.
        if index == 8 {
            args.extend(["--cap-drop=ALL".into(), "--cap-add=NET_BIND_SERVICE".into()]);
        } else {
            for v in add {
                args.push(format!("--cap-add={v}"));
            }
            for v in drop {
                args.push(format!("--cap-drop={v}"));
            }
        }
        args.push(run.base.clone());
        args.extend(COMMAND.map(String::from));
        let bytes = small(run, meter, || docker(run, &args));
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed capability CLI ID"))
            .to_owned()
    };
    assert!(identifier(&id), "canonical capability create ID");
    // Never use the full shared bind while charging a small allowance.
    let v = projection(run, meter, &run.names[index]);
    assert!(
        v["id"] == id
            && v["name"] == format!("/{}", run.names[index])
            && v["owner"] == run.run
            && v["config_image"] == run.base
            && run.ids.iter().flatten().all(|other| other != &id)
            && id != required("NATIVE_OUTER_CONTAINER_ID"),
        "canonical unique owned capability binding"
    );
    run.ids[index] = Some(id);
}
fn decimal(text: &str, positive: bool) -> u64 {
    assert!(
        !text.is_empty() && text.len() <= 20 && text.bytes().all(|b| b.is_ascii_digit()),
        "bounded decimal proc identity"
    );
    let n: u64 = text
        .parse()
        .unwrap_or_else(|_| panic!("bounded decimal proc identity"));
    assert!(
        n.to_string() == text && (!positive || n > 0),
        "canonical proc identity"
    );
    n
}
fn mask(text: &str) -> u64 {
    assert!(
        text.len() == 16
            && text
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "closed u64 capability hex mask"
    );
    u64::from_str_radix(text, 16).unwrap_or_else(|_| panic!("bounded capability mask"))
}
fn witness(bytes: &[u8], id: &str) -> (Value, u64) {
    assert!(
        !bytes.is_empty() && bytes.len() <= 4096,
        "bounded capability report"
    );
    let text = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("capability report UTF8"));
    let rows: Vec<Vec<_>> = text.lines().map(|line| line.split(' ').collect()).collect();
    assert!(
        text.ends_with('\n')
            && rows.len() == 16
            && rows[0] == [CONTRACT]
            && rows[1] == ["hostname", &id[..12]],
        "closed capability report rows"
    );
    let mut samples = Vec::new();
    for (offset, phase) in [(2, "before"), (9, "after")] {
        let id = &rows[offset];
        assert!(
            id.len() == 9
                && id[0] == phase
                && id[1] == "1"
                && id[7..] == ["held_current_pid1", "sleep"],
            "held direct PID1 identity"
        );
        decimal(id[2], true);
        decimal(id[3], false);
        decimal(id[4], true);
        let ns = id[5]
            .strip_prefix("user:[")
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or_else(|| panic!("user namespace identity"));
        decimal(ns, true);
        assert!(
            id[5] == id[6] && rows[offset + 1] == ["uid", "0", "0", "0", "0"],
            "namespace-local root context"
        );
        let masks: Vec<u64> = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let row = &rows[offset + 2 + i];
                assert!(
                    row.len() == 2 && row[0] == *key,
                    "closed unique capability field"
                );
                mask(row[1])
            })
            .collect();
        assert!(
            masks[2] & !masks[1] == 0 && masks[2] & !masks[3] == 0,
            "effective capability context"
        );
        samples.push((id[1..].to_vec(), masks));
    }
    assert!(
        samples[0] == samples[1],
        "identity and all mask context stable across held observation"
    );
    let digest: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    (json!({"raw":text,"sha256":digest}), samples[0].1[2])
}
fn comparisons(masks: &[u64]) {
    assert!(masks.len() == 11, "all eleven capability controls");
    let d = masks[0];
    let a = masks[9];
    assert!(
        d & 1024 == 1024 && d & 2097152 == 0 && masks[1..7] == [d; 6],
        "measured defaults and all unmodified artifact/CLI pairs"
    );
    assert!(
        masks[7] == 0 && masks[8] == 1024 && a & 2097152 == 2097152 && masks[10] == a & !2097152,
        "independent zero/addback and ALL/minus causal CLI oracles"
    );
}
fn capabilities_cleanup_with(
    attempted: &[bool],
    ids: &[Option<String>],
    inner: impl FnOnce() -> CleanupDisposition,
) -> CleanupDisposition {
    if attempted.len() != 11
        || ids.len() != 11
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
#[ignore = "requires isolated explicitly selected native Engine"]
fn live_named_capabilities_match_engine() {
    let backend = source_outer_backend();
    let started = Instant::now();
    let target = ProofTarget::new_for("NATIVE_CAPABILITIES_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_CAPABILITIES_CANDIDATE_SHA",
        "NATIVE_CAPABILITIES_DEADLINE_EPOCH",
    );
    run.names = ROLES
        .iter()
        .map(|role| format!("dl-cap-{}-{role}", run.run))
        .collect();
    run.ids = vec![None; 11];
    run.attempted = vec![false; 11];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let meter = SmallMeter::default();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: capabilities_context");
        let uid = run.context();
        let image = image_snapshot(&run);
        assert!(
            (image["config"]["Volumes"].is_null() || image["config"]["Volumes"] == json!({}))
                && (image["config"]["Entrypoint"].is_null()
                    || image["config"]["Entrypoint"] == json!([]))
                && matches!(image["config"]["User"].as_str(), Some("" | "0" | "0:0")),
            "borrowed image has no volumes, wrapper or altered UID"
        );
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::LinuxCapabilities,
            Capability::CapAddNetBindService,
            Capability::CapDropSysAdmin,
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
                    9
                } else {
                    8
                }) + backend.snapshot_extra_calls(),
            "closed capability context accounting"
        );
        let pending = 88 * SMALL + 3 * FULL + backend.snapshot_extra_bytes();
        assert!(
            run.bytes
                .get()
                .checked_add(pending)
                .is_some_and(|n| n <= MAX_BYTES - CLEANUP_BYTES)
                && context_calls + 91 + backend.snapshot_extra_calls() <= MAX_CALLS - CLEANUP_CALLS
                && 99 <= CLEANUP_CALLS
                && 99 * (8192 + 2048) <= CLEANUP_BYTES,
            "pre-reserved capability observations, final reads and 99 cleanup calls"
        );
        eprintln!("DOCKERLENS_NATIVE_CHECK: capabilities_effects");
        let mut records = Vec::new();
        let mut masks = Vec::new();
        for (index, role) in ROLES.iter().enumerate() {
            let calls = run.calls.get();
            create_capabilities(&mut run, &meter, index);
            let id = run.ids[index].as_ref().unwrap().clone();
            let created = projection(&run, &meter, &id);
            check_config(&run, index, &image, &created, false);
            if rendered(index) {
                assert!(
                    small(&run, &meter, || run.api(
                        "POST",
                        &format!("/v{}/containers/{id}/start", run.api),
                        None,
                        false
                    ))
                    .0 == 204,
                    "capability API start"
                );
            } else {
                let bytes = small(&run, &meter, || docker(&run, &["start".into(), id.clone()]));
                assert!(
                    bytes == format!("{id}\n").as_bytes(),
                    "exact capability CLI start ID"
                );
            }
            let current = projection(&run, &meter, &id);
            check_config(&run, index, &image, &current, true);
            let bytes = small(&run, &meter, || {
                docker(
                    &run,
                    &[
                        "exec".into(),
                        "--user".into(),
                        "0:0".into(),
                        id.clone(),
                        "sh".into(),
                        "-c".into(),
                        OBSERVE.into(),
                    ],
                )
            });
            let (effect, mask) = witness(&bytes, &id);
            masks.push(mask);
            let after = projection(&run, &meter, run.ids[index].as_ref().unwrap());
            check_config(&run, index, &image, &after, true);
            assert!(
                current == after && run.calls.get() - calls == 8,
                "stable running PID/start and exact eight-call capability slot"
            );
            records.push(json!({"role":role,"id":run.ids[index],"name":run.names[index],"owner":run.run,"wire":if rendered(index){"literal_rendered"}else{"independent_cli"},"created":created,"running":current,"after":after,"effect":effect,"cleanup":"absent"}));
        }
        comparisons(&masks);
        assert!(
            run.api("GET", "/version", None, false).1["Version"] == run.engine,
            "post-capability daemon health"
        );
        assert!(
            backend.final_snapshot_room(run.calls.get(), run.bytes.get(), 2),
            "pending final capability readback reserve"
        );
        (uid, image, records, context_calls)
    }));
    let work_elapsed = started.elapsed();
    let before_calls = run.calls.get();
    let before_bytes = run.bytes.get();
    let cleanup_started = Instant::now();
    eprintln!("DOCKERLENS_NATIVE_CHECK: capabilities_cleanup");
    let attempted = run.attempted.clone();
    let ids = run.ids.clone();
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        capabilities_cleanup_with(&attempted, &ids, || cleanup(&mut run))
    }))
    .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_calls = run.calls.get() - before_calls;
    let cleanup_bytes = run.bytes.get() - before_bytes;
    terminal_cleanup(&mut run, &owner, disposition);
    let (uid, image, records, context_calls) = require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none() && image_snapshot(&run) == image,
        "borrowed capability image unchanged and never removed"
    );
    let outer = outer_context(&run);
    assert!(
        outer == owner.snapshot,
        "same authenticated capability outer"
    );
    let ordinary_calls = run.calls.get() - cleanup_calls;
    let ordinary_bytes = run.bytes.get() - cleanup_bytes;
    let ordinary_elapsed = started.elapsed().saturating_sub(cleanup_elapsed);
    let final_calls = 2 + backend.snapshot_extra_calls();
    let full = if run.lane.starts_with("debian11-") {
        12
    } else {
        11
    };
    assert!(
        ordinary_calls == context_calls + 89 + final_calls
            && meter.calls.get() == 88
            && meter.bytes.get() <= 88 * SMALL
            && ordinary_bytes >= meter.bytes.get() + 2 * backend.snapshot_extra_bytes()
            && ordinary_bytes <= full * FULL + 88 * SMALL + 2 * backend.snapshot_extra_bytes()
            && ordinary_bytes <= MAX_BYTES - CLEANUP_BYTES
            && cleanup_calls == 99
            && cleanup_bytes <= 99 * (8192 + 2048),
        "closed actual capability accounting"
    );
    assert!(
        work_elapsed <= Duration::from_secs(134)
            && ordinary_elapsed <= Duration::from_secs(134)
            && cleanup_elapsed <= Duration::from_secs(46)
            && started.elapsed() <= Duration::from_secs(180),
        "unchanged capability deadline and cleanup reserve"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"capability_admission":[],"catalogue_admission":false,"scope":"cli_causal_transitions_and_rendered_retention_namespace_local","normalization":"four_profiles_named_optional_CAP_prefix_ALL_literal","outer_backend":if matches!(backend,SourceOuterBackend::Docker){"docker"}else{"podman"},
        "context":{"candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,"rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-"){"1.41"}else{"1.49"},"mode":if run.mode==DaemonMode::Rootless{"rootless"}else{"rootful"},"docker_package":if run.lane.starts_with("debian11-"){"20.10.5+dfsg1-1+deb11u2"}else{""},"fixture_image":run.base,"daemon_uid":uid,"outer":outer},
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"containers":records,"daemon_health":"version_matches_after_controls",
        "accounting":{"context_calls":context_calls,"slot_calls":vec![8;11],"daemon_health_calls":1,"final_readback_calls":final_calls,"ordinary_calls":ordinary_calls,"ordinary_bytes":ordinary_bytes,"small_calls":meter.calls.get(),"small_bytes":meter.bytes.get(),"cleanup_calls":cleanup_calls,"cleanup_bytes":cleanup_bytes,"deadline_seconds":180,"cleanup_reserve_seconds":46,"ordinary_elapsed_ns":ordinary_elapsed.as_nanos(),"cleanup_elapsed_ns":cleanup_elapsed.as_nanos(),"elapsed_ns":started.elapsed().as_nanos(),"initial_context_acquisition":{"max_requests":16,"max_total_bytes":2097152,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"}},"cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: capabilities_proof");
    target.publish_bounded(&proof, 65536);
}

#[test]
fn unknown_capability_create_never_enters_name_cleanup() {
    for slot in 0..11 {
        let mut attempted = vec![false; 11];
        attempted[slot] = true;
        let ids = vec![None; 11];
        let entered = Cell::new(false);
        assert!(
            capabilities_cleanup_with(&attempted, &ids, || {
                entered.set(true);
                CleanupDisposition::VerifiedAbsent
            }) == CleanupDisposition::OuterTeardownRequired
                && !entered.get()
        );
    }
}
#[test]
fn named_capability_shapes_require_each_fact_in_all_four_profiles() {
    for minor in [41, 56] {
        for mode in [DaemonMode::Rootful, DaemonMode::Rootless] {
            for index in [2, 4, 6] {
                let (add, drop) = cap_lists(index);
                let intent =
                    intent("capability-test", "busybox-fixture", "Run12345", add, drop).unwrap();
                let observation_id = ObservationId::fresh().unwrap();
                let release = EngineRelease::new(
                    if minor == 41 {
                        "20.10.5+dfsg1"
                    } else {
                        "29.8.1"
                    }
                    .into(),
                )
                .unwrap();
                let api_version = ApiVersion::new(NonZeroU16::new(1).unwrap(), minor);
                let scope = CapabilityScope {
                    observation_id,
                    release: release.clone(),
                    api_version,
                    mode,
                };
                let mut required = vec![
                    Capability::StandaloneContainer,
                    Capability::Command,
                    Capability::ContainerLabels,
                    Capability::LinuxCapabilities,
                ];
                if !add.is_empty() {
                    required.push(Capability::CapAddNetBindService);
                }
                if !drop.is_empty() {
                    required.push(Capability::CapDropSysAdmin);
                }
                let facts = DaemonFacts {
                    observation_id,
                    release: Some(release),
                    api_version: Some(api_version),
                    minimum_api_version: None,
                    mode,
                    capabilities: required
                        .iter()
                        .map(|&capability| CapabilityFact {
                            capability,
                            state: CapabilityState::Available,
                            provenance: FactProvenance::NativeConformance,
                            scope: Some(scope.clone()),
                        })
                        .collect(),
                };
                let graph = DockerPlanner
                    .plan(&intent, &ValidatedCapabilities::new(&facts).unwrap())
                    .unwrap();
                let request: Value =
                    serde_json::from_slice(DockerApiRenderer.render(&graph).unwrap().bytes())
                        .unwrap();
                let host = match index {
                    2 => json!({"CapAdd":["NET_BIND_SERVICE"]}),
                    4 => json!({"CapDrop":["SYS_ADMIN"]}),
                    6 => json!({"CapAdd":["NET_BIND_SERVICE"],"CapDrop":["SYS_ADMIN"]}),
                    _ => unreachable!(),
                };
                assert!(
                    request
                        == json!({"method":"POST","path":format!("/v1.{minor}/containers/create?name=capability-test"),"body":{"Image":"busybox-fixture","Cmd":["sleep","180"],"Labels":{(OWNER):"Run12345"},"HostConfig":host}})
                );
                for missing in required {
                    let mut absent = facts.clone();
                    absent.capabilities.retain(|f| f.capability != missing);
                    assert!(
                        DockerPlanner
                            .plan(&intent, &ValidatedCapabilities::new(&absent).unwrap())
                            .is_err()
                    );
                }
            }
        }
    }
}
#[test]
fn named_capability_vocabulary_rejects_oracle_only_and_duplicate_inputs() {
    for (add, drop) in [
        (vec!["ALL"], vec![]),
        (vec![], vec!["ALL"]),
        (vec!["SYS_ADMIN"], vec![]),
        (vec![], vec!["NET_BIND_SERVICE"]),
        (vec!["NET_BIND_SERVICE", "NET_BIND_SERVICE"], vec![]),
        (vec![], vec!["SYS_ADMIN", "SYS_ADMIN"]),
        (vec!["NET_BIND_SERVICE"], vec!["NET_BIND_SERVICE"]),
    ] {
        assert!(intent("invalid", "busybox-fixture", "Run12345", &add, &drop).is_err());
    }
}
#[test]
fn capability_mask_parser_and_comparisons_reject_false_causality() {
    let masks = [
        1024, 1024, 1024, 1024, 1024, 1024, 1024, 0, 1024, 2098176, 1024,
    ];
    comparisons(&masks);
    for (i, value) in [
        (0, 0),
        (0, 2098176),
        (1, 0),
        (2, 1025),
        (4, 0),
        (6, 0),
        (7, 1024),
        (8, 0),
        (8, 1025),
        (9, 1024),
        (10, 0),
        (10, 2098176),
    ] {
        let mut wrong = masks;
        wrong[i] = value;
        assert!(std::panic::catch_unwind(|| comparisons(&wrong)).is_err());
    }
    assert!(mask("ffffffffffffffff") == u64::MAX);
    for text in [
        "",
        "0",
        "0x0000000000000400",
        "0000000000000400 ",
        "00000000000004000",
        "0000000000000A00",
        "0000000000000g00",
    ] {
        assert!(std::panic::catch_unwind(|| mask(text)).is_err());
    }
}
