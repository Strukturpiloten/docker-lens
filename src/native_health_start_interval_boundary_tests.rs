//! Omitted/zero health representation only; no scheduler effect or admission.
//!
//! This child borrows lifecycle's authenticated outer owner, finite removal and
//! terminal handoff. It never starts a container or owns an image. Every inner
//! mutation is attempted once; uncertainty goes directly to outer teardown.

use super::*;

const CONTRACT: &str = "health-start-interval-boundary-v1";
const FILENAME: &str = "health-start-interval-boundary-v1.json";
const HEALTH_COMMAND: &str = "exit 1";
const PROCESS: &str = "exit 0";
const CASES: [&str; 2] = ["omitted", "zero"];
// Primary's pinned Debian parser-only observation on 2026-10-11:
// /tmp/dockerlens114-cli-signature-20261011.py. Exit125, empty stdout, exact
// stderr. Envelope keeps stdout/stderr distinct and retains trailing newlines.
// This observation does not replace four-lane native source qualification.
const LEGACY_CLIENT_REJECTION: &[u8] = b"stdout\n\x01stderr\nunknown flag: --health-start-interval\nSee 'docker create --help'.\n\x01status=125\n";

#[derive(PartialEq, Eq)]
enum IntervalState {
    Absent,
    Null,
    PresentZero,
    PresentPositive(u64),
    WrongType,
}

#[derive(PartialEq, Eq)]
enum ParentFailure {
    InspectWrongType,
    ConfigAbsent,
    ConfigNull,
    ConfigWrongType,
    HealthcheckAbsent,
    HealthcheckNull,
    HealthcheckWrongType,
}

fn interval_state(value: &Value) -> Result<IntervalState, ParentFailure> {
    let inspect = value.as_object().ok_or(ParentFailure::InspectWrongType)?;
    let config = match inspect.get("Config") {
        None => return Err(ParentFailure::ConfigAbsent),
        Some(Value::Null) => return Err(ParentFailure::ConfigNull),
        Some(config) => config.as_object().ok_or(ParentFailure::ConfigWrongType)?,
    };
    let health = match config.get("Healthcheck") {
        None => return Err(ParentFailure::HealthcheckAbsent),
        Some(Value::Null) => return Err(ParentFailure::HealthcheckNull),
        Some(health) => health
            .as_object()
            .ok_or(ParentFailure::HealthcheckWrongType)?,
    };
    Ok(match health.get("StartInterval") {
        None => IntervalState::Absent,
        Some(Value::Null) => IntervalState::Null,
        Some(value) => match value.as_u64() {
            Some(0) => IntervalState::PresentZero,
            Some(positive) => IntervalState::PresentPositive(positive),
            None => IntervalState::WrongType,
        },
    })
}

enum ClientResult {
    Accepted(String),
    UnknownFlag(i32),
}

fn client_result(bytes: &[u8]) -> ClientResult {
    if let Some(id) = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.strip_prefix("stdout\n"))
        .and_then(|text| text.strip_suffix("\n\x01stderr\n\x01status=0\n"))
        .filter(|id| identifier(id))
    {
        return ClientResult::Accepted(id.to_owned());
    }
    if bytes == LEGACY_CLIENT_REJECTION {
        return ClientResult::UnknownFlag(125);
    }
    panic!("closed client create result");
}

fn expected_health() -> Value {
    json!({"Test":["CMD-SHELL",HEALTH_COMMAND],"Interval":8*SECOND,
        "Timeout":SECOND,"Retries":3,"StartPeriod":30*SECOND})
}

fn expected_state() -> Value {
    json!({"Status":"created","Running":false,"Pid":0,
        "StartedAt":"0001-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z",
        "OOMKilled":false,"Restarting":false,"Paused":false,"Dead":false,
        "ExitCode":0,"Error":""})
}

fn rendered_request(run: &HealthRun, index: usize) -> Value {
    let mut health = Healthcheck::configured(
        HealthTest::Shell(Argument::new(HEALTH_COMMAND.as_bytes().to_vec()).unwrap()),
        NonZeroU64::new(8 * SECOND),
        NonZeroU64::new(SECOND),
        NonZeroU32::new(3),
    )
    .and_then(|health| health.with_start_period(30 * SECOND))
    .unwrap_or_else(|_| panic!("typed boundary health"));
    if index / 2 == 1 {
        health = health
            .with_start_interval(0)
            .unwrap_or_else(|_| panic!("typed explicit zero interval"));
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
            ["sh", "-c", PROCESS]
                .map(|text| Argument::new(text.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck: Some(health),
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                    .unwrap(),
            ],
            ..ContainerSettings::default()
        },
    };
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
    let capabilities = ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap();
    let graph = DockerPlanner
        .plan(&intent, &capabilities)
        .unwrap_or_else(|_| panic!("test-local boundary planning"));
    let artifact = DockerApiRenderer
        .render(&graph)
        .unwrap_or_else(|_| panic!("test-local boundary rendering"));
    let request: Value = serde_json::from_slice(artifact.bytes())
        .unwrap_or_else(|_| panic!("one inert boundary request"));
    // Independently authored literal expectation, not inspect-derived intent.
    let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
    let mut literal_health = expected_health();
    if index / 2 == 1 {
        literal_health["StartInterval"] = json!(0);
    }
    let expected = json!({"method":"POST","path":path,"body":{"Image":run.base,
        "Cmd":["sh","-c",PROCESS],"Labels":{(OWNER):run.run},
        "Healthcheck":literal_health,"HostConfig":{}}});
    assert_eq!(request, expected);
    request
}

fn create(run: &mut HealthRun, index: usize) -> Option<i32> {
    assert_eq!(run.inspect(&run.names[index], false).0, 404);
    if index.is_multiple_of(2) {
        // A private shell envelope preserves exact command status/output while
        // the inherited outer transport still requires its own success. All
        // arguments are positional; native strings are never shell source.
        let mut command = vec!["sh".into(), "-c".into(),
            "export LC_ALL=C; printf 'stdout\\n'; { captured=$(\"$@\" 2>&1 >&3; status=$?; printf '\\001status=%s\\n' \"$status\"); printf '\\001stderr\\n%s\\n' \"$captured\"; } 3>&1".into(),
            "health-boundary-cli".into(), "env".into(), format!("DOCKER_API_VERSION={}",run.api),
            "docker".into(), "-H".into(), "unix:///dockerlens-native/docker.sock".into(),
            "create".into(), "--name".into(),run.names[index].clone(), "--label".into(),
            format!("{OWNER}={}",run.run), "--health-cmd".into(), "exit 1".into(),
            "--health-interval".into(), "8s".into(), "--health-timeout".into(), "1s".into(),
            "--health-retries".into(), "3".into(), "--health-start-period".into(), "30s".into()];
        if index / 2 == 1 {
            command.push("--health-start-interval=0s".into());
        }
        command.extend([run.base.clone(), "sh".into(), "-c".into(), "exit 0".into()]);
        run.attempted[index] = true;
        let output = run.outer(&command, false);
        match client_result(&output) {
            ClientResult::Accepted(id) => {
                assert!(
                    !(run.lane.starts_with("debian11-") && index == 2),
                    "legacy zero CLI unexpectedly accepted"
                );
                bind(run, index, &id);
                None
            }
            ClientResult::UnknownFlag(status) => {
                assert!(
                    run.lane.starts_with("debian11-") && index == 2,
                    "unexpected client rejection"
                );
                assert_eq!(run.inspect(&run.names[index], false).0, 404);
                Some(status)
            }
        }
    } else {
        let request = rendered_request(run, index);
        run.attempted[index] = true;
        let (status, value) = run.api(
            "POST",
            request["path"].as_str().unwrap(),
            Some(&request["body"]),
            false,
        );
        // Any server rejection refuses, never becomes a client refusal record.
        assert_eq!(status, 201);
        assert!(
            value["Warnings"].is_null() || value["Warnings"] == json!([]),
            "unambiguous literal request acceptance"
        );
        bind(
            run,
            index,
            value["Id"]
                .as_str()
                .unwrap_or_else(|| panic!("canonical API create ID")),
        );
        None
    }
}

fn observe(run: &mut HealthRun, index: usize, image: &Value) -> Value {
    let rejected = create(run, index);
    let cli = index.is_multiple_of(2);
    let mut record = json!({"role":if cli {"oracle"} else {"rendered"},
        "name":run.names[index],"owner":run.run,"image":run.base,
        "wire":if cli {"independent_cli"} else {"literal_rendered"},
        "request_intent":if index/2==0 {"omitted"} else {"explicit_zero"},
        "request_member":if cli {"not_observed"} else if index/2==0 {"absent"} else {"integer_zero"},
        "result":if rejected.is_some() {"client_unknown_flag"} else {"accepted"},
        "client_exit":if cli {Some(rejected.unwrap_or(0))} else {None},
        "server_status":if cli {None} else {Some(201)},
        "id":null,"image_id":null,"configured":null,"readback_state":null,
        "state":null,"restart_count":null,"cleanup":"absent"});
    if rejected.is_some() {
        assert!(
            run.ids[index].is_none(),
            "rejected client owns no created ID"
        );
        return record;
    }
    let id = run.ids[index].as_ref().unwrap().clone();
    let (status, value) = run.inspect(&id, false);
    assert_eq!(status, 200);
    assert!(
        owned(run, &value, index, Some(&id)),
        "exact created boundary identity"
    );
    assert_eq!(value["Image"], image["id"]);
    assert!(
        matches!(interval_state(&value), Ok(IntervalState::Absent)),
        "raw configured interval must be absent"
    );
    assert_eq!(value["Config"]["Healthcheck"], expected_health());
    assert_eq!(value["Config"]["Cmd"], json!(["sh", "-c", "exit 0"]));
    let expected = expected_state();
    let mut state = json!({});
    for field in expected.as_object().unwrap().keys() {
        state[field] = value["State"][field].clone();
    }
    assert_eq!(state, expected);
    assert_eq!(value["RestartCount"], 0);
    record["id"] = json!(id);
    record["image_id"] = value["Image"].clone();
    record["configured"] = json!({"Config":{"Healthcheck":value["Config"]["Healthcheck"]}});
    record["readback_state"] = json!("absent");
    record["state"] = state;
    record["restart_count"] = value["RestartCount"].clone();
    // One removal attempt, using original ID/name/owner and no image ownership.
    // A failed/uncertain removal unwinds; terminal handling never retries it.
    assert!(
        remove_container(run, index),
        "boundary removal must be verified"
    );
    record
}

fn terminal_absence(run: &HealthRun) -> bool {
    let rejected = run.lane.starts_with("debian11-");
    assert!(
        run.names.len() == 4 && run.ids.len() == 4 && run.attempted == [true; 4],
        "complete finite boundary ledger"
    );
    for _ in 0..2 {
        for index in 0..4 {
            match &run.ids[index] {
                Some(id) => {
                    assert!(!(rejected && index == 2), "refused slot has no ID");
                    if run.inspect(id, true).0 != 404 {
                        return false;
                    }
                }
                None => assert!(
                    rejected && index == 2,
                    "successful slot requires original ID"
                ),
            }
            if run.inspect(&run.names[index], true).0 != 404 {
                return false;
            }
        }
    }
    true
}

#[test]
#[ignore = "requires the isolated exact-profile native harness"]
fn live_health_start_interval_boundary_matches_engine() {
    let began = Instant::now();
    let target = ProofTarget::new_for("NATIVE_HEALTH_START_INTERVAL_BOUNDARY_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_HEALTH_START_INTERVAL_BOUNDARY_CANDIDATE_SHA",
        "NATIVE_HEALTH_START_INTERVAL_BOUNDARY_DEADLINE_EPOCH",
    );
    run.names = CASES
        .into_iter()
        .flat_map(|case| {
            ["oracle", "rendered"].map(|role| format!("dl-hsi-{}-{case}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 4];
    run.attempted = vec![false; 4];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: health_start_interval_boundary_context");
        let outer = owner.snapshot.clone();
        let daemon_uid = run.context();
        let image = image_snapshot(&run);
        assert!(
            image["config"]["Healthcheck"].is_null(),
            "borrowed fixture has no inherited health"
        );
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::HealthShell,
            Capability::HealthStartPeriod,
            Capability::HealthStartInterval,
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
        for (case, name) in CASES.into_iter().enumerate() {
            eprintln!("DOCKERLENS_NATIVE_CHECK: health_start_interval_boundary_configuration");
            let records = [
                observe(&mut run, 2 * case, &image),
                observe(&mut run, 2 * case + 1, &image),
            ];
            cases.push(json!({"case":name,"records":records}));
        }
        (outer, daemon_uid, image, cases)
    }));
    eprintln!("DOCKERLENS_NATIVE_CHECK: health_start_interval_boundary_cleanup");
    let disposition = if result.is_ok() {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cleanup_disposition(terminal_absence(&run))
        }))
        .unwrap_or(CleanupDisposition::OuterTeardownRequired)
    } else {
        // No second inner mutation after observation/create/removal uncertainty.
        CleanupDisposition::OuterTeardownRequired
    };
    terminal_cleanup(&mut run, &owner, disposition);
    let (outer, daemon_uid, image, cases) = require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none(),
        "borrowed image never owned"
    );
    assert_eq!(image_snapshot(&run), image);
    assert_eq!(outer_context(&run), outer);
    let elapsed = u64::try_from(began.elapsed().as_nanos()).unwrap();
    assert!(
        elapsed > 0 && elapsed <= 180 * SECOND,
        "original bounded invocation elapsed"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"context":{
        "candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,
        "rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},
        "mode":if run.mode==DaemonMode::Rootless {"rootless"} else {"rootful"},
        "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},
        "fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "admission":"unadmitted","scope":"created_configuration_only",
        "apis":{"fixture_cli":run.api,"renderer":run.api,"request":run.api,"health_probe":"test_local_unadmitted"},
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},
        "budget":{"limit_seconds":180,"cleanup_reserve_seconds":46,"elapsed_ns":elapsed},
        "cases":cases,"cleanup":{"containers":"absent","rounds":2,"ledger_slots":4,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: health_start_interval_boundary_evidence");
    target.publish(&proof);
}

#[test]
fn boundary_interval_states_preserve_presence_without_normalization() {
    assert!(matches!(
        interval_state(&json!({"Config":{"Healthcheck":{}}})),
        Ok(IntervalState::Absent)
    ));
    for (value, expected) in [
        (Value::Null, IntervalState::Null),
        (json!(0), IntervalState::PresentZero),
        (json!(1), IntervalState::PresentPositive(1)),
        (json!(u64::MAX), IntervalState::PresentPositive(u64::MAX)),
        (json!(false), IntervalState::WrongType),
        (json!(-1), IntervalState::WrongType),
        (json!(0.0), IntervalState::WrongType),
        (json!("PRIVATE_BOUNDARY_CANARY"), IntervalState::WrongType),
        (json!([]), IntervalState::WrongType),
        (json!({}), IntervalState::WrongType),
    ] {
        assert_eq!(
            interval_state(&json!({"Config":{"Healthcheck":{"StartInterval":value}}})),
            Ok(expected)
        );
    }
}

#[test]
fn boundary_parent_objects_have_distinct_negative_states() {
    for (value, expected) in [
        (json!([]), ParentFailure::InspectWrongType),
        (json!({}), ParentFailure::ConfigAbsent),
        (json!({"Config":null}), ParentFailure::ConfigNull),
        (json!({"Config":false}), ParentFailure::ConfigWrongType),
        (json!({"Config":{}}), ParentFailure::HealthcheckAbsent),
        (
            json!({"Config":{"Healthcheck":null}}),
            ParentFailure::HealthcheckNull,
        ),
        (
            json!({"Config":{"Healthcheck":[]}}),
            ParentFailure::HealthcheckWrongType,
        ),
    ] {
        assert_eq!(interval_state(&value), Err(expected));
    }
}

#[test]
fn boundary_client_frame_rejects_server_errors_and_ambiguous_output() {
    assert!(matches!(
        client_result(format!("stdout\n{}\n\x01stderr\n\x01status=0\n", "a".repeat(64)).as_bytes()),
        ClientResult::Accepted(_)
    ));
    assert!(matches!(
        client_result(LEGACY_CLIENT_REJECTION),
        ClientResult::UnknownFlag(125)
    ));
    for bytes in [
        b"1\nPRIVATE_BOUNDARY_CANARY\n".as_slice(),
        b"125\nserver rejected\n",
        b"124\nunknown flag: --health-start-interval\n",
        b"0\nshort-id\n",
        b"0\n\n",
    ] {
        assert!(
            std::panic::catch_unwind(|| client_result(bytes)).is_err(),
            "closed client frame refusal"
        );
    }
}
