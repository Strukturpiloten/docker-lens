//! Six independent default/zero effect fixtures; no capability admission.

use super::*;

const CONTRACT: &str = "lifecycle-default-effects-v1";
const FILENAME: &str = "lifecycle-default-effects-v1.json";
const LEGACY_REJECTION: &[u8] = b"stdout\n\x01stderr\nunknown flag: --health-start-interval\nSee 'docker create --help'.\n\x01status=125\n";

fn process(index: usize) -> &'static str {
    if index < 4 {
        STOP_PROCESS
    } else {
        HEALTH_PROCESS
    }
}

// Availability is classified before any default interpretation. Null, bool,
// negative and positive values are never normalized into an absent/zero value.
fn raw_zero(parent: &Value, key: &str) -> &'static str {
    let object = parent
        .as_object()
        .unwrap_or_else(|| panic!("object default parent"));
    match object.get(key) {
        None => "absent",
        Some(value) if value.as_u64() == Some(0) => "present_zero",
        _ => panic!("closed default raw availability"),
    }
}

fn rendered_request(run: &HealthRun, index: usize) -> Value {
    let healthcheck = (index == 5).then(|| {
        Healthcheck::configured(
            HealthTest::Shell(Argument::new(HEALTH_COMMAND.as_bytes().to_vec()).unwrap()),
            NonZeroU64::new(8 * SECOND),
            NonZeroU64::new(SECOND),
            NonZeroU32::new(3),
        )
        .and_then(|health| health.with_start_period(30 * SECOND))
        .and_then(|health| health.with_start_interval(0))
        .unwrap_or_else(|_| panic!("typed zero default health"))
    });
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
            ["sh", "-c", process(index)]
                .map(|text| Argument::new(text.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                    .unwrap(),
            ],
            stop_timeout_seconds: (index == 3).then_some(0),
            ..ContainerSettings::default()
        },
    };
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
    let capabilities = ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap();
    let graph = DockerPlanner
        .plan(&intent, &capabilities)
        .unwrap_or_else(|_| panic!("test-local default planning"));
    let artifact = DockerApiRenderer
        .render(&graph)
        .unwrap_or_else(|_| panic!("test-local default rendering"));
    let request: Value = serde_json::from_slice(artifact.bytes())
        .unwrap_or_else(|_| panic!("one inert default request"));
    let mut body = json!({"Image":run.base,"Cmd":["sh","-c",process(index)],"Labels":{(OWNER):run.run},"HostConfig":{}});
    if index == 3 {
        body["StopTimeout"] = json!(0);
    }
    if index == 5 {
        body["Healthcheck"] = json!({"Test":["CMD-SHELL",HEALTH_COMMAND],"Interval":8*SECOND,
            "Timeout":SECOND,"Retries":3,"StartPeriod":30*SECOND,"StartInterval":0});
    }
    assert_eq!(
        request,
        json!({"method":"POST","path":format!("/v{}/containers/create?name={}",run.api,run.names[index]),"body":body})
    );
    request
}

fn create(run: &mut HealthRun, index: usize) {
    assert_eq!(run.inspect(&run.names[index], false).0, 404);
    if index.is_multiple_of(2) {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
        ];
        if index == 2 {
            args.extend(["--stop-timeout".into(), "0".into()]);
        }
        if index == 4 {
            args.extend([
                "--health-cmd".into(),
                HEALTH_COMMAND.into(),
                "--health-interval".into(),
                "8s".into(),
                "--health-timeout".into(),
                "1s".into(),
                "--health-retries".into(),
                "3".into(),
                "--health-start-period".into(),
                "30s".into(),
            ]);
        }
        args.extend([
            run.base.clone(),
            "sh".into(),
            "-c".into(),
            process(index).into(),
        ]);
        run.attempted[index] = true;
        let bytes = docker(run, &args);
        let id = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| text.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("exact independent default CLI ID"));
        bind(run, index, id);
    } else {
        // Complete literal comparison precedes marking/submitting this once-only mutation.
        let request = rendered_request(run, index);
        run.attempted[index] = true;
        let (status, value) = run.api(
            "POST",
            request["path"].as_str().unwrap(),
            Some(&request["body"]),
            false,
        );
        assert_eq!(status, 201);
        assert!(
            value["Warnings"].is_null() || value["Warnings"] == json!([]),
            "unambiguous default create"
        );
        bind(
            run,
            index,
            value["Id"]
                .as_str()
                .unwrap_or_else(|| panic!("canonical default rendered ID")),
        );
    }
}

fn configured(run: &HealthRun, index: usize, base: &Value) -> (Value, &'static str) {
    let id = run.ids[index].as_deref().unwrap();
    let (status, value) = run.inspect(id, false);
    assert_eq!(status, 200);
    assert!(
        owned(run, &value, index, Some(id)),
        "exact default ownership"
    );
    assert_eq!(value["Image"], base["id"]);
    assert_eq!(value["Config"]["Cmd"], json!(["sh", "-c", process(index)]));
    assert!(
        value["Config"]["Entrypoint"].is_null() || value["Config"]["Entrypoint"] == json!([]),
        "empty inherited entrypoint"
    );
    assert_eq!(value["Path"], "sh");
    assert_eq!(value["Args"], json!(["-c", process(index)]));
    assert_eq!(value["RestartCount"], 0);
    let config = &value["Config"];
    let raw = if index < 4 {
        assert!(
            config["StopSignal"].is_null()
                || config["StopSignal"] == ""
                || config["StopSignal"] == "SIGTERM",
            "default TERM only"
        );
        let raw = raw_zero(config, "StopTimeout");
        assert_eq!(raw, if index < 2 { "absent" } else { "present_zero" });
        raw
    } else {
        let health = config
            .get("Healthcheck")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("present object default health parent"));
        for (key, expected) in [
            ("Test", json!(["CMD-SHELL", HEALTH_COMMAND])),
            ("Interval", json!(8 * SECOND)),
            ("Timeout", json!(SECOND)),
            ("Retries", json!(3)),
            ("StartPeriod", json!(30 * SECOND)),
        ] {
            assert_eq!(health.get(key), Some(&expected));
        }
        let raw = raw_zero(&config["Healthcheck"], "StartInterval");
        if run.lane.starts_with("debian11-") {
            // Moby 20.10.5/API 1.41 has no StartInterval field. HTTP 201
            // accepts an unknown member; actual legacy cadence is not zero
            // semantics. Preserve and require the observed absence separately.
            assert_eq!(raw, "absent");
        }
        raw
    };
    (value, raw)
}

fn refusal_name(run: &HealthRun) -> String {
    let name = format!("dl-def-{}-zero-cli-refusal", run.run);
    if run.lane.starts_with("debian11-") {
        // The same closed lookup binding is required before mutation and in
        // final cleanup. The deterministic name never enters names/ids and
        // therefore gains no create/start/delete authorization.
        assert_eq!(run.legacy_default_absence_name(), Some(name.clone()));
    }
    name
}

fn legacy_refusal(run: &HealthRun) -> Value {
    let name = refusal_name(run);
    assert!(
        !run.names.contains(&name),
        "refusal is not an owned mutation slot"
    );
    if !run.lane.starts_with("debian11-") {
        return json!({"name":name,"outcome":"not_applicable","exit_code":null,
            "stdout_empty":true,"stderr_signature":"not_applicable","absence_reads":0,"started":false});
    }
    assert_eq!(run.inspect(&name, false).0, 404);
    let command = vec!["sh".into(),"-c".into(),
        "export LC_ALL=C; printf 'stdout\\n'; { captured=$(\"$@\" 2>&1 >&3; status=$?; printf '\\001status=%s\\n' \"$status\"); printf '\\001stderr\\n%s\\n' \"$captured\"; } 3>&1".into(),
        "default-zero-cli-refusal".into(),"env".into(),format!("DOCKER_API_VERSION={}",run.api),
        "docker".into(),"-H".into(),"unix:///dockerlens-native/docker.sock".into(),"create".into(),
        "--name".into(),name.clone(),"--label".into(),format!("{OWNER}={}",run.run),
        "--health-start-interval=0s".into(),run.base.clone(),"sh".into(),"-c".into(),HEALTH_PROCESS.into()];
    let output = run.outer(&command, false);
    assert_eq!(output.as_slice(), LEGACY_REJECTION);
    // These exact two reads finish before ANY later mutation. A separate
    // rendered-zero name is neither a retry nor a parser-refused owned slot.
    assert_eq!(run.inspect(&name, false).0, 404);
    assert_eq!(run.inspect(&name, false).0, 404);
    json!({"name":name,"outcome":"unknown_flag","exit_code":125,"stdout_empty":true,
        "stderr_signature":"unknown_health_start_interval","absence_reads":2,"started":false})
}

fn stop_observation(run: &mut HealthRun, index: usize, base: &Value) -> Value {
    create(run, index);
    assert_eq!(configured(run, index, base).0["State"]["Status"], "created");
    start(run, index);
    let id = run.ids[index].as_deref().unwrap().to_owned();
    let ready = docker(
        run,
        &[
            "exec".into(),
            id.clone(),
            "sh".into(),
            "-c".into(),
            READY.into(),
        ],
    );
    assert_eq!(ready.as_slice(), b"pid1-term-ready\n".as_slice());
    let (before, raw) = configured(run, index, base);
    assert!(running(&before), "ready actual PID1");
    let started = before["State"]["StartedAt"].as_str().unwrap();
    let (ready_at, ready_clock) = native_time(run);
    let (requested_at, request_clock) = native_time(run);
    let timer = Instant::now();
    // Ordinary stop only; no -t/--time/--timeout or signal override.
    let output = docker(run, &["stop".into(), id.clone()]);
    let elapsed = u64::try_from(timer.elapsed().as_nanos()).unwrap();
    let (exit, lower, upper) = if index < 2 {
        (41, 2_800_000_000, 5_500_000_000)
    } else {
        (137, 0, 800_000_000)
    };
    assert!(
        (lower..upper).contains(&elapsed),
        "closed default monotonic stop window"
    );
    assert_eq!(output.as_slice(), format!("{id}\n").as_bytes());
    let (after, after_raw) = configured(run, index, base);
    assert_eq!(after_raw, raw);
    assert!(
        stopped(&after, exit),
        "definite default stopped state without OOM"
    );
    assert_eq!(after["State"]["StartedAt"], started);
    let logs = docker(run, &["logs".into(), id]);
    let marker = logs.as_slice() == b"lifecycle-term\n";
    assert!(
        marker || index >= 2 && logs.is_empty(),
        "closed empty-or-single TERM log grammar"
    );
    let finished = after["State"]["FinishedAt"].as_str().unwrap();
    let (observed_at, observed_clock) = native_time(run);
    let times = [started, &ready_at, &requested_at, finished, &observed_at]
        .map(|time| timestamp_ns(time).unwrap_or_else(|| panic!("default native stop time")));
    assert!(
        times.windows(2).all(|pair| pair[0] <= pair[1])
            && times[4] <= times[0] + 180 * u128::from(SECOND),
        "default native stop causality"
    );
    let duration = times[3] - times[2];
    assert!(
        u128::from(lower) <= duration
            && duration < u128::from(upper)
            && duration.abs_diff(u128::from(elapsed)) <= 500_000_000,
        "native and monotonic default agreement"
    );
    let mut record = identity(run, index, base);
    record.as_object_mut().unwrap().extend(json!({"timeout_request":if index<2 {json!("omitted")} else {json!(0)},
        "raw_timeout":raw,"readiness":"pid1-term-ready","term_log":if marker {"single_term"} else {"empty"},
        "running_before_stop":true,"started_at":started,"ready_observed_at":ready_at,"stop_requested_at":requested_at,
        "finished_at":finished,"stopped_observed_at":observed_at,"ready_clock":ready_clock,
        "request_clock":request_clock,"observed_clock":observed_clock,"timeout_override":false,"signal_override":false,
        "stop_elapsed_ns":elapsed,"exit_code":exit,"state":"exited","running":false,"pid":0,"oom_killed":false,
        "restarting":false,"restart_count":0,"paused":false,"dead":false,"state_error_empty":true})
        .as_object().unwrap().clone());
    record
}

fn health_snapshot(
    run: &HealthRun,
    index: usize,
    base: &Value,
    started: &str,
    raw: &str,
    early: bool,
) -> Value {
    let anchor = timestamp_ns(started).unwrap();
    let (target, lower, upper) = if early {
        (6_300_000_000, 6_000_000_000, 7_200_000_000)
    } else {
        (11_600_000_000, 11_200_000_000, 13_000_000_000)
    };
    let (now, _) = native_time(run);
    let now = timestamp_ns(&now).unwrap();
    assert!(
        anchor <= now && now < anchor + upper,
        "never late default health observation"
    );
    let wait = Duration::from_nanos(u64::try_from((anchor + target).saturating_sub(now)).unwrap());
    assert!(
        run.remaining() > wait + Duration::from_secs(46),
        "original cleanup reserve before default wait"
    );
    std::thread::sleep(wait);
    let (before, before_clock) = native_time(run);
    let (value, observed_raw) = configured(run, index, base);
    let (after, after_clock) = native_time(run);
    let before_ns = timestamp_ns(&before).unwrap();
    let after_ns = timestamp_ns(&after).unwrap();
    assert!(
        anchor + lower <= before_ns && before_ns <= after_ns && after_ns < anchor + upper,
        "own start bounded default health bracket"
    );
    assert_eq!(value["State"]["StartedAt"], started);
    assert_eq!(observed_raw, raw);
    assert!(running(&value), "default health PID1 remains running");
    assert_eq!(value["State"]["Health"]["Status"], "starting");
    assert_eq!(value["State"]["Health"]["FailingStreak"], 0);
    let attempts = attempts(&value, anchor, after_ns);
    let expected_ages: &[u64] = if run.lane.starts_with("debian11-") {
        if early { &[] } else { &[8] }
    } else if early {
        &[5]
    } else {
        &[5, 10]
    };
    assert_eq!(attempts.len(), expected_ages.len());
    for (attempt, age) in attempts.iter().zip(expected_ages) {
        let actual = timestamp_ns(attempt["start"].as_str().unwrap()).unwrap() - anchor;
        assert!(
            u128::from(*age * SECOND) <= actual
                && actual < u128::from(*age * SECOND + 1_200_000_000),
            "actual exact-lane default scheduler attempt"
        );
    }
    json!({"before":before,"after":after,"before_clock":before_clock,"after_clock":after_clock,
        "raw_start_interval":raw,"status":"starting","failing_streak":0,"running":true,"restart_count":0,"attempts":attempts})
}

fn health_observation(run: &mut HealthRun, index: usize, base: &Value) -> Value {
    create(run, index);
    assert_eq!(configured(run, index, base).0["State"]["Status"], "created");
    start(run, index);
    let (value, raw) = configured(run, index, base);
    assert!(running(&value), "actual started default health fixture");
    let started = value["State"]["StartedAt"].as_str().unwrap();
    let early = health_snapshot(run, index, base, started, raw, true);
    let late = health_snapshot(run, index, base, started, raw, false);
    let early_attempts = early["attempts"].as_array().unwrap();
    let late_attempts = late["attempts"].as_array().unwrap();
    assert_eq!(
        &late_attempts[..early_attempts.len()],
        early_attempts.as_slice()
    );
    let early_after = timestamp_ns(early["after"].as_str().unwrap()).unwrap();
    assert!(
        late_attempts
            .iter()
            .any(
                |attempt| timestamp_ns(attempt["start"].as_str().unwrap()).unwrap() >= early_after
            ),
        "genuine later default attempt"
    );
    let mut record = identity(run, index, base);
    record.as_object_mut().unwrap().extend(json!({"start_interval_request":if index==4 {json!("omitted")} else {json!(0)},
        "raw_start_interval":raw,"request_accepted":true,"started_at":started,"early":early,"late":late})
        .as_object().unwrap().clone());
    record
}

#[test]
#[ignore = "requires isolated exact-profile Docker Engine and authenticated harness"]
fn live_lifecycle_default_effects_match_engine() {
    let target = ProofTarget::new_for("NATIVE_LIFECYCLE_DEFAULT_EFFECT_PROOF_PATH", FILENAME);
    // Exactly one invocation deadline; inherited transport retains 100 calls /
    // 2MiB cleanup reserve, 400 calls / 4MiB total, and finite per-call timers.
    let mut run = HealthRun::new_for(
        "NATIVE_LIFECYCLE_DEFAULT_EFFECT_CANDIDATE_SHA",
        "NATIVE_LIFECYCLE_DEFAULT_EFFECT_DEADLINE_EPOCH",
    );
    run.names = [
        "timeout-omitted-oracle",
        "timeout-omitted-rendered",
        "timeout-zero-oracle",
        "timeout-zero-rendered",
        "health-control",
        "health-candidate",
    ]
    .map(|suffix| format!("dl-def-{}-{suffix}", run.run))
    .into();
    run.ids = vec![None; 6];
    run.attempted = vec![false; 6];
    let cleanup_owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let outer = cleanup_owner.snapshot.clone();
        let daemon_uid = run.context();
        let base = image_snapshot(&run);
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::StopTimeout,
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
        // Parser refusal is complete and absence-proven before any fixture mutation.
        let refusal = legacy_refusal(&run);
        let stops = [
            stop_observation(&mut run, 0, &base),
            stop_observation(&mut run, 1, &base),
            stop_observation(&mut run, 2, &base),
            stop_observation(&mut run, 3, &base),
        ];
        let health = [
            health_observation(&mut run, 4, &base),
            health_observation(&mut run, 5, &base),
        ];
        (outer, daemon_uid, base, refusal, stops, health)
    }));
    let ordinary_calls = run.calls.get();
    let ordinary_bytes = run.bytes.get();
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let disposition = cleanup(&mut run);
        let mut refusal_absent = true;
        if run.lane.starts_with("debian11-") {
            for _ in 0..2 {
                refusal_absent &= run.inspect(&refusal_name(&run), true).0 == 404;
            }
        }
        if disposition == CleanupDisposition::VerifiedAbsent && refusal_absent {
            CleanupDisposition::VerifiedAbsent
        } else {
            CleanupDisposition::OuterTeardownRequired
        }
    }))
    .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_calls = run.calls.get() - ordinary_calls;
    let cleanup_bytes = run.bytes.get() - ordinary_bytes;
    terminal_cleanup(&mut run, &cleanup_owner, disposition);
    let (outer, daemon_uid, base, refusal, stops, health) =
        require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none(),
        "borrowed default image never owned"
    );
    assert_eq!(image_snapshot(&run), base);
    assert_eq!(outer_context(&run), outer);
    let ordinary_calls = run.calls.get() - cleanup_calls;
    let ordinary_bytes = run.bytes.get() - cleanup_bytes;
    assert!(
        ordinary_calls <= 300
            && cleanup_calls <= 56
            && ordinary_bytes <= 2 * 1024 * 1024
            && cleanup_bytes <= 2 * 1024 * 1024,
        "original default effect accounting limits"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"context":{
        "candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,
        "rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},
        "mode":if run.mode==DaemonMode::Rootless {"rootless"} else {"rootful"},
        "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},
        "fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "apis":{"fixture_cli":run.api,"stop_renderer":run.api,"health_renderer":run.api,"request":run.api,"health_probe":"test_local_unadmitted"},
        "borrowed_image":{"id":base["id"],"identity":"unchanged","removal":"not_owned"},
        "legacy_zero_cli":refusal,"stop_timeout":stops,
        "health_start_interval":{"outcome":if run.lane.starts_with("debian11-") {"unsupported_legacy_field"} else {"default_equivalent"},
            "source_scope":if run.lane.starts_with("debian11-") {"accepted_unknown_member_legacy_schedule_only"} else {"supported_field_zero_default_schedule"},
            "interval_ns":8*SECOND,"start_period_ns":30*SECOND,
            "start_interval_request":0,"timeout_ns":SECOND,"retries":3,"containers":health},
        "cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false},
        "accounting":{"ordinary_calls":ordinary_calls,"cleanup_calls":cleanup_calls,"ordinary_bytes":ordinary_bytes,
            "cleanup_bytes":cleanup_bytes,"deadline_seconds":180,"renewed":false}});
    target.publish(&proof);
}

#[test]
fn default_raw_availability_refuses_normalizing_malformed_values() {
    assert_eq!(raw_zero(&json!({}), "value"), "absent");
    assert_eq!(raw_zero(&json!({"value":0}), "value"), "present_zero");
    for parent in [
        json!(null),
        json!([]),
        json!({"value":null}),
        json!({"value":false}),
        json!({"value":-1}),
        json!({"value":1}),
        json!({"value":"0"}),
        json!({"value":0.0}),
    ] {
        assert!(
            std::panic::catch_unwind(|| raw_zero(&parent, "value")).is_err(),
            "malformed raw default rejected"
        );
    }
}

// Pure controls call the SAME composed predicate used by api(), not a mirrored
// authorization model. cleaned=true makes even unwinding entirely inert.
fn allowlist_fixture(lane: &str) -> HealthRun {
    let run = "A1B2C3D4";
    let api = if lane.starts_with("debian11-") {
        "1.41"
    } else {
        "1.56"
    };
    HealthRun {
        run: run.into(),
        lane: lane.into(),
        candidate: "a".repeat(40),
        api: api.into(),
        engine: String::new(),
        mode: if lane.ends_with("-rootless") {
            DaemonMode::Rootless
        } else {
            DaemonMode::Rootful
        },
        socket: String::new(),
        outer: String::new(),
        base: "borrowed-fixture".into(),
        derived_tag: "not-owned".into(),
        derived_id: None,
        image_attempted: false,
        names: [
            "timeout-omitted-oracle",
            "timeout-omitted-rendered",
            "timeout-zero-oracle",
            "timeout-zero-rendered",
            "health-control",
            "health-candidate",
        ]
        .map(|suffix| format!("dl-def-{run}-{suffix}"))
        .into(),
        ids: vec![None; 6],
        attempted: vec![false; 6],
        absence_lookup: HealthAbsenceLookup::for_invocation(
            "NATIVE_LIFECYCLE_DEFAULT_EFFECT_CANDIDATE_SHA",
            "NATIVE_LIFECYCLE_DEFAULT_EFFECT_DEADLINE_EPOCH",
            run,
            lane,
            api,
        ),
        deadline: Instant::now() + Duration::from_secs(180),
        calls: Cell::new(0),
        bytes: Cell::new(0),
        facts: None,
        cleaned: true,
        cleanup_delegated: false,
    }
}

#[test]
fn legacy_absence_composed_allowlist_adds_only_the_exact_get() {
    for lane in ["debian11-rootful", "debian11-rootless"] {
        let run = allowlist_fixture(lane);
        let name = "dl-def-A1B2C3D4-zero-cli-refusal";
        let exact = format!("/v1.41/containers/{name}/json");
        assert_eq!(run.legacy_default_absence_name(), Some(name.to_owned()));
        assert!(
            run.request_allowed("GET", &exact),
            "exact independently named absence GET"
        );
        for method in ["POST", "DELETE", "PUT", "PATCH", "HEAD", "get"] {
            assert!(
                !run.request_allowed(method, &exact),
                "absence lookup cannot authorize mutations"
            );
        }
        for path in [
            format!("/v1.41/containers/create?name={name}"),
            format!("/v1.41/containers/{name}/start"),
            format!("/v1.41/containers/{name}?force=1"),
            exact.replace("A1B2C3D4", "E5F6G7H8"),
            exact.replace("zero-cli-refusal", "health-candidate-other"),
            exact.replace("1.41", "1.56"),
            exact.replace("1.41", "1.49"),
            format!("{exact}?all=1"),
            format!("{exact}/"),
            format!("{exact}-other"),
            "/v1.41/containers/unregistered-id/json".into(),
        ] {
            for method in ["GET", "POST", "DELETE"] {
                assert!(
                    !run.request_allowed(method, &path),
                    "closed absence method/path composition"
                );
            }
        }
        assert_eq!(run.names.len(), 6);
        assert_eq!(run.ids.len(), 6);
        assert_eq!(run.attempted, vec![false; 6]);
        assert!(
            !run.names.iter().any(|owned| owned == name),
            "absence name stays outside owned slots"
        );
        assert!(
            run.ids.iter().all(Option::is_none),
            "absence control owns no ID"
        );
        assert_eq!(run.calls.get(), 0);
        assert_eq!(run.bytes.get(), 0);
    }
}

#[test]
fn legacy_absence_binding_refuses_other_invocations_and_changed_context() {
    let exact = "/v1.41/containers/dl-def-A1B2C3D4-zero-cli-refusal/json";
    for (candidate, deadline, token, lane, api) in [
        (
            "NATIVE_LIFECYCLE_CANDIDATE_SHA",
            "NATIVE_LIFECYCLE_DEFAULT_EFFECT_DEADLINE_EPOCH",
            "A1B2C3D4",
            "debian11-rootful",
            "1.41",
        ),
        (
            "NATIVE_LIFECYCLE_DEFAULT_EFFECT_CANDIDATE_SHA",
            "NATIVE_LIFECYCLE_DEADLINE_EPOCH",
            "A1B2C3D4",
            "debian11-rootful",
            "1.41",
        ),
        (
            "NATIVE_LIFECYCLE_DEFAULT_EFFECT_CANDIDATE_SHA",
            "NATIVE_LIFECYCLE_DEFAULT_EFFECT_DEADLINE_EPOCH",
            "A1B2C3D4",
            "upstream-rootful",
            "1.41",
        ),
        (
            "NATIVE_LIFECYCLE_DEFAULT_EFFECT_CANDIDATE_SHA",
            "NATIVE_LIFECYCLE_DEFAULT_EFFECT_DEADLINE_EPOCH",
            "A1B2C3D4",
            "debian11-rootful",
            "1.56",
        ),
        (
            "NATIVE_LIFECYCLE_DEFAULT_EFFECT_CANDIDATE_SHA",
            "NATIVE_LIFECYCLE_DEFAULT_EFFECT_DEADLINE_EPOCH",
            "A1B2/../",
            "debian11-rootful",
            "1.41",
        ),
    ] {
        let mut run = allowlist_fixture("debian11-rootful");
        run.absence_lookup =
            HealthAbsenceLookup::for_invocation(candidate, deadline, token, lane, api);
        assert!(
            !run.request_allowed("GET", exact),
            "unrelated or malformed invocation cannot opt in"
        );
    }
    let mut run = allowlist_fixture("debian11-rootful");
    run.run = "E5F6G7H8".into();
    assert!(
        !run.request_allowed("GET", exact),
        "original bound run cannot be replaced"
    );
    assert!(
        !run.request_allowed("GET", &exact.replace("A1B2C3D4", "E5F6G7H8")),
        "changed run cannot mint another absence name"
    );
    let mut run = allowlist_fixture("debian11-rootful");
    run.lane = "debian11-rootless".into();
    assert!(
        !run.request_allowed("GET", exact),
        "original exact lane cannot be replaced"
    );
    for lane in ["upstream-rootful", "upstream-rootless"] {
        let run = allowlist_fixture(lane);
        assert!(
            run.legacy_default_absence_name().is_none(),
            "modern context has no absence exception"
        );
        assert!(
            !run.request_allowed("GET", exact),
            "modern invocation cannot use legacy exception"
        );
    }
}

#[test]
fn legacy_absence_composition_preserves_the_six_owned_request_ledgers() {
    let mut run = allowlist_fixture("debian11-rootful");
    for name in &run.names {
        assert!(
            run.request_allowed("GET", &format!("/v1.41/containers/{name}/json")),
            "ordinary owned-name read unchanged"
        );
        assert!(
            run.request_allowed("POST", &format!("/v1.41/containers/create?name={name}")),
            "ordinary once-create ledger unchanged"
        );
        assert!(
            !run.request_allowed("DELETE", &format!("/v1.41/containers/{name}?force=1")),
            "owned names never authorize deletion"
        );
    }
    let id = "1".repeat(64);
    run.ids[0] = Some(id.clone());
    assert!(
        run.request_allowed("GET", &format!("/v1.41/containers/{id}/json")),
        "bound owned ID read unchanged"
    );
    assert!(
        run.request_allowed("POST", &format!("/v1.41/containers/{id}/start")),
        "bound owned ID start unchanged"
    );
    assert!(
        run.request_allowed("DELETE", &format!("/v1.41/containers/{id}?force=1")),
        "bound owned ID cleanup unchanged"
    );
    for path in [
        "/version",
        "/v1.41/info",
        "/v1.41/images/borrowed-fixture/json",
    ] {
        assert!(
            run.request_allowed("GET", path),
            "existing context/image read unchanged"
        );
    }
    assert_eq!(run.names.len(), 6);
    assert_eq!(run.ids.len(), 6);
    assert_eq!(run.attempted, vec![false; 6]);
    assert!(
        !run.image_attempted && run.derived_id.is_none(),
        "no owned image authorization added"
    );
}
