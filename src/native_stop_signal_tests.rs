//! Independent stop-signal-v1 proof. Test-local facts never admit a catalogue capability.

use super::*;

const SIGNALS: [(&str, i64); 2] = [("SIGTERM", 41), ("SIGINT", 42)];
const CONTRACT: &str = "stop-signal-v1";
const FILENAME: &str = "stop-signal-v1.json";
// The readiness marker is written by PID1 only after both distinguishable traps
// exist. No natural completion can imitate either trap's exit status.
const PROCESS: &str = "[ \"$$\" -eq 1 ] || exit 43; trap 'exit 41' TERM; trap 'exit 42' INT; printf 'pid1-traps-ready\\n' > /tmp/dl-stop-ready; while :; do sleep 1 & wait $!; done";
const READY: &str = "for n in 1 2 3 4 5 6 7 8 9 10; do if [ -f /tmp/dl-stop-ready ]; then cat /tmp/dl-stop-ready; exit 0; fi; sleep 0.2; done; exit 1";

enum StopStage {
    Create,
    Created,
    Start,
    Readiness,
    Running,
    Clock,
    Stop,
    Elapsed,
    Output,
    Inspect,
    Exit,
    State,
    Causality,
}

fn stop_stage(index: usize, stage: StopStage) {
    let (signal, role) = match index {
        0 => ("term", "oracle"),
        1 => ("term", "rendered"),
        2 => ("int", "oracle"),
        3 => ("int", "rendered"),
        _ => panic!("closed stop fixture index"),
    };
    let stage = match stage {
        StopStage::Create => "create",
        StopStage::Created => "created",
        StopStage::Start => "start",
        StopStage::Readiness => "readiness",
        StopStage::Running => "running",
        StopStage::Clock => "clock",
        StopStage::Stop => "stop",
        StopStage::Elapsed => "elapsed",
        StopStage::Output => "output",
        StopStage::Inspect => "inspect",
        StopStage::Exit => "exit",
        StopStage::State => "state",
        StopStage::Causality => "causality",
    };
    eprintln!("DOCKERLENS_NATIVE_STOP_SIGNAL_STAGE: case={signal} role={role} stage={stage}");
}

fn outer_context(run: &HealthRun, cleanup: bool) -> Value {
    let id = required("NATIVE_OUTER_CONTAINER_ID");
    assert!(identifier(&id), "closed immutable outer ID");
    let image = required("NATIVE_OUTER_IMAGE");
    let (_, digest) = image
        .rsplit_once('@')
        .unwrap_or_else(|| panic!("pinned outer image"));
    assert!(image_identifier(digest), "pinned outer digest");
    let elevated = match required("NATIVE_PODMAN_USE_SUDO").as_str() {
        "0" => false,
        "1" => true,
        _ => panic!("closed privilege selector"),
    };
    let mut command = run.timer(cleanup, elevated);
    command.args(["podman", "inspect", "--format", "{{json .}}", &id]);
    let value: Value = serde_json::from_slice(&run.capture(&mut command, None, cleanup))
        .unwrap_or_else(|_| panic!("private outer JSON"));
    let mounts = value["Mounts"]
        .as_array()
        .unwrap_or_else(|| panic!("closed outer mounts"));
    let volumes: Vec<_> = mounts
        .iter()
        .filter(|item| item["Type"] == "volume")
        .collect();
    let binds: Vec<_> = mounts
        .iter()
        .filter(|item| item["Type"] == "bind")
        .collect();
    let storage = if run.mode == DaemonMode::Rootless {
        "/home/docker/.local/share/docker"
    } else {
        "/var/lib/docker"
    };
    let directory = PathBuf::from(required("NATIVE_CAPTURE_DIR"));
    let networks = value["NetworkSettings"]["Networks"]
        .as_object()
        .unwrap_or_else(|| panic!("closed outer network"));
    assert!(
        value["Id"] == id
            && value["Name"] == run.outer
            && value["Config"]["Labels"][OWNER] == run.run
            && value["ImageDigest"] == digest
            && value["State"]["Running"] == true
            && value["HostConfig"]["Privileged"] == true
            && value["HostConfig"]["Memory"] == 4294967296_u64
            && value["HostConfig"]["CpuQuota"] == 200000
            && value["HostConfig"]["CpuPeriod"] == 100000
            && value["HostConfig"]["PidsLimit"] == 512
            && mounts.len() == 2
            && volumes.len() == 1
            && binds.len() == 1
            && volumes[0]["Name"] == format!("dl-native-data-{}", run.run)
            && volumes[0]["Destination"] == storage
            && volumes[0]["RW"] == true
            && binds[0]["Source"] == directory.join("socket").to_str().unwrap()
            && binds[0]["Destination"] == "/dockerlens-native"
            && binds[0]["RW"] == true
            && networks.len() == 1
            && networks.contains_key(&format!("dl-native-net-{}", run.run)),
        "authenticated outer context"
    );
    json!({"id":id,"name":run.outer,"owner":run.run,"image":image,
        "data_volume":format!("dl-native-data-{}",run.run),"socket_source":directory.join("socket"),
        "privileged":true,"memory_bytes":4294967296_u64,"cpu_quota":200000,"cpu_period":100000,"pids_limit":512})
}

fn image_snapshot(run: &HealthRun, cleanup: bool) -> Value {
    let (status, value) = run.api(
        "GET",
        &format!("/v{}/images/{}/json", run.api, run.base),
        None,
        cleanup,
    );
    assert_eq!(status, 200);
    assert!(
        value["Id"].as_str().is_some_and(image_identifier),
        "borrowed canonical image"
    );
    let digest = run.base.rsplit_once('@').unwrap().1;
    assert!(
        value["RepoDigests"]
            .as_array()
            .is_some_and(|items| items
                .iter()
                .any(|item| item.as_str().is_some_and(|text| text
                    .rsplit_once('@')
                    .is_some_and(|(_, actual)| actual == digest)))),
        "actual borrowed image digest"
    );
    json!({"id":value["Id"],"repo_digests":value["RepoDigests"],"config":value["Config"]})
}

fn native_time(run: &HealthRun) -> String {
    let (status, info) = run.api("GET", &format!("/v{}/info", run.api), None, false);
    assert_eq!(status, 200);
    let time = info["SystemTime"]
        .as_str()
        .unwrap_or_else(|| panic!("native observation time"));
    assert!(timestamp_ns(time).is_some(), "bounded native time");
    time.to_owned()
}

fn configured(run: &HealthRun, index: usize, base_id: &Value) -> Value {
    let id = run.ids[index]
        .as_deref()
        .unwrap_or_else(|| panic!("bound fixture ID"));
    let (status, value) = run.inspect(id, false);
    assert_eq!(status, 200);
    assert!(
        run.owned(&value, index, Some(id)),
        "exact stop fixture ownership"
    );
    assert_eq!(value["Image"], *base_id);
    assert_eq!(value["Config"]["StopSignal"], SIGNALS[index / 2].0);
    assert_eq!(value["Config"]["Cmd"], json!(["sh", "-c", PROCESS]));
    assert!(
        value["Config"]["Entrypoint"].is_null() || value["Config"]["Entrypoint"] == json!([]),
        "unchanged BusyBox entrypoint"
    );
    assert_eq!(value["Path"], "sh");
    assert_eq!(value["Args"], json!(["-c", PROCESS]));
    assert_eq!(value["RestartCount"], 0);
    value
}

fn create(run: &mut HealthRun, index: usize) {
    assert_eq!(run.inspect(&run.names[index], false).0, 404);
    let signal = SIGNALS[index / 2].0;
    if index % 2 == 0 {
        run.attempted[index] = true;
        let output = run.docker(
            &[
                "create".into(),
                "--name".into(),
                run.names[index].clone(),
                "--label".into(),
                format!("{OWNER}={}", run.run),
                "--stop-signal".into(),
                signal.into(),
                run.base.clone(),
                "sh".into(),
                "-c".into(),
                PROCESS.into(),
            ],
            false,
        );
        let id = std::str::from_utf8(&output)
            .ok()
            .and_then(|text| text.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed CLI create ID"));
        run.bind(index, id);
        return;
    }
    let container = ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(run.names[index].as_bytes().to_vec())
            .unwrap_or_else(|_| panic!("typed name")),
        image: ImageReference::new(run.base.as_bytes().to_vec())
            .unwrap_or_else(|_| panic!("typed image")),
        environment: vec![],
        ports: vec![],
        mounts: vec![],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Exec(
            ["sh", "-c", PROCESS]
                .map(|value| {
                    Argument::new(value.as_bytes().to_vec())
                        .unwrap_or_else(|_| panic!("typed process"))
                })
                .into(),
        ),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                    .unwrap_or_else(|_| panic!("typed owner")),
            ],
            stop_signal: Some(
                Argument::new(signal.as_bytes().to_vec())
                    .unwrap_or_else(|_| panic!("typed signal")),
            ),
            ..ContainerSettings::default()
        },
    };
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))])
        .unwrap_or_else(|_| panic!("stop intent"));
    let facts = run
        .facts
        .as_ref()
        .unwrap_or_else(|| panic!("actual context"));
    let caps = ValidatedCapabilities::new(facts).unwrap_or_else(|_| panic!("test scoped facts"));
    let graph = DockerPlanner
        .plan(&intent, &caps)
        .unwrap_or_else(|_| panic!("stop planning"));
    let artifact = DockerApiRenderer
        .render(&graph)
        .unwrap_or_else(|_| panic!("stop rendering"));
    let request: Value =
        serde_json::from_slice(artifact.bytes()).unwrap_or_else(|_| panic!("one inert request"));
    let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
    let expected = json!({"method":"POST","path":path,"body":{"Image":run.base,"Cmd":["sh","-c",PROCESS],
        "Labels":{(OWNER):run.run},"StopSignal":signal,"HostConfig":{}}});
    assert_eq!(request, expected);
    run.attempted[index] = true;
    let (status, value) = run.api("POST", &path, Some(&request["body"]), false);
    assert_eq!(status, 201);
    run.bind(
        index,
        value["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("bound rendered ID")),
    );
}

fn stopped(value: &Value, expected_exit: i64) -> bool {
    value["State"]["Status"] == "exited"
        && value["State"]["Running"] == false
        && value["State"]["Restarting"] == false
        && value["State"]["Paused"] == false
        && value["State"]["Dead"] == false
        && value["State"]["OOMKilled"] == false
        && value["State"]["Pid"] == 0
        && value["State"]["ExitCode"] == expected_exit
        && value["State"]["Error"] == ""
        && value["RestartCount"] == 0
}

fn observe(run: &mut HealthRun, index: usize, base_id: &Value) -> Value {
    stop_stage(index, StopStage::Create);
    create(run, index);
    stop_stage(index, StopStage::Created);
    let before = configured(run, index, base_id);
    assert_eq!(before["State"]["Status"], "created");
    let id = run.ids[index].as_deref().unwrap().to_owned();
    stop_stage(index, StopStage::Start);
    assert_eq!(
        run.api(
            "POST",
            &format!("/v{}/containers/{id}/start", run.api),
            None,
            false
        )
        .0,
        204
    );
    stop_stage(index, StopStage::Readiness);
    let output = run.docker(
        &[
            "exec".into(),
            id.clone(),
            "sh".into(),
            "-c".into(),
            READY.into(),
        ],
        false,
    );
    assert_eq!(output.as_slice(), b"pid1-traps-ready\n".as_slice());
    stop_stage(index, StopStage::Running);
    let ready = configured(run, index, base_id);
    assert_eq!(ready["State"]["Running"], true);
    assert_eq!(ready["State"]["Status"], "running");
    assert!(
        ready["State"]["Pid"].as_u64().is_some_and(|pid| pid > 0),
        "actual running PID1"
    );
    stop_stage(index, StopStage::Clock);
    let started = ready["State"]["StartedAt"]
        .as_str()
        .unwrap_or_else(|| panic!("native start time"));
    let ready_at = native_time(run);
    let requested_at = native_time(run);
    stop_stage(index, StopStage::Stop);
    let clock = Instant::now();
    // -t is the common 20.10/29 spelling without the deprecated --time alias.
    // No --signal:
    // the independently inspected configured signal must drive PID1's trap.
    let output = run.docker(&["stop".into(), "-t".into(), "3".into(), id.clone()], false);
    let elapsed = clock.elapsed();
    stop_stage(index, StopStage::Elapsed);
    assert!(
        elapsed < Duration::from_secs(5),
        "bounded actual stop completion"
    );
    stop_stage(index, StopStage::Output);
    assert_eq!(output.as_slice(), format!("{id}\n").as_bytes());
    stop_stage(index, StopStage::Inspect);
    let after = configured(run, index, base_id);
    stop_stage(index, StopStage::Exit);
    assert_eq!(after["State"]["ExitCode"], SIGNALS[index / 2].1);
    stop_stage(index, StopStage::State);
    assert!(
        stopped(&after, SIGNALS[index / 2].1),
        "exact trap exit, never forced-kill success"
    );
    stop_stage(index, StopStage::Causality);
    assert_eq!(after["State"]["StartedAt"], started);
    let finished = after["State"]["FinishedAt"]
        .as_str()
        .unwrap_or_else(|| panic!("native finish time"));
    let observed_at = native_time(run);
    let times = [
        started,
        ready_at.as_str(),
        requested_at.as_str(),
        finished,
        observed_at.as_str(),
    ]
    .map(|text| timestamp_ns(text).unwrap_or_else(|| panic!("ordered native timestamp")));
    assert!(
        times.windows(2).all(|pair| pair[0] <= pair[1])
            && times[2] < times[3]
            && times[3] - times[2] < 5 * u128::from(SECOND),
        "native stop causality"
    );
    json!({"role":if index%2 == 0 {"oracle"} else {"rendered"},"id":id,"name":run.names[index],"owner":run.run,
        "image":run.base,"image_id":base_id,"configured_signal":SIGNALS[index/2].0,"wire":"passed",
        "readiness":"pid1-traps-ready","running_before_stop":true,"started_at":started,"ready_observed_at":ready_at,
        "stop_requested_at":requested_at,"finished_at":finished,"stopped_observed_at":observed_at,
        "stop_timeout_seconds":3,"signal_override":false,"stop_elapsed_ns":u64::try_from(elapsed.as_nanos()).unwrap(),
        "exit_code":SIGNALS[index/2].1,"state":"exited","running":false,"pid":0,"oom_killed":false,
        "restarting":false,"restart_count":0,"cleanup":"absent"})
}

#[test]
#[ignore = "requires isolated exact-profile Docker Engine and authenticated harness"]
fn live_stop_signal_matches_engine() {
    let target = ProofTarget::new_for("NATIVE_STOP_SIGNAL_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_STOP_SIGNAL_CANDIDATE_SHA",
        "NATIVE_STOP_SIGNAL_DEADLINE_EPOCH",
    );
    run.names = ["term", "int"]
        .into_iter()
        .flat_map(|signal| {
            ["oracle", "rendered"].map(|role| format!("dl-stop-{}-{signal}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 4];
    run.attempted = vec![false; 4];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: stop_signal_context");
        let outer = outer_context(&run, false);
        let daemon_uid = run.context();
        let base = image_snapshot(&run, false);
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        // Scaffolding restricted to this ignored proof; never a public resolver.
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::StopSignal,
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
        for (case, (signal, exit)) in SIGNALS.into_iter().enumerate() {
            if case == 0 {
                eprintln!("DOCKERLENS_NATIVE_CHECK: stop_signal_term");
            } else {
                eprintln!("DOCKERLENS_NATIVE_CHECK: stop_signal_int");
            }
            let containers = [
                observe(&mut run, 2 * case, &base["id"]),
                observe(&mut run, 2 * case + 1, &base["id"]),
            ];
            cases.push(json!({"signal":signal,"expected_exit_code":exit,"containers":containers}));
        }
        (outer, daemon_uid, base, cases)
    }));
    eprintln!("DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup");
    let clean =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.cleanup())).unwrap_or(false);
    if !clean {
        eprintln!("DOCKERLENS_NATIVE_CHECK: stop_signal_cleanup_unverified");
    }
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    assert!(clean, "verified stop fixture cleanup");
    let (outer, daemon_uid, base, cases) = result.unwrap_or_else(|_| unreachable!());
    // The shared base was only borrowed. The image mutation ledger stays empty.
    assert!(
        !run.image_attempted && run.derived_id.is_none(),
        "borrowed image is never owned"
    );
    assert_eq!(image_snapshot(&run, true), base);
    assert_eq!(outer_context(&run, true), outer);
    let proof = json!({"schema_version":1,"contract":CONTRACT,"context":{
        "candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,
        "rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},
        "mode":if run.mode == DaemonMode::Rootless {"rootless"} else {"rootful"},
        "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},
        "fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "shapes":["StopSignal"],"borrowed_image":{"id":base["id"],"identity":"unchanged","removal":"not_owned"},
        "cases":cases,"cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: stop_signal_evidence");
    target.publish(&proof);
}

#[test]
fn stop_signal_assertions_never_format_compared_native_values() {
    let error = std::panic::catch_unwind(|| {
        assert_eq!("PRIVATE_STOP_SIGNAL_CANARY", "different");
    })
    .expect_err("distinct values must fail");
    let message = error
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| error.downcast_ref::<String>().map(String::as_str));
    assert!(message.is_some_and(|message| message == "closed health metadata equality failed"));
}

#[test]
fn stop_signal_requires_distinct_trap_exit_and_stopped_state() {
    let expected = json!({"State":{"Status":"exited","Running":false,"Restarting":false,"Paused":false,
        "Dead":false,"OOMKilled":false,"Pid":0,"ExitCode":41,"Error":""},"RestartCount":0});
    assert!(stopped(&expected, 41) && !stopped(&expected, 42));
    for (field, value) in [
        ("ExitCode", json!(137)),
        ("ExitCode", json!(0)),
        ("Running", json!(true)),
        ("OOMKilled", json!(true)),
        ("Pid", json!(1)),
        ("Restarting", json!(true)),
        ("Error", json!("failure")),
    ] {
        let mut bad = expected.clone();
        bad["State"][field] = value;
        assert!(!stopped(&bad, 41));
    }
    assert!(
        PROCESS.contains("trap 'exit 41' TERM")
            && PROCESS.contains("trap 'exit 42' INT")
            && PROCESS.contains("while :;")
            && !PROCESS.contains("exit 0")
    );
}
