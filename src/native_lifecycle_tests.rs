//! lifecycle-v1 source probe. Test-local facts are never capability admission.

use super::*;

#[path = "native_lifecycle_default_effect_tests.rs"]
mod default_effect;

#[path = "native_runtime_filesystem_tests.rs"]
mod runtime_filesystem;

#[path = "native_tmpfs_effect_tests.rs"]
mod tmpfs_effect;

#[path = "native_health_start_interval_boundary_tests.rs"]
mod health_start_interval_boundary;

#[path = "native_hostname_tests.rs"]
mod hostname;

const CONTRACT: &str = "lifecycle-v1";
const FILENAME: &str = "lifecycle-v1.json";
const CLEANUP_OWNER: &str = "native_conformance_outer_v1";
const CLEANUP_HANDOFF: &str = "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required";
const STOP_PROCESS: &str = "[ \"$$\" -eq 1 ] || exit 43; trap 'printf \"lifecycle-term\\n\"; sleep 3; exit 41' TERM; printf 'pid1-term-ready\\n' > /tmp/dl-lifecycle-ready; while :; do sleep 1 & wait $!; done";
const READY: &str = "for n in 1 2 3 4 5 6 7 8 9 10; do if [ -f /tmp/dl-lifecycle-ready ]; then cat /tmp/dl-lifecycle-ready; exit 0; fi; sleep 0.2; done; exit 1";
const HEALTH_PROCESS: &str = "while :; do sleep 1; done";
const HEALTH_COMMAND: &str = "printf 'lifecycle-health-failure\\n'; exit 1";
const STOP_CASES: [(u32, i64, u64, u64); 2] = [
    (1, 137, 800_000_000, 2_500_000_000),
    (5, 41, 2_800_000_000, 5_500_000_000),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum CleanupDisposition {
    VerifiedAbsent,
    OuterTeardownRequired,
}

// Construction requires a positive immutable outer-context readback, not merely
// a caller token. This is a harness contract, never cryptographic attestation.
struct BoundOuterCleanupOwner {
    snapshot: Value,
}

impl BoundOuterCleanupOwner {
    fn bind(run: &HealthRun) -> Self {
        let snapshot = outer_context(run);
        assert_eq!(required("NATIVE_LIFECYCLE_CLEANUP_OWNER"), CLEANUP_OWNER);
        Self { snapshot }
    }

    fn require_teardown(&self) {
        // Canonical native-conformance.sh supplies this token, preserves the
        // exact-test nonzero exit -> set -e -> EXIT trap chain, and verifies
        // terminal outer ID/name/owner and data-volume ownership/readback. That
        // owner removes its disposable daemon and storage; this inner test must
        // never retry a mutation after uncertain transport. Only this constant
        // marker may cross the wrapper's public diagnostics boundary. A request
        // for teardown is not confirmation that outer teardown succeeded.
        // Diagnostics cannot replace the original observation failure if the
        // wrapper's output pipe has closed. Nonzero exit still owns the handoff.
        let _ = writeln!(std::io::stderr(), "{CLEANUP_HANDOFF}");
    }
}

fn cleanup_disposition(verified: bool) -> CleanupDisposition {
    if verified {
        CleanupDisposition::VerifiedAbsent
    } else {
        CleanupDisposition::OuterTeardownRequired
    }
}

fn terminal_cleanup(
    run: &mut HealthRun,
    owner: &BoundOuterCleanupOwner,
    disposition: CleanupDisposition,
) {
    if disposition == CleanupDisposition::OuterTeardownRequired {
        let _ = writeln!(
            std::io::stderr(),
            "DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup_unverified"
        );
        owner.require_teardown();
    }
    // This terminal handler alone disarms the incompatible historical Drop.
    // On failure the already-bound outer owner has received a teardown request;
    // the disposition stays nonpositive and no success proof may be published.
    run.cleaned = true;
}

fn require_verified_result<T>(
    result: std::thread::Result<T>,
    disposition: CleanupDisposition,
) -> T {
    // An original observation panic always wins over a cleanup failure. Either
    // failure propagates through the mandatory wrapper into outer EXIT teardown.
    let value = match result {
        Ok(value) => value,
        Err(error) => std::panic::resume_unwind(error),
    };
    assert!(
        disposition == CleanupDisposition::VerifiedAbsent,
        "lifecycle outer teardown required; success proof refused"
    );
    value
}

// Unlike the shared context's informational CLI calls, every fixture CLI call
// is explicitly API-pinned. No negotiated CLI API is claimed as request proof.
fn docker(run: &HealthRun, args: &[String]) -> Vec<u8> {
    let mut command = vec![
        "env".into(),
        format!("DOCKER_API_VERSION={}", run.api),
        "docker".into(),
        "-H".into(),
        "unix:///dockerlens-native/docker.sock".into(),
    ];
    command.extend_from_slice(args);
    run.outer(&command, false)
}

fn outer_context(run: &HealthRun) -> Value {
    let id = required("NATIVE_OUTER_CONTAINER_ID");
    assert!(identifier(&id), "closed outer identity");
    let image = required("NATIVE_OUTER_IMAGE");
    let (_, digest) = image
        .rsplit_once('@')
        .unwrap_or_else(|| panic!("pinned outer image"));
    assert!(image_identifier(digest), "canonical outer digest");
    let elevated = match required("NATIVE_PODMAN_USE_SUDO").as_str() {
        "0" => false,
        "1" => true,
        _ => panic!("closed privilege selector"),
    };
    run.charge_outer_snapshot(false);
    let mut command = run.timer(false, elevated);
    command.args(crate::native_outer_test_command::prefix());
    command.args(["inspect", "--format", "{{json .}}", &id]);
    let value: Value = serde_json::from_slice(&run.capture(&mut command, None, false))
        .unwrap_or_else(|_| panic!("private outer JSON"));
    let mounts = value["Mounts"]
        .as_array()
        .unwrap_or_else(|| panic!("outer mounts"));
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
        .unwrap_or_else(|| panic!("outer network"));
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
        "authenticated unchanged two-CPU outer context"
    );
    json!({"id":id,"name":run.outer,"owner":run.run,"image":image,
        "data_volume":format!("dl-native-data-{}",run.run),"socket_source":directory.join("socket"),
        "privileged":true,"memory_bytes":4294967296_u64,"cpu_quota":200000,"cpu_period":100000,"pids_limit":512})
}

fn image_snapshot(run: &HealthRun) -> Value {
    let (status, value) = run.api(
        "GET",
        &format!("/v{}/images/{}/json", run.api, run.base),
        None,
        false,
    );
    assert_eq!(status, 200);
    assert!(
        value["Id"].as_str().is_some_and(image_identifier),
        "canonical borrowed image"
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
        "actual borrowed digest"
    );
    assert!(
        value["Config"]["StopSignal"].is_null()
            || value["Config"]["StopSignal"] == ""
            || value["Config"]["StopSignal"] == "SIGTERM",
        "borrowed default TERM signal"
    );
    json!({"id":value["Id"],"repo_digests":value["RepoDigests"],"config":value["Config"]})
}

fn utc_ns() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| panic!("caller UTC epoch"))
            .as_nanos(),
    )
    .unwrap_or_else(|_| panic!("bounded caller UTC"))
}

fn clock_consistent(native: u128, before: u64, after: u64, elapsed: u64) -> bool {
    after >= before
        && after - before <= 500_000_000
        && elapsed <= 500_000_000
        && (after - before).abs_diff(elapsed) <= 50_000_000
        && native >= u128::from(before.saturating_sub(250_000_000))
        && native <= u128::from(after) + 250_000_000
}

// Never silently assume daemon/caller UTC agreement: retain each small private
// UTC bracket and monotonic RTT. Clock jumps, slow requests and drift fail.
fn native_time(run: &HealthRun) -> (String, Value) {
    let monotonic = Instant::now();
    let before = utc_ns();
    let (status, info) = run.api("GET", &format!("/v{}/info", run.api), None, false);
    let after = utc_ns();
    let elapsed = u64::try_from(monotonic.elapsed().as_nanos()).unwrap();
    assert_eq!(status, 200);
    let value = info["SystemTime"]
        .as_str()
        .unwrap_or_else(|| panic!("native clock"));
    let native = timestamp_ns(value).unwrap_or_else(|| panic!("bounded native timestamp"));
    assert!(
        clock_consistent(native, before, after, elapsed),
        "bounded caller and daemon clock agreement"
    );
    (value.to_owned(), json!([before, after, elapsed]))
}

fn process(index: usize) -> &'static str {
    if index < 4 {
        STOP_PROCESS
    } else {
        HEALTH_PROCESS
    }
}

// The historical health helper assigns slots 4..7 to a derived image. This
// contract owns six containers of the borrowed base, never that image ledger.
fn owned(run: &HealthRun, value: &Value, index: usize, id: Option<&str>) -> bool {
    value["Id"]
        .as_str()
        .is_some_and(|actual| identifier(actual) && id.is_none_or(|expected| actual == expected))
        && value["Name"] == format!("/{}", run.names[index])
        && value["Config"]["Image"] == run.base
        && value["Config"]["Labels"][OWNER] == run.run
}

fn bind(run: &mut HealthRun, index: usize, id: &str) {
    assert!(identifier(id), "canonical created lifecycle ID");
    let (status, value) = run.inspect(&run.names[index], false);
    assert_eq!(status, 200);
    assert!(
        owned(run, &value, index, Some(id))
            && run.ids.iter().flatten().all(|other| other != id)
            && id != required("NATIVE_OUTER_CONTAINER_ID"),
        "fresh exact lifecycle ownership"
    );
    run.ids[index] = Some(id.to_owned());
}

fn remove_container(run: &mut HealthRun, index: usize) -> bool {
    let (status, value) = run.inspect(&run.names[index], true);
    if status == 404 {
        return run.ids[index].is_some();
    }
    if status != 200 || !owned(run, &value, index, run.ids[index].as_deref()) {
        return false;
    }
    let id = value["Id"]
        .as_str()
        .unwrap_or_else(|| panic!("owned cleanup ID"))
        .to_owned();
    if id == required("NATIVE_OUTER_CONTAINER_ID")
        || run
            .ids
            .iter()
            .enumerate()
            .any(|(other, registered)| other != index && registered.as_deref() == Some(&id))
    {
        return false;
    }
    run.ids[index] = Some(id.clone());
    let (status, immediate) = run.inspect(&id, true);
    if status != 200 || !owned(run, &immediate, index, Some(&id)) {
        return false;
    }
    run.api(
        "DELETE",
        &format!("/v{}/containers/{id}?force=1", run.api),
        None,
        true,
    )
    .0 == 204
        && run.inspect(&id, true).0 == 404
        && run.inspect(&run.names[index], true).0 == 404
}

fn cleanup(run: &mut HealthRun) -> CleanupDisposition {
    let mut verified = true;
    for index in 0..run.names.len() {
        if run.attempted[index] {
            verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                remove_container(run, index)
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
        if index < 4 {
            args.extend(["--stop-timeout".into(), STOP_CASES[index / 2].0.to_string()]);
        } else {
            // Deliberately omit --health-start-interval. Modern Engine may use
            // its default 5s during grace; the control is not assumed to be 8s.
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
        let output = docker(run, &args);
        let id = std::str::from_utf8(&output)
            .ok()
            .and_then(|text| text.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("exact CLI create ID"));
        bind(run, index, id);
        return;
    }
    let healthcheck = (index == 5).then(|| {
        Healthcheck::configured(
            HealthTest::Shell(Argument::new(HEALTH_COMMAND.as_bytes().to_vec()).unwrap()),
            NonZeroU64::new(8 * SECOND),
            NonZeroU64::new(SECOND),
            NonZeroU32::new(3),
        )
        .and_then(|health| health.with_start_period(30 * SECOND))
        .and_then(|health| health.with_start_interval(SECOND))
        .unwrap_or_else(|_| panic!("typed lifecycle health"))
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
                .map(|value| Argument::new(value.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                    .unwrap(),
            ],
            stop_timeout_seconds: if index < 4 {
                Some(STOP_CASES[index / 2].0)
            } else {
                None
            },
            ..ContainerSettings::default()
        },
    };
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
    let caps = ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap();
    let graph = DockerPlanner
        .plan(&intent, &caps)
        .unwrap_or_else(|_| panic!("test-local lifecycle planning"));
    let artifact = DockerApiRenderer
        .render(&graph)
        .unwrap_or_else(|_| panic!("test-local lifecycle rendering"));
    let request: Value =
        serde_json::from_slice(artifact.bytes()).unwrap_or_else(|_| panic!("one inert request"));
    let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
    let mut body = json!({"Image":run.base,"Cmd":["sh","-c",process(index)],"Labels":{(OWNER):run.run},"HostConfig":{}});
    if index < 4 {
        body["StopTimeout"] = json!(STOP_CASES[index / 2].0);
    } else {
        body["Healthcheck"] = json!({"Test":["CMD-SHELL",HEALTH_COMMAND],"Interval":8*SECOND,"Timeout":SECOND,
            "Retries":3,"StartPeriod":30*SECOND,"StartInterval":SECOND});
    }
    // Independent complete literal comparison precedes submission, including
    // the candidate's actual StartInterval field on the selected request API.
    assert_eq!(request, json!({"method":"POST","path":path,"body":body}));
    run.attempted[index] = true;
    let (status, value) = run.api("POST", &path, Some(&request["body"]), false);
    assert_eq!(status, 201);
    assert!(
        value["Warnings"].is_null() || value["Warnings"] == json!([]),
        "unambiguous create acceptance"
    );
    bind(
        run,
        index,
        value["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical rendered ID")),
    );
}

fn configured(run: &HealthRun, index: usize, base: &Value) -> Value {
    let id = run.ids[index].as_deref().unwrap();
    let (status, value) = run.inspect(id, false);
    assert_eq!(status, 200);
    assert!(
        owned(run, &value, index, Some(id)),
        "exact lifecycle ownership"
    );
    assert_eq!(value["Image"], base["id"]);
    assert_eq!(value["Config"]["Cmd"], json!(["sh", "-c", process(index)]));
    assert!(
        value["Config"]["Entrypoint"].is_null() || value["Config"]["Entrypoint"] == json!([]),
        "inherited empty entrypoint"
    );
    assert_eq!(value["Path"], "sh");
    assert_eq!(value["Args"], json!(["-c", process(index)]));
    assert_eq!(value["RestartCount"], 0);
    if index < 4 {
        assert_eq!(value["Config"]["StopTimeout"], STOP_CASES[index / 2].0);
        assert!(
            value["Config"]["StopSignal"].is_null()
                || value["Config"]["StopSignal"] == ""
                || value["Config"]["StopSignal"] == "SIGTERM",
            "default TERM configuration"
        );
    } else {
        let health = &value["Config"]["Healthcheck"];
        assert_eq!(health["Test"], json!(["CMD-SHELL", HEALTH_COMMAND]));
        assert_eq!(health["Interval"], 8 * SECOND);
        assert_eq!(health["Timeout"], SECOND);
        assert_eq!(health["Retries"], 3);
        assert_eq!(health["StartPeriod"], 30 * SECOND);
    }
    value
}

fn running(value: &Value) -> bool {
    value["State"]["Status"] == "running"
        && value["State"]["Running"] == true
        && value["State"]["Pid"].as_u64().is_some_and(|pid| pid > 0)
        && value["State"]["Restarting"] == false
        && value["State"]["Paused"] == false
        && value["State"]["Dead"] == false
        && value["State"]["OOMKilled"] == false
        && value["State"]["Error"] == ""
        && value["RestartCount"] == 0
}

fn start(run: &HealthRun, index: usize) {
    let id = run.ids[index].as_deref().unwrap();
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
}

fn stopped(value: &Value, exit: i64) -> bool {
    value["State"]["Status"] == "exited"
        && value["State"]["Running"] == false
        && value["State"]["Pid"] == 0
        && value["State"]["ExitCode"] == exit
        && value["State"]["Restarting"] == false
        && value["State"]["Paused"] == false
        && value["State"]["Dead"] == false
        && value["State"]["OOMKilled"] == false
        && value["State"]["Error"] == ""
        && value["RestartCount"] == 0
}

fn identity(run: &HealthRun, index: usize, base: &Value) -> Value {
    json!({"role":if index.is_multiple_of(2) {"oracle"} else {"rendered"},"id":run.ids[index],"name":run.names[index],
        "owner":run.run,"image":run.base,"image_id":base["id"],"wire":if index.is_multiple_of(2) {"independent_cli"} else {"literal_rendered"},
        "cleanup":"absent"})
}

fn stop_observation(run: &mut HealthRun, index: usize, base: &Value) -> Value {
    eprintln!("DOCKERLENS_NATIVE_LIFECYCLE_STAGE: case={index} stage=create");
    create(run, index);
    assert_eq!(configured(run, index, base)["State"]["Status"], "created");
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
    let before = configured(run, index, base);
    assert!(running(&before), "actual ready running PID1");
    let started = before["State"]["StartedAt"].as_str().unwrap();
    let (ready_at, ready_clock) = native_time(run);
    let (requested_at, request_clock) = native_time(run);
    eprintln!("DOCKERLENS_NATIVE_LIFECYCLE_STAGE: case={index} stage=stop");
    let clock = Instant::now();
    // Ordinary stop: neither timeout nor signal override may mask configuration.
    let output = docker(run, &["stop".into(), id.clone()]);
    let elapsed = u64::try_from(clock.elapsed().as_nanos()).unwrap();
    let (seconds, exit, lower, upper) = STOP_CASES[index / 2];
    assert!(
        (lower..upper).contains(&elapsed),
        "unambiguous monotonic stop window"
    );
    assert_eq!(output.as_slice(), format!("{id}\n").as_bytes());
    let after = configured(run, index, base);
    assert!(
        stopped(&after, exit),
        "forced or graceful configured-timeout effect"
    );
    assert_eq!(after["State"]["StartedAt"], started);
    let logs = docker(run, &["logs".into(), id]);
    assert_eq!(logs.as_slice(), b"lifecycle-term\n".as_slice());
    let finished = after["State"]["FinishedAt"].as_str().unwrap();
    let (observed_at, observed_clock) = native_time(run);
    let times = [started, &ready_at, &requested_at, finished, &observed_at]
        .map(|time| timestamp_ns(time).unwrap_or_else(|| panic!("ordered lifecycle time")));
    assert!(
        times.windows(2).all(|pair| pair[0] <= pair[1])
            && times[2] < times[3]
            && times[4] <= times[0] + 180 * u128::from(SECOND),
        "native stop causality"
    );
    let duration = times[3] - times[2];
    assert!(
        duration >= u128::from(lower)
            && duration < u128::from(upper)
            && duration.abs_diff(u128::from(elapsed)) <= 500_000_000,
        "native and monotonic stop agreement"
    );
    let mut record = identity(run, index, base);
    record.as_object_mut().unwrap().extend(json!({"configured_seconds":seconds,"readiness":"pid1-term-ready",
        "term_marker":true,"running_before_stop":true,"started_at":started,"ready_observed_at":ready_at,
        "stop_requested_at":requested_at,"finished_at":finished,"stopped_observed_at":observed_at,
        "ready_clock":ready_clock,"request_clock":request_clock,"observed_clock":observed_clock,
        "timeout_override":false,"signal_override":false,"stop_elapsed_ns":elapsed,"exit_code":exit,
        "state":"exited","running":false,"pid":0,"oom_killed":false,"restarting":false,"restart_count":0,
        "paused":false,"dead":false,"state_error_empty":true}).as_object().unwrap().clone());
    record
}

fn attempts(value: &Value, started: u128, observed: u128) -> Vec<Value> {
    let log = match value["State"]["Health"].get("Log") {
        Some(Value::Null) => return Vec::new(),
        Some(Value::Array(log)) => log,
        _ => panic!("complete health attempt log"),
    };
    assert!(log.len() <= 5, "bounded health history");
    let mut previous = started;
    log.iter()
        .map(|entry| {
            assert_eq!(entry["ExitCode"], 1);
            assert_eq!(entry["Output"], "lifecycle-health-failure\n");
            let start = entry["Start"]
                .as_str()
                .unwrap_or_else(|| panic!("attempt start"));
            let end = entry["End"]
                .as_str()
                .unwrap_or_else(|| panic!("attempt end"));
            let start_ns = timestamp_ns(start).unwrap_or_else(|| panic!("attempt start time"));
            let end_ns = timestamp_ns(end).unwrap_or_else(|| panic!("attempt finish time"));
            assert!(
                previous <= start_ns
                    && start_ns < end_ns
                    && end_ns <= observed
                    && end_ns - start_ns < u128::from(SECOND),
                "real ordered completed health attempt"
            );
            previous = end_ns;
            json!({"start":start,"end":end,"exit_code":1,"marker":"lifecycle-health-failure"})
        })
        .collect()
}

fn start_interval(value: &Value) -> u64 {
    let healthcheck = value
        .get("Config")
        .and_then(Value::as_object)
        .and_then(|config| config.get("Healthcheck"))
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("healthcheck readback object"));
    match healthcheck.get("StartInterval") {
        None => 0,
        Some(interval) => interval
            .as_u64()
            .unwrap_or_else(|| panic!("bounded interval readback")),
    }
}

fn health_snapshot(
    run: &HealthRun,
    index: usize,
    base: &Value,
    started: &str,
    readback: u64,
    early: bool,
) -> Value {
    let start_ns = timestamp_ns(started).unwrap_or_else(|| panic!("own health start time"));
    let (target, lower, upper) = if early {
        (3_400_000_000, 3_300_000_000, 4_000_000_000)
    } else {
        (9_500_000_000, 9_000_000_000, 12_000_000_000)
    };
    let (now, _) = native_time(run);
    let now = timestamp_ns(&now).unwrap();
    assert!(
        now >= start_ns && now < start_ns + upper,
        "never late health observation"
    );
    let wait =
        Duration::from_nanos(u64::try_from((start_ns + target).saturating_sub(now)).unwrap());
    assert!(
        run.remaining() > wait + Duration::from_secs(46),
        "same cleanup reserve before health wait"
    );
    std::thread::sleep(wait);
    let (before, before_clock) = native_time(run);
    let value = configured(run, index, base);
    let (after, after_clock) = native_time(run);
    let before_ns = timestamp_ns(&before).unwrap();
    let after_ns = timestamp_ns(&after).unwrap();
    assert!(
        start_ns + lower <= before_ns && before_ns <= after_ns && after_ns < start_ns + upper,
        "timely bracket relative to this container's own start"
    );
    assert_eq!(value["State"]["StartedAt"], started);
    assert_eq!(start_interval(&value), readback);
    assert!(running(&value), "health PID1 remains running");
    assert_eq!(value["State"]["Health"]["Status"], "starting");
    assert_eq!(value["State"]["Health"]["FailingStreak"], 0);
    json!({"before":before,"after":after,"before_clock":before_clock,"after_clock":after_clock,
        "status":"starting","failing_streak":0,"running":true,"restart_count":0,
        "attempts":attempts(&value,start_ns,after_ns)})
}

fn health_observation(run: &mut HealthRun, index: usize, base: &Value) -> Value {
    eprintln!("DOCKERLENS_NATIVE_LIFECYCLE_STAGE: case={index} stage=create");
    create(run, index);
    assert_eq!(configured(run, index, base)["State"]["Status"], "created");
    start(run, index);
    let value = configured(run, index, base);
    assert!(running(&value), "health fixture running");
    let started = value["State"]["StartedAt"].as_str().unwrap();
    let readback = start_interval(&value);
    assert!(
        readback == 0 || index == 5 && readback == SECOND,
        "closed interval readback"
    );
    eprintln!("DOCKERLENS_NATIVE_LIFECYCLE_STAGE: case={index} stage=early");
    let early = health_snapshot(run, index, base, started, readback, true);
    eprintln!("DOCKERLENS_NATIVE_LIFECYCLE_STAGE: case={index} stage=late");
    let late = health_snapshot(run, index, base, started, readback, false);
    let early_after = timestamp_ns(early["after"].as_str().unwrap()).unwrap();
    assert!(
        late["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |attempt| timestamp_ns(attempt["start"].as_str().unwrap()).unwrap() >= early_after
            ),
        "genuine later failed attempt while still starting"
    );
    let mut record = identity(run, index, base);
    record.as_object_mut().unwrap().extend(
        json!({"request_accepted":true,
        "start_interval_request":if index==5 {json!(SECOND)} else {json!("omitted")},
        "start_interval_readback_ns":readback,"started_at":started,"early":early,"late":late})
        .as_object()
        .unwrap()
        .clone(),
    );
    record
}

fn health_outcome(lane: &str, control: &Value, candidate: &Value) -> &'static str {
    assert_eq!(control["early"]["attempts"].as_array().unwrap().len(), 0);
    assert_eq!(control["start_interval_readback_ns"], 0);
    let count = candidate["early"]["attempts"].as_array().unwrap().len();
    if count >= 3 && candidate["start_interval_readback_ns"] == SECOND {
        "effective"
    } else {
        // A version alone, refusal, absent field, one/two attempts or late poll
        // can never create a negative observation. Both later effects already
        // passed and the literal candidate request was actually accepted.
        assert!(
            lane.starts_with("debian11-")
                && count == 0
                && candidate["start_interval_readback_ns"] == 0,
            "ambiguous health scheduling effect"
        );
        "not_effective_on_selected_api"
    }
}

#[test]
#[ignore = "requires isolated exact-profile Docker Engine and authenticated harness"]
fn live_lifecycle_matches_engine() {
    let target = ProofTarget::new_for("NATIVE_LIFECYCLE_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_LIFECYCLE_CANDIDATE_SHA",
        "NATIVE_LIFECYCLE_DEADLINE_EPOCH",
    );
    run.names = [
        "timeout-1-oracle",
        "timeout-1-rendered",
        "timeout-5-oracle",
        "timeout-5-rendered",
        "health-control",
        "health-candidate",
    ]
    .map(|suffix| format!("dl-life-{}-{suffix}", run.run))
    .into();
    run.ids = vec![None; 6];
    run.attempted = vec![false; 6];
    eprintln!("DOCKERLENS_NATIVE_CHECK: lifecycle_context");
    // Bind the mandatory terminal owner before entering any fixture mutation.
    // If this preflight fails, all attempted entries are still false.
    let cleanup_owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let outer = cleanup_owner.snapshot.clone();
        let daemon_uid = run.context();
        let base = image_snapshot(&run);
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        // Existing renderer at actual lane API, explicitly unadmitted test
        // facts. This neither invents a generic API floor nor alters a catalog.
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
        let mut stops = Vec::new();
        for (case, (seconds, exit, _, _)) in STOP_CASES.into_iter().enumerate() {
            let containers = [
                stop_observation(&mut run, 2 * case, &base),
                stop_observation(&mut run, 2 * case + 1, &base),
            ];
            stops.push(json!({"configured_seconds":seconds,"expected_exit_code":exit,"containers":containers}));
        }
        // Sequential starts deliberately avoid any simultaneous-start premise.
        let control = health_observation(&mut run, 4, &base);
        let candidate = health_observation(&mut run, 5, &base);
        let outcome = health_outcome(&run.lane, &control, &candidate);
        let health = json!({"outcome":outcome,"interval_ns":8*SECOND,"start_period_ns":30*SECOND,
            "start_interval_ns":SECOND,"timeout_ns":SECOND,"retries":3,"containers":[control,candidate]});
        (outer, daemon_uid, base, stops, health)
    }));
    if result.is_ok() {
        eprintln!("DOCKERLENS_NATIVE_LIFECYCLE: observations_complete");
    }
    eprintln!("DOCKERLENS_NATIVE_CHECK: lifecycle_cleanup");
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cleanup(&mut run)))
        .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    terminal_cleanup(&mut run, &cleanup_owner, disposition);
    let (outer, daemon_uid, base, stops, health) = require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none(),
        "borrowed image is never owned"
    );
    // Final snapshots remain ordinary work; no cleanup reserve or reset.
    assert_eq!(image_snapshot(&run), base);
    assert_eq!(outer_context(&run), outer);
    let proof = json!({"schema_version":1,"contract":CONTRACT,"context":{
        "candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,
        "rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},
        "mode":if run.mode==DaemonMode::Rootless {"rootless"} else {"rootful"},
        "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},
        "fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "apis":{"fixture_cli":run.api,"stop_renderer":run.api,"health_renderer":run.api,"request":run.api,
            "health_probe":"test_local_unadmitted"},
        "borrowed_image":{"id":base["id"],"identity":"unchanged","removal":"not_owned"},
        "stop_timeout":stops,"health_start_interval":health,
        "cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: lifecycle_evidence");
    target.publish(&proof);
}

#[test]
fn lifecycle_cleanup_handoff_is_nonpositive_and_preserves_the_original_panic() {
    assert!(cleanup_disposition(true) == CleanupDisposition::VerifiedAbsent);
    assert!(cleanup_disposition(false) == CleanupDisposition::OuterTeardownRequired);
    assert_eq!(
        require_verified_result(Ok(41), CleanupDisposition::VerifiedAbsent),
        41
    );
    let refused = std::panic::catch_unwind(|| {
        require_verified_result(Ok(41), CleanupDisposition::OuterTeardownRequired)
    });
    assert!(refused.is_err(), "handoff cannot become verified cleanup");
    for disposition in [
        CleanupDisposition::VerifiedAbsent,
        CleanupDisposition::OuterTeardownRequired,
    ] {
        let original = std::panic::catch_unwind(|| {
            require_verified_result::<()>(Err(Box::new("original lifecycle failure")), disposition)
        })
        .expect_err("original failure must propagate");
        assert_eq!(
            original.downcast_ref::<&str>().copied(),
            Some("original lifecycle failure")
        );
    }
    assert_eq!(
        CLEANUP_HANDOFF,
        "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"
    );
}

#[test]
fn lifecycle_clock_checks_refuse_drift_jumps_and_slow_roundtrips() {
    assert!(clock_consistent(
        1_000_000_000,
        990_000_000,
        1_010_000_000,
        20_000_000
    ));
    assert!(!clock_consistent(
        2_000_000_000,
        990_000_000,
        1_010_000_000,
        20_000_000
    ));
    assert!(!clock_consistent(
        1_000_000_000,
        1_010_000_000,
        990_000_000,
        20_000_000
    ));
    assert!(!clock_consistent(
        1_000_000_000,
        900_000_000,
        1_100_000_000,
        20_000_000
    ));
    assert!(!clock_consistent(
        1_000_000_000,
        900_000_000,
        1_600_000_000,
        700_000_000
    ));
}

#[test]
fn lifecycle_attempts_distinguish_empty_history_from_incomplete_or_wrong_output() {
    let start = "2026-10-01T00:00:00Z";
    let started = timestamp_ns(start).unwrap();
    assert!(
        attempts(
            &json!({"State":{"Health":{"Log":null}}}),
            started,
            started + 4 * u128::from(SECOND)
        )
        .is_empty()
    );
    let valid = json!({"State":{"Health":{"Log":[{"Start":"2026-10-01T00:00:01Z",
        "End":"2026-10-01T00:00:01.01Z","ExitCode":1,"Output":"lifecycle-health-failure\n"}]}}});
    assert_eq!(
        attempts(&valid, started, started + 4 * u128::from(SECOND)).len(),
        1
    );
    for invalid in [
        json!({"State":{"Health":{}}}),
        json!({"State":{"Health":{"Log":false}}}),
    ] {
        assert!(
            std::panic::catch_unwind(|| attempts(
                &invalid,
                started,
                started + 4 * u128::from(SECOND)
            ))
            .is_err()
        );
    }
    for (key, wrong) in [
        ("ExitCode", json!(0)),
        ("Output", json!("PRIVATE_LIFECYCLE_CANARY")),
    ] {
        let mut invalid = valid.clone();
        invalid["State"]["Health"]["Log"][0][key] = wrong;
        assert!(
            std::panic::catch_unwind(|| attempts(
                &invalid,
                started,
                started + 4 * u128::from(SECOND)
            ))
            .is_err()
        );
    }
}

#[test]
fn lifecycle_start_interval_accepts_absence_zero_and_positive_integer() {
    assert_eq!(start_interval(&json!({"Config":{"Healthcheck":{}}})), 0);
    for interval in [0, 1, SECOND] {
        assert_eq!(
            start_interval(&json!({"Config":{"Healthcheck":{"StartInterval":interval}}})),
            interval
        );
    }
}

#[test]
fn lifecycle_start_interval_rejects_null_malformed_and_missing_parent_objects() {
    for interval in [
        Value::Null,
        json!("PRIVATE_LIFECYCLE_CANARY"),
        json!(false),
        json!(-1),
        json!(0.0),
        json!(1.5),
        json!([]),
        json!({}),
    ] {
        let invalid = json!({"Config":{"Healthcheck":{"StartInterval":interval}}});
        let failure = std::panic::catch_unwind(|| {
            start_interval(&invalid);
        })
        .expect_err("malformed interval must fail");
        assert_eq!(
            failure.downcast_ref::<&str>().copied(),
            Some("bounded interval readback")
        );
    }
    for invalid in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"Config":null}),
        json!({"Config":[]}),
        json!({"Config":{}}),
        json!({"Config":{"Healthcheck":null}}),
        json!({"Config":{"Healthcheck":false}}),
        json!({"Config":{"Healthcheck":[]}}),
        json!({"Config":{"Healthcheck":"PRIVATE_LIFECYCLE_CANARY"}}),
    ] {
        let failure = std::panic::catch_unwind(|| {
            start_interval(&invalid);
        })
        .expect_err("healthcheck object must be present");
        assert_eq!(
            failure.downcast_ref::<&str>().copied(),
            Some("healthcheck readback object")
        );
    }
}

#[test]
fn lifecycle_assertions_never_format_compared_native_values() {
    let failure = std::panic::catch_unwind(|| {
        assert_eq!("PRIVATE_LIFECYCLE_CANARY", "other");
    })
    .expect_err("unequal closed comparison");
    let message = failure
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| failure.downcast_ref::<String>().map(String::as_str));
    assert!(message.is_some_and(|message| message == "closed health metadata equality failed"));
}

#[test]
fn lifecycle_timeouts_require_distinct_effects_and_nonoverlapping_windows() {
    assert!(STOP_CASES[0].3 < STOP_CASES[1].2);
    assert_eq!(STOP_CASES[0].1, 137);
    assert_eq!(STOP_CASES[1].1, 41);
    let value = json!({"State":{"Status":"exited","Running":false,"Pid":0,"ExitCode":41,
        "Restarting":false,"Paused":false,"Dead":false,"OOMKilled":false,"Error":""},"RestartCount":0});
    assert!(stopped(&value, 41) && !stopped(&value, 137));
    for (key, invalid) in [
        ("OOMKilled", json!(true)),
        ("Running", json!(true)),
        ("Paused", json!(true)),
        ("Dead", json!(true)),
        ("Restarting", json!(true)),
        ("Pid", json!(1)),
        ("Error", json!("private")),
    ] {
        let mut value = value.clone();
        value["State"][key] = invalid;
        assert!(!stopped(&value, 41));
    }
}
