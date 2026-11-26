//! Logging32 source component, registered after mandatory capabilities31.
//! Exact configured drivers and one bounded read; never rotation or admission.
use super::*;
use crate::target::{LogConfig, LogDriver};
use sha2::{Digest, Sha256};

const CONTRACT: &str = "logging-v1";
const FILENAME: &str = "logging-v1.json";
const PROCESS: &str = "test \"$$\" = 1 || exit 61; printf \"%s\\n\" \"$1\"";
const DRIVERS: [&str; 3] = ["json-file", "local", "none"];
const FULL: usize = 65_550 + 8192;
const SMALL: usize = 1024 + 8192;
const CLEANUP_ENVELOPE: usize = 8192 + 2048;
const REFUSAL: &str =
    "Error response from daemon: configured logging driver does not support reading\n";
const DELIMITER: &str = "\nDOCKERLENS_LOG_EXIT:";
// Stream combined CLI bytes directly; shell variables cannot preserve NUL bytes.
// Only this inner CLI status is captured; a failed outer capture never becomes
// an accepted none result. No partial/follow/streaming reader is introduced.
const STATUS_FRAME: &str =
    "\"$@\" 2>&1; status=$?; printf '\\nDOCKERLENS_LOG_EXIT:%s\\n' \"$status\"";

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn driver(index: usize) -> &'static str {
    DRIVERS[index / 2]
}
fn role(index: usize) -> &'static str {
    if index.is_multiple_of(2) {
        "oracle"
    } else {
        "rendered"
    }
}
fn token(run: &HealthRun, index: usize) -> String {
    let token = format!(
        "dockerlens-log-v1:{}:{}:{}",
        run.run,
        driver(index),
        role(index)
    );
    assert!(
        token.is_ascii() && token.len() < 96,
        "closed bounded logging token"
    );
    token
}
fn expected(driver: &str) -> Value {
    assert!(DRIVERS.contains(&driver), "closed logging driver");
    json!({"Type":driver,"Config":if driver=="json-file"{json!({"max-size":"1m"})}else{json!({})}})
}
fn typed(driver: &str, options: Vec<ContainerLabel>) -> LogConfig {
    LogConfig {
        driver: match driver {
            "json-file" => LogDriver::JsonFile,
            "local" => LogDriver::Local,
            "none" => LogDriver::None,
            _ => panic!("closed log driver"),
        },
        options,
    }
}
fn target(
    name: &str,
    image: &str,
    run: Option<&str>,
    token: Option<&str>,
    log: Option<LogConfig>,
) -> ContainerIntent {
    ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(name.as_bytes().to_vec()).unwrap(),
        image: ImageReference::new(image.as_bytes().to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: if let Some(token) = token {
            ImageCommand::Exec(
                ["sh", "-c", PROCESS, "dl-log", token]
                    .map(|v| Argument::new(v.as_bytes().to_vec()).unwrap())
                    .into(),
            )
        } else {
            ImageCommand::Inherit
        },
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            labels: run
                .map(|owner| {
                    vec![
                        ContainerLabel::new(OWNER.as_bytes().to_vec(), owner.as_bytes().to_vec())
                            .unwrap(),
                    ]
                })
                .unwrap_or_default(),
            log_config: log,
            ..ContainerSettings::default()
        },
    }
}
fn authored(run: &HealthRun, index: usize) -> Value {
    let token = token(run, index);
    let options = if driver(index) == "json-file" {
        vec![ContainerLabel::new(b"max-size".to_vec(), b"1m".to_vec()).unwrap()]
    } else {
        vec![]
    };
    let container = target(
        &run.names[index],
        &run.base,
        Some(&run.run),
        Some(&token),
        Some(typed(driver(index), options)),
    );
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
    let graph = DockerPlanner
        .plan(
            &intent,
            &ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
    let request: Value =
        serde_json::from_slice(DockerApiRenderer.render(&graph).unwrap().bytes()).unwrap();
    let options = if driver(index) == "json-file" {
        json!({"max-size":"1m"})
    } else {
        json!({})
    };
    // Complete independently authored wire expectation; no rendered-data oracle.
    assert!(
        request
            == json!({"method":"POST","path":format!("/v{}/containers/create?name={}",run.api,run.names[index]),
        "body":{"Image":run.base,"Cmd":["sh","-c",PROCESS,"dl-log",token],"Labels":{(OWNER):run.run},"HostConfig":{"LogConfig":{"Type":driver(index),"Config":options}}}}),
        "complete literal logging request"
    );
    request
}
struct AbsenceMessage {
    message: String,
}
// Manual visitor uses the existing serde dependency without adding derive features.
impl<'de> serde::Deserialize<'de> for AbsenceMessage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MessageVisitor;
        impl<'de> serde::de::Visitor<'de> for MessageVisitor {
            type Value = AbsenceMessage;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("one exact absence message member")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut message = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key != "message" || message.is_some() {
                        return Err(serde::de::Error::custom(
                            "unknown or duplicate absence member",
                        ));
                    }
                    message = Some(map.next_value::<String>()?);
                }
                message
                    .map(|message| AbsenceMessage { message })
                    .ok_or_else(|| serde::de::Error::custom("missing absence message"))
            }
        }
        deserializer.deserialize_map(MessageVisitor)
    }
}

fn parse_absence(bytes: &[u8], name: &str) {
    assert!(bytes.len() <= 1024, "bounded name404 frame");
    let body = bytes
        .strip_suffix(b"\n404")
        .unwrap_or_else(|| panic!("exact logging name404 status"));
    let value: AbsenceMessage = serde_json::from_slice(body)
        .unwrap_or_else(|_| panic!("single exact logging absence message"));
    assert!(
        value.message == format!("No such container: {name}"),
        "absence for exact owned name only"
    );
}
fn absence(run: &HealthRun, index: usize) {
    let path = format!("/v{}/containers/{}/json", run.api, run.names[index]);
    assert!(
        run.request_allowed("GET", &path),
        "existing exact-name GET authorization"
    );
    let seconds = run
        .remaining()
        .checked_sub(Duration::from_secs(46))
        .map(|r| r.as_secs().min(7))
        .filter(|s| *s > 0)
        .unwrap_or_else(|| panic!("original logging absence cutoff"));
    let before = run.bytes.get();
    let mut command = run.timer(false, false);
    command.args([
        "python3",
        concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/native-unix-http.py"),
        "--socket",
        &run.socket,
        "--method",
        "GET",
        "--path",
        &path,
        "--timeout",
        &seconds.to_string(),
        "--max-response-bytes",
        "1000",
    ]);
    let bytes = run.capture(&mut command, None, false);
    assert!(
        run.bytes.get() - before <= SMALL,
        "small captured logging freshness envelope"
    );
    parse_absence(&bytes, &run.names[index]);
}
fn small_docker(run: &HealthRun, args: &[String]) -> Vec<u8> {
    let before = run.bytes.get();
    let bytes = docker(run, args);
    assert!(
        bytes.len() <= 1024 && run.bytes.get() - before <= SMALL,
        "small captured logging CLI envelope"
    );
    bytes
}
fn configured(run: &HealthRun, index: usize, id: &str, image: &Value, terminal: bool) -> Value {
    let key = if terminal {
        id
    } else {
        run.names[index].as_str()
    };
    let (status, v) = run.inspect(key, false);
    let token = token(run, index);
    assert!(
        status == 200
            && owned(run, &v, index, Some(id))
            && v["Image"] == image["id"]
            && v["Config"]["Labels"] == json!({(OWNER):run.run})
            && v["Config"]["Cmd"] == json!(["sh", "-c", PROCESS, "dl-log", token])
            && v["Config"]["Tty"] == false
            && (v["Config"]["Entrypoint"].is_null() || v["Config"]["Entrypoint"] == json!([]))
            && (v["HostConfig"]["Init"].is_null() || v["HostConfig"]["Init"] == false)
            && v["Config"]["Healthcheck"].is_null()
            && v["HostConfig"]["LogConfig"] == expected(driver(index))
            && v["Mounts"].as_array().is_some_and(Vec::is_empty)
            && v["HostConfig"]["Privileged"] == false
            && v["RestartCount"] == 0
            && v["State"]["Pid"] == 0
            && v["State"]["Running"] == false
            && v["State"]["Restarting"] == false
            && v["State"]["Paused"] == false
            && v["State"]["Dead"] == false
            && v["State"]["OOMKilled"] == false
            && v["State"]["ExitCode"] == 0
            && v["State"]["Error"] == "",
        "exact owned logging configuration and terminal/created outcome"
    );
    if terminal {
        let start = timestamp_ns(v["State"]["StartedAt"].as_str().unwrap()).unwrap();
        let finish = timestamp_ns(v["State"]["FinishedAt"].as_str().unwrap()).unwrap();
        assert!(
            v["State"]["Status"] == "exited" && start > 0 && finish >= start,
            "actual successfully finished logging program, never live PID0 claim"
        );
    } else {
        assert!(
            v["State"]["Status"] == "created"
                && v["State"]["StartedAt"] == "0001-01-01T00:00:00Z"
                && v["State"]["FinishedAt"] == "0001-01-01T00:00:00Z",
            "never-started owned logging configuration"
        );
    }
    json!({"log_config":v["HostConfig"]["LogConfig"],"cmd":v["Config"]["Cmd"],"tty":false,"entrypoint":"empty_inherited","init":"not_inserted","status":v["State"]["Status"],"pid":0,"running":false,"exit":0,"oom":false,"restarts":0,"error_empty":true,"started_at":v["State"]["StartedAt"],"finished_at":v["State"]["FinishedAt"]})
}
fn create(run: &mut HealthRun, index: usize, image: &Value) -> Value {
    absence(run, index);
    let request = if index.is_multiple_of(2) {
        None
    } else {
        Some(authored(run, index))
    };
    run.attempted[index] = true; // Liability is visible before either mutation.
    let id = if let Some(request) = request {
        let (status, v) = run.api(
            "POST",
            request["path"].as_str().unwrap(),
            Some(&request["body"]),
            false,
        );
        assert!(
            status == 201 && (v["Warnings"].is_null() || v["Warnings"] == json!([])),
            "known warning-free logging API create"
        );
        v["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical logging API ID"))
            .to_owned()
    } else {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
            "--log-driver".into(),
            driver(index).into(),
        ];
        if driver(index) == "json-file" {
            args.extend(["--log-opt".into(), "max-size=1m".into()]);
        }
        args.extend([
            run.base.clone(),
            "sh".into(),
            "-c".into(),
            PROCESS.into(),
            "dl-log".into(),
            token(run, index),
        ]);
        let bytes = small_docker(run, &args);
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("canonical logging CLI ID"))
            .to_owned()
    };
    assert!(
        identifier(&id)
            && id != required("NATIVE_OUTER_CONTAINER_ID")
            && run.ids.iter().flatten().all(|other| other != &id),
        "unique logging ID distinct from outer"
    );
    let before = configured(run, index, &id, image, false);
    run.ids[index] = Some(id);
    before
}
fn parse_read(bytes: &[u8], driver: &str, token: &str, id: &str) -> Value {
    assert!(
        bytes.len() <= 1024 && !bytes.contains(&0),
        "bounded NUL-free one-shot logging status frame"
    );
    let frame = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("closed logging UTF8 frame"));
    let stripped = frame
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("complete logging frame"));
    let (raw, status) = stripped
        .rsplit_once(DELIMITER)
        .unwrap_or_else(|| panic!("terminal logging status delimiter"));
    assert!(
        !raw.contains("DOCKERLENS_LOG_EXIT:") && matches!(status, "0" | "1"),
        "one noninjected actual CLI status"
    );
    let status = if status == "0" { 0 } else { 1 };
    assert!(
        if driver == "none" {
            status == 1 && raw == REFUSAL
        } else {
            status == 0 && raw == format!("{token}\n")
        },
        "actual exact driver-specific canary/refusal, not transport status"
    );
    json!({"target":id,"argv":["logs","--tail","1","--timestamps=false",id],"status":status,"raw":raw,"raw_sha256":hash(raw.as_bytes()),"frame":frame,"frame_sha256":hash(bytes)})
}
fn read(run: &HealthRun, index: usize) -> Value {
    let id = run.ids[index].as_ref().unwrap();
    let before = run.bytes.get();
    let bytes = run.outer(
        &[
            "sh".into(),
            "-c".into(),
            STATUS_FRAME.into(),
            "dl-log-status".into(),
            "env".into(),
            "LC_ALL=C".into(),
            format!("DOCKER_API_VERSION={}", run.api),
            "docker".into(),
            "-H".into(),
            "unix:///dockerlens-native/docker.sock".into(),
            "logs".into(),
            "--tail".into(),
            "1".into(),
            "--timestamps=false".into(),
            id.clone(),
        ],
        false,
    );
    assert!(
        run.bytes.get() - before <= SMALL,
        "small actual logging status capture"
    );
    parse_read(&bytes, driver(index), &token(run, index), id)
}
fn cleanup_with(
    attempted: &[bool],
    ids: &[Option<String>],
    inner: impl FnOnce() -> CleanupDisposition,
) -> CleanupDisposition {
    if attempted.len() != 6
        || ids.len() != 6
        || attempted
            .iter()
            .zip(ids)
            .any(|(a, id)| *a && !id.as_deref().is_some_and(identifier))
    {
        return CleanupDisposition::OuterTeardownRequired;
    }
    inner()
}
fn final_room(backend: SourceOuterBackend, calls: usize, bytes: usize) -> bool {
    calls
        .checked_add(54)
        .zip(bytes.checked_add(54 * CLEANUP_ENVELOPE))
        .is_some_and(|(calls, bytes)| backend.final_snapshot_room(calls, bytes, 2))
}

#[test]
fn logging_frames_require_real_inner_exit_exact_bytes_and_no_injected_records() {
    let token = "dockerlens-log-v1:RunA1234:json-file:oracle";
    let id = "a".repeat(64);
    parse_read(
        format!("{token}\n\nDOCKERLENS_LOG_EXIT:0\n").as_bytes(),
        "json-file",
        token,
        &id,
    );
    parse_read(
        format!("{REFUSAL}\nDOCKERLENS_LOG_EXIT:1\n").as_bytes(),
        "none",
        token,
        &id,
    );
    for text in [
        format!("{token}\nDOCKERLENS_LOG_EXIT:0\n"),
        format!("{token}\n\n\nDOCKERLENS_LOG_EXIT:0\n"),
        format!("{token}\n\nDOCKERLENS_LOG_EXIT:1\n"),
        format!("{token}\n\nDOCKERLENS_LOG_EXIT:0\nextra"),
        format!("{token}\n\nDOCKERLENS_LOG_EXIT:0\n\nDOCKERLENS_LOG_EXIT:0\n"),
    ] {
        assert!(
            std::panic::catch_unwind(|| parse_read(text.as_bytes(), "json-file", token, &id))
                .is_err()
        );
    }
    for (driver, raw, status) in [
        ("json-file", format!("{token}\n\0"), 0),
        ("none", format!("{REFUSAL}\0"), 1),
    ] {
        let frame = format!("{raw}\nDOCKERLENS_LOG_EXIT:{status}\n");
        assert!(
            std::panic::catch_unwind(|| parse_read(frame.as_bytes(), driver, token, &id)).is_err()
        );
    }
    assert!(
        std::panic::catch_unwind(|| parse_read(b"\nDOCKERLENS_LOG_EXIT:1\n", "none", token, &id))
            .is_err()
    );
}
#[test]
fn logging_unknown_create_never_starts_inner_cleanup() {
    let called = Cell::new(false);
    let state = cleanup_with(
        &[true, false, false, false, false, false],
        &vec![None; 6],
        || {
            called.set(true);
            CleanupDisposition::VerifiedAbsent
        },
    );
    assert!(state == CleanupDisposition::OuterTeardownRequired && !called.get());
}
#[test]
fn logging_absence_is_exact_bounded_and_rejects_duplicate_or_unknown_json() {
    parse_absence(
        b"{\"message\":\"No such container: dl-log-RunA1234-none-oracle\"}\n404",
        "dl-log-RunA1234-none-oracle",
    );
    for text in [b"{\"message\":\"No such container: wrong\"}\n404".as_slice(),b"{\"message\":\"No such container: target\",\"message\":\"No such container: target\"}\n404",b"{\"message\":\"No such container: target\",\"extra\":1}\n404",b"{\"message\":\"No such container: target\"}\n200"]{assert!(std::panic::catch_unwind(||parse_absence(text,"target")).is_err());}
}
#[test]
fn logging_pending_cleanup_and_final_reads_use_checked_original_capacity() {
    assert!(final_room(SourceOuterBackend::Podman, 244, 1_396_708));
    assert!(!final_room(SourceOuterBackend::Podman, 245, 1_396_708));
    assert!(!final_room(SourceOuterBackend::Podman, 244, 1_396_709));
    assert!(final_room(SourceOuterBackend::Docker, 243, 1_331_172));
    assert!(!final_room(SourceOuterBackend::Docker, 243, 1_331_173));
    assert!(!final_room(SourceOuterBackend::Docker, usize::MAX, 0));
    assert!(!final_room(SourceOuterBackend::Podman, 0, usize::MAX));
}

#[test]
#[ignore = "requires exact isolated native lane"]
fn live_logging_matches_engine() {
    let backend = source_outer_backend();
    let started = Instant::now();
    let target = ProofTarget::new_for("NATIVE_LOGGING_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_LOGGING_CANDIDATE_SHA",
        "NATIVE_LOGGING_DEADLINE_EPOCH",
    );
    run.names = DRIVERS
        .iter()
        .flat_map(|driver| {
            ["oracle", "rendered"].map(|role| format!("dl-log-{}-{driver}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 6];
    run.attempted = vec![false; 6];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: logging_context");
        let uid = run.context();
        let image = image_snapshot(&run);
        assert!(
            (image["config"]["Volumes"].is_null() || image["config"]["Volumes"] == json!({}))
                && (image["config"]["Entrypoint"].is_null()
                    || image["config"]["Entrypoint"] == json!([]))
                && image["config"]["Healthcheck"].is_null(),
            "borrowed logging fixture has no volume/entrypoint/health behavior"
        );
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::LogConfig,
            Capability::LogOptionMaxSize,
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
        let context_bytes = run.bytes.get();
        let pending = 21 * FULL + 24 * SMALL + backend.snapshot_extra_bytes();
        let slot_limits = [2 * FULL + 5 * SMALL, 4 * FULL + 3 * SMALL];
        assert!(
            context_calls
                == (if run.lane.starts_with("debian11-") {
                    9
                } else {
                    8
                }) + backend.snapshot_extra_calls()
                && context_calls + 45 + backend.snapshot_extra_calls() <= MAX_CALLS - CLEANUP_CALLS
                && context_bytes
                    .checked_add(pending)
                    .is_some_and(|n| n <= MAX_BYTES - CLEANUP_BYTES),
            "measured logging context and complete pending ordinary reservation"
        );
        let mut records = Vec::new();
        let mut slot_bytes = Vec::new();
        eprintln!("DOCKERLENS_NATIVE_CHECK: logging_effects");
        for index in 0..6 {
            let before_calls = run.calls.get();
            let before_bytes = run.bytes.get();
            let configured_before = create(&mut run, index, &image);
            let id = run.ids[index].as_ref().unwrap().clone();
            if index.is_multiple_of(2) {
                assert!(
                    small_docker(&run, &["start".into(), id.clone()])
                        == format!("{id}\n").as_bytes(),
                    "actual oracle start ID"
                );
            } else {
                assert!(
                    run.api(
                        "POST",
                        &format!("/v{}/containers/{id}/start", run.api),
                        None,
                        false
                    )
                    .0 == 204,
                    "actual logging rendered start"
                );
            }
            assert!(
                small_docker(&run, &["wait".into(), id.clone()]) == b"0\n",
                "actual logging program wait0"
            );
            let read = read(&run, index);
            let after = configured(&run, index, &id, &image, true);
            let bytes = run.bytes.get() - before_bytes;
            assert!(
                run.calls.get() - before_calls == 7 && bytes <= slot_limits[index % 2],
                "exact logging slot call/output schedule"
            );
            slot_bytes.push(bytes);
            records.push(json!({"driver":driver(index),"role":role(index),"id":id,"name":run.names[index],"owner":run.run,"image_id":image["id"],"wire":if index.is_multiple_of(2){"independent_cli"}else{"literal_rendered"},"requested":expected(driver(index)),"before":configured_before,"after":after,"wait_exit":0,"read":read,"cleanup":"absent"}));
        }
        let before = run.bytes.get();
        let (status, health) = run.api("GET", "/version", None, false);
        assert!(
            status == 200 && health["Version"] == run.engine,
            "post-control logging daemon version"
        );
        let daemon_health_bytes = run.bytes.get() - before;
        assert!(
            final_room(backend, run.calls.get(), run.bytes.get()),
            "cumulative cleanup plus final ordinary reads remain below original capture guard"
        );
        (
            uid,
            image,
            records,
            context_calls,
            context_bytes,
            slot_bytes,
            daemon_health_bytes,
        )
    }));
    let work_elapsed = started.elapsed();
    let before_calls = run.calls.get();
    let before_bytes = run.bytes.get();
    let cleanup_started = Instant::now();
    eprintln!("DOCKERLENS_NATIVE_CHECK: logging_cleanup");
    let attempted = run.attempted.clone();
    let ids = run.ids.clone();
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cleanup_with(&attempted, &ids, || cleanup(&mut run))
    }))
    .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_calls = run.calls.get() - before_calls;
    let cleanup_bytes = run.bytes.get() - before_bytes;
    terminal_cleanup(&mut run, &owner, disposition);
    let (uid, image, records, context_calls, context_bytes, slot_bytes, daemon_health_bytes) =
        require_verified_result(result, disposition);
    let final_calls = run.calls.get();
    let final_bytes = run.bytes.get();
    assert!(
        !run.image_attempted && run.derived_id.is_none() && image_snapshot(&run) == image,
        "borrowed logging image unchanged and never owned"
    );
    let outer = outer_context(&run);
    assert!(
        outer == owner.snapshot,
        "unchanged authenticated logging outer"
    );
    let final_readback_calls = run.calls.get() - final_calls;
    let final_readback_bytes = run.bytes.get() - final_bytes;
    let ordinary_calls = run.calls.get() - cleanup_calls;
    let ordinary_bytes = run.bytes.get() - cleanup_bytes;
    let ordinary_elapsed = started.elapsed().saturating_sub(cleanup_elapsed);
    assert!(
        ordinary_calls == context_calls + 45 + backend.snapshot_extra_calls()
            && ordinary_bytes <= MAX_BYTES - CLEANUP_BYTES
            && cleanup_calls == 54
            && cleanup_bytes <= 54 * CLEANUP_ENVELOPE
            && final_readback_calls == 2 + backend.snapshot_extra_calls(),
        "exact final logging accounting"
    );
    assert!(
        work_elapsed <= Duration::from_secs(134)
            && ordinary_elapsed <= Duration::from_secs(134)
            && cleanup_elapsed <= Duration::from_secs(46)
            && started.elapsed() <= Duration::from_secs(180),
        "original logging deadline and46second reserve"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"capability_admission":[],"catalogue_admission":false,"scope":"explicit_drivers_configured_one_line_read_only","outer_backend":if matches!(backend,SourceOuterBackend::Docker){"docker"}else{"podman"},
        "context":{"candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,"rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-"){"1.41"}else{"1.49"},"mode":if run.mode==DaemonMode::Rootless{"rootless"}else{"rootful"},"docker_package":if run.lane.starts_with("debian11-"){"20.10.5+dfsg1-1+deb11u2"}else{""},"fixture_image":run.base,"daemon_uid":uid,"outer":outer},"borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"containers":records,"daemon_health":"version_matches_after_controls",
        "accounting":{"context_calls":context_calls,"context_bytes":context_bytes,"slot_calls":[7,7,7,7,7,7],"slot_bytes":slot_bytes,"daemon_health_calls":1,"daemon_health_bytes":daemon_health_bytes,"before_cleanup_calls":before_calls,"before_cleanup_bytes":before_bytes,"ordinary_calls":ordinary_calls,"ordinary_bytes":ordinary_bytes,"cleanup_calls":cleanup_calls,"cleanup_bytes":cleanup_bytes,"final_readback_calls":final_readback_calls,"final_readback_bytes":final_readback_bytes,
        "reservation":{"pending_ordinary_bytes":21*FULL+24*SMALL+backend.snapshot_extra_bytes(),"slot_byte_limits":[2*FULL+5*SMALL,4*FULL+3*SMALL,2*FULL+5*SMALL,4*FULL+3*SMALL,2*FULL+5*SMALL,4*FULL+3*SMALL],"cleanup_calls":54,"cleanup_bytes":54*CLEANUP_ENVELOPE,"final_calls":2+backend.snapshot_extra_calls(),"final_bytes":2*FULL+backend.snapshot_extra_bytes(),"byte_scope":"captured_stdout_stderr_not_wire"},"deadline_seconds":180,"cleanup_reserve_seconds":46,"ordinary_elapsed_ns":ordinary_elapsed.as_nanos(),"cleanup_elapsed_ns":cleanup_elapsed.as_nanos(),"elapsed_ns":started.elapsed().as_nanos(),"initial_context_acquisition":{"max_requests":16,"max_total_bytes":2097152,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"}},"cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: logging_proof");
    target.publish(&proof);
}

fn unit_facts(api: u16, mode: DaemonMode, available: &[Capability]) -> DaemonFacts {
    use crate::version::{CapabilityScope, EngineRelease, ObservationId};
    let observation_id = ObservationId::fresh().unwrap();
    let release = EngineRelease::new(if api == 41 { "20.10.5" } else { "29.8.1" }.into()).unwrap();
    let api_version = ApiVersion::new(NonZeroU16::new(1).unwrap(), api);
    let scope = CapabilityScope {
        observation_id,
        release: release.clone(),
        api_version,
        mode,
    };
    DaemonFacts {
        observation_id,
        release: Some(release),
        api_version: Some(api_version),
        minimum_api_version: None,
        mode,
        capabilities: available
            .iter()
            .copied()
            .map(|capability| CapabilityFact {
                capability,
                state: CapabilityState::Available,
                provenance: FactProvenance::NativeConformance,
                scope: Some(scope.clone()),
            })
            .collect(),
    }
}
#[test]
fn logging_omitted_empty_and_explicit_requests_have_independent_literals() {
    for api in [41, 56] {
        for mode in [DaemonMode::Rootful, DaemonMode::Rootless] {
            let facts = unit_facts(
                api,
                mode,
                &[
                    Capability::StandaloneContainer,
                    Capability::LogConfig,
                    Capability::LogOptionMaxSize,
                ],
            );
            for (driver_name, with_size) in [
                (None, false),
                (Some("json-file"), false),
                (Some("json-file"), true),
                (Some("local"), false),
                (Some("none"), false),
            ] {
                let options = if with_size {
                    vec![ContainerLabel::new(b"max-size".to_vec(), b"1m".to_vec()).unwrap()]
                } else {
                    vec![]
                };
                let container = target(
                    "app",
                    "image:1",
                    None,
                    None,
                    driver_name.map(|d| typed(d, options)),
                );
                let intent =
                    TargetIntent::new(vec![TargetResource::Container(Box::new(container))])
                        .unwrap();
                let graph = DockerPlanner
                    .plan(&intent, &ValidatedCapabilities::new(&facts).unwrap())
                    .unwrap();
                let actual: Value =
                    serde_json::from_slice(DockerApiRenderer.render(&graph).unwrap().bytes())
                        .unwrap();
                let mut body = json!({"Image":"image:1","HostConfig":{}});
                if let Some(d) = driver_name {
                    body["HostConfig"] = json!({"LogConfig":{"Type":d,"Config":if with_size{json!({"max-size":"1m"})}else{json!({})}}});
                }
                assert!(
                    actual
                        == json!({"method":"POST","path":format!("/v1.{api}/containers/create?name=app"),"body":body}),
                    "literal omission/empty/explicit logging request per exact API/mode"
                );
            }
        }
    }
}
#[test]
fn logging_driver_and_max_size_capabilities_remain_independent() {
    use crate::target::{PlanningError, TargetField};
    for api in [41, 56] {
        for mode in [DaemonMode::Rootful, DaemonMode::Rootless] {
            for (available, field, capability) in [
                (
                    vec![
                        Capability::StandaloneContainer,
                        Capability::LogOptionMaxSize,
                    ],
                    TargetField::LogConfig,
                    Capability::LogConfig,
                ),
                (
                    vec![Capability::StandaloneContainer, Capability::LogConfig],
                    TargetField::LogOptionMaxSize,
                    Capability::LogOptionMaxSize,
                ),
            ] {
                let container = target(
                    "app",
                    "image:1",
                    None,
                    None,
                    Some(typed(
                        "json-file",
                        vec![ContainerLabel::new(b"max-size".to_vec(), b"1m".to_vec()).unwrap()],
                    )),
                );
                let intent =
                    TargetIntent::new(vec![TargetResource::Container(Box::new(container))])
                        .unwrap();
                let facts = unit_facts(api, mode, &available);
                assert!(
                    matches!(DockerPlanner.plan(&intent,&ValidatedCapabilities::new(&facts).unwrap()),Err(PlanningError::MissingCapability{field:found,capability:missing,..}) if found==field && missing==capability),
                    "logging permission facts do not imply one another"
                );
            }
        }
    }
}
#[test]
fn logging_options_refuse_unknown_driver_keys_and_malformed_sizes() {
    use crate::target::IntentError;
    for (d, key, value) in [
        ("json-file", "max-file", "3"),
        ("json-file", "compress", "false"),
        ("local", "max-size", "1m"),
        ("none", "max-size", "1m"),
        ("json-file", "max-size", "0m"),
        ("json-file", "max-size", "1"),
        ("json-file", "max-size", "1M"),
        ("json-file", "max-size", "18446744073709551616m"),
    ] {
        let container = target(
            "app",
            "image:1",
            None,
            None,
            Some(typed(
                d,
                vec![
                    ContainerLabel::new(key.as_bytes().to_vec(), value.as_bytes().to_vec())
                        .unwrap(),
                ],
            )),
        );
        assert!(
            matches!(
                TargetIntent::new(vec![TargetResource::Container(Box::new(container))]),
                Err(IntentError::InvalidContainerSetting)
            ),
            "finite logging options reject unsupported grammar"
        );
    }
    let container = target(
        "app",
        "image:1",
        None,
        None,
        Some(typed(
            "json-file",
            ["1m", "2m"]
                .map(|v| ContainerLabel::new(b"max-size".to_vec(), v.as_bytes().to_vec()).unwrap())
                .into(),
        )),
    );
    assert!(
        matches!(
            TargetIntent::new(vec![TargetResource::Container(Box::new(container))]),
            Err(IntentError::DuplicateContainerSetting)
        ),
        "duplicate logging option never overwrites first value"
    );
}
