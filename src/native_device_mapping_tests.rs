//! Device mapping configured retention and bounded read source; never admission.
use super::*;
use crate::target::{DeviceMapping, DevicePermissions, WorkingDirectory};
use sha2::{Digest, Sha256};

const CONTRACT: &str = "device-mapping-v1";
const FILENAME: &str = "device-mapping-v1.json";
const PROCESS: &str = "test \"$$\" = 1 || exit 61; while :; do sleep 1; done";
// Read only the held descriptor. Compare its inode with the nonsymlink target
// before and after the bounded read; all failures propagate through docker exec.
const OBSERVE: &str = r#"set -eu; LC_ALL=C; export LC_ALL; umask 077
p=/dev/native-null; f=/tmp/dl-device-read
test ! -L /dev/null; test -c /dev/null
test ! -L "$p"; test -c "$p"
printf 'source '; stat -c '%t %T' /dev/null
printf 'target '; stat -c '%d %i %t %T' "$p"
exec 3<"$p"
test "$p" -ef "/proc/$$/fd/3"; test -c "/proc/$$/fd/3"
printf 'opened '; stat -L -c '%d %i %t %T' "/proc/$$/fd/3"
test ! -e "$f"; test ! -L "$f"; set -C
: >"$f"; set +C
dd bs=1 count=1 <&3 >"$f" 2>/dev/null
printf 'read '; wc -c <"$f"
test ! -L "$p"; test -c "$p"; test "$p" -ef "/proc/$$/fd/3"
printf 'after '; stat -c '%d %i %t %T' "$p"
rm "$f"; exec 3<&-"#;
const ORDINARY_ENVELOPE: usize = 65_550 + 8192;
const CLEANUP_ENVELOPE: usize = 8192 + 2048;

fn mapping() -> Value {
    json!([{"PathOnHost":"/dev/null","PathInContainer":"/dev/native-null","CgroupPermissions":"r"}])
}

fn authored(run: &HealthRun, index: usize) -> Value {
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
            devices: vec![DeviceMapping {
                host_path: WorkingDirectory::new(b"/dev/null".to_vec()).unwrap(),
                container_path: WorkingDirectory::new(b"/dev/native-null".to_vec()).unwrap(),
                permissions: DevicePermissions {
                    read: true,
                    write: false,
                    create: false,
                },
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
    // Literal expectation authored independently from both renderer and decoder.
    assert!(
        request
            == json!({"method":"POST","path":format!("/v{}/containers/create?name={}",run.api,run.names[index]),
        "body":{"Image":run.base,"Cmd":["sh","-c",PROCESS],"Labels":{(OWNER):run.run},
        "HostConfig":{"Devices":[{"PathOnHost":"/dev/null","PathInContainer":"/dev/native-null","CgroupPermissions":"r"}]}}}),
        "independent complete device request literal"
    );
    request
}

fn create_device(run: &mut HealthRun, index: usize) {
    assert!(
        run.inspect(&run.names[index], false).0 == 404,
        "fresh device name"
    );
    let request = if index == 1 {
        Some(authored(run, index))
    } else {
        None
    };
    // Publish mutation liability before either actual create attempt.
    run.attempted[index] = true;
    if let Some(request) = request {
        let (status, value) = run.api(
            "POST",
            request["path"].as_str().unwrap(),
            Some(&request["body"]),
            false,
        );
        assert!(
            status == 201 && (value["Warnings"].is_null() || value["Warnings"] == json!([])),
            "known device create ID"
        );
        bind(
            run,
            index,
            value["Id"]
                .as_str()
                .unwrap_or_else(|| panic!("canonical device create ID")),
        );
    } else {
        let bytes = docker(
            run,
            &[
                "create".into(),
                "--name".into(),
                run.names[index].clone(),
                "--label".into(),
                format!("{OWNER}={}", run.run),
                "--device".into(),
                "/dev/null:/dev/native-null:r".into(),
                run.base.clone(),
                "sh".into(),
                "-c".into(),
                PROCESS.into(),
            ],
        );
        let id = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed device CLI ID"));
        bind(run, index, id);
    }
}

fn configured(run: &HealthRun, index: usize, image: &Value, live: bool) -> Value {
    let id = run.ids[index].as_ref().unwrap();
    let (status, value) = run.inspect(id, false);
    assert!(
        status == 200
            && owned(run, &value, index, Some(id))
            && value["Image"] == image["id"]
            && value["Config"]["Cmd"] == json!(["sh", "-c", PROCESS])
            && (value["Config"]["Entrypoint"].is_null()
                || value["Config"]["Entrypoint"] == json!([]))
            && value["HostConfig"]["Devices"] == mapping()
            && value["HostConfig"]["Privileged"] == false
            && (value["HostConfig"]["CapAdd"].is_null()
                || value["HostConfig"]["CapAdd"] == json!([]))
            && (value["HostConfig"]["CapDrop"].is_null()
                || value["HostConfig"]["CapDrop"] == json!([]))
            && value["Mounts"].as_array().is_some_and(Vec::is_empty)
            && value["RestartCount"] == 0
            && value["State"]["OOMKilled"] == false
            && value["State"]["Running"] == live
            && value["State"]["Restarting"] == false
            && value["State"]["Paused"] == false
            && value["State"]["Dead"] == false
            && value["State"]["Error"] == ""
            && value["State"]["ExitCode"] == 0,
        "owned exact device configuration and stable process"
    );
    assert!(
        if live {
            value["State"]["Status"] == "running"
                && value["State"]["Pid"].as_u64().is_some_and(|n| n > 0)
        } else {
            value["State"]["Status"] == "created"
                && value["State"]["Pid"] == 0
                && value["State"]["StartedAt"] == "0001-01-01T00:00:00Z"
                && value["State"]["FinishedAt"] == "0001-01-01T00:00:00Z"
        },
        "exact device running disposition"
    );
    value
}

fn witness(bytes: &[u8]) -> Value {
    assert!(bytes.len() <= 1024, "bounded device report");
    let report = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("device report UTF8"));
    let lines: Vec<_> = report.lines().collect();
    assert!(
        report.ends_with('\n')
            && lines.len() == 5
            && lines[0] == "source 1 3"
            && lines[3] == "read 0",
        "closed real device read report"
    );
    let target: Vec<_> = lines[1].split(' ').collect();
    assert!(
        target.len() == 5 && target[0] == "target" && target[3..] == ["1", "3"],
        "null character identity"
    );
    for (i, part) in target[1..3].iter().enumerate() {
        let value = part
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("bounded device node identity"));
        assert!(
            value.to_string() == *part && (i == 0 || value > 0),
            "canonical device node identity"
        );
    }
    let suffix = target[1..].join(" ");
    assert!(
        lines[2] == format!("opened {suffix}") && lines[4] == format!("after {suffix}"),
        "held descriptor matches stable target"
    );
    let report_sha256: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json!({"report":report,"report_sha256":report_sha256,"nonsymlink":true,"kind":"character","rdev":{"major":1,"minor":3},"read":{"exit":0,"max_bytes":1,"bytes":0},"binding":"held_fd_same_inode_before_after"})
}

fn device_cleanup_with(
    attempted: &[bool],
    ids: &[Option<String>],
    inner: impl FnOnce() -> CleanupDisposition,
) -> CleanupDisposition {
    if attempted.len() != 2
        || ids.len() != 2
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
fn unknown_device_create_never_enters_inner_cleanup() {
    let entered = Cell::new(false);
    let disposition = device_cleanup_with(&[true, false], &[None, None], || {
        entered.set(true);
        CleanupDisposition::VerifiedAbsent
    });
    assert!(disposition == CleanupDisposition::OuterTeardownRequired && !entered.get());
}

#[test]
fn device_report_rejects_wrong_node_read_and_rebound_marker() {
    let valid = b"source 1 3\ntarget 9 12 1 3\nopened 9 12 1 3\nread 0\nafter 9 12 1 3\n";
    witness(valid);
    for text in [
        String::from_utf8(valid.to_vec())
            .unwrap()
            .replace("1 3", "1 5"),
        String::from_utf8(valid.to_vec())
            .unwrap()
            .replace("read 0", "read 1"),
        String::from_utf8(valid.to_vec())
            .unwrap()
            .replace("opened 9 12", "opened 9 13"),
        "source 1 3\nread 0\n".into(),
    ] {
        assert!(std::panic::catch_unwind(|| witness(text.as_bytes())).is_err());
    }
}

#[test]
#[ignore = "requires exact isolated native lane and bound outer owner"]
fn live_device_mapping_matches_engine() {
    let backend = source_outer_backend();
    let started = Instant::now();
    let target = ProofTarget::new_for("NATIVE_DEVICE_MAPPING_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_DEVICE_MAPPING_CANDIDATE_SHA",
        "NATIVE_DEVICE_MAPPING_DEADLINE_EPOCH",
    );
    run.names = ["oracle", "rendered"]
        .map(|role| format!("dl-device-{}-{role}", run.run))
        .into();
    run.ids = vec![None; 2];
    run.attempted = vec![false; 2];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: device_mapping_context");
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
            Capability::DeviceMappings,
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
            "closed device context accounting"
        );
        // The API create retains the full ordinary envelope. Only successful
        // CLI create/start, both exec reports and empty API start use <=1024
        // stdout. No counter or timer is renewed.
        let pending_bytes = 11 * ORDINARY_ENVELOPE
            + 5 * (1024 + 8192)
            + ORDINARY_ENVELOPE
            + 2 * ORDINARY_ENVELOPE
            + backend.snapshot_extra_bytes();
        assert!(
            context_calls + 16 + 1 + 2 + backend.snapshot_extra_calls()
                <= MAX_CALLS - CLEANUP_CALLS
                && run
                    .bytes
                    .get()
                    .checked_add(pending_bytes)
                    .is_some_and(|n| n <= MAX_BYTES - CLEANUP_BYTES)
                && 18 * CLEANUP_ENVELOPE <= CLEANUP_BYTES
                && 18 <= CLEANUP_CALLS,
            "precomputed device work, final readback and cleanup envelopes"
        );
        eprintln!("DOCKERLENS_NATIVE_CHECK: device_mapping_effects");
        let mut records = Vec::new();
        for index in 0..2 {
            let before = run.calls.get();
            create_device(&mut run, index);
            configured(&run, index, &image, false);
            if index == 0 {
                let bytes = docker(
                    &run,
                    &["start".into(), run.ids[index].as_ref().unwrap().clone()],
                );
                assert!(
                    bytes == format!("{}\n", run.ids[index].as_ref().unwrap()).as_bytes(),
                    "exact started CLI ID"
                );
            } else {
                assert!(
                    run.api(
                        "POST",
                        &format!(
                            "/v{}/containers/{}/start",
                            run.api,
                            run.ids[index].as_ref().unwrap()
                        ),
                        None,
                        false
                    )
                    .0 == 204,
                    "device API start"
                );
            }
            let current = configured(&run, index, &image, true);
            let bytes = docker(
                &run,
                &[
                    "exec".into(),
                    "--user".into(),
                    "0:0".into(),
                    run.ids[index].as_ref().unwrap().clone(),
                    "sh".into(),
                    "-c".into(),
                    OBSERVE.into(),
                ],
            );
            let effect = witness(&bytes);
            let after = configured(&run, index, &image, true);
            assert!(
                after["State"]["Pid"] == current["State"]["Pid"] && run.calls.get() - before == 8,
                "stable process and exact device slot accounting"
            );
            records.push(json!({"role":if index==0{"oracle"}else{"rendered"},"id":run.ids[index],"name":run.names[index],"owner":run.run,"image_id":image["id"],
                "wire":if index==0{"independent_cli"}else{"literal_rendered"},"configured":{"devices":mapping(),"process":"owned_pid1_loop","running":true,"pid":current["State"]["Pid"],"restarts":0},"effect":effect,"cleanup":"absent"}));
        }
        assert!(
            run.api("GET", "/version", None, false).1["Version"] == run.engine,
            "post-device daemon health"
        );
        assert!(
            backend.final_snapshot_room(run.calls.get(), run.bytes.get(), 2),
            "pending final ordinary readback reserve"
        );
        (uid, image, records, context_calls)
    }));
    let work_elapsed = started.elapsed();
    let before_calls = run.calls.get();
    let before_bytes = run.bytes.get();
    let cleanup_started = Instant::now();
    eprintln!("DOCKERLENS_NATIVE_CHECK: device_mapping_cleanup");
    let attempted = run.attempted.clone();
    let ids = run.ids.clone();
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        device_cleanup_with(&attempted, &ids, || cleanup(&mut run))
    }))
    .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_calls = run.calls.get() - before_calls;
    let cleanup_bytes = run.bytes.get() - before_bytes;
    terminal_cleanup(&mut run, &owner, disposition);
    let (uid, image, records, context_calls) = require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none() && image_snapshot(&run) == image,
        "borrowed image unchanged and never removed"
    );
    let outer = outer_context(&run);
    assert!(outer == owner.snapshot, "same authenticated outer");
    let ordinary_calls = run.calls.get() - cleanup_calls;
    let ordinary_bytes = run.bytes.get() - cleanup_bytes;
    let ordinary_elapsed = started.elapsed().saturating_sub(cleanup_elapsed);
    let final_calls = 2 + backend.snapshot_extra_calls();
    assert!(
        ordinary_calls == context_calls + 16 + 1 + final_calls
            && ordinary_bytes > 0
            && ordinary_bytes <= MAX_BYTES - CLEANUP_BYTES
            && cleanup_calls == 18
            && cleanup_bytes <= 18 * CLEANUP_ENVELOPE,
        "closed final device accounting"
    );
    assert!(
        work_elapsed <= Duration::from_secs(134)
            && ordinary_elapsed <= Duration::from_secs(134)
            && cleanup_elapsed <= Duration::from_secs(46)
            && started.elapsed() <= Duration::from_secs(180),
        "original device deadline and cleanup reserve"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"capability_admission":[],"catalogue_admission":false,
        "scope":"configured_mapping_and_character_read_only","outer_backend":if matches!(backend,SourceOuterBackend::Docker){"docker"}else{"podman"},
        "context":{"candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,"rendering_api":run.api,
        "acquisition_api":if run.lane.starts_with("debian11-"){"1.41"}else{"1.49"},"mode":if run.mode==DaemonMode::Rootless{"rootless"}else{"rootful"},
        "docker_package":if run.lane.starts_with("debian11-"){"20.10.5+dfsg1-1+deb11u2"}else{""},"fixture_image":run.base,"daemon_uid":uid,"outer":outer},
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"containers":records,"daemon_health":"version_matches_after_controls",
        "accounting":{"context_calls":context_calls,"slot_calls":[8,8],"daemon_health_calls":1,"final_readback_calls":final_calls,"ordinary_calls":ordinary_calls,"ordinary_bytes":ordinary_bytes,
        "cleanup_calls":cleanup_calls,"cleanup_bytes":cleanup_bytes,"deadline_seconds":180,"cleanup_reserve_seconds":46,"ordinary_elapsed_ns":ordinary_elapsed.as_nanos(),"cleanup_elapsed_ns":cleanup_elapsed.as_nanos(),"elapsed_ns":started.elapsed().as_nanos(),
        "initial_context_acquisition":{"max_requests":16,"max_total_bytes":2097152,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"}},
        "cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: device_mapping_proof");
    target.publish(&proof);
}
