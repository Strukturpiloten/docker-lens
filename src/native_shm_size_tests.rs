//! Prepared shm-size-v1 lifecycle child; registration belongs to the primary.
//! Only disposable borrowed-image fixtures are mutated. No catalogue admission.

use super::*;
use crate::observation::{Availability, Origin};

const CONTRACT: &str = "shm-size-v1";
const FILENAME: &str = "shm-size-v1.json";
const CASES: [(&str, Option<u64>); 3] = [
    ("omitted", None),
    ("one_mib", Some(1_048_576)),
    ("two_mib", Some(2_097_152)),
];
const SHM_PROCESS: &str = "while :; do sleep 1; done";
const CONTROL_BYTES: u64 = 3_145_728;
const ACQUISITION_CALLS: usize = 16;
const ACQUISITION_BYTES: usize = 512 * 1024;
const ORDINARY_ENVELOPE: usize = 65_550 + 8192;

#[derive(Clone)]
struct Measurement {
    capacity: u64,
    unit: u64,
    blocks: u64,
    ipc: u64,
}

fn positive_decimal(text: &str) -> Option<u64> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn measurement(bytes: &[u8]) -> Option<Measurement> {
    if bytes.len() > 192 {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    let fields: Vec<_> = text.split(' ').collect();
    if fields.len() != 4 {
        return None;
    }
    let capacity = positive_decimal(fields[0])?;
    let unit = positive_decimal(fields[1])?;
    let blocks = positive_decimal(fields[2])?;
    let ipc = positive_decimal(fields[3].strip_prefix("ipc:[")?.strip_suffix(']')?)?;
    if capacity > i64::MAX as u64
        || !(4096..=65_536).contains(&unit)
        || !unit.is_power_of_two()
        || unit.checked_mul(blocks)? != capacity
    {
        return None;
    }
    Some(Measurement {
        capacity,
        unit,
        blocks,
        ipc,
    })
}

fn marker(run: &HealthRun, index: usize) -> String {
    format!("dockerlens-shm-{}-{index}", run.run)
}

fn create_shm(run: &mut HealthRun, index: usize) {
    assert!(
        run.inspect(&run.names[index], false).0 == 404,
        "fresh shm fixture name"
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
        if let Some(size) = authored {
            // Docker CLI documentation: no suffix means bytes. Never derive the
            // oracle argv from a rendered request or assume a daemon default.
            args.extend(["--shm-size".into(), size.to_string()]);
        }
        args.extend([
            run.base.clone(),
            "sh".into(),
            "-c".into(),
            SHM_PROCESS.into(),
        ]);
        run.attempted[index] = true;
        let bytes = docker(run, &args);
        let id = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|value| value.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed shm CLI create ID"));
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
            ["sh", "-c", SHM_PROCESS]
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
            shm_size_bytes: authored.and_then(NonZeroU64::new),
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
    let mut body = json!({"Image":run.base,"Cmd":["sh","-c",SHM_PROCESS],"Labels":{(OWNER):run.run},"HostConfig":{}});
    if let Some(size) = authored {
        body["HostConfig"]["ShmSize"] = json!(size);
    }
    assert!(
        request == json!({"method":"POST","path":path,"body":body}),
        "independent shm literal request"
    );
    run.attempted[index] = true;
    let (status, created) = run.api("POST", &path, Some(&request["body"]), false);
    assert!(status == 201, "shm create accepted");
    assert!(
        created["Warnings"].is_null() || created["Warnings"] == json!([]),
        "no shm create warning"
    );
    bind(
        run,
        index,
        created["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("closed rendered shm ID")),
    );
}

fn configured_shm(run: &HealthRun, index: usize, image: &Value) -> u64 {
    let id = run.ids[index].as_deref().unwrap();
    let (status, value) = run.inspect(id, false);
    assert!(
        status == 200 && owned(run, &value, index, Some(id)),
        "owned shm inspect"
    );
    assert!(
        value["Image"] == image["id"] && value["Config"]["Cmd"] == json!(["sh", "-c", SHM_PROCESS]),
        "shm image and argv"
    );
    assert!(
        value["Config"]["Entrypoint"].is_null() || value["Config"]["Entrypoint"] == json!([]),
        "borrowed shm entrypoint"
    );
    assert!(
        value["Path"] == "sh" && value["Args"] == json!(["-c", SHM_PROCESS]),
        "actual shm worker argv"
    );
    assert!(
        running(&value),
        "running shm fixture without OOM or restart"
    );
    assert!(
        value["Mounts"].as_array().is_some_and(Vec::is_empty),
        "no authored mount over shm"
    );
    assert!(
        value["HostConfig"]["IpcMode"] == "private",
        "private native IPC mode"
    );
    let size = value["HostConfig"]["ShmSize"]
        .as_u64()
        .filter(|size| *size > 0 && *size <= i64::MAX as u64)
        .unwrap_or_else(|| panic!("positive native shm size"));
    assert!(
        CASES[index / 2].1.is_none_or(|authored| size == authored),
        "authored shm size retained"
    );
    size
}

fn seed_shm(run: &HealthRun, index: usize, configured: u64) -> Measurement {
    let id = run.ids[index].as_deref().unwrap();
    // Every fixture remains live with its own value at the SAME path until all
    // six seed writes finish. Shared shm/IPC cannot pass sequential overwrites.
    let script = format!(
        "set -eu; LC_ALL=C; export LC_ALL; test \"$(id -u)\" = 0; test -d /dev/shm; test ! -L /dev/shm; \
         test \"$(stat -f -c %T /dev/shm)\" = tmpfs; \
         unit=$(stat -f -c %S /dev/shm); blocks=$(stat -f -c %b /dev/shm); capacity=$((unit * blocks)); \
         test \"$capacity\" = {configured}; \
         options=$(awk '$2==\"/dev/shm\" && $3==\"tmpfs\" {{count++; value=$4}} END {{if (count != 1) exit 1; print value}}' /proc/mounts); \
         case ,$options, in *,rw,*) ;; *) exit 71;; esac; \
         test ! -e /dev/shm/dl-shm-canary; test ! -L /dev/shm/dl-shm-canary; \
         test ! -e /dev/shm/dl-shm-payload; test ! -L /dev/shm/dl-shm-payload; \
         printf '%s' '{marker}' >/dev/shm/dl-shm-canary; \
         test \"$(cat /dev/shm/dl-shm-canary)\" = '{marker}'; \
         ipc=$(readlink /proc/self/ns/ipc); printf '%s %s %s %s\\n' \"$capacity\" \"$unit\" \"$blocks\" \"$ipc\"",
        marker = marker(run, index),
    );
    let bytes = docker(
        run,
        &["exec".into(), id.into(), "sh".into(), "-c".into(), script],
    );
    let measured = measurement(&bytes).unwrap_or_else(|| panic!("closed native shm measurement"));
    assert!(
        measured.capacity == configured,
        "configured and measured shm capacity agree"
    );
    measured
}

fn effect_shm(run: &HealthRun, index: usize, measured: &Measurement) {
    let id = run.ids[index].as_deref().unwrap();
    let authored = CASES[index / 2].1;
    let bytes = authored.unwrap_or(CONTROL_BYTES);
    let write = if authored.is_some() {
        format!(
            "if failure=$(dd if=/dev/zero of=/dev/shm/dl-shm-payload bs=4096 count={} 2>&1); then exit 74; fi; \
            case \"$failure\" in *'No space left on device'*) ;; *) exit 75;; esac;",
            bytes / 4096 + 1
        )
    } else {
        format!(
            "dd if=/dev/zero of=/dev/shm/dl-shm-payload bs=4096 count={} 2>/dev/null;",
            bytes / 4096
        )
    };
    let script = format!(
        "set -eu; LC_ALL=C; export LC_ALL; \
         test \"$(readlink /proc/self/ns/ipc)\" = 'ipc:[{ipc}]'; \
         test \"$(cat /dev/shm/dl-shm-canary)\" = '{marker}'; rm /dev/shm/dl-shm-canary; \
         test ! -e /dev/shm/dl-shm-payload; test ! -L /dev/shm/dl-shm-payload; \
         unit=$(stat -f -c %S /dev/shm); blocks=$(stat -f -c %b /dev/shm); \
         test $((unit * blocks)) = {capacity}; test \"$(stat -f -c %T /dev/shm)\" = tmpfs; \
         {write} test \"$(stat -c %s /dev/shm/dl-shm-payload)\" = {bytes}; \
         dd if=/dev/zero bs=4096 count={count} 2>/dev/null | cmp /dev/shm/dl-shm-payload -; \
         rm /dev/shm/dl-shm-payload; test ! -e /dev/shm/dl-shm-payload; \
         printf 'shm-effect-v1 {outcome} {bytes}\\n'",
        ipc = measured.ipc,
        marker = marker(run, index),
        capacity = measured.capacity,
        count = bytes / 4096,
        outcome = if authored.is_some() {
            "enospc"
        } else {
            "control_written"
        },
    );
    let observed = docker(
        run,
        &["exec".into(), id.into(), "sh".into(), "-c".into(), script],
    );
    let expected = format!(
        "shm-effect-v1 {} {bytes}\n",
        if authored.is_some() {
            "enospc"
        } else {
            "control_written"
        }
    );
    assert!(
        observed == expected.as_bytes(),
        "closed actual shm write effect"
    );
}

fn acquire_shm(run: &HealthRun, measured: &[Measurement]) -> Value {
    // Charge the entire allowance, never six per-container captures and never
    // silently reuse the separately bounded initial context acquisition.
    let calls = run.calls.get().checked_add(ACQUISITION_CALLS).unwrap();
    let bytes = run.bytes.get().checked_add(ACQUISITION_BYTES).unwrap();
    assert!(
        calls + 2 <= MAX_CALLS - CLEANUP_CALLS
            && bytes + 2 * ORDINARY_ENVELOPE <= MAX_BYTES - CLEANUP_BYTES,
        "shm acquisition and final snapshot reserve"
    );
    let elapsed = run
        .remaining()
        .checked_sub(Duration::from_secs(46))
        .filter(|left| !left.is_zero())
        .unwrap_or_else(|| panic!("shm capture cleanup reserve"));
    run.calls.set(calls);
    run.bytes.set(bytes);
    let selected: Vec<_> = run
        .ids
        .iter()
        .map(|id| NativeId::new(id.as_ref().unwrap().clone()).unwrap())
        .collect();
    let capture = acquire(
        &Endpoint::unix_socket(PathBuf::from(&run.socket)),
        Selector::ContainerIds(selected),
        Limits {
            max_requests: ACQUISITION_CALLS,
            max_selected_resources: 6,
            max_expansions: 8,
            max_response_bytes: 128 * 1024,
            max_total_bytes: ACQUISITION_BYTES,
            max_elapsed: elapsed.min(Duration::from_secs(10)),
        },
        &AtomicBool::new(false),
    )
    .unwrap_or_else(|_| panic!("actual six-ID shm capture"));
    assert!(
        capture.route() == CaptureRoute::ExplicitUnixSocket
            && capture.selected_roots().len() == 6
            && capture
                .exchanges()
                .iter()
                .all(|exchange| exchange.status().code() == 200),
        "complete selected shm capture"
    );
    let requested = ApiVersion::new(
        NonZeroU16::new(1).unwrap(),
        if run.lane.starts_with("debian11-") {
            41
        } else {
            49
        },
    );
    assert!(
        capture
            .exchanges()
            .iter()
            .filter_map(|exchange| exchange.api_version())
            .all(|api| api == requested),
        "actual shm acquisition API"
    );
    let decoded = decode_capture(&capture).unwrap_or_else(|_| panic!("actual shm capture decode"));
    assert!(
        decoded.containers.len() == 6
            && decoded.version.requested_api_versions == vec![requested]
            && decoded.version.daemon.observation_id == capture.observation_id()
            && decoded
                .version
                .daemon
                .release
                .as_ref()
                .is_some_and(|release| release.as_str() == run.engine),
        "exact decoded shm context"
    );
    let mode_evidence = match (run.mode, decoded.version.daemon.mode) {
        (DaemonMode::Rootless, DaemonMode::Rootless) => "rootless_observed",
        (DaemonMode::Rootful, DaemonMode::Rootful) => "rootful_observed",
        // Docker /info can omit Rootless. Preserve Unknown rather than promote
        // absence to a decoder fact; independent context already binds UID/mode.
        (DaemonMode::Rootful, DaemonMode::Unknown) => "unknown_with_independent_rootful_context",
        _ => panic!("nonconflicting decoded shm daemon mode"),
    };
    let mut seen = BTreeSet::new();
    for container in &decoded.containers {
        let id = container
            .id
            .value()
            .unwrap_or_else(|| panic!("request-bound decoded shm ID"))
            .as_bytes();
        let index = run
            .ids
            .iter()
            .position(|expected| expected.as_ref().unwrap().as_bytes() == id)
            .unwrap_or_else(|| panic!("selected decoded shm ID"));
        let value = &container.runtime.shm_size_bytes;
        assert!(
            seen.insert(index)
                && container.id.availability == Availability::Present
                && container.id.origin == Origin::RuntimeAssigned
                && value.availability == Availability::Present
                && value.origin == Origin::Effective
                && value
                    .value()
                    .is_some_and(|size| *size > 0 && *size as u64 == measured[index].capacity),
            "present effective decoded shm size matches independent native effect"
        );
    }
    let response_bytes: usize = capture
        .exchanges()
        .iter()
        .map(|exchange| exchange.body().as_bytes().len())
        .sum();
    assert!(
        capture.exchanges().len() <= ACQUISITION_CALLS && response_bytes <= ACQUISITION_BYTES,
        "bounded actual shm exchanges"
    );
    json!({"route":"explicit_unix_socket","selected_ids":6,"requested_api":format!("{}.{}",requested.major,requested.minor),
        "daemon_mode_evidence":mode_evidence,
        "reserved_calls":ACQUISITION_CALLS,"reserved_bytes":ACQUISITION_BYTES,
        "byte_scope":"decoded_response_bodies_only",
        "separate_transport_bounds":{"response_header_bytes":16384,"chunk_line_bytes":64,
            "chunk_payload_crlf_bytes":2,"final_trailer_line_bytes":16384,"actual_wire_bytes":"not_measured"},
        "actual_requests":capture.exchanges().len(),"actual_response_bytes":response_bytes,
        "decoded":"present_effective_exact_sizes","limits":{"max_requests":16,"max_selected_resources":6,"max_expansions":8,
            "max_response_bytes":128*1024,"max_total_bytes":ACQUISITION_BYTES,"max_elapsed_seconds":10}})
}

#[test]
#[ignore = "unregistered source preparation; requires exact native harness and bound outer owner"]
fn live_shm_size_effects_match_engine() {
    let started = Instant::now();
    let target = ProofTarget::new_for("NATIVE_SHM_SIZE_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_SHM_SIZE_CANDIDATE_SHA",
        "NATIVE_SHM_SIZE_DEADLINE_EPOCH",
    );
    run.names = CASES
        .into_iter()
        .flat_map(|(case, _)| {
            ["oracle", "rendered"].map(|role| format!("dl-shm-{}-{case}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 6];
    run.attempted = vec![false; 6];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: shm_size_context");
        let outer = owner.snapshot.clone();
        let daemon_uid = run.context();
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
            Capability::ShmSize,
        ]
        .into_iter()
        .map(|capability| CapabilityFact {
            capability,
            state: CapabilityState::Available,
            provenance: FactProvenance::NativeConformance,
            scope: scope.clone(),
        })
        .collect();
        let mut measured = Vec::new();
        let mut namespaces = BTreeSet::new();
        eprintln!("DOCKERLENS_NATIVE_CHECK: shm_size_seed");
        for index in 0..6 {
            create_shm(&mut run, index);
            start(&run, index);
            let configured = configured_shm(&run, index, &image);
            let observed = seed_shm(&run, index, configured);
            assert!(
                namespaces.insert(observed.ipc),
                "six distinct private IPC namespaces"
            );
            measured.push(observed);
        }
        assert!(
            measured[0].capacity == measured[1].capacity && measured[0].capacity >= CONTROL_BYTES,
            "observed comparative omission default"
        );
        eprintln!("DOCKERLENS_NATIVE_CHECK: shm_size_effects");
        let mut cases = Vec::new();
        for (case, (name, authored)) in CASES.into_iter().enumerate() {
            let mut containers = Vec::new();
            for (role_index, role) in ["oracle", "rendered"].into_iter().enumerate() {
                let index = 2 * case + role_index;
                let observed = &measured[index];
                effect_shm(&run, index, observed);
                assert!(
                    configured_shm(&run, index, &image) == observed.capacity,
                    "stable native shm size after effects"
                );
                containers.push(json!({"role":role,"id":run.ids[index],"name":run.names[index],"owner":run.run,
                    "image_id":image["id"],"wire":if role_index == 0 {"independent_cli"} else {"literal_rendered"},
                    "configured_size_bytes":observed.capacity,"filesystem":"tmpfs","mount_access":"rw","ipc_mode":"private",
                    "ipc_namespace":observed.ipc,"statfs_unit":observed.unit,"statfs_blocks":observed.blocks,"capacity_bytes":observed.capacity,
                    "canary":"own_value_retained_after_all_six_seeds","payload_bytes":authored.unwrap_or(CONTROL_BYTES),
                    "write_outcome":if authored.is_some() {"exact_saturation_native_enospc"} else {"three_mib_written_readback"},
                    "running_after":true,"restart_count":0,"oom_killed":false,"cleanup":"absent"}));
            }
            cases.push(json!({"case":name,"authored_size_bytes":authored,"containers":containers}));
        }
        eprintln!("DOCKERLENS_NATIVE_CHECK: shm_size_capture");
        let acquisition = acquire_shm(&run, &measured);
        (outer, daemon_uid, image, cases, acquisition)
    }));
    let work_elapsed = started.elapsed();
    let before_calls = run.calls.get();
    let before_bytes = run.bytes.get();
    let cleanup_started = Instant::now();
    eprintln!("DOCKERLENS_NATIVE_CHECK: shm_size_cleanup");
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cleanup(&mut run)))
        .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_calls = run.calls.get() - before_calls;
    let cleanup_bytes = run.bytes.get() - before_bytes;
    terminal_cleanup(&mut run, &owner, disposition);
    let (outer, daemon_uid, image, cases, acquisition) =
        require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none(),
        "borrowed image never owned"
    );
    assert!(
        image_snapshot(&run) == image && outer_context(&run) == outer,
        "unchanged borrowed image and outer"
    );
    let ordinary_elapsed = started.elapsed().saturating_sub(cleanup_elapsed);
    let work_calls = run.calls.get() - cleanup_calls;
    let work_bytes = run.bytes.get() - cleanup_bytes;
    assert!(
        work_calls
            == if run.lane.starts_with("debian11-") {
                75
            } else {
                74
            }
            && work_bytes <= MAX_BYTES - CLEANUP_BYTES
            && cleanup_calls == 54
            && cleanup_bytes <= CLEANUP_BYTES,
        "closed positive shm accounting"
    );
    assert!(
        work_elapsed <= Duration::from_secs(134)
            && ordinary_elapsed <= Duration::from_secs(134)
            && cleanup_elapsed <= Duration::from_secs(46)
            && started.elapsed() <= Duration::from_secs(180),
        "original bounded shm deadline"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"capability_admission":[],"catalogue_admission":false,
        "scope":"explicit_1MiB_2MiB_with_observed_omission_only","context":{
            "candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,
            "rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},
            "mode":if run.mode == DaemonMode::Rootless {"rootless"} else {"rootful"},
            "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},
            "fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"cases":cases,
        "acquisition":acquisition,"accounting":{"ordinary_calls":work_calls,"ordinary_bytes":work_bytes,
            "cleanup_calls":cleanup_calls,"cleanup_bytes":cleanup_bytes,"deadline_seconds":180,"cleanup_reserve_seconds":46,
            "ordinary_elapsed_ns":ordinary_elapsed.as_nanos(),"cleanup_elapsed_ns":cleanup_elapsed.as_nanos(),"elapsed_ns":started.elapsed().as_nanos(),
            "initial_context_acquisition":{"max_requests":16,"max_total_bytes":2*1024*1024,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"}},
        "cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: shm_size_proof");
    target.publish(&proof);
}

#[test]
fn shm_measurement_refuses_partial_malformed_and_overflowing_effects() {
    assert!(measurement(b"1048576 4096 256 ipc:[1234]\n").is_some());
    for bytes in [
        b"1048576 4096 256 ipc:[1234]".as_slice(),
        b"1048576 4096 255 ipc:[1234]\n",
        b"1048576 0 256 ipc:[1234]\n",
        b"1048576 4096 256 ipc:[0]\n",
        b"1048576 4096 256 ipc:[+1]\n",
        b"1048576 4096 256 ipc:[01]\n",
        b"1048576 4096 256 ipc:[1234]\nprivate",
        b"1048576 4096 256 ipc:[1234] \n",
        b"9223372036854775808 4096 2251799813685248 ipc:[1234]\n",
    ] {
        assert!(measurement(bytes).is_none());
    }
}
