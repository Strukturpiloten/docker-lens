//! Unregistered #115 preparation, proposed child of native_lifecycle_tests.
//! Borrows the parent's bound terminal owner, API-pinned CLI, immutable image,
//! actual context and original HealthRun budgets. No catalogue admission.
//! Init effect is PID1 indirection only: no executable name, reaping or signal
//! behavior is inferred. Six finite controls combine independent process and
//! rootfs probes; no start/create retries, new images or daemon storage edits.

use super::*;

const CONTRACT: &str = "runtime-filesystem-v1";
const FILENAME: &str = "runtime-filesystem-v1.json";
const CASES: [(&str, Option<bool>); 3] = [
    ("omitted", None),
    ("false", Some(false)),
    ("true", Some(true)),
];
const PROCESS: &str = "while :; do sleep 1; done";
// Exact NUL-delimited authored argv locates the worker, never the init binary's
// name. The exec observer has different argv. Polling is finite readiness work
// inside one API-pinned exec, not a retried mutation or a reset time budget.
const PROC: &str = r#"expected=$(printf 'sh\n-c\n%s\n%s' "$1" "$2"); for n in 1 2 3 4 5 6 7 8 9 10; do found=; for d in /proc/[0-9]*; do args=$(tr '\000' '\n' < "$d/cmdline" 2>/dev/null) || continue; [ "$args" = "$expected" ] || continue; [ -z "$found" ] || exit 31; found=$d; done; if [ -n "$found" ]; then pid=; ppid=; state=; while read -r key value rest; do case "$key" in Pid:) pid=$value;; PPid:) ppid=$value;; State:) state=$value;; esac; done < "$found/status"; one=; while read -r key value rest; do [ "$key" != 'Pid:' ] || one=$value; done < /proc/1/status; printf '%s %s %s %s\n' "$pid" "$ppid" "$state" "$one"; exit 0; fi; sleep 0.2; done; exit 32"#;
// The failing write's own status and stderr are measured inside the container.
// Permission errors, command/transport failures and arbitrary nonzero exits
// cannot impersonate EROFS. Native stderr remains inside the private transport.
const WRITE: &str = r#"export LC_ALL=C; p=/dockerlens-rootfs-canary; [ ! -e "$p" ] || exit 33; err=$( { printf '%s' 'dockerlens-rootfs-canary-v1' > "$p"; } 2>&1); code=$?; if [ "$code" -eq 0 ]; then [ "$(cat "$p")" = 'dockerlens-rootfs-canary-v1' ] || exit 34; printf '0 written exact_canary\n'; else [ ! -e "$p" ] || exit 35; case "$err" in *'Read-only file system'*) printf '%s erofs absent\n' "$code";; *) exit 36;; esac; fi"#;

fn configured(run: &HealthRun, index: usize, image: &Value, running: bool) -> Value {
    let id = run.ids[index]
        .as_deref()
        .unwrap_or_else(|| panic!("bound runtime ID"));
    let (status, value) = run.inspect(id, false);
    assert_eq!(status, 200);
    assert!(
        owned(run, &value, index, Some(id)),
        "exact runtime ownership"
    );
    assert_eq!(value["Image"], image["id"]);
    assert_eq!(
        value["Config"]["Cmd"],
        json!(["sh", "-c", PROCESS, run.names[index]])
    );
    assert!(
        value["Config"]["Entrypoint"].is_null() || value["Config"]["Entrypoint"] == json!([]),
        "borrowed entrypoint"
    );
    assert_eq!(value["Path"], "sh");
    assert_eq!(value["Args"], json!(["-c", PROCESS, run.names[index]]));
    assert!(
        value["Mounts"].as_array().is_some_and(Vec::is_empty),
        "no rootfs probe mount"
    );
    let authored = CASES[index / 2].1;
    if let Some(init) = authored {
        assert_eq!(value["HostConfig"]["Init"], init);
    } else {
        assert!(
            value["HostConfig"]["Init"].is_null() || value["HostConfig"]["Init"] == false,
            "omitted init is not positive"
        );
    }
    assert_eq!(
        value["HostConfig"]["ReadonlyRootfs"],
        authored == Some(true)
    );
    assert_eq!(
        value["State"]["Status"],
        if running { "running" } else { "created" }
    );
    assert_eq!(value["State"]["Running"], running);
    assert_eq!(value["State"]["Restarting"], false);
    assert_eq!(value["State"]["Paused"], false);
    assert_eq!(value["State"]["OOMKilled"], false);
    assert_eq!(value["RestartCount"], 0);
    value
}

fn create(run: &mut HealthRun, index: usize) {
    assert_eq!(run.inspect(&run.names[index], false).0, 404);
    let authored = CASES[index / 2].1;
    if index % 2 == 0 {
        // Independent CLI spelling: omission is no flags, false is explicit,
        // true is explicit. No renderer output is used to author this oracle.
        let mut args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
        ];
        if let Some(flag) = authored {
            args.extend([format!("--init={flag}"), format!("--read-only={flag}")]);
        }
        args.extend([
            run.base.clone(),
            "sh".into(),
            "-c".into(),
            PROCESS.into(),
            run.names[index].clone(),
        ]);
        run.attempted[index] = true;
        let bytes = docker(run, &args);
        let id = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| text.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("canonical runtime create output"));
        bind(run, index, id);
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
            ["sh", "-c", PROCESS, run.names[index].as_str()]
                .map(|text| {
                    Argument::new(text.as_bytes().to_vec())
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
            init: authored,
            read_only_rootfs: authored,
            ..ContainerSettings::default()
        },
    };
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))])
        .unwrap_or_else(|_| panic!("typed runtime intent"));
    let facts = run
        .facts
        .as_ref()
        .unwrap_or_else(|| panic!("actual runtime context"));
    let caps =
        ValidatedCapabilities::new(facts).unwrap_or_else(|_| panic!("test scoped capabilities"));
    let graph = DockerPlanner
        .plan(&intent, &caps)
        .unwrap_or_else(|_| panic!("runtime plan"));
    let artifact = DockerApiRenderer
        .render(&graph)
        .unwrap_or_else(|_| panic!("runtime rendering"));
    let request: Value = serde_json::from_slice(artifact.bytes())
        .unwrap_or_else(|_| panic!("one inert runtime request"));
    let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
    let mut host = json!({});
    if let Some(flag) = authored {
        host["Init"] = json!(flag);
        host["ReadonlyRootfs"] = json!(flag);
    }
    // Independent literal expectation, not renderer roundtrip agreement.
    let expected = json!({"method":"POST", "path":path, "body":{"Image":run.base,
        "Cmd":["sh","-c",PROCESS,run.names[index]],"Labels":{(OWNER):run.run},"HostConfig":host}});
    assert_eq!(request, expected);
    run.attempted[index] = true;
    let (status, value) = run.api("POST", &path, Some(&request["body"]), false);
    assert_eq!(status, 201);
    bind(
        run,
        index,
        value["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical rendered ID")),
    );
}

fn process_effect(bytes: &[u8], init: bool) -> (u32, u32, &'static str) {
    let text = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("closed proc output"));
    let fields: Vec<_> = text
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("closed proc terminator"))
        .split(' ')
        .collect();
    assert_eq!(fields.len(), 4);
    let numeric = |text: &str| {
        let number = text
            .parse::<u32>()
            .unwrap_or_else(|_| panic!("native proc number"));
        assert_eq!(text, number.to_string());
        number
    };
    let pid = numeric(fields[0]);
    let ppid = numeric(fields[1]);
    assert_eq!(numeric(fields[3]), 1);
    assert!(
        pid <= 4_194_304 && ppid <= 4_194_304,
        "bounded native proc IDs"
    );
    assert!(
        if init {
            pid > 1 && ppid == 1
        } else {
            pid == 1 && ppid == 0
        },
        "actual PID1 indirection"
    );
    let state = match fields[2] {
        "R" => "R",
        "S" => "S",
        _ => panic!("live worker state"),
    };
    (pid, ppid, state)
}

fn write_effect(bytes: &[u8], readonly: bool) -> (u8, &'static str, &'static str) {
    let text = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("closed write output"));
    let fields: Vec<_> = text
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("closed write terminator"))
        .split(' ')
        .collect();
    assert_eq!(fields.len(), 3);
    let code = fields[0]
        .parse::<u8>()
        .unwrap_or_else(|_| panic!("native write exit"));
    assert_eq!(fields[0], code.to_string());
    if readonly {
        assert!(code > 0, "actual rejected rootfs write");
        assert_eq!(fields[1], "erofs");
        assert_eq!(fields[2], "absent");
        (code, "erofs", "absent")
    } else {
        assert_eq!(code, 0);
        assert_eq!(fields[1], "written");
        assert_eq!(fields[2], "exact_canary");
        (code, "written", "exact_canary")
    }
}

fn observe(run: &mut HealthRun, index: usize, image: &Value) -> Value {
    create(run, index);
    configured(run, index, image, false);
    let id = run.ids[index].as_deref().unwrap().to_owned();
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
    let before = configured(run, index, image, true);
    let output = docker(
        run,
        &[
            "exec".into(),
            id.clone(),
            "sh".into(),
            "-c".into(),
            PROC.into(),
            "dl-proc".into(),
            PROCESS.into(),
            run.names[index].clone(),
        ],
    );
    let (pid, ppid, state) = process_effect(&output, CASES[index / 2].1 == Some(true));
    let process_at = native_time(run).0;
    let output = docker(
        run,
        &[
            "exec".into(),
            id.clone(),
            "sh".into(),
            "-c".into(),
            WRITE.into(),
        ],
    );
    let (code, effect, readback) = write_effect(&output, CASES[index / 2].1 == Some(true));
    let write_at = native_time(run).0;
    let after = configured(run, index, image, true);
    assert_eq!(after["State"]["StartedAt"], before["State"]["StartedAt"]);
    // Recheck the actual worker after the write, not only inspect booleans.
    let output = docker(
        run,
        &[
            "exec".into(),
            id.clone(),
            "sh".into(),
            "-c".into(),
            PROC.into(),
            "dl-proc".into(),
            PROCESS.into(),
            run.names[index].clone(),
        ],
    );
    let (after_pid, after_ppid, _) = process_effect(&output, CASES[index / 2].1 == Some(true));
    assert_eq!((after_pid, after_ppid), (pid, ppid));
    let observed_at = native_time(run).0;
    let started = before["State"]["StartedAt"]
        .as_str()
        .unwrap_or_else(|| panic!("native start time"));
    let times = [started, &process_at, &write_at, &observed_at]
        .map(|text| timestamp_ns(text).unwrap_or_else(|| panic!("native time")));
    assert!(
        times[0] < times[1]
            && times.windows(2).all(|pair| pair[0] <= pair[1])
            && times[3] - times[0] <= 180 * u128::from(SECOND),
        "ordered bounded effects"
    );
    json!({"role":if index % 2 == 0 {"oracle"} else {"rendered"},"id":id,"name":run.names[index],
        "owner":run.run,"image":run.base,"image_id":image["id"],"wire":if index % 2 == 0 {"independent_cli"} else {"literal_rendered"},
        "cli_api":run.api,"init_configured":before["HostConfig"]["Init"],"readonly_configured":before["HostConfig"]["ReadonlyRootfs"],
        "worker_pid":pid,"worker_ppid":ppid,"worker_state":state,"pid1_pid":1,"rootfs_probe_path":"/dockerlens-rootfs-canary",
        "probe_path_mount":false,"write_exit":code,"write_effect":effect,"readback":readback,"started_at":started,
        "process_observed_at":process_at,"write_observed_at":write_at,"running_after_at":observed_at,
        "running_after":true,"restart_count":0,"cleanup":"absent"})
}

#[test]
#[ignore = "unregistered preparation; requires reviewed bound outer cleanup owner and exact native harness"]
fn live_runtime_filesystem_matches_engine() {
    let target = ProofTarget::new_for("NATIVE_RUNTIME_FILESYSTEM_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_RUNTIME_FILESYSTEM_CANDIDATE_SHA",
        "NATIVE_RUNTIME_FILESYSTEM_DEADLINE_EPOCH",
    );
    run.names = CASES
        .into_iter()
        .flat_map(|(case, _)| {
            ["oracle", "rendered"].map(|role| format!("dl-runtime-{}-{case}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 6];
    run.attempted = vec![false; 6];
    // Proposed inherited #114 seam: it authenticates outer ID/owner/storage and
    // the harness terminal owner token before any attempted mutation is marked.
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: runtime_filesystem_context");
        let outer = owner.snapshot.clone();
        let daemon_uid = run.context();
        let image = image_snapshot(&run);
        assert!(
            image["config"]["Volumes"].is_null() || image["config"]["Volumes"] == json!({}),
            "borrowed fixture has no automatic mounts"
        );
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::ContainerInit,
            Capability::ReadOnlyRootfs,
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
        for (case, (name, flag)) in CASES.into_iter().enumerate() {
            eprintln!("DOCKERLENS_NATIVE_CHECK: runtime_filesystem_effects");
            let containers = [
                observe(&mut run, 2 * case, &image),
                observe(&mut run, 2 * case + 1, &image),
            ];
            cases.push(json!({"case":name,"authored_init":flag,"authored_readonly":flag,"containers":containers}));
        }
        (outer, daemon_uid, image, cases)
    }));
    // Exactly the inherited #114 one-pass ledger and terminal handoff. Never
    // call HealthRun::cleanup, create a second retry owner or let unsafe Drop
    // retry inner mutation after transport/ownership uncertainty.
    eprintln!("DOCKERLENS_NATIVE_CHECK: runtime_filesystem_cleanup");
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cleanup(&mut run)))
        .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    terminal_cleanup(&mut run, &owner, disposition);
    let (outer, daemon_uid, image, cases) = require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none(),
        "borrowed image never owned"
    );
    assert_eq!(image_snapshot(&run), image);
    assert_eq!(outer_context(&run), outer);
    let proof = json!({"schema_version":1,"contract":CONTRACT,"context":{
        "candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,
        "rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},
        "mode":if run.mode == DaemonMode::Rootless {"rootless"} else {"rootful"},
        "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},
        "fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "capability_admission":[],"catalogue_admission":false,"init_effect_scope":"pid1_indirection_only",
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"cases":cases,
        "cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: runtime_filesystem_evidence");
    target.publish(&proof);
}

#[test]
fn runtime_process_and_write_controls_require_effects() {
    assert_eq!(process_effect(b"1 0 S 1\n", false), (1, 0, "S"));
    assert_eq!(process_effect(b"7 1 R 1\n", true), (7, 1, "R"));
    for (bytes, init) in [
        (b"1 0 S 1\n".as_slice(), true),
        (b"7 1 S 1\n", false),
        (b"7 2 S 1\n", true),
        (b"7 1 Z 1\n", true),
    ] {
        assert!(std::panic::catch_unwind(|| process_effect(bytes, init)).is_err());
    }
    assert_eq!(
        write_effect(b"0 written exact_canary\n", false),
        (0, "written", "exact_canary")
    );
    assert_eq!(
        write_effect(b"2 erofs absent\n", true),
        (2, "erofs", "absent")
    );
    for (bytes, readonly) in [
        (b"0 written exact_canary\n".as_slice(), true),
        (b"2 erofs absent\n", false),
        (b"2 permission_denied absent\n", true),
        (b"0 erofs absent\n", true),
    ] {
        assert!(std::panic::catch_unwind(|| write_effect(bytes, readonly)).is_err());
    }
}
