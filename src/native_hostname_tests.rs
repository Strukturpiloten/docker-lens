//! Finite hostname-v1 source proof. Product rendering and catalogue stay inert.
//! Reuses the existing private fixture budgets, ownership and terminal cleanup.

use super::super::ProofTarget;
use super::*;
use crate::target::ContainerHostname;

const CONTRACT: &str = "hostname-v1";
const FILENAME: &str = "hostname-v1.json";
const CASES: [&str; 2] = ["omitted", "explicit"];
const HOST_PROCESS: &str = "while :; do sleep 1; done";

fn authored_hostname(run: &str, case: usize) -> Option<String> {
    (case == 1).then(|| format!("dl-hostname-{run}"))
}

fn expected_hostname(id: &str, authored: Option<&str>) -> String {
    assert!(identifier(id), "canonical hostname fixture ID");
    authored.map_or_else(|| id[..12].to_owned(), str::to_owned)
}

fn process_hostname_matches(bytes: &[u8], expected: &str) -> bool {
    bytes == format!("{expected}\n").as_bytes()
}

fn create(run: &mut HealthRun, index: usize) {
    assert!(
        run.inspect(&run.names[index], false).0 == 404,
        "hostname name initially absent"
    );
    let authored = authored_hostname(&run.run, index / 2);
    if index.is_multiple_of(2) {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
        ];
        if let Some(hostname) = authored {
            args.extend(["--hostname".into(), hostname]);
        }
        args.extend([
            run.base.clone(),
            "sh".into(),
            "-c".into(),
            HOST_PROCESS.into(),
        ]);
        run.attempted[index] = true;
        let output = docker(run, &args);
        let id = std::str::from_utf8(&output)
            .ok()
            .and_then(|value| value.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed hostname CLI create output"));
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
            ["sh", "-c", HOST_PROCESS]
                .map(|value| Argument::new(value.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                    .unwrap(),
            ],
            hostname: authored
                .as_ref()
                .map(|value| ContainerHostname::new(value.as_bytes().to_vec()).unwrap()),
            ..ContainerSettings::default()
        },
    };
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
    // Existing crate-private test-only scope, never a fabricated public reviewed
    // profile or product planner bypass. Public hostname capability stays absent.
    let graph = DockerPlanner
        .plan(
            &intent,
            &ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
    let request: Value =
        serde_json::from_slice(DockerApiRenderer.render(&graph).unwrap().bytes()).unwrap();
    let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
    let mut body = json!({"Image":run.base,"Cmd":["sh","-c",HOST_PROCESS],"Labels":{(OWNER):run.run},"HostConfig":{}});
    if let Some(hostname) = authored {
        body["Hostname"] = json!(hostname);
    }
    assert!(
        request == json!({"method":"POST","path":path,"body":body}),
        "independently authored hostname request"
    );
    run.attempted[index] = true;
    let (status, value) = run.api("POST", &path, Some(&request["body"]), false);
    assert!(status == 201, "hostname create accepted");
    bind(
        run,
        index,
        value["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical hostname create ID")),
    );
}

fn observe(run: &mut HealthRun, index: usize, image: &Value) -> Value {
    create(run, index);
    let id = run.ids[index].clone().unwrap();
    let authored = authored_hostname(&run.run, index / 2);
    let expected = expected_hostname(&id, authored.as_deref());
    let (status, configured) = run.inspect(&id, false);
    assert!(
        status == 200 && owned(run, &configured, index, Some(&id)),
        "hostname configured ownership"
    );
    assert!(
        configured["Config"]["Hostname"] == expected,
        "hostname configured readback"
    );
    start(run, index);
    let (status, before) = run.inspect(&id, false);
    assert!(
        status == 200 && owned(run, &before, index, Some(&id)) && running(&before),
        "hostname running before effect"
    );
    assert!(
        before["Image"] == image["id"] && before["Config"]["Hostname"] == expected,
        "hostname running identity"
    );
    // The borrowed image must actually supply hostname. Any missing applet,
    // permission, runtime or transport failure is refusal, never a skipped cell.
    let output = docker(run, &["exec".into(), id.clone(), "hostname".into()]);
    assert!(
        process_hostname_matches(&output, &expected),
        "hostname process effect"
    );
    let process = std::str::from_utf8(&output)
        .unwrap()
        .strip_suffix('\n')
        .unwrap();
    let (status, after) = run.inspect(&id, false);
    assert!(
        status == 200 && owned(run, &after, index, Some(&id)) && running(&after),
        "hostname running after effect"
    );
    assert!(
        after["Image"] == image["id"]
            && after["Config"]["Hostname"] == expected
            && before["State"]["StartedAt"] == after["State"]["StartedAt"],
        "hostname stable process identity"
    );
    let started = before["State"]["StartedAt"]
        .as_str()
        .unwrap_or_else(|| panic!("hostname started timestamp"));
    assert!(
        timestamp_ns(started).is_some_and(|value| value > 0),
        "hostname started clock"
    );
    json!({"role":if index.is_multiple_of(2) {"oracle"} else {"rendered"},
        "id":id,"name":run.names[index],"owner":run.run,"image":run.base,"image_id":image["id"],
        "wire":if index.is_multiple_of(2) {"independent_cli"} else {"literal_rendered"},"cli_api":run.api,
        "request_hostname":authored.unwrap_or_else(|| "omitted".into()),
        "configured_hostname":before["Config"]["Hostname"],"process_hostname":process,"started_at":started,
        "running_before":true,"running_after":true,"restart_count":0,"cleanup":"absent"})
}

#[test]
#[ignore = "requires the isolated native Engine harness"]
fn live_hostname_matches_engine() {
    let target = ProofTarget::new_for("NATIVE_HOSTNAME_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_HOSTNAME_CANDIDATE_SHA",
        "NATIVE_HOSTNAME_DEADLINE_EPOCH",
    );
    run.names = CASES
        .into_iter()
        .flat_map(|case| {
            ["oracle", "rendered"].map(|role| format!("dl-host-{}-{case}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 4];
    run.attempted = vec![false; 4];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: hostname_context");
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
            Capability::ContainerHostname,
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
            eprintln!("DOCKERLENS_NATIVE_CHECK: hostname_effects");
            let containers = [
                observe(&mut run, 2 * case, &image),
                observe(&mut run, 2 * case + 1, &image),
            ];
            cases.push(json!({"case":name,"authored_hostname":authored_hostname(&run.run, case),"containers":containers}));
        }
        (outer, daemon_uid, image, cases)
    }));
    eprintln!("DOCKERLENS_NATIVE_CHECK: hostname_cleanup");
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cleanup(&mut run)))
        .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    terminal_cleanup(&mut run, &owner, disposition);
    let (outer, daemon_uid, image, cases) = require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none(),
        "borrowed hostname image never owned"
    );
    assert!(
        image_snapshot(&run) == image && outer_context(&run) == outer,
        "hostname borrowed image and outer unchanged"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"context":{
        "candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,
        "rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},
        "mode":if run.mode == DaemonMode::Rootless {"rootless"} else {"rootful"},
        "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},
        "fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "capability_admission":[],"catalogue_admission":false,
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"cases":cases,
        "cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: hostname_evidence");
    target.publish(&proof);
}

#[test]
fn hostname_effect_and_default_controls_are_exact_and_private() {
    let id = "a".repeat(64);
    assert_eq!(authored_hostname("Ab12Cd34", 0), None);
    assert_eq!(
        authored_hostname("Ab12Cd34", 1).as_deref(),
        Some("dl-hostname-Ab12Cd34")
    );
    assert_eq!(expected_hostname(&id, None), "aaaaaaaaaaaa");
    assert_eq!(
        expected_hostname(&id, Some("dl-hostname-Ab12Cd34")),
        "dl-hostname-Ab12Cd34"
    );
    assert!(process_hostname_matches(
        b"dl-hostname-Ab12Cd34\n",
        "dl-hostname-Ab12Cd34"
    ));
    for value in [
        b"foreign\n".as_slice(),
        b"dl-hostname-Ab12Cd34",
        b"dl-hostname-Ab12Cd34\nextra",
        b"dl-hostname-Ab12Cd34\r\n",
    ] {
        assert!(!process_hostname_matches(value, "dl-hostname-Ab12Cd34"));
    }
}
