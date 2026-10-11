//! Prepared tmpfs-effect-v1 child of lifecycle; deliberately not registered.
//! Finite source controls are test-local facts, never capability admission.

use super::*;
use crate::target::{Mount, TmpfsOptions};

const CONTRACT: &str = "tmpfs-effect-v1";
const FILENAME: &str = "tmpfs-effect-v1.json";
const TARGET: &str = "/dl-tmpfs";
const TMPFS_PROCESS: &str = "while :; do sleep 1; done";
// Explicit options only. Omitted options, other sizes/modes and combinations
// are NOT implied by these eight observations.
const OPTIONS: [(u64, u32, bool); 4] = [
    (1_048_576, 0o700, false),
    (1_048_576, 0o700, true),
    (2_097_152, 0o750, false),
    (2_097_152, 0o750, true),
];

fn create_tmpfs(run: &mut HealthRun, index: usize) {
    let (size, mode, read_only) = OPTIONS[index / 2];
    assert_eq!(run.inspect(&run.names[index], false).0, 404);
    if index % 2 == 0 {
        // CLI is independently authored, not generated from a rendered request.
        let specification = format!(
            "type=tmpfs,destination={TARGET},tmpfs-size={size},tmpfs-mode={mode:o}{}",
            if read_only { ",readonly" } else { "" }
        );
        let args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
            "--mount".into(),
            specification,
            run.base.clone(),
            "sh".into(),
            "-c".into(),
            TMPFS_PROCESS.into(),
        ];
        run.attempted[index] = true;
        let bytes = docker(run, &args);
        let id = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| text.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed tmpfs CLI ID"));
        bind(run, index, id);
        return;
    }
    let container = ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(run.names[index].as_bytes().to_vec()).unwrap(),
        image: ImageReference::new(run.base.as_bytes().to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![
            Mount::tmpfs(
                TARGET.as_bytes().to_vec(),
                read_only,
                TmpfsOptions {
                    size_bytes: NonZeroU64::new(size),
                    mode: Some(mode),
                },
            )
            .unwrap(),
        ],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Exec(
            ["sh", "-c", TMPFS_PROCESS]
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
            ..ContainerSettings::default()
        },
    };
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
    let caps = ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap();
    let graph = DockerPlanner.plan(&intent, &caps).unwrap();
    let rendered = DockerApiRenderer.render(&graph).unwrap();
    let request: Value = serde_json::from_slice(rendered.bytes())
        .unwrap_or_else(|_| panic!("one closed tmpfs request"));
    let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
    let literal = json!({"method":"POST","path":path,"body":{
        "Image":run.base,"Cmd":["sh","-c",TMPFS_PROCESS],"Labels":{(OWNER):run.run},
        "HostConfig":{"Mounts":[{"Type":"tmpfs","Target":TARGET,"ReadOnly":read_only,
            "TmpfsOptions":{"SizeBytes":size,"Mode":mode}}]}}});
    assert_eq!(request, literal);
    run.attempted[index] = true;
    let (status, created) = run.api("POST", &path, Some(&request["body"]), false);
    assert_eq!(status, 201);
    assert!(created["Warnings"].is_null() || created["Warnings"] == json!([]));
    bind(
        run,
        index,
        created["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("closed rendered tmpfs ID")),
    );
}

fn configured_tmpfs(run: &HealthRun, index: usize, base: &Value) -> Value {
    let (size, mode, read_only) = OPTIONS[index / 2];
    let id = run.ids[index].as_deref().unwrap();
    let (status, value) = run.inspect(id, false);
    assert_eq!(status, 200);
    assert!(owned(run, &value, index, Some(id)));
    assert_eq!(value["Image"], base["id"]);
    assert_eq!(value["Config"]["Cmd"], json!(["sh", "-c", TMPFS_PROCESS]));
    assert!(value["Config"]["Entrypoint"].is_null() || value["Config"]["Entrypoint"] == json!([]));
    assert!(running(&value));
    let configured = value["HostConfig"]["Mounts"]
        .as_array()
        .unwrap_or_else(|| panic!("closed configured tmpfs array"));
    assert_eq!(configured.len(), 1);
    assert_eq!(configured[0]["Type"], "tmpfs");
    assert_eq!(configured[0]["Target"], TARGET);
    assert_eq!(configured[0]["ReadOnly"], read_only);
    assert_eq!(configured[0]["TmpfsOptions"]["SizeBytes"], size);
    assert_eq!(configured[0]["TmpfsOptions"]["Mode"], mode);
    assert!(configured[0]["Source"].is_null() || configured[0]["Source"] == "");
    let active = value["Mounts"]
        .as_array()
        .unwrap_or_else(|| panic!("closed active mounts"));
    assert_eq!(active.len(), 1);
    assert_eq!(active[0]["Type"], "tmpfs");
    assert_eq!(active[0]["Destination"], TARGET);
    assert_eq!(active[0]["RW"], !read_only);
    value
}

fn observe_tmpfs(run: &mut HealthRun, index: usize, base: &Value) -> Value {
    let (size, mode, read_only) = OPTIONS[index / 2];
    create_tmpfs(run, index);
    start(run, index);
    configured_tmpfs(run, index, base);
    let id = run.ids[index].as_deref().unwrap();
    // Fixed BusyBox-only probes. Capacity is independently measured by statfs;
    // writable mounts additionally must saturate at exactly the configured size.
    // A failed command without these positive substrate observations is no proof.
    let script = format!(
        "set -eu; LC_ALL=C; export LC_ALL; test \"$(id -u)\" = 0; test \"$(stat -c %u {TARGET})\" = 0; test \"$(stat -f -c %T {TARGET})\" = tmpfs; \
         test \"$(stat -c %a {TARGET})\" = {mode:o}; \
         unit=$(stat -f -c %S {TARGET}); blocks=$(stat -f -c %b {TARGET}); \
         capacity=$((unit * blocks)); test \"$capacity\" = {size}; \
         options=$(awk '$2==\"{TARGET}\" && $3==\"tmpfs\" {{print $4}}' /proc/mounts); \
         test -n \"$options\"; case ,$options, in *,{access},*) ;; *) exit 71;; esac; \
         case ,$options, in *,size={kib}k,*) ;; *) exit 72;; esac; \
         case ,$options, in *,mode={mode:o},*) ;; *) exit 73;; esac; \
         {write} \
         printf '{{\"filesystem\":\"tmpfs\",\"capacity_bytes\":%s,\"mode\":{mode},\"mount_access\":\"{access}\",\"write_outcome\":\"{outcome}\",\"saturation_bytes\":{saturation}}}\\n' \"$capacity\"",
        access = if read_only { "ro" } else { "rw" },
        kib = size / 1024,
        write = if read_only {
            format!(
                "test ! -e {TARGET}/access; if failure=$( (printf tmpfs-canary >{TARGET}/access) 2>&1); then exit 74; fi; case \"$failure\" in *'Read-only file system'*) ;; *) exit 76;; esac; test ! -e {TARGET}/access;"
            )
        } else {
            format!(
                "printf tmpfs-canary >{TARGET}/access; test \"$(cat {TARGET}/access)\" = tmpfs-canary; rm {TARGET}/access; if failure=$(dd if=/dev/zero of={TARGET}/full bs=4096 count={} 2>&1); then exit 75; fi; case \"$failure\" in *'No space left on device'*) ;; *) exit 77;; esac; test \"$(stat -c %s {TARGET}/full)\" = {size}; rm {TARGET}/full;",
                size / 4096 + 1
            )
        },
        outcome = if read_only {
            "refused"
        } else {
            "written_then_enospc"
        },
        saturation = if read_only { 0 } else { size },
    );
    let bytes = docker(
        run,
        &["exec".into(), id.into(), "sh".into(), "-c".into(), script],
    );
    let effect: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("closed tmpfs effect observation"));
    assert_eq!(
        effect,
        json!({"filesystem":"tmpfs","capacity_bytes":size,"mode":mode,
        "mount_access":if read_only {"ro"} else {"rw"},
        "write_outcome":if read_only {"refused"} else {"written_then_enospc"},
        "saturation_bytes":if read_only {0} else {size}})
    );
    configured_tmpfs(run, index, base);
    json!({"role":if index % 2 == 0 {"oracle"} else {"rendered"},
        "id":id,"name":run.names[index],"owner":run.run,"image_id":base["id"],
        "configuration":{"type":"tmpfs","target":TARGET,"size_bytes":size,"mode":mode,"read_only":read_only},
        "effect":effect})
}

#[test]
#[ignore = "requires independently integrated exact-profile authenticated native harness"]
fn live_tmpfs_effects_match_engine() {
    let target = ProofTarget::new_for("NATIVE_TMPFS_EFFECT_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_TMPFS_EFFECT_CANDIDATE_SHA",
        "NATIVE_TMPFS_EFFECT_DEADLINE_EPOCH",
    );
    run.names = (0..8)
        .map(|index| format!("dl-tmpfs-{}-{index}", run.run))
        .collect();
    run.ids = vec![None; 8];
    run.attempted = vec![false; 8];
    // Lifecycle's independently bound outer owner is mandatory BEFORE mutation.
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let outer = owner.snapshot.clone();
        let daemon_uid = run.context();
        let base = image_snapshot(&run);
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::TmpfsMount,
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
        for (case, (size, mode, read_only)) in OPTIONS.into_iter().enumerate() {
            let containers = [
                observe_tmpfs(&mut run, 2 * case, &base),
                observe_tmpfs(&mut run, 2 * case + 1, &base),
            ];
            cases.push(json!({"size_bytes":size,"mode":mode,"read_only":read_only,"containers":containers}));
        }
        (outer, daemon_uid, base, cases)
    }));
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cleanup(&mut run)))
        .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    terminal_cleanup(&mut run, &owner, disposition);
    let (outer, daemon_uid, base, cases) = require_verified_result(result, disposition);
    assert!(!run.image_attempted && run.derived_id.is_none());
    assert_eq!(image_snapshot(&run), base);
    assert_eq!(outer_context(&run), outer);
    let proof = json!({"schema_version":1,"contract":CONTRACT,"admission":"unadmitted","context":{
        "candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,
        "rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},
        "mode":if run.mode==DaemonMode::Rootless {"rootless"} else {"rootful"},
        "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},
        "fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "apis":{"fixture_cli":run.api,"renderer":run.api,"request":run.api},
        "borrowed_image":{"id":base["id"],"identity":"unchanged","removal":"not_owned"},
        "cases":cases,"limits":{"containers":8,"deadline_seconds":180,"retries":0},
        "coverage":"explicit_1MiB_0700_and_2MiB_0750_rw_ro_only",
        "cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    target.publish(&proof);
}
