//! Hostname-v1 semantics with mandatory private-v2 resolver source observations.
//! Product rendering and catalogue stay inert.
//! Reuses the existing private fixture budgets, ownership and terminal cleanup.

use super::super::ProofTarget;
use super::*;
use crate::target::{ContainerHostname, ExtraHost};
use crate::version::{EngineRelease, ObservationId};
use std::collections::BTreeSet;
use std::net::IpAddr;

const CONTRACT: &str = "hostname-v1";
const FILENAME: &str = "hostname-v2.json";
const CASES: [&str; 2] = ["omitted", "explicit"];
const HOST_PROCESS: &str = "while :; do sleep 1; done";
const RESOLVER_CASES: [&str; 2] = ["ipv4", "ipv6"];
const RESOLVER_CONTRACT: &str = "resolver-files-v1";
const RESOLVER_FILE_LIMIT: usize = 4096;
const OWNER_SLOTS: usize = 8;

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

fn resolver_values(case: usize) -> (&'static str, &'static str, &'static str) {
    match case {
        0 => ("192.0.2.53", "fixture-v4.local", "192.0.2.10"),
        1 => ("2001:4860:4860::8888", "fixture-v6.local", "2001:db8::10"),
        _ => panic!("closed resolver case"),
    }
}

// The actual unlabelled fixture is shared by native and offline paths.
// Ownership labels remain a separate native bookkeeping overlay.
fn resolver_container(name: &str, image: &str, case: usize) -> ContainerIntent {
    let (dns, host, address) = resolver_values(case);
    ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(name.as_bytes().to_vec()).unwrap(),
        image: ImageReference::new(image.as_bytes().to_vec()).unwrap(),
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
            dns: vec![dns.parse().unwrap()],
            extra_hosts: vec![ExtraHost {
                name: ContainerHostname::new(host.as_bytes().to_vec()).unwrap(),
                address: address.parse().unwrap(),
            }],
            ..ContainerSettings::default()
        },
    }
}

fn resolver_create(run: &mut HealthRun, index: usize) {
    assert!(
        run.inspect(&run.names[index], false).0 == 404,
        "resolver name initially absent"
    );
    let case = (index - 4) / 2;
    let (dns, host, address) = resolver_values(case);
    if index.is_multiple_of(2) {
        let args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
            "--dns".into(),
            dns.into(),
            "--add-host".into(),
            format!("{host}:{address}"),
            run.base.clone(),
            "sh".into(),
            "-c".into(),
            HOST_PROCESS.into(),
        ];
        run.attempted[index] = true;
        let output = docker(run, &args);
        let id = std::str::from_utf8(&output)
            .ok()
            .and_then(|value| value.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed resolver CLI create output"));
        bind(run, index, id);
        return;
    }
    let mut container = resolver_container(&run.names[index], &run.base, case);
    container
        .settings
        .labels
        .push(ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec()).unwrap());
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
    let graph = DockerPlanner
        .plan(
            &intent,
            &ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
    let request: Value =
        serde_json::from_slice(DockerApiRenderer.render(&graph).unwrap().bytes()).unwrap();
    // Complete literal expectations do not come from the typed fixture.
    let host_config = if case == 0 {
        json!({"Dns":["192.0.2.53"],"ExtraHosts":["fixture-v4.local:192.0.2.10"]})
    } else {
        json!({"Dns":["2001:4860:4860::8888"],"ExtraHosts":["fixture-v6.local:2001:db8::10"]})
    };
    let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
    assert!(
        request
            == json!({"method":"POST","path":path,"body":{
        "Image":run.base,"Cmd":["sh","-c","while :; do sleep 1; done"],
        "Labels":{(OWNER):run.run},"HostConfig":host_config}}),
        "independently authored resolver request"
    );
    run.attempted[index] = true;
    let (status, value) = run.api("POST", &path, Some(&request["body"]), false);
    assert!(status == 201, "resolver create accepted");
    bind(
        run,
        index,
        value["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical resolver create ID")),
    );
}

fn resolver_lines(bytes: &[u8]) -> Option<Vec<Vec<&str>>> {
    if bytes.len() > RESOLVER_FILE_LIMIT
        || !bytes.is_ascii()
        || bytes
            .iter()
            .any(|byte| byte.is_ascii_control() && !matches!(*byte, b'\n' | b'\t'))
    {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    if text.lines().count() > 64 {
        return None;
    }
    text.lines()
        .map(|line| {
            let fields: Vec<_> = line.split('#').next()?.split_ascii_whitespace().collect();
            (fields.len() <= 16 && fields.iter().all(|field| field.len() <= 255)).then_some(fields)
        })
        .collect()
}

fn resolver_domain(value: &str) -> bool {
    if value == "." {
        return true;
    }
    let name = value.strip_suffix('.').unwrap_or(value);
    name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn resolver_options(fields: &[&str]) -> bool {
    let mut seen = BTreeSet::new();
    fields.iter().all(|field| {
        let (name, number) = field
            .split_once(':')
            .map_or((*field, None), |(name, number)| (name, Some(number)));
        if !seen.insert(name) {
            return false;
        }
        match (name, number) {
            ("edns0" | "trust-ad" | "rotate", None) => true,
            ("ndots" | "timeout" | "attempts", Some(number)) => {
                number.parse::<u8>().ok().is_some_and(|value| {
                    value.to_string() == number
                        && match name {
                            "ndots" => value <= 15,
                            "timeout" => (1..=30).contains(&value),
                            "attempts" => (1..=5).contains(&value),
                            _ => false,
                        }
                })
            }
            _ => false,
        }
    })
}

fn resolver_nameservers(bytes: &[u8]) -> Option<Vec<String>> {
    let mut servers = Vec::new();
    for fields in resolver_lines(bytes)? {
        match fields.first().copied() {
            None => {}
            Some("nameserver") if fields.len() == 2 => {
                servers.push(fields[1].parse::<IpAddr>().ok()?.to_string())
            }
            Some("domain") if fields.len() == 2 && resolver_domain(fields[1]) => {}
            Some("search")
                if fields.len() >= 2 && fields[1..].iter().all(|value| resolver_domain(value)) => {}
            Some("options") if fields.len() >= 2 && resolver_options(&fields[1..]) => {}
            // This finite fixture grammar does not support sortlist or other
            // directives. Refuse rather than silently accept unchecked syntax.
            _ => return None,
        }
    }
    Some(servers)
}

fn resolver_host_matches(bytes: &[u8], target: &str) -> Option<Vec<Value>> {
    let mut matches = Vec::new();
    for fields in resolver_lines(bytes)? {
        if fields.is_empty() {
            continue;
        }
        if fields.len() < 2 {
            return None;
        }
        let address = fields[0].parse::<IpAddr>().ok()?.to_string();
        if !fields[1..]
            .iter()
            .all(|name| *name != "." && resolver_domain(name))
        {
            return None;
        }
        if fields[1..].contains(&target) {
            // Retain every exact-target row, including duplicates/wrong IPs.
            if fields.len() != 2 {
                return None;
            }
            matches.push(json!({"address":address,"names":[fields[1]]}));
        }
    }
    Some(matches)
}

fn resolver_configured(value: &Value, case: usize) -> bool {
    let expected = if case == 0 {
        json!({"Dns":["192.0.2.53"],"ExtraHosts":["fixture-v4.local:192.0.2.10"]})
    } else {
        json!({"Dns":["2001:4860:4860::8888"],"ExtraHosts":["fixture-v6.local:2001:db8::10"]})
    };
    value["HostConfig"]["Dns"] == expected["Dns"]
        && value["HostConfig"]["ExtraHosts"] == expected["ExtraHosts"]
}

fn resolver_observe(run: &mut HealthRun, index: usize, image: &Value) -> Value {
    resolver_create(run, index);
    let id = run.ids[index].clone().unwrap();
    let case = (index - 4) / 2;
    let (dns, host, address) = resolver_values(case);
    let (status, configured) = run.inspect(&id, false);
    assert!(
        status == 200
            && owned(run, &configured, index, Some(&id))
            && resolver_configured(&configured, case),
        "resolver configured ownership and values"
    );
    start(run, index);
    let (status, before) = run.inspect(&id, false);
    assert!(
        status == 200
            && owned(run, &before, index, Some(&id))
            && running(&before)
            && before["Image"] == image["id"]
            && resolver_configured(&before, case),
        "resolver running before file observation"
    );
    // A sentinel byte distinguishes an exact bounded file from truncation.
    // Missing applets, permissions and command failures refuse the lane.
    let resolv = docker(
        run,
        &[
            "exec".into(),
            id.clone(),
            "head".into(),
            "-c".into(),
            (RESOLVER_FILE_LIMIT + 1).to_string(),
            "/etc/resolv.conf".into(),
        ],
    );
    let hosts = docker(
        run,
        &[
            "exec".into(),
            id.clone(),
            "head".into(),
            "-c".into(),
            (RESOLVER_FILE_LIMIT + 1).to_string(),
            "/etc/hosts".into(),
        ],
    );
    let nameservers = resolver_nameservers(&resolv)
        .unwrap_or_else(|| panic!("bounded complete resolver file grammar"));
    let host_matches = resolver_host_matches(&hosts, host)
        .unwrap_or_else(|| panic!("bounded complete hosts file grammar"));
    assert!(
        nameservers == [dns] && host_matches == vec![json!({"address":address,"names":[host]})],
        "independently expected resolver file records"
    );
    let (status, after) = run.inspect(&id, false);
    assert!(
        status == 200
            && owned(run, &after, index, Some(&id))
            && running(&after)
            && after["Image"] == image["id"]
            && resolver_configured(&after, case)
            && before["State"]["StartedAt"] == after["State"]["StartedAt"],
        "resolver stable running identity and values"
    );
    let started = before["State"]["StartedAt"]
        .as_str()
        .unwrap_or_else(|| panic!("resolver started timestamp"));
    assert!(
        timestamp_ns(started).is_some_and(|value| value > 0),
        "resolver started clock"
    );
    json!({"role":if index.is_multiple_of(2) {"oracle"} else {"rendered"},
        "id":id,"name":run.names[index],"owner":run.run,"image":run.base,"image_id":image["id"],
        "wire":if index.is_multiple_of(2) {"independent_cli"} else {"literal_rendered"},"cli_api":run.api,
        "configured_dns":before["HostConfig"]["Dns"],"configured_extra_hosts":before["HostConfig"]["ExtraHosts"],
        "nameservers":nameservers,"host_matches":host_matches,"started_at":started,
        "running_before":true,"running_after":true,"restart_count":0,"cleanup":"absent"})
}

fn combined_cleanup_room(backend: SourceOuterBackend, calls: usize, bytes: usize) -> bool {
    // Existing lifecycle cleanup: five known-ID removal calls, then two
    // ID/name absence rounds per slot. The envelope is capture_room's existing
    // cleanup stdout/stderr caps, not an additional allowance.
    let cleanup_calls = OWNER_SLOTS * (5 + 2 * 2);
    let cleanup_bytes = cleanup_calls * (8192 + 2048);
    cleanup_calls <= CLEANUP_CALLS
        && cleanup_bytes <= CLEANUP_BYTES
        && calls
            .checked_add(cleanup_calls)
            .zip(bytes.checked_add(cleanup_bytes))
            .is_some_and(|(calls, bytes)| backend.final_snapshot_room(calls, bytes, 2))
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
    run.names
        .extend(RESOLVER_CASES.into_iter().flat_map(|case| {
            ["oracle", "rendered"].map(|role| format!("dl-resolver-{}-{case}-{role}", run.run))
        }));
    run.ids = vec![None; OWNER_SLOTS];
    run.attempted = vec![false; OWNER_SLOTS];
    let backend = source_outer_backend();
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
            Capability::DnsServers,
            Capability::ExtraHosts,
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
        let mut resolver_cases = Vec::new();
        for (case, name) in RESOLVER_CASES.into_iter().enumerate() {
            // Keep the established closed stage-marker vocabulary.
            eprintln!("DOCKERLENS_NATIVE_CHECK: hostname_effects");
            let containers = [
                resolver_observe(&mut run, 4 + 2 * case, &image),
                resolver_observe(&mut run, 5 + 2 * case, &image),
            ];
            resolver_cases.push(json!({"case":name,"containers":containers}));
        }
        assert!(
            combined_cleanup_room(backend, run.calls.get(), run.bytes.get()),
            "combined cleanup and final ordinary snapshot reserve"
        );
        (outer, daemon_uid, image, cases, resolver_cases)
    }));
    eprintln!("DOCKERLENS_NATIVE_CHECK: hostname_cleanup");
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cleanup(&mut run)))
        .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    terminal_cleanup(&mut run, &owner, disposition);
    let (outer, daemon_uid, image, cases, resolver_cases) =
        require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none(),
        "borrowed hostname image never owned"
    );
    assert!(
        image_snapshot(&run) == image && outer_context(&run) == outer,
        "hostname borrowed image and outer unchanged"
    );
    let proof = json!({"schema_version":2,"contract":CONTRACT,"context":{
        "candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,
        "rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},
        "mode":if run.mode == DaemonMode::Rootless {"rootless"} else {"rootful"},
        "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},
        "fixture_image":run.base,"daemon_uid":daemon_uid,"outer":outer},
        "capability_admission":[],"catalogue_admission":false,
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"cases":cases,
        "resolver":{"contract":RESOLVER_CONTRACT,"cases":resolver_cases},
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

fn resolver_offline_facts(minor: u16, mode: DaemonMode) -> DaemonFacts {
    let observation_id = ObservationId::fresh().unwrap();
    let release = EngineRelease::new(if minor == 41 {
        "20.10.5+dfsg1".into()
    } else {
        "29.8.1".into()
    })
    .unwrap();
    let api_version = ApiVersion::new(NonZeroU16::new(1).unwrap(), minor);
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
        capabilities: [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::DnsServers,
            Capability::ExtraHosts,
        ]
        .into_iter()
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
fn unlabelled_ipv6_resolver_fixture_requires_each_fact_in_all_four_profiles() {
    for minor in [41, 56] {
        for mode in [DaemonMode::Rootful, DaemonMode::Rootless] {
            let container = resolver_container("resolver-v6", "busybox-fixture", 1);
            assert!(
                container.settings.labels.is_empty(),
                "unlabelled shared fixture"
            );
            let intent =
                TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
            let facts = resolver_offline_facts(minor, mode);
            let graph = DockerPlanner
                .plan(&intent, &ValidatedCapabilities::new(&facts).unwrap())
                .unwrap();
            let request: Value =
                serde_json::from_slice(DockerApiRenderer.render(&graph).unwrap().bytes()).unwrap();
            assert!(
                request
                    == json!({"method":"POST",
                "path":format!("/v1.{minor}/containers/create?name=resolver-v6"),
                "body":{"Image":"busybox-fixture","Cmd":["sh","-c","while :; do sleep 1; done"],
                    "HostConfig":{"Dns":["2001:4860:4860::8888"],
                        "ExtraHosts":["fixture-v6.local:2001:db8::10"]}}}),
                "independent unlabelled IPv6 request"
            );
            for withheld in [
                Capability::StandaloneContainer,
                Capability::Command,
                Capability::DnsServers,
                Capability::ExtraHosts,
            ] {
                let mut absent = resolver_offline_facts(minor, mode);
                absent
                    .capabilities
                    .retain(|fact| fact.capability != withheld);
                assert!(
                    DockerPlanner
                        .plan(&intent, &ValidatedCapabilities::new(&absent).unwrap())
                        .is_err(),
                    "each required resolver fact is independent"
                );
            }
        }
    }
}

#[test]
fn resolver_file_records_are_complete_bounded_and_unambiguous() {
    assert_eq!(
        resolver_nameservers(
            b"# private comment\nnameserver 2001:4860:4860::8888\noptions ndots:0\n"
        ),
        Some(vec!["2001:4860:4860::8888".into()])
    );
    let expected = vec![json!({"address":"2001:db8::10","names":["fixture-v6.local"]})];
    assert!(
        resolver_host_matches(
            b"127.0.0.1 localhost\n2001:db8::10\tfixture-v6.local\n",
            "fixture-v6.local"
        ) == Some(expected.clone())
    );
    for bad in [
        b"nameserver\n".as_slice(),
        b"nameserver bad\n",
        b"nameserver 192.0.2.53 extra\n",
        b"nameserverx 192.0.2.53\n",
        b"nameserver 192.0.2.53\r\n",
        b"nameserver 192.0.2.53\0",
    ] {
        assert!(
            resolver_nameservers(bad).is_none(),
            "malformed resolver record"
        );
    }
    for text in [
        "# nameserver 192.0.2.53\n",
        "nameserver 192.0.2.54\n",
        "nameserver 192.0.2.53\nnameserver 192.0.2.53\n",
    ] {
        assert_ne!(
            resolver_nameservers(text.as_bytes()),
            Some(vec!["192.0.2.53".into()])
        );
    }
    for text in [
        "2001:db8::11 fixture-v6.local\n",
        "2001:db8::10 prefix-fixture-v6.local\n",
        "2001:db8::10 fixture-v6.local\n2001:db8::10 fixture-v6.local\n",
    ] {
        assert!(
            resolver_host_matches(text.as_bytes(), "fixture-v6.local") != Some(expected.clone()),
            "retain wrong, absent and duplicate target observations"
        );
    }
    for text in [
        "bad fixture-v6.local\n",
        "2001:db8::10 fixture-v6.local alias\n",
        "2001:db8::10\n",
    ] {
        assert!(
            resolver_host_matches(text.as_bytes(), "fixture-v6.local").is_none(),
            "malformed or ambiguous hosts record"
        );
    }
    assert!(resolver_lines(&vec![b' '; RESOLVER_FILE_LIMIT]).is_some());
    assert!(resolver_lines(&vec![b' '; RESOLVER_FILE_LIMIT + 1]).is_none());
    assert!(resolver_lines(&[255]).is_none());
    assert!(resolver_lines("\n".repeat(65).as_bytes()).is_none());
    assert!(resolver_lines("x ".repeat(17).as_bytes()).is_none());
    assert!(resolver_lines("x".repeat(256).as_bytes()).is_none());
}

#[test]
fn valid_target_host_cannot_hide_malformed_unrelated_aliases() {
    let expected = Some(vec![
        json!({"address":"2001:db8::10","names":["fixture-v6.local"]}),
    ]);
    let valid = b"127.0.0.1 localhost localhost.localdomain\n::1 ip6-localhost ip6-loopback\n2001:db8::10 fixture-v6.local\n";
    assert!(
        resolver_host_matches(valid, "fixture-v6.local") == expected,
        "valid unrelated multi-alias records retain the complete target observation"
    );
    for alias in [
        "/path",
        "-bad.example",
        "bad-.example",
        "bad..example",
        ".",
        "bad_name",
    ] {
        let file = format!("2001:db8::10 fixture-v6.local\n127.0.0.1 {alias}\n");
        assert!(
            resolver_host_matches(file.as_bytes(), "fixture-v6.local").is_none(),
            "valid target cannot mask a malformed unrelated alias"
        );
    }
    let file = b"2001:db8::10 fixture-v6.local\n127.0.0.1 localhost /path\n";
    assert!(
        resolver_host_matches(file, "fixture-v6.local").is_none(),
        "validate every unrelated alias before filtering for the target"
    );
}

#[test]
fn valid_nameserver_cannot_hide_malformed_or_unsupported_surrounding_directives() {
    let expected = Some(vec!["192.0.2.53".to_owned()]);
    for directive in [
        "domain one.example",
        "domain .",
        "domain one.example.",
        "search one.example two.example.",
        "search .",
        "options ndots:0",
        "options ndots:15 timeout:30 attempts:5",
        "options edns0 trust-ad rotate",
    ] {
        let file = format!("# bounded fixture\nnameserver 192.0.2.53\n{directive}\n");
        assert_eq!(resolver_nameservers(file.as_bytes()), expected);
    }
    for directive in [
        "domain",
        "domain one.example two.example",
        "domain -one.example",
        "domain one..example",
        "domain one_.example",
        "search",
        "search good.example bad..example",
        "options",
        "options unknown",
        "options edns0:1",
        "options ndots:bad",
        "options ndots:16",
        "options ndots:00",
        "options timeout:0",
        "options timeout:31",
        "options attempts:0",
        "options attempts:6",
        "options ndots:0 ndots:1",
        "options trust-ad trust-ad",
        "sortlist not-an-address",
        "sortlist 192.0.2.0/255.255.255.0",
    ] {
        let file = format!("nameserver 192.0.2.53\n{directive}\n");
        assert!(
            resolver_nameservers(file.as_bytes()).is_none(),
            "valid required nameserver cannot mask malformed or unsupported directive"
        );
    }
    let long_label = format!("domain {}.example", "a".repeat(64));
    let file = format!("nameserver 192.0.2.53\n{long_label}\n");
    assert!(
        resolver_nameservers(file.as_bytes()).is_none(),
        "bounded domain labels"
    );
}

#[test]
fn combined_owner_reserves_cleanup_and_final_snapshots_without_new_allowances() {
    let removal_and_absence_calls = OWNER_SLOTS * (5 + 2 * 2);
    assert_eq!(removal_and_absence_calls, 72);
    for backend in [SourceOuterBackend::Podman, SourceOuterBackend::Docker] {
        let calls = MAX_CALLS
            - CLEANUP_CALLS
            - removal_and_absence_calls
            - 2
            - backend.snapshot_extra_calls();
        let bytes = MAX_BYTES
            - CLEANUP_BYTES
            - removal_and_absence_calls * (8192 + 2048)
            - 2 * (65_550 + 8192)
            - backend.snapshot_extra_bytes();
        assert!(combined_cleanup_room(backend, calls, bytes));
        assert!(!combined_cleanup_room(backend, calls + 1, bytes));
        assert!(!combined_cleanup_room(backend, calls, bytes + 1));
        assert!(!combined_cleanup_room(backend, usize::MAX, 0));
        assert!(!combined_cleanup_room(backend, 0, usize::MAX));
        assert!(!combined_cleanup_room(
            backend,
            MAX_CALLS - CLEANUP_CALLS,
            0
        ));
        assert!(!combined_cleanup_room(
            backend,
            0,
            MAX_BYTES - CLEANUP_BYTES
        ));
        // Actual complete success-call accounting includes both context image
        // inspections, both outer snapshots and all 68 fixture calls.
        for package_read in [0, 1] {
            let ordinary = 78 + package_read + 2 * backend.snapshot_extra_calls();
            assert!(ordinary + removal_and_absence_calls < MAX_CALLS - CLEANUP_CALLS);
        }
    }
    for unknown in ["", "Docker", "unknown"] {
        assert!(SourceOuterBackend::parse(unknown).is_none());
    }
    assert!(!capture_room(MAX_CALLS - CLEANUP_CALLS, 0, false));
    assert!(capture_room(MAX_CALLS - CLEANUP_CALLS, 0, true));
    assert!(!capture_room(MAX_CALLS, 0, true));
    assert!(!capture_room(0, MAX_BYTES, true));
}
