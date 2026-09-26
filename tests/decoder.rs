use std::num::NonZeroU16;
use std::time::Duration;

use docker_lens::acquisition::{Budget, Limits, NativeId, ReadRequest};
use docker_lens::decoder::{
    CommandValue, DecodeError, HealthcheckTest, MountKind, NetworkModeKind, TransportProtocol,
    decode_capture,
};
use docker_lens::evidence::HttpStatus;
use docker_lens::observation::{Availability, Origin, ResourceRef};
use docker_lens::version::{ApiVersion, DaemonMode};

fn api(minor: u16) -> ApiVersion {
    ApiVersion::new(NonZeroU16::new(1).unwrap(), minor)
}

type FixtureExchange<'a> = (
    ReadRequest,
    Option<ResourceRef>,
    Option<ApiVersion>,
    u16,
    &'a str,
);

fn capture(exchanges: Vec<FixtureExchange<'_>>) -> docker_lens::evidence::Capture {
    capture_selected(exchanges, 0)
}

fn capture_selected(
    exchanges: Vec<FixtureExchange<'_>>,
    selected_resources: usize,
) -> docker_lens::evidence::Capture {
    let mut budget = Budget::new(Limits {
        max_requests: 12,
        max_selected_resources: 12,
        max_expansions: 12,
        max_response_bytes: 2 * 1024 * 1024,
        max_total_bytes: 8 * 1024 * 1024,
        max_elapsed: Duration::from_secs(30),
    })
    .unwrap();
    if selected_resources > 0 {
        budget.record_selection(selected_resources).unwrap();
    }
    for (request, resource, version, status, body) in exchanges {
        budget.record_request(request, resource, version).unwrap();
        budget
            .read_response(HttpStatus::new(status).unwrap(), body.as_bytes())
            .unwrap();
    }
    budget.into_capture().unwrap()
}

fn container(body: &str) -> docker_lens::evidence::Capture {
    capture(vec![(
        ReadRequest::InspectContainer(NativeId::new("container-1".into()).unwrap()),
        Some(ResourceRef::new(1)),
        Some(api(41)),
        200,
        body,
    )])
}

#[test]
fn independent_engine_fixture_decodes_typed_inventory_without_authorship() {
    let fixture = capture(vec![
        (
            ReadRequest::DaemonVersion,
            None,
            None,
            200,
            r#"{"Version":"20.10.5+dfsg1","ApiVersion":"1.41","MinAPIVersion":"1.12"}"#,
        ),
        (
            ReadRequest::DaemonInfo,
            None,
            Some(api(41)),
            200,
            r#"{"ServerVersion":"20.10.5+dfsg1","SecurityOptions":["name=rootless"],"Rootless":true}"#,
        ),
        (
            ReadRequest::InspectContainer(NativeId::new("c1".into()).unwrap()),
            Some(ResourceRef::new(1)),
            Some(api(41)),
            200,
            r#"{"Config":{"Image":"example:1","Env":["TOKEN=private-value","FLAG"],"ExposedPorts":{"80/tcp":{}},"Cmd":["serve","--password=private-value"],"Entrypoint":[],"Healthcheck":{"Test":["CMD","true"],"Interval":1000000000,"StartPeriod":2000000000,"StartInterval":3000000000,"Retries":2}},"HostConfig":{"NetworkMode":"bridge","PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}]},"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":3}},"Mounts":[{"Type":"volume","Name":"data","Source":"/secret/host/path","Destination":"/data","RW":true}],"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"::","HostPort":""}]},"Networks":{"app":{"IPAddress":"172.18.0.4"}}}}"#,
        ),
        (
            ReadRequest::InspectNetwork(NativeId::new("net1".into()).unwrap()),
            Some(ResourceRef::new(2)),
            Some(api(41)),
            200,
            r#"{"Name":"app","Driver":"bridge","Internal":false}"#,
        ),
        (
            ReadRequest::InspectVolume(NativeId::new("vol1".into()).unwrap()),
            Some(ResourceRef::new(3)),
            Some(api(41)),
            200,
            r#"{"Name":"data","Driver":"local","Mountpoint":"/secret/host/path"}"#,
        ),
    ]);
    let decoded = decode_capture(&fixture).unwrap();
    assert_eq!(
        decoded.version.daemon.release.as_ref().unwrap().as_str(),
        "20.10.5+dfsg1"
    );
    assert_eq!(decoded.version.daemon.mode, DaemonMode::Rootless);
    assert_eq!(decoded.version.daemon.api_version, Some(api(41)));
    assert!(decoded.version.client_release.is_none());
    assert!(decoded.version.distribution_package_revision.is_none());
    assert!(decoded.version.daemon.capabilities.is_empty());
    assert_eq!(decoded.containers.len(), 1);
    let c = &decoded.containers[0];
    assert_eq!(c.image.origin, Origin::Effective);
    assert_eq!(c.image_id.availability, Availability::Missing);
    assert_eq!(c.environment.origin, Origin::Effective);
    assert_eq!(c.environment.value().unwrap()[0].name.as_bytes(), b"TOKEN");
    assert_eq!(
        c.environment.value().unwrap()[0]
            .value
            .as_ref()
            .unwrap()
            .as_bytes(),
        b"private-value"
    );
    assert!(c.environment.value().unwrap()[1].value.is_none());
    assert_eq!(
        c.exposed_ports.value().unwrap()[0].protocol,
        TransportProtocol::Tcp
    );
    assert_eq!(
        c.configured_ports.value().unwrap()[0]
            .bindings
            .value()
            .unwrap()[0]
            .host_port
            .value(),
        Some(&8080)
    );
    assert_eq!(c.runtime_ports.origin, Origin::RuntimeAssigned);
    assert_eq!(
        c.runtime_ports.value().unwrap()[0]
            .bindings
            .value()
            .unwrap()[0]
            .host_port
            .origin,
        Origin::RuntimeAssigned
    );
    assert_eq!(
        c.runtime_ports.value().unwrap()[0]
            .bindings
            .value()
            .unwrap()[0]
            .host_port
            .availability,
        Availability::Empty
    );
    assert_eq!(c.mounts.value().unwrap()[0].kind, MountKind::Volume);
    assert_eq!(
        c.networks.value().unwrap()[0].ip_address.origin,
        Origin::RuntimeAssigned
    );
    assert!(matches!(c.command.value(), Some(CommandValue::Exec(parts)) if parts.len() == 2));
    assert_eq!(c.entrypoint.availability, Availability::Empty);
    assert_eq!(
        c.network_mode.value().unwrap().kind,
        NetworkModeKind::Bridge
    );
    assert!(
        matches!(c.healthcheck.value().unwrap().test.value(), Some(HealthcheckTest::Cmd(parts)) if parts.len() == 1)
    );
    assert_eq!(
        c.healthcheck.value().unwrap().start_period_ns.value(),
        Some(&2_000_000_000)
    );
    assert_eq!(
        c.healthcheck.value().unwrap().start_interval_ns.value(),
        Some(&3_000_000_000)
    );
    assert_eq!(c.healthcheck.value().unwrap().retries.value(), Some(&2));
    assert_eq!(
        c.restart_policy
            .value()
            .unwrap()
            .maximum_retry_count
            .value(),
        Some(&3)
    );
    assert_eq!(decoded.networks.len(), 1);
    assert_eq!(decoded.volumes.len(), 1);
    let debug = format!("{decoded:?} {:?}", c.environment);
    assert!(!debug.contains("private-value"));
    assert!(!debug.contains("/secret/host/path"));
}

#[test]
fn absence_null_empty_and_redaction_stay_distinct() {
    let fixture = container(
        r#"{"Config":{"Image":"","Env":null,"Cmd":{"__docker_lens_redacted__":true},"Entrypoint":[]},"HostConfig":{},"Mounts":[],"NetworkSettings":{"Ports":null}}"#,
    );
    let c = &decode_capture(&fixture).unwrap().containers.remove(0);
    assert_eq!(c.image.availability, Availability::Empty);
    assert_eq!(c.environment.availability, Availability::Null);
    assert_eq!(c.command.availability, Availability::Redacted);
    assert_eq!(c.entrypoint.availability, Availability::Empty);
    assert_eq!(c.configured_ports.availability, Availability::Missing);
    assert_eq!(c.mounts.availability, Availability::Empty);
    assert_eq!(c.runtime_ports.availability, Availability::Null);
    assert_eq!(c.healthcheck.availability, Availability::Missing);
}

#[test]
fn malformed_and_status_failures_are_closed_and_do_not_leak() {
    let invalid = container(r#"{"Config":{"Env":["=secret-value"]}}"#);
    let error = decode_capture(&invalid).err().unwrap();
    assert!(matches!(error, DecodeError::InvalidValue(_)));
    assert!(!format!("{error:?}").contains("secret-value"));
    let malformed = container("{private-value");
    assert_eq!(
        decode_capture(&malformed).err(),
        Some(DecodeError::InvalidJson)
    );
    let failed = capture(vec![(
        ReadRequest::DaemonVersion,
        None,
        None,
        500,
        "private-value",
    )]);
    assert_eq!(
        decode_capture(&failed).err(),
        Some(DecodeError::UnexpectedStatus)
    );
    let invalid_release = capture(vec![(
        ReadRequest::DaemonVersion,
        None,
        None,
        200,
        r#"{"Version":123}"#,
    )]);
    assert_eq!(
        decode_capture(&invalid_release).err(),
        Some(DecodeError::InvalidShape(
            docker_lens::observation::FieldPath::EngineRelease
        ))
    );
    let oversized_collection = format!("[{}]", vec!["null"; 4097].join(","));
    let oversized = capture(vec![(
        ReadRequest::ListContainers,
        None,
        Some(api(41)),
        200,
        &oversized_collection,
    )]);
    assert_eq!(
        decode_capture(&oversized).err(),
        Some(DecodeError::CollectionTooLarge)
    );
}

#[test]
fn api_boundary_and_version_conflicts_do_not_become_capabilities() {
    let old = capture(vec![
        (
            ReadRequest::DaemonVersion,
            None,
            None,
            200,
            r#"{"Version":"20.10.5+dfsg1","ApiVersion":"1.41","MinAPIVersion":"1.24"}"#,
        ),
        (ReadRequest::ListContainers, None, Some(api(23)), 200, "[]"),
    ]);
    assert_eq!(
        decode_capture(&old).err(),
        Some(DecodeError::ApiVersionOutOfRange)
    );
    let conflict = capture(vec![
        (
            ReadRequest::DaemonInfo,
            None,
            Some(api(41)),
            200,
            r#"{"ServerVersion":"20.10.5"}"#,
        ),
        (
            ReadRequest::DaemonVersion,
            None,
            None,
            200,
            r#"{"Version":"20.10.6","ApiVersion":"1.41"}"#,
        ),
    ]);
    assert_eq!(
        decode_capture(&conflict).err(),
        Some(DecodeError::ConflictingFacts)
    );
    let unknown_mode = capture(vec![(
        ReadRequest::DaemonInfo,
        None,
        Some(api(41)),
        200,
        r#"{"SecurityOptions":[]}"#,
    )]);
    let decoded = decode_capture(&unknown_mode).unwrap();
    assert_eq!(decoded.version.daemon.mode, DaemonMode::Unknown);
    assert!(decoded.version.daemon.capabilities.is_empty());
}

#[test]
fn unknown_mount_kind_is_reported_without_native_value() {
    let fixture = container(
        r#"{"Mounts":[{"Type":"secret-custom-kind","Source":"/private","Destination":"/data"}]}"#,
    );
    let decoded = decode_capture(&fixture).unwrap();
    assert_eq!(
        decoded.containers[0].mounts.value().unwrap()[0].kind,
        MountKind::Other
    );
    assert!(decoded.findings.iter().any(|finding| {
        finding.code == docker_lens::finding::FindingCode::UnsupportedValue
            && finding.resource == Some(ResourceRef::new(1))
    }));
    assert!(!format!("{decoded:?}").contains("secret-custom-kind"));
}

#[test]
fn network_modes_preserve_aliases_and_diagnose_non_bridge_modes() {
    for (native, expected) in [
        ("default", NetworkModeKind::Default),
        ("bridge", NetworkModeKind::Bridge),
        ("host", NetworkModeKind::Host),
        ("none", NetworkModeKind::None),
        ("container:private-container-id", NetworkModeKind::Container),
        ("private-network-alias", NetworkModeKind::Named),
    ] {
        let body = format!(r#"{{"HostConfig":{{"NetworkMode":"{native}"}}}}"#);
        let decoded = decode_capture(&container(&body)).unwrap();
        let mode = decoded.containers[0].network_mode.value().unwrap();
        assert_eq!(mode.kind, expected);
        assert_eq!(mode.native_value.as_bytes(), native.as_bytes());
        assert_eq!(
            decoded
                .findings
                .iter()
                .any(|finding| finding.field
                    == Some(docker_lens::observation::FieldPath::NetworkMode)),
            !matches!(expected, NetworkModeKind::Default | NetworkModeKind::Bridge),
        );
        assert!(!format!("{decoded:?}").contains(native));
    }
}

#[test]
fn healthcheck_forms_and_optional_timers_remain_distinct() {
    let shell = decode_capture(&container(r#"{"Config":{"Healthcheck":{"Test":["CMD-SHELL","private-command"],"StartPeriod":0,"StartInterval":500000000}}}"#)).unwrap();
    let health = shell.containers[0].healthcheck.value().unwrap();
    assert!(
        matches!(health.test.value(), Some(HealthcheckTest::CmdShell(command)) if command.as_bytes() == b"private-command")
    );
    assert_eq!(health.start_period_ns.value(), Some(&0));
    assert_eq!(health.start_interval_ns.value(), Some(&500_000_000));
    assert!(!format!("{shell:?}").contains("private-command"));

    let disabled = decode_capture(&container(
        r#"{"Config":{"Healthcheck":{"Test":["NONE"]}}}"#,
    ))
    .unwrap();
    let health = disabled.containers[0].healthcheck.value().unwrap();
    assert!(matches!(health.test.value(), Some(HealthcheckTest::None)));
    assert_eq!(health.start_period_ns.availability, Availability::Missing);
    assert_eq!(health.start_interval_ns.availability, Availability::Missing);

    let unknown = decode_capture(&container(
        r#"{"Config":{"Healthcheck":{"Test":["PRIVATE-NEW-FORM","secret"]}}}"#,
    ))
    .unwrap();
    assert!(matches!(
        unknown.containers[0]
            .healthcheck
            .value()
            .unwrap()
            .test
            .value(),
        Some(HealthcheckTest::Other(_))
    ));
    assert!(
        unknown
            .findings
            .iter()
            .any(|finding| finding.field == Some(docker_lens::observation::FieldPath::Healthcheck))
    );
    assert!(!format!("{unknown:?}").contains("secret"));
}

#[test]
fn each_known_api_bound_rejects_a_request_independently() {
    let minimum_only = capture(vec![
        (
            ReadRequest::DaemonVersion,
            None,
            None,
            200,
            r#"{"MinAPIVersion":"1.24"}"#,
        ),
        (ReadRequest::ListContainers, None, Some(api(23)), 200, "[]"),
    ]);
    assert_eq!(
        decode_capture(&minimum_only).err(),
        Some(DecodeError::ApiVersionOutOfRange)
    );
    let maximum_only = capture(vec![
        (
            ReadRequest::DaemonVersion,
            None,
            None,
            200,
            r#"{"ApiVersion":"1.41"}"#,
        ),
        (ReadRequest::ListContainers, None, Some(api(42)), 200, "[]"),
    ]);
    assert_eq!(
        decode_capture(&maximum_only).err(),
        Some(DecodeError::ApiVersionOutOfRange)
    );
}

#[test]
fn nonempty_discovery_requires_matching_inspection() {
    let listed_only = capture(vec![(
        ReadRequest::ListContainers,
        None,
        Some(api(41)),
        200,
        r#"[{"Id":"c1"}]"#,
    )]);
    assert_eq!(
        decode_capture(&listed_only).err(),
        Some(DecodeError::IncompleteInventory)
    );
    let mismatched = capture(vec![
        (
            ReadRequest::ListContainers,
            None,
            Some(api(41)),
            200,
            r#"[{"Id":"c1"}]"#,
        ),
        (
            ReadRequest::InspectContainer(NativeId::new("c2".into()).unwrap()),
            Some(ResourceRef::new(1)),
            Some(api(41)),
            200,
            "{}",
        ),
    ]);
    assert_eq!(
        decode_capture(&mismatched).err(),
        Some(DecodeError::IncompleteInventory)
    );
    let matched = capture(vec![
        (
            ReadRequest::ListContainers,
            None,
            Some(api(41)),
            200,
            r#"[{"Id":"c1"}]"#,
        ),
        (
            ReadRequest::InspectContainer(NativeId::new("c1".into()).unwrap()),
            Some(ResourceRef::new(1)),
            Some(api(41)),
            200,
            "{}",
        ),
    ]);
    assert_eq!(decode_capture(&matched).unwrap().containers.len(), 1);
    let partial = capture_selected(
        vec![
            (
                ReadRequest::ListContainers,
                None,
                Some(api(41)),
                200,
                r#"[{"Id":"c1"},{"Id":"c2"}]"#,
            ),
            (
                ReadRequest::InspectContainer(NativeId::new("c1".into()).unwrap()),
                Some(ResourceRef::new(1)),
                Some(api(41)),
                200,
                "{}",
            ),
        ],
        1,
    );
    assert_eq!(decode_capture(&partial).unwrap().containers.len(), 1);
    let missing_selected = capture_selected(
        vec![
            (
                ReadRequest::ListContainers,
                None,
                Some(api(41)),
                200,
                r#"[{"Id":"c1"},{"Id":"c2"}]"#,
            ),
            (
                ReadRequest::InspectContainer(NativeId::new("c1".into()).unwrap()),
                Some(ResourceRef::new(1)),
                Some(api(41)),
                200,
                "{}",
            ),
        ],
        2,
    );
    assert_eq!(
        decode_capture(&missing_selected).err(),
        Some(DecodeError::IncompleteInventory)
    );
    let network_only = capture(vec![(
        ReadRequest::ListNetworks,
        None,
        Some(api(41)),
        200,
        r#"[{"Id":"net1"}]"#,
    )]);
    assert_eq!(
        decode_capture(&network_only).err(),
        Some(DecodeError::IncompleteInventory)
    );
    let network_subset = capture(vec![
        (
            ReadRequest::ListNetworks,
            None,
            Some(api(41)),
            200,
            r#"[{"Id":"net1"},{"Id":"net2"}]"#,
        ),
        (
            ReadRequest::InspectNetwork(NativeId::new("net1".into()).unwrap()),
            Some(ResourceRef::new(2)),
            Some(api(41)),
            200,
            "{}",
        ),
    ]);
    assert_eq!(decode_capture(&network_subset).unwrap().networks.len(), 1);
    let volume_only = capture(vec![(
        ReadRequest::ListVolumes,
        None,
        Some(api(41)),
        200,
        r#"{"Volumes":[{"Name":"data"}]}"#,
    )]);
    assert_eq!(
        decode_capture(&volume_only).err(),
        Some(DecodeError::IncompleteInventory)
    );
    let volume_subset = capture(vec![
        (
            ReadRequest::ListVolumes,
            None,
            Some(api(41)),
            200,
            r#"{"Volumes":[{"Name":"data"},{"Name":"unselected"}]}"#,
        ),
        (
            ReadRequest::InspectVolume(NativeId::new("data".into()).unwrap()),
            Some(ResourceRef::new(3)),
            Some(api(41)),
            200,
            "{}",
        ),
    ]);
    assert_eq!(decode_capture(&volume_subset).unwrap().volumes.len(), 1);
}

#[test]
fn network_endpoint_aliases_preserve_values_and_availability() {
    let decoded = decode_capture(&container(r#"{"NetworkSettings":{"Networks":{"a":{"Aliases":["private-app","db"]},"b":{"Aliases":[]},"c":{"Aliases":null},"d":{"Aliases":{"__docker_lens_redacted__":true}},"e":{}}}}"#)).unwrap();
    let networks = decoded.containers[0].networks.value().unwrap();
    let aliases = |name: &[u8]| {
        &networks
            .iter()
            .find(|network| network.name.as_bytes() == name)
            .unwrap()
            .aliases
    };
    assert_eq!(aliases(b"a").origin, Origin::Effective);
    assert_eq!(aliases(b"a").availability, Availability::Present);
    assert_eq!(aliases(b"a").value().unwrap()[0].as_bytes(), b"private-app");
    assert_eq!(aliases(b"b").availability, Availability::Empty);
    assert_eq!(aliases(b"c").availability, Availability::Null);
    assert_eq!(aliases(b"d").availability, Availability::Redacted);
    assert_eq!(aliases(b"e").availability, Availability::Missing);
    assert!(!format!("{decoded:?}").contains("private-app"));
}
