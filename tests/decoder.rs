use std::num::NonZeroU16;
use std::time::Duration;

use docker_lens::acquisition::{Budget, Limits, NativeId, ReadRequest};
use docker_lens::decoder::{
    CommandValue, DecodeError, HealthcheckTest, MountKind, NetworkModeKind, TransportProtocol,
    decode_capture,
};
use docker_lens::evidence::HttpStatus;
use docker_lens::observation::{Availability, FieldPath, Origin, ResourceRef};
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
        let mut fixture = serde_json::from_str::<serde_json::Value>(body).ok();
        let identity = match &request {
            ReadRequest::InspectContainer(id) | ReadRequest::InspectNetwork(id) => {
                Some(("Id", id.as_str()))
            }
            ReadRequest::InspectVolume(id) => Some(("Name", id.as_str())),
            _ => None,
        };
        if let (Some((key, id)), Some(serde_json::Value::Object(object))) = (identity, &mut fixture)
        {
            object
                .entry(key)
                .or_insert_with(|| serde_json::Value::String(id.to_owned()));
        }
        let body = fixture.map_or_else(|| body.to_owned(), |value| value.to_string());
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

fn network(body: &str) -> docker_lens::evidence::Capture {
    capture(vec![(
        ReadRequest::InspectNetwork(NativeId::new("private-network-id".into()).unwrap()),
        Some(ResourceRef::new(2)),
        Some(api(41)),
        200,
        body,
    )])
}

#[test]
fn network_active_membership_top_level_availability_is_distinct() {
    for (body, expected) in [
        (r#"{}"#, Availability::Missing),
        (r#"{"Containers":null}"#, Availability::Null),
        (r#"{"Containers":{}}"#, Availability::Empty),
        (
            r#"{"Containers":{"__docker_lens_redacted__":true}}"#,
            Availability::Redacted,
        ),
    ] {
        let decoded = decode_capture(&network(body)).unwrap();
        let members = &decoded.networks[0].active_endpoints;
        assert_eq!(members.availability, expected);
        assert_eq!(members.origin, Origin::RuntimeAssigned);
        assert_eq!(members.value().is_some(), expected == Availability::Empty);
    }
}

#[test]
fn network_active_membership_entry_and_name_availability_are_independent() {
    let id = "a".repeat(64);
    for (entry, endpoint_state, name_state) in [
        ("null", Availability::Null, None),
        (
            r#"{"__docker_lens_redacted__":true}"#,
            Availability::Redacted,
            None,
        ),
        ("{}", Availability::Empty, Some(Availability::Missing)),
        (
            r#"{"Name":null}"#,
            Availability::Present,
            Some(Availability::Null),
        ),
        (
            r#"{"Name":""}"#,
            Availability::Present,
            Some(Availability::Empty),
        ),
        (
            r#"{"Name":{"__docker_lens_redacted__":true}}"#,
            Availability::Present,
            Some(Availability::Redacted),
        ),
        (
            r#"{"Name":"private-endpoint-name"}"#,
            Availability::Present,
            Some(Availability::Present),
        ),
    ] {
        let body = format!(r#"{{"Containers":{{"{id}":{entry}}}}}"#);
        let decoded = decode_capture(&network(&body)).unwrap();
        let members = decoded.networks[0].active_endpoints.value().unwrap();
        assert_eq!(members.len(), 1);
        let member = &members[0];
        assert_eq!(member.container_id.origin, Origin::RuntimeAssigned);
        assert_eq!(member.container_id.availability, Availability::Present);
        assert_eq!(
            member.container_id.value().unwrap().as_bytes(),
            id.as_bytes()
        );
        assert_eq!(member.endpoint.origin, Origin::RuntimeAssigned);
        assert_eq!(member.endpoint.availability, endpoint_state);
        match name_state {
            Some(expected) => {
                let name = &member.endpoint.value().unwrap().name;
                assert_eq!(name.origin, Origin::Effective);
                assert_eq!(name.availability, expected);
                if expected == Availability::Present {
                    assert_eq!(name.value().unwrap().as_bytes(), b"private-endpoint-name");
                }
                assert!(!format!("{name:?}").contains("private-endpoint-name"));
            }
            None => assert!(member.endpoint.value().is_none()),
        }
        assert!(!format!("{:?}", member.container_id).contains(&id));
        assert!(!format!("{decoded:?}").contains("private-endpoint-name"));
    }
}

#[test]
fn network_active_membership_invalid_shapes_and_ids_fail_without_values() {
    let id = "a".repeat(64);
    for (body, expected) in [
        (
            r#"{"Containers":[]}"#.to_owned(),
            DecodeError::InvalidShape(FieldPath::Network { index: 0 }),
        ),
        (
            r#"{"Containers":42}"#.to_owned(),
            DecodeError::InvalidShape(FieldPath::Network { index: 0 }),
        ),
        (
            r#"{"Containers":{"private-id":{}}}"#.to_owned(),
            DecodeError::InvalidValue(FieldPath::Network { index: 0 }),
        ),
        (
            format!(r#"{{"Containers":{{"{}":{{}}}}}}"#, "z".repeat(64)),
            DecodeError::InvalidValue(FieldPath::Network { index: 0 }),
        ),
        (
            format!(r#"{{"Containers":{{"{id}":[]}}}}"#),
            DecodeError::InvalidShape(FieldPath::Network { index: 0 }),
        ),
        (
            format!(r#"{{"Containers":{{"{id}":{{"Name":42}}}}}}"#),
            DecodeError::InvalidShape(FieldPath::Network { index: 0 }),
        ),
    ] {
        let error = decode_capture(&network(&body)).err().unwrap();
        assert_eq!(error, expected);
        assert!(!format!("{error:?}").contains("private-id"));
    }
}

#[test]
fn network_active_membership_is_bounded_and_does_not_expand_selection() {
    let selected = "a".repeat(64);
    let unselected = "b".repeat(64);
    let body = format!(
        r#"{{"Containers":{{"{selected}":{{"Name":"selected"}},"{unselected}":{{"Name":"unselected"}}}}}}"#
    );
    let decoded = decode_capture(&capture(vec![
        (
            ReadRequest::InspectContainer(NativeId::new(selected.clone()).unwrap()),
            Some(ResourceRef::new(1)),
            Some(api(41)),
            200,
            &format!(r#"{{"Id":"{selected}"}}"#),
        ),
        (
            ReadRequest::InspectNetwork(NativeId::new("private-network-id".into()).unwrap()),
            Some(ResourceRef::new(2)),
            Some(api(41)),
            200,
            &body,
        ),
    ]))
    .unwrap();
    assert_eq!(decoded.containers.len(), 1);
    assert_eq!(
        decoded.networks[0].active_endpoints.value().unwrap().len(),
        2
    );
    assert!(
        decoded.networks[0]
            .active_endpoints
            .value()
            .unwrap()
            .iter()
            .any(|member| member.container_id.value().unwrap().as_bytes() == unselected.as_bytes())
    );

    let mut entries = serde_json::Map::new();
    for index in 0..4096 {
        entries.insert(format!("{index:064x}"), serde_json::json!({}));
    }
    let body = serde_json::json!({"Containers": entries}).to_string();
    assert_eq!(
        decode_capture(&network(&body)).unwrap().networks[0]
            .active_endpoints
            .value()
            .unwrap()
            .len(),
        4096
    );
    let mut value: serde_json::Value = serde_json::from_str(&body).unwrap();
    value["Containers"]
        .as_object_mut()
        .unwrap()
        .insert(format!("{:064x}", 4096), serde_json::json!({}));
    assert_eq!(
        decode_capture(&network(&value.to_string())).err(),
        Some(DecodeError::CollectionTooLarge)
    );
}

#[test]
fn inspect_identity_must_match_closed_request() {
    for body in [
        r#"{"Id":"different-container"}"#,
        r#"{"Id":null}"#,
        r#"{"Id":{"__docker_lens_redacted__":true}}"#,
    ] {
        assert!(matches!(
            decode_capture(&container(body)),
            Err(DecodeError::ConflictingFacts)
        ));
    }
    let volume = capture(vec![(
        ReadRequest::InspectVolume(NativeId::new("data".into()).unwrap()),
        Some(ResourceRef::new(1)),
        Some(api(41)),
        200,
        r#"{"Name":"stale-data"}"#,
    )]);
    assert!(matches!(
        decode_capture(&volume),
        Err(DecodeError::ConflictingFacts)
    ));
}

#[test]
fn inspected_network_id_is_typed_runtime_identity_and_private() {
    let fixture = capture(vec![(
        ReadRequest::InspectNetwork(NativeId::new("private-network-id".into()).unwrap()),
        Some(ResourceRef::new(2)),
        Some(api(41)),
        200,
        r#"{"Id":"private-network-id","Name":"backend"}"#,
    )]);
    let decoded = decode_capture(&fixture).unwrap();
    let id = &decoded.networks[0].id;
    assert_eq!(id.availability, Availability::Present);
    assert_eq!(id.origin, Origin::RuntimeAssigned);
    assert_eq!(id.value().unwrap().as_bytes(), b"private-network-id");
    assert!(!format!("{id:?}").contains("private-network-id"));
    assert!(!format!("{decoded:?}").contains("private-network-id"));
}

#[test]
fn inspected_container_id_is_typed_runtime_identity_and_private() {
    let id = "a".repeat(64);
    let fixture = capture(vec![(
        ReadRequest::InspectContainer(NativeId::new(id.clone()).unwrap()),
        Some(ResourceRef::new(1)),
        Some(api(41)),
        200,
        &format!(r#"{{"Id":"{id}","Name":"/app"}}"#),
    )]);
    let decoded = decode_capture(&fixture).unwrap();
    let observed = &decoded.containers[0].id;
    assert_eq!(observed.availability, Availability::Present);
    assert_eq!(observed.origin, Origin::RuntimeAssigned);
    assert_eq!(observed.value().unwrap().as_bytes(), id.as_bytes());
    assert!(!format!("{observed:?}").contains(&id));
    assert!(!format!("{decoded:?}").contains(&id));
}

#[test]
fn matching_noncanonical_inspect_container_id_preserves_capture_compatibility() {
    let fixture = container(r#"{"Id":"container-1"}"#);
    let decoded = decode_capture(&fixture).unwrap();
    let observed = &decoded.containers[0].id;
    assert_eq!(observed.origin, Origin::RuntimeAssigned);
    assert_eq!(observed.availability, Availability::Present);
    assert_eq!(observed.value().unwrap().as_bytes(), b"container-1");
}

#[test]
fn inspected_container_id_rejects_unavailable_wrong_shape_or_mismatched() {
    for body in [
        r#"{"Id":null}"#,
        r#"{"Id":{"__docker_lens_redacted__":true}}"#,
        r#"{"Id":""}"#,
        r#"{"Id":42}"#,
        r#"{"Id":"private-canary"}"#,
    ] {
        let fixture = capture(vec![(
            ReadRequest::InspectContainer(NativeId::new("expected-id".into()).unwrap()),
            Some(ResourceRef::new(1)),
            Some(api(41)),
            200,
            body,
        )]);
        let error = decode_capture(&fixture).unwrap_err();
        assert_eq!(error, DecodeError::ConflictingFacts);
        assert!(!format!("{error:?}").contains("private-canary"));
    }
}

#[test]
fn inspected_network_id_cannot_be_null_redacted_empty_or_mismatched() {
    for body in [
        r#"{"Id":null}"#,
        r#"{"Id":{"__docker_lens_redacted__":true}}"#,
        r#"{"Id":""}"#,
        r#"{"Id":"other-network"}"#,
    ] {
        let fixture = capture(vec![(
            ReadRequest::InspectNetwork(NativeId::new("private-network-id".into()).unwrap()),
            Some(ResourceRef::new(2)),
            Some(api(41)),
            200,
            body,
        )]);
        assert_eq!(
            decode_capture(&fixture).err(),
            Some(DecodeError::ConflictingFacts)
        );
    }
}

#[test]
fn literal_missing_inspect_identity_is_rejected() {
    for request in [
        ReadRequest::InspectContainer(NativeId::new("a".repeat(64)).unwrap()),
        ReadRequest::InspectNetwork(NativeId::new("b".repeat(64)).unwrap()),
        ReadRequest::InspectVolume(NativeId::new("data".into()).unwrap()),
    ] {
        // Bypass fixture normalization: the literal response has no Id or Name.
        let mut budget = Budget::new(Limits {
            max_requests: 1,
            max_selected_resources: 1,
            max_expansions: 1,
            max_response_bytes: 1024,
            max_total_bytes: 1024,
            max_elapsed: Duration::from_secs(30),
        })
        .unwrap();
        budget
            .record_request(request, Some(ResourceRef::new(1)), Some(api(41)))
            .unwrap();
        budget
            .read_response(HttpStatus::new(200).unwrap(), b"{}".as_slice())
            .unwrap();
        assert!(matches!(
            decode_capture(&budget.into_capture().unwrap()),
            Err(DecodeError::ConflictingFacts)
        ));
    }
}

#[test]
fn synthetic_engine_fixture_decodes_typed_inventory_without_authorship() {
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
            ReadRequest::InspectVolume(NativeId::new("data".into()).unwrap()),
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
fn container_identity_and_effective_config_are_typed_and_private() {
    // Shape mirrors Engine's container inspect: Name is top-level, while the
    // other fields are members of Config. Values are observations, not intent.
    let decoded = decode_capture(&container(
        r#"{"Name":"/private-app","Config":{"Labels":{"app.role":"frontend","secret.key":"private-token","empty.label":""},"User":"1000:1000","WorkingDir":"/private/work","Hostname":"private-host"}}"#,
    ))
    .unwrap();
    let c = &decoded.containers[0];
    assert_eq!(c.reference, ResourceRef::new(1));
    assert_eq!(c.name.origin, Origin::Effective);
    assert_eq!(c.name.value().unwrap().as_bytes(), b"/private-app");
    assert_eq!(c.user.value().unwrap().as_bytes(), b"1000:1000");
    assert_eq!(
        c.working_directory.value().unwrap().as_bytes(),
        b"/private/work"
    );
    assert_eq!(c.hostname.value().unwrap().as_bytes(), b"private-host");
    assert_eq!(c.labels.origin, Origin::Effective);
    assert_eq!(c.labels.availability, Availability::Present);
    let label = |key: &[u8]| {
        &c.labels
            .value()
            .unwrap()
            .iter()
            .find(|label| label.key.as_bytes() == key)
            .unwrap()
            .value
    };
    assert_eq!(label(b"app.role").value().unwrap().as_bytes(), b"frontend");
    assert_eq!(
        label(b"secret.key").value().unwrap().as_bytes(),
        b"private-token"
    );
    assert_eq!(label(b"empty.label").availability, Availability::Empty);
    assert!(decoded.findings.iter().all(|finding| {
        !matches!(
            finding.field,
            Some(
                FieldPath::ContainerName
                    | FieldPath::User
                    | FieldPath::WorkingDirectory
                    | FieldPath::Hostname
                    | FieldPath::Label { .. }
            )
        )
    }));
    let debug = format!(
        "{decoded:?} {:?} {:?} {:?} {:?} {:?}",
        c.name, c.labels, c.user, c.working_directory, c.hostname
    );
    for private in [
        "/private-app",
        "secret.key",
        "private-token",
        "1000:1000",
        "/private/work",
        "private-host",
    ] {
        assert!(!debug.contains(private));
    }
}

#[test]
fn effective_config_preserves_absence_null_empty_and_redaction() {
    let missing = decode_capture(&container(r#"{}"#)).unwrap();
    let c = &missing.containers[0];
    for availability in [
        c.name.availability,
        c.labels.availability,
        c.user.availability,
        c.working_directory.availability,
        c.hostname.availability,
    ] {
        assert_eq!(availability, Availability::Missing);
    }

    let null = decode_capture(&container(
        r#"{"Name":null,"Config":{"Labels":null,"User":null,"WorkingDir":null,"Hostname":null}}"#,
    ))
    .unwrap();
    let c = &null.containers[0];
    for availability in [
        c.name.availability,
        c.labels.availability,
        c.user.availability,
        c.working_directory.availability,
        c.hostname.availability,
    ] {
        assert_eq!(availability, Availability::Null);
    }

    let empty = decode_capture(&container(
        r#"{"Name":"","Config":{"Labels":{},"User":"","WorkingDir":"","Hostname":""}}"#,
    ))
    .unwrap();
    let c = &empty.containers[0];
    for availability in [
        c.name.availability,
        c.labels.availability,
        c.user.availability,
        c.working_directory.availability,
        c.hostname.availability,
    ] {
        assert_eq!(availability, Availability::Empty);
    }
    assert!(c.labels.value().unwrap().is_empty());
    assert_eq!(c.user.value().unwrap().as_bytes(), b"");

    let redacted = decode_capture(&container(
        r#"{"Name":{"__docker_lens_redacted__":true},"Config":{"Labels":{"__docker_lens_redacted__":true},"User":{"__docker_lens_redacted__":true},"WorkingDir":{"__docker_lens_redacted__":true},"Hostname":{"__docker_lens_redacted__":true}}}"#,
    ))
    .unwrap();
    let c = &redacted.containers[0];
    for availability in [
        c.name.availability,
        c.labels.availability,
        c.user.availability,
        c.working_directory.availability,
        c.hostname.availability,
    ] {
        assert_eq!(availability, Availability::Redacted);
    }
    assert!(c.labels.value().is_none());

    let partial = decode_capture(&container(
        r#"{"Config":{"Labels":{"plain":"value","hidden":{"__docker_lens_redacted__":true},"unavailable":null}}}"#,
    ))
    .unwrap();
    let labels = partial.containers[0].labels.value().unwrap();
    for (key, expected) in [
        (b"plain".as_slice(), Availability::Present),
        (b"hidden".as_slice(), Availability::Redacted),
        (b"unavailable".as_slice(), Availability::Null),
    ] {
        assert_eq!(
            labels
                .iter()
                .find(|label| label.key.as_bytes() == key)
                .unwrap()
                .value
                .availability,
            expected
        );
    }
}

#[test]
fn malformed_effective_metadata_fails_without_native_values_in_errors() {
    for (body, field) in [
        (r#"{"Name":42}"#, FieldPath::ContainerName),
        (r#"{"Config":{"Labels":[]}}"#, FieldPath::Label { index: 0 }),
        (
            r#"{"Config":{"Labels":{"private-key":42}}}"#,
            FieldPath::Label { index: 0 },
        ),
        (r#"{"Config":{"User":42}}"#, FieldPath::User),
        (
            r#"{"Config":{"WorkingDir":false}}"#,
            FieldPath::WorkingDirectory,
        ),
        (r#"{"Config":{"Hostname":[]}}"#, FieldPath::Hostname),
    ] {
        let error = decode_capture(&container(body)).err().unwrap();
        assert_eq!(error, DecodeError::InvalidShape(field));
        assert!(!format!("{error:?}").contains("private-key"));
    }
}

#[test]
fn oversized_label_object_fails_closed() {
    let labels: serde_json::Map<String, serde_json::Value> = (0..4097)
        .map(|index| {
            (
                format!("label-{index}"),
                serde_json::Value::String("private-value".into()),
            )
        })
        .collect();
    let body = serde_json::json!({ "Config": { "Labels": labels } }).to_string();
    let error = decode_capture(&container(&body)).err().unwrap();
    assert_eq!(error, DecodeError::CollectionTooLarge);
    assert!(!format!("{error:?}").contains("private-value"));
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

#[test]
fn runtime_and_network_inspect_fields_keep_independent_native_meanings() {
    let fixture = capture(vec![
        (
            ReadRequest::InspectContainer(NativeId::new("app".into()).unwrap()),
            Some(ResourceRef::new(1)),
            Some(api(41)),
            200,
            r#"{"Config":{"StopSignal":"SIGTERM","StopTimeout":15},"HostConfig":{"ReadonlyRootfs":true,"Memory":536870912,"PidsLimit":-1,"ShmSize":67108864,"Ulimits":[{"Name":"nofile","Soft":1024,"Hard":2048}],"CapAdd":["NET_BIND_SERVICE"],"SecurityOpt":["no-new-privileges:true"],"GroupAdd":["1001"],"Sysctls":{"net.ipv4.ip_unprivileged_port_start":"0"},"Dns":["127.0.0.11"],"ExtraHosts":["db:host-gateway"],"Init":true,"Tmpfs":{"/run":"rw,size=65536"},"LogConfig":{"Type":"json-file","Config":{"max-size":"10m"}},"Devices":[{"PathOnHost":"/dev/fuse","PathInContainer":"/dev/fuse","CgroupPermissions":"rwm"}]},"NetworkSettings":{"Networks":{"backend":{"NetworkID":"net-1","IPAddress":"172.18.0.4","GlobalIPv6Address":"fd00::4","IPAMConfig":{"IPv4Address":"172.18.0.4","IPv6Address":"fd00::4"},"Aliases":["app"]}}}}"#,
        ),
        (
            ReadRequest::InspectNetwork(NativeId::new("net-1".into()).unwrap()),
            Some(ResourceRef::new(2)),
            Some(api(41)),
            200,
            r#"{"Name":"backend","Driver":"bridge","Internal":true,"EnableIPv6":true,"IPAM":{"Driver":"default","Config":[{"Subnet":"fd00::/64","Gateway":"fd00::1","IPRange":null}]},"Options":{"com.example.private":"value"},"Labels":{"app":"private"}}"#,
        ),
    ]);
    let decoded = decode_capture(&fixture).unwrap();
    let container = &decoded.containers[0];
    assert_eq!(container.runtime.read_only_rootfs.value(), Some(&true));
    assert_eq!(container.runtime.memory_bytes.value(), Some(&536_870_912));
    assert_eq!(container.runtime.pids_limit.value(), Some(&-1));
    assert_eq!(
        container.runtime.ulimits.value().unwrap()[0].hard.value(),
        Some(&2048)
    );
    assert_eq!(
        container
            .runtime
            .logging
            .value()
            .unwrap()
            .driver
            .value()
            .unwrap()
            .as_bytes(),
        b"json-file"
    );
    assert_eq!(container.runtime.stop_timeout.value(), Some(&15));
    let attachment = &container.networks.value().unwrap()[0];
    assert_eq!(attachment.ip_address.origin, Origin::RuntimeAssigned);
    assert_eq!(attachment.requested_ipv4_address.origin, Origin::Effective);
    assert_eq!(
        attachment
            .requested_ipv4_address
            .value()
            .unwrap()
            .as_bytes(),
        b"172.18.0.4"
    );
    let network = &decoded.networks[0];
    assert_eq!(network.internal.value(), Some(&true));
    assert_eq!(network.enable_ipv6.value(), Some(&true));
    assert_eq!(
        network.ipam_configs.value().unwrap()[0]
            .ip_range
            .availability,
        Availability::Null
    );
    assert!(!format!("{decoded:?}").contains("no-new-privileges"));
    assert!(!format!("{decoded:?}").contains("fd00::/64"));
}

#[test]
fn runtime_availability_and_failure_categories_are_closed() {
    let named = decode_capture(&container(r#"{"HostConfig":{"UsernsMode":"private"}}"#)).unwrap();
    assert_eq!(
        named.containers[0].runtime.userns_mode.origin,
        Origin::Effective
    );
    assert_eq!(
        named.containers[0]
            .runtime
            .userns_mode
            .value()
            .unwrap()
            .as_bytes(),
        b"private"
    );
    let redacted = decode_capture(&container(
        r#"{"HostConfig":{"UsernsMode":{"__docker_lens_redacted__":true}}}"#,
    ))
    .unwrap();
    assert_eq!(
        redacted.containers[0].runtime.userns_mode.availability,
        Availability::Redacted
    );
    let decoded = decode_capture(&container(r#"{"HostConfig":{"ReadonlyRootfs":null,"Memory":{"__docker_lens_redacted__":true},"PidsLimit":0,"CapAdd":[],"Dns":null},"Config":{"StopSignal":""}}"#)).unwrap();
    let runtime = &decoded.containers[0].runtime;
    assert_eq!(runtime.read_only_rootfs.availability, Availability::Null);
    assert_eq!(runtime.memory_bytes.availability, Availability::Redacted);
    assert_eq!(runtime.pids_limit.value(), Some(&0));
    assert_eq!(runtime.cap_add.availability, Availability::Empty);
    assert_eq!(runtime.dns_servers.availability, Availability::Null);
    assert_eq!(runtime.stop_signal.availability, Availability::Empty);
    assert_eq!(runtime.devices.availability, Availability::Missing);
    assert!(matches!(
        decode_capture(&container(r#"{"HostConfig":{"Memory":"512m"}}"#)),
        Err(DecodeError::InvalidShape(FieldPath::ResourceLimit))
    ));
}
