//! Authored prerequisite serialization controls, not native qualification.

use super::*;
use crate::target::{
    BindRelabel, ContainerIntent, ContainerSettings, DockerPlanner, ImageCommand, ImageReference,
    Mount, NetworkAttachmentIntent, NetworkDriver, NetworkIntent, NetworkRole, Planner,
    PlanningError, TargetField, TargetIdentity, TargetIntent,
};
use crate::version::{
    Capability, CapabilityError, CapabilityFact, CapabilityScope, CapabilityState, DaemonFacts,
    EngineRelease, FactProvenance, NativeCapabilityShape, ObservationId, TargetCapabilityCatalog,
    TargetCapabilityFact, ValidatedCapabilities,
};
use serde_json::{Value, json};
use std::num::NonZeroU16;

const CAPABILITIES: &[Capability] = &[
    Capability::StandaloneContainer,
    Capability::NamedVolume,
    Capability::VolumeExternalReference,
    Capability::BridgeNetwork,
    Capability::NetworkExternalReference,
    Capability::NetworkExternalInternalExpectation,
    Capability::BindMount,
    Capability::BindRelabelPrivate,
];

fn facts(api: u16, mode: DaemonMode, capabilities: &[Capability]) -> DaemonFacts {
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
        capabilities: capabilities
            .iter()
            .map(|capability| CapabilityFact {
                capability: *capability,
                state: CapabilityState::Available,
                provenance: FactProvenance::NativeConformance,
                scope: Some(scope.clone()),
            })
            .collect(),
    }
}

fn external(reference: u64, name: &[u8], expected_internal: Option<bool>) -> TargetResource {
    TargetResource::Network(NetworkIntent {
        reference: ResourceRef::new(reference),
        identity: TargetIdentity::new(name.to_vec()).unwrap(),
        role: NetworkRole::Declared,
        source: NetworkSource::External {
            expected_driver: NetworkDriver::Bridge,
            expected_internal,
        },
    })
}

fn target(expected_internal: Option<bool>, relabel: bool) -> TargetIntent {
    let plain = Mount::bind(b"/private-source-canary".to_vec(), b"/data".to_vec(), true).unwrap();
    let bind = if relabel {
        plain.with_bind_relabel(BindRelabel::Private).unwrap()
    } else {
        plain
    };
    TargetIntent::new(vec![
        external(1, b"private-network-canary", expected_internal),
        TargetResource::ExternalVolume {
            reference: ResourceRef::new(2),
            identity: TargetIdentity::new(b"private-volume-canary".to_vec()).unwrap(),
        },
        external(3, b"unconstrained-network-canary", None),
        TargetResource::Container(Box::new(ContainerIntent {
            reference: ResourceRef::new(4),
            identity: TargetIdentity::new(b"private-container-canary".to_vec()).unwrap(),
            image: ImageReference::new(b"example.invalid/image:1".to_vec()).unwrap(),
            environment: vec![],
            ports: vec![],
            mounts: vec![
                bind,
                Mount::volume(ResourceRef::new(2), b"/volume".to_vec(), false).unwrap(),
            ],
            networks: vec![NetworkAttachmentIntent {
                network: ResourceRef::new(1),
                aliases: vec![],
                ipv4_address: None,
                ipv6_address: None,
            }],
            entrypoint: ImageCommand::Inherit,
            command: ImageCommand::Inherit,
            healthcheck: None,
            restart: None,
            settings: ContainerSettings::default(),
        })),
    ])
    .unwrap()
}

fn render(target: &TargetIntent, api: u16, mode: DaemonMode) -> RenderedArtifact {
    let facts = facts(api, mode, CAPABILITIES);
    let validated = ValidatedCapabilities::new(&facts).unwrap();
    DockerApiRenderer
        .render(&DockerPlanner.plan(target, &validated).unwrap())
        .unwrap()
}

#[test]
fn expectation_preserves_none_false_true_requests_order_and_conditional_schema() {
    for (api, mode) in [
        (41, DaemonMode::Rootful),
        (41, DaemonMode::Rootless),
        (56, DaemonMode::Rootful),
        (56, DaemonMode::Rootless),
    ] {
        for relabel in [false, true] {
            let baseline = render(&target(None, relabel), api, mode);
            let baseline_document: Value =
                serde_json::from_slice(&baseline.complete_bytes().unwrap()).unwrap();
            assert_eq!(
                baseline_document["schema_version"],
                if relabel { 2 } else { 1 }
            );
            assert_eq!(
                baseline_document["prerequisites"][0],
                json!({
                    "kind": "network", "reference": "1", "identity": "private-network-canary", "expected_driver": "bridge",
                })
            );
            assert_eq!(baseline_document["prerequisites"][1]["kind"], "volume");
            assert_eq!(baseline_document["prerequisites"][2]["reference"], "3");
            assert_eq!(
                baseline_document["prerequisites"].as_array().unwrap().len(),
                if relabel { 4 } else { 3 }
            );
            if relabel {
                assert_eq!(baseline_document["prerequisites"][3]["kind"], "bind_source");
            }
            for expectation in [None, Some(false), Some(true)] {
                let intent = target(expectation, relabel);
                let artifact = render(&intent, api, mode);
                assert_eq!(artifact.bytes(), baseline.bytes());
                assert_eq!(
                    artifact.network_prerequisites()[0].expected_internal,
                    expectation
                );
                assert_eq!(artifact.network_prerequisites()[1].expected_internal, None);
                let mut expected = baseline_document.clone();
                if let Some(value) = expectation {
                    expected["schema_version"] = json!(3);
                    expected["prerequisites"][0]["expected_internal"] = json!(value);
                }
                let document: Value =
                    serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
                assert_eq!(document, expected);
                if expectation.is_none() {
                    assert_eq!(
                        artifact.complete_bytes().unwrap(),
                        baseline.complete_bytes().unwrap()
                    );
                }
                for debug in [
                    format!("{intent:?}"),
                    format!("{artifact:?}"),
                    format!("{:?}", artifact.network_prerequisites()),
                ] {
                    assert!(!debug.contains("canary"));
                }
            }
        }
    }
}

#[test]
fn existing_external_prerequisite_keeps_exact_schema_one_bytes() {
    let intent = TargetIntent::new(vec![external(1, b"edge", None)]).unwrap();
    let artifact = render(&intent, 41, DaemonMode::Rootful);
    assert!(artifact.bytes().is_empty());
    assert_eq!(artifact.complete_bytes().unwrap(), br#"{"schema_version":1,"context":{"kind":"observed","provenance":"process_local_only","engine_release":"20.10.5","api_version":"1.41","daemon_mode":"rootful"},"requests":[],"prerequisites":[{"kind":"network","reference":"1","identity":"edge","expected_driver":"bridge"}]}
"#);
}

#[test]
fn unconstrained_external_network_and_relabelled_bind_keep_literal_schema_two_and_request_bytes() {
    // Independently authored from the original 3742f1136 renderer contract;
    // neither expected stream is derived from the renderer under test.
    let bind = Mount::bind(b"/private\"source\\leaf".to_vec(), b"/data".to_vec(), true)
        .unwrap()
        .with_bind_relabel(BindRelabel::Private)
        .unwrap();
    let intent = TargetIntent::new(vec![
        external(1, b"edge_net-1", None),
        TargetResource::Container(Box::new(ContainerIntent {
            reference: ResourceRef::new(2),
            identity: TargetIdentity::new(b"app.fixture-1".to_vec()).unwrap(),
            image: ImageReference::new(b"example.invalid/image:1".to_vec()).unwrap(),
            environment: vec![],
            ports: vec![],
            mounts: vec![bind],
            networks: vec![NetworkAttachmentIntent {
                network: ResourceRef::new(1),
                aliases: vec![],
                ipv4_address: None,
                ipv6_address: None,
            }],
            entrypoint: ImageCommand::Inherit,
            command: ImageCommand::Inherit,
            healthcheck: None,
            restart: None,
            settings: ContainerSettings::default(),
        })),
    ])
    .unwrap();
    let artifact = render(&intent, 41, DaemonMode::Rootful);
    assert_eq!(artifact.network_prerequisites()[0].expected_internal, None);
    assert_eq!(artifact.bytes(), br#"{"method":"POST","path":"/v1.41/containers/create?name=app.fixture-1","body":{"Image":"example.invalid/image:1","HostConfig":{"Binds":["/private\"source\\leaf:/data:ro,Z"],"NetworkMode":"edge_net-1"},"NetworkingConfig":{"EndpointsConfig":{"edge_net-1":{}}}}}
"#);
    assert_eq!(artifact.complete_bytes().unwrap(), br#"{"schema_version":2,"context":{"kind":"observed","provenance":"process_local_only","engine_release":"20.10.5","api_version":"1.41","daemon_mode":"rootful"},"requests":[{"method":"POST","path":"/v1.41/containers/create?name=app.fixture-1","body":{"Image":"example.invalid/image:1","HostConfig":{"Binds":["/private\"source\\leaf:/data:ro,Z"],"NetworkMode":"edge_net-1"},"NetworkingConfig":{"EndpointsConfig":{"edge_net-1":{}}}}}],"prerequisites":[{"kind":"network","reference":"1","identity":"edge_net-1","expected_driver":"bridge"},{"kind":"bind_source","reference":"2","identity":"app.fixture-1","mount_index":"0","source":"/private\"source\\leaf","target":"/data","read_only":true,"relabel":"private","source_conditions":["exists","type_reviewed","contents_reviewed","ownership_reviewed","permissions_reviewed"],"selinux_effect":"unverified","selinux_conditions":["daemon_selinux_enabled","container_mount_label_present","policy_filesystem_support","relabel_authority"]}]}
"#);
}

#[test]
fn explicit_false_and_true_require_the_distinct_external_capability() {
    for expectation in [Some(false), Some(true)] {
        let intent =
            TargetIntent::new(vec![external(1, b"private-network-canary", expectation)]).unwrap();
        for state in [
            None,
            Some(CapabilityState::Unknown),
            Some(CapabilityState::Unavailable),
        ] {
            let mut daemon = facts(
                41,
                DaemonMode::Rootful,
                &[
                    Capability::NetworkExternalReference,
                    Capability::NetworkInternal,
                ],
            );
            if let Some(state) = state {
                daemon.capabilities.push(CapabilityFact {
                    capability: Capability::NetworkExternalInternalExpectation,
                    state,
                    provenance: if state == CapabilityState::Unknown {
                        FactProvenance::Unknown
                    } else {
                        FactProvenance::NativeConformance
                    },
                    scope: if state == CapabilityState::Unknown {
                        None
                    } else {
                        Some(CapabilityScope {
                            observation_id: daemon.observation_id,
                            release: daemon.release.clone().unwrap(),
                            api_version: daemon.api_version.unwrap(),
                            mode: daemon.mode,
                        })
                    },
                });
            }
            let validated = ValidatedCapabilities::new(&daemon).unwrap();
            let error = DockerPlanner.plan(&intent, &validated).unwrap_err();
            assert_eq!(
                error,
                PlanningError::MissingCapability {
                    resource: ResourceRef::new(1),
                    field: TargetField::NetworkExternalInternalExpectation,
                    capability: Capability::NetworkExternalInternalExpectation,
                }
            );
            assert!(!format!("{error:?}").contains("canary"));
        }
        let daemon = facts(
            56,
            DaemonMode::Rootless,
            &[Capability::NetworkExternalInternalExpectation],
        );
        let validated = ValidatedCapabilities::new(&daemon).unwrap();
        assert!(matches!(
            DockerPlanner.plan(&intent, &validated),
            Err(PlanningError::MissingCapability {
                capability: Capability::NetworkExternalReference,
                ..
            })
        ));
    }
}

#[test]
fn version_and_unknown_daemon_mode_boundaries_are_not_bypassed() {
    let intent = TargetIntent::new(vec![external(1, b"edge", Some(false))]).unwrap();
    let old = facts(40, DaemonMode::Rootful, CAPABILITIES);
    let validated = ValidatedCapabilities::new(&old).unwrap();
    assert!(matches!(
        DockerPlanner.plan(&intent, &validated),
        Err(PlanningError::UnsupportedApi { .. })
    ));
    assert!(ValidatedCapabilities::new(&facts(41, DaemonMode::Unknown, CAPABILITIES)).is_err());
}

#[test]
fn mixed_external_expectations_keep_false_true_and_absent_distinct() {
    let intent = TargetIntent::new(vec![
        external(1, b"ordinary", Some(false)),
        external(2, b"internal", Some(true)),
        external(3, b"unconstrained", None),
    ])
    .unwrap();
    let artifact = render(&intent, 56, DaemonMode::Rootless);
    assert!(artifact.bytes().is_empty());
    let document: Value = serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
    assert_eq!(document["schema_version"], 3);
    assert_eq!(document["prerequisites"][0]["expected_internal"], false);
    assert_eq!(document["prerequisites"][1]["expected_internal"], true);
    assert!(
        document["prerequisites"][2]
            .get("expected_internal")
            .is_none()
    );
}

#[test]
fn future_test_local_admission_requires_both_external_shapes() {
    let capability = Capability::NetworkExternalInternalExpectation;
    let required = NativeCapabilityShape::required_for(capability).unwrap();
    assert_eq!(
        required,
        &[
            NativeCapabilityShape::ExternalNetworkInternalFalse,
            NativeCapabilityShape::ExternalNetworkInternalTrue,
        ]
    );
    for shapes in [
        vec![],
        vec![required[0]],
        vec![required[1]],
        required.to_vec(),
    ] {
        // Test-local records only. The sealed records and their selection are immutable.
        let mut record = crate::reviewed_catalog::records().remove(0);
        let profile = record.profile.clone();
        record.capabilities.push(TargetCapabilityFact {
            capability,
            state: CapabilityState::Available,
        });
        record.admitted_shapes.extend(&shapes);
        let catalog = TargetCapabilityCatalog::from_test_records(vec![record]);
        if shapes.len() == 2 {
            assert!(
                catalog
                    .unwrap()
                    .resolve(&profile)
                    .unwrap()
                    .supports(capability)
            );
        } else {
            assert!(matches!(
                catalog,
                Err(CapabilityError::IncompleteEvidenceShapes)
            ));
        }
    }
}
