//! Explicit standalone intent, capability-gated planning, and inert Engine requests.
//!
//! Nothing in this module contacts a daemon, executes a request, or writes a file.

#[path = "target_modules/container.rs"]
mod container;
#[path = "target_modules/graph.rs"]
mod graph;
#[path = "target_modules/intent.rs"]
mod intent;
#[path = "target_modules/network.rs"]
mod network;
#[path = "target_modules/render.rs"]
mod render;

pub use container::{
    Argument, ContainerIntent, EnvironmentAssignment, Healthcheck, ImageReference, Mount,
    MountSource, PortBinding, Protocol, RestartPolicy,
};
pub use graph::{
    DockerPlanner, Operation, OperationAction, OperationGraph, OperationNode, OperationStep,
    OperationStepAction, OperationStepId, Planner, PlanningCapabilitySet, PlanningContext,
    PlanningError, TargetField, TargetKind,
};
pub use intent::{IntentError, Orchestration, TargetIdentity, TargetIntent, TargetResource};
pub use network::{
    BridgeOption, NetworkAddress, NetworkAlias, NetworkAttachmentIntent, NetworkAuxAddress,
    NetworkCreate, NetworkDriver, NetworkIntent, NetworkIpam, NetworkIpamDriver, NetworkIpamPool,
    NetworkLabel, NetworkRole, NetworkSource, NetworkSubnet,
};
pub use render::{DockerApiRenderer, NetworkPrerequisite, RenderError, RenderedArtifact, Renderer};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::ResourceRef;
    use crate::version::{
        ApiVersion, CapabilityEvidenceKey, CapabilityFact, CapabilityScope, CapabilityState,
        DaemonFacts, DaemonMode, EngineRelease, FactProvenance, NativeCapabilityShape,
        NativeEvidenceLane, NativeEvidenceReference, ObservationId, TargetCapabilityCatalog,
        TargetCapabilityFact, TargetCapabilityRecord,
    };
    use crate::version::{Capability, TargetProfile, ValidatedCapabilities};
    use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

    fn facts(api_minor: u16, mode: DaemonMode, available: &[Capability]) -> DaemonFacts {
        let observation_id = ObservationId::fresh().unwrap();
        let release = EngineRelease::new("20.10.24".into()).unwrap();
        let api_version = ApiVersion::new(NonZeroU16::new(1).unwrap(), api_minor);
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

    fn bridge(reference: u64, name: &[u8]) -> TargetResource {
        TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(reference),
            identity: TargetIdentity::new(name.to_vec()).unwrap(),
            role: NetworkRole::Declared,
            source: NetworkSource::Create(NetworkCreate::bridge()),
        })
    }

    fn attachment(reference: u64) -> NetworkAttachmentIntent {
        NetworkAttachmentIntent {
            network: ResourceRef::new(reference),
            aliases: Vec::new(),
            ipv4_address: None,
            ipv6_address: None,
        }
    }

    fn complete_intent() -> TargetIntent {
        let nz16 = |value| NonZeroU16::new(value).unwrap();
        TargetIntent::new(vec![
            TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(3),
                identity: TargetIdentity::new(b"app".to_vec()).unwrap(),
                image: ImageReference::new(b"registry/app:1".to_vec()).unwrap(),
                environment: vec![
                    EnvironmentAssignment::new(b"TOKEN".to_vec(), b"secret\"\\\nvalue".to_vec())
                        .unwrap(),
                ],
                ports: vec![PortBinding {
                    host: nz16(8080),
                    container: nz16(80),
                    protocol: Protocol::Tcp,
                }],
                mounts: vec![Mount::volume(ResourceRef::new(2), b"/data".to_vec(), false).unwrap()],
                networks: vec![attachment(1)],
                entrypoint: Some(vec![Argument::new(b"/bin/app".to_vec()).unwrap()]),
                command: Some(vec![Argument::new(b"--serve".to_vec()).unwrap()]),
                healthcheck: Some(
                    Healthcheck::new(
                        vec![Argument::new(b"/bin/health".to_vec()).unwrap()],
                        NonZeroU64::new(1_000_000_000).unwrap(),
                        NonZeroU64::new(500_000_000).unwrap(),
                        NonZeroU32::new(3).unwrap(),
                    )
                    .unwrap(),
                ),
                restart: Some(RestartPolicy::OnFailure { maximum_retries: 2 }),
            })),
            TargetResource::Volume {
                reference: ResourceRef::new(2),
                identity: TargetIdentity::new(b"app_data".to_vec()).unwrap(),
            },
            bridge(1, b"app_net"),
        ])
        .unwrap()
    }

    const ALL_SETTINGS: &[Capability] = &[
        Capability::StandaloneContainer,
        Capability::NamedVolume,
        Capability::BridgeNetwork,
        Capability::PortPublish,
        Capability::EnvironmentAssignment,
        Capability::Command,
        Capability::Entrypoint,
        Capability::Healthcheck,
        Capability::RestartPolicy,
    ];

    #[test]
    fn minimal_container_request_has_exact_inert_shape() {
        let facts = facts(41, DaemonMode::Rootful, &[Capability::StandaloneContainer]);
        let capabilities = ValidatedCapabilities::new(&facts).unwrap();
        let intent =
            TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"example".to_vec()).unwrap(),
                image: ImageReference::new(b"image:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![],
                mounts: vec![],
                networks: vec![],
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: None,
            }))])
            .unwrap();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        assert_eq!(
            artifact.bytes(),
            b"{\"method\":\"POST\",\"path\":\"/v1.41/containers/create?name=example\",\"body\":{\"Image\":\"image:1\",\"HostConfig\":{}}}\n"
        );
    }

    #[test]
    fn network_seam_preserves_the_exact_inert_request() {
        let facts = facts(41, DaemonMode::Rootful, &[Capability::BridgeNetwork]);
        let capabilities = ValidatedCapabilities::new(&facts).unwrap();
        let intent = TargetIntent::new(vec![bridge(1, b"private_net")]).unwrap();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        assert_eq!(
            DockerApiRenderer.render(&graph).unwrap().bytes(),
            b"{\"method\":\"POST\",\"path\":\"/v1.41/networks/create\",\"body\":{\"Name\":\"private_net\",\"Driver\":\"bridge\"}}\n"
        );
    }

    #[test]
    fn complete_target_renders_ordered_native_requests_without_executing() {
        let facts = facts(41, DaemonMode::Rootless, ALL_SETTINGS);
        let capabilities = ValidatedCapabilities::new(&facts).unwrap();
        let intent = complete_intent();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        assert_eq!(
            graph.nodes()[0].depends_on,
            vec![ResourceRef::new(1), ResourceRef::new(2)]
        );
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        let output = std::str::from_utf8(artifact.bytes()).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("/v1.41/volumes/create"));
        assert!(lines[1].contains("/v1.41/networks/create"));
        assert!(lines[2].contains("/v1.41/containers/create?name=app"));
        assert!(lines[2].contains("\"Image\":\"registry/app:1\""));
        assert!(lines[2].contains("\"PortBindings\":{\"80/tcp\":[{\"HostPort\":\"8080\"}]"));
        assert!(lines[2].contains("\"Type\":\"volume\",\"Source\":\"app_data\""));
        assert!(lines[2].contains("\"EndpointsConfig\":{\"app_net\":{}}"));
        assert!(lines[2].contains("\"Test\":[\"CMD\",\"/bin/health\"]"));
        assert!(
            lines[2]
                .contains("\"RestartPolicy\":{\"Name\":\"on-failure\",\"MaximumRetryCount\":2}")
        );
        assert!(lines[2].contains("TOKEN=secret\\\"\\\\\\nvalue"));
        assert!(!output.contains("TOKEN=secret\"\\\nvalue"));
        for protected in ["secret", "registry/app:1", "app_net", "TOKEN"] {
            assert!(!format!("{graph:?} {artifact:?}").contains(protected));
        }
    }

    #[test]
    fn each_setting_requires_its_own_exact_capability() {
        let intent = complete_intent();
        let expected = [
            (Capability::PortPublish, TargetField::Port),
            (Capability::EnvironmentAssignment, TargetField::Environment),
            (Capability::Command, TargetField::Command),
            (Capability::Entrypoint, TargetField::Entrypoint),
            (Capability::Healthcheck, TargetField::Healthcheck),
            (Capability::RestartPolicy, TargetField::Restart),
        ];
        for (missing, field) in expected {
            let available: Vec<_> = ALL_SETTINGS
                .iter()
                .copied()
                .filter(|item| *item != missing)
                .collect();
            let facts = facts(41, DaemonMode::Rootful, &available);
            let capabilities = ValidatedCapabilities::new(&facts).unwrap();
            assert_eq!(
                DockerPlanner.plan(&intent, &capabilities).unwrap_err(),
                PlanningError::MissingCapability {
                    resource: ResourceRef::new(3),
                    field,
                    capability: missing,
                }
            );
        }
    }

    #[test]
    fn bind_mount_udp_and_empty_environment_value_are_exact() {
        let daemon = facts(
            41,
            DaemonMode::Rootful,
            &[
                Capability::StandaloneContainer,
                Capability::BindMount,
                Capability::PortPublish,
                Capability::EnvironmentAssignment,
                Capability::RestartPolicy,
            ],
        );
        let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
        let intent =
            TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"dns".to_vec()).unwrap(),
                image: ImageReference::new(b"dns:1".to_vec()).unwrap(),
                environment: vec![EnvironmentAssignment::new(b"EMPTY".to_vec(), vec![]).unwrap()],
                ports: vec![PortBinding {
                    host: NonZeroU16::new(5353).unwrap(),
                    container: NonZeroU16::new(53).unwrap(),
                    protocol: Protocol::Udp,
                }],
                mounts: vec![
                    Mount::bind(b"/host/config".to_vec(), b"/etc/config".to_vec(), true).unwrap(),
                ],
                networks: vec![],
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: Some(RestartPolicy::UnlessStopped),
            }))])
            .unwrap();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        let body = std::str::from_utf8(artifact.bytes()).unwrap();
        assert!(body.contains("\"Env\":[\"EMPTY=\"]"));
        assert!(body.contains("\"53/udp\":[{\"HostPort\":\"5353\"}]"));
        assert!(body.contains("\"Type\":\"bind\",\"Source\":\"/host/config\",\"Target\":\"/etc/config\",\"ReadOnly\":true"));
        assert!(body.contains("\"Name\":\"unless-stopped\""));

        let without_bind = facts(
            41,
            DaemonMode::Rootful,
            &[
                Capability::StandaloneContainer,
                Capability::PortPublish,
                Capability::EnvironmentAssignment,
                Capability::RestartPolicy,
            ],
        );
        let unsupported = ValidatedCapabilities::new(&without_bind).unwrap();
        assert_eq!(
            DockerPlanner.plan(&intent, &unsupported).unwrap_err(),
            PlanningError::MissingCapability {
                resource: ResourceRef::new(1),
                field: TargetField::BindMount,
                capability: Capability::BindMount,
            }
        );
    }

    #[test]
    fn on_failure_zero_means_unlimited_and_overflow_is_rejected() {
        let make = |maximum_retries| {
            TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"worker".to_vec()).unwrap(),
                image: ImageReference::new(b"worker:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![],
                mounts: vec![],
                networks: vec![],
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: Some(RestartPolicy::OnFailure { maximum_retries }),
            }))])
        };
        let intent = make(0).unwrap();
        let daemon = facts(
            41,
            DaemonMode::Rootful,
            &[Capability::StandaloneContainer, Capability::RestartPolicy],
        );
        let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        assert!(
            std::str::from_utf8(artifact.bytes())
                .unwrap()
                .contains("\"RestartPolicy\":{\"Name\":\"on-failure\",\"MaximumRetryCount\":0}")
        );
        assert_eq!(
            make(i32::MAX as u32 + 1).unwrap_err(),
            IntentError::InvalidRestart
        );
    }

    #[test]
    fn target_api_version_and_dependencies_fail_closed() {
        let intent = complete_intent();
        let old = facts(40, DaemonMode::Rootless, ALL_SETTINGS);
        let capabilities = ValidatedCapabilities::new(&old).unwrap();
        assert_eq!(
            DockerPlanner.plan(&intent, &capabilities).unwrap_err(),
            PlanningError::UnsupportedApi {
                actual: ApiVersion::new(NonZeroU16::new(1).unwrap(), 40),
                minimum: ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            }
        );
        let current = facts(41, DaemonMode::Rootless, ALL_SETTINGS);
        let capabilities = ValidatedCapabilities::new(&current).unwrap();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        let mut nodes = graph.nodes().to_vec();
        nodes[0].depends_on.pop();
        assert_eq!(
            OperationGraph::new(&intent, &capabilities, nodes).unwrap_err(),
            PlanningError::DependencyMismatch {
                resource: ResourceRef::new(3),
                dependency: ResourceRef::new(2),
                expected: TargetKind::Volume,
            }
        );
        let missing =
            TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(3),
                identity: TargetIdentity::new(b"app".to_vec()).unwrap(),
                image: ImageReference::new(b"image:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![],
                mounts: vec![
                    Mount::volume(ResourceRef::new(99), b"/data".to_vec(), false).unwrap(),
                ],
                networks: vec![],
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: None,
            }))])
            .unwrap();
        assert_eq!(
            DockerPlanner.plan(&missing, &capabilities).unwrap_err(),
            PlanningError::InvalidDependency
        );
    }

    #[test]
    fn rootless_low_host_port_is_rejected_even_with_generic_publish_claim() {
        let facts = facts(
            41,
            DaemonMode::Rootless,
            &[Capability::StandaloneContainer, Capability::PortPublish],
        );
        let capabilities = ValidatedCapabilities::new(&facts).unwrap();
        let intent =
            TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(4),
                identity: TargetIdentity::new(b"web".to_vec()).unwrap(),
                image: ImageReference::new(b"web:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![PortBinding {
                    host: NonZeroU16::new(987).unwrap(),
                    container: NonZeroU16::new(80).unwrap(),
                    protocol: Protocol::Tcp,
                }],
                mounts: vec![],
                networks: vec![],
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: None,
            }))])
            .unwrap();
        let error = DockerPlanner.plan(&intent, &capabilities).unwrap_err();
        assert_eq!(
            error,
            PlanningError::RestrictedPort {
                resource: ResourceRef::new(4),
                mode: DaemonMode::Rootless,
            }
        );
        assert!(!format!("{error:?}").contains("987"));
    }

    #[test]
    fn invalid_target_values_are_rejected_without_echoing_them() {
        assert_eq!(
            TargetIdentity::new(b"-flag".to_vec()).unwrap_err(),
            IntentError::InvalidIdentity
        );
        assert_eq!(
            Argument::new(b"bad\0argument".to_vec()).unwrap_err(),
            IntentError::InvalidArgument
        );
        assert_eq!(
            Mount::bind(b"relative".to_vec(), b"/target".to_vec(), false).unwrap_err(),
            IntentError::InvalidMount
        );
        assert_eq!(
            Healthcheck::new(
                vec![],
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(1).unwrap(),
                NonZeroU32::new(1).unwrap()
            )
            .unwrap_err(),
            IntentError::InvalidHealthcheck
        );
        assert_eq!(
            Healthcheck::new(
                vec![Argument::new(b"health".to_vec()).unwrap()],
                NonZeroU64::new(i64::MAX as u64 + 1).unwrap(),
                NonZeroU64::new(1_000_000).unwrap(),
                NonZeroU32::new(1).unwrap()
            )
            .unwrap_err(),
            IntentError::InvalidHealthcheck
        );
        assert_eq!(
            Healthcheck::new(
                vec![Argument::new(b"health".to_vec()).unwrap()],
                NonZeroU64::new(999_999).unwrap(),
                NonZeroU64::new(1_000_000).unwrap(),
                NonZeroU32::new(1).unwrap()
            )
            .unwrap_err(),
            IntentError::InvalidHealthcheck
        );
        assert_eq!(
            Healthcheck::new(
                vec![Argument::new(Vec::new()).unwrap()],
                NonZeroU64::new(1_000_000).unwrap(),
                NonZeroU64::new(1_000_000).unwrap(),
                NonZeroU32::new(1).unwrap()
            )
            .unwrap_err(),
            IntentError::InvalidHealthcheck
        );
        assert_eq!(
            Healthcheck::new(
                vec![Argument::new(b"health".to_vec()).unwrap()],
                NonZeroU64::new(1_000_000).unwrap(),
                NonZeroU64::new(999_999).unwrap(),
                NonZeroU32::new(1).unwrap()
            )
            .unwrap_err(),
            IntentError::InvalidHealthcheck
        );
    }

    #[test]
    fn target_intent_is_explicit_and_sensitive_data_stays_out_of_debug() {
        let container = ContainerIntent {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"private-app".to_vec()).unwrap(),
            image: ImageReference::new(b"private-registry/app:1".to_vec()).unwrap(),
            environment: vec![
                EnvironmentAssignment::new(b"PASSWORD".to_vec(), b"private-secret".to_vec())
                    .unwrap(),
            ],
            ports: vec![],
            mounts: vec![],
            networks: vec![],
            entrypoint: None,
            command: None,
            healthcheck: None,
            restart: None,
        };
        let intent =
            TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
        let debug = format!("{intent:?}");
        for sensitive in [
            "private-app",
            "private-registry",
            "PASSWORD",
            "private-secret",
        ] {
            assert!(!debug.contains(sensitive));
        }
        assert_eq!(intent.resources().len(), 1);
    }

    #[test]
    fn malformed_and_duplicate_intent_is_rejected() {
        assert_eq!(
            TargetIntent::new_with_orchestration(vec![], Orchestration::Swarm).unwrap_err(),
            IntentError::UnsupportedOrchestration
        );
        assert_eq!(TargetIntent::new(vec![]).unwrap_err(), IntentError::Empty);
        assert_eq!(
            EnvironmentAssignment::new(b"A=B".to_vec(), vec![]).unwrap_err(),
            IntentError::InvalidEnvironment
        );
        let make = || bridge(7, b"network");
        assert_eq!(
            TargetIntent::new(vec![make(), make()]).unwrap_err(),
            IntentError::DuplicateResource
        );
        assert_eq!(
            TargetIntent::new(vec![
                TargetResource::Volume {
                    reference: ResourceRef::new(1),
                    identity: TargetIdentity::new(b"shared".to_vec()).unwrap(),
                },
                TargetResource::Volume {
                    reference: ResourceRef::new(2),
                    identity: TargetIdentity::new(b"shared".to_vec()).unwrap(),
                },
            ])
            .unwrap_err(),
            IntentError::DuplicateResource
        );
    }

    #[test]
    fn operation_graph_rejects_missing_dependencies_and_cycles() {
        let mut daemon = DaemonFacts {
            observation_id: ObservationId::fresh().unwrap(),
            release: EngineRelease::new("20.10.24".into()),
            api_version: Some(ApiVersion::new(NonZeroU16::new(1).unwrap(), 41)),
            minimum_api_version: None,
            mode: DaemonMode::Rootless,
            capabilities: vec![],
        };
        // Fabricated test facts exercise graph checks; they are not native evidence.
        let scope = CapabilityScope {
            observation_id: daemon.observation_id,
            release: daemon.release.clone().unwrap(),
            api_version: daemon.api_version.unwrap(),
            mode: daemon.mode,
        };
        for capability in [
            Capability::BridgeNetwork,
            Capability::NamedVolume,
            Capability::StandaloneContainer,
        ] {
            daemon.capabilities.push(CapabilityFact {
                capability,
                state: CapabilityState::Available,
                provenance: FactProvenance::NativeConformance,
                scope: Some(scope.clone()),
            });
        }
        let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
        let intent = TargetIntent::new(vec![
            bridge(1, b"network"),
            TargetResource::Volume {
                reference: ResourceRef::new(2),
                identity: TargetIdentity::new(b"volume".to_vec()).unwrap(),
            },
            TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(3),
                identity: TargetIdentity::new(b"container".to_vec()).unwrap(),
                image: ImageReference::new(b"image:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![],
                mounts: vec![],
                networks: vec![],
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: None,
            })),
        ])
        .unwrap();
        let node = |reference: u64, kind: TargetKind, depends_on: Vec<u64>| OperationNode {
            operation: Operation {
                resource: ResourceRef::new(reference),
                kind,
                action: OperationAction::Create,
            },
            depends_on: depends_on.into_iter().map(ResourceRef::new).collect(),
        };
        let network = || node(1, TargetKind::Network, vec![]);
        let volume = || node(2, TargetKind::Volume, vec![]);
        let container = || node(3, TargetKind::Container, vec![1, 2]);
        assert!(matches!(
            OperationGraph::new(&intent, &capabilities, vec![network(), volume()]),
            Err(PlanningError::InvalidDependency)
        ));
        assert!(matches!(
            OperationGraph::new(
                &intent,
                &capabilities,
                vec![
                    node(1, TargetKind::Container, vec![]),
                    volume(),
                    container()
                ]
            ),
            Err(PlanningError::InvalidDependency)
        ));
        assert!(matches!(
            OperationGraph::new(
                &intent,
                &capabilities,
                vec![node(1, TargetKind::Network, vec![3]), volume(), container()]
            ),
            Err(PlanningError::Cycle)
        ));
        let graph = OperationGraph::new(
            &intent,
            &capabilities,
            vec![network(), volume(), container()],
        )
        .unwrap();
        assert_eq!(graph.nodes().len(), 3);
        assert!(std::ptr::eq(graph.intent(), &intent));
        assert!(matches!(graph.context(), PlanningContext::Observed(_)));
        let all_facts = daemon.capabilities.clone();
        for missing in [
            Capability::BridgeNetwork,
            Capability::NamedVolume,
            Capability::StandaloneContainer,
        ] {
            daemon.capabilities = all_facts
                .iter()
                .filter(|fact| fact.capability != missing)
                .cloned()
                .collect();
            let incomplete = ValidatedCapabilities::new(&daemon).unwrap();
            assert!(matches!(
                OperationGraph::new(&intent, &incomplete, vec![network(), volume(), container()]),
                Err(PlanningError::MissingCapability { .. })
            ));
        }
    }

    #[test]
    fn offline_target_context_is_retained_without_live_observation() {
        let api = ApiVersion::new(NonZeroU16::new(1).unwrap(), 41);
        let identity = crate::version::TargetProfileIdentity::new(
            crate::version::EngineBuild::Upstream,
            EngineRelease::new("29.8.1".into()).unwrap(),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 50),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 49),
            api,
            DaemonMode::Rootless,
        )
        .unwrap();
        let profile = TargetProfile::new(identity, CapabilityEvidenceKey::sha256([7; 32]).unwrap());
        // Fabricated test record; the production catalog admits only reviewed records.
        let catalog = TargetCapabilityCatalog::from_test_records(vec![TargetCapabilityRecord {
            profile: profile.clone(),
            evidence: NativeEvidenceReference::new(
                NativeEvidenceLane::UpstreamRootless,
                "https://github.com/Strukturpiloten/docker-lens/actions/runs/123/attempts/1".into(),
                "0123456789abcdef0123456789abcdef01234567".into(),
                NativeEvidenceLane::UpstreamRootless.artifact_name().into(),
                profile.evidence_key().clone(),
                profile.evidence_key().clone(),
            )
            .unwrap(),
            capabilities: vec![TargetCapabilityFact {
                capability: Capability::NamedVolume,
                state: CapabilityState::Available,
            }],
            admitted_shapes: NativeCapabilityShape::required_for(Capability::NamedVolume)
                .unwrap()
                .to_vec(),
        }])
        .unwrap();
        let capabilities = catalog.resolve(&profile).unwrap();
        assert!(PlanningCapabilitySet::supports(
            &capabilities,
            Capability::NamedVolume
        ));
        let intent = TargetIntent::new(vec![TargetResource::Volume {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"private-volume".to_vec()).unwrap(),
        }])
        .unwrap();
        let graph = OperationGraph::new(
            &intent,
            &capabilities,
            vec![OperationNode {
                operation: Operation {
                    resource: ResourceRef::new(1),
                    kind: TargetKind::Volume,
                    action: OperationAction::Create,
                },
                depends_on: vec![],
            }],
        )
        .unwrap();
        assert_eq!(graph.context(), &PlanningContext::Target(profile));
        assert!(!format!("{graph:?}").contains("private-volume"));
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        let requests = std::str::from_utf8(artifact.bytes()).unwrap();
        assert!(requests.contains("/v1.41/volumes/create"));
        assert!(!requests.contains("/v1.49/"));
    }

    fn expanded_network_intent() -> TargetIntent {
        let v4 = NetworkSubnet::new(NetworkAddress::new("10.25.0.0").unwrap(), 24).unwrap();
        let v6 = NetworkSubnet::new(NetworkAddress::new("fd00:25::").unwrap(), 64).unwrap();
        let mut create = NetworkCreate::bridge();
        create.internal = true;
        create.enable_ipv6 = true;
        create.ipam = Some(NetworkIpam {
            driver: Some(NetworkIpamDriver::Default),
            pools: vec![
                NetworkIpamPool {
                    subnet: v4,
                    gateway: Some(NetworkAddress::new("10.25.0.1").unwrap()),
                    ip_range: Some(
                        NetworkSubnet::new(NetworkAddress::new("10.25.0.128").unwrap(), 25)
                            .unwrap(),
                    ),
                    auxiliary_addresses: vec![NetworkAuxAddress {
                        name: NetworkAlias::new(b"gateway".to_vec()).unwrap(),
                        address: NetworkAddress::new("10.25.0.2").unwrap(),
                    }],
                },
                NetworkIpamPool {
                    subnet: v6,
                    gateway: None,
                    ip_range: None,
                    auxiliary_addresses: vec![],
                },
            ],
        });
        create.options = vec![
            BridgeOption::Mtu(NonZeroU32::new(1400).unwrap()),
            BridgeOption::InterContainerCommunication(false),
            BridgeOption::IpMasquerade(false),
            BridgeOption::HostBindingIp(NetworkAddress::new("127.0.0.1").unwrap()),
        ];
        create.labels =
            vec![NetworkLabel::new(b"owner".to_vec(), b"application".to_vec()).unwrap()];
        TargetIntent::new(vec![
            TargetResource::Network(NetworkIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"private_net".to_vec()).unwrap(),
                role: NetworkRole::ApplicationDefault,
                source: NetworkSource::Create(create),
            }),
            TargetResource::Network(NetworkIntent {
                reference: ResourceRef::new(2),
                identity: TargetIdentity::new(b"edge".to_vec()).unwrap(),
                role: NetworkRole::Declared,
                source: NetworkSource::External {
                    expected_driver: NetworkDriver::Bridge,
                },
            }),
            TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(3),
                identity: TargetIdentity::new(b"app".to_vec()).unwrap(),
                image: ImageReference::new(b"image:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![],
                mounts: vec![],
                networks: vec![
                    NetworkAttachmentIntent {
                        network: ResourceRef::new(1),
                        aliases: vec![NetworkAlias::new(b"private-app".to_vec()).unwrap()],
                        ipv4_address: Some(NetworkAddress::new("10.25.0.10").unwrap()),
                        ipv6_address: None,
                    },
                    NetworkAttachmentIntent {
                        network: ResourceRef::new(2),
                        aliases: vec![NetworkAlias::new(b"edge-app".to_vec()).unwrap()],
                        ipv4_address: None,
                        ipv6_address: None,
                    },
                ],
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: None,
            })),
        ])
        .unwrap()
    }

    const EXPANDED_NETWORK_CAPABILITIES: &[Capability] = &[
        Capability::BridgeNetwork,
        Capability::StandaloneContainer,
        Capability::NetworkExternalReference,
        Capability::NetworkInternal,
        Capability::NetworkIpv6,
        Capability::NetworkIpam,
        Capability::NetworkIpamDriver,
        Capability::NetworkOptions,
        Capability::NetworkLabels,
        Capability::NetworkAliases,
        Capability::NetworkStaticAddress,
        Capability::NetworkMultipleAttachment,
    ];

    fn static_container(
        reference: u64,
        name: &[u8],
        network: u64,
        address: &str,
    ) -> TargetResource {
        TargetResource::Container(Box::new(ContainerIntent {
            reference: ResourceRef::new(reference),
            identity: TargetIdentity::new(name.to_vec()).unwrap(),
            image: ImageReference::new(b"image:1".to_vec()).unwrap(),
            environment: vec![],
            ports: vec![],
            mounts: vec![],
            networks: vec![NetworkAttachmentIntent {
                network: ResourceRef::new(network),
                aliases: vec![],
                ipv4_address: Some(NetworkAddress::new(address).unwrap()),
                ipv6_address: None,
            }],
            entrypoint: None,
            command: None,
            healthcheck: None,
            restart: None,
        }))
    }

    #[test]
    fn typed_topology_renders_create_then_connect_and_retains_external_prerequisite() {
        let intent = expanded_network_intent();
        let daemon = facts(41, DaemonMode::Rootful, EXPANDED_NETWORK_CAPABILITIES);
        let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        assert_eq!(graph.steps().len(), 4);
        assert_eq!(
            graph.steps()[1].action,
            OperationStepAction::RequireExisting(TargetKind::Network)
        );
        assert_eq!(
            graph.steps()[3].action,
            OperationStepAction::ConnectNetwork {
                network: ResourceRef::new(2),
                attachment_index: 1,
            }
        );
        assert_eq!(graph.steps()[3].id.ordinal, 1);
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        let lines: Vec<_> = std::str::from_utf8(artifact.bytes())
            .unwrap()
            .lines()
            .collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("/v1.41/networks/create"));
        assert!(lines[0].contains("\"Internal\":true,\"EnableIPv6\":true"));
        assert!(lines[0].contains("\"Subnet\":\"10.25.0.0/24\""));
        assert!(lines[0].contains("\"IPAM\":{\"Driver\":\"default\""));
        assert!(lines[0].contains("\"IPRange\":\"10.25.0.128/25\""));
        assert!(lines[0].contains("com.docker.network.driver.mtu"));
        assert!(lines[0].contains("\"Labels\":{\"owner\":\"application\"}"));
        assert!(lines[1].contains("/v1.41/containers/create?name=app"));
        assert!(lines[1].contains("\"Aliases\":[\"private-app\"]"));
        assert!(lines[1].contains("\"IPv4Address\":\"10.25.0.10\""));
        assert!(lines[2].contains("/v1.41/networks/edge/connect"));
        assert!(lines[2].contains("\"Container\":\"app\""));
        assert!(lines[2].contains("\"Aliases\":[\"edge-app\"]"));
        assert_eq!(artifact.network_prerequisites().len(), 1);
        assert_eq!(
            artifact.network_prerequisites()[0].reference,
            ResourceRef::new(2)
        );
        assert_eq!(artifact.network_prerequisites()[0].identity(), b"edge");
        assert_eq!(
            artifact.network_prerequisites()[0].expected_driver,
            NetworkDriver::Bridge
        );
        for protected in [
            "private_net",
            "private-app",
            "edge-app",
            "edge",
            "10.25.0.0",
            "10.25.0.1",
            "10.25.0.2",
            "10.25.0.10",
            "fd00:25::",
            "127.0.0.1",
            "owner",
            "application",
        ] {
            assert!(
                !format!(
                    "{intent:?} {graph:?} {artifact:?} {:?}",
                    artifact.network_prerequisites()
                )
                .contains(protected)
            );
        }
        assert_eq!(
            format!("{:?}", NetworkAddress::new("10.25.0.1").unwrap()),
            "NetworkAddress([redacted])"
        );
        assert_eq!(
            format!(
                "{:?}",
                NetworkSubnet::new(NetworkAddress::new("10.25.0.0").unwrap(), 24).unwrap()
            ),
            "NetworkSubnet([redacted])"
        );
    }

    #[test]
    fn network_intent_rejects_invalid_or_unsupported_topology() {
        assert_eq!(
            NetworkAlias::new(vec![]).unwrap_err(),
            IntentError::InvalidNetworkAlias
        );
        let invalid_alias = NetworkAlias::new(b"private/secret".to_vec()).unwrap_err();
        assert!(!format!("{invalid_alias:?}").contains("private/secret"));
        assert_eq!(
            NetworkSubnet::new(NetworkAddress::new("10.25.0.1").unwrap(), 24).unwrap_err(),
            IntentError::InvalidNetworkSubnet
        );
        let unsupported = TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"host".to_vec()).unwrap(),
            role: NetworkRole::Declared,
            source: NetworkSource::Create(NetworkCreate {
                driver: NetworkDriver::Host,
                ..NetworkCreate::bridge()
            }),
        });
        assert_eq!(
            TargetIntent::new(vec![unsupported]).unwrap_err(),
            IntentError::InvalidNetworkDriver
        );
        let nonbridge_external = TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"edge".to_vec()).unwrap(),
            role: NetworkRole::Declared,
            source: NetworkSource::External {
                expected_driver: NetworkDriver::Overlay,
            },
        });
        assert_eq!(
            TargetIntent::new(vec![nonbridge_external]).unwrap_err(),
            IntentError::InvalidNetworkDriver
        );
        let default_network = |reference, name: &[u8]| {
            TargetResource::Network(NetworkIntent {
                reference: ResourceRef::new(reference),
                identity: TargetIdentity::new(name.to_vec()).unwrap(),
                role: NetworkRole::ApplicationDefault,
                source: NetworkSource::External {
                    expected_driver: NetworkDriver::Bridge,
                },
            })
        };
        assert_eq!(
            TargetIntent::new(vec![
                default_network(1, b"first"),
                default_network(2, b"second"),
            ])
            .unwrap_err(),
            IntentError::DuplicateDefaultNetwork
        );
        let invalid_ipam = TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"private".to_vec()).unwrap(),
            role: NetworkRole::Declared,
            source: NetworkSource::Create(NetworkCreate {
                ipam: Some(NetworkIpam {
                    driver: None,
                    pools: vec![],
                }),
                ..NetworkCreate::bridge()
            }),
        });
        assert_eq!(
            TargetIntent::new(vec![invalid_ipam]).unwrap_err(),
            IntentError::InvalidNetworkIpam
        );
        let pool = NetworkIpamPool {
            subnet: NetworkSubnet::new(NetworkAddress::new("10.25.0.0").unwrap(), 24).unwrap(),
            gateway: Some(NetworkAddress::new("10.25.0.1").unwrap()),
            ip_range: None,
            auxiliary_addresses: vec![],
        };
        let overlap = NetworkIpamPool {
            subnet: NetworkSubnet::new(NetworkAddress::new("10.25.0.128").unwrap(), 25).unwrap(),
            gateway: None,
            ip_range: None,
            auxiliary_addresses: vec![],
        };
        let network_with = |pools| {
            TargetResource::Network(NetworkIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"private".to_vec()).unwrap(),
                role: NetworkRole::Declared,
                source: NetworkSource::Create(NetworkCreate {
                    ipam: Some(NetworkIpam {
                        driver: None,
                        pools,
                    }),
                    ..NetworkCreate::bridge()
                }),
            })
        };
        assert_eq!(
            TargetIntent::new(vec![network_with(vec![pool, overlap])]).unwrap_err(),
            IntentError::InvalidNetworkIpam
        );
        let pool = NetworkIpamPool {
            subnet: NetworkSubnet::new(NetworkAddress::new("10.25.0.0").unwrap(), 24).unwrap(),
            gateway: Some(NetworkAddress::new("10.25.0.1").unwrap()),
            ip_range: None,
            auxiliary_addresses: vec![NetworkAuxAddress {
                name: NetworkAlias::new(b"reserved".to_vec()).unwrap(),
                address: NetworkAddress::new("10.25.0.1").unwrap(),
            }],
        };
        assert_eq!(
            TargetIntent::new(vec![network_with(vec![pool])]).unwrap_err(),
            IntentError::InvalidNetworkIpam
        );
        let pool = NetworkIpamPool {
            subnet: NetworkSubnet::new(NetworkAddress::new("10.25.0.0").unwrap(), 24).unwrap(),
            gateway: Some(NetworkAddress::new("10.25.0.1").unwrap()),
            ip_range: None,
            auxiliary_addresses: vec![],
        };
        assert_eq!(
            TargetIntent::new(vec![
                network_with(vec![pool]),
                static_container(2, b"first", 1, "10.25.0.10"),
                static_container(3, b"second", 1, "10.25.0.10"),
            ])
            .unwrap_err(),
            IntentError::DuplicateNetworkAddress
        );
        let external = TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"edge".to_vec()).unwrap(),
            role: NetworkRole::Declared,
            source: NetworkSource::External {
                expected_driver: NetworkDriver::Bridge,
            },
        });
        assert_eq!(
            TargetIntent::new(vec![external, static_container(2, b"app", 1, "10.25.0.10"),])
                .unwrap_err(),
            IntentError::InvalidNetworkAttachment
        );
        let duplicate = TargetResource::Container(Box::new(ContainerIntent {
            reference: ResourceRef::new(3),
            identity: TargetIdentity::new(b"app".to_vec()).unwrap(),
            image: ImageReference::new(b"image:1".to_vec()).unwrap(),
            environment: vec![],
            ports: vec![],
            mounts: vec![],
            networks: vec![attachment(1), attachment(1)],
            entrypoint: None,
            command: None,
            healthcheck: None,
            restart: None,
        }));
        assert_eq!(
            TargetIntent::new(vec![duplicate]).unwrap_err(),
            IntentError::DuplicateNetworkAttachment
        );
    }

    #[test]
    fn ipv4_pool_slots_are_checked_for_gateways_auxiliary_and_static_addresses() {
        let subnet = NetworkSubnet::new(NetworkAddress::new("10.25.0.0").unwrap(), 24).unwrap();
        let network = |gateway, auxiliary_addresses| {
            TargetResource::Network(NetworkIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"private".to_vec()).unwrap(),
                role: NetworkRole::Declared,
                source: NetworkSource::Create(NetworkCreate {
                    ipam: Some(NetworkIpam {
                        driver: None,
                        pools: vec![NetworkIpamPool {
                            subnet,
                            gateway,
                            ip_range: None,
                            auxiliary_addresses,
                        }],
                    }),
                    ..NetworkCreate::bridge()
                }),
            })
        };
        for address in ["10.25.0.0", "10.25.0.255"] {
            let address = NetworkAddress::new(address).unwrap();
            assert_eq!(
                TargetIntent::new(vec![network(Some(address), vec![])]).unwrap_err(),
                IntentError::InvalidNetworkIpam
            );
            assert_eq!(
                TargetIntent::new(vec![network(
                    None,
                    vec![NetworkAuxAddress {
                        name: NetworkAlias::new(b"reserved".to_vec()).unwrap(),
                        address,
                    }],
                )])
                .unwrap_err(),
                IntentError::InvalidNetworkIpam
            );
            assert_eq!(
                TargetIntent::new(vec![
                    network(None, vec![]),
                    static_container(2, b"app", 1, &address.value().to_string()),
                ])
                .unwrap_err(),
                IntentError::InvalidNetworkAttachment
            );
        }
    }

    #[test]
    fn narrow_ipv4_subnets_keep_their_host_slots_without_native_admission() {
        let daemon = facts(
            41,
            DaemonMode::Rootful,
            &[Capability::BridgeNetwork, Capability::NetworkIpam],
        );
        let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
        for (base, prefix, addresses) in [
            ("10.25.0.0", 31, ["10.25.0.0", "10.25.0.1"]),
            ("10.25.0.7", 32, ["10.25.0.7", "10.25.0.7"]),
        ] {
            let subnet = NetworkSubnet::new(NetworkAddress::new(base).unwrap(), prefix).unwrap();
            for address in addresses {
                assert!(subnet.contains_usable_host(NetworkAddress::new(address).unwrap()));
            }
            let intent = TargetIntent::new(vec![TargetResource::Network(NetworkIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"private".to_vec()).unwrap(),
                role: NetworkRole::Declared,
                source: NetworkSource::Create(NetworkCreate {
                    ipam: Some(NetworkIpam {
                        driver: None,
                        pools: vec![NetworkIpamPool {
                            subnet,
                            gateway: None,
                            ip_range: None,
                            auxiliary_addresses: vec![],
                        }],
                    }),
                    ..NetworkCreate::bridge()
                }),
            })])
            .unwrap();
            assert_eq!(
                DockerPlanner.plan(&intent, &capabilities).unwrap_err(),
                PlanningError::UnsupportedNetworkIpam {
                    resource: ResourceRef::new(1),
                }
            );
        }
        for prefix in [31, 32] {
            let intent = TargetIntent::new(vec![TargetResource::Network(NetworkIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"private".to_vec()).unwrap(),
                role: NetworkRole::Declared,
                source: NetworkSource::Create(NetworkCreate {
                    ipam: Some(NetworkIpam {
                        driver: None,
                        pools: vec![NetworkIpamPool {
                            subnet: NetworkSubnet::new(
                                NetworkAddress::new("10.25.0.0").unwrap(),
                                24,
                            )
                            .unwrap(),
                            gateway: None,
                            ip_range: Some(
                                NetworkSubnet::new(
                                    NetworkAddress::new("10.25.0.10").unwrap(),
                                    prefix,
                                )
                                .unwrap(),
                            ),
                            auxiliary_addresses: vec![],
                        }],
                    }),
                    ..NetworkCreate::bridge()
                }),
            })])
            .unwrap();
            assert!(DockerPlanner.plan(&intent, &capabilities).is_ok());
        }
        let ordinary = NetworkSubnet::new(NetworkAddress::new("10.25.0.0").unwrap(), 24).unwrap();
        assert!(!ordinary.contains_usable_host(NetworkAddress::new("10.25.0.0").unwrap()));
        assert!(!ordinary.contains_usable_host(NetworkAddress::new("10.25.0.255").unwrap()));
        assert!(ordinary.contains_usable_host(NetworkAddress::new("10.25.0.1").unwrap()));
    }

    #[test]
    fn network_capabilities_and_api_boundaries_fail_closed() {
        let intent = expanded_network_intent();
        for (missing, resource, field) in [
            (Capability::NetworkInternal, 1, TargetField::NetworkInternal),
            (Capability::NetworkIpv6, 1, TargetField::NetworkIpv6),
            (Capability::NetworkIpam, 1, TargetField::NetworkIpam),
            (
                Capability::NetworkIpamDriver,
                1,
                TargetField::NetworkIpamDriver,
            ),
            (Capability::NetworkOptions, 1, TargetField::NetworkOptions),
            (Capability::NetworkLabels, 1, TargetField::NetworkLabels),
            (
                Capability::NetworkExternalReference,
                2,
                TargetField::NetworkExternalReference,
            ),
            (
                Capability::NetworkMultipleAttachment,
                3,
                TargetField::NetworkMultipleAttachment,
            ),
            (Capability::NetworkAliases, 3, TargetField::NetworkAliases),
            (
                Capability::NetworkStaticAddress,
                3,
                TargetField::NetworkStaticAddress,
            ),
        ] {
            let available: Vec<_> = EXPANDED_NETWORK_CAPABILITIES
                .iter()
                .copied()
                .filter(|capability| *capability != missing)
                .collect();
            let daemon = facts(41, DaemonMode::Rootful, &available);
            let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
            assert_eq!(
                DockerPlanner.plan(&intent, &capabilities).unwrap_err(),
                PlanningError::MissingCapability {
                    resource: ResourceRef::new(resource),
                    field,
                    capability: missing,
                }
            );
        }
        let missing_multi: Vec<_> = EXPANDED_NETWORK_CAPABILITIES
            .iter()
            .copied()
            .filter(|capability| *capability != Capability::NetworkMultipleAttachment)
            .collect();
        let daemon = facts(41, DaemonMode::Rootless, &missing_multi);
        let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
        assert_eq!(
            DockerPlanner.plan(&intent, &capabilities).unwrap_err(),
            PlanningError::MissingCapability {
                resource: ResourceRef::new(3),
                field: TargetField::NetworkMultipleAttachment,
                capability: Capability::NetworkMultipleAttachment,
            }
        );
        let daemon = facts(40, DaemonMode::Rootful, EXPANDED_NETWORK_CAPABILITIES);
        let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
        assert!(matches!(
            DockerPlanner.plan(&intent, &capabilities),
            Err(PlanningError::UnsupportedApi { .. })
        ));
        let catalog = TargetCapabilityCatalog::reviewed();
        for profile in catalog.profiles() {
            let capabilities = catalog.resolve(profile).unwrap();
            assert!(!capabilities.supports(Capability::NetworkMultipleAttachment));
            assert!(!capabilities.supports(Capability::NetworkInternal));
        }
    }
}
