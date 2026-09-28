//! Explicit standalone intent, capability-gated planning, and inert Engine requests.
//!
//! Nothing in this module contacts a daemon, executes a request, or writes a file.

#[path = "target_modules/container.rs"]
mod container;
#[path = "target_modules/graph.rs"]
mod graph;
#[path = "target_modules/intent.rs"]
mod intent;
#[path = "target_modules/render.rs"]
mod render;

pub use container::{
    Argument, ContainerIntent, EnvironmentAssignment, Healthcheck, ImageReference, Mount,
    MountSource, PortBinding, Protocol, RestartPolicy,
};
pub use graph::{
    DockerPlanner, Operation, OperationGraph, OperationNode, Planner, PlanningCapabilitySet,
    PlanningContext, PlanningError, TargetField, TargetKind,
};
pub use intent::{IntentError, Orchestration, TargetIdentity, TargetIntent, TargetResource};
pub use render::{DockerApiRenderer, RenderError, RenderedArtifact, Renderer};

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
                network: Some(ResourceRef::new(1)),
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
            TargetResource::Network {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"app_net".to_vec()).unwrap(),
            },
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
                network: None,
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
        let intent = TargetIntent::new(vec![TargetResource::Network {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"private_net".to_vec()).unwrap(),
        }])
        .unwrap();
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
                network: None,
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
                network: None,
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
                network: None,
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
                network: None,
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
            network: None,
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
        let make = || TargetResource::Network {
            reference: ResourceRef::new(7),
            identity: TargetIdentity::new(b"network".to_vec()).unwrap(),
        };
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
            TargetResource::Network {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"network".to_vec()).unwrap(),
            },
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
                network: None,
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
}
