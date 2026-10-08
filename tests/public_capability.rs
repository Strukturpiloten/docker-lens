//! An external consumer can discover reviewed profiles but cannot supply
//! positive capability claims without a matching catalog record.

use docker_lens::observation::ResourceRef;
use docker_lens::target::{
    Argument, BindRelabel, ContainerIntent, ContainerLabel, ContainerSettings, ContainerUser,
    DockerApiRenderer, DockerPlanner, HealthTest, Healthcheck, HostBinding, ImageCommand,
    ImageReference, IntentError, Mount, NetworkAlias, NetworkAttachmentIntent, NetworkCreate,
    NetworkDriver, NetworkIntent, NetworkLabel, NetworkRole, NetworkSource, Planner,
    PlanningContext, PlanningError, PortHostIp, PortHostPort, PortPublication, Protocol, Renderer,
    TargetField, TargetIdentity, TargetIntent, TargetResource, UserNamespaceMode, VolumeLabel,
    WorkingDirectory,
};
use docker_lens::version::{
    ApiVersion, Capability, CapabilityError, CapabilityEvidenceKey, DaemonMode,
    DebianPackageRevision, EngineBuild, EngineRelease, NativeEvidenceLane, NativeEvidenceReference,
    TargetCapabilityCatalog, TargetProfile, TargetProfileIdentity,
};
use std::num::NonZeroU16;

fn api(minor: u16) -> ApiVersion {
    ApiVersion::new(NonZeroU16::new(1).unwrap(), minor)
}

#[test]
fn exact_profiles_admit_reviewed_prerequisites_but_keep_other_groups_closed() {
    let catalog = TargetCapabilityCatalog::reviewed();
    assert_eq!(catalog.profiles().len(), 4);
    for profile in catalog.profiles() {
        let resolved = catalog.resolve(profile).unwrap();
        assert_eq!(
            resolved.evidence().candidate_sha(),
            "133f2857dac77c60aa79eab1a473c5749fd459ab"
        );
        assert_eq!(
            resolved.evidence().run_url(),
            "https://github.com/Strukturpiloten/docker-lens/actions/runs/37788762974/attempts/1"
        );
        for capability in [
            Capability::StandaloneContainer,
            Capability::NamedVolume,
            Capability::BridgeNetwork,
            Capability::PortPublish,
            Capability::BindMount,
            Capability::EnvironmentAssignment,
            Capability::Command,
            Capability::Entrypoint,
            Capability::Healthcheck,
            Capability::RestartPolicy,
            Capability::VolumeExternalReference,
            Capability::NetworkExternalReference,
            Capability::NetworkExternalInternalExpectation,
            Capability::NetworkInternal,
            Capability::VolumeLabels,
            Capability::ContainerUser,
            Capability::ContainerWorkdir,
            Capability::PortHostIpv4,
            Capability::PortMultipleBindings,
            Capability::PortExposeOnly,
            Capability::PortEphemeral,
            Capability::ContainerLabels,
            Capability::HealthShell,
            Capability::HealthStartPeriod,
            Capability::NetworkLabels,
            Capability::NetworkAliases,
            Capability::NetworkMultipleAttachment,
            Capability::BindRelabelShared,
            Capability::BindRelabelPrivate,
        ] {
            assert!(resolved.supports(capability));
        }
        for capability in [
            Capability::TmpfsMount,
            Capability::NetworkIpv6,
            Capability::NetworkIpam,
            Capability::NetworkIpamDriver,
            Capability::NetworkOptions,
            Capability::NetworkStaticAddress,
            Capability::HostNetwork,
            Capability::CommandClear,
            Capability::EntrypointClear,
            Capability::HealthDisabled,
            Capability::HealthStartInterval,
            Capability::ContainerHostname,
            Capability::SupplementaryGroups,
            Capability::ReadOnlyRootfs,
            Capability::ContainerInit,
            Capability::StopSignal,
            Capability::StopTimeout,
            Capability::MemoryLimit,
            Capability::PidsLimit,
            Capability::ShmSize,
            Capability::Ulimits,
            Capability::UlimitNofile,
            Capability::DeviceMappings,
            Capability::LinuxCapabilities,
            Capability::CapAddNetBindService,
            Capability::CapDropSysAdmin,
            Capability::SecurityOptions,
            Capability::Sysctls,
            Capability::SysctlIpv4Forward,
            Capability::DnsServers,
            Capability::ExtraHosts,
            Capability::LogConfig,
            Capability::LogOptionMaxSize,
            Capability::UserNamespace,
        ] {
            assert!(!resolved.supports(capability));
        }
        assert_eq!(
            resolved.supports(Capability::PortHostIpv6),
            matches!(profile.identity().build(), EngineBuild::Upstream)
        );
    }
}

#[test]
fn sealed_external_expectations_distinguish_absence_false_true_without_requests() {
    let catalog = TargetCapabilityCatalog::reviewed();
    for profile in catalog.profiles() {
        let capabilities = catalog.resolve(profile).unwrap();
        for expectation in [None, Some(false), Some(true)] {
            let intent = external_network_intent(expectation);
            let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
            let artifact = DockerApiRenderer.render(&graph).unwrap();
            assert!(artifact.bytes().is_empty());
            let complete: serde_json::Value =
                serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
            let mut row = serde_json::json!({
                "kind": "network", "reference": "1",
                "identity": "private-network-canary", "expected_driver": "bridge",
            });
            if let Some(internal) = expectation {
                row["expected_internal"] = internal.into();
            }
            assert_eq!(
                complete,
                serde_json::json!({
                    "schema_version": if expectation.is_some() { 3 } else { 1 },
                    "context": reviewed_prerequisite_context(profile),
                    "requests": [], "prerequisites": [row],
                })
            );
            let prerequisite = &artifact.network_prerequisites()[0];
            assert_eq!(prerequisite.expected_internal, expectation);
            for debug in [
                format!("{intent:?}"),
                format!("{graph:?}"),
                format!("{artifact:?}"),
                format!("{prerequisite:?}"),
            ] {
                assert!(!debug.contains("private-network-canary"));
            }
        }
    }
}

fn external_network_intent(expected_internal: Option<bool>) -> TargetIntent {
    TargetIntent::new(vec![TargetResource::Network(NetworkIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(b"private-network-canary".to_vec()).unwrap(),
        role: NetworkRole::Declared,
        source: NetworkSource::External {
            expected_driver: NetworkDriver::Bridge,
            expected_internal,
        },
    })])
    .unwrap()
}

fn authored_network_snapshot(internal: bool) -> docker_lens::decoder::DecodedInventory {
    use docker_lens::acquisition::{
        Budget, Limits, NativeId, ReadRequest, RootKind, SelectedRoot, SelectionReason,
    };
    use docker_lens::evidence::HttpStatus;
    let mut budget = Budget::new(Limits {
        max_requests: 1,
        max_selected_resources: 1,
        max_expansions: 1,
        max_response_bytes: 4096,
        max_total_bytes: 4096,
        max_elapsed: std::time::Duration::from_secs(2),
    })
    .unwrap();
    budget
        .record_request(
            ReadRequest::InspectNetwork(NativeId::new("a".repeat(64)).unwrap()),
            Some(ResourceRef::new(97)),
            Some(api(41)),
        )
        .unwrap();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "Id": "a".repeat(64), "Name": "private-network-canary", "Driver": "bridge", "Internal": internal,
    })).unwrap();
    budget
        .read_response(HttpStatus::new(200).unwrap(), bytes.as_slice())
        .unwrap();
    let mut inventory =
        docker_lens::decoder::decode_capture(&budget.into_capture().unwrap()).unwrap();
    // A caller-assembled snapshot is an assertion, not authenticated native proof.
    inventory.selected_roots.push(SelectedRoot {
        resource: ResourceRef::new(97),
        kind: RootKind::Network,
        reason: SelectionReason::ExactNetworkId,
    });
    inventory
}

#[test]
fn sealed_prerequisites_assess_supplied_snapshots_without_granting_native_authority() {
    use docker_lens::acquisition::NativeId;
    use docker_lens::observation::{Availability, Observed, Origin};
    use docker_lens::target::NetworkPrerequisiteError as Error;
    let id = NativeId::new("a".repeat(64)).unwrap();
    let catalog = TargetCapabilityCatalog::reviewed();
    for profile in catalog.profiles() {
        for expectation in [None, Some(false), Some(true)] {
            let intent = external_network_intent(expectation);
            let graph = DockerPlanner
                .plan(&intent, &catalog.resolve(profile).unwrap())
                .unwrap();
            let artifact = DockerApiRenderer.render(&graph).unwrap();
            let prerequisite = &artifact.network_prerequisites()[0];
            let mut snapshot = authored_network_snapshot(expectation.unwrap_or(false));
            let scope = snapshot.observation_id;
            assert_ne!(prerequisite.reference, snapshot.networks[0].reference);
            assert_eq!(prerequisite.assess(&snapshot, scope, &id), Ok(()));
            if let Some(expected) = expectation {
                snapshot.networks[0].internal =
                    Observed::present(!expected, Availability::Present, Origin::Effective);
                let error = prerequisite.assess(&snapshot, scope, &id).unwrap_err();
                assert_eq!(error, Error::NetworkInternalMismatch);
                assert!(!format!("{error:?}").contains("canary"));
            }
            snapshot.networks[0].internal =
                Observed::unavailable(Availability::Null, Origin::Effective);
            assert_eq!(
                prerequisite.assess(&snapshot, scope, &id),
                if expectation.is_some() {
                    Err(Error::InvalidNetworkInternalEvidence)
                } else {
                    Ok(())
                }
            );
            assert_eq!(
                prerequisite.assess(
                    &snapshot,
                    authored_network_snapshot(false).observation_id,
                    &id
                ),
                Err(Error::ObservationScopeMismatch)
            );
            snapshot.selected_roots.clear();
            assert_eq!(
                prerequisite.assess(&snapshot, scope, &id),
                Err(Error::SelectedRootNotFound)
            );
        }
    }
}

#[test]
fn sealed_schema_three_keeps_mixed_bind_obligations_and_schema_two_when_unconstrained() {
    for profile in TargetCapabilityCatalog::reviewed().profiles() {
        for expectation in [None, Some(false), Some(true)] {
            let mut container = application_container();
            container.mounts.push(
                Mount::bind(b"/private-source".to_vec(), b"/target".to_vec(), true)
                    .unwrap()
                    .with_bind_relabel(BindRelabel::Private)
                    .unwrap(),
            );
            let intent = TargetIntent::new(vec![
                TargetResource::Network(NetworkIntent {
                    reference: ResourceRef::new(1),
                    identity: TargetIdentity::new(b"private-network-canary".to_vec()).unwrap(),
                    role: NetworkRole::Declared,
                    source: NetworkSource::External {
                        expected_driver: NetworkDriver::Bridge,
                        expected_internal: expectation,
                    },
                }),
                TargetResource::Container(Box::new(container)),
            ])
            .unwrap();
            let complete = complete_application(profile, &intent);
            assert_eq!(
                complete["schema_version"],
                if expectation.is_some() { 3 } else { 2 }
            );
            assert_eq!(complete["requests"].as_array().unwrap().len(), 1);
            let api = if matches!(profile.identity().build(), EngineBuild::Upstream) {
                "1.56"
            } else {
                "1.41"
            };
            assert_eq!(
                complete["requests"][0]["path"],
                format!("/v{api}/containers/create?name=private-application")
            );
            let rows = complete["prerequisites"].as_array().unwrap();
            assert_eq!(rows.len(), 2);
            assert_eq!(
                rows[1],
                serde_json::json!({
                    "kind":"bind_source","reference":"3","identity":"private-application",
                    "mount_index":"0","source":"/private-source","target":"/target",
                    "read_only":true,"relabel":"private",
                    "source_conditions":["exists","type_reviewed","contents_reviewed","ownership_reviewed","permissions_reviewed"],
                    "selinux_effect":"unverified",
                    "selinux_conditions":["daemon_selinux_enabled","container_mount_label_present","policy_filesystem_support","relabel_authority"],
                })
            );
            assert_eq!(
                rows[0].get("expected_internal"),
                expectation.map(serde_json::Value::Bool).as_ref()
            );
        }
    }
}

fn application_container() -> ContainerIntent {
    ContainerIntent {
        reference: ResourceRef::new(3),
        identity: TargetIdentity::new(b"private-application".to_vec()).unwrap(),
        image: ImageReference::new(b"unverified-image:fixture".to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Inherit,
        healthcheck: None,
        restart: None,
        settings: ContainerSettings::default(),
    }
}

fn container_target(container: ContainerIntent) -> TargetIntent {
    TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap()
}

fn complete_application(profile: &TargetProfile, intent: &TargetIntent) -> serde_json::Value {
    let catalog = TargetCapabilityCatalog::reviewed();
    let resolved = catalog.resolve(profile).unwrap();
    let graph = DockerPlanner.plan(intent, &resolved).unwrap();
    let artifact = DockerApiRenderer.render(&graph).unwrap();
    let complete: serde_json::Value =
        serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
    let requests: Vec<serde_json::Value> = artifact
        .bytes()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(complete["requests"], serde_json::json!(requests));
    assert_eq!(complete["context"], reviewed_prerequisite_context(profile));
    complete
}

#[test]
fn sealed_application_ports_preserve_each_complete_common_group() {
    for profile in TargetCapabilityCatalog::reviewed().profiles() {
        let mut container = application_container();
        let host = |address: &str, port| HostBinding {
            host_ip: PortHostIp::Address(address.parse().unwrap()),
            host_port: port,
        };
        container.ports = vec![
            PortPublication::published(
                NonZeroU16::new(80).unwrap(),
                Protocol::Tcp,
                vec![
                    host(
                        "127.0.0.1",
                        PortHostPort::Fixed(NonZeroU16::new(8080).unwrap()),
                    ),
                    host(
                        "127.0.0.2",
                        PortHostPort::Fixed(NonZeroU16::new(8081).unwrap()),
                    ),
                ],
            )
            .unwrap(),
            PortPublication::published(
                NonZeroU16::new(81).unwrap(),
                Protocol::Tcp,
                vec![
                    host("127.0.0.1", PortHostPort::Ephemeral),
                    host("127.0.0.2", PortHostPort::Ephemeral),
                ],
            )
            .unwrap(),
            PortPublication::published(
                NonZeroU16::new(82).unwrap(),
                Protocol::Udp,
                vec![HostBinding {
                    host_ip: PortHostIp::Unspecified,
                    host_port: PortHostPort::Ephemeral,
                }],
            )
            .unwrap(),
            PortPublication::exposed(NonZeroU16::new(83).unwrap(), Protocol::Tcp),
        ];
        let complete = complete_application(profile, &container_target(container));
        assert_eq!(complete["schema_version"], 1);
        let body = &complete["requests"][0]["body"];
        assert_eq!(
            body["HostConfig"]["PortBindings"],
            serde_json::json!({
                "80/tcp": [{"HostIp":"127.0.0.1","HostPort":"8080"},{"HostIp":"127.0.0.2","HostPort":"8081"}],
                "81/tcp": [{"HostIp":"127.0.0.1","HostPort":""},{"HostIp":"127.0.0.2","HostPort":""}],
                "82/udp": [{"HostPort":""}],
            })
        );
        assert_eq!(
            body["ExposedPorts"],
            serde_json::json!({"80/tcp":{},"81/tcp":{},"82/udp":{},"83/tcp":{}})
        );
        assert_eq!(complete["prerequisites"], serde_json::json!([]));
    }
}

#[test]
fn sealed_ipv6_ports_are_upstream_only_for_fixed_and_ephemeral_shapes() {
    let catalog = TargetCapabilityCatalog::reviewed();
    for profile in catalog.profiles() {
        for port in [
            PortHostPort::Fixed(NonZeroU16::new(8080).unwrap()),
            PortHostPort::Ephemeral,
        ] {
            let mut container = application_container();
            container.ports = vec![
                PortPublication::published(
                    NonZeroU16::new(80).unwrap(),
                    Protocol::Tcp,
                    vec![HostBinding {
                        host_ip: PortHostIp::Address("::1".parse().unwrap()),
                        host_port: port,
                    }],
                )
                .unwrap(),
            ];
            let intent = container_target(container);
            let resolved = catalog.resolve(profile).unwrap();
            if matches!(profile.identity().build(), EngineBuild::DebianPackage(_)) {
                assert!(matches!(
                    DockerPlanner.plan(&intent, &resolved),
                    Err(PlanningError::MissingCapability {
                        field: TargetField::PortHostIpv6,
                        ..
                    })
                ));
            } else {
                let complete = complete_application(profile, &intent);
                assert_eq!(
                    complete["requests"][0]["body"]["HostConfig"]["PortBindings"]["80/tcp"],
                    serde_json::json!([{"HostIp":"::1","HostPort": match port {
                        PortHostPort::Fixed(_) => "8080", PortHostPort::Ephemeral => "",
                    }}])
                );
            }
        }
    }
}

#[test]
fn sealed_shell_health_start_period_and_container_labels_keep_authored_bytes() {
    for profile in TargetCapabilityCatalog::reviewed().profiles() {
        for period in [0, 20_000_000_000] {
            let mut container = application_container();
            container.settings.labels = vec![
                ContainerLabel::new(b"private-label".to_vec(), b"private-value".to_vec()).unwrap(),
            ];
            container.healthcheck = Some(
                Healthcheck::configured(
                    HealthTest::Shell(Argument::new(b"test -r /private-file".to_vec()).unwrap()),
                    None,
                    None,
                    None,
                )
                .unwrap()
                .with_start_period(period)
                .unwrap(),
            );
            let intent = container_target(container);
            assert!(!format!("{intent:?}").contains("private-file"));
            assert!(!format!("{intent:?}").contains("private-value"));
            let complete = complete_application(profile, &intent);
            let body = &complete["requests"][0]["body"];
            assert_eq!(
                body["Labels"],
                serde_json::json!({"private-label":"private-value"})
            );
            assert_eq!(
                body["Healthcheck"],
                serde_json::json!({
                    "Test":["CMD-SHELL","test -r /private-file"], "StartPeriod":period,
                })
            );
            assert_eq!(complete["schema_version"], 1);
        }
    }
}

#[test]
fn sealed_health_controls_do_not_admit_disabled_or_start_interval() {
    let catalog = TargetCapabilityCatalog::reviewed();
    for profile in catalog.profiles() {
        for (check, field) in [
            (
                Healthcheck::configured(HealthTest::Disabled, None, None, None).unwrap(),
                TargetField::HealthDisabled,
            ),
            (
                Healthcheck::configured(
                    HealthTest::Shell(Argument::new(b"true".to_vec()).unwrap()),
                    None,
                    None,
                    None,
                )
                .unwrap()
                .with_start_interval(1_000_000)
                .unwrap(),
                TargetField::HealthStartInterval,
            ),
        ] {
            let mut container = application_container();
            container.healthcheck = Some(check);
            assert!(
                matches!(DockerPlanner.plan(&container_target(container), &catalog.resolve(profile).unwrap()),
                Err(PlanningError::MissingCapability { field: actual, .. }) if actual == field)
            );
        }
    }
}

#[test]
fn sealed_application_network_labels_aliases_and_secondary_request_order() {
    for profile in TargetCapabilityCatalog::reviewed().profiles() {
        let network = |index, name: &[u8]| {
            let mut create = NetworkCreate::bridge();
            create.labels =
                vec![NetworkLabel::new(b"owner".to_vec(), b"private-owner".to_vec()).unwrap()];
            TargetResource::Network(NetworkIntent {
                reference: ResourceRef::new(index),
                identity: TargetIdentity::new(name.to_vec()).unwrap(),
                role: NetworkRole::Declared,
                source: NetworkSource::Create(create),
            })
        };
        let mut container = application_container();
        container.networks = vec![
            NetworkAttachmentIntent {
                network: ResourceRef::new(1),
                aliases: vec![NetworkAlias::new(b"primary-alias".to_vec()).unwrap()],
                ipv4_address: None,
                ipv6_address: None,
            },
            NetworkAttachmentIntent {
                network: ResourceRef::new(2),
                aliases: vec![NetworkAlias::new(b"secondary-alias".to_vec()).unwrap()],
                ipv4_address: None,
                ipv6_address: None,
            },
        ];
        let intent = TargetIntent::new(vec![
            network(1, b"primary"),
            network(2, b"secondary"),
            TargetResource::Container(Box::new(container)),
        ])
        .unwrap();
        let complete = complete_application(profile, &intent);
        let requests = complete["requests"].as_array().unwrap();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0]["body"]["Name"], "primary");
        assert_eq!(requests[1]["body"]["Name"], "secondary");
        for request in &requests[..2] {
            assert_eq!(
                request["body"]["Labels"],
                serde_json::json!({"owner":"private-owner"})
            );
        }
        assert_eq!(
            requests[2]["body"]["NetworkingConfig"]["EndpointsConfig"],
            serde_json::json!({"primary":{"Aliases":["primary-alias"]}})
        );
        assert_eq!(
            requests[3]["path"],
            format!(
                "/v{}.{}/networks/secondary/connect",
                profile.rendering_api_version().major,
                profile.rendering_api_version().minor
            )
        );
        assert_eq!(
            requests[3]["body"],
            serde_json::json!({
                "Container":"private-application", "EndpointConfig":{"Aliases":["secondary-alias"]},
            })
        );
        assert_eq!(complete["schema_version"], 1);
    }
}

#[test]
fn sealed_bind_retention_keeps_all_four_modes_and_conditional_source_obligations() {
    for profile in TargetCapabilityCatalog::reviewed().profiles() {
        let mut container = application_container();
        container
            .mounts
            .push(Mount::bind(b"/plain".to_vec(), b"/plain-target".to_vec(), false).unwrap());
        let modes = [
            (BindRelabel::Shared, false, "rw,z", "shared"),
            (BindRelabel::Shared, true, "ro,z", "shared"),
            (BindRelabel::Private, false, "rw,Z", "private"),
            (BindRelabel::Private, true, "ro,Z", "private"),
        ];
        for (index, (relabel, read_only, _, _)) in modes.iter().enumerate() {
            container.mounts.push(
                Mount::bind(
                    format!("/source-{index}").into_bytes(),
                    format!("/target-{index}").into_bytes(),
                    *read_only,
                )
                .unwrap()
                .with_bind_relabel(*relabel)
                .unwrap(),
            );
        }
        let complete = complete_application(profile, &container_target(container));
        assert_eq!(complete["schema_version"], 2);
        let body = &complete["requests"][0]["body"];
        assert_eq!(
            body["HostConfig"]["Mounts"],
            serde_json::json!([
                {"Type":"bind","Source":"/plain","Target":"/plain-target","ReadOnly":false},
            ])
        );
        let binds = body["HostConfig"]["Binds"].as_array().unwrap();
        let prerequisites = complete["prerequisites"].as_array().unwrap();
        assert_eq!(prerequisites.len(), 4);
        for (index, (_, read_only, mode, relabel)) in modes.iter().enumerate() {
            assert_eq!(
                binds[index],
                format!("/source-{index}:/target-{index}:{mode}")
            );
            assert_eq!(
                prerequisites[index],
                serde_json::json!({
                    "kind":"bind_source","reference":"3","identity":"private-application",
                    "mount_index":(index + 1).to_string(), "source":format!("/source-{index}"),
                    "target":format!("/target-{index}"), "read_only":read_only,"relabel":relabel,
                    "source_conditions":["exists","type_reviewed","contents_reviewed","ownership_reviewed","permissions_reviewed"],
                    "selinux_effect":"unverified",
                    "selinux_conditions":["daemon_selinux_enabled","container_mount_label_present","policy_filesystem_support","relabel_authority"],
                })
            );
        }
    }
}

#[test]
fn admitted_application_fields_still_reject_invalid_authored_values() {
    assert!(
        PortPublication::published(NonZeroU16::new(80).unwrap(), Protocol::Tcp, vec![]).is_err()
    );
    assert!(NetworkAlias::new(b"invalid/alias".to_vec()).is_err());
    assert!(ContainerLabel::new(vec![], b"private-value".to_vec()).is_err());
    assert!(NetworkLabel::new(vec![], b"private-value".to_vec()).is_err());
    assert!(
        Healthcheck::configured(
            HealthTest::Shell(Argument::new(b"true".to_vec()).unwrap()),
            None,
            None,
            None
        )
        .unwrap()
        .with_start_period(1)
        .is_err()
    );
    assert!(
        Mount::bind(b"/private:source".to_vec(), b"/target".to_vec(), false)
            .unwrap()
            .with_bind_relabel(BindRelabel::Shared)
            .is_err()
    );
    let mut container = application_container();
    container.settings.labels = vec![
        ContainerLabel::new(b"private-key".to_vec(), b"one".to_vec()).unwrap(),
        ContainerLabel::new(b"private-key".to_vec(), b"two".to_vec()).unwrap(),
    ];
    assert!(TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).is_err());
    let mut container = application_container();
    container.mounts = vec![
        Mount::bind(b"/first".to_vec(), b"/data".to_vec(), false).unwrap(),
        Mount::bind(b"/second".to_vec(), b"/x/../data".to_vec(), true)
            .unwrap()
            .with_bind_relabel(BindRelabel::Private)
            .unwrap(),
    ];
    assert!(TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).is_err());
}

fn identity_container(settings: ContainerSettings) -> TargetIntent {
    TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(b"private-identity-container".to_vec()).unwrap(),
        image: ImageReference::new(b"unverified-private-image:fixture".to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Inherit,
        healthcheck: None,
        restart: None,
        settings,
    }))])
    .unwrap()
}

#[test]
fn sealed_identity_profiles_render_parameterized_fields_and_protect_values() {
    // These are independently authored request expectations. No image is read:
    // account lookup, directory creation and process startup remain native obligations.
    let catalog = TargetCapabilityCatalog::reviewed();
    for user in [
        None,
        Some("1000"),
        Some("1000:1001"),
        Some("private_principal"),
        Some("private_principal:private_group"),
        Some("private_principal:1001"),
        Some("1000:private_group"),
        Some("0"),
        Some("2147483647:2147483647"),
        Some("missing_image_account:missing_image_group"),
    ] {
        for directory in [
            None,
            Some("/private-new-directory"),
            Some("/private/Grüße\"\\"),
        ] {
            let settings = ContainerSettings {
                user: user.map(|value| ContainerUser::new(value.as_bytes().to_vec()).unwrap()),
                working_dir: directory
                    .map(|value| WorkingDirectory::new(value.as_bytes().to_vec()).unwrap()),
                ..ContainerSettings::default()
            };
            assert!(!format!("{settings:?}").contains("private"));
            if let Some(value) = &settings.user {
                assert!(!format!("{value:?}").contains(user.unwrap()));
            }
            if let Some(value) = &settings.working_dir {
                assert!(!format!("{value:?}").contains(directory.unwrap()));
            }
            let intent = identity_container(settings);
            for profile in catalog.profiles() {
                let admitted = catalog.resolve(profile).unwrap();
                let graph = DockerPlanner.plan(&intent, &admitted).unwrap();
                let artifact = DockerApiRenderer.render(&graph).unwrap();
                let mut body = serde_json::json!({
                    "Image": "unverified-private-image:fixture",
                    "HostConfig": {},
                });
                if let Some(value) = user {
                    body["User"] = value.into();
                }
                if let Some(value) = directory {
                    body["WorkingDir"] = value.into();
                }
                let request = serde_json::json!({
                    "method": "POST",
                    "path": format!("/v{}.{}/containers/create?name=private-identity-container",
                                    profile.rendering_api_version().major,
                                    profile.rendering_api_version().minor),
                    "body": body,
                });
                let request_only: serde_json::Value =
                    serde_json::from_slice(artifact.bytes()).unwrap();
                assert_eq!(request_only, request);
                let complete: serde_json::Value =
                    serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
                assert_eq!(
                    complete,
                    serde_json::json!({
                        "schema_version": 1,
                        "context": reviewed_prerequisite_context(profile),
                        "requests": [request],
                        "prerequisites": [],
                    })
                );
                assert_eq!(graph.context(), &PlanningContext::Target(profile.clone()));
                assert!(artifact.volume_prerequisites().is_empty());
                assert!(artifact.network_prerequisites().is_empty());
                for debug in [
                    format!("{intent:?}"),
                    format!("{graph:?}"),
                    format!("{artifact:?}"),
                ] {
                    for protected in [
                        "private-identity-container",
                        "unverified-private-image",
                        "private_principal",
                        "private_group",
                        "missing_image_account",
                        "missing_image_group",
                        "private-new-directory",
                        "Grüße",
                    ] {
                        assert!(!debug.contains(protected));
                    }
                }
            }
        }
    }
}

#[test]
fn identity_admission_does_not_admit_supplementary_groups_or_host_namespace() {
    let catalog = TargetCapabilityCatalog::reviewed();
    for (field, capability, settings) in [
        (
            TargetField::SupplementaryGroups,
            Capability::SupplementaryGroups,
            ContainerSettings {
                group_add: vec![ContainerUser::new(b"private_group".to_vec()).unwrap()],
                ..ContainerSettings::default()
            },
        ),
        (
            TargetField::UserNamespace,
            Capability::UserNamespace,
            ContainerSettings {
                userns_mode: Some(UserNamespaceMode::Host),
                ..ContainerSettings::default()
            },
        ),
    ] {
        let intent = identity_container(ContainerSettings {
            user: Some(ContainerUser::new(b"2147483647:private_group".to_vec()).unwrap()),
            working_dir: Some(WorkingDirectory::new(b"/unverified-directory".to_vec()).unwrap()),
            ..settings
        });
        for profile in catalog.profiles() {
            let admitted = catalog.resolve(profile).unwrap();
            let error = DockerPlanner.plan(&intent, &admitted).unwrap_err();
            assert_eq!(
                error,
                PlanningError::MissingCapability {
                    resource: ResourceRef::new(1),
                    field,
                    capability,
                }
            );
            assert!(!format!("{error:?}").contains("private_group"));
            assert!(!format!("{error:?}").contains("unverified-directory"));
        }
    }
}

#[test]
fn public_identity_values_reject_malformed_syntax_without_disclosing_values() {
    for value in [
        "private:user:group",
        "private:",
        "01",
        "2147483648",
        "private user",
    ] {
        let error = ContainerUser::new(value.as_bytes().to_vec()).unwrap_err();
        assert_eq!(error, IntentError::InvalidContainerUser);
        assert!(!format!("{error:?}").contains(value));
    }
    for value in [
        b"private-relative".as_slice(),
        b"/private\0directory",
        &[0xff],
    ] {
        let error = WorkingDirectory::new(value.to_vec()).unwrap_err();
        assert_eq!(error, IntentError::InvalidWorkingDirectory);
        assert!(!format!("{error:?}").contains("private"));
    }
}

fn reviewed_prerequisite_context(profile: &TargetProfile) -> serde_json::Value {
    let (build, release, rendering_api, acquisition_api, rootful_key, rootless_key) =
        match profile.identity().build() {
            EngineBuild::DebianPackage(_) => (
                serde_json::json!({
                    "kind": "debian_package",
                    "revision": "20.10.5+dfsg1-1+deb11u2",
                }),
                "20.10.5+dfsg1",
                "1.41",
                "1.41",
                "60d1a2a4892eb47bc95244194113a1d0fd24c52a1e057ce3469be433106b3d12",
                "e014e47b24643055f01349e5a3296a938d4d88f34415f0f9bb4f1286709be29a",
            ),
            EngineBuild::Upstream => (
                serde_json::json!({"kind": "upstream"}),
                "29.8.1",
                "1.56",
                "1.49",
                "727db2b40c56df2f03d26b9134a35d31f2837db8ed00d5887371896ab336635e",
                "f951bf1919e7dc039c8900f3c2144e4b71ad05e675ec54fa64406963b37dba35",
            ),
        };
    let (mode, evidence_key) = match profile.mode() {
        DaemonMode::Rootful => ("rootful", rootful_key),
        DaemonMode::Rootless => ("rootless", rootless_key),
        DaemonMode::Unknown => panic!("reviewed profiles must bind a daemon mode"),
    };
    serde_json::json!({
        "kind": "target",
        "build": build,
        "engine_release": release,
        "advertised_api_version": rendering_api,
        "acquisition_api_version": acquisition_api,
        "rendering_api_version": rendering_api,
        "daemon_mode": mode,
        "evidence_sha256": evidence_key,
    })
}

#[test]
fn reviewed_profiles_plan_and_render_exact_prerequisites_and_internal_bridge() {
    let mut internal = NetworkCreate::bridge();
    internal.internal = true;
    let intent = TargetIntent::new(vec![
        TargetResource::ExternalVolume {
            reference: ResourceRef::new(11),
            identity: TargetIdentity::new(b"existing-data".to_vec()).unwrap(),
        },
        TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(22),
            identity: TargetIdentity::new(b"existing-edge".to_vec()).unwrap(),
            role: NetworkRole::Declared,
            source: NetworkSource::External {
                expected_driver: NetworkDriver::Bridge,
                expected_internal: None,
            },
        }),
        TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(33),
            identity: TargetIdentity::new(b"private-backend".to_vec()).unwrap(),
            role: NetworkRole::Declared,
            source: NetworkSource::Create(internal),
        }),
    ])
    .unwrap();
    let catalog = TargetCapabilityCatalog::reviewed();
    assert_eq!(catalog.profiles().len(), 4);
    for profile in catalog.profiles() {
        let admitted = catalog.resolve(profile).unwrap();
        let graph = DockerPlanner.plan(&intent, &admitted).unwrap();
        assert_eq!(graph.context(), &PlanningContext::Target(profile.clone()));
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        assert_eq!(artifact.context(), Some(graph.context()));

        assert_eq!(artifact.volume_prerequisites().len(), 1);
        let volume = &artifact.volume_prerequisites()[0];
        assert_eq!(volume.reference, ResourceRef::new(11));
        assert_eq!(volume.identity(), b"existing-data");
        assert_eq!(artifact.network_prerequisites().len(), 1);
        let network = &artifact.network_prerequisites()[0];
        assert_eq!(network.reference, ResourceRef::new(22));
        assert_eq!(network.identity(), b"existing-edge");
        assert_eq!(network.expected_driver, NetworkDriver::Bridge);

        let context = reviewed_prerequisite_context(profile);
        let request = serde_json::json!({
            "method": "POST",
            "path": format!(
                "/v{}/networks/create",
                context["rendering_api_version"].as_str().unwrap(),
            ),
            "body": {"Name": "private-backend", "Driver": "bridge", "Internal": true},
        });
        // Parsing the entire stream as one object rejects any external create request.
        let request_only: serde_json::Value = serde_json::from_slice(artifact.bytes()).unwrap();
        assert_eq!(request_only, request);
        let complete: serde_json::Value =
            serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
        assert_eq!(
            complete,
            serde_json::json!({
                "schema_version": 1,
                "context": context,
                "requests": [request],
                "prerequisites": [
                    {"kind": "volume", "reference": "11", "identity": "existing-data"},
                    {
                        "kind": "network", "reference": "22", "identity": "existing-edge",
                        "expected_driver": "bridge",
                    },
                ],
            }),
        );
    }
}

fn literal_label_artifact(profile: &TargetProfile) -> &'static str {
    // Independently authored wire expectations, not bytes obtained from the renderer.
    match (profile.identity().build(), profile.mode()) {
        (EngineBuild::DebianPackage(_), DaemonMode::Rootful) => {
            "{\"schema_version\":1,\"context\":{\"kind\":\"target\",\"build\":{\"kind\":\"debian_package\",\"revision\":\"20.10.5+dfsg1-1+deb11u2\"},\"engine_release\":\"20.10.5+dfsg1\",\"advertised_api_version\":\"1.41\",\"acquisition_api_version\":\"1.41\",\"rendering_api_version\":\"1.41\",\"daemon_mode\":\"rootful\",\"evidence_sha256\":\"60d1a2a4892eb47bc95244194113a1d0fd24c52a1e057ce3469be433106b3d12\"},\"requests\":[{\"method\":\"POST\",\"path\":\"/v1.41/volumes/create\",\"body\":{\"Name\":\"candidate-volume\",\"Labels\":{\"io.boxferry.owner\":\"fixture\",\"empty\":\"\",\"private-key\":\"Grüße\\\"\\\\\\n\"}}}],\"prerequisites\":[]}\n"
        }
        (EngineBuild::Upstream, DaemonMode::Rootful) => {
            "{\"schema_version\":1,\"context\":{\"kind\":\"target\",\"build\":{\"kind\":\"upstream\"},\"engine_release\":\"29.8.1\",\"advertised_api_version\":\"1.56\",\"acquisition_api_version\":\"1.49\",\"rendering_api_version\":\"1.56\",\"daemon_mode\":\"rootful\",\"evidence_sha256\":\"727db2b40c56df2f03d26b9134a35d31f2837db8ed00d5887371896ab336635e\"},\"requests\":[{\"method\":\"POST\",\"path\":\"/v1.56/volumes/create\",\"body\":{\"Name\":\"candidate-volume\",\"Labels\":{\"io.boxferry.owner\":\"fixture\",\"empty\":\"\",\"private-key\":\"Grüße\\\"\\\\\\n\"}}}],\"prerequisites\":[]}\n"
        }
        (EngineBuild::DebianPackage(_), DaemonMode::Rootless) => {
            "{\"schema_version\":1,\"context\":{\"kind\":\"target\",\"build\":{\"kind\":\"debian_package\",\"revision\":\"20.10.5+dfsg1-1+deb11u2\"},\"engine_release\":\"20.10.5+dfsg1\",\"advertised_api_version\":\"1.41\",\"acquisition_api_version\":\"1.41\",\"rendering_api_version\":\"1.41\",\"daemon_mode\":\"rootless\",\"evidence_sha256\":\"e014e47b24643055f01349e5a3296a938d4d88f34415f0f9bb4f1286709be29a\"},\"requests\":[{\"method\":\"POST\",\"path\":\"/v1.41/volumes/create\",\"body\":{\"Name\":\"candidate-volume\",\"Labels\":{\"io.boxferry.owner\":\"fixture\",\"empty\":\"\",\"private-key\":\"Grüße\\\"\\\\\\n\"}}}],\"prerequisites\":[]}\n"
        }
        (EngineBuild::Upstream, DaemonMode::Rootless) => {
            "{\"schema_version\":1,\"context\":{\"kind\":\"target\",\"build\":{\"kind\":\"upstream\"},\"engine_release\":\"29.8.1\",\"advertised_api_version\":\"1.56\",\"acquisition_api_version\":\"1.49\",\"rendering_api_version\":\"1.56\",\"daemon_mode\":\"rootless\",\"evidence_sha256\":\"f951bf1919e7dc039c8900f3c2144e4b71ad05e675ec54fa64406963b37dba35\"},\"requests\":[{\"method\":\"POST\",\"path\":\"/v1.56/volumes/create\",\"body\":{\"Name\":\"candidate-volume\",\"Labels\":{\"io.boxferry.owner\":\"fixture\",\"empty\":\"\",\"private-key\":\"Grüße\\\"\\\\\\n\"}}}],\"prerequisites\":[]}\n"
        }
        (_, DaemonMode::Unknown) => panic!("reviewed profiles must bind a daemon mode"),
    }
}

#[test]
fn candidate_label_profiles_render_literal_complete_artifacts_and_protect_debug() {
    let label =
        VolumeLabel::new(b"private-key".to_vec(), "Grüße\"\\\n".as_bytes().to_vec()).unwrap();
    assert!(!format!("{label:?}").contains("private-key"));
    let intent = TargetIntent::new(vec![labelled_volume(vec![
        VolumeLabel::new(b"io.boxferry.owner".to_vec(), b"fixture".to_vec()).unwrap(),
        VolumeLabel::new(b"empty".to_vec(), vec![]).unwrap(),
        label,
    ])])
    .unwrap();
    let catalog = TargetCapabilityCatalog::reviewed();
    assert_eq!(catalog.profiles().len(), 4);
    for profile in catalog.profiles() {
        let admitted = catalog.resolve(profile).unwrap();
        let graph = DockerPlanner.plan(&intent, &admitted).unwrap();
        assert_eq!(graph.context(), &PlanningContext::Target(profile.clone()));
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        assert_eq!(artifact.context(), Some(graph.context()));
        assert!(artifact.volume_prerequisites().is_empty());
        assert!(artifact.network_prerequisites().is_empty());
        let expected = literal_label_artifact(profile);
        assert_eq!(artifact.complete_bytes().unwrap(), expected.as_bytes());
        let expected: serde_json::Value = serde_json::from_str(expected).unwrap();
        let request: serde_json::Value = serde_json::from_slice(artifact.bytes()).unwrap();
        assert_eq!(request, expected["requests"][0]);
        for debug in [
            format!("{intent:?}"),
            format!("{graph:?}"),
            format!("{artifact:?}"),
        ] {
            for protected in [
                "candidate-volume",
                "io.boxferry.owner",
                "private-key",
                "Grüße",
                "fixture",
            ] {
                assert!(!debug.contains(protected));
            }
        }
    }
}

fn labelled_volume(labels: Vec<VolumeLabel>) -> TargetResource {
    TargetResource::Volume {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(b"candidate-volume".to_vec()).unwrap(),
        labels,
    }
}

#[test]
fn public_volume_label_invalid_duplicate_and_oversized_values_fail_closed() {
    assert!(VolumeLabel::new(vec![b'k'; 128], vec![b'v'; 4096]).is_ok());
    for (key, value) in [
        (vec![], vec![]),
        (vec![b'k'; 129], vec![]),
        (b"private-key".to_vec(), vec![b'v'; 4097]),
        (b"private\0key".to_vec(), vec![]),
        (b"private-key".to_vec(), b"private\0value".to_vec()),
        (vec![0xff], vec![]),
        (b"private-key".to_vec(), vec![0xff]),
    ] {
        let error = VolumeLabel::new(key, value).unwrap_err();
        assert_eq!(error, IntentError::InvalidVolumeLabel);
        assert!(!format!("{error:?}").contains("private"));
    }
    let duplicate = (0..2)
        .map(|_| VolumeLabel::new(b"private-key".to_vec(), b"private-value".to_vec()).unwrap())
        .collect();
    let error = TargetIntent::new(vec![labelled_volume(duplicate)]).unwrap_err();
    assert_eq!(error, IntentError::DuplicateVolumeLabel);
    assert!(!format!("{error:?}").contains("private"));
    for count in [64, 65] {
        let labels = (0..count)
            .map(|index| VolumeLabel::new(format!("key-{index}").into_bytes(), vec![]).unwrap())
            .collect();
        let result = TargetIntent::new(vec![labelled_volume(labels)]);
        if count == 64 {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err(), IntentError::InvalidVolumeLabel);
        }
    }
    for value_bytes in [4095, 4096] {
        let labels = (0..4)
            .map(|index| {
                VolumeLabel::new(format!("{index}").into_bytes(), vec![b'v'; value_bytes]).unwrap()
            })
            .collect();
        let result = TargetIntent::new(vec![labelled_volume(labels)]);
        if value_bytes == 4095 {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err(), IntentError::InvalidVolumeLabel);
        }
    }
}

#[test]
fn public_external_volume_cannot_be_relabelled_by_a_conflicting_created_volume() {
    let error = TargetIntent::new(vec![
        labelled_volume(vec![
            VolumeLabel::new(b"private-key".to_vec(), b"private-value".to_vec()).unwrap(),
        ]),
        TargetResource::ExternalVolume {
            reference: ResourceRef::new(2),
            identity: TargetIdentity::new(b"candidate-volume".to_vec()).unwrap(),
        },
    ])
    .unwrap_err();
    assert_eq!(error, IntentError::DuplicateResource);
    let intent = TargetIntent::new(vec![TargetResource::ExternalVolume {
        reference: ResourceRef::new(2),
        identity: TargetIdentity::new(b"existing-private-data".to_vec()).unwrap(),
    }])
    .unwrap();
    let catalog = TargetCapabilityCatalog::reviewed();
    for profile in catalog.profiles() {
        let admitted = catalog.resolve(profile).unwrap();
        let graph = DockerPlanner.plan(&intent, &admitted).unwrap();
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        assert!(artifact.bytes().is_empty());
        let complete: serde_json::Value =
            serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
        assert_eq!(complete["requests"], serde_json::json!([]));
        assert_eq!(
            complete["prerequisites"],
            serde_json::json!([
                {"kind":"volume", "reference":"2", "identity":"existing-private-data"},
            ])
        );
    }
}

#[test]
fn label_candidates_reject_wrong_mode_evidence_and_api_before_planning() {
    let intent = TargetIntent::new(vec![labelled_volume(vec![
        VolumeLabel::new(b"private-key".to_vec(), b"private-value".to_vec()).unwrap(),
    ])])
    .unwrap();
    let catalog = TargetCapabilityCatalog::reviewed();
    for profile in catalog.profiles() {
        let wrong_mode = if profile.mode() == DaemonMode::Rootful {
            DaemonMode::Rootless
        } else {
            DaemonMode::Rootful
        };
        let identity = profile.identity();
        let mismatches = [
            TargetProfile::new(
                identity.clone(),
                CapabilityEvidenceKey::sha256([7; 32]).unwrap(),
            ),
            TargetProfile::new(
                TargetProfileIdentity::new(
                    identity.build().clone(),
                    profile.release().clone(),
                    identity.advertised_api_version(),
                    identity.acquisition_api_version(),
                    profile.rendering_api_version(),
                    wrong_mode,
                )
                .unwrap(),
                profile.evidence_key().clone(),
            ),
            TargetProfile::new(
                TargetProfileIdentity::new(
                    identity.build().clone(),
                    profile.release().clone(),
                    api(identity.advertised_api_version().minor + 1),
                    identity.acquisition_api_version(),
                    api(profile.rendering_api_version().minor + 1),
                    profile.mode(),
                )
                .unwrap(),
                profile.evidence_key().clone(),
            ),
        ];
        for mismatch in mismatches {
            assert!(matches!(
                catalog.resolve(&mismatch),
                Err(CapabilityError::ProfileNotReviewed)
            ));
        }
        let admitted = catalog.resolve(profile).unwrap();
        assert!(DockerPlanner.plan(&intent, &admitted).is_ok());
    }
}

#[test]
fn public_catalog_resolves_four_exact_profiles_and_renders_inert_requests() {
    let catalog = TargetCapabilityCatalog::reviewed();
    assert_eq!(catalog.profiles().len(), 4);
    for profile in catalog.profiles() {
        let admitted = catalog.resolve(profile).unwrap();
        assert!(admitted.supports(Capability::VolumeLabels));
        assert_eq!(admitted.profile(), profile);
        assert_eq!(admitted.evidence_key(), profile.evidence_key());
        let opposite_mode = if profile.mode() == DaemonMode::Rootful {
            DaemonMode::Rootless
        } else {
            DaemonMode::Rootful
        };
        let mismatched_mode = TargetProfile::new(
            TargetProfileIdentity::new(
                profile.identity().build().clone(),
                profile.release().clone(),
                profile.identity().advertised_api_version(),
                profile.identity().acquisition_api_version(),
                profile.rendering_api_version(),
                opposite_mode,
            )
            .unwrap(),
            profile.evidence_key().clone(),
        );
        assert!(matches!(
            catalog.resolve(&mismatched_mode),
            Err(CapabilityError::ProfileNotReviewed)
        ));
        let intent = TargetIntent::new(vec![TargetResource::Volume {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"consumer-volume".to_vec()).unwrap(),
            labels: vec![],
        }])
        .unwrap();
        let graph = DockerPlanner.plan(&intent, &admitted).unwrap();
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        let rendered: serde_json::Value = serde_json::from_slice(
            artifact
                .bytes()
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(rendered["method"], "POST");
        assert_eq!(rendered["body"]["Name"], "consumer-volume");
        assert_eq!(
            rendered["path"],
            format!(
                "/v{}.{}/volumes/create",
                profile.rendering_api_version().major,
                profile.rendering_api_version().minor
            )
        );
    }

    let build = EngineBuild::DebianPackage(
        DebianPackageRevision::new("20.10.5+dfsg1-1+deb11u2".into()).unwrap(),
    );
    let identity = TargetProfileIdentity::new(
        build,
        EngineRelease::new("20.10.5+dfsg1".into()).unwrap(),
        api(41),
        api(41),
        api(41),
        DaemonMode::Rootless,
    )
    .unwrap();
    let key = CapabilityEvidenceKey::sha256([7; 32]).unwrap();
    let caller_claim = TargetProfile::new(identity.clone(), key.clone());

    assert_eq!(caller_claim.identity(), &identity);
    assert_eq!(caller_claim.evidence_key().as_sha256_bytes(), &[7; 32]);
    assert!(catalog.resolve_identity(&identity).is_ok());
    assert!(matches!(
        catalog.resolve(&caller_claim),
        Err(CapabilityError::ProfileNotReviewed)
    ));
}

#[test]
fn exact_debian11_candidates_admit_only_reviewed_identity_dimensions() {
    let catalog = TargetCapabilityCatalog::reviewed();
    let release = EngineRelease::new("20.10.5+dfsg1".into()).unwrap();
    let package = "20.10.5+dfsg1-1+deb11u2";
    for mode in [DaemonMode::Rootful, DaemonMode::Rootless] {
        let exact = TargetProfileIdentity::new(
            EngineBuild::DebianPackage(DebianPackageRevision::new(package.into()).unwrap()),
            release.clone(),
            api(41),
            api(41),
            api(41),
            mode,
        )
        .unwrap();
        assert!(catalog.resolve_identity(&exact).is_ok());
        let neighbors = [
            TargetProfileIdentity::new(
                EngineBuild::DebianPackage(
                    DebianPackageRevision::new("20.10.5+dfsg1-1+deb11u3".into()).unwrap(),
                ),
                release.clone(),
                api(41),
                api(41),
                api(41),
                mode,
            )
            .unwrap(),
            TargetProfileIdentity::new(
                EngineBuild::DebianPackage(DebianPackageRevision::new(package.into()).unwrap()),
                EngineRelease::new("20.10.6".into()).unwrap(),
                api(41),
                api(41),
                api(41),
                mode,
            )
            .unwrap(),
            TargetProfileIdentity::new(
                EngineBuild::DebianPackage(DebianPackageRevision::new(package.into()).unwrap()),
                release.clone(),
                api(42),
                api(41),
                api(41),
                mode,
            )
            .unwrap(),
            TargetProfileIdentity::new(
                EngineBuild::DebianPackage(DebianPackageRevision::new(package.into()).unwrap()),
                release.clone(),
                api(42),
                api(42),
                api(41),
                mode,
            )
            .unwrap(),
            TargetProfileIdentity::new(
                EngineBuild::DebianPackage(DebianPackageRevision::new(package.into()).unwrap()),
                release.clone(),
                api(42),
                api(41),
                api(42),
                mode,
            )
            .unwrap(),
            TargetProfileIdentity::new(
                EngineBuild::Upstream,
                release.clone(),
                api(41),
                api(41),
                api(41),
                mode,
            )
            .unwrap(),
        ];
        for identity in &neighbors {
            assert!(matches!(
                catalog.resolve_identity(identity),
                Err(CapabilityError::ProfileNotReviewed)
            ));
        }
    }
}

#[test]
fn upstream_profiles_bind_distinct_advertised_acquisition_and_rendering_apis() {
    let catalog = TargetCapabilityCatalog::reviewed();
    let release = EngineRelease::new("29.8.1".into()).unwrap();
    for mode in [DaemonMode::Rootful, DaemonMode::Rootless] {
        let identity = |advertised, acquisition, rendering| {
            TargetProfileIdentity::new(
                EngineBuild::Upstream,
                release.clone(),
                api(advertised),
                api(acquisition),
                api(rendering),
                mode,
            )
            .unwrap()
        };
        assert!(catalog.resolve_identity(&identity(56, 49, 56)).is_ok());
        for neighbor in [
            identity(55, 49, 55),
            identity(57, 49, 56),
            identity(56, 48, 56),
            identity(56, 50, 56),
            identity(56, 49, 55),
            identity(56, 56, 49),
            TargetProfileIdentity::new(
                EngineBuild::Upstream,
                EngineRelease::new("29.8.2".into()).unwrap(),
                api(56),
                api(49),
                api(56),
                mode,
            )
            .unwrap(),
        ] {
            assert!(matches!(
                catalog.resolve_identity(&neighbor),
                Err(CapabilityError::ProfileNotReviewed)
            ));
        }
    }
}

#[test]
fn public_evidence_locator_cannot_admit_a_profile() {
    let key = CapabilityEvidenceKey::sha256([7; 32]).unwrap();
    let evidence = NativeEvidenceReference::new(
        NativeEvidenceLane::Debian11Rootful,
        "https://github.com/Strukturpiloten/docker-lens/actions/runs/123/attempts/1".into(),
        "0123456789abcdef0123456789abcdef01234567".into(),
        NativeEvidenceLane::Debian11Rootful.artifact_name().into(),
        key.clone(),
        key.clone(),
    )
    .unwrap();
    assert_eq!(evidence.record_key(), &key);
    let identity = TargetProfileIdentity::new(
        EngineBuild::DebianPackage(
            DebianPackageRevision::new("20.10.5+dfsg1-1+deb11u2".into()).unwrap(),
        ),
        EngineRelease::new("20.10.5+dfsg1".into()).unwrap(),
        api(41),
        api(41),
        api(41),
        DaemonMode::Rootful,
    )
    .unwrap();
    let caller_claim = TargetProfile::new(identity, key);
    assert!(matches!(
        TargetCapabilityCatalog::reviewed().resolve(&caller_claim),
        Err(CapabilityError::ProfileNotReviewed)
    ));
}

#[test]
fn public_identity_preserves_distinct_api_dimensions_and_rejects_mismatch() {
    let release = EngineRelease::new("28.0.0".into()).unwrap();
    let identity = TargetProfileIdentity::new(
        EngineBuild::Upstream,
        release.clone(),
        api(50),
        api(49),
        api(48),
        DaemonMode::Rootful,
    )
    .unwrap();
    assert_eq!(identity.advertised_api_version(), api(50));
    assert_eq!(identity.acquisition_api_version(), api(49));
    assert_eq!(identity.rendering_api_version(), api(48));
    assert!(matches!(identity.build(), EngineBuild::Upstream));
    assert_eq!(identity.release(), &release);

    assert_eq!(
        TargetProfileIdentity::new(
            EngineBuild::Upstream,
            release.clone(),
            api(49),
            api(50),
            api(48),
            DaemonMode::Rootful,
        ),
        Err(CapabilityError::InvalidTargetApiRange)
    );
    assert_eq!(
        TargetProfileIdentity::new(
            EngineBuild::Upstream,
            release,
            api(50),
            api(49),
            api(40),
            DaemonMode::Rootful,
        ),
        Err(CapabilityError::InvalidTargetApiRange)
    );
    assert_eq!(
        DebianPackageRevision::new(" ".into()),
        Err(CapabilityError::InvalidPackageRevision)
    );
}
