//! An external consumer can discover reviewed profiles but cannot supply
//! positive capability claims without a matching catalog record.

use docker_lens::observation::ResourceRef;
use docker_lens::target::{
    ContainerIntent, ContainerSettings, ContainerUser, DockerApiRenderer, DockerPlanner,
    ImageCommand, ImageReference, IntentError, NetworkCreate, NetworkDriver, NetworkIntent,
    NetworkRole, NetworkSource, Planner, PlanningContext, PlanningError, Renderer, TargetField,
    TargetIdentity, TargetIntent, TargetResource, UserNamespaceMode, VolumeLabel, WorkingDirectory,
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
            "032b1510524f391f08a795dab4da73f6fa8f7213"
        );
        assert_eq!(
            resolved.evidence().run_url(),
            "https://github.com/Strukturpiloten/docker-lens/actions/runs/37439627551/attempts/1"
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
            Capability::NetworkInternal,
            Capability::VolumeLabels,
            Capability::ContainerUser,
            Capability::ContainerWorkdir,
        ] {
            assert!(resolved.supports(capability));
        }
        for capability in [
            Capability::TmpfsMount,
            Capability::NetworkIpv6,
            Capability::NetworkIpam,
            Capability::NetworkIpamDriver,
            Capability::NetworkOptions,
            Capability::NetworkLabels,
            Capability::NetworkAliases,
            Capability::NetworkStaticAddress,
            Capability::NetworkMultipleAttachment,
            Capability::HostNetwork,
            Capability::PortExposeOnly,
            Capability::PortHostIpv4,
            Capability::PortHostIpv6,
            Capability::PortMultipleBindings,
            Capability::PortEphemeral,
            Capability::CommandClear,
            Capability::EntrypointClear,
            Capability::HealthShell,
            Capability::HealthDisabled,
            Capability::HealthStartPeriod,
            Capability::HealthStartInterval,
            Capability::ContainerLabels,
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
    }
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
                "24313f10b84b8a3410906d5ad4721d3ef389ad2e09be5b59416929ef57e86b78",
                "c9800d722f1b505f5b1e5a54d9c60e68502fceaa0779f690c5504623ec473333",
            ),
            EngineBuild::Upstream => (
                serde_json::json!({"kind": "upstream"}),
                "29.8.1",
                "1.56",
                "1.49",
                "b6cebf2f71be5992b112661650e37e69270d45f7d1b8e89843e843bded325020",
                "81a1ee33c3a02d83fe6cd0f1683e1bb9b6c8774dc8aa192b2160c6ee44ba0943",
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
            "{\"schema_version\":1,\"context\":{\"kind\":\"target\",\"build\":{\"kind\":\"debian_package\",\"revision\":\"20.10.5+dfsg1-1+deb11u2\"},\"engine_release\":\"20.10.5+dfsg1\",\"advertised_api_version\":\"1.41\",\"acquisition_api_version\":\"1.41\",\"rendering_api_version\":\"1.41\",\"daemon_mode\":\"rootful\",\"evidence_sha256\":\"24313f10b84b8a3410906d5ad4721d3ef389ad2e09be5b59416929ef57e86b78\"},\"requests\":[{\"method\":\"POST\",\"path\":\"/v1.41/volumes/create\",\"body\":{\"Name\":\"candidate-volume\",\"Labels\":{\"io.boxferry.owner\":\"fixture\",\"empty\":\"\",\"private-key\":\"Grüße\\\"\\\\\\n\"}}}],\"prerequisites\":[]}\n"
        }
        (EngineBuild::Upstream, DaemonMode::Rootful) => {
            "{\"schema_version\":1,\"context\":{\"kind\":\"target\",\"build\":{\"kind\":\"upstream\"},\"engine_release\":\"29.8.1\",\"advertised_api_version\":\"1.56\",\"acquisition_api_version\":\"1.49\",\"rendering_api_version\":\"1.56\",\"daemon_mode\":\"rootful\",\"evidence_sha256\":\"b6cebf2f71be5992b112661650e37e69270d45f7d1b8e89843e843bded325020\"},\"requests\":[{\"method\":\"POST\",\"path\":\"/v1.56/volumes/create\",\"body\":{\"Name\":\"candidate-volume\",\"Labels\":{\"io.boxferry.owner\":\"fixture\",\"empty\":\"\",\"private-key\":\"Grüße\\\"\\\\\\n\"}}}],\"prerequisites\":[]}\n"
        }
        (EngineBuild::DebianPackage(_), DaemonMode::Rootless) => {
            "{\"schema_version\":1,\"context\":{\"kind\":\"target\",\"build\":{\"kind\":\"debian_package\",\"revision\":\"20.10.5+dfsg1-1+deb11u2\"},\"engine_release\":\"20.10.5+dfsg1\",\"advertised_api_version\":\"1.41\",\"acquisition_api_version\":\"1.41\",\"rendering_api_version\":\"1.41\",\"daemon_mode\":\"rootless\",\"evidence_sha256\":\"c9800d722f1b505f5b1e5a54d9c60e68502fceaa0779f690c5504623ec473333\"},\"requests\":[{\"method\":\"POST\",\"path\":\"/v1.41/volumes/create\",\"body\":{\"Name\":\"candidate-volume\",\"Labels\":{\"io.boxferry.owner\":\"fixture\",\"empty\":\"\",\"private-key\":\"Grüße\\\"\\\\\\n\"}}}],\"prerequisites\":[]}\n"
        }
        (EngineBuild::Upstream, DaemonMode::Rootless) => {
            "{\"schema_version\":1,\"context\":{\"kind\":\"target\",\"build\":{\"kind\":\"upstream\"},\"engine_release\":\"29.8.1\",\"advertised_api_version\":\"1.56\",\"acquisition_api_version\":\"1.49\",\"rendering_api_version\":\"1.56\",\"daemon_mode\":\"rootless\",\"evidence_sha256\":\"81a1ee33c3a02d83fe6cd0f1683e1bb9b6c8774dc8aa192b2160c6ee44ba0943\"},\"requests\":[{\"method\":\"POST\",\"path\":\"/v1.56/volumes/create\",\"body\":{\"Name\":\"candidate-volume\",\"Labels\":{\"io.boxferry.owner\":\"fixture\",\"empty\":\"\",\"private-key\":\"Grüße\\\"\\\\\\n\"}}}],\"prerequisites\":[]}\n"
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
