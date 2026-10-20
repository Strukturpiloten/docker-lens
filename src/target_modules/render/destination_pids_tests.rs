//! Independently authored inert obligations and adversarial destination snapshots.
//! Test-local capability facts/records never change the sealed public catalogue.

use super::*;
use crate::decoder::{DecodedInventory, DecodedVersion};
use crate::observation::{Availability, Observed, Origin};
use crate::resource_support::ResourceSupportObservation;
use crate::target::{
    BindRelabel, ContainerIntent, ContainerSettings, DestinationPidsAssessment,
    DestinationPidsPrerequisiteError, DockerPlanner, ImageCommand, ImageReference, Mount,
    NetworkAttachmentIntent, NetworkDriver, NetworkIntent, NetworkRole, PidsLimit, Planner,
    TargetIdentity, TargetIntent,
};
use crate::version::{
    Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonFacts, EngineRelease,
    FactProvenance, NativeCapabilityShape, ObservationId, TargetCapabilityCatalog,
    TargetCapabilityFact, ValidatedCapabilities,
};
use serde_json::{Value, json};
use std::num::NonZeroU16;

fn api(minor: u16) -> ApiVersion {
    ApiVersion::new(NonZeroU16::new(1).unwrap(), minor)
}

fn target(reference: u64, limit: Option<PidsLimit>) -> TargetIntent {
    TargetIntent::new(vec![container_resource(reference, limit)]).unwrap()
}

fn container_resource(reference: u64, limit: Option<PidsLimit>) -> TargetResource {
    TargetResource::Container(Box::new(ContainerIntent {
        reference: ResourceRef::new(reference),
        identity: TargetIdentity::new(b"private-owner-canary".to_vec()).unwrap(),
        image: ImageReference::new(b"image:1".to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Inherit,
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            pids_limit: limit,
            ..ContainerSettings::default()
        },
    }))
}

fn finite() -> Option<PidsLimit> {
    Some(PidsLimit::Count(NonZeroU64::new(16).unwrap()))
}

fn facts(mode: DaemonMode) -> DaemonFacts {
    let observation_id = ObservationId::fresh().unwrap();
    let release = EngineRelease::new("20.10.5".into()).unwrap();
    let scope = CapabilityScope {
        observation_id,
        release: release.clone(),
        api_version: api(41),
        mode,
    };
    DaemonFacts {
        observation_id,
        release: Some(release),
        api_version: Some(api(41)),
        minimum_api_version: None,
        mode,
        capabilities: [
            Capability::StandaloneContainer,
            Capability::PidsLimit,
            Capability::BridgeNetwork,
            Capability::NetworkExternalReference,
            Capability::NetworkExternalInternalExpectation,
            Capability::NamedVolume,
            Capability::VolumeExternalReference,
            Capability::BindMount,
            Capability::BindRelabelPrivate,
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

fn render(mode: DaemonMode, reference: u64, limit: Option<PidsLimit>) -> RenderedArtifact {
    let facts = facts(mode);
    let capabilities = ValidatedCapabilities::new(&facts).unwrap();
    DockerApiRenderer
        .render(
            &DockerPlanner
                .plan(&target(reference, limit), &capabilities)
                .unwrap(),
        )
        .unwrap()
}

fn snapshot() -> DecodedInventory {
    let mut daemon = facts(DaemonMode::Rootless);
    daemon.capabilities.clear();
    let observation_id = daemon.observation_id;
    let mut reports = ResourceSupportObservation::missing(observation_id);
    reports.pids_limit = Observed::present(true, Availability::Present, Origin::Effective);
    reports.cgroup_driver = text(b"systemd", Availability::Present, Origin::Effective);
    reports.cgroup_version = text(b"2", Availability::Present, Origin::Effective);
    DecodedInventory {
        observation_id,
        version: DecodedVersion {
            daemon,
            resource_support: reports,
            client_release: None,
            distribution_package_revision: None,
            requested_api_versions: vec![api(41)],
        },
        containers: vec![],
        discovered_containers: vec![],
        selected_roots: vec![],
        networks: vec![],
        volumes: vec![],
        findings: vec![],
    }
}

fn matching_snapshot(obligation: &DestinationPidsPrerequisite) -> DecodedInventory {
    let mut inventory = snapshot();
    if let PlanningContext::Observed(scope) = obligation.context() {
        inventory.observation_id = scope.observation_id;
        inventory.version.daemon.observation_id = scope.observation_id;
        inventory.version.resource_support.observation_id = scope.observation_id;
    }
    inventory
}

fn text(bytes: &[u8], availability: Availability, origin: Origin) -> Observed<ProtectedValue> {
    Observed::present(ProtectedValue::new(bytes.to_vec()), availability, origin)
}

#[test]
fn finite_rootless_obligation_has_closed_schema_four_and_protected_owner_binding() {
    let artifact = render(DaemonMode::Rootless, u64::MAX, finite());
    let row = &artifact.destination_pids_prerequisites()[0];
    assert_eq!(row.reference, ResourceRef::new(u64::MAX));
    assert_eq!(row.identity(), b"private-owner-canary");
    assert_eq!(row.pids_limit().get(), 16);
    assert_eq!(Some(row.context()), artifact.context());
    let document: Value = serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
    assert_eq!(document["schema_version"], 4);
    assert_eq!(
        document["prerequisites"],
        json!([{
            "kind":"rootless_pids", "reference":"18446744073709551615", "identity":"private-owner-canary",
            "pids_limit":"16", "required_cgroup_driver":"systemd", "required_cgroup_version":"2",
            "required_pids_report":true, "delegation":"unverified", "enforcement":"unverified"
        }])
    );
    assert_eq!(
        document["requests"],
        json!([{"method":"POST", "path":"/v1.41/containers/create?name=private-owner-canary",
        "body":{"Image":"image:1", "HostConfig":{"PidsLimit":16}}}])
    );
    assert_eq!(artifact.bytes(), b"{\"method\":\"POST\",\"path\":\"/v1.41/containers/create?name=private-owner-canary\",\"body\":{\"Image\":\"image:1\",\"HostConfig\":{\"PidsLimit\":16}}}\n");
    assert!(!format!("{row:?}").contains("private-owner-canary"));
    assert!(!format!("{row:?}").contains("pids_limit: 16"));
    assert!(!format!("{artifact:?}").contains("private-owner-canary"));
    let renamed = render(DaemonMode::Rootless, 7, finite());
    assert_eq!(renamed.bytes(), artifact.bytes());
    assert_eq!(
        renamed.destination_pids_prerequisites()[0].identity(),
        row.identity()
    );
}

#[test]
fn finite_rootless_counts_keep_checked_integer_boundaries_and_string_precision() {
    for count in [1, i64::MAX as u64] {
        let artifact = render(
            DaemonMode::Rootless,
            1,
            Some(PidsLimit::Count(NonZeroU64::new(count).unwrap())),
        );
        let document: Value = serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
        assert_eq!(
            document["prerequisites"][0]["pids_limit"],
            count.to_string()
        );
        assert_eq!(
            document["requests"][0]["body"]["HostConfig"]["PidsLimit"],
            json!(count)
        );
        assert_eq!(
            artifact.destination_pids_prerequisites()[0]
                .pids_limit()
                .get(),
            count
        );
    }
    assert!(
        TargetIntent::new(vec![container_resource(
            1,
            Some(PidsLimit::Count(
                NonZeroU64::new(i64::MAX as u64 + 1).unwrap()
            ))
        )])
        .is_err()
    );
}

#[test]
fn absent_unlimited_and_rootful_finite_keep_literal_schema_one_and_request_bytes() {
    for (mode, limit, mode_text, host) in [
        (DaemonMode::Rootless, None, "rootless", ",\"HostConfig\":{}"),
        (
            DaemonMode::Rootless,
            Some(PidsLimit::Unlimited),
            "rootless",
            ",\"HostConfig\":{\"PidsLimit\":-1}",
        ),
        (
            DaemonMode::Rootful,
            finite(),
            "rootful",
            ",\"HostConfig\":{\"PidsLimit\":16}",
        ),
        (DaemonMode::Rootful, None, "rootful", ",\"HostConfig\":{}"),
        (
            DaemonMode::Rootful,
            Some(PidsLimit::Unlimited),
            "rootful",
            ",\"HostConfig\":{\"PidsLimit\":-1}",
        ),
    ] {
        let artifact = render(mode, 1, limit);
        assert!(artifact.destination_pids_prerequisites().is_empty());
        let request = format!(
            "{{\"method\":\"POST\",\"path\":\"/v1.41/containers/create?name=private-owner-canary\",\"body\":{{\"Image\":\"image:1\"{host}}}}}"
        );
        assert_eq!(artifact.bytes(), format!("{request}\n").as_bytes());
        let expected = format!(
            "{{\"schema_version\":1,\"context\":{{\"kind\":\"observed\",\"provenance\":\"process_local_only\",\"engine_release\":\"20.10.5\",\"api_version\":\"1.41\",\"daemon_mode\":\"{mode_text}\"}},\"requests\":[{request}],\"prerequisites\":[]}}\n"
        );
        assert_eq!(artifact.complete_bytes().unwrap(), expected.as_bytes());
    }
    let opaque = RenderedArtifact::new(vec![]);
    assert!(opaque.destination_pids_prerequisites().is_empty());
    assert_eq!(
        opaque.complete_bytes(),
        Err(CompleteArtifactError::MissingNativeProvenance)
    );
}

#[test]
fn schema_four_keeps_network_volume_bind_and_container_order_without_metadata_leaks() {
    let mut resources = vec![container_resource(3, finite())];
    let TargetResource::Container(container) = &mut resources[0] else {
        panic!("container")
    };
    container.networks.push(NetworkAttachmentIntent {
        network: ResourceRef::new(1),
        aliases: vec![],
        ipv4_address: None,
        ipv6_address: None,
    });
    container.mounts = vec![
        Mount::volume(ResourceRef::new(2), b"/volume".to_vec(), false).unwrap(),
        Mount::bind(b"/private-source-canary".to_vec(), b"/data".to_vec(), true)
            .unwrap()
            .with_bind_relabel(BindRelabel::Private)
            .unwrap(),
    ];
    resources.insert(
        0,
        TargetResource::ExternalVolume {
            reference: ResourceRef::new(2),
            identity: TargetIdentity::new(b"data".to_vec()).unwrap(),
        },
    );
    resources.insert(
        0,
        TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"edge".to_vec()).unwrap(),
            role: NetworkRole::Declared,
            source: NetworkSource::External {
                expected_driver: NetworkDriver::Bridge,
                expected_internal: Some(false),
            },
        }),
    );
    let intent = TargetIntent::new(resources).unwrap();
    let facts = facts(DaemonMode::Rootless);
    let capabilities = ValidatedCapabilities::new(&facts).unwrap();
    let artifact = DockerApiRenderer
        .render(&DockerPlanner.plan(&intent, &capabilities).unwrap())
        .unwrap();
    let document: Value = serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
    assert_eq!(document["schema_version"], 4);
    assert_eq!(
        document["prerequisites"],
        json!([
            {"kind":"network","reference":"1","identity":"edge","expected_driver":"bridge","expected_internal":false},
            {"kind":"volume","reference":"2","identity":"data"},
            {"kind":"rootless_pids","reference":"3","identity":"private-owner-canary","pids_limit":"16",
             "required_cgroup_driver":"systemd","required_cgroup_version":"2","required_pids_report":true,"delegation":"unverified","enforcement":"unverified"},
            {"kind":"bind_source","reference":"3","identity":"private-owner-canary","mount_index":"1",
             "source":"/private-source-canary","target":"/data","read_only":true,"relabel":"private",
             "source_conditions":["exists","type_reviewed","contents_reviewed","ownership_reviewed","permissions_reviewed"],
             "selinux_effect":"unverified","selinux_conditions":["daemon_selinux_enabled","container_mount_label_present","policy_filesystem_support","relabel_authority"]}
        ])
    );
    assert_eq!(document["requests"].as_array().unwrap().len(), 1);
    assert_eq!(
        document["requests"][0]["body"]["HostConfig"]["PidsLimit"],
        16
    );
    assert_eq!(
        document["requests"][0]["body"]["HostConfig"]["Binds"],
        json!(["/private-source-canary:/data:ro,Z"])
    );
    assert_eq!(artifact.network_prerequisites().len(), 1);
    assert_eq!(artifact.volume_prerequisites().len(), 1);
    assert_eq!(artifact.bind_source_prerequisites().len(), 1);
    assert_eq!(artifact.destination_pids_prerequisites().len(), 1);
}

#[test]
fn each_finite_container_keeps_its_own_name_reference_and_limit_in_planning_order() {
    let first = container_resource(7, finite());
    let mut second = container_resource(9, Some(PidsLimit::Count(NonZeroU64::new(64).unwrap())));
    let TargetResource::Container(container) = &mut second else {
        panic!("container")
    };
    container.identity = TargetIdentity::new(b"second-owner".to_vec()).unwrap();
    let mut unlimited = container_resource(8, Some(PidsLimit::Unlimited));
    let TargetResource::Container(container) = &mut unlimited else {
        panic!("container")
    };
    container.identity = TargetIdentity::new(b"unlimited-owner".to_vec()).unwrap();
    let intent = TargetIntent::new(vec![first, unlimited, second]).unwrap();
    let facts = facts(DaemonMode::Rootless);
    let capabilities = ValidatedCapabilities::new(&facts).unwrap();
    let artifact = DockerApiRenderer
        .render(&DockerPlanner.plan(&intent, &capabilities).unwrap())
        .unwrap();
    let rows = artifact.destination_pids_prerequisites();
    assert_eq!(rows.len(), 2);
    for (row, reference, identity, count) in [
        (&rows[0], 7, b"private-owner-canary".as_slice(), 16),
        (&rows[1], 9, b"second-owner".as_slice(), 64),
    ] {
        assert_eq!(row.reference, ResourceRef::new(reference));
        assert_eq!(row.identity(), identity);
        assert_eq!(row.pids_limit().get(), count);
        assert_eq!(Some(row.context()), artifact.context());
    }
    let document: Value = serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
    assert_eq!(document["requests"].as_array().unwrap().len(), 3);
    assert_eq!(
        document["prerequisites"][0]["identity"],
        "private-owner-canary"
    );
    assert_eq!(document["prerequisites"][1]["identity"], "second-owner");
    assert_eq!(document["prerequisites"][1]["pids_limit"], "64");
}

#[test]
fn absent_finite_rootless_obligation_keeps_literal_schema_three_bytes() {
    let intent = TargetIntent::new(vec![TargetResource::Network(NetworkIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(b"edge".to_vec()).unwrap(),
        role: NetworkRole::Declared,
        source: NetworkSource::External {
            expected_driver: NetworkDriver::Bridge,
            expected_internal: Some(false),
        },
    })])
    .unwrap();
    let facts = facts(DaemonMode::Rootless);
    let capabilities = ValidatedCapabilities::new(&facts).unwrap();
    let artifact = DockerApiRenderer
        .render(&DockerPlanner.plan(&intent, &capabilities).unwrap())
        .unwrap();
    assert_eq!(artifact.complete_bytes().unwrap(), b"{\"schema_version\":3,\"context\":{\"kind\":\"observed\",\"provenance\":\"process_local_only\",\"engine_release\":\"20.10.5\",\"api_version\":\"1.41\",\"daemon_mode\":\"rootless\"},\"requests\":[],\"prerequisites\":[{\"kind\":\"network\",\"reference\":\"1\",\"identity\":\"edge\",\"expected_driver\":\"bridge\",\"expected_internal\":false}]}\n");
    assert!(artifact.destination_pids_prerequisites().is_empty());
    assert!(artifact.bytes().is_empty());
}

#[test]
fn explicit_destination_selection_never_resolves_delegation_or_enforcement() {
    let artifact = render(DaemonMode::Rootless, 1, finite());
    let obligation = &artifact.destination_pids_prerequisites()[0];
    let inventory = snapshot();
    let PlanningContext::Observed(source) = obligation.context() else {
        panic!("observed context")
    };
    assert_ne!(source.observation_id, inventory.observation_id);
    assert_eq!(
        obligation.assess(&inventory, source.observation_id),
        Err(DestinationPidsPrerequisiteError::ObservationScopeMismatch)
    );
    assert_eq!(
        obligation.assess(&inventory, inventory.observation_id),
        Err(DestinationPidsPrerequisiteError::ObservationScopeMismatch)
    );
    let matching = matching_snapshot(obligation);
    assert_eq!(
        obligation.assess(&matching, matching.observation_id),
        Ok(DestinationPidsAssessment::MetadataCompatibleDelegationAndEnforcementUnverified)
    );
    for scope in 0..3 {
        let mut changed = matching_snapshot(obligation);
        let expected = changed.observation_id;
        let different = ObservationId::fresh().unwrap();
        match scope {
            0 => changed.observation_id = different,
            1 => changed.version.daemon.observation_id = different,
            _ => changed.version.resource_support.observation_id = different,
        }
        assert_eq!(
            obligation.assess(&changed, expected),
            Err(DestinationPidsPrerequisiteError::ObservationScopeMismatch)
        );
    }
}

#[test]
fn metadata_availability_origin_and_valueless_cross_products_refuse() {
    let artifact = render(DaemonMode::Rootless, 1, finite());
    let obligation = &artifact.destination_pids_prerequisites()[0];
    for availability in [
        Availability::Missing,
        Availability::Null,
        Availability::Empty,
        Availability::Present,
        Availability::Redacted,
    ] {
        for origin in [
            Origin::Configured,
            Origin::Effective,
            Origin::RuntimeAssigned,
            Origin::Unknown,
        ] {
            for field in 0..3 {
                for has_value in [false, true] {
                    let mut inventory = matching_snapshot(obligation);
                    let reports = &mut inventory.version.resource_support;
                    match field {
                        0 => {
                            reports.pids_limit = if has_value {
                                Observed::present(true, availability, origin)
                            } else {
                                Observed::unavailable(availability, origin)
                            }
                        }
                        1 => {
                            reports.cgroup_driver = if has_value {
                                text(b"systemd", availability, origin)
                            } else {
                                Observed::unavailable(availability, origin)
                            }
                        }
                        _ => {
                            reports.cgroup_version = if has_value {
                                text(b"2", availability, origin)
                            } else {
                                Observed::unavailable(availability, origin)
                            }
                        }
                    }
                    let result = obligation.assess(&inventory, inventory.observation_id);
                    if availability == Availability::Present
                        && origin == Origin::Effective
                        && has_value
                    {
                        assert_eq!(result, Ok(DestinationPidsAssessment::MetadataCompatibleDelegationAndEnforcementUnverified));
                    } else {
                        let expected = match field {
                            0 => DestinationPidsPrerequisiteError::PidsReportIncompatible,
                            1 => DestinationPidsPrerequisiteError::CgroupDriverIncompatible,
                            _ => DestinationPidsPrerequisiteError::CgroupVersionIncompatible,
                        };
                        assert_eq!(result, Err(expected));
                    }
                }
            }
        }
    }
}

#[test]
fn false_driver_none_cgroupfs_v1_and_lexical_near_misses_are_not_compatible() {
    let artifact = render(DaemonMode::Rootless, 1, finite());
    let obligation = &artifact.destination_pids_prerequisites()[0];
    let mut inventory = matching_snapshot(obligation);
    inventory.version.resource_support.pids_limit =
        Observed::present(false, Availability::Present, Origin::Effective);
    assert_eq!(
        obligation.assess(&inventory, inventory.observation_id),
        Err(DestinationPidsPrerequisiteError::PidsReportIncompatible)
    );
    for driver in [
        b"none".as_slice(),
        b"cgroupfs",
        b"Systemd",
        b"systemd ",
        b"",
        b"private-driver-canary",
    ] {
        let mut inventory = matching_snapshot(obligation);
        inventory.version.resource_support.cgroup_driver =
            text(driver, Availability::Present, Origin::Effective);
        let error = obligation
            .assess(&inventory, inventory.observation_id)
            .unwrap_err();
        assert_eq!(
            error,
            DestinationPidsPrerequisiteError::CgroupDriverIncompatible
        );
        assert!(!format!("{error:?}").contains("private-driver-canary"));
    }
    for version in [
        b"1".as_slice(),
        b"02",
        b"2 ",
        b"",
        b"private-version-canary",
    ] {
        let mut inventory = matching_snapshot(obligation);
        inventory.version.resource_support.cgroup_version =
            text(version, Availability::Present, Origin::Effective);
        let error = obligation
            .assess(&inventory, inventory.observation_id)
            .unwrap_err();
        assert_eq!(
            error,
            DestinationPidsPrerequisiteError::CgroupVersionIncompatible
        );
        assert!(!format!("{error:?}").contains("private-version-canary"));
    }
}

#[test]
fn observed_context_rejects_missing_changed_identity_ranges_and_unbounded_versions() {
    let artifact = render(DaemonMode::Rootless, 1, finite());
    let obligation = &artifact.destination_pids_prerequisites()[0];
    for (case, expected) in [
        (0, DestinationPidsPrerequisiteError::ReleaseMismatch),
        (1, DestinationPidsPrerequisiteError::ReleaseMismatch),
        (2, DestinationPidsPrerequisiteError::ApiVersionMismatch),
        (3, DestinationPidsPrerequisiteError::ApiVersionMismatch),
        (4, DestinationPidsPrerequisiteError::ModeMismatch),
        (5, DestinationPidsPrerequisiteError::ModeMismatch),
        (6, DestinationPidsPrerequisiteError::ApiRangeMismatch),
        (7, DestinationPidsPrerequisiteError::ApiRangeMismatch),
        (8, DestinationPidsPrerequisiteError::AcquisitionApiMismatch),
        (9, DestinationPidsPrerequisiteError::CollectionTooLarge),
    ] {
        let mut inventory = matching_snapshot(obligation);
        match case {
            0 => inventory.version.daemon.release = None,
            1 => {
                inventory.version.daemon.release =
                    EngineRelease::new("private-release-canary".into())
            }
            2 => inventory.version.daemon.api_version = None,
            3 => inventory.version.daemon.api_version = Some(api(42)),
            4 => inventory.version.daemon.mode = DaemonMode::Rootful,
            5 => inventory.version.daemon.mode = DaemonMode::Unknown,
            6 => inventory.version.daemon.minimum_api_version = Some(api(42)),
            7 => inventory.version.requested_api_versions = vec![api(42)],
            8 => inventory.version.requested_api_versions.clear(),
            _ => inventory.version.requested_api_versions = vec![api(41); 4097],
        }
        let error = obligation
            .assess(&inventory, inventory.observation_id)
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!format!("{error:?}").contains("private-release-canary"));
    }
    let mut inventory = matching_snapshot(obligation);
    inventory.version.daemon.minimum_api_version = Some(api(41));
    assert!(
        obligation
            .assess(&inventory, inventory.observation_id)
            .is_ok()
    );
    inventory.version.daemon.minimum_api_version = Some(api(40));
    inventory.version.requested_api_versions = vec![api(39)];
    assert_eq!(
        obligation.assess(&inventory, inventory.observation_id),
        Err(DestinationPidsPrerequisiteError::ApiRangeMismatch)
    );
}

#[test]
fn offline_context_checks_observable_projection_without_claiming_build_authentication() {
    for mut record in crate::reviewed_catalog::records()
        .into_iter()
        .filter(|record| record.profile.mode() == DaemonMode::Rootless)
    {
        // Local complete-shape positive control only, never a native admission.
        record.capabilities.push(TargetCapabilityFact {
            capability: Capability::PidsLimit,
            state: CapabilityState::Available,
        });
        record
            .admitted_shapes
            .extend(NativeCapabilityShape::required_for(Capability::PidsLimit).unwrap());
        let profile = record.profile.clone();
        let catalog = TargetCapabilityCatalog::from_test_records(vec![record]).unwrap();
        let capabilities = catalog.resolve(&profile).unwrap();
        let artifact = DockerApiRenderer
            .render(
                &DockerPlanner
                    .plan(&target(1, finite()), &capabilities)
                    .unwrap(),
            )
            .unwrap();
        let obligation = &artifact.destination_pids_prerequisites()[0];
        assert_eq!(
            obligation.context(),
            &PlanningContext::Target(profile.clone())
        );
        let mut inventory = snapshot();
        inventory.version.daemon.release = Some(profile.release().clone());
        inventory.version.daemon.api_version = Some(profile.identity().advertised_api_version());
        inventory.version.requested_api_versions =
            vec![profile.identity().acquisition_api_version()];
        assert!(inventory.version.distribution_package_revision.is_none());
        assert_eq!(
            obligation.assess(&inventory, inventory.observation_id),
            Ok(DestinationPidsAssessment::MetadataCompatibleDelegationAndEnforcementUnverified)
        );
        assert_eq!(
            obligation.assess(&inventory, ObservationId::fresh().unwrap()),
            Err(DestinationPidsPrerequisiteError::ObservationScopeMismatch)
        );
        inventory.version.requested_api_versions = vec![api(40)];
        assert_eq!(
            obligation.assess(&inventory, inventory.observation_id),
            Err(DestinationPidsPrerequisiteError::AcquisitionApiMismatch)
        );
        inventory.version.requested_api_versions =
            vec![profile.identity().acquisition_api_version(), api(40)];
        assert_eq!(
            obligation.assess(&inventory, inventory.observation_id),
            Err(DestinationPidsPrerequisiteError::AcquisitionApiMismatch)
        );
        inventory.version.requested_api_versions =
            vec![profile.identity().acquisition_api_version()];
        inventory.version.daemon.minimum_api_version = Some(profile.rendering_api_version());
        if profile.identity().acquisition_api_version() < profile.rendering_api_version() {
            assert_eq!(
                obligation.assess(&inventory, inventory.observation_id),
                Err(DestinationPidsPrerequisiteError::ApiRangeMismatch)
            );
        }
    }
}
