//! Authored configured-intent controls, not native compatibility or effects.

use super::*;
use crate::observation::{BindRelabel, ResourceRef};
use crate::target::{
    ContainerIntent, ContainerSettings, DockerPlanner, ImageCommand, ImageReference, IntentError,
    Mount, Planner, PlanningError, TargetField, TargetIdentity, TargetIntent, TargetResource,
};
use crate::version::{
    Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonFacts, FactProvenance,
    NativeCapabilityShape, ObservationId, TargetCapabilityCatalog, ValidatedCapabilities,
};
use serde_json::{Value, json};
use std::num::NonZeroU16;

fn intent(reference: ResourceRef, mounts: Vec<Mount>) -> Result<TargetIntent, IntentError> {
    TargetIntent::new(vec![container(reference, mounts)])
}

fn container(reference: ResourceRef, mounts: Vec<Mount>) -> TargetResource {
    TargetResource::Container(Box::new(ContainerIntent {
        reference,
        identity: TargetIdentity::new(b"app".to_vec()).unwrap(),
        image: ImageReference::new(b"example.invalid/image:1".to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts,
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Inherit,
        healthcheck: None,
        restart: None,
        settings: ContainerSettings::default(),
    }))
}

fn facts(api_minor: u16, mode: DaemonMode, capabilities: &[Capability]) -> DaemonFacts {
    let observation_id = ObservationId::fresh().unwrap();
    let release = crate::version::EngineRelease::new(if api_minor == 41 {
        "20.10.5".to_owned()
    } else {
        "29.8.1".to_owned()
    })
    .unwrap();
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

fn render(target: &TargetIntent, api: u16, mode: DaemonMode) -> RenderedArtifact {
    let facts = facts(
        api,
        mode,
        &[
            Capability::StandaloneContainer,
            Capability::BindMount,
            Capability::BindRelabelShared,
            Capability::BindRelabelPrivate,
        ],
    );
    let validated = ValidatedCapabilities::new(&facts).unwrap();
    let graph = DockerPlanner.plan(target, &validated).unwrap();
    DockerApiRenderer.render(&graph).unwrap()
}

#[test]
fn four_literal_relabel_modes_keep_requests_and_conditional_prerequisites() {
    for (api, mode) in [
        (41, DaemonMode::Rootful),
        (41, DaemonMode::Rootless),
        (56, DaemonMode::Rootful),
        (56, DaemonMode::Rootless),
    ] {
        for (read_only, relabel, suffix, name) in [
            (true, BindRelabel::Shared, "ro,z", "shared"),
            (false, BindRelabel::Shared, "rw,z", "shared"),
            (true, BindRelabel::Private, "ro,Z", "private"),
            (false, BindRelabel::Private, "rw,Z", "private"),
        ] {
            let mount = Mount::bind(
                b"/unverified-source".to_vec(),
                b"/destination".to_vec(),
                read_only,
            )
            .unwrap()
            .with_bind_relabel(relabel)
            .unwrap();
            let target = intent(ResourceRef::new(u64::MAX), vec![mount]).unwrap();
            let artifact = render(&target, api, mode);
            let request: Value = serde_json::from_slice(artifact.bytes()).unwrap();
            assert_eq!(
                request["path"],
                format!("/v1.{api}/containers/create?name=app")
            );
            assert_eq!(
                request["body"]["HostConfig"],
                json!({
                    "Binds": [format!("/unverified-source:/destination:{suffix}")],
                })
            );
            let bytes = artifact.complete_bytes().unwrap();
            assert_eq!(bytes.last(), Some(&b'\n'));
            let document: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(document["schema_version"], 2);
            assert_eq!(document["requests"], json!([request]));
            assert_eq!(
                document["prerequisites"],
                json!([{
                    "kind": "bind_source", "reference": "18446744073709551615", "identity": "app", "mount_index": "0",
                    "source": "/unverified-source", "target": "/destination",
                    "read_only": read_only, "relabel": name,
                    "source_conditions": ["exists", "type_reviewed", "contents_reviewed", "ownership_reviewed", "permissions_reviewed"],
                    "selinux_effect": "unverified",
                    "selinux_conditions": ["daemon_selinux_enabled", "container_mount_label_present", "policy_filesystem_support", "relabel_authority"],
                }])
            );
            let prerequisite = &artifact.bind_source_prerequisites()[0];
            assert_eq!(prerequisite.reference, ResourceRef::new(u64::MAX));
            assert_eq!(prerequisite.mount_index, 0);
            assert_eq!(prerequisite.identity(), b"app");
            assert_eq!(prerequisite.source(), b"/unverified-source");
            assert_eq!(prerequisite.target(), b"/destination");
            assert_eq!(prerequisite.read_only(), read_only);
            assert_eq!(prerequisite.relabel(), relabel);
            assert_eq!(
                prerequisite.source_conditions(),
                &[
                    BindSourceCondition::Exists,
                    BindSourceCondition::TypeReviewed,
                    BindSourceCondition::ContentsReviewed,
                    BindSourceCondition::OwnershipReviewed,
                    BindSourceCondition::PermissionsReviewed,
                ]
            );
            assert_eq!(
                prerequisite.selinux_conditions(),
                &[
                    BindRelabelCondition::DaemonSelinuxEnabled,
                    BindRelabelCondition::ContainerMountLabelPresent,
                    BindRelabelCondition::PolicyFilesystemSupport,
                    BindRelabelCondition::RelabelAuthority,
                ]
            );
        }
    }
}

#[test]
fn mixed_mounts_keep_original_indexes_and_structured_path_domain() {
    let plain = Mount::bind(b"/source:colon".to_vec(), b"/plain:target".to_vec(), true).unwrap();
    let relabel = Mount::bind(
        "/private source\"\\,Ω\n".as_bytes().to_vec(),
        b"/relabel-target".to_vec(),
        false,
    )
    .unwrap()
    .with_bind_relabel(BindRelabel::Shared)
    .unwrap();
    let tmpfs = Mount::tmpfs(b"/tmp".to_vec(), false, Default::default()).unwrap();
    let target = intent(ResourceRef::new(1), vec![plain, relabel, tmpfs]).unwrap();
    let mut available = facts(
        41,
        DaemonMode::Rootful,
        &[
            Capability::StandaloneContainer,
            Capability::BindMount,
            Capability::BindRelabelShared,
            Capability::TmpfsMount,
        ],
    );
    let validated = ValidatedCapabilities::new(&available).unwrap();
    let graph = DockerPlanner.plan(&target, &validated).unwrap();
    let artifact = DockerApiRenderer.render(&graph).unwrap();
    let body: Value = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(
        body["body"]["HostConfig"]["Binds"],
        json!(["/private source\"\\,Ω\n:/relabel-target:rw,z"])
    );
    assert_eq!(
        body["body"]["HostConfig"]["Mounts"],
        json!([
            {"Type":"bind","Source":"/source:colon","Target":"/plain:target","ReadOnly":true},
            {"Type":"tmpfs","Target":"/tmp","ReadOnly":false},
        ])
    );
    assert_eq!(artifact.bind_source_prerequisites()[0].mount_index, 1);
    assert!(
        !format!("{artifact:?} {:?}", artifact.bind_source_prerequisites())
            .contains("private source")
    );
    available
        .capabilities
        .retain(|fact| fact.capability != Capability::BindRelabelShared);
    let validated = ValidatedCapabilities::new(&available).unwrap();
    assert!(matches!(
        DockerPlanner.plan(&target, &validated),
        Err(PlanningError::MissingCapability {
            field: TargetField::BindRelabel,
            capability: Capability::BindRelabelShared,
            ..
        })
    ));
}

#[test]
fn default_absence_keeps_exact_v1_request_and_complete_bytes() {
    let mount = Mount::bind(b"/plain:source".to_vec(), b"/plain:target".to_vec(), true).unwrap();
    assert_eq!(mount.bind_relabel(), None);
    let target = intent(ResourceRef::new(1), vec![mount]).unwrap();
    let artifact = render(&target, 41, DaemonMode::Rootful);
    assert_eq!(artifact.bytes(), br#"{"method":"POST","path":"/v1.41/containers/create?name=app","body":{"Image":"example.invalid/image:1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/plain:source","Target":"/plain:target","ReadOnly":true}]}}}
"#);
    assert_eq!(artifact.complete_bytes().unwrap(), br#"{"schema_version":1,"context":{"kind":"observed","provenance":"process_local_only","engine_release":"20.10.5","api_version":"1.41","daemon_mode":"rootful"},"requests":[{"method":"POST","path":"/v1.41/containers/create?name=app","body":{"Image":"example.invalid/image:1","HostConfig":{"Mounts":[{"Type":"bind","Source":"/plain:source","Target":"/plain:target","ReadOnly":true}]}}}],"prerequisites":[]}
"#);
    let document: Value = serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["prerequisites"], json!([]));
    assert!(artifact.bind_source_prerequisites().is_empty());
    assert!(
        RenderedArtifact::new(artifact.bytes().to_vec())
            .complete_bytes()
            .is_err()
    );
}

#[test]
fn external_volume_and_relabel_prerequisites_keep_dependency_order() {
    let volume_reference = ResourceRef::new(2);
    let mounts = vec![
        Mount::volume(volume_reference, b"/data".to_vec(), true).unwrap(),
        Mount::bind(b"/first".to_vec(), b"/first-target".to_vec(), true)
            .unwrap()
            .with_bind_relabel(BindRelabel::Private)
            .unwrap(),
        Mount::bind(b"/second".to_vec(), b"/second-target".to_vec(), false)
            .unwrap()
            .with_bind_relabel(BindRelabel::Shared)
            .unwrap(),
    ];
    let target = TargetIntent::new(vec![
        container(ResourceRef::new(1), mounts),
        TargetResource::ExternalVolume {
            reference: volume_reference,
            identity: TargetIdentity::new(b"existing-data".to_vec()).unwrap(),
        },
    ])
    .unwrap();
    let available = facts(
        41,
        DaemonMode::Rootful,
        &[
            Capability::StandaloneContainer,
            Capability::BindMount,
            Capability::BindRelabelShared,
            Capability::BindRelabelPrivate,
            Capability::NamedVolume,
            Capability::VolumeExternalReference,
        ],
    );
    let validated = ValidatedCapabilities::new(&available).unwrap();
    let graph = DockerPlanner.plan(&target, &validated).unwrap();
    let artifact = DockerApiRenderer.render(&graph).unwrap();
    let body: Value = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(
        body["body"]["HostConfig"]["Mounts"],
        json!([
            {"Type":"volume","Source":"existing-data","Target":"/data","ReadOnly":true},
        ])
    );
    assert_eq!(
        body["body"]["HostConfig"]["Binds"],
        json!(["/first:/first-target:ro,Z", "/second:/second-target:rw,z",])
    );
    let complete: Value = serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
    let prerequisites = complete["prerequisites"].as_array().unwrap();
    assert_eq!(prerequisites.len(), 3);
    assert_eq!(
        prerequisites[0],
        json!({"kind":"volume","reference":"2","identity":"existing-data"})
    );
    assert_eq!(prerequisites[1]["kind"], "bind_source");
    assert_eq!(prerequisites[1]["mount_index"], "1");
    assert_eq!(prerequisites[1]["identity"], "app");
    assert_eq!(prerequisites[2]["kind"], "bind_source");
    assert_eq!(prerequisites[2]["mount_index"], "2");
    assert_eq!(prerequisites[2]["identity"], "app");
}

#[test]
fn bind_source_rows_keep_container_identity_across_reference_renaming_and_repeated_mount_indexes() {
    let names = ["private-target_a", "private-target_b"];
    let mut previous_requests: Option<Vec<u8>> = None;
    for (references, serialized_references) in [
        ([0, 1], ["0", "1"]),
        (
            [u64::MAX, 9_007_199_254_740_993],
            ["18446744073709551615", "9007199254740993"],
        ),
        ([73, 2], ["73", "2"]),
    ] {
        let mut resources = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let mounts = vec![
                Mount::bind(
                    b"/private-shared-first".to_vec(),
                    b"/same-first".to_vec(),
                    false,
                )
                .unwrap()
                .with_bind_relabel(BindRelabel::Shared)
                .unwrap(),
                Mount::bind(
                    b"/private-shared-second".to_vec(),
                    b"/same-second".to_vec(),
                    true,
                )
                .unwrap()
                .with_bind_relabel(BindRelabel::Private)
                .unwrap(),
            ];
            let TargetResource::Container(mut target) =
                container(ResourceRef::new(references[index]), mounts)
            else {
                unreachable!()
            };
            target.identity = TargetIdentity::new(name.as_bytes().to_vec()).unwrap();
            resources.push(TargetResource::Container(target));
        }
        let target = TargetIntent::new(resources).unwrap();
        let artifact = render(&target, 41, DaemonMode::Rootful);
        if let Some(requests) = &previous_requests {
            assert_eq!(artifact.bytes(), requests.as_slice());
        }
        previous_requests = Some(artifact.bytes().to_vec());
        let complete: Value = serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
        assert_eq!(complete["schema_version"], 2);
        let requests = complete["requests"].as_array().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0]["path"],
            "/v1.41/containers/create?name=private-target_a"
        );
        assert_eq!(
            requests[1]["path"],
            "/v1.41/containers/create?name=private-target_b"
        );
        // Entire request bodies are identical: the association cannot use
        // source, destination, access, relabel mode or mount index as a key.
        assert_eq!(requests[0]["body"], requests[1]["body"]);
        assert_eq!(
            requests[0]["body"]["HostConfig"]["Binds"],
            json!([
                "/private-shared-first:/same-first:rw,z",
                "/private-shared-second:/same-second:ro,Z",
            ])
        );
        let rows = complete["prerequisites"].as_array().unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(artifact.bind_source_prerequisites().len(), 4);
        for (row_index, row) in rows.iter().enumerate() {
            let container_index = row_index / 2;
            let mount_index = row_index % 2;
            assert_eq!(row["kind"], "bind_source");
            assert_eq!(row["identity"], names[container_index]);
            assert_eq!(row["reference"], serialized_references[container_index]);
            assert_eq!(row["mount_index"], ["0", "1"][mount_index]);
            assert_eq!(
                row["source"],
                ["/private-shared-first", "/private-shared-second"][mount_index]
            );
            assert_eq!(
                row["target"],
                if mount_index == 0 {
                    "/same-first"
                } else {
                    "/same-second"
                }
            );
            assert_eq!(row["read_only"], mount_index == 1);
            assert_eq!(row["relabel"], ["shared", "private"][mount_index]);
            let typed = &artifact.bind_source_prerequisites()[row_index];
            assert_eq!(typed.identity(), names[container_index].as_bytes());
            assert_eq!(
                typed.reference,
                ResourceRef::new(references[container_index])
            );
            assert_eq!(typed.mount_index, mount_index);
            let debug = format!("{artifact:?} {typed:?}");
            for protected in [
                names[0],
                names[1],
                "private-shared",
                "same-first",
                "same-second",
            ] {
                assert!(!debug.contains(protected));
            }
            assert!(format!("{typed:?}").contains("identity: \"[redacted]\""));
        }
    }
}

#[test]
fn non_bind_duplicate_modes_colon_paths_and_cross_field_destinations_fail_closed() {
    assert!(
        Mount::volume(ResourceRef::new(1), b"/volume".to_vec(), false)
            .unwrap()
            .with_bind_relabel(BindRelabel::Shared)
            .is_err()
    );
    assert!(
        Mount::tmpfs(b"/tmp".to_vec(), false, Default::default())
            .unwrap()
            .with_bind_relabel(BindRelabel::Private)
            .is_err()
    );
    for (source, target) in [("/source:colon", "/target"), ("/source", "/target:colon")] {
        let mount =
            Mount::bind(source.as_bytes().to_vec(), target.as_bytes().to_vec(), true).unwrap();
        let failure = mount.with_bind_relabel(BindRelabel::Shared).err().unwrap();
        assert_eq!(failure, IntentError::InvalidMount);
        assert!(!format!("{failure:?}").contains("colon"));
    }
    for repeated in [BindRelabel::Shared, BindRelabel::Private] {
        let mount = Mount::bind(b"/source".to_vec(), b"/target".to_vec(), false)
            .unwrap()
            .with_bind_relabel(BindRelabel::Shared)
            .unwrap();
        assert!(mount.with_bind_relabel(repeated).is_err());
    }
    let plain = Mount::bind(b"/source".to_vec(), b"/target".to_vec(), true).unwrap();
    let relabel = Mount::bind(b"/other".to_vec(), b"/target".to_vec(), false)
        .unwrap()
        .with_bind_relabel(BindRelabel::Private)
        .unwrap();
    assert_eq!(
        intent(ResourceRef::new(1), vec![plain, relabel]).err(),
        Some(IntentError::DuplicateMount)
    );
}

fn mount_kind(kind: usize, target: &str) -> Mount {
    let target = target.as_bytes().to_vec();
    match kind {
        0 => Mount::bind(b"/private-source".to_vec(), target, false).unwrap(),
        1 => Mount::bind(b"/private-source".to_vec(), target, true)
            .unwrap()
            .with_bind_relabel(BindRelabel::Shared)
            .unwrap(),
        2 => Mount::bind(b"/private-source".to_vec(), target, false)
            .unwrap()
            .with_bind_relabel(BindRelabel::Private)
            .unwrap(),
        3 => Mount::tmpfs(target, false, Default::default()).unwrap(),
        4 => Mount::volume(ResourceRef::new(2), target, false).unwrap(),
        _ => unreachable!(),
    }
}

#[test]
fn native_lexical_destination_collisions_fail_across_all_mount_domains() {
    for left_kind in 0..5 {
        for right_kind in 0..5 {
            for (left, right) in [
                ("/data", "/data/"),
                ("/data", "//data//"),
                ("/data", "/x/../data"),
                ("/data", "/./data"),
                ("/data", "/../../data"),
                ("/", "/root/.."),
                ("/", "///"),
            ] {
                for (left, right) in [(left, right), (right, left)] {
                    let mounts = vec![mount_kind(left_kind, left), mount_kind(right_kind, right)];
                    assert_eq!(mounts[0].target(), left.as_bytes());
                    assert_eq!(mounts[1].target(), right.as_bytes());
                    let failure = intent(ResourceRef::new(1), mounts).err().unwrap();
                    assert_eq!(failure, IntentError::DuplicateMount);
                    assert!(!format!("{failure:?}").contains("private-source"));
                }
            }
        }
    }
    for kind in 0..5 {
        assert!(
            intent(
                ResourceRef::new(1),
                vec![
                    mount_kind(kind, "/data"),
                    mount_kind(kind, "/data-child"),
                    mount_kind(kind, "/data/child"),
                    mount_kind(kind, "/other/../distinct"),
                ]
            )
            .is_ok()
        );
    }
}

#[test]
fn lexical_comparison_preserves_authored_destination_bytes_in_both_fields() {
    let mounts = vec![
        mount_kind(0, "/plain/./path//"),
        mount_kind(2, "/x/../relabel/"),
    ];
    let target = intent(ResourceRef::new(1), mounts).unwrap();
    let artifact = render(&target, 41, DaemonMode::Rootful);
    let request: Value = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(
        request["body"]["HostConfig"]["Mounts"][0]["Target"],
        "/plain/./path//"
    );
    assert_eq!(
        request["body"]["HostConfig"]["Binds"],
        json!(["/private-source:/x/../relabel/:rw,Z"])
    );
    assert_eq!(
        artifact.bind_source_prerequisites()[0].target(),
        b"/x/../relabel/"
    );
}

#[test]
fn mount_device_overlap_uses_the_same_lexical_destination_key() {
    use crate::target::{DeviceMapping, DevicePermissions, WorkingDirectory};

    for kind in 0..5 {
        for (device_target, collision) in [
            ("/data/", true),
            ("/x/../data", true),
            ("/data-child", false),
        ] {
            let TargetResource::Container(mut resource) =
                container(ResourceRef::new(1), vec![mount_kind(kind, "/data")])
            else {
                unreachable!();
            };
            resource.settings.devices = vec![DeviceMapping {
                host_path: WorkingDirectory::new(b"/dev/private-source".to_vec()).unwrap(),
                container_path: WorkingDirectory::new(device_target.as_bytes().to_vec()).unwrap(),
                permissions: DevicePermissions {
                    read: true,
                    write: false,
                    create: false,
                },
            }];
            let target = TargetIntent::new(vec![TargetResource::Container(resource)]);
            if collision {
                assert_eq!(target.err(), Some(IntentError::DuplicateMount));
            } else {
                assert!(target.is_ok());
            }
        }
    }
}

#[test]
fn api_floor_unknown_mode_remain_closed_while_reviewed_bind_groups_are_admitted() {
    let target = intent(
        ResourceRef::new(1),
        vec![
            Mount::bind(b"/source".to_vec(), b"/target".to_vec(), false)
                .unwrap()
                .with_bind_relabel(BindRelabel::Shared)
                .unwrap(),
        ],
    )
    .unwrap();
    let old = facts(
        40,
        DaemonMode::Rootful,
        &[
            Capability::StandaloneContainer,
            Capability::BindMount,
            Capability::BindRelabelShared,
        ],
    );
    let validated = ValidatedCapabilities::new(&old).unwrap();
    assert!(matches!(
        DockerPlanner.plan(&target, &validated),
        Err(PlanningError::UnsupportedApi { .. })
    ));
    assert!(
        ValidatedCapabilities::new(&facts(
            41,
            DaemonMode::Unknown,
            &[Capability::BindRelabelShared]
        ))
        .is_err()
    );
    let catalog = TargetCapabilityCatalog::reviewed();
    for (relabel, capability) in [
        (BindRelabel::Shared, Capability::BindRelabelShared),
        (BindRelabel::Private, Capability::BindRelabelPrivate),
    ] {
        let target = intent(
            ResourceRef::new(1),
            vec![
                Mount::bind(b"/source".to_vec(), b"/target".to_vec(), false)
                    .unwrap()
                    .with_bind_relabel(relabel)
                    .unwrap(),
            ],
        )
        .unwrap();
        for profile in catalog.profiles() {
            let resolved = catalog.resolve(profile).unwrap();
            assert!(resolved.supports(capability));
            let graph = DockerPlanner.plan(&target, &resolved).unwrap();
            let artifact = DockerApiRenderer.render(&graph).unwrap();
            let complete: Value =
                serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
            assert_eq!(complete["schema_version"], 2);
            assert_eq!(complete["prerequisites"][0]["selinux_effect"], "unverified");
            assert_eq!(
                complete["prerequisites"][0]["source_conditions"]
                    .as_array()
                    .unwrap()
                    .len(),
                5
            );
            assert_eq!(
                complete["prerequisites"][0]["selinux_conditions"]
                    .as_array()
                    .unwrap()
                    .len(),
                4
            );
        }
    }
    assert_eq!(
        NativeCapabilityShape::required_for(Capability::BindRelabelShared).unwrap(),
        &[
            NativeCapabilityShape::BindMountSharedRelabelReadWrite,
            NativeCapabilityShape::BindMountSharedRelabelReadOnly,
        ]
    );
    assert_eq!(
        NativeCapabilityShape::required_for(Capability::BindRelabelPrivate).unwrap(),
        &[
            NativeCapabilityShape::BindMountPrivateRelabelReadWrite,
            NativeCapabilityShape::BindMountPrivateRelabelReadOnly,
        ]
    );
}
