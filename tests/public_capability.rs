//! An external consumer can discover reviewed profiles but cannot supply
//! positive capability claims without a matching catalog record.

use docker_lens::observation::ResourceRef;
use docker_lens::target::{
    DockerApiRenderer, DockerPlanner, NetworkCreate, NetworkDriver, NetworkIntent, NetworkRole,
    NetworkSource, Planner, PlanningContext, Renderer, TargetIdentity, TargetIntent,
    TargetResource,
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
            "702910b003daae58babd540d7ba3de4998275feb"
        );
        assert_eq!(
            resolved.evidence().run_url(),
            "https://github.com/Strukturpiloten/docker-lens/actions/runs/37209363801/attempts/1"
        );
        for capability in [
            Capability::VolumeExternalReference,
            Capability::NetworkExternalReference,
            Capability::NetworkInternal,
        ] {
            assert!(resolved.supports(capability));
        }
        for capability in [
            Capability::VolumeLabels,
            Capability::NetworkIpv6,
            Capability::NetworkIpam,
            Capability::NetworkOptions,
            Capability::NetworkLabels,
            Capability::NetworkAliases,
            Capability::NetworkStaticAddress,
            Capability::NetworkMultipleAttachment,
            Capability::PortEphemeral,
            Capability::CommandClear,
            Capability::HealthShell,
            Capability::HealthStartInterval,
            Capability::ContainerLabels,
            Capability::ContainerUser,
            Capability::MemoryLimit,
            Capability::PidsLimit,
            Capability::SecurityOptions,
            Capability::UserNamespace,
        ] {
            assert!(!resolved.supports(capability));
        }
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
                "b9f3064cadfc2302678b9a334597907fd35eeb856464d4e6c81bf4465875d0e8",
                "365e8a70e2e5a369912da47d2a510e45acd7cca3ac6e932e3536ad75f22c64b9",
            ),
            EngineBuild::Upstream => (
                serde_json::json!({"kind": "upstream"}),
                "29.8.1",
                "1.56",
                "1.49",
                "27c47307f4fdd523a22448415238a729e7a6458fddc554259f23ea99fff5ff76",
                "c0f8160bf8787e9490713595f58c1b4eeb9aeee3ff5f4739776a1010bdea6e1f",
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

#[test]
fn public_catalog_resolves_four_exact_profiles_and_renders_inert_requests() {
    let catalog = TargetCapabilityCatalog::reviewed();
    assert_eq!(catalog.profiles().len(), 4);
    for profile in catalog.profiles() {
        let admitted = catalog.resolve(profile).unwrap();
        assert!(!admitted.supports(Capability::VolumeLabels));
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
