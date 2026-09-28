//! An external consumer can discover reviewed profiles but cannot supply
//! positive capability claims without a matching catalog record.

use docker_lens::observation::ResourceRef;
use docker_lens::target::{
    DockerApiRenderer, DockerPlanner, Planner, Renderer, TargetIdentity, TargetIntent,
    TargetResource,
};
use docker_lens::version::{
    ApiVersion, CapabilityError, CapabilityEvidenceKey, DaemonMode, DebianPackageRevision,
    EngineBuild, EngineRelease, NativeEvidenceLane, NativeEvidenceReference,
    TargetCapabilityCatalog, TargetProfile, TargetProfileIdentity,
};
use std::num::NonZeroU16;

fn api(minor: u16) -> ApiVersion {
    ApiVersion::new(NonZeroU16::new(1).unwrap(), minor)
}

#[test]
fn public_catalog_resolves_four_exact_profiles_and_renders_inert_requests() {
    let catalog = TargetCapabilityCatalog::reviewed();
    assert_eq!(catalog.profiles().len(), 4);
    for profile in catalog.profiles() {
        let admitted = catalog.resolve(profile).unwrap();
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
