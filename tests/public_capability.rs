//! An external consumer can discover reviewed profiles but cannot supply
//! positive capability claims without a matching catalog record.

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
fn public_catalog_discovery_and_resolution_fail_closed_until_native_review() {
    let catalog = TargetCapabilityCatalog::reviewed();
    assert_eq!(catalog.profiles().len(), 0);

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
    assert!(matches!(
        catalog.resolve_identity(&identity),
        Err(CapabilityError::ProfileNotReviewed)
    ));
    assert!(matches!(
        catalog.resolve(&caller_claim),
        Err(CapabilityError::ProfileNotReviewed)
    ));
}

#[test]
fn exact_debian11_candidates_in_both_modes_remain_unadmitted_without_native_records() {
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
        ];
        for identity in std::iter::once(&exact).chain(neighbors.iter()) {
            assert!(matches!(
                catalog.resolve_identity(identity),
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
