//! Independently authored snapshots; no daemon or native compatibility proof.

use super::*;
use crate::acquisition::{Budget, Limits, ReadRequest, SelectedRoot};
use crate::decoder::{NetworkObservation, VolumeObservation, decode_capture};
use crate::evidence::{HttpStatus, ProtectedValue};
use crate::observation::ResourceRef;
use crate::target::{
    DockerApiRenderer, DockerPlanner, NetworkIntent, NetworkRole, NetworkSource, Planner,
    RenderedArtifact, Renderer, TargetIdentity, TargetIntent, TargetResource,
};
use crate::version::{
    ApiVersion, Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonMode,
    EngineRelease, FactProvenance, ValidatedCapabilities,
};
use std::num::NonZeroU16;
use std::time::Duration;

const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CAPTURE_REFERENCE: ResourceRef = ResourceRef::new(97);
const AVAILABILITIES: &[Availability] = &[
    Availability::Missing,
    Availability::Null,
    Availability::Empty,
    Availability::Present,
    Availability::Redacted,
];
const ORIGINS: &[Origin] = &[
    Origin::Configured,
    Origin::Effective,
    Origin::RuntimeAssigned,
    Origin::Unknown,
];

fn inventory_with_container(include_container: bool) -> DecodedInventory {
    let mut budget = Budget::new(Limits {
        max_requests: 2,
        max_selected_resources: 2,
        max_expansions: 2,
        max_response_bytes: 4096,
        max_total_bytes: 8192,
        max_elapsed: Duration::from_secs(2),
    })
    .unwrap();
    budget
        .record_selection(if include_container { 2 } else { 1 })
        .unwrap();
    let api = ApiVersion::new(NonZeroU16::new(1).unwrap(), 41);
    budget
        .record_request(
            ReadRequest::InspectNetwork(NativeId::new(ID.into()).unwrap()),
            Some(CAPTURE_REFERENCE),
            Some(api),
        )
        .unwrap();
    budget.read_response(HttpStatus::new(200).unwrap(), br#"{"Id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Name":"independent_edge","Driver":"bridge","Internal":false}"#.as_slice()).unwrap();
    let mut roots = vec![SelectedRoot {
        resource: CAPTURE_REFERENCE,
        kind: RootKind::Network,
        reason: SelectionReason::ExactNetworkId,
    }];
    if include_container {
        budget
            .record_request(
                ReadRequest::InspectContainer(NativeId::new(ID.into()).unwrap()),
                Some(ResourceRef::new(98)),
                Some(api),
            )
            .unwrap();
        budget
            .read_response(
                HttpStatus::new(200).unwrap(),
                br#"{"Id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#
                    .as_slice(),
            )
            .unwrap();
        roots.push(SelectedRoot {
            resource: ResourceRef::new(98),
            kind: RootKind::Container,
            reason: SelectionReason::ExactId,
        });
    }
    decode_capture(&budget.into_capture().unwrap().with_selected_roots(roots)).unwrap()
}

fn inventory() -> DecodedInventory {
    inventory_with_container(false)
}

fn artifact(expected_internal: Option<bool>) -> RenderedArtifact {
    let target = TargetIntent::new(vec![TargetResource::Network(NetworkIntent {
        reference: ResourceRef::new(9001),
        identity: TargetIdentity::new(b"independent_edge".to_vec()).unwrap(),
        role: NetworkRole::Declared,
        source: NetworkSource::External {
            expected_driver: NetworkDriver::Bridge,
            expected_internal,
        },
    })])
    .unwrap();
    // Only cfg(test) can assemble validated positive facts. This does not admit
    // the pending external capability or authenticate the authored capture.
    let mut daemon = inventory().version.daemon;
    let release = EngineRelease::new("20.10.5".into()).unwrap();
    let api = ApiVersion::new(NonZeroU16::new(1).unwrap(), 41);
    daemon.release = Some(release.clone());
    daemon.api_version = Some(api);
    daemon.mode = DaemonMode::Rootful;
    let scope = CapabilityScope {
        observation_id: daemon.observation_id,
        release,
        api_version: api,
        mode: daemon.mode,
    };
    daemon.capabilities = [
        Capability::NetworkExternalReference,
        Capability::NetworkExternalInternalExpectation,
    ]
    .iter()
    .map(|capability| CapabilityFact {
        capability: *capability,
        state: CapabilityState::Available,
        provenance: FactProvenance::NativeConformance,
        scope: Some(scope.clone()),
    })
    .collect();
    let validated = ValidatedCapabilities::new(&daemon).unwrap();
    DockerApiRenderer
        .render(&DockerPlanner.plan(&target, &validated).unwrap())
        .unwrap()
}

fn assess(
    artifact: &RenderedArtifact,
    inventory: &DecodedInventory,
) -> Result<(), NetworkPrerequisiteError> {
    artifact.network_prerequisites()[0].assess(
        inventory,
        inventory.observation_id,
        &NativeId::new(ID.into()).unwrap(),
    )
}

fn protected(
    value: &[u8],
    availability: Availability,
    origin: Origin,
    has_value: bool,
) -> Observed<ProtectedValue> {
    if has_value {
        Observed::present(ProtectedValue::new(value.to_vec()), availability, origin)
    } else {
        Observed::unavailable(availability, origin)
    }
}

fn unrelated_network(index: u64) -> NetworkObservation {
    let mut network = inventory().networks.remove(0);
    network.reference = ResourceRef::new(index + 1000);
    network.id = protected(
        format!("{index:064x}").as_bytes(),
        Availability::Present,
        Origin::RuntimeAssigned,
        true,
    );
    network
}

#[test]
fn none_false_true_match_only_the_explicit_snapshot_not_target_reference() {
    for expected in [None, Some(false), Some(true)] {
        let artifact = artifact(expected);
        let prerequisite = &artifact.network_prerequisites()[0];
        assert_ne!(prerequisite.reference, CAPTURE_REFERENCE);
        let mut snapshot = inventory();
        assert!(snapshot.version.daemon.capabilities.is_empty());
        snapshot.networks[0].internal = Observed::present(
            expected.unwrap_or(false),
            Availability::Present,
            Origin::Effective,
        );
        assert_eq!(assess(&artifact, &snapshot), Ok(()));
        if let Some(expected) = expected {
            snapshot.networks[0].internal =
                Observed::present(!expected, Availability::Present, Origin::Effective);
            assert_eq!(
                assess(&artifact, &snapshot),
                Err(NetworkPrerequisiteError::NetworkInternalMismatch)
            );
        }
    }
    let artifact = artifact(None);
    let mut snapshot = inventory();
    snapshot.networks[0].reference = artifact.network_prerequisites()[0].reference;
    snapshot.selected_roots[0].resource = snapshot.networks[0].reference;
    assert_eq!(
        assess(&artifact, &snapshot),
        Ok(()),
        "accidentally equal local numbers do not couple reference domains"
    );
}

#[test]
fn identity_name_driver_availability_origin_and_valueless_cross_product() {
    let artifact = artifact(None);
    for field in 0..3 {
        for &availability in AVAILABILITIES {
            for &origin in ORIGINS {
                for has_value in [false, true] {
                    let mut snapshot = inventory();
                    let value: &[u8] = match field {
                        0 => ID.as_bytes(),
                        1 => b"independent_edge",
                        _ => b"bridge",
                    };
                    let observed = protected(value, availability, origin, has_value);
                    match field {
                        0 => snapshot.networks[0].id = observed,
                        1 => snapshot.networks[0].name = observed,
                        _ => snapshot.networks[0].driver = observed,
                    }
                    let required_origin = if field == 0 {
                        Origin::RuntimeAssigned
                    } else {
                        Origin::Effective
                    };
                    assert_eq!(
                        assess(&artifact, &snapshot).is_ok(),
                        availability == Availability::Present
                            && origin == required_origin
                            && has_value
                    );
                }
            }
        }
    }
}

#[test]
fn internal_availability_origin_and_valueless_cross_product_and_none_skips_it() {
    for value in [false, true] {
        let constrained = artifact(Some(value));
        let unconstrained = artifact(None);
        for &availability in AVAILABILITIES {
            for &origin in ORIGINS {
                for has_value in [false, true] {
                    let mut snapshot = inventory();
                    snapshot.networks[0].internal = if has_value {
                        Observed::present(value, availability, origin)
                    } else {
                        Observed::unavailable(availability, origin)
                    };
                    assert_eq!(
                        assess(&constrained, &snapshot).is_ok(),
                        availability == Availability::Present
                            && origin == Origin::Effective
                            && has_value
                    );
                    assert_eq!(assess(&unconstrained, &snapshot), Ok(()));
                }
            }
        }
    }
}

#[test]
fn both_inventory_and_daemon_need_the_callers_exact_scope() {
    let artifact = artifact(None);
    let prerequisite = &artifact.network_prerequisites()[0];
    let selected = NativeId::new(ID.into()).unwrap();
    for mutate in 0..3 {
        let mut snapshot = inventory();
        let expected = snapshot.observation_id;
        let other = ObservationId::fresh().unwrap();
        match mutate {
            0 => snapshot.observation_id = other,
            1 => snapshot.version.daemon.observation_id = other,
            _ => {}
        }
        assert_eq!(
            prerequisite.assess(
                &snapshot,
                if mutate == 2 { other } else { expected },
                &selected
            ),
            Err(NetworkPrerequisiteError::ObservationScopeMismatch)
        );
    }
}

#[test]
fn native_id_syntax_and_id_name_driver_mismatches_are_value_free() {
    let artifact = artifact(None);
    let prerequisite = &artifact.network_prerequisites()[0];
    let mut snapshot = inventory();
    for invalid in [
        "a".repeat(63),
        "a".repeat(65),
        "g".repeat(64),
        format!("{ID}/"),
        "é".repeat(32),
        "private-id-canary".into(),
    ] {
        let error = prerequisite
            .assess(
                &snapshot,
                snapshot.observation_id,
                &NativeId::new(invalid.clone()).unwrap(),
            )
            .unwrap_err();
        assert_eq!(error, NetworkPrerequisiteError::InvalidSelectedNetworkId);
        assert!(!format!("{error:?}").contains(&invalid));
    }
    let upper = "A".repeat(64);
    snapshot.networks[0].id = protected(
        upper.as_bytes(),
        Availability::Present,
        Origin::RuntimeAssigned,
        true,
    );
    assert_eq!(
        prerequisite.assess(
            &snapshot,
            snapshot.observation_id,
            &NativeId::new(upper).unwrap()
        ),
        Ok(())
    );
    for field in 0..3 {
        let mut snapshot = inventory();
        let value = if field == 0 {
            "b".repeat(64)
        } else {
            "private-native-value-canary".into()
        };
        let observed = protected(
            value.as_bytes(),
            Availability::Present,
            if field == 0 {
                Origin::RuntimeAssigned
            } else {
                Origin::Effective
            },
            true,
        );
        match field {
            0 => snapshot.networks[0].id = observed,
            1 => snapshot.networks[0].name = observed,
            _ => snapshot.networks[0].driver = observed,
        }
        let error = assess(&artifact, &snapshot).unwrap_err();
        assert_eq!(
            error,
            match field {
                0 => NetworkPrerequisiteError::NetworkNotFound,
                1 => NetworkPrerequisiteError::NetworkNameMismatch,
                _ => NetworkPrerequisiteError::NetworkDriverMismatch,
            }
        );
        assert!(!format!("{error:?}").contains(&value));
    }
}

#[test]
fn selected_root_kind_reason_missing_duplicate_and_wrong_reference_fail() {
    let artifact = artifact(None);
    for mutate in 0..6 {
        let mut snapshot = inventory();
        match mutate {
            0 => snapshot.selected_roots.clear(),
            1 => snapshot.selected_roots[0].kind = RootKind::Container,
            2 => snapshot.selected_roots[0].reason = SelectionReason::ExactName,
            3 => snapshot.selected_roots[0].resource = ResourceRef::new(9001),
            4 => snapshot.selected_roots.push(snapshot.selected_roots[0]),
            _ => snapshot.selected_roots.push(SelectedRoot {
                resource: CAPTURE_REFERENCE,
                kind: RootKind::Volume,
                reason: SelectionReason::ExactVolumeName,
            }),
        }
        assert_eq!(
            assess(&artifact, &snapshot),
            Err(match mutate {
                0 | 3 => NetworkPrerequisiteError::SelectedRootNotFound,
                1 | 2 => NetworkPrerequisiteError::InvalidSelectedRoot,
                _ => NetworkPrerequisiteError::DuplicateSelectedRoot,
            })
        );
    }
    let mut snapshot = inventory();
    snapshot.networks.clear();
    assert_eq!(
        assess(&artifact, &snapshot),
        Err(NetworkPrerequisiteError::NetworkNotFound)
    );
}

#[test]
fn duplicate_network_ids_and_capture_references_are_ambiguous() {
    let artifact = artifact(None);
    let mut snapshot = inventory();
    let mut duplicate = inventory().networks.remove(0);
    duplicate.reference = ResourceRef::new(99);
    snapshot.networks.push(duplicate);
    assert_eq!(
        assess(&artifact, &snapshot),
        Err(NetworkPrerequisiteError::AmbiguousNetwork)
    );
    let mut snapshot = inventory();
    let mut other = unrelated_network(1);
    other.reference = CAPTURE_REFERENCE;
    snapshot.networks.push(other);
    assert_eq!(
        assess(&artifact, &snapshot),
        Err(NetworkPrerequisiteError::AmbiguousResourceReference)
    );
    let mut snapshot = inventory_with_container(true);
    assert_eq!(
        assess(&artifact, &snapshot),
        Ok(()),
        "same native ID spelling in another kind is not ambiguous"
    );
    snapshot.containers[0].reference = CAPTURE_REFERENCE;
    assert_eq!(
        assess(&artifact, &snapshot),
        Err(NetworkPrerequisiteError::AmbiguousResourceReference)
    );
    let mut snapshot = inventory();
    snapshot.volumes.push(VolumeObservation {
        reference: CAPTURE_REFERENCE,
        name: protected(b"volume", Availability::Present, Origin::Effective, true),
        driver: Observed::unavailable(Availability::Missing, Origin::Effective),
        mountpoint: Observed::unavailable(Availability::Missing, Origin::RuntimeAssigned),
        options: Observed::unavailable(Availability::Missing, Origin::Effective),
        labels: Observed::unavailable(Availability::Missing, Origin::Effective),
    });
    assert_eq!(
        assess(&artifact, &snapshot),
        Err(NetworkPrerequisiteError::AmbiguousResourceReference)
    );
}

#[test]
fn caller_assembled_scanned_collections_keep_decoder_bounds() {
    let artifact = artifact(None);
    let mut snapshot = inventory();
    for index in 0..(MAX_COLLECTION_ITEMS - 1) {
        snapshot.networks.push(unrelated_network(index as u64));
        snapshot.selected_roots.push(SelectedRoot {
            resource: ResourceRef::new(index as u64 + 1000),
            kind: RootKind::Network,
            reason: SelectionReason::ExactNetworkId,
        });
    }
    assert_eq!(assess(&artifact, &snapshot), Ok(()));
    snapshot
        .networks
        .push(unrelated_network(MAX_COLLECTION_ITEMS as u64));
    assert_eq!(
        assess(&artifact, &snapshot),
        Err(NetworkPrerequisiteError::CollectionTooLarge)
    );
    snapshot.networks.pop();
    snapshot.selected_roots.push(SelectedRoot {
        resource: ResourceRef::new(9001),
        kind: RootKind::Network,
        reason: SelectionReason::ExactNetworkId,
    });
    assert_eq!(
        assess(&artifact, &snapshot),
        Err(NetworkPrerequisiteError::CollectionTooLarge)
    );
    let mut snapshot = inventory();
    for index in 0..=MAX_COLLECTION_ITEMS {
        let mut container = inventory_with_container(true).containers.remove(0);
        container.reference = ResourceRef::new(index as u64 + 1000);
        snapshot.containers.push(container);
    }
    assert_eq!(
        assess(&artifact, &snapshot),
        Err(NetworkPrerequisiteError::CollectionTooLarge)
    );
    snapshot.containers.clear();
    for index in 0..=MAX_COLLECTION_ITEMS {
        snapshot.volumes.push(VolumeObservation {
            reference: ResourceRef::new(index as u64 + 1000),
            name: Observed::unavailable(Availability::Missing, Origin::Effective),
            driver: Observed::unavailable(Availability::Missing, Origin::Effective),
            mountpoint: Observed::unavailable(Availability::Missing, Origin::RuntimeAssigned),
            options: Observed::unavailable(Availability::Missing, Origin::Effective),
            labels: Observed::unavailable(Availability::Missing, Origin::Effective),
        });
    }
    assert_eq!(
        assess(&artifact, &snapshot),
        Err(NetworkPrerequisiteError::CollectionTooLarge)
    );
}
