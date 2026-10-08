//! Pure matching of a network prerequisite to one explicitly selected snapshot.
//! No acquisition, execution, authentication, current-existence or capability claim.

use super::{NetworkDriver, NetworkPrerequisite};
use crate::acquisition::{NativeId, RootKind, SelectionReason};
use crate::decoder::{DecodedInventory, NetworkObservation};
use crate::observation::{Availability, Observed, Origin};
use crate::version::ObservationId;
use std::collections::HashSet;

// The decoder's existing collection limit. Bound every collection scanned here;
// this is not a validation of unvisited nested fields or the whole inventory.
const MAX_COLLECTION_ITEMS: usize = 4096;

/// Closed, value-free snapshot assessment failures, not runtime error messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkPrerequisiteError {
    ObservationScopeMismatch,
    InvalidSelectedNetworkId,
    CollectionTooLarge,
    NetworkNotFound,
    AmbiguousNetwork,
    AmbiguousResourceReference,
    SelectedRootNotFound,
    DuplicateSelectedRoot,
    InvalidSelectedRoot,
    InvalidNetworkIdEvidence,
    InvalidNetworkNameEvidence,
    NetworkNameMismatch,
    InvalidNetworkDriverEvidence,
    NetworkDriverMismatch,
    InvalidNetworkInternalEvidence,
    NetworkInternalMismatch,
}

impl NetworkPrerequisite {
    /// Match this obligation only against a caller-selected network in the given
    /// observation. `NativeId::new` alone does not validate the full native ID.
    ///
    /// Inventory and daemon scope must both match. The network needs one exact
    /// selected root, a present runtime-assigned ID, and present effective name
    /// and driver. Explicit internal expectations also need present effective
    /// boolean evidence; `None` leaves that field entirely unconstrained.
    /// Capture-local references bind the root to its observation, never to this
    /// prerequisite's unrelated target-graph reference. Caller-assembled fields
    /// remain caller assertions; success grants no capability, authentication,
    /// atomicity, current/future existence, ownership or reachability guarantee.
    /// This method performs no I/O and does not inspect other nested settings.
    pub fn assess(
        &self,
        inventory: &DecodedInventory,
        expected_observation: ObservationId,
        selected_network_id: &NativeId,
    ) -> Result<(), NetworkPrerequisiteError> {
        use NetworkPrerequisiteError as Error;
        if inventory.observation_id != expected_observation
            || inventory.version.daemon.observation_id != expected_observation
        {
            return Err(Error::ObservationScopeMismatch);
        }
        let id = selected_network_id.as_str().as_bytes();
        if id.len() != 64 || !id.iter().all(u8::is_ascii_hexdigit) {
            return Err(Error::InvalidSelectedNetworkId);
        }
        let network = selected_network(inventory, id)?;
        if !usable(&network.id, Origin::RuntimeAssigned) {
            return Err(Error::InvalidNetworkIdEvidence);
        }
        if !usable(&network.name, Origin::Effective) {
            return Err(Error::InvalidNetworkNameEvidence);
        }
        if network
            .name
            .value()
            .is_none_or(|value| value.as_bytes() != self.identity())
        {
            return Err(Error::NetworkNameMismatch);
        }
        if !usable(&network.driver, Origin::Effective) {
            return Err(Error::InvalidNetworkDriverEvidence);
        }
        let driver: &[u8] = match self.expected_driver {
            NetworkDriver::Bridge => b"bridge",
            NetworkDriver::Host => b"host",
            NetworkDriver::Overlay => b"overlay",
            NetworkDriver::Macvlan => b"macvlan",
        };
        if network
            .driver
            .value()
            .is_none_or(|value| value.as_bytes() != driver)
        {
            return Err(Error::NetworkDriverMismatch);
        }
        if let Some(expected) = self.expected_internal {
            if !usable(&network.internal, Origin::Effective) {
                return Err(Error::InvalidNetworkInternalEvidence);
            }
            if network.internal.value() != Some(&expected) {
                return Err(Error::NetworkInternalMismatch);
            }
        }
        Ok(())
    }
}

fn selected_network<'a>(
    inventory: &'a DecodedInventory,
    id: &[u8],
) -> Result<&'a NetworkObservation, NetworkPrerequisiteError> {
    use NetworkPrerequisiteError as Error;
    if [
        inventory.networks.len(),
        inventory.selected_roots.len(),
        inventory.containers.len(),
        inventory.volumes.len(),
    ]
    .iter()
    .any(|length| *length > MAX_COLLECTION_ITEMS)
    {
        return Err(Error::CollectionTooLarge);
    }
    let mut matches = inventory.networks.iter().filter(|network| {
        network
            .id
            .value()
            .is_some_and(|value| value.as_bytes() == id)
    });
    let network = matches.next().ok_or(Error::NetworkNotFound)?;
    if matches.next().is_some() {
        return Err(Error::AmbiguousNetwork);
    }
    if inventory
        .networks
        .iter()
        .filter(|other| other.reference == network.reference)
        .count()
        != 1
        || inventory
            .containers
            .iter()
            .any(|other| other.reference == network.reference)
        || inventory
            .volumes
            .iter()
            .any(|other| other.reference == network.reference)
    {
        return Err(Error::AmbiguousResourceReference);
    }
    let mut references = HashSet::new();
    if inventory
        .selected_roots
        .iter()
        .any(|root| !references.insert(root.resource))
    {
        return Err(Error::DuplicateSelectedRoot);
    }
    let root = inventory
        .selected_roots
        .iter()
        .find(|root| root.resource == network.reference)
        .ok_or(Error::SelectedRootNotFound)?;
    if root.kind != RootKind::Network || root.reason != SelectionReason::ExactNetworkId {
        return Err(Error::InvalidSelectedRoot);
    }
    Ok(network)
}

fn usable<T>(field: &Observed<T>, origin: Origin) -> bool {
    field.availability == Availability::Present && field.origin == origin && field.value().is_some()
}

#[cfg(test)]
#[path = "prerequisite/tests.rs"]
mod tests;
