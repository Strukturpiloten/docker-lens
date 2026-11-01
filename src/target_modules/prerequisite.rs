//! Pure matching of inert prerequisites to explicitly selected snapshots.
//! No acquisition, execution, authentication, current-existence or capability claim.

use super::{DestinationPidsPrerequisite, NetworkDriver, NetworkPrerequisite, PlanningContext};
use crate::acquisition::{NativeId, RootKind, SelectionReason};
use crate::decoder::{DecodedInventory, NetworkObservation};
use crate::observation::{Availability, Observed, Origin};
use crate::resource_support::{
    ReportedCgroupDriver, ReportedCgroupVersion, ReportedResourceSupport,
};
use crate::version::{DaemonMode, ObservationId};
use std::collections::HashSet;

// The decoder's existing collection limit. Bound every collection scanned here;
// this is not a validation of unvisited nested fields or the whole inventory.
const MAX_COLLECTION_ITEMS: usize = 4096;

/// Metadata compatibility is not satisfied delegation or enforcement. Exact
/// build/package provenance and current runtime identity also remain unproved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationPidsAssessment {
    MetadataCompatibleDelegationAndEnforcementUnverified,
}

/// Closed, value-free destination-snapshot refusal; no runtime error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationPidsPrerequisiteError {
    ObservationScopeMismatch,
    ReleaseMismatch,
    ApiVersionMismatch,
    ApiRangeMismatch,
    AcquisitionApiMismatch,
    CollectionTooLarge,
    ModeMismatch,
    PidsReportIncompatible,
    CgroupDriverIncompatible,
    CgroupVersionIncompatible,
}

impl DestinationPidsPrerequisite {
    /// Assess only the caller's explicitly selected destination snapshot.
    ///
    /// All three observation scopes must match that selection. An observed
    /// planning context must also match the explicitly selected destination;
    /// no stored ID substitutes for that argument or authenticates a daemon.
    /// Release, advertised API and rootless mode must match the context. Offline
    /// targets additionally require their chosen acquisition API in the actual
    /// request-version list; all those reads must use that API. Rendering and
    /// reads must fit the reported API range; missing minimum stays unknown,
    /// never an invented version. Scanned request versions retain decoder bounds.
    ///
    /// Only present effective true/systemd/2 reports are metadata-compatible.
    /// Success does not authenticate build/package provenance, peer identity,
    /// atomicity, current/future state, delegation, enforcement or readiness.
    /// Caller-assembled snapshots remain assertions. Catalogue capability
    /// evidence remains separate. This method performs no acquisition or I/O.
    pub fn assess(
        &self,
        inventory: &DecodedInventory,
        expected_destination: ObservationId,
    ) -> Result<DestinationPidsAssessment, DestinationPidsPrerequisiteError> {
        use DestinationPidsPrerequisiteError as Error;
        let daemon = &inventory.version.daemon;
        let reports = &inventory.version.resource_support;
        if inventory.observation_id != expected_destination
            || daemon.observation_id != expected_destination
            || reports.observation_id != expected_destination
            || matches!(self.context(), PlanningContext::Observed(scope) if scope.observation_id != expected_destination)
        {
            return Err(Error::ObservationScopeMismatch);
        }
        let (release, advertised, rendering, acquisition, mode) = match self.context() {
            PlanningContext::Observed(scope) => (
                &scope.release,
                scope.api_version,
                scope.api_version,
                None,
                scope.mode,
            ),
            PlanningContext::Target(profile) => (
                profile.release(),
                profile.identity().advertised_api_version(),
                profile.rendering_api_version(),
                Some(profile.identity().acquisition_api_version()),
                profile.mode(),
            ),
        };
        if daemon.release.as_ref() != Some(release) {
            return Err(Error::ReleaseMismatch);
        }
        if daemon.api_version != Some(advertised) {
            return Err(Error::ApiVersionMismatch);
        }
        if mode != DaemonMode::Rootless || daemon.mode != mode {
            return Err(Error::ModeMismatch);
        }
        let requests = &inventory.version.requested_api_versions;
        if requests.len() > MAX_COLLECTION_ITEMS {
            return Err(Error::CollectionTooLarge);
        }
        if rendering > advertised
            || daemon
                .minimum_api_version
                .is_some_and(|minimum| minimum > rendering || minimum > advertised)
            || requests.iter().any(|api| {
                api.major != advertised.major
                    || *api > advertised
                    || daemon
                        .minimum_api_version
                        .is_some_and(|minimum| *api < minimum)
            })
        {
            return Err(Error::ApiRangeMismatch);
        }
        if requests.is_empty()
            || acquisition.is_some_and(|expected| requests.iter().any(|api| *api != expected))
        {
            return Err(Error::AcquisitionApiMismatch);
        }
        let assessment = reports
            .assess(expected_destination)
            .map_err(|_| Error::ObservationScopeMismatch)?;
        if assessment.pids_limit != ReportedResourceSupport::ReportedAvailableUnverified {
            return Err(Error::PidsReportIncompatible);
        }
        if assessment.cgroup_driver != ReportedCgroupDriver::Systemd {
            return Err(Error::CgroupDriverIncompatible);
        }
        if assessment.cgroup_version != ReportedCgroupVersion::V2 {
            return Err(Error::CgroupVersionIncompatible);
        }
        Ok(DestinationPidsAssessment::MetadataCompatibleDelegationAndEnforcementUnverified)
    }
}

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
