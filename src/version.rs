//! Engine facts are observations, not inferred from a requested target version.

use std::collections::HashSet;
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_OBSERVATION_ID: AtomicU64 = AtomicU64::new(1);

/// Process-local identity for one acquisition. It is not an Engine identifier,
/// persistent fixture key, or proof of daemon contact.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ObservationId(u64);

impl ObservationId {
    /// Allocate an opaque identity without reusing one within this process.
    pub fn fresh() -> Result<Self, ObservationIdError> {
        NEXT_OBSERVATION_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map(Self)
            .map_err(|_| ObservationIdError::Exhausted)
    }
}

impl std::fmt::Debug for ObservationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservationId([opaque])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationIdError {
    Exhausted,
}

/// Exact Docker Engine API version; it is independent of the Engine release.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ApiVersion {
    pub major: NonZeroU16,
    pub minor: u16,
}

impl ApiVersion {
    /// Construct a two-component API version without assuming a supported range.
    #[must_use]
    pub const fn new(major: NonZeroU16, minor: u16) -> Self {
        Self { major, minor }
    }
}

/// Engine release text is kept separate from API negotiation.
/// The value is untrusted and therefore intentionally omitted from `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct EngineRelease(String);

impl EngineRelease {
    /// Retain the exact reported release, if nonempty.
    pub fn new(value: String) -> Option<Self> {
        (!value.is_empty()).then_some(Self(value))
    }

    /// Read the release for explicit, trusted display decisions.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EngineRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngineRelease([redacted])")
    }
}

/// Do not infer privilege mode from the client's UID or socket path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonMode {
    Rootful,
    Rootless,
    Unknown,
}

/// A capability must be observed or independently validated for its exact daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityState {
    Available,
    Unavailable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Capability {
    BindMount,
    NamedVolume,
    BridgeNetwork,
    HostNetwork,
    PortPublish,
    UserNamespace,
}

/// The exact daemon scope of a capability claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityScope {
    pub observation_id: ObservationId,
    pub release: EngineRelease,
    pub api_version: ApiVersion,
    pub mode: DaemonMode,
}

/// Claims carry provenance and exact scope. `Unknown` is never positive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityFact {
    pub capability: Capability,
    pub state: CapabilityState,
    pub provenance: FactProvenance,
    pub scope: Option<CapabilityScope>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactProvenance {
    DaemonResponse,
    NativeConformance,
    Unknown,
}

/// Facts have no default values that could be mistaken for confirmed support.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonFacts {
    pub observation_id: ObservationId,
    pub release: Option<EngineRelease>,
    pub api_version: Option<ApiVersion>,
    pub minimum_api_version: Option<ApiVersion>,
    pub mode: DaemonMode,
    pub capabilities: Vec<CapabilityFact>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    MissingDaemonIdentity,
    InvalidApiRange,
    DuplicateCapability,
    InvalidProvenance,
    ScopeMismatch,
}

/// Checks the formal claims before planning; native evidence still needs
/// independent conformance tests. It cannot establish that a daemon was read.
pub struct ValidatedCapabilities<'a> {
    facts: &'a DaemonFacts,
}

impl<'a> ValidatedCapabilities<'a> {
    pub fn new(facts: &'a DaemonFacts) -> Result<Self, CapabilityError> {
        let (Some(release), Some(api_version)) = (&facts.release, facts.api_version) else {
            return Err(CapabilityError::MissingDaemonIdentity);
        };
        if facts.mode == DaemonMode::Unknown {
            return Err(CapabilityError::MissingDaemonIdentity);
        }
        if facts
            .minimum_api_version
            .is_some_and(|minimum| minimum > api_version)
        {
            return Err(CapabilityError::InvalidApiRange);
        }
        let mut seen = HashSet::new();
        for fact in &facts.capabilities {
            if !seen.insert(fact.capability) {
                return Err(CapabilityError::DuplicateCapability);
            }
            match (fact.state, fact.provenance) {
                (CapabilityState::Available, FactProvenance::NativeConformance)
                | (CapabilityState::Unavailable, FactProvenance::NativeConformance)
                | (CapabilityState::Unavailable, FactProvenance::DaemonResponse)
                | (CapabilityState::Unknown, FactProvenance::Unknown) => {}
                _ => return Err(CapabilityError::InvalidProvenance),
            }
            match (&fact.scope, fact.state) {
                (None, CapabilityState::Unknown) => {}
                (Some(scope), CapabilityState::Available | CapabilityState::Unavailable)
                    if scope.observation_id == facts.observation_id
                        && scope.release == *release
                        && scope.api_version == api_version
                        && scope.mode == facts.mode => {}
                _ => return Err(CapabilityError::ScopeMismatch),
            }
        }
        Ok(Self { facts })
    }

    #[must_use]
    pub fn supports(&self, capability: Capability) -> bool {
        self.facts
            .capabilities
            .iter()
            .any(|fact| fact.capability == capability && fact.state == CapabilityState::Available)
    }

    #[must_use]
    pub fn facts(&self) -> &'a DaemonFacts {
        self.facts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> DaemonFacts {
        DaemonFacts {
            observation_id: ObservationId::fresh().unwrap(),
            release: EngineRelease::new("20.10.24".to_string()),
            api_version: Some(ApiVersion::new(NonZeroU16::new(1).unwrap(), 41)),
            minimum_api_version: None,
            mode: DaemonMode::Rootless,
            capabilities: vec![],
        }
    }

    #[test]
    fn available_capability_requires_native_provenance_and_exact_scope() {
        let mut daemon = facts();
        let scope = CapabilityScope {
            observation_id: daemon.observation_id,
            release: daemon.release.clone().unwrap(),
            api_version: daemon.api_version.unwrap(),
            mode: daemon.mode,
        };
        daemon.capabilities.push(CapabilityFact {
            capability: Capability::NamedVolume,
            state: CapabilityState::Available,
            provenance: FactProvenance::DaemonResponse,
            scope: Some(scope.clone()),
        });
        assert!(matches!(
            ValidatedCapabilities::new(&daemon),
            Err(CapabilityError::InvalidProvenance)
        ));
        daemon.capabilities[0].provenance = FactProvenance::NativeConformance;
        daemon.capabilities[0].scope.as_mut().unwrap().mode = DaemonMode::Rootful;
        assert!(matches!(
            ValidatedCapabilities::new(&daemon),
            Err(CapabilityError::ScopeMismatch)
        ));
        daemon.capabilities[0].scope = Some(scope);
        assert!(
            ValidatedCapabilities::new(&daemon)
                .unwrap()
                .supports(Capability::NamedVolume)
        );
        daemon.capabilities.push(daemon.capabilities[0].clone());
        assert!(matches!(
            ValidatedCapabilities::new(&daemon),
            Err(CapabilityError::DuplicateCapability)
        ));
    }

    #[test]
    fn incomplete_daemon_identity_cannot_be_planning_context() {
        let mut daemon = facts();
        daemon.mode = DaemonMode::Unknown;
        assert!(matches!(
            ValidatedCapabilities::new(&daemon),
            Err(CapabilityError::MissingDaemonIdentity)
        ));
    }

    #[test]
    fn same_version_daemons_cannot_exchange_capability_claims() {
        let first = facts();
        let mut second = facts();
        assert_ne!(first.observation_id, second.observation_id);
        assert_eq!(first.release, second.release);
        assert_eq!(first.api_version, second.api_version);
        assert_eq!(first.mode, second.mode);
        second.capabilities.push(CapabilityFact {
            capability: Capability::NamedVolume,
            state: CapabilityState::Available,
            provenance: FactProvenance::NativeConformance,
            scope: Some(CapabilityScope {
                observation_id: first.observation_id,
                release: first.release.clone().unwrap(),
                api_version: first.api_version.unwrap(),
                mode: first.mode,
            }),
        });
        assert!(matches!(
            ValidatedCapabilities::new(&second),
            Err(CapabilityError::ScopeMismatch)
        ));
    }
}
