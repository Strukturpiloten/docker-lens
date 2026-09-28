use super::{ContainerIntent, RestartPolicy, TargetKind};
use crate::evidence::ProtectedValue;
use crate::observation::ResourceRef;
use std::collections::HashSet;

/// Explicit desired identity, never an observed or runtime-assigned name.
pub struct TargetIdentity(ProtectedValue);

impl TargetIdentity {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        if !valid_identity(&bytes) {
            return Err(IntentError::InvalidIdentity);
        }
        Ok(Self(ProtectedValue::new(bytes)))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for TargetIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TargetIdentity([redacted])")
    }
}

fn valid_identity(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.'))
}

#[derive(Debug)]
pub enum TargetResource {
    Network {
        reference: ResourceRef,
        identity: TargetIdentity,
    },
    Volume {
        reference: ResourceRef,
        identity: TargetIdentity,
    },
    Container(Box<ContainerIntent>),
}

impl TargetResource {
    #[must_use]
    pub const fn reference(&self) -> ResourceRef {
        match self {
            Self::Network { reference, .. } | Self::Volume { reference, .. } => *reference,
            Self::Container(container) => container.reference,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        match self {
            Self::Network { .. } => TargetKind::Network,
            Self::Volume { .. } => TargetKind::Volume,
            Self::Container(_) => TargetKind::Container,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentError {
    Empty,
    DuplicateResource,
    UnsupportedOrchestration,
    InvalidIdentity,
    InvalidImage,
    InvalidEnvironment,
    InvalidArgument,
    InvalidMount,
    InvalidHealthcheck,
    InvalidRestart,
    DuplicatePort,
    DuplicateMount,
}

#[derive(Debug)]
pub struct TargetIntent {
    resources: Vec<TargetResource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Orchestration {
    Standalone,
    Swarm,
}

impl TargetIntent {
    pub fn new(resources: Vec<TargetResource>) -> Result<Self, IntentError> {
        Self::new_with_orchestration(resources, Orchestration::Standalone)
    }

    pub fn new_with_orchestration(
        resources: Vec<TargetResource>,
        orchestration: Orchestration,
    ) -> Result<Self, IntentError> {
        if orchestration != Orchestration::Standalone {
            return Err(IntentError::UnsupportedOrchestration);
        }
        if resources.is_empty() {
            return Err(IntentError::Empty);
        }
        let mut seen = HashSet::new();
        if !resources
            .iter()
            .all(|resource| seen.insert(resource.reference()))
        {
            return Err(IntentError::DuplicateResource);
        }
        let mut identities = HashSet::new();
        for resource in &resources {
            let identity = match resource {
                TargetResource::Network { identity, .. }
                | TargetResource::Volume { identity, .. } => identity,
                TargetResource::Container(container) => &container.identity,
            };
            if !identities.insert((resource.kind(), identity.bytes())) {
                return Err(IntentError::DuplicateResource);
            }
        }
        for resource in &resources {
            if let TargetResource::Container(container) = resource {
                let mut environment = HashSet::new();
                if !container
                    .environment
                    .iter()
                    .all(|assignment| environment.insert(assignment.key()))
                {
                    return Err(IntentError::InvalidEnvironment);
                }
                let mut ports = HashSet::new();
                let mut host_ports = HashSet::new();
                if !container.ports.iter().all(|port| {
                    ports.insert((port.container, port.protocol))
                        && host_ports.insert((port.host, port.protocol))
                }) {
                    return Err(IntentError::DuplicatePort);
                }
                let mut mounts = HashSet::new();
                if !container
                    .mounts
                    .iter()
                    .all(|mount| mounts.insert(mount.target()))
                {
                    return Err(IntentError::DuplicateMount);
                }
                for arguments in [&container.entrypoint, &container.command]
                    .into_iter()
                    .flatten()
                {
                    if arguments.is_empty() || arguments[0].bytes().is_empty() {
                        return Err(IntentError::InvalidArgument);
                    }
                }
                if matches!(container.restart, Some(RestartPolicy::OnFailure { maximum_retries }) if maximum_retries > i32::MAX as u32)
                {
                    return Err(IntentError::InvalidRestart);
                }
            }
        }
        Ok(Self { resources })
    }

    #[must_use]
    pub fn resources(&self) -> &[TargetResource] {
        &self.resources
    }
}
