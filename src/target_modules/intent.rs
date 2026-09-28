use super::{
    BridgeOption, ContainerIntent, NetworkDriver, NetworkIntent, NetworkRole, NetworkSource,
    RestartPolicy, TargetKind,
};
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
    Network(NetworkIntent),
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
            Self::Network(network) => network.reference,
            Self::Volume { reference, .. } => *reference,
            Self::Container(container) => container.reference,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        match self {
            Self::Network(_) => TargetKind::Network,
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
    InvalidNetworkDriver,
    DuplicateNetworkOption,
    InvalidNetworkOption,
    DuplicateNetworkLabel,
    InvalidNetworkLabel,
    InvalidNetworkAddress,
    DuplicateNetworkAddress,
    InvalidNetworkSubnet,
    InvalidNetworkIpam,
    InvalidNetworkAlias,
    DuplicateNetworkAlias,
    DuplicateNetworkAttachment,
    DuplicateDefaultNetwork,
    InvalidNetworkAttachment,
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
        let mut default_network = false;
        for resource in &resources {
            if let TargetResource::Network(network) = resource {
                if network.role == NetworkRole::ApplicationDefault {
                    if default_network {
                        return Err(IntentError::DuplicateDefaultNetwork);
                    }
                    default_network = true;
                }
            }
            let identity = match resource {
                TargetResource::Network(network) => &network.identity,
                TargetResource::Volume { identity, .. } => identity,
                TargetResource::Container(container) => &container.identity,
            };
            if !identities.insert((resource.kind(), identity.bytes())) {
                return Err(IntentError::DuplicateResource);
            }
        }
        for resource in &resources {
            if let TargetResource::Network(network) = resource {
                if let NetworkSource::External { expected_driver } = &network.source {
                    if *expected_driver != NetworkDriver::Bridge {
                        return Err(IntentError::InvalidNetworkDriver);
                    }
                }
                if let NetworkSource::Create(create) = &network.source {
                    if create.driver != NetworkDriver::Bridge {
                        return Err(IntentError::InvalidNetworkDriver);
                    }
                    let mut options = HashSet::new();
                    for option in &create.options {
                        let key = match option {
                            BridgeOption::Mtu(_) => 0,
                            BridgeOption::InterContainerCommunication(_) => 1,
                            BridgeOption::IpMasquerade(_) => 2,
                            BridgeOption::HostBindingIp(address) => {
                                if address.is_ipv6() {
                                    return Err(IntentError::InvalidNetworkOption);
                                }
                                3
                            }
                        };
                        if !options.insert(key) {
                            return Err(IntentError::DuplicateNetworkOption);
                        }
                    }
                    let mut labels = HashSet::new();
                    if !create.labels.iter().all(|label| labels.insert(label.key())) {
                        return Err(IntentError::DuplicateNetworkLabel);
                    }
                    if let Some(ipam) = &create.ipam {
                        if ipam.pools.is_empty() {
                            return Err(IntentError::InvalidNetworkIpam);
                        }
                        for (index, pool) in ipam.pools.iter().enumerate() {
                            if ipam.pools[..index]
                                .iter()
                                .any(|other| pool.subnet.overlaps(other.subnet))
                                || (pool.subnet.address().is_ipv6() && !create.enable_ipv6)
                                || pool.gateway.is_some_and(|gateway| {
                                    !pool.subnet.contains_usable_host(gateway)
                                })
                                || pool.ip_range.is_some_and(|range| {
                                    range.address().is_ipv6() != pool.subnet.address().is_ipv6()
                                        || range.prefix() < pool.subnet.prefix()
                                        || !pool.subnet.contains(range.address())
                                })
                            {
                                return Err(IntentError::InvalidNetworkIpam);
                            }
                            let mut auxiliary_names = HashSet::new();
                            let mut reserved_addresses = HashSet::new();
                            if let Some(gateway) = pool.gateway {
                                reserved_addresses.insert(gateway.value());
                            }
                            for auxiliary in &pool.auxiliary_addresses {
                                if !auxiliary_names.insert(auxiliary.name.bytes())
                                    || !pool.subnet.contains_usable_host(auxiliary.address)
                                    || !reserved_addresses.insert(auxiliary.address.value())
                                {
                                    return Err(IntentError::InvalidNetworkIpam);
                                }
                            }
                        }
                    }
                }
            }
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
                let mut networks = HashSet::new();
                for attachment in &container.networks {
                    if !networks.insert(attachment.network) {
                        return Err(IntentError::DuplicateNetworkAttachment);
                    }
                    if attachment
                        .ipv4_address
                        .is_some_and(|address| address.is_ipv6())
                        || attachment
                            .ipv6_address
                            .is_some_and(|address| !address.is_ipv6())
                    {
                        return Err(IntentError::InvalidNetworkAttachment);
                    }
                    let mut aliases = HashSet::new();
                    if !attachment
                        .aliases
                        .iter()
                        .all(|alias| aliases.insert(alias.bytes()))
                    {
                        return Err(IntentError::DuplicateNetworkAlias);
                    }
                    if let Some(TargetResource::Network(network)) = resources
                        .iter()
                        .find(|resource| resource.reference() == attachment.network)
                    {
                        match &network.source {
                            NetworkSource::External { .. }
                                if attachment.ipv4_address.is_some()
                                    || attachment.ipv6_address.is_some() =>
                            {
                                return Err(IntentError::InvalidNetworkAttachment);
                            }
                            NetworkSource::Create(create) => {
                                if attachment.ipv6_address.is_some() && !create.enable_ipv6 {
                                    return Err(IntentError::InvalidNetworkAttachment);
                                }
                                for address in [attachment.ipv4_address, attachment.ipv6_address]
                                    .into_iter()
                                    .flatten()
                                {
                                    if create.ipam.as_ref().is_none_or(|ipam| {
                                        !ipam.pools.iter().any(|pool| {
                                            pool.subnet.contains_usable_host(address)
                                                && pool.gateway != Some(address)
                                                && !pool
                                                    .auxiliary_addresses
                                                    .iter()
                                                    .any(|auxiliary| auxiliary.address == address)
                                        })
                                    }) {
                                        return Err(IntentError::InvalidNetworkAttachment);
                                    }
                                }
                            }
                            NetworkSource::External { .. } => {}
                        }
                    }
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
        let mut static_addresses = HashSet::new();
        for resource in &resources {
            if let TargetResource::Container(container) = resource {
                for attachment in &container.networks {
                    for address in [attachment.ipv4_address, attachment.ipv6_address]
                        .into_iter()
                        .flatten()
                    {
                        if !static_addresses.insert((attachment.network, address.value())) {
                            return Err(IntentError::DuplicateNetworkAddress);
                        }
                    }
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
