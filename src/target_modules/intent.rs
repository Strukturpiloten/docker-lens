use super::container::valid_user_principal;
use super::volume::{MAX_VOLUME_LABEL_COUNT, MAX_VOLUME_LABEL_TOTAL_BYTES};
use super::{
    BridgeOption, ContainerIntent, ContainerSettings, ImageCommand, LogDriver, MemoryLimit,
    NetworkDriver, NetworkIntent, NetworkRole, NetworkSource, PidsLimit, PortHostIp, PortHostPort,
    RestartPolicy, TargetKind, UlimitValue, VolumeLabel,
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
        labels: Vec<VolumeLabel>,
    },
    /// Exact caller-supplied destination name; existence and data are not inferred.
    ExternalVolume {
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
            Self::Volume { reference, .. } | Self::ExternalVolume { reference, .. } => *reference,
            Self::Container(container) => container.reference,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        match self {
            Self::Network(_) => TargetKind::Network,
            Self::Volume { .. } | Self::ExternalVolume { .. } => TargetKind::Volume,
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
    CommandClearRequiresEntrypoint,
    InvalidMount,
    InvalidHealthcheck,
    InvalidRestart,
    DuplicatePort,
    InvalidPort,
    DuplicateMount,
    InvalidContainerLabel,
    DuplicateContainerLabel,
    InvalidContainerUser,
    InvalidWorkingDirectory,
    InvalidContainerHostname,
    InvalidContainerSetting,
    DuplicateContainerSetting,
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
    InvalidVolumeLabel,
    DuplicateVolumeLabel,
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
        let mut fixed_host_ports = Vec::new();
        for resource in &resources {
            if let TargetResource::Volume { labels, .. } = resource {
                if labels.len() > MAX_VOLUME_LABEL_COUNT
                    || labels
                        .iter()
                        .map(|label| label.key().len() + label.value().len())
                        .sum::<usize>()
                        > MAX_VOLUME_LABEL_TOTAL_BYTES
                {
                    return Err(IntentError::InvalidVolumeLabel);
                }
                let mut keys = HashSet::new();
                if !labels.iter().all(|label| keys.insert(label.key())) {
                    return Err(IntentError::DuplicateVolumeLabel);
                }
            }
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
                TargetResource::Volume { identity, .. }
                | TargetResource::ExternalVolume { identity, .. } => identity,
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
                for port in &container.ports {
                    if !ports.insert((port.container, port.protocol)) {
                        return Err(IntentError::DuplicatePort);
                    }
                    let mut dynamic_hosts = Vec::new();
                    for binding in port.bindings() {
                        match binding.host_port {
                            PortHostPort::Fixed(host_port) => {
                                if fixed_host_ports
                                    .iter()
                                    .any(|(existing, protocol, address)| {
                                        *existing == host_port
                                            && *protocol == port.protocol
                                            && host_ip_overlaps(*address, binding.host_ip)
                                    })
                                {
                                    return Err(IntentError::DuplicatePort);
                                }
                                fixed_host_ports.push((host_port, port.protocol, binding.host_ip));
                            }
                            PortHostPort::Ephemeral => {
                                if dynamic_hosts
                                    .iter()
                                    .any(|address| host_ip_overlaps(*address, binding.host_ip))
                                {
                                    return Err(IntentError::DuplicatePort);
                                }
                                dynamic_hosts.push(binding.host_ip);
                            }
                        }
                    }
                }
                let mut labels = HashSet::new();
                if !container
                    .settings
                    .labels
                    .iter()
                    .all(|label| labels.insert(label.key()))
                {
                    return Err(IntentError::DuplicateContainerLabel);
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
                    .all(|mount| mounts.insert(lexical_absolute_path_key(mount.target())))
                    || container.settings.devices.iter().any(|device| {
                        mounts.contains(&lexical_absolute_path_key(device.container_path.bytes()))
                    })
                {
                    return Err(IntentError::DuplicateMount);
                }
                for command in [&container.entrypoint, &container.command] {
                    if let ImageCommand::Exec(arguments) = command {
                        if arguments.is_empty() || arguments[0].bytes().is_empty() {
                            return Err(IntentError::InvalidArgument);
                        }
                    }
                }
                if matches!(&container.command, ImageCommand::Clear)
                    && !matches!(&container.entrypoint, ImageCommand::Exec(_))
                {
                    return Err(IntentError::CommandClearRequiresEntrypoint);
                }
                if container
                    .settings
                    .stop_signal
                    .as_ref()
                    .is_some_and(|value| value.bytes().is_empty())
                {
                    return Err(IntentError::InvalidArgument);
                }
                validate_container_settings(&container.settings)?;
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

// Linux mount destinations are compared lexically after slash/dot cleaning.
// This key never rewrites authored bytes or resolves filesystem/symlink state.
fn lexical_absolute_path_key(path: &[u8]) -> Vec<&[u8]> {
    let mut components = Vec::new();
    for component in path.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." => {
                components.pop();
            }
            _ => components.push(component),
        }
    }
    components
}

fn host_ip_overlaps(left: PortHostIp, right: PortHostIp) -> bool {
    let wildcard = |address| match address {
        PortHostIp::Unspecified => true,
        PortHostIp::Address(std::net::IpAddr::V4(value)) => value.is_unspecified(),
        PortHostIp::Address(std::net::IpAddr::V6(value)) => value.is_unspecified(),
    };
    wildcard(left) || wildcard(right) || left == right
}

fn validate_container_settings(settings: &ContainerSettings) -> Result<(), IntentError> {
    if matches!(settings.memory_limit, Some(MemoryLimit::Bytes(value)) if value.get() > i64::MAX as u64)
        || matches!(settings.pids_limit, Some(PidsLimit::Count(value)) if value.get() > i64::MAX as u64)
        || settings
            .shm_size_bytes
            .is_some_and(|value| value.get() > i64::MAX as u64)
    {
        return Err(IntentError::InvalidContainerSetting);
    }
    let mut names = HashSet::new();
    for limit in &settings.ulimits {
        let valid_value = |value| match value {
            UlimitValue::Unlimited => true,
            UlimitValue::Value(number) => number <= i64::MAX as u64,
        };
        if limit.name.bytes() != b"nofile"
            || !names.insert(limit.name.bytes())
            || !valid_value(limit.soft)
            || !valid_value(limit.hard)
            || matches!(
                (limit.soft, limit.hard),
                (UlimitValue::Unlimited, UlimitValue::Value(_))
            )
            || matches!((limit.soft, limit.hard), (UlimitValue::Value(soft), UlimitValue::Value(hard)) if soft > hard)
        {
            return Err(IntentError::InvalidContainerSetting);
        }
    }
    let mut targets = HashSet::new();
    for device in &settings.devices {
        let permissions = device.permissions;
        if !targets.insert(device.container_path.bytes())
            || !(permissions.read || permissions.write || permissions.create)
        {
            return Err(IntentError::InvalidContainerSetting);
        }
    }
    let mut capabilities = HashSet::new();
    for token in settings.cap_add.iter().chain(&settings.cap_drop) {
        if !capabilities.insert(token.bytes()) {
            return Err(IntentError::DuplicateContainerSetting);
        }
    }
    if settings
        .cap_add
        .iter()
        .any(|token| token.bytes() != b"NET_BIND_SERVICE")
        || settings
            .cap_drop
            .iter()
            .any(|token| token.bytes() != b"SYS_ADMIN")
    {
        return Err(IntentError::InvalidContainerSetting);
    }
    let mut unique = HashSet::new();
    if !settings
        .security_options
        .iter()
        .all(|item| unique.insert(std::mem::discriminant(item)))
    {
        return Err(IntentError::DuplicateContainerSetting);
    }
    let mut unique = HashSet::new();
    for item in &settings.sysctls {
        if item.key() != b"net.ipv4.ip_forward" || !matches!(item.value(), b"0" | b"1") {
            return Err(IntentError::InvalidContainerSetting);
        }
        if !unique.insert(item.key()) {
            return Err(IntentError::DuplicateContainerSetting);
        }
    }
    let mut unique = HashSet::new();
    if !settings
        .group_add
        .iter()
        .all(|item| unique.insert(item.bytes()))
    {
        return Err(IntentError::DuplicateContainerSetting);
    }
    if settings
        .group_add
        .iter()
        .any(|item| !valid_user_principal(item.bytes()))
    {
        return Err(IntentError::InvalidContainerSetting);
    }
    let mut unique = HashSet::new();
    if !settings
        .extra_hosts
        .iter()
        .all(|item| unique.insert(item.name.bytes()))
    {
        return Err(IntentError::DuplicateContainerSetting);
    }
    if let Some(log) = &settings.log_config {
        if log.driver == LogDriver::None && !log.options.is_empty() {
            return Err(IntentError::InvalidContainerSetting);
        }
        let mut unique = HashSet::new();
        for item in &log.options {
            if log.driver != LogDriver::JsonFile
                || item.key() != b"max-size"
                || !valid_log_max_size(item.value())
            {
                return Err(IntentError::InvalidContainerSetting);
            }
            if !unique.insert(item.key()) {
                return Err(IntentError::DuplicateContainerSetting);
            }
        }
    }
    Ok(())
}

fn valid_log_max_size(value: &[u8]) -> bool {
    let Some((&suffix, digits)) = value.split_last() else {
        return false;
    };
    matches!(suffix, b'k' | b'm' | b'g')
        && !digits.is_empty()
        && std::str::from_utf8(digits)
            .ok()
            .and_then(|digits| digits.parse::<u64>().ok())
            .is_some_and(|size| size != 0)
}
