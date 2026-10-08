use super::{
    HealthTest, ImageCommand, MountSource, NetworkSource, PortHostIp, PortHostPort, TargetIntent,
    TargetResource,
};
use crate::observation::ResourceRef;
use crate::version::{
    ApiVersion, Capability, CapabilityScope, DaemonMode, TargetCapabilities, TargetProfile,
    ValidatedCapabilities,
};
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU16;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetKind {
    Network,
    Volume,
    Container,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    pub resource: ResourceRef,
    pub kind: TargetKind,
    pub action: OperationAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationAction {
    Create,
    RequireExisting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationNode {
    pub operation: Operation,
    pub depends_on: Vec<ResourceRef>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperationStepId {
    pub resource: ResourceRef,
    pub ordinal: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStepAction {
    Create(TargetKind),
    RequireExisting(TargetKind),
    ConnectNetwork {
        network: ResourceRef,
        attachment_index: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationStep {
    pub id: OperationStepId,
    pub action: OperationStepAction,
    pub depends_on: Vec<OperationStepId>,
}

#[derive(Debug)]
pub struct OperationGraph<'a> {
    intent: &'a TargetIntent,
    context: PlanningContext,
    nodes: Vec<OperationNode>,
    steps: Vec<OperationStep>,
}

/// The validated source of capability claims used for this inert graph.
/// Offline targets never acquire an observation ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanningContext {
    Observed(CapabilityScope),
    Target(TargetProfile),
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::version::ValidatedCapabilities<'_> {}
    impl Sealed for crate::version::TargetCapabilities<'_> {}
}

/// Only validated observed facts or a resolved offline target can be used.
pub trait PlanningCapabilitySet: sealed::Sealed {
    fn supports(&self, capability: Capability) -> bool;
    fn context(&self) -> PlanningContext;
}

impl PlanningCapabilitySet for ValidatedCapabilities<'_> {
    fn supports(&self, capability: Capability) -> bool {
        ValidatedCapabilities::supports(self, capability)
    }
    fn context(&self) -> PlanningContext {
        let facts = self.facts();
        PlanningContext::Observed(CapabilityScope {
            observation_id: facts.observation_id,
            release: facts
                .release
                .clone()
                .expect("validated daemon has a release"),
            api_version: facts
                .api_version
                .expect("validated daemon has an API version"),
            mode: facts.mode,
        })
    }
}

impl PlanningCapabilitySet for TargetCapabilities<'_> {
    fn supports(&self, capability: Capability) -> bool {
        TargetCapabilities::supports(self, capability)
    }
    fn context(&self) -> PlanningContext {
        PlanningContext::Target(self.profile().clone())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanningError {
    UnsupportedApi {
        actual: ApiVersion,
        minimum: ApiVersion,
    },
    MissingCapability {
        resource: ResourceRef,
        field: TargetField,
        capability: Capability,
    },
    RestrictedPort {
        resource: ResourceRef,
        mode: DaemonMode,
    },
    /// IPv4 /31 and /32 bridge pools await independent Engine evidence.
    UnsupportedNetworkIpam {
        resource: ResourceRef,
    },
    InvalidDependency,
    DependencyMismatch {
        resource: ResourceRef,
        dependency: ResourceRef,
        expected: TargetKind,
    },
    Cycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetField {
    Resource,
    Port,
    PortExposeOnly,
    PortHostIpv4,
    PortHostIpv6,
    PortMultipleBindings,
    PortEphemeral,
    BindMount,
    BindRelabel,
    TmpfsMount,
    NamedVolume,
    VolumeLabels,
    Network,
    NetworkInternal,
    NetworkIpv6,
    NetworkIpam,
    NetworkIpamDriver,
    NetworkOptions,
    NetworkLabels,
    NetworkAliases,
    NetworkStaticAddress,
    NetworkMultipleAttachment,
    NetworkExternalReference,
    NetworkExternalInternalExpectation,
    VolumeExternalReference,
    Environment,
    Command,
    CommandClear,
    Entrypoint,
    EntrypointClear,
    Healthcheck,
    HealthShell,
    HealthDisabled,
    HealthStartPeriod,
    HealthStartInterval,
    Restart,
    ContainerLabels,
    ContainerUser,
    ContainerWorkdir,
    ContainerHostname,
    ReadOnlyRootfs,
    ContainerInit,
    StopSignal,
    StopTimeout,
    MemoryLimit,
    PidsLimit,
    ShmSize,
    Ulimits,
    UlimitNofile,
    DeviceMappings,
    LinuxCapabilities,
    CapAddNetBindService,
    CapDropSysAdmin,
    SecurityOptions,
    Sysctls,
    SysctlIpv4Forward,
    SupplementaryGroups,
    DnsServers,
    ExtraHosts,
    LogConfig,
    LogOptionMaxSize,
    UserNamespace,
}

impl<'a> OperationGraph<'a> {
    /// Validate every operation, dependency, and setting capability.
    pub fn new(
        intent: &'a TargetIntent,
        capabilities: &dyn PlanningCapabilitySet,
        nodes: Vec<OperationNode>,
    ) -> Result<Self, PlanningError> {
        let mut references = HashSet::new();
        if nodes.len() != intent.resources().len()
            || !nodes
                .iter()
                .all(|node| references.insert(node.operation.resource))
        {
            return Err(PlanningError::InvalidDependency);
        }
        if nodes.iter().any(|node| {
            !intent.resources().iter().any(|resource| {
                let action = match resource {
                    TargetResource::Network(network)
                        if matches!(&network.source, NetworkSource::External { .. }) =>
                    {
                        OperationAction::RequireExisting
                    }
                    TargetResource::ExternalVolume { .. } => OperationAction::RequireExisting,
                    _ => OperationAction::Create,
                };
                resource.reference() == node.operation.resource
                    && resource.kind() == node.operation.kind
                    && node.operation.action == action
            })
        }) {
            return Err(PlanningError::InvalidDependency);
        }
        if nodes.iter().any(|node| {
            node.depends_on.iter().any(|dependency| {
                !references.contains(dependency) || *dependency == node.operation.resource
            })
        }) {
            return Err(PlanningError::InvalidDependency);
        }

        let resources: HashMap<_, _> = intent
            .resources()
            .iter()
            .map(|resource| (resource.reference(), resource))
            .collect();
        for node in &nodes {
            if let Some(TargetResource::Container(container)) =
                resources.get(&node.operation.resource)
            {
                let required = container
                    .networks
                    .iter()
                    .map(|attachment| (attachment.network, TargetKind::Network))
                    .chain(
                        container
                            .mounts
                            .iter()
                            .filter_map(|mount| match mount.source() {
                                MountSource::Volume(reference) => {
                                    Some((*reference, TargetKind::Volume))
                                }
                                MountSource::Bind(_) | MountSource::Tmpfs(_) => None,
                            }),
                    );
                for (reference, kind) in required {
                    if resources
                        .get(&reference)
                        .is_none_or(|resource| resource.kind() != kind)
                        || !node.depends_on.contains(&reference)
                    {
                        return Err(PlanningError::DependencyMismatch {
                            resource: node.operation.resource,
                            dependency: reference,
                            expected: kind,
                        });
                    }
                }
            }
        }

        let mut remaining = HashMap::new();
        let mut dependents: HashMap<ResourceRef, Vec<ResourceRef>> = HashMap::new();
        for node in &nodes {
            let dependencies: HashSet<_> = node.depends_on.iter().copied().collect();
            remaining.insert(node.operation.resource, dependencies.len());
            for dependency in dependencies {
                dependents
                    .entry(dependency)
                    .or_default()
                    .push(node.operation.resource);
            }
        }
        let mut ready: Vec<_> = remaining
            .iter()
            .filter_map(|(reference, count)| (*count == 0).then_some(*reference))
            .collect();
        let mut visited = 0;
        while let Some(reference) = ready.pop() {
            visited += 1;
            if let Some(next) = dependents.get(&reference) {
                for dependent in next {
                    let count = remaining
                        .get_mut(dependent)
                        .expect("dependent was validated above");
                    *count -= 1;
                    if *count == 0 {
                        ready.push(*dependent);
                    }
                }
            }
        }
        if visited != nodes.len() {
            return Err(PlanningError::Cycle);
        }
        let context = capabilities.context();
        let api = match &context {
            PlanningContext::Observed(scope) => scope.api_version,
            PlanningContext::Target(profile) => profile.rendering_api_version(),
        };
        let mode = match &context {
            PlanningContext::Observed(scope) => scope.mode,
            PlanningContext::Target(profile) => profile.mode(),
        };
        let minimum = ApiVersion::new(NonZeroU16::new(1).expect("nonzero"), 41);
        if api.major.get() != 1 || api < minimum {
            return Err(PlanningError::UnsupportedApi {
                actual: api,
                minimum,
            });
        }
        for resource in intent.resources() {
            let reference = resource.reference();
            let require = |field, capability| {
                capabilities.supports(capability).then_some(()).ok_or(
                    PlanningError::MissingCapability {
                        resource: reference,
                        field,
                        capability,
                    },
                )
            };
            match resource {
                TargetResource::Network(network) => match &network.source {
                    NetworkSource::Create(create) => {
                        require(TargetField::Resource, Capability::BridgeNetwork)?;
                        if create.ipam.as_ref().is_some_and(|ipam| {
                            ipam.pools.iter().any(|pool| {
                                !pool.subnet.address().is_ipv6() && pool.subnet.prefix() >= 31
                            })
                        }) {
                            return Err(PlanningError::UnsupportedNetworkIpam {
                                resource: reference,
                            });
                        }
                        if create.internal {
                            require(TargetField::NetworkInternal, Capability::NetworkInternal)?;
                        }
                        if create.enable_ipv6 {
                            require(TargetField::NetworkIpv6, Capability::NetworkIpv6)?;
                        }
                        if create.ipam.is_some() {
                            require(TargetField::NetworkIpam, Capability::NetworkIpam)?;
                        }
                        if create
                            .ipam
                            .as_ref()
                            .is_some_and(|ipam| ipam.driver.is_some())
                        {
                            require(
                                TargetField::NetworkIpamDriver,
                                Capability::NetworkIpamDriver,
                            )?;
                        }
                        if !create.options.is_empty() {
                            require(TargetField::NetworkOptions, Capability::NetworkOptions)?;
                        }
                        if !create.labels.is_empty() {
                            require(TargetField::NetworkLabels, Capability::NetworkLabels)?;
                        }
                    }
                    NetworkSource::External {
                        expected_internal, ..
                    } => {
                        require(
                            TargetField::NetworkExternalReference,
                            Capability::NetworkExternalReference,
                        )?;
                        if expected_internal.is_some() {
                            require(
                                TargetField::NetworkExternalInternalExpectation,
                                Capability::NetworkExternalInternalExpectation,
                            )?;
                        }
                    }
                },
                TargetResource::Volume { labels, .. } => {
                    require(TargetField::Resource, Capability::NamedVolume)?;
                    if !labels.is_empty() {
                        require(TargetField::VolumeLabels, Capability::VolumeLabels)?;
                    }
                }
                TargetResource::ExternalVolume { .. } => require(
                    TargetField::VolumeExternalReference,
                    Capability::VolumeExternalReference,
                )?,
                TargetResource::Container(container) => {
                    require(TargetField::Resource, Capability::StandaloneContainer)?;
                    if mode == DaemonMode::Rootless
                        && container.ports.iter().flat_map(|port| port.bindings()).any(|binding| {
                            matches!(binding.host_port, PortHostPort::Fixed(port) if port.get() < 1024)
                        })
                    {
                        return Err(PlanningError::RestrictedPort {
                            resource: reference,
                            mode,
                        });
                    }
                    for port in &container.ports {
                        if port.bindings().is_empty() {
                            require(TargetField::PortExposeOnly, Capability::PortExposeOnly)?;
                        } else {
                            require(TargetField::Port, Capability::PortPublish)?;
                        }
                        if port.bindings().len() > 1 {
                            require(
                                TargetField::PortMultipleBindings,
                                Capability::PortMultipleBindings,
                            )?;
                        }
                        for binding in port.bindings() {
                            match binding.host_ip {
                                PortHostIp::Unspecified => {}
                                PortHostIp::Address(std::net::IpAddr::V4(_)) => {
                                    require(TargetField::PortHostIpv4, Capability::PortHostIpv4)?;
                                }
                                PortHostIp::Address(std::net::IpAddr::V6(_)) => {
                                    require(TargetField::PortHostIpv6, Capability::PortHostIpv6)?;
                                }
                            }
                            if binding.host_port == PortHostPort::Ephemeral {
                                require(TargetField::PortEphemeral, Capability::PortEphemeral)?;
                            }
                        }
                    }
                    for mount in &container.mounts {
                        match mount.source() {
                            MountSource::Bind(_) => {
                                require(TargetField::BindMount, Capability::BindMount)?
                            }
                            MountSource::Volume(_) => {
                                require(TargetField::NamedVolume, Capability::NamedVolume)?
                            }
                            MountSource::Tmpfs(_) => {
                                require(TargetField::TmpfsMount, Capability::TmpfsMount)?
                            }
                        }
                        if let Some(relabel) = mount.bind_relabel() {
                            let capability = match relabel {
                                super::BindRelabel::Shared => Capability::BindRelabelShared,
                                super::BindRelabel::Private => Capability::BindRelabelPrivate,
                            };
                            require(TargetField::BindRelabel, capability)?;
                        }
                    }
                    if !container.networks.is_empty() {
                        require(TargetField::Network, Capability::BridgeNetwork)?;
                    }
                    if container.networks.len() > 1 {
                        require(
                            TargetField::NetworkMultipleAttachment,
                            Capability::NetworkMultipleAttachment,
                        )?;
                    }
                    for attachment in &container.networks {
                        if !attachment.aliases.is_empty() {
                            require(TargetField::NetworkAliases, Capability::NetworkAliases)?;
                        }
                        if attachment.ipv4_address.is_some() || attachment.ipv6_address.is_some() {
                            require(
                                TargetField::NetworkStaticAddress,
                                Capability::NetworkStaticAddress,
                            )?;
                        }
                    }
                    if !container.environment.is_empty() {
                        require(TargetField::Environment, Capability::EnvironmentAssignment)?;
                    }
                    match &container.command {
                        ImageCommand::Inherit => {}
                        ImageCommand::Clear => {
                            require(TargetField::CommandClear, Capability::CommandClear)?
                        }
                        ImageCommand::Exec(_) => {
                            require(TargetField::Command, Capability::Command)?
                        }
                    }
                    match &container.entrypoint {
                        ImageCommand::Inherit => {}
                        ImageCommand::Clear => {
                            require(TargetField::EntrypointClear, Capability::EntrypointClear)?
                        }
                        ImageCommand::Exec(_) => {
                            require(TargetField::Entrypoint, Capability::Entrypoint)?
                        }
                    }
                    if let Some(health) = &container.healthcheck {
                        match health.test() {
                            HealthTest::Exec(_) => {
                                require(TargetField::Healthcheck, Capability::Healthcheck)?
                            }
                            HealthTest::Shell(_) => {
                                require(TargetField::HealthShell, Capability::HealthShell)?
                            }
                            HealthTest::Disabled => {
                                require(TargetField::HealthDisabled, Capability::HealthDisabled)?
                            }
                        }
                        if health.start_period_ns().is_some() {
                            require(
                                TargetField::HealthStartPeriod,
                                Capability::HealthStartPeriod,
                            )?;
                        }
                        if health.start_interval_ns().is_some() {
                            require(
                                TargetField::HealthStartInterval,
                                Capability::HealthStartInterval,
                            )?;
                        }
                    }
                    if container.restart.is_some() {
                        require(TargetField::Restart, Capability::RestartPolicy)?;
                    }
                    if !container.settings.labels.is_empty() {
                        require(TargetField::ContainerLabels, Capability::ContainerLabels)?;
                    }
                    if container.settings.user.is_some() {
                        require(TargetField::ContainerUser, Capability::ContainerUser)?;
                    }
                    if container.settings.working_dir.is_some() {
                        require(TargetField::ContainerWorkdir, Capability::ContainerWorkdir)?;
                    }
                    if container.settings.hostname.is_some() {
                        require(
                            TargetField::ContainerHostname,
                            Capability::ContainerHostname,
                        )?;
                    }
                    if container.settings.read_only_rootfs.is_some() {
                        require(TargetField::ReadOnlyRootfs, Capability::ReadOnlyRootfs)?;
                    }
                    if container.settings.init.is_some() {
                        require(TargetField::ContainerInit, Capability::ContainerInit)?;
                    }
                    if container.settings.stop_signal.is_some() {
                        require(TargetField::StopSignal, Capability::StopSignal)?;
                    }
                    if container.settings.stop_timeout_seconds.is_some() {
                        require(TargetField::StopTimeout, Capability::StopTimeout)?;
                    }
                    if container.settings.memory_limit.is_some() {
                        require(TargetField::MemoryLimit, Capability::MemoryLimit)?;
                    }
                    if container.settings.pids_limit.is_some() {
                        require(TargetField::PidsLimit, Capability::PidsLimit)?;
                    }
                    if container.settings.shm_size_bytes.is_some() {
                        require(TargetField::ShmSize, Capability::ShmSize)?;
                    }
                    if !container.settings.ulimits.is_empty() {
                        require(TargetField::Ulimits, Capability::Ulimits)?;
                        require(TargetField::UlimitNofile, Capability::UlimitNofile)?;
                    }
                    if !container.settings.devices.is_empty() {
                        require(TargetField::DeviceMappings, Capability::DeviceMappings)?;
                    }
                    if !container.settings.cap_add.is_empty()
                        || !container.settings.cap_drop.is_empty()
                    {
                        require(
                            TargetField::LinuxCapabilities,
                            Capability::LinuxCapabilities,
                        )?;
                    }
                    if !container.settings.cap_add.is_empty() {
                        require(
                            TargetField::CapAddNetBindService,
                            Capability::CapAddNetBindService,
                        )?;
                    }
                    if !container.settings.cap_drop.is_empty() {
                        require(TargetField::CapDropSysAdmin, Capability::CapDropSysAdmin)?;
                    }
                    if !container.settings.security_options.is_empty() {
                        require(TargetField::SecurityOptions, Capability::SecurityOptions)?;
                    }
                    if !container.settings.sysctls.is_empty() {
                        require(TargetField::Sysctls, Capability::Sysctls)?;
                        require(
                            TargetField::SysctlIpv4Forward,
                            Capability::SysctlIpv4Forward,
                        )?;
                    }
                    if !container.settings.group_add.is_empty() {
                        require(
                            TargetField::SupplementaryGroups,
                            Capability::SupplementaryGroups,
                        )?;
                    }
                    if !container.settings.dns.is_empty() {
                        require(TargetField::DnsServers, Capability::DnsServers)?;
                    }
                    if !container.settings.extra_hosts.is_empty() {
                        require(TargetField::ExtraHosts, Capability::ExtraHosts)?;
                    }
                    if container.settings.log_config.is_some() {
                        require(TargetField::LogConfig, Capability::LogConfig)?;
                    }
                    if container
                        .settings
                        .log_config
                        .as_ref()
                        .is_some_and(|log| !log.options.is_empty())
                    {
                        require(TargetField::LogOptionMaxSize, Capability::LogOptionMaxSize)?;
                    }
                    if container.settings.userns_mode.is_some() {
                        require(TargetField::UserNamespace, Capability::UserNamespace)?;
                    }
                }
            }
        }
        let mut steps = Vec::new();
        for node in &nodes {
            let base_id = OperationStepId {
                resource: node.operation.resource,
                ordinal: 0,
            };
            steps.push(OperationStep {
                id: base_id,
                action: match node.operation.action {
                    OperationAction::Create => OperationStepAction::Create(node.operation.kind),
                    OperationAction::RequireExisting => {
                        OperationStepAction::RequireExisting(node.operation.kind)
                    }
                },
                depends_on: node
                    .depends_on
                    .iter()
                    .map(|reference| OperationStepId {
                        resource: *reference,
                        ordinal: 0,
                    })
                    .collect(),
            });
            if let Some(TargetResource::Container(container)) =
                resources.get(&node.operation.resource)
            {
                for (attachment_index, attachment) in container.networks.iter().enumerate().skip(1)
                {
                    steps.push(OperationStep {
                        id: OperationStepId {
                            resource: node.operation.resource,
                            ordinal: attachment_index,
                        },
                        action: OperationStepAction::ConnectNetwork {
                            network: attachment.network,
                            attachment_index,
                        },
                        depends_on: vec![
                            base_id,
                            OperationStepId {
                                resource: attachment.network,
                                ordinal: 0,
                            },
                        ],
                    });
                }
            }
        }
        Ok(Self {
            intent,
            context,
            nodes,
            steps,
        })
    }

    #[must_use]
    pub fn nodes(&self) -> &[OperationNode] {
        &self.nodes
    }

    #[must_use]
    pub fn steps(&self) -> &[OperationStep] {
        &self.steps
    }

    #[must_use]
    pub fn intent(&self) -> &'a TargetIntent {
        self.intent
    }

    #[must_use]
    pub fn context(&self) -> &PlanningContext {
        &self.context
    }
}

/// Implementations must prove required capabilities for the requested daemon.
pub trait Planner {
    fn plan<'a>(
        &self,
        intent: &'a TargetIntent,
        capabilities: &dyn PlanningCapabilitySet,
    ) -> Result<OperationGraph<'a>, PlanningError>;
}

/// Builds dependencies only from explicit target references.
pub struct DockerPlanner;

impl Planner for DockerPlanner {
    fn plan<'a>(
        &self,
        intent: &'a TargetIntent,
        capabilities: &dyn PlanningCapabilitySet,
    ) -> Result<OperationGraph<'a>, PlanningError> {
        let nodes = intent
            .resources()
            .iter()
            .map(|resource| {
                let depends_on = match resource {
                    TargetResource::Container(container) => {
                        let mut references = Vec::new();
                        for attachment in &container.networks {
                            if !references.contains(&attachment.network) {
                                references.push(attachment.network);
                            }
                        }
                        for mount in &container.mounts {
                            if let MountSource::Volume(reference) = mount.source() {
                                if !references.contains(reference) {
                                    references.push(*reference);
                                }
                            }
                        }
                        references
                    }
                    TargetResource::Network(_)
                    | TargetResource::Volume { .. }
                    | TargetResource::ExternalVolume { .. } => Vec::new(),
                };
                OperationNode {
                    operation: Operation {
                        resource: resource.reference(),
                        kind: resource.kind(),
                        action: match resource {
                            TargetResource::Network(network)
                                if matches!(&network.source, NetworkSource::External { .. }) =>
                            {
                                OperationAction::RequireExisting
                            }
                            TargetResource::ExternalVolume { .. } => {
                                OperationAction::RequireExisting
                            }
                            _ => OperationAction::Create,
                        },
                    },
                    depends_on,
                }
            })
            .collect();
        OperationGraph::new(intent, capabilities, nodes)
    }
}
