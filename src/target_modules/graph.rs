use super::{MountSource, TargetIntent, TargetResource};
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationNode {
    pub operation: Operation,
    pub depends_on: Vec<ResourceRef>,
}

#[derive(Debug)]
pub struct OperationGraph<'a> {
    intent: &'a TargetIntent,
    context: PlanningContext,
    nodes: Vec<OperationNode>,
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
    BindMount,
    NamedVolume,
    Network,
    Environment,
    Command,
    Entrypoint,
    Healthcheck,
    Restart,
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
                resource.reference() == node.operation.resource
                    && resource.kind() == node.operation.kind
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
                    .network
                    .into_iter()
                    .map(|reference| (reference, TargetKind::Network))
                    .chain(
                        container
                            .mounts
                            .iter()
                            .filter_map(|mount| match mount.source() {
                                MountSource::Volume(reference) => {
                                    Some((*reference, TargetKind::Volume))
                                }
                                MountSource::Bind(_) => None,
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
                TargetResource::Network { .. } => {
                    require(TargetField::Resource, Capability::BridgeNetwork)?
                }
                TargetResource::Volume { .. } => {
                    require(TargetField::Resource, Capability::NamedVolume)?
                }
                TargetResource::Container(container) => {
                    require(TargetField::Resource, Capability::StandaloneContainer)?;
                    if mode == DaemonMode::Rootless
                        && container.ports.iter().any(|port| port.host.get() < 1024)
                    {
                        return Err(PlanningError::RestrictedPort {
                            resource: reference,
                            mode,
                        });
                    }
                    if !container.ports.is_empty() {
                        require(TargetField::Port, Capability::PortPublish)?;
                    }
                    for mount in &container.mounts {
                        match mount.source() {
                            MountSource::Bind(_) => {
                                require(TargetField::BindMount, Capability::BindMount)?
                            }
                            MountSource::Volume(_) => {
                                require(TargetField::NamedVolume, Capability::NamedVolume)?
                            }
                        }
                    }
                    if container.network.is_some() {
                        require(TargetField::Network, Capability::BridgeNetwork)?;
                    }
                    if !container.environment.is_empty() {
                        require(TargetField::Environment, Capability::EnvironmentAssignment)?;
                    }
                    if container.command.is_some() {
                        require(TargetField::Command, Capability::Command)?;
                    }
                    if container.entrypoint.is_some() {
                        require(TargetField::Entrypoint, Capability::Entrypoint)?;
                    }
                    if container.healthcheck.is_some() {
                        require(TargetField::Healthcheck, Capability::Healthcheck)?;
                    }
                    if container.restart.is_some() {
                        require(TargetField::Restart, Capability::RestartPolicy)?;
                    }
                }
            }
        }
        Ok(Self {
            intent,
            context,
            nodes,
        })
    }

    #[must_use]
    pub fn nodes(&self) -> &[OperationNode] {
        &self.nodes
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
                        if let Some(network) = container.network {
                            references.push(network);
                        }
                        for mount in &container.mounts {
                            if let MountSource::Volume(reference) = mount.source()
                                && !references.contains(reference)
                            {
                                references.push(*reference);
                            }
                        }
                        references
                    }
                    TargetResource::Network { .. } | TargetResource::Volume { .. } => Vec::new(),
                };
                OperationNode {
                    operation: Operation {
                        resource: resource.reference(),
                        kind: resource.kind(),
                    },
                    depends_on,
                }
            })
            .collect();
        OperationGraph::new(intent, capabilities, nodes)
    }
}
