//! Explicit standalone intent, capability-gated planning, and inert Engine requests.
//!
//! Nothing in this module contacts a daemon, executes a request, or writes a file.

use crate::evidence::ProtectedValue;
use crate::observation::ResourceRef;
use crate::version::{
    ApiVersion, Capability, CapabilityScope, DaemonMode, TargetCapabilities, TargetProfile,
    ValidatedCapabilities,
};
use std::collections::{HashMap, HashSet};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

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

/// An explicit image reference, with no inferred tag or platform.
pub struct ImageReference(ProtectedValue);

impl ImageReference {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        let Ok(value) = std::str::from_utf8(&bytes) else {
            return Err(IntentError::InvalidImage);
        };
        if value.is_empty() || value.chars().any(char::is_whitespace) || value.contains('\0') {
            return Err(IntentError::InvalidImage);
        }
        Ok(Self(ProtectedValue::new(bytes)))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ImageReference([redacted])")
    }
}

/// An authored assignment, including an explicitly empty value.
pub struct EnvironmentAssignment {
    key: ProtectedValue,
    value: ProtectedValue,
}

impl EnvironmentAssignment {
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Result<Self, IntentError> {
        if key.is_empty()
            || key.contains(&b'=')
            || key.contains(&0)
            || value.contains(&0)
            || std::str::from_utf8(&key).is_err()
            || std::str::from_utf8(&value).is_err()
        {
            return Err(IntentError::InvalidEnvironment);
        }
        Ok(Self {
            key: ProtectedValue::new(key),
            value: ProtectedValue::new(value),
        })
    }

    #[must_use]
    pub fn key(&self) -> &[u8] {
        self.key.as_bytes()
    }

    #[must_use]
    pub fn value(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

impl std::fmt::Debug for EnvironmentAssignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnvironmentAssignment([redacted])")
    }
}

/// An argument is one Engine exec-form element, never a shell fragment.
pub struct Argument(ProtectedValue);

impl Argument {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
            return Err(IntentError::InvalidArgument);
        }
        Ok(Self(ProtectedValue::new(bytes)))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for Argument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Argument([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A fixed host port. Runtime-assigned ports are deliberately not inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortBinding {
    pub host: NonZeroU16,
    pub container: NonZeroU16,
    pub protocol: Protocol,
}

/// A bind path or an explicitly declared named-volume dependency.
pub enum MountSource {
    Bind(ProtectedValue),
    Volume(ResourceRef),
}

impl std::fmt::Debug for MountSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(_) => f.write_str("Bind([redacted])"),
            Self::Volume(reference) => f.debug_tuple("Volume").field(reference).finish(),
        }
    }
}

pub struct Mount {
    source: MountSource,
    target: ProtectedValue,
    read_only: bool,
}

impl std::fmt::Debug for Mount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mount")
            .field("source", &self.source)
            .field("target", &"[redacted]")
            .field("read_only", &self.read_only)
            .finish()
    }
}

impl Mount {
    pub fn bind(source: Vec<u8>, target: Vec<u8>, read_only: bool) -> Result<Self, IntentError> {
        if !valid_absolute_path(&source) || !valid_absolute_path(&target) {
            return Err(IntentError::InvalidMount);
        }
        Ok(Self {
            source: MountSource::Bind(ProtectedValue::new(source)),
            target: ProtectedValue::new(target),
            read_only,
        })
    }

    pub fn volume(
        source: ResourceRef,
        target: Vec<u8>,
        read_only: bool,
    ) -> Result<Self, IntentError> {
        if !valid_absolute_path(&target) {
            return Err(IntentError::InvalidMount);
        }
        Ok(Self {
            source: MountSource::Volume(source),
            target: ProtectedValue::new(target),
            read_only,
        })
    }

    #[must_use]
    pub const fn source(&self) -> &MountSource {
        &self.source
    }

    #[must_use]
    pub fn target(&self) -> &[u8] {
        self.target.as_bytes()
    }

    #[must_use]
    pub const fn read_only(&self) -> bool {
        self.read_only
    }
}

fn valid_absolute_path(value: &[u8]) -> bool {
    value.starts_with(b"/") && !value.contains(&0) && std::str::from_utf8(value).is_ok()
}

/// Exec-form health check; no shell evaluation is requested.
/// The fields are private so callers cannot bypass duration and command checks.
///
/// ```compile_fail
/// use docker_lens::target::{Argument, Healthcheck};
/// use std::num::{NonZeroU32, NonZeroU64};
/// let _ = Healthcheck {
///     command: vec![Argument::new(b"health".to_vec()).unwrap()],
///     interval_ns: NonZeroU64::new(1).unwrap(),
///     timeout_ns: NonZeroU64::new(1).unwrap(),
///     retries: NonZeroU32::new(1).unwrap(),
/// };
/// ```
#[derive(Debug)]
pub struct Healthcheck {
    command: Vec<Argument>,
    interval_ns: NonZeroU64,
    timeout_ns: NonZeroU64,
    retries: NonZeroU32,
}

impl Healthcheck {
    pub fn new(
        command: Vec<Argument>,
        interval_ns: NonZeroU64,
        timeout_ns: NonZeroU64,
        retries: NonZeroU32,
    ) -> Result<Self, IntentError> {
        if command.is_empty()
            || command[0].bytes().is_empty()
            || !(1_000_000..=i64::MAX as u64).contains(&interval_ns.get())
            || !(1_000_000..=i64::MAX as u64).contains(&timeout_ns.get())
            || retries.get() > i32::MAX as u32
        {
            return Err(IntentError::InvalidHealthcheck);
        }
        Ok(Self {
            command,
            interval_ns,
            timeout_ns,
            retries,
        })
    }

    #[must_use]
    pub fn command(&self) -> &[Argument] {
        &self.command
    }

    #[must_use]
    pub const fn interval_ns(&self) -> NonZeroU64 {
        self.interval_ns
    }

    #[must_use]
    pub const fn timeout_ns(&self) -> NonZeroU64 {
        self.timeout_ns
    }

    #[must_use]
    pub const fn retries(&self) -> NonZeroU32 {
        self.retries
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartPolicy {
    No,
    Always,
    UnlessStopped,
    /// Zero means unlimited retries, as in the Engine API.
    OnFailure {
        maximum_retries: u32,
    },
}

/// All settings are caller-authored; source `Config.*` is never promoted here.
#[derive(Debug)]
pub struct ContainerIntent {
    pub reference: ResourceRef,
    pub identity: TargetIdentity,
    pub image: ImageReference,
    pub environment: Vec<EnvironmentAssignment>,
    pub ports: Vec<PortBinding>,
    pub mounts: Vec<Mount>,
    pub network: Option<ResourceRef>,
    pub entrypoint: Option<Vec<Argument>>,
    pub command: Option<Vec<Argument>>,
    pub healthcheck: Option<Healthcheck>,
    pub restart: Option<RestartPolicy>,
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
            PlanningContext::Target(profile) => profile.api_version(),
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

/// Inert bytes require an explicit caller decision before any file write.
pub struct RenderedArtifact(Vec<u8>);

impl RenderedArtifact {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for RenderedArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RenderedArtifact([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderError {
    InvalidGraph,
}

pub trait Renderer {
    fn render(&self, graph: &OperationGraph<'_>) -> Result<RenderedArtifact, RenderError>;
}

/// Emits newline-delimited inert HTTP request descriptions; it has no transport.
pub struct DockerApiRenderer;

impl Renderer for DockerApiRenderer {
    fn render(&self, graph: &OperationGraph<'_>) -> Result<RenderedArtifact, RenderError> {
        let api = match graph.context() {
            PlanningContext::Observed(scope) => scope.api_version,
            PlanningContext::Target(profile) => profile.api_version(),
        };
        let prefix = format!("/v{}.{}/", api.major.get(), api.minor);
        let resources: HashMap<_, _> = graph
            .intent()
            .resources()
            .iter()
            .map(|resource| (resource.reference(), resource))
            .collect();
        let mut emitted = HashSet::new();
        let mut lines = String::new();
        while emitted.len() < graph.nodes().len() {
            let node = graph
                .nodes()
                .iter()
                .find(|node| {
                    !emitted.contains(&node.operation.resource)
                        && node
                            .depends_on
                            .iter()
                            .all(|reference| emitted.contains(reference))
                })
                .ok_or(RenderError::InvalidGraph)?;
            let resource = resources
                .get(&node.operation.resource)
                .ok_or(RenderError::InvalidGraph)?;
            let (path, body) = match resource {
                TargetResource::Network { identity, .. } => {
                    let mut body = String::from("{\"Name\":");
                    json_string(&mut body, identity.bytes());
                    body.push_str(",\"Driver\":\"bridge\"}");
                    (format!("{prefix}networks/create"), body)
                }
                TargetResource::Volume { identity, .. } => {
                    let mut body = String::from("{\"Name\":");
                    json_string(&mut body, identity.bytes());
                    body.push('}');
                    (format!("{prefix}volumes/create"), body)
                }
                TargetResource::Container(container) => (
                    format!(
                        "{prefix}containers/create?name={}",
                        percent_encode(container.identity.bytes())
                    ),
                    render_container(container, &resources)?,
                ),
            };
            lines.push_str("{\"method\":\"POST\",\"path\":");
            json_string(&mut lines, path.as_bytes());
            lines.push_str(",\"body\":");
            lines.push_str(&body);
            lines.push_str("}\n");
            emitted.insert(node.operation.resource);
        }
        Ok(RenderedArtifact::new(lines.into_bytes()))
    }
}

fn render_container(
    container: &ContainerIntent,
    resources: &HashMap<ResourceRef, &TargetResource>,
) -> Result<String, RenderError> {
    let mut body = String::from("{\"Image\":");
    json_string(&mut body, container.image.bytes());
    if !container.environment.is_empty() {
        body.push_str(",\"Env\":[");
        for (index, assignment) in container.environment.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            let mut pair = assignment.key().to_vec();
            pair.push(b'=');
            pair.extend_from_slice(assignment.value());
            json_string(&mut body, &pair);
        }
        body.push(']');
    }
    if let Some(entrypoint) = &container.entrypoint {
        body.push_str(",\"Entrypoint\":[");
        json_arguments(&mut body, entrypoint);
        body.push(']');
    }
    if let Some(command) = &container.command {
        body.push_str(",\"Cmd\":[");
        json_arguments(&mut body, command);
        body.push(']');
    }
    if let Some(health) = &container.healthcheck {
        body.push_str(",\"Healthcheck\":{\"Test\":[\"CMD\",");
        json_arguments(&mut body, &health.command);
        body.push_str(&format!(
            "],\"Interval\":{},\"Timeout\":{},\"Retries\":{} }}",
            health.interval_ns, health.timeout_ns, health.retries
        ));
    }
    if !container.ports.is_empty() {
        body.push_str(",\"ExposedPorts\":{");
        for (index, port) in container.ports.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(&mut body, port_key(*port).as_bytes());
            body.push_str(":{}");
        }
        body.push('}');
    }
    body.push_str(",\"HostConfig\":{");
    let mut host_field = false;
    if !container.ports.is_empty() {
        body.push_str("\"PortBindings\":{");
        for (index, port) in container.ports.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(&mut body, port_key(*port).as_bytes());
            body.push_str(":[{\"HostPort\":");
            json_string(&mut body, port.host.to_string().as_bytes());
            body.push_str("}]");
        }
        body.push('}');
        host_field = true;
    }
    if !container.mounts.is_empty() {
        if host_field {
            body.push(',');
        }
        body.push_str("\"Mounts\":[");
        for (index, mount) in container.mounts.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            let (kind, source): (&str, &[u8]) = match mount.source() {
                MountSource::Bind(path) => ("bind", path.as_bytes()),
                MountSource::Volume(reference) => match resources.get(reference) {
                    Some(TargetResource::Volume { identity, .. }) => ("volume", identity.bytes()),
                    _ => return Err(RenderError::InvalidGraph),
                },
            };
            body.push_str("{\"Type\":");
            json_string(&mut body, kind.as_bytes());
            body.push_str(",\"Source\":");
            json_string(&mut body, source);
            body.push_str(",\"Target\":");
            json_string(&mut body, mount.target());
            body.push_str(if mount.read_only() {
                ",\"ReadOnly\":true}"
            } else {
                ",\"ReadOnly\":false}"
            });
        }
        body.push(']');
        host_field = true;
    }
    if let Some(network) = container.network {
        let Some(TargetResource::Network { identity, .. }) = resources.get(&network) else {
            return Err(RenderError::InvalidGraph);
        };
        if host_field {
            body.push(',');
        }
        body.push_str("\"NetworkMode\":");
        json_string(&mut body, identity.bytes());
        host_field = true;
    }
    if let Some(restart) = container.restart {
        if host_field {
            body.push(',');
        }
        body.push_str("\"RestartPolicy\":{\"Name\":");
        let (name, maximum_retries) = match restart {
            RestartPolicy::No => ("no", 0),
            RestartPolicy::Always => ("always", 0),
            RestartPolicy::UnlessStopped => ("unless-stopped", 0),
            RestartPolicy::OnFailure { maximum_retries } => ("on-failure", maximum_retries),
        };
        json_string(&mut body, name.as_bytes());
        body.push_str(&format!(",\"MaximumRetryCount\":{maximum_retries}}}"));
    }
    body.push('}');
    if let Some(network) = container.network {
        let Some(TargetResource::Network { identity, .. }) = resources.get(&network) else {
            return Err(RenderError::InvalidGraph);
        };
        body.push_str(",\"NetworkingConfig\":{\"EndpointsConfig\":{");
        json_string(&mut body, identity.bytes());
        body.push_str(":{}}}");
    }
    body.push('}');
    Ok(body)
}

fn port_key(port: PortBinding) -> String {
    let protocol = match port.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    format!("{}/{protocol}", port.container)
}

fn json_arguments(output: &mut String, arguments: &[Argument]) {
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        json_string(output, argument.bytes());
    }
}

fn json_string(output: &mut String, bytes: &[u8]) {
    let value = std::str::from_utf8(bytes).expect("target constructors checked UTF-8");
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
}

fn percent_encode(bytes: &[u8]) -> String {
    let mut encoded = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{
        ApiVersion, CapabilityEvidenceKey, CapabilityFact, CapabilityScope, CapabilityState,
        DaemonFacts, DaemonMode, EngineRelease, FactProvenance, ObservationId,
        TargetCapabilityCatalog, TargetCapabilityFact, TargetCapabilityRecord,
    };
    use std::num::NonZeroU16;

    fn facts(api_minor: u16, mode: DaemonMode, available: &[Capability]) -> DaemonFacts {
        let observation_id = ObservationId::fresh().unwrap();
        let release = EngineRelease::new("20.10.24".into()).unwrap();
        let api_version = ApiVersion::new(NonZeroU16::new(1).unwrap(), api_minor);
        let scope = CapabilityScope {
            observation_id,
            release: release.clone(),
            api_version,
            mode,
        };
        DaemonFacts {
            observation_id,
            release: Some(release),
            api_version: Some(api_version),
            minimum_api_version: None,
            mode,
            capabilities: available
                .iter()
                .copied()
                .map(|capability| CapabilityFact {
                    capability,
                    state: CapabilityState::Available,
                    provenance: FactProvenance::NativeConformance,
                    scope: Some(scope.clone()),
                })
                .collect(),
        }
    }

    fn complete_intent() -> TargetIntent {
        let nz16 = |value| NonZeroU16::new(value).unwrap();
        TargetIntent::new(vec![
            TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(3),
                identity: TargetIdentity::new(b"app".to_vec()).unwrap(),
                image: ImageReference::new(b"registry/app:1".to_vec()).unwrap(),
                environment: vec![
                    EnvironmentAssignment::new(b"TOKEN".to_vec(), b"secret\"\\\nvalue".to_vec())
                        .unwrap(),
                ],
                ports: vec![PortBinding {
                    host: nz16(8080),
                    container: nz16(80),
                    protocol: Protocol::Tcp,
                }],
                mounts: vec![Mount::volume(ResourceRef::new(2), b"/data".to_vec(), false).unwrap()],
                network: Some(ResourceRef::new(1)),
                entrypoint: Some(vec![Argument::new(b"/bin/app".to_vec()).unwrap()]),
                command: Some(vec![Argument::new(b"--serve".to_vec()).unwrap()]),
                healthcheck: Some(
                    Healthcheck::new(
                        vec![Argument::new(b"/bin/health".to_vec()).unwrap()],
                        NonZeroU64::new(1_000_000_000).unwrap(),
                        NonZeroU64::new(500_000_000).unwrap(),
                        NonZeroU32::new(3).unwrap(),
                    )
                    .unwrap(),
                ),
                restart: Some(RestartPolicy::OnFailure { maximum_retries: 2 }),
            })),
            TargetResource::Volume {
                reference: ResourceRef::new(2),
                identity: TargetIdentity::new(b"app_data".to_vec()).unwrap(),
            },
            TargetResource::Network {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"app_net".to_vec()).unwrap(),
            },
        ])
        .unwrap()
    }

    const ALL_SETTINGS: &[Capability] = &[
        Capability::StandaloneContainer,
        Capability::NamedVolume,
        Capability::BridgeNetwork,
        Capability::PortPublish,
        Capability::EnvironmentAssignment,
        Capability::Command,
        Capability::Entrypoint,
        Capability::Healthcheck,
        Capability::RestartPolicy,
    ];

    #[test]
    fn minimal_container_request_has_exact_inert_shape() {
        let facts = facts(41, DaemonMode::Rootful, &[Capability::StandaloneContainer]);
        let capabilities = ValidatedCapabilities::new(&facts).unwrap();
        let intent =
            TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"example".to_vec()).unwrap(),
                image: ImageReference::new(b"image:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![],
                mounts: vec![],
                network: None,
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: None,
            }))])
            .unwrap();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        assert_eq!(
            artifact.bytes(),
            b"{\"method\":\"POST\",\"path\":\"/v1.41/containers/create?name=example\",\"body\":{\"Image\":\"image:1\",\"HostConfig\":{}}}\n"
        );
    }

    #[test]
    fn complete_target_renders_ordered_native_requests_without_executing() {
        let facts = facts(41, DaemonMode::Rootless, ALL_SETTINGS);
        let capabilities = ValidatedCapabilities::new(&facts).unwrap();
        let intent = complete_intent();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        assert_eq!(
            graph.nodes()[0].depends_on,
            vec![ResourceRef::new(1), ResourceRef::new(2)]
        );
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        let output = std::str::from_utf8(artifact.bytes()).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("/v1.41/volumes/create"));
        assert!(lines[1].contains("/v1.41/networks/create"));
        assert!(lines[2].contains("/v1.41/containers/create?name=app"));
        assert!(lines[2].contains("\"Image\":\"registry/app:1\""));
        assert!(lines[2].contains("\"PortBindings\":{\"80/tcp\":[{\"HostPort\":\"8080\"}]"));
        assert!(lines[2].contains("\"Type\":\"volume\",\"Source\":\"app_data\""));
        assert!(lines[2].contains("\"EndpointsConfig\":{\"app_net\":{}}"));
        assert!(lines[2].contains("\"Test\":[\"CMD\",\"/bin/health\"]"));
        assert!(
            lines[2]
                .contains("\"RestartPolicy\":{\"Name\":\"on-failure\",\"MaximumRetryCount\":2}")
        );
        assert!(lines[2].contains("TOKEN=secret\\\"\\\\\\nvalue"));
        assert!(!output.contains("TOKEN=secret\"\\\nvalue"));
        for protected in ["secret", "registry/app:1", "app_net", "TOKEN"] {
            assert!(!format!("{graph:?} {artifact:?}").contains(protected));
        }
    }

    #[test]
    fn each_setting_requires_its_own_exact_capability() {
        let intent = complete_intent();
        let expected = [
            (Capability::PortPublish, TargetField::Port),
            (Capability::EnvironmentAssignment, TargetField::Environment),
            (Capability::Command, TargetField::Command),
            (Capability::Entrypoint, TargetField::Entrypoint),
            (Capability::Healthcheck, TargetField::Healthcheck),
            (Capability::RestartPolicy, TargetField::Restart),
        ];
        for (missing, field) in expected {
            let available: Vec<_> = ALL_SETTINGS
                .iter()
                .copied()
                .filter(|item| *item != missing)
                .collect();
            let facts = facts(41, DaemonMode::Rootful, &available);
            let capabilities = ValidatedCapabilities::new(&facts).unwrap();
            assert_eq!(
                DockerPlanner.plan(&intent, &capabilities).unwrap_err(),
                PlanningError::MissingCapability {
                    resource: ResourceRef::new(3),
                    field,
                    capability: missing,
                }
            );
        }
    }

    #[test]
    fn bind_mount_udp_and_empty_environment_value_are_exact() {
        let daemon = facts(
            41,
            DaemonMode::Rootful,
            &[
                Capability::StandaloneContainer,
                Capability::BindMount,
                Capability::PortPublish,
                Capability::EnvironmentAssignment,
                Capability::RestartPolicy,
            ],
        );
        let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
        let intent =
            TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"dns".to_vec()).unwrap(),
                image: ImageReference::new(b"dns:1".to_vec()).unwrap(),
                environment: vec![EnvironmentAssignment::new(b"EMPTY".to_vec(), vec![]).unwrap()],
                ports: vec![PortBinding {
                    host: NonZeroU16::new(5353).unwrap(),
                    container: NonZeroU16::new(53).unwrap(),
                    protocol: Protocol::Udp,
                }],
                mounts: vec![
                    Mount::bind(b"/host/config".to_vec(), b"/etc/config".to_vec(), true).unwrap(),
                ],
                network: None,
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: Some(RestartPolicy::UnlessStopped),
            }))])
            .unwrap();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        let body = std::str::from_utf8(artifact.bytes()).unwrap();
        assert!(body.contains("\"Env\":[\"EMPTY=\"]"));
        assert!(body.contains("\"53/udp\":[{\"HostPort\":\"5353\"}]"));
        assert!(body.contains("\"Type\":\"bind\",\"Source\":\"/host/config\",\"Target\":\"/etc/config\",\"ReadOnly\":true"));
        assert!(body.contains("\"Name\":\"unless-stopped\""));

        let without_bind = facts(
            41,
            DaemonMode::Rootful,
            &[
                Capability::StandaloneContainer,
                Capability::PortPublish,
                Capability::EnvironmentAssignment,
                Capability::RestartPolicy,
            ],
        );
        let unsupported = ValidatedCapabilities::new(&without_bind).unwrap();
        assert_eq!(
            DockerPlanner.plan(&intent, &unsupported).unwrap_err(),
            PlanningError::MissingCapability {
                resource: ResourceRef::new(1),
                field: TargetField::BindMount,
                capability: Capability::BindMount,
            }
        );
    }

    #[test]
    fn on_failure_zero_means_unlimited_and_overflow_is_rejected() {
        let make = |maximum_retries| {
            TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"worker".to_vec()).unwrap(),
                image: ImageReference::new(b"worker:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![],
                mounts: vec![],
                network: None,
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: Some(RestartPolicy::OnFailure { maximum_retries }),
            }))])
        };
        let intent = make(0).unwrap();
        let daemon = facts(
            41,
            DaemonMode::Rootful,
            &[Capability::StandaloneContainer, Capability::RestartPolicy],
        );
        let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        assert!(
            std::str::from_utf8(artifact.bytes())
                .unwrap()
                .contains("\"RestartPolicy\":{\"Name\":\"on-failure\",\"MaximumRetryCount\":0}")
        );
        assert_eq!(
            make(i32::MAX as u32 + 1).unwrap_err(),
            IntentError::InvalidRestart
        );
    }

    #[test]
    fn target_api_version_and_dependencies_fail_closed() {
        let intent = complete_intent();
        let old = facts(40, DaemonMode::Rootless, ALL_SETTINGS);
        let capabilities = ValidatedCapabilities::new(&old).unwrap();
        assert_eq!(
            DockerPlanner.plan(&intent, &capabilities).unwrap_err(),
            PlanningError::UnsupportedApi {
                actual: ApiVersion::new(NonZeroU16::new(1).unwrap(), 40),
                minimum: ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            }
        );
        let current = facts(41, DaemonMode::Rootless, ALL_SETTINGS);
        let capabilities = ValidatedCapabilities::new(&current).unwrap();
        let graph = DockerPlanner.plan(&intent, &capabilities).unwrap();
        let mut nodes = graph.nodes().to_vec();
        nodes[0].depends_on.pop();
        assert_eq!(
            OperationGraph::new(&intent, &capabilities, nodes).unwrap_err(),
            PlanningError::DependencyMismatch {
                resource: ResourceRef::new(3),
                dependency: ResourceRef::new(2),
                expected: TargetKind::Volume,
            }
        );
        let missing =
            TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(3),
                identity: TargetIdentity::new(b"app".to_vec()).unwrap(),
                image: ImageReference::new(b"image:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![],
                mounts: vec![
                    Mount::volume(ResourceRef::new(99), b"/data".to_vec(), false).unwrap(),
                ],
                network: None,
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: None,
            }))])
            .unwrap();
        assert_eq!(
            DockerPlanner.plan(&missing, &capabilities).unwrap_err(),
            PlanningError::InvalidDependency
        );
    }

    #[test]
    fn rootless_low_host_port_is_rejected_even_with_generic_publish_claim() {
        let facts = facts(
            41,
            DaemonMode::Rootless,
            &[Capability::StandaloneContainer, Capability::PortPublish],
        );
        let capabilities = ValidatedCapabilities::new(&facts).unwrap();
        let intent =
            TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(4),
                identity: TargetIdentity::new(b"web".to_vec()).unwrap(),
                image: ImageReference::new(b"web:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![PortBinding {
                    host: NonZeroU16::new(987).unwrap(),
                    container: NonZeroU16::new(80).unwrap(),
                    protocol: Protocol::Tcp,
                }],
                mounts: vec![],
                network: None,
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: None,
            }))])
            .unwrap();
        let error = DockerPlanner.plan(&intent, &capabilities).unwrap_err();
        assert_eq!(
            error,
            PlanningError::RestrictedPort {
                resource: ResourceRef::new(4),
                mode: DaemonMode::Rootless,
            }
        );
        assert!(!format!("{error:?}").contains("987"));
    }

    #[test]
    fn invalid_target_values_are_rejected_without_echoing_them() {
        assert_eq!(
            TargetIdentity::new(b"-flag".to_vec()).unwrap_err(),
            IntentError::InvalidIdentity
        );
        assert_eq!(
            Argument::new(b"bad\0argument".to_vec()).unwrap_err(),
            IntentError::InvalidArgument
        );
        assert_eq!(
            Mount::bind(b"relative".to_vec(), b"/target".to_vec(), false).unwrap_err(),
            IntentError::InvalidMount
        );
        assert_eq!(
            Healthcheck::new(
                vec![],
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(1).unwrap(),
                NonZeroU32::new(1).unwrap()
            )
            .unwrap_err(),
            IntentError::InvalidHealthcheck
        );
        assert_eq!(
            Healthcheck::new(
                vec![Argument::new(b"health".to_vec()).unwrap()],
                NonZeroU64::new(i64::MAX as u64 + 1).unwrap(),
                NonZeroU64::new(1_000_000).unwrap(),
                NonZeroU32::new(1).unwrap()
            )
            .unwrap_err(),
            IntentError::InvalidHealthcheck
        );
        assert_eq!(
            Healthcheck::new(
                vec![Argument::new(b"health".to_vec()).unwrap()],
                NonZeroU64::new(999_999).unwrap(),
                NonZeroU64::new(1_000_000).unwrap(),
                NonZeroU32::new(1).unwrap()
            )
            .unwrap_err(),
            IntentError::InvalidHealthcheck
        );
        assert_eq!(
            Healthcheck::new(
                vec![Argument::new(Vec::new()).unwrap()],
                NonZeroU64::new(1_000_000).unwrap(),
                NonZeroU64::new(1_000_000).unwrap(),
                NonZeroU32::new(1).unwrap()
            )
            .unwrap_err(),
            IntentError::InvalidHealthcheck
        );
        assert_eq!(
            Healthcheck::new(
                vec![Argument::new(b"health".to_vec()).unwrap()],
                NonZeroU64::new(1_000_000).unwrap(),
                NonZeroU64::new(999_999).unwrap(),
                NonZeroU32::new(1).unwrap()
            )
            .unwrap_err(),
            IntentError::InvalidHealthcheck
        );
    }

    #[test]
    fn target_intent_is_explicit_and_sensitive_data_stays_out_of_debug() {
        let container = ContainerIntent {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"private-app".to_vec()).unwrap(),
            image: ImageReference::new(b"private-registry/app:1".to_vec()).unwrap(),
            environment: vec![
                EnvironmentAssignment::new(b"PASSWORD".to_vec(), b"private-secret".to_vec())
                    .unwrap(),
            ],
            ports: vec![],
            mounts: vec![],
            network: None,
            entrypoint: None,
            command: None,
            healthcheck: None,
            restart: None,
        };
        let intent =
            TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
        let debug = format!("{intent:?}");
        for sensitive in [
            "private-app",
            "private-registry",
            "PASSWORD",
            "private-secret",
        ] {
            assert!(!debug.contains(sensitive));
        }
        assert_eq!(intent.resources().len(), 1);
    }

    #[test]
    fn malformed_and_duplicate_intent_is_rejected() {
        assert_eq!(
            TargetIntent::new_with_orchestration(vec![], Orchestration::Swarm).unwrap_err(),
            IntentError::UnsupportedOrchestration
        );
        assert_eq!(TargetIntent::new(vec![]).unwrap_err(), IntentError::Empty);
        assert_eq!(
            EnvironmentAssignment::new(b"A=B".to_vec(), vec![]).unwrap_err(),
            IntentError::InvalidEnvironment
        );
        let make = || TargetResource::Network {
            reference: ResourceRef::new(7),
            identity: TargetIdentity::new(b"network".to_vec()).unwrap(),
        };
        assert_eq!(
            TargetIntent::new(vec![make(), make()]).unwrap_err(),
            IntentError::DuplicateResource
        );
        assert_eq!(
            TargetIntent::new(vec![
                TargetResource::Volume {
                    reference: ResourceRef::new(1),
                    identity: TargetIdentity::new(b"shared".to_vec()).unwrap(),
                },
                TargetResource::Volume {
                    reference: ResourceRef::new(2),
                    identity: TargetIdentity::new(b"shared".to_vec()).unwrap(),
                },
            ])
            .unwrap_err(),
            IntentError::DuplicateResource
        );
    }

    #[test]
    fn operation_graph_rejects_missing_dependencies_and_cycles() {
        let mut daemon = DaemonFacts {
            observation_id: ObservationId::fresh().unwrap(),
            release: EngineRelease::new("20.10.24".into()),
            api_version: Some(ApiVersion::new(NonZeroU16::new(1).unwrap(), 41)),
            minimum_api_version: None,
            mode: DaemonMode::Rootless,
            capabilities: vec![],
        };
        // Fabricated test facts exercise graph checks; they are not native evidence.
        let scope = CapabilityScope {
            observation_id: daemon.observation_id,
            release: daemon.release.clone().unwrap(),
            api_version: daemon.api_version.unwrap(),
            mode: daemon.mode,
        };
        for capability in [
            Capability::BridgeNetwork,
            Capability::NamedVolume,
            Capability::StandaloneContainer,
        ] {
            daemon.capabilities.push(CapabilityFact {
                capability,
                state: CapabilityState::Available,
                provenance: FactProvenance::NativeConformance,
                scope: Some(scope.clone()),
            });
        }
        let capabilities = ValidatedCapabilities::new(&daemon).unwrap();
        let intent = TargetIntent::new(vec![
            TargetResource::Network {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"network".to_vec()).unwrap(),
            },
            TargetResource::Volume {
                reference: ResourceRef::new(2),
                identity: TargetIdentity::new(b"volume".to_vec()).unwrap(),
            },
            TargetResource::Container(Box::new(ContainerIntent {
                reference: ResourceRef::new(3),
                identity: TargetIdentity::new(b"container".to_vec()).unwrap(),
                image: ImageReference::new(b"image:1".to_vec()).unwrap(),
                environment: vec![],
                ports: vec![],
                mounts: vec![],
                network: None,
                entrypoint: None,
                command: None,
                healthcheck: None,
                restart: None,
            })),
        ])
        .unwrap();
        let node = |reference: u64, kind: TargetKind, depends_on: Vec<u64>| OperationNode {
            operation: Operation {
                resource: ResourceRef::new(reference),
                kind,
            },
            depends_on: depends_on.into_iter().map(ResourceRef::new).collect(),
        };
        let network = || node(1, TargetKind::Network, vec![]);
        let volume = || node(2, TargetKind::Volume, vec![]);
        let container = || node(3, TargetKind::Container, vec![1, 2]);
        assert!(matches!(
            OperationGraph::new(&intent, &capabilities, vec![network(), volume()]),
            Err(PlanningError::InvalidDependency)
        ));
        assert!(matches!(
            OperationGraph::new(
                &intent,
                &capabilities,
                vec![
                    node(1, TargetKind::Container, vec![]),
                    volume(),
                    container()
                ]
            ),
            Err(PlanningError::InvalidDependency)
        ));
        assert!(matches!(
            OperationGraph::new(
                &intent,
                &capabilities,
                vec![node(1, TargetKind::Network, vec![3]), volume(), container()]
            ),
            Err(PlanningError::Cycle)
        ));
        let graph = OperationGraph::new(
            &intent,
            &capabilities,
            vec![network(), volume(), container()],
        )
        .unwrap();
        assert_eq!(graph.nodes().len(), 3);
        assert!(std::ptr::eq(graph.intent(), &intent));
        assert!(matches!(graph.context(), PlanningContext::Observed(_)));
        let all_facts = daemon.capabilities.clone();
        for missing in [
            Capability::BridgeNetwork,
            Capability::NamedVolume,
            Capability::StandaloneContainer,
        ] {
            daemon.capabilities = all_facts
                .iter()
                .filter(|fact| fact.capability != missing)
                .cloned()
                .collect();
            let incomplete = ValidatedCapabilities::new(&daemon).unwrap();
            assert!(matches!(
                OperationGraph::new(&intent, &incomplete, vec![network(), volume(), container()]),
                Err(PlanningError::MissingCapability { .. })
            ));
        }
    }

    #[test]
    fn offline_target_context_is_retained_without_live_observation() {
        let api = ApiVersion::new(NonZeroU16::new(1).unwrap(), 41);
        let profile = TargetProfile::new(
            EngineRelease::new("20.10.24".into()).unwrap(),
            api,
            DaemonMode::Rootless,
            CapabilityEvidenceKey::sha256([7; 32]).unwrap(),
        )
        .unwrap();
        // Fabricated test record; production catalog is empty until native review.
        let catalog = TargetCapabilityCatalog::from_test_records(vec![TargetCapabilityRecord {
            profile: profile.clone(),
            capabilities: vec![TargetCapabilityFact {
                capability: Capability::NamedVolume,
                state: CapabilityState::Available,
            }],
        }])
        .unwrap();
        let capabilities = catalog.resolve(&profile).unwrap();
        assert!(PlanningCapabilitySet::supports(
            &capabilities,
            Capability::NamedVolume
        ));
        let intent = TargetIntent::new(vec![TargetResource::Volume {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"private-volume".to_vec()).unwrap(),
        }])
        .unwrap();
        let graph = OperationGraph::new(
            &intent,
            &capabilities,
            vec![OperationNode {
                operation: Operation {
                    resource: ResourceRef::new(1),
                    kind: TargetKind::Volume,
                },
                depends_on: vec![],
            }],
        )
        .unwrap();
        assert_eq!(graph.context(), &PlanningContext::Target(profile));
        assert!(!format!("{graph:?}").contains("private-volume"));
    }
}
