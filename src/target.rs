//! Typed, inert target intent and operation graph seams.
//!
//! These types cannot execute requests or write files. Planner and renderer
//! traits have no implementations in the scaffold crate.

use crate::evidence::ProtectedValue;
use crate::observation::ResourceRef;
use crate::version::ValidatedCapabilities;
use std::collections::{HashMap, HashSet};

/// Explicit desired identity, never an observed or runtime-assigned name.
pub struct TargetIdentity(ProtectedValue);

impl TargetIdentity {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        if bytes.is_empty() || bytes.contains(&0) {
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

/// An explicit image reference, with no inferred tag or platform.
pub struct ImageReference(ProtectedValue);

impl ImageReference {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        if bytes.is_empty() || bytes.contains(&0) {
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
        if key.is_empty() || key.contains(&b'=') || key.contains(&0) || value.contains(&0) {
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

/// Ports, mounts, and commands are reserved for reviewed native work in #3.
#[derive(Debug)]
pub struct ContainerIntent {
    pub reference: ResourceRef,
    pub identity: TargetIdentity,
    pub image: ImageReference,
    pub environment: Vec<EnvironmentAssignment>,
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
    Container(ContainerIntent),
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
    InvalidIdentity,
    InvalidImage,
    InvalidEnvironment,
}

#[derive(Debug)]
pub struct TargetIntent {
    resources: Vec<TargetResource>,
}

impl TargetIntent {
    pub fn new(resources: Vec<TargetResource>) -> Result<Self, IntentError> {
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
        Ok(Self { resources })
    }

    #[must_use]
    pub fn resources(&self) -> &[TargetResource] {
        &self.resources
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    nodes: Vec<OperationNode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanningError {
    Unsupported,
    MissingCapability,
    InvalidDependency,
    Cycle,
}

impl<'a> OperationGraph<'a> {
    pub fn new(intent: &'a TargetIntent, nodes: Vec<OperationNode>) -> Result<Self, PlanningError> {
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
            node.depends_on
                .iter()
                .any(|dependency| !references.contains(dependency))
        }) {
            return Err(PlanningError::InvalidDependency);
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
        Ok(Self { intent, nodes })
    }

    #[must_use]
    pub fn nodes(&self) -> &[OperationNode] {
        &self.nodes
    }

    #[must_use]
    pub fn intent(&self) -> &'a TargetIntent {
        self.intent
    }
}

/// Implementations must prove required capabilities for the requested daemon.
pub trait Planner {
    fn plan<'a>(
        &self,
        intent: &'a TargetIntent,
        capabilities: &ValidatedCapabilities<'_>,
    ) -> Result<OperationGraph<'a>, PlanningError>;
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
    Unsupported,
    InvalidGraph,
}

pub trait Renderer {
    fn render(&self, graph: &OperationGraph<'_>) -> Result<RenderedArtifact, RenderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let intent = TargetIntent::new(vec![TargetResource::Container(container)]).unwrap();
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
    }

    #[test]
    fn operation_graph_rejects_missing_dependencies_and_cycles() {
        let intent = TargetIntent::new(vec![
            TargetResource::Network {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(b"network".to_vec()).unwrap(),
            },
            TargetResource::Volume {
                reference: ResourceRef::new(2),
                identity: TargetIdentity::new(b"volume".to_vec()).unwrap(),
            },
            TargetResource::Container(ContainerIntent {
                reference: ResourceRef::new(3),
                identity: TargetIdentity::new(b"container".to_vec()).unwrap(),
                image: ImageReference::new(b"image:1".to_vec()).unwrap(),
                environment: vec![],
            }),
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
            OperationGraph::new(&intent, vec![network(), volume()]),
            Err(PlanningError::InvalidDependency)
        ));
        assert!(matches!(
            OperationGraph::new(
                &intent,
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
                vec![node(1, TargetKind::Network, vec![3]), volume(), container()]
            ),
            Err(PlanningError::Cycle)
        ));
        let graph = OperationGraph::new(&intent, vec![network(), volume(), container()]).unwrap();
        assert_eq!(graph.nodes().len(), 3);
        assert!(std::ptr::eq(graph.intent(), &intent));
    }
}
