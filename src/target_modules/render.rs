use super::{OperationGraph, PlanningContext, TargetResource};
use std::collections::{HashMap, HashSet};

#[path = "render/container.rs"]
mod container;
#[path = "render/network.rs"]
mod network;

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
            PlanningContext::Target(profile) => profile.rendering_api_version(),
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
                TargetResource::Network { identity, .. } => (
                    format!("{prefix}networks/create"),
                    network::render_network(identity),
                ),
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
                    container::render_container(container, &resources)?,
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
