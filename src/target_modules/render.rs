use super::{NetworkSource, OperationGraph, OperationStepAction, PlanningContext, TargetResource};
use crate::evidence::ProtectedValue;
use crate::observation::ResourceRef;
use crate::version::{ApiVersion, DaemonMode, EngineBuild};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

#[path = "render/container.rs"]
mod container;
#[path = "render/network.rs"]
mod network;
#[cfg(test)]
#[path = "render/review_tests.rs"]
mod review_tests;

/// Inert request-only bytes and optional native-renderer review provenance.
/// Any file write remains an explicit caller decision.
pub struct RenderedArtifact {
    bytes: Vec<u8>,
    network_prerequisites: Vec<NetworkPrerequisite>,
    volume_prerequisites: Vec<VolumePrerequisite>,
    native: Option<NativeRenderState>,
}

struct NativeRenderState {
    context: PlanningContext,
    requests: Vec<String>,
    prerequisite_order: Vec<PrerequisiteOrder>,
}

enum PrerequisiteOrder {
    Network(usize),
    Volume(usize),
}

/// A declared external network must be checked by the consumer before use.
pub struct NetworkPrerequisite {
    pub reference: ResourceRef,
    pub expected_driver: super::NetworkDriver,
    identity: ProtectedValue,
}

impl NetworkPrerequisite {
    #[must_use]
    pub fn identity(&self) -> &[u8] {
        self.identity.as_bytes()
    }
}

impl std::fmt::Debug for NetworkPrerequisite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkPrerequisite")
            .field("reference", &self.reference)
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// A declared external named volume must be checked by the consumer before use.
/// This does not assert destination existence, content, or data transfer.
pub struct VolumePrerequisite {
    pub reference: ResourceRef,
    identity: ProtectedValue,
}

impl VolumePrerequisite {
    #[must_use]
    pub fn identity(&self) -> &[u8] {
        self.identity.as_bytes()
    }
}

impl std::fmt::Debug for VolumePrerequisite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumePrerequisite")
            .field("reference", &self.reference)
            .field("identity", &"[redacted]")
            .finish()
    }
}

impl RenderedArtifact {
    /// Construct opaque request-only bytes with no native-renderer provenance.
    /// This cannot be serialized as a complete review artifact.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            network_prerequisites: Vec::new(),
            volume_prerequisites: Vec::new(),
            native: None,
        }
    }

    /// Return only the ordered native request stream, not its prerequisites.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn network_prerequisites(&self) -> &[NetworkPrerequisite] {
        &self.network_prerequisites
    }

    #[must_use]
    pub fn volume_prerequisites(&self) -> &[VolumePrerequisite] {
        &self.volume_prerequisites
    }

    /// The validated planning context retained by the native renderer.
    /// Caller-created opaque request bytes have no such context.
    #[must_use]
    pub fn context(&self) -> Option<&PlanningContext> {
        self.native.as_ref().map(|native| &native.context)
    }

    /// Explicitly reveal a versioned, complete inert review artifact.
    /// `bytes()` remains the legacy request-only stream; neither form executes.
    /// Opaque bytes from `new` cannot be promoted into a complete artifact.
    pub fn complete_bytes(&self) -> Result<Vec<u8>, CompleteArtifactError> {
        let native = self
            .native
            .as_ref()
            .ok_or(CompleteArtifactError::MissingNativeProvenance)?;
        let mut document = String::from("{\"schema_version\":1,\"context\":");
        append_context(&mut document, &native.context);
        document.push_str(",\"requests\":[");
        for (index, request) in native.requests.iter().enumerate() {
            if index != 0 {
                document.push(',');
            }
            document.push_str(request);
        }
        document.push_str("],\"prerequisites\":[");
        for (index, prerequisite) in native.prerequisite_order.iter().enumerate() {
            if index != 0 {
                document.push(',');
            }
            match prerequisite {
                PrerequisiteOrder::Network(index) => {
                    let network = &self.network_prerequisites[*index];
                    document.push_str("{\"kind\":\"network\",\"reference\":");
                    json_string(
                        &mut document,
                        network.reference.local_index().to_string().as_bytes(),
                    );
                    document.push_str(",\"identity\":");
                    json_string(&mut document, network.identity());
                    document.push_str(",\"expected_driver\":");
                    json_string(
                        &mut document,
                        network_driver_name(network.expected_driver).as_bytes(),
                    );
                }
                PrerequisiteOrder::Volume(index) => {
                    let volume = &self.volume_prerequisites[*index];
                    document.push_str("{\"kind\":\"volume\",\"reference\":");
                    json_string(
                        &mut document,
                        volume.reference.local_index().to_string().as_bytes(),
                    );
                    document.push_str(",\"identity\":");
                    json_string(&mut document, volume.identity());
                }
            }
            document.push('}');
        }
        document.push_str("]}\n");
        Ok(document.into_bytes())
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

/// Closed failure when caller-provided bytes lack native renderer provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompleteArtifactError {
    MissingNativeProvenance,
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
        let mut requests = Vec::new();
        let mut network_prerequisites = Vec::new();
        let mut volume_prerequisites = Vec::new();
        let mut prerequisite_order = Vec::new();
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
            let request = match resource {
                TargetResource::Network(network) => match &network.source {
                    NetworkSource::Create(_) => Some((
                        format!("{prefix}networks/create"),
                        network::render_network(network),
                    )),
                    NetworkSource::External { expected_driver } => {
                        prerequisite_order
                            .push(PrerequisiteOrder::Network(network_prerequisites.len()));
                        network_prerequisites.push(NetworkPrerequisite {
                            reference: network.reference,
                            expected_driver: *expected_driver,
                            identity: ProtectedValue::new(network.identity.bytes().to_vec()),
                        });
                        None
                    }
                },
                TargetResource::Volume { identity, .. } => {
                    let mut body = String::from("{\"Name\":");
                    json_string(&mut body, identity.bytes());
                    body.push('}');
                    Some((format!("{prefix}volumes/create"), body))
                }
                TargetResource::ExternalVolume {
                    reference,
                    identity,
                } => {
                    prerequisite_order.push(PrerequisiteOrder::Volume(volume_prerequisites.len()));
                    volume_prerequisites.push(VolumePrerequisite {
                        reference: *reference,
                        identity: ProtectedValue::new(identity.bytes().to_vec()),
                    });
                    None
                }
                TargetResource::Container(container) => Some((
                    format!(
                        "{prefix}containers/create?name={}",
                        percent_encode(container.identity.bytes())
                    ),
                    container::render_container(container, &resources)?,
                )),
            };
            if let Some((path, body)) = request {
                append_request(&mut lines, &mut requests, &path, &body);
            }
            if let TargetResource::Container(container) = resource {
                for step in graph.steps().iter().filter(|step| {
                    step.id.resource == node.operation.resource
                        && matches!(step.action, OperationStepAction::ConnectNetwork { .. })
                }) {
                    let OperationStepAction::ConnectNetwork {
                        attachment_index, ..
                    } = step.action
                    else {
                        unreachable!("filtered to network connections")
                    };
                    let attachment = container
                        .networks
                        .get(attachment_index)
                        .ok_or(RenderError::InvalidGraph)?;
                    let (path, body) =
                        container::render_secondary_connection(container, attachment, &resources)?;
                    append_request(&mut lines, &mut requests, &format!("{prefix}{path}"), &body);
                }
            }
            emitted.insert(node.operation.resource);
        }
        Ok(RenderedArtifact {
            bytes: lines.into_bytes(),
            network_prerequisites,
            volume_prerequisites,
            native: Some(NativeRenderState {
                context: graph.context().clone(),
                requests,
                prerequisite_order,
            }),
        })
    }
}

fn append_request(lines: &mut String, requests: &mut Vec<String>, path: &str, body: &str) {
    let mut request = String::from("{\"method\":\"POST\",\"path\":");
    json_string(&mut request, path.as_bytes());
    request.push_str(",\"body\":");
    request.push_str(body);
    request.push('}');
    lines.push_str(&request);
    lines.push('\n');
    requests.push(request);
}

fn append_context(output: &mut String, context: &PlanningContext) {
    match context {
        PlanningContext::Observed(scope) => {
            output.push_str(
                "{\"kind\":\"observed\",\"provenance\":\"process_local_only\",\"engine_release\":",
            );
            json_string(output, scope.release.as_str().as_bytes());
            output.push_str(",\"api_version\":");
            append_api_version(output, scope.api_version);
            output.push_str(",\"daemon_mode\":");
            json_string(output, daemon_mode_name(scope.mode).as_bytes());
        }
        PlanningContext::Target(profile) => {
            let identity = profile.identity();
            output.push_str("{\"kind\":\"target\",\"build\":");
            match identity.build() {
                EngineBuild::Upstream => output.push_str("{\"kind\":\"upstream\"}"),
                EngineBuild::DebianPackage(revision) => {
                    output.push_str("{\"kind\":\"debian_package\",\"revision\":");
                    json_string(output, revision.as_str().as_bytes());
                    output.push('}');
                }
            }
            output.push_str(",\"engine_release\":");
            json_string(output, identity.release().as_str().as_bytes());
            output.push_str(",\"advertised_api_version\":");
            append_api_version(output, identity.advertised_api_version());
            output.push_str(",\"acquisition_api_version\":");
            append_api_version(output, identity.acquisition_api_version());
            output.push_str(",\"rendering_api_version\":");
            append_api_version(output, identity.rendering_api_version());
            output.push_str(",\"daemon_mode\":");
            json_string(output, daemon_mode_name(identity.mode()).as_bytes());
            output.push_str(",\"evidence_sha256\":\"");
            for byte in profile.evidence_key().as_sha256_bytes() {
                write!(output, "{byte:02x}").expect("writing to String cannot fail");
            }
            output.push('"');
        }
    }
    output.push('}');
}

fn append_api_version(output: &mut String, version: ApiVersion) {
    json_string(
        output,
        format!("{}.{}", version.major.get(), version.minor).as_bytes(),
    );
}

fn daemon_mode_name(mode: DaemonMode) -> &'static str {
    match mode {
        DaemonMode::Rootful => "rootful",
        DaemonMode::Rootless => "rootless",
        DaemonMode::Unknown => "unknown",
    }
}

fn network_driver_name(driver: super::NetworkDriver) -> &'static str {
    match driver {
        super::NetworkDriver::Bridge => "bridge",
        super::NetworkDriver::Host => "host",
        super::NetworkDriver::Overlay => "overlay",
        super::NetworkDriver::Macvlan => "macvlan",
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
