//! Pure decoding of bounded, protected Docker Engine captures.
//!
//! The request, HTTP status, local reference and actual URL API version are
//! part of the input contract. No JSON field can establish Compose authorship
//! or a positive target capability. Decoder errors contain no native values.

use std::collections::HashSet;
use std::num::NonZeroU16;

use serde_json::Value;

use crate::acquisition::ReadRequest;
use crate::evidence::{Capture, ProtectedValue};
use crate::finding::{Finding, FindingCode, Severity};
use crate::observation::{Availability, FieldPath, Observed, Origin, ResourceRef};
use crate::version::{ApiVersion, DaemonFacts, DaemonMode, EngineRelease, ObservationId};

const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_COLLECTION_ITEMS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    ResponseTooLarge,
    InvalidJson,
    InvalidShape(FieldPath),
    InvalidValue(FieldPath),
    UnexpectedStatus,
    MissingApiVersion,
    ApiVersionOutOfRange,
    ConflictingFacts,
    DuplicateResource,
    IncompleteInventory,
    CollectionTooLarge,
}

/// Strings returned by the daemon may contain application identifiers or
/// protected data. The client and distribution package revisions are separate
/// from the daemon release and cannot be reconstructed from `/version`.
pub struct DecodedVersion {
    pub daemon: DaemonFacts,
    pub client_release: Option<ProtectedValue>,
    pub distribution_package_revision: Option<ProtectedValue>,
    pub requested_api_versions: Vec<ApiVersion>,
}

pub struct DecodedInventory {
    pub observation_id: ObservationId,
    pub version: DecodedVersion,
    pub containers: Vec<ContainerObservation>,
    pub networks: Vec<NetworkObservation>,
    pub volumes: Vec<VolumeObservation>,
    pub findings: Vec<Finding>,
}

impl std::fmt::Debug for DecodedInventory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedInventory")
            .field("observation_id", &self.observation_id)
            .field("containers", &self.containers.len())
            .field("networks", &self.networks.len())
            .field("volumes", &self.volumes.len())
            .field("findings", &self.findings)
            .finish_non_exhaustive()
    }
}

pub struct ContainerObservation {
    pub reference: ResourceRef,
    pub image: Observed<ProtectedValue>,
    pub image_id: Observed<ProtectedValue>,
    pub environment: Observed<Vec<EnvironmentAssignment>>,
    pub exposed_ports: Observed<Vec<PortKey>>,
    pub configured_ports: Observed<Vec<PortObservation>>,
    pub runtime_ports: Observed<Vec<PortObservation>>,
    pub mounts: Observed<Vec<MountObservation>>,
    pub networks: Observed<Vec<NetworkAttachment>>,
    pub network_mode: Observed<NetworkModeObservation>,
    pub command: Observed<CommandValue>,
    pub entrypoint: Observed<CommandValue>,
    pub healthcheck: Observed<Healthcheck>,
    pub restart_policy: Observed<RestartPolicy>,
}

pub struct EnvironmentAssignment {
    pub name: ProtectedValue,
    pub value: Option<ProtectedValue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Sctp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortKey {
    pub container_port: u16,
    pub protocol: TransportProtocol,
}

pub struct HostBinding {
    pub host_ip: Observed<ProtectedValue>,
    pub host_port: Observed<u16>,
}

pub struct PortObservation {
    pub key: PortKey,
    pub bindings: Observed<Vec<HostBinding>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountKind {
    Bind,
    Volume,
    Tmpfs,
    Other,
}

pub struct MountObservation {
    pub kind: MountKind,
    pub source: Observed<ProtectedValue>,
    pub destination: Observed<ProtectedValue>,
    pub name: Observed<ProtectedValue>,
    pub read_write: Observed<bool>,
}

pub struct NetworkAttachment {
    pub name: ProtectedValue,
    pub ip_address: Observed<ProtectedValue>,
    pub aliases: Observed<Vec<ProtectedValue>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkModeKind {
    Default,
    Bridge,
    Host,
    None,
    Container,
    Named,
}

pub struct NetworkModeObservation {
    pub kind: NetworkModeKind,
    pub native_value: ProtectedValue,
}

pub enum CommandValue {
    Exec(Vec<ProtectedValue>),
    Shell(ProtectedValue),
}

pub struct Healthcheck {
    pub test: Observed<HealthcheckTest>,
    pub interval_ns: Observed<u64>,
    pub timeout_ns: Observed<u64>,
    pub start_period_ns: Observed<u64>,
    pub start_interval_ns: Observed<u64>,
    pub retries: Observed<u32>,
}

pub enum HealthcheckTest {
    Cmd(Vec<ProtectedValue>),
    CmdShell(ProtectedValue),
    None,
    Other(Vec<ProtectedValue>),
}

pub struct RestartPolicy {
    pub name: Observed<ProtectedValue>,
    pub maximum_retry_count: Observed<u32>,
}

pub struct NetworkObservation {
    pub reference: ResourceRef,
    pub name: Observed<ProtectedValue>,
    pub driver: Observed<ProtectedValue>,
    pub internal: Observed<bool>,
}

pub struct VolumeObservation {
    pub reference: ResourceRef,
    pub name: Observed<ProtectedValue>,
    pub driver: Observed<ProtectedValue>,
    pub mountpoint: Observed<ProtectedValue>,
}

/// Only the decoder's explicit redaction envelope is recognized. Native
/// JSON with this shape is conservatively unavailable; it never yields data.
fn is_redacted(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == 1 && object.get("__docker_lens_redacted__") == Some(&Value::Bool(true))
    })
}

fn field_value<'a>(
    root: &'a Value,
    path: &[&str],
    field: FieldPath,
) -> Result<Option<&'a Value>, DecodeError> {
    let mut current = root;
    for component in path {
        if current.is_null() || is_redacted(current) {
            return Ok(Some(current));
        }
        current = match current.as_object() {
            Some(object) => match object.get(*component) {
                Some(value) => value,
                None => return Ok(None),
            },
            None => return Err(DecodeError::InvalidShape(field)),
        };
    }
    Ok(Some(current))
}

fn observed<T>(
    root: &Value,
    path: &[&str],
    field: FieldPath,
    origin: Origin,
    parse: impl FnOnce(&Value) -> Result<T, DecodeError>,
) -> Result<Observed<T>, DecodeError> {
    match field_value(root, path, field)? {
        None => Ok(Observed::unavailable(Availability::Missing, origin)),
        Some(value) if value.is_null() => Ok(Observed::unavailable(Availability::Null, origin)),
        Some(value) if is_redacted(value) => {
            Ok(Observed::unavailable(Availability::Redacted, origin))
        }
        Some(value) => {
            let availability = if value.as_str().is_some_and(str::is_empty)
                || value.as_array().is_some_and(Vec::is_empty)
                || value.as_object().is_some_and(serde_json::Map::is_empty)
            {
                Availability::Empty
            } else {
                Availability::Present
            };
            Ok(Observed::present(parse(value)?, availability, origin))
        }
    }
}

fn string(value: &Value, field: FieldPath) -> Result<ProtectedValue, DecodeError> {
    value
        .as_str()
        .map(|s| ProtectedValue::new(s.as_bytes().to_vec()))
        .ok_or(DecodeError::InvalidShape(field))
}

fn string_field(
    root: &Value,
    path: &[&str],
    field: FieldPath,
    origin: Origin,
) -> Result<Observed<ProtectedValue>, DecodeError> {
    observed(root, path, field, origin, |value| string(value, field))
}

fn bool_field(
    root: &Value,
    path: &[&str],
    field: FieldPath,
    origin: Origin,
) -> Result<Observed<bool>, DecodeError> {
    observed(root, path, field, origin, |value| {
        value.as_bool().ok_or(DecodeError::InvalidShape(field))
    })
}

fn unsigned_field(
    root: &Value,
    path: &[&str],
    field: FieldPath,
    origin: Origin,
) -> Result<Observed<u64>, DecodeError> {
    observed(root, path, field, origin, |value| {
        value.as_u64().ok_or(DecodeError::InvalidShape(field))
    })
}

fn array(value: &Value, field: FieldPath) -> Result<&[Value], DecodeError> {
    let values = value.as_array().ok_or(DecodeError::InvalidShape(field))?;
    if values.len() > MAX_COLLECTION_ITEMS {
        return Err(DecodeError::CollectionTooLarge);
    }
    Ok(values)
}

fn object(value: &Value, field: FieldPath) -> Result<&serde_json::Map<String, Value>, DecodeError> {
    let values = value.as_object().ok_or(DecodeError::InvalidShape(field))?;
    if values.len() > MAX_COLLECTION_ITEMS {
        return Err(DecodeError::CollectionTooLarge);
    }
    Ok(values)
}

fn parse_api(value: &str) -> Option<ApiVersion> {
    let (major, minor) = value.split_once('.')?;
    if minor.contains('.')
        || major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(ApiVersion::new(
        NonZeroU16::new(major.parse().ok()?)?,
        minor.parse().ok()?,
    ))
}

fn parse_port_key(value: &str) -> Result<PortKey, DecodeError> {
    let (port, protocol) = value
        .split_once('/')
        .ok_or(DecodeError::InvalidValue(FieldPath::Port { index: 0 }))?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DecodeError::InvalidValue(FieldPath::Port { index: 0 }));
    }
    let protocol = match protocol {
        "tcp" => TransportProtocol::Tcp,
        "udp" => TransportProtocol::Udp,
        "sctp" => TransportProtocol::Sctp,
        _ => return Err(DecodeError::InvalidValue(FieldPath::Port { index: 0 })),
    };
    let container_port = port
        .parse()
        .map_err(|_| DecodeError::InvalidValue(FieldPath::Port { index: 0 }))?;
    if container_port == 0 {
        return Err(DecodeError::InvalidValue(FieldPath::Port { index: 0 }));
    }
    Ok(PortKey {
        container_port,
        protocol,
    })
}

fn parse_host_port(value: &Value) -> Result<u16, DecodeError> {
    let raw = value
        .as_str()
        .ok_or(DecodeError::InvalidShape(FieldPath::Port { index: 0 }))?;
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DecodeError::InvalidValue(FieldPath::Port { index: 0 }));
    }
    raw.parse()
        .map_err(|_| DecodeError::InvalidValue(FieldPath::Port { index: 0 }))
}

fn host_port_field(
    root: &Value,
    field: FieldPath,
    origin: Origin,
) -> Result<Observed<u16>, DecodeError> {
    match field_value(root, &["HostPort"], field)? {
        None => Ok(Observed::unavailable(Availability::Missing, origin)),
        Some(Value::Null) => Ok(Observed::unavailable(Availability::Null, origin)),
        Some(value) if is_redacted(value) => {
            Ok(Observed::unavailable(Availability::Redacted, origin))
        }
        Some(Value::String(value)) if value.is_empty() => {
            Ok(Observed::unavailable(Availability::Empty, origin))
        }
        Some(value) => Ok(Observed::present(
            parse_host_port(value)?,
            Availability::Present,
            origin,
        )),
    }
}

fn port_bindings(value: &Value, origin: Origin) -> Result<Vec<PortObservation>, DecodeError> {
    let mut ports = Vec::new();
    for (port, bindings) in object(value, FieldPath::Port { index: 0 })? {
        let key = parse_port_key(port)?;
        let bindings = if bindings.is_null() {
            Observed::unavailable(Availability::Null, origin)
        } else if is_redacted(bindings) {
            Observed::unavailable(Availability::Redacted, origin)
        } else {
            let values = array(bindings, FieldPath::Port { index: ports.len() })?;
            let mut result = Vec::with_capacity(values.len());
            for binding in values {
                object(binding, FieldPath::Port { index: ports.len() })?;
                result.push(HostBinding {
                    host_ip: string_field(
                        binding,
                        &["HostIp"],
                        FieldPath::Port { index: ports.len() },
                        origin,
                    )?,
                    host_port: host_port_field(
                        binding,
                        FieldPath::Port { index: ports.len() },
                        origin,
                    )?,
                });
            }
            Observed::present(
                result,
                if values.is_empty() {
                    Availability::Empty
                } else {
                    Availability::Present
                },
                origin,
            )
        };
        ports.push(PortObservation { key, bindings });
    }
    Ok(ports)
}

fn command(value: &Value, field: FieldPath) -> Result<CommandValue, DecodeError> {
    if value.is_string() {
        return Ok(CommandValue::Shell(string(value, field)?));
    }
    Ok(CommandValue::Exec(
        array(value, field)?
            .iter()
            .map(|part| string(part, field))
            .collect::<Result<_, _>>()?,
    ))
}

fn environment(value: &Value) -> Result<Vec<EnvironmentAssignment>, DecodeError> {
    array(value, FieldPath::Environment { index: 0 })?
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let raw = item
                .as_str()
                .ok_or(DecodeError::InvalidShape(FieldPath::Environment { index }))?;
            let (name, value) = match raw.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (raw, None),
            };
            if name.is_empty() {
                return Err(DecodeError::InvalidValue(FieldPath::Environment { index }));
            }
            Ok(EnvironmentAssignment {
                name: ProtectedValue::new(name.as_bytes().to_vec()),
                value: value.map(|value| ProtectedValue::new(value.as_bytes().to_vec())),
            })
        })
        .collect()
}

fn mounts(value: &Value) -> Result<Vec<MountObservation>, DecodeError> {
    array(value, FieldPath::Mount { index: 0 })?
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let field = FieldPath::Mount { index };
            object(item, field)?;
            let kind = match field_value(item, &["Type"], field)?.and_then(Value::as_str) {
                Some("bind") => MountKind::Bind,
                Some("volume") => MountKind::Volume,
                Some("tmpfs") => MountKind::Tmpfs,
                _ => MountKind::Other,
            };
            Ok(MountObservation {
                kind,
                source: string_field(item, &["Source"], field, Origin::Effective)?,
                destination: string_field(item, &["Destination"], field, Origin::Effective)?,
                name: string_field(item, &["Name"], field, Origin::Effective)?,
                read_write: bool_field(item, &["RW"], field, Origin::Effective)?,
            })
        })
        .collect()
}

fn networks(value: &Value) -> Result<Vec<NetworkAttachment>, DecodeError> {
    object(value, FieldPath::Network { index: 0 })?
        .iter()
        .enumerate()
        .map(|(index, (name, item))| {
            let field = FieldPath::Network { index };
            object(item, field)?;
            Ok(NetworkAttachment {
                name: ProtectedValue::new(name.as_bytes().to_vec()),
                ip_address: string_field(item, &["IPAddress"], field, Origin::RuntimeAssigned)?,
                aliases: observed(item, &["Aliases"], field, Origin::Effective, |aliases| {
                    array(aliases, field)?
                        .iter()
                        .map(|alias| string(alias, field))
                        .collect()
                })?,
            })
        })
        .collect()
}

fn network_mode(value: &Value) -> Result<NetworkModeObservation, DecodeError> {
    let native_value = value
        .as_str()
        .ok_or(DecodeError::InvalidShape(FieldPath::NetworkMode))?;
    let kind = match native_value {
        "default" => NetworkModeKind::Default,
        "bridge" => NetworkModeKind::Bridge,
        "host" => NetworkModeKind::Host,
        "none" => NetworkModeKind::None,
        mode if mode.starts_with("container:") && mode.len() > "container:".len() => {
            NetworkModeKind::Container
        }
        _ => NetworkModeKind::Named,
    };
    Ok(NetworkModeObservation {
        kind,
        native_value: ProtectedValue::new(native_value.as_bytes().to_vec()),
    })
}

fn healthcheck_test(value: &Value) -> Result<HealthcheckTest, DecodeError> {
    let parts = array(value, FieldPath::Healthcheck)?;
    let parsed = parts
        .iter()
        .map(|part| string(part, FieldPath::Healthcheck))
        .collect::<Result<Vec<_>, _>>()?;
    let form = parts.first().and_then(Value::as_str);
    match (form, parts.len()) {
        (Some("CMD"), 2..) => Ok(HealthcheckTest::Cmd(parsed.into_iter().skip(1).collect())),
        (Some("CMD-SHELL"), 2) => Ok(HealthcheckTest::CmdShell(
            parsed.into_iter().nth(1).expect("length checked"),
        )),
        (Some("NONE"), 1) => Ok(HealthcheckTest::None),
        (Some("CMD" | "CMD-SHELL" | "NONE"), _) => {
            Err(DecodeError::InvalidValue(FieldPath::Healthcheck))
        }
        _ => Ok(HealthcheckTest::Other(parsed)),
    }
}

fn healthcheck(value: &Value) -> Result<Healthcheck, DecodeError> {
    object(value, FieldPath::Healthcheck)?;
    Ok(Healthcheck {
        test: observed(
            value,
            &["Test"],
            FieldPath::Healthcheck,
            Origin::Effective,
            healthcheck_test,
        )?,
        interval_ns: unsigned_field(
            value,
            &["Interval"],
            FieldPath::Healthcheck,
            Origin::Effective,
        )?,
        timeout_ns: unsigned_field(
            value,
            &["Timeout"],
            FieldPath::Healthcheck,
            Origin::Effective,
        )?,
        start_period_ns: unsigned_field(
            value,
            &["StartPeriod"],
            FieldPath::Healthcheck,
            Origin::Effective,
        )?,
        start_interval_ns: unsigned_field(
            value,
            &["StartInterval"],
            FieldPath::Healthcheck,
            Origin::Effective,
        )?,
        retries: observed(
            value,
            &["Retries"],
            FieldPath::Healthcheck,
            Origin::Effective,
            |retries| {
                u32::try_from(
                    retries
                        .as_u64()
                        .ok_or(DecodeError::InvalidShape(FieldPath::Healthcheck))?,
                )
                .map_err(|_| DecodeError::InvalidValue(FieldPath::Healthcheck))
            },
        )?,
    })
}

fn restart_policy(value: &Value) -> Result<RestartPolicy, DecodeError> {
    object(value, FieldPath::RestartPolicy)?;
    Ok(RestartPolicy {
        name: string_field(
            value,
            &["Name"],
            FieldPath::RestartPolicy,
            Origin::Effective,
        )?,
        maximum_retry_count: observed(
            value,
            &["MaximumRetryCount"],
            FieldPath::RestartPolicy,
            Origin::Effective,
            |count| {
                u32::try_from(
                    count
                        .as_u64()
                        .ok_or(DecodeError::InvalidShape(FieldPath::RestartPolicy))?,
                )
                .map_err(|_| DecodeError::InvalidValue(FieldPath::RestartPolicy))
            },
        )?,
    })
}

fn container(root: &Value, reference: ResourceRef) -> Result<ContainerObservation, DecodeError> {
    object(root, FieldPath::Other)?;
    Ok(ContainerObservation {
        reference,
        image: string_field(
            root,
            &["Config", "Image"],
            FieldPath::Image,
            Origin::Effective,
        )?,
        image_id: string_field(root, &["Image"], FieldPath::Image, Origin::RuntimeAssigned)?,
        environment: observed(
            root,
            &["Config", "Env"],
            FieldPath::Environment { index: 0 },
            Origin::Effective,
            environment,
        )?,
        exposed_ports: observed(
            root,
            &["Config", "ExposedPorts"],
            FieldPath::Port { index: 0 },
            Origin::Effective,
            |value| {
                object(value, FieldPath::Port { index: 0 })?
                    .keys()
                    .map(|key| parse_port_key(key))
                    .collect()
            },
        )?,
        configured_ports: observed(
            root,
            &["HostConfig", "PortBindings"],
            FieldPath::Port { index: 0 },
            Origin::Effective,
            |value| port_bindings(value, Origin::Effective),
        )?,
        runtime_ports: observed(
            root,
            &["NetworkSettings", "Ports"],
            FieldPath::Port { index: 0 },
            Origin::RuntimeAssigned,
            |value| port_bindings(value, Origin::RuntimeAssigned),
        )?,
        mounts: observed(
            root,
            &["Mounts"],
            FieldPath::Mount { index: 0 },
            Origin::Effective,
            mounts,
        )?,
        networks: observed(
            root,
            &["NetworkSettings", "Networks"],
            FieldPath::Network { index: 0 },
            Origin::RuntimeAssigned,
            networks,
        )?,
        network_mode: observed(
            root,
            &["HostConfig", "NetworkMode"],
            FieldPath::NetworkMode,
            Origin::Effective,
            network_mode,
        )?,
        command: observed(
            root,
            &["Config", "Cmd"],
            FieldPath::Command,
            Origin::Effective,
            |value| command(value, FieldPath::Command),
        )?,
        entrypoint: observed(
            root,
            &["Config", "Entrypoint"],
            FieldPath::Entrypoint,
            Origin::Effective,
            |value| command(value, FieldPath::Entrypoint),
        )?,
        healthcheck: observed(
            root,
            &["Config", "Healthcheck"],
            FieldPath::Healthcheck,
            Origin::Effective,
            healthcheck,
        )?,
        restart_policy: observed(
            root,
            &["HostConfig", "RestartPolicy"],
            FieldPath::RestartPolicy,
            Origin::Effective,
            restart_policy,
        )?,
    })
}

fn network(root: &Value, reference: ResourceRef) -> Result<NetworkObservation, DecodeError> {
    object(root, FieldPath::Other)?;
    Ok(NetworkObservation {
        reference,
        name: string_field(
            root,
            &["Name"],
            FieldPath::Network { index: 0 },
            Origin::Effective,
        )?,
        driver: string_field(
            root,
            &["Driver"],
            FieldPath::Network { index: 0 },
            Origin::Effective,
        )?,
        internal: bool_field(
            root,
            &["Internal"],
            FieldPath::Network { index: 0 },
            Origin::Effective,
        )?,
    })
}

fn volume(root: &Value, reference: ResourceRef) -> Result<VolumeObservation, DecodeError> {
    object(root, FieldPath::Other)?;
    Ok(VolumeObservation {
        reference,
        name: string_field(
            root,
            &["Name"],
            FieldPath::Volume { index: 0 },
            Origin::Effective,
        )?,
        driver: string_field(
            root,
            &["Driver"],
            FieldPath::Volume { index: 0 },
            Origin::Effective,
        )?,
        mountpoint: string_field(
            root,
            &["Mountpoint"],
            FieldPath::Volume { index: 0 },
            Origin::RuntimeAssigned,
        )?,
    })
}

fn version_field(root: &Value, name: &str) -> Result<Option<ApiVersion>, DecodeError> {
    match field_value(root, &[name], FieldPath::ApiVersion)? {
        None | Some(Value::Null) => Ok(None),
        Some(value) if is_redacted(value) => Ok(None),
        Some(value) => value
            .as_str()
            .and_then(parse_api)
            .map(Some)
            .ok_or(DecodeError::InvalidValue(FieldPath::ApiVersion)),
    }
}

fn release_field(root: &Value, name: &str) -> Result<Option<EngineRelease>, DecodeError> {
    match field_value(root, &[name], FieldPath::EngineRelease)? {
        None | Some(Value::Null) => Ok(None),
        Some(value) if is_redacted(value) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|text| EngineRelease::new(text.to_owned()))
            .ok_or(DecodeError::InvalidShape(FieldPath::EngineRelease)),
    }
}

fn listed_id(item: &Value, field: FieldPath, key: &str) -> Result<String, DecodeError> {
    let id = object(item, field)?
        .get(key)
        .and_then(Value::as_str)
        .ok_or(DecodeError::InvalidShape(field))?;
    if id.is_empty() {
        return Err(DecodeError::InvalidValue(field));
    }
    Ok(id.to_owned())
}

/// Decode a completed capture. A completed capture can be caller-supplied and
/// is not itself proof of daemon contact or an atomic daemon snapshot.
pub fn decode_capture(capture: &Capture) -> Result<DecodedInventory, DecodeError> {
    if capture.exchanges().len() > MAX_COLLECTION_ITEMS {
        return Err(DecodeError::CollectionTooLarge);
    }
    let mut result = DecodedInventory {
        observation_id: capture.observation_id(),
        version: DecodedVersion {
            daemon: DaemonFacts {
                observation_id: capture.observation_id(),
                release: None,
                api_version: None,
                minimum_api_version: None,
                mode: DaemonMode::Unknown,
                capabilities: Vec::new(),
            },
            client_release: None,
            distribution_package_revision: None,
            requested_api_versions: Vec::new(),
        },
        containers: Vec::new(),
        networks: Vec::new(),
        volumes: Vec::new(),
        findings: Vec::new(),
    };
    let mut seen_resources = HashSet::new();
    let mut listed_ids: [HashSet<String>; 3] = std::array::from_fn(|_| HashSet::new());
    let mut inspected_ids: [HashSet<String>; 3] = std::array::from_fn(|_| HashSet::new());
    let mut version_seen = false;
    let mut info_seen = false;
    for exchange in capture.exchanges() {
        if exchange.status().code() != 200 {
            return Err(DecodeError::UnexpectedStatus);
        }
        if exchange.body().as_bytes().len() > MAX_JSON_BYTES {
            return Err(DecodeError::ResponseTooLarge);
        }
        let body: Value = serde_json::from_slice(exchange.body().as_bytes())
            .map_err(|_| DecodeError::InvalidJson)?;
        if let Some(api) = exchange.api_version() {
            if !result.version.requested_api_versions.contains(&api) {
                result.version.requested_api_versions.push(api);
            }
        } else if !matches!(exchange.request(), ReadRequest::DaemonVersion) {
            return Err(DecodeError::MissingApiVersion);
        }
        match exchange.request() {
            ReadRequest::DaemonVersion => {
                if version_seen {
                    return Err(DecodeError::ConflictingFacts);
                }
                version_seen = true;
                object(&body, FieldPath::Other)?;
                let release = release_field(&body, "Version")?;
                if let Some(release) = release {
                    if result
                        .version
                        .daemon
                        .release
                        .as_ref()
                        .is_some_and(|known| known != &release)
                    {
                        return Err(DecodeError::ConflictingFacts);
                    }
                    result.version.daemon.release = Some(release);
                }
                result.version.daemon.api_version = version_field(&body, "ApiVersion")?;
                result.version.daemon.minimum_api_version = version_field(&body, "MinAPIVersion")?;
            }
            ReadRequest::DaemonInfo => {
                if info_seen {
                    return Err(DecodeError::ConflictingFacts);
                }
                info_seen = true;
                object(&body, FieldPath::Other)?;
                if let Some(release) = release_field(&body, "ServerVersion")? {
                    if result
                        .version
                        .daemon
                        .release
                        .as_ref()
                        .is_some_and(|known| known != &release)
                    {
                        return Err(DecodeError::ConflictingFacts);
                    }
                    result.version.daemon.release = Some(release);
                }
                if let Some(options) =
                    field_value(&body, &["SecurityOptions"], FieldPath::DaemonMode)?
                {
                    if !options.is_null() && !is_redacted(options) {
                        let mut rootless = false;
                        for option in array(options, FieldPath::DaemonMode)? {
                            let option = option
                                .as_str()
                                .ok_or(DecodeError::InvalidShape(FieldPath::DaemonMode))?;
                            rootless |=
                                option == "name=rootless" || option.starts_with("name=rootless,");
                        }
                        if rootless {
                            result.version.daemon.mode = DaemonMode::Rootless;
                        }
                    }
                }
                if let Some(rootless) = field_value(&body, &["Rootless"], FieldPath::DaemonMode)? {
                    if !rootless.is_null() && !is_redacted(rootless) {
                        let rootless = rootless
                            .as_bool()
                            .ok_or(DecodeError::InvalidShape(FieldPath::DaemonMode))?;
                        let mode = if rootless {
                            DaemonMode::Rootless
                        } else {
                            DaemonMode::Rootful
                        };
                        if result.version.daemon.mode != DaemonMode::Unknown
                            && result.version.daemon.mode != mode
                        {
                            return Err(DecodeError::ConflictingFacts);
                        }
                        result.version.daemon.mode = mode;
                    }
                }
            }
            ReadRequest::ListContainers => {
                for item in array(&body, FieldPath::Other)? {
                    listed_ids[0].insert(listed_id(item, FieldPath::Other, "Id")?);
                }
            }
            ReadRequest::ListNetworks => {
                for item in array(&body, FieldPath::Other)? {
                    listed_ids[1].insert(listed_id(item, FieldPath::Network { index: 0 }, "Id")?);
                }
            }
            ReadRequest::ListVolumes => {
                object(&body, FieldPath::Other)?;
                if let Some(volumes) =
                    field_value(&body, &["Volumes"], FieldPath::Volume { index: 0 })?
                {
                    if !volumes.is_null() && !is_redacted(volumes) {
                        for item in array(volumes, FieldPath::Volume { index: 0 })? {
                            listed_ids[2].insert(listed_id(
                                item,
                                FieldPath::Volume { index: 0 },
                                "Name",
                            )?);
                        }
                    }
                }
            }
            ReadRequest::InspectContainer(_)
            | ReadRequest::InspectNetwork(_)
            | ReadRequest::InspectVolume(_) => {
                let reference = exchange
                    .resource()
                    .ok_or(DecodeError::InvalidShape(FieldPath::Other))?;
                let (kind, id) = match exchange.request() {
                    ReadRequest::InspectContainer(id) => (0, id.as_str()),
                    ReadRequest::InspectNetwork(id) => (1, id.as_str()),
                    ReadRequest::InspectVolume(id) => (2, id.as_str()),
                    _ => unreachable!("inspect request matched above"),
                };
                if !seen_resources.insert((kind, reference)) {
                    return Err(DecodeError::DuplicateResource);
                }
                inspected_ids[kind].insert(id.to_owned());
                match kind {
                    0 => {
                        let container = container(&body, reference)?;
                        if let Some(mounts) = container.mounts.value() {
                            for (index, mount) in mounts.iter().enumerate() {
                                if mount.kind == MountKind::Other {
                                    result.findings.push(Finding {
                                        severity: Severity::Warning,
                                        code: FindingCode::UnsupportedValue,
                                        resource: Some(reference),
                                        field: Some(FieldPath::Mount { index }),
                                    });
                                }
                            }
                        }
                        if container.network_mode.value().is_some_and(|mode| {
                            !matches!(
                                mode.kind,
                                NetworkModeKind::Default | NetworkModeKind::Bridge
                            )
                        }) {
                            result.findings.push(Finding {
                                severity: Severity::Warning,
                                code: FindingCode::UnsupportedValue,
                                resource: Some(reference),
                                field: Some(FieldPath::NetworkMode),
                            });
                        }
                        if container.healthcheck.value().is_some_and(|health| {
                            matches!(health.test.value(), Some(HealthcheckTest::Other(_)))
                        }) {
                            result.findings.push(Finding {
                                severity: Severity::Warning,
                                code: FindingCode::UnsupportedValue,
                                resource: Some(reference),
                                field: Some(FieldPath::Healthcheck),
                            });
                        }
                        result.containers.push(container);
                    }
                    1 => result.networks.push(network(&body, reference)?),
                    _ => result.volumes.push(volume(&body, reference)?),
                }
            }
        }
    }
    if (0..3).any(|kind| {
        !listed_ids[kind].is_empty() && listed_ids[kind].is_disjoint(&inspected_ids[kind])
    }) || capture.bounds().selected_resources > result.containers.len()
    {
        return Err(DecodeError::IncompleteInventory);
    }
    let minimum = result.version.daemon.minimum_api_version;
    let maximum = result.version.daemon.api_version;
    if minimum
        .zip(maximum)
        .is_some_and(|(minimum, maximum)| minimum > maximum)
        || result.version.requested_api_versions.iter().any(|api| {
            minimum.is_some_and(|minimum| *api < minimum)
                || maximum.is_some_and(|maximum| *api > maximum)
        })
    {
        return Err(DecodeError::ApiVersionOutOfRange);
    }
    if result.version.daemon.release.is_none() || result.version.daemon.api_version.is_none() {
        result.findings.push(Finding {
            severity: Severity::Warning,
            code: FindingCode::MissingField,
            resource: None,
            field: Some(FieldPath::EngineRelease),
        });
    }
    if result.version.daemon.mode == DaemonMode::Unknown {
        result.findings.push(Finding {
            severity: Severity::Warning,
            code: FindingCode::CapabilityUnknown,
            resource: None,
            field: Some(FieldPath::DaemonMode),
        });
    }
    Ok(result)
}
