//! Pure decoding of bounded, protected Docker Engine captures.
//!
//! The request, HTTP status, local reference and actual URL API version are
//! part of the input contract. No JSON field can establish Compose authorship
//! or a positive target capability. Decoder errors contain no native values.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU16;

use serde_json::Value;

use crate::acquisition::{ReadRequest, RootKind, SelectedRoot, Selector, selected_ids};
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
    /// Bounded list metadata; names, labels and image remain protected.
    pub discovered_containers: Vec<ContainerSummary>,
    /// Explicit inspected roots and selection reasons, with opaque references.
    pub selected_roots: Vec<SelectedRoot>,
    pub networks: Vec<NetworkObservation>,
    pub volumes: Vec<VolumeObservation>,
    pub findings: Vec<Finding>,
}

impl std::fmt::Debug for DecodedInventory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedInventory")
            .field("observation_id", &self.observation_id)
            .field("containers", &self.containers.len())
            .field("discovered_containers", &self.discovered_containers.len())
            .field("networks", &self.networks.len())
            .field("volumes", &self.volumes.len())
            .field("findings", &self.findings)
            .finish_non_exhaustive()
    }
}

/// List metadata is not an inspected container or proof of authored intent.
pub struct ContainerSummary {
    pub id: ProtectedValue,
    pub names: Observed<Vec<ProtectedValue>>,
    pub labels: Observed<Vec<LabelObservation>>,
    pub image: Observed<ProtectedValue>,
}

impl std::fmt::Debug for ContainerSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainerSummary")
            .field("id", &"[redacted]")
            .field("names", &self.names)
            .field("labels", &self.labels)
            .field("image", &self.image)
            .finish()
    }
}

pub struct ContainerObservation {
    pub reference: ResourceRef,
    /// Inspect `Name` is an effective identity, not evidence of who chose it.
    pub name: Observed<ProtectedValue>,
    pub image: Observed<ProtectedValue>,
    pub image_id: Observed<ProtectedValue>,
    pub labels: Observed<Vec<LabelObservation>>,
    pub user: Observed<ProtectedValue>,
    pub working_directory: Observed<ProtectedValue>,
    pub hostname: Observed<ProtectedValue>,
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
    pub runtime: RuntimeObservation,
}

/// Effective runtime configuration from inspect, never proof of original authorship.
pub struct RuntimeObservation {
    pub read_only_rootfs: Observed<bool>,
    pub memory_bytes: Observed<i64>,
    pub pids_limit: Observed<i64>,
    pub shm_size_bytes: Observed<i64>,
    pub ulimits: Observed<Vec<UlimitObservation>>,
    pub cap_add: Observed<Vec<ProtectedValue>>,
    pub cap_drop: Observed<Vec<ProtectedValue>>,
    pub security_options: Observed<Vec<ProtectedValue>>,
    pub userns_mode: Observed<ProtectedValue>,
    pub supplementary_groups: Observed<Vec<ProtectedValue>>,
    pub sysctls: Observed<Vec<MapEntryObservation>>,
    pub dns_servers: Observed<Vec<ProtectedValue>>,
    pub dns_options: Observed<Vec<ProtectedValue>>,
    pub dns_search: Observed<Vec<ProtectedValue>>,
    pub extra_hosts: Observed<Vec<ProtectedValue>>,
    pub init: Observed<bool>,
    pub stop_signal: Observed<ProtectedValue>,
    pub stop_timeout: Observed<i64>,
    pub logging: Observed<LoggingObservation>,
    pub tmpfs: Observed<Vec<MapEntryObservation>>,
    pub binds: Observed<Vec<ProtectedValue>>,
    pub configured_mounts: Observed<Vec<ConfiguredMountObservation>>,
    pub volumes_from: Observed<Vec<ProtectedValue>>,
    pub devices: Observed<Vec<DeviceObservation>>,
}

pub struct ConfiguredMountObservation {
    pub kind: Observed<ProtectedValue>,
    pub source: Observed<ProtectedValue>,
    pub target: Observed<ProtectedValue>,
    pub read_only: Observed<bool>,
    pub bind_propagation: Observed<ProtectedValue>,
    pub volume_no_copy: Observed<bool>,
    pub tmpfs_size_bytes: Observed<i64>,
}

pub struct UlimitObservation {
    pub name: Observed<ProtectedValue>,
    pub soft: Observed<i64>,
    pub hard: Observed<i64>,
}

pub struct MapEntryObservation {
    pub key: ProtectedValue,
    pub value: Observed<ProtectedValue>,
}

pub struct LoggingObservation {
    pub driver: Observed<ProtectedValue>,
    pub options: Observed<Vec<MapEntryObservation>>,
}

pub struct DeviceObservation {
    pub host_path: Observed<ProtectedValue>,
    pub container_path: Observed<ProtectedValue>,
    pub permissions: Observed<ProtectedValue>,
}

/// A native label key and its independently available value. Both are private.
pub struct LabelObservation {
    pub key: ProtectedValue,
    pub value: Observed<ProtectedValue>,
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
    pub mode: Observed<ProtectedValue>,
    pub propagation: Observed<ProtectedValue>,
}

pub struct NetworkAttachment {
    pub name: ProtectedValue,
    pub network_id: Observed<ProtectedValue>,
    pub ip_address: Observed<ProtectedValue>,
    pub ipv6_address: Observed<ProtectedValue>,
    pub requested_ipv4_address: Observed<ProtectedValue>,
    pub requested_ipv6_address: Observed<ProtectedValue>,
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
    pub enable_ipv6: Observed<bool>,
    pub ipam_driver: Observed<ProtectedValue>,
    pub ipam_configs: Observed<Vec<IpamConfigObservation>>,
    pub options: Observed<Vec<MapEntryObservation>>,
    pub labels: Observed<Vec<LabelObservation>>,
}

pub struct IpamConfigObservation {
    pub subnet: Observed<ProtectedValue>,
    pub gateway: Observed<ProtectedValue>,
    pub ip_range: Observed<ProtectedValue>,
    pub auxiliary_addresses: Observed<Vec<MapEntryObservation>>,
}

pub struct VolumeObservation {
    pub reference: ResourceRef,
    pub name: Observed<ProtectedValue>,
    pub driver: Observed<ProtectedValue>,
    pub mountpoint: Observed<ProtectedValue>,
    pub options: Observed<Vec<MapEntryObservation>>,
    pub labels: Observed<Vec<LabelObservation>>,
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

fn labels(value: &Value) -> Result<Vec<LabelObservation>, DecodeError> {
    object(value, FieldPath::Label { index: 0 })?
        .iter()
        .enumerate()
        .map(|(index, (key, value))| {
            let field = FieldPath::Label { index };
            let value = if value.is_null() {
                Observed::unavailable(Availability::Null, Origin::Effective)
            } else if is_redacted(value) {
                Observed::unavailable(Availability::Redacted, Origin::Effective)
            } else {
                let value = string(value, field)?;
                let availability = if value.is_empty() {
                    Availability::Empty
                } else {
                    Availability::Present
                };
                Observed::present(value, availability, Origin::Effective)
            };
            Ok(LabelObservation {
                key: ProtectedValue::new(key.as_bytes().to_vec()),
                value,
            })
        })
        .collect()
}

fn signed_field(
    root: &Value,
    path: &[&str],
    field: FieldPath,
    origin: Origin,
) -> Result<Observed<i64>, DecodeError> {
    observed(root, path, field, origin, |value| {
        value.as_i64().ok_or(DecodeError::InvalidShape(field))
    })
}

fn string_list(value: &Value, field: FieldPath) -> Result<Vec<ProtectedValue>, DecodeError> {
    array(value, field)?
        .iter()
        .map(|item| string(item, field))
        .collect()
}

fn map_entries(value: &Value, field: FieldPath) -> Result<Vec<MapEntryObservation>, DecodeError> {
    object(value, field)?
        .iter()
        .map(|(key, value)| {
            Ok(MapEntryObservation {
                key: ProtectedValue::new(key.as_bytes().to_vec()),
                value: observed(value, &[], field, Origin::Effective, |item| {
                    string(item, field)
                })?,
            })
        })
        .collect()
}

fn ulimits(value: &Value) -> Result<Vec<UlimitObservation>, DecodeError> {
    array(value, FieldPath::ResourceLimit)?
        .iter()
        .map(|item| {
            object(item, FieldPath::ResourceLimit)?;
            Ok(UlimitObservation {
                name: string_field(item, &["Name"], FieldPath::ResourceLimit, Origin::Effective)?,
                soft: signed_field(item, &["Soft"], FieldPath::ResourceLimit, Origin::Effective)?,
                hard: signed_field(item, &["Hard"], FieldPath::ResourceLimit, Origin::Effective)?,
            })
        })
        .collect()
}

fn devices(value: &Value) -> Result<Vec<DeviceObservation>, DecodeError> {
    array(value, FieldPath::Device)?
        .iter()
        .map(|item| {
            object(item, FieldPath::Device)?;
            Ok(DeviceObservation {
                host_path: string_field(
                    item,
                    &["PathOnHost"],
                    FieldPath::Device,
                    Origin::Effective,
                )?,
                container_path: string_field(
                    item,
                    &["PathInContainer"],
                    FieldPath::Device,
                    Origin::Effective,
                )?,
                permissions: string_field(
                    item,
                    &["CgroupPermissions"],
                    FieldPath::Device,
                    Origin::Effective,
                )?,
            })
        })
        .collect()
}

fn configured_mounts(value: &Value) -> Result<Vec<ConfiguredMountObservation>, DecodeError> {
    array(value, FieldPath::RuntimeMount)?
        .iter()
        .map(|item| {
            object(item, FieldPath::RuntimeMount)?;
            Ok(ConfiguredMountObservation {
                kind: string_field(item, &["Type"], FieldPath::RuntimeMount, Origin::Effective)?,
                source: string_field(
                    item,
                    &["Source"],
                    FieldPath::RuntimeMount,
                    Origin::Effective,
                )?,
                target: string_field(
                    item,
                    &["Target"],
                    FieldPath::RuntimeMount,
                    Origin::Effective,
                )?,
                read_only: bool_field(
                    item,
                    &["ReadOnly"],
                    FieldPath::RuntimeMount,
                    Origin::Effective,
                )?,
                bind_propagation: string_field(
                    item,
                    &["BindOptions", "Propagation"],
                    FieldPath::RuntimeMount,
                    Origin::Effective,
                )?,
                volume_no_copy: bool_field(
                    item,
                    &["VolumeOptions", "NoCopy"],
                    FieldPath::RuntimeMount,
                    Origin::Effective,
                )?,
                tmpfs_size_bytes: signed_field(
                    item,
                    &["TmpfsOptions", "SizeBytes"],
                    FieldPath::RuntimeMount,
                    Origin::Effective,
                )?,
            })
        })
        .collect()
}

fn logging(value: &Value) -> Result<LoggingObservation, DecodeError> {
    object(value, FieldPath::Logging)?;
    Ok(LoggingObservation {
        driver: string_field(value, &["Type"], FieldPath::Logging, Origin::Effective)?,
        options: observed(
            value,
            &["Config"],
            FieldPath::Logging,
            Origin::Effective,
            |item| map_entries(item, FieldPath::Logging),
        )?,
    })
}

fn ipam_configs(value: &Value) -> Result<Vec<IpamConfigObservation>, DecodeError> {
    array(value, FieldPath::NetworkIpam)?
        .iter()
        .map(|item| {
            object(item, FieldPath::NetworkIpam)?;
            Ok(IpamConfigObservation {
                subnet: string_field(item, &["Subnet"], FieldPath::NetworkIpam, Origin::Effective)?,
                gateway: string_field(
                    item,
                    &["Gateway"],
                    FieldPath::NetworkIpam,
                    Origin::Effective,
                )?,
                ip_range: string_field(
                    item,
                    &["IPRange"],
                    FieldPath::NetworkIpam,
                    Origin::Effective,
                )?,
                auxiliary_addresses: observed(
                    item,
                    &["AuxiliaryAddresses"],
                    FieldPath::NetworkIpam,
                    Origin::Effective,
                    |value| map_entries(value, FieldPath::NetworkIpam),
                )?,
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
                mode: string_field(item, &["Mode"], field, Origin::Effective)?,
                propagation: string_field(item, &["Propagation"], field, Origin::Effective)?,
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
                network_id: string_field(item, &["NetworkID"], field, Origin::RuntimeAssigned)?,
                ip_address: string_field(item, &["IPAddress"], field, Origin::RuntimeAssigned)?,
                ipv6_address: string_field(
                    item,
                    &["GlobalIPv6Address"],
                    field,
                    Origin::RuntimeAssigned,
                )?,
                requested_ipv4_address: string_field(
                    item,
                    &["IPAMConfig", "IPv4Address"],
                    field,
                    Origin::Effective,
                )?,
                requested_ipv6_address: string_field(
                    item,
                    &["IPAMConfig", "IPv6Address"],
                    field,
                    Origin::Effective,
                )?,
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

fn runtime(root: &Value) -> Result<RuntimeObservation, DecodeError> {
    let effective = Origin::Effective;
    let string_array = |path: &[&str], field| {
        observed(root, path, field, effective, |value| {
            string_list(value, field)
        })
    };
    Ok(RuntimeObservation {
        read_only_rootfs: bool_field(
            root,
            &["HostConfig", "ReadonlyRootfs"],
            FieldPath::RuntimeMount,
            effective,
        )?,
        memory_bytes: signed_field(
            root,
            &["HostConfig", "Memory"],
            FieldPath::ResourceLimit,
            effective,
        )?,
        pids_limit: signed_field(
            root,
            &["HostConfig", "PidsLimit"],
            FieldPath::ResourceLimit,
            effective,
        )?,
        shm_size_bytes: signed_field(
            root,
            &["HostConfig", "ShmSize"],
            FieldPath::ResourceLimit,
            effective,
        )?,
        ulimits: observed(
            root,
            &["HostConfig", "Ulimits"],
            FieldPath::ResourceLimit,
            effective,
            ulimits,
        )?,
        cap_add: string_array(&["HostConfig", "CapAdd"], FieldPath::SecuritySetting)?,
        cap_drop: string_array(&["HostConfig", "CapDrop"], FieldPath::SecuritySetting)?,
        security_options: string_array(&["HostConfig", "SecurityOpt"], FieldPath::SecuritySetting)?,
        userns_mode: string_field(
            root,
            &["HostConfig", "UsernsMode"],
            FieldPath::SecuritySetting,
            effective,
        )?,
        supplementary_groups: string_array(
            &["HostConfig", "GroupAdd"],
            FieldPath::SecuritySetting,
        )?,
        sysctls: observed(
            root,
            &["HostConfig", "Sysctls"],
            FieldPath::SecuritySetting,
            effective,
            |value| map_entries(value, FieldPath::SecuritySetting),
        )?,
        dns_servers: string_array(&["HostConfig", "Dns"], FieldPath::NameResolution)?,
        dns_options: string_array(&["HostConfig", "DnsOptions"], FieldPath::NameResolution)?,
        dns_search: string_array(&["HostConfig", "DnsSearch"], FieldPath::NameResolution)?,
        extra_hosts: string_array(&["HostConfig", "ExtraHosts"], FieldPath::NameResolution)?,
        init: bool_field(
            root,
            &["HostConfig", "Init"],
            FieldPath::StopBehavior,
            effective,
        )?,
        stop_signal: string_field(
            root,
            &["Config", "StopSignal"],
            FieldPath::StopBehavior,
            effective,
        )?,
        stop_timeout: signed_field(
            root,
            &["Config", "StopTimeout"],
            FieldPath::StopBehavior,
            effective,
        )?,
        logging: observed(
            root,
            &["HostConfig", "LogConfig"],
            FieldPath::Logging,
            effective,
            logging,
        )?,
        tmpfs: observed(
            root,
            &["HostConfig", "Tmpfs"],
            FieldPath::RuntimeMount,
            effective,
            |value| map_entries(value, FieldPath::RuntimeMount),
        )?,
        binds: string_array(&["HostConfig", "Binds"], FieldPath::RuntimeMount)?,
        configured_mounts: observed(
            root,
            &["HostConfig", "Mounts"],
            FieldPath::RuntimeMount,
            effective,
            configured_mounts,
        )?,
        volumes_from: string_array(&["HostConfig", "VolumesFrom"], FieldPath::RuntimeMount)?,
        devices: observed(
            root,
            &["HostConfig", "Devices"],
            FieldPath::Device,
            effective,
            devices,
        )?,
    })
}

fn container_summary(root: &Value) -> Result<ContainerSummary, DecodeError> {
    object(root, FieldPath::Other)?;
    let id = listed_id(root, FieldPath::Other, "Id")?;
    Ok(ContainerSummary {
        id: ProtectedValue::new(id.into_bytes()),
        names: observed(
            root,
            &["Names"],
            FieldPath::ContainerName,
            Origin::Effective,
            |value| {
                array(value, FieldPath::ContainerName)?
                    .iter()
                    .map(|name| string(name, FieldPath::ContainerName))
                    .collect()
            },
        )?,
        labels: observed(
            root,
            &["Labels"],
            FieldPath::Label { index: 0 },
            Origin::Effective,
            labels,
        )?,
        image: string_field(root, &["Image"], FieldPath::Image, Origin::Effective)?,
    })
}

fn container(root: &Value, reference: ResourceRef) -> Result<ContainerObservation, DecodeError> {
    object(root, FieldPath::Other)?;
    Ok(ContainerObservation {
        reference,
        name: string_field(root, &["Name"], FieldPath::ContainerName, Origin::Effective)?,
        image: string_field(
            root,
            &["Config", "Image"],
            FieldPath::Image,
            Origin::Effective,
        )?,
        image_id: string_field(root, &["Image"], FieldPath::Image, Origin::RuntimeAssigned)?,
        labels: observed(
            root,
            &["Config", "Labels"],
            FieldPath::Label { index: 0 },
            Origin::Effective,
            labels,
        )?,
        user: string_field(
            root,
            &["Config", "User"],
            FieldPath::User,
            Origin::Effective,
        )?,
        working_directory: string_field(
            root,
            &["Config", "WorkingDir"],
            FieldPath::WorkingDirectory,
            Origin::Effective,
        )?,
        hostname: string_field(
            root,
            &["Config", "Hostname"],
            FieldPath::Hostname,
            Origin::Effective,
        )?,
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
        runtime: runtime(root)?,
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
        enable_ipv6: bool_field(
            root,
            &["EnableIPv6"],
            FieldPath::NetworkOption,
            Origin::Effective,
        )?,
        ipam_driver: string_field(
            root,
            &["IPAM", "Driver"],
            FieldPath::NetworkIpam,
            Origin::Effective,
        )?,
        ipam_configs: observed(
            root,
            &["IPAM", "Config"],
            FieldPath::NetworkIpam,
            Origin::Effective,
            ipam_configs,
        )?,
        options: observed(
            root,
            &["Options"],
            FieldPath::NetworkOption,
            Origin::Effective,
            |value| map_entries(value, FieldPath::NetworkOption),
        )?,
        labels: observed(
            root,
            &["Labels"],
            FieldPath::Label { index: 0 },
            Origin::Effective,
            labels,
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
        options: observed(
            root,
            &["Options"],
            FieldPath::Volume { index: 0 },
            Origin::Effective,
            |value| map_entries(value, FieldPath::Volume { index: 0 }),
        )?,
        labels: observed(
            root,
            &["Labels"],
            FieldPath::Label { index: 0 },
            Origin::Effective,
            labels,
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
        discovered_containers: Vec::new(),
        selected_roots: capture.selected_roots().to_vec(),
        networks: Vec::new(),
        volumes: Vec::new(),
        findings: Vec::new(),
    };
    let mut seen_resources = HashSet::new();
    let mut listed_ids: [HashSet<String>; 3] = std::array::from_fn(|_| HashSet::new());
    let mut inspected_ids: [HashSet<String>; 3] = std::array::from_fn(|_| HashSet::new());
    let mut inspected_native_objects: [HashSet<String>; 3] =
        std::array::from_fn(|_| HashSet::new());
    let mut inspected_containers_by_ref = HashMap::new();
    let mut selected_from_list: Option<HashSet<String>> = None;
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
                if selected_from_list.is_some() {
                    return Err(DecodeError::ConflictingFacts);
                }
                if let Some(
                    selector @ (Selector::ContainerNames(_)
                    | Selector::NamePrefix(_)
                    | Selector::Label { .. }
                    | Selector::AllContainers),
                ) = capture.selector()
                {
                    selected_from_list = Some(
                        selected_ids(exchange.body().as_bytes(), selector)
                            .map_err(|_| DecodeError::IncompleteInventory)?
                            .into_iter()
                            .map(|id| id.as_str().to_owned())
                            .collect(),
                    );
                }
                for item in array(&body, FieldPath::Other)? {
                    listed_ids[0].insert(listed_id(item, FieldPath::Other, "Id")?);
                    result.discovered_containers.push(container_summary(item)?);
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
                let identity_key = if kind == 2
                    || (kind == 1 && capture.network_name_fallbacks().contains(&reference))
                {
                    "Name"
                } else {
                    "Id"
                };
                if body.get(identity_key).and_then(Value::as_str) != Some(id) {
                    return Err(DecodeError::ConflictingFacts);
                }
                let native_key = if kind == 2 { "Name" } else { "Id" };
                let native_id = body
                    .get(native_key)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or(DecodeError::InvalidShape(FieldPath::Other))?;
                if !inspected_native_objects[kind].insert(native_id.to_owned()) {
                    return Err(DecodeError::DuplicateResource);
                }
                if !seen_resources.insert((kind, reference)) {
                    return Err(DecodeError::DuplicateResource);
                }
                inspected_ids[kind].insert(id.to_owned());
                if kind == 0 {
                    inspected_containers_by_ref.insert(reference, id.to_owned());
                }
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
    let mut selected_references = HashSet::new();
    if capture
        .network_name_fallbacks()
        .iter()
        .any(|reference| !seen_resources.contains(&(1, *reference)))
    {
        return Err(DecodeError::IncompleteInventory);
    }
    if let Some(expected) = selected_from_list {
        let selected: HashSet<_> = capture
            .selected_roots()
            .iter()
            .filter(|root| root.kind == RootKind::Container)
            .filter_map(|root| inspected_containers_by_ref.get(&root.resource).cloned())
            .collect();
        if expected != selected {
            return Err(DecodeError::IncompleteInventory);
        }
    } else if matches!(
        capture.selector(),
        Some(
            Selector::ContainerNames(_)
                | Selector::NamePrefix(_)
                | Selector::Label { .. }
                | Selector::AllContainers
        )
    ) {
        return Err(DecodeError::IncompleteInventory);
    }
    if capture.selected_roots().len() != capture.bounds().selected_resources
        && !capture.selected_roots().is_empty()
    {
        return Err(DecodeError::IncompleteInventory);
    }
    if capture.selected_roots().iter().any(|root| {
        !selected_references.insert(root.resource)
            || !match root.kind {
                RootKind::Container => result
                    .containers
                    .iter()
                    .any(|container| container.reference == root.resource),
                RootKind::Network => result
                    .networks
                    .iter()
                    .any(|network| network.reference == root.resource),
                RootKind::Volume => result
                    .volumes
                    .iter()
                    .any(|volume| volume.reference == root.resource),
            }
            || (root.kind == RootKind::Container
                && root.reason != crate::acquisition::SelectionReason::ExactId
                && inspected_containers_by_ref
                    .get(&root.resource)
                    .is_none_or(|id| !listed_ids[0].contains(id)))
    }) {
        return Err(DecodeError::IncompleteInventory);
    }
    if (0..3).any(|kind| {
        !(capture.discovery_only() && kind == 0)
            && !listed_ids[kind].is_empty()
            && listed_ids[kind].is_disjoint(&inspected_ids[kind])
    }) || (capture.selected_roots().is_empty()
        && capture.bounds().selected_resources > result.containers.len())
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

#[cfg(test)]
mod selector_replay_tests {
    use super::*;
    use crate::acquisition::{Budget, Limits, NativeId, SelectionReason};
    use crate::evidence::HttpStatus;
    use std::time::Duration;

    #[test]
    fn replay_rejects_uninspected_matching_prefix_peer() {
        let mut budget = Budget::new(Limits {
            max_requests: 3,
            max_selected_resources: 2,
            max_expansions: 1,
            max_response_bytes: 4096,
            max_total_bytes: 8192,
            max_elapsed: Duration::from_secs(2),
        })
        .unwrap();
        budget.record_selection(1).unwrap();
        let api = ApiVersion::new(NonZeroU16::new(1).unwrap(), 49);
        let selected = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        budget
            .record_request(ReadRequest::ListContainers, None, Some(api))
            .unwrap();
        let list = format!(
            r#"[{{"Id":"{selected}","Names":["/app-one"]}},{{"Id":"{peer}","Names":["/app-two"]}}]"#
        );
        budget
            .read_response(HttpStatus::new(200).unwrap(), list.as_bytes())
            .unwrap();
        let reference = ResourceRef::new(1);
        budget
            .record_request(
                ReadRequest::InspectContainer(NativeId::new(selected.to_owned()).unwrap()),
                Some(reference),
                Some(api),
            )
            .unwrap();
        let inspect = format!(r#"{{"Id":"{selected}"}}"#);
        budget
            .read_response(HttpStatus::new(200).unwrap(), inspect.as_bytes())
            .unwrap();
        let capture = budget
            .into_capture()
            .unwrap()
            .with_selected_roots(vec![SelectedRoot {
                resource: reference,
                kind: RootKind::Container,
                reason: SelectionReason::NamePrefix,
            }])
            .with_selector(Selector::NamePrefix(
                NativeId::new("app-".to_owned()).unwrap(),
            ));
        assert!(matches!(
            decode_capture(&capture),
            Err(DecodeError::IncompleteInventory)
        ));
    }

    #[test]
    fn replay_rejects_one_network_under_name_and_id() {
        let mut budget = Budget::new(Limits {
            max_requests: 2,
            max_selected_resources: 1,
            max_expansions: 2,
            max_response_bytes: 4096,
            max_total_bytes: 8192,
            max_elapsed: Duration::from_secs(2),
        })
        .unwrap();
        let api = ApiVersion::new(NonZeroU16::new(1).unwrap(), 49);
        let canonical = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let body = format!(r#"{{"Id":"{canonical}","Name":"shared"}}"#);
        for (id, reference) in [("shared", 1), (canonical, 2)] {
            budget
                .record_request(
                    ReadRequest::InspectNetwork(NativeId::new(id.to_owned()).unwrap()),
                    Some(ResourceRef::new(reference)),
                    Some(api),
                )
                .unwrap();
            budget
                .read_response(HttpStatus::new(200).unwrap(), body.as_bytes())
                .unwrap();
        }
        let capture = budget
            .into_capture()
            .unwrap()
            .with_network_name_fallbacks(HashSet::from([ResourceRef::new(1)]));
        assert!(matches!(
            decode_capture(&capture),
            Err(DecodeError::DuplicateResource)
        ));
    }
}
