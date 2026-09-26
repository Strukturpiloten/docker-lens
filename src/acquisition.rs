//! Closed, explicit, read-only Docker Engine acquisition over a supplied Unix socket.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::num::NonZeroU16;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use socket2::{Domain, SockAddr, Socket, Type};

use crate::evidence::{Capture, CaptureBounds, CapturedExchange, HttpStatus, ProtectedValue};
use crate::observation::ResourceRef;
use crate::version::{ApiVersion, ObservationId, ObservationIdError};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_COLLECTION_ITEMS: usize = 4096;
const IO_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_KNOWN_API_MINOR: u16 = 49;

/// Acquisition errors never contain socket paths, native names, or response bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquisitionError {
    Endpoint,
    Cancelled,
    Deadline,
    Io,
    Protocol,
    Status,
    Version,
    Shape,
    Budget(LimitError),
}

impl From<LimitError> for AcquisitionError {
    fn from(value: LimitError) -> Self {
        Self::Budget(value)
    }
}

/// A caller-provided endpoint. No ambient socket search is permitted.
pub struct Endpoint(std::path::PathBuf);

impl Endpoint {
    #[must_use]
    pub fn unix_socket(path: std::path::PathBuf) -> Self {
        Self(path)
    }

    /// Access is explicit so callers can decide how to protect the path.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Endpoint([redacted])")
    }
}

/// Identifiers may disclose application names and are excluded from `Debug`.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct NativeId(String);

impl NativeId {
    pub fn new(value: String) -> Option<Self> {
        (!value.is_empty()).then_some(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for NativeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeId([redacted])")
    }
}

/// The only requests the transport may issue. No arbitrary URL or method.
#[derive(Debug)]
pub enum ReadRequest {
    DaemonVersion,
    DaemonInfo,
    ListContainers,
    InspectContainer(NativeId),
    ListNetworks,
    InspectNetwork(NativeId),
    ListVolumes,
    InspectVolume(NativeId),
}

/// Explicit selectors are applied before bounded resource expansion.
#[derive(Debug)]
pub enum Selector {
    ContainerIds(Vec<NativeId>),
    AllContainers,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_requests: usize,
    pub max_selected_resources: usize,
    pub max_expansions: usize,
    pub max_response_bytes: usize,
    pub max_total_bytes: usize,
    pub max_elapsed: Duration,
}

impl Limits {
    /// No limit is implicit; each dimension must be nonzero and response bytes
    /// must fit inside the total byte budget.
    pub fn validate(self) -> Result<Self, LimitError> {
        if self.max_requests == 0
            || self.max_selected_resources == 0
            || self.max_expansions == 0
            || self.max_response_bytes == 0
            || self.max_response_bytes == usize::MAX
            || self.max_total_bytes == 0
            || self.max_response_bytes > self.max_total_bytes
            || self.max_elapsed.is_zero()
        {
            return Err(LimitError::Invalid);
        }
        Ok(self)
    }
}

/// Errors deliberately omit endpoint, native identifiers, and response bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitError {
    Invalid,
    Requests,
    PendingResponse,
    ResponseWithoutRequest,
    Exhausted,
    SelectedResources,
    Expansions,
    Bytes,
    Elapsed,
    Input,
    InvalidResourceRef,
    Incomplete,
    ObservationIdExhausted,
    CaptureAccounting,
    MissingApiVersion,
    ResourceConflict,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum ResourceKind {
    Container,
    Network,
    Volume,
}

struct PendingRequest {
    request: ReadRequest,
    resource: Option<ResourceRef>,
    api_version: Option<ApiVersion>,
}

/// One acquisition's counters; captures are not atomic daemon snapshots.
pub struct Budget {
    observation_id: ObservationId,
    limits: Limits,
    started: Instant,
    requests: usize,
    selected_resources: usize,
    expansions: usize,
    bytes_read: usize,
    pending: Option<PendingRequest>,
    exchanges: Vec<CapturedExchange>,
    resource_ids: HashMap<ResourceRef, (ResourceKind, NativeId)>,
    native_refs: HashMap<(ResourceKind, NativeId), ResourceRef>,
    failed: bool,
}

impl Budget {
    pub fn new(limits: Limits) -> Result<Self, LimitError> {
        let limits = limits.validate()?;
        Ok(Self {
            observation_id: ObservationId::fresh()
                .map_err(|ObservationIdError::Exhausted| LimitError::ObservationIdExhausted)?,
            limits,
            started: Instant::now(),
            requests: 0,
            selected_resources: 0,
            expansions: 0,
            bytes_read: 0,
            pending: None,
            exchanges: Vec::new(),
            resource_ids: HashMap::new(),
            native_refs: HashMap::new(),
            failed: false,
        })
    }

    fn check_time(&mut self) -> Result<(), LimitError> {
        if self.failed {
            return Err(LimitError::Exhausted);
        }
        if self.started.elapsed() > self.limits.max_elapsed {
            self.failed = true;
            Err(LimitError::Elapsed)
        } else {
            Ok(())
        }
    }

    /// Record the exact closed request and URL API version before transport I/O.
    /// Inspect requests require a local resource reference; list and version
    /// requests must not be assigned one.
    pub fn record_request(
        &mut self,
        request: ReadRequest,
        resource: Option<ResourceRef>,
        api_version: Option<ApiVersion>,
    ) -> Result<(), LimitError> {
        self.check_time()?;
        if self.pending.is_some() {
            return Err(LimitError::PendingResponse);
        }
        let inspected = match &request {
            ReadRequest::InspectContainer(id) => Some((ResourceKind::Container, id)),
            ReadRequest::InspectNetwork(id) => Some((ResourceKind::Network, id)),
            ReadRequest::InspectVolume(id) => Some((ResourceKind::Volume, id)),
            _ => None,
        };
        if inspected.is_some() != resource.is_some() {
            return Err(LimitError::InvalidResourceRef);
        }
        if !matches!(request, ReadRequest::DaemonVersion) && api_version.is_none() {
            return Err(LimitError::MissingApiVersion);
        }
        if let (Some(reference), Some((kind, id))) = (resource, inspected) {
            if self
                .resource_ids
                .get(&reference)
                .is_some_and(|registered| registered.0 != kind || registered.1 != *id)
            {
                return Err(LimitError::ResourceConflict);
            }
            if self
                .native_refs
                .get(&(kind, id.clone()))
                .is_some_and(|registered| *registered != reference)
            {
                return Err(LimitError::ResourceConflict);
            }
            let next_expansions = self.expansions.checked_add(1).ok_or_else(|| {
                self.failed = true;
                LimitError::Expansions
            })?;
            if next_expansions > self.limits.max_expansions {
                self.failed = true;
                return Err(LimitError::Expansions);
            }
            self.expansions = next_expansions;
            self.resource_ids
                .entry(reference)
                .or_insert_with(|| (kind, id.clone()));
            self.native_refs
                .entry((kind, id.clone()))
                .or_insert(reference);
        }
        self.requests = self.requests.checked_add(1).ok_or_else(|| {
            self.failed = true;
            LimitError::Requests
        })?;
        if self.requests > self.limits.max_requests {
            self.failed = true;
            return Err(LimitError::Requests);
        }
        self.pending = Some(PendingRequest {
            request,
            resource,
            api_version,
        });
        Ok(())
    }

    pub fn record_selection(&mut self, count: usize) -> Result<(), LimitError> {
        self.check_time()?;
        self.selected_resources = self.selected_resources.checked_add(count).ok_or_else(|| {
            self.failed = true;
            LimitError::SelectedResources
        })?;
        if self.selected_resources > self.limits.max_selected_resources {
            self.failed = true;
            return Err(LimitError::SelectedResources);
        }
        Ok(())
    }

    pub fn record_expansion(&mut self, count: usize) -> Result<(), LimitError> {
        self.check_time()?;
        self.expansions = self.expansions.checked_add(count).ok_or_else(|| {
            self.failed = true;
            LimitError::Expansions
        })?;
        if self.expansions > self.limits.max_expansions {
            self.failed = true;
            return Err(LimitError::Expansions);
        }
        Ok(())
    }

    /// Read at most the remaining budget plus one sentinel byte. The sentinel
    /// detects an oversized body without allocating the remainder of it.
    /// The socket transport separately configures an I/O deadline: a blocking
    /// reader cannot be interrupted by this synchronous counter alone.
    pub fn read_response<R: Read>(
        &mut self,
        status: HttpStatus,
        reader: R,
    ) -> Result<&ProtectedValue, LimitError> {
        self.check_time()?;
        if self.pending.is_none() {
            return Err(LimitError::ResponseWithoutRequest);
        }
        let allowance = self
            .limits
            .max_response_bytes
            .min(self.limits.max_total_bytes - self.bytes_read);
        let mut limited = reader.take((allowance as u64).saturating_add(1));
        let mut bytes = Vec::new();
        let result = limited.read_to_end(&mut bytes);
        self.bytes_read = self.bytes_read.saturating_add(bytes.len());
        if result.is_err() {
            self.failed = true;
            return Err(LimitError::Input);
        }
        self.check_time()?;
        if bytes.len() > allowance {
            self.failed = true;
            return Err(LimitError::Bytes);
        }
        let pending = self.pending.take().expect("pending response checked above");
        self.exchanges.push(CapturedExchange::new(
            pending.request,
            pending.resource,
            pending.api_version,
            status,
            ProtectedValue::new(bytes),
        ));
        Ok(self
            .exchanges
            .last()
            .expect("exchange was just added")
            .body())
    }

    #[must_use]
    pub fn counts(&self) -> CaptureBounds {
        CaptureBounds {
            request_count: self.requests,
            selected_resources: self.selected_resources,
            expansions: self.expansions,
            bytes_read: self.bytes_read,
        }
    }

    /// Finish only after every counted request received one bounded response.
    /// The resulting ID is process local and is not proof of daemon contact.
    pub fn into_capture(self) -> Result<Capture, LimitError> {
        if self.failed {
            return Err(LimitError::Exhausted);
        }
        if self.started.elapsed() > self.limits.max_elapsed {
            return Err(LimitError::Elapsed);
        }
        if self.pending.is_some() || self.requests == 0 {
            return Err(LimitError::Incomplete);
        }
        Capture::from_completed(self.observation_id, self.counts(), self.exchanges)
            .map_err(|_| LimitError::CaptureAccounting)
    }
}

fn remaining(
    started: Instant,
    limit: Duration,
    cancelled: &AtomicBool,
) -> Result<Duration, AcquisitionError> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(AcquisitionError::Cancelled);
    }
    limit
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(AcquisitionError::Deadline)
}

fn connect(
    endpoint: &Endpoint,
    started: Instant,
    limit: Duration,
    cancelled: &AtomicBool,
) -> Result<UnixStream, AcquisitionError> {
    if !endpoint.path().is_absolute() {
        return Err(AcquisitionError::Endpoint);
    }
    let address = SockAddr::unix(endpoint.path()).map_err(|_| AcquisitionError::Endpoint)?;
    loop {
        let timeout = remaining(started, limit, cancelled)?.min(IO_POLL_INTERVAL);
        let socket =
            Socket::new(Domain::UNIX, Type::STREAM, None).map_err(|_| AcquisitionError::Io)?;
        match socket.connect_timeout(&address, timeout) {
            Ok(()) => {
                let fd: OwnedFd = socket.into();
                return Ok(UnixStream::from(fd));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                remaining(started, limit, cancelled)?;
            }
            Err(_) => return Err(AcquisitionError::Io),
        }
    }
}

struct Wire<'a> {
    stream: UnixStream,
    started: Instant,
    limit: Duration,
    cancelled: &'a AtomicBool,
}

impl Wire<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, AcquisitionError> {
        loop {
            let timeout =
                remaining(self.started, self.limit, self.cancelled)?.min(IO_POLL_INTERVAL);
            self.stream
                .set_read_timeout(Some(timeout))
                .map_err(|_| AcquisitionError::Io)?;
            match self.stream.read(bytes) {
                Ok(count) => return Ok(count),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(AcquisitionError::Io),
            }
        }
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), AcquisitionError> {
        while !bytes.is_empty() {
            let timeout =
                remaining(self.started, self.limit, self.cancelled)?.min(IO_POLL_INTERVAL);
            self.stream
                .set_write_timeout(Some(timeout))
                .map_err(|_| AcquisitionError::Io)?;
            match self.stream.write(bytes) {
                Ok(0) => return Err(AcquisitionError::Io),
                Ok(count) => bytes = &bytes[count..],
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(AcquisitionError::Io),
            }
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, AcquisitionError> {
        let mut byte = [0];
        if self.read(&mut byte)? != 1 {
            return Err(AcquisitionError::Protocol);
        }
        Ok(byte[0])
    }

    fn line(&mut self, cap: usize) -> Result<Vec<u8>, AcquisitionError> {
        let mut line = Vec::new();
        while line.len() < cap {
            line.push(self.byte()?);
            if line.ends_with(b"\r\n") {
                line.truncate(line.len() - 2);
                return Ok(line);
            }
        }
        Err(AcquisitionError::Protocol)
    }

    fn exact(&mut self, mut count: usize, out: &mut Vec<u8>) -> Result<(), AcquisitionError> {
        let mut buffer = [0; 8192];
        while count > 0 {
            let amount = count.min(buffer.len());
            let read = self.read(&mut buffer[..amount])?;
            if read == 0 {
                return Err(AcquisitionError::Protocol);
            }
            out.extend_from_slice(&buffer[..read]);
            count -= read;
        }
        Ok(())
    }
}

fn http_get(
    endpoint: &Endpoint,
    path: &str,
    started: Instant,
    limit: Duration,
    cancelled: &AtomicBool,
    allowance: usize,
) -> Result<(HttpStatus, Vec<u8>), AcquisitionError> {
    let mut wire = Wire {
        stream: connect(endpoint, started, limit, cancelled)?,
        started,
        limit,
        cancelled,
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: docker\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    wire.write_all(request.as_bytes())?;

    let mut headers = Vec::new();
    while headers.len() < MAX_HEADER_BYTES {
        headers.push(wire.byte()?);
        if headers.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !headers.ends_with(b"\r\n\r\n") {
        return Err(AcquisitionError::Protocol);
    }
    let headers = std::str::from_utf8(&headers).map_err(|_| AcquisitionError::Protocol)?;
    let mut lines = headers.split("\r\n");
    let status_line = lines.next().ok_or(AcquisitionError::Protocol)?;
    let mut status_parts = status_line.split_ascii_whitespace();
    if !matches!(status_parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(AcquisitionError::Protocol);
    }
    let code = status_parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(AcquisitionError::Protocol)?;
    let status = HttpStatus::new(code).map_err(|_| AcquisitionError::Protocol)?;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(AcquisitionError::Protocol)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(AcquisitionError::Protocol);
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| AcquisitionError::Protocol)?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(AcquisitionError::Protocol);
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case("identity")
        {
            return Err(AcquisitionError::Protocol);
        }
    }
    if chunked == content_length.is_some() {
        return Err(AcquisitionError::Protocol);
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let line = wire.line(64)?;
            let hex = line
                .split(|byte| *byte == b';')
                .next()
                .ok_or(AcquisitionError::Protocol)?;
            let hex = std::str::from_utf8(hex).map_err(|_| AcquisitionError::Protocol)?;
            let size = usize::from_str_radix(hex, 16).map_err(|_| AcquisitionError::Protocol)?;
            if size == 0 {
                if !wire.line(MAX_HEADER_BYTES)?.is_empty() {
                    return Err(AcquisitionError::Protocol);
                }
                break;
            }
            if size > allowance.saturating_sub(body.len()) {
                return Err(AcquisitionError::Budget(LimitError::Bytes));
            }
            wire.exact(size, &mut body)?;
            if wire.byte()? != b'\r' || wire.byte()? != b'\n' {
                return Err(AcquisitionError::Protocol);
            }
        }
    } else if let Some(size) = content_length {
        if size > allowance {
            return Err(AcquisitionError::Budget(LimitError::Bytes));
        }
        wire.exact(size, &mut body)?;
    }
    Ok((status, body))
}

fn encode_segment(id: &NativeId) -> Result<String, AcquisitionError> {
    if id.as_str().len() > 1024 {
        return Err(AcquisitionError::Shape);
    }
    let mut encoded = String::new();
    for byte in id.as_str().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").map_err(|_| AcquisitionError::Shape)?;
        }
    }
    Ok(encoded)
}

fn request_path(
    request: &ReadRequest,
    api: Option<ApiVersion>,
) -> Result<String, AcquisitionError> {
    if matches!(request, ReadRequest::DaemonVersion) {
        return Ok("/version".to_owned());
    }
    let api = api.ok_or(AcquisitionError::Version)?;
    let prefix = format!("/v{}.{}", api.major, api.minor);
    let path = match request {
        ReadRequest::DaemonVersion => unreachable!(),
        ReadRequest::DaemonInfo => "/info".to_owned(),
        ReadRequest::ListContainers => "/containers/json?all=1".to_owned(),
        ReadRequest::InspectContainer(id) => format!("/containers/{}/json", encode_segment(id)?),
        ReadRequest::ListNetworks => "/networks".to_owned(),
        ReadRequest::InspectNetwork(id) => format!("/networks/{}", encode_segment(id)?),
        ReadRequest::ListVolumes => "/volumes".to_owned(),
        ReadRequest::InspectVolume(id) => format!("/volumes/{}", encode_segment(id)?),
    };
    Ok(prefix + &path)
}

fn exchange<'a>(
    budget: &'a mut Budget,
    endpoint: &Endpoint,
    request: ReadRequest,
    resource: Option<ResourceRef>,
    api: Option<ApiVersion>,
    cancelled: &AtomicBool,
) -> Result<&'a ProtectedValue, AcquisitionError> {
    let path = request_path(&request, api)?;
    budget.record_request(request, resource, api)?;
    let allowance = budget
        .limits
        .max_response_bytes
        .min(budget.limits.max_total_bytes - budget.bytes_read)
        .min(MAX_JSON_BYTES);
    let (status, body) = http_get(
        endpoint,
        &path,
        budget.started,
        budget.limits.max_elapsed,
        cancelled,
        allowance,
    )?;
    let captured = budget.read_response(status, body.as_slice())?;
    if status.code() != 200 {
        return Err(AcquisitionError::Status);
    }
    Ok(captured)
}

fn parse_api(text: &str) -> Option<ApiVersion> {
    let (major, minor) = text.split_once('.')?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|b| b.is_ascii_digit())
        || !minor.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some(ApiVersion::new(
        NonZeroU16::new(major.parse().ok()?)?,
        minor.parse().ok()?,
    ))
}

fn negotiated_api(body: &[u8]) -> Result<ApiVersion, AcquisitionError> {
    let version: Value = serde_json::from_slice(body).map_err(|_| AcquisitionError::Version)?;
    let maximum = version
        .get("ApiVersion")
        .and_then(Value::as_str)
        .and_then(parse_api)
        .ok_or(AcquisitionError::Version)?;
    let minimum = match version.get("MinAPIVersion") {
        Some(value) => Some(
            value
                .as_str()
                .and_then(parse_api)
                .ok_or(AcquisitionError::Version)?,
        ),
        None => None,
    };
    let known = ApiVersion::new(
        NonZeroU16::new(1).expect("one is nonzero"),
        MAX_KNOWN_API_MINOR,
    );
    if maximum.major.get() != 1 {
        return Err(AcquisitionError::Version);
    }
    let selected = maximum.min(known);
    if selected.minor < 41 || minimum.is_some_and(|minimum| minimum > selected) {
        return Err(AcquisitionError::Version);
    }
    Ok(selected)
}

fn selected_ids(body: &[u8]) -> Result<Vec<NativeId>, AcquisitionError> {
    let list: Value = serde_json::from_slice(body).map_err(|_| AcquisitionError::Shape)?;
    let entries = list.as_array().ok_or(AcquisitionError::Shape)?;
    if entries.len() > MAX_COLLECTION_ITEMS {
        return Err(AcquisitionError::Shape);
    }
    entries
        .iter()
        .map(|entry| {
            entry
                .get("Id")
                .and_then(Value::as_str)
                .and_then(|id| NativeId::new(id.to_owned()))
                .ok_or(AcquisitionError::Shape)
        })
        .collect()
}

fn related_ids(body: &[u8]) -> Result<(Vec<NativeId>, Vec<NativeId>), AcquisitionError> {
    let root: Value = serde_json::from_slice(body).map_err(|_| AcquisitionError::Shape)?;
    let object = root.as_object().ok_or(AcquisitionError::Shape)?;
    let mut networks = Vec::new();
    let mut volumes = Vec::new();
    if let Some(endpoints) = object
        .get("NetworkSettings")
        .and_then(|settings| settings.get("Networks"))
        .filter(|value| !value.is_null())
    {
        let entries = endpoints.as_object().ok_or(AcquisitionError::Shape)?;
        if entries.len() > MAX_COLLECTION_ITEMS {
            return Err(AcquisitionError::Shape);
        }
        for (name, endpoint) in entries {
            let id = endpoint
                .get("NetworkID")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or(name);
            networks.push(NativeId::new(id.to_owned()).ok_or(AcquisitionError::Shape)?);
        }
    }
    if let Some(mounts) = object.get("Mounts").filter(|value| !value.is_null()) {
        let entries = mounts.as_array().ok_or(AcquisitionError::Shape)?;
        if entries.len() > MAX_COLLECTION_ITEMS {
            return Err(AcquisitionError::Shape);
        }
        for mount in entries {
            if mount.get("Type").and_then(Value::as_str) == Some("volume") {
                let name = mount
                    .get("Name")
                    .and_then(Value::as_str)
                    .and_then(|name| NativeId::new(name.to_owned()))
                    .ok_or(AcquisitionError::Shape)?;
                volumes.push(name);
            }
        }
    }
    Ok((networks, volumes))
}

/// Read a bounded inventory from one explicitly supplied Unix socket.
///
/// The caller can cancel between I/O polls. Each completed exchange is protected
/// and tagged with the API version used in its URL. Socket contact is not peer
/// authentication, and the resulting reads are not an atomic daemon snapshot.
pub fn acquire(
    endpoint: &Endpoint,
    selector: Selector,
    limits: Limits,
    cancelled: &AtomicBool,
) -> Result<Capture, AcquisitionError> {
    let mut budget = Budget::new(limits)?;
    let api = negotiated_api(
        exchange(
            &mut budget,
            endpoint,
            ReadRequest::DaemonVersion,
            None,
            None,
            cancelled,
        )?
        .as_bytes(),
    )?;
    exchange(
        &mut budget,
        endpoint,
        ReadRequest::DaemonInfo,
        None,
        Some(api),
        cancelled,
    )?;

    let containers = match selector {
        Selector::ContainerIds(ids) => {
            if ids.len() > budget.limits.max_selected_resources {
                return Err(AcquisitionError::Budget(LimitError::SelectedResources));
            }
            ids
        }
        Selector::AllContainers => selected_ids(
            exchange(
                &mut budget,
                endpoint,
                ReadRequest::ListContainers,
                None,
                Some(api),
                cancelled,
            )?
            .as_bytes(),
        )?,
    };
    let mut seen = HashSet::new();
    let containers: Vec<_> = containers
        .into_iter()
        .filter(|id| seen.insert(id.clone()))
        .collect();
    budget.record_selection(containers.len())?;
    let mut next_reference = 1_u64;
    let mut networks = HashSet::new();
    let mut volumes = HashSet::new();
    for id in containers {
        let reference = ResourceRef::new(next_reference);
        next_reference = next_reference
            .checked_add(1)
            .ok_or(AcquisitionError::Shape)?;
        let body = exchange(
            &mut budget,
            endpoint,
            ReadRequest::InspectContainer(id),
            Some(reference),
            Some(api),
            cancelled,
        )?;
        let (related_networks, related_volumes) = related_ids(body.as_bytes())?;
        let new_networks: HashSet<_> = related_networks
            .into_iter()
            .filter(|id| !networks.contains(id))
            .collect();
        let new_volumes: HashSet<_> = related_volumes
            .into_iter()
            .filter(|id| !volumes.contains(id))
            .collect();
        let additional = new_networks
            .len()
            .checked_add(new_volumes.len())
            .ok_or(AcquisitionError::Budget(LimitError::Expansions))?;
        let projected = budget
            .expansions
            .checked_add(additional)
            .ok_or(AcquisitionError::Budget(LimitError::Expansions))?;
        if projected > budget.limits.max_expansions {
            return Err(AcquisitionError::Budget(LimitError::Expansions));
        }
        networks.extend(new_networks);
        volumes.extend(new_volumes);
    }
    let mut networks: Vec<_> = networks.into_iter().collect();
    networks.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let mut volumes: Vec<_> = volumes.into_iter().collect();
    volumes.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    for id in networks {
        let reference = ResourceRef::new(next_reference);
        next_reference = next_reference
            .checked_add(1)
            .ok_or(AcquisitionError::Shape)?;
        exchange(
            &mut budget,
            endpoint,
            ReadRequest::InspectNetwork(id),
            Some(reference),
            Some(api),
            cancelled,
        )?;
    }
    for id in volumes {
        let reference = ResourceRef::new(next_reference);
        next_reference = next_reference
            .checked_add(1)
            .ok_or(AcquisitionError::Shape)?;
        exchange(
            &mut budget,
            endpoint,
            ReadRequest::InspectVolume(id),
            Some(reference),
            Some(api),
            cancelled,
        )?;
    }
    remaining(budget.started, budget.limits.max_elapsed, cancelled)?;
    Ok(budget.into_capture()?.with_explicit_socket())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            max_requests: 2,
            max_selected_resources: 2,
            max_expansions: 1,
            max_response_bytes: 4,
            max_total_bytes: 6,
            max_elapsed: Duration::from_secs(30),
        }
    }

    fn ok() -> HttpStatus {
        HttpStatus::new(200).unwrap()
    }

    fn api() -> ApiVersion {
        ApiVersion::new(std::num::NonZeroU16::new(1).unwrap(), 41)
    }

    fn version(budget: &mut Budget) {
        budget
            .record_request(ReadRequest::DaemonVersion, None, None)
            .unwrap();
    }

    #[test]
    fn response_is_bounded_while_reading() {
        let mut budget = Budget::new(limits()).unwrap();
        version(&mut budget);
        assert_eq!(
            budget
                .read_response(ok(), "abcd".as_bytes())
                .unwrap()
                .as_bytes(),
            b"abcd"
        );
        budget
            .record_request(ReadRequest::ListContainers, None, Some(api()))
            .unwrap();
        assert_eq!(
            budget.read_response(ok(), "xyz".as_bytes()).err(),
            Some(LimitError::Bytes)
        );
        assert_eq!(budget.counts().bytes_read, 7);
        assert_eq!(
            budget.read_response(ok(), "xy".as_bytes()).err(),
            Some(LimitError::Exhausted)
        );
    }

    #[test]
    fn every_expansion_dimension_is_checked() {
        let mut budget = Budget::new(limits()).unwrap();
        version(&mut budget);
        budget.read_response(ok(), "".as_bytes()).unwrap();
        budget
            .record_request(ReadRequest::ListContainers, None, Some(api()))
            .unwrap();
        budget.read_response(ok(), "".as_bytes()).unwrap();
        assert_eq!(
            budget.record_request(ReadRequest::ListNetworks, None, Some(api())),
            Err(LimitError::Requests)
        );
        let mut selection = Budget::new(limits()).unwrap();
        selection.record_selection(2).unwrap();
        assert_eq!(
            selection.record_selection(1),
            Err(LimitError::SelectedResources)
        );
        let mut expansion = Budget::new(limits()).unwrap();
        expansion.record_expansion(1).unwrap();
        assert_eq!(expansion.record_expansion(1), Err(LimitError::Expansions));
    }

    #[test]
    fn response_requires_one_counted_request_and_failure_poison_budget() {
        let mut budget = Budget::new(limits()).unwrap();
        assert_eq!(
            budget.read_response(ok(), "a".as_bytes()).err(),
            Some(LimitError::ResponseWithoutRequest)
        );
        version(&mut budget);
        assert_eq!(
            budget.record_request(ReadRequest::ListContainers, None, Some(api())),
            Err(LimitError::PendingResponse)
        );
        assert_eq!(
            budget.read_response(ok(), "12345".as_bytes()).err(),
            Some(LimitError::Bytes)
        );
        assert_eq!(budget.counts().bytes_read, 5);
        assert_eq!(
            budget.record_request(ReadRequest::ListContainers, None, Some(api())),
            Err(LimitError::Exhausted)
        );
    }

    #[test]
    fn failed_reader_cannot_reuse_byte_or_request_allowance() {
        struct FailsAfterOneRead(bool);
        impl Read for FailsAfterOneRead {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.0 {
                    Err(std::io::Error::other("sensitive transport detail"))
                } else {
                    self.0 = true;
                    buffer[0] = b'x';
                    Ok(1)
                }
            }
        }
        let mut budget = Budget::new(limits()).unwrap();
        version(&mut budget);
        assert_eq!(
            budget.read_response(ok(), FailsAfterOneRead(false)).err(),
            Some(LimitError::Input)
        );
        assert_eq!(budget.counts().bytes_read, 1);
        assert_eq!(
            budget.read_response(ok(), "ok".as_bytes()).err(),
            Some(LimitError::Exhausted)
        );
    }

    #[test]
    fn sensitive_request_parts_are_redacted() {
        let id = NativeId::new("private-name".into()).unwrap();
        let request = format!("{:?}", ReadRequest::InspectContainer(id));
        assert!(!request.contains("private-name"));
        let endpoint = format!("{:?}", Endpoint::unix_socket("/private/socket".into()));
        assert!(!endpoint.contains("/private/socket"));
    }

    #[test]
    fn captured_exchange_keeps_request_resource_version_and_status_together() {
        let mut budget = Budget::new(limits()).unwrap();
        let api = ApiVersion::new(std::num::NonZeroU16::new(1).unwrap(), 41);
        let resource = ResourceRef::new(7);
        assert_eq!(
            budget.record_request(ReadRequest::ListContainers, Some(resource), Some(api)),
            Err(LimitError::InvalidResourceRef)
        );
        assert_eq!(
            budget.record_request(
                ReadRequest::InspectContainer(NativeId::new("private-id".into()).unwrap()),
                None,
                Some(api)
            ),
            Err(LimitError::InvalidResourceRef)
        );
        budget
            .record_request(
                ReadRequest::InspectContainer(NativeId::new("private-id".into()).unwrap()),
                Some(resource),
                Some(api),
            )
            .unwrap();
        assert_eq!(budget.into_capture().err(), Some(LimitError::Incomplete));

        let mut budget = Budget::new(limits()).unwrap();
        budget
            .record_request(
                ReadRequest::InspectContainer(NativeId::new("private-id".into()).unwrap()),
                Some(resource),
                Some(api),
            )
            .unwrap();
        let status = HttpStatus::new(404).unwrap();
        assert_eq!(
            budget
                .read_response(status, "private-body".as_bytes())
                .err(),
            Some(LimitError::Bytes)
        );
        assert_eq!(budget.into_capture().err(), Some(LimitError::Exhausted));

        let mut budget = Budget::new(limits()).unwrap();
        budget
            .record_request(
                ReadRequest::InspectContainer(NativeId::new("private-id".into()).unwrap()),
                Some(resource),
                Some(api),
            )
            .unwrap();
        budget.read_response(status, "s3cr".as_bytes()).unwrap();
        let capture = budget.into_capture().unwrap();
        assert_eq!(capture.bounds().request_count, 1);
        let exchange = &capture.exchanges()[0];
        assert!(matches!(
            exchange.request(),
            ReadRequest::InspectContainer(_)
        ));
        assert_eq!(exchange.resource(), Some(resource));
        assert_eq!(exchange.api_version(), Some(api));
        assert_eq!(exchange.status(), status);
        assert_eq!(exchange.body().as_bytes(), b"s3cr");
        let debug = format!("{capture:?} {exchange:?}");
        assert!(!debug.contains("private-id"));
        assert!(!debug.contains("s3cr"));
    }

    #[test]
    fn arithmetic_overflow_poisons_each_budget_dimension() {
        let mut broad = limits();
        broad.max_requests = usize::MAX;
        broad.max_selected_resources = usize::MAX;
        broad.max_expansions = usize::MAX;

        let mut requests = Budget::new(broad).unwrap();
        requests.requests = usize::MAX;
        assert_eq!(
            requests.record_request(ReadRequest::DaemonVersion, None, None),
            Err(LimitError::Requests)
        );
        assert_eq!(
            requests.record_request(ReadRequest::DaemonVersion, None, None),
            Err(LimitError::Exhausted)
        );

        let mut selected = Budget::new(broad).unwrap();
        selected.selected_resources = usize::MAX;
        assert_eq!(
            selected.record_selection(1),
            Err(LimitError::SelectedResources)
        );
        assert_eq!(selected.record_selection(0), Err(LimitError::Exhausted));

        let mut expanded = Budget::new(broad).unwrap();
        expanded.expansions = usize::MAX;
        assert_eq!(expanded.record_expansion(1), Err(LimitError::Expansions));
        assert_eq!(expanded.record_expansion(0), Err(LimitError::Exhausted));
    }

    #[test]
    fn versioned_reads_require_the_actual_request_api_version() {
        let mut budget = Budget::new(limits()).unwrap();
        assert_eq!(
            budget.record_request(ReadRequest::DaemonInfo, None, None),
            Err(LimitError::MissingApiVersion)
        );
        assert_eq!(
            budget.record_request(ReadRequest::ListContainers, None, None),
            Err(LimitError::MissingApiVersion)
        );
        assert_eq!(
            budget.record_request(
                ReadRequest::InspectContainer(NativeId::new("private".into()).unwrap()),
                Some(ResourceRef::new(1)),
                None
            ),
            Err(LimitError::MissingApiVersion)
        );
        budget
            .record_request(ReadRequest::DaemonVersion, None, None)
            .unwrap();
        assert_eq!(
            budget.read_response(ok(), b"version".as_slice()).err(),
            Some(LimitError::Bytes)
        );

        let mut budget = Budget::new(limits()).unwrap();
        budget
            .record_request(ReadRequest::DaemonInfo, None, Some(api()))
            .unwrap();
        budget.read_response(ok(), b"info".as_slice()).unwrap();
        let capture = budget.into_capture().unwrap();
        assert_eq!(capture.exchanges()[0].api_version(), Some(api()));
    }

    #[test]
    fn inspections_count_as_expansions_even_without_manual_accounting() {
        let mut budget = Budget::new(limits()).unwrap();
        budget
            .record_request(
                ReadRequest::InspectContainer(NativeId::new("first".into()).unwrap()),
                Some(ResourceRef::new(1)),
                Some(api()),
            )
            .unwrap();
        budget.read_response(ok(), b"one".as_slice()).unwrap();
        assert_eq!(budget.counts().expansions, 1);
        assert_eq!(
            budget.record_request(
                ReadRequest::InspectVolume(NativeId::new("second".into()).unwrap()),
                Some(ResourceRef::new(2)),
                Some(api())
            ),
            Err(LimitError::Expansions)
        );
        assert_eq!(budget.into_capture().err(), Some(LimitError::Exhausted));
    }

    #[test]
    fn a_resource_ref_cannot_change_kind_or_native_id() {
        let mut broad = limits();
        broad.max_requests = 4;
        broad.max_expansions = 4;
        let mut budget = Budget::new(broad).unwrap();
        let reference = ResourceRef::new(9);
        budget
            .record_request(
                ReadRequest::InspectContainer(NativeId::new("private-a".into()).unwrap()),
                Some(reference),
                Some(api()),
            )
            .unwrap();
        budget.read_response(ok(), b"one".as_slice()).unwrap();
        assert_eq!(
            budget.record_request(
                ReadRequest::InspectContainer(NativeId::new("private-b".into()).unwrap()),
                Some(reference),
                Some(api())
            ),
            Err(LimitError::ResourceConflict)
        );
        assert_eq!(
            budget.record_request(
                ReadRequest::InspectVolume(NativeId::new("private-a".into()).unwrap()),
                Some(reference),
                Some(api())
            ),
            Err(LimitError::ResourceConflict)
        );
        assert_eq!(budget.counts().expansions, 1);
        budget
            .record_request(
                ReadRequest::InspectContainer(NativeId::new("private-a".into()).unwrap()),
                Some(reference),
                Some(api()),
            )
            .unwrap();
        budget.read_response(ok(), b"two".as_slice()).unwrap();
        let capture = budget.into_capture().unwrap();
        assert_eq!(capture.exchanges().len(), 2);
        assert!(!format!("{capture:?}").contains("private-a"));
    }

    #[test]
    fn one_native_object_cannot_acquire_two_local_references() {
        let mut broad = limits();
        broad.max_expansions = 2;
        let mut budget = Budget::new(broad).unwrap();
        let db = || NativeId::new("db".into()).unwrap();
        budget
            .record_request(
                ReadRequest::InspectContainer(db()),
                Some(ResourceRef::new(1)),
                Some(api()),
            )
            .unwrap();
        budget.read_response(ok(), b"one".as_slice()).unwrap();
        assert_eq!(
            budget.record_request(
                ReadRequest::InspectContainer(db()),
                Some(ResourceRef::new(2)),
                Some(api())
            ),
            Err(LimitError::ResourceConflict)
        );
        assert_eq!(budget.counts().expansions, 1);
        budget
            .record_request(
                ReadRequest::InspectContainer(db()),
                Some(ResourceRef::new(1)),
                Some(api()),
            )
            .unwrap();
        budget.read_response(ok(), b"two".as_slice()).unwrap();
        let capture = budget.into_capture().unwrap();
        assert_eq!(capture.exchanges().len(), 2);
        assert_eq!(
            capture.exchanges()[0].resource(),
            capture.exchanges()[1].resource()
        );
        assert!(!format!("{capture:?}").contains("db"));
    }
}
