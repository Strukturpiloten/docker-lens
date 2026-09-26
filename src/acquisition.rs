//! Closed, explicit, read-only acquisition vocabulary and limits.
//!
//! There is no transport implementation in this bootstrap. A future transport
//! must enforce these limits while reading and must never infer a local daemon.

use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, Instant};

use crate::evidence::{Capture, CaptureBounds, CapturedExchange, HttpStatus, ProtectedValue};
use crate::observation::ResourceRef;
use crate::version::{ApiVersion, ObservationId, ObservationIdError};

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

/// The only requests a future transport may issue. No arbitrary URL or method.
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
    /// A future transport must also configure an I/O deadline: a blocking
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
