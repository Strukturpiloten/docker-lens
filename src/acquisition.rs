//! Closed, explicit, read-only acquisition vocabulary and limits.
//!
//! There is no transport implementation in this bootstrap. A future transport
//! must enforce these limits while reading and must never infer a local daemon.

use std::io::Read;
use std::time::{Duration, Instant};

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
}

/// One acquisition's counters; captures are not atomic daemon snapshots.
pub struct Budget {
    limits: Limits,
    started: Instant,
    requests: usize,
    selected_resources: usize,
    expansions: usize,
    bytes_read: usize,
    pending_response: bool,
    failed: bool,
}

impl Budget {
    pub fn new(limits: Limits) -> Result<Self, LimitError> {
        Ok(Self {
            limits: limits.validate()?,
            started: Instant::now(),
            requests: 0,
            selected_resources: 0,
            expansions: 0,
            bytes_read: 0,
            pending_response: false,
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

    pub fn record_request(&mut self, _request: &ReadRequest) -> Result<(), LimitError> {
        self.check_time()?;
        if self.pending_response {
            return Err(LimitError::PendingResponse);
        }
        self.requests = self.requests.checked_add(1).ok_or(LimitError::Requests)?;
        if self.requests > self.limits.max_requests {
            self.failed = true;
            return Err(LimitError::Requests);
        }
        self.pending_response = true;
        Ok(())
    }

    pub fn record_selection(&mut self, count: usize) -> Result<(), LimitError> {
        self.check_time()?;
        self.selected_resources = self
            .selected_resources
            .checked_add(count)
            .ok_or(LimitError::SelectedResources)?;
        if self.selected_resources > self.limits.max_selected_resources {
            self.failed = true;
            return Err(LimitError::SelectedResources);
        }
        Ok(())
    }

    pub fn record_expansion(&mut self, count: usize) -> Result<(), LimitError> {
        self.check_time()?;
        self.expansions = self
            .expansions
            .checked_add(count)
            .ok_or(LimitError::Expansions)?;
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
    pub fn read_response<R: Read>(&mut self, reader: R) -> Result<Vec<u8>, LimitError> {
        self.check_time()?;
        if !self.pending_response {
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
        self.pending_response = false;
        Ok(bytes)
    }

    #[must_use]
    pub fn counts(&self) -> crate::evidence::CaptureBounds {
        crate::evidence::CaptureBounds {
            request_count: self.requests,
            bytes_read: self.bytes_read,
        }
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

    #[test]
    fn response_is_bounded_while_reading() {
        let mut budget = Budget::new(limits()).unwrap();
        budget.record_request(&ReadRequest::DaemonVersion).unwrap();
        assert_eq!(budget.read_response("abcd".as_bytes()).unwrap(), b"abcd");
        budget.record_request(&ReadRequest::ListContainers).unwrap();
        assert_eq!(
            budget.read_response("xyz".as_bytes()).unwrap_err(),
            LimitError::Bytes
        );
        assert_eq!(budget.counts().bytes_read, 7);
        assert_eq!(
            budget.read_response("xy".as_bytes()),
            Err(LimitError::Exhausted)
        );
    }

    #[test]
    fn every_expansion_dimension_is_checked() {
        let mut budget = Budget::new(limits()).unwrap();
        budget.record_request(&ReadRequest::DaemonVersion).unwrap();
        budget.read_response("".as_bytes()).unwrap();
        budget.record_request(&ReadRequest::ListContainers).unwrap();
        budget.read_response("".as_bytes()).unwrap();
        assert_eq!(
            budget.record_request(&ReadRequest::ListNetworks),
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
            budget.read_response("a".as_bytes()),
            Err(LimitError::ResponseWithoutRequest)
        );
        budget.record_request(&ReadRequest::DaemonVersion).unwrap();
        assert_eq!(
            budget.record_request(&ReadRequest::ListContainers),
            Err(LimitError::PendingResponse)
        );
        assert_eq!(
            budget.read_response("12345".as_bytes()),
            Err(LimitError::Bytes)
        );
        assert_eq!(budget.counts().bytes_read, 5);
        assert_eq!(
            budget.record_request(&ReadRequest::ListContainers),
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
        budget.record_request(&ReadRequest::DaemonVersion).unwrap();
        assert_eq!(
            budget.read_response(FailsAfterOneRead(false)),
            Err(LimitError::Input)
        );
        assert_eq!(budget.counts().bytes_read, 1);
        assert_eq!(
            budget.read_response("ok".as_bytes()),
            Err(LimitError::Exhausted)
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
}
