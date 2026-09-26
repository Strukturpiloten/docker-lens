//! Protected native bytes never enter finding or error messages.

/// Raw input has no printable `Debug`, `Display`, or serialization interface.
pub struct ProtectedValue(Vec<u8>);

impl ProtectedValue {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

use crate::acquisition::ReadRequest;
use crate::observation::ResourceRef;
use crate::version::{ApiVersion, ObservationId};

/// Value-free accounting. It does not prove daemon contact or an atomic sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureBounds {
    pub request_count: usize,
    pub selected_resources: usize,
    pub expansions: usize,
    pub bytes_read: usize,
}

/// An HTTP status supplied by the transport, with no response text in errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpStatus(u16);

impl HttpStatus {
    pub fn new(code: u16) -> Result<Self, CaptureError> {
        (100..=599)
            .contains(&code)
            .then_some(Self(code))
            .ok_or(CaptureError::InvalidStatus)
    }

    #[must_use]
    pub const fn code(self) -> u16 {
        self.0
    }
}

/// One closed request and its exact response metadata and protected body.
/// The transport must supply the API version from the URL it actually sent.
pub struct CapturedExchange {
    request: ReadRequest,
    resource: Option<ResourceRef>,
    api_version: Option<ApiVersion>,
    status: HttpStatus,
    body: ProtectedValue,
}

impl CapturedExchange {
    pub(crate) fn new(
        request: ReadRequest,
        resource: Option<ResourceRef>,
        api_version: Option<ApiVersion>,
        status: HttpStatus,
        body: ProtectedValue,
    ) -> Self {
        Self {
            request,
            resource,
            api_version,
            status,
            body,
        }
    }

    #[must_use]
    pub fn request(&self) -> &ReadRequest {
        &self.request
    }
    #[must_use]
    pub const fn resource(&self) -> Option<ResourceRef> {
        self.resource
    }
    #[must_use]
    pub const fn api_version(&self) -> Option<ApiVersion> {
        self.api_version
    }
    #[must_use]
    pub const fn status(&self) -> HttpStatus {
        self.status
    }
    #[must_use]
    pub fn body(&self) -> &ProtectedValue {
        &self.body
    }
}

impl std::fmt::Debug for CapturedExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedExchange")
            .field("request", &self.request)
            .field("resource", &self.resource)
            .field("api_version", &self.api_version)
            .field("status", &self.status)
            .field("body", &"[redacted]")
            .finish()
    }
}

pub struct Capture {
    observation_id: ObservationId,
    bounds: CaptureBounds,
    exchanges: Vec<CapturedExchange>,
    route: CaptureRoute,
}

/// How this in-memory capture was assembled. A socket route does not
/// authenticate the peer as Docker Engine or make the reads an atomic sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureRoute {
    CallerAssembled,
    ExplicitUnixSocket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    AccountingMismatch,
    InvalidStatus,
}

impl Capture {
    pub(crate) fn from_completed(
        observation_id: ObservationId,
        bounds: CaptureBounds,
        exchanges: Vec<CapturedExchange>,
    ) -> Result<Self, CaptureError> {
        let total = exchanges.iter().try_fold(0usize, |sum, exchange| {
            sum.checked_add(exchange.body.as_bytes().len())
        });
        if bounds.request_count != exchanges.len() || total != Some(bounds.bytes_read) {
            return Err(CaptureError::AccountingMismatch);
        }
        Ok(Self {
            observation_id,
            bounds,
            exchanges,
            route: CaptureRoute::CallerAssembled,
        })
    }

    pub(crate) fn with_explicit_socket(mut self) -> Self {
        self.route = CaptureRoute::ExplicitUnixSocket;
        self
    }

    #[must_use]
    pub const fn route(&self) -> CaptureRoute {
        self.route
    }

    #[must_use]
    pub const fn observation_id(&self) -> ObservationId {
        self.observation_id
    }

    #[must_use]
    pub const fn bounds(&self) -> CaptureBounds {
        self.bounds
    }

    #[must_use]
    pub fn exchanges(&self) -> &[CapturedExchange] {
        &self.exchanges
    }
}

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capture")
            .field("bounds", &self.bounds)
            .field("observation_id", &self.observation_id)
            .field("exchanges", &self.exchanges.len())
            .field("route", &self.route)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_rejects_inconsistent_accounting_and_redacts_bytes() {
        let observation_id = ObservationId::fresh().unwrap();
        let bounds = CaptureBounds {
            request_count: 1,
            selected_resources: 0,
            expansions: 0,
            bytes_read: 6,
        };
        let exchange = || {
            CapturedExchange::new(
                ReadRequest::DaemonVersion,
                None,
                None,
                HttpStatus::new(200).unwrap(),
                ProtectedValue::new(b"secret".to_vec()),
            )
        };
        assert!(matches!(
            Capture::from_completed(observation_id, bounds, vec![exchange(), exchange()]),
            Err(CaptureError::AccountingMismatch)
        ));
        let capture = Capture::from_completed(observation_id, bounds, vec![exchange()]).unwrap();
        assert_eq!(capture.bounds(), bounds);
        assert_eq!(capture.route(), CaptureRoute::CallerAssembled);
        assert!(!format!("{capture:?}").contains("secret"));
        assert!(!format!("{:?}", capture.exchanges()[0]).contains("secret"));
        assert_eq!(HttpStatus::new(600), Err(CaptureError::InvalidStatus));
    }
}
