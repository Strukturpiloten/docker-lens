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

/// Caller-supplied, value-free accounting. It is not verified transport evidence
/// and does not prove that a daemon was contacted or sampled atomically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureBounds {
    pub request_count: usize,
    pub bytes_read: usize,
}

pub struct Capture {
    bounds: CaptureBounds,
    response_bytes: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    AccountingMismatch,
}

impl Capture {
    pub fn new(bounds: CaptureBounds, response_bytes: Vec<Vec<u8>>) -> Result<Self, CaptureError> {
        let total = response_bytes
            .iter()
            .try_fold(0usize, |sum, response| sum.checked_add(response.len()));
        if bounds.request_count != response_bytes.len() || total != Some(bounds.bytes_read) {
            return Err(CaptureError::AccountingMismatch);
        }
        Ok(Self {
            bounds,
            response_bytes,
        })
    }

    #[must_use]
    pub const fn bounds(&self) -> CaptureBounds {
        self.bounds
    }

    #[must_use]
    pub fn responses(&self) -> &[Vec<u8>] {
        &self.response_bytes
    }
}

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capture")
            .field("bounds", &self.bounds)
            .field("responses", &self.response_bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_rejects_inconsistent_accounting_and_redacts_bytes() {
        let bounds = CaptureBounds {
            request_count: 1,
            bytes_read: 6,
        };
        assert!(matches!(
            Capture::new(bounds, vec![b"secret".to_vec(), vec![]]),
            Err(CaptureError::AccountingMismatch)
        ));
        let capture = Capture::new(bounds, vec![b"secret".to_vec()]).unwrap();
        assert_eq!(capture.bounds(), bounds);
        assert!(!format!("{capture:?}").contains("secret"));
    }
}
