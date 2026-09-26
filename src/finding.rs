//! Findings deliberately contain no captured native value or freeform context.

use crate::observation::{FieldPath, ResourceRef};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingCode {
    MissingField,
    NullField,
    RedactedField,
    UnsupportedValue,
    LimitExceeded,
    NativeConflict,
    CapabilityUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    pub code: FindingCode,
    pub resource: Option<ResourceRef>,
    pub field: Option<FieldPath>,
}
