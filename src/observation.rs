//! Native location and availability do not prove authored intent.

use crate::evidence::ProtectedValue;

/// A local opaque reference, never a name or daemon identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResourceRef(u64);

impl ResourceRef {
    #[must_use]
    pub const fn new(local_index: u64) -> Self {
        Self(local_index)
    }
}

/// Closed field categories prevent native paths or values appearing in findings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldPath {
    Image,
    Command,
    Entrypoint,
    Environment { index: usize },
    Label { index: usize },
    Mount { index: usize },
    Port { index: usize },
    Network { index: usize },
    NetworkMode,
    Volume { index: usize },
    Healthcheck,
    RestartPolicy,
    EngineRelease,
    ApiVersion,
    DaemonMode,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Availability {
    Missing,
    Null,
    Empty,
    Present,
    Redacted,
}

/// Origin is orthogonal to availability. Docker `Config.*` may include image defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    Configured,
    Effective,
    RuntimeAssigned,
    Unknown,
}

/// Values remain private; `Debug` never prints them.
pub struct ObservedField {
    pub resource: ResourceRef,
    pub field: FieldPath,
    pub availability: Availability,
    pub origin: Origin,
    value: Option<ProtectedValue>,
}

impl ObservedField {
    #[must_use]
    pub const fn missing(resource: ResourceRef, field: FieldPath, origin: Origin) -> Self {
        Self::without_value(resource, field, Availability::Missing, origin)
    }

    #[must_use]
    pub const fn null(resource: ResourceRef, field: FieldPath, origin: Origin) -> Self {
        Self::without_value(resource, field, Availability::Null, origin)
    }

    #[must_use]
    pub const fn redacted(resource: ResourceRef, field: FieldPath, origin: Origin) -> Self {
        Self::without_value(resource, field, Availability::Redacted, origin)
    }

    const fn without_value(
        resource: ResourceRef,
        field: FieldPath,
        availability: Availability,
        origin: Origin,
    ) -> Self {
        Self {
            resource,
            field,
            availability,
            origin,
            value: None,
        }
    }

    pub fn present(
        resource: ResourceRef,
        field: FieldPath,
        origin: Origin,
        value: ProtectedValue,
    ) -> Self {
        Self {
            resource,
            field,
            availability: if value.is_empty() {
                Availability::Empty
            } else {
                Availability::Present
            },
            origin,
            value: Some(value),
        }
    }

    #[must_use]
    pub fn value(&self) -> Option<&ProtectedValue> {
        self.value.as_ref()
    }
}

impl std::fmt::Debug for ObservedField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservedField")
            .field("resource", &self.resource)
            .field("field", &self.field)
            .field("availability", &self.availability)
            .field("origin", &self.origin)
            .field("value", &self.value.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// One decoded native field. Values can contain paths, credentials or command
/// arguments; only callers explicitly accessing `value` can inspect them.
pub struct Observed<T> {
    pub availability: Availability,
    pub origin: Origin,
    value: Option<T>,
}

impl<T> Observed<T> {
    #[must_use]
    pub const fn unavailable(availability: Availability, origin: Origin) -> Self {
        Self {
            availability,
            origin,
            value: None,
        }
    }

    #[must_use]
    pub fn present(value: T, availability: Availability, origin: Origin) -> Self {
        Self {
            availability,
            origin,
            value: Some(value),
        }
    }

    #[must_use]
    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }
}

impl<T> std::fmt::Debug for Observed<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observed")
            .field("availability", &self.availability)
            .field("origin", &self.origin)
            .field("value", &self.value.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_and_origin_are_independent_and_redacted() {
        let reference = ResourceRef::new(3);
        let field = FieldPath::Environment { index: 0 };
        let missing = ObservedField::missing(reference, field, Origin::Configured);
        let null = ObservedField::null(reference, field, Origin::Configured);
        let empty = ObservedField::present(
            reference,
            field,
            Origin::Effective,
            ProtectedValue::new(Vec::new()),
        );
        let secret = ObservedField::present(
            reference,
            field,
            Origin::RuntimeAssigned,
            ProtectedValue::new(b"secret-value".to_vec()),
        );
        let redacted = ObservedField::redacted(reference, field, Origin::Unknown);
        assert_eq!(missing.availability, Availability::Missing);
        assert_eq!(null.availability, Availability::Null);
        assert_eq!(empty.availability, Availability::Empty);
        assert_eq!(secret.availability, Availability::Present);
        assert_eq!(redacted.availability, Availability::Redacted);
        assert!(!format!("{secret:?}").contains("secret-value"));
    }
}
