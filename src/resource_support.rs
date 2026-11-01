//! Pure assessment of observation-scoped daemon resource-support reports.
//!
//! `/info` reports do not prove enforcement, authenticate a daemon, or admit
//! target capabilities. They are evidence about one source capture only.

use crate::evidence::ProtectedValue;
use crate::observation::{Availability, Observed, Origin};
use crate::version::ObservationId;

/// Independent resource and cgroup reports from `/info` in one completed capture.
///
/// Fields remain independently available. The decoder assigns effective origin
/// to every native report; no Engine release, schema or mode supplies a default.
/// Publicly assembled fields and scope are caller assertions, not authenticated
/// daemon evidence. [`Self::assess`] checks their state before using a value.
#[derive(Debug)]
pub struct ResourceSupportObservation {
    pub observation_id: ObservationId,
    /// Native `MemoryLimit`, not a successful memory-enforcement probe.
    pub memory_limit: Observed<bool>,
    /// Native `SwapLimit`, independent of memory and not an enforcement probe.
    pub swap_limit: Observed<bool>,
    /// Native `PidsLimit`, not a successful PID-controller enforcement probe.
    pub pids_limit: Observed<bool>,
    /// Native `CgroupDriver` bytes, not evidence of controller delegation.
    pub cgroup_driver: Observed<ProtectedValue>,
    /// Native `CgroupVersion` bytes; omitted fields do not imply version 1.
    pub cgroup_version: Observed<ProtectedValue>,
}

/// A daemon report's limited meaning within its matching observation scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportedResourceSupport {
    /// An effective, present `false` report in this source environment only.
    /// It does not establish a general Engine/version limitation.
    ReportedUnavailable,
    /// An effective, present `true` report; enforcement remains unverified.
    /// Even independent failed effect evidence cannot turn this into support.
    ReportedAvailableUnverified,
    /// Missing, null, empty, redacted, valueless, or non-effective evidence.
    Unknown,
}

/// Closed lexical classification of the effective, present `CgroupDriver` report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportedCgroupDriver {
    /// Exact native bytes `none`, not a generic unsupported-runtime verdict.
    None,
    /// Exact native bytes `cgroupfs`, not controller ownership evidence.
    Cgroupfs,
    /// Exact native bytes `systemd`, not proof of delegation or enforcement.
    Systemd,
    /// Present nonempty bytes outside the known exact spellings.
    Unrecognized,
    /// Unavailable, valueless, empty, or non-effective evidence.
    Unknown,
}

/// Closed lexical classification of the effective, present `CgroupVersion` report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportedCgroupVersion {
    /// Exact native bytes `1`, not a version-derived default.
    V1,
    /// Exact native bytes `2`, not a positive controller-effect proof.
    V2,
    /// Present nonempty bytes outside the known exact spellings.
    Unrecognized,
    /// Unavailable, valueless, empty, or non-effective evidence.
    Unknown,
}

/// Independent report assessments; no field is a planning capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceSupportAssessment {
    pub memory_limit: ReportedResourceSupport,
    pub swap_limit: ReportedResourceSupport,
    pub pids_limit: ReportedResourceSupport,
    pub cgroup_driver: ReportedCgroupDriver,
    pub cgroup_version: ReportedCgroupVersion,
}

/// Closed, value-free assessment failure. A mismatch assesses no report field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceSupportError {
    ObservationScopeMismatch,
}

impl ResourceSupportObservation {
    /// Initialize every independent field as missing with effective origin.
    /// No schema default or other reported field materializes a value.
    #[must_use]
    pub const fn missing(observation_id: ObservationId) -> Self {
        Self {
            observation_id,
            memory_limit: Observed::unavailable(Availability::Missing, Origin::Effective),
            swap_limit: Observed::unavailable(Availability::Missing, Origin::Effective),
            pids_limit: Observed::unavailable(Availability::Missing, Origin::Effective),
            cgroup_driver: Observed::unavailable(Availability::Missing, Origin::Effective),
            cgroup_version: Observed::unavailable(Availability::Missing, Origin::Effective),
        }
    }

    /// Assess reports only for the caller's explicitly supplied observation.
    ///
    /// Matching versions or daemon modes cannot substitute for identity. Only
    /// `Present` fields with `Effective` origin and an actual value are reports;
    /// empty text and redacted-but-valued caller data remain unknown. This method
    /// neither evaluates effect evidence nor grants destination guarantees.
    pub fn assess(
        &self,
        observation_id: ObservationId,
    ) -> Result<ResourceSupportAssessment, ResourceSupportError> {
        if self.observation_id != observation_id {
            return Err(ResourceSupportError::ObservationScopeMismatch);
        }
        Ok(ResourceSupportAssessment {
            memory_limit: assess_report(&self.memory_limit),
            swap_limit: assess_report(&self.swap_limit),
            pids_limit: assess_report(&self.pids_limit),
            cgroup_driver: assess_driver(&self.cgroup_driver),
            cgroup_version: assess_version(&self.cgroup_version),
        })
    }
}

fn assess_report(report: &Observed<bool>) -> ReportedResourceSupport {
    if report.availability != Availability::Present || report.origin != Origin::Effective {
        return ReportedResourceSupport::Unknown;
    }
    match report.value() {
        Some(false) => ReportedResourceSupport::ReportedUnavailable,
        Some(true) => ReportedResourceSupport::ReportedAvailableUnverified,
        None => ReportedResourceSupport::Unknown,
    }
}

fn reported_bytes(report: &Observed<ProtectedValue>) -> Option<&[u8]> {
    if report.availability != Availability::Present || report.origin != Origin::Effective {
        return None;
    }
    let value = report.value()?.as_bytes();
    (!value.is_empty()).then_some(value)
}

fn assess_driver(report: &Observed<ProtectedValue>) -> ReportedCgroupDriver {
    match reported_bytes(report) {
        Some(b"none") => ReportedCgroupDriver::None,
        Some(b"cgroupfs") => ReportedCgroupDriver::Cgroupfs,
        Some(b"systemd") => ReportedCgroupDriver::Systemd,
        Some(_) => ReportedCgroupDriver::Unrecognized,
        None => ReportedCgroupDriver::Unknown,
    }
}

fn assess_version(report: &Observed<ProtectedValue>) -> ReportedCgroupVersion {
    match reported_bytes(report) {
        Some(b"1") => ReportedCgroupVersion::V1,
        Some(b"2") => ReportedCgroupVersion::V2,
        Some(_) => ReportedCgroupVersion::Unrecognized,
        None => ReportedCgroupVersion::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_supplied_inconsistent_availability_and_origin_are_unknown() {
        let observation_id = ObservationId::fresh().unwrap();
        for value in [false, true] {
            for availability in [
                Availability::Missing,
                Availability::Null,
                Availability::Empty,
                Availability::Present,
                Availability::Redacted,
            ] {
                for origin in [
                    Origin::Configured,
                    Origin::Effective,
                    Origin::RuntimeAssigned,
                    Origin::Unknown,
                ] {
                    let mut reports = ResourceSupportObservation {
                        memory_limit: Observed::present(value, availability, origin),
                        swap_limit: Observed::unavailable(availability, origin),
                        pids_limit: Observed::present(value, availability, origin),
                        ..ResourceSupportObservation::missing(observation_id)
                    };
                    let assessment = reports.assess(observation_id).unwrap();
                    let expected =
                        if availability == Availability::Present && origin == Origin::Effective {
                            if value {
                                ReportedResourceSupport::ReportedAvailableUnverified
                            } else {
                                ReportedResourceSupport::ReportedUnavailable
                            }
                        } else {
                            ReportedResourceSupport::Unknown
                        };
                    assert_eq!(assessment.memory_limit, expected);
                    assert_eq!(assessment.pids_limit, expected);
                    assert_eq!(assessment.swap_limit, ReportedResourceSupport::Unknown);
                    reports.pids_limit = Observed::unavailable(availability, origin);
                    assert_eq!(
                        reports.assess(observation_id).unwrap().pids_limit,
                        ReportedResourceSupport::Unknown
                    );
                }
            }
        }
    }

    fn text(value: &[u8], availability: Availability, origin: Origin) -> Observed<ProtectedValue> {
        Observed::present(ProtectedValue::new(value.to_vec()), availability, origin)
    }

    #[test]
    fn missing_constructor_preserves_scope_and_all_five_missing_effective_fields() {
        let observation_id = ObservationId::fresh().unwrap();
        let reports = ResourceSupportObservation::missing(observation_id);
        assert_eq!(reports.observation_id, observation_id);
        for field in [
            &reports.memory_limit,
            &reports.swap_limit,
            &reports.pids_limit,
        ] {
            assert_eq!(field.availability, Availability::Missing);
            assert_eq!(field.origin, Origin::Effective);
            assert!(field.value().is_none());
        }
        for field in [&reports.cgroup_driver, &reports.cgroup_version] {
            assert_eq!(field.availability, Availability::Missing);
            assert_eq!(field.origin, Origin::Effective);
            assert!(field.value().is_none());
        }
        assert_eq!(
            reports.assess(observation_id).unwrap(),
            ResourceSupportAssessment {
                memory_limit: ReportedResourceSupport::Unknown,
                swap_limit: ReportedResourceSupport::Unknown,
                pids_limit: ReportedResourceSupport::Unknown,
                cgroup_driver: ReportedCgroupDriver::Unknown,
                cgroup_version: ReportedCgroupVersion::Unknown,
            }
        );
    }

    #[test]
    fn cgroup_lexical_classification_is_exact_and_independent() {
        let observation_id = ObservationId::fresh().unwrap();
        let drivers: &[(&[u8], ReportedCgroupDriver)] = &[
            (b"none", ReportedCgroupDriver::None),
            (b"cgroupfs", ReportedCgroupDriver::Cgroupfs),
            (b"systemd", ReportedCgroupDriver::Systemd),
            (b"None", ReportedCgroupDriver::Unrecognized),
            (b"Systemd", ReportedCgroupDriver::Unrecognized),
            (b" systemd", ReportedCgroupDriver::Unrecognized),
            (b"systemd ", ReportedCgroupDriver::Unrecognized),
            (b"systemd\n", ReportedCgroupDriver::Unrecognized),
            (b"private-driver-canary", ReportedCgroupDriver::Unrecognized),
            (b"\xff", ReportedCgroupDriver::Unrecognized),
            (b"", ReportedCgroupDriver::Unknown),
        ];
        let versions: &[(&[u8], ReportedCgroupVersion)] = &[
            (b"1", ReportedCgroupVersion::V1),
            (b"2", ReportedCgroupVersion::V2),
            (b"01", ReportedCgroupVersion::Unrecognized),
            (b"v2", ReportedCgroupVersion::Unrecognized),
            (b"2.0", ReportedCgroupVersion::Unrecognized),
            (b" 2", ReportedCgroupVersion::Unrecognized),
            (b"2\n", ReportedCgroupVersion::Unrecognized),
            (
                b"private-version-canary",
                ReportedCgroupVersion::Unrecognized,
            ),
            (b"\xff", ReportedCgroupVersion::Unrecognized),
            (b"", ReportedCgroupVersion::Unknown),
        ];
        for &(driver, expected_driver) in drivers {
            for &(version, expected_version) in versions {
                let reports = ResourceSupportObservation {
                    cgroup_driver: text(driver, Availability::Present, Origin::Effective),
                    cgroup_version: text(version, Availability::Present, Origin::Effective),
                    ..ResourceSupportObservation::missing(observation_id)
                };
                let assessment = reports.assess(observation_id).unwrap();
                assert_eq!(assessment.cgroup_driver, expected_driver);
                assert_eq!(assessment.cgroup_version, expected_version);
                assert_eq!(assessment.pids_limit, ReportedResourceSupport::Unknown);
                assert_eq!(assessment.memory_limit, ReportedResourceSupport::Unknown);
                assert_eq!(assessment.swap_limit, ReportedResourceSupport::Unknown);
            }
        }
    }

    #[test]
    fn cgroup_availability_origin_empty_and_valueless_inconsistencies_are_unknown() {
        let observation_id = ObservationId::fresh().unwrap();
        for availability in [
            Availability::Missing,
            Availability::Null,
            Availability::Empty,
            Availability::Present,
            Availability::Redacted,
        ] {
            for origin in [
                Origin::Configured,
                Origin::Effective,
                Origin::RuntimeAssigned,
                Origin::Unknown,
            ] {
                for (driver, version, expected_driver, expected_version) in [
                    (
                        b"systemd".as_slice(),
                        b"2".as_slice(),
                        ReportedCgroupDriver::Systemd,
                        ReportedCgroupVersion::V2,
                    ),
                    (
                        b"other".as_slice(),
                        b"02".as_slice(),
                        ReportedCgroupDriver::Unrecognized,
                        ReportedCgroupVersion::Unrecognized,
                    ),
                    (
                        b"".as_slice(),
                        b"".as_slice(),
                        ReportedCgroupDriver::Unknown,
                        ReportedCgroupVersion::Unknown,
                    ),
                ] {
                    let mut reports = ResourceSupportObservation {
                        cgroup_driver: text(driver, availability, origin),
                        cgroup_version: text(version, availability, origin),
                        ..ResourceSupportObservation::missing(observation_id)
                    };
                    let assessment = reports.assess(observation_id).unwrap();
                    let present =
                        availability == Availability::Present && origin == Origin::Effective;
                    assert_eq!(
                        assessment.cgroup_driver,
                        if present {
                            expected_driver
                        } else {
                            ReportedCgroupDriver::Unknown
                        }
                    );
                    assert_eq!(
                        assessment.cgroup_version,
                        if present {
                            expected_version
                        } else {
                            ReportedCgroupVersion::Unknown
                        }
                    );
                    reports.cgroup_driver = Observed::unavailable(availability, origin);
                    reports.cgroup_version = Observed::unavailable(availability, origin);
                    let assessment = reports.assess(observation_id).unwrap();
                    assert_eq!(assessment.cgroup_driver, ReportedCgroupDriver::Unknown);
                    assert_eq!(assessment.cgroup_version, ReportedCgroupVersion::Unknown);
                }
            }
        }
    }

    #[test]
    fn scope_mismatch_returns_no_assessment_and_no_native_values() {
        let observation_id = ObservationId::fresh().unwrap();
        let reports = ResourceSupportObservation {
            pids_limit: Observed::present(true, Availability::Present, Origin::Effective),
            cgroup_driver: text(
                b"private-driver-canary",
                Availability::Present,
                Origin::Effective,
            ),
            cgroup_version: text(
                b"private-version-canary",
                Availability::Present,
                Origin::Effective,
            ),
            ..ResourceSupportObservation::missing(observation_id)
        };
        let error = reports.assess(ObservationId::fresh().unwrap()).unwrap_err();
        assert_eq!(error, ResourceSupportError::ObservationScopeMismatch);
        assert_eq!(format!("{error:?}"), "ObservationScopeMismatch");
    }

    #[test]
    fn public_reports_do_not_expose_boolean_values_in_debug() {
        let observation_id = ObservationId::fresh().unwrap();
        let reports = ResourceSupportObservation {
            memory_limit: Observed::present(true, Availability::Present, Origin::Effective),
            swap_limit: Observed::present(false, Availability::Present, Origin::Effective),
            pids_limit: Observed::present(true, Availability::Present, Origin::Effective),
            cgroup_driver: Observed::present(
                ProtectedValue::new(b"private-driver-canary".to_vec()),
                Availability::Present,
                Origin::Effective,
            ),
            cgroup_version: Observed::present(
                ProtectedValue::new(b"private-version-canary".to_vec()),
                Availability::Present,
                Origin::Effective,
            ),
            ..ResourceSupportObservation::missing(observation_id)
        };
        let debug = format!("{reports:?}");
        assert!(!debug.contains("true"));
        assert!(!debug.contains("false"));
        assert!(!debug.contains("private-driver-canary"));
        assert!(!debug.contains("private-version-canary"));
        assert!(debug.contains("[redacted]"));
    }
}
