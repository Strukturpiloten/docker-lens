//! Pure assessment of observation-scoped daemon resource-support reports.
//!
//! `/info` reports do not prove enforcement, authenticate a daemon, or admit
//! target capabilities. They are evidence about one source capture only.

use crate::observation::{Availability, Observed, Origin};
use crate::version::ObservationId;

/// Memory and swap support as reported by `/info` in one completed capture.
///
/// Fields remain independently available. The decoder assigns effective origin
/// to both native reports; no Engine release or mode supplies a default.
/// Publicly assembled fields and scope are caller assertions, not authenticated
/// daemon evidence. [`Self::assess`] checks their state before using a value.
#[derive(Debug)]
pub struct ResourceSupportObservation {
    pub observation_id: ObservationId,
    /// Native `MemoryLimit`, not a successful memory-enforcement probe.
    pub memory_limit: Observed<bool>,
    /// Native `SwapLimit`, independent of memory and not an enforcement probe.
    pub swap_limit: Observed<bool>,
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

/// Independent report assessments; neither field is a planning capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceSupportAssessment {
    pub memory_limit: ReportedResourceSupport,
    pub swap_limit: ReportedResourceSupport,
}

/// Closed, value-free assessment failure. A mismatch assesses neither daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceSupportError {
    ObservationScopeMismatch,
}

impl ResourceSupportObservation {
    /// Assess reports only for the caller's explicitly supplied observation.
    ///
    /// Matching versions or daemon modes cannot substitute for identity. Only
    /// `Present` fields with `Effective` origin and an actual boolean value are
    /// reports; redacted-but-valued caller data remains unknown. This method
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
                    let reports = ResourceSupportObservation {
                        observation_id,
                        memory_limit: Observed::present(value, availability, origin),
                        swap_limit: Observed::unavailable(availability, origin),
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
                    assert_eq!(assessment.swap_limit, ReportedResourceSupport::Unknown);
                }
            }
        }
    }

    #[test]
    fn public_reports_do_not_expose_boolean_values_in_debug() {
        let observation_id = ObservationId::fresh().unwrap();
        let reports = ResourceSupportObservation {
            observation_id,
            memory_limit: Observed::present(true, Availability::Present, Origin::Effective),
            swap_limit: Observed::present(false, Availability::Present, Origin::Effective),
        };
        let debug = format!("{reports:?}");
        assert!(!debug.contains("true"));
        assert!(!debug.contains("false"));
        assert!(debug.contains("[redacted]"));
    }
}
