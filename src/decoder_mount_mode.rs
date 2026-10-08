//! Bounded native mode interpretation; raw bytes remain in the protected field.

use super::{DecodeError, MountAccess, MountModeInterpretation};
use crate::evidence::ProtectedValue;
use crate::observation::{BindRelabel, FieldPath, Observed};

const MAX_MODE_BYTES: usize = 256;
const MAX_MODE_TOKENS: usize = 16;

pub(super) fn access_conflicts(
    mode: &Observed<MountModeInterpretation>,
    read_write: &Observed<bool>,
) -> bool {
    matches!(
        (mode.value(), read_write.value()),
        (
            Some(MountModeInterpretation::Supported {
                access: Some(MountAccess::ReadOnly),
                ..
            }),
            Some(true)
        ) | (
            Some(MountModeInterpretation::Supported {
                access: Some(MountAccess::ReadWrite),
                ..
            }),
            Some(false)
        )
    )
}

pub(super) fn interpret(
    mode: &Observed<ProtectedValue>,
    field: FieldPath,
) -> Result<Observed<MountModeInterpretation>, DecodeError> {
    let Some(raw) = mode.value() else {
        return Ok(Observed::unavailable(mode.availability, mode.origin));
    };
    Ok(Observed::present(
        parse(raw.as_bytes(), field)?,
        mode.availability,
        mode.origin,
    ))
}

fn parse(raw: &[u8], field: FieldPath) -> Result<MountModeInterpretation, DecodeError> {
    if raw.len() > MAX_MODE_BYTES {
        return Err(DecodeError::InvalidValue(field));
    }
    let mut access = None;
    let mut relabel = None;
    let mut propagation = false;
    let mut consistency = false;
    let mut copy = false;
    let mut unsupported = false;
    if !raw.is_empty() {
        for (index, token) in raw.split(|byte| *byte == b',').enumerate() {
            if index >= MAX_MODE_TOKENS || token.is_empty() {
                return Err(DecodeError::InvalidValue(field));
            }
            match token {
                b"ro" | b"rw" => {
                    if access.is_some() {
                        return Err(DecodeError::InvalidValue(field));
                    }
                    access = Some(if token == b"ro" {
                        MountAccess::ReadOnly
                    } else {
                        MountAccess::ReadWrite
                    });
                }
                b"z" | b"Z" => {
                    if relabel.is_some() {
                        return Err(DecodeError::InvalidValue(field));
                    }
                    relabel = Some(if token == b"z" {
                        BindRelabel::Shared
                    } else {
                        BindRelabel::Private
                    });
                }
                b"private" | b"rprivate" | b"shared" | b"rshared" | b"slave" | b"rslave" => {
                    if propagation {
                        return Err(DecodeError::InvalidValue(field));
                    }
                    propagation = true;
                    unsupported = true;
                }
                b"consistent" | b"cached" | b"delegated" => {
                    if consistency {
                        return Err(DecodeError::InvalidValue(field));
                    }
                    consistency = true;
                    unsupported = true;
                }
                b"nocopy" => {
                    if copy {
                        return Err(DecodeError::InvalidValue(field));
                    }
                    copy = true;
                    unsupported = true;
                }
                _ => unsupported = true,
            }
        }
    }
    // Scan the entire bounded token list before classifying unknown options:
    // an unknown token cannot conceal a contradictory or duplicated known mode.
    Ok(if unsupported {
        MountModeInterpretation::Unsupported
    } else {
        MountModeInterpretation::Supported { access, relabel }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::{Availability, Origin};
    use serde_json::{Value, json};

    #[test]
    fn native_access_and_relabel_modes_are_closed_and_case_sensitive() {
        for (text, access, relabel) in [
            ("", None, None),
            ("ro", Some(MountAccess::ReadOnly), None),
            ("rw", Some(MountAccess::ReadWrite), None),
            ("z", None, Some(BindRelabel::Shared)),
            ("Z", None, Some(BindRelabel::Private)),
            (
                "ro,z",
                Some(MountAccess::ReadOnly),
                Some(BindRelabel::Shared),
            ),
            (
                "rw,z",
                Some(MountAccess::ReadWrite),
                Some(BindRelabel::Shared),
            ),
            (
                "ro,Z",
                Some(MountAccess::ReadOnly),
                Some(BindRelabel::Private),
            ),
            (
                "rw,Z",
                Some(MountAccess::ReadWrite),
                Some(BindRelabel::Private),
            ),
            (
                "Z,ro",
                Some(MountAccess::ReadOnly),
                Some(BindRelabel::Private),
            ),
        ] {
            assert_eq!(
                parse(text.as_bytes(), FieldPath::Mount { index: 0 }).unwrap(),
                MountModeInterpretation::Supported { access, relabel },
            );
        }
    }

    #[test]
    fn contradictory_duplicate_empty_and_overbound_modes_fail_closed() {
        for text in [
            "z,Z",
            "Z,z",
            "z,z",
            "Z,Z",
            "ro,rw",
            "rw,rw",
            "ro,ro",
            ",ro",
            "ro,",
            "ro,,z",
            "unknown,z,Z",
            "z,unknown,Z",
            "ro,unknown,rw",
            "private,rprivate",
            "cached,delegated",
            "nocopy,nocopy",
        ] {
            assert_eq!(
                parse(text.as_bytes(), FieldPath::Mount { index: 7 }),
                Err(DecodeError::InvalidValue(FieldPath::Mount { index: 7 })),
            );
        }
        let bytes = vec![b'x'; MAX_MODE_BYTES + 1];
        assert!(parse(&bytes, FieldPath::Mount { index: 0 }).is_err());
        assert_eq!(
            parse(&bytes[..MAX_MODE_BYTES], FieldPath::Mount { index: 0 }).unwrap(),
            MountModeInterpretation::Unsupported
        );
        let tokens = vec!["unknown"; MAX_MODE_TOKENS + 1].join(",");
        assert!(parse(tokens.as_bytes(), FieldPath::Mount { index: 0 }).is_err());
        let tokens = vec!["unknown"; MAX_MODE_TOKENS].join(",");
        assert_eq!(
            parse(tokens.as_bytes(), FieldPath::Mount { index: 0 }).unwrap(),
            MountModeInterpretation::Unsupported
        );
    }

    #[test]
    fn recognized_other_and_future_options_remain_unsupported_not_absent_relabel() {
        for text in [
            "rprivate",
            "ro,z,rprivate",
            "ro,Z,cached",
            "nocopy",
            "native-private-canary",
            "native-private-canary,z",
            "ro,z,private-canary-Ω",
        ] {
            let mode = Observed::present(
                ProtectedValue::new(text.as_bytes().to_vec()),
                Availability::Present,
                Origin::Effective,
            );
            let decoded = interpret(&mode, FieldPath::Mount { index: 0 }).unwrap();
            assert_eq!(decoded.value(), Some(&MountModeInterpretation::Unsupported));
            assert_eq!(mode.value().unwrap().as_bytes(), text.as_bytes());
            assert_eq!(decoded.availability, mode.availability);
            assert_eq!(decoded.origin, mode.origin);
            assert!(!format!("{mode:?} {decoded:?}").contains(text));
        }
    }

    #[test]
    fn mount_fields_preserve_missing_null_empty_redacted_and_effective_origin() {
        for (value, availability) in [
            (None, Availability::Missing),
            (Some(json!(null)), Availability::Null),
            (Some(json!("")), Availability::Empty),
            (
                Some(json!({"__docker_lens_redacted__": true})),
                Availability::Redacted,
            ),
            (Some(json!("ro,Z")), Availability::Present),
        ] {
            let mut mount =
                json!({"Type":"bind","Source":"/private-source","Destination":"/private-target"});
            if let Some(value) = value {
                mount["Mode"] = value;
            }
            let mounts = super::super::mounts(&json!([mount])).unwrap();
            let observed = &mounts[0];
            assert_eq!(observed.mode.availability, availability);
            assert_eq!(observed.mode_interpretation.availability, availability);
            assert_eq!(observed.mode.origin, Origin::Effective);
            assert_eq!(observed.mode_interpretation.origin, Origin::Effective);
            assert_eq!(
                observed.mode.value().is_some(),
                observed.mode_interpretation.value().is_some()
            );
            assert_eq!(observed.read_write.availability, Availability::Missing);
            assert!(!format!("{:?}", observed.mode).contains("private"));
        }
        assert!(super::super::mounts(&json!([{"Type":"bind","Mode":1}])).is_err());
        let mounts =
            super::super::mounts(&json!([{"Type":"bind","Mode":"ro,Z","RW":true}])).unwrap();
        assert_eq!(mounts[0].read_write.value(), Some(&true));
        assert_eq!(
            mounts[0].mode_interpretation.value(),
            Some(&MountModeInterpretation::Supported {
                access: Some(MountAccess::ReadOnly),
                relabel: Some(BindRelabel::Private),
            })
        );
    }

    fn captured_mode(
        mode: Option<Value>,
        read_write: Option<Value>,
    ) -> (crate::evidence::Capture, super::super::DecodedInventory) {
        use crate::acquisition::{Budget, Limits, NativeId, ReadRequest};
        use crate::evidence::HttpStatus;
        use crate::observation::ResourceRef;
        use crate::version::ApiVersion;
        use std::num::NonZeroU16;
        use std::time::Duration;

        let reference = ResourceRef::new(9);
        let mut budget = Budget::new(Limits {
            max_requests: 2,
            max_selected_resources: 1,
            max_expansions: 1,
            max_response_bytes: 4096,
            max_total_bytes: 8192,
            max_elapsed: Duration::from_secs(2),
        })
        .unwrap();
        budget
            .record_request(ReadRequest::DaemonVersion, None, None)
            .unwrap();
        budget
            .read_response(
                HttpStatus::new(200).unwrap(),
                br#"{"Version":"20.10.5","ApiVersion":"1.41","MinAPIVersion":"1.41"}"#.as_slice(),
            )
            .unwrap();
        budget
            .record_request(
                ReadRequest::InspectContainer(
                    NativeId::new("observed-container".to_owned()).unwrap(),
                ),
                Some(reference),
                Some(ApiVersion::new(NonZeroU16::new(1).unwrap(), 41)),
            )
            .unwrap();
        let mut mount =
            json!({"Type":"bind","Source":"/private-source","Destination":"/private-target"});
        if let Some(mode) = mode {
            mount["Mode"] = mode;
        }
        if let Some(read_write) = read_write {
            mount["RW"] = read_write;
        }
        let body =
            serde_json::to_vec(&json!({"Id":"observed-container","Mounts":[mount]})).unwrap();
        budget
            .read_response(HttpStatus::new(200).unwrap(), body.as_slice())
            .unwrap();
        let capture = budget.into_capture().unwrap();
        let inventory = super::super::decode_capture(&capture).unwrap();
        (capture, inventory)
    }

    #[test]
    fn captured_future_mode_reports_value_free_finding_and_keeps_protected_evidence() {
        use crate::finding::{FindingCode, Severity};
        use crate::observation::ResourceRef;

        let canary = "private-future-mode-Ω";
        let (capture, inventory) = captured_mode(Some(json!(canary)), Some(json!(true)));
        let mounts = inventory.containers[0].mounts.value().unwrap();
        assert_eq!(
            mounts[0].mode.value().unwrap().as_bytes(),
            canary.as_bytes()
        );
        assert_eq!(
            mounts[0].mode_interpretation.value(),
            Some(&MountModeInterpretation::Unsupported)
        );
        let findings: Vec<_> = inventory
            .findings
            .iter()
            .filter(|finding| finding.field == Some(FieldPath::Mount { index: 0 }))
            .collect();
        assert_eq!(findings.len(), 1);
        let finding = findings[0];
        assert_eq!(finding.code, FindingCode::UnsupportedValue);
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.resource, Some(ResourceRef::new(9)));
        assert_eq!(finding.field, Some(FieldPath::Mount { index: 0 }));
        assert!(!format!("{capture:?} {inventory:?} {finding:?}").contains(canary));
    }

    #[test]
    fn captured_access_contradictions_keep_fields_and_report_value_free_conflict() {
        use crate::finding::{FindingCode, Severity};
        use crate::observation::ResourceRef;

        for (mode, read_write, access, relabel) in [
            ("ro,Z", true, MountAccess::ReadOnly, BindRelabel::Private),
            ("rw,z", false, MountAccess::ReadWrite, BindRelabel::Shared),
        ] {
            let (capture, inventory) = captured_mode(Some(json!(mode)), Some(json!(read_write)));
            let mount = &inventory.containers[0].mounts.value().unwrap()[0];
            assert_eq!(mount.mode.value().unwrap().as_bytes(), mode.as_bytes());
            assert_eq!(mount.read_write.value(), Some(&read_write));
            assert_eq!(
                mount.mode_interpretation.value(),
                Some(&MountModeInterpretation::Supported {
                    access: Some(access),
                    relabel: Some(relabel),
                })
            );
            assert_eq!(mount.mode_interpretation.origin, Origin::Effective);
            assert_eq!(mount.read_write.origin, Origin::Effective);
            let findings: Vec<_> = inventory
                .findings
                .iter()
                .filter(|finding| finding.field == Some(FieldPath::Mount { index: 0 }))
                .collect();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].code, FindingCode::NativeConflict);
            assert_eq!(findings[0].severity, Severity::Warning);
            assert_eq!(findings[0].resource, Some(ResourceRef::new(9)));
            let debug = format!("{capture:?} {inventory:?} {:?}", findings[0]);
            assert!(!debug.contains(mode));
            assert!(!debug.contains("private-source"));
            assert!(!debug.contains("private-target"));
        }
    }

    #[test]
    fn coherent_default_and_unavailable_fields_do_not_invent_access_conflicts() {
        for (mode, read_write) in [("ro,Z", false), ("rw,z", true), ("", true), ("z", false)] {
            let (_, inventory) = captured_mode(Some(json!(mode)), Some(json!(read_write)));
            assert!(
                !inventory
                    .findings
                    .iter()
                    .any(|finding| finding.field == Some(FieldPath::Mount { index: 0 }))
            );
        }
        for (unavailable, availability) in [
            (None, Availability::Missing),
            (Some(json!(null)), Availability::Null),
            (
                Some(json!({"__docker_lens_redacted__":true})),
                Availability::Redacted,
            ),
        ] {
            let (_, inventory) = captured_mode(unavailable.clone(), Some(json!(true)));
            let mount = &inventory.containers[0].mounts.value().unwrap()[0];
            assert_eq!(mount.mode.availability, availability);
            assert_eq!(mount.mode_interpretation.availability, availability);
            assert!(
                !inventory
                    .findings
                    .iter()
                    .any(|finding| finding.field == Some(FieldPath::Mount { index: 0 }))
            );
            let (_, inventory) = captured_mode(Some(json!("ro,Z")), unavailable);
            let mount = &inventory.containers[0].mounts.value().unwrap()[0];
            assert_eq!(mount.read_write.availability, availability);
            assert!(
                !inventory
                    .findings
                    .iter()
                    .any(|finding| finding.field == Some(FieldPath::Mount { index: 0 }))
            );
        }
    }
}
