# ADR 0032: Retain observation-scoped cgroup and PIDs-support reports

Status: accepted observation contract; native and destination qualification remain open.

## Context and provenance

The decoder already retains memory/swap support reports from the captured
`/info` response. Discarding the independent PIDs-support and cgroup-environment
reports loses useful inputs to a future destination-prerequisite assessment.
Observing them is not that assessment and cannot admit a capability.

Official Docker schemas at documentation commit
`31d174d090fd7111ca2199ed54a3978e0d4ac74d` define these fields in both
[API 1.41](https://github.com/docker/docs/blob/31d174d090fd7111ca2199ed54a3978e0d4ac74d/_vendor/github.com/moby/moby/api/docs/v1.41.yaml#L5355)
and
[API 1.56](https://github.com/docker/docs/blob/31d174d090fd7111ca2199ed54a3978e0d4ac74d/_vendor/github.com/moby/moby/api/docs/v1.56.yaml#L7024):
PidsLimit is boolean, CgroupDriver is a string with cgroupfs/systemd/none
values, and CgroupVersion is a string with 1/2 values. The boolean is not the
integer container HostConfig.PidsLimit. No introduction floor is inferred.
No property is required or declared nullable. Declared schema defaults are
not observed evidence; missing properties stay missing. Explicit null remains
Null/unknown under the decoder's tolerant observation model, not a claim that
null is schema-conforming.

Historical Engine commit
[`363e9a88a11be517d9e8c65c998ff56f774eb4dc`](https://github.com/moby/moby/blob/363e9a88a11be517d9e8c65c998ff56f774eb4dc/api/types/types.go#L167)
and API module api/v1.56.1 commit
[`14ebc602124e280ef4ae3e1a8e688dac1255baa6`](https://github.com/moby/moby/blob/14ebc602124e280ef4ae3e1a8e688dac1255baa6/api/types/system/info.go#L30)
use bool/string/string types; CgroupVersion may be omitted. Modern native
population additionally gates PIDs reporting on a non-none driver, whereas
the historical implementation does not. Preserve every report literally,
including apparently inconsistent combinations. These are documentation
references, not executed oracles. No upstream implementation or payload is
copied or redistributed; implementation and expectations are independently
authored.

## Decision

Extend ResourceSupportObservation with independent PIDs-support and protected
cgroup driver/version reports from the same existing capture. Missing, null,
empty and explicitly redacted states remain distinct. Wrong present JSON types
fail with the existing value-free resource-limit error. No request is added.

The pure assessment first requires the caller's matching observation ID. This
checks scope consistency, not daemon authentication or destination identity.
Only Present, Effective fields with actual values can be classified. False
PIDs support is a reported unavailability; true remains available/unverified.
Driver/version values require exact byte matches. No trimming, case folding,
numeric coercion, schema default or Engine/mode-derived inference is allowed.
Present nonempty unexpected strings classify as Unrecognized while their
original bytes remain protected. Unavailable, empty, non-effective, valueless
or redacted-but-valued caller fields classify as Unknown.

Do not combine these fields into rootless readiness, infer usable cgroup
delegation, admit a capability, modify a target plan or artifact, or project
new public native evidence. Even systemd/v2 plus a positive PIDs report proves
no enforcement. Future public PIDs admission still needs its separately
reviewed evidence-bound destination prerequisite and conditional-plan design.

Adding public struct fields changes Rust struct-literal construction. Consumers
must include them or use ResourceSupportObservation::missing(observation_id),
which creates complete Missing/Effective observation defaults, not native
defaults. The unpublished BoxFerry fixture is the known downstream literal;
its coordinated source verification is not published-package evidence. No
release number, publication or compatibility promise is selected here.

## Verification and consumers

Unit and independent oracle controls cover lexical boundaries, independent
availability/origin, malformed shapes, scope mismatch and protected Debug.
The existing native selection test compares all reports with its already saved
direct `/info` oracle. Its marker, all 28 native invocations, six owner scopes,
private proof protocols, budgets and cleanup are unchanged. Definition-only
tests and offline gates do not constitute genuine native qualification.

Local, PR, main, trusted-native dispatch and release consumers keep their
canonical scripts. No package, image, Action, downloaded-tool or toolchain pin
or extraction path changes. Renovate's current Cargo and five-image manager
ownership, grouping and manual-review rules therefore require no edit; policy
regressions and final-diff inspection must verify that no new pin was added.
Other Lens products and the website have no resource-report literal consumer.
No Lens product depends on BoxFerry, and historical evidence stays immutable.

Independent final-diff review and complete final-edit validation precede source
publication. The existing draft milestone still requires fresh exact-candidate
four-lane native proof, actual six-fixture and application consumers, published
dependency/package checks and separately authorized manual releases. The
delegated rootless fixture and authenticated original outer resource boundary
remain unresolved; this observational groundwork resolves neither.
