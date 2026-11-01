# ADR 0020: Retain observation-scoped cgroup and PIDs reports

Status: accepted inert observation contract; native qualification and capability
admission remain separate and unverified by this change.

## Decision

Recover the existing #125 observation contract from DockerLens source
`f406cb22efc53fc7df04c24ea44a9ecd7900f41b`, without its later native transport or
admission machinery. Retain independent PIDs-support, cgroup-driver and
cgroup-version fields from the existing captured `/info` response, alongside
memory and swap reports. No request or dependency is added.

Availability, effective origin, protected raw text and explicit observation
scope remain independent. Assessment requires the caller's matching scope and
only classifies present/effective values. Boolean true means reported available
but unverified. Cgroup classification uses exact bytes without defaults or
normalization. Reports neither infer controller delegation or enforcement nor
grant capabilities. Caller-assembled fields remain assertions.

Adding public struct fields affects Rust struct literals. Consumers must supply
the fields or use `ResourceSupportObservation::missing(observation_id)`; this
constructor preserves missing/effective states rather than manufacturing native
values. Downstream source integration and validation remain required.

## Verification boundary

Recovered pure controls cover independent availability/origin, lexical
boundaries, malformed types, privacy and scope mismatch. They establish no
native compatibility, destination authority or catalogue admission. No software
pins, workflows, dependencies or Renovate ownership change. The separate
[destination obligation](0021-rootless-pids-destination-obligation.md) does not
change these reports' meaning.
