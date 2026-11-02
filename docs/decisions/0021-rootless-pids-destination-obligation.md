# ADR 0021: Keep finite rootless PIDs destination obligations unresolved

Status: accepted inert rendering and pure metadata-assessment contract; native
qualification, destination delegation/enforcement and PIDs admission remain
unproved by this change.

## Decision

Recover the existing #125 contract from DockerLens source
`f406cb22efc53fc7df04c24ea44a9ecd7900f41b`, not its native authority or transport.
After existing capability validation, each authored finite rootless PIDs setting
adds a typed obligation bound to the owning container identity/reference,
finite count and planning context. Absent, unlimited and rootful settings add
no rootless finite-enforcement obligation; their existing gates still apply.
Production capability profiles remain unchanged.

This supersedes only ADRs 0009, 0015 and 0017's artifact-version selection when
this new obligation exists: complete output then uses schema 4 and closed
`rootless_pids` rows before the owner's bind-source rows. Delegation and
enforcement are explicitly unverified. Other prerequisites, ordinary requests,
and schema 1/2/3 bytes without this obligation remain unchanged. Request-only
output is still incomplete; consumers must not discard unknown prerequisites.

Pure assessment requires explicit destination selection, consistent inventory,
daemon and report scopes, matching observed planning scope where present,
release/API/rootless identity, bounded nonempty actual request versions and
valid reported API ranges. Offline targets require their chosen acquisition
API without inventing an observation identity. Only exact present/effective
true/systemd/2 metadata is compatible. The sole positive result remains
`MetadataCompatibleDelegationAndEnforcementUnverified`; it never satisfies an
obligation, authenticates a peer/build/package, changes an artifact or grants
a capability. Missing minimum API remains unknown. Errors are value-free.

## Verification and integration boundary

Pure controls cover finite/absent/unlimited/rootful boundaries, exact request
and legacy artifact bytes, ownership/order/privacy, malformed metadata, scope
and API failures, and test-local offline-profile projection. These controls are
not native evidence. No executor, I/O, host change, native proof, catalogue
grant, dependency or pin is added. Exact-candidate validation, independent
review and downstream closed schema-4 support remain separate requirements.

See the [contract reference](../destination-pids-prerequisite.md) and
[observation decision](0020-observation-scoped-cgroup-reports.md).
