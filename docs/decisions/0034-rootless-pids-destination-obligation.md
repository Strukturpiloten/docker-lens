# ADR 0034: An unresolved finite-rootless-PIDs destination obligation

Status: accepted typed/rendering and pure snapshot-assessment contract;
native qualification and public PIDs admission remain pending.

## Context and scope

ADR 0031 requires destination environment requirements separate from exact
Engine/API/mode capability identity before public rootless PIDs admission.
ADR 0032 retains independent `/info` reports but explicitly does not grant
destination readiness. Implement this separate inert contract without changing
those report meanings, the acquisition request set, native proofs or catalogue.

This amends ADR 0032's observation-only product boundary only by adding the
separate pure prerequisite assessment. It supersedes ADRs 0009, 0015 and 0017's
artifact-version selection only when a finite rootless-PIDs obligation exists.
All other historical artifact bytes and obligations remain unchanged.

## Decision

Native rendering of an authored finite `PidsLimit::Count` in a rootless planning
context adds a `DestinationPidsPrerequisite`. It is bound to the owning
container's protected authored identity, caller-local reference, finite count
and immutable planning context. It is not supplied by source import or inferred
from an observed runtime limit. Absent and explicit unlimited limits remain
distinct and add no finite-enforcement obligation. Rootful requests do not
acquire the rootless-specific systemd/v2 requirement. All existing capability
gates remain mandatory, including for explicit unlimited limits. Every current
sealed profile continues to refuse PIDs settings; test-local positive facts or
records cannot admit them.

`RenderedArtifact::destination_pids_prerequisites()` exposes these typed
obligations. Complete inert artifacts containing at least one use schema 4,
with one closed `rootless_pids` row per owning container in planning order,
before that container's bind-source obligations. The row includes reference,
identity, decimal-string finite count, required systemd/v2/true metadata and
explicit unverified delegation/enforcement. The existing top-level context
binds the row to planning authority, including the offline profile and evidence
key where applicable. It does not bind or authenticate a destination. Context,
ordered requests and network/volume/bind representations retain their bytes.
Artifacts without this obligation retain exactly the existing v1/v2/v3
selection and serialization. Request-only bytes remain request-only and must
not be mistaken for a complete plan. Consumers must reject unknown schema
versions or obligation kinds rather than discard them. No output is executed.

## Pure destination snapshot assessment

`DestinationPidsPrerequisite::assess` takes a supplied `DecodedInventory` and
the caller's explicitly selected destination `ObservationId`. Inventory,
daemon facts and resource reports must all share that exact scope. The
observed planning context's ID must also equal that explicitly selected
destination; a same-version different observation refuses. Offline profiles
have no destination observation binding. No stored context ID substitutes for
the explicit selection, and a source capture is never implicitly selected as
destination evidence. Matching release/mode cannot substitute for scope consistency.
A caller can explicitly select a capture it regards as the destination;
DockerLens does not authenticate that designation or its daemon peer.

The assessment checks only observable profile projection: exact release,
advertised API and rootless mode. Offline targets additionally require a
nonempty actual request-version list using their chosen acquisition API.
Observed contexts require a nonempty actual request-version list too, without
inventing an offline acquisition API. All rendering/read API versions must fit
the reported maximum and any reported minimum. Missing minimum remains
unknown; no release-derived or schema-derived minimum is fabricated. The
request-version collection is bounded to 4096 even for caller-assembled data.

Only present, effective, valued reports with exact `PidsLimit: true`, driver
`systemd` and cgroup version `2` are metadata-compatible. False, unavailable,
null, empty, redacted, non-effective, valueless, mismatched and unknown values
refuse with closed value-free errors. No normalization, defaults, cross-field
inference or additional daemon requests are introduced.

The only positive assessment is explicitly
`MetadataCompatibleDelegationAndEnforcementUnverified`, never a satisfied or
ready boolean. Even this result proves neither usable controller delegation nor
PIDs enforcement, exact build or Debian-package provenance, daemon identity,
atomicity or current/future runtime state. Build/package provenance cannot be
authenticated from these existing fields and is not inferred from release.
The planning context's existing catalogue evidence remains separate authority.
Caller-assembled observations remain assertions. Assessment never changes an
artifact's unresolved delegation/enforcement state or grants a capability.

## Verification, consumers and non-claims

Independently authored controls cover finite/unlimited/absent and rootful
boundaries, exact legacy bytes, combined obligations and v4 precedence,
container identity/reference binding, destination-versus-source selection,
three-way scope mismatch, availability/origin/lexical negatives, observable
profile/API boundaries, missing minimum, collection bounds and redacted Debug.
Public regressions keep finite and unlimited PIDs unsupported on every sealed
profile. Test-local fabricated positive capability controls are not genuine
native evidence. No upstream implementation or oracle payload is copied.

No dependency, tool, image, Action, toolchain or workflow pin/definition moves.
Final scoped diff inspection verifies manifests, lockfile, native-image script,
workflow definitions and Renovate configuration are unchanged. Existing Cargo,
toolchain, GitHub Actions and five-image ownership/extraction/grouping/approval
rules therefore need no Renovate edit or duplicate manager. No other Lens or
website consumer requires a change. BoxFerry's closed artifact reader must
separately support schema 4 before consuming it; it must not silently ignore
unresolved requirements. DockerLens retains no BoxFerry dependency.

This is source-only groundwork, not public PIDs admission, rootless fixture
delegation, original outer custody qualification, application acceptance or a
release. Independent review, final complete gates, genuine exact-candidate
native evidence and downstream/package gates remain separate requirements.
No release, publication, deployment, host capture or runtime mutation is added.
