# ADR 0022: Shared development automation

Status: accepted for staged adoption; native runtime rollout remains separate

Builds on ADR 0021's trusted reader seed and amends ADR 0020's prerequisite-only stage and the repository-local common
workflow mechanics. Product and native evidence decisions remain unchanged.

## Decision

Use the immutable BoxFerry development package, common/Rust Renovate presets,
shared Rust/dependency/API tasks and exact-candidate release aggregate. This is
a development dependency only; DockerLens's Cargo graph stays independent.

Merge an interface-1 manifest and trusted metadata service before the selective
caller. PR and queue policy comes from that already trusted base. Missing base
admission policy fails closed; the candidate cannot grant its own exemption.
Main/manual complete validation, native dispatch and local complete gates stay
complete. Known prose and Rust-test changes select reviewed job unions; source,
policy, decisions, evidence and unknown paths select everything.

The stable Required CI job independently checks the selected plan and native
branch policy. Only explicitly planned offline skips pass. PRs and queues retain
no native execution; main requires all four existing lanes. The trusted service
alone writes eligibility statuses and bounded age-maturity retries. Normal
candidate jobs have read-only tokens. Ordinary introduced dependencies retain
the 72-hour rule; exact isolated first-party source updates and their necessary
resolution use the reviewed exception, with integrity and compatibility checks.

Downloaded development tools and Cargo tool versions have their sole operational
inventory in the immutable shared source. Consumers do not maintain local
version-only or checksum-review copies. The stable frontloader delegates raw
arguments to the selected implementation and preserves explicit trusted inputs.

DockerLens already has a published 0.1.0 baseline, so public API checks must
compare against crates.io and cannot use an initial-publication exemption.
Release validation requires exact candidate outputs from complete offline,
native, dependency and API checks. Publication remains disabled in the shared
policy; no publisher, tag, release or deployment is introduced.

## Native boundary

DockerLens #127 / held PR #128 and BoxFerry #469 own the outstanding ADR 0079
runtime rollout. The current main harness explicitly requires outer Podman,
including on hosted runners; this adoption preserves its reviewed implementation.
It does not claim that hosted outer Docker or fresh native qualification has
been delivered. Backend changes and qualification remain separately reviewed.
Native fixture updates cannot substitute shared policy or offline success for
the product's exact native admission and evidence requirements.

## Bootstrap and rollback

The initial unreleased internal source uses a full commit SHA with honest
`automation-v1 interface v1` provenance, following BoxFerry ADR 0092. This is not
a release tag. Keep manifest, reusable calls, checkout inputs and preset refs in
one immutable adoption update. Roll back all of them together to the last
verified source; never fall back to candidate-controlled admission policy.

Qualified native fixtures remain fixed during this overhaul. Disable routine
Renovate updates for the exact five image identities at their native harness
path, with nearby-name/path counterexamples covered by native extraction tests.
Do not retain a manual-review-only update stream. The complete tuple inventory
and separately owned replacement qualification are in the shared automation guide.
