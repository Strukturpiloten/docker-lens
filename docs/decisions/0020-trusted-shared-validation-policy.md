# ADR 0020: Seed trusted shared validation policy

Status: accepted

## Context

DockerLens currently runs its complete offline gate for every pull request. The
BoxFerry workflow overhaul needs an immutable base policy before it can safely
select checks for a candidate. Reading a new policy from that candidate would let
an untrusted change choose its own validation.

## Decision

Land `scripts/validation-policy.json` before replacing the caller workflows. This
seed declares the future shared planner contract and explicit repository-owned
tasks. The existing Check, reviewed native dispatch, release validation, and local
complete gate remain active and complete during this prerequisite stage. Check
also runs that same complete offline gate for `merge_group` candidates, so the
merge queue can validate the prerequisite before shared selection is available.
The stable `Required CI` aggregate requires offline success and planned native
skips for PRs and queue candidates; main still requires all native lanes.

The future caller must load policy from the pull request or merge queue base
revision. Missing or invalid trusted policy cannot authorize a selective run.
Unknown paths, policy changes, decisions, evidence, and unreliable comparisons
require complete validation. Plain prose under `docs/` may use the existing
Python policy suite without Rust builds; executable documentation uses the full
offline gate. Mixed changes select the union required by the trusted planner.

Cargo aliases expose equivalent locked check, Clippy, test, doctest, and Rustdoc
commands for shared callers. Native Engine conformance remains DockerLens-owned:
all four lanes, exact-candidate admission, privacy, resource budgets, and cleanup
continue to use the existing harness. No compatibility claim, publication,
deployment, dependency-age service, or shared caller is delivered by this seed.

## Consequences

A follow-up adoption change can use an already-reviewed policy from `main`, with
shared automation hosted in `Strukturpiloten/boxferry` and pinned immutably.
The canonical crates.io API reports DockerLens `0.1.0`, published on
2026-09-28, with this repository as its source. API adoption must compare against
that real published baseline; no initial-publication exemption applies. Shared
dependency and API job identities are reserved in the trusted seed alongside
Rust, MSRV, documentation, and dependency eligibility.

Product crates gain no BoxFerry dependency. This prerequisite introduces no
software version, download, image, or Action pin, so existing Renovate extraction
and grouping remain unchanged.
