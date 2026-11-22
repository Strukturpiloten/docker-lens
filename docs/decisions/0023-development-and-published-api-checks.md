# ADR 0023: Development and published API checks

Status: accepted for staged adoption; admitted producer selected, consumer
complete and hosted checks pending

Amends [ADR 0020](0020-trusted-shared-validation-policy.md)'s universal
published comparison and [ADR 0022](0022-shared-development-automation.md)'s API
purpose. Their accepted records remain historical. BoxFerry ADR 0096, tracked by
[BoxFerry #576](https://github.com/Strukturpiloten/boxferry/issues/576), owns
canonical selection and source-identity mechanics.

## Decision

Ordinary PR, merge queue and main API jobs explicitly select `development`. The
complete local gate invokes one typed `api-development` task through the
existing interface-1 frontloader and locked project. Its literal command calls
the canonical API helper with DockerLens's repository/package identity. The
helper compares trusted Git history with the whole tested proposal and verifies
the actual Cargo tool/compiler. Consumers add no baseline algorithm,
source-identity glue or second pin inventory.

Release validation, which remains publication-disabled, explicitly selects
`published` and leaves release-type inference to the actual chosen manifest
version. Its existing final required aggregate additionally requires successful
API output `published_api_candidate_sha` equal to the exact expected candidate.
The generic shared release gate still checks generic candidate bindings; it does
not inspect that new field. Every offline, dependency, four-lane native and
current-main prerequisite remains required.

DockerLens's existing publication must never be treated as initial. Previously
accumulated published incompatibilities remain release failures; neither a
workflow adoption nor a major override or product version change conceals them.
New development breaks still fail the canonical default compatibility allowance.
Check's manual dispatch retains its separate diagnostic-only boundary.

## Reviewed DockerLens 0.2.0 development intent

The default remains minor. For the reviewed addition of `pids_limit`,
`cgroup_driver` and `cgroup_version` to both resource-support structs, the
development check can use major after retaining the exact minor failure and
matching all six witnesses. The ordinary and major comparisons use the same
canonical selector, package and held source. A different lint, additional
witness, incomplete output or infrastructure failure cannot authorize major.

An independently reviewed `scripts/development-api-intent.json` must first
land in the trusted preparation commit. It records schema 1, the preparation
commit's first parent as `previous_main`, the exact candidate version and
`delta_sha256` over the complete raw Git diff from preparation to the approved
product. Compute that diff with `git diff-tree -r --no-commit-id --raw
--no-renames --no-abbrev -z`. Keep the record identical on both sides of the
comparison. The record is valid only at its introducing baseline, for clean
candidate source with the same automation manifest and the exact reviewed
delta. The preparation PR itself uses minor.

PR and queue check the record from the independently held event base against
the synthetic tested tree. Main uses the validated push `before` for the
single prepared transition. Local uses the existing canonical fork-base or
clean-main first-parent selector. The advertised default tip must still be
the preparation commit or the exact clean merged candidate. The hosted preflight reads its guard from
that event baseline before allowing the existing reusable API job to use
major. Candidate records and workflow inputs supply no development intent.
The protected review must include changes to the caller workflow itself.

This preparation adds no active intent record. Reconcile and independently
review the final product delta before introducing it. Published Release
continues to infer compatibility from the candidate manifest against its
registry baseline and retains its separate exact-candidate approval policy.

## Adoption boundary

The caller selects the admitted API producer through aligned manifest,
workflow, checkout/input and preset refs under the existing Renovate ownership.
The selected source supports the API purpose and local task contract. Consumer
adoption still requires independent review, both complete gates and required
hosted checks; focused schema and frontloader checks alone do not establish
readiness. No product, native fixture, package version, publisher, release or
deployment is changed or authorized.
