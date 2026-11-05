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

## Adoption boundary

The caller selects the admitted API producer through aligned manifest,
workflow, checkout/input and preset refs under the existing Renovate ownership.
The selected source supports the API purpose and local task contract. Consumer
adoption still requires independent review, both complete gates and required
hosted checks; focused schema and frontloader checks alone do not establish
readiness. No product, native fixture, package version, publisher, release or
deployment is changed or authorized.
