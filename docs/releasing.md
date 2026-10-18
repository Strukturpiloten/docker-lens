# Manual crates.io release handoff

The maintainer has reported that `docker-lens` `0.1.0` is already published.
Do not attempt to publish that version again. DockerLens has validation workflows,
not a publisher, release-plz configuration, or automated GitHub release creation.
The maintainer chooses the next version and publishes manually only after the
complete milestone below is qualified and a release is explicitly requested.

## Current milestone status

The next coherent release milestone is
[#31](https://github.com/Strukturpiloten/docker-lens/issues/31), under
[#3](https://github.com/Strukturpiloten/docker-lens/issues/3): the complete,
independently verified standalone Docker migration contract. Published `0.1.0`
and historical evidence retain only their existing bounded scope. No next version
is selected, and no upload, tag, GitHub release or release pull request is
requested or authorized by this preparation.

The current source rehearsal prerequisite is BoxFerry
[#343](https://github.com/Strukturpiloten/boxferry/issues/343)/
[#366](https://github.com/Strukturpiloten/boxferry/issues/366), including real
adapter/CLI and full application candidate rehearsal against the exact DockerLens
source candidate. Required consumer work remains pending. BoxFerry
[#455](https://github.com/Strukturpiloten/boxferry/issues/455)'s ZIP dependency/MSRV
choice is closed. That resolved dependency decision does not qualify the current
source candidate or replace complete and application gates. Standalone DockerLens
requires MSRV `1.98.1`, matching the current pinned development compiler.

[ADR 0022](decisions/0022-reviewed-lifecycle-cohort.md) selects the independently
reviewed lifecycle cohort at Debian 34 capabilities/56 shapes and upstream 36/60.
Raw family markers remain `raw_source_only`/`catalogue_admission: unadmitted`;
they describe raw authority, not the separate compiled selection. Under
[ADR 0023](decisions/0023-process-source-proof-wiring.md), hostname and command/
entrypoint-clear proofs remain mandatory. Those three process groups remain unselected.
[ADR 0024](decisions/0024-health-disabled-raw-source-projection.md) adds only raw
HealthDisabled/DisabledHealthcheck after the existing complete health-metadata-v1
validation. [ADR 0025](decisions/0025-shm-size-source-integration.md) adds the
twenty-fourth ShmSize source invocation and strict proof gate, bringing current
raw source slice to Debian 39/61 and upstream 41/65.
[ADR 0026](decisions/0026-runtime-settings-source-integration.md) appends mandatory
supplementary/kernel invocations 25/26 and their strict readers; current raw totals
are Debian 43/66 and upstream 45/70. Its four finite groups remain unselected.
Host capture remains deferred; no nofile admission is included. HealthDisabled and
ShmSize remain outside compiled selection. The original 23 native invocations,
six-child ownership block, strict private protocols and historical evidence stay unchanged.
Complete milestone coverage, fresh exact-final-candidate native proof,
independent review and actual downstream acceptance remain required; this is not
a release-readiness claim.

## Readiness

Prepare one release handoff only after all required #31/#3 native work is
implemented, independently reviewed and merged. Keep the feature ledger binding
every required source/target shape to its typed API, independent expected
semantics, native test, exact profile, BoxFerry consumer route and release blocker.
Do not relabel missing implementation as unsupported to close a required gap.
Image publication, passing offline checks and native runs on older heads do not
satisfy this requirement.

For the final current-main candidate require:

- The complete offline gate and package verification below.
- Fresh successful exact-candidate `Release validation`, including all four
  independent native lanes, each executing the canonical twenty-six exact test
  invocations, and its fail-closed final aggregate. A failed, skipped or cancelled
  lane blocks publication. If required work extends the canonical suite, every
  added invocation is mandatory too.
- Reviewed positive public target profiles with immutable native evidence, and
  complete downstream candidate rehearsal against that exact source SHA,
  including real BoxFerry adapter/CLI and application routes. Public constructor
  or mock tests alone are insufficient. Retain all six actual authored-fixture
  volume-only rehearsals and actual Nextcloud/Supabase bind and desired-external
  expectation consumers required by the accepted ADRs. Rehearsal must expose no
  unresolved required native gap; partial shape acceptance is not the milestone.
- Reviewed exact package/Engine/API/mode identities, privacy-safe evidence,
  failure/version boundaries, resource budgets and cleanup limitations. Record
  cold/warm duration and resource measurements before expanding release tiers;
  cached results do not replace fresh candidate evidence.
- A package version intentionally selected by the maintainer, with an available
  next version on crates.io. The existing `0.1.0` manifest is not a selection for
  the next release; a failed registry lookup does not prove availability.

Source rehearsal uses isolated local overrides only, never published manifests
or `main`. Record both candidate SHAs and bind the complete rehearsal to the final
exact source. Any subsequent source change invalidates that qualification and
requires fresh rehearsal. Remove overrides before final published-registry
verification. Preserve historical exact-SHA/run/attempt/artifact/shape records;
neither an old source cohort nor a successful generic lane admits untested shapes.

## Validate the candidate

The maintainer must select and record the next version before final candidate
validation; do not validate `0.1.0` for another upload.

Run from a clean Linux host checkout with the repository's development tools.
Native suites use isolated Podman-launched fixtures, not host Docker. The hosted
workflow supplies their required privileged Linux environment.

```sh
cd /home/becks/Entwicklung/standard/github/strukturpiloten/docker-lens
test -z "$(git status --porcelain)"
git switch main
git fetch origin main
git merge --ff-only origin/main
candidate_sha=$(git rev-parse HEAD)
test "$candidate_sha" = "$(git rev-parse origin/main)"

./scripts/check-all.sh --check
cargo package --list --locked --package docker-lens
cargo publish --dry-run --locked --package docker-lens

gh workflow run release-validation.yml --ref main -f "expected_sha=$candidate_sha"
gh run list --workflow release-validation.yml --event workflow_dispatch \
  --commit "$candidate_sha" --json databaseId,headSha,status,conclusion,url
```

Inspect the package listing: it contains product source, Cargo metadata, license,
README and supporting documentation, not agent configuration, test orchestration,
credentials or runtime artifacts. The manifest's include list is the boundary;
Cargo may additionally generate its standard metadata files.

Select the newly dispatched run, confirm its SHA, and wait for its successful
completion. Do not substitute an older run at a different revision or an offline
PR gate. If `main` moves, any source edit is needed (including the version change),
or a required check fails, repeat the complete/package and four-lane validation
for the new exact-current-main candidate. Source changes also require fresh
complete downstream rehearsal. Older runs, including passing transport-source
runs, do not qualify a future head.

## One maintainer handoff and upload

Only after all readiness gates pass, assemble one handoff containing the selected
next version, exact current-main SHA, complete/package results, fresh Release
validation run/attempt and all four lane artifacts, independently reviewed shape
admission and exact-source downstream rehearsal results. State remaining genuine
platform/version limitations and cleanup/SIGKILL limitations. Unresolved required
work blocks the handoff. This guide does not itself authorize an upload, tag,
GitHub release or release pull request; those need a separate explicit request.

Create or sign in to the intended crates.io account, verify its email address,
and create a token permitted to publish the new crate. Enter it interactively;
never paste it into an issue, a command argument, shell history or a GitHub secret.
Cargo stores it through the configured local credential provider.

For a separately authorized maintainer publication, the following assumes
`candidate_sha` still holds the validated commit from the previous section, the
selected next version is in that commit, and all readiness gates passed.
Authentication does not grant permission to publish a different candidate.

```sh
cargo login
test -z "$(git status --porcelain)"
test "$(git rev-parse HEAD)" = "$candidate_sha"
git fetch origin main
test "$(git rev-parse origin/main)" = "$candidate_sha"
cargo publish --dry-run --locked --package docker-lens
cargo publish --locked --package docker-lens
```

The final command is the irreversible external publication step. Do not use
`--allow-dirty` or `--no-verify`. A registry/API error blocks the upload; it is not
evidence that a name is free. A successful Cargo upload must be followed by checking
the published version and allowing the registry index to become available.

An annotated Git tag and GitHub release can be created separately by the
maintainer after verifying the published version and exact source commit. They
are not created automatically by this procedure. Later trusted-publishing setup
is a separate reviewed task, not a reason to put this bootstrap token in GitHub.

Tell the BoxFerry integration task the published version and validated commit.
BoxFerry #343/#366 must then consume that registry version without local overrides
and rerun its complete/package, adapter/CLI and application checks. Source
rehearsal is a pre-release prerequisite; a temporary path dependency cannot
replace this downstream published-registry verification.

## Maintenance ownership

This documentation-only preparation changes no package allowlist, dependency,
tool, operational pin, workflow or Renovate definition. The existing Cargo
manager owns declarations and `Cargo.lock`; the native-image manager still owns
the five tag/digest declarations in `scripts/native-conformance.sh`, and existing
toolchain/Action ownership, extraction paths, grouping and approvals remain.
Local/main/reviewed-dispatch/release native consumers share that canonical harness.
No extra manager is needed. Other workspace packages retain their existing
protected release workflows and independent verification responsibilities.
