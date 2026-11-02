# Manual crates.io releases

The maintainer has already bootstrapped DockerLens 0.1.0 on crates.io. Subsequent
publication remains manual. DockerLens has validation workflows, not a publisher,
release-plz configuration, or automated GitHub release creation. An agent must
stop before publication and hand over one coherent, verified library milestone.
Source implementation, native qualification, merge and publication are separate
states; none follows merely from a passing offline check.

## Readiness

The expanded native-library milestone is tracked in
[#3](https://github.com/Strukturpiloten/docker-lens/issues/3) and
[#31](https://github.com/Strukturpiloten/docker-lens/issues/31). Finish its required
implementation, independent review and consumer contracts before requesting a
release. Image publication, passing offline checks and successful native runs on
older PR heads do not satisfy this requirement. The original bootstrap
prerequisites in #13, #22 and #23 are historical, not evidence for a later candidate.

For the final current-main candidate require:

- The complete offline gate and package verification below.
- Fresh successful exact-candidate `Release validation`, including all four
  independent native lanes and its fail-closed final aggregate. A failed,
  skipped or cancelled lane blocks publication.
- Reviewed positive public target profiles with immutable native evidence, and
  external-consumer checks of the typed observation and target APIs. Preserve
  the application-derived consumer obligations in
  [ADR 0012](decisions/0012-candidate-volume-label-admission.md) and the
  [migration ledger](standalone-migration-ledger.md); a small smoke test cannot
  replace those obligations or establish full BoxFerry application acceptance.
- A package version intentionally selected by the maintainer, with an available
  version on crates.io, and a coherent `CHANGELOG.md` describing public changes,
  construction/schema migration requirements and remaining support limits.
  Do not attempt to republish 0.1.0. A manifest declaration or failed registry
  lookup does not establish version availability.

Prepare a single manual handoff containing the exact merged commit, selected
version, reviewed changelog, complete/package/native run evidence, downstream
contract results and any remaining blockers. Continue independent work while a
release is unnecessary. At the publication dependency, stop and let the maintainer
release; do not create or merge a release PR, upload a crate, or deploy anything.

## Validate the candidate

Run from a clean Linux host checkout with the repository's development tools.
Native suites default locally to isolated Podman-launched inner fixtures. Admitted
hosted jobs explicitly verify/select outer Docker under the [canonical test-only
runtime](native-outer-runtime.md), without using its host daemon as the test subject
or mounting its socket into a guest. Fresh qualification remains required; the
hosted workflow supplies the privileged Linux environment.

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
PR gate. If `main` moves, a source edit is needed, or a required check fails,
repeat validation for the new complete candidate before publishing.

## Maintainer-only upload

Use the intended crates.io account with permission to publish this existing
crate. If initial local authentication is still needed, enter its token
interactively with `cargo login`; never paste it into an issue, a command
argument, shell history or a GitHub secret. Cargo stores it through the configured
local credential provider. Existing authentication is not permission for an agent
to publish.

The following assumes `candidate_sha` still holds the validated commit from the
previous section and the exact-candidate hosted release gate passed. Authentication
does not grant permission to publish a different candidate.

```sh
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
is a separate reviewed task, not a reason to put a local publishing token in GitHub.

Tell the BoxFerry integration task the published version and validated commit.
BoxFerry #343 must consume that registry version and rerun package and integration
checks; a temporary path dependency is not published-dependency verification.

## Maintenance ownership

The package allowlist and publication documentation add no dependency version or
operational pin. Renovate's existing Cargo manager continues to own declarations
and `Cargo.lock`; no extraction path is moved and no extra manager is needed.
Other workspace packages retain their existing protected release workflows. This
manual release procedure does not change their shared verification responsibilities.
