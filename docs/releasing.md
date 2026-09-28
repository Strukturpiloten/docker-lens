# First crates.io release

The maintainer performs the initial publication locally. DockerLens currently has
validation workflows, not a publisher, release-plz configuration, or automated
GitHub release creation. An agent must stop before publication and hand over the
verified commit, version, native validation run and remaining limitations.

## Readiness

Do not publish the scaffold. The first release requires DockerLens issues
[#13](https://github.com/Strukturpiloten/docker-lens/issues/13),
[#22](https://github.com/Strukturpiloten/docker-lens/issues/22) and
[#23](https://github.com/Strukturpiloten/docker-lens/issues/23) to be implemented,
reviewed and merged. Image publication, passing offline checks and successful
native runs on older PR heads do not satisfy this requirement.

For the final current-main candidate require:

- The complete offline gate and package verification below.
- Fresh successful exact-candidate `Release validation`, including all four
  independent native lanes and its fail-closed final aggregate. A failed,
  skipped or cancelled lane blocks publication.
- Reviewed positive public target profiles with immutable native evidence, and
  external-consumer checks of the typed observation and target APIs.
- A package version intentionally selected by the maintainer, with an available
  crate name/version on crates.io. The initial manifest proposes `0.1.0`; neither
  that proposal nor a failed registry lookup proves name availability.

## Validate the candidate

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
PR gate. If `main` moves, a source edit is needed, or a required check fails,
repeat validation for the new complete candidate before publishing.

## Maintainer-only upload

Create or sign in to the intended crates.io account, verify its email address,
and create a token permitted to publish the new crate. Enter it interactively;
never paste it into an issue, a command argument, shell history or a GitHub secret.
Cargo stores it through the configured local credential provider.

The following assumes `candidate_sha` still holds the validated commit from the
previous section and the exact-candidate hosted release gate passed. Authentication
does not grant permission to publish a different candidate.

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
BoxFerry #343 must consume that registry version and rerun package and integration
checks; a temporary path dependency is not published-dependency verification.

## Maintenance ownership

The package allowlist and publication documentation add no dependency version or
operational pin. Renovate's existing Cargo manager continues to own declarations
and `Cargo.lock`; no extraction path is moved and no extra manager is needed.
Other workspace packages retain their existing protected release workflows. This
one-time bootstrap does not change their shared verification responsibilities.
