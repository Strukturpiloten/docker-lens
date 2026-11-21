# Release validation and publication

DockerLens has a published 0.1.0 baseline, verified by ADR 0020. The DockerLens
integration owner selects the public API, version and release notes. The maintainer
approves crate publication in GitHub after the exact candidate has passed validation.

## Qualify the release candidate

Require reviewed product and downstream evidence under [DockerLens #31](https://github.com/Strukturpiloten/docker-lens/issues/31)
and [BoxFerry #343](https://github.com/Strukturpiloten/boxferry/issues/343). Preserve
the reviewed target profiles, complete local and package gates, external-consumer
checks and actual four-lane native evidence. Older runs do not qualify a new SHA.
DockerLens #127 and the held #128 track the hosted backend and renewed native
qualification. Enabling the publisher does not resolve that work.

Select a new stable crate version, update the manifest and lockfile together, and
finalize accurate release notes in one matching changelog section, such as
`## [X.Y.Z] - YYYY-MM-DD`. Merge and verify the exact final candidate on main.

Run from a clean Linux checkout with the repository's development tools:

```sh
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
```

Inspect the package listing for the declared boundaries in `Cargo.toml`. The
standalone workflow validates the same complete gate used by the Release caller.
It requires four independent native lanes, the published API baseline, shared
dependencies and a final current-main recheck. Failed, absent, skipped, cancelled
or mismatched prerequisites block the gate. Development API results cannot
substitute for the published baseline.

## Set up crates.io Trusted Publishing

Before registry activation, configure the existing GitHub `release` environment
to require TheRealBecks as its sole reviewer, disable administrator bypass, and
allow only the protected main branch through its custom branch policies. Remove
any tag policies. Trusted Publishing binds the workflow filename and environment,
so these carrier settings must also protect against a workflow definition on a tag.
The job checks the live settings and the maintainer's approval record on its first
attempt.

The registry owner then verifies or creates a [crates.io Trusted Publisher](https://crates.io/docs/trusted-publishing)
for crate `docker-lens`, GitHub owner `Strukturpiloten`, repository `docker-lens`,
workflow `release.yml`, environment `release`. The crate owner's settings hold
that registration. The shared publisher uses OIDC after approval and requires
no stored registry token.

## Request validation or maintainer approval

From GitHub's **Release DockerLens** workflow, choose main and supply the full
SHA and finalized package version. Keep `validation_only=true` for a dry run that
also checks notes and the crate inventory. Crate publication requires a separate
explicit dispatch with `validation_only=false` on the qualified candidate.

In a publishing run, wait for full validation and for the publish job to request
approval. Give the maintainer the run URL, version, exact commit and notes shown
in the run summary. The maintainer reviews these values and uses **Review
deployments** for the `release` environment. After approval the job checks the
live main SHA, version and notes again before using Trusted Publishing. If main
advances, an input differs, approval cannot be verified, or a required step fails,
use a fresh reviewed run on the intended candidate.

The shared publisher verifies registry visibility after upload. If the version
already exists, retain upload evidence or independent artifact provenance before
associating it with this candidate. Git tags and GitHub release records are
separate maintainer operations. Hand the published version and verified commit
back to BoxFerry for registry-dependency verification.
