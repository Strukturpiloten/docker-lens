# Release validation and publication

DockerLens uses the published 0.1.0 baseline under [ADR 0023](decisions/0023-development-and-published-api-checks.md). The DockerLens
integration owner selects the public API, version and release notes. The maintainer
approves crate publication in GitHub after the exact candidate has passed validation.

## Qualify the release candidate

Require reviewed product and downstream evidence under [DockerLens #31](https://github.com/Strukturpiloten/docker-lens/issues/31)
and [BoxFerry #343](https://github.com/Strukturpiloten/boxferry/issues/343). Preserve
the reviewed target profiles, complete local and package gates, external-consumer
checks and actual four-lane native evidence. Older runs do not qualify a new SHA.
The [migration ledger](standalone-migration-ledger.md) retains the
application-derived consumer obligations, including [ADR 0012](decisions/0012-candidate-volume-label-admission.md).
A small consumer smoke test cannot establish application acceptance. Native
qualification and publication approval remain separate.

Select a new stable crate version, update the manifest and lockfile together, and
finalize accurate release notes in one matching changelog section, such as
`## [X.Y.Z] - YYYY-MM-DD`. Merge and verify the exact final candidate on main.

Run from a clean Linux checkout with the repository's development tools.
The isolated native harness uses local outer Podman and admitted hosted outer
Docker, with [explicit backend selection](native-outer-runtime.md).

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

The existing GitHub `release` environment requires TheRealBecks, allows `main`
and `v*` tags, and permits administrator bypass. This workflow admits only
`refs/heads/main` and verifies the live reviewer and approval. Environment
settings also apply to workflow definitions on other eligible refs. Trusted
Publishing binds the workflow filename and environment. Before activation,
verify an enforceable control that limits every definition eligible for this
registration to the reviewed publishing policy, including those reachable
through tag creation and administrator access. The main workflow's own ref
check does not restrict other definitions.

The [crate owner settings](https://crates.io/crates/docker-lens/settings) hold
the [Trusted Publisher registration](https://crates.io/docs/trusted-publishing).
A crate owner must verify or configure crate `docker-lens`, GitHub owner
`Strukturpiloten`, repository `docker-lens`, workflow `release.yml` and
environment `release`. A future enabling change would use the shared publisher
and request OIDC only after the verified personal approval and final recheck.

## Request validation or maintainer approval

From GitHub's **Release DockerLens** workflow, choose main and supply the full
SHA and finalized package version. Keep `validation_only=true` for a dry run that
also checks notes and the crate inventory. Publication is currently unavailable.
The `validation_only=false` path checks approval evidence after the same
candidate validation and terminates before registry authentication. Any hosted
approval exercise needs its own authorization.

In an authorized approval exercise, wait for full validation and for the approval
job to request review. Give the maintainer the run URL and the version, commit and notes from
the run summary. In **Review deployments**, the maintainer selects `release`,
copies the exact **Release approval comment** from the summary and chooses
**Approve and deploy**.

GitHub's [review history](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run)
gives the reviewer, environment ID, state and comment for a run. The workflow
requires one approved record for `release` from TheRealBecks with the exact
first-attempt comment. The same schema carries no attempt or bypass marker,
and GitHub accepts comments for both UI actions. Even a matching history row
cannot demonstrate which action was taken from that schema alone.

Before enabling registry access, establish an authenticated source that
distinguishes a genuine approval from administrator bypass and binds it to the
exact run, attempt and environment. The workflow currently rechecks live main,
version and notes after reading the approval record, then refuses publication.

Once enabled, the shared publisher verifies registry visibility after upload. If the version
already exists, retain upload evidence or independent artifact provenance before
associating it with this candidate. Git tags and GitHub release records are
separate maintainer operations. Hand the published version and verified commit
back to BoxFerry for registry-dependency verification.
