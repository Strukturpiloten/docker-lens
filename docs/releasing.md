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

## Existing crates.io Trusted Publishing

The maintainer adopted [ADR 0024](decisions/0024-protected-crate-publication.md)
for DockerLens under the existing settings. The owner confirmed crate
`docker-lens`, GitHub owner `Strukturpiloten`, repository `docker-lens`, workflow
`release.yml`, environment `release`. The registration is owner-confirmed and
independently API-unavailable. No settings change or private registry API proof
is required for this caller.

The live environment ID is `22952362673`, requiring TheRealBecks (user ID
`1497405`). It permits administrator bypass and admits main and `v*` tags.
GitHub review history cannot distinguish ordinary approval from bypass. The
registry registration has no Git-ref filter; other eligible definitions on tags
remain outside this main-only caller's guard. The maintainer explicitly accepts
both limits. Settings remain unchanged.

## Request validation or maintainer approval

From GitHub's **Release DockerLens** workflow, choose main and supply the full
SHA and finalized package version. Keep `validation_only=true` for validation
and credential-free inventory without requesting protected environment admission.
For a separately authorized publication choose `validation_only=false`. Only a
first-attempt dispatch from protected current main can reach the protected job,
after complete offline, dependency, published API and all four native checks.

Wait for full validation and the approval job's review request. Give the
maintainer the run URL and the version, commit and notes from the run summary.
In **Review deployments**, the maintainer selects `release`, copies the exact
**Release approval comment** from the summary, then chooses **Approve and deploy**.
The statement binds the run ID, attempt 1, full SHA, version and extracted notes
SHA-256. Agents must never approve or override the deployment.

The job requires exactly one matching approved history record for the verified
environment from that personal account. Missing, stale, conflicting or ambiguous
records fail closed. It rechecks protected live main, clean source, version and
notes after approval, then calls the manifest-pinned shared publisher. OIDC is
scoped only to this job; the publisher obtains credentials after its own inventory
and exact-gate checks. A rerun is refused: use a fresh authorized dispatch and
new human review. If main moves, qualify its new exact SHA first.

The protected publication job has a 45-minute bound, matching the established
Rust callers. After an interrupted upload, check canonical registry visibility
and artifact identity before authorizing a fresh dispatch; a timeout is not
evidence that upload failed.

The shared publisher retains idempotency and waits for canonical registry
visibility after upload. If the version already exists, retain upload evidence
or independent artifact provenance before associating it with this candidate.
Record source activation/integrated qualification separately from the first
real publication run, human approval and registry evidence. Tags and GitHub
releases are separate maintainer operations. Hand the published version and
verified commit back to BoxFerry for registry-dependency verification.
