# Verification

Run `./scripts/format-lint.sh --fix` for local formatting and lint feedback.
Run `./scripts/check-all.sh --check` for the complete offline gate: format,
Clippy, unit and documentation tests, policy tests, and documentation build.
`--fix` runs the same checks after formatting. The VS Code task calls the fast
format/lint script; PR and main CI call the complete offline gate. PR checks
never run the privileged native matrix or claim native Engine evidence.

The native workflow lanes are `debian11-rootful`, `debian11-rootless`,
`upstream-rootful`, and `upstream-rootless`. Each has its own rootful outer Podman container, inner
Docker daemon and storage volume, and independent hosted CI job. Debian 11's
distribution `docker.io` package revision is asserted separately from the
Engine release reported by `/version`. Engine releases are matched exactly;
the Debian lanes allow only the Debian `+dfsg1` suffix, not a version prefix.
The rootless lane runs a rootless inner
daemon; rootless outer Podman nesting is not assumed.

Each lane reads live Engine API version, info, container, network, and volume
responses. The harness creates only synthetic test resources and stores live
responses in a private temporary directory. The Rust integration test checks
bounded capture decoding without writing responses to the repository or CI
log. A rootful `/info` response without affirmative mode evidence remains
`Unknown` in the decoder. The target conformance test independently checks
that exactly one inner `dockerd` has effective UID zero for rootful or nonzero
for rootless, and requires positive rootless `/info` evidence before using a
test-local mode fact for planning. The gate also requires #10's live acquisition
test and an independent `native_target` test of #12's rendered request shapes
against Engine behavior.
The latter first checks independently created CLI resources and direct API
responses, including TCP/UDP traffic, before admitting capabilities scoped to
#10's actual observation. It applies only three allowlisted inert POST shapes
inside the isolated test daemon and checks the resulting resources, traffic,
mounts, environment, command, health, and restart behavior. Decoder-only
fixtures cannot establish this evidence. Native compatibility remains unproven
until all lanes genuinely pass and their evidence is independently reviewed.

The Debian guests use one fixed official Debian Snapshot date, not the live
Bullseye mirror: the latter advertised the pinned `docker.io` package after
its file disappeared. The snapshot's signed metadata and package hashes remain
verified; only historical `Valid-Until` expiry is disabled. This proves a
historical Debian 11 package baseline, not current security support.

Run one lane with `./scripts/native-conformance.sh <lane>` on Linux with
rootful Podman through passwordless `sudo`, at least 8 GiB free, and access to
the pinned image manifests and Debian 11 snapshot. The script caps
the nested daemon at 4 GiB storage, 4 GiB memory, two CPUs and 512 processes.
It bounds the outer image pull to three minutes, checks free space before the
pull, monitors space during it, and forbids an implicit pull when starting the
outer container. Failure diagnostics show the exact native test, exit status,
numeric libtest summary, last fixed native check marker, and a closed
acquisition-error category where applicable. Daemon startup failures show
bounded container state and a classified startup category. Debian lanes also
show the last fixed APT stage, including a fail-closed `package_sources_unexpected`
category if the pinned image gains another APT source, plus signature, clock,
dependency and post-invoke failures. The Debian harness checks every requested revision in
APT metadata before install, and reports a fixed `package_version_unavailable`
category if a pin is absent. Failed installs also report bounded disk, lock,
dependency, download, or `dpkg` categories when recognized. The guest captures
the full install output in a temporary file, emits only a fixed category, and
removes the file on exit. Unknown failures report `package_apt_failure` without
printing APT output. Raw assertions, daemon logs, and API responses stay private.
It deletes its exact named container, volume, and temporary files after
success, failure, or catchable termination. SIGKILL, host failure, or hard
runner shutdown can prevent cleanup; inspect the printed exact names and
`io.dockerlens.native-run` labels before manual removal. Never global-prune.
Podman existence-query errors are not treated as absence: cleanup attempts
label-verified removal where possible, reads back exact resource absence, and
still fails the lane for review when absence cannot be verified.

Release validation checks the supplied full SHA against current `main`, runs
the complete gate, runs all four native lanes independently, then rechecks
current `main`. Its aggregate gate fails on any failed, skipped, or cancelled
job. There is no publication or deployment job. The four native lanes run on
main push and exact-candidate release validation, not on any PR. PRs run the
complete offline gate and their aggregate explicitly reports offline-only
evidence. Before marking the #13 harness PR ready, use the trusted-main
validation-only dispatcher below to run all four native lanes against its
exact reviewed draft head; passing PR CI alone is not native compatibility
evidence. The main-push and release native gates remain mandatory after merge.
Their time and resource budgets need review after genuine hosted runs. A lane
definition is not a compatibility claim until its native evidence passes.

The validation-only `Reviewed native validation` dispatcher is bootstrapped
before the #13 native suite. It does not make the still-failing release gate
pass or establish compatibility on its own. With the dispatcher on trusted
`main`, a maintainer can review the exact head and bounded native
harness of an open, same-repository PR (including a draft), set `pr_number`
and `reviewed_sha` to its number and full lowercase 40-character head SHA,
then run:

```sh
gh workflow run native-validation.yml --ref main \
  -f "pr_number=$pr_number" -f "expected_sha=$reviewed_sha"
```

The dispatcher requires current write/maintain/admin permissions for both the
original and rerun actors, validates the current PR head and repository identity,
runs the exact candidate's complete offline gate, and only then runs four
independent native lanes from that SHA. Each lane rechecks admission from
trusted `main` before candidate checkout, including when only one job is rerun.
The final aggregate fails if admission, offline checks, any lane, or the final
PR-head and actor recheck fails or is skipped. API uncertainty, including a
token that cannot read collaborator permissions, fails closed and must not be
bypassed. No PR event triggers this privileged workflow. It does not merge,
publish, release, or deploy. A draft PR stays unmergeable during validation;
after all four lanes genuinely pass, review the exact head and mark it ready
before applying ordinary required-check and mergeability rules. For #13,
its native script remains only in the candidate branch until its own
implementation is verified and merged.
Record the manual run URL and exact candidate SHA in the PR: the dispatch
runs on `main` and is not an automatic required check on the PR head.

The intended client platform is Linux. Mac client compatibility is not
validated by this scaffold. There is no macOS or Windows runner requirement.

The fake Unix-socket acquisition tests verify request framing, privacy,
deadlines, cancellation, and budget failures without a Docker daemon. The
ignored `live_read_only_acquisition_matches_oracle` test is invoked only by the
isolated native Engine harness. It reads that harness's explicit socket and
private direct-API oracle files to compare selected container, network, volume,
version, and mode semantics. A fake-socket pass is not rootful or rootless
Engine compatibility evidence.
