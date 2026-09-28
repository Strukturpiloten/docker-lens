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
#10's actual observation. It applies only three allowlisted POST endpoint kinds
inside the isolated test daemon and checks the resulting resources, traffic,
mounts, environment, command, health, and restart behavior. Decoder-only
fixtures cannot establish this evidence. Native compatibility remains unproven
until all lanes genuinely pass and their evidence is independently reviewed.

The target conformance test lives in `src/native_target_tests.rs` under
`#[cfg(test)]`; the exact-name runner selects its single ignored library test.
This lets the isolated harness use the crate-private scoped-fact validator
without exposing a public way to manufacture positive planning capabilities.
The module is included by the crate's `src/**` package rule but has no runtime
effect in a published library build. After its shape-specific assertions pass,
the test writes a private closed shape list. The manifest emitter checks that
list against the full catalog admission set before declaring positive outcomes.

The Debian guests are maintained test images published by containers#260.
Each contains native docker.io 20.10.5+dfsg1-1+deb11u2; the harness checks
that installed package revision separately from /version. The upstream
images contain Engine 29.8.1. No lane installs packages at runtime. Debian 11
is a historical compatibility baseline, not current security support.
The Debian rootless image needs --oom-score-adj=0 on its privileged rootful
outer Podman container for nested workloads. All lanes explicitly disable
AppArmor for that already-privileged outer container only; the harness does
not change host policy. The Debian rootless lane additionally mounts its
task-owned outer data-root volume with suid,dev. Controlled independent CLI
probes showed the historical runc could not start a read-only named-volume
container when that outer mount instead had nosuid,nodev. The harness checks
the effective mount flags before native tests. The other three lanes keep
their default volume options.

Run one lane with ./scripts/native-conformance.sh <lane> on Linux with
rootful Podman through passwordless sudo, at least 8 GiB free, and access
to the pinned GHCR and BusyBox manifests. The script caps the nested daemon
at 4 GiB storage, 4 GiB memory, two CPUs and 512 processes. It bounds the
outer image pull to three minutes, monitors space during it, and prevents an
implicit second pull. The image's native launcher starts a Unix-socket
daemon. The harness binds a second Unix socket at `/dockerlens-native` into
its private temporary directory for explicit, local-only capture and requires
a host-side `/_ping` before proceeding. This path stays outside the rootless
launcher's `/run` copy-up. It exposes no TCP daemon port. The synthetic bind
fixture is writable inside this task-private directory so the rootless mapped
UID can exercise the rendered read-write bind mount. The separate read-only
bind assertion therefore tests mount behavior independently of host ownership.

Every image declares a Docker data-root VOLUME. The harness disables
automatic image volumes and mounts exactly one task-labeled named volume at
the declared data root. It checks the mounted volume after launch; an
unexpected anonymous or extra volume fails the lane. A watchdog bounds
storage use and free space. This isolated nesting setup does not demonstrate
compatibility with restrictive data-root mount flags or an enforcing outer
AppArmor profile. Failure diagnostics show the exact native test,
exit status, numeric libtest summary, fixed native marker, and closed
acquisition-error category where applicable. Daemon startup failures show
bounded container state and a fixed category. Raw daemon logs and API
responses remain private; unknown failures are unclassified. The read-only
volume shape uses fixed phase and write-exit-category markers to pinpoint
failures without publishing daemon responses or volume contents. Its
API-created container uses the independent CLI start probe to report both a
closed component category and a separate closed errno/reason token for a
failed start before checking the live read-only mount behavior.

After all three native Rust tests pass, a workflow lane writes one
sanitized JSON manifest containing the exact candidate SHA, image
tag and digest, observed Engine release and advertised API bounds, the
selected acquisition API, rendering API, reported containerd and runc
component versions, daemon mode, installed Debian
package revision where applicable, and the ten tested target capability
names and the closed renderer shapes exercised by the target test. Acquisition
selects at most API 1.49 even if the daemon advertises
a newer API; rendering uses the observed advertised API. The workflow
uploads only this JSON as dockerlens-native-<lane>, with a fixed <lane>.json
filename. Artifact upload failure fails the lane. A reviewer must bind
the exact artifact bytes, run attempt, and candidate SHA before adding
positive catalog evidence. No local harness definition or green offline
check creates that evidence. The manifest records Engine identity and tested
shapes, not outer mount or AppArmor settings; the reviewed exact-candidate
harness and genuine passing lane run must establish those test conditions.
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

## Reviewed target-profile records

The catalog remains empty until the four native lanes produce genuine reviewed
evidence. A proposed record must conform to
[`native-evidence.schema.json`](native-evidence.schema.json). Its lane and exact
identity bind the distribution package revision (or upstream origin), reported
Engine release, advertised maximum API, negotiated acquisition API, tested
rendering API, and rootful or rootless mode. The run URL includes the attempt
number. `candidate_sha` names the source tree actually executed by that run.
`native_manifest_artifact_name` identifies the run's per-lane artifact;
`native_manifest_sha256` is the SHA-256 of its sanitized JSON manifest
emitted by the native harness after success; that manifest contains observed
image, package, runtime, API, and capability outcomes, without captured user
or daemon values. The proposed record lists each capability and the specific
request shapes its native test admitted. A generic successful lane does not
authorize every shape of a capability.

The #13 artifact is named `dockerlens-native-<lane>` and contains exactly
`<lane>.json`. Its fixed metadata includes the image tag and digest, actual
Engine release and maximum/minimum APIs, negotiated acquisition and rendering
APIs, Debian package revision where applicable, containerd/runc component
versions when reported, and the ten tested capability outcomes. Keep the
manifest bytes available for independent digest verification.

For the initial Debian 11 lane, the record must name the `docker.io` package in
the `debian11` distribution at revision `20.10.5+dfsg1-1+deb11u2`, with
reported Engine `20.10.5+dfsg1` and all three API dimensions at 1.41. The
upstream lane is limited to Engine 29.8.1; its API values must come from the
run. A positive catalog fact requires every closed renderer shape for its
capability. In particular, `PortPublish` requires separate fixed TCP and UDP
evidence, named volumes require create and both mount access modes, and restart
policy requires all four variants including limited and unlimited on-failure.
Any untested shape leaves that entire capability unadmitted. The #13 manifest's
coarse `capability_outcome` alone cannot fill `admitted_shapes`; reviewers must
trace each claimed shape to native assertions in the exact run. Unsupported
`HostNetwork` and `UserNamespace` cannot become positive catalog facts.

After independently checking the run, lane result, candidate SHA, native
manifest digest and fields, review the proposed record and preserve its exact
UTF-8 bytes in the repository. Compute SHA-256 over those bytes; that digest is
the catalog's `CapabilityEvidenceKey`. The digest is deliberately outside the
record, avoiding a self-reference. The public `NativeEvidenceReference`
retrieves the source run, candidate, native manifest digest and record digest
for an admitted profile. Its constructor checks only syntax and cannot add a
catalog entry. A checked-in historical native run can establish source
evidence for a later catalog commit; the final catalog candidate still needs
its own complete checks and native validation. Never substitute the historical
source SHA for the final candidate SHA or infer an API version from a release
label. Public resolver and rendering tests should be enabled only after exact
records are reviewed and added.
