# Verification

The complete inert review artifact has offline exact-byte, schema, order,
privacy, context-binding, and fail-closed opaque-artifact tests. These verify
serialization, not destination existence, data migration, or native Engine
compatibility. See [the version 1 format](complete-artifact.md) and
[ADR 0009](decisions/0009-complete-inert-artifact.md).

Run `./scripts/format-lint.sh --fix` for local formatting and lint feedback.
The target-module checkpoint has an exact network request regression alongside
the existing container and graph tests. These offline checks preserve the
0.1.0 contract; they do not prove new migration shapes or native compatibility.
The typed-network offline cases exercise create/external separation, multiple
attachment request order, alias and IPAM encoding, redacted prerequisites,
invalid topology, missing capabilities and the API floor. The #31 negative
cases for overlapping IPAM pools, subnet-base and broadcast gateway/auxiliary/
static addresses, and static-address collisions are offline library-policy
rejections before any Engine request. IPv4 `/31` and `/32` bridge parent subnets
remain an explicit planning rejection; this extension does not establish their
Engine behavior on any API or daemon mode.
For native assertion failures, the exact-test wrapper may expose the selected
native test's fixed source basename and bounded numeric line/column. It does not
print the assertion message, compared values, thread name, or absolute build
path. The location is diagnostic only and never changes a failed outcome.
The CLI network oracle also emits only its closed create/inspect/assert phase
and, on a failed command, a closed exit and stderr category. Native stdout and
stderr are bounded independently to 8 KiB; raw bytes remain private. A category
such as a disabled firewall identifies a failure to investigate, not permission
to skip the assertion or admit an unsupported result as positive evidence.
Before creating run-owned resources, the canonical native harness requires the
host `br_netfilter` module and both `bridge-nf-call-iptables` and
`bridge-nf-call-ip6tables` to read back as `1`. Already-ready hosts need no
load. Local, unknown, and other untrusted environments perform read-only
checks and fail if a prerequisite is absent or disabled. Only a positively
identified GitHub-hosted Linux `native-conformance` job for this repository on
trusted `main` push or workflow dispatch may attempt only
`sudo -n timeout --signal=TERM --kill-after=2s 10s modprobe br_netfilter`;
the root-owned timeout bounds that exact module load, and the helper then
requires the same readback. A separate outer deadline is only a fallback:
an unprivileged runner cannot necessarily signal sudo's root process group.
These environment values prevent accidental local mutation, not impersonation by a
root caller. The harness never changes sysctls, unloads modules, installs
packages, changes forwarding policy, or treats the host check as proof of the
inner daemon's network behavior. Failures expose closed categories, not
subprocess output. This bounded prerequisite does not relax any native test.
On a failed edge-side DNS positive, the network test may create one exact
run-owned diagnostic peer. Its closed summary distinguishes resolver setup,
default/explicit/dotted A lookups, named/direct-IP HTTP and cleanup without
exposing daemon output. Optional probes respect the exact runner's 180-second
deadline, reserve cleanup/reporting time and cannot turn the failed positive
into a pass. A timeout before the failure branch may prevent any summary;
SIGKILL or host failure can prevent cleanup. No retry or diagnostic result
establishes compatibility without the original assertion passing.

The native #31 network test uses an independent Docker CLI bridge oracle,
direct Engine GETs, an externally seeded bridge, and test-only application of
the inert renderer requests. It checks two rendered network creates, ordered
secondary connects, per-network alias DNS and traffic, static IPv6 peer traffic,
bridge-interface MTU, and the unchanged external network identity. Isolation
uses separate backend-only and edge-only CLI peers: each positive local DNS
control explicitly queries the IPv4 A record and checks an exact parsed answer
for the inspected endpoint IPv4, excluding the resolver's address and partial
matches, before local HTTP succeeds. Each DNS oracle verifies the peer's embedded
resolver configuration and queries `127.0.0.11` explicitly. The isolation
fixtures are distinct, running, single-network peers with canonical inspected
IDs and distinct IPv4 addresses. Both carry the literal `edge-sentinel` alias;
from each peer, an absolute A query to the embedded resolver must contain the
complete named answer set of exactly that peer's inspected IP, with no extra,
foreign, malformed, or truncated answer. Named HTTP to the shared alias must
return distinct local canary bodies, and backend-to-edge direct-IP HTTP must
still fail. Ordinary unqualified named HTTP for rendered app aliases remains
a separate positive traffic check. This proves collision-scoped local alias
selection and route isolation, not unshadowed `NXDOMAIN` or all DNS-forwarding
behavior. Run `36504139504` observed Debian rootful `cli_resolver/other/other`
for an unshadowed foreign-name query on the internal backend. That closed
result did not prove either forwarding or an alias leak, and no timeout is
accepted as isolation success. Collision failures expose only fixed-category
diagnostics from bounded CLI output. A dual-homed app's edge IP is not an
isolation oracle. Closed DNS and HTTP markers distinguish each stage. The
executor allows only the run-owned network and
container names, including exact `networks/{id}/connect` paths. The separate closed
`network_probes` manifest field retains the original nineteen network renderer
shapes and appends `NetworkBridgeIccDisabled`,
`NetworkBridgeMasqueradeEnabled`, and `NetworkCreateLabelsValueDomain` only
after the exact ignored test passes; these three added markers do not extend
`admitted_shapes`, catalog capabilities, or a compatibility claim. IPAM fields,
labels, masquerade and host-binding options have request/inspect checks, not
independent kernel-behavior proof. Matched control bridges differ only in ICC;
both have independently healthy same-bridge peers, with the same direct-IP
inter-peer HTTP probe succeeding when enabled and failing when disabled. This
uses no external DNS or Internet dependency. Both
masquerade values are accepted and inspectable, but this does not prove their
routing or NAT effect. Representative empty and non-ASCII/escaped network-label
values are checked through independent CLI and inert-rendered creates and Engine
inspects; this does not prove every key or length boundary.
The separate ignored internal-network proof gets its own 180-second bound after
the general network test. It compares independently CLI-created bridges with
matched inert requests sent to Engine, then checks direct Engine inspect values.
The rendered internal and ordinary bridges both enable ICC and masquerade; their
single-homed peers must each have healthy same-bridge HTTP. A task-owned BusyBox
HTTP sidecar and the nested Docker daemon attach to one separate outer Podman
bridge with distinct private IPv4 addresses and network namespaces. The ordinary
peer must fetch the sidecar by direct IPv4 before and after the internal peer
fails to fetch that same address. The sidecar is not in the inner Docker host
namespace: traffic from inner bridges crosses Docker's FORWARD path. No public
Internet or DNS result is involved. Sidecar setup failures expose only closed
phases, error categories, and a fixed canary-write stage. A successful write-stage
marker proves only that the health file was written, not that HTTP started or
that the permission text came from the sidecar rather than the Podman logs query.
The HTTP document root contains only the synthetic canary. Private httpd stderr
is captured outside that root with owner-only permissions, capped at 8 KiB or
less by a checked file-size limit in the HTTP process subshell, and removed
on exit. Supported shells use 512-byte or 1-KiB limit units; neither can exceed
that cap. Limit setup failure prevents HTTP startup and fails the lane.
A unique, exact closed cause marker from a nonzero httpd return takes precedence
over unrelated Podman logs-query errors;
missing applets and shell errors remain distinct causes. Missing, conflicting,
or malformed cause markers do not establish an attributed cause. These
diagnostics preserve sidecar privileges and cannot turn a failed lane into
positive network evidence.
A panic-time inner cleanup attempt separately reports a closed pass/fail result.
Neither marker prints native output or turns a failed lane into evidence.
A positive ordinary-bridge control and a blocked internal
probe are both required independently; reachable internal traffic fails the
proof even when all request and inspect fields match.
The negative HTTP probe requires a successful Docker exec carrying a fixed
`blocked` result from the running peer, with the control fetching the exact
canary again afterward. Outer command timeouts and Docker exec failures cannot
count as blocked traffic. Every proof operation reserves time for bounded
label-verified cleanup within the 180-second runner deadline. Failed removals
stay in the cleanup ledger for a retry, and only an exact direct Engine 404
clears an uncertain resource. Only after the live assertions and verified
cleanup does the test
replace the private network probe file with a closed positive shape result.
The manifest emitter rejects a missing, negative, malformed, oversized, or
symlinked result; a valid result adds `NetworkInternal` and its sole
`InternalBridgeNetworkCreate` shape to raw lane evidence. The separate reviewed
#68 cohort below admits only that singleton internal-network group; original
historical evidence remains unchanged. This test adds no dependency, image,
action, or tool pin,
so Renovate extraction and ownership need no change.
The three option/label additions remain non-admission evidence, and the historical nineteen
names and manifests are unchanged. IPv4 `/31` and `/32` bridge parents remain
rejected by planning, independent of any Engine acceptance behavior.
The typed-container offline regressions cover exact grouped `PortBindings`
and `ExposedPorts` bodies, host-IP privacy, wildcard conflicts, ephemeral
allocation requests, command/entrypoint inheritance and clearing, shell and
disabled health, timing, metadata, tmpfs, and runtime settings. Command clear
with an inherited or cleared entrypoint fails intent validation; only an
explicit exec entrypoint plus clear command reaches capability-gated inert
rendering. This candidate is not a native clear claim. These are local contract
tests only. #31's independent native assertions must check
resulting loopback and IPv6 exposure, repeated/dynamic assignments, mount
access, process identity, health behavior, and resource/security outcomes in
each claimed mode and API. `StartInterval` needs exact native support and a
1.41 negative boundary before any catalog admission; no generic introduction
floor is inferred from Compose documentation.
Run `./scripts/check-all.sh --check` for the complete offline gate: format,
Clippy, a locked all-target check under the minimum Rust release declared by
`Cargo.toml`, unit and documentation tests, policy tests, and documentation build.
The MSRV check installs the exact official Rust distribution through rustup
when it is not already available; its failure stops the gate. PR, main,
validation-dispatch, and release workflows all call this same gate.
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

The #28 selector and typed-observation fixtures are offline contract checks.
The separate ignored `live_network_membership_matches_engine` native test runs
after the existing selector test and before evidence emission. It creates two
exact run-labelled active peers on the owned bridge, acquires only one exact
container ID, and compares protected typed membership to direct network GETs
before and after acquisition. The unselected peer must not gain a container
inspect request. After stopping that peer it repeats the comparison to the
actual Engine response without assuming that stopped peers remain listed.
Only successful assertions and verified fixture cleanup append
`NetworkActiveMembership`, `NetworkStoppedMembershipBoundary`, and
`ContainerInspectIdOracle` to the sixteen baseline source probes. The last
marker follows comparisons of the protected container inspect ID with both the
canonical narrowed-selection request ID and the direct inspect `Id` for exact
ID, name, prefix, and label selectors. The emitter requires all nineteen; a
failure cannot emit partial source evidence. These are source-observation
checks, not ownership, atomic-snapshot, or target-capability admission. All
four exact lanes still require genuine passing runs and independent review
before compatibility claims.
They cover protected predicate replay closure, canonical list identities,
inspect response binding (including network-name fallback), explicit resource
roots, typed inspected network IDs distinct from fallback names and empty
endpoint IDs, and effective user namespace availability. Offline decoder tests
cover the typed container ID's runtime origin, privacy, and fail-closed invalid
identity cases, while a matching noncanonical caller-assembled capture remains
accepted; acquisition tests retain the four-request narrowed-name path.
The network-inspect membership fixtures additionally check protected canonical
container-ID keys, entry versus `Name` availability, the 4096-entry bound,
malformed-value diagnostics, and an unselected active member that does not
expand container inspection. These are pure decoder contracts, not proof of
Engine behavior. Independent source proof must compare a selected and an
unselected active attachment, then a stopped-peer boundary, against direct
network-inspect responses in all four exact lanes. A stopped peer's absence
from an active snapshot cannot establish that no other resource is shared.
They do not extend reviewed profile claims until fresh independent native tests
cover each new source shape on the exact versions and daemon modes.

The #31 source test runs after the harness creates a selected container, a
decoy, and a separate two-loopback-binding port fixture in the same isolated
daemon. It checks discovery names, labels, and image, exact ID and name,
shorter literal prefix, label, explicit-all, and exact network and volume
roots against direct Engine GET oracles and fixed CLI fixture settings. The
Compose-style project label remains advisory metadata. Narrow selectors must
never inspect unrelated containers. The test checks exact host IPs and both
bindings, selected identity, mounts, environment, health, restart, and the
origins and availability of selected effective and runtime-assigned fields.
Offline tests retain exhaustive missing, null, empty, and redacted boundary
coverage; the native source list claims only the fields it asserts.
The lane manifest records an exact closed `source_probes` list only after this
ignored test passes; it contains no native values and does not add target
capability admissions. Existing reviewed manifests and the reviewed catalog
remain historical evidence for their original shapes. The new assertions need
genuine runs in all four exact lanes before a source compatibility claim.

The source test's `DaemonResourceSupportOracle` assertion compares typed
`MemoryLimit` and `SwapLimit` reports with the already saved independent direct
`/info` response. It reuses the existing acquisition, checks effective origin,
independent boolean/unavailable states, matching capture scope and rejection of
another capture's scope, and adds no request. Reported false stays bounded
source-environment evidence; true stays available but unverified, even when
separate effect evidence fails. Missing, null and explicit redaction remain
unknown. Neither the assertion nor its closed marker proves enforcement or
adds a capability or admitted shape. The baseline list contains the original
fifteen markers plus this new marker; membership completion retains its three
markers, and the emitter rejects the old eighteen-marker list. Historical
reviewed evidence bytes and catalogue admission remain unchanged. These are
new assertion definitions: genuine passing four-lane exact-candidate runs and
independent review are still required before source compatibility is claimed.
The direct oracle and acquisition are separate observations in time; matching
capture identity correlates typed evidence, not authentication or an atomic
snapshot. Offline helper tests check classification and value-free rejection
only. No operational pin or Renovate extraction path changes are introduced.

The created-volume label probe is a separate exact ignored library test,
`native_volume_label_tests::live_created_volume_labels_match_engine`. Each lane
runs it before manifest emission and reads its private, bounded
`NATIVE_VOLUME_LABEL_PROBES_PATH` file. The manifest records only the closed
`volume_label_probes` names: `VolumeCreateLabels`, `VolumeLabelInspect`,
`VolumeLabelPersistence`, and `VolumeLabelOwnershipCleanup`. These markers
alone are non-admission evidence; only independently reviewed complete lane
records can add `VolumeLabels` / `VolumeCreateLabels`. The bounded #49
candidate cohort below enables pre-merge rehearsal, not production clearance.
Native compatibility still requires genuine passing lanes and independent
review of the exact candidate evidence.

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
fixtures cannot establish this evidence. Native compatibility claims require
genuine passing lanes and independently reviewed evidence for the exact scope.

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
outer Podman container for nested workloads. This lane explicitly disables
AppArmor for that already-privileged outer container only; the harness does
not change host policy. The Debian rootless lane additionally mounts its
task-owned outer data-root volume with suid,dev. Controlled independent CLI
probes showed the historical runc could not start a read-only named-volume
container when that outer mount instead had nosuid,nodev. The harness checks
the effective mount flags before native tests. The other three lanes keep
their default volume and AppArmor options. Their independent native runs
must pass with that unchanged setup; the historical lane's requirements
do not authorize broadening the other lanes' configuration.

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

All three harness curl sites (readiness polling, the final readiness check and
the direct API GET helper) use first-option `-q` and literal `--noproxy '*'`.
This disables default curl configuration and proxy routing for the existing
explicit Unix-socket requests, without changing executable selection, inherited
environment, URLs, request counts, limits, startup cadence, privileges or cleanup.
Offline fake-client regressions check complete argv and nonzero invocation counts
for each site, including the final readiness fallback and native/status failures.
They neither diagnose historical failures nor establish native or release evidence.

The canonical harness continues to serve local execution, `check.yml` main push,
`native-validation.yml` reviewed dispatch and `release-validation.yml` exact-main
dispatch. Renovate's original native-image manager still uniquely extracts the
same five image/fixture tag-and-digest pairs; its paths, grouping and approvals
need no edit. BoxFerry's frozen producer receipt and script-digest catalogue binding
remain unchanged: adopting a revised harness source separately requires an explicit
consumer contract or a new independently verified producer build and receipt, not a
hash-only refresh.

Every image declares a Docker data-root VOLUME. The harness disables
automatic image volumes and mounts exactly one task-labeled named volume at
the declared data root. It checks the mounted volume after launch; an
unexpected anonymous or extra volume fails the lane. A watchdog checks the
owned volume and Podman storage every five seconds. It retries failed `du` or
`df` measurements at most twice, one second apart, to tolerate disappearing
overlay paths during traversal. Both measurements still run on each attempt,
and any measured volume above 4 GiB, free space below 2 GiB, or elapsed time
above 30 minutes terminates the lane immediately, even if that measurement's
command also reported a traversal error. Persistent command errors
and malformed measurements also terminate it with fixed reason markers;
raw measurement paths and command errors are suppressed. The normal
ownership-checked cleanup then runs. This isolated nesting setup does not
demonstrate compatibility with restrictive data-root mount flags or an
enforcing outer AppArmor profile. Failure diagnostics show the exact native test,
exit status, numeric libtest summary, fixed native marker, and closed
acquisition-error category where applicable. Daemon startup failures show
bounded container state and a fixed category. Raw daemon logs and API
responses remain private; unknown failures are unclassified. The read-only
volume shape uses fixed phase and write-exit-category markers to pinpoint
failures without publishing daemon responses or volume contents. Its
API-created container uses the independent CLI start probe to report both a
closed component category and a separate closed errno/reason token for a
failed start before checking the live read-only mount behavior.

After every required native Rust test passes, a workflow lane writes one
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
The validation-only `scripts/native-presence.py` helper gives preflight and
cleanup a closed `present`/0, `absent`/1, `unknown`/2 protocol. Only an actual
completed native exit 0 or 1 with completely empty combined stdout and stderr
proves presence or absence. Warnings (including exit 0), diagnostics on exit 1,
other exits, timeout, cancellation, overflow or unverified group termination
are unknown. The helper streams into private mode-0600 evidence with a combined
16 KiB cap, observes exit without reaping the group leader, then terminates its
group and verifies teardown before classifying. The helper and its outer
timeout share the Podman client's root privileges where sudo is used. A separate
six-second timeout with a two-second kill fallback bounds the actual client
inside its teardown group, even if the helper is killed.
This applies to the daemon container, sidecar, network and volume, including
all positive absence readbacks and generated-name preflight. The existing inner
Docker exact-name cleanup listing uses the same helper: only completed empty
exit 0 on both streams establishes absence. No query or mutation is added.
Unknown presence retains the private run directory for manual review, attempts
label-verified removal where possible, and fails teardown even when later
readback succeeds. Raw diagnostics never reach logs. Mocked regression tests
exercise these outcomes without launching a native runtime; they establish no
new compatibility or capability admission.
Each cleanup command retains its eight-second deadline and two-second kill
fallback; for elevated Podman the timeout also runs under sudo so it can signal
the root-owned client. Only a task-named container with the matching run label
is removed with `--force --time 0`: Podman's default ten-second stop grace
otherwise exceeds that command budget. The daemon container and sidecar are
removed before their exact network and data volume, which are never force-removed.
Removal errors expose closed categories, with raw Podman output suppressed.
The success summary is printed only after all cleanup and absence readbacks
pass; a manifest written earlier is not passing lane evidence by itself.

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

DockerLens [#42](https://github.com/Strukturpiloten/docker-lens/issues/42)
owns the canonical reviewed-PR admission script. With `EXPECTED_REPOSITORY`
absent, it retains DockerLens's native-validation repository policy. A trusted
workflow may set literal `EXPECTED_REPOSITORY=Strukturpiloten/boxferry` when
BoxFerry application validation invokes an immutable DockerLens commit
checkout; the event repository, open PR's head and base full names and numeric
IDs, and both actors must then all match BoxFerry. Unknown values and CLI
arguments are rejected before any API request. BoxFerry
[#369](https://github.com/Strukturpiloten/boxferry/issues/369) owns the
immutable consumer pin and manual-review `github-digest` Renovate ownership;
this producer change adds no pin or native workflow gate. Both consumers need
independent validation before the shared admission rollout is complete. This
helper never admits a release or publication operation.

The intended client platform is Linux. Mac client compatibility is not
validated by this scaffold. There is no macOS or Windows runner requirement.

The fake Unix-socket acquisition tests verify request framing, privacy,
deadlines, cancellation, and budget failures without a Docker daemon.
`tests/acquisition_backlog.rs` adds Linux-only full-listener-queue controls:
retained real filler connections and a separate fresh nonblocking admission
prove saturation before deadline and pre/pending-cancellation assertions.
An unlistened bound socket remains a terminal I/O failure. Successful HTTP
controls cover both immediate admission and eventual admission after a delayed
drain of the counted fillers. Each fixture uses an exclusively created private
directory, owns its descriptors and threads, bounds completion and joins only
finished threads, and checks recorded directory/socket identities before exact,
nonrecursive cleanup, including on assertion failure. Unverified worker
termination or replaced resources preserve the fixture and fail cleanup.

Linux AF_UNIX queue saturation is retried using fresh nonblocking sockets with
backoff bounded by the remaining deadline and the existing 100 ms cancellation
interval. Blocking mode is restored only after successful admission. Other Unix
platforms retain their existing timeout-connect path; this is not new macOS
validation. These controls neither contact nor authenticate an Engine, and do
not replace the complete and exact-candidate four-lane native gates.

The existing Renovate native `cargo` manager owns the unchanged `Cargo.toml`
socket2 `=0.6.5` declaration and its lockfile resolution. This transport change
adds no dependency, software pin, extraction path, shared gate definition, or
manager; no Renovate or lockfile edit is needed. Rust 1.85 remains the MSRV.

The ignored `live_read_only_acquisition_matches_oracle` test is invoked only by the
isolated native Engine harness. It reads that harness's explicit socket and
private direct-API oracle files to compare selected container, network, volume,
version, and mode semantics. A fake-socket pass is not rootful or rootless
Engine compatibility evidence.

The ignored `live_existing_volume_prerequisite_matches_engine` library test
adds a separate, exact native lane check for ADR 0008's existing named-volume
target. It seeds a task-owned, labeled volume, checks the rendered external
prerequisite and exact read-only/read-write mount requests, and verifies seeded
data access, write rejection on the read-only mount, and persistence after a
consumer container is removed and recreated. A missing volume must fail the
harness's direct Engine GET preflight before any rendered POST; Engine container
creation can otherwise create a missing named volume implicitly. The test
uses only synthetic resources and label-verified cleanup. Each passing lane
records six closed `volume_probes` in its sanitized manifest, sourced from a
bounded private test file; raw volume names, data, and API responses remain
private. These probes are non-admission evidence: they do not modify the
historical reviewed catalog or its schema, establish that an arbitrary
destination volume exists or is populated, or authorize copying or applying
data. Fresh, independently reviewed rootful and rootless runs on every claimed
Engine profile remain necessary before an existing-volume compatibility claim.

DockerLens #49 adds a separate ignored `live_created_volume_labels_match_engine`
test for created-volume labels. Offline tests enforce protected key/value,
count, aggregate-byte, duplicate and exact-wire boundaries, including unchanged
unlabelled requests and label-free external prerequisites. The native probe
compares an independent CLI-created volume with the inert labelled request,
including empty and non-ASCII/escaped values, then checks direct Engine inspect
labels, data persistence across task-owned containers, ownership labels and
exact cleanup. Its closed results are not catalogue admission: all four exact
lanes must pass and be independently
reviewed before an exact capability claim. Historical unlabelled `NamedVolume`
evidence cannot prove `VolumeLabels`.

The evidence emitter's bounded #31 prerequisite checkpoint maps complete,
validated existing native proof files to exactly three additional raw groups:
`VolumeExternalReference` to `ExternalVolumeReference` after all six volume
probes, `VolumeLabels` to `VolumeCreateLabels` after all four volume-label
probes, and `NetworkExternalReference` to `ExternalNetworkReference` after all
twenty-two network probes and the separate passing internal proof. The existing
`NetworkInternal` group remains separate. Missing, partial, duplicate, unknown,
or failed proof inputs reject the complete manifest; no probe name alone
admits a capability. This changes only future raw `capability_outcome` and
`admitted_shapes` emission, not the source nineteen-marker set, historical
records, schema or reviewed catalogue. Earlier #67 raw records did not emit
these three groups and cannot be retroactively treated as having admitted
them. Fresh exact-candidate four-lane runs, independent review and separate
new-cohort admission remain required. ADR 0012 explicitly supersedes ADR 0010's
sequencing clause to permit sealed candidate records for pre-merge rehearsal;
the six actual BoxFerry authored fixture volume-only mappings and consumer
rehearsal still gate production merge/main/release, alongside fresh final-candidate
four-lane native proof and complete gates. Those gates remain pending. No arbitrary
destination prerequisite, data availability, application compatibility or
release is established by this checkpoint. No native request, operational pin,
dependency or Renovate extraction path changes are introduced.

## Bounded container process identity proof (#74)

[ADR 0013](decisions/0013-parameterized-container-identity.md) bounds authored
user/group syntax and defines the expanded parameterized proof required before
identity capability admission. The historical proof described below remains
numeric-only non-admission evidence. #86's expanded ten-pair source proof
passed all four lanes in run `37439627551`, attempt 1. Candidate sealed
selection is governed separately by ADR 0014 and the final-candidate gates.

The version-2 producer/consumer seam is documented in
[parameterized identity proof](native-identity-contract.md). The canonical check
now contains the ten pairs, while the historical numeric-only v1 record below
retains its original meaning. Only complete validated v2 proof can map the two
singleton raw identity groups; this does not automatically change sealed catalogue admission
or establish a passing native run.

### Historical v1 proof (retained non-admission contract)

At the #74 checkpoint, the exact ignored `live_container_process_identity_matches_engine` test was a
separate tenth mandatory native check; none of the existing nine checks is
removed, filtered, retried, or made optional. Its only authored setting shape
is numeric container user `1000:1000` and the already-existing `/tmp` directory
in the unchanged pinned BusyBox fixture. An independently authored Docker CLI
create and the ordinary crate-private sealed planner/inert renderer each create
one labelled container. Direct Engine inspection checks both Config fields,
the command and inherited entrypoint before either starts. Their actual PID1
workload runs `id -u`, `id -g`, and `pwd -P`; exact output must be numeric
`1000`, numeric `1000`, and `/tmp`, followed by inspected exited state, not
running, and exit code zero. Docker exec with a user override is not an identity
oracle. Rootful/rootless daemon mode and exact Engine/API context are checked
separately: the container process account is not the daemon or host account,
even where their numeric values coincide. This proves no named-user/group
lookup, arbitrary directory creation or ownership, supplementary groups,
host-mapped UID, or general user-namespace guarantee.

Each role is bound through its exact run-owned name and literal ownership
label to a distinct canonical immutable ID. Cleanup revalidates that binding,
deletes by ID only, and requires genuine direct Engine 404s for both names and
both IDs twice. A failed assertion, timeout, unresolved ownership or cleanup
failure cannot produce positive proof. Bounded commands share the runner
deadline, reserve cleanup time, and keep native stdout/stderr private; closed
markers and selected numeric panic locations alone may reach logs. Abrupt
SIGKILL or host failure can prevent cleanup and is not positive evidence.

Only after every assertion and cleanup succeeds does the test create a fresh
mode-0600 private proof bound to candidate SHA, lane, daemon mode, rendering API
and run token. The emitter requires one bounded regular owner-private,
single-link, non-symlink file, exact fields and marker order, distinct IDs,
exact names/owner, and every configured/runtime/cleanup result. Missing,
partial, failed, duplicate-key, stale, malformed or unbound files reject the
entire manifest. This is trusted-harness provenance, not cryptographic
attestation against a privileged writer able to replace a valid proof.

Future sanitized manifests add only the closed `identity_probes` group:
`ContainerUser`, `ContainerWorkdir`, `ContainerNumericUidGid`,
`ContainerProcessWorkingDirectory`, and `ContainerIdentityOwnershipCleanup`.
Raw IDs, names, owner labels and run tokens are not emitted. These markers do
not extend `capability_outcome`, `admitted_shapes`, production capabilities or
the reviewed catalogue. The schema's reviewed-record root remains unchanged;
dedicated `$defs` describe the separate raw group and private proof. Historical
evidence is preserved byte-for-byte. Fresh exact-head four-lane success and
independent review are still required; this source checkpoint claims neither
native compatibility nor #39 completion. In particular, #39 / PR #73's failed
run [`37218370132`](https://github.com/Strukturpiloten/docker-lens/actions/runs/37218370132)
remains failed, with its resource/device assertions and cleanup requirements
unchanged. No cgroup/device workaround or production admission is delivered.

The canonical harness is shared by DockerLens local/main/dispatch/Release
native execution; the offline gates also exercise its regression tests. The
consumer audit found no external raw-manifest parser: BoxFerry reads the
digest-bound reviewed records and sealed catalogue and owns its receipts and
application tests; other workflows transport/upload artifact bytes. No
cross-repository API or consumer edits are needed. All five existing native
image/fixture pins remain in `scripts/native-conformance.sh`, with unchanged
Renovate ownership, extraction paths, grouping and approvals; no dependency,
downloaded tool, or operational definition is added or moved.

## Ports-only native proof preparation (#39)

`native_port_tests::live_port_publications_match_engine` is a new ignored,
test-only extraction of the repository-authored `7345ea3` port assertions, not
the unrelated broad container-settings suite. Separate IPv4, fixed IPv6,
ephemeral IPv6 and repeated-ephemeral functions retain all eight port markers,
independent CLI creates, literal request comparisons, ordinary sealed planning,
configured/runtime inspections, TCP and UDP canaries, and exact kernel-refusal
loopback isolation. UDP controls exercise both oracle and rendered fixtures.
Context uses genuine bounded acquisition/decode scope, direct and CLI Engine
facts, and exactly one inner dockerd's effective UID; an environment assertion
alone is not mode, version or capability evidence. The reused outer-namespace
helper retains immutable outer identity and its held namespace FD. Before
identity publication or namespace entry, that exact FD's kernel device/inode
must differ from the helper's host/self network namespace. A name, label or
bridge intent is not a substitute; unavailable/equal identities fail closed.
The approved first-option `curl -q` keeps default client configuration disabled.

The initial `NATIVE_PORT_PROBES_PATH` contract is a fresh, exclusive,
owner-private regular file directly under validated `NATIVE_CAPTURE_DIR`.
Its bounded schema-1 `dockerlens-native-port-probes` record binds candidate,
lane, actual `engine_release`, rendering API and mode, plus the private exact
run token and `cleanup: absent`. Its nested schema-1 `probes` contains ordered
`positive` and `expected_negative` collections whose mutually exclusive union
is exactly all eight shapes. Only fixed/ephemeral IPv6 in the two exact Debian
lanes may retain the existing independently controlled
`nested_default_bridge_ipv6_unavailable` or
`nested_default_bridge_ipv6_runtime_binding_absent` reasons. These are observed
boundaries, not passes or availability claims; upstream negatives, unknown
reasons, duplicates, missing shapes and overlaps reject the entire proof.
Independent IPv4, repeated-binding, exposed-only and ephemeral positives remain
positive without promoting the negative IPv6 group. Every other requested group
still needs every required shape positive before capability admission.

The file is written only after all actual assertions and ID/name/label-verified
cleanup with genuine name/ID absence readbacks. The canonical runner requires
this eleventh ignored test by exact name before manifest emission, preserving
the exact-one execution check and 180-second deadline. The emitter validates
the private direct-child file, directory identity, owner/mode, stable bounded
bytes, full context and complete outcomes before writing any lane manifest.
Only ordered `port_probes` shape/outcome/reason entries survive sanitization;
private run and cleanup context is stripped. Capability admission remains
separate and pending; neither an explicit boundary nor a missing file is a
positive capability or IPv4-unavailable result. The shared deadline reserves cleanup time; unknown
failures, untested/partial results, cancellation, uncertain mutation or cleanup
cannot publish a proof. Rootless low-port, missing-capability and API-floor checks are
pure pre-I/O boundaries, not native reachability evidence.

On a failed port invocation, the exact-test wrapper preserves the last closed
port progress stage before cleanup separately from the cleanup/unverified marker.
It projects the first selected-thread panic outside the optional IPv6 follow-up
scope from the port test's fixed source basename to bounded numeric line/column
only. Constant internal begin/end markers bracket the existing caught follow-up
checks; their panics cannot replace the subsequent HTTP assertion's location.
The projection waits for the complete scope stream: nested, unmatched,
malformed or unfinished scopes suppress every source site and report only a
fixed invalid-scope diagnostic. A later wrapper or Drop panic cannot replace
the first eligible location. This location and the pre-cleanup stage narrow the
failure; retained diagnostic families are observations, not universal root-cause
claims. Strict full-line finite grammars retain at most one
diagnostic per API transport/status, CLI, HTTP, namespace, IPv6 state/boundary,
isolation and runtime-binding family. Unknown fields/enums, raw values, secret
suffixes and other test targets cannot pass this port diagnostic boundary.
Primary and Drop cleanup attempts separately report only `pass`, `fail` or
`panic`, remaining reserve (`exhausted`: at most one whole second; `low`: two
through forty; `reserved`: more than forty), and mutation `clear`/`uncertain`.
These are observations after each existing cleanup attempt, not new allocations,
retries, evidence or proof of remaining resources. Deadlines, exact ownership,
repeated genuine absence checks, assertion outcomes and admission stay unchanged;
raw test, controller and runtime output remains private.

Failed API diagnostics separately retain the first closed action/phase/exit for
probe and cleanup, distinguishing curl's request timeout from the outer command
timeout and signals without printing a route, ID or response. Only a transport
failure starting the exact registered repeated-ephemeral IPv4 CLI oracle enables
an optional version GET and that same immutable ID's inspect GET. This uses a
test-only guarded seam into the existing acquisition transport, not subprocess
capture or another HTTP client; product acquisition behavior is unchanged.
The two reads share one monotonic window of at most four seconds, each clipped
to at most two seconds and the remaining original deadline before its forty-second
cleanup reserve. Insufficient time reserve skips the observations without new
I/O. The original 512-command/8-MiB retained-output counters are untouched on
every diagnostic path; this failure-only allowance separately admits at most
two GETs and charges a conservative whole-wire bound before each read. That
bound derives from the canonical 16-KiB header/body and 64-byte chunk-line caps,
bounded trailers and the longest 163-byte allowed request. The aggregate
envelope is the original budgets plus this separate two-read allowance,
not a claim that every budget is unchanged. This avoids spending cleanup
counter space: its conservative known-resource byte envelope would not fit in
the original 8 MiB even without diagnostics. Canonical framing, cancellation and terminal
time checks cover complete framing and JSON classification; no child, drain,
kill-grace or reap budget is introduced. An optional caught panic stays inside
the same closed diagnostic scope and cannot replace the original failed API
assertion. Only fixed responsiveness, exact identity, container state and
primary/secondary allocation cardinalities and `allocation_relation` are emitted.
That relation is `same` or `different` only when the already-read, owned
`8085/tcp` response has exactly two bindings: one canonical nonzero decimal
allocation for each of `127.0.0.1` and `127.0.0.2`. Missing, malformed, foreign-address or
duplicate or zero-padded entries retain `unknown`; no further I/O or time allowance
is added.
This compares observed numerical allocations, not effective RootlessKit/proxy
behavior or the cause of a failed start. A foreign or partial
identity cannot authorize further observations; malformed/late results remain
unknown. The same numerical port on different host addresses is valid and is
never rejected by this diagnostic. No readback clears mutation uncertainty,
retries start/delete, changes existing timeouts/assertions, creates an unsupported
outcome or permits a proof after the original failure.

The independently reviewed, nonqualifying isolated CLI reproduction recorded
in [#83's observation](https://github.com/Strukturpiloten/docker-lens/issues/83#issuecomment-6037955983)
completed one repeated-ephemeral IPv4 START in 16,919 ms on Debian 11 rootless
Engine 20.10.5 / API 1.41. The container ran with two different numerical host
allocations and RootlessKit 0.14.2's builtin driver listed two rows. Private logs
contained the fixed `Timed out proxy starting` marker and no address-in-use
marker. This is one fresh-daemon diagnostic observation, not the full native
sequence, capability evidence or a universal cause. Reviewed exact Debian
`libnetwork/portmapper/proxy.go` source has a 16-second docker-proxy readiness
timeout/recovery path that can outlive the prior eight-second client cutoff.
RootlessKit v0.14.2's reviewed wrapper source supports investigation of an
allocation/reservation collision, but that explanation remains a hypothesis.
No oracle source is copied or translated into the implementation.

Only non-cleanup POST START requests for the exact registered canonical IDs and
names of `multi-dynamic-oracle` and `multi-dynamic-rendered` get curl/outer
ceilings of 24/26 seconds, and only after the independently verified
`debian11-rootless` context records matching rootless capture facts, API 1.41
and exact Engine 20.10.5 release text. The context's already accepted
`20.10.5+dfsg1` spelling requires that same exact spelling in the captured facts;
lane/environment declarations alone cannot enable the allowance. Other methods,
fixtures, profiles and cleanup retain eight/ten-second ceilings. Both extended
limits are clipped to the remaining original 180-second deadline, preserving
forty seconds for cleanup, the existing one-second KILL grace, and a further
one-second setup/reporting margin. Full 24/26 limits require 68 whole seconds
remaining; at 45 seconds the clipped limits are 1/3, and less time submits no
request. Curl remains two seconds below its outer timer. Limits are recomputed
after optional private record publication before request I/O.

All eight shape outcomes, traffic and exact assertions, command/byte caps,
original 180-second deadline, existing four-second two-GET follow-up and separate
four-second parent observer remain mandatory and unchanged. There is no START
retry, unsupported reclassification, capability/catalogue or pin change. The
private diagnostic window accepts at most 27 seconds only for its already
authenticated Debian rootless / API 1.41 oracle phase and exact name; every
other lane retains eleven seconds. Overlong, mismatched, future, reversed or
stale windows still fail closed under the same cutoff. Fresh complete gates,
independent review and all exact-final-candidate native lanes remain pending
before qualification of this timeout correction.

Only that same registered canonical repeated-ephemeral IPv4 CLI oracle's
non-cleanup POST start can also create a best-effort private start-window
record. `NATIVE_PORT_START_DIAGNOSTIC_PATH` is a mode-0600, single-link direct
child of the separate mode-0700 `$run_dir/diagnostics` directory, outside the
direct native proof inputs. The closed record binds run, lane, exact candidate,
immutable outer ID and name, created ID and name, API, phase, and the original
180-second cutoff. It starts immediately before capture and is finalized only
on that original curl/command timeout, recording the actual POST failure end.
Failure to publish or finalize leaves the optional observation unavailable;
it cannot affect the original request, assertions, eight port shapes, existing
four-second two-GET follow-up, forty-second inner cleanup reserve, or proof.

Before the existing outer run, the caller exclusively pre-creates a no-follow,
mode-0600 `diagnostics/daemon.log` and holds its original descriptor. Only the
daemon outer container gets the explicit `k8s-file` driver, that exact path,
and a 1-MiB maximum-size setting. The existing authorized setup privilege
inspection serializes the full object with `{{json .}}`, then reads canonical
ID, exact name, native-run label, observed image digest and log driver/path;
its ID must equal the actual creation ID. Mandatory `HostConfig.Privileged`
boolean validation remains separate from optional log registration.
The digest must equal the immutable digest in the expected image pin; normalized
image display names never substitute for digest integrity. Successful local
registration binds those facts to the original file's device/inode/UID/mode/link
count and a nonempty bounded startup-prefix digest in a separate private record.
Missing or mismatched facts leave the optional observation unavailable.

The parent captures only the final exact port wrapper's status. On failure,
before outer EXIT cleanup, the stdlib-only helper reads only the held local file,
in either caller mode, with no sudo, Podman, daemon query or privilege handoff.
Registration must match the exact Rust POST window's immutable outer identity
and run/lane context. Both private records reject missing/pending/stale inputs,
duplicate keys, unknown fields, oversized files, symlinks, owner/mode/link
mismatches, path/file drift, future timestamps and reversed windows. The file
snapshot has a 64-KiB total log-input cap, independent of the 1-MiB storage cap:
larger logs are unavailable rather than tail-sampled as complete. Original
descriptor and named-path metadata, prefix, and stable before/after metadata
must all match. Replacement/rotation, ownership changes, truncation/prefix drift,
concurrent writes, malformed timestamps and incomplete CRI records fail closed.
The observer never reads a replacement file or repairs its permissions.

Only complete timestamped CRI stdout/stderr records inside the actual start
through actual POST failure end enter classification. More than 80 eligible
records yields closed unavailability rather than silently dropping an early
failure; startup, post-failure and cleanup records are excluded.
Rootless trace lines are classified rather than discarded; only fixed `source`,
`category` and `collector` enums leave the boundary. No raw messages, traces, IDs,
ports, timestamps, runtime errors or diagnostic files enter manifests or evidence
archives. Categories identify observations for investigation, not attributed causes.

This separate failure-only observation has at most four seconds inside the
remaining existing parent 30-minute active budget, including helper
initialization, private record validation, file collection, classification and
TERM/KILL/reap. The parent conservatively requires five remaining whole seconds,
checks the existing watchdog, and uses Linux BOOTTIME readings before collection
and before accepting output; the helper checks BOOTTIME and a shared monotonic
deadline. The 3.5-second TERM timeout and 0.25-second KILL fallback share the
file reader's caller privileges, including ordinary non-root hosted invocations.
Normal native harness sudo behavior and workflow privileges remain unchanged.
Late, cancelled,
nonzero, oversized or
incomplete results remain uncertainty and cannot turn the original failure into
a pass. The original wrapper status is retained even if diagnostics fail, and
outer EXIT cleanup still runs. No parent budget is reset or extended. The hosted
35-minute timeout supplies no promised five-minute cleanup reserve: the existing
parent watchdog has no aggregate protected cleanup reserve, and SIGKILL or host
failure can still prevent cleanup or any diagnostic.

A bounded local Podman 6.0.2 probe preserved a caller-owned mode-0600 file's
inode for small `k8s-file` stdout/stderr and confirmed the configured driver/path
and immutable image digest. A 64-KiB overflow probe instead replaced the inode
with a different-owner mode-0640 file. The observer explicitly refuses that
rotation behavior without reading the new file or changing permissions. These
local observations do not establish hosted availability or universal Podman
behavior; fresh hosted execution must establish whether a usable source exists.

Run `37609069502` failed all four lanes before native tests because the setup
Go template projected `.Id`, which hosted Podman 4.9 could not evaluate. That is
a harness regression, not Docker compatibility evidence. The existing inspect
query now serializes the complete JSON object rather than depending on Go field
spellings; JSON's `Id` key still requires exact creation-ID matching. The offline
fixture rejects the unsafe `.Id` projection and supplies a full JSON snapshot
with normalized display name, exact digest and log configuration. Missing image
digest metadata refuses optional registration while mandatory privilege checks
and native assertions continue. This is authored fake coverage; hosted JSON
image-digest availability and the changed harness remain unverified until a
fresh exact-candidate run passes. No ImageID fallback or integrity relaxation
is introduced.

Run `37447905139` observed only a Debian 11 rootless timeout at this oracle's
POST start, followed by responsive version GET and a timed-out same-object
inspect. State, bindings and cleanup remained uncertain. That observation does
not establish a cause, an unsupported boundary, or positive native evidence;
fresh exact-candidate passing lanes and independent review remain required.

The existing main, reviewed-PR native dispatcher and Release validation workflows
all consume `scripts/native-conformance.sh`; that canonical definition now
requires the port proof in every exact lane. No new workflow, dependency,
downloaded tool, image/version/digest pin, extraction path or manager is added
or moved. Existing native script pins retain their Renovate ownership, grouping
and approvals; historical records and catalogue admission stay unchanged.
The failed-start helper is a DockerLens-only consumer of the canonical native
harness; it introduces no BoxFerry dependency. Verified Renovate manager paths
still own the unchanged five image references in `scripts/native-conformance.sh`
and the unchanged toolchain and Action references; the new stdlib helper adds
no operational pin, manager, extraction path, grouping or approval change.
Genuine exact-candidate native evidence remains integrator-owned and pending.
Offline helper, emitter, harness and Rust controls do not establish native compatibility,
BoxFerry application acceptance, #39 completion or a release. Historical
evidence and all earlier worktrees remain unchanged.

## Reviewed target-profile records

The #89 candidate catalogue selects four reviewed records from native run
[`37439627551`, attempt 1](https://github.com/Strukturpiloten/docker-lens/actions/runs/37439627551/attempts/1),
of #88 source candidate `032b1510524f391f08a795dab4da73f6fa8f7213`, under
[ADR 0014](decisions/0014-reviewed-identity-cohort.md). The exact set is sixteen
capabilities and twenty-six shapes: the #70 fourteen/twenty-four set plus only
`ContainerUser` / `ContainerUser` and `ContainerWorkdir` / `ContainerWorkdir`.
The ten independent CLI/renderer pairs and complete private v2 proof establish
parameterized native fields, not arbitrary-image startup or host UID mapping.

Production merge/main/release remain blocked until fresh exact-final-candidate
four-lane native proof, complete gates and independently reviewed six actual
authored-fixture volume-only consumer rehearsals pass. The retained
[ADR 0012](decisions/0012-candidate-volume-label-admission.md) gate applies
because this selection still admits `VolumeLabels`. Offline consumer tests
exercise the sealed planner but do not replace isolated native rehearsal.
The authenticated source run validates its source candidate, not a later
candidate, release or six-application acceptance. The trusted dispatcher
workflow head is distinct from the executed source SHA.

All earlier raw and reviewed cohorts remain immutable and retain their own
admissions: original run `36451790131`, attempt 1, source
`d51d7dbfda5ee6f8fefe92605afe8baea3dc504e` (ten/twenty);
#68 run `37209363801`, attempt 1, source
`702910b003daae58babd540d7ba3de4998275feb` (thirteen/twenty-three);
and #70 run `37214738475`, attempt 1, source
`0d8268155a5aacddaeb501adf7f8b2fe06a718ca` (fourteen/twenty-four).
No prior record is relabeled, regenerated or rewritten. The active catalogue
still has exactly four identities, selected only from #88.

Exact manifests and reviewed envelopes live under
`docs/evidence/native/sha256/` and `docs/evidence/reviewed/sha256/`.
Records conform to [the reviewed schema](native-evidence.schema.json) and bind
lane, build/package provenance, reported Engine release, advertised maximum,
acquisition and rendering APIs, daemon mode, actual source SHA and run attempt.
The compiled catalogue requires exactly sixteen complete capability groups
and twenty-six shapes per lane. Each `NativeCapabilityShape::required_for`
group must match its linked raw manifest's exact available shape group.
Missing/duplicate lanes, partial groups, wrong-group shapes or unavailable
outcomes cannot authorize planning. Raw probe markers alone grant no claim.

The four unmodified #88 artifacts are named `dockerlens-native-<lane>` and
contain `<lane>.json`. Downloaded archive hashes matched authenticated GitHub
artifact digests; the independently reviewed bounded projector verified the
candidate/lane/image/package/API/probe/case bindings. Each exact manifest is
retained verbatim under its content SHA-256. Its reviewed envelope derives
build provenance from the observed lane/package, copies the native identity
and APIs, binds the actual source/run above, and selects only the sixteen
complete available groups. UTF-8 JSON with two-space indentation and a final
newline has a separate SHA-256 naming the reviewed file and evidence key.

`tests/test_reviewed_catalog.py` pins all four cohorts' raw/reviewed hashes,
identity bindings and complete groups and checks the exact compiled selection.
Identity admission additionally requires the exact ordered parameterized case
and probe markers; legacy, omitted, partial, duplicated or reordered markers
fail the linked-evidence regression checks.
Public regressions use the real sealed catalogue, independently authored
identity requests and complete labelled-volume artifacts on every profile.
They check omission, canonical numeric/named/mixed users, protected Debug,
malformed values, wrong evidence/mode/API, duplicate/oversized labels and
external-volume non-mutation. Supplementary groups, host namespace, port and
remaining runtime/network groups stay unadmitted. Offline assertions cannot
replace fresh native or consumer proof.

The #88 source run passed ten exact ignored proof tests per lane. Its raw
manifests retain nineteen source, twenty-two network, six external-volume,
four label and five identity probe markers plus the ten ordered identity
cases and `container-identity-v1` contract. Test count is not probe count.
No operational pin, manager ownership or Renovate extraction path changes;
immutable historical evidence remains outside automatic update streams.

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
evidence for a later catalog commit; each changed candidate and release still
needs fresh complete checks and native validation. Never substitute the historical
source SHA for the final candidate SHA or infer an API version from a release
label. Public resolver and inert rendering tests cover the admitted records.
