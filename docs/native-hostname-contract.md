# Finite hostname source-effect contract

DockerLens #39/#30 adds one mandatory twenty-second exact ignored invocation:
`native_health_metadata_tests::lifecycle::hostname::live_hostname_matches_engine`.
The first twenty-one invocations retain their order and requirements. This is
test-only source-effect preparation, not native qualification, public API
acceptance or catalogue admission. ADR 0023 separately projects closed raw
source outcomes only after both complete process proofs validate.

## Independent requests and effects

Four finite run-owned containers borrow the existing digest-pinned BusyBox
image. Two cases each have independent CLI and literal-rendered roles:

| Case | Authored intent | Independent expected configured/process hostname |
| --- | --- | --- |
| Omitted | CLI has no `--hostname`; the complete rendered literal has no `Hostname` member. | The generated first twelve hexadecimal characters of that container's validated native ID. This is a daemon default, never authored or portable desired intent. |
| Explicit | CLI flag and typed target independently specify `dl-hostname-<run>`. | Exactly that synthetic test-owned value. |

The explicit target uses existing `ContainerSettings.hostname` and
`ContainerHostname`; no product API changes. Test-local scoped native facts use
the existing crate-private test convention, not a fabricated public reviewed
profile or a product catalogue bypass. Each complete rendered request must
equal its independently authored Engine literal before once-only submission.
CLI intent is not misrepresented as an observed CLI HTTP request body.

Each container binds a canonical globally distinct ID and exact name, owner
label and borrowed image. Native inspect must confirm `Config.Hostname` before
start and while running. An API-pinned `docker exec ID hostname` must actually
execute in that container and return the expected value with exactly one
newline. A later inspect must retain the same StartedAt, hostname/image/owner,
running state, positive PID, zero restarts and no paused/dead/restarting/OOM/error
state. The expected value never comes from renderer output or observed Config.
No DNS, domain-name, application identity or generated-hostname promotion claim
follows. No arbitrary hostname grammar or normalization is certified.

The borrowed image must supply the `hostname` command. Missing command,
unexpected default, unsupported native behavior, permission error or transport
failure refuses the cell and the lane; there is no skip, alternative command,
fallback daemon, retry or reclassification as successful unsupported evidence.

## Ownership, limits and private proof

The probe reuses the existing original 180-second invocation deadline,
400-call/4 MiB aggregate limits, 100-call/2 MiB cleanup reserve, 46-second
ordinary-work margin and finite command/stream caps. Its four exact names are
`dl-host-<run>-{omitted,explicit}-{oracle,rendered}`. It creates no derived image
and neither edits nor removes the borrowed image.

The existing bound outer cleanup owner is authenticated before mutations.
Immediate ID/name/image/label ownership recheck precedes once-only removal;
two complete ID/name absence rounds precede publication. Cleanup uncertainty
retains the original failure and requests bound outer teardown, never a second
inner mutation attempt. That marker is not proof of completed outer teardown.
Final original image and outer identity snapshots must match. The existing
five lifecycle-family protocols are unchanged; this invocation receives the
same scoped owner as a sixth child.

`hostname-v1.json` is a new fixed direct child of the owner-private capture
directory. Publication is exclusive, bounded and 0600. It contains protected
native values only in the private proof. `native_hostname_proof.py` reuses the
stable bounded direct-child reader, enforcing canonical 0700 ancestry, owner,
single-link regular 0600 file, size/stability and duplicate-key refusal.
Closed schema/context, both cases/roles, actual configured/process values,
strict types, distinct identities, started state and verified cleanup are
mandatory. Wrong-context, missing, partial, malformed, failed-effect or
uncertain-cleanup proofs reject with a fixed value-free error.

The harness invokes the strict reader unconditionally after the exact test and
before its existing public emitter. Twelve explicit CLI arguments carry the
independently established candidate/run/lane, Engine/package/API/mode,
fixture/outer image/ID and observed daemon UID; proof self-context is never its
oracle. The proof retains `capability_admission: []` and
`catalogue_admission: false`. Success is silent. Public output projects only
fixed stage markers and a numeric selected-source panic location; arbitrary
observed hostnames, IDs, paths, output and messages never cross that boundary.
Under [ADR 0023](decisions/0023-process-source-proof-wiring.md), the stable
nineteen-argument emitter separately revalidates this proof and the complete
command-clear proof before adding three source-only raw singleton groups.
The closed hostname public subset contains only its contract, fixed outcome and
raw-source/unadmitted markers; the private v1 protocol, compiled catalogue and
historical evidence remain unchanged.

## Qualification and maintenance

The independent native oracle is
`./scripts/native-conformance.sh <lane>`: exact Debian 11 docker.io
`20.10.5+dfsg1-1+deb11u2` / Engine `20.10.5+dfsg1` / API 1.41, and upstream
Engine 29.8.1 / rendering API 1.56 / bounded acquisition API 1.49, each in its own
rootful/rootless cell. These existing immutable image/package/runtime baselines
are preserved. Docker's [container networking documentation](https://docs.docker.com/engine/network/#ip-address-and-hostname)
documents container-ID hostname defaults and explicit `--hostname` overrides;
the finite twelve-character expectation here must still pass genuine lanes.
Existing Docker/Moby Apache-2.0 provenance applies; no oracle source or binaries
are copied or redistributed by this change.

Local native execution, Check main, trusted candidate dispatch and Release
validation consume the same canonical harness. Other Lens products and the
website have no changed consumer. BoxFerry consumes reviewed records and needs
separate real adapter/application rehearsal, not this private proof. No
dependency, tool, workflow, Action or image pin/extraction path changes;
Renovate retains its existing Cargo/Action/toolchain ownership and five-image
regex, native-image grouping and disabled automerge.

Offline mock/reader tests prove no native compatibility. Independent final-diff
review, complete final-edit gate and fresh exact-head twenty-six-test four-lane
qualification remain required. Raw projection grants no admission; separately
authenticated cohort selection and actual consumer gates remain required.
No release, publication, deployment or host runtime change is requested.
