# External network Internal prerequisite proof

`external-network-internal-v1` is a new test-only source proof producer and
private validator for [ADR 0017](decisions/0017-external-network-internal-expectation.md).
The canonical harness invokes it as the fifteenth mandatory test, after the
configured-bind proof and before raw emission. No passing native run or sealed
admission is claimed. All fourteen preceding native invocations, sealed profiles
and historical evidence retain their contracts and bytes.

## Independent assertions

The ignored `native_external_network_tests::live_external_network_internal_matches_engine`
test independently creates two run-owned bridges through Docker CLI, explicitly
ordinary and internal. It checks immutable full IDs, exact names and owner labels
against direct Engine GET and independent CLI inspect. Both IDs must be distinct
within the network kind; another resource kind sharing ID spelling is not a
network collision. Existing named resources fail preflight and are not removed.

Each network then receives its own fresh explicit private Unix-socket
`NetworkIds` acquisition: exactly unversioned `/version`, one versioned `/info`
and one exact network inspect, all completed HTTP 200. Actual versioned exchanges
must use API 1.41 on Debian or 1.49 upstream, independently of advertised/rendering
1.41 or 1.56. Decoded requested APIs must match those literal acquisition facts;
daemon API remains its actual advertised value. Inventory and daemon scope must
equal the actual capture observation identity. One exact selected root must bind
the observed network ID through its capture-local reference, never a target ref.
Fresh decoded rootless mode must be affirmative `Rootless`. Rootful `Unknown`
is permitted only with independently observed UID zero and no contrary fresh
mode; the configured lane alone cannot supply that corroboration.

Present effective native `Internal` must equal the independently authored false
or true case. The corresponding external-only artifact must retain explicit
`Some(false)` or `Some(true)` in schema 3, with empty request bytes and an empty
complete request array. Its one row is compared with the independent literal
identity, reference, driver and boolean. Pure assessment must succeed for that
explicit captured scope/ID; the opposite requirement must fail specifically
with `NetworkInternalMismatch`. Direct inspection afterward rechecks identity,
ownership, driver and internal flag. No artifact request is applied; no container,
traffic, application acceptance or isolation-effect claim is introduced.
Both expected and opposite artifacts must also preserve the exact in-memory
observed scope: fresh capture identity, corroborated mode, literal release and
advertised/rendering API. Their closed serialized observed context must retain
`process_local_only` provenance and those release/API/mode values, without a
durable observation identifier. Upstream acquisition 1.49 cannot substitute for
rendering 1.56 in either artifact. Pure negative controls cover these boundaries;
they do not establish native qualification.

## Boundaries, budgets and cleanup

The test independently corroborates canonical lane/release/API/package facts,
CLI/direct daemon mode, exactly one dockerd effective UID, and the held outer
container's immutable ID, owner, image digest, running state, mount/socket/data
volume and resource limits. The observed UID must agree with the separate
canonical harness UID fact. Observed rootful mode is not inferred merely from
a missing rootless marker. Candidate/run identities and fixture image binding
remain private context; this network-only test makes no fixture-image behavior
claim. Observation identities are checked in process, never serialized as
durable provenance or daemon authentication.

One monotonic deadline is clipped to the exact wrapper's existing 180-second
wall-clock cutoff. Work reserves 40 seconds and separate cleanup pools: 128 work
calls/8 MiB and 64 cleanup calls/4 MiB. Calls reserve both bounded output streams
before spawning; acquisition reserves its complete three-request/384-KiB envelope
before five-second explicit capture. No pool resets or borrowing are allowed.
Native output stays private. Commands use matching-privilege TERM/KILL timeouts.

Only attempted, exact run-owned networks enter cleanup. Ownership and immutable
ID are revalidated before deleting by ID. Uncertain creates recover only through
that exact name/owner/ID; uncertainty never produces proof. Two independent
rounds require genuine direct HTTP 404 for every owned ID and name. Removal
failure remains eligible for bounded cleanup retry. Any original assertion or
cleanup failure prevents publication. SIGKILL/host failure can prevent cleanup;
the outer harness remains responsible for its recorded resources.

## Private protocol

Only after all assertions and cleanup pass does the producer exclusively create
`external-network-internal-v1.json`, a bounded 16-KiB single-link mode-0600 regular
file under the canonical owner-private mode-0700 capture directory. Publication
holds the directory descriptor and checks file/directory identity after write
and sync. Post-write descriptor and named metadata must still be regular,
current-UID-owned, mode 0600 and single-link, and retain the initial device,
inode, owner, group, mode and link custody. Simultaneous changes to both metadata
views cannot conceal drift from the initial custody. Failed finalization
truncates the file so it cannot become valid proof.

The strict reader refuses missing/empty/overbound/duplicate-key/unknown-field
records, symlinks, hardlinks, wrong ownership/modes, file or parent drift and
context mismatches. Independently supplied expected context—not the proof's own
context—must bind candidate, run, exact lane, release, all API dimensions, mode,
package, immutable image/outer boundaries and daemon UID. Both ordered network
cases, eight closed checks and two verified absence rounds are mandatory.
Matching trusted-harness context is not cryptographic attestation against a
privileged writer able to forge a proof.

## Canonical raw integration

`scripts/native-conformance.sh` exports the fixed direct-child proof path and
its already verified candidate SHA. The exact runner selects the library's
ignored test, requires exactly one successful execution and retains the causal
failure stage before cleanup. Only six fixed stages and a fixed source basename
with bounded numeric panic locations may escape; private messages remain hidden.

The emitter retains its nineteen-positional-argument protocol. It requires the
fixed proof in the canonical capture directory, deriving expected context from
existing harness facts plus the independently observed dockerd UID, never from
the proof's own context. Only strict complete-proof validation permits the
fixed `external_network_contract` and ordered `external_network_probes` public
projection and complete `ExternalNetworkInternalFalse`/`ExternalNetworkInternalTrue`
raw group, separately from created-network `NetworkInternal`. Missing, partial,
stale, cross-context or custody-invalid proof refuses the entire manifest.
Schema projection definitions are additive and disconnected from the unchanged
reviewed root contract. With parameterized identity-v2, prospective raw counts
are Debian 29/46 and upstream 30/48; definitions/counts are not genuine evidence.
The sealed catalogue remains unchanged until fresh authenticated four-lane
execution, independent review and a separate admission change. No dependencies,
software pins, operational images, workflow pins or Renovate extraction change.

Local execution, `check.yml` main push, `native-validation.yml` reviewed-PR
dispatch and `release-validation.yml` consume this same canonical harness; no
workflow fork is added. Renovate's existing unique native-image manager still
owns the same five tag/digest pairs, grouping and manual approvals. Cargo,
toolchain and Action ownership/extraction remain unchanged. Other Lens products
and the website do not consume this Docker-only proof. BoxFerry profile and
producer-receipt contracts and ADR 0012/0016 authored-fixture/bind-consumer gates
remain separate; no product dependency or consumer acceptance follows.
