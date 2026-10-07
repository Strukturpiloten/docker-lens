# Bounded native network attachment source proof

`network-attachments-v1` is a test-only source-proof contract for four ordered
shapes: `NetworkCreateLabels`, `NetworkPrimaryAliases`,
`NetworkSecondaryAliases`, and `NetworkSecondaryConnect`. Together these cover
the complete raw groups `NetworkLabels`, `NetworkAliases`, and
`NetworkMultipleAttachment`. A proof is not catalogue admission, release
qualification, an attestation, or application-migration acceptance.

The existing historical native records and 22-marker network result remain
immutable. Neither those markers nor this contract add IPv6, static addresses,
IPAM, bridge options, internal or external network ownership, Swarm, arbitrary
metadata domains, or broader platform claims. BoxFerry remains responsible for
conversion and actual application/runtime acceptance; DockerLens libraries stay
independent of it and continue to produce inert requests.

## Independent roles and expected effects

Each role owns exactly five resources, in order: a primary ordinary bridge, a
secondary ordinary bridge, one server, one primary-only peer, and one
secondary-only peer. The `oracle` role uses independently authored Docker CLI
commands. Only after that role passes and its resources are absent does the
`rendered` role use the sealed native planner/renderer with freshly captured
daemon facts. The temporary capability facts are scoped to that observation,
release, API, and mode and exist only inside the test seam; they cannot grant a
product capability.

The rendered stream must match six independently authored JSON request
expectations in this exact order:

1. Create the primary bridge with authored labels.
2. Create the secondary bridge with authored labels.
3. Create the server with only the primary endpoint and its aliases.
4. Connect the server to the secondary bridge with its secondary aliases.
5. Create the primary-only peer without authored aliases.
6. Create the secondary-only peer without authored aliases.

The server is explicitly started between requests 3 and 4. Before connect, its
running attachment is primary-only and exact active membership is
primary={server}, secondary={}. After both peers start, each network's active
membership is exactly the server and its local peer. Inspections bind full IDs,
names, ownership labels, the immutable fixture image, fixed commands, running
state, endpoint network IDs, and distinct canonical private IPv4 addresses.

The server has a distinct unique alias on each attachment and an identical
shared alias on both. The peers are running and single-homed. From each peer,
both its local unique alias and the shared alias are queried as absolute A names
through the explicitly verified embedded resolver `127.0.0.11`. The complete
answer must contain exactly one address, equal to the server's local endpoint
address. Resolver addresses, partial answers, foreign names, duplicate answers,
and answers containing the other endpoint do not pass. Unique-name HTTP,
shared-name HTTP, and direct-local-IP HTTP must each return the fixed canary.
HTTP proxy use is disabled. Timeout, NXDOMAIN, failed execution, or missing
output never counts as negative evidence. Running state, endpoint addresses,
network memberships, and label retention are checked again after traffic.

Both bridges retain representative simple, empty, and escaped/non-ASCII label
values, separately from the run-ownership label. These finite cases establish
the small authored shape; observed runtime values are not promoted to intent.

## Context and closed private proof

The ignored Rust test is
`native_network_attachment_tests::live_network_attachments_match_engine`.
It uses the existing bounded lane harness inputs and additionally requires
`NATIVE_NETWORK_ATTACHMENT_CANDIDATE_SHA`,
`NATIVE_NETWORK_ATTACHMENT_PROOF_PATH`, `NATIVE_OUTER_CONTAINER_ID`, and
`NATIVE_OUTER_IMAGE`. The path must be the direct child
`$NATIVE_CAPTURE_DIR/network-attachments-v1.json`. The candidate is a canonical
40-character hexadecimal SHA, the run token is eight alphanumeric characters,
and all resource IDs are distinct canonical 64-character hexadecimal IDs,
including distinctness from the outer container ID.

The top-level fields are exactly `schema_version` (integer 1), `contract`
(`network-attachments-v1`), `context`, `roles`, `shapes`, and `cleanup`.
The independently supplied harness context must match the proof context
exactly. Its fields are:

- `candidate_sha`, `run_id`, `lane`, `engine_release`, `rendering_api`,
  `acquisition_api`, `mode`, `docker_package`, `fixture_image`, and `outer`.
- `outer` contains exactly `id`, `name`, `owner`, `image`, `data_volume`,
  `socket_source`, `privileged`, `memory_bytes`, `cpu_quota`, `cpu_period`, and
  `pids_limit`. It binds the exact run-owned outer identity, pinned image,
  run-owned volume, socket bind, privilege, 4 GiB memory, 2 CPU quota, and
  512-PID limit. The producer independently inspects the exact mounts and
  single expected outer network; it corroborates inner mode using Engine info,
  Docker CLI info, and exactly one dockerd process's effective UID.

The four lanes are Debian 11 and upstream, each rootful/rootless. Debian's
Engine release is `20.10.5` or `20.10.5+dfsg1`, package is
`20.10.5+dfsg1-1+deb11u2`, and rendering/acquisition API is `1.41`. Upstream's
Engine release is `29.8.1`, package is empty, rendering API is `1.56`, and the
captured acquisition API is exactly `1.49`, the library's acquisition ceiling.
Acquisition is real, explicitly
selected Unix-socket capture of the known baseline container, followed by the
pure decoder. Advertised/rendered API and negotiated acquisition API are
recorded separately: upstream advertised/rendered API remains `1.56`, while
Debian advertised/rendered and acquisition APIs remain `1.41`. The Rust proof
requires a nonempty set of versioned capture exchanges, all using the exact
lane acquisition API, and the decoder's requested API list must contain only
that version. Both the private proof and independently supplied expected
context reject any other acquisition API, even when they agree with each
other. These are contract checks against the existing harness, not new
operational pins or dependencies.

`roles` is ordered `oracle`, `rendered`; each record contains exactly `role`,
`request_check` (`independent_cli` or `literal_rendered` respectively),
`resources`, `checks`, and `cleanup` (`absent`). Its resources are ordered
`primary_network`, `secondary_network`, `server`, `primary_peer`,
`secondary_peer`. Every resource contains exactly `slot`, `kind`, `id`, `name`,
`owner`, `configured` (`passed`), and `cleanup` (`absent`); containers also
require `image`, equal to the independently expected fixture image. Names are
`dl-na-{run_id}-{role}-{hyphenated-slot}`, with owner equal to the run token.

`checks` contains exactly the passing assertions `primary_only`,
`secondary_connected`, `labels`, `aliases`, `running`, and `membership`, plus
`primary` and `secondary`. Each side contains exactly `unique_dns`,
`shared_dns`, `named_http`, `shared_http`, and `direct_http`, all `passed`.
Top-level `cleanup` is exactly `outcome=absent`, integer `rounds=2`, integer
`outstanding=0`, and Boolean `uncertain=false`. Extra, missing, duplicate,
reordered, noncanonical, foreign, incomplete, or private extension fields fail
closed. No free-form inspect, request, alias, label, DNS, or HTTP payload belongs
in the proof.

The producer exclusively creates a regular single-link 0600 file in a
caller-owned canonical 0700 directory only after all assertions and verified
cleanup pass; an incomplete publication is truncated and does not pass the
consumer. Maximum file size is 16 KiB. The consumer
`read_network_attachment_proof(path, capture_dir, expected_context)` uses held
directory/file descriptors and no-follow opens, rejects symlinked ancestors,
wrong owners/modes, special bits, hardlinks, nonregular files, duplicate JSON
keys, oversized/truncated input, and observed metadata/inode drift. Errors are
closed and contain no payload. Successful validation returns only the fixed
four-shape tuple; identities and context must not enter public output.
Private provenance and trusted harness completion cannot authenticate against
a privileged writer and do not replace candidate admission or archive review.

## Budgets and ownership-safe cleanup

The existing wrapper cutoff remains 180 seconds. Work stops while at least a
45-second cleanup reserve remains; the reserve grows with ledger history and
live resources to `max(45, 2*live + 4*historical + 5)` seconds. With ten known
resources and five live resources this is 55 seconds: ownership/delete checks
for the live resources, two ID/name absence rounds for every historical
resource, and context/publication overhead. At most five resources are live at
once. Work and cleanup have separate 200/160 command budgets and separate
4-MiB retained-output budgets. Before spawning a command, checked arithmetic
requires room for both full per-stream output envelopes in its selected pool;
exhausted work cannot consume cleanup capacity, and exhausted cleanup refuses
before I/O. Boundary controls cover exact fit, one-byte shortfall, zero capacity,
and arithmetic overflow. Initial acquisition is conservatively charged
16 requests and 1 MiB, is bounded to ten seconds and its own read/expansion/
response limits, and cannot consume the cleanup reserve.

Each work command has a three-second TERM deadline and 0.25-second KILL grace;
curl has a two-second request limit. Cleanup uses 0.5-second curl requests,
0.75-second outer TERM deadlines, and 0.25-second KILL grace. Bounded stream
draining prevents raw output files or unbounded captured output. The API
allowlist permits only exact contract resources/routes, and no host ports are
published. Root privilege selection follows the existing harness selector;
this test never acquires ambient containers or changes unrelated resources.

Every exact-name preflight must return genuine 404 before a create attempt is
marked potentially live. A collision is never adopted or deleted. Cleanup
first authenticates the immutable outer ID/name/owner/image, then inspects each
potentially live resource and authenticates its full ID/name/owner and, for a
container, fixture image. Deletes use IDs only, containers before networks.
A missing creation response can be recovered only by authenticated inspection
of that already-preflighted attempted name. A foreign or uncertain resource is
not deleted. Failure on one resource does not prevent cleanup attempts for
other authenticated resources. Two final global rounds require genuine 404
for every known name and every known ID. No timeout or unavailable socket is
absence. Uncertainty remains sticky and blocks proof publication; best-effort
drop cleanup is not completion evidence.

## Integration and validation ownership

The primary has integrated the Rust module, exact runner, canonical harness
context forwarding and fail-closed emitter after the health-proof checkpoint.
The reviewed-record schema and active catalogue are unchanged. Complete gates
and authentic four-lane native qualification remain separate obligations;
implemented definitions and synthetic controls are not runtime evidence.

Focused pure controls are the Rust DNS, independent literal-wire, and cleanup
reserve/collision tests in the owning module, plus
`python3 -m unittest discover -s tests -p 'test_native_network_attachment_proof.py'`.
The primary must run the canonical complete gates after its final integration
edit and independently review fresh exact-candidate four-lane native evidence,
archive/manifest bindings, native test success, and cleanup. No source control,
dependency pin, Renovate extraction path, or historical admission record is
changed by this proof implementation.
