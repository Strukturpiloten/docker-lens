# Bounded configured-bind native proof

`bind-relabel-config-v1` is a test-only proof of retained configuration under
[ADR 0015](decisions/0015-bind-relabel-intent.md). Its four ordered shapes are
`BindMountSharedRelabelReadWrite`, `BindMountSharedRelabelReadOnly`,
`BindMountPrivateRelabelReadWrite`, and `BindMountPrivateRelabelReadOnly`.
They cover literal `rw,z`, `ro,z`, `rw,Z`, and `ro,Z`. They do not prove SELinux
label changes, policy enforcement, write restrictions, migration acceptance,
or arbitrary destination-host suitability. SELinux effects remain `unverified`.
Neither the private result nor raw emitter metadata admits a reviewed capability.
The sixteen-capability/twenty-six-shape catalogue, historical evidence, and
default schema-1 artifact bytes are unchanged.

## Independent fixtures and source ownership

Each case runs the `oracle` role, cleans it completely, then runs the `rendered`
role and cleans it completely. At most one owned inner container and synthetic
source tree are live. Oracle fixtures use independently authored Docker CLI
create arguments. Rendered fixtures use fresh explicit acquisition of the
known harness container, observation-scoped test-only facts, the sealed planner
and renderer, and a separately authored literal JSON create expectation.
Every rendered request must match that complete expectation before application.
Before applying a rendered request, the producer also requires both the typed
bind prerequisite identity and the serialized schema-2 `bind_source.identity`
to equal the independently chosen owned fixture name. Caller-local reference
numbers cannot establish that association. This artifact correction does not
change the private proof's keys or its closed public shape projection.
This executor exists only in the ignored native test; product output stays inert.

Sources are never host binds, `/dockerlens-native/native-bind`, historical
fixtures, or shared directories. The declared run-owned outer data volume must
be mounted exactly at `/var/lib/docker` for rootful mode or
`/home/docker/.local/share/docker` for rootless mode. Direct outer inspection
also requires its sole expected socket bind and sole expected outer network.
Direct Engine info must independently report that same data root.

The synthetic root is `{storage_root}/dl-bind-relabel-{run_id}`. Genuine absence
is required before an exclusive `mkdir`, using the independently observed
dockerd effective UID. Canonical storage ancestors must contain no symlinks.
The root has mode 0700; its exclusive `.owner` file has mode 0600 and exactly
the run token. A single `{case}-{role}` leaf has mode 0755 and one mode-0644
`canary` file containing only the fixed synthetic canary. All four entries'
device/inode/UID/mode records are retained privately. Files must be single-link.
Subsequent source checks and cleanup require exact identity metadata, contents,
canonical root, and no symlinks. The private reader retains only the source
boundary and closed leaf identity, never those metadata or file bytes.

Each role starts its container and requires running state. Direct Engine
inspection must retain the literal singleton `HostConfig.Binds`, no structured
duplicate, and exactly one native mount with the expected `Source`,
`Destination`, `Type=bind`, complete case-sensitive `Mode`, and Boolean `RW`.
An independent fresh explicit socket capture of that exact full container ID
is decoded by the library. Typed source/destination/mode values must match the
direct response with present effective origins; typed access and relabel must
match the case, with no unsupported or conflicting mount finding. Running
state and native fields are checked again after acquisition. Image, command,
full ID, name, and ownership label are bound independently throughout.
Observed configuration does not prove that an original application authored it.

## Exact context and private result

The ignored Rust entry point is
`native_bind_relabel_tests::live_bind_relabel_configuration_matches_engine`.
Alongside the existing native harness inputs it requires
`NATIVE_BIND_RELABEL_CANDIDATE_SHA`, `NATIVE_BIND_RELABEL_PROOF_PATH`,
`NATIVE_OUTER_CONTAINER_ID`, and `NATIVE_OUTER_IMAGE`.
The proof path must be exactly
`$NATIVE_CAPTURE_DIR/bind-relabel-config-v1.json`, absent before execution.
It uses the existing wrapper's `NATIVE_NETWORK_TEST_DEADLINE_EPOCH`.

`context` has exactly `candidate_sha`, `run_id`, `lane`, `engine_release`,
`rendering_api`, `acquisition_api`, `mode`, `docker_package`, `fixture_image`,
`outer`, and `source_boundary`. Candidate SHA is 40 lowercase hexadecimal
characters; the run token is eight alphanumeric characters. Debian's release
is exactly `20.10.5` or `20.10.5+dfsg1`, package is
`20.10.5+dfsg1-1+deb11u2`, and advertised/rendered/acquisition API is `1.41`.
Upstream's release is exactly `29.8.1`, package is empty, advertised/rendered
API is `1.56`, and acquisition is exactly the library ceiling `1.49`.
Every capture requires a nonempty set of actual versioned exchanges using the
exact acquisition API and the decoder's singleton requested API list.
Daemon release, CLI server release/API, package where applicable, Engine info,
CLI security options, and exactly one dockerd effective UID corroborate mode
and context. Missing rootless facts never independently prove rootful mode.

`outer` contains exactly `id`, `name`, `owner`, `image`, `data_volume`,
`socket_source`, `privileged`, `memory_bytes`, `cpu_quota`, `cpu_period`, and
`pids_limit`. It binds the independently inspected outer identity and immutable
image, run-owned volume and socket, privilege, 4 GiB memory, two CPU quota, and
512-PID limit. `source_boundary` contains exactly `kind=owned_data_volume`,
`volume`, `storage_root`, `root`, `owner`, integer `owner_uid`, and `mode=0700`.
Owner UID is zero in rootful mode and positive in rootless mode. Both images
must have a version tag plus a canonical SHA-256 digest. The harness must
derive expected context independently; copying it from the proof is invalid.
`scripts/native-daemon-uid.py` separately queries the exact owned outer container
for its single dockerd process's effective UID. The root-side command has an
eight-second TERM deadline and two-second KILL grace; bounded collection allows
32 stdout bytes and 4 KiB stderr, with a twelve-second read deadline and at most
twelve further seconds for failed-query teardown. Any stderr, incomplete output,
timeout, overflow or malformed/mismatched UID refuses evidence. The emitter uses
that independently observed private UID, not the submitted proof's value.

The top-level proof contains exactly integer `schema_version=1`,
`contract=bind-relabel-config-v1`, `context`, `shapes`, `cases`, `cleanup`, and
`selinux_effect=unverified`. Cases have exactly `case`, `shape`, and `roles`.
Roles are ordered `oracle`, `rendered`, each with exactly `role`,
`request_check` (`independent_cli` or `literal_rendered` respectively), `id`,
`name`, `owner`, `image`, `source_leaf`, `checks`, `container_cleanup=absent`,
and `source_cleanup=absent`. Names are `dl-br-{run_id}-{case}-{role}`. All eight
container IDs are distinct canonical 64-character lowercase hexadecimal IDs,
also distinct from the outer ID. `checks` contains exactly the passing
`source_boundary`, `literal_bind`, `native_mount`, `running`, `capture`, and
`decoded_mount` results. Top-level cleanup is exactly `containers=absent`,
`sources=absent`, integer `rounds=2`, integer `outstanding=0`, and Boolean
`uncertain=false`. No inspect or request payload belongs in this proof.

Only complete assertions and cleanup allow exclusive publication of a regular
single-link 0600 file inside a canonical caller-owned 0700 capture directory.
It is capped at 16 KiB. Incomplete writes are truncated. The reader
`read_bind_relabel_proof(path, capture_dir, expected_context)` holds directory
and file descriptors, uses no-follow opens, and rejects unsafe ownership,
permissions/special bits, symlinked ancestors, hardlinks, nonregular files,
duplicate JSON keys, oversized/truncated input, inode or metadata drift,
extra/missing keys, wrong context, reordered/duplicate cases, incomplete checks,
and globally reused resource IDs. It returns only the fixed four-shape tuple.
Errors are closed and contain no payload. Private provenance cannot authenticate
against a privileged writer or replace independent archive review.

## Budgets and cleanup

The whole runner remains bounded by 180 seconds. Work requires a cleanup
reserve of `max(45, 5*historical_containers + 15)` seconds: 55 seconds with all
eight historical identities. Commands use a three-second TERM deadline and
0.25-second KILL grace; work curl has a two-second limit. Cleanup curl has a
0.5-second limit and cleanup commands have a 0.75-second TERM deadline plus
0.25-second KILL grace. Work has 400 request/command units and 12 MiB retained
output; cleanup has separate 192-command and 2 MiB bounds. Before changing
command counters or starting any process, checked arithmetic requires
`current_bytes + 2*stream_cap <= selected_pool_limit`. Both stdout and stderr
must fit their full envelopes; arithmetic overflow or a one-byte shortfall
refuses the start callback. Work cannot consume the cleanup pool. Actual
retained bytes are charged after bounded draining. Each acquisition is
conservatively charged sixteen requests and 512 KiB, capped at ten seconds,
sixteen requests, one selected resource, eight expansions, 128 KiB per response,
and 512 KiB total. Every acquisition reserves cleanup before it starts.
Bounded concurrent stdout/stderr draining keeps overflow private and fails it.

Container name collisions are never adopted or deleted. After successful
preflight, uncertain creation may recover an ID only through authenticated
inspection of that attempted exact name. Deletion requires outer ownership and
full container ID/name/image/label checks and uses only the immutable ID. Each
case requires two genuine 404 rounds by ID and name before source removal.
Source removal authenticates the recorded identities and owner/canary contents,
then removes only the exact canary file, empty leaf, exact owner file, and empty
root. There is no recursive deletion. Two source-absence checks follow, and
final global cleanup repeats two rounds for all known container identities and
the source root. Failed or uncertain cleanup stays sticky, blocks publication,
and does not authorize deleting a foreign replacement. Missing creation
metadata never authorizes adopting a source directory. Best-effort drop cleanup
is not completion evidence.

## Integration and verification ownership

The source seam supplies the Rust module, private Python reader, independent
pure controls, and this contract. Primary integration implements module
registration, exact wrapper selection and closed markers, harness environment
forwarding/invocation, independently derived expected context, and raw emitter/schema
plumbing. Complete gates and fresh four-lane native qualification remain required.
The proof needs no new software
dependency, operational pin, or Renovate extraction path.

The owning Python controls are selected with
`python3 -m unittest discover -s tests -p 'test_native_bind_relabel_proof.py'`.
Rust controls cover command admission at exact capacity, one-byte shortfalls
and arithmetic overflow without invoking the start callback or changing the
other byte pool; exact acquisition boundaries; foreign-identity refusal;
independent literal modes, and rendered equality on both APIs and daemon modes.
No host test or offline control qualifies native behavior. All project checks
must run in the primary-controlled DevContainer, followed by independently
reviewed exact-candidate Debian/upstream rootful/rootless evidence and verified
cleanup. The integrated harness requires this fourteenth native test and
independently observes the daemon UID before accepting its private proof.
Implementation does not establish qualification, publication, catalogue
admission, SELinux effects, or consumer schema-2 acceptance.
