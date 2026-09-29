# Architecture

## Data flow

1. An explicitly supplied endpoint and selector create a bounded read request
   plan. Every operation belongs to the closed `ReadRequest` enum.
2. The explicit Unix-socket transport records each closed HTTP GET request, its local resource
   reference when inspecting a resource, and the API version from its actual
   request URL. Versioned reads require that version; only unversioned
   `DaemonVersion` negotiation may omit it. Inspections count against the
   expansion budget. Within one capture, a local reference binds one native
   kind and ID, and that native object binds one local reference. `Budget`
   stores the HTTP status and protected body with that
   request, checks limits while reading, and creates one process-local
   observation ID for the completed capture. A failed or unfinished budget
   cannot become a capture. Socket connection, reads, and writes use the
   remaining acquisition deadline and 100 ms cancellation polls. Body limits
   are separate from the 16 KiB response-header cap. The transport requires
   Content-Length or chunked framing and rejects other content encodings.
   A capture route distinguishes caller assembly from explicit socket contact;
   neither proves the peer is a genuine Engine. Responses may be from different
   moments; this is not an atomic snapshot.
3. `decoder::decode_capture` turns protected capture into typed observed inventory.
   It checks closed requests, local references, status, and actual request API
   versions; caps JSON responses at 8 MiB and collections at 4096 entries; and
   reports closed errors without native bytes. It keeps missing, null, empty,
   and redacted apart and never treats `Config.*` as proof of authored intent.
   Runtime port bindings and network addresses have runtime-assigned origin.
   Findings contain no raw values. A caller-provided capture is not proof of
   daemon contact.
4. Target intent carries explicit identities and typed standalone container
   settings: image, scoped and repeated port publications, mounts, typed
   bridge networks and attachments, protected environment and metadata,
   explicit command/entrypoint inheritance or clearing, exec/shell/disabled
   health and timing, runtime settings, and restart policy.
   The public planner admits
   only profiles resolved from the reviewed catalog; caller-authored positive
   daemon claims cannot authorize planning. A profile distinguishes upstream
   from an exact Debian package revision, the reported Engine release,
   advertised maximum API, negotiated acquisition API, tested rendering API,
   and daemon mode. Catalog discovery returns its SHA-256 evidence key. The
   public catalog contains four exact records from a reviewed historical native
   run. Each changed candidate and release needs fresh complete and four-lane
   native gates before a compatibility claim. The operation graph
   retains the chosen context and
   checks standalone containers, named volumes, bridge networks, and each
   requested setting. Other network modes await explicit native review.
   Offline targets never receive a fabricated observation ID. The renderer
   emits inert Engine API request descriptions; it never contacts a daemon,
   applies an operation, or writes the artifact. API versions below 1.41 are
   rejected conservatively pending independent native evidence.
   The renderer also owns a [versioned complete review artifact](complete-artifact.md)
   containing those ordered requests, external prerequisites, and target
   context/evidence binding. Its explicit bytes read is distinct from the
   legacy request-only stream; neither representation executes work.

`src/acquisition.rs` owns the closed socket transport, request and resource budgets; `src/decoder.rs` owns
pure native JSON decoding; `src/evidence.rs` owns
protected values and captures; `src/observation.rs` owns availability and origin;
`src/finding.rs` owns value-free diagnostics; `src/version.rs` owns Engine, API,
mode, and capability facts; `src/target.rs` preserves public target paths while
`src/target_modules/intent.rs` owns shared intent and validation,
`src/target_modules/container.rs` owns container types,
`src/target_modules/network.rs` owns typed bridge and attachment intent,
`src/target_modules/graph.rs` owns planning, and
`src/target_modules/render.rs` dispatches inert rendering to separate
container and network modules. The [migration ledger](standalone-migration-ledger.md)
defines subsequent ownership and evidence requirements.

Created network resources emit inert bridge-create requests. External network
resources remain explicit `RequireExisting` graph steps and protected
artifact prerequisites; they emit no create request and do not claim
existence. A container's first attachment is in its create request, while
each later attachment has its own step ID and inert network-connect request.
New network capability facts are absent from the four historical profiles
until exact-lane native conformance and independent evidence review.
New container-setting facts are likewise absent. `StartInterval` is gated by
an exact capability claim; no generic Engine API introduction version is
assumed from Compose metadata. Port rendering groups host bindings under one
container port/protocol key and preserves an explicitly authored host address
or ephemeral allocation request. Values remain protected in Debug and
diagnostics. The renderer still produces only inert request data.
These modules define independent ownership boundaries for later native work.

## Decoder evidence boundary

`decode_capture` accepts only the closed acquisition request set. It checks
HTTP status, retains opaque resource references, and records the request URL
API versions; it does not contact or authenticate a daemon. Discovery lists
may include resources outside a bounded selection. A nonempty list with no
matching inspection of its kind fails as incomplete; when acquisition records
a selected-container count, fewer inspections than selected containers also
fail. Unselected list entries do not force extra inspections. Socket captures
retain the protected selection predicate; replay recomputes every matching
canonical container ID from bounded list metadata and requires that exact set
of root inspections. List IDs must be 64 hexadecimal characters before any
inspect. Inspect bodies must bind to the requested container ID, network ID
or recorded network-name fallback, or volume name. Two network lookups that
resolve to the same native ID fail as conflicting capture evidence. Matching uses
canonical native IDs or volume names from the closed inspect requests.
Discovery-only captures contain bounded, protected list metadata and no
container inspections. Literal name, name-prefix, and label selectors inspect
only matching container IDs from that metadata. Direct container-ID selection
requires a full 64-character hexadecimal ID and does not list ambient
containers. A completed socket capture retains opaque selected-root references
and closed selection reasons; replay checks their inspect and list closure.
Unmatched peer metadata stays protected. Effective runtime, network IPAM, and
mount observations are not authored target intent. Unmapped native bytes remain
in the protected capture for an explicit downstream loss decision.
Container `Config.*` and `HostConfig.*` values have effective origin, because
image defaults and runtime normalization can contribute to them. Observed
`NetworkSettings.Ports`, network addresses, image IDs, and volume mountpoints
have runtime-assigned origin. Network endpoint aliases are retained as
protected effective values with missing, null, empty, and redacted states.
An inspected network's validated native `Id` is separately exposed as a protected,
runtime-assigned typed observation. A name-fallback request does not turn its
selector or an empty endpoint `NetworkID` into that identity.
A single-field redaction envelope
`{"__docker_lens_redacted__":true}` denotes unavailable data and never yields a
value. Native JSON with that exact shape is also conservatively unavailable.
`HostConfig.UsernsMode` retains an independently available effective runtime
value. `HostConfig.NetworkMode` retains the native alias and distinguishes default,
bridge, host, none, container sharing, and named modes. Non-bridge modes receive
a value-free unsupported-setting finding pending target review. Healthcheck
tests distinguish `CMD`, `CMD-SHELL`, `NONE`, and unknown forms; start period
and start interval remain separate nanosecond values when reported.

`/version` supplies Engine release and API range; `/info` can corroborate the
release and explicitly report rootless mode. Each known API bound is enforced
even if the other bound is absent. A missing rootless marker does not
prove rootful mode. Neither endpoint supplies a trustworthy client release or
distribution package revision, so those stay unknown until separate evidence
is available. Decoded version strings do not add positive capability facts.

DockerLens has no BoxFerry or other Lens product dependency. BoxFerry will
consume a released DockerLens and route all conversions through its neutral
model. Debian 11 and upstream Engine 29 coverage in both daemon modes uses
maintained, digest-pinned GHCR images with native entrypoints. The validation
harness mounts an explicit named volume at each image's data root and binds
only a private Unix test socket. Debian package provenance is checked inside
the image. Genuine native runs and independent review are required before any
compatibility catalog record is positive; discovering a version number is
not compatibility evidence.
