# Architecture

## Data flow

1. An explicitly supplied endpoint and selector create a bounded read request
   plan. Every operation belongs to the closed `ReadRequest` enum.
2. A future transport records each closed read request, its local resource
   reference when inspecting a resource, and the API version from its actual
   request URL. Versioned reads require that version; only unversioned
   `DaemonVersion` negotiation may omit it. Inspections count against the
   expansion budget. Within one capture, a local reference binds one native
   kind and ID, and that native object binds one local reference. `Budget`
   stores the HTTP status and protected body with that
   request, checks limits while reading, and creates one process-local
   observation ID for the completed capture. A failed or unfinished budget
   cannot become a capture. The transport must enforce an I/O deadline:
   synchronous counters cannot interrupt a blocked reader. These records and
   counters are caller-supplied, not proof of daemon contact. Responses may be
   from different moments; this is not an atomic snapshot.
3. `decoder::decode_capture` turns protected capture into typed observed inventory.
   It checks closed requests, local references, status, and actual request API
   versions; caps JSON responses at 8 MiB and collections at 4096 entries; and
   reports closed errors without native bytes. It keeps missing, null, empty,
   and redacted apart and never treats `Config.*` as proof of authored intent.
   Runtime port bindings and network addresses have runtime-assigned origin.
   Findings contain no raw values. A caller-provided capture is not proof of
   daemon contact.
4. Target intent currently carries explicit resource identities, a container
   image, and protected environment assignments. A future planner accepts
   either validated observed-daemon capabilities or a distinct offline target
   profile. The offline profile names an exact Engine release, API version,
   daemon mode, and SHA-256 key of reviewed capability evidence; it must match
   an entry in the reviewed catalog. The public catalog is empty until native
   conformance supplies reviewed records, so callers cannot admit arbitrary
   positive capabilities. The operation graph retains the chosen context and
   checks the current resource requirements: standalone containers, named
   volumes, and bridge networks. A network target currently means a bridge
   network; other network modes await explicit native review. Offline targets
   never receive a fabricated observation ID. Future setting-level checks
   and a renderer produce inert bytes. DockerLens never
   applies those operations or writes the artifact.

`src/acquisition.rs` owns request and resource budgets; `src/decoder.rs` owns
pure native JSON decoding; `src/evidence.rs` owns
protected values and captures; `src/observation.rs` owns availability and origin;
`src/finding.rs` owns value-free diagnostics; `src/version.rs` owns Engine, API,
mode, and capability facts; `src/target.rs` owns intent, graph, and renderer seams.
These modules define independent ownership boundaries for later native work.

## Decoder evidence boundary

`decode_capture` accepts only the closed acquisition request set. It checks
HTTP status, retains opaque resource references, and records the request URL
API versions; it does not contact or authenticate a daemon. Discovery lists
may include resources outside a bounded selection. A nonempty list with no
matching inspection of its kind fails as incomplete; when acquisition records
a selected-container count, fewer inspections than selected containers also
fail. Unselected list entries do not force extra inspections. Matching uses
canonical native IDs or volume names from the closed inspect requests.
Container `Config.*` and `HostConfig.*` values have effective origin, because
image defaults and runtime normalization can contribute to them. Observed
`NetworkSettings.Ports`, network addresses, image IDs, and volume mountpoints
have runtime-assigned origin. Network endpoint aliases are retained as
protected effective values with missing, null, empty, and redacted states.
A single-field redaction envelope
`{"__docker_lens_redacted__":true}` denotes unavailable data and never yields a
value. Native JSON with that exact shape is also conservatively unavailable.
`HostConfig.NetworkMode` retains the native alias and distinguishes default,
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
model. Debian 11 Engine and rootful/rootless coverage require genuine native
tests; discovery of a version number is not compatibility evidence.
