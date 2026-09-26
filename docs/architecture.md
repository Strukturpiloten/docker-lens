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
3. A future decoder turns protected capture into observed inventory. It keeps
   missing, null, empty, and redacted apart and never treats `Config.*` as proof
   of authored intent. Findings contain no raw values.
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

`src/acquisition.rs` owns request and resource budgets; `src/evidence.rs` owns
protected values and captures; `src/observation.rs` owns availability and origin;
`src/finding.rs` owns value-free diagnostics; `src/version.rs` owns Engine, API,
mode, and capability facts; `src/target.rs` owns intent, graph, and renderer seams.
These modules define independent ownership boundaries for later native work.

DockerLens has no BoxFerry or other Lens product dependency. BoxFerry will
consume a released DockerLens and route all conversions through its neutral
model. Debian 11 Engine and rootful/rootless coverage require genuine native
tests; discovery of a version number is not compatibility evidence.
