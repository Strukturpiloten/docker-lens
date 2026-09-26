# Architecture

## Data flow

1. An explicitly supplied endpoint and selector create a bounded read request
   plan. Every operation belongs to the closed `ReadRequest` enum.
2. A future transport captures bytes under `Limits`, checking the bound while
   reading and enforcing an I/O deadline. The current `Budget` checks elapsed
   time before and after reads but cannot interrupt a blocked reader. Supplied
   `CaptureBounds` accounting is not proof of daemon contact. Responses may be
   from different moments; this is not an atomic snapshot.
3. A future decoder turns protected capture into observed inventory. It keeps
   missing, null, empty, and redacted apart and never treats `Config.*` as proof
   of authored intent. Findings contain no raw values.
4. Target intent currently carries explicit resource identities, a container
   image, and protected environment assignments. A future planner maps intent
   and capability claims scoped to one acquisition identity, exact Engine
   release, API version, and daemon mode to an operation graph. The process-local
   identity prevents accidental reuse across same-version daemon observations;
   it is not independent evidence that a daemon was contacted. A future renderer produces
   inert bytes. DockerLens never
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
