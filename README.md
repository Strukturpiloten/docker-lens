# DockerLens

DockerLens is a native Docker Engine library under construction. The current
crate establishes privacy, observation, acquisition-limit, and inert target
contracts. It does **not** connect to Docker, decode Engine responses, render
output, validate an Engine version, or execute a target.

The planned native work is tracked in [DockerLens #3](https://github.com/Strukturpiloten/docker-lens/issues/3).
BoxFerry integration is a separate stream in
[BoxFerry #343](https://github.com/Strukturpiloten/boxferry/issues/343).
Debian 11 Docker Engine support needs independent native evidence; Debian 11
Compose compatibility and Swarm mode are separate discussion topics.

## Contract boundaries

- A caller supplies an endpoint and bounded selector. No daemon is discovered.
- Acquisition uses a closed set of read requests and enforces request count,
  selection, expansion, response bytes, total bytes, and elapsed time.
- Captured bytes and observed values are protected. Findings contain only closed
  codes, opaque local resource references, and closed field categories.
- Each completed capture exchange binds its closed request, local resource
  reference where applicable, actual request-URL API version, HTTP status, and
  protected body. Inspect reads count as expansions and native objects have
  one-to-one local references within a capture. An unfinished or failed acquisition cannot
  become a capture.
- Availability (missing, null, empty, present, redacted) and origin (configured,
  effective, runtime assigned, unknown) are independent. `Config.*` fields do
  not imply an application author wrote those values.
- Engine release, API version, daemon mode, and capability facts are separate.
  Capability claims are tied to an opaque acquisition identity as well as the
  exact daemon facts; caller-declared provenance is not proof of conformance.
- An offline target profile uses an exact Engine release, API version, mode and
  immutable capability-evidence digest. It must match a reviewed catalog entry;
  the public catalog remains empty until independent native review supplies
  records. Offline planning does not invent a live observation. The operation
  graph checks capabilities for the current standalone container, named volume,
  and bridge network shapes, then retains its planning context.
- Target intent includes explicit resource identities, a container image, and
  protected environment assignments; other settings await native review.
  Target intent, operation graph, and rendered artifact are inert data. The
  crate has no executor, deployment API, or file writer.

No native conformance has been established yet. The release validation workflow
contains a deliberately failing native gate until a separately reviewed native
suite replaces it. See [architecture](docs/architecture.md) and
[verification](docs/verification.md).
