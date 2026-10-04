# DockerLens

DockerLens is a native Docker Engine library under construction. The current
crate establishes privacy, observation, bounded explicit Unix-socket acquisition,
pure Engine JSON decoding, and inert standalone target planning and rendering.
It does not execute a target. Four exact profiles backed by reviewed native
source records are available for inert rendering. Each changed candidate and
release must pass fresh complete and four-lane native gates before a
compatibility claim.

The planned native work is tracked in [DockerLens #3](https://github.com/Strukturpiloten/docker-lens/issues/3).
Typed multi-network target intent, external prerequisites and secondary
connect requests are available as inert data. The four exact profiles admit
external volume/network prerequisites and internal bridge creation through the
reviewed #68 cohort. Other topology shapes still await native admission.
Typed container intent also distinguishes host-IP scoped, repeated and
ephemeral publications, exposed-only ports, command clearing, shell and
disabled health checks, and protected runtime settings. These new branches
likewise remain capability-unadmitted pending exact native evidence.
Created named volumes can carry bounded protected labels in the inert target
contract. Labelled creation has its own unadmitted capability; external-volume
prerequisites cannot carry labels or mutate an existing volume.
The [standalone migration ledger](docs/standalone-migration-ledger.md) records
the finite remaining shapes, evidence, and implementation owners; the current
0.1.0 surface is the foundation, not completion of that ledger.
BoxFerry integration is a separate stream in
[BoxFerry #343](https://github.com/Strukturpiloten/boxferry/issues/343).
Debian 11 Docker Engine support is bounded by exact reviewed native evidence; Debian 11
Compose compatibility and Swarm mode are separate discussion topics.

## Contract boundaries

- A caller supplies an absolute Unix-socket endpoint and bounded selector. No
  daemon is discovered. Cancellation is checked between bounded I/O polls.
- Acquisition uses a closed set of HTTP GET requests and enforces request count,
  selection, expansion, response bytes, total bytes, and elapsed time.
- Negotiation reads unversioned `/version`, then uses the greatest reported API
  at or below the currently understood 1.49 ceiling, provided the daemon's
  declared minimum permits it. API versions below 1.41 fail closed. Selected
  containers and their referenced networks and named volumes are inspected.
  Response headers have a separate 16 KiB cap; bodies require a bounded
  Content-Length or chunked framing. An unsupported framing or encoding fails.
- Captured bytes and observed values are protected. Findings contain only closed
  codes, opaque local resource references, and closed field categories.
- Each completed capture exchange binds its closed request, local resource
  reference where applicable, actual request-URL API version, HTTP status, and
  protected body. Inspect reads count as expansions and native objects have
  one-to-one local references within a capture. An unfinished or failed acquisition cannot
  become a capture.
- The capture records whether it was caller assembled or read through the
  explicit socket API. Socket contact does not authenticate a Docker Engine;
  replay is pure and makes no atomic-snapshot claim.
- Availability (missing, null, empty, present, redacted) and origin (configured,
  effective, runtime assigned, unknown) are independent. `Config.*` fields do
  not imply an application author wrote those values.
- Engine release, API version, daemon mode, and capability facts are separate.
  Capability claims are tied to an opaque acquisition identity as well as the
  exact daemon facts; caller-declared provenance is not proof of conformance.
- An offline target profile distinguishes upstream builds from an exact Debian
  package revision, the reported Engine release, advertised maximum API,
  negotiated acquisition API, tested rendering API, and daemon mode. The
  reviewed catalog exposes exact profiles and their immutable evidence digests;
  callers cannot manufacture positive planning claims. It contains four exact
  profiles backed by reviewed native source records. Offline planning does not invent
  a live observation. The operation graph retains the resolved context and
  checks capabilities for each requested standalone shape.
- Target intent includes explicit resource identities, container image,
  typed publications and mounts, typed bridge-network resources and
  per-container attachments, protected environment and metadata, explicit
  command inheritance/clearing, health forms and timing, runtime settings,
  and restart policy. Additional container-setting and remaining network shapes remain
  capability-unadmitted.
  Unsupported settings remain explicit.
  Target intent, operation graph, and rendered artifact are inert data. The
  crate has no executor, deployment API, or file writer.
  `RenderedArtifact::bytes()` is a request-only stream; consumers needing
  external network and volume prerequisites use the [complete inert review
  artifact](docs/complete-artifact.md) instead.

Native conformance has separate maintained Debian 11 and upstream Engine 29
rootful/rootless image lanes, each pinned by tag and digest. Passing hosted
evidence for live #10 acquisition and #12 target
request conformance is required before any compatibility claim. See
[architecture](docs/architecture.md) and
[verification](docs/verification.md).
