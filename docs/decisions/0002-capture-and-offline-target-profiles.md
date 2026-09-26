# ADR 0002: Bind capture exchanges and separate offline target evidence

Status: accepted contract; explicit socket transport implemented, native conformance pending.

Each bounded exchange binds its closed read request, optional local resource
reference, request URL API version, HTTP status, and protected body. The budget
retains the request until a bounded response completes. It owns a process-local
observation ID and rejects capture conversion after failure, timeout, or an
unfinished request. The ID and caller-provided metadata do not authenticate
the transport or prove daemon contact. Native conformance must verify emitted
URLs and captured metadata against independent Engine behavior.
All versioned reads require an explicit API version; only unversioned daemon
version negotiation may omit it. Inspect reads automatically consume the
expansion budget. Each local reference binds one native resource kind and ID,
and each native object binds one local reference throughout a capture.

Observed-source capability facts remain scoped to one observation. An external
caller cannot turn a caller-assembled `DaemonFacts` into positive planning
capabilities by assigning `NativeConformance` provenance: construction of
`ValidatedCapabilities` is internal until a reviewed native path exists.
Offline target planning resolves an exact build origin (upstream or Debian
package revision), Engine release, advertised API, acquisition API, tested
rendering API, daemon mode, and immutable SHA-256 evidence key against the
reviewed catalog. Callers can enumerate admitted profiles and retrieve a
resolved profile's evidence key. The exact identity lookup returns no profile
on any mismatch; a supplied digest alone never adds a catalog record.
The public catalog is empty until native conformance supplies independently
reviewed records. The operation graph retains its resolved context and checks
capabilities for its standalone container, named volume, and bridge network
resources. Further setting-level checks and release conformance remain
mandatory.

Observed facts and authored target intent remain separate. Ports, mounts,
commands, health checks, and restart policies require later native review of
their distinct source and target representations before promotion rules exist.
