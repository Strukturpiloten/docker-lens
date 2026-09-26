# ADR 0002: Bind capture exchanges and separate offline target evidence

Status: accepted contract; native transport and conformance remain unimplemented.

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

Observed-source capability facts remain scoped to one observation. Offline
target planning instead resolves an exact Engine release, API version, daemon
mode, and immutable SHA-256 evidence key against a reviewed catalog. External
callers cannot add catalog records in this milestone; the public catalog is
empty until native conformance supplies reviewed entries. The operation graph
retains which context it used and checks the capabilities needed for its
current standalone container, named volume, and bridge network resources.
Further setting-level checks and release conformance remain mandatory.

Observed facts and authored target intent remain separate. Ports, mounts,
commands, health checks, and restart policies require later native review of
their distinct source and target representations before promotion rules exist.
