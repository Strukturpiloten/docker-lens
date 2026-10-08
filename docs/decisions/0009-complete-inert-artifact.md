# ADR 0009: Add a complete inert Docker review artifact

Status: accepted implementation contract; consumer rehearsal and fresh native
evidence remain open.

[ADR 0015](0015-bind-relabel-intent.md) amends the version-selection and
prerequisite-kind contract for relabelled binds only. Existing artifacts without
those prerequisites retain version 1 and their existing representation.

ADR 0003's newline-delimited `RenderedArtifact::bytes()` is an ordered native
request stream, not a complete migration plan. ADRs 0006 and 0008 added
external network and volume prerequisites that deliberately emit no create
request. Persisting only request bytes loses them and can allow Docker Engine
to auto-create an absent named volume during container creation.

Add `RenderedArtifact::complete_bytes()` as an explicit protected-data read.
It returns version 1 of the complete inert JSON review document: the native
renderer-produced ordered request objects, all external prerequisites in
planning order with local references and exact destination identities, and
the chosen planning context. Network prerequisites include expected driver;
local references serialize as unsigned decimal strings, preserving the full
`u64` range through JSON consumers without IEEE-754 numeric rounding;
volume prerequisites require an existing named volume but do not assert its
contents or ownership. Offline target context includes exact build, release,
all three API dimensions, mode, and reviewed evidence key. Observed context
is explicitly process-local and has no durable observation identifier.
`RenderedArtifact::context()` retains the typed planning context in memory.

The request-only bytes stay unchanged. A caller-created
`RenderedArtifact::new(bytes)` has no verified native-renderer provenance and
cannot produce a complete document, even if its opaque bytes happen to be
JSON. This is an additive pre-1.0 public API, not a change to native request
semantics or capability admission. Both representations are inert; DockerLens
does not check destination existence, copy data, execute requests, contact a
daemon, or write files. Protected values appear only after an explicit bytes
read and remain redacted from Debug and closed errors. See
[`complete-artifact.md`](../complete-artifact.md) for the versioned format.
