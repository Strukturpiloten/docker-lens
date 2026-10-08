# ADR 0015: Retain bind-relabel intent without claiming SELinux effects

Status: accepted implementation contract; native admission and consumer
integration remain open. Amends ADR 0009 only for artifacts with bind-source
prerequisites; preserves ADRs 0003, 0007 and 0008's inert and protected boundaries.

DockerLens #94 requires closed shared/private bind-relabel intent. Structured
Engine `HostConfig.Mounts.BindOptions` has no relabel field. Legacy
`HostConfig.Binds` retains case-sensitive `z`/`Z`, but can create a missing
source directory when a container starts. Emitting that branch without an
explicit source-review obligation would weaken the structured-mount boundary.

## Contract

`Mount` defaults to no relabel. `Mount::with_bind_relabel` accepts closed
`BindRelabel::Shared` or `Private` only for binds, independently of read-only
access. Repeated assignments, non-bind intent and colon-containing paths fail
with closed value-free errors. Colons are ambiguous in unescaped legacy binds;
ordinary structured mounts retain their wider path domain. Duplicate destination
validation compares Linux lexical slash/dot/parent-component keys across the
complete mount list before splitting fields, including ordinary structured
mounts. `/data`, `/data/` and `/x/../data` therefore collide. The key neither
rewrites authored target bytes nor inspects filesystems or resolves symlinks;
rendered requests and protected prerequisites retain those original bytes.

Only relabelled binds render into `HostConfig.Binds` with explicit `ro,z`,
`rw,z`, `ro,Z` or `rw,Z`. Other mounts keep their structured representation.
`BindRelabelShared` and `BindRelabelPrivate` are separate configured-retention
capabilities, each requiring both read-only and read-write native shapes.
Neither is admitted by the reviewed catalogue; historical evidence is unchanged.
Disconnected `unadmitted_bind_relabel_capability` and
`unadmitted_bind_relabel_shape` schema definitions and closed string parsers
recognize the finite names without changing root reviewed-record vocabulary,
the active sixteen-capability/twenty-six-shape set, cohorts or historical
evidence. The additive-definition regression preserves the exact canonical
root hash. Future sealed admission is a separate reviewed change, not automatic
promotion from definitions, parser recognition or tests.
Four exact native lanes and independent review are still required for admission.
No capability or ordinary SELinux-disabled CI result proves actual relabeling,
enforcement, application acceptance, or arbitrary-host suitability.

Each relabelled bind carries a protected typed `BindSourcePrerequisite`, with
container reference, protected container target identity, original mount index,
source, target, access and relabel
intent. Its closed source obligations require pre-existing, reviewed type,
contents, ownership and permissions. SELinux effects are explicitly unverified;
their closed conditions are enabled daemon SELinux, a nonempty container mount
label, policy/filesystem support and relabel authority. Unknown obligations
remain conditional. Known unsatisfied obligations cannot be treated as supported
execution. DockerLens does no path inspection, source creation, relabeling,
execution or daemon contact while planning/rendering.

Each schema-2 `bind_source` row serializes that protected container name as
`identity`, binding the obligation to the authored container-create target.
The caller-local `reference` remains metadata; arbitrary canonical u64 reference
renaming does not change container names or request bytes. `mount_index` is local
to the container's original mount list and can repeat across containers.
Consumers must use identity to associate the row with its create request and
reject missing or ambiguous associations. The explicit typed accessor is
`BindSourcePrerequisite::identity()`; Debug continues to redact the name.

ADR 0009's complete artifact emits schema 2 only when these prerequisites are
present. Existing schema 1 bytes remain unchanged. Ordered network and volume
prerequisites survive alongside bind obligations. Consumers must reject unknown
versions/kinds instead of dropping prerequisites. Request-only bytes remain
incomplete for review; caller-created opaque bytes have no complete provenance.

Source `MountObservation.mode` retains protected raw bytes, availability and
effective origin. The new `mode_interpretation` field shares those states and
exposes finite access/relabel intent or explicit `Unsupported`. A whole empty
mode means native default; empty comma components, duplicate/contradictory
known groups and bounds violations fail closed. Interpretation is bounded to
256 bytes and 16 tokens. Propagation, consistency, `nocopy` and unknown options
remain unsupported; scanning the entire bounded list prevents an unknown token
from concealing a known contradiction. Unsupported capture findings carry no
raw value. Neither interpretation nor `RW` proves source authorship or actual
SELinux effects; downstream promotion/loss decisions remain BoxFerry-owned.
`Supported` means syntactically supported mode, not coherent native evidence.
An explicit `ro` with `RW: true` or `rw` with `RW: false` retains both observed
fields and yields a value-free `NativeConflict` finding at the mount field.
Missing/null/redacted access fields or a mode without explicit access cannot
invent a contradiction. Consumers must retain that conflict in their evidence
and loss decisions, not promote supported syntax to authored or effect proof.
This pre-1.0 source API adds a public observation field; consumers constructing
`MountObservation` literals must supply the matching interpreted availability
and origin. Consumers must use the Lens interpretation rather than duplicate
native mode parsing. Target callers opt in with the new method; existing
constructors preserve absent relabel intent.

## Evidence boundary

The native grammar references are [Moby v20.10.5](https://github.com/moby/moby/blob/v20.10.5/volume/mounts/linux_parser.go#L166),
[docker-v29.8.1](https://github.com/moby/moby/blob/464cd50c3d9e92877d56940ea160de6fca7bea23/daemon/volume/mounts/linux_parser.go#L177),
and exact [Debian source package 20.10.5+dfsg1-1+deb11u2](https://sources.debian.org/src/docker.io/20.10.5%2Bdfsg1-1%2Bdeb11u2/engine/volume/mounts/linux_parser.go/).
The upstream tag was resolved through its annotated tag object
`b2d20c90a74af78b3f0f967db92292e4a603c03d` to commit
`464cd50c3d9e92877d56940ea160de6fca7bea23`. Research read parser/setup,
Swagger, container inspection, structured mount types and vendored SELinux
label behavior; it did not execute a native oracle. Recorded command patterns
were `timeout 25s gh api --method GET '<endpoint>' -H 'Accept: application/vnd.github.raw+json'`
for versioned GitHub contents and
`curl --disable --max-time 25 --fail --silent --show-error '<url>'` for Debian
source. Exact representative endpoints are
`repos/moby/moby/contents/volume/mounts/linux_parser.go?ref=v20.10.5`,
`repos/moby/moby/contents/daemon/volume/mounts/linux_parser.go?ref=docker-v29.8.1`
and `https://sources.debian.org/data/main/d/docker.io/20.10.5%2Bdfsg1-1%2Bdeb11u2/engine/volume/mounts/linux_parser.go`.
Tag resolution used the same bounded GitHub GET with endpoint
`repos/moby/moby/git/tags/b2d20c90a74af78b3f0f967db92292e4a603c03d` and
`--jq '{tag,object,tagger}'`. The local research executable was
`/home/becks/.local/bin/gh`.

[Docker's SELinux bind documentation](https://github.com/docker/docs/blob/main/content/manuals/engine/storage/bind-mounts.md#configure-the-selinux-label)
was read with that GitHub contents command at endpoint
`repos/docker/docs/contents/content/manuals/engine/storage/bind-mounts.md?ref=main`;
this mutable documentation is explanatory, not version-qualified native proof.
The lexical destination rule is independently referenced by the
[20.10.5 parser](https://github.com/moby/moby/blob/v20.10.5/volume/mounts/linux_parser.go#L293)
and [duplicate guard](https://github.com/moby/moby/blob/v20.10.5/daemon/volumes.go#L184),
and the resolved [29.8.1 parser](https://github.com/moby/moby/blob/464cd50c3d9e92877d56940ea160de6fca7bea23/daemon/volume/mounts/linux_parser.go#L325)
and [duplicate guard](https://github.com/moby/moby/blob/464cd50c3d9e92877d56940ea160de6fca7bea23/daemon/volumes.go#L165).
Legacy and structured parsers share lexical normalization; the duplicate guard
precedes symlink dereference. The supplementary source read used the same
bounded GitHub raw GET at `repos/moby/moby/contents/daemon/volumes.go?ref=v20.10.5`;
other versioned references reused the recorded reads. These are specification
references, not live proof or mechanically translated implementation.
Moby repository license metadata and the exact Debian source copyright report
Apache-2.0; no versioned upstream LICENSE inspection is claimed.
The implementation is authored from scratch. No oracle source or binaries are
copied, mechanically translated or redistributed in this change.
No dependency declarations, pins, tool versions, workflows or Renovate
extraction/ownership paths changed; the existing Renovate configuration remains
unchanged. Historical machine capability evidence remains immutable.

Offline tests cover all four literal modes on API 1.41/1.56 with authored
rootful/rootless facts, absent defaults, mixed mount/prerequisite order,
availability, malformed/unsupported/bounded decoding, privacy and refusal.
They are not native qualification. Native harness/emitter registration is
implemented. Fresh exact-candidate four-lane configured-retention qualification,
independently reviewed catalogue admission, consumer schema support and explicit
BoxFerry mapping/loss remain separate work. Actual SELinux effects require their own suitable host
evidence; no host changes are authorized by this contract.
