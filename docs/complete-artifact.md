# Complete inert Docker review artifact

`RenderedArtifact::bytes()` remains the low-level, newline-delimited native
POST request stream. It is **request-only** and may omit external-resource
and destination bind-source requirements. Consumers persisting or reviewing a migration plan must use
`RenderedArtifact::complete_bytes()` and must reject its closed error for
caller-created opaque artifacts. This API exposes protected authored values
explicitly; storage, display, and access control belong to the consumer.

The complete artifact is one UTF-8 JSON object followed by a newline. Artifacts
without bind-source prerequisites retain version 1 and their existing bytes:

```json
{
  "schema_version": 1,
  "context": {
    "kind": "target",
    "build": { "kind": "upstream" },
    "engine_release": "29.8.1",
    "advertised_api_version": "1.52",
    "acquisition_api_version": "1.49",
    "rendering_api_version": "1.52",
    "daemon_mode": "rootful",
    "evidence_sha256": "<64 lowercase hexadecimal digits>"
  },
  "requests": [
    { "method": "POST", "path": "/v1.52/containers/create?name=app", "body": {} }
  ],
  "prerequisites": [
    { "kind": "network", "reference": "1", "identity": "edge", "expected_driver": "bridge" },
    { "kind": "volume", "reference": "2", "identity": "existing_data" }
  ]
}
```

The example describes fields, not an admitted profile or an executable
request. The `requests` array contains the exact JSON request objects emitted
by the native renderer, in the same order as `bytes()`; no request is inferred
from a prerequisite. `prerequisites` retains the renderer's dependency order,
including when there are no requests. A created-volume request includes its
authored `Labels` object only when nonempty; an external-volume prerequisite
never contains or applies labels. The labelled create branch remains
retained in ADR 0016's coherent candidate for pre-merge consumer rehearsal under
[ADR 0012](decisions/0012-candidate-volume-label-admission.md). Production
merge/main/release remain blocked on fresh exact-final-candidate four-lane
native proof, independently reviewed six-authored-fixture volume-only consumer
rehearsal, reviewed actual Nextcloud/Supabase schema-2 bind consumers and complete
gates; the version 1 format and inert API are unchanged.
A `reference` is the exact unsigned
decimal string of a caller-local `u64` target graph index, never a Docker
resource ID. It is a string so even indices above 2^53, through
`18446744073709551615`, survive JSON consumers without numeric precision loss;
consumers must not coerce it to a floating-point number. `identity` is the exact UTF-8 target
name; JSON escaping does not change its decoded bytes. Target constructors
reject unsupported identity characters. For a Debian package target, `build`
is `{"kind":"debian_package","revision":"<exact package revision>"}`.

For an observed graph, `context` instead contains `kind: "observed"`,
`provenance: "process_local_only"`, `engine_release`, `api_version`, and
`daemon_mode`. Its process-local observation identity remains available only
through the typed in-memory `context()` accessor; serialization does not
invent a durable ID or imply authenticated daemon contact. An offline target
context similarly records the chosen reviewed profile, not a fresh native
compatibility result.

The document carries prerequisites for review and explicit consumer-side
preflight decisions; it does not prove existence, contents, driver at runtime,
or data transfer. Docker Engine may create an absent named volume implicitly
when a container is created, so a consumer must not apply a mount request
without independently checking the external volume prerequisite. DockerLens
has no execution, transport, deployment, or file-writing method.

## Conditional version 2 bind-source prerequisites

ADR 0016 admits shared/private configured retention on all four exact candidate
profiles. This does not establish source suitability or SELinux effects; actual
Nextcloud/Supabase consumer reviews and final-candidate native gates remain required.
Only an artifact containing a relabelled bind emits `schema_version: 2`.
The context, ordered request objects, and existing network/volume prerequisites
keep their version 1 representation. Each relabelled bind adds this closed
prerequisite kind in container planning order and original mount-index order:

```json
{
  "kind": "bind_source",
  "reference": "3",
  "identity": "app",
  "mount_index": "1",
  "source": "/reviewed-host-source",
  "target": "/data",
  "read_only": true,
  "relabel": "private",
  "source_conditions": ["exists", "type_reviewed", "contents_reviewed", "ownership_reviewed", "permissions_reviewed"],
  "selinux_effect": "unverified",
  "selinux_conditions": ["daemon_selinux_enabled", "container_mount_label_present", "policy_filesystem_support", "relabel_authority"]
}
```

`identity` is the exact authored container target name. It associates this
obligation with that container's create request; it is never a native container
ID or an observed name. Consumers must match this name to the create request's
target and reject missing or ambiguous associations. `reference` is only the
caller-local graph reference, never a request-array index or native resource ID;
renaming references does not rename containers or change request bytes.
`mount_index` is the original zero-based index within that container's authored
mount list, also an unsigned decimal string. Different containers can have the
same mount index. Container identity, source and target are protected authored
values disclosed only by an explicit artifact/prerequisite read; DockerLens
does not inspect them. The typed container-name accessor is
`BindSourcePrerequisite::identity()`; its Debug representation stays redacted.
`relabel` is the closed `shared` or `private` intent (`z` or `Z`), independent
of read-only access. A prerequisite records obligations, not satisfied facts.

Relabelled binds render as legacy `HostConfig.Binds`; plain binds, volumes and
tmpfs remain in structured `HostConfig.Mounts`. Legacy binds can create a
missing source directory when a container starts. Consumers must establish
pre-existing destination-host source type, contents, ownership and permissions
before use; known missing or unsuitable sources must be refused. Unknown
conditions remain conditional, not a complete supported-execution claim.

Configured mode retention does not establish host labeling or enforcement.
Actual relabel effects require enabled daemon SELinux, a nonempty container
mount label, suitable policy/filesystem support, and relabel authority. Effects
remain explicitly unverified; disabled SELinux or an empty mount label can be
a no-op. No existing reviewed profile admits the new relabel capabilities.

Consumers supporting only schema 1 must reject schema 2, never ignore its new
prerequisite. Consumers must update their closed schema/kind handling and
retain every obligation before accepting these artifacts. The typed accessor
is `RenderedArtifact::bind_source_prerequisites()`. Caller-created opaque
artifacts still cannot produce either complete version. See
[ADR 0015](decisions/0015-bind-relabel-intent.md).
