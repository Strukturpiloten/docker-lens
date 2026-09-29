# Complete inert Docker review artifact

`RenderedArtifact::bytes()` remains the low-level, newline-delimited native
POST request stream. It is **request-only** and may omit external-resource
requirements. Consumers persisting or reviewing a migration plan must use
`RenderedArtifact::complete_bytes()` and must reject its closed error for
caller-created opaque artifacts. This API exposes protected authored values
explicitly; storage, display, and access control belong to the consumer.

Version 1 is one UTF-8 JSON object, followed by a newline:

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
capability-unadmitted pending exact native evidence.
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
