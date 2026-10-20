# Harness Unix-HTTP transport v1

DockerLens #119 owns `scripts/native-unix-http.py`, a test-only Python standard
library transport authored independently of the product acquisition implementation.
It contacts only the explicitly supplied absolute AF_UNIX socket. It imports no
product code, discovers no endpoint, resolves no hostname, reads no credentials or
environment configuration, starts no subprocess and has no alternate client.
The fixed `Host: localhost` header is HTTP syntax, never a DNS or TCP destination.

## Python interface

`request(socket_path, method, path, body=None, *, timeout, max_response_bytes,
max_request_bytes=67108864, content_type=None)` returns `(actual_status, bytes)`
only after a complete bounded HTTP response. `body` is absent or exact bytes.
`content_type` is either absent or the literal `application/json`; it is never
inferred. POST always sends an explicit Content-Length, including zero for an
absent/empty body. Caller-supplied origin-form paths and bodies are preserved.

`TransportError.category` is the closed string enum `Category`: `validation`,
`deadline`, `io`, `protocol`, `size`, `output`. Its string representation contains
only that category, and `.code` maps to the CLI exits below. Cancellation
exceptions such as KeyboardInterrupt and SystemExit propagate. Neither API
failure nor cancellation supplies a fabricated HTTP status or proves absence.

One monotonic absolute deadline covers connect, write, headers and body; the CLI
also charges stdin collection to that same deadline. Positive finite timeouts
cannot exceed 3600 seconds; positive body caps cannot exceed 64 MiB. Existing
caller limits, aggregate request/stream counters, process timers and cleanup
reserves remain authoritative and may be stricter. The helper adds no subprocess
controller or renewable invocation budget.

Headers have a separate 16 KiB bound. Complete Content-Length and chunked bodies
are supported, as are empty 204 responses. Conflicting/duplicate framing,
nonidentity encodings, missing framing, malformed/truncated bodies and overbound
responses fail closed. Chunk extensions and trailers are deliberately unsupported;
chunk metadata has a separate 16 KiB aggregate bound. Incremental progress never
renews the deadline. No partial response is returned.

## CLI and observations

Required options are `--socket`, `--method`, `--path`, `--timeout` and
`--max-response-bytes`. `--body-stdin` requires `--max-request-bytes`.
`--json-content-type` requests the explicit JSON header, including on GET when
the caller previously supplied it. Default stdout is the complete raw body,
one LF, and the actual three-digit HTTP status, without a trailing LF.

Mutually exclusive `--discard-body` and `--response-body-file PATH` instead
produce only the status followed by LF. File output requires a fresh exclusive
destination in a caller-owned mode-0700 directory. Directory descriptors reject
symlink traversal; publication links a fully written temporary mode-0600 file
without replacing an existing destination. Failed output is never eligible
evidence: callers must require helper success and their explicit HTTP status.
Do not reuse a destination or interpret old bytes after any failed invocation.

| Exit | Meaning |
| --- | --- |
| 0 | Complete valid HTTP response, including actual 201/204/400/404/500 |
| 2 | Invalid argument |
| 3 | Absolute deadline |
| 4 | Connection or I/O failure |
| 5 | HTTP protocol failure |
| 6 | Size bound |
| 7 | Private output failure |

Transport/protocol/deadline/size failures before publication produce no stdout.
Output failures cannot retract bytes already delivered; the caller must require
successful exit and retain its outer publication/capture timer. Diagnostics use at most the fixed
`native-unix-http-v1:<category-marker>` stderr line. Paths, native exception text,
request/response bytes and protected identities are never diagnostic text.
These exits are helper codes, never curl codes. Outer GNU timeout, signals,
capture failures, original mutation uncertainty and cleanup remain separate.
The readiness loop and final readiness check explicitly require HTTP 200;
API GET capture also requires 200. Only a successful complete real 404 response
can establish absence. An HTTP error is not a transport failure.

Port API diagnostics now identify `version=2 client=unix_http_v1` and distinguish
the six helper categories, outer timeout and signals. The request-timeout
start-window trigger changes from historical curl exit 28 to helper exit 3;
the original outer timeout trigger, absolute deadline and reserves are retained.
Separate TCP/UDP/network-namespace diagnostics retain native curl observations.

## Adoption and qualification

The canonical native harness and every host Engine Unix-HTTP Rust test consumer
use this helper. Their closed route and ownership assertions, byte/request
budgets, uncertain mutations, absence rounds and the original twenty-four exact
native invocations are preserved. The appended source gates are required by the
[current canonical four-lane suite](verification.md). Docker CLI, Compose providers,
real Rust acquisition and independent fixed native expectations remain separate oracles. The
TCP/UDP/network-namespace curl probes remain mandatory and unchanged.
[ADR 0023](decisions/0023-process-source-proof-wiring.md) adds hostname/command-clear source wiring without changing this
transport. That process slice's raw source counts were Debian 37/59 and upstream 39/63.
[ADR 0024](decisions/0024-health-disabled-raw-source-projection.md) separately adds
raw-only HealthDisabled after the unchanged complete health proof validates;
[ADR 0025](decisions/0025-shm-size-source-integration.md) adds the separate
twenty-fourth ShmSize source gate without changing this transport. [ADR 0026](decisions/0026-runtime-settings-source-integration.md) appends the
mandatory supplementary/kernel source gates as invocations 25/26; their four
finite raw groups remain unselected and host capture stays deferred. Current
combined raw projection totals are Debian 43/66 and upstream 45/70.
[ADR 0022](decisions/0022-reviewed-lifecycle-cohort.md)'s separate compiled selection stays 34/56 and 36/60. Historical
21-invocation source records remain unchanged; fresh final-candidate qualification
uses the 26-invocation canonical harness.

Local/main/reviewed-native-dispatch/release native definitions all consume
`scripts/native-conformance.sh`; the complete offline gate discovers
`tests/test_native_unix_http.py` through its existing unittest discovery.
BoxFerry #366 must bind both the reviewed DockerLens revision and the exact
helper SHA-256, in addition to native-script identity, and adopt all matching
consumers. Frozen producer receipts require a new producer build and receipt;
a digest-only refresh does not qualify changed code.

[ADR 0020](decisions/0020-harness-unix-http-transport.md) supersedes the narrow
curl-only freeze. Python and curl have different executable-specific AppArmor
mediation; this implementation neither diagnoses/repairs historical curl denial
nor promises identical confinement. Historical archives and failed captures
remain historical and unchanged. No host security, privileges, image, launcher,
capability catalogue or software pin changes are part of this transport change.

Renovate review: `renovate.json` remains unchanged. Its native-image custom
manager still uniquely matches `scripts/native-conformance.sh` and extracts the
same five tag/digest declarations for the two upstream, two Debian and BusyBox
images. The rust-toolchain custom manager, Cargo/GitHub Actions managers, image
grouping and manual approval/automerge policy are unchanged. Python was already
a runner prerequisite; this stdlib-only helper adds no dependency, downloaded
tool, operational pin or extraction path. ComposeLens, PodmanLens, QuadletLens
and the website do not consume this Docker-only helper and need no changes.

Authored fake-server tests cover wire bytes, actual status, framing, bounded
incremental progress, stdin, cancellation, private output and cleanup-related
failure. They do not establish native compatibility. Final-edit complete gates,
independent review, fresh exact-candidate four-lane execution, required BoxFerry
core/volume/application gates and normal PR checks remain mandatory. This
document authorizes no native retry, release, publication or deployment.
