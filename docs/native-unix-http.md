# Harness Unix-HTTP transport v1

`scripts/native-unix-http.py` is independently authored test infrastructure using
only Python's standard library and an explicit absolute AF_UNIX socket. It imports
no product/sibling code, starts no subprocess, discovers no endpoint and reads no
credentials or environment selectors. `Host: localhost` never causes DNS or TCP.

## Interface and bounds

`request(socket_path, method, path, body=None, *, timeout, max_response_bytes,
max_request_bytes=67108864, content_type=None)` returns `(actual_status, bytes)`
only for a complete bounded response. Body is absent or exact bytes; content type
is absent or literal `application/json`. POST always sends Content-Length.
Origin-form paths and body bytes are preserved. `TransportError.category` is one
of `validation`, `deadline`, `io`, `protocol`, `size`, `output`; `.code` maps to
CLI exits below. Cancellation propagates; failure never invents an HTTP status.

One monotonic deadline covers connect/write/headers/body and CLI stdin. Positive
finite timeouts are at most 3600 seconds; positive body caps at most 64 MiB.
Headers and aggregate chunk metadata each have a separate 16 KiB cap. Complete
Content-Length/chunked bodies and empty 204 responses are supported. Conflicting
or duplicate framing, encodings other than identity, absent framing, malformed,
truncated or overbound bodies, chunk extensions and trailers fail closed.
Progress never renews deadlines. Caller budgets and cleanup remain authoritative.

Required CLI options: `--socket`, `--method`, `--path`, `--timeout`,
`--max-response-bytes`. `--body-stdin` requires `--max-request-bytes`;
`--json-content-type` adds the explicit JSON header. Default stdout is body, LF,
actual three-digit status without trailing LF. Mutually exclusive `--discard-body`
and `--response-body-file PATH` instead emit status plus LF. File publication
requires a fresh exclusive destination in a caller-owned mode-0700 directory,
rejects symlink traversal, and links a complete mode-0600 temporary file without
replacement. Require successful exit and the explicitly expected real status;
never reuse old bytes after failure. Output errors cannot retract delivered bytes.

CLI exits: 0 complete response (including HTTP error statuses), 2 invalid argument,
3 deadline, 4 connection/I/O, 5 protocol, 6 size, 7 private output. Failures before
publication emit no stdout. Diagnostics are only the fixed
`native-unix-http-v1:<category-marker>` line, never protected identities or bytes.
These are helper exits, not curl codes. Outer timeout/signals, capture failures,
mutation uncertainty and cleanup remain separate. Only successful complete
transport with an explicitly required real status can supply absence evidence.

## Bounded adoption and qualification

DockerLens #127 supplies this standalone helper for BoxFerry's reviewed test-only
closure. Existing DockerLens native harness and Rust HTTP consumers are
not migrated. Their nineteen mandatory invocations, transport, ownership, limits,
deadlines and cleanup remain unchanged. No broker, runtime pipeline, native roster
or product API is transplanted. Consumers must bind exact reviewed revision and
helper bytes, retain admission/ownership controls and qualify actual adoption.
The helper neither authorizes mutations nor discovers resources.

Existing unittest discovery runs independent fake-AF_UNIX wire/framing/bounds/
deadline/cancellation/private-publication tests without an Engine. They establish
no native compatibility. Frozen producer receipts require a new producer build
and receipt; a digest-only refresh is insufficient. Python is already required;
this stdlib-only helper adds no dependency, downloaded tool, operational pin or
Renovate extraction path. Five native image references/grouping are unchanged.
