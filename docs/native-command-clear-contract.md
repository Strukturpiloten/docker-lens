# Native command and entrypoint clear source contract

`command-clear-v1` is a bounded DockerLens #39/#30 test-only source proof.
Product target planning and rendering remain inert. The proof creates no public
profile, catalogue selection or compatibility claim. Historical records remain
unchanged. [ADR 0023](decisions/0023-process-source-proof-wiring.md) integrates the exact ignored invocation
`native_health_metadata_tests::command_clear::live_command_clear_matches_engine`
as mandatory canonical invocation 23, after hostname invocation 22 and its
mandatory strict reader. The inline command-clear adapter always validates the
fixed private `command-clear-v1.json` against twelve independent harness facts,
even when public evidence emission is disabled. Fixed diagnostics retain the
first causal stage/panic only; cleanup-unverified always fails.

The unchanged nineteen-argument emitter requires both strict private proofs
before any new group or output. ADR 0023's process slice maps only ContainerHostname,
CommandClear/ClearCommand and EntrypointClear/ClearEntrypoint. That slice's raw totals
were Debian 37 capabilities/59 shapes and upstream 39/63, with closed source-only/
unadmitted public family outcomes. No hostname, argv, IDs, timestamps or private
payloads are projected. Compiled selection stays 34/56 and 36/60; HealthDisabled
was excluded from that slice. [ADR 0024](decisions/0024-health-disabled-raw-source-projection.md)
separately derives only raw HealthDisabled/DisabledHealthcheck after the unchanged
complete health-metadata-v1 validation. [ADR 0025](decisions/0025-shm-size-source-integration.md)
adds raw ShmSize after its separate complete proof; [ADR 0026](decisions/0026-runtime-settings-source-integration.md) appends the
mandatory supplementary/kernel source gates as invocations 25/26; their four
finite raw groups remain unselected and host capture stays deferred. Current combined raw totals
are 43/66 and 45/70 without selecting any of these groups. The original 23 ordered
invocations remain unchanged and ShmSize is mandatory invocation 24. Private v1 protocols and historical schema-root acceptance remain
unchanged through disconnected public projection definitions.

Four ordered cases each require an independently authored Docker CLI oracle and
a DockerLens-planned/rendered request applied only by the isolated native fixture:

| Case | Rendered entrypoint | Rendered command | Required effect |
| --- | --- | --- | --- |
| image_defaults | omitted | omitted | image entrypoint plus image command |
| entrypoint_inherit | explicit executable | omitted | explicit entrypoint without image command |
| command_clear | same explicit executable | literal `[]` | explicit entrypoint without image command |
| entrypoint_clear | literal `[]` | explicit executable and argument | explicit command without image entrypoint |

`Inherit` preserves omission, rather than promising an image default survives
an entrypoint override. The two middle effects intentionally agree: the proof
does not claim the empty Cmd array causally differs from the omitted Cmd field
when an explicit entrypoint already suppresses image CMD. Command clear with
inherited/cleared entrypoint remains rejected by the existing intent contract.
No empty-string Cmd substitution is introduced. Entrypoint clear is independent.

## Independent process oracle

The harness borrows only its existing digest-pinned BusyBox. One exact stopped
seed is created, started with a fixed bounded script, and inspected for exact
ownership, command and successful exit. It writes three fixed executable probes
only in its own image layer. One bounded commit sets image ENTRYPOINT to
`/dl-image-entrypoint` and CMD to `image-command`. The sole derived tag is
`dl-command-clear-<lowercase-run>:fixture`; both original tag absence and the
committed canonical image ID/default vectors/run label must be checked.
There is no build, pull, new external image pin, global prune or host write.

Each probe requires actual shell PID 1, writes its own `$0` and `$@` to a fixed
marker, then loops. Three executable paths distinguish image entrypoint,
explicit entrypoint and explicit command. The CLI's single executable
`--entrypoint` spelling therefore does not need to move entrypoint arguments
into Cmd. The entrypoint-clear oracle uses an empty CLI entrypoint and an
explicit positional command. Rendered requests are compared against independent
literal complete requests before application, including omission versus `[]`.

Direct Engine inspect must agree on configured vectors, actual image ID,
Path/Args, running state, positive PID, zero restarts and no error/paused/dead/OOM
state. An independent exec reads the PID1-written marker and the exact NUL
terminated `/proc/1/cmdline` bytes. The shebang process argv is expected to be
`/bin/sh`, the exact probe path, then the expected arguments. A readback-only,
process-only, default-preserving, unknown or unobservable result fails.
These shebang/native assumptions require real lane execution; offline tests
cannot establish them. No application or arbitrary-image semantics are claimed.

Only fields whose expected effective vector is empty may be native JSON null
or an empty array. The exact actual variant is retained and validated alongside
all process effects; missing keys, `[""]`, nonempty defaults, malformed types
and variant disagreement fail. Nonempty vectors must match exactly. Literal
rendered clear arrays must remain `[]` even when native readback canonicalizes
to null. There is no blanket null/inherit normalization.

## Ownership, budgets and cleanup

The command wrapper delegates away the health-specific destructor without
marking it cleaned. Its own destructor attempts bounded command cleanup on
every early exit; attempted and verified cleanup are distinct. Terminal cleanup
attempts once, preserves the original observation failure and emits fixed
`command_clear_cleanup_unverified` when incomplete. An uncertain result never
publishes proof or becomes a successful native outcome. The canonical outer
container/storage owner remains responsible for final cleanup after failure.

Nine exact run-owned slots comprise eight case containers and the seed. Cleanup
rechecks name/ID/image/run ownership, deletes only bound exact IDs, and verifies
immediate ID/name absence. It removes the sole derived image by canonical ID
with `force=0` only after all container removals verify and tag/ID/default/owner
checks agree. Two subsequent complete direct ID/name and image ID/tag absence
rounds are mandatory. Ownership ambiguity retains resources and fails; no global
cleanup or borrowed-image deletion is permitted. The nine-slot complete path
uses at most 89 reserved commands (45 container removal/readback operations,
36 final container absence reads, four image operations and four image absence
reads), within the unchanged 100-call cleanup reserve. Actual elapsed cleanup
completion still requires native evidence.

HealthRun's existing 400-command/4-MiB total, 300-command/2-MiB ordinary-work,
100-command/2-MiB cleanup and 46-second work cutoff are reused unchanged.
Commands retain existing at-most-eight-second timers and kill grace; counters
and the original invocation deadline are never reset. Actual acquisition,
CLI/Engine identity, daemon effective UID and package checks are reused.
Locally authored before/after outer snapshots bind the immutable outer ID,
run/image/resource limits, storage/socket mounts and network. The borrowed base
ID/digests/config must remain identical. These final snapshots use ordinary
work limits rather than cleanup streams.

## Private protocol and validation

The fresh fixed file `command-clear-v1.json` uses the existing held-directory,
exclusive no-follow mode-0600 publication inside a mode-0700 private capture
directory, at most 16 KiB. The hardened reader retains the existing stable-file,
single-link, owner, duplicate-key and direct-child checks. It requires an
independently supplied expected harness context, not this proof's self-reported
context. Environment keys are `NATIVE_COMMAND_CLEAR_CANDIDATE_SHA`,
`NATIVE_COMMAND_CLEAR_DEADLINE_EPOCH` and `NATIVE_COMMAND_CLEAR_PROOF_PATH`.

Root fields are exactly schema_version (integer 1), contract, context, shapes
(`ClearCommand`, `ClearEntrypoint`), borrowed_image, derived_image, seed, ordered
cases and cleanup. The strict executable schema is
`scripts/native_command_clear_proof.py`. It requires all eight distinct role
IDs, a distinct seed/outer ID, exact defaults/configuration/Path/Args/process
argv/marker facts, and two verified cleanup rounds with no outstanding or
uncertain resources. Partial/swapped cases, missing controls, wrong types,
image ownership drift, readback/effect disagreement and cleanup uncertainty
reject with fixed value-free errors. This is trusted-harness completion, not
cryptographic attestation against a privileged writer.

Current official Docker documentation was consulted through Context7
`/docker/docs`: the Docker CLI run reference documents that `--entrypoint`
suppresses image CMD, including the empty-string reset; the Dockerfile reference
documents CMD/ENTRYPOINT cooperation. These informed independent expected
values; no oracle source was copied or mechanically translated. Native oracle
versions/provenance/licenses remain the harness-pinned Debian package
20.10.5+dfsg1-1+deb11u2 and upstream Engine 29.8.1 under ADR 0004 and existing
dependency policy. No new dependency, software pin, Renovate extraction path,
binary redistribution or public API is introduced.

The focused Python policy controls establish only source validation. This
change has not executed native lanes. Complete final-edit gates, integrated
exact-head execution of the [current canonical four-lane suite](verification.md)
and independent review remain the primary's responsibility. Missing process
observations are a real failure, never a skip.
