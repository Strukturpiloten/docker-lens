# ADR 0025: Mandatory ShmSize source integration

Status: accepted source integration; exact-final-candidate qualification pending.

## Context

ADR 0022 selects the reviewed lifecycle cohort at Debian 34 capabilities/56
shapes and upstream 36/60. ADR 0023 added the three process-source raw groups;
ADR 0024 added raw HealthDisabled from unchanged complete health metadata,
bringing that health-only slice to 38/60 and 40/64 without compiled admission.
Every earlier ADR, record and receipt remains unchanged.

The independently reviewed ShmSize source producer and strict private reader
cover explicit 1 MiB/2 MiB effects with observed omitted controls and private
IPC isolation. Source/format/pure-test reviews do not establish actual native
qualification. Passing 23-test campaign `39130478489` binds the earlier source
`e7995ecfa9cadaae0bc7bc1685e5e1f320c907ff`; it cannot qualify these new bytes.

## Canonical wiring and ownership

Register `native_shm_size_tests.rs` as lifecycle child `shm_size`. Append only
the twenty-fourth exact ignored invocation:
`native_health_metadata_tests::lifecycle::shm_size::live_shm_size_effects_match_engine`.
Retain every original first-23 ordinal and the command-clear validator. Keep the
original six-child owner subshell byte-identical; use a new separate one-child
subshell exporting the existing `native_conformance_outer_v1` cleanup token.
This does not broaden the original block or invent another cleanup protocol.

Bind candidate SHA to the same exact checkout, the fixed direct child
`shm-size-v1.json`, and the same once-created 180-second invocation cutoff.
Closed Shm markers and first selected-source numeric panic diagnostics retain
the causal failure without native values. Existing cleanup-unverified and
outer-handoff markers force failure even beside a successful numeric summary.
Original statuses, command limits, privilege and outer budgets remain unchanged.

After invocation 24, require the unchanged CLI strict reader on every native
execution, including runs without public emission. Its twelve independently
supplied facts are capture directory, candidate, run, lane, Engine, rendering
API, mode, package, fixture image, outer image/ID and observed daemon UID.
Proof self-context is never its oracle. The real-reader harness-tail tests
require hostname, command-clear and Shm gates in that order before simulated
public output, with no live Docker calls.

## Closed raw projection

The emitter retains nineteen positional arguments and every earlier mandatory
strict reader, including the unchanged complete health validation/legacy return.
Require the fixed Shm child under the existing capture directory against the
already independently constructed context before any group or public output.
Its return must have the exact concrete types and closed values:
contract string `shm-size-v1`, empty list `capability_admission`, and Boolean
false `catalogue_admission`, with no missing or additional keys. Integer zero
cannot stand in for Boolean false. Only then add `ShmSize: [ShmSize]`.

Public fields are only `shm_size_contract: shm-size-v1` and closed
`shm_size_outcomes` with `admission: raw_source_only`,
`catalogue_admission: unadmitted`, scope
`explicit_1MiB_2MiB_with_observed_omission_only`, and outcome
`tmpfs_effect_and_ipc_isolation_verified`. The disconnected
`$defs.shm_size_source_projection` changes no historical reviewed-root acceptance.
Actual omitted defaults, IPC namespaces, IDs, argv, timestamps, private proof
payloads and per-run accounting remain private. No generic default size or
arbitrary IPC/application guarantee follows.

Current combined raw totals are Debian 39 capabilities/61 shapes and upstream
41/65. Compiled selection remains 34/56 and 36/60. ShmSize, HealthDisabled and
the three process groups remain unselected; this creates no public target
profile, renderer behavior, product API or catalogue admission.

## Maintenance and outstanding gates

The prepared Shm producer/private reader and old health reader are immutable in
this integration. No private protocol, historical evidence/receipt, dependency,
operational pin or workflow changes. The same five image pins remain under the
existing Renovate extraction owner, native-image group and disabled automerge.
Local/main/trusted-dispatch/release callers still use the canonical harness;
BoxFerry consumers and other Lens products gain no dependency on this private
proof and require their separate source-bound acceptance.

Literal four-profile unit fixtures test whole-output refusal for missing,
partial, wrong-context, wrong-return, failed-effect, isolation and cleanup
inputs, closed metadata, exact raw sets, unchanged selected counts and old root
acceptance. They are not authenticated native evidence. Independent final-diff
review, a complete final-edit gate, a fresh exact-final-candidate 24-by-four
native campaign (96 mandatory invocations) with independent evidence review,
all six actual authored-fixture volume-only rehearsals and required actual
Nextcloud/Supabase bind and desired-external consumer review remain mandatory.
No compatibility, full migration acceptance, release, publication or deployment
is established here.
