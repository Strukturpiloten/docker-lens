# ADR 0023: Mandatory process-source probes and closed raw projection

Status: Accepted for source integration; fresh native and consumer qualification pending.

## Context

ADR 0022 selects the authenticated lifecycle source cohort for candidate rehearsal:
Debian 34 capabilities/56 shapes and upstream 36/60. Its source run `39124651853`,
attempt 1, candidate `a251748de3a61f9dc3d735e670ce3ea461ee0a30`, passed 21
invocations per lane (84 total). Those historical records, receipts and campaign
facts remain unchanged. They do not qualify changed process-source wiring.

Hostname and command/entrypoint clearing have separately reviewed native source
probes and strict private readers. Source integration must require both complete
families without allowing proof self-context, partial groups, private payloads or
raw source markers to authorize product catalogue admission.

## Decision

The canonical harness retains the original 21 invocations in order. Hostname is
invocation 22; its mandatory strict reader must succeed before command-clear runs
as invocation 23. The command-clear inline adapter always requires the fixed
direct-child `command-clear-v1.json`, including when public evidence is disabled.
Its twelve facts come independently from canonical harness arguments: capture
directory, candidate, run, lane, Engine, API, mode, package, fixture image, outer
image/ID and observed daemon UID. Context never comes from the private proof.
The shared context validator enforces exact profiles, ownership and budgets.

All original deadlines, privilege, privacy and resource/cleanup controls remain.
Command-clear receives the same original once-created 180-second invocation
deadline and owns its separate bounded cleanup; it does not borrow lifecycle
cleanup success or extend the lifecycle owner-token scope. Fixed allowlisted
causal markers/stages and the first selected-source panic location may diagnose
failure, never arbitrary messages or native payloads. Cleanup-unverified forces
failure even if the numeric test summary reports success.

The public emitter keeps its nineteen positional arguments and all prior strict
readers. It requires both additional strict readers against the existing
independently constructed context and fixed direct children before any new group
or public output. Only these complete singleton raw groups are added:

- `ContainerHostname`: `ContainerHostname`.
- `CommandClear`: `ClearCommand`.
- `EntrypointClear`: `ClearEntrypoint`.

Current raw totals are Debian 37 capabilities/59 shapes and upstream 39/63.
HealthDisabled is excluded. The two public families contain only contract names,
`admission: raw_source_only`, `catalogue_admission: unadmitted` and fixed closed
outcomes: `omitted_and_explicit_verified` or `all_four_process_controls_verified`.
No actual hostname, argv, IDs, timestamps or private proof payloads are projected.
Disconnected `$defs.hostname_source_projection` and
`$defs.command_clear_source_projection` describe these closed subsets without
changing historical reviewed-record root acceptance or private v1 protocols.

## Consequences and gates

The compiled catalogue remains ADR 0022's 34/56 and 36/60; the three process
groups remain unselected. Raw family markers describe source authority, not
global capability availability or the separate compiled selection. No product
API, native producer/private-reader behavior, dependency, operational pin,
workflow, historical evidence or consumer receipt changes here.

Local/main/trusted-dispatch/release consumers share `native-conformance.sh`.
The existing Renovate manager still owns its same five image pins and extraction
paths; no added, moved or changed pin requires configuration changes. BoxFerry's
generic wrapper binds the clean exact source and script SHA; historical wrapper
or application receipts cannot establish acceptance of this changed candidate.

Focused inert fixtures test source wiring only. Independent final-diff review,
complete final-edit gates, fresh exact-final-candidate 23-invocation four-lane
native qualification (92 total), all six actual authored-fixture volume-only
consumer rehearsals and actual Nextcloud/Supabase bind and desired-external
consumer review remain required. No full migration acceptance, compatibility,
catalogue admission, release, publication or deployment is established here.
