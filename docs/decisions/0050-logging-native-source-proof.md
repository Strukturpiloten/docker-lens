# ADR 0050: Explicit logging configured-state and one-line source proof

Status: accepted test-only contract; source integrated; native qualification pending.

## Decision

Register logging32 after unchanged original29/read, memory30/read and
capabilities31/read. The canonical roster is 32 invocations and eleven delegated
cleanup scopes. Shared registration, runner/coordinator, evidence dispatcher,
decision index and current roster docs are integrated in the same change.
This supersedes only ADR 0049's roster seam from 31 invocations/ten owners to
32 invocations/eleven owners. Earlier source-proof and ADR0007 contracts retain
their semantics and non-admission boundaries.

The [owning contract](../native-logging-contract.md) defines six fresh explicit
CLI/rendered controls: json-file with max-size=1m, local with empty Config, none
with empty Config. Borrow the existing pinned BusyBox image, one HealthRun,
once-bound absolute deadline and verified cleanup owner. Exact typed rendered
requests are compared with independent complete literals; CLI oracle arguments
are independently authored. Offline controls preserve omission versus explicit
empty wire Config and independent LogConfig/LogOptionMaxSize fact requirements.

## Actual outcome and closed refusal

A fixed single-line PID1 program must really exit0. Actual wait, full configured
and terminal inspections bind command, image, ownership, exact options, no TTY,
no inserted init, no OOM/restart/error and nonzero start/finish timestamps.
Terminal PID0 is not live-process evidence. One bounded logs command reads each
owned ID after wait. Direct combined-output streaming and a terminal status frame preserve actual inner CLI exit and exact
raw LF/NUL bytes independently of outer transport success.

Json-file/local require exactly one reconstructed canary line and status0.
None requires status1 and the exact reviewed unreadable-driver diagnostic plus
one LF. Empty success, arbitrary errors, missing/extra output, timeouts, transport
failure and injected/truncated frames fail. This proves explicit configuration
and a bounded read result only; rotation, storage durability, compression,
max-file enforcement, other drivers and default behavior remain outside scope.
Never read daemon log storage/LogPath, change defaults or add an executor.

## Custody, budgets and acceptance

Private schema1 logging-v1 remains under the existing16KiB held-file default.
The independent reader reconstructs exact settings, semantics and accounting;
raw hashes are supplementary. Its only result is the exact typed non-admitting
three-key dictionary. Immediate reader execution without publication and repeated
validation with an independent emitter result guard run before output. Add no
public logging fields, capability or catalogue entry.

Retain180 seconds,46-second cleanup reserve,300 ordinary/100 cleanup calls,
2MiB ordinary/2MiB cleanup,400calls/4MiB aggregate and1800-second whole lane.
Measure actual context bytes before mutation; reserve all pending work and final
readbacks. A checked cumulative cleanup-plus-final guard is separately necessary
because shared capture accounting does not reset cleanup bytes. Unknown attempted
create IDs require outer teardown; borrowed image removal is never authorized.
No successful proof may retain uncertain cleanup.

Source-only tests and static schedule calculations establish no actual profile
compatibility. Independent expected-result review, complete final-edit checks and fresh full32 four-profile native
qualification remain required. The pinned none diagnostic may differ in an actual
profile only after preserved exact evidence and independent contract review;
broad unsupported/error acceptance is prohibited. No dependency, pin, manager,
product API, release or deployment policy changes are made.
