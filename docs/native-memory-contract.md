# Inner memory native source contract

[ADR 0048](decisions/0048-inner-memory-native-source-proof.md) appends memory30
only after the unchanged original 29, including PIDs27/read, nofile28/read and
device29/read. Nine delegated owners retain the existing lane EXIT cleanup.
This is a private, non-admitting source proof. Fresh complete and four-profile
native qualification remain required; no actual memory run is claimed here.

## Independent intent and controlled effect

Six fresh containers borrow the existing pinned BusyBox image: ordered CLI and
literal-rendered pairs for omission, finite 67108864 bytes, and explicit0. The
entire rendered request must equal independently authored expected JSON. Omission
has no Memory field; zero has literal Memory: 0. No MemorySwap, OOMKillDisable,
score adjustment, extra product field, inner privilege, image or pin is added.
Existing #147 memory bounds, decoder, renderer and capability gates are unchanged.
The same exact two-process fixture runs in every case.

The proof claims observed direct leaf-local memory pressure and the actual bound
allocation-child victim, under the sampled visible context. It does not establish
that the leaf was the unique cause of every concurrent event or exclude arbitrary
hidden/global interference. Local oom_kill counts victims of any OOM killer;
local max and oom deltas provide the separate pressure-origin evidence.

## Two processes, two barriers and actual wait

PID1 is a fixed BusyBox shell supervising exactly one child shell. The child
installs USR1 handling before readiness, then waits with builtins and execs
`dd if=/dev/zero of=/dev/null bs=100663296 count=1`. No allocation payload is
captured. PID1 initially waits on a builtin flag; its first USR1 only sets that
flag. PID1 then ignores further USR1, forwards one release to its bound child,
and performs one actual wait. Shell wait diagnostics stay in a bounded private
fixture file, so a shell-generated Killed line is not mistaken for allocator
output; the actual numeric wait status remains mandatory. Release cannot interrupt that wait and masquerade
as child exit 137. No background worker or sleep remains in the workload beyond
the one explicitly owned child.

PID1 installs its final USR2 handler before publishing child status. Builtin
bound/held markers follow the foreground publication helpers' completion, so
observers cannot accept a file while its helper is still a cgroup member.
A completed temporary readiness exec binds actual PID/start, namespace, child
PPid 1, UID 0, exact child argv/executable and no inherited entrypoint/init wrapper.
Only after that observer finishes may the outer reader require exactly the two
bound members. The post-pressure observation waits outside the workload, reads
the fixed private child-result file through the bound parent's root, then
requires exactly the same surviving parent as the sole member. Parent death,
missing status, interrupted wait, group kill or unknown membership fails.

Exec preserves the child's PID/start identity by process semantics. No direct
post-exec child PID sample is claimed. After counter/event checks, USR2 lets PID1
propagate the child's status. Parent exit 137 is explicitly supervisor-propagated
child status, not evidence that the kernel killed PID1.

## Actual cgroup2 and private-root observations

Canonical PIDs27 already requires cgroup2. This slice implements only that source
contract; it introduces no cgroup-v1 portability framework or PIDs machinery.
A fixed root read-only actor executes inside the exact authenticated owned outer.
It correlates the workload's completed readiness observation with bounded outer
proc reads, actual memory-controller membership, PID namespaces and start ticks.
The live memory leaf and each immediate visible ancestor are read through held
directory descriptors. Reports are at most 4096 bytes; paths, mount rows, process
scan 512 and visible depth 8 are bounded and ambiguous views fail.

An independently authenticated raw outer inspection requires private cgroupns and
binds actual outer PID/start/configuration. The guest mount-root object `/` is
valid and may have a finite actual limit. Its identity, namespaces and real
memory.max/current/events.local files are retained. PID1's current membership
may instead be init.scope; it does not select the root object. Ancestors above
this private root remain unobserved, never unbounded. The observed root limit
must corroborate the authenticated configured4 GiB outer; that setting alone is
not a kernel observation or a workload Memory proof.

Finite leaves require actual memory.max = 67108864. Omitted/zero leaves require
actual local max and agreement on the same observed visible inherited limits.
Finite inherited capacity is compatible with unlimited/no authored leaf cap.
Before release, every observed finite strict ancestor has measured current usage
and checked limit-minus-usage headroom at least 100663296 bytes. There is no 512 MiB
threshold or universal support-memory bound. Global SwapTotal = 0 is independently
observed; unknown/effective swap fails rather than being disabled. MemorySwap
inspect defaults remain observed metadata, never authored Memory semantics.

## Live local pressure, victim, event and Engine flag

Both snapshots require observed leaf memory.oom.group = 0, without writes or OOM
protection. While PID1 remains alive, finite cases require real child wait137,
positive leaf-local max and oom deltas and exactly one new oom_kill victim.
The leaf must remain present with the same identity/limit; a vanished leaf cannot
pass. Omitted/zero controls require actual child wait0 and one complete96 MiB
record, independently parsed from full records in/out, with no local pressure or
victim increment. Exit0, partial records or a printed success marker are insufficient.

All observed strict ancestors retain identities/limits and unchanged local
pressure/victim counters. Hierarchical memory.events is never substituted for
memory.events.local; a leaf OOM may legitimately propagate hierarchical events.
Counter resets, a wrong scope, extra victim or changing ancestry fails. These are
sampled observations, not an atomic or whole-host resource attestation.

The producer queries the same daemon's exact-CID, container-type, oom-filtered
bounded events after the child result and live counter readback. Native clocks
and caller UTC/monotonic brackets bind the fixed event window. Finite cases need
one genuine matching OOM event before final parent release; positives need none.
Only then is PID1 released and waited. Final inspect must retain actual expected
exit, identity/start and genuine OOMKilled true for finite cases, false for
positives. Old Engine ordering leaving the flag false remains a failed lane.

## Exact reserved accounting

Counts below are HealthRun captured-command/accounting charges. Fixed collector
captures contain bounded read-only field operations; counts do not claim one
kernel read or Engine request per capture. All stdout and stderr bytes are charged;
these are captured bytes, not measured total wire traffic.

| Stage | Captures/charges | Successful captured-byte reservation |
| --- | --- | --- |
| Bound owner, context, borrowed image, independent raw outer | 9 upstream /10 Debian plus two selected Docker extras | Base captures at 73742 each; each Docker extra 65536 |
| One initial visible-root baseline | 1 small |8192 |
| Each of six controls |15 small |15*8192 |
| Final daemon health |1 full |73742 |
| Final borrowed image and outer |2 full plus one Docker extra |2*73742 plus65536 on Docker |
| Cleanup |36 separate |36*(8192+2048)=368640 |

Each 15-step slot is: fresh name, create, owned configured projection, start,
completed readiness, running projection, pre-pressure sample, allocation release,
live post-child sample/result, logs, pre-release native event clock, exact events,
final parent release, parent wait, terminal projection. There are91 small captures.

| Lane family / selected backend | Ordinary charges | Successful ordinary-byte ceiling |
| --- | --- | --- |
| Upstream /Podman |103 |1630376 |
| Debian /Podman |104 |1704118 |
| Upstream /Docker |106 |1826984 |
| Debian /Docker |107 |1900726 |

A checked pre-mutation guard reserves all pending small work and final ordinary
snapshots. The existing pending-final guard remains before cleanup. Each small
capture checks the actual call and captured-byte delta<=8192; inspect/report
outputs are separately bounded. Unexpected output fails and retains cleanup.
No time/counter resets or borrowed cleanup capacity occur. The existing180-second
exact deadline,46-second reserve, 300-call/2 MiB ordinary and 100-call/2 MiB cleanup,
400-call/4 MiB aggregate and 1800-second lane ceiling remain unchanged. Context
acquisition keeps its separate 16-request/2 MiB/15-second bound. Native actual fit,
including the whole 30-call lane, remains unmeasured.

## Private custody, readers and qualification

`memory-limits-v1.json` is one stable caller-private direct child, regular 0600,
owned by the current UID, singly linked and nonsymlink, under held 0700 directory
custody, with an explicit 65536-byte ceiling. Existing publisher/reader custody is
reused. The closed schema binds candidate/run/lane, APIs, mode/UID, selected
backend/outer/image, all six ordered roles, raw hash-bound reports, both actual
process/outcome kinds, real counters/events/flag, timing/bytes and verified cleanup.
Rebinding a hash cannot legitimize false semantic evidence.

The exact wrapper and immediate twelve-argument reader are mandatory even when
public emission is off. The unchanged nineteen-argument emitter revalidates and
requires the exact typed three-key non-admitting result. No memory public field,
shape, capability or catalogue record is added. Unknown IDs or process/outcome
state require the existing verified outer teardown path; known terminal objects
are removed with ownership checks and two ID/name absence rounds. The borrowed
image never becomes owned or removed and both final snapshots must agree.

Focused component, semantic, actual-shell/fake-dd, custody, privacy, counter,
barrier, context and strict-roster controls are source evidence only. Fresh complete
checks, independent review and real Debian11/API1.41 and upstream/API1.56
rootful/rootless whole 30 runs must establish genuine outcomes and cleanup.
Named capability add/drop, logging, catalogue admission, BoxFerry application
acceptance and publication remain separate open obligations.

Kernel counter/namespace meanings were checked against the official Linux
[cgroup2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
and upstream Linux v6.12 memcg event definitions (GPL-2.0 source reference only).
No upstream implementation or binary was copied or redistributed. The oracle
remains the already pinned BusyBox 1.37.0 fixture and exact contextual Docker CLI/
Engine versions, under their existing provenance/license records; new tests
execute only a fake nonallocating dd and never qualify those native binaries.
