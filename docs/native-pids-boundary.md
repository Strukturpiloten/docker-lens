# Prepared live PIDs boundary collector

`scripts/native_pids_boundary.py` is an **unwired source collector**, governed by
[ADR 0039](decisions/0039-measured-pids-boundary.md). It is not invocation 27,
an effect producer, a private-proof publisher/reader, or a product API. The
canonical first 26 invocations, emitter, capability maps, catalogue and prepared
nofile source remain unchanged. Tests with injected sources establish controls,
not native runtime evidence.

## Measured window and authority

The intended owner starts the collector after daemon startup and before releasing
the PIDs experiment. BindOuter must complete before creating/releasing experiment
workers; BindLeaf must complete while the already-created inner task is held at
the owner's barrier. This collector does not release barriers or run workloads.
Custody describes this bounded window, not process birth, consumed OCI bytes,
runtime defaults, account setup, logs, or whole-launch provenance. Historical ADRs
0022–0035 remain unadopted.

The selected trusted runtime and caller must independently identify the owned
outer container and each inner container's reader-namespace PID/start. PID/start
arguments are locators, not authentication. The collector measures the actual
located process and controllers; matching context or inspect fields cannot prove
the task belongs to a particular container/run. The independently owned runtime
PID locator, including daemon/reader PID-namespace translation, remains pending.
There is no container-ID-to-path inference or ambient `/proc` scan.

The trusted hosted Linux reader must have the intended host PID/mount/cgroup
view and ordinary read access to the selected processes and cgroup2 hierarchy.
There is no automatic privilege escalation. Missing pidfd, libc `getdents64`,
permissions or unambiguous namespace/mount coordinates causes refusal. The
helper never enters a namespace or writes a kernel/controller setting. Host root,
the selected daemon/runtime, and the privileged guest's cooperation at barriers
remain trusted; this is not protection from a malicious runtime or host root.

The OS source verifies real procfs/cgroup2 filesystem types, derives cgroup
coordinates from the reader's kernel mountinfo and each task's cgroup entry,
and walks actual directory FDs without symlinks. It checks the held mount's
kernel `mnt_id` and device against its mountinfo record. It holds pidfd, proc
directory, process root, PID/mount/cgroup namespaces, ancestor directories and
the four controller file FDs. Start ticks, UID/NSpid status, namespace/root
identity (including root FD mount ID), membership, mount record, directory identity and file identity are
rechecked. Leaf lookup must be a strict object-identity descendant of the held
outer group; equal groups, parents, siblings and reused slot/group aliases fail.
Only domain cgroups with no child directories or aliases are sampled.

## Private session protocol

The executable accepts exactly three positional decimal arguments: inherited
request pipe FD, inherited response pipe FD, and the parent's original absolute
`CLOCK_MONOTONIC` terminal deadline in nanoseconds. It accepts only distinct
anonymous pipes, with the expected read/write modes, and marks them nonblocking
and non-inheritable. The owner must retain exclusive pipe custody, supervise
child status, and close unrelated inherited handles before launch. There is no
socket, public service, path argument, command argument, rebind or replay API.

Requests and responses are newline-delimited JSON. Each request is at most 2048
bytes, including the newline. Duplicate keys at any depth, malformed JSON,
nonfinite numbers, wrong types, unknown fields/operations, invalid order and
expired work time terminate the session. Integer fields exclude booleans.
The exact request shapes are:

| Operation | Fields in addition to `op` |
| --- | --- |
| `BindOuter` | `pid`, `start`, `context` |
| `BindLeaf` | `slot`, `pid`, `start` |
| `Sample` | `slot`, `phase` |
| `Finish` | none |

`context` has exactly `backend`, `candidate`, `run`, `lane`, `outer_id`.
Backend is `docker` or `podman`; context strings are bounded opaque tokens and
remain caller assertions. Slots are exactly `cli16`, `cli64`, `cli_unlimited`,
`rendered16`, `rendered64`, `rendered_unlimited`. Each binds once. Actual outer
`pids.max` must be 512; actual slot limits must respectively be 16, 64 or `max`.
The collector does not change these limits.

Each slot's first sample phase is `before`. Later distinct phases advance through
`at_limit`, then either `after_failure` or `control`, then `after_release`;
intermediate phases may be omitted. Phases describe caller-selected barriers;
their names do not prove a syscall or effect occurred. A sample privately returns
actual maximum, current, `pids.events`'s `max` counter, and accounted TID/start
pairs. Exact `cgroup.threads` membership, per-task status/namespaces/cgroup, and
`pids.current` must agree across repeated bounded reads. Counts include threads,
not just `cgroup.procs`. These reads are not an atomic kernel snapshot and cannot
exclude an intervening change that returns to its original state.
The no-child leaf check brackets the stable controller/task reads; a persistent
empty child appearing during sampling also rejects the sample.

Successful non-sample responses contain only `op` and `status: ok`. The owner
sends `Finish`, closes its request writer, then reads the final response and
waits for exit status. Trailing requests, premature EOF, process death, failed
descriptor cleanup or any uncertainty reject the session. Finish may close an
incomplete measurement session; it does not certify a complete experiment.
Neither an acknowledgment nor partial sample output is acceptable proof without
successful final process status and the owner's independent cleanup checks.

Diagnostics are the single value-free `native-pids-boundary: refused` line.
SIGINT/KeyboardInterrupt invalidates the session with nonzero status. Cancellation
during descriptor cleanup marks failure while remaining descriptors are attempted;
it does not interrupt cleanup with a traceback or renew the deadline.
PID/context/controller values appear only on the private response pipe. A caller
must not forward that pipe or raw exceptions into public job logs.

## Bounds and remaining integration

The terminal deadline must be within the original 180-second envelope and leave
more than the original 46-second cleanup reserve. Work ends at the immutable
terminal deadline minus 46 seconds; requests never renew either deadline.
Descriptor closure is attempted even after work expires and must finish before
the terminal deadline. Nonblocking pipe waits share that work deadline. Local
kernel filesystem calls can still block in the kernel; the independent parent
timeout/process owner is mandatory.

Conservative pre-I/O charges retain failed reservations and never refund unused
success reservations. The collector caps combined source/input/output bytes at
2 MiB, output at 64 KiB, physical reads plus read reservations at 65,536, live FD
reservations at 256, cumulative FD reservations at 32,768, and requests at 64.
Limits include real proc/controller bytes and fixed 4096-byte `getdents64`
buffers, not just projected JSON. Oversized proc fields/mountinfo, more than 96
leaf TIDs, more than 128 directory entries, deep paths or ambiguous mounts
refuse rather than broaden the contract. This conservative bound can refuse
otherwise valid experiments. A complete six-role measurement fitting this bound
has **not** been demonstrated.

These local bounds do not allocate new allowance from the existing parent
400-call/4-MiB total, 300-call/2-MiB ordinary capacity and 100-call/2-MiB cleanup
reserve. A one-way parent
reservation/accounting adapter and complete experiment ledger remain pending;
integration must fit the unchanged aggregate bounds or fail. Runtime command
costs and helper physical reads are different quantities and cannot replace
one another. No new allowance is authorized by this source slice.

Still required before canonical PIDs27: independently owned runtime PID locator,
parent-owned barrier/process/cleanup integration and inherited-FD allowlist,
ancestor controller headroom/event attribution (the current source holds/rechecks
ancestor directories but samples only outer/leaf controller values), a real
fork/errno witness, matched finite16/finite64/unlimited controls, competing-limit
checks, strict integrated private reader/owner, native matrix and final gates.
The collector does not classify rootless delegation. Rootless none/v2 refusal
is not mandatory positive four-lane PIDs27 success and cannot bypass nofile28.
No complete PIDs support, destination enforcement or catalogue admission follows.

No software, dependency, image/tool pin, workflow or runtime selection changes.
Renovate ownership/extraction/grouping need no change because no dependency or
pin declaration is added, moved or modified. Standard-library Python/ctypes
accesses existing Linux interfaces; unavailable interfaces fail closed.
