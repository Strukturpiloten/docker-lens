# Prepared live PIDs boundary collector

[ADR 0041](decisions/0041-original-owner-pids-experiment.md) now integrates this
measured boundary through the fixed runtime source and actual original Rust
owner as canonical PIDs27. See [the owner contract](native-pids-owner.md).
Earlier unwired checkpoint statements below remain historical descriptions;
the measured-window restrictions still apply and native qualification remains
pending. The legacy standalone pipe collector is not a new authority source.

`scripts/native_pids_boundary.py` supplies the measured collector governed by
[ADR 0039](decisions/0039-measured-pids-boundary.md). Its legacy standalone pipe
entry point remains outside canonical invocation 27; the fixed runtime source
composes its collector with the original owner's effect producer and independent
private reader. The first 26 invocations, product APIs, capability maps,
catalogue and prepared nofile source remain unchanged. The emitter now requires
the PIDs reader and adds only an unadmitted source outcome. Injected-source tests
establish controls, not native runtime evidence.

The [prepared runtime source session](native-pids-runtime.md), governed by
[ADR 0040](decisions/0040-pids-runtime-source-session.md), now supplies an
in-process inner-peer/container locator and root descriptor/watchdog protocol.
Its fixed root factory now acquires actual kernel/daemon objects from exclusive
original-owner outer PID/start locators and requires pending/confirmation before
experiment creation. ADR 0041 supplies the original Rust owner's actual
canonical before/after CID acquisition and producer integration; native
qualification remains pending. Root acknowledgments alone authenticate no
container or completed experiment.
The legacy pipe Session below does not acquire that authority by being wrapped.

## Host verification call-escape observations

The fixed supervisor retains `gh_verify` as the host-group verification fallback.
Its nested closed sites distinguish construction (`gv_make`), dynamic verifier
entry (`gv_call`), the initial deadline check (`gv_time`), mount-record read,
decode and membership (`gv_record`), mount binding (`gv_bind`), held directory
identities (`gv_ids`), the complete directory and file reopening loops
(`gv_dirs`, `gv_files`), the complete cgroup.type operation (`gv_type`), and
locator cache lookup/controller verification (`gv_cache`). Each operation includes
its original cleanup: only the exception escaping after cleanup is classified.
These names identify operations, not root causes, failed operands, or native
acceptance.

Only the observed outer-group route forwards the optional observer; default
verifier calls retain their original one-argument form. The unchanged recorder
consumes the first attempt before validation or writing, so outer fallback scopes
cannot retry a failed record. The closed host catalogue has 223 legal site/tag
pairs; `declared_unsupported_events` remains restricted to `gh_root`/`gh_nodes`.
The 72-byte record allowance, sole 1,024-byte EOF-validating stderr capture,
retirement, snapshot, START/BIND conflict suppression, and same-stream failed
bind EOF/reset companion requirements remain unchanged. No budget, guard,
source charge, deadline, native evidence requirement, or cleanup action changes.

Only `gv_type` with an `unclassified` escaping primitive tag may add the
optional closed `d=` field. The 223 bare forms remain admitted; 18 detail forms
bring the total to 241. Known exception tags retain their original bare format.

| Detail | Already evaluated observation |
| --- | --- |
| `o_time`, `o_fds`, `o_opens`, `o_other` | Original open deadline/FD/open-count refusal, or another open escape |
| `m_syscall`, `m_guard`, `m_other` | Original fstatfs status failure, false magic equality, or another magic escape |
| `r_time`, `r_reads`, `r_bytes`, `r_cap`, `r_other` | Original read deadline/read-count/byte-count/file-cap refusal, or another read escape |
| `d_domain`, `d_domthr`, `d_dominv`, `d_thread`, `d_other` | Returned bytes match an exact documented type literal, or the closed catch-all |
| `cleanup` | Direct close operation escape, superseding any pending work detail |

The byte whitelist is exactly `domain`, `domain threaded`, `domain invalid`, and
`threaded`, each with its required newline. Categorization returns the identical
read object into the unchanged exact-domain comparison; it accepts no additional
type. The original magic/domain AND expression and its short circuit remain.
Metadata observes existing guard booleans, syscall status and return values; it
adds no clock, source read, counter comparison, reservation, or persistent
source/Budget/Group field. Metadata or classifier failure honestly retains a
bare record. A successful close restores the pending work detail; failed close
retains only cleanup. Emission occurs after the entire original finally.
Unknown, misplaced, duplicated, conflicting, non-type or known-error details
refuse closed. The original 72-byte line and 1,024-byte capture limits remain.
The separate type-detail baseline freezes every altered pre-edit primitive and
recorder method from `ea69314435b036c94afb84ed8d09ba6ff967d583`, with source
locations and SHA-256, alongside the unchanged historical fixtures.

The separate immutable verifier baseline fixture records both original
`check_group` methods from `ba22366407660447a7845d1dad5ff810de1587e0`, with
per-method SHA-256 and source locations verified against that commit. Regression
controls remove only the reviewed diagnostic scopes and observer plumbing before
comparing their ASTs on the current interpreter. Historical fixtures remain intact.

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
the task belongs to a particular container/run. The in-process locator implements
inner-daemon/reader PID-namespace translation; the original runtime owner's
actual outer acquisition and fixed source launch are integrated under ADR 0041.
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
pairs, plus `task_namespace_ids` rows containing reader TID and complete native
NSpid/NStgid vectors for later worker-child mapping. Exact `cgroup.threads`
membership, per-task status/namespaces/cgroup, and
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
success reservations. ADR 0040 replaces the unsuitable combined2MiB physical
bound with a separate32MiB source/input cap, output at64KiB, physical reads plus
read reservations at65,536, live FD
reservations at 256, cumulative FD reservations at 32,768, and requests at 64.
Limits include real proc/controller bytes and fixed 4096-byte `getdents64`
buffers, not just projected JSON. Oversized proc fields/mountinfo, more than 96
leaf TIDs, more than 128 directory entries, deep paths or ambiguous mounts
refuse rather than broaden the contract. This conservative bound can refuse
otherwise valid experiments. The runtime-source documentation records an
executable six-role authored-kernel ledger; full native fit remains unproved.

These local bounds do not allocate new allowance from the existing parent
400-call/4-MiB total, 300-call/2-MiB ordinary capacity and 100-call/2-MiB cleanup
reserve. The prepared runtime locator exposes a one-way parent reservation
callback/receipt, while its actual Rust-owner integration and complete experiment
ledger remain pending;
integration must fit the unchanged aggregate bounds or fail. Runtime command
costs and helper physical reads are different quantities and cannot replace
one another. No new allowance is authorized by this source slice.

Still required before canonical PIDs27: original runtime-owner integration of
the prepared locator,
parent-owned barrier/process/cleanup integration and inherited-FD allowlist,
strict producer interpretation of the runtime source's implemented held-ancestor
local/hierarchical counters and global/worker-limit observations (the legacy
base collector alone samples only outer/leaf values), a real
fork/errno witness, matched finite16/finite64/unlimited controls, competing-limit
checks, strict integrated private reader/owner, native matrix and final gates.
The collector does not classify rootless delegation. Rootless none/v2 refusal
is not mandatory positive four-lane PIDs27 success and cannot bypass nofile28.
No complete PIDs support, destination enforcement or catalogue admission follows.

No software, dependency, image/tool pin, workflow or runtime selection changes.
Renovate ownership/extraction/grouping need no change because no dependency or
pin declaration is added, moved or modified. Standard-library Python/ctypes
accesses existing Linux interfaces; unavailable interfaces fail closed.
