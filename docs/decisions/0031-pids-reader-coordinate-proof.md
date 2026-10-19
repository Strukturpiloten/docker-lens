# ADR 0031: Retained reader coordinates in the private PIDs successor

Status: accepted bounded source contract; implementation and native qualification pending.

[ADR 0033](0033-original-outer-custody.md) supersedes only the unused boundary
reserve and unresolved original-root handoff below. Its connected source contract
retains every coordinate and semantic predicate; it is not native qualification.

## Context

Run 39173069422 at 19f1ce4 failed PIDs invocation 27 on every lane. The
rootful member-ID mismatch does not establish a parser defect or its runtime
cause. Three complete raw-frame regressions now protect the existing raw outer
PID comparison and later delta packing. They do not establish that the actual
procfs mount and controller reader use the same PID coordinate system.

ADR 0030's rootless systemd/cgroup-v2 prerequisite remains mandatory. Its
fixture-delegation gap is separate from reader coordinates and from the still
unresolved authenticated outer PID/memory controller boundary.

## Decision

Supersede only the current private PIDs packet/reader selection from ADR 0027
and the missing retained coordinate witness in ADR 0029. Keep historical v1
reader, tests and evidence unchanged. Current qualification uses schema 2,
contract `pids-limit-v2` and fixed direct child `pids-limit-v2.json`; it must
never fall back to v1 or accept a relabelled legacy packet.

Inside each actual observer shell, read `/proc/self/status` inline using shell
builtins, not a pipeline or command substitution. Observe `Pid`, the complete
bounded `NSpid` chain and the same shell's `$$`. Require exactly one `NSpid`
entry and agreement among all three observations. Resolve PID/mount/cgroup
namespace links through `/proc/<that observed Pid>/ns/`, not an external
helper's `/proc/self`. Reject missing, duplicate or malformed observations.

Apply this to the initial outer context and every scan/controller read: 37
ordered observations, consisting of context followed by scan/controller pairs
for baseline, held and restored in the existing six case positions. Each
reader must agree with the initial observer namespaces before the unchanged
raw MEMBER/CURRENT comparison. Do not translate PIDs or enter namespaces.

Retain each witness under `coordinates` as the exact six-slot tuple
`[shell_pid, proc_pid_delta, nspid_deltas, pidns_delta, mntns_delta, cgns_delta]`.
PID differences are relative to the recorded shell PID; namespace differences
are relative to the original observer's corresponding namespace. The positive
contract requires a shell PID in 1..4194304, zero scalar differences and exactly
`[0]` for the NSpid differences. Derive these values from actual observations;
they are not caller-authored verification flags. PID uniqueness or monotonicity
is not required: a terminated observer's PID may be reused.

Compact only the 18 final private phase snapshots into fixed ten-slot tuples:
`[rows, members, pids_current, pids_max, denials, oom_kills, outer_pids,
outer_memory, ancestor_headroom, phase]`. Preserve every original value,
including phase strings. Live controller objects, comparisons, mappings and
packing retain their meanings. The strict successor expands validated tuples
and reuses only the original pure semantic validator internally, checking its
exact typed return before constructing its own four-key v2 return. It never
calls the old file/custody wrapper or relabels legacy input as positive evidence.

Original v2 bytes first pass the existing exclusive no-follow stable-file and
duplicate-key custody checks, with the unchanged 16-KiB ceiling. Validate exact
keys, types, counts, numeric bounds, context and all witnesses before legacy
semantic reconstruction. Booleans are never integers. Both producer and reader
also enforce compact UTF-8 serialization at most 15360 bytes, leaving a real
1-KiB planning reserve; there is no padding or invented future boundary field.
The 2178-byte lossless phase-key saving exceeds the at-most-830-byte witness
addition. Synthetic sizing and round trips are not native observations and do
not prove that a future boundary design fits.

## Preserved requirements and consumers

All positive finite16/finite64/unlimited effects, ownership, raw membership,
CURRENT short circuit, task/byte/call accounting, cleanup and acquisition
predicates remain mandatory. No additional capture request is introduced.
The original 180-second deadline, 46-second cleanup reserve and all other
budgets remain unchanged; the extra observations must fit or fail closed.

Switch both current consumers together: the canonical harness's fixed child
and twelve-argument reader, and the nineteen-argument emitter's mandatory
reader and exact typed four-key return. Local, main, trusted dispatch and
Release consume that same harness. Public evidence schemas, raw/selected
catalogue totals, product APIs and inert output remain unchanged. Other Lens
products and the website have no private PIDs consumer. BoxFerry retains its
separate exact-candidate consumer and application gates.

No dependency, image, Action or toolchain pin moves. The existing five native
image extractions, manager ownership, grouping and manual-review rule remain
unchanged; no Renovate edit or duplicate manager is needed. Historical records
remain immutable.

Independent controls must cover coordinate mismatch, misleading multi-entry
NSpid, namespace drift, malformed/duplicate fields, tuple losslessness and
size, original semantic negatives, raw outer/private PID counterexamples,
legacy-file/schema refusal, custody and all current consumer paths. Main owns
independent final review and complete final-edit verification.

This is a source contract, not an established native failure cause or native
coordinate result. The actual delegated rootless fixture and authenticated
exact outer controller boundary remain unresolved. Fresh four-lane positive
qualification, consumer/application gates and manual release remain separate;
host capture stays deferred.

Future public rootless PIDs admission must additionally distinguish destination
environment prerequisites from Engine/API/mode identity. Current capability
scope and offline profile matching do not encode cgroup driver, version or
delegation; an identically versioned daemon may use driver none. A successful
systemd/v2 fixture must not become an unconditional same-version grant. Before
any such admission, separately design typed evidence-bound requirements,
same-destination environment assessment and an explicit unresolved inert
artifact prerequisite or fail-closed planning. Source observations and positive
metadata alone are not destination enforcement evidence. No public PIDs
capability is selected or added by this private-proof change.
