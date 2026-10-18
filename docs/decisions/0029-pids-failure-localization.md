# ADR 0029: Closed PIDs failure localization and canonical mapped paths

Status: accepted bounded diagnostic and path-representation repair; fresh exact-candidate qualification pending.

This supersedes only ADR 0027's diagnostic-absence clause. Its canonical invocation
27, first-26 ordering/owner scopes, private protocol and mandatory readers remain
unchanged. No nofile integration or public projection is introduced here.

## Failed source campaign

Independently reviewed [run 39165508951, attempt 1](https://github.com/Strukturpiloten/docker-lens/actions/runs/39165508951/attempts/1)
tested exact candidate `be19402cccb94e20659acb04b1c267efe4390250`. Each lane passed
the first 26 ordered invocations, then failed PIDs invocation 27: 104 prior passes
and four failed attempts, 108 actual attempts total. Both rootful lanes first
panicked at that candidate's shared native_health_metadata_tests.rs:542:9 command
success assertion; both rootless lanes first panicked at
native_pids_limit_tests.rs:360:5 exact-one mount-root resolution assertion.
All four last closed markers were health_metadata_context. That was the last
shared marker, not an established failure phase: the PIDs producer emitted no
source-local stages and both assertions have multiple possible callsites.

The campaign produced zero artifacts and zero cleanup-dependent lane successes.
Private proofs and raw command output were unavailable; absence of an observed
cleanup-unverified/handoff marker does not attest cleanup completion. Neither the
prior passes nor these stopping points qualify the candidate, its public outputs,
runtime compatibility or a specific cgroup/namespace cause. Historical records
and the failed campaign remain unchanged.

Independently reviewed [run 39169948731, attempt 1](https://github.com/Strukturpiloten/docker-lens/actions/runs/39169948731/attempts/1)
tested `e2f0f479b5058fb9a5cd237adc95c998da6e6349`. Again each lane passed
26 invocations and failed PIDs 27 (104 prior passes and four failures, original
Cargo exits 101); nofile 28 was not reached and no artifacts or cleanup-dependent
lane successes were produced. Both rootful lanes reached finite16/oracle
baseline_controller and the conjunction at that source's
native_pids_limit_tests.rs:824:5. It does not distinguish unequal member IDs from
unequal current-task count, or both. Both rootless lanes reached finite16/oracle
leaf_pids_resolve, outside_owned_descendant and exact-one assertion 484:5. That
reason does not distinguish equality with the observer-derived owner from a path
outside its component prefix. These are established stopping points, not known
runtime causes; absent cleanup markers do not prove cleanup completion. Neither
failure nor the earlier representation repair qualifies this candidate.

## Decision

The actual PIDs producer emits finite stopping points before context acquisition,
image inspection, outer observation, daemon-identity parsing, both outer resolver
calls, each case/role operation, acquisition and final snapshots/publication.
Case is context/finite16/finite64/unlimited; role is observer/oracle/rendered.
Operation names come from a private closed enum, not native data. Context operations
use only the observer role; workload operations use only the six fixed case/role
pairs. Stages identify source operations, not successful observations or proof.

On resolver refusal, classify only predicates already evaluated by the existing
resolver, without logging raw counts:

| Classification | Meaning |
| --- | --- |
| no_controller_mount | No mount matches the selected controller generation/name. |
| root_coordinate_mismatch | Eligible mounts exist, but none contains both membership paths under its mount root. |
| outside_owned_descendant | At least one root fits, but no mapping passes the existing ownership/strict-descendant predicate. |
| multiple_eligible_mounts | More than one mapping passes all existing predicates, not merely more than one mounted filesystem. |

For outside_owned_descendant, append only a closed relation: equal_owner means
the selected path equals the owner while a strict descendant is required;
outside_owner means the selected path lacks the owner's component prefix. Mixed
means both refusal predicates were observed across rooted mounts. These are
existing path predicates, not an authenticated ownership finding. Do not select
an arbitrary last rejected mount. The original success predicate remains intact.

One mapping emits no refusal classification. The original exact-one assertion,
mountinfo fields 3/4 and component-wise prefix checks remain authoritative.
Do not translate/rebase paths, switch to daemon namespace views, relax ownership,
skip a controller, raise bounds, or infer unsupported behavior from failure.

Immediately before the original exclusive-single-threaded-membership assertion,
classify the existing member-ID comparison and captured CURRENT comparison as
member_ids_mismatch, current_count_mismatch or members_and_current_mismatch.
No classification is emitted when both match. Inspect CURRENT without panicking;
missing, duplicate, noncanonical or overflowing values emit no classification.
The original assertion, including its short-circuit evaluation and malformed-value
failure behavior, remains authoritative. Do not log IDs or counts, perform another
controller read, change namespace views or treat a mismatch as a proven cause.

Only the PIDs wrapper branch admits actual closed producer stages/classifications.
Retain the last valid stage before the first panic or cleanup boundary. Accept a
single resolver classification only beside a resolver stage, or a controller
classification only beside baseline/held/restored_controller. At most two PIDs
lines leave the wrapper: the stage and one classification. Duplicate or mixed
classifications are omitted, and a new stage clears the previous classification.
Later cleanup/secondary panics cannot replace the original causal
stage or first allowlisted panic location. Original failure status, exact selection,
numeric-summary requirements and handoff refusal remain unchanged. Native stderr,
paths, IDs, namespaces, memberships, command payloads and host facts stay private.

## Canonical mapped-path representation

The new independent pure Rust fixture exposed a separate producer/reader
inconsistency when the outer membership equals the mount root. Rust 1.98.1
`PathBuf::join` retains a trailing separator for an empty relative path, while
the existing strict Python reader requires canonical `PurePosixPath` strings.
The original fixture expects the canonical mountpoint, not the rejected spelling.
Normalize both already-validated joined paths through their components before
serialization and the unchanged ownership checks. This changes representation
only: controller selection, mount-root stripping, exact-one resolution,
component-prefix and strict-descendant predicates remain unchanged. It never
rebases membership coordinates or switches namespace views. Keep the strict
reader and independent expected values unchanged; cover both controller
generations at the empty-relative-path boundary.

This is an independently demonstrated representation defect, not an established
cause of failed native campaign 39165508951. Only fresh native execution can
establish the changed candidate's actual stopping point or qualification.

## Unresolved coordinate and authenticated-boundary evidence

Process rows use the scan's procfs PID coordinates. Controller member IDs use the
controller reader's current PID namespace. Both commands execute through the
owned outer container, but the source does not independently prove these PID
coordinate views equivalent or recheck controller-reader namespaces. The scan's
PID/mount/cgroup namespace checks do not supply that missing relationship.

The resolver's owner membership comes from the initial observer command itself,
not an independently authenticated bounded outer-container root. The configured
outer identity and limits are retained, and the observed controller ceilings are
checked numerically against 512 PIDs/4 GiB, but no independent binding proves those
controller paths/inodes represent that exact owned boundary. Matching namespace
identities alone neither proves unchanged membership nor authenticates the owner.
Do not replace it with an ancestor, daemon view or mount root to pass containment.

A separate evidence design must independently bind the scan procfs PID view to
the actual controller-reader PID namespace, bind that reader's namespace/membership
context, and authenticate each controller boundary to the exact owned outer and
its unchanged measured 512-PID/4-GiB limits. Any extra observations, private fields
or requests require separately reviewed acquisition/identity rules, proof readers,
custody and call/byte/time accounting before implementation. This change collects
none of that evidence and does not extend the current protocol or footprint.

## Validation and remaining gates

Independent pure Rust fixtures exercise v1 co-mount/v2 and non-root mount roots,
component-prefix siblings, untranslated coordinates, duplicates and strict
descendants. Source guards bind the diagnostic observations to the original
predicates and stages to actual operations. Mocked wrapper controls cover closed
vocabulary, first-panic/cleanup ordering, malformed/secret suppression and unchanged
selection/handoff behavior. Pure cases also cover both controller conjuncts,
canonical CURRENT refusal and equal/outside ownership relations. They do not
execute a native worker or establish a
runtime cause.

Shared HealthRun, private producer/reader protocol, all budgets, controller and
ownership predicates, public schema, catalogue, pins and historical evidence remain unchanged. Local,
main, trusted dispatch and release retain the same canonical harness consumers;
no workflow, dependency, Renovate extraction, grouping or approval change is needed.
Raw counts remain 43/66 Debian and 45/70 upstream; selected catalogue stays 34/56
and 36/60. Complete final-edit gates, independent review, fresh exact-candidate
four-lane qualification and required actual consumer gates remain mandatory.
Host capture remains deferred. Diagnostics are not proof, compatibility,
application acceptance, a release, publication or deployment.
