# Thread-aware PIDs source contract

[ADR 0044](decisions/0044-typed-pids-source-and-proof-v2.md) integrates the
[ADR 0043](decisions/0043-thread-aware-pids-source-contract.md) preparation into
the fixed runtime source. The private pure topology helper validates observed
roles; the discovery lease binds actual local leader membership and custody.
Neither helper accepts caller-supplied native authority. Current private proof
and readers use v2; root framing and worker/controller protocols remain v1.
Rootless systemd/PidsLimit requirements, resource ceilings and all 27 canonical
calls remain unchanged. Final-source and fresh native qualification are pending.

## Typed coverage and roles

Select the actual configured outer512 through the existing held private guest
mount/ancestor inode identity, before checking its limit and actual current at
most 512. Do not choose a different object with a convenient limit. Its type must
be `domain` or `domain threaded`; a `threaded` outer could clip a thread domain
whose process leader lies outside the boundary and must refuse this route.
The helper's opaque integer keys are local labels, not inodes, descriptors,
paths, process identities or authentication of that selection.

Decode only exact `domain\n`, `domain threaded\n` and `threaded\n` bytes. Missing,
unknown, malformed and `domain invalid` types refuse. Fully traverse the held
outer subtree, retaining the existing depth 12 (root depth zero), 128-directory,
mount/device, no-follow, identity, alias and entry bounds. The only non-root
edges in this restricted route are:

| Parent | Child |
| --- | --- |
| domain | domain or domain threaded |
| domain threaded | threaded |
| threaded | threaded |

The real hierarchy-root exception remains separately authenticated outside this
planner. There is no exception here for a configured outer below a threaded
ancestor. The helper requires exactly one supplied root, unique keys, known
parents and a connected, bounded tree. It cannot detect an omitted real child,
false supplied type, inode alias hidden behind two labels or a fabricated tree.

Ordinary nodes contribute their local `cgroup.procs`. Each thread root
(`domain threaded`) contributes its aggregate `cgroup.procs`. Threaded
descendants inherit exactly that enclosing thread root's coverage and must
never request `cgroup.procs`; traverse and type-check them anyway. The immutable
plan uses root-first traversal with numerically sorted sibling labels and
`local`, `aggregate` or `none` procs-read roles. Contributing owners are disjoint
in this shape model. Coverage ownership never substitutes for a leader's actual
local membership within that thread domain.

A future source must reject duplicate leaders within or across contributing
records, malformed lists, more than 512 distinct leaders and required procs
reads returning EOPNOTSUPP. Canonical duplicate-free sets permit kernel list
reordering but must never hide duplicates or truncate input. There is no
fallback enumeration and no all-TID candidate procfs census. This helper parses
no process records and establishes none of those source facts.

## Required discovery lease

There are exactly two existing discovery occasions: initial version-peer
binding and LocateBatch after the six pre-inspects. Later retained-object
rechecks must not add hidden traversals. Replace candidate discovery only after
independent implementation review of this complete in-process schedule:

1. Recheck outer custody. Pass A opens and holds the complete typed directory
   graph and reads contributing procs sets. Bracket every contributing read by
   matching type observations; hold the directories through Pass B.
2. For each leader, temporarily open its directory below the genuine held reader
   procfs and read stat/start, cgroup membership, stat/start. The two starts and
   proc identity must agree. Map membership to an actual held local graph object
   and its coverage object: exact local node for ordinary coverage, or the
   thread root/wholly threaded descendant for aggregate coverage. Close temporary
   handles promptly. These records are locators, not process lifetime authority.
3. The existing consumer acquires actual processes against those recorded starts
   and proc identities, requiring identical actual local membership. Peer binding
   retains SO_PEERPIDFD authority. Worker matching retains true TGID/leader,
   UID/time/root, actual NS_GET_PARENT objects, daemon-coordinate State.Pid,
   private-init coordinate 1 and unique role checks. Release unmatched processes.
   Keep only selected process/namespace custody; do not acquire six complete
   controller chains while holding the directory traversal.
4. Pass B repeats every listing/type, contributing set and provisional leader
   record. Require the same complete graph, sets, starts, proc identities and
   **local memberships**, and check names against held directories. Recheck
   selected processes and outer. Aggregate-set equality cannot hide a leader
   moving between threaded descendants.
5. Preserve selected local/coverage directory witnesses through explicit custody
   transfer, close other traversal objects, then construct full worker controller
   chains and compare their actual objects to the witnesses. Require strict
   outer descent, six distinct childless worker leaves, expected limits/current 1
   and final inspect/process rechecks. A peer may inhabit outer itself; a worker
   leaf may not. No closed descriptor may be reused as a witness.

Every failure must invalidate tentative selection and release owned resources,
including consumer rejection and transfer/cleanup errors. No final association
may escape before Pass B and the role-specific checks finish. Supplied source
data, matching namespace numbers and serialized observations grant no authority.

The lease is observation-scoped. Persistent identity/start/membership/type/name
drift refuses; change-and-return between observations can remain invisible.
It does not promise an atomic global freeze, birth-time membership, interval-wide
nonmovement or protection from hostile trusted-root behavior. Retained selected
pidfds and rechecks do not turn provisional records into race-free handles.

## Type lifetime and unchanged worker measurements

| Phase | Permitted observed same-object type pairs |
| --- | --- |
| Each discovery lease | Identical type only |
| Between leases before measurements | Identical type or domain ↔ domain threaded |
| Located measurement chains through SealMeasurements | Identical type only |
| Intentional cleanup after seal | Identical type or domain ↔ domain threaded |

The pure transition helper checks only this necessary type-pair condition.
Every permitted change still requires complete applicable role/tree validation
with separately held same-object identity. It does not establish the phase,
detect hidden transitions, authorize thread conversion, rebind objects, restart
discovery after seal or reopen measurements. Threaded-to-domain reversal is
never permitted. Detected changes during a lease or measurement interval refuse.

Any admitted worker-leaf type still requires actual childlessness, local
`cgroup.threads` accounting, exact pids.current, all worker/child start and
namespace identities, and NSpid=NStgid for every measured task. PID1 and its
15/32 children remain single-threaded. Finite16 still requires actual fork
EAGAIN, leaf local-enforcer increment 1, ancestor local 0, valid hierarchical
propagation, controls and capacity reuse. Complete ancestor/local-event/root
exemption/headroom/global/NPROC/kernel/time guarantees above outer512 remain;
bounded discovery must not truncate attribution.

## Private proof and implementation gates

The current source and independent readers use the private proof revision: `schema_version:2`,
`contract:pids-v2`, `candidate_membership:typed_procs_local_membership_v1` in
source attribution and `cgroup_type` in each existing non-root controller row.
The discriminator describes the algorithm; it authenticates no execution. Rust
and the independent Python reader must separately validate exact new shapes,
configured-root roles, topology, observed type stability and every existing
effect, source/hash, context, worker, accounting and cleanup predicate. No raw
candidate inventory is emitted. Mixed old/new sample shapes must refuse.
Existing version-1 root framing and worker/controller protocols need not change;
never bump them accidentally through a shared version constant. Historical
proofs, fixtures and their meanings remain unchanged. The producer, launcher, immediate reader and emitter require v2;
historical v1 proofs cannot qualify this candidate.

ADR 0044 supersedes only current-source diagnostic AST-equivalence assertions
for intentionally changed methods. The separately named pretyped diagnostic
archive preserves exact source and hashes from commit
`b4c9339fddeab7c107d02005448a13926e478a7d`; frozen comparisons retain the
historical meaning of `tests/test_native_pids_locator.py` and the unchanged
`tests/native_pids_type_detail_support.py` normalizer. Preserve historical fixture bytes,
hashes and equivalence/mutation controls against their frozen implementation.
Replace only inapplicable current/historical comparisons with independently
reviewed typed-contract, operation-order, budget and diagnostic tests. Use a new
named baseline only when justified; broader erasure or rewritten old fixtures
must not disguise a semantic change as metadata-only. No other current positive guard or historical equivalence assertion is superseded.

Require exception-safe lease/transfer controls and a real-I/O authored full IPC
transcript covering both discoveries, multithreaded daemon groups, six 16/33-task
phases, output, finalization and closure before enabling the route. Independently
review exact aggregate source/read/open/live-FD/output totals, not just a partial
cost model. Required negatives include unchanged aggregate membership with local
leader movement; missing/outside/duplicate/reused leaders; wrong coverage;
changed type/name/mount; omitted threaded subtrees; attempted threaded procs;
namespace collisions; extra worker threads; false root exemption; ancestor
enforcement substituted for leaf enforcement; reservation exhaustion before I/O;
consumer/cleanup failure; and stale/mixed proof/type rows.

Keep source 32 MiB/65,536 operations, live FD 256/cumulative opens 32,768, 64 KiB
output, 16 KiB frames, 128 KiB proof, all fixed reservations, parent 400 calls/
4 MiB and its existing partitions, and the original 180-second deadline/46-second
cleanup reserve. Charge before I/O; never reset/refund failed charges or enlarge
allowances to fit this route. Existing 1024-byte stat/cgroup and 4096-byte status
caps remain. Two passes add `2D+2C` type reads and two provisional guards add
`8L` opens/`6L` file reads, while replacing `2D` procs reads with `2C` saves `2T`.
These incremental expressions omit existing work and extra metadata/witness
costs and establish no complete fit. Arbitrary short reads can consume far more
reservations than ordinary-read estimates. Sum both discoveries with their
separate D/C/L values and retain all process/namespace, sampling and finalization
costs. Neither 512 leaders nor 128 directories guarantees success within budget;
bounded refusal remains mandatory. No fitting physical envelope is claimed here.

Pure literal controls test this planner's shapes and phase conditions only.
Complete final-source validation, independent review, fresh exact-candidate
four-lane native evidence and original whole-lane cleanup remain necessary.
Prepared nofile28, capability admission, fixture repair and product execution
remain deferred. No dependency, operational pin, pin location or shared workflow
changes; existing Renovate ownership/extraction/grouping/approvals remain intact.


## Current typed source authored envelope

The [discovery lease](../scripts/native_pids_discovery.py) is selected by the
production runtime locator for peer binding and complete worker matching.
[Pure controls](../tests/test_native_pids_discovery.py) retain custody, local
membership, unique witness ownership, descriptor reuse and failure cleanup.
The [complete authored transcript](../tests/test_native_pids_discovery_transcript.py)
uses the actual runtime locator and source classes, real bounded file I/O,
socket framing and process lifecycle. Fixed adapters simulate kernel filesystem,
namespace/pidfd, Engine and clock facts only. No selectable native provider or
product API is added.

Both models contain an empty configured domain, PID1 in init.scope, a threaded
daemon, six childless domain/thread-root/threaded worker leaves at different
depths, and an ancestor above the configured boundary. Literal expectations
check all type/parent/current/event/task facts, 24 sample responses, two complete
discoveries, 30 owner requests, 25 acknowledgments, 55 input frames and all source
closure. Sampling cannot reopen removed leaves after SealMeasurements; retained
outer/daemon custody still supports finalization. Threaded process-list reads
and nonleader proc acquisition are rejected before I/O.

| Authored model | Source bytes reserved | Read reservations | Open reservations | Peak FD reservations | Output bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| One-task daemon | 17,649,015 | 21,592 | 22,084 | 215 | 63,445 |
| Three-task daemon | 17,694,094 | 21,620 | 22,098 | 215 | 63,517 |

One additional cap32 baseline read for the above-outer ancestor uses two actual
regular-file read reservations, 59 reserved bytes and one open, included above.
All original ceilings, the 180-second deadline and 46-second cleanup reserve
remain unchanged. The three-task authored model leaves only 2,019 bytes below
the output ceiling. More/deeper ancestors, different inode or counter lengths,
short reads and native scheduling may exhaust a budget and must fail closed.
These models prove no maximum-size fit or native latency. They do not publish
the Rust private proof or qualify native execution.

The preceding preparation used test-local matching adapters and ordinary worker
chains. Its results remain historical observations, not evidence for this typed
implementation. Fresh exact-candidate native qualification, original whole-lane
cleanup, nofile28 and downstream acceptance remain required.
