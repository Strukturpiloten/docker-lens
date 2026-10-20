# Finite PID-controller source-effect contract

The PIDs child of the existing lifecycle helper is mandatory private invocation
27 under [ADR 0027](decisions/0027-pids-limit-private-qualification.md).
[ADR 0031](decisions/0031-pids-reader-coordinate-proof.md) defines its private
`pids-limit-v2` successor with retained reader-coordinate witnesses; historical
v1 evidence and reader remain unchanged, with no current fallback. The canonical
harness and unchanged nineteen-argument emitter require the strict successor
even without public PIDs projection. The 16 KiB custody ceiling remains unchanged.
[ADR 0033](decisions/0033-original-outer-custody.md) supersedes the unused boundary
reserve and unresolved original-root handoff with connected source; it does not
turn historical failed campaigns into qualified native evidence.
This is source-only integration for
#39/#31/#3, not passing native qualification, catalogue admission or a compatibility
claim. The primary owns complete/four-lane gates. Product output stays inert;
no native operational-pin, public API, public evidence-schema or historical
record changes. The dev-only clock pin and private custody-schema additions are
documented separately in ADR 0033 and the dependency policy.

## Retained per-reader coordinates

Each actual context/scan/controller shell reads its own status inline, requiring
one NSpid entry and `$$ == Pid == NSpid[0]`, then anchors namespace links through
that same observed PID. The 37 witnesses retain shell PID, proc/NSpid differences
and differences from the initial observer's three namespaces. The strict reader
independently checks exact integer types and bounds before enforcing every old
semantic predicate. No PID translation or namespace entry is introduced.

Eighteen phase objects become fixed ten-slot tuples without losing a datum.
Both sides enforce compact main-proof size at most 15 KiB within the existing
16 KiB custody cap. ADR 0033 now uses the remaining 1 KiB for one closed ten-slot
original-boundary record; the complete packet still cannot exceed 16 KiB. These
are serialization guards, not native boundary or packet-fit evidence. The
twelve/nineteen-argument interfaces, 28 native calls, owner scopes and aggregate
180-second/46-second budgets remain unchanged.
Synthetic round trips and source checks do not demonstrate native coordinate
alignment, rootless delegation, ownership or compatibility.

## Early rootless positive-qualification prerequisite

[ADR 0030](decisions/0030-rootless-positive-pids-prerequisite.md) requires reported
systemd and cgroup v2 for a rootless lane, after the existing sanitized ENV line
and before fixture pull or any of the 28 mandatory native invocations. Other or
unavailable values emit the fixed
DOCKERLENS_NATIVE_PREREQUISITE: rootless_positive_pids_requires_systemd_cgroup_v2
diagnostic and exit nonzero through the existing owned-resource EXIT cleanup.
No runtime query, fallback, skip or negative qualification is added; rootful
behavior, all positive assertions/proofs and budgets remain unchanged.

This is a necessary condition from the pinned official Docker rootless resource
documentation, never sufficient evidence of effects, ownership or compatibility.
Run 39173069422 at 19f1ce4c15c81dd1003e79065be4c5bddb0c17e9 failed PIDs in all
four lanes after 104 prior passes; nofile 28 was not reached and no artifacts or
cleanup-dependent lane successes were produced. Its separately authenticated
existing ENV lines report none/v2 rootless and cgroupfs/v2 rootful. Those reports
do not establish a runtime cause or actual enforcement. The rootless delegation
fixture prerequisite and rootful PID-coordinate/controller-boundary proof gaps
remain open; all four positive profiles still require genuine qualification.

## Failure localization and canonical mapped paths

[ADR 0029](decisions/0029-pids-failure-localization.md) supersedes only ADR 0027's
absence-of-PIDs-stage clause and repairs the independently demonstrated
empty-relative-path representation seam: both validated joined paths use
canonical components, matching the unchanged strict reader. Controller selection,
membership coordinates and ownership predicates do not change. This is not an
established cause of the failed native campaign. Actual closed case/role/operation stages precede
commands and each of the four outer/leaf controller resolutions. The wrapper keeps
the last valid stage before the first panic or cleanup boundary and only a single
phase-compatible resolver or controller classification (at most two PIDs lines).
Native stderr, paths, IDs, namespace
values, memberships and command payloads remain private. Refusal categories
distinguish no controller mount, no common mount-root coordinates, failed owned
descendancy and multiple fully matching mounts; they never translate paths or
relax the original exact-one predicate. Diagnostics are not proof or a root cause.

The outside_owned_descendant reason additionally distinguishes relation=equal_owner
from relation=outside_owner using the already evaluated equality/component-prefix
predicates; relation=mixed conservatively retains both observations across rooted
mounts. Controller classifications distinguish member_ids_mismatch,
current_count_mismatch and members_and_current_mismatch from existing captured
values, never raw IDs/counts. A matching controller observation emits no reason;
missing, duplicate, malformed or overflowing CURRENT also emits none. Original
assertions and short-circuit behavior remain intact; no extra request is made.
The wrapper omits duplicate/mixed classifications, clears them at each new stage
and ignores later output for this classification; shared cleanup/handoff reporting
is unchanged. These outcomes cannot identify a
runtime cause or authenticate an ownership boundary.

Failed exact-source run 39165508951 (attempt 1, be19402cccb94e20659acb04b1c267efe4390250)
passed 26 prior invocations per lane then failed PIDs 27 on all four: 104 prior
passes and four failed attempts, with zero artifacts and zero cleanup-dependent
lane successes. At that source, rootful first panics were shared command-success
542:9; rootless first panics were resolver 360:5. health_metadata_context was only
the last shared marker, not a demonstrated phase. No private proof/raw output was
available. Those failures remain unqualified; this change adds localization, not
a speculative namespace/controller fix. Host capture remains deferred.

Failed exact-source run 39169948731 (attempt 1, e2f0f479b5058fb9a5cd237adc95c998da6e6349)
also passed the first 26 per lane and failed PIDs 27 everywhere: 104 prior passes,
four failed attempts, no artifacts or cleanup-dependent lane successes; nofile 28
was not reached. Rootful finite16/oracle baseline_controller stopped at that
source's conjunction 824:5 without identifying either failed comparison. Rootless
finite16/oracle leaf_pids_resolve stopped at 484:5 with outside_owned_descendant,
which did not distinguish equality from outside-prefix refusal. The new closed
discrimination does not retroactively resolve those ambiguities or prove cleanup.

## Six independently authored cases

CLI/literal-rendered pairs explicitly request PidsLimit 16, 64 and unlimited.
Unlimited means no authored leaf PID ceiling, still inside the unchanged outer
512-PID boundary; 32 successful child launches do not prove arbitrary capacity.
Every whole rendered request is checked before once-only submission. One charged
six-ID Unix-socket acquisition retains the existing 16-request/512KiB envelope.

PID1 supervises one explicit BusyBox ash worker. It opens all control FIFOs before
the worker starts, and uses builtins during observation. The worker attempts at
most 32 single-threaded children, each held on an inherited FIFO. An EXIT trap
saves the original status and holds the original worker alive without forking.
The finite16 case requires precisely PID1, worker and 14 retained children, one
failed attempt, a native C-locale EAGAIN fork diagnostic and a matching owned-leaf
PID-controller denial increment. The controls require 32 retained children and
no denial. Missed trap, extra task, stale error, exhausted ceiling or ambiguous
observation rejects the proof, never becoming a generic unsupported result.

The trap design is informed by BusyBox 1.37.0 `shell/ash.c` fork and exit paths,
read as an external oracle only through Debian's upstream original archive:
`https://deb.debian.org/debian/pool/main/b/busybox/busybox_1.37.0.orig.tar.bz2`.
Archive SHA256 is `3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4`;
source licence is GPLv2-or-later. No implementation is copied or translated, and
no source or binary is incorporated or redistributed. The actual pinned image's
trap/diagnostic behaviour remains unverified until genuine execution. This is
source review, not an executed external runtime oracle; the intended native
oracle command is `/bin/busybox ash -c PIDS_WORKER dl-pids-worker`, defined in
the owned Rust source. No worker or observer command was executed in preparation.

## Namespace and controller attribution

Inspect State.Pid is never guessed to be an outer-namespace PID. Before pressure,
an actual private PID1 observation supplies its namespace inode, start identity
and UID. A bounded scan of the owned outer container's `/proc` binds these facts
to exactly one visible PID. An independently observed dockerd namespace depth
binds State.Pid to the correct NSpid element, including rootlesskit nesting.
Each fixture namespace must differ from both the daemon and outer observer
namespaces, including nested layouts. The initial resolver checks executable and
start identity only for private PID1; exiting non-PID1 members are not probed
before the bounded idle/reaping barrier. The complete post-barrier inventory
still checks every member's executable, namespace, identity and leaf membership.
UID-map translation, namespace identity, process start and parentage remain
stable across the observation. Each phase rechecks the observer namespaces;
control writes recheck PID1's namespace, start and mapped UID after opening a
verified FIFO descriptor. No host `/proc`, namespace entry or guessed
Docker cgroup path is used. Unknown/ambiguous mappings refuse.

The historical observations alone did not bind the scan's procfs coordinates to
each controller reader or authenticate the initial observer membership as the
bounded outer root. Numerical 512-PID/4-GiB checks and namespace equality cannot
supply either missing identity. ADR 0031 adds all 37 actual reader-coordinate
witnesses. ADR 0033 connects the retained original OCI inode and ancestor
descriptors to the producer and independent reader through bounded private stdin;
each actual reader rechecks the original PID1/start/UID, namespaces and controller
identity. PID1 relocation or a later equal-limit descendant cannot replace that
original root. No ancestor, daemon-view or mount-root rebasing is authorized.
This connected source is not a genuine native observation: coordinate, boundary
and positive-effect qualification remain open until the exact candidate passes.
Neither source correction establishes the cause of the historical failures.

Controller membership and the observer's actual mountinfo resolve v1 controller
mounts or v2 unified mounts with component-wise mount-root handling. Read actual
leaf members, current/maximum and denial events; use local counters when present,
otherwise require an exclusive leaf with no child cgroups. Hierarchical ancestor
event counters may propagate the leaf event and need not remain unchanged.
Actual constraining ancestors must retain at least 128 PID slots; the outer must
retain at least 1GiB memory and 128 slots within its 4GiB/512-PID bounds. Read
actual RLIMIT_NPROC and native no-OOM evidence. Metadata, generic fork text,
reported support or an Engine version alone never proves enforcement.
The worker cannot predate its original PID1; Linux soft NPROC cannot exceed the
hard limit, with unlimited accepted only according to that ordering. Each
controller has six distinct live leaf device/inode identities and resolved
paths, bound to one consistent owned outer mount/root/membership/device tuple.
Copied leaf facts or a conflicting outer controller binding reject the proof.

## Budgets, custody and cleanup

Only one workload is active. After a held observation, builtins release the
worker and children; leaf membership must return to the original idle PID1
before another case starts. Intended work accounting is at most 180 charged
ordinary calls including the separately charged acquisition, within 2MiB of the
4MiB charged total. The successful ledger is 16 calls per case (96), 6 upstream
or 7 Debian context commands, initial outer/image/observer reads (3), the charged
16-request acquisition allowance, and final image/outer reads (2): 123 upstream
or 124 Debian ordinary calls. Cleanup retains 100 calls/2MiB and 46 seconds of the original
180-second deadline. Six terminal removal/absence ledgers require 54 successful
cleanup captures. Six case ceilings of 15 seconds leave a bounded context/readback
allowance within the 134-second work window; these are enforced ceilings, not
evidence of actual native timing. The existing independent context acquisition
keeps its separate unchanged 16-request/2MiB/15-second envelope, outside these
charged byte/call counters but inside the same original deadline. Thus charged
captures plus that context acquisition can consume at most 6MiB overall; no
context allowance is silently included in the charged 4MiB ledger. At most
177/178 charged captures including successful cleanup are expected; this is
not a claim that every command can simultaneously consume its timeout ceiling.

ADR 0033 adds physical source-I/O claims and disjoint, once-preclaimed roles
within the original aggregate envelopes; it does not relabel these historical
123/124 ordinary or 54 cleanup capture counters as complete connected accounting.
Contexts, acquisition, protocol frames, native dual streams, private proof I/O
and immutable source-record reads must all be covered. Actual bytes stay spent
after cancellation or expiry; only unused claims are released, and an in-flight
claim cannot cross phases. Reader/emitter bootstrap spends are admitted once
into the original role rather than gaining a new pool. Original monotonic S/D
remains authoritative through blocking I/O, completion and publication. PIDs
producer cleanup and original-root recovery share the existing cleanup envelope;
the same once-only recovery reservation cannot be renewed. ADR 0033 records the
former caller-slice refusal and experimental fixed redistribution within the
unchanged aggregate. Four authored connected scenarios fit that candidate;
partial fixtures and the synthetic phase driver do not qualify genuine native
metadata I/O, payload variability or the complete native workload.

The fixed owner-private direct-child proof is limited to 16KiB. Compact numeric
PID/start/parent tuples and selected mount/controller facts avoid retaining full
proc tables or logs. Process rows encode `[outer_pid_delta, private_pid,
outer_parent_delta, start_delta, uid_delta]` relative to independently bound
PID1's outer PID, start and mapped UID; separate actual `cgroup.procs` members
are outer-PID deltas. The reader reverses this encoding before checking every
identity, parent and membership; no observed member evidence is dropped.
Serialization and the strict stable no-follow reader both
enforce that bound; an oversized or incomplete proof cannot be published.
Authored compact fixtures occupy 15,452–15,748 bytes. These short synthetic paths
do not establish that genuine cgroup paths fit: the focused long-path case
retains valid identity/controller evidence but exceeds custody and is refused.
Larger native evidence needs a separately reviewed scoped exception, not dropped
facts, truncation or a silent shared limit change.

The authored create body is 1458 bytes with the existing pinned-image reference.
Duplicated `Config.Cmd`, `Path` and `Args` inspect fields occupy 2564 compact
bytes, leaving 5628 bytes for all other native fields/framing within the unchanged
8192-byte cleanup capture limit. The pure check reserves at least 5KiB for that
unknown remainder; it cannot prove the complete genuine inspect envelope fits.
Ordinary capture, request-body and cleanup limits stay unchanged and fail closed.

Every attempted create needs a canonical bound ID. Any missing/malformed ID
requires authenticated outer teardown **before** invoking inner cleanup or name
recovery. Bound resources retain immediate ownership rechecks, once-only removal,
two ID/name absence rounds and unchanged borrowed-image/outer snapshots. Cleanup
ambiguity preserves failure and requests outer teardown, not a positive receipt.
Public diagnostics remain closed and value-free; private proc/ID/path/error
evidence never becomes a capability claim. Pure/synthetic checks establish none
of the outstanding native gates.
