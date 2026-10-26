# Prepared PIDs runtime locator and root source session

The original-owner integration described by [ADR 0041](decisions/0041-original-owner-pids-experiment.md)
and [the owner contract](native-pids-owner.md) now wires this fixed source
session into canonical invocation 27. Statements below that its owner/reader
integration is pending describe the preceding prepared-source checkpoint.
Actual native qualification, final outer cleanup and capability admission
remain separate; this source implementation alone establishes none of them.

[ADR 0040](decisions/0040-pids-runtime-source-session.md) supplements the measured
window in ADR 0039. The fixed runtime source is now composed into canonical
PIDs27 under ADR 0041; the emitter independently reads its private proof and
adds only an unadmitted outcome. Canonical calls 1–26, public APIs, capabilities,
catalogue and nofile source remain unchanged. Neither these controls nor a
successful source session qualify mandatory PIDs27.
Rootless none/v2 refusal is never positive evidence or permission for nofile28.

## Actual in-process association

`scripts/native_pids_locator.py` composes `LocatorSource` with the existing
`LinuxSource`. `RuntimeLocator` accepts retained **actual** outer `Process` and
`Group` objects, a `HeldEndpoint`, an independently selected `DaemonExpectation`,
an exact API version, original ownership labels and a synchronous parent-ledger
reservation callback. It never accepts process authority over a JSON request.
The original trusted runtime owner must acquire the exact owned outer CID using
its canonical backend/actor/context before using PID/start as kernel locators,
and repeat that actual acquisition after root kernel acquisition, before Confirm.
Matching caller PID/context fields do not authenticate that CID. The helper has
no default Docker lookup, Podman privilege switch or runtime command broker.

`locate_batch()` accepts exactly the ordered six registered slot/ID pairs:
`cli16`, `cli64`, `cli_unlimited`, `rendered16`, `rendered64`,
`rendered_unlimited`. IDs must be distinct complete lowercase hexadecimal IDs.
For each ID it reads the fixed selected-version container-inspect GET before
and after one shared kernel traversal. Actual ID, owner labels, running/nondead/
nonpaused/nonrestarting state, positive `State.Pid`, start time and restart count
must remain stable. Unknown routes, paths, methods, commands, PID lists,
namespace tuples and arbitrary source providers are absent from the protocol.

The fixed `socket/docker.sock` endpoint is opened below the received capture
directory, with held no-follow directory and `O_PATH|O_NOFOLLOW|O_CLOEXEC` socket
descriptors. Every exchange rechecks pathname custody and connects only through
the socket FD's `/proc/self/fd/` reference. Replacement/unlink refuses policy;
there is no pathname fallback. An authorized owned Unix-server smoke on
2026-10-25 verified the kernel recipe locally across rename, replacement and
unlink. This is not a hosted-runner or dockerd qualification.

The optional Unix-HTTP peer lease obtains `SO_PEERCRED` and **SO_PEERPIDFD on
that exact inspect connection**. A numeric peer PID followed by `pidfd_open` is
not a replacement for the socket peer pidfd. The first original peer pidfd is
duplicated into source custody and retained across connections, alongside the
daemon's process/pidfd/root/namespace and executable FDs. Fresh peers must match
that original process. Liveness, UID, executable, namespace/root and outer
custody checks bracket the complete body. Unsupported peer-pidfd interfaces,
dead peers, proxies, unrelated listeners and changed executables refuse.
The fixed factory first binds that actual peer with a bounded `GET /version`,
before any experiment workers are created; the per-ID inspections occur later.

Daemon UID and executable components must come from independently reviewed lane
facts, with reader-visible UID mapping established by the original runtime
owner. They must never be chosen by observing the peer being authenticated.
`direct_managed_runtime=True` is a required trusted fixture qualification, not
automatic proof of arbitrary containerd/shim State.Pid coordinates. Native
verification of that coordinate contract remains required for each exact lane.

Independent immutable fixture research identifies upstream dockerd at
`usr/local/bin/dockerd` (Containers revision
`0b136a13a8bb612d91960ae5d07e72f449c89ec1`) and Debian's exact
`20.10.5+dfsg1-1+deb11u2` install at `usr/sbin/dockerd`
([package install source](https://sources.debian.org/data/main/d/docker.io/20.10.5%2Bdfsg1-1%2Bdeb11u2/debian/docker.io.install),
image revision `d148838d2b1234f5a898ff2a6d4e7393a259d92c`). The image accounts
use UID0/1000 for rootful/rootless. These are image coordinates: the original
owner must independently establish reader-visible UID0/1000. The implemented
first route opens and holds actual outer and reader `ns/user` FDs and requires
their identities to agree, rechecking the outer identity thereafter. A mapped
outer user namespace refuses; no caller boolean substitutes for that check.
Rootful Podman selection alone does not prove the absence of containers.conf
userns remapping. No peer-observed UID oracle chooses the expectation and no
default is implemented. Broader independently mapped routes remain out of scope.

Candidate leaders come only from actual `cgroup.procs` files below the held outer
group, including its own file: at most512 leaders,128 directories and12 levels.
Reads use bounded `getdents64` buffers and descriptor-relative opens. Mount/device
changes, directory aliases/replacement, duplicate membership, migration and
incomplete scans refuse. There is no `top`, `ps`, global proc enumeration,
argv/environment scan, namespace entry or controller write.

The reader verifies that actual self PID/Tgid/NSpid/NStgid describe exactly its
procfs coordinate namespace. Each candidate's complete leader vectors must
match the retained, actual `NS_GET_PARENT` chain to that reader namespace.
The daemon namespace must occur by **namespace object identity**, then its exact
vector coordinate must equal `State.Pid`. Both RootlessKit with and without an
extra PID namespace are represented; sibling namespace numbers never match.
Inaccessible/unsupported ancestry is refusal, never guessed initial-namespace
proof. Exactly one live private-init match and a distinct strict descendant leaf
with the intended limit/current1 must exist per slot. Reinspection/rechecks
retain the same objects, never a replacement numeric PID.

`RuntimeBoundProcess` objects pass directly into `RootSession` sampling in that
same source server process. They are not serialized and reopened. TID accounting
keeps reader PID/start pairs and complete native NSpid/NStgid coordinates in
`task_namespace_ids`, for later independent worker-child report mapping.

## Root bootstrap, watchdog and protocol

`scripts/native-pids-supervisor.py supervise ABSOLUTE_MONOTONIC_NS` is the fixed
root launch target. The original owner must launch through fixed reviewed sudo
and isolated Python paths, stdin mapped to an anonymous Unix stream socketpair,
stdout `/dev/null`, bounded fixed stderr and all unrelated descriptors closed.
Sibling helpers load only from fixed paths relative to `__file__`, retaining
isolated Python startup; cached modules are reused only when their actual file
paths match those exact siblings. There is no PYTHONPATH/environment fallback.
No `sudo -C`, sudoers/host setup, arbitrary path argument or listening service is
provided. Actual FD0 must remain an unnamed connected Unix stream with live
peer credentials/pidfd; substituted pipe/PTY/named listener refuses.

Before source reads, the root watchdog forks only its fixed server child, holds
real parent/child pidfds, establishes its private child process group and gates
startup. Cancellation is blocked until handlers/ownership are ready. The child
arms `PR_SET_PDEATHSIG(SIGKILL)` and checks its original supervisor parent before
work. The monitor parses no JSON and reads no procfs/cgroup/runtime data. It
polls/signals/reaps under the original terminal deadline: parent death/cancel
triggers TERM and at most1second grace; terminal TERM starts at deadline−2sec,
KILL no later than the original deadline. Unreapable tasks are failed cleanup,
never a blocking timer extension or successful evidence.

The child revalidates the actual peer, UID, process identity, shared time
namespace and a bounded eight-process ancestry through its fixed supervisor and
actual `/usr/bin/sudo` monitors. It holds/rechecks process starts/parent links;
environment variables and JSON parent facts are not authority. This assumes the
trusted original harness, guest/runtime and host root, not hostile-root defense.
No Cargo, tests, caches or capture publication run as root.

Bootstrap is exactly `BFPIDS1\n` with one SCM_RIGHTS capture-directory FD, followed
by `BFREADY\n`. The actual directory must be mode0700 including special-bit
rejection, owned by the actual original peer UID, and close-on-exec. Split stream
messages are accumulated without assuming send/receive boundaries. Every read,
including post-terminal EOF, uses bounded `recvmsg`; truncation, malformed,
missing/multiple/late rights or other ancillary data fails. All delivered rights
are closed on rejection, even when another control item is invalid.

Subsequent frames have a four-byte network-order length and one UTF-8 JSON object
of at most16KiB. Version1 and consecutive sequence numbers are mandatory. Zero/
oversized/truncated frames, duplicate keys, nonfinite numbers, unknown keys and
state/order violations fail. At most64 requests and64KiB cumulative responses
are allowed. There is one request in flight. `RootSession` accepts only:

| Operation | Additional fields | State |
| --- | --- | --- |
| `RootBindRuntime` | closed context, outer PID/start locators, fixed owner label | unbound → pending |
| `ConfirmRuntime` | none; original owner has completed actual second inspection | pending → confirmed |
| `LocateBatch` | `slots`: six exact original-owner CIDs in fixed slot order | confirmed → measuring |
| `RecheckBatch` | none | measuring |
| `Sample` | fixed `slot`, ordered `phase` | measuring |
| `SealMeasurements` | none | all six complete |
| `OuterFinalize` | none | sealed, terminal |

Common fields are exactly `version:1`, consecutive integer `sequence`, and `op`.
RootBindRuntime additionally accepts exactly `context`, `outer_pid`,
`outer_start`, `owner_labels`, `external_source`. Context has exactly backend (`podman`/`docker`),
candidate (40 lowercase hexadecimal), run (1–128 ASCII token characters), lane
(`debian11-rootful`, `debian11-rootless`, `upstream-rootful`,
`upstream-rootless`) and outer_id (64 lowercase hexadecimal). PID/start are
numeric locators, not CID authentication. The fixed factory opens/checks the
actual outer leader/private-init/root/namespace/cgroup objects and derives
UID/executable/Engine/API expectations from the closed lane table. It executes
the actual version GET and retains the resulting original daemon binding before
returning `pending`. It performs no outer runtime CLI call.

The original Rust owner must then execute its second canonical exact-CID
inspection under the original actor/context and compare actual state/start/
restart/PID facts before sending ConfirmRuntime. Root rechecks its original held
objects and returns `confirmed`; the acknowledgment alone does not prove those
Rust operations ran. Only then may the owner create the six barrier fixtures and
send their IDs in LocateBatch. Outer custody therefore precedes experiment
creation. RootBindRuntime cannot be repeated or silently rebind replacements.

The fixed owner-label map is exactly `io.dockerlens.native-pids: <context.run>`.
Every inner fixture must also carry `io.dockerlens.native-pids-slot: <slot>`;
the exact inspect body must bind that role, including same-limit CLI/rendered
pairs. Neither label nor immutable context assertion is independently trusted
runtime ownership proof. No UID, executable, API version, path, source selector,
deadline or caller `verified` field is accepted.

RootBindRuntime requires exactly `external_source:{bytes,reads}`. These
nonnegative integers only debit the existing32MiB/65,536 source counters before
factory I/O, preserving prior bootstrap/parent-guard charges. They cannot raise
limits or authenticate operations. The original owner precharges actual host
artifact/hash reads and one guest-copy read/write/readback before doing them;
its actual I/O receipts and complete producer establish those costs. Missing,
repeated, malformed or exhausting external debits fail closed. No binary travels
through this private parent/helper transport.

For each API call the server sends a reverse control frame with exactly
version, the **same pending owner-request sequence**, op=`ReserveApi`, a global
consecutive `reservation`, units=1 and max_body_bytes (4096 for initial version,
32768 for each inspect). The original owner debits its shared ledger before
replying with exactly version, that same sequence, op=`ApiReservationAccepted`
and matching reservation. This acknowledgment does not advance the normal
request sequence or establish runtime authority. No API call starts on missing,
stale, malformed, denied or over-budget acknowledgment. The real owner adapter
must actually debit; a fabricated acknowledgment cannot become native proof.

Normal non-sample replies have exactly version, sequence, op and status. Status
is pending/confirmed/ok/sealed respectively. Sample has those common fields and
`sample` only, with maximum/current/events_max/tasks/task_namespace_ids plus
attribution/globals below;
its slot/phase are bound by the outstanding request/sequence. OuterFinalize adds
`reservations`: inspect_calls_reserved, inspect_body_bytes_reserved,
runtime_probe_calls_reserved and runtime_probe_body_bytes_reserved. It also adds
`source_ledger`: external_reserved/root_reserved/total_reserved byte/read pairs,
fixed limits, FD reservation totals and output_reserved_before_final. The last
value excludes the final frame; the original owner adds its actual final-frame
length and checks64KiB. Source-owned remaining FDs must be zero before this result.

The canonical no-Recheck transcript is29 owner requests (bind,confirm,locate,
24samples,seal,finalize) plus19 API debit acknowledgments, for48 input frames.
The explicit-Recheck superset is30requests plus25acknowledgments,55frames.
Both remain under64 and are executed over actual socketpair IPC with all six
16/33-task phases in an authored kernel tree, not a native daemon/runtime.

Each role's four phases are before,at_limit,after_failure/control,after_release;
finite16 uses after_failure, finite64/unlimited use control. These phase labels
alone do not prove fork errno or enforcement. Seal rechecks all live measurements
by original elapsed second134, releases inner-only descriptors and irrevocably
forbids new lookup/sampling. Original outer/daemon handles remain during the
owner's intentional inner cleanup. `OuterFinalize` requires actual request EOF,
checks only original outer/daemon/root/namespace/controller custody, closes all
source handles before acknowledgment and never demands removed leaves survive.
It leaves at least the watchdog's final2seconds. By the original180-second
case27 deadline the owner must verify all six inner absences, its controller/
copy/descriptor cleanup, final actual same-actor outer inspection, helper EOF
and supervised successful exit. Case27 deliberately retains the shared outer
fixture for later28. Its removal remains the original harness EXIT owner's
responsibility; only actual whole-lane cleanup plus successful job/aggregate
can establish that teardown and admission. A descriptive outer_teardown_owner
marker is not cleanup authority. No case deadline or global-cleanup guarantee
is expanded; unknown/partial cleanup never qualifies.

`source_server()` now constructs `RuntimeBoundSession` after actual parent and
bootstrap guards, transfers the received capture FD irreversibly into source
ownership, and runs the fixed factory/protocol. The received server capability
remains held through seal/inner cleanup and closes with all source handles
**before** final response; close failure prevents acknowledgment. The parent's
separate original capture FD remains its own. No borrowed descriptor is closed
twice or only after a successful final acknowledgment.

**Remaining integration:** the original Rust owner's actual canonical before/
after outer acquisition, launch/debit adapter and complete producer/private
reader still require independent integration/review. Root source acknowledgments
alone cannot prove the parent operations or a native experiment. Exact lane
runtime behavior, actual root/sudo qualification and full experiment are pending.

## Configured outer boundary and attribution

PID1 may move into an `init.scope` descendant. Its direct cgroup is not assumed
to be the configured outer512 root. The factory retains that original process,
root and mount/cgroup-namespace FDs, requires the reviewed private cgroupns route
and opens `sys/fs/cgroup` componentwise below the held process root. It holds the
genuine cgroup2 directory and mount ID, matches one actual PID1 mountinfo record
by mount ID/device/filesystem and exact mount point `/sys/fs/cgroup`, then
matches that inode to exactly one already-held global ancestor of PID1. It
selects **that object first**, then requires actual `pids.max`512. No nearest512
search, CID-to-path guess or target mountinfo-root-text inference exists.
Target mount record/FD/mount ID, named fixed-path reopening and original process
root/namespaces are rechecked through finalization. A global-root, same-reader
cgroup namespace, unmatched/ambiguous or unqualified private route refuses;
the original owner's before/after inspection also corroborates actual private
configuration. Rootful dockerd may remain PID1 and share outer PID namespace/
group; moved PID1 and another daemon descendant are supported explicitly.

Each RuntimeLocator sample adds `attribution` and `globals`. Attribution holds
fixed no-follow controller FDs for the already-held directory chain, cached by
actual identity. `controllers` runs leaf→rootward through **every** held non-root
ancestor above original outer512. Each row has identity `[device,inode,mount_id]`,
maximum/current, events_max and events_local_max. `outer_index` identifies the
original outer and must exceed zero. Root/controller/file identities and values
bracket the task sample. A missing `.local` interface or actual `pids_localevents`
mount flag gives closed UnsupportedEventSemantics refusal.

The complete-chain root witness combines genuine cgroup2/mount-ID/device,
mountinfo root `/`, actual controller availability containing pids, and explicit
ENOENT for **pids.max, cgroup.type and cgroup.events** at the same held anchor.
The latter controller-independent files carry actual-kernel NOT_ON_ROOT flags;
namespace-relative `/` alone is insufficient. Reader cgroup namespace is held/
rechecked against the authenticated original parent's namespace, recorded only
as identity, never called initial from an inode or EPERM. Root exemptions are
explicit identity/absence records, with no invented maximum/current zero. Hidden
prefixes or unresolved witnesses set complete_chain=false and qualification;
they cannot establish positive all-ancestor headroom.

Globals read only fixed procfs threads-max, pid_max and loadavg (actual fourth-
field total-task denominator), bound worker stat policy field41 and Max processes
soft/hard limits, plus bounded actual uname release/version/machine. Finite and
unlimited NPROC are retained exactly; no UID-population estimate, process scan
or guessed exemption is made. Root/worker measured kernel identities and limits
must match in the strict producer. File presence or a version string does not
authenticate arbitrary vendor-kernel semantics.

Dynamic global task counts and ancestor current counts are observations, not
global exclusivity. `total_tasks_samples` and each controller's `current_samples`
retain actual before/after values; total_tasks/current are the maximum of those
**two endpoints only**, never a claimed interval peak. Hierarchical/local event
sample pairs are retained, must be nondecreasing and expose unrelated ancestor
events without attributing extras to this attempt. Actual leaf task/current/
counters and all identities, limits, kernel, scheduler and NPROC facts still
must agree across a barrier. Unsafe sampled headroom remains a producer refusal,
not permission to release planned workload from a merely successful read.

The reader, authenticated original parent, actual outer/daemon/inner processes
and accounted TIDs must share the same held `ns/time` object. Role-process time
FDs remain held/rechecked; TID time checks close their transient descriptors.
This binds the unchanged HOST monotonic deadline to the worker's actual domain
without an offset assumption or caller JSON flag.

Under reviewed default hierarchical/local-enforcer semantics, the sole owned
finite16 EAGAIN attempt needs leaf local+hierarchical delta1 and ancestor LOCAL
delta0. Ancestor hierarchical counters may propagate+1; requiring them to stay
zero is incorrect. Reviewed fork ordering places NPROC, threads-max, scheduler
and PID allocation checks before cgroup_can_fork. A correlated enforcing-leaf
local event excludes those earlier checks for this attempt without requiring
NPROC infinity. Ordinary policy0 and actual32-child controls/reuse remain
necessary. Threads-max sampled headroom is remaining planned new tasks+1, plus
only explicitly planned extra harness forks; existing helpers are counted.
pid_max is a stable positive ceiling, **not a free-PID census** or permanent
capacity promise. These are measured-window conclusions, not atomic snapshots
or arbitrary-host/birth attestations.

Semantic references: Linux[v6.11 pids.c](https://github.com/torvalds/linux/blob/v6.11/kernel/cgroup/pids.c),
[v6.11 fork.c](https://github.com/torvalds/linux/blob/v6.11/kernel/fork.c), and
[cgroup-v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).
v6.6 lacks the local interface. No kernel allowlist, installation/upgrade or
external code copying/mechanical translation is added.

## Independent budgets and evidence limits

The **physical source ceiling is32MiB/65,536 read/reservations**, with256 live FD
reservations and32,768 cumulative opens. Sixteen fixed FD slots conservatively
reserve bounded HTTP/control/stdio, peer and watchdog/launch overhead through
process exit; three additional Channel slots cover capture/ancillary custody.
Those reservations are retained after source-owned descriptors close. It
includes procfs/cgroup buffers,
namespace walks, HTTP socket reads and IPC input, precharged before I/O including
partial/EOF reads. File reads precharge each actual syscall chunk of at most1024
bytes before seek/read; per-file caps remain unchanged. Expected root absence
uses bounded256-byte metadata reservations without failed FD allocations.
Failed reservations remain charged. It is distinct from the
unchanged parent400 command/API units and4MiB captured output/API bodies,
300-unit/2MiB work partition and100-unit/2MiB cleanup reserve.64KiB helper output
is a capture cap, not a fresh allowance. All roles/phases share one source ledger
and the immutable original180-second deadline; cleanup uses the existing46-second
reserve. Legacy `Budget`/`Session` remain work-only; only sealed `RuntimeBudget`
enters cleanup mode.

`ParentReservations` synchronously calls the original owner's mandatory debit
callback **before** each inspect connection, reserving one API unit and32KiB
maximum body. Its closed receipt is accounting data, not source authority. A
locate12 + seal6 sequence reserves18inspects/589,824 body bytes, plus one4096-byte
version probe:19calls/593,920bytes. With Recheck6 the superset is24inspects plus
probe:25calls/790,528bytes. The
owner must separately pre-reserve launch/IPC, other captures, case-local cleanup
and final outer inspection in its existing ledger. Whole-outer teardown stays
with the original harness EXIT owner. The32KiB inspect cap is a conservative
refusal bound for these six small fixtures, with no larger-body fallback; actual
native bodies must fit. The preceding64KiB×24 proposal plus the existing512KiB
acquisition reserve already consumed the entire ordinary2MiB before responses
and was not viable. Negative debit-exhaustion controls require failure before
any connection/source I/O and retain failed reservations. No full Rust callback
or complete parent/native fit is claimed here.

The full factory transcript test executes all six16/33-task phases, actual
socketpair API-debit acknowledgments, kernel-file/controller reads, selected
guest-mount rechecks, source sealing and pre-ack closure over an authored kernel
tree. A read-only exact-code trace retained both actual final source ledgers:

| Flow | Root reserved bytes/operations | Total with1MiB/1024 external debit | Helper capture | FD opens/peak |
| --- | --- | --- | --- | --- |
| Canonical18inspects+probe |14,211,900/16,870|15,260,476/17,894|50,996bytes (50,337+659)|17,512/174|
| Superset24inspects+probe |15,033,023/17,892|16,081,599/18,916|51,655bytes (50,996+659)|18,879/174|

Both close all source-owned descriptors before acknowledgment; sixteen fixed
overhead slots remain reserved through process exit. The receipt records
identical eight Python file bytes/modes before and after both measurements.

These numbers belong only to this fixed authored model: proc/cgroup file reads,
descriptor custody and Unix IPC are actual OS I/O; namespace/pidfd/fs-type/mount
facts and Engine replies are simulated. External1MiB is a test debit, not an
actual binary-copy receipt. Real root/sudo/host mount sizes, extra ancestors,
original-parent guards and actual worker/native fixture behavior still require
native fit. The standalone sample projection is separate evidence and is not
substituted for the complete IPC transcript. No full worst-ceiling or four-lane
native qualification follows from either test.

Still pending: original owner integration/barriers, independent worker-report
mapping, strict producer acceptance of the implemented ancestor/global/raw
counter observations and causal effect predicates, strict private
proof reader, original-context root/sudo tests, complete final gate and fresh
four-lane native qualification. No OCI/birth/log attestation is added.

No dependency, image/tool/workflow pin, manifest, lockfile, canonical coordinator
or Renovate extraction path is changed. Existing manager ownership, grouping,
approvals and native-image extraction remain unchanged; no new manager applies.
