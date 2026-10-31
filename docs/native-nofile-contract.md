# Diagonal nofile source-only contract

`nofile-v1` is canonical test-only invocation 28 under
[ADR 0045](decisions/0045-canonical-nofile-source-integration.md). Its producer
was recovered from committed `f406cb22efc53fc7df04c24ea44a9ecd7900f41b` without
that checkout's later coordinator, broker or catalogue changes. Historical
ADR 0028 remains provenance, not adoption of that runtime rewrite.

All original 27 calls, the fixed PIDs witness prebuild and immediate strict
PIDs27 reader must succeed before the separate one-child nofile owner scope.
The exact producer remains ignored outside the canonical harness. Its wrapper
forwards one original 180-second deadline without renewal; the 46-second
cleanup reserve, eight-slot ID guard, bounded captures and once-only handoff
remain unchanged. The existing 12-fact private reader runs immediately even
without evidence emission, and the emitter repeats validation with independent
external context and the separately selected outer backend. Only the exact
three-key result (`contract: nofile-v1`, empty `capability_admission`, false
`catalogue_admission`) passes. No public nofile projection is added.

Strict PIDs/delegation and hosted-runtime prerequisites cannot be skipped or
weakened to run nofile. Original lane EXIT cleanup remains mandatory. Source
wiring and synthetic controls do not prove native execution or qualification;
independent review, complete final-source gates and fresh exact-candidate
four-lane 28-call evidence remain pending. No raw admission, catalogue,
19-argument emitter ABI, product API, version, private packet schema, runtime
operation, software pin or budget is changed.

The existing `Ulimits`/`UlimitNofile` capability groups require finite **and**
unlimited source shapes. Finite success with negative unlimited outcomes must
not authorize those groups. A separately reviewed additive finite-only
capability would be a later product decision, not this change. Test-local
capabilities permit inert rendering of existing typed requests only. Every
proof explicitly retains empty capability admission and false catalogue
admission.

## Eight borrowed fixtures and truthful outcomes

Four ordered cases each have independent CLI and complete literal-rendered
roles: soft64/hard128; soft128/hard128; soft64/unlimited hard; unlimited
soft/hard. CLI requests explicitly supply both limits; rendered requests
independently contain one `HostConfig.Ulimits` entry with `Name: nofile`, finite
integers and signed `-1` for authored unlimited. Full request equality precedes
rendered submission. Neither role is generated from the other's serialization.

Only the unchanged harness-pinned BusyBox 1.37.0 is borrowed. Eight distinct
names/IDs carry exact run labels and pinned image identity. No derived image,
image acquisition, host mount, capability addition/drop, daemon-default change,
host limit change or sysctl write is permitted. Each created fixture must yield
a canonical ID. A create refusal, including a specifically attributable one,
fails qualification. A nofile-local guard checks the complete eight-slot ledger
before shared cleanup: any attempted slot lacking a canonical ID requires the
existing authenticated outer teardown without invoking inner cleanup at all.
Name lookup/recovery, name absence or a manufactured ID cannot turn such a
refusal into a successful source result. Shared historical cleanup is unchanged.

Finite cases must start and prove their exact actual limits and finite effects.
Each unlimited request has three distinct possible source dispositions:

- A known-ID START refusal, specifically attributable to setting Linux
  `RLIMIT_NOFILE` (rlimit type7) with the exact C-locale EPERM diagnostic. CLI
  exit1 and API HTTP500 must independently match the inspected native error,
  created/PID0/zero-start-time facts and stable never-started terminal state.
  Both roles must agree. Generic EPERM, nonzero, timeout, ENFILE, ENOSPC,
  malformed framing/body, unknown errors or create refusal cannot qualify.
- A successful start with finite kernel normalization. Record the actual
  finite values distinctly; never rename them exact unlimited.
- A successful start with exact intended unlimited state. Soft64/unlimited
  hard still requires finite-soft EMFILE. Only unlimited soft/hard uses bounded
  successful opens beyond the finite controls, not a claim of unlimited opens.

All running observations must agree across the independent roles. The actual
`fs.nr_open` ceiling is read only inside owned live fixture contexts and must
agree there. Linux can refuse a hard `RLIMIT_NOFILE` above that ceiling with
EPERM; the source never assumes that authored unlimited will start. Finite
effects plus a final matching daemon-version read corroborate a functioning
environment but never explain an otherwise unknown unlimited failure.

## Genuine inherited worker and live descriptor witnesses

Actual PID1 independently reads its own and its child's procfs limits/status
before and after the experiment. A background fork explicitly execs `/bin/awk`;
PID1 retains `$!` and later waits, preventing tail-exec ambiguity. Parent and
independent root observer check the live executable inode and the exact binary
NUL-delimited argv, including the separately passed program and unique token.
The worker independently reads `/proc/self/limits` and status. All eight
PID/PPID/soft/hard samples must agree: parent PID1/PPID0; original distinct
worker PID>1/PPID1. Root exec only corroborates those live actors.

Before the worker execs, PID1 creates 256 distinct owned regular input files
with exact token/index canaries and a FIFO. It opens the FIFO read/write and
retains the peer; the worker inherits it as already-open stdin, with separate
already-open private stdout/stderr files. Three flushed phase markers and
single authenticated FIFO releases bound baseline, held-open and post-close
observations. PID1 never queues a later release before the corresponding live
inventory; the worker remains alive and blocked while each inventory is read.

The worker performs nonfatal input `getline` on distinct filenames, retaining
successful streams. It resets and immediately captures native numeric `ERRNO`
around each attempt. A failed open qualifies only as `getline=-1, ERRNO=24`
(Linux EMFILE). No invented strerror, fatal-process exit or generic error is
substituted. Unsupported ERRNO behavior, stream recycling, unexpected closure,
wrong canary, early failure or reaching the finite-attempt ceiling fails the
entire proof, not an unsupported-platform grant. At most192 streams are tried.

PID1 independently inventories actual descriptor numbers, symlink targets and
dereferenced device/inode identities. It repeats baseline and held inventories
while the worker stays blocked. Up to16 measured baseline descriptors must bind
to the three owned control-file inodes; no unknown inherited target is accepted.
All 259 owned stream/control inodes must be distinct. Every held stream must
bind to its own numbered file inode, with no aliases or recycled descriptors.
Finite saturation must occupy **every actual numeric descriptor below the soft
limit** and fail opening the next distinct existing input. Capacity is derived
from this observed baseline and live occupied range, never assumed as limit-3.
Both soft128 roles must retain more streams than their corresponding soft64
controls.

After release, the original worker closes only its successfully retained
streams, checking each return. It then completes256 exact canary reads with an
immediate successful close after every read, under unchanged limits and the
same file/attempt budget. This necessarily reopens the formerly failing input
and exceeds both finite thresholds without retention. The original worker's
descriptor inventory must return exactly to its measured baseline. A failed
input may have a cached entry without a descriptor; `close=0` alone is never
treated as proof that the failed input had opened. Successful operations are
not assumed to clear ERRNO. No native internal program is executed by the
source-only Python tests; shell checks use `sh -n` only.

## One acquisition, original budgets and cleanup

A successful proof has all eight known canonical created IDs, including any
never-started IDs. One actual aggregate explicit-socket acquisition reserves20
request units and512KiB response bodies **before I/O** in the existing ledger.
Limits are eight selected IDs, ten expansions,128KiB per body,512KiB aggregate
bodies and at most `min(10s, original remaining time minus46s)`. Actual selected
roots, unique decoded IDs, Engine, observation identity, requested APIs and
present/effective nofile entries must match independently configured values.
Decoded retention does not imply kernel unlimited support. Rootless requires
positive decoding; rootful decoded Unknown remains separate and is backed by
the independently observed daemon context/UID, never silently promoted.

Body accounting is not wire accounting. Headers remain separately bounded at
16KiB, chunk-size lines64 bytes, payload CRLF2 bytes and final trailer line16KiB;
actual wire bytes are unmeasured. Initial context acquisition remains separately
bounded at16 requests/2MiB bodies/15s. Neither bound is multiplied per fixture,
reset after a refusal or claimed to be included in measured captured-command
bytes.

The immutable180-second deadline,134-second work cutoff,46-second cleanup
reserve,400 calls/4MiB captured-output-plus-reserved-body envelope and100-call/
2MiB cleanup reserve stay unchanged. Closed accounting is derived by outcome:
context8 upstream/9 Debian plus the independently selected Docker snapshot's
one extra call; each live slot8 captures, each precisely refused
known-ID start7; daemon-health1; aggregate acquisition20 reserved units; final
unchanged image/outer readbacks2 plus one extra call for selected Docker.
Thus ordinary units are91..95 upstream or92..96 Debian on Podman, and93..97
upstream or94..98 Debian on Docker. Ordinary bytes must fit2MiB and include the
existing two Docker image-observation reservations of65536 bytes each, in
addition to the512KiB decoded-body acquisition reservation. These conservative
ledger charges are not measured raw-wire bytes. All eight ordinary exact-ID
cleanup paths consume72 captures: five per removal and four across two complete
ID/name absence rounds per slot. Cleanup bytes are at most72×10240=737280,
within the original reserve. Timings and byte counts must pass, not just formulas.

The producer binds the closed `SourceOuterBackend` once before proof/fixture
owners or native I/O. Its enum and `source_outer_backend()` belong to the shared
24–26 lifecycle recovery, not a duplicate helper here. Existing `outer_context`
is the sole actual snapshot-charge owner. Acquisition checks room for its one
batch plus both pending final captures and the selected extra image reservation;
it does not spend those future charges twice or enlarge any reserve.

The Python validator and private reader require keyword-only `outer_backend`.
The twelve-positional CLI independently binds validated `NATIVE_OUTER_ENGINE`;
missing, unknown or non-string selections refuse, and no packet/context member
can select its own cost. `native_source_accounting.outer_snapshot_cost` and
`native_shm_size_proof`'s pure `exact`/`integer` are shared dependencies supplied
by the 24–26 recovery. Inner rootful/rootless mode, lane and proof self-context
are never substitutes. No backend field is added to the private v1 packet.

The fully bound path runs exactly one inherited lifecycle cleanup attempt.
Before entering it, the nofile-only guard validates bounded immutable snapshots
of all eight attempted flags and ID bindings. An attempted missing, lost or
malformed ID (or a partial ledger) skips the entire inner cleanup callback and
returns `OuterTeardownRequired`; no inner read, name recovery or mutation occurs.
The existing terminal handler requests authenticated outer teardown, disables
Drop retry and preserves failure. Valid bound IDs allow ordinary shared cleanup,
whose unverified result still propagates unchanged. Authenticated bound outer
ownership and the existing terminal handoff remain mandatory; no local cleanup
relaxation, deadline/counter reset, retry or unsafe Drop mutation is introduced.
Unverified cleanup or any uncertain transport/ownership/effect fails the whole
proof. Borrowed image and authenticated outer snapshots must remain unchanged
after cleanup before publication.

## Private protocol, sizing and integration seam

The fixed direct child is `nofile-v1.json`. Twelve independent harness facts,
not proof self-context, bind candidate/run/lane/Engine/APIs/mode/package/fixture/
daemon UID/outer identity and private capture directory. The closed reader
validates all ordered cases, typed outcomes/ranges, full actual manifests,
pair agreement, errno, limits, reuse, accounting, cleanup and empty/false
admission. Duplicate keys, missing/extra fields, Boolean-as-integer, stale
context and incomplete families refuse the entire proof. Success prints nothing;
refusal emits only a fixed private-value-free message. Raw errors, paths,
descriptor reports, IDs, inode values and argv remain private.

This recovery restores scoped shared custody support: `ProofTarget.publish_bounded`
and `read_private_proof(..., max_bytes=...)` retain identical held-directory,
exclusive no-follow, owner/mode, single-link and stable-readback controls. Their
old default remains16KiB; only nofile explicitly opts into512KiB. This does not
enlarge command stdout65550/stderr8192, API bodies, ordinary bytes, requests,
workload, deadlines or native admission. The only shared additions are the explicit
bound parameters and checked ceilings; current ancestry/file identity guards remain
unchanged. Recovered shared-custody controls cover the default and explicit bounds.
Rust compilation and final integrated complete verification remain primary
responsibilities; mocked controls are not native proof.

Each of eight witnesses has259 owned nodes. With baseline≤16 and the four
case-specific held caps, the complete proof has at most2072 owned nodes and2240
descriptor records. Linux descriptor/PID numbers are bounded to signed32-bit;
device/inode fields to unsigned64-bit; owned target paths are fixed. Metadata
excluding the two full inventory members is separately capped at65536 encoded
bytes. A conservative427672-byte inventory bound plus that metadata is493208,
below512KiB. The independent maximum-width synthetic fixture actually serializes
to449400 bytes (383864 inventory+65536 metadata), leaving74888 bytes. Its largest
complete native text report is54961 bytes, below65550. These sizing controls
retain full bindings, not hashes or producer-only summary claims. Actual lane
output and elapsed fit remain unverified and must fail closed if exceeded.

## External evidence and outstanding empirical checks

Documentation queried2026-10-18 through Context7 `/docker/cli`:
`docs/reference/commandline/container_run.md` documents
`--ulimit <type>=<soft>[:<hard>]` and nofile as `RLIMIT_NOFILE`. That unversioned
reference does not establish successful unlimited startup or kernel behavior;
native proof is mandatory. Docker CLI repository documentation is Apache-2.0;
no implementation is copied or redistributed.

Independent read-only specification research inspected upstream BusyBox1.37.0
as distributed at
`https://deb.debian.org/debian/pool/main/b/busybox/busybox_1.37.0.orig.tar.bz2`,
2565764 bytes, SHA-256
`3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4`.
Its awk source is GPLv2-or-later. Findings used only to check the proposed
oracle: nonfatal input open failure exposes numeric errno; distinct named
streams remain cached until close; close of an unopened cached entry can still
return zero; successful operations need not clear ERRNO; stdout flushing and
an already-open held FIFO require live arrival/readback checks. This source
implements the experiment independently and redistributes no oracle source.
No archive/tool/native workload is run by this change's validation.

Outstanding native assumptions: the exact pinned image's awk build implements
those behaviors; inherited FIFO/argv/procfs witnesses work in all four lanes;
explicit `-1` requests and precise runtime refusal diagnostics match the closed
contract; unlimited normalization, if any, is observed honestly; real captures
and cleanup fit the unchanged byte/time budgets. Unsupported awk behavior or
unknown runtime errors are proof failures, not evidence of native support.
No new dependency, tool/image pin or extraction path is introduced; existing
shared fixture/Renovate ownership is untouched. Host experiments, host capture,
runtime application/deployment and production finite-only admission are outside
this task.
