# ADR 0033: Original outer custody and connected private PIDs qualification

Status: accepted validation-infrastructure contract; connected-source and native
qualification remain pending.

## Context

ADR 0031 retains all 37 actual reader-coordinate witnesses but leaves the exact
original outer controller boundary unresolved. The bootstrap, lifecycle and
broker prerequisites alone do not establish a connected native proof. Failed
campaigns and historical source records remain immutable and unqualified.

## Decision

Supersede only ADR 0031's unused boundary reserve and unresolved original-root
handoff. Keep the existing semantic predicates, all 37 six-slot coordinate
witnesses and 18 lossless phase tuples. The private v2 packet adds one closed
ten-slot boundary within the existing 1 KiB reserve: main serialization remains
at most 15360 bytes and the complete packet at most 16384 bytes. A synthetically
fitting packet is not a native fit or positive effect observation.

One root broker retains the original OCI inode and ancestor descriptors from
initialization through final cleanup. The canonical caller owns its private
log inode from birth; diagnostic code adopts a duplicate rather than creating
a competing custody object. PID1 relocation never redefines the original
controller root, and a later equal-limit descendant is not its substitute.
Every actual reader rechecks the original PID1/start/UID, namespace and
controller identity alongside its original coordinate and effect predicates.

Wire v2 has a closed preflight, create, initialize, bind_expectation, start
sequence. Immutable intent and complete expectations are independently derived
from reviewed static intent and verified preflight/database facts on both
sides. A caller echo or an OCI document cannot supply its own expected values.
Original OCI bytes move once, only after expectation binding. Trusted runtime
configuration/executable metadata supplies the reviewed provenance boundary;
there is no new binary-hash, recursive host-device or OS-attestation claim.

One unprivileged canonical coordinator exclusively owns the root broker pipes.
Phase proxies and a relay carry closed control messages; they never inherit
broker authority. Private producer and independent reader/emitter contexts use
bounded stdin rather than raw source paths, environment maps or sidecars.
The existing twelve-argument reader and nineteen-argument emitter contracts
remain; all 28 exact tests and six owner scopes stay independently mandatory.
The Cargo list barrier receives null stdin and completes before the one-time
PIDs start S. Worker-built binaries are not reused as final-candidate evidence.
The legacy emitter's required fixture, outer-ID and daemon-UID environment
fields are rebuilt only from maintained source and validated coordinator state;
same-named parent environment values are never inherited as authority.

Execution provenance is explicit: github_actions requires actual positive
run/attempt strings; local_process has null CI identifiers and the fresh local
session. Partial or malformed hosted identity refuses before shell resource
creation. Numeric labels do not authenticate GitHub. Rust validates the closed
context and actual reader observations; authoritative original source/session
and CI identity checks remain the coordinator's and independent consumers'
responsibility. Pre-context delivery remains under coordinator supervision.

Physical source I/O is authorized against the existing role/phase before the
read or write. Actual bytes stay spent even if cancellation or deadline expiry
is noticed immediately afterwards; only unused in-flight claims are released.
Diagnostic registration metadata and raw writes use that same caller slice;
there is no separate diagnostic allowance or buffered uncharged write.
An outstanding claim cannot migrate to another phase. A clamped read that fills
its authorization cannot masquerade as complete, successfully bounded input.
Reader/emitter stdin has an intrinsic, source-defined bootstrap cap within its
already preclaimed role slice. Strict admission binds the session/sequence and
adopts that initial spend exactly once before other source I/O; it never creates
a new allowance. Before context S/D is available, the coordinator's original
absolute deadline still supervises delivery and the child process.

The original absolute CLOCK_MONOTONIC S/D is authoritative at admission and
through debit, blocking reads, capture completion and publication. Wall-clock
labels and a new relative duration cannot renew D. Temporary in-flight stream
claims may wait under that same D; unread claims are released, but actually
spent bytes are never refunded or recreated. Real overflow remains fatal.

All actors use disjoint preclaimed slices of the same existing envelopes:
outer 16 native calls/1 MiB, PIDs 180 calls/2 MiB, HealthRun 400 calls/4 MiB,
and cleanup 100 calls/2 MiB. PIDs producer cleanup is 96 calls/2015159 bytes;
root recovery is the same once-only original four-call/81993-byte slice, not
an additional pool. The 120-second startup, 180-second PIDs phase and
46-second cleanup reserve remain unchanged. Final slice allocations require
measured complete-path fit, including the real immutable source-record reads,
all context and transport copies, streams, framing and lookahead. An injected
account loader or a passing isolated helper is not whole-path fit evidence.

The former outer split of 400000 root / 200000 caller / 448576 emitter bytes
cannot authorize the real caller's source prepayment; an explicit negative
regression preserves that refusal. A measured, experimental static candidate
uses the same 1048576-byte total, with no automatic redistribution or fallback:

| Role | Candidate bytes | Authored measured maximum | Remaining bytes |
| --- | ---: | ---: | ---: |
| root_lane | 288000 | 264712 | 23288 |
| caller_lane | 290000 | 267713 | 22287 |
| emitter | 470576 | 447701 | 22875 |

These maxima include the charged numeric observer output. Four authored cases
exercise the unpatched candidate in both parent and independent consumer
processes, with the real source-record loaders, framing, guards and proof
readers. A six-phase synthetic shell driver is not the complete 28-test native
workload. Native-shaped command responses and the producer are authored;
executable/configuration metadata rechecks are no-ops and the held OCI UID is
projected as root. Thus metadata I/O and genuine native payload/size/timing
variability remain unqualified; the table's margins are not native headroom
guarantees. All native-call/I/O caps, other slices, deadlines, claims and original
health/port byte-reread predicates remain unchanged. Do not replace those reads
with cached first observations merely to make a budget fit.

Ordinary failure closes the root channel for exact-owned recovery, releases
phase proxies, and permits shell EXIT handling under the original deadline.
Independent exact ID/name absence gates removal of the known owned sidecar,
network and volume; ACK is neither absence nor presence. Lost ACK retains a
failed result even if later absence permits cleanup. Whole-group termination
and descriptor finalization remain bounded. Expired authority, SIGKILL,
machine death or an unreaped process can prevent complete cleanup and must be
reported, never converted into successful absence.

## Verification, consumers and non-claims

This is validation infrastructure, not product deployment behavior. Public
capability/catalogue selection and all inert output remain unchanged. Rootless
systemd/delegation qualification is independent from original-root custody.
Fresh exact-final-candidate complete and four-lane 28-test native gates,
independent review, six authored-fixture consumers, all six application suites
and package/published-dependency checks remain mandatory. Host capture remains
deferred. No release, image publication or deployment authority is granted.

Local, main, trusted dispatch and release consume the same canonical harness;
PR offline success is not native qualification. Other Lens products and the
website do not consume this private protocol; BoxFerry keeps its own downstream
consumer and application gates. No Lens product gains a BoxFerry dependency.
The dev-only safe rustix clock uses the Cargo-owned exact declaration and real
lockfile checksums. Existing native-image/Action extraction ownership remains
unique and must be verified in the final diff. The fixed outer-runtime
qualification profile and its source records are reviewed evidence constraints,
not software-installation pins or permission to auto-admit a new runtime. They
remain outside automatic updates; changing an actual install/image/toolchain pin
still requires same-change extraction and native requalification. Historical
evidence is never rewritten by Renovate.
