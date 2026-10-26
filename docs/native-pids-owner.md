# Original-owner PIDs27 experiment

The Linux-only test module `src/native_pids_tests.rs` supplies canonical native
invocation 27, followed immediately by the independent `native_pids_proof.py`
reader. This is test-only source infrastructure. It does not admit PidsLimit,
establish arbitrary destination delegation, execute generated product output,
or qualify an unrun lane. Prepared nofile 28 remains outside this change.

[ADR 0041](decisions/0041-original-owner-pids-experiment.md) adopts the integration
seams in [ADR 0040](decisions/0040-pids-runtime-source-session.md). Linux validation
does not add macOS native testing or Windows support. The public library keeps
its unsafe-code prohibition and has no new executor or public transport API.

## Custody and the original budget

The original `HealthRun` retains its immutable 180-second terminal deadline,
400-call/4-MiB parent capture ceiling and 100-call/2-MiB cleanup reserve. Ordinary
work stops before its original 46-second cleanup reserve. Root and controller
protocols derive a single monotonic deadline from that owner; neither creates a
new workload window. Destructors retain this deadline and never authorize a new
runtime or a guessed process identifier.

Before root acquisition, the actual selected outer runtime is inspected through
the original actor's canonical bridge. Its exact CID/labels, running state,
restart count, runtime StartedAt and private cgroup-namespace configuration are
retained. Actual host `/proc/PID/stat` start ticks are measured separately.
The second observation is a second actual inspection after root acquisition,
before confirmation; it is not a clone reported as a measurement. A third actual
inspection follows inner cleanup. All three must agree.

The privileged source receives one caller-private capture-directory descriptor
over an exclusively owned socketpair. SCM_RIGHTS is accepted only for that
bootstrap. Every inbound Rust read, including EOF, uses safe `rustix::recvmsg`
with no ancillary capacity and rejects truncation or other unexpected flags.
The fixed source request vocabulary cannot select a command, PID list, kernel
path or source-provider implementation. Runtime reverse reservations debit the
original parent's call/body budget before acknowledgment and before HTTP I/O.

The root source and external source reads share fixed limits of 32 MiB and
65,536 physical operations. External file/copy/proc/nonce costs are preflighted
before reads; root binding reserves those costs from the same ceiling. This
reservation is accounting, not authentication or a claim the root performed
the caller's I/O. Root output plus stderr stays within 64 KiB, canonical owner
input within 8 KiB, and frames within 16 KiB. Final source totals, descriptor
reservations and actual received output bytes are checked before acceptance.

The build receipt has a separate bounded prebuild deadline before invocation 27.
It never counts as the live source experiment or renews its deadline. Existing
Cargo owns the exact dev-only `rustix` and `sha2` declarations and Cargo.lock
integrity; the Cargo manager already covers Cargo.toml/Cargo.lock. No duplicate
Renovate manager, new download pin, runtime image or historical-fixture update
is needed. Maintained version policy still applies to future changes.

## One inert executable, six controlled cases

The static witness is built without execution and retains exact candidate,
compiler/toolchain, architecture, Cargo/source hashes, optimization/linker flags,
ELF and bounded installed-tool/consumed-CRT provenance. GCC's reported native
target remains raw. Only the exact same CPU's standard GNU Linux triples and
the explicit SUSE/Red Hat suffixless GNU aliases are accepted; there is no ABI
or architecture fallback. OS wrapper hashes do not attest their interpreter or
the entire implementation closure, which remains explicitly unresolved.

The same artifact implements the fixed outer-guest controller. It runs outside
the six inner enforcement leaves, accepts only Prepare/Event/Seal/Close, and
has no fork, exec, runtime API or cgroup write. It creates six private FIFO
directories for `cli16`, `cli64`, `cli_unlimited`, `rendered16`, `rendered64`,
`rendered_unlimited`. Rootful fixture data uses UID 0; rootless uses UID 1000.

The controller copies its own executable once to an owned guest path. Every
source read, destination write and readback read is precharged in fixed chunks
of at most 65,536 bytes, with two charged EOF probes. Short or interrupted
operations refuse without retries. The closed `dockerlens-pids-copy-io-v1`
receipt distinguishes requested reserved bytes from actual read/write bytes and
operations. It must match the original owner's preflight. The writable file
handle is explicitly closed before reopening the same version read-only;
otherwise Linux can reject execution with ETXTBSY. Host caller UID 1001 does not
become an invented guest daemon UID or a reason to change source ownership.

Both independently authored CLI cases and literal-checked rendered requests
create finite 16, finite 64 and unlimited leaves, with explicit `Init=false`.
Workers are single-threaded PID1, with finite 16 holding 15 children before an
actual failed fork returns Linux EAGAIN. Higher-capacity controls hold 32
children without the failed fork. All release and successfully reuse capacity.
The original owner's four measured barriers per case bind exact task/start
identities and namespace PID/TGID mappings to actual worker children.

Attribution requires the same complete controller chain and root exemption,
leaf local-enforcer increment 1 only at the actual finite 16 failed attempt,
unchanged ancestor local events, hierarchical propagation and ancestor/global
headroom. Endpoint pairs preserve dynamic ancestor/global observations rather
than claiming an atomic global freeze. Actual worker kernel identity and
RLIMIT_NPROC match the root source; finite NPROC is allowed when corroborated.
Configuration, counts or EAGAIN alone never establish causal PIDs enforcement.

An independently bounded, read-only product acquisition of all six exact IDs
must decode each effective limit. Its body and conservative transport bounds
are debited before I/O; the old uncharged general context acquisition is not
reused. Native test capability claims remain private to the renderer experiment.

## Cleanup and independent reading

After all measurements and actual root seal, inner cleanup stops only known
owned IDs, requires intended worker zero exit, removes those IDs and checks
ID/name absence in two rounds. Unknown create replies and uncertain mutations
authorize only the already-bound lane owner, never a lookup/retry mutation.
Controller Close requires original stdin EOF, verified owned FIFO/copy cleanup,
reply EOF and successful supervised exit. Root finalization likewise requires
closed held source descriptors, final acknowledgment, EOF and supervised exit.
Early setup failures retain spawned-child ownership rather than detaching it.

Case 27 retains the outer daemon for the following prepared case 28. Only the
original lane EXIT finalizer and fresh aggregate can establish eventual outer
and data-volume removal. An `outer_teardown_owner` string is descriptive context,
not removal evidence. SIGKILL or host death can prevent automatic cleanup;
uncertain cleanup cannot produce a successful PIDs proof or native admission.

The default private proof bound for other source families stays 16 KiB. Only
this explicit publisher/reader uses 128 KiB. The independent reader requires the
caller-private stable 0600 file, exact independently supplied harness context,
all six worker/control cases, actual copy receipt and complete accounting and
cleanup fields. It separately rereads the private prebuild/raw records/current
source with bounded no-follow descriptors and hashes, and independently parses
the static ELF program headers without executing anything. These post-test
reader reads are bounded validation I/O, not original root-source measurements.
Every object is closed; missing fields, duplicates, bool-as-integer values,
cross-context receipts, inconsistent counters and partial controls refuse.

The immediate reader always runs, including when optional public evidence is
disabled. The evidence emitter repeats it without changing its nineteen-argument
ABI and exposes only a closed unadmitted source outcome. Pure tests, prebuilds,
source review and a passing reader do not replace the complete repository gate,
genuine exact-candidate 27 four-lane runs, final cleanup, independent review and
eventual downstream qualification. No release or compatibility claim follows
from source integration alone.
