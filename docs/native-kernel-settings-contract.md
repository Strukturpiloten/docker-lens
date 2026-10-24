# Diagonal no-new-privileges and IPv4 forwarding source proof

`kernel-settings-v1` is recovered mandatory invocation 26. It retains
closed unadmitted source observations and no selected catalogue admission. The kernel-local
cleanup repair changes no shared transport/helper, private proof protocol,
registration, unadmitted projection, catalogue, product API, workflow, operational pin,
dependency or ADR. No native resources are launched by its pure mocked-transport
or syntax controls. Fresh exact-candidate four-lane qualification and independent
review remain required. Host capture stays deferred.

## Finite configured and actual boundaries

Six owned containers borrow only the unchanged pinned BusyBox image. Three
ordered diagonal cases have independently authored CLI/rendered pairs:

| Case | Authored no-new-privileges | Authored net.ipv4.ip_forward |
| --- | --- | --- |
| Omitted | No SecurityOpt member | No Sysctls member |
| false_zero | Explicit false | Explicit string `0` |
| true_one | Explicit true | Explicit string `1` |

Only these diagonal combinations are tested, not Cartesian combinations or
general security effects. Existing typed `SecurityOption::NoNewPrivileges` and
the existing finite sysctl validation/rendering are used with crate-private
test-local capabilities. Independent CLI uses explicit
`--security-opt no-new-privileges:false/true` and
`--sysctl net.ipv4.ip_forward=0/1`. The complete independent literal request
contains matching SecurityOpt strings and Sysctls map, or omits both fields.
Literal equality precedes submission. No CLI output authors renderer expectations.

Direct native configuration checks exact ID/name/run/image, command and argv,
live state without OOM/restarts, no authored mounts and default/bridge networking.
Missing, null and empty omitted native options/maps remain distinct through
acquisition/decoding. Explicit values require the complete exact native fields.
Omitted controls retain their actual observed NNP and forwarding bits. They do
not promise universal daemon/kernel defaults or authored clearing semantics.

Explicit NNP false requires actual kernel zero. A host/daemon-inherited one
that cannot be cleared **fails the entire proof**. It cannot count as false,
support, a legacy negative, an unsupported disposition or a successful fallback.
Explicit true must show one; forwarding must show exactly zero/one as authored.
No host policy change, SYS_ADMIN escalation, capability addition/removal,
setpriv/prctl workaround, sysctl write from a test process or namespace entry is
used to obtain the expected result. Only the owned container creation asks the
Engine to configure its private namespace.

## Actual PID1 and genuine exec inheritance

The same long-lived PID1 shell runs in all cases and independently reads its
own `/proc/1/status` NoNewPrivs, its namespaced IPv4 forwarding file and network/
PID namespace identities before and after a child launch. It forks a background
subshell that explicitly execs `/bin/sh` with a separate child program and unique
fixture token. PID1 retains `$!`, verifies the child and later waits for it.
Neither parent nor child is a final-command optimization or an ambiguous exec
observer from the daemon. The child remains alive and independently reports its
actual PID/PPID, NoNewPrivs, forwarding and namespace identities.

PID1 independently checks child executable inode against `/bin/sh`, exact
NUL-delimited argv/token and `/proc/<child>/status` PID/PPID/NoNewPrivs. A separate
root exec corroborates the same live parent/child facts, executable/argv and
namespaces; it is never the only kernel-state oracle. Both argv checks stream the
expected NUL-terminated arguments directly into a binary `cmp` against procfs;
no NUL is stored in a shell variable or normalized to a newline. This preserves
argument boundaries even when the child program contains newlines. Pure controls
demonstrate the old newline-normalization collision and reject boundary drift.
Parent is PID1/PPID0,
child is distinct PID>1/PPID1. Actual NoNewPrivs must agree before/after and
persist across that genuine exec. All forwarding reads and all per-kind namespace
readbacks must agree. Dead/stale/unbound children, wrong executable/argv, differing
bits or daemon-exec-only observations refuse proof.

Six simultaneously owned container network namespaces and PID namespaces must
be unique per kind, and differ from independently read outer harness namespace
identities. Cross-kind numeric identifiers are not mixed into one identity set.
Outer namespace identities are rechecked unchanged after cleanup, alongside
borrowed-image and outer-context snapshots. No outside namespace is mutated.
This proves those finite bits and inheritance, not setuid prevention, arbitrary
application behavior, general security isolation or unrelated sysctls.

## Acquisition, budgets and cleanup

One real Unix-socket acquisition selects all six exact canonical IDs after
effects. The product decoder must retain matching effective SecurityOpt/Sysctls
availability and exact configured bytes, alongside exact request-bound IDs,
Engine/API/context and capture observation binding. Existing public observation
types suffice; no caller-authored positive profile or product API extension.

Charge 16 request units/512 KiB response-body allowance before I/O in the
original HealthRun counters. Limits remain six selected resources, eight
expansions, 128 KiB per response body, 512 KiB total bodies and at most ten seconds
within original remaining time minus 46 seconds. Acquisition APIs are 1.41 on
Debian/1.49 upstream, distinct from rendering/fixture CLI 1.41/1.56. Rootless
must be positively decoded; rootful Unknown is retained separately with the
independently bound rootful context, never promoted from missing evidence.

This is body-only accounting, not measured socket wire totals. Existing separate
transport bounds remain 16 KiB response headers, 64-byte chunk lines, two-byte
chunk payload CRLF and 16 KiB final trailer line, under the same elapsed bound.
Actual wire bytes are explicitly unmeasured. Initial context acquisition keeps
its separate 16-request/2-MiB-body/15-second bound; no hidden per-container repeat.

Keep the once-created absolute 180-second deadline, 400-call/4-MiB captured-output
and reserved-body envelope, 100-call/2-MiB cleanup reserve, 46-second ordinary-work
cutoff and original per-command timers. Seven ordinary captures per fixture,
context, initial/final outer namespace reads, final ordinary snapshots and the
16-unit batch reservation yield 70 upstream/71 Debian Podman ordinary units (72/73 on Docker). Actual
ordinary bytes must fit 2 MiB. Six-slot cleanup still requires exactly54 captures
and at most552960 charged bytes, including two full ID/name absence rounds.
The charge now conservatively includes consumed ownership-inspect bodies as
well as actual captured projection/output bytes, as detailed below. Positive
cleanup must finish within46 seconds; total execution must finish within180
seconds. These counts do not prove actual native timing.

The inherited exact-owned borrowed-image ledger, authenticated outer cleanup
owner, one-shot cleanup and terminal handler remain authoritative. Uncertainty
preserves failure, requests the existing authenticated outer teardown where
needed and refuses publication. A handoff is not completed teardown. No derived
image, second cleanup owner or unsafe Drop retry is introduced.

### Kernel-local ownership projection and complete-body accounting

Campaign39142780962 passed the first25 invocations on each of four lanes, then
failed kernel invocation26. The wrapper preserves the first panic; independent
source diagnosis placed it in `HealthRun::capture`'s per-stream limit, not the
aggregate4MiB assertion. No earlier configured/acquisition panic was selected.
Cleanup ownership GETs previously allowed65536-byte HTTP bodies but forwarded
the whole body through8192-byte cleanup stdout. Long duplicated Cmd/Args are a
plausible source of that mismatch; actual campaign response lengths were not
measured, so this is not a proven payload-length diagnosis or native repair claim.

Only the kernel child uses `scripts/native_kernel_cleanup.py` for its two
ownership GETs per fixture. It calls the existing `native-unix-http.py`
`request()` API directly, preserving its actual `(status, complete body bytes)`
contract. Method is fixed GET, paths are bounded exact1.41/1.56 container-inspect
paths and Rust retains the original request allowlist. The existing explicit
socket,7-second HTTP timeout,65536-byte response body, request/header/framing
bounds and `run.timer(true,false)` absolute-deadline behavior remain unchanged.
There is no Docker CLI oracle substitution, alternate HTTP parser, shortened
native command, body minification workaround, retry or enlarged stream budget.

The helper validates the entire consumed native JSON, including ignored fields,
before projecting only actual status, consumed body-byte count, Id, Name,
Config.Image and Config.Labels[owner]. Duplicate keys anywhere, nonfinite
numbers, malformed UTF-8/JSON, unpaired surrogates, malformed required fields,
oversize bodies/projections and unknown statuses fail with one closed diagnostic
and no native payload. Actual200 projects the four ownership fields; actual404
requires a valid closed native error object and projects no ownership object.
Other HTTP errors, malformed transport frames, timeouts and unknown operations
remain nonpositive. Native response bodies and unused labels/argv never reach
the projected stdout.

Projection shape is not ownership authority. The unchanged `owned` predicate
must match the exact run/name/image and the already-bound canonical ID at BOTH
the name lookup and immediate ID lookup before an ID-only DELETE. Outer-ID and
cross-slot alias exclusions remain. No created ID is recovered from a name:
a six-slot local guard rejects any attempted slot with a missing or
noncanonical ID before any inner lookup or mutation. It requests the existing
authenticated outer handoff through the unchanged terminal handler, preserves
the original failure and disables incompatible Drop retry. A handoff is not
completed teardown. Shared historical cleanup is not modified.

Before each projected GET, capacity must cover the full65536-byte body plus
the existing8192 stdout/2048 stderr envelope within the original aggregate
budget. The runner precharges the full body allowance before I/O. Only a valid
complete closed helper frame can reconcile its unused reservation to the actual
consumed-body count; checked arithmetic preserves every actual captured stdout/
stderr byte. This is reconciliation of unconsumed reservation, not a reset or
reuse of actual consumed budget. On capture/framing/status/type/oversize/unknown
failure, the entire body reservation remains charged conservatively. Bodies
are counted even though they were consumed inside the helper rather than sent
through captured stdout. Header/framing wire bytes are still separately bounded
by the existing transport and are not measured by this body-only addition.

DELETE and all absence readbacks remain on the existing transport. On the
complete path there are12 projected ownership GETs,6 deletes,12 immediate
ID/name absence GETs and24 GETs across two further complete ID/name absence
rounds: still54 calls. The private proof reader is unchanged and still demands
`cleanup_calls=54`, `cleanup_bytes<=54*(8192+2048)=552960`, the original cleanup
reserve and verified terminal absence. The stricter consumed-body-plus-output
charge must ALSO fit that unchanged final limit. Passing an individual65536-byte
synthetic projection or its pre-I/O capacity check is not proof that a whole
native run fits; if the aggregate final charge or original timing fails, no
positive private proof may be published. No limits are silently raised.

Pure controls cover large complete synthetic inspect bodies,65536/65537 body
boundaries, full-body accounting, private constant errors, malformed/duplicate/
nonfinite/type/status/frame refusals, composed name/ID ownership rejection and
unknown-created-ID guard ordering. Rust guard/accounting unit controls require
later primary compilation/execution. Python callback/ownership expectations and
source controls are not claims of executing Rust cleanup, real native effects,
actual lengths or successful cleanup. The helper's transport is mocked, not an
ambient or experimental host daemon. Fresh full-candidate native execution is
required; earlier25 successes cannot qualify these changed bytes.

## Private proof, provenance and remaining work

The fixed direct child `kernel-settings-v1.json` is published only after all
effects, acquisition, verified cleanup and final snapshots. The stable held
no-follow/single-link 0600 reader requires the independently supplied canonical
0700 capture directory, closed typed schemas, duplicate-key/range checks, ordered
roles, exact context, independent namespace identities and complete accounting.
Private IDs/kernel reports/argv/readback bytes never enter public diagnostics;
only fixed `kernel_settings_*` markers are emitted. Empty capability admission
and false catalogue admission are mandatory. Missing or failed proof is not
evidence of an unsupported platform.

The strict CLI takes twelve independent harness facts: capture directory,
candidate SHA, run token, lane, Engine release, rendering API, daemon mode,
Debian package (empty upstream), fixture image, outer image, outer ID and daemon
UID. Success prints nothing. The canonical child retains its separately bound
candidate/proof path, original deadline, dedicated outer-owner scope and fixed
proof validation even without public emission under this contract. The cleanup repair
changes neither its closed unadmitted projection nor the nineteen-argument emitter ABI.

Official Docker CLI docs were queried through Context7 `/docker/cli` on
2026-10-18: `man/docker-run.1.md` documents `--security-opt`, namespaced `--sysctl`
and exclusion of network sysctls with host networking. That documentation does
not establish explicit false handling or inherited NNP clearance; real kernel
proof is required. Reference: [docker run](https://docs.docker.com/reference/cli/docker/container/run/).
Docker CLI repository source is Apache-2.0. No oracle source/documentation
implementation is copied or mechanically translated. Native oracle remains
the existing canonical harness, Debian docker.io 20.10.5+dfsg1-1+deb11u2 and
upstream Engine 29.8.1, with existing BusyBox/image provenance and pins. No
binary or private proof payload is redistributed; no Renovate extraction changes.

Rust formatting/compilation, coherent main-owned integration, complete gates,
fresh exact-candidate four-lane native evidence and independent review remain
required. No application, full migration, release, publication or deployment
acceptance follows from this source-only preparation.

## Selected-backend recovery accounting

The independently selected backend is supplied by canonical `NATIVE_OUTER_ENGINE`,
separately from the proof and its unchanged context. Only exact `podman` and
`docker` are accepted. Missing, unknown, case-modified or malformed selectors
fail closed; there is no Podman fallback. Pure readers require an explicit
`outer_backend` keyword; their twelve-argument CLI and the nineteen-argument
emitter validate that separate canonical environment fact.

Podman ordinary totals are exactly 71 Debian / 70 upstream; Docker totals are
exactly 73 Debian / 72 upstream. Each existing Docker outer snapshot charges
one additional call and 65,536 bytes before I/O. The two snapshots therefore
contribute two calls and 131,072 bytes in the final ledger, without new or
duplicate charges. Ordinary-byte floors are 524,289 Podman and 655,361 Docker;
the 2,097,152-byte ceiling is unchanged.

At the batch-acquisition preflight the initial snapshot charge is already
spent. Reserve only the pending final snapshot's extra one call / 65,536 bytes
for Docker, alongside three existing ordinary envelopes of 73,742 bytes.
All additions are checked before I/O; neither the initial extra charge nor the
cleanup reserve is borrowed or counted twice. Existing proof/context schemas,
deadlines, body/stream/proof caps, once-only cleanup and protected-value
boundaries remain unchanged.

This recovered source extends the current mandatory sequence to 26 calls in
five owner scopes: the original five children, hostname alone, then one scope
per new family. Command-clear remains outside every owner scope. Mandatory
strict readers run immediately after each new child, even without emission,
and before the AppArmor non-acceptance barrier. Fresh exact-final-candidate
26-invocation four-lane qualification and independent review remain required.
There is no reviewed catalogue admission or native compatibility claim.
