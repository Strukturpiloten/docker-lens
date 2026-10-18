# Diagonal no-new-privileges and IPv4 forwarding source proof

`kernel-settings-v1` is an unregistered source-only preparation for DockerLens
#39/#31. The primary owns later parent/runner/harness integration. No canonical
invocation, raw projection, catalogue, product API, workflow, operational pin,
dependency, ADR or existing documentation changes here. No native resources are
launched by source/reader/syntax controls. Genuine exact-candidate four-lane
qualification and independent review remain required. Host capture stays deferred.

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
16-unit batch reservation yield 70 upstream/71 Debian ordinary units. Actual
ordinary bytes must fit 2 MiB. Six-slot cleanup uses 54 captures, including two
full ID/name absence rounds, with at most 552960 bytes under unchanged stream
envelopes. Positive cleanup must finish within 46 seconds; total execution must
finish within 180 seconds. These counts do not prove actual native timing.

The inherited exact-owned borrowed-image ledger, authenticated outer cleanup
owner, one-shot cleanup and terminal handler remain authoritative. Uncertainty
preserves failure, requests the existing authenticated outer teardown where
needed and refuses publication. A handoff is not completed teardown. No derived
image, second cleanup owner or unsafe Drop retry is introduced.

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
UID. Success prints nothing. Main must later register the lifecycle child, bind
candidate/proof path and the same original deadline, provide a dedicated bounded
outer-owner scope, and validate the fixed proof even without public emission.
No raw projection or nineteen-argument emitter ABI change is implemented here.

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
