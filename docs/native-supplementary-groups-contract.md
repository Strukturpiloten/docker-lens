# Supplementary groups: finite nonroot DAC source proof

`supplementary-groups-v1` is an integrated source-only lifecycle child for
DockerLens #39/#31. The recovered canonical source registers it as mandatory canonical invocation 25, followed by its strict private
reader even without public manifest emission. Only complete validation permits
the closed unadmitted observation;
SupplementaryGroups remains outside compiled catalogue selection. This wiring
adds no product API, dependency, image or operational pin. This source and
synthetic controls are not genuine native qualification. Host capture remains
deferred.

## Independent controls and actual worker

Six containers borrow only the existing pinned BusyBox fixture. Ordered omitted,
one-group `[23456]` and pair `[23456,34567]` cases each have independently authored
CLI and rendered roles. All explicitly configure numeric user `12345:3456`.
CLI uses repeated numeric `--group-add`; independently authored literal requests
omit GroupAdd for the omitted case or contain the exact ordered string array.
The same immutable worker script runs in every role/case; it does not know the
expected group list or permission outcome. Literal equality precedes submission.

An explicitly root `docker exec --user 0:0` creates only internal `/dl-sg` files
in the exact owned container, never a host mount. The parent directory is root
owned 0755. Two files begin with different fixed baseline contents and have
owner 0, groups 23456/34567 and mode 0660. Root checks the actual metadata before
publishing a ready marker. Failed ownership/mode setup refuses the proof; no
rootless GID mapping or privileged chown behavior is inferred from configuration.

The nonroot long-lived **PID1 worker** independently reads `/proc/1/status`
before and after its actual writes. Real/effective/saved/filesystem UID must all
be 12345; GID must all be 3456; effective capabilities must be zero. Kernel
supplementary GIDs are recorded truthfully. Removing primary 3456, if present,
must leave exactly the finite expected groups. Primary GID presence in the
kernel supplementary list is neither required nor silently erased: its actual
presence is retained separately. Extra, duplicate, unsorted, unmapped or incorrect
groups refuse proof. Omission is not an authored request to clear groups.

The worker first verifies that printf is a shell builtin. It uses builtin
redirects in brace groups, without a
permission-testing subshell or root exec. Each file write records success or the
actual C-locale Permission denied failure and its nonzero exit. It then publishes
its private report atomically and remains alive. Root exec only waits for/readbacks
the report, independently rereads PID1 kernel facts and verifies unchanged file
ownership/modes and exact contents. Zero CapEff alone is insufficient: UID/GID,
membership, actual writer, file metadata and content transitions must all agree.

| Authored GroupAdd | File group 23456 | File group 34567 |
| --- | --- | --- |
| Omitted | Native denial; original bytes unchanged | Native denial; original bytes unchanged |
| `[23456]` | Actual worker canary replaces baseline | Native denial; original bytes unchanged |
| `[23456,34567]` | Actual worker canary replaces baseline | Actual worker canary replaces baseline |

Generic nonzero exits, root-written canaries, EROFS/ENOSPC, wrong/partial canaries,
changed denied files, dead/restarted workers or effective capabilities cannot pass.
Every native fixture has exact canonical ID/name/owner/image bindings, running
state without OOM/restarts and no authored mounts. Native GroupAdd missing, null
and empty states remain distinct on omission; explicit cases require the exact
native string lists. This proves only these numeric nonroot/DAC cases, not named
groups, arbitrary numeric IDs, host mappings, image account resolution or general
application permission behavior. Each of four exact native lanes must prove its
own representability and effects; missing evidence is never unsupported evidence.

## Actual acquisition and budget boundaries

Existing product intent/rendering/planning already supports a separately gated
SupplementaryGroups list, and the decoder exposes effective
`runtime.supplementary_groups`. One actual bounded Unix-socket acquisition selects
all six canonical IDs after effects. Exactly six selected roots/decoded IDs must
agree with the ledger; observed User must be present/effective `12345:3456` and
decoded GroupAdd availability/bytes must match each direct native observation.
No extra per-container acquisitions or fabricated positive profile is used.

Charge 16 request units and 512 KiB response-body allowance in the original
HealthRun counters **before** I/O. Bounds: six selected resources, eight
expansions, 128 KiB per response body, 512 KiB total bodies, and at most the
minimum of ten seconds and original time remaining minus 46 seconds. Actual
request APIs remain Debian 1.41/upstream 1.49, distinct from rendering/CLI
1.41/1.56. Rootless must be positively decoded; rootful can retain decoder Unknown
with independently bound rootful context, never promoted missing-field evidence.

The body counter is not a wire-byte total. Existing response headers are bounded
to 16 KiB, chunk-size lines to 64 bytes, chunk CRLF to two bytes and final trailer
line to 16 KiB, under the original elapsed deadline. These separate bounds are
recorded; actual wire bytes are unmeasured. The inherited initial context capture
retains its separate 16-request/2-MiB-body/15-second bound. Neither overhead nor
that capture is falsely described as covered by captured stdout/body totals.

Keep the once-created absolute 180-second deadline, 400 shared call units/4 MiB
captured-output-plus-reserved-body accounting, 100-call/2-MiB cleanup reserve and
46-second ordinary-work cutoff. Eight ordinary captures per fixture plus context,
image/outer reads and the batch allowance yield 74 upstream/75 Debian Podman ordinary
units (76/77 on Docker). Six-slot exact-owned cleanup uses 54 captures, including two full ID/name
absence rounds: at most 552960 bytes under existing cleanup stream envelopes.
Actual ordinary bytes must fit 2 MiB; positive cleanup must finish within 46
seconds and total execution within 180 seconds. Final image/outer snapshots
remain ordinary work, not renewed cleanup reads. These static counts are not
evidence that real lanes complete within time or resource budgets.

## Private protocol and integrated source wiring

Only verified effects, actual acquisition, complete once-only cleanup and final
unchanged borrowed-image/outer snapshots can publish the fixed owner-private
direct child `supplementary-groups-v1.json`. The stable no-follow/single-link 0600
reader requires the independently supplied canonical 0700 capture directory,
closed typed schemas, duplicate-key/range checks, ordered six roles, finite group
representations, complete DAC matrix and exact accounting. Empty capability
admission and false catalogue admission are mandatory. IDs/native reports/error
bytes stay private; public markers are fixed `supplementary_groups_*` labels.

All context facts come independently from the trusted harness: capture directory,
candidate SHA, run token, lane, Engine release, rendering API, daemon mode,
Debian package (empty upstream), fixture image, outer image, outer ID and daemon
UID. Those are the reader's twelve CLI arguments. Success prints no payload.
Parent registration, candidate/proof-path binding and the dedicated bound
lifecycle outer-owner scope are integrated under this contract. The strict reader
follows invocation 25 before kernel-settings invocation 26 and before optional
public emission, using the existing once-created deadline. The nineteen-argument
emitter independently requires the same complete private proof and closed return
before projecting the fixed numeric-nonroot scope and DAC outcome; it exposes no
private group values, IDs or receipts and grants no reviewed catalogue admission.
Existing shared cleanup handles uncertainty once and requests authenticated outer
teardown; handoff is not completed teardown. No unsafe Drop retry or derived-image
owner is introduced.

Current official Docker CLI documentation was queried through Context7
`/docker/cli` on 2026-10-18 for numeric supplementary `--group-add` and explicit
`--user uid:gid`: [docker run](https://docs.docker.com/reference/cli/docker/container/run/).
Those flags document configured intent, not kernel mapping or DAC proof. Native
oracle command/version remains the canonical native harness with Debian docker.io
20.10.5+dfsg1-1+deb11u2 and upstream Engine 29.8.1. Docker CLI repository source
is Apache-2.0; no oracle source/documentation implementation was copied or
mechanically translated, and no binaries/private proof payloads are redistributed.
Existing pins/provenance remain authoritative; no Renovate extraction change.

Fresh final-edit full offline gates, independent final-diff review and genuine
exact-final-candidate 26-invocation four-lane native qualification with independent
evidence review remain required. Historical campaigns and failures stay immutable;
they do not qualify later changed candidate bytes. Source integration grants no
reviewed catalogue admission or native compatibility and establishes no BoxFerry
application, full migration, release, publication or deployment acceptance.

## Selected-backend recovery accounting

The independently selected backend is supplied by canonical `NATIVE_OUTER_ENGINE`,
separately from the proof and its unchanged context. Only exact `podman` and
`docker` are accepted. Missing, unknown, case-modified or malformed selectors
fail closed; there is no Podman fallback. Pure readers require an explicit
`outer_backend` keyword; their twelve-argument CLI and the nineteen-argument
emitter validate that separate canonical environment fact.

Podman ordinary totals are exactly 75 Debian / 74 upstream; Docker totals are
exactly 77 Debian / 76 upstream. Each existing Docker outer snapshot charges
one additional call and 65,536 bytes before I/O. The two snapshots therefore
contribute two calls and 131,072 bytes in the final ledger, without new or
duplicate charges. Ordinary-byte floors are 524,289 Podman and 655,361 Docker;
the 2,097,152-byte ceiling is unchanged.

At the batch-acquisition preflight the initial snapshot charge is already
spent. Reserve only the pending final snapshot's extra one call / 65,536 bytes
for Docker, alongside two existing ordinary envelopes of 73,742 bytes.
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
