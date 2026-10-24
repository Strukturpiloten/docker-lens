# Finite ShmSize source-effect contract

`shm-size-v1` is a recovered lifecycle child for DockerLens #39/#31, appended as mandatory
invocation 24 after the unchanged first 23 and command-clear validator. It has
its own one-child subshell using the existing outer cleanup owner, without
changing the original five-child block and separate hostname scope. Mandatory private CLI validation always
precedes optional public emission. Only a closed unadmitted observation is projected; neither raw capability/shape
admission nor the compiled catalogue is extended.
Source, synthetic tests and a passing offline gate do not establish native
qualification. Fresh exact-candidate four-lane execution and independent review
remain necessary. Host capture is deferred; this source uses only the existing
disposable native harness, never an ambient daemon or host setting.

## Six finite borrowed-image fixtures

Three ordered cases each have independent CLI and literal-rendered roles:
omitted ShmSize, explicit 1 MiB, and explicit 2 MiB. Each owns one distinct
run-bound container while borrowing the unchanged harness-pinned BusyBox image.
No derived image, pull/build, daemon default change, host knob or new pin is added.
CLI explicit values use byte counts without a suffix. Independent literal
requests omit `HostConfig.ShmSize` or contain exactly 1048576/2097152, respectively;
they do not author an IPC-mode field. Request equality precedes submission.

Direct native inspection binds exact name/ID/owner/image and literal process
configuration, running state, zero restart/OOM and native `IpcMode: private`.
Missing, empty, shareable or host IPC mode refuses proof; no fallback infers
support. Positive native `HostConfig.ShmSize` must equal actual statfs capacity.
Explicit values must match their authored bytes. The two omitted controls must
agree on an observed positive default large enough for the 3 MiB control; there
is no generic 64 MiB default claim.

Every live fixture independently observes `/dev/shm` as a unique rw tmpfs mount,
checks statfs unit/count/capacity and its actual IPC namespace. Six simultaneously
live IPC namespace identifiers must be distinct. All six write different fixed
canary values at the same path before any canary is removed. Each then reads
back its own value, proving retention across the other five seed writes. A
configured mode, duplicate namespace, absent/wrong canary or inspect-only size
cannot establish isolation or a filesystem effect.

After canary removal, omitted controls successfully write and compare exactly
3 MiB of zero payload. Explicit controls attempt one block beyond their limit,
require actual C-locale `No space left on device`, and require the saturation
file size to equal exactly 1 MiB/2 MiB with matching zero readback. A generic
nonzero exit, timeout, EACCES, read-only error, OOM or partial file refuses proof.
Payloads are removed, and owned running state/configuration is rechecked. This
does not prove arbitrary values, special IPC modes or application acceptance.

## Actual acquisition and exact decoder evidence

The existing product seam already carries `ContainerSettings.shm_size_bytes`,
gates `Capability::ShmSize`, renders `HostConfig.ShmSize`, and decodes effective
`RuntimeObservation.shm_size_bytes`. No product API extension is needed.

After effects, one actual explicit Unix-socket acquisition selects all six
canonical container IDs. Reserve 16 request units and 512 KiB in the original
HealthRun counters before I/O. Limits are 16 requests, six selected resources,
eight expansions, 128 KiB per body, 512 KiB total body bytes and at most
`min(10s, original remaining time minus 46s)`. There is no per-fixture reset or
six-fold 512 KiB allowance. All exchanges must succeed, exactly six selected
roots/decoded IDs must agree with the ledger, and the decoder must retain present,
effective ShmSize values matching independent statfs. Request APIs are Debian
1.41 and upstream 1.49; rendering/fixture CLI stays 1.41/1.56.
Rootless mode must be positively decoded. A rootful capture can retain decoded
Unknown when `/info` omits `Rootless`; the proof names that state separately from
an observed rootful value, retaining independently bound context/daemon UID.
It never promotes missing evidence to a decoder fact or accepts conflicting mode.

The 512 KiB allowance measures decoded response bodies, **not total wire bytes**.
The existing transport separately bounds response headers to 16 KiB, chunk-size
lines to 64 bytes, each nonempty chunk's following CRLF to two bytes and the
final trailer line to 16 KiB. Nonempty chunks each consume at least one body
byte, so framing is finite under the body/request limits and the same elapsed
deadline, but its theoretical wire overhead can exceed the captured-output
counter. Actual wire bytes are not measured. The private proof explicitly records
this body-only scope and separate framing bounds; no 4 MiB wire claim follows.

The inherited initial `HealthRun::context` acquisition remains a separate bound:
16 requests, 2 MiB bodies, at most 15 seconds within the original work cutoff.
It is not silently counted in the shared captured-command byte total and is not
repeated for these fixtures.

## Budgets, ownership and private proof

Keep 400 shared call units/4 MiB captured-output-plus-reserved-body accounting,
100 calls/2 MiB cleanup reserve, the 46-second ordinary-work cutoff, unchanged
per-command timers and one once-created 180-second invocation deadline. The
positive path accounts for 74 upstream/75 Debian Podman ordinary units (76/77 on Docker), including the
16-unit batch reservation. Actual ordinary bytes must fit 2 MiB. The inherited
six-slot cleanup uses 54 captures: five ownership/removal/readback captures plus
four captures across two complete ID/name absence rounds per slot. Its maximum
stdout/stderr allowance is 54 × 10240 = 552960 bytes, below the reserve. Counts
alone do not prove elapsed completion: positive publication also requires cleanup
within 46 seconds and total execution within 180 seconds. Final unchanged
borrowed-image/outer-context snapshots remain ordinary work, never cleanup reads.

Use the existing lifecycle ownership predicate, once-only mutation ledger,
authenticated bound outer cleanup owner and terminal handoff. No `HealthRun`
derived-image cleanup, second cleanup owner or unsafe Drop retry is introduced.
Transport/ownership/effect/cleanup uncertainty preserves failure, requests the
existing outer teardown when needed and produces no positive proof. Missing
evidence is not an unsupported-platform result.

The fixed owner-private direct child `shm-size-v1.json` is published only after
verified cleanup and final snapshots. The strict reader uses stable held
no-follow/single-link 0600 file custody within the independently supplied 0700
capture directory, closed schemas, duplicate-key/type/range checks and separately
bound candidate/run/lane/package/API/mode/daemon UID/image/outer context. It
validates ordered finite cases, exact accounting, isolation/effects and explicit
empty capability admission/false catalogue admission. IDs, native values and
payloads remain private; public diagnostics contain only fixed `shm_size_*`
markers. The closed complete observation remains unadmitted;
the private protocol and every reviewed record remain unchanged.

The reader's command-line arguments are the independently supplied capture
directory, candidate SHA, run token, lane, Engine release, rendering API, daemon
mode, Debian package (empty upstream), fixture image, outer image, outer ID and
daemon UID. Success emits no payload. The canonical harness validates this fixed child
on every native execution, including runs without public manifest output.

## Documentation provenance and maintenance

Official Docker CLI documentation was consulted through Context7 `/docker/cli`
on 2026-10-18: `man/docker-run.1.md` documents `--shm-size` and byte counts when
no suffix is supplied; `docs/reference/dockerd.md` documents configurable
`default-shm-size` and `default-ipc-mode` (`private`/`shareable`). The documented
64m default is not evidence of the selected daemon configuration. References:
[docker run](https://docs.docker.com/reference/cli/docker/container/run/),
[dockerd](https://docs.docker.com/reference/cli/dockerd/). Docker CLI repository
source is Apache-2.0; no oracle implementation or documentation text is copied
or mechanically translated. Native versions/command remain the existing exact
Debian docker.io 20.10.5+dfsg1-1+deb11u2 and upstream Engine 29.8.1 under
`./scripts/native-conformance.sh <lane>`; existing image/provenance records remain
authoritative. No binaries or private proof/log payloads are redistributed.

No dependency, operational software pin, toolchain, workflow or Renovate
extraction changes. Registration consumes the canonical existing harness; other
Lens products and BoxFerry do not depend on this private proof. Fresh complete
and genuine native qualification, review and actual downstream consumer gates
remain required; no release, application or full migration claim follows.

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
