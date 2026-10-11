# Native configured stop-signal contract

`stop-signal-v1` is a separate DockerLens #112 test-only source proof. It neither
changes `health-metadata-v1` nor admits a sealed capability. Existing `StopSignal`
target/evidence vocabulary is reused; no health/start-interval, timeout, init or
other runtime capability is promoted. Product planning/rendering stays inert.
Historical raw/reviewed records and active catalogue selection stay exact.

## Independent effect oracle

The ordered cases are explicit symbolic `SIGTERM` and `SIGINT`, each with an
independent CLI oracle and ordinary DockerLens-planned/rendered container. All
four use the unchanged canonical pinned BusyBox. No image is built, committed,
tagged or removed. Rendered requests are compared with literal independently
authored expectations before submission. Direct Engine inspect checks exact
signal spelling, canonical ID/name/run label, pinned image reference and actual
image ID, command, inherited empty entrypoint and PID1 path.

Actual shell PID1 verifies its PID, registers TERM exit **41** and INT exit **42**
traps, then writes a fixed readiness marker. Otherwise it loops indefinitely.
A bounded independent exec reads that marker; an inspect requires a running PID
before stopping. This exec does not signal the process or substitute its own
exit status. `docker stop -t 3 ID` has no per-stop signal override, so the
container setting must select the trap. The common short option avoids `--time`,
which Docker deprecated and hid in version 28 in favor of `--timeout`. Stop stdout
must still equal the complete submitted ID and newline; warnings, shortened IDs
or other output are not accepted as identity evidence.

Stop must complete in less than five monotonic seconds. Native inspect requires
the corresponding 41/42 exit, exited/not-running state, PID zero, no restart,
paused/dead/OOM state or Engine state error. Exit 0, 137, the wrong trap, timeout
or uncertainty fails: forced SIGKILL cannot count as signal success. StartedAt
stays unchanged. Actual Engine SystemTime readings bound readiness, submission
and FinishedAt in order; finish must follow the pre-stop reading by less than
five seconds. No effect retry, fallback positive or unsupported outcome exists.

## Shared bounds and ownership

The separate ignored test nests under the health module solely to reuse its
bounded transport, actual acquisition/context checks, exact ownership cleanup
and private publication. Historical health constructor and proof defaults stay
unchanged. The canonical runner maps `native_stop_signal
live_stop_signal_matches_engine` to
`native_health_metadata_tests::stop_signal::live_stop_signal_matches_engine`
and requires exactly one ignored test inside its own original 180-second cutoff.

Shared limits stay unchanged: 400 commands/4 MiB retained streams; work stops
before 300 calls/2 MiB, reserving 100 calls/2 MiB and 45 seconds plus a one-second
command margin for cleanup. Commands last at most eight seconds plus one-second
kill grace. Actual acquisition retains 16 requests, two selected roots, eight
expansions, 256-KiB response/2-MiB total limits and at most 15 seconds clipped to
the same deadline. Neither counters nor deadlines reset. Direct Engine, CLI,
actual acquisition and single-dockerd effective UID bind Engine release, API
dimensions, Debian package and daemon mode. Immutable outer ID, owner, image
digest, bounded setup, volume/socket mounts and owned network are checked before
and after. Positive test-local capability facts are scaffolding, not admission.

Only the four owned containers enter the deletion ledger. Removal rechecks ID,
name, pinned image and owner, deletes by ID and requires two final direct name/ID
404 rounds. BusyBox is **borrowed**: its image-creation ledger stays empty and its
canonical ID, digest list and configuration must remain unchanged after cleanup.
Failure never publishes proof. Catchable failures preserve the original assertion
while attempting bounded cleanup; SIGKILL/host failure can prevent cleanup and
never constitutes evidence.

## Private protocol and public projection

Fresh mode-0600 single-link regular `stop-signal-v1.json` must be a direct child
of held mode-0700 `NATIVE_CAPTURE_DIR`. Exclusive publication follows every effect,
two absence rounds and borrowed-image/outer readback. The reader reuses the existing
held-directory/no-follow/stable-file 16-KiB boundary with attachment-proof defaults
unchanged. Duplicate/extra keys, links, wrong types, partial/swapped cases, context
drift, reused IDs, invalid times or uncertain cleanup refuse the whole manifest.
Failures reveal only closed stages and bounded source locations, never native text.
The wrapper also retains the last fixed case/role/operation marker before the
first cleanup marker, including when a shared or worker-thread panic has no
selected-test location. It never publishes panic payloads or native values.

Root keys are exactly `schema_version` (integer 1), `contract`, `context`, `shapes`
(`["StopSignal"]`), `borrowed_image`, `cases`, `cleanup`. Context is the existing
independently derived network/outer context plus observed `daemon_uid`, not this
proof read back as its own oracle. Borrowed-image fields are canonical `id`,
`identity: unchanged`, `removal: not_owned`. Cleanup requires containers absent,
integer rounds 2, integer outstanding 0 and boolean uncertain false. Ordered cases
contain exact signal/expected exit and two ordered role records. Roles retain
private ownership/image binding, configured spelling, wire/readiness completion,
native timestamps, finite timeout/monotonic duration, no signal override, exact
exit/stopped-state facts and absence. The executable strict schema is
`scripts/native_stop_signal_proof.py`. This is trusted-harness completion, not
cryptographic attestation against a privileged writer.

The nineteen-argument emitter remains unchanged. After sixteen required tests,
the fixed new private file permits only `stop_signal_contract`,
`stop_signal_probes` and the complete raw StopSignal singleton. With identity-v2
and prescribed Debian IPv6 boundaries, future raw counts are Debian **30/47**
capabilities/shapes and upstream **31/49**. Current sealed counts stay **29/46**
and **30/48**. Counts and offline controls are expectations, never native proof.

Local/main/reviewed-dispatch/release share `scripts/native-conformance.sh`; no
consumer workflow or nineteen-argument caller changes. Other Lens products and
the website do not consume this private Docker protocol. BoxFerry's separate
admission/producer receipts and application gates remain; no Lens depends on it.
The same five image tag/digest pairs stay solely in the canonical harness under
the existing Renovate manager, grouping and manual approvals. Cargo/lockfile,
toolchain and Action pins/ownership are unchanged. No pin/dependency/tool or
extraction path is added, changed, moved or removed.

Current official Docker [STOPSIGNAL documentation](https://github.com/docker/docs/blob/main/_vendor/github.com/moby/buildkit/frontend/dockerfile/docs/reference.md)
and [stop semantics](https://github.com/docker/docs/blob/main/data/cli/engine/docker_container_stop.yaml),
consulted through Context7 `/docker/docs`, informed the independent oracle. No
upstream implementation was copied or translated. Existing pinned CLI/Engine
versions, image provenance and licenses remain under ADR 0004 and dependency
policy; no external source or binary is redistributed by this change.

Fresh complete gates, genuine exact-head four-lane execution and independent
authenticated evidence review must precede any separate admission change. That
change still needs fresh final-candidate and BoxFerry consumer gates. Historical
health evidence and the original #112 observation cannot substitute for this
proof. This infrastructure claims no native compatibility, release or deployment.
