# Explicit logging native source contract

[ADR 0050](decisions/0050-logging-native-source-proof.md) defines logging32,
registered after unchanged original29/read, memory30/read and capabilities31/read.
The canonical sequence has 32 invocations and eleven delegated cleanup scopes.
The runner binds one deadline and private capture; the immediate strict reader
is mandatory without publication, and the nineteen-argument emitter repeats
validation before output. Source controls are not native compatibility or
capability/catalogue admission.

## Six finite, independently authored controls

One HealthRun borrows the existing digest-pinned BusyBox 1.37.0. Six fresh
containers run in this exact order:

| Driver | Role | Exact requested LogConfig | Actual one-shot read |
| --- | --- | --- | --- |
| json-file | oracle | Type=json-file, Config={max-size: 1m} | Exit0, exact canary plus LF |
| json-file | rendered | Type=json-file, Config={max-size: 1m} | Exit0, exact canary plus LF |
| local | oracle | Type=local, Config={} | Exit0, exact canary plus LF |
| local | rendered | Type=local, Config={} | Exit0, exact canary plus LF |
| none | oracle | Type=none, Config={} | Exit1, exact unreadable-driver diagnostic plus LF |
| none | rendered | Type=none, Config={} | Exit1, exact unreadable-driver diagnostic plus LF |

PID1 runs `test "$$" = 1 || exit 61; printf "%s\n" "$1"` through
`sh -c`, with argv0 `dl-log` and canary
`dockerlens-log-v1:<run>:<driver>:<role>`. Its single output line is at most96
bytes. The image must have no inherited volume, entrypoint or health behavior.
Full owned inspections bind actual Cmd, Tty=false, image, owner, no inserted init,
exact configured option strings and created/exited states. Terminal PID0 is
never described as a live identity sample. Actual wait must return exactly0 LF;
nonzero exit, never-started timestamps, OOM, restart or State.Error fails.

The CLI oracle is independently authored with `--log-driver`; only json-file adds
`--log-opt max-size=1m`. The rendered path uses typed intent/planner/renderer and
compares its entire POST, path and body against an independent literal before
mutation. Start is CLI for oracle and API204 for rendered. Offline Rust controls
preserve absent LogConfig versus explicit empty Config for both rendering APIs
and modes, independent LogConfig/LogOptionMaxSize capability gates, and existing
finite option grammar. The registered Rust controls use authored offline
expectations.

## Exact read and private evidence

After wait, execute once `docker logs --tail 1 --timestamps=false <owned-ID>`
through the selected authenticated outer and pinned inner API. No retry, follow,
file read, LogPath access or daemon-default alteration is introduced. The shell
status wrapper streams combined CLI bytes directly and appends one terminal
actual-status frame. No shell variable can strip NUL bytes or trailing LF; both
parsers reject NUL. Outer capture failure cannot become accepted none refusal.

Json-file/local require the reconstructed canary plus exactly one LF and actual
status0. None requires actual status1 and exactly
`Error response from daemon: configured logging driver does not support reading`
plus one LF. Empty success/failure, permission/404/generic errors, timeout,
cancellation, different spelling, extra lines or injected status frames fail.
The canary is far below1m: this establishes explicit configured retention and one
bounded read only, not rotation, max-file enforcement, compression, durability,
restart/crash persistence, throughput, other drivers or universal logging support.

Schema1 `logging-v1.json` fits the existing16KiB default private held-descriptor
custody limit. Directory0700, regular direct-child mode0600 single-link file,
identity stability, complete bounded JSON and duplicate/unknown-member rejection
remain mandatory. Independent Python semantics reconstruct all six settings,
commands/canaries, exact success/refusal bytes and hashes, caller context,
backend, cleanup and accounting. Rebinding hashes cannot legitimize false output.
The result has only contract=logging-v1, capability_admission=[] and
catalogue_admission=false. It carries no raw/public logging projection.

The twelve-argument private reader runs immediately after the producer even
without emission. The existing nineteen-argument public emitter repeats
independently bound validation and separately enforces the exact typed three-key
result before creating output. It adds no logging public shape or field.

## Exact captured-output reservations

Let A=73742, S=9216 and K=10240 bytes; delta is0 for outer Podman or1 for outer
Docker, with E=65536*delta. These are subprocess stdout/stderr envelopes, not
measured wire traffic, storage or kernel-read counts.

| Stage | Captures | Reserved captured bytes |
| --- | --- | --- |
| Authenticated context and borrowed image | C=8+delta upstream;9+delta Debian | Actual measured B |
| Each CLI oracle slot |7 |2A+5S=193564 |
| Each rendered slot |7 |4A+3S=322616 |
| Final daemon health |1 |A |
| Final borrowed image and authenticated outer |2+delta |2A+E |
| Cleanup, including two ID/name absence rounds |54 |54K=552960 |

Each slot is exact-name freshness404, create, full bound pre-start inspection,
start, actual wait, one status-framed logs read, full terminal inspection.
A source-local invocation of the existing Unix HTTP helper reads only the exact
run-owned name via GET, no body, response cap1000, timeout at most7 seconds clipped
against the original work cutoff. It requires an exact single-message404;
unknown/duplicate keys fail. Shared authorization and full inspection envelopes
remain unchanged.

Before the first mutation require B+21A+24S+E <=2097152. Pending reservation is
1769766 Podman or1835302 Docker; B must be <=327386 or261850 respectively. Final
ordinary captures total C+45+delta:53 upstream Podman,54 Debian Podman,55 upstream
Docker,56 Debian Docker. Aggregate including cleanup is107–110.

The shared capture guard counts cumulative cleanup bytes before final ordinary
reads. A separate checked pre-cleanup guard therefore requires actual bytes
before cleanup <=1396708 Podman or1331172 Docker, reserving54K+2A+E without any
counter reset. Exceeding this bound fails even if ordinary-only arithmetic fits.
Unknown attempted creation without a verified canonical ID requires verified
outer teardown before any unsafe inner cleanup. The first observation failure
is preserved; accepted proof requires verified inner absence, unchanged borrowed
image and authenticated outer, zero outstanding liability and no uncertainty.

The original180-second absolute deadline,46-second cleanup reserve,
300 ordinary/100 cleanup/400 aggregate calls,2MiB ordinary/2MiB cleanup/4MiB
aggregate output and1800-second lane ceiling remain. All commands retain clipped
timers and no case renews time. Static feasibility does not prove actual
54-command cleanup fits46 seconds or the full32-call lane fits1800 seconds.

## Qualification, provenance and unchanged policy

Focused Python controls execute the actual reader, shell frame and
existing HTTP helper against authored fixtures. They do not execute an Engine.
The registered Rust module still requires independent review, the
complete final-source gate and fresh exact-candidate four-profile native evidence
for the full32-call sequence, including actual canary/refusal, option strings,
context bytes, time and cleanup. Existing historical evidence is not refreshed.

Current official Docker logging configuration/json-file/local/dual-logging docs
were resolved via Context7 on2026-11-01 under `/docker/docs` during contract
research. Versioned read-only Moby v20.10.5 and docker-v29.8.1 `daemon/logs.go` and
`daemon/logger/logger.go` motivate the closed none refusal; actual pinned Debian
and upstream behavior remains a required observation. Oracle source/docs are
Apache-2.0; no implementation is copied, translated, vendored or redistributed.
The implementation contract records exact source links and profile commands.

ADR0007, public LogConfig policy, all four profile pins, catalogue, software
versions, dependency manifests, lockfile and Renovate ownership/extraction remain
unchanged. No new dependency/image/tool or manager is introduced. This source
slice grants no BoxFerry/application acceptance, release or deployment authority.
