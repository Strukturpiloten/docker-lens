# Test-only outer runtime

`DOCKERLENS_OUTER_ENGINE=podman|docker` selects one backend before native work.
Local execution defaults to rootful Podman. Empty/unknown values, remote selectors,
wrong daemon identity and unavailable selected tools refuse; no probe-based or
failure-driven fallback exists. Hosted native jobs explicitly select Docker.
The same four digest-pinned **inner** Engines, BusyBox pin, nineteen mandatory
exact tests, source receipts and admission rules remain unchanged. Synthetic
controls and definitions do not qualify a native lane.

## Isolation and rootful identity

DockerLens and BoxFerry retain the shared rootful host outer store used by their
existing Podman harnesses. Only the named inner daemon container, sidecar, bridge,
data volume and inner socket belong to an invocation. The host Docker daemon is
never the test subject and its socket is never mounted into a guest. The containers
product's stronger private outer store/12 GiB contract needs its own Python lifecycle
adapter; this seam does not replace it.

Docker requires explicitly admitted GitHub-hosted Linux Ubuntu 24.04 on trusted
`main`. This guard prevents accidents, not actor impersonation: the coordinator
still owns exact head, actor, workflow and clean-checkout admission. The client
uses a new private empty configuration directory, scrubbed context/TLS/API
selectors and only `unix:///var/run/docker.sock`. No global Docker configuration,
package, daemon, bridge policy or service unit changes. No installation, restart,
ambient discovery, remote/Desktop endpoint or rootless outer daemon is substituted.

A bounded read-only `systemctl show docker.service` identifies active/running
MainPID. Necessary `/proc` metadata binds its root UID, root-owned real executable,
start identity and local filesystem root. A bounded `/proc/<MainPID>/net/unix`
read must have exactly one listening `/run/docker.sock` or `/var/run/docker.sock`
entry; the daemon must hold `socket:[kernel inode]`. Filesystem socket device/inode
is separately bracketed through both path aliases and the daemon's root view.
Kernel and filesystem socket inodes are not equated. SO_PEERCRED must identify this
daemon or verified root systemd PID1, supporting ordinary `dockerd -H fd://`
activation. A root socket owner or absent rootless marker alone is insufficient.
Info independently checks Linux, non-Desktop/rootless/userns mode and DockerRootDir.
No process environments, credentials or token files are read.

Fresh private `outer-runtime.json` records actual CLI/server/runner image versions
and local daemon/executable metadata. It is unqualified audit data, never accepted
to skip live setup or establish inner compatibility. Only closed version/setup
summaries leave the private directory. Official Docker references:
[contexts](https://docs.docker.com/engine/manage-resources/contexts/) and
[dockerd](https://docs.docker.com/reference/cli/dockerd/).

## Closed preflight diagnostics

Preflight failures emit only fixed diagnostic labels on stderr. Python's
`outer runtime observation unavailable` marker appends a closed mode (`peer`,
`info`, `receipt`), group and category (`refused` or `io`). The group distinguishes
socket type/ownership, connect/peer credentials, service state, systemd peer,
process identity/UID/executable/root/stability, aliases, listener/FD ownership,
info validation and receipt publication; its allowlist is `GROUPS` in
`native-outer-observation.py`. Non-preflight helper failures retain the original
generic marker. No raw exceptions, paths, UIDs, PIDs, socket identities,
environment values or protected data are diagnostic text.

The fixed `DOCKERLENS_NATIVE_OUTER_PREFLIGHT` marker separately classifies the
service query, peer observation, info command versus validation, versions,
runner-image check, receipt and store path. Categories distinguish refusal,
command failure, timeout, kill and cancellation without printing native status
details. These labels do not change predicates, helper arguments/stdout, failure
status, original privilege/capture/deadline owners, cleanup or admission. They add
no probes, retries, endpoint fallback or renewable budgets. Existing caller-or-root
private-configuration custody does not trust ambient `SUDO_UID` or equate the
held directory owner with the observer's effective UID.

Diagnostic observations are not native qualification. A prior generic failure
cannot establish which guard rejected its host, and a new passing preflight
cannot replace complete exact-candidate validation or the four native lanes.
Changed helper bytes require fresh reviewed source binding and producer evidence;
never refresh only a digest to qualify an old receipt.

## Canonical source seam and helper closure

Source `scripts/native-outer-runtime.sh` only from the exact reviewed checkout
after verifying its complete helper closure. Sourcing performs no probes or
side effects. Transitive helpers are `native-outer-observation.py` and existing
`native-presence.py`; CI's verification entry is `native-outer-setup.sh`.
External timeout owners and all thirteen Rust native command consumers use the
fixed `native-outer-command.sh` bridge. Rust's literal argv builder is cfg(test)
only (`src/native_outer_test_command.rs`), including the selection integration
test. The coordinator explicitly exports its selected engine and private run
directory; the historical `NATIVE_PODMAN_USE_SUDO` variable selects privilege only.
It no longer selects an executable. Local default remains Podman.
No product dependency on BoxFerry or Rust API change is introduced.

The separate stdlib-only [Unix-HTTP transport](native-unix-http.md),
`native-unix-http.py`, is also supplied for BoxFerry's reviewed test closure.
It is not a transitive dependency of this Bash seam. Existing DockerLens harness
and Rust HTTP consumers are not migrated; no broker or native test is transplanted.

The test-only Bash functions select/preflight the backend, bound commands,
normalize observations, check exact identity, classify presence and remove held
IDs. `native_outer_create_daemon(map_name)` creates the **inner** daemon container
and returns its creation CID. Its caller-held map contains name, run, owner_key,
network, volume, socket_dir, guest_dir, lane, image and log_path. Maps and receipts
are not serialized authority. Callers retain their aggregate/watchdog/cleanup
owners, actual resource bindings and original deadlines. Observe preserves native
state/configuration/mount fields while normalizing backend identity keys.

The low-level create function must run beneath the original fixed bridge's
120-second owner, which includes the one `run` and CID-file validation (no split
create/start or appended read timer). A fresh `RUN/outer-create.cid` is opened
no-follow and checked for exact private parent, regular type, owner, link count,
mode, stable identity/size and exactly 64 lowercase hex bytes with optional LF.
A valid CID is emitted even when run fails, while preserving its original status
(including timeout/cancellation). Missing/malformed/late CID evidence stays
unknown; success without valid CID refuses. A preexisting file is never reused.
The CID file is not authority: the caller must independently bind actual ID,
name, image and run-owner evidence before cleanup. Replacement/uncertain resources
and private evidence are retained, never pruned or recovered by discovery.

Docker has no `exists` emulation through inspect errors. Its broad name/ID list
filter is followed by independent exact formatter equality. Presence is 0,
absence 1, unknown 2; only completed closed inventory succeeds. Duplicate matches,
unexpected rows, any stderr, failure, cancellation, overflow or uncertain teardown
are unknown. The same canonical child owner retains separate stderr in this mode,
with the existing combined 16 KiB limit and teardown. The old Podman exists and
inner empty-success contracts are unchanged.

Podman retains image-volume suppression and scoped `:U`/Debian-rootless `suid,dev`.
Docker validates and overrides the image's sole declared data volume, prepares
only the independently creation-bound empty local named volume, and rechecks
the fixed rootless image account's 1000:1000 ownership. There is no recursive chown.
Exact mount readback binds name, local driver, source, destination and socket bind;
extra anonymous volumes or host-socket mounts fail. The mandatory effective Debian
rootless suid/dev check remains. Docker uses immediate `rm --force` by held ID;
Podman keeps `--force --time 0`. Both require exact owner/name/ID and absence checks.

Docker uses bounded json-file logging. The optional k8s-file descriptor collector
is explicitly unavailable, not replaced by a follower or misleading complete claim.
All mandatory native assertions still run. Original 30-minute/4 GiB storage,
8 GiB initial/2 GiB minimum free space, five-second sampler, 180-second pulls,
120-second launch, sidecar limits and eight-second cleanup plus two-second kill
fallback remain. Unknown cleanup retains private evidence. No prune or unrelated
resource/image deletion is introduced.

## Fixed external command bridge

Invoke `bash scripts/native-outer-command.sh --engine ENGINE --directory RUN OP ...`
under the caller's original privilege-aware timeout/capture. Only initial
`preflight` selects/creates the private client configuration and verifies the
daemon, returning the store root. Every other operation attaches without mkdir,
probes, preflight, privilege escalation or deadline renewal. Attach requires a
real mode-0700 run directory and, for Docker, an empty real mode-0700 client
directory owned by the run owner or root. It never accepts an audit receipt as
authority. Cancellation does not create or replace configuration.

Rust propagates only the explicit non-secret policy-context allowlist through
the existing sudo/timeout owner as literal `env` assignments, never sudo -E,
shell-evaluated prefixes or executable discovery. Canonical policy still rejects
ambient remote selectors; Docker still has its fixed endpoint/private config.

| Operation | Arguments after operation |
| --- | --- |
| `preflight` | none; initial setup only, stdout store root |
| `check-context` | none; attach-only validation for final/failed cleanup |
| `exec` | optional `--user UID`, caller-held target, exact guest argv |
| `snapshot` | held container ID; outer-proof JSON only |
| `inspect` | `--format` plus one inventoried outer template and held target |
| `observe` / `presence` | kind, held identity |
| `binding` | kind, ID, name, owner key, run |
| `daemon-binding` | ID, name, owner key, run, exact image pin; actual image evidence |
| `remove` | held container ID, name, owner key, run |
| `create-daemon` | name, run, owner, network, volume, socket, guest, lane, image, log |
| `prepare-data` | image, mode, volume, data path, store root |
| `check-mounts` | ID, volume, mode, socket, guest, store root |
| `pull` / `image-info` | exact tagged digest pin; info returns Id/Os/Architecture |
| `image-save` | exact pin, RUN/busybox.tar |
| `copy-into` | ID, RUN/busybox.tar, /tmp/bf-core-busybox.tar |
| `logs` | held ID; fixed tail 80 |
| `volume-create` / `volume-remove` / `volume-path` | name, owner key, run |

Only outer `inspect --format '{{json .}}'` uses snapshot normalization. Docker's
actual container image ID must match the independently inspected image ID, and
the exact declared manifest pin must match that image's repository digest before
the adapter supplies the Podman-compatible ImageDigest and slash-free outer name.
Other native fields remain observed, not synthesized. Docker creation explicitly
sets period 100000/quota 200000 (two CPUs), preserving the original independent
quota assertions rather than rewriting NanoCpus. Each Docker snapshot charges one
extra command and 64 KiB image-observation reserve to the existing Rust owner;
original command/byte/deadline/cleanup limits are unchanged. Raw guest exec and
inner Engine oracle results are never normalized. Existing name-based sidecar
topology reads and their independent ownership assertions remain unchanged.

## Transitional reviewed dispatcher policy

The installed trusted-main `native-validation.yml` predates the environment setting.
Only its exact native-conformance job, trusted-main workflow_dispatch/ref/repository
and full hosted guard may explicitly choose Docker when the variable is **unset**.
The candidate SHA must match the clean checkout before native work. Empty/invalid/
explicit values are never rescued; other contexts retain the ordinary default.
A fixed legacy-dispatch marker and real Docker prerequisite receipt identify this
path. It does not relax actor/head admission or count older Podman evidence as
Docker qualification. New workflow definitions explicitly set Docker and invoke
the same setup verification. Fresh final-candidate complete and four-lane native
gates still block ready/merge/release claims.
