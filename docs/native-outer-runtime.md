# Test-only outer runtime

`DOCKERLENS_OUTER_ENGINE=podman|docker` selects one backend before native work.
Local execution defaults to rootful Podman. Empty/unknown values, remote selectors,
wrong daemon identity and unavailable selected tools refuse; no probe-based or
failure-driven fallback exists. Hosted native jobs explicitly select Docker.
The same four digest-pinned **inner** Engines, BusyBox pin, nineteen mandatory
exact tests, source receipts and admission rules remain unchanged. Synthetic
controls and definitions do not qualify a native lane.

## Isolation and rootful identity

Failure-only rootless diagnostics do not constitute a repair or a compatibility
claim. The existing attachment inspect retains its 4096-character total bound
and exact single-network/private-IPv4 predicates; selected daemon State fields
are projected as closed running/status/exit-class/OOM/Error-presence values.
The same Docker daemon attachment inspect additionally projects
`inspect_reported_apparmor=unconfined|docker_default|other|empty|unknown`.
Only a string exactly equal to `unconfined`, `docker-default`, or the empty
string selects the corresponding token; other strings select `other`, and
missing/non-string metadata selects `unknown`. No raw profile name leaves the
template. The fixed header and original IPv4/State response share the original
4096-character total bound and ten-second owner. Only startup failure prints the
token; malformed/missing headers and callers without held metadata use `unknown`.
This is inspect-reported metadata, not a live kernel-label observation or proof
of a denied operation. Privileged configuration and a missing explicit security
option do not establish the effective AppArmor label or the failure cause.
That same attachment query uses the canonical ten-second command owner, keeping
`sudo -n` outside GNU timeout without changing its query, client vector or budget.
On daemon attachment refusal the held sanitized State is reused for startup
diagnosis, without a second State query. Only the existing bounded log query is
added: at most 10 seconds plus the 2-second kill fallback, within the lane's
original 30-minute watchdog. The same logs query uses the canonical command
owner, keeping `sudo -n` outside the timer so it can terminate the root client.
Later startup-diagnosis callers without held State retain their two existing
queries, now both under that canonical ten-second owner: at most 24 seconds
including both kill fallbacks, not the early path's 12 seconds. No query or
retry is added. Logs are not persisted or printed.

The same log query merges Docker CLI stdout and stderr into the existing 64 KiB
tail before classification. Only anchored default shell xtrace (`+ `, `++ `,
and deeper repeated-plus prefixes) is removed. Ordinary tool/driver mentions do
not identify an error family. Explicit error observations retain closed families
in this fixed order: `rootless_launcher_unavailable`, `rootless_uidmap`,
`rootless_network`, `daemon_storage`, `daemon_permission`, `daemon_network`,
`daemon_startup`. `families` is an ordered comma-separated subset, `none`, or
`unavailable`; `category` is the sole family, `ambiguous`, `unclassified`, or
`unavailable`. These are observations, not proven causes. Generic permission or
startup wrappers do not add a second family to the same specific error line.
`preflight` separately retains an ordered subset of `xdg`, `home`, `rootlesskit`,
`state`, `uid`, `detach`, or `none`/`unavailable`, using only six verified fatal
preflight messages. Exact fixed prefixes/suffixes surround dynamic state paths
and detach values; those values neither leave the collector nor add families.
The six messages indicate startup prerequisites, not proof of the current
failure cause. Ordinary echo and filtered xtrace are not those observations.

The message contract was read only from the official Docker rootless extras
29.8.1 amd64 archive, SHA-256
`8f1ed16fc6913241e599af6234a7f30502bde6e73bebbbc7176b17802d967d49`;
the single `dockerd-rootless.sh` member hashes to
`200203633806081a401e60aefdf68a8fa73fc7dc80aa854c52a69d47710a3488`.
Inspection used `tar -xOf` stdout only, without execution or broad extraction.
The historical payload manifest declares Apache-2.0; a versioned license was
not independently verified. Neither archive nor script is redistributed here,
and this historical source reference adds no operational dependency or pin.

`rootlesskit_self_reexec=permission_denied|operation_not_permitted|ambiguous|unobserved|unavailable`
is a separate passive observation from the same bounded logs. It matches only
the complete, case-sensitive raw line
`[rootlesskit:parent] error: failed to start the child: fork/exec /proc/self/exe: permission denied`
or the same fixed line ending in `operation not permitted`. LF separates lines;
CR, spaces, controls, prefixes/suffixes, different paths/errno and default xtrace
do not match. Both exact errno observations yield `ambiguous`; no matching line
yields `unobserved`, while a failed log collector yields `unavailable`.
At each byte-cap trim the collector retains whether the preceding discarded
byte was LF. An uncertain leading fragment cannot supply this exact-line
observation, even if truncation removed its nonmatching prefix. A known LF cut
and later complete LF-delimited lines remain eligible. Only this new observation
uses the boundary fact; legacy family/preflight matching and tail bytes remain
unchanged.
Family/category/preflight matching remains independent and unchanged.
The observation identifies a reported child-launch refusal, not the particular
clone/userns/mountns/exec substep, effective label, kernel policy or cause. The
earlier generic permission projection does not establish this observation.

The same official 29.8.1 archive's `docker-rootless-extras/rootlesskit` member
has SHA-256 `9a70304fdedb9f526f24d4f82029310506c9e6fde7551ec28a069378ee22d5d6`.
Read-only `tar -xOf` stdout piped to `strings` identifies RootlessKit v3.1.0,
revision `62d2101fbbe4f79bc845a337c4e868d27ff602c9`, `vcs.modified=false`, and
Go 1.26.8; piping the same member to `sha256sum` verifies its hash. No binary
was executed. The fixed message was independently checked against that revision's
[parent.go](https://github.com/rootless-containers/rootlesskit/blob/62d2101fbbe4f79bc845a337c4e868d27ff602c9/pkg/parent/parent.go#L176)
and [main.go](https://github.com/rootless-containers/rootlesskit/blob/62d2101fbbe4f79bc845a337c4e868d27ff602c9/cmd/rootlesskit/main.go#L331),
and the compiler-matching
[Go exec wrapper](https://github.com/golang/go/blob/go1.26.8/src/os/exec_posix.go#L55).
Pinned raw HTTPS source/license reads used bounded `curl` downloads (30 seconds,
1 MiB source/128 KiB license caps), not execution. The same-revision RootlessKit
license was independently verified as Apache-2.0 and Go's as BSD-3-Clause.
Only diagnostic grammar/provenance was inspected: no upstream implementation
was copied, translated, vendored or redistributed. Archive provenance is not
fresh attestation of the failing image's bytes, or a compatibility claim.

Failed ordinary internal-proof wget commands classify their already-held bounded
stderr as connection refusal, no route, timeout, HTTP error, or unknown. The
probe, its oracle, endpoint, and six-second budget are unchanged. These
observations do not establish that the independent rootless failures share a
cause, nor settle address-pool overlap. On failed ordinary control-bridge wget,
`DOCKERLENS_NATIVE_INTERNAL_SUBNET_DIAG` and
`DOCKERLENS_NATIVE_CONTROL_SUBNET_DIAG` add only the independent
`sidecar_on_internal_subnet=true|false|unknown` and
`sidecar_on_control_subnet=true|false|unknown` observations. Each compares the
already-held sidecar IPv4 against `IPAM.Config[].Subnet` from its own
already-inspected rendered network, retaining only that closed result at the
original read. Neither adds an inspect or reuses the other network snapshot.
Both are printed only on that same external ordinary-control wget failure,
not on successful wget or the expected internal-network rejection. Missing,
malformed, noncanonical-network CIDRs or IPv6-only metadata yield `unknown`;
IPv4 `/0`, `/32`, and subnet boundaries are handled explicitly. `false` does
not rule out other held networks, the default bridge, routes or firewall issues,
and never asserts whole outer/inner CIDR disjointness or a timeout cause.
The exact rendered requests, CLI oracles and default IPAM remain unchanged;
these observations do not authorize a network-pool or fixture-routing repair.
Only at that failed ordinary-control wget boundary, with its explicit held
sidecar/API/socket/client context, one optional read may additionally inspect
the owned inner Engine's exact `/v<held-api>/networks/bridge`. It additionally
requires the held observed daemon mode to be rootless and the canonical explicit
`NATIVE_OUTER_ENGINE` selector to be exactly `docker`. Rootful Docker, local
Podman, missing selectors and unrelated failures add no read; neither an image
label nor an Engine version substitutes for either fact. The optional
default-bridge subcontext is absent when the observed API is missing; no API
default or new assertion is introduced, and existing internal/control subnet
observations are retained independently. The general
executor allowlist remains unchanged; no other name, method, path, endpoint,
listing, retry or resource is introduced. A response must identify `Name=bridge`,
`Driver=bridge` and a canonical native ID. Its complete IPAM subnet list uses the
same strict membership helper: malformed, missing, partial or IPv6-only evidence
is unknown, not a salvaged positive match. The complete JSON document rejects
duplicate decoded keys at every depth, including ignored objects and escaped-key
collisions, before membership can be reported. Serde supplies JSON parsing;
its normal recursion and end-of-input checks remain enabled. The closed failure-only
`DOCKERLENS_NATIVE_DEFAULT_BRIDGE_SUBNET_DIAG` reports
`sidecar_on_default_bridge_subnet=true|false`, or `unknown` with
`reason=unavailable|budget_exhausted`. No address, ID, reply, error text or socket
path is printed or persisted. The failure sanitizer accepts only those complete
fixed lines; the original wget failure, assertions and exact native summary
checks remain authoritative even when this optional collector fails.

The optional read rechecks the original 180-second proof deadline **after**
wget. Eight owned liabilities reserve 90 seconds for existing cleanup, so less
than 98 seconds remaining skips the read before launch. Missing, expired or
malformed deadline evidence also skips it. There is no deadline renewal or
cleanup-reserve reduction. The request has a six-second curl/TERM deadline,
one-second kill allowance inside the eight-second operation reservation, and a
64 KiB total response cap. Its foreground timeout remains in the original
cancellation group; no new cancellation handler is installed. Stderr is
discarded, and spawn/read/wait/join/status/framing errors return unavailable
rather than replacing the original proof failure. This is a limited snapshot
of declared default-bridge subnet membership, not a kernel-route observation,
application compatibility proof, or established timeout cause. Neither true
nor false authorizes changing IPAM, routes, firewall policy or the fixture.

After that exact internal-network test returns nonzero, the shell coordinator
may make one status-only guest-to-sidecar GET, only for selected outer Docker
and the already-verified rootless lane. Original cancellation statuses 130/143
bypass this observation. It uses the existing selected `native_outer_command`
directly, the held creation-bound daemon ID and held sidecar IPv4/port 18084/root
path. There is no attach helper, new inspection, endpoint, resource, retry,
namespace entry, installation or fallback. Fixed guest `/usr/bin/curl` disables
configuration/proxy/retry/redirect behavior, has a two-second transfer limit,
discards the response body and emits only its HTTP status. Missing curl and any
nonzero, malformed, multiline or over-cap result remain unavailable.

The direct client's existing privilege-aware timer has a three-second TERM plus
two-second kill envelope. A separate six-second TERM plus one-second kill owner
bounds the no-child host reader, which reads at most four bytes and emits only
a closed category. These are timer envelopes, not a universal seven-second wall
or process-death guarantee: pre-timer sudo/PAM startup remains the existing
admitted direct-client privilege boundary. No new privilege supervisor is added.
Collection requires an alive original watchdog and at least nine seconds of the
original 1800-second lane budget. A positive observation requires the whole
pipeline to complete within the conservative BOOTTIME interval of less than 799
centiseconds, with the watchdog and lane budget still valid. Late or uncertain
completion is unavailable; existing lane/job disposal obligations remain.
The two seconds of lane margin are not a protected cleanup reserve. Rust's
180-second invocation, 90-second cleanup reservation and default-bridge read's
98-second admission are unchanged and are not borrowed or renewed here.

Only `DOCKERLENS_NATIVE_OUTER_GUEST_HTTP: status=http_200|http_other|unavailable`
is printed. HTTP 200 is a later status snapshot, not an exact-body proof,
route/RootlessKit correctness, established timeout cause, lifecycle/cleanup proof
or native acceptance. The original nonzero test status is retained, unless
explicit child cancellation exits through the coordinator's existing EXIT
cleanup owner. It does not depend on self-signalling SIGINT, which may be
inherited as ignored from an asynchronous gate, and cannot resume via `|| true`.

Check/main, trusted native dispatch and release validation all consume the same
canonical nineteen-test harness and inherit this failure-only observation. No
image, Action, tool or dependency pin/extraction path changes; the existing Cargo,
GitHub Actions and five-image Renovate ownership/grouping/manual review remain
unchanged. Guest curl is observation-only image software and unavailable if
absent, not an installed operational dependency. Other workspace products and
the shared runtime bridge protocol receive no change from this private diagnostic.
No extra startup-stage grammar is inferred from generic permission errors.
The separately bounded [failure-only kernel window](native-rootless-kernel-window.md)
may read the current-boot journal only after the exact hosted rootless self-reexec
failure. It preserves the original lane failure and reports job-window evidence,
not exact-process attribution or cause. Other passive per-process host/userns
facts remain unavailable. There are no active canaries, profile loads, sysctl
changes or daemon restarts.

This diagnostic-only change is confined to DockerLens's harness/tests and failure
sanitizer. It does not change the shared runtime bridge protocol consumed by
BoxFerry, product APIs, workflow definitions or runtime acceptance. Existing
Renovate ownership remains unchanged: the five image assignments and their
comments stay in `scripts/native-conformance.sh`, matched by the existing
`renovate.json` regex manager and native-image review group. The only dependency
addition is the already-locked dev-only Serde declaration described in
[dependency policy](dependency-policy.md); its existing Cargo manager remains
the unique owner. No operational pin, extraction path, manager or grouping is
added, moved or changed.

Cleanup remains unchanged: its existing
closed stage/status labels do not identify the stderr cause. A collector was
omitted because safely retaining closed stderr across the original sudo/timer
owner would broaden the privilege/protocol seam.

Hermetic namespace-cancellation fixtures publish their authored PID receipt
atomically through a private 0600 file. Malformed or missing receipts still fail;
closed fixture phase/exception/teardown acknowledgments provide failure context
without raw stderr, paths or process identities. Positive process-group absence
proof precedes fallback teardown, which cannot convert a failed proof into a
pass. Reaping remains within the existing fixture deadline. A forced partial
receipt reproduces the source race, not the cause of any earlier opaque failure.

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

Existing cleanup identity failures additionally emit `DOCKERLENS_NATIVE_CLEANUP_STAGE`
with a fixed role, stage (`network-binding`, `network-owner-inspect`, or
`volume-identity-inspect`) and closed exit category. The original retention
decision and `identity_unknown` marker remain unchanged. No raw command status,
reply, stderr, extra query, retry or renewed budget is introduced; these labels
locate a failure but do not repair or prove cleanup.

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

The independent dockerd UID helper receives the selected engine and private run
directory explicitly and uses the same attach-only `exec` boundary. Its native
UID oracle, eight-second root-owned command timer and twelve-second capture
window are unchanged. The namespace helper likewise receives explicit context;
Rust forwards only the canonical non-secret policy inputs after its original
privilege-aware sixteen-second timer. Namespace identity uses one exact allowed
raw inspect template, never snapshot normalization. Each inspect retains its
512-byte/two-second limit (including attach), a nested two-second root-owned
timer and the existing one-second termination allowance. Held process/network
FD bracketing, running/owner/CID/PID/start identity and namespace probes remain
independent and unchanged. No endpoint fallback or namespace entry follows a
failed identity observation.

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
Attached Python observations, including the initial custody validation, run
directly under that caller's timer/process group; no nested helper timeout can
escape its containment. Standalone sourced-runtime and initial preflight helper
timers retain their existing eight-second behavior and privilege handling.

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
