# Verification

## Closed native fixture launcher seam

The four registered lanes still execute exactly the image-native
`/usr/local/bin/start-dockerd --host=unix:///dockerlens-native/docker.sock`.
`native-conformance.sh` remains the sole operational image tag/digest and
Engine-release source; the launcher helper derives these identities there.
Its closed declaration binds the lane, repository, native launcher defaults
(no new config-file override), account, home, private socket and exclusive
run-owned data root. Debian rootless uses `dockertest`, upstream rootless
uses `docker`, both guest UID 1000 and `/home/docker`; rootful uses root.
This is not a global account rename. Existing Debian package checks, volume
options, BusyBox sidecar/workload pin and configured outer memory/PID limits
are unchanged. Configuration does not prove enforcement or no-swap behavior;
the strict native effective memory/PID assertions remain required, and the
Containers #344 resource-fixture failure remains unresolved. No archive, label or caller-supplied
launcher can register a new lane or create published image evidence.

After readiness, a mandatory read-only acquisition checks the actual unique
passwd account, numeric UID/home, `id` result and daemon effective UID/HOME.
A bounded proc scan requires one dockerd, its executable identity, start ticks
and owned init PID namespace; user/mount namespace identities are retained
without assuming rootless shares those namespaces with init. Account and
process identities are read twice. Outer running ID/name/ownership label,
PID/start timestamp and pinned image identity are inspected before and after.
The canonical pinned reference is resolved read-only to its immutable local
image ID, which must match the container's image ID; tag spelling is not
treated as identity proof.
Guest exec targets the inspected immutable container ID. A mismatch, failed
read, oversized reply, deadline or cancellation fails the lane, with only a
closed failure category exposed. This non-atomic check establishes neither
writable cgroup delegation, controller enforcement nor compatibility.

The caller forwards a nine-second CLOCK_BOOTTIME cutoff before interpreter
startup. The root batch has its own GNU TERM/KILL timer, each Podman call
has a root timer, each guest read has a three-second short-option timer,
and captured stdout/stderr share an 8 KiB cap. An anonymous stdin lifeline
prevents another read after caller cancellation. Local timeout/monitor exit
never proves an already-running remote command terminated; guest timers,
runner loss, SIGKILL and uninterruptible kernel work retain those limits.
Offline synthetic proc and subprocess tests verify the source checks and
failure behavior, not an acquired real fixture or native conformance.

Systemd is a closed but unregistered, deliberately unimplemented alternative.
Its source prerequisite list requires actual systemd PID 1, a reviewed exact
runtime, fixture-specific account, fixed config/private listener/data root
and systemd cgroup driver, account-derived user manager/bus, writable memory
and PID delegation, placement revalidation and bounded shutdown with stopped
readback. The pure lifecycle ordering guard rejects missing ownership,
failure, cancellation, expiry, out-of-order removal and failed stop/readback;
it neither executes these steps nor supplies observation provenance. No
systemd unit names, runtime versions or fixture identities are invented.
Containers #344 fixture adoption and actual bounded systemd orchestration
remain separate work. Emergency removal remains failed-run cleanup, never
positive shutdown evidence. ADR 0004's current native-launcher contract and
all registrations are unchanged, so no ADR is superseded.

Renovate still owns and extracts exactly the same five pins from
`native-conformance.sh`; no manager, extraction path, grouping or approval
definition changes. The new helper uses existing host Python/coreutils and
guest image utilities, without downloads or new tool pins. Fresh genuine
exact-candidate native runs and independent review remain required before
any corresponding admission.

The complete inert review artifact has offline exact-byte, schema, order,
privacy, context-binding, and fail-closed opaque-artifact tests. These verify
serialization, not destination existence, data migration, or native Engine
compatibility. See [the version 1 format](complete-artifact.md) and
[ADR 0009](decisions/0009-complete-inert-artifact.md).

Run `./scripts/format-lint.sh --fix` for local formatting and lint feedback.
The target-module checkpoint has an exact network request regression alongside
the existing container and graph tests. These offline checks preserve the
0.1.0 contract; they do not prove new migration shapes or native compatibility.
The typed-network offline cases exercise create/external separation, multiple
attachment request order, alias and IPAM encoding, redacted prerequisites,
invalid topology, missing capabilities and the API floor. The #31 negative
cases for overlapping IPAM pools, subnet-base and broadcast gateway/auxiliary/
static addresses, and static-address collisions are offline library-policy
rejections before any Engine request. IPv4 `/31` and `/32` bridge parent subnets
remain an explicit planning rejection; this extension does not establish their
Engine behavior on any API or daemon mode.
For native assertion failures, the exact-test wrapper may expose the selected
native test's fixed source basename and bounded numeric line/column. It does not
print the assertion message, compared values, thread name, or absolute build
path. The location is diagnostic only and never changes a failed outcome.
The CLI network oracle also emits only its closed create/inspect/assert phase
and, on a failed command, a closed exit and stderr category. Native stdout and
stderr are bounded independently to 8 KiB; raw bytes remain private. A category
such as a disabled firewall identifies a failure to investigate, not permission
to skip the assertion or admit an unsupported result as positive evidence.
Before creating run-owned resources, the canonical native harness requires the
host `br_netfilter` module and both `bridge-nf-call-iptables` and
`bridge-nf-call-ip6tables` to read back as `1`. Already-ready hosts need no
load. Local, unknown, and other untrusted environments perform read-only
checks and fail if a prerequisite is absent or disabled. Only a positively
identified GitHub-hosted Linux `native-conformance` job for this repository on
trusted `main` push or workflow dispatch may attempt only
`sudo -n timeout --signal=TERM --kill-after=2s 10s modprobe br_netfilter`;
the root-owned timeout bounds that exact module load, and the helper then
requires the same readback. A separate outer deadline is only a fallback:
an unprivileged runner cannot necessarily signal sudo's root process group.
These environment values prevent accidental local mutation, not impersonation by a
root caller. The harness never changes sysctls, unloads modules, installs
packages, changes forwarding policy, or treats the host check as proof of the
inner daemon's network behavior. Failures expose closed categories, not
subprocess output. This bounded prerequisite does not relax any native test.
On a failed edge-side DNS positive, the network test may create one exact
run-owned diagnostic peer. Its closed summary distinguishes resolver setup,
default/explicit/dotted A lookups, named/direct-IP HTTP and cleanup without
exposing daemon output. Optional probes respect the exact runner's 180-second
deadline, reserve cleanup/reporting time and cannot turn the failed positive
into a pass. A timeout before the failure branch may prevent any summary;
SIGKILL or host failure can prevent cleanup. No retry or diagnostic result
establishes compatibility without the original assertion passing.

The native #31 network test uses an independent Docker CLI bridge oracle,
direct Engine GETs, an externally seeded bridge, and test-only application of
the inert renderer requests. It checks two rendered network creates, ordered
secondary connects, per-network alias DNS and traffic, static IPv6 peer traffic,
bridge-interface MTU, and the unchanged external network identity. Isolation
uses separate backend-only and edge-only CLI peers: each positive local DNS
control explicitly queries the IPv4 A record and checks an exact parsed answer
for the inspected endpoint IPv4, excluding the resolver's address and partial
matches, before local HTTP succeeds. Each DNS oracle verifies the peer's embedded
resolver configuration and queries `127.0.0.11` explicitly. The isolation
fixtures are distinct, running, single-network peers with canonical inspected
IDs and distinct IPv4 addresses. Both carry the literal `edge-sentinel` alias;
from each peer, an absolute A query to the embedded resolver must contain the
complete named answer set of exactly that peer's inspected IP, with no extra,
foreign, malformed, or truncated answer. Named HTTP to the shared alias must
return distinct local canary bodies, and backend-to-edge direct-IP HTTP must
still fail. Ordinary unqualified named HTTP for rendered app aliases remains
a separate positive traffic check. This proves collision-scoped local alias
selection and route isolation, not unshadowed `NXDOMAIN` or all DNS-forwarding
behavior. Run `36504139504` observed Debian rootful `cli_resolver/other/other`
for an unshadowed foreign-name query on the internal backend. That closed
result did not prove either forwarding or an alias leak, and no timeout is
accepted as isolation success. Collision failures expose only fixed-category
diagnostics from bounded CLI output. A dual-homed app's edge IP is not an
isolation oracle. Closed DNS and HTTP markers distinguish each stage. The
executor allows only the run-owned network and
container names, including exact `networks/{id}/connect` paths. The separate closed
`network_probes` manifest field retains the original nineteen network renderer
shapes and appends `NetworkBridgeIccDisabled`,
`NetworkBridgeMasqueradeEnabled`, and `NetworkCreateLabelsValueDomain` only
after the exact ignored test passes; these three added markers do not extend
`admitted_shapes`, catalog capabilities, or a compatibility claim. IPAM fields,
labels, masquerade and host-binding options have request/inspect checks, not
independent kernel-behavior proof. Matched control bridges differ only in ICC;
both have independently healthy same-bridge peers, with the same direct-IP
inter-peer HTTP probe succeeding when enabled and failing when disabled. This
uses no external DNS or Internet dependency. Both
masquerade values are accepted and inspectable, but this does not prove their
routing or NAT effect. Representative empty and non-ASCII/escaped network-label
values are checked through independent CLI and inert-rendered creates and Engine
inspects; this does not prove every key or length boundary.
The separate ignored internal-network proof gets its own 180-second bound after
the general network test. It compares independently CLI-created bridges with
matched inert requests sent to Engine, then checks direct Engine inspect values.
The rendered internal and ordinary bridges both enable ICC and masquerade; their
single-homed peers must each have healthy same-bridge HTTP. A task-owned BusyBox
HTTP sidecar and the nested Docker daemon attach to one separate outer Podman
bridge with distinct private IPv4 addresses and network namespaces. The ordinary
peer must fetch the sidecar by direct IPv4 before and after the internal peer
fails to fetch that same address. The sidecar is not in the inner Docker host
namespace: traffic from inner bridges crosses Docker's FORWARD path. No public
Internet or DNS result is involved. Sidecar setup failures expose only closed
phases, error categories, and a fixed canary-write stage. A successful write-stage
marker proves only that the health file was written, not that HTTP started or
that the permission text came from the sidecar rather than the Podman logs query.
The HTTP document root contains only the synthetic canary. Private httpd stderr
is captured outside that root with owner-only permissions, capped at 8 KiB or
less by a checked file-size limit in the HTTP process subshell, and removed
on exit. Supported shells use 512-byte or 1-KiB limit units; neither can exceed
that cap. Limit setup failure prevents HTTP startup and fails the lane.
A unique, exact closed cause marker from a nonzero httpd return takes precedence
over unrelated Podman logs-query errors;
missing applets and shell errors remain distinct causes. Missing, conflicting,
or malformed cause markers do not establish an attributed cause. These
diagnostics preserve sidecar privileges and cannot turn a failed lane into
positive network evidence.
A panic-time inner cleanup attempt separately reports a closed pass/fail result.
Neither marker prints native output or turns a failed lane into evidence.
A positive ordinary-bridge control and a blocked internal
probe are both required independently; reachable internal traffic fails the
proof even when all request and inspect fields match.
The negative HTTP probe requires a successful Docker exec carrying a fixed
`blocked` result from the running peer, with the control fetching the exact
canary again afterward. Outer command timeouts and Docker exec failures cannot
count as blocked traffic. Every proof operation reserves time for bounded
label-verified cleanup within the 180-second runner deadline. Failed removals
stay in the cleanup ledger for a retry, and only an exact direct Engine 404
clears an uncertain resource. Only after the live assertions and verified
cleanup does the test
replace the private network probe file with a closed positive shape result.
The manifest emitter rejects a missing, negative, malformed, oversized, or
symlinked result; a valid result adds `NetworkInternal` and its sole
`InternalBridgeNetworkCreate` shape to raw lane evidence. The separate reviewed
#68 cohort below admits only that singleton internal-network group; original
historical evidence remains unchanged. This test adds no dependency, image,
action, or tool pin,
so Renovate extraction and ownership need no change.
The three option/label additions remain non-admission evidence, and the historical nineteen
names and manifests are unchanged. IPv4 `/31` and `/32` bridge parents remain
rejected by planning, independent of any Engine acceptance behavior.
The typed-container offline regressions cover exact grouped `PortBindings`
and `ExposedPorts` bodies, host-IP privacy, wildcard conflicts, ephemeral
allocation requests, command/entrypoint inheritance and clearing, shell and
disabled health, timing, metadata, tmpfs, and runtime settings. Command clear
with an inherited or cleared entrypoint fails intent validation; only an
explicit exec entrypoint plus clear command reaches capability-gated inert
rendering. This candidate is not a native clear claim. These are local contract
tests only. #31's independent native assertions must check
resulting loopback and IPv6 exposure, repeated/dynamic assignments, mount
access, process identity, health behavior, and resource/security outcomes in
each claimed mode and API. `StartInterval` needs exact native support and a
1.41 negative boundary before any catalog admission; no generic introduction
floor is inferred from Compose documentation.

## Typed container native evidence checkpoint

The isolated `native_container_tests::live_container_settings_match_engine`
test is separate from the historical target test. It uses the pinned BusyBox
fixture and task-owned names in the existing private inner daemon. Independent
Docker CLI creates establish expected native fields before corresponding inert
renderer bodies are compared against independently authored, closed JSON
requests, applied only by the test, inspected directly, and checked for live
effects. Clear command and entrypoint are an explicit exception to the CLI
oracle: the test derives task-owned local images with nonempty defaults from
the pinned BusyBox image, then compares independent literal Engine API and
rendered empty-array creates, inspect results, and distinct inherited-versus-
cleared process exit codes for command and entrypoint separately.
The derived images are not downloaded or product dependencies.

The test writes a private schema-1 `container-probes.json` only after every
compiled expected shape has exactly one closed result and exact resource cleanup
succeeds. `positive` contains exact `NativeCapabilityShape` names whose closed
request, independent native inspect, and stated shape-specific effects passed.
It is a non-admission checkpoint: timing, rotation, and resource-enforcement
claims must be limited to the effects actually asserted, not inferred from
acceptance alone. Unlimited nofile must exceed the independently checked
1024/2048 finite control. NET_BIND_SERVICE is a Docker default: separate
CLI drop-all and drop-all/add-back controls establish a causal runtime effect
for the exact Engine and mode, while the rendered request proves its `CapAdd`
body and inspect value and checks its resulting bit. That rendered bit alone
does not establish a runtime delta. `expected_negative`
contains only `{shape,reason}` with two distinct Debian API 1.41 boundaries:
positive `StartInterval` is `HealthStartIntervalPositive` /
`api_1_41_no_start_interval`, while explicit zero is
`HealthStartIntervalZero` / `api_1_41_start_interval_zero_unobservable` because
its inspect value is indistinguishable from an absent field. The zero probe
first checks the positive support witness, then sends explicit zero and compares
both inspected results against an absent-field baseline. Upstream API 1.56 must
prove both shapes positively, including a healthy container after zero timing.
An unexpected native rejection,
transport/start failure, or semantic mismatch fails the lane; it is never
converted into an unsupported pass. The test-only scoped facts enable an
inert renderer branch after independent oracle checks and do not authorize a
production profile. Raw Engine replies, labels, and authored values remain
private. Native CLI stdout and stderr are each capped at 8 KiB before capture;
the exact-test wrapper caps its private Cargo/libtest output file at 256 KiB
before parsing closed diagnostics. Exceeding either cap fails the lane without
printing raw output. The shared exact runner and manifest emitter own admission of this
closed output. On a failed port probe, the wrapper reports only its last closed
subphase: fixed or repeated IPv4 versus fixed or dynamic IPv6, independent CLI
oracle versus rendered request, and create, inspect, binding, start, HTTP, or
UDP checks. A failing CLI command adds only a closed exit and recognized stderr
category; an Engine API transport or unexpected status adds only a closed
category. These diagnostics do not print native output, change the assertion,
skip a probe, or permit a failed lane to produce evidence.
The repeated fixed-IPv4 CLI oracle must also start and serve both exact
loopback publications before the rendered container is created. Each HTTP
check now observes the outer Podman network namespace directly, with no extra
Docker host-network probe container and no dependence on tools inside the
outer image. A bounded host helper verifies the exact running, labelled Podman
container and its PID/start identity, opens its network namespace through a
held file descriptor, and invokes only closed host `curl` or Bash probes via
`nsenter`; identity is checked again before and after. The host tools and
namespace entry are preflighted. HTTP requests disable proxies and have five
bounded attempts. The separate negative loopback-isolation check uses a direct
three-second TCP connection in the same pinned namespace and accepts only the
kernel's `ECONNREFUSED`; an open connection, timeout, permission/routing error,
or malformed result fails. It does not depend on curl's version-dependent error
wording. The preceding exact-canary positive proves the service is available.
Each HTTP attempt has a two-second connection and three-second total limit.
A local in-container service check
precedes each published-port assertion; for the IPv6 fixture either local
address family may establish service readiness, and the `::1` local result is
reported separately on publication failure. Only after the original published
IPv6 HTTP assertion fails, a fixed diagnostic reads `all/disable_ipv6` and
`lo/disable_ipv6` in that exact run-owned inner container and checks TCP6
creation, `::1` bind, and loopback connect in the separately verified,
file-descriptor-pinned outer network namespace. It emits bounded closed states
and a recognized curl exit-code token, never addresses, ports, or native output.
If exact inner inspect or pinned outer probing fails, that optional field is
`unavailable` or `probe_failed`; the original HTTP failure marker remains.
Outer namespace availability does not establish inner-container IPv6 support
or the cause of an HTTP failure; diagnostics neither reclassify nor pass the
failed positive. For the exact Debian 11 nested default-bridge fixture, both
fixed and ephemeral IPv6 CLI and rendered requests additionally carry a
Debian-only `127.0.0.1` binding to the same container service. Each must show
its exact configured and runtime bindings, running container state, a local
IPv4 service canary, and a successful published IPv4 canary. The pinned outer
namespace must independently prove TCP6 loopback availability. Only then may
the direct TCP6 probe accept kernel `ECONNREFUSED` at the exact fixed or
runtime-assigned `::1` port, with both CLI and rendered fixtures agreeing, as
`nested_default_bridge_ipv6_unavailable`. Five direct probes spaced 250 ms
apart must all return exact refusal, covering the former positive HTTP
readiness window. Before accepting a negative, the fixture repeats running
state, default-bridge identity, configured and runtime bindings, local and
published IPv4 canaries, and pinned outer TCP6 availability, then requires one
final exact refusal and disabled inner IPv6 state. A connection at any probe,
including that final check, must instead
pass the published IPv6 HTTP canary and records a positive; timeout, routing
or permission errors, malformed output, missing identity, or differing fixture
outcomes fail the lane. This narrow expected negative is not an Engine 20.10,
API 1.41, rootless, or general IPv6 rule. Upstream fixtures retain their
positive IPv6 HTTP assertions without a Debian control binding. No profile
or production capability is admitted by this test-only outcome.
Run `36525280564` established a narrower Debian fixture observation in both
daemon modes: the fixed CLI request had both exact configured bindings, but
runtime inspect reported only the exact IPv4 control binding. A separate
`nested_default_bridge_ipv6_runtime_binding_absent` outcome now requires an
exact one-entry IPv4 runtime array with a numeric host port, no IPv6 or other
entry, and unchanged running/configured/default-bridge state. Five inspected
snapshots spaced 250 ms apart and a final post-control snapshot must retain
that exact shape and IPv4 port. The local and published IPv4 canaries, pinned
outer TCP6 loopback, and inner `all`/`lo` IPv6-disabled states are checked
before and after the window. For a fixed requested IPv6 port, every snapshot
and the final check additionally require exact kernel `ECONNREFUSED` at that
requested port. For an ephemeral request there is no inspected IPv6 host port:
the harness never guesses an allocation or probes an unrelated port. Any
transition to an assigned binding, malformed value, mismatched CLI/rendered
outcome, or failed control fails the lane. This reason means an IPv6 runtime
binding is absent from inspect, not that no hidden host port exists or that
Docker 20.10 generically lacks IPv6. It does not admit `PortHostIpv6`.
Run `36523854395` reached the Debian fixed IPv6 CLI fixture but failed before
the TCP6 boundary because its runtime port-binding array did not satisfy the
two-entry assertion. The log does not reveal which address or port was
missing. A new closed diagnostic reports only runtime key state, count and
exact-address cardinality buckets, and numeric/empty/malformed port-shape
categories. It never prints a binding, address, assigned port, or native JSON;
the original two-entry assigned-binding branch and all traffic oracles remain
unchanged. In
particular, an absent ephemeral IPv6 assignment is never guessed.
The same run reached the command-clear literal on both upstream lanes and
showed that `Cmd:[]` alone retained the image command rather than clearing it.
The native oracle therefore requires that control to retain the image command
and exit 7. A separate control sends an explicit `/bin/sh` entrypoint with
`Cmd` omitted to show whether the entrypoint override itself removes the
default command; its inspected arguments and exit status must agree with the
observed branch. Only the paired explicit `/bin/sh` entrypoint plus `Cmd:[]`
literal and identically rendered request may count as `ClearCommand`: each
must inspect with exact entrypoint, `Config.Cmd` explicitly `[]` or `null`,
runtime `Path=/bin/sh` and `Args=[]`, and exit 0. This proves only conditional
no-argument behavior, not that `Cmd:[]` alone clears a command. `ClearEntrypoint`
remains a separate native shape. Closed substage and command-shape diagnostics
report failures without native values. Even successful native evidence does
not admit a generic production `CommandClear` capability: intent validation
now rejects clearing with inherited or cleared entrypoint, and catalog admission
requires separate review and an exact passing candidate.
Run `36525280564` passed that conditional command-clear region on both
upstream lanes, then failed the resource/security oracle at exact inspected
`HostConfig.CapDrop` spelling. Docker's published container-run reference
accepts capability names with or without `CAP_`; native inspect may therefore
be checked against only a singleton `SYS_ADMIN` or `CAP_SYS_ADMIN`. The
rendered request remains exactly `SYS_ADMIN`, and the existing effective
runtime `CapBnd` check requires bit 21 to be absent. Docker's default capability
set already omits `SYS_ADMIN`: this proves request preservation and observed
absence, not causal removal by the drop operation, and does not independently
authorize production admission of `CapDropSysAdmin`. A closed spelling
and cardinality diagnostic exposes no native value. Any other spelling,
case, extra drop, or failed effective check still fails the lane.
Closed resource/security substages distinguish create, inspect, start, and
each effective process/cgroup check without disclosing values. In particular,
rootless `cgroup_driver=none` is diagnostic context, not permission to treat
configured memory or PID limits as effective; both runtime assertions remain
strict and have no expected-negative exception.
Run `36527523744` failed in both Debian lanes before the fixed IPv6 refusal
probe: the closed namespace-mode validator omitted the already-used
`tcp6_refusal` mode. The validator now shares one explicit mode list with a
local regression that enumerates static call sites and exercises allowed and
rejected modes. This restores the intended probe; it does not establish an
IPv6 result. Both upstream lanes reached the resource/security oracle START,
where Engine returned unexpected HTTP 500 (rootful) and 400 (rootless). The
closed API status alone does not establish why either request failed. On an
unexpected START status, a bounded diagnostic now classifies the protected
JSON response body's shape and emits only fixed lexical mention flags for
`cgroup`, `device`, `sysctl`, `ulimit`/`rlimit`, `apparmor`, `errno`, `controller`,
`bpf`, and fixed permission phrases. A mention may come from a protected path
or secret and is not a cause,
an effective-setting check, or native capability evidence. Missing, malformed,
and oversized bodies report unknown flags. The exact-test runner accepts only
the closed diagnostic line; it never prints body text. START must still return
204, and all resource/security assertions and admission rules remain strict.
Run `36528815479` reached the resource/security START in Debian rootful and
upstream rootful, where both returned unexpected HTTP 500 and a `cgroup`
mention. Upstream rootless returned HTTP 400 with a `device` mention; Debian
rootless timed out in the repeated/dynamic IPv4 CLI oracle START. These closed
markers do not identify an Engine cause. The container native test now executes
five independent groups—ports, identity/health/clear, storage/lifecycle,
resources/security, and resolver/logging—each with fresh test state. A failed
group may be followed by another only after bounded cleanup verifies exact
container-test names, canonical IDs, and the run label, checks the three exact
task-owned derived-image references and labels, and reads back absence. A
run-labeled image with an unexpected or dangling tag makes cleanup unverified;
the harness leaves that image untouched and does not start the next group. A
transport-uncertain mutation or unverified cleanup stops the lane even if a
single inventory appears empty. Completed groups contribute shapes only after
cleanup; any group failure prevents the 57-shape manifest. The existing
180-second wrapper timeout and closed-output boundary remain, and at most five
closed group-failure markers are exposed. No failure becomes a skip, expected
negative, or production capability.

On a known non-204 resource/security oracle START response, the failed native
test may run at most five independent, task-owned controls with the same image
and command: no resource/security flags, memory limit only, PID limit only,
and renamed device mapping only, followed by a separate same-path device
mapping, in that order. The original `device` control remains
`/dev/null:/dev/native-null:r`; `device-same-path` uses `/dev/null:/dev/null:r`.
Each inspected `HostConfig` must match
only its intended option before start; image, command, name, and run label must
also match the task-owned fixture. Before any control, a bounded exact-ID
readback must show that the failed original oracle remains created and not
running. Running, exited, missing, mismatched, or unreadable original state
stops controls as mutation uncertainty. Controls use exact-ID Engine API START,
then inspect state: only HTTP 204 and running counts started; a non-204 response
with still-created state is a rejected control, while transport errors or
status/state disagreement remain uncertain. Closed HTTP status, lexical
response-body category, and state are diagnostics, never native capability
evidence. Each control starts only while the wrapper deadline leaves at least
90 seconds for bounded create, inspect, START, and exact cleanup. An uncertain
mutation stops further controls and the next group even when inventory reads
empty. The closed group-decision marker reports `probe_failed` after a failed
positive and verified cleanup; only a passing probe can report `merge`. The
original oracle START must still return 204; control outcomes cannot
reclassify its failure.
Each rejected control additionally retains its own closed
`DOCKERLENS_NATIVE_RESOURCE_START_BODY_DIAG` record, correlated with its
baseline, memory, PID-limit, renamed-device, or same-path device role. The exact
runner exposes at most five complete, allowlisted records alongside the
original last global body diagnostic. These remain lexical mentions, not an
Engine cause or capability.

The two device controls also emit bounded
`DOCKERLENS_NATIVE_DEVICE_START_BODY_DIAG` records with exact fixture-path
mentions and a closed errno-phrase category from the protected START body.
Larger path substrings do not match; malformed, missing and oversized bodies
remain unknown. Multiple recognized errno phrases are ambiguous. These are
lexical observations, not a syscall errno or a causal attribution. No current
probe binds the device paths to the exact dockerd/runc mount namespace, so
namespace, source presence and source type explicitly remain unknown. The
runner exposes at most two complete, allowlisted records. A successful
same-path diagnostic cannot replace the required renamed mapping or relax a
failed positive. Reading `/dev/null` proves neither restricted `r` permissions
nor causal device-cgroup enforcement: that device is allowed by default with
`rwm`. Effective memory and PID-limit assertions remain mandatory, and neither
control admits `DeviceMappings` or another production capability.

The startup-only context call in `native-conformance.sh` uses
`native-device-source.py --context` for one combined five-second monotonic phase,
not five seconds per diagnostic. Before interpreter launch the shell reads a
conservative `/proc/uptime` timestamp (monotonic CLOCK_BOOTTIME, including suspend)
and starts a caller-owned TERM/KILL timer around the entire pipeline: 4.8 seconds
plus a 0.2-second kill reserve. Thus stalled imports and local capture/parser
waiting count, not merely successful operations. The direct timer child stays
alive through TERM until its pipeline finishes or KILL fires. The absolute cutoff
is also forwarded to the root-owned batch, reserving 0.7 seconds for startup,
timer fallback, local teardown and reporting. The cgroup and device reads each
receive at most two seconds, clamped to the actual remaining work deadline;
an exhausted slice produces fixed unknown records without another read. Slice
alarms reserve local teardown, and both readers honor the supplied deadline
internally; remaining BOOTTIME durations are converted to the readers' existing
monotonic clock without assuming zero suspend offset. The standalone helpers
retain their existing five-second defaults.
The time counts inside the unchanged 30-minute outer deadline; the phase runs
before the unchanged 180-second exact-test deadline and 90-second control/cleanup
reservation. The context capture caps combined private stdout and stderr at
2 KiB, then accepts only one complete batch: exactly two closed cgroup records
and two closed device records with fixed field order, identities and value
domains. Nonzero exits, overflow, partial, duplicate, extra or malformed records
become fixed unknowns; raw output, arguments and subprocess errors are never
printed or written to capture files. The shell buffers the validated result and
prints it only after the whole pipeline succeeds. A batch that receives
whole-phase cancellation does not start its second reader, and the caller
preserves the lane's existing cleanup traps.
An anonymous stdin lifeline also connects caller cancellation to the root
batch's separate process group: the capture closes its writer before local
failure/cancellation waiting, and the batch requires a live, empty FIFO before
and after each slice. EOF, unexpected data or non-FIFO stdin produce all-unknown
records without starting another reader. This does not synchronously interrupt
an already-running remote read or prove its termination.

The `native-cgroup-diagnostic.py` reader uses one cumulative 8 KiB bound for its
private stdout and stderr combined across operations. It validates the running outer
container's immutable ID, exact name, ownership label, PID, and start identity
before and after. The context batch runs as host UID zero under its root-owned
timeout; standalone elevated Podman operations, including both inspections,
also have root-owned TERM/KILL timers with teardown time reserved inside
their deadline. Context cancellation or overflow uses the remaining local wait
reserve, not an assertion that a delayed privileged timer has expired. The
unprivileged sudo monitor remains in the caller's timed local process group;
where permitted it is individually stopped and reaped before local return.
Permission or wait failure remains private and unknown. Root process groups,
delayed sudo/root startup, and remote Podman work have independent lifetimes:
neither an unprivileged signal, monitor exit, nor a host timeout proves their
termination. The forwarded absolute work cutoff prevents late batch work;
SIGKILL, uninterruptible kernel work and runner loss remain irreducible limits.
Standalone local unprivileged command groups are killed and reaped;
both private pipes close even if signaling or waiting fails. Guest reads also
have their own bounded timeout; cancellation,
overflow, read errors, or identity changes produce closed unavailable states.
No captured bytes, paths, PIDs, limits, or subprocess errors are printed.

The guest timer uses `timeout -k 0.2 <seconds>` rather than GNU-only
`--kill-after=0.2`; the root-owned host GNU wrappers remain unchanged. The
read-only portability oracle was
[`mirror/busybox@371fe9f71d445d18be28c82a2a6d82115c8af19d/coreutils/timeout.c`](https://github.com/mirror/busybox/blob/371fe9f71d445d18be28c82a2a6d82115c8af19d/coreutils/timeout.c#L89),
whose option parser admits the short `-s` and `-k` options, and workspace GNU
coreutils 9.12 `timeout --version` / `timeout --help`, which identifies `-k`
as the kill-after option. The exact BusyBox commit's
[`LICENSE`](https://github.com/mirror/busybox/blob/371fe9f71d445d18be28c82a2a6d82115c8af19d/LICENSE)
and timeout-file license notice were read and verified as GPL-2.0-only; GNU's
version output identifies GPL-3.0-or-later. These are interface references,
not proof of the exact guest build or native compatibility. No oracle source
or binaries are copied or redistributed. An independently authored
short-option-only fake rejects the former invocation and checks the exact
new argument shape and nonzero-exit failure propagation using synthetic
replies, without any runtime resources. This correction neither relaxes the
native assertions nor resolves missing rootless systemd prerequisites.

The outer start identity explicitly requests `{{json .State.StartedAt}}` and
decodes a bounded JSON string before strict RFC3339 and calendar validation;
the complete decoded value, including nanoseconds, participates in the
before/after comparison. Plain Go display text, malformed JSON, non-string
values, and changed timestamps remain unavailable. A read-only oracle using
workspace Podman 6.0.2 compared `podman version --format
'{{.Client.Version}}'`, `podman inspect --format '{{.State.StartedAt}}'
<existing-owned-container>`, and `podman inspect --format
'{{json .State.StartedAt}}' <existing-owned-container>`: the plain template
returned Go display text, whereas explicit JSON returned quoted RFC3339.
No container was launched or modified; its identity and timestamp are omitted.
The published Ubuntu 24.04 runner record
[`ubuntu24/20260927.320`](https://github.com/actions/runner-images/blob/ubuntu24/20260927.320/images/ubuntu/Ubuntu2404-Readme.md#L97)
identifies Podman 4.9.3. The public source-contract oracle is
[`v4.9.3/libpod/define/container_inspect.go`](https://github.com/containers/podman/blob/v4.9.3/libpod/define/container_inspect.go#L220),
whose inspect-state start field is `time.Time`. Its exact-tag
[`LICENSE`](https://github.com/containers/podman/blob/v4.9.3/LICENSE) was read
and verified as Apache-2.0. These references describe the format boundary;
no upstream source or native replies are copied or redistributed. The helper
and synthetic display/JSON regressions were authored independently. This
diagnostic correction does not change native assertions or admit compatibility.

The helper reads `cgroup.controllers`, `cgroup.subtree_control`, `memory.max`,
and `memory.swap.max` at the visible cgroup2 root. A daemon-directory read
also requires exactly one mode-correct `dockerd`, stable process identity,
effective UID and cgroup membership, matching mount/cgroup namespaces, one
total mountpoint entry with a rooted cgroup2 mount, and a traversal- and
symlink-free directory mapping. Rootful requires effective UID zero; rootless
requires the canonical selected lane's account and exact UID: Debian
`dockertest`, upstream `docker`, both UID 1000. No mode-only account default
or alternate account fallback is used. The account and effective UID are rechecked
after reads. Missing or ambiguous account evidence and stacked mounts stay
unavailable. Different
RootlessKit namespaces or ambiguous mappings leave that scope unavailable;
the helper never guesses their host correspondence or enters another namespace.
The two `DOCKERLENS_NATIVE_CGROUP_DIAG` records expose only scope, read outcome,
memory/PID controller presence, subtree flags, and finite/max/missing/unknown
memory and swap states. Fields called `memory_delegated` and `pids_delegated`
report only enabled subtree flags: they do not establish writable delegation,
permission, effective limits, enforcement, or a reason to weaken a failed
native assertion. The helper makes no writes or policy/privilege changes and
does not affect native success, manifests, or production capability admission.

The two `DOCKERLENS_NATIVE_DEVICE_SOURCE` records describe only fixed leaf
metadata in the verified daemon's view, with roles `host-null` and `renamed-null`.
Both have `scope=daemon-view`: the role name is not host-namespace attribution.
The reader requires authentic procfs for every process/namespace directory and
metadata file, independently verifies proc magic-link targets, binds the guest
init to the owned outer process, and requires the daemon's held PID namespace
to match that init in both modes. Foreign or nested PID namespaces remain
unknown. A 32 KiB cumulative read bound and a bounded process scan apply; only
leaf metadata is read, never device contents. Process, namespace, root, `/dev`,
leaf and container identities are rechecked. No guest exec or namespace entry
is added by the device reader. `runtime_source` and `permissions` always remain
unknown: these non-atomic observations neither identify transient runc's source
namespace nor prove access or enforcement. Diagnostic timeout is optional,
not permission to skip the renamed-device or effective memory/PID assertions.
Offline integration does not establish native compatibility or resolve the
Containers #344 systemd prerequisites; fresh genuine exact-candidate native
evidence remains required before any corresponding admission.

The finite resource assertions, unlimited-resource comparison and failed-resource
control matrix resolve memory/PID controller files from the owned container's
PID1 membership and mountinfo, rather than reading a fixed visible cgroup root.
The resolver requires one matching hierarchy and mount-root/mountpoint mapping
per controller, supporting a namespace root, an unambiguous bind-root mapping,
and split v1 controllers. Authenticated v1 assignments take precedence in hybrid
views and never fall back to a visible unified hierarchy. Mount parent chains
must establish the active view for both proc evidence and controller files;
an unrelated ancestor overmount cannot supply substitute data. Unsafe paths,
unrelated roots, escaped paths, stacked or shadowing mounts, ambiguous membership
and incomplete replies fail closed.
It never substitutes an ancestor limit or guesses a namespace correspondence.
Before and after the leaf reads, immutable ID, exact name/run label, running
PID/start timestamp, PID1 start ticks, PID/mount/cgroup namespaces and complete
membership/mount snapshots must remain consistent. Private PID mode is required:
host/shared PID namespaces cannot identify the target init through PID1. The
guest must share those namespaces and exact membership with PID1. Procfs and
every consumed init/helper proc path must have an unshadowed mount view. These
are non-atomic readbacks, not a guarantee against
undetected transient external mutation. A failed diagnostic remains unknown;
required assertion failures still fail the native suite and ownership cleanup.

Metadata reads are capped at 512 bytes for stat, 1 KiB for membership and 6 KiB
for mountinfo, below the existing private 8 KiB CLI cap. Each snapshot/read has
the existing one-second guest timer and three-second CLI bound. Controller
reads reject symlinked path components and preserve newlines when enforcing
their byte cap; no v1 or visible-root fallback follows a missing leaf.
Independent synthetic fixtures distinguish ancestor and leaf values, namespace
roots, bind mappings, split controllers, unsafe/ambiguous views, truncation and
changed ownership/process/namespace identities. They establish no native
compatibility, writable delegation or enforcement, and add no pins or catalogue
admission. The strict memory/PID, START and zero-swap requirements remain in force.

Each failed one of the five container groups retains one closed
`DOCKERLENS_NATIVE_GROUP_FIRST_FAILURE` checkpoint independently of later
cleanup-verified groups. Observed API/CLI timeouts remain timeout observations;
an otherwise caught probe assertion remains `probe`/`unknown`, never an inferred
cause. Cleanup and preflight failures likewise retain closed unknown context.
The original combined resource-oracle START response is recorded immediately,
before the failure-only controls, as `RESOURCE_START_HTTP` with `control=oracle`,
a bounded numeric status (or unknown), and its closed status category. A rejection
retains `resource_oracle_start`/`http_status` as that group's first checkpoint.
Neither these checkpoints nor lexical error-body mentions establish kernel,
controller, swap, delegation, or enforcement causes. Existing last observations
remain supplemental, and the first selected-source numeric panic location is
preserved. All strict START, memory/PID, device and cleanup assertions stay intact.

The exact-test runner validates the new records as a bounded set: at most one
checkpoint per known group and one original resource START response, exact fields,
consistent status/category and failed-group bindings, and no duplicates or
private suffixes. Malformed or inconsistent records fail closed without printing
their payload. A successful test emits no failure diagnostics. This is trusted
harness provenance, not authentication against a writer able to forge an entire
consistent private capture. The existing 180-second invocation, capture byte cap,
eleven mandatory tests, proof inputs and capability-admission boundaries do not
change. Offline diagnostic regressions establish no native compatibility.

The failed-resource control matrix can additionally read these bounded, fixed
memory/PID controller files inside a started, run-owned control container.
Its private readout is limited to two records and 512 bytes at classification;
each file read is capped at 65 bytes and rejects values exceeding 64 bytes,
within the existing shared control budget. Closed
`DOCKERLENS_NATIVE_RESOURCE_EFFECT_DIAG` records distinguish configured
finite/unset/unlimited limits from observed matching, different or unlimited
limit files and missing, denied, invalid-file, malformed, oversized or failed
reads. Neither START 204, configured values, controller flags nor matching
file values proves enforcement: every record retains `enforcement=unknown`.
The wrapper admits at most five exact closed records on failure, never raw
numbers or paths. The required native memory/PID effect assertions, failure
propagation, cleanup and evidence schema are unchanged.

The exact PR #73 run `37218370132` failed all four lanes. Rootful memory-only
START rejection and absent visible subtree flags leave the cgroup fixture
prerequisites unresolved, not a proven Engine incompatibility. Rootless
renamed-device rejection remains an unadmitted exact-shape candidate;
same-path `/dev/null` success is insufficient because that node already exists
in an ordinary container. Debian rootless repeated-dynamic IPv4 START timeout
and unverified cleanup are inconclusive, never an unsupported classification
or permission to emit evidence. These diagnostics repair no host policy and
do not resolve any of those blockers.

`native-conformance.sh` remains the canonical caller for local lanes,
`check.yml` main push, `native-validation.yml` reviewed dispatch, and
`release-validation.yml` exact-main validation; all inherit this diagnostic.
The other workspace products retain their independent harnesses. This uses
runner Python's standard library and core utilities already provided by the
digest-pinned Engine images, with no download or new software pin. Renovate's
existing native-image manager still uniquely extracts the same five tag/digest
pairs from the same script; managers, paths, grouping, and review ownership
therefore remain unchanged.
Resolver/logging now reports closed IPv4, IPv6, local-driver, and none-driver
oracle/rendered substages for create, inspect, START, and relevant resolver,
hosts, log, and body assertions. The ports failure path reports closed mutation,
tracked cleanup, inventory cleanup, stable-absence readback, and decision
phases. These markers expose neither native output nor resource names and do
not retry an uncertain START or widen the exact task-owned cleanup scope.

The manifest emitter requires both Debian API 1.41 start-interval negatives,
accepts each of the two IPv6 fixture outcomes independently only on the
Debian lanes, and preserves the observed positive or exact narrow negative in
the sanitized manifest. It rejects reordered, unknown, duplicate, mismatched,
or overlapping outcomes; an upstream negative is always rejected. The
ephemeral UDP sender uses the outer namespace with a validated numeric port
and a fixed canary.
The disabled-health inheritance oracle now creates a run-owned CLI container
with an explicit failing health check, commits it to a task-owned local image,
and verifies the image's health test, timing, retry count, and ownership label
before checking inherited unhealthy and disabled no-health behavior. This
does not require image-build tooling. The derived image uses a fixed lowercase
repository role and retains the exact case-sensitive run ID in its tag; it
never uses the mixed-case run-owned container name as a Docker repository.
Run `36517967971` failed in the prior image-build setup on both upstream modes
with only an unknown closed CLI category, and run `36521163238` failed during
the revised image setup with the same broad category. Neither record proves a
builder or daemon root cause. A local audit found the generated mixed-case
repository name and motivates exact source-create, source-inspect, commit,
image-inspect, and source-cleanup markers plus value-free recognized stderr
categories. Its Debian modes failed the original fixed-IPv6 CLI published HTTP
positive: inner `all` and `lo` IPv6 were disabled while the pinned outer
namespace could create, bind, and connect TCP6. The explicit host `::1`
publication returned curl exit 7. This is a context-specific failure, not a
general Docker 20.10 or rootless rule; no failed positive becomes an expected
negative without an independently checked contract.
Closed HTTP, IPv6 and health-disable subphase markers distinguish failures without
publishing native output. A selected native test panic may expose only its
allowlisted source basename and bounded numeric line and column, never its
assertion text, path, or compared values. Exhaustion still fails the lane and
cannot be classified as unsupported from the diagnostic alone.

The five-second watchdog and final size check use one sampler. Before every
attempt, a privileged, time-limited `stat` verifies the same run-owned volume
directory device and inode, including rootless outer lanes whose Podman storage
is inaccessible to the unprivileged harness. The sampler bounds `stat`, `df`
and `du` output and execution time, and keeps command stderr in a private,
size-limited file. Both `df` and `du` run on an attempt: an observed volume
total above 4 GiB or free space below 2 GiB fails immediately, even if the
other command failed. A partial `du` total can establish a breach but never
establish success. Only an exact disappearing descendant beneath the unchanged
owned root permits another complete sample, for at most three attempts.
Root loss or replacement, permissions, timeout, malformed totals, persistent
churn, and all other errors fail closed. The 30-minute deadline is enforced on
every attempt. No raw paths or command errors are published.

`ImageReference::new` rejects dollar-sign image references, including unresolved
Compose interpolation such as `${IMAGE}`, before inert Engine create planning.
This is a narrow native invalid-input boundary, not a complete Docker image
reference grammar; tagged, digest and image-ID forms remain accepted.

The runner selects the ignored library test by exact name after
the other native probes. Only then does the emitter accept a bounded schema-1
`container_probes` object with 57 unique, disjoint closed outcomes, the
exact lane-specific start-interval boundary, and no additional fields or raw
values. Missing, duplicate, overlapping, unexpected, or unexecuted results
fail without a manifest; these outcomes do not expand `admitted_shapes`.

`TmpfsMountOptions` additionally requires inside-fixture filesystem capacity
and permission-mode readback on both `/scratch` and `/sealed`, independently
for the CLI oracle and rendered fixture. Checked block-size/count arithmetic
must yield the authored 4096 bytes, and each mode must be 0700 before recording
a positive outcome. Offline wrong-size/mode and malformed-readback tests do
not establish native conformance.

The 57-shape draft adds explicit zero and false values, unlimited limits,
IPv6 resolver entries, alternative IPv6 and ephemeral port combinations,
capability addition, and local/none logging. These definitions are not native
compatibility evidence until all four exact Engine lanes pass and their results
are independently reviewed. This checkpoint still does not cover every finite
field alternative required to admit aggregate capabilities; only the exact
closed shapes actually asserted can support a future admission decision.
Rootless or older-API limitations discovered by the probes require an
independently reviewed negative outcome before the expected set may change.
BoxFerry's six application routes and a coherent release gate remain separate.

Run `./scripts/check-all.sh --check` for the complete offline gate: format,
Clippy, a locked all-target check under the minimum Rust release declared by
`Cargo.toml`, unit and documentation tests, policy tests, and documentation build.
The MSRV check installs the exact official Rust distribution through rustup
when it is not already available; its failure stops the gate. PR, main,
validation-dispatch, and release workflows all call this same gate.
`--fix` runs the same checks after formatting. The VS Code task calls the fast
format/lint script; PR and main CI call the complete offline gate. PR checks
never run the privileged native matrix or claim native Engine evidence.

The native workflow lanes are `debian11-rootful`, `debian11-rootless`,
`upstream-rootful`, and `upstream-rootless`. Each has its own rootful outer Podman container, inner
Docker daemon and storage volume, and independent hosted CI job. Debian 11's
distribution `docker.io` package revision is asserted separately from the
Engine release reported by `/version`. Engine releases are matched exactly;
the Debian lanes allow only the Debian `+dfsg1` suffix, not a version prefix.
The rootless lane runs a rootless inner
daemon; rootless outer Podman nesting is not assumed.

The #28 selector and typed-observation fixtures are offline contract checks.
The separate ignored `live_network_membership_matches_engine` native test runs
after the existing selector test and before evidence emission. It creates two
exact run-labelled active peers on the owned bridge, acquires only one exact
container ID, and compares protected typed membership to direct network GETs
before and after acquisition. The unselected peer must not gain a container
inspect request. After stopping that peer it repeats the comparison to the
actual Engine response without assuming that stopped peers remain listed.
Only successful assertions and verified fixture cleanup append
`NetworkActiveMembership`, `NetworkStoppedMembershipBoundary`, and
`ContainerInspectIdOracle` to the sixteen baseline source probes. The last
marker follows comparisons of the protected container inspect ID with both the
canonical narrowed-selection request ID and the direct inspect `Id` for exact
ID, name, prefix, and label selectors. The emitter requires all nineteen; a
failure cannot emit partial source evidence. These are source-observation
checks, not ownership, atomic-snapshot, or target-capability admission. All
four exact lanes still require genuine passing runs and independent review
before compatibility claims.
They cover protected predicate replay closure, canonical list identities,
inspect response binding (including network-name fallback), explicit resource
roots, typed inspected network IDs distinct from fallback names and empty
endpoint IDs, and effective user namespace availability. Offline decoder tests
cover the typed container ID's runtime origin, privacy, and fail-closed invalid
identity cases, while a matching noncanonical caller-assembled capture remains
accepted; acquisition tests retain the four-request narrowed-name path.
The network-inspect membership fixtures additionally check protected canonical
container-ID keys, entry versus `Name` availability, the 4096-entry bound,
malformed-value diagnostics, and an unselected active member that does not
expand container inspection. These are pure decoder contracts, not proof of
Engine behavior. Independent source proof must compare a selected and an
unselected active attachment, then a stopped-peer boundary, against direct
network-inspect responses in all four exact lanes. A stopped peer's absence
from an active snapshot cannot establish that no other resource is shared.
They do not extend reviewed profile claims until fresh independent native tests
cover each new source shape on the exact versions and daemon modes.

The #31 source test runs after the harness creates a selected container, a
decoy, and a separate two-loopback-binding port fixture in the same isolated
daemon. It checks discovery names, labels, and image, exact ID and name,
shorter literal prefix, label, explicit-all, and exact network and volume
roots against direct Engine GET oracles and fixed CLI fixture settings. The
Compose-style project label remains advisory metadata. Narrow selectors must
never inspect unrelated containers. The test checks exact host IPs and both
bindings, selected identity, mounts, environment, health, restart, and the
origins and availability of selected effective and runtime-assigned fields.
Offline tests retain exhaustive missing, null, empty, and redacted boundary
coverage; the native source list claims only the fields it asserts.
The lane manifest records an exact closed `source_probes` list only after this
ignored test passes; it contains no native values and does not add target
capability admissions. Existing reviewed manifests and the reviewed catalog
remain historical evidence for their original shapes. The new assertions need
genuine runs in all four exact lanes before a source compatibility claim.

The source test's `DaemonResourceSupportOracle` assertion compares typed
`MemoryLimit` and `SwapLimit` reports with the already saved independent direct
`/info` response. It reuses the existing acquisition, checks effective origin,
independent boolean/unavailable states, matching capture scope and rejection of
another capture's scope, and adds no request. Reported false stays bounded
source-environment evidence; true stays available but unverified, even when
separate effect evidence fails. Missing, null and explicit redaction remain
unknown. Neither the assertion nor its closed marker proves enforcement or
adds a capability or admitted shape. The baseline list contains the original
fifteen markers plus this new marker; membership completion retains its three
markers, and the emitter rejects the old eighteen-marker list. Historical
reviewed evidence bytes and catalogue admission remain unchanged. These are
new assertion definitions: genuine passing four-lane exact-candidate runs and
independent review are still required before source compatibility is claimed.
The direct oracle and acquisition are separate observations in time; matching
capture identity correlates typed evidence, not authentication or an atomic
snapshot. Offline helper tests check classification and value-free rejection
only. No operational pin or Renovate extraction path changes are introduced.

The created-volume label probe is a separate exact ignored library test,
`native_volume_label_tests::live_created_volume_labels_match_engine`. Each lane
runs it before manifest emission and reads its private, bounded
`NATIVE_VOLUME_LABEL_PROBES_PATH` file. The manifest records only the closed
`volume_label_probes` names: `VolumeCreateLabels`, `VolumeLabelInspect`,
`VolumeLabelPersistence`, and `VolumeLabelOwnershipCleanup`. These are
non-admission evidence; they do not add `VolumeLabels` or
`VolumeCreateLabels` to the reviewed capability catalog or its admitted shapes.
Native compatibility still requires genuine passing lanes and independent
review of the exact candidate evidence.

Each lane reads live Engine API version, info, container, network, and volume
responses. The harness creates only synthetic test resources and stores live
responses in a private temporary directory. The Rust integration test checks
bounded capture decoding without writing responses to the repository or CI
log. A rootful `/info` response without affirmative mode evidence remains
`Unknown` in the decoder. The target conformance test independently checks
that exactly one inner `dockerd` has effective UID zero for rootful or nonzero
for rootless, and requires positive rootless `/info` evidence before using a
test-local mode fact for planning. The gate also requires #10's live acquisition
test and an independent `native_target` test of #12's rendered request shapes
against Engine behavior.
The latter first checks independently created CLI resources and direct API
responses, including TCP/UDP traffic, before admitting capabilities scoped to
#10's actual observation. It applies only three allowlisted POST endpoint kinds
inside the isolated test daemon and checks the resulting resources, traffic,
mounts, environment, command, health, and restart behavior. Decoder-only
fixtures cannot establish this evidence. Native compatibility claims require
genuine passing lanes and independently reviewed evidence for the exact scope.

The target conformance test lives in `src/native_target_tests.rs` under
`#[cfg(test)]`; the exact-name runner selects its single ignored library test.
This lets the isolated harness use the crate-private scoped-fact validator
without exposing a public way to manufacture positive planning capabilities.
The module is included by the crate's `src/**` package rule but has no runtime
effect in a published library build. After its shape-specific assertions pass,
the test writes a private closed shape list. The manifest emitter checks that
list against the full catalog admission set before declaring positive outcomes.

The Debian guests are maintained test images published by containers#260.
Each contains native docker.io 20.10.5+dfsg1-1+deb11u2; the harness checks
that installed package revision separately from /version. The upstream
images contain Engine 29.8.1. No lane installs packages at runtime. Debian 11
is a historical compatibility baseline, not current security support.
The Debian rootless image needs --oom-score-adj=0 on its privileged rootful
outer Podman container for nested workloads. This lane explicitly disables
AppArmor for that already-privileged outer container only; the harness does
not change host policy. The Debian rootless lane additionally mounts its
task-owned outer data-root volume with suid,dev. Controlled independent CLI
probes showed the historical runc could not start a read-only named-volume
container when that outer mount instead had nosuid,nodev. The harness checks
the effective mount flags before native tests. The other three lanes keep
their default volume and AppArmor options. Their independent native runs
must pass with that unchanged setup; the historical lane's requirements
do not authorize broadening the other lanes' configuration.

Run one lane with ./scripts/native-conformance.sh <lane> on Linux with
rootful Podman through passwordless sudo, at least 8 GiB free, and access
to the pinned GHCR and BusyBox manifests. The script caps the nested daemon
at 4 GiB storage, 4 GiB memory, two CPUs and 512 processes. It bounds the
outer image pull to three minutes, monitors space during it, and prevents an
implicit second pull. The image's native launcher starts a Unix-socket
daemon. The harness binds a second Unix socket at `/dockerlens-native` into
its private temporary directory for explicit, local-only capture and requires
a host-side `/_ping` before proceeding. This path stays outside the rootless
launcher's `/run` copy-up. It exposes no TCP daemon port. The synthetic bind
fixture is writable inside this task-private directory so the rootless mapped
UID can exercise the rendered read-write bind mount. The separate read-only
bind assertion therefore tests mount behavior independently of host ownership.

Every image declares a Docker data-root VOLUME. The harness disables
automatic image volumes and mounts exactly one task-labeled named volume at
the declared data root. It checks the mounted volume after launch; an
unexpected anonymous or extra volume fails the lane. A watchdog samples the owned volume and Podman
storage every five seconds with the same bounded sampler used for the final
check. It retries only exact disappearing descendants beneath the unchanged
owned root, at most twice after the first attempt. A volume above 4 GiB, free
space below 2 GiB, or elapsed time above 30 minutes terminates the lane immediately;
malformed or unverified measurements fail closed. The normal ownership-checked
cleanup then runs. This isolated nesting setup does not
demonstrate compatibility with restrictive data-root mount flags or an
enforcing outer AppArmor profile. Failure diagnostics show the exact native test,
exit status, numeric libtest summary, fixed native marker, and closed
acquisition-error category where applicable. Daemon startup failures show
bounded container state and a fixed category. Raw daemon logs and API
responses remain private; unknown failures are unclassified. The read-only
volume shape uses fixed phase and write-exit-category markers to pinpoint
failures without publishing daemon responses or volume contents. Its
API-created container uses the independent CLI start probe to report both a
closed component category and a separate closed errno/reason token for a
failed start before checking the live read-only mount behavior.

After every required native Rust test passes, a workflow lane writes one
sanitized JSON manifest containing the exact candidate SHA, image
tag and digest, observed Engine release and advertised API bounds, the
selected acquisition API, rendering API, reported containerd and runc
component versions, daemon mode, installed Debian
package revision where applicable, and the ten tested target capability
names and the closed renderer shapes exercised by the target test. Acquisition
selects at most API 1.49 even if the daemon advertises
a newer API; rendering uses the observed advertised API. The workflow
uploads only this JSON as dockerlens-native-<lane>, with a fixed <lane>.json
filename. Artifact upload failure fails the lane. A reviewer must bind
the exact artifact bytes, run attempt, and candidate SHA before adding
positive catalog evidence. No local harness definition or green offline
check creates that evidence. The manifest records Engine identity and tested
shapes, not outer mount or AppArmor settings; the reviewed exact-candidate
harness and genuine passing lane run must establish those test conditions.
It deletes its exact named container, volume, and temporary files after
success, failure, or catchable termination. SIGKILL, host failure, or hard
runner shutdown can prevent cleanup; inspect the printed exact names and
`io.dockerlens.native-run` labels before manual removal. Never global-prune.
The validation-only `scripts/native-presence.py` helper gives preflight and
cleanup a closed `present`/0, `absent`/1, `unknown`/2 protocol. Only an actual
completed native exit 0 or 1 with completely empty combined stdout and stderr
proves presence or absence. Warnings (including exit 0), diagnostics on exit 1,
other exits, timeout, cancellation, overflow or unverified group termination
are unknown. The helper streams into private mode-0600 evidence with a combined
16 KiB cap, observes exit without reaping the group leader, then terminates its
group and verifies teardown before classifying. The helper and its outer
timeout share the Podman client's root privileges where sudo is used. A separate
six-second timeout with a two-second kill fallback bounds the actual client
inside its teardown group, even if the helper is killed.
This applies to the daemon container, sidecar, network and volume, including
all positive absence readbacks and generated-name preflight. The existing inner
Docker exact-name cleanup listing uses the same helper: only completed empty
exit 0 on both streams establishes absence. No query or mutation is added.
Unknown presence retains the private run directory for manual review, attempts
label-verified removal where possible, and fails teardown even when later
readback succeeds. Raw diagnostics never reach logs. Mocked regression tests
exercise these outcomes without launching a native runtime; they establish no
new compatibility or capability admission.
Each cleanup command retains its eight-second deadline and two-second kill
fallback; for elevated Podman the timeout also runs under sudo so it can signal
the root-owned client. Only a task-named container with the matching run label
is removed with `--force --time 0`: Podman's default ten-second stop grace
otherwise exceeds that command budget. The daemon container and sidecar are
removed before their exact network and data volume, which are never force-removed.
Removal errors expose closed categories, with raw Podman output suppressed.
The success summary is printed only after all cleanup and absence readbacks
pass; a manifest written earlier is not passing lane evidence by itself.

Release validation checks the supplied full SHA against current `main`, runs
the complete gate, runs all four native lanes independently, then rechecks
current `main`. Its aggregate gate fails on any failed, skipped, or cancelled
job. There is no publication or deployment job. The four native lanes run on
main push and exact-candidate release validation, not on any PR. PRs run the
complete offline gate and their aggregate explicitly reports offline-only
evidence. Before marking the #13 harness PR ready, use the trusted-main
validation-only dispatcher below to run all four native lanes against its
exact reviewed draft head; passing PR CI alone is not native compatibility
evidence. The main-push and release native gates remain mandatory after merge.
Their time and resource budgets need review after genuine hosted runs. A lane
definition is not a compatibility claim until its native evidence passes.

The validation-only `Reviewed native validation` dispatcher is bootstrapped
before the #13 native suite. It does not make the still-failing release gate
pass or establish compatibility on its own. With the dispatcher on trusted
`main`, a maintainer can review the exact head and bounded native
harness of an open, same-repository PR (including a draft), set `pr_number`
and `reviewed_sha` to its number and full lowercase 40-character head SHA,
then run:

```sh
gh workflow run native-validation.yml --ref main \
  -f "pr_number=$pr_number" -f "expected_sha=$reviewed_sha"
```

The dispatcher requires current write/maintain/admin permissions for both the
original and rerun actors, validates the current PR head and repository identity,
runs the exact candidate's complete offline gate, and only then runs four
independent native lanes from that SHA. Each lane rechecks admission from
trusted `main` before candidate checkout, including when only one job is rerun.
The final aggregate fails if admission, offline checks, any lane, or the final
PR-head and actor recheck fails or is skipped. API uncertainty, including a
token that cannot read collaborator permissions, fails closed and must not be
bypassed. No PR event triggers this privileged workflow. It does not merge,
publish, release, or deploy. A draft PR stays unmergeable during validation;
after all four lanes genuinely pass, review the exact head and mark it ready
before applying ordinary required-check and mergeability rules. For #13,
its native script remains only in the candidate branch until its own
implementation is verified and merged.
Record the manual run URL and exact candidate SHA in the PR: the dispatch
runs on `main` and is not an automatic required check on the PR head.

DockerLens [#42](https://github.com/Strukturpiloten/docker-lens/issues/42)
owns the canonical reviewed-PR admission script. With `EXPECTED_REPOSITORY`
absent, it retains DockerLens's native-validation repository policy. A trusted
workflow may set literal `EXPECTED_REPOSITORY=Strukturpiloten/boxferry` when
BoxFerry application validation invokes an immutable DockerLens commit
checkout; the event repository, open PR's head and base full names and numeric
IDs, and both actors must then all match BoxFerry. Unknown values and CLI
arguments are rejected before any API request. BoxFerry
[#369](https://github.com/Strukturpiloten/boxferry/issues/369) owns the
immutable consumer pin and manual-review `github-digest` Renovate ownership;
this producer change adds no pin or native workflow gate. Both consumers need
independent validation before the shared admission rollout is complete. This
helper never admits a release or publication operation.

The intended client platform is Linux. Mac client compatibility is not
validated by this scaffold. There is no macOS or Windows runner requirement.

The fake Unix-socket acquisition tests verify request framing, privacy,
deadlines, cancellation, and budget failures without a Docker daemon. The
ignored `live_read_only_acquisition_matches_oracle` test is invoked only by the
isolated native Engine harness. It reads that harness's explicit socket and
private direct-API oracle files to compare selected container, network, volume,
version, and mode semantics. A fake-socket pass is not rootful or rootless
Engine compatibility evidence.

The ignored `live_existing_volume_prerequisite_matches_engine` library test
adds a separate, exact native lane check for ADR 0008's existing named-volume
target. It seeds a task-owned, labeled volume, checks the rendered external
prerequisite and exact read-only/read-write mount requests, and verifies seeded
data access, write rejection on the read-only mount, and persistence after a
consumer container is removed and recreated. A missing volume must fail the
harness's direct Engine GET preflight before any rendered POST; Engine container
creation can otherwise create a missing named volume implicitly. The test
uses only synthetic resources and label-verified cleanup. Each passing lane
records six closed `volume_probes` in its sanitized manifest, sourced from a
bounded private test file; raw volume names, data, and API responses remain
private. These probes are non-admission evidence: they do not modify the
historical reviewed catalog or its schema, establish that an arbitrary
destination volume exists or is populated, or authorize copying or applying
data. Fresh, independently reviewed rootful and rootless runs on every claimed
Engine profile remain necessary before an existing-volume compatibility claim.

DockerLens #49 adds a separate ignored `live_created_volume_labels_match_engine`
test for created-volume labels. Offline tests enforce protected key/value,
count, aggregate-byte, duplicate and exact-wire boundaries, including unchanged
unlabelled requests and label-free external prerequisites. The native probe
compares an independent CLI-created volume with the inert labelled request,
including empty and non-ASCII/escaped values, then checks direct Engine inspect
labels, data persistence across task-owned containers, ownership labels and
exact cleanup. Its closed results are not catalogue admission: all four exact
lanes must pass and be independently
reviewed before an exact capability claim. Historical unlabelled `NamedVolume`
evidence cannot prove `VolumeLabels`.

The evidence emitter's bounded #31 prerequisite checkpoint maps complete,
validated existing native proof files to exactly three additional raw groups:
`VolumeExternalReference` to `ExternalVolumeReference` after all six volume
probes, `VolumeLabels` to `VolumeCreateLabels` after all four volume-label
probes, and `NetworkExternalReference` to `ExternalNetworkReference` after all
twenty-two network probes and the separate passing internal proof. The existing
`NetworkInternal` group remains separate. Missing, partial, duplicate, unknown,
or failed proof inputs reject the complete manifest; no probe name alone
admits a capability. This changes only future raw `capability_outcome` and
`admitted_shapes` emission, not the source nineteen-marker set, historical
records, schema or reviewed catalogue. Earlier #67 raw records did not emit
these three groups and cannot be retroactively treated as having admitted
them. Fresh exact-candidate four-lane runs, independent review and separate
new-cohort admission remain required. ADR 0010 additionally requires the six
BoxFerry authored fixture mappings and consumer rehearsal before a positive
production `VolumeLabels` record; those gates remain pending. No arbitrary
destination prerequisite, data availability, application compatibility or
release is established by this checkpoint. No native request, operational pin,
dependency or Renovate extraction path changes are introduced.

## Bounded container process identity proof (#74)

The exact ignored `live_container_process_identity_matches_engine` test is a
separate eleventh mandatory native check; none of the existing ten checks is
removed, filtered, retried, or made optional. Its only authored setting shape
is numeric container user `1000:1000` and the already-existing `/tmp` directory
in the unchanged pinned BusyBox fixture. An independently authored Docker CLI
create and the ordinary crate-private sealed planner/inert renderer each create
one labelled container. Direct Engine inspection checks both Config fields,
the command and inherited entrypoint before either starts. Their actual PID1
workload runs `id -u`, `id -g`, and `pwd -P`; exact output must be numeric
`1000`, numeric `1000`, and `/tmp`, followed by inspected exited state, not
running, and exit code zero. Docker exec with a user override is not an identity
oracle. Rootful/rootless daemon mode and exact Engine/API context are checked
separately: the container process account is not the daemon or host account,
even where their numeric values coincide. This proves no named-user/group
lookup, arbitrary directory creation or ownership, supplementary groups,
host-mapped UID, or general user-namespace guarantee.

Each role is bound through its exact run-owned name and literal ownership
label to a distinct canonical immutable ID. Cleanup revalidates that binding,
deletes by ID only, and requires genuine direct Engine 404s for both names and
both IDs twice. A failed assertion, timeout, unresolved ownership or cleanup
failure cannot produce positive proof. Bounded commands share the runner
deadline, reserve cleanup time, and keep native stdout/stderr private; closed
markers and selected numeric panic locations alone may reach logs. Abrupt
SIGKILL or host failure can prevent cleanup and is not positive evidence.

Only after every assertion and cleanup succeeds does the test create a fresh
mode-0600 private proof bound to candidate SHA, lane, daemon mode, rendering API
and run token. The emitter requires one bounded regular owner-private,
single-link, non-symlink file, exact fields and marker order, distinct IDs,
exact names/owner, and every configured/runtime/cleanup result. Missing,
partial, failed, duplicate-key, stale, malformed or unbound files reject the
entire manifest. This is trusted-harness provenance, not cryptographic
attestation against a privileged writer able to replace a valid proof.

Future sanitized manifests add only the closed `identity_probes` group:
`ContainerUser`, `ContainerWorkdir`, `ContainerNumericUidGid`,
`ContainerProcessWorkingDirectory`, and `ContainerIdentityOwnershipCleanup`.
Raw IDs, names, owner labels and run tokens are not emitted. These markers do
not extend `capability_outcome`, `admitted_shapes`, production capabilities or
the reviewed catalogue. The schema's reviewed-record root remains unchanged;
dedicated `$defs` describe the separate raw group and private proof. Historical
evidence is preserved byte-for-byte. Fresh exact-head four-lane success and
independent review are still required; this source checkpoint claims neither
native compatibility nor #39 completion. In particular, #39 / PR #73's failed
run [`37218370132`](https://github.com/Strukturpiloten/docker-lens/actions/runs/37218370132)
remains failed, with its resource/device assertions and cleanup requirements
unchanged. No cgroup/device workaround or production admission is delivered.

The canonical harness is shared by DockerLens local/main/dispatch/Release
native execution; the offline gates also exercise its regression tests. The
consumer audit found no external raw-manifest parser: BoxFerry reads the
digest-bound reviewed records and sealed catalogue and owns its receipts and
application tests; other workflows transport/upload artifact bytes. No
cross-repository API or consumer edits are needed. All five existing native
image/fixture pins remain in `scripts/native-conformance.sh`, with unchanged
Renovate ownership, extraction paths, grouping and approvals; no dependency,
downloaded tool, or operational definition is added or moved.

The #39 container checkpoint remains an additional required emitter input,
with its exact schema, lane-specific API boundary and 57 closed outcomes.
Its `container_probes` do not extend the raw capability groups or admit a
production capability. The reconciled emitter preserves the nineteen source
markers and validates every proof file, including container outcomes, before
writing a manifest. All four synthetic lane regressions check these contracts
together; duplicate network-proof keys at either object depth fail even when
the final key would hide a failure. These offline tests do not establish that
any native lane has run or passed.
## Reviewed target-profile records

The compiled catalogue selects four reviewed records from native run
[`37209363801`, attempt 1](https://github.com/Strukturpiloten/docker-lens/actions/runs/37209363801/attempts/1),
of source candidate `702910b003daae58babd540d7ba3de4998275feb`. This separate
#68 cohort admits the original ten capabilities/twenty shapes plus exactly
`VolumeExternalReference` / `ExternalVolumeReference`,
`NetworkExternalReference` / `ExternalNetworkReference`, and
`NetworkInternal` / `InternalBridgeNetworkCreate`: thirteen capabilities and
twenty-three shapes for each exact lane identity. The original four records
from run `36451790131`, attempt 1, candidate
`d51d7dbfda5ee6f8fefe92605afe8baea3dc504e`, and all of their raw bytes remain
preserved. They retain their original ten/twenty admissions and are not
relabeled as #68 evidence. The public catalogue still has four identities,
selected from the new cohort rather than duplicate old/new profile entries.
Exact raw manifests and reviewed envelopes are checked in under
`docs/evidence/native/sha256/` and `docs/evidence/reviewed/sha256/`. Each
changed candidate and release needs fresh complete and four-lane native gates.
Each record must conform to
[`native-evidence.schema.json`](native-evidence.schema.json). Its lane and exact
identity bind the distribution package revision (or upstream origin), reported
Engine release, advertised maximum API, negotiated acquisition API, tested
rendering API, and rootful or rootless mode. The run URL includes the attempt
number. `candidate_sha` names the source tree actually executed by that run.
The schema recognizes the capability and renderer-shape names already defined
by DockerLens, but recognition is not admission. The compiled catalogue
requires exactly the new cohort's thirteen capabilities and twenty-three
shapes per lane. `VolumeLabels` / `VolumeCreateLabels` remains excluded even
though #68's raw manifests contain positive label proof. ADR 0010's six
BoxFerry authored fixtures and consumer rehearsal still gate that separate
admission. Other topology, resource, security and container-setting groups
remain unadmitted; the broader #31, #44 and consumer milestones remain open.
A later cohort must explicitly bind its candidate SHA, source run, each lane's
identity and content digests, and the complete
`NativeCapabilityShape::required_for` group for every positive capability.
Each positive reviewed shape list must exactly match the linked raw manifest's
admitted shapes, and its raw capability outcome must be `available`.
Duplicate or missing lanes, partial groups, and shapes belonging to another
capability cannot establish a catalog claim. Preserve historical evidence
bytes unchanged when preparing that separate review.

The new envelopes were generated from the four unmodified #68 artifacts named
`dockerlens-native-<lane>`, each containing `<lane>.json`. SHA-256 was computed
over each downloaded artifact file's exact bytes with `sha256sum`; the raw file
was retained verbatim at that digest's native evidence path. Each envelope
derives upstream versus Debian build provenance from the observed lane and
exact package field, copies Engine, advertised/acquisition/rendering APIs and
mode from its linked raw manifest, binds the actual source
candidate and run attempt above, and selects only the closed thirteen groups
whose ordered shape lists exactly match those raw positive outcomes. It adds
no default identity or inferred probe-to-capability admission. The envelope is
UTF-8 JSON with two-space indentation and one final newline; its independent
SHA-256 names the reviewed file and compiled evidence key. The cohort
specification in `tests/test_reviewed_catalog.py` pins all four raw and
reviewed digests and checks both old and new cohorts, source binding, complete
`required_for` groups and the exact compiled selection. Historical source and
reviewed files were neither regenerated nor rewritten. No operational pin,
manager ownership or Renovate extraction path changes are introduced; these
content-addressed historical evidence files remain outside update streams.
`native_manifest_artifact_name` identifies the run's per-lane artifact;
`native_manifest_sha256` is the SHA-256 of its sanitized JSON manifest
emitted by the native harness after success; that manifest contains observed
image, package, runtime, API, and capability outcomes, without captured user
or daemon values. The proposed record lists each capability and the specific
request shapes its native test admitted. A generic successful lane does not
authorize every shape of a capability.

The #13 artifact is named `dockerlens-native-<lane>` and contains exactly
`<lane>.json`. Its fixed metadata includes the image tag and digest, actual
Engine release and maximum/minimum APIs, negotiated acquisition and rendering
APIs, Debian package revision where applicable, containerd/runc component
versions when reported, and the ten tested capability outcomes. Keep the
manifest bytes available for independent digest verification.

For the initial Debian 11 lane, the record must name the `docker.io` package in
the `debian11` distribution at revision `20.10.5+dfsg1-1+deb11u2`, with
reported Engine `20.10.5+dfsg1` and all three API dimensions at 1.41. The
upstream lane is limited to Engine 29.8.1; its API values must come from the
run. A positive catalog fact requires every closed renderer shape for its
capability. In particular, `PortPublish` requires separate fixed TCP and UDP
evidence, named volumes require create and both mount access modes, and restart
policy requires all four variants including limited and unlimited on-failure.
Any untested shape leaves that entire capability unadmitted. The #13 manifest's
coarse `capability_outcome` alone cannot fill `admitted_shapes`; reviewers must
trace each claimed shape to native assertions in the exact run. Unsupported
`HostNetwork` and `UserNamespace` cannot become positive catalog facts.

After independently checking the run, lane result, candidate SHA, native
manifest digest and fields, review the proposed record and preserve its exact
UTF-8 bytes in the repository. Compute SHA-256 over those bytes; that digest is
the catalog's `CapabilityEvidenceKey`. The digest is deliberately outside the
record, avoiding a self-reference. The public `NativeEvidenceReference`
retrieves the source run, candidate, native manifest digest and record digest
for an admitted profile. Its constructor checks only syntax and cannot add a
catalog entry. A checked-in historical native run can establish source
evidence for a later catalog commit; each changed candidate and release still
needs fresh complete checks and native validation. Never substitute the historical
source SHA for the final candidate SHA or infer an API version from a release
label. Public resolver and inert rendering tests cover the admitted records.
