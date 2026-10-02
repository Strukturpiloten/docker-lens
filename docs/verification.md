# Verification

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
after the exact ignored test passes; it does not extend
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
`InternalBridgeNetworkCreate` shape to raw lane evidence. The compiled catalog
and historical evidence remain unchanged until a separate review binds fresh
four-lane artifacts. This test adds no dependency, image, action, or tool pin,
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
test may run at most four independent, task-owned controls with the same image
and command: no resource/security flags, memory limit only, PID limit only,
and device mapping only, in that order. Each inspected `HostConfig` must match
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
baseline, memory, PID-limit, or device role. The exact runner exposes at most
four complete, allowlisted records alongside the original last global body
diagnostic. These remain lexical mentions, not an Engine cause or capability.

The startup-only `native-cgroup-diagnostic.py` helper reads cgroup context
within the exact run-owned outer container. One five-second monotonic deadline
and one cumulative 8 KiB bound cover private stdout and stderr combined across
all operations. The time counts inside the unchanged 30-minute outer deadline;
the helper runs before the unchanged 180-second exact-test deadline and
90-second control/cleanup reservation. It validates the running outer
container's immutable ID, exact name, ownership label, PID, and start identity
before and after. Every elevated Podman operation, including both inspections,
runs under a root-owned TERM/KILL timeout with teardown time reserved inside
the original deadline. Cancellation or overflow waits for that bound rather
than treating an unprivileged signal or an exited sudo monitor as proof that
root descendants stopped. Local unprivileged groups are killed and reaped;
both private pipes close even if signaling or waiting fails. Guest reads also
have their own bounded timeout; cancellation,
overflow, read errors, or identity changes produce closed unavailable states.
No captured bytes, paths, PIDs, limits, or subprocess errors are printed.

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
requires the exact nonzero UID from one validated local `docker` account
entry, without assuming UID 1000. The account and effective UID are rechecked
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
`ContainerInspectIdOracle` to the original fifteen source probes. The last
marker follows comparisons of the protected container inspect ID with both the
canonical narrowed-selection request ID and the direct inspect `Id` for exact
ID, name, prefix, and label selectors. The emitter requires all eighteen; a
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

The created-volume label probe is a separate exact ignored library test,
`native_volume_label_tests::live_created_volume_labels_match_engine`. Each lane
runs it before manifest emission and reads its private, bounded
`NATIVE_VOLUME_LABEL_PROBES_PATH` file. The manifest records only the closed
`volume_label_probes` names: `VolumeCreateLabels`, `VolumeLabelInspect`,
`VolumeLabelPersistence`, and `VolumeLabelOwnershipCleanup`. These are
non-admission evidence; they do not add `VolumeLabels` or
`VolumeCreateLabels` to the reviewed capability catalog or admitted shapes.
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
Podman existence-query errors are not treated as absence: cleanup attempts
label-verified removal where possible, reads back exact resource absence, and
still fails the lane for review when absence cannot be verified.
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

## Reviewed target-profile records

The catalog contains four reviewed records from native run `36451790131`,
attempt 1, of source candidate `d51d7dbfda5ee6f8fefe92605afe8baea3dc504e`.
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
by DockerLens, but recognition is not admission. The compiled historical
catalog still requires its exact ten capabilities and twenty shapes per lane.
A later cohort must explicitly bind its candidate SHA, source run, each lane's
identity and content digests, and the complete
`NativeCapabilityShape::required_for` group for every positive capability.
Each positive reviewed shape list must exactly match the linked raw manifest's
admitted shapes, and its raw capability outcome must be `available`.
Duplicate or missing lanes, partial groups, and shapes belonging to another
capability cannot establish a catalog claim. Preserve historical evidence
bytes unchanged when preparing that separate review.
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
