# Bounded outer broker protocol source component

Status: **unwired source prerequisite, not a privileged broker or native proof**.
Continues DockerLens #39/#31 under #3. The canonical harness, lifecycle helper,
PIDs producer/readers, all 28 native invocations and capability catalogue are
unchanged. No runtime adapter, sudo invocation, CLI or executable helper exists.

## Intended split and trust boundary

Future activation separates the caller-owned log/proof coordinator from one
long-lived root owner of the original OCI file and ancestor descriptors. This
module supplies only the bounded communication primitive between those roles.
It does not authenticate peer credentials, helper installation, ownership of
the OCI file, actual launch defaults or resource removal. The real broker must
derive the original OCI path from its own verified exact-ID observation; this
protocol has no arbitrary command, path, OPEN or daemon-query operation.

Both endpoints receive independently established immutable Binding values:
session, exact Git candidate, run/attempt, launch digest and image digest. A
message or handshake cannot supply trusted expectations. Numeric run/attempt
labels do not authenticate GitHub or replace the separately bound native
name/run-owner launch expectations. Caller-supplied pipe
ends must have exclusive anonymous-pipe provenance; FIFO metadata alone cannot
prove that provenance. Descriptor ownership transfers to the endpoint and
descriptors are made non-inheritable/nonblocking. No namespace, extra mount,
socket, mailbox or evidence sidecar is introduced.

## Closed messages and state

The wire uses a four-byte big-endian length and canonical ASCII JSON with exact
envelope keys/types. Every message binds the independent identity, direction,
sequence, closed verb and exact container ID. Only the first create request
has a null ID. Its valid reply pins the returned full ID for every later verb.
The closed order is create, initialize, start, then recheck; teardown is also
allowed after a known create. No reconnection, retry or reinitialization exists.

Initialize returns at most65536 original OCI bytes once, losslessly in bounded
canonical base64, with typed metadata, complete-byte digest and init PID. These
are assertions from the peer, not proof it actually holds the original inode.
Start pins nonzero StartedAt and the init PID. Rechecks retain that PID/time
and original digest. They do not replace live original-object rechecks, the
mandatory independent reader or final caller-owned log custody.

No message authorizes publication. An Empty teardown acknowledgement explicitly
retains teardown_acknowledged_unverified; it never establishes verified native
absence. Unknown create completion and known live-ID obligations survive faults.
Actual exact-owned cleanup and independently observed absence remain obligations
of the future runtime owner, including its EOF/cancellation/timeout handling.

## Bounds, failure and integration holds

A caller-owned Ledger debits frames, readiness waits, read/write calls and wire
bytes, never allocating a new allowance per endpoint or request. Caller-supplied
startup/custody/cleanup/watchdog deadlines are absolute and never renewed. Idle
broker reception may use the existing cleanup reserve, but a decoded non-cleanup
verb must still meet its own original phase deadline before dispatch.

Tests may share one conservative in-memory ledger. That object does not become
shared memory between OS processes: real cross-process aggregate enforcement
and accounting for runtime children remain unwired integration requirements.
The90000-byte frame cap accommodates original OCI transfer in private memory;
it does not enlarge the15360-byte main/16384-byte total private proof limit.

EOF, truncation, malformed/oversize input, wrong identity/sequence, exhausted
budget, blocked-pipe deadline, cancellation or clock drift permanently poison
and close the endpoint. Errors and default object representations do not print
protected bytes. FD closure is best-effort, not authenticated resource cleanup.
No actual peer supervision or installed privilege policy is established here.

Independent controls use authored envelopes, actual anonymous pipes, fake
clocks and temporary threads only. They exercise maximum-size transfer,
canonical encodings, malformed/replayed input, deadlines, cancellation,
backpressure and cleanup obligations. They are not native execution or image
compatibility evidence.

Activation still requires the real broker/coordinator, independently derived
image/create expectations, authenticated original controller objects even if
PID1 relocates, both bounded producer/reader/emitter handoffs and final checks.
All37 coordinate witnesses, positive predicates, two mounts and existing
120s startup/180s PIDs/46s cleanup/call/I/O/proof budgets remain mandatory.
Rootless delegation fixtures, fresh genuine4x28 native tests, real consumers,
all application suites, package checks and protected merge remain open. Host
capture is deferred; no release is ready/requested.

No shared workflow, native invocation, dependency, operational pin or canonical
pin location changes. Existing Renovate manager/extraction/grouping ownership
is unchanged; no other Lens or BoxFerry product consumes this private helper.
