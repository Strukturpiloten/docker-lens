# In-memory outer lifecycle custody source component

Status: **unwired source prerequisite, not native or boundary qualification**.
Continues DockerLens #39/#31 under #3. The canonical harness, PIDs-v2
producer/readers, mandatory native invocations and capability selection remain
unchanged.

`scripts/native_outer_lifecycle.py` defines a single-use custody owner and an
injected `RuntimeOps` protocol. There is no concrete runtime adapter, command
execution, installed CLI, report/proof writer or publication path. Its tests
use fake operations and temporary files only. Four independently authored lane
representatives are not the actual pinned images' launch defaults or execution.

## Independent inputs and lifecycle

Frozen launch expectations contain explicit original argv, environment, numeric
user/groups, working directory, complete standard mounts and exactly two user
mounts. They must not be copied from the OCI input being checked. The staged
profile requires independently supplied Linux/local/rootful Podman 4.9.3,
crun 1.14.1, systemd and cgroup v2 facts. Passing caller-authored facts is not
actual profile admission or binary attestation. An explicit `machine.slice`
creation expectation binds `machine.slice:libpod:<returned-ID>`; it is not
inferred from the inspected file or an assumed host default.

The normalized inspect dataclass is a future adapter contract, not an invented
Podman JSON schema. The coordinator binds the exact returned ID, name, image
digest, owner, log driver/path, original init PID, Created state and no previous
start/restart/restore. It holds and checks effective OCI before starting that
same ID once, then requires Running and pins a nonzero StartedAt value. Wrong
ordering, drift, cancellation or exhaustion permanently poisons the owner.

Effective OCI validation checks the independent launch/mount expectations,
private new PID/mount/cgroup namespaces, exact systemd cgroup path, subgroup
`container`, empty delegation, exact test-only sandbox handler selector, absent
hooks/unified overrides and exact resource ceilings. Bounded immutable expected
resource extras allow complete memory/cpu/pids sections, including independently
expected swap fields; mandatory ceilings cannot be overridden. Keys and scalar
types/values must match exactly, with no inferred native support. The selector is not
Kubernetes product support. Parsing is bounded, rejects duplicate keys and
nonfinite constants and never turns authored observations into native proof.

## Held original objects

The OCI path comes only from the exact-ID normalized observation. Every path
component is opened without following symlinks and retained; the bounded
regular file must be root-owned, single-link and not group/world writable.
Rechecks bind its original inode, metadata and complete bytes, refusing even an
identical-content replacement. Ancestor directory identity/ownership/modes stay
bound, but legitimate sibling writes do not fail merely for changing directory
timestamps.

The log is exclusively created and held from birth as caller-owned 0600 under
the caller's private 0700 run/diagnostics directories. It may append but may not
observably shrink, change ownership/mode/link count or replace the held/named
object. Capture examines at most 2048 leading bytes and retains the exact full
physical prefix ending at the first complete stdout bootstrap frame. The
existing strict decoder checks that prefix; unrelated later daemon output is
not promoted into evidence or required to stay immutable. This is not a claim
of detecting every later duplicate or a truncate-and-regrow event between reads.

Private candidate data stays immutable and in memory. The owner and its live
descriptors must span future independent consumers and final rechecks. There
is deliberately no serialized-success or standalone receipt API.

## Budgets, cleanup and remaining integration

One externally supplied absolute startup deadline allows at most 120 seconds;
it is never reset per operation. Later custody and cleanup use separate
externally supplied absolute deadlines within the caller's existing lane
watchdog. Component call/I/O/source-byte limits are defensive caps, not extra
native allowances. Actual integration must account for every added call and
byte within existing budgets; the 180-second PIDs deadline and 46-second
cleanup reserve are unchanged.

In-process failure or injected cancellation attempts to close owned descriptors
and attempts only exact-identity cleanup
through the injected adapter's explicit existing cleanup deadline. A future
adapter may return cleanup completion only after ownership checks, removal and
verified absence; fake return values establish none of those native facts.
Unknown create completion and failed cleanup remain explicit caller obligations.
The caller owns run-directory disposal; there is no global prune, permission
widening, guessed runtime-state path or host configuration change. Descriptor
close errors are best-effort here, not independently verified disposal. No OS
signal/process-group adapter exists yet; unhandled termination, SIGKILL or
machine loss can prevent cleanup. Those integration gaps cannot become a
cleanup-dependent success claim.

Activation must land together: canonical create/init/start, actual profile and
launch/default-mount derivation, metadata read access, original runtime-input
custody, Rust original-controller rechecks, two independently bounded context
handoffs, mandatory independent reader, every existing positive predicate and
all 37 reader-coordinate witnesses. The actual serialized main/total proof
must fit 15360/16384 bytes; this larger in-memory candidate is not that wire
format and makes no fit claim. Final held-object checks and existing cleanup
gates remain mandatory before any success publication.

Rootless systemd/user-manager/delegation fixtures, genuine four-lane/28-test
execution, actual six-authored-fixture consumers, real application migrations,
package checks and protected merge remain open. No release is ready/requested.

No canonical local/main/dispatch/release consumer changes yet. Other Lens
products and the website have no private custody-helper consumer; BoxFerry's
separate consumer/application gates remain. No dependency, operational pin or
canonical pin location changes, so existing Cargo/toolchain/Action and five
native-image Renovate ownership/extraction/grouping remain unchanged.
The exact Podman/crun strings are source-reviewed compatibility predicates, not
new installation pins or an admitted hosted runtime. They are intentionally not
automatic release-update streams; a changed actual runtime requires new review.
