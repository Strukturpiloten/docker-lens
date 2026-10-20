# Connected outer broker protocol

Status: connected validation-source implementation; complete-path accounting,
fresh complete gates and genuine native qualification remain pending. See
[ADR 0033](decisions/0033-original-outer-custody.md). This is neither a product
daemon client nor a deployment mechanism.

## Owners and independent expectations

The unprivileged canonical coordinator exclusively holds the root broker pipes.
A shell relay and short-lived phase proxies carry only closed requests. Producer,
mandatory reader and optional emitter receive bounded private stdin contexts,
never broker descriptors, arbitrary environment maps or context sidecars.

One root owner holds the original OCI inode and ancestors from initialization
through final cleanup. The caller owns its original log inode from birth;
diagnostics adopt a duplicate. Replacing a pathname or moving PID1 cannot rebase
either owner. Reviewed image/config/account/path facts and verified native
preflight/database observations independently derive each side's complete
expectation. A caller echo or observed OCI document cannot define its expected
values. Runtime metadata is the reviewed provenance boundary, not a new binary,
recursive device or host-OS attestation.

## Strict wire v2

Four-byte big-endian lengths frame canonical ASCII JSON with exact keys, types,
direction, sequence and identity. Bindings include session, exact candidate,
execution origin, hosted run/attempt when present, immutable intent and image
digests. Local-process identity has null CI labels and a real fresh session;
partial/malformed hosted identity is refused before shell mutation. Labels alone
do not authenticate GitHub. There is no v1 fallback or reconnection.

The closed sequence is preflight, create, initialize, bind_expectation, start.
Preflight returns the bounded native runtime/image observations. Create pins the
full exact ID. Initialize returns database facts while root retains original
OCI custody; only the once-only bind_expectation reply transports the original
OCI bytes. Start and every later recheck retain original PID/start/controller
identity rather than adopting a later observer's location.

PIDs begin/recheck/seal verbs install the original S/D after the exact-list
barrier, with all 37 independent reader observations and existing semantic
predicates retained. Producer, mandatory reader and optional emitter each bind
to independent source authority. Teardown ACK never proves absence. Shell
cleanup separately checks the exact ID and name before other known owned
resources may be removed.

## Existing budgets and physical custody

Disjoint once-preclaimed roles share the same outer 16 native calls/1 MiB,
PIDs 180 calls/2 MiB, HealthRun 400 calls/4 MiB and cleanup 100 calls/2 MiB.
Root recovery's four calls/81993 bytes and producer cleanup's 96 calls/2015159
bytes partition that one cleanup pool; a late or sealed phase cannot allocate
another root recovery slice. No per-process fresh full ledger or refund exists.

Frame/control copies, every raw source/context read, native stream, repeated
bounded legacy read, log prefix, diagnostic registration write and output all
consume their owning allowance.
Physical reads/writes are claimed before I/O; actual spend remains charged even
when cancellation/expiry is noticed afterwards. Only unread reservation capacity
is released. In-flight claims cannot cross phases or turn a clamped prefix into
successful complete input. Initial consumer stdin is bounded within its intrinsic
preclaimed role, then its spend is adopted exactly once after strict context
binding; the coordinator supervises delivery under the original deadline.

Startup remains 120 seconds, each PIDs invocation 180 seconds with the same
46-second cleanup reserve. Actual CLOCK_MONOTONIC S/D remains authoritative;
wall-clock labels, blocking waits and reader handoffs never renew it.
Preflight/database frames retain 32768/16384-byte limits, raw OCI 65536 bytes
and the containing frame 90000 bytes. The private context cap is 131072 bytes.
These transport caps do not enlarge the 15360-byte main/16384-byte total PIDs
proof. Every limit can refuse; bounds do not promise every authored/native
profile will fit.

## Faults, cleanup and remaining acceptance

EOF, malformed/truncated input, wrong identity/sequence, drift, exhaustion,
cancellation and expiry fail closed. Ordinary failure requests root EOF recovery,
releases phase proxies and permits shell EXIT handling under the original
deadline, then terminates the entire owned process group. Lost ACK preserves
failure even if later independent absence allows owned-resource cleanup.
Expired authority, SIGKILL, machine death and unknown reaping can prevent cleanup;
no failure path is relabelled successful absence.

The earlier caller's hard lower bound was 214690 bytes (65875 shell + 66855
immutable source records + 5 × 16392 request reservations), exceeding its former
200000-byte slice before other traffic. That source-budget refusal remains an
explicit negative regression. The existing isolated emitter fixture retains its
tighter measured-spend assertion of at most 448576 bytes; its current candidate
allowance is not a reason to weaken the exact byte equation.

The experimental static partition and four authored connected measurements are
recorded in ADR 0033. Both parent and independent children use the actual,
unpatched candidate plan and the aggregate remains 1 MiB. Native responses and
producer effects remain authored, metadata I/O is not qualified, and the
six-phase shell driver is not the full native workload. Observed margins do
not establish native variability or whole-harness fit. Never publish this state
as a qualified native harness or a compatibility claim.

Source/fake-process tests do not establish original native controller ownership,
rootless delegation, real effects, actual size/timing fit or cleanup. All fresh
exact-final-candidate four-lane/28-test gates, six actual authored-fixture
consumers, six application migrations and package/published-dependency gates
remain mandatory. Host capture stays deferred; no release is ready/requested.

The same canonical harness serves local, main, trusted dispatch and exact-release
validation. PR offline green is not native proof. Other Lens products and the
website have no private broker consumer, and no Lens depends on BoxFerry.
Existing five image tag/digest locations and Action ownership are unchanged.
The new dev-only clock pin is uniquely Cargo-owned, with real lockfile checksums
and policy regression; immutable qualification source records are not automatic
software-install updates. See [dependency policy](dependency-policy.md).
