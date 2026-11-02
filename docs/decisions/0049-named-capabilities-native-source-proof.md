# ADR 0049: Named capabilities native source proof

Status: accepted test-only implementation contract; native qualification pending.

## Decision

Append only capabilities31 after the unchanged thirty invocation prefix and all
strict readers. This narrowly supersedes ADR 0048's30/nine roster seam with 31
invocations and ten delegated owners. PIDs27/read → nofile28/read → device29/read
→ memory30/read remains mandatory. Memory 0048, device 0047, resolver 0046 and every
existing custody/budget/non-admission requirement remain intact.

The [owning contract](../native-capabilities-contract.md) defines eleven idle
borrowed-image controls: default, add-only CLI/rendered, drop-only CLI/rendered,
both CLI/rendered, dropALL, dropALL/named-add-back, addALL and addALL/named-drop.
Only test-local CLI causal oracles use ALL. Product requests retain exactly the
three existing shapes: add NET_BIND_SERVICE, drop SYS_ADMIN, or both. The general
and applicable named facts stay required. ALL/opposite/duplicate product tokens
remain rejected; no public shape or catalogue admission is added.

Default NET_BIND_SERVICE presence and SYS_ADMIN absence make these product
requests redundant against the measured default. Unmodified artifacts establish
exact request/native retention plus consistent namespace-local effective state.
They do not establish unique artifact-induced transitions. Independent CLI
zero/add-back and ALL/minus controls supply the causal comparisons. Contradictory
native behavior fails a lane; do not skip rootless, reorder flags or weaken facts.

## Observation and boundaries

Use existing pinned BusyBox, direct idle sleep PID1 and namespace-local root,
with checked inherited entrypoint/user/init. Regular API-pinned nonprivileged
exec holds/checks `/proc/1`, binds actual PID/start/proc identity, UID and user
namespace, and reads PID1 CapEff with permitted/bounding/inheritable/ambient
context before/after. Namespace IDs need not match between containers. The
observed default kernel hostname binds each raw report to the canonical CID;
no hostname is authored or added to a product request. Kernel bits do not prove
host-root authority, low-port binding, mounting or arbitrary capability support.

The independent private 64 KiB reader validates raw hashes and recomputes ordered
role, context, raw configuration, stability and causal comparisons; rebound
hashes never replace semantics. Only finite named CAP_ prefix normalization on
the four exact profiles is allowed, preserving raw inspect evidence; ALL stays
literal. Held0700/regular 0600/single-link/nonsymlink/stable custody is unchanged.
Immediate validation remains mandatory without public emission. The unchanged
nineteen-argument emitter repeats validation and requires the exact typed
three-key empty-admission result. No public projection or historical rewrite.

## Budget, cleanup and qualification

One existing HealthRun keeps180 seconds,46 seconds reserve,300 ordinary calls/2 MiB,
100 cleanup calls/2 MiB,400 aggregate calls/4 MiB and1800 seconds/lane. Eleven slots
use 88 actual-bounded 8 KiB captures including small binding/inspect projections;
full context/final reads and backend snapshot extras remain separately reserved.
Successful common cleanup costs exactly99 calls/1013760 maximum captured bytes.
Attempt liability precedes creation; an unknown canonical ID forces bound outer
teardown before common name-based cleanup. Borrowed image removal is forbidden.
Failure, cancellation or uncertainty retains original lane EXIT failure dominance.

Independent source controls and focused compilation are not native qualification.
Complete final-source checks, independent final review and fresh exact-candidate
Debian11API1.41/upstreamAPI1.56 rootful/rootless whole 31 evidence, measured
byte/time fit and verified cleanup remain due. Application/BoxFerry acceptance,
capability admission, logging proof and publication remain separate obligations.
No new dependency/pin/action/image/shared workflow is introduced; existing
Renovate ownership, extraction paths, grouping and approval policy are unchanged.
