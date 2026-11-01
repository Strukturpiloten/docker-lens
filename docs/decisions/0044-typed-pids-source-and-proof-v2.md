# ADR 0044: Typed PIDs source collection and private proof v2

Status: accepted implementation contract; final-source and native qualification pending.

## Decision

Extend ADRs 0039–0041's measured source contract using the independently
reviewed coverage and custody preparation in ADR 0043. Replace the ordinary-domain-only
assumption with explicitly checked cgroup v2 domain, domain-threaded and threaded
roles. This changes test-source semantics; a broader string comparison alone is
not an implementation of this decision.

The configured outer boundary remains the actual private guest-root mount inode
on the held outer process's ancestor chain, selected before checking its limit.
It must cover an entire domain or thread root, never a clipped threaded member.
Non-root domain parents admit domain/thread-root children; thread-root or
threaded parents admit threaded children. Preserve the independently authenticated
genuine-hierarchy-root exception and complete ancestor attribution.

Source discovery uses contributing domain/thread-root process lists and verifies
each leader's actual local membership through held procfs identities. Threaded
members contribute no process-list read. Acquire and recheck real process,
namespace and time-namespace custody inside the complete two-pass lease. Complete
worker matching still visits every discovered leader. Transfer only internally
captured scopes, close graph witnesses once, and hand selected custody to the
original source owner without a caller-supplied descriptor list or new cleanup
owner. Preserve original seal/finalization ordering and uncertainty refusal.

Reuse the existing bounded cgroup.type read and return its observed canonical
kind only after successful cleanup. Add that fact to sampled leaves and every
non-root controller row. A strict childless leaf may be any of the three valid
kinds when the unchanged exact all-TID, single-threaded worker and causal fork
proof passes. Keep every local-enforcer, ancestor/global headroom, NPROC, process,
namespace, inode, mount, kernel, accounting and cleanup requirement. Type and
parent relationships remain stable over all 24 measurement observations; allowed
domain/thread-root changes outside that phase require fresh role validation.
Bootstrap observations are not substitutes for the measurement baseline.

## Private representation and consumers

Use only schema_version 2 with contract pids-v2 and private filename pids-v2.json.
Each sample carries cgroup_type matching controller row zero. Every non-root
controller row carries cgroup_type. Attribution carries the fixed algorithm
discriminator typed_procs_local_membership_v1; this label is not authentication
or proof that a source operation ran. Independent readers require the actual
context, complete identity/parent/type relationships and all existing effects.
Reject mixed, missing, extra, malformed or inconsistent representations.

Root framing remains version 1, as does the separate worker/controller protocol.
Producer, launcher, immediate Python reader, Rust parser/proof builder, emitter,
current raw pids_contract discriminator and its schema agree on v2. No fallback
to an old private proof is allowed. Preserve immutable historical evidence and
fixtures. Keep source outcomes unadmitted and product capability/profile maps
unchanged; source support does not grant a destination capability.

Before functional changes replace only current-versus-historical AST-equivalence
assertions contradicted by this decision. Preserve frozen source fixtures and
mutation controls. Independently check unchanged custody/read/cleanup ordering
and the new typed semantics; never erase semantic changes with a broader
normalizer or silently remove a mandatory guard.

## Verification and resource boundary

Keep original parent and source budgets, charged reads/opens, descriptor limits,
frame/output/private-proof bounds, deadlines and cleanup reserve. No reset,
refund, retry allowance, provider switch or namespace-entry operation is added.
New helper imports must resolve to the fixed current source tree and be included
in the exact source/closure authorization where required. Kernel and reader work
remain separate from BoxFerry; no Lens product depends on BoxFerry.

The authored mixed-topology transcripts exercise real bounded I/O and IPC with
explicit simulated kernel/Engine/clock facts. They do not qualify fully typed
worker chains, native semantics or arbitrary maximum-size fitting envelopes.
Require independent implementation review, a complete typed owner transcript,
unchanged-budget measurements, complete exact-final-source checks and fresh
four-lane native qualification before acceptance. Rootless none remains
incompatible with mandatory positive PIDs27; systemd/v2/PidsLimit and actual
delegation are still required. Nofile28, downstream application acceptance and
manual package/image publication remain separate gates.

No software dependency, image/tool/action pin or canonical pin location is
changed by this decision. Existing Renovate ownership and extraction remain.
