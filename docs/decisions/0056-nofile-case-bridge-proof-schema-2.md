# ADR 0056: Isolate unlimited nofile cases in private proof schema 2

Status: accepted test-only fixture/proof revision; final-source/native qualification pending.

## Decision

Keep all eight independently created CLI/rendered nofile fixtures and their original
four cases and witnesses. The two finite cases retain omitted network configuration
and the original borrowed default bridge. Each unlimited case uses one separate
owned bridge shared only by its two roles. Reuse ADR 0006's existing typed network
and first-attachment rendering; do not change public acquisition or decoder policy.
Two independently identity-valid network requests resolving to one native network
still fail, including byte-identical replies. Never drop a refused fixture, heal an
endpoint ID, merge aliases or suppress a related GET to manufacture success.

Version the private packet with `schema_version: 2`, retaining `nofile-v1.json`,
the `nofile-v1` contract/status label, twelve external reader arguments and the
19-argument emitter. Current readers reject schema 1. This explicitly amends ADR
0045's original fixture/proof schedule; historical source packets and evidence
retain their original meaning. Public evidence gains no nofile field, schema,
capability or catalogue admission. All 32 ordered invocations and eleven owners,
the immediate PIDs27 and nofile28 readers, and original outer cleanup remain.

The private reader independently binds the borrowed default role and two distinct
canonical owned IDs to their names, run label, bridge driver and fixed case/role
audiences. It retains whole endpoint-map availability for all eight roots: no
accessible entries means no observed endpoint name/ID/ID availability/lookup. It
never assigns a peer's GET to that slot. Captured networks are only the ordered
subset supported by actual endpoint references; the borrowed default ID is null
unless observed. Present entries must bind their intended case and actual exchange. Endpoint ID missing/null/empty/redacted remains distinct
from present and requires the actual name-bound fallback, not an invented ID.
Active membership is optional and never ownership: retain its availability,
fixture-ordered selected IDs and bounded unselected count. Unavailable is not
empty, observed selected peers must belong to that network's audience, and
positively observed foreign peers on an owned bridge refuse. The default may have
unselected peers; record only their count and never adopt or delete that bridge.

Every successful capture has eight selected roots. For N distinct supported network
exchanges (0..3), require 8+N actual inspect expansions and 10+N actual GETs. Only
the fully referenced topology has eleven expansions and thirteen GETs. No absent
whole map or configured NetworkMode invents a request key or observed network.
The explicit expansion ceiling changes from ten to **eleven**. Preserve twenty reserved
request units, 512 KiB response bodies, 128 KiB per body and the ten-second
acquisition ceiling; measure actual requests, expansions, bytes and elapsed time.
The reader also checks the necessary 73×(8+N)-byte identity bound, derived from a
compact `{"Id":"<64 hex>"}` object for each inspected container/network. It is
neither a measurement nor the exact minimum of a complete capture; the producer
retains its authentic sum across every response body and the 512 KiB ceiling.
Keep the original 180/46-second work/cleanup clock, 300 ordinary/100 cleanup call
ceilings and 2 MiB per-phase byte bounds. No budget is funded by removing old
container checks or by reusing the reserved amount as an actual measurement.

Two bridge setups add six measured ordinary captures: fresh-name absence, CREATE
and exact creation-ID/name/driver/label binding per bridge. Unknown/partial CREATE
identity cannot authorize name recovery or successful proof. After verified
container absence, each owned bridge has six measured cleanup captures: bound
identity, exact-ID DELETE and two full ID/name absence rounds. Container cleanup
remains 72 calls; network cleanup adds twelve, total **84**, under the original
100-call reserve. Per-network deltas reconcile with the phase totals, including
actual bytes; no cleanup success is inferred from membership. Borrowed image and
default network remain nonowned. Any uncertainty retains the original failure and
authenticated outer teardown obligation. A successful private packet requires all
original witness/effect, context, accounting, cleanup and empty/false admission checks.

## Evidence and limits

The live pinned Engine 29.8.1 guest returned the same canonical network ID for two
independently identity-checked request keys. A separate Unix-socket control ran the
Rust acquisition caller on that reference pattern and returned `Shape`. The old
hosted failure recorded only `Shape`; its underlying cause remains unverified.
Separate unlimited-case networks target that cross-case interaction while keeping
public one-object/one-reference rules.
Synthetic controls must cover every independent exact/normalized/refused outcome
combination and reject alias, ownership, availability, cost, cap and teardown drift.
Actual measured Engine receipts remain distinct from official exact-head native
qualification. Final complete gates, independent review and fresh four-lane32
execution with real byte/time/cleanup fit remain due.

No public product API, dependency, software pin, shared workflow reference or
Renovate manager/extraction location changes. The existing image/tool/action
ownership remains authoritative; no new network dependency or BoxFerry product
dependency is introduced. The fixed private filename, CLI and status remain stable
for current harness consumers; no schema-1 fallback is enabled for this candidate.
