# ADR 0047: Append finite device mapping native source proof

Status: accepted test-only implementation contract; native qualification pending.

## Decision

Append only device invocation 29, with independent CLI and rendered controls for
`/dev/null:/dev/native-null:r`, exact configured retention, nonsymlink character
identity and held-descriptor bounded read. Reuse the existing HealthRun, borrowed
image, bound outer cleanup owner, private custody and terminal-cleanup primitives.
The [source contract](../native-device-mapping-contract.md) specifies strict
context/semantic/counter/cleanup validation and success-path output reservations.

This narrowly supersedes only ADR 0046's 28-invocation/seven-owner constraint:
there are now 29 invocations and eight delegated cleanup scopes. Preserve all
original 28 names and order, including expanded hostname/resolver invocation 22,
PIDs27 and its immediate strict reader, then nofile28 and its immediate strict
reader. Append the new one-child owner and immediate mandatory device reader
only after both preceding readers succeed. Failure dominance and original lane
EXIT cleanup remain mandatory; no prerequisite can be bypassed.

Every ADR 0046 resolver, custody, budget and non-admission rule remains intact.
Keep the original 180-second exact-test deadline, 46-second reserve, 400-call/
4-MiB aggregate, 100-call/2-MiB cleanup reserve and 1800-second lane ceiling.
No deadline/counter reset, new image, runtime framework, public schema,
capability/catalogue admission, pin or dependency change is authorized.

## Boundaries and verification

The private schema-1 device reader is mandatory without publication; the existing
19-argument emitter repeats validation and requires an exact typed three-key
unadmitted result. No device field appears publicly. Configured mapping and a
character-device read do not establish write/create denial, general enforcement
or arbitrary-device support. Borrowed image removal is forbidden. Uncertain
mutation liability requires the existing verified outer cleanup path.

Independent semantic/custody/ordering controls and complete final-source gates
remain source checks. Fresh exact-candidate whole-29-call Debian11 API1.41 and
upstream API1.56 rootful/rootless qualification, actual byte/time fit and verified
cleanup remain due. Historical evidence retains its exact scope; catalogue,
BoxFerry/application acceptance and publication are separate. This adopts no
resolver29 fallback, memory, named-capability or logging proof and no historical
runtime/broker rewrite. Existing pins and Renovate ownership/extraction remain
unchanged because no software version, dependency or shared workflow is changed.
