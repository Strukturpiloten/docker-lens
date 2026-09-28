# ADR 0005: Bound the standalone migration and separate target ownership

Status: accepted checkpoint; DockerLens #3 remains open.

DockerLens 0.1.0 is a native source/target foundation, not a complete
BoxFerry application migration. The finite required field and scenario set,
current versus missing shapes, independent evidence requirements, and issue
owners are recorded in [the migration ledger](../standalone-migration-ledger.md).
This ADR preserves ADR 0003's current public intent, graph, renderer and
catalog behavior. It does not admit new native capability facts.

The current `target` public paths remain stable while implementation moves
into container intent, shared intent, graph, renderer dispatch, and separate
container/network renderer modules. Shared resource variants, dependency
rules, capability vocabulary, and evidence admission are integrator-owned.
Network work (#29) and container work (#30) have distinct implementation
files; any common contract change is reviewed and applied by the integrator
before those workstreams proceed. Read-only acquisition (#28), independent
native conformance (#31), and BoxFerry consumer/application work (#343/#366)
remain separate owners.

Each new target branch requires source authority and a typed neutral consumer
decision, closed unsupported/loss behavior, version and mode boundaries, and
independent native request/result evidence before a positive catalog claim.
Only the exact changed candidate's complete gate and four genuine native
lanes can establish release compatibility. Offline unit tests preserve local
behavior but cannot establish Engine compatibility. No executor, Swarm,
build-context, or Windows feature is authorized by this checkpoint.
