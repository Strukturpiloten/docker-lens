# ADR 0017: Preserve external-network internal expectations without admission

Status: accepted typed/rendering and pure snapshot-assessment contract; native
proof and admission remain pending.

Amends ADR 0006's external-network prerequisite contract and supersedes only
ADRs 0009 and 0015's complete-artifact version selection when an explicit
external-network internal expectation is present. Their inert execution,
protected-data, request-only and bind-source obligations remain unchanged.

## Decision

DockerLens #29 requires a caller-authored internal-network expectation for an
existing destination network. `NetworkSource::External` and its typed
`NetworkPrerequisite` carry `expected_internal: Option<bool>`. `None` is
unconstrained, not false; explicit false and true remain distinct. Existing
external intent literals supply `None`. The identity remains protected in Debug,
and closed planning failures expose no authored name or native value.

Each explicit value requires the new `NetworkExternalInternalExpectation`
capability in addition to `NetworkExternalReference`. Its complete native group
requires both `ExternalNetworkInternalFalse` and `ExternalNetworkInternalTrue`.
Created bridge `NetworkInternal` evidence is never reused. Root schema and
closed parser vocabulary recognize the names only; reviewed/upstream capability
arrays, active sealed counts/selection and all historical records stay
unchanged. Every current sealed profile therefore refuses explicit expectations.
Test-local fabricated facts/records test this contract and cannot establish
native compatibility or authorize admission.

The complete inert document uses schema 3 only when at least one external
expectation is explicit, adding a boolean `expected_internal` to that network
row. Unconstrained rows omit it. Without explicit expectations, schema 1 and
bind-only schema 2 retain their exact representation. Combined schema 3 retains
all source-review and unverified SELinux obligations, protected identities,
context and prerequisite order. Native request bytes never change. Consumers
must reject unknown versions/constraints rather than silently discard them.

The expectation is an obligation, not proof of existence, observed Internal,
ownership, isolation or reachability. The pure `NetworkPrerequisite::assess`
method matches only a supplied snapshot's inventory/daemon observation scope,
canonical selected network ID, exact selected network root, and required field
availability/origin/value. The inspected ID is present runtime-assigned evidence;
name/driver and any explicitly required internal boolean are present effective
evidence. Unconstrained internal state is not assessed. Unavailable, valueless,
redacted-but-valued, wrong-origin or mismatched required data fails closed.
Network ID matching is kind-scoped; selected capture references remain globally
unambiguous across inspected kinds. A target graph reference is never a capture
reference. Scanned collections retain the decoder's 4096 limit; unrelated
container/volume scans read only references, not native bytes.

Success concerns only those checked snapshot fields/bindings, not full inventory
validation, native authentication, atomicity, current/future existence or
capability admission. Caller-assembled snapshots remain assertions. This method
implements no acquisition, runtime preflight, execution or file writer. Genuine exact-lane native
proof, independent review and admission are later bounded phases. It adds no
IPAM, options, driver modes or network mutation. The implementation and authored
tests are from scratch; no oracle source or artifacts are copied or redistributed.
Supplementary inspect documentation is not version-qualified native proof.
No dependencies, software/runtime pins, tools, workflows or Renovate ownership
or extraction paths change.

A separate ignored native source producer and strict private proof validator
are now defined by [external-network-internal-v1](../native-external-network-contract.md).
They require two independently CLI-created bridges, fresh explicit captures,
preserved advertised/acquisition API distinctions, empty-request schema-3
expected/opposite checks and verified cleanup. The canonical harness now requires
that fifteenth test after configured binds, before raw emission. The emitter
retains nineteen positional arguments and requires the fixed private proof
against independently derived harness context plus observed dockerd UID. Only
complete false/true proof permits the closed public projection and raw group;
created-network `NetworkInternal` remains separate. Disconnected additive schema
definitions leave the reviewed root unchanged. Prospective identity-v2 raw counts
are Debian 29/46 and upstream 30/48; sealed counts remain 28/44 and 29/46.

This amends ADR 0016's current final-candidate gate from fourteen to fifteen
mandatory tests without rewriting its accepted fourteen-test historical source
run. Fresh authenticated exact-final-candidate four-lane execution, independent
review, complete gates and ADR 0012/0016 authored-fixture/bind-consumer obligations
remain required before ready/merge; a separate admission decision is still
needed for the new group. No native run, compatibility or sealed admission
follows from definitions or offline controls. Local/main/reviewed-PR/release
consumers share the same canonical harness; unchanged Renovate pin ownership,
extraction, grouping and approvals need no configuration edit. BoxFerry profile
and producer-receipt contracts remain separate, with no product dependency.

See [the complete artifact](../complete-artifact.md) and the
[decision index](README.md).
