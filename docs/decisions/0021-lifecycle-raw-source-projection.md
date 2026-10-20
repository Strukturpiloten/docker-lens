# ADR 0021: Project complete lifecycle groups into raw source evidence

Status: accepted implementation contract for raw source projection only;
changed-source qualification and catalogue selection remain pending.

## Decision and evidence boundary

DockerLens #122 complements #114/#115/#116 under #39/#31/#3. Run
`39121741122`, attempt 1, source `cead64a28f7c409c2de23ee298fad9b080e106fc`
completed all twenty-one canonical invocations in each of four lanes and was
independently reviewed. That earlier source evidence informs the finite mapping;
it does not qualify this changed emitter or admit a successor compiled cohort.

After every existing strict reader succeeds, `scripts/native-evidence.py` adds
only the following complete groups to raw `capability_outcome` and
`admitted_shapes`, in `NativeCapabilityShape::required_for` order:

| Raw source capability | Complete shapes | Exact lane boundary |
| --- | --- | --- |
| StopTimeout | StopTimeoutZero, StopTimeoutPositive | All four lanes; complementary positive and omitted/zero actual TERM-effect proofs. |
| ContainerInit | ContainerInitTrue, ContainerInitFalse | All four lanes; omitted/false/true controls, scoped to PID1 indirection. |
| ReadOnlyRootfs | ReadOnlyRootfsTrue, ReadOnlyRootfsFalse | All four lanes; diagonal omitted/false/true write/EROFS controls only. |
| TmpfsMount | TmpfsMountReadWrite, TmpfsMountReadOnly, TmpfsMountOptions | All four lanes; explicit 1 MiB/0700 and 2 MiB/0750 rw/ro effect cases only. |
| HealthStartInterval | HealthStartIntervalZero, HealthStartIntervalPositive | Upstream rootful/rootless only; complete positive, zero/default scheduling and representation proofs. |

Omission controls are not invented extra shapes. Init reaping/general signal
semantics, arbitrary flag combinations, tmpfs defaults/partial options and
unobserved values/interactions remain unproved. No Cartesian expansion follows.
The independently authored CLI/literal expectations and actual effects remain
the oracles; renderer output is never copied to manufacture a positive result.

Every existing private proof remains mandatory, even when a family adds no
positive group on that lane. Stable bounded private-file custody, duplicate-key
and closed-schema checks, independently supplied exact candidate/run/lane,
Engine/package/API/mode, daemon UID, borrowed-image/outer identity, negative
controls, accounting, original deadlines and complete ownership/cleanup checks
all precede projection. Missing, partial, malformed, wrong-context, failed-effect
or uncertain-cleanup proof rejects the entire manifest before writing output.

Debian retains `health_start_interval_not_effective_on_selected_api` and
`health_start_interval_unsupported_legacy_field`, with the underlying
`accepted_unknown_member_legacy_schedule_only` boundary. Unknown JSON acceptance,
created-state representation and legacy cadence never establish zero/default
field support. No Debian HealthStartInterval group or generic API introduction
floor is added. Upstream projection requires its exact effective/default-equivalent
and configured-absence results, not a generic version comparison.

## Public projection versus compiled catalogue

All five public family outcomes now carry both `admission: raw_source_only` and
`catalogue_admission: unadmitted`. The representation family carries these
markers as supporting source evidence, not a standalone grant. Their contract
names, existing closed outcome values and finite effect scopes are retained.
The closed current subset is `$defs.lifecycle_source_projection` in
`docs/native-evidence.schema.json`, including exact lane-dependent outcome
combinations. It is disconnected from the historical reviewed-record root.
Historical raw records and reviewed envelopes retain their original acceptance
and bytes; private v1 proof schemas and unadmitted markers are unchanged.

Canonical raw Debian records become 34 capabilities/56 shapes and upstream
36/60, retaining every prior group. Those numbers assume canonical parameterized
identity-v2 and prescribed Debian IPv6 negatives; legacy identity fixtures retain
their independently narrower coverage. The compiled catalogue stays selected by
ADR 0019 at Debian 30/47 and upstream 31/49, withholding all five capabilities.
No product constructor, renderer, admission record, historical hash or public API
changes. A separately authenticated and independently reviewed successor cohort
decision owns actual candidate-rehearsal admission.

## Qualification and maintenance

Keep ADR 0020's independent Unix-HTTP transport, every CLI/acquisition/network
oracle, twenty-one ordered invocations, nineteen-argument emitter protocol,
180-second invocation deadlines, privacy, resource limits and cleanup intact.
Local execution, Check main push, trusted native dispatch and Release validation
consume the canonical `scripts/native-conformance.sh` and this emitter. Offline
PR policy tests exercise the same projection without contacting a daemon.
BoxFerry consumes reviewed catalogue/pin records rather than this private emitter;
other Lens products and the website have no changed consumer or dependency.

No operational pin, dependency, image, Action, workflow, downloaded tool or
extraction location moves. Existing Renovate Cargo/GitHub Actions ownership,
one toolchain regex and one native-image regex remain unique. The latter still
extracts five version/digest pairs from `scripts/native-conformance.sh`, under
`DockerLens native conformance images` with automerge disabled. The existing
policy extraction checks verify this no-configuration-edit decision.

Independent final-diff review, complete final-edit gates and fresh exact-head
four-lane qualification remain required. ADR 0012's six actual authored-fixture
volume consumers, actual Nextcloud/Supabase bind and desired-external consumers,
and BoxFerry #343/#366 application obligations remain separate. No source-only
projection closes #31/#3, proves full migration/application acceptance or
authorizes release, publication, deployment or host runtime changes.
