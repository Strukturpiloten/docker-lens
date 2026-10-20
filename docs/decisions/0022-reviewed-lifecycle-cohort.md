# ADR 0022: Select the reviewed lifecycle successor cohort

Status: accepted candidate rehearsal admission; independent final-diff review,
fresh final-candidate and actual consumer gates remain required before
ready/merge/main admission or release.

## Decision and authenticated source

DockerLens #39/#31 selects four exact reviewed records from run `39124651853`,
attempt 1, executed candidate `a251748de3a61f9dc3d735e670ce3ea461ee0a30`
for source PR #123. Trusted-main dispatcher
`96d83f6d6959dba6079e3e9bdc35db3b27635609` is a distinct identity. All seven
jobs and every step passed, with 21 actual canonical tests once/in-order on
each of four lanes, six actor/exact-head admission successes and four
cleanup-dependent lane successes. The primary authenticated official live API
metadata and all four archive digests. The independent reviewer checked held,
bounded, stable/no-follow ZIP reads, exact single regular unencrypted members,
CRC, strict canonical UTF-8/duplicate-free/nonfinite-free JSON, profile bindings
and the complete public projections. Extracted members match ZIP member bytes.

[Sanitized provenance](../evidence/lifecycle-cohort-39124651853.json) binds
artifact IDs, archive API digests/sizes, member hashes and reviewed-envelope
hashes to the byte-exact
[independent source receipt](../evidence/lifecycle-independent-review-39124651853.json).
The receipt covers source input review; it does not attest to this later
admission diff. The independent reviewer relied on primary-authenticated API
metadata rather than independently fetching live actor identities/permissions.
Successful trusted source assertions and closed logs establish the bounded
effect/ownership/cleanup checks. Private raw timestamps, IDs, payloads and
independent host resource inventories were not directly inspected or redistributed.
This is neither cryptographic daemon attestation nor application acceptance.

This supersedes only ADR 0019's active-cohort selection and completes the
separate selection reserved by ADR 0021. All seven earlier cohorts, provenance
and evidence bytes remain unchanged. Earlier run `39121741122` informed the
mapping; it is never qualification for this changed source or selected candidate.

## Complete finite admission

Every prior capability/group is retained. Add only these complete
`NativeCapabilityShape::required_for` groups:

| Capability | Complete shapes | Exact profiles |
| --- | --- | --- |
| StopTimeout | StopTimeoutZero, StopTimeoutPositive | All four lanes |
| ContainerInit | ContainerInitTrue, ContainerInitFalse | All four lanes |
| ReadOnlyRootfs | ReadOnlyRootfsTrue, ReadOnlyRootfsFalse | All four lanes |
| TmpfsMount | TmpfsMountReadWrite, TmpfsMountReadOnly, TmpfsMountOptions | All four lanes |
| HealthStartInterval | HealthStartIntervalZero, HealthStartIntervalPositive | Upstream rootful/rootless only |

Debian is exactly 34 capabilities/56 shapes; upstream is 36/60, retaining its
existing complete IPv6 port group. Debian keeps both IPv6 expected negatives
and health `not_effective_on_selected_api`/`unsupported_legacy_field` outcomes.
Unknown-member acceptance and legacy cadence never establish StartInterval
support, zero/default equivalence or a generic API introduction floor.

All five complementary public outcome families and their exact contracts are
mandatory. Positive stops complement omitted-graceful/zero-forced effects;
upstream health requires positive, default-equivalent and created-configuration
absence outcomes. Init proves only PID1 indirection. Rootfs effects cover the
diagonal omitted/false/true controls. Tmpfs effects cover only explicit
1 MiB/0700 and 2 MiB/0750 rw/ro cases. Omission controls are not extra shapes;
reaping, general signal semantics, Cartesian flag combinations, tmpfs defaults,
partial options, arbitrary values and unobserved interactions remain unproved.
No additional Cartesian or reaping proof is a prerequisite for these finite groups.

Append four raw members and four reviewed envelopes under SHA-256 paths.
Raw `admission: raw_source_only` and `catalogue_admission: unadmitted` bytes
remain unchanged; only reviewed envelopes plus explicit compiled selection
authorize candidate planning. Partial, duplicate, wrong-group, nonpositive,
wrong-lane, broadened-scope or incomplete-family evidence fails closed.
No product API, renderer, executor, private reader, harness or dependency changes.
Configured binds still prove no SELinux effect; schema-2/source-review and
schema-3/external-expectation obligations remain intact.

## Remaining gates and maintenance

This is source-bound candidate rehearsal admission. Before ready/merge/main
admission or release, retain independent admission-diff review, final-edit
complete gates, fresh authenticated exact-final-candidate four-lane/21-test
execution and review, six actual authored-fixture volume-only rehearsals, and
actual Nextcloud/Supabase bind and desired-external consumer review. ADR 0012's
consumer sequencing, BoxFerry source-bound admission/producer receipts and
separate application acceptance remain. No older source run or consumer receipt
qualifies later changed bytes. This does not close #39/#31/#3, establish full
migration acceptance, authorize host capture, or permit release/publication/deployment.

The oracle remains `./scripts/native-conformance.sh <lane>`, using exact Debian
docker.io `20.10.5+dfsg1-1+deb11u2` (Engine `20.10.5+dfsg1`) and upstream Engine
`29.8.1`. Debian acquisition/rendering API is 1.41; upstream acquisition is 1.49
and advertised/rendering API is 1.56. Retain existing Apache-2.0 Moby/Debian
provenance from ADR 0015 and lifecycle contracts. No oracle source or binaries
are copied or redistributed; sanitized metadata remains under repository MPL-2.0.

Local/main/trusted-dispatch/release consumers keep the canonical harness and
nineteen-argument emitter. No operational software pin, dependency, manifest,
lockfile, toolchain, Action, workflow, image or extraction location changes.
Renovate retains unique Cargo/GitHub Actions ownership, one toolchain regex and
one five-image regex, native-image grouping and disabled automerge. Historical
records remain outside update streams. Other Lens products and the website have
no changed consumer; BoxFerry consumes reviewed catalogue records separately.
