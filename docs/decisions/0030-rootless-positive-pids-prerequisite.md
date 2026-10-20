# ADR 0030: Fail-closed prerequisite for positive rootless PIDs qualification

Status: accepted bounded harness prerequisite; four-profile positive qualification remains open.

## Context and evidence

ADR 0027's mandatory private PIDs invocation 27 requires positive finite-limit
effects and independently attributed controller/ownership evidence. Reported
configuration alone cannot satisfy it or turn a failed observation into support.

Independently reviewed [run 39173069422, attempt 1](https://github.com/Strukturpiloten/docker-lens/actions/runs/39173069422/attempts/1)
tested `19f1ce4c15c81dd1003e79065be4c5bddb0c17e9`. Every lane passed 26
invocations and failed PIDs 27: 104 prior passes, four failures, no nofile-28
execution, no artifacts and no cleanup-dependent lane successes. The original
failed review remains immutable, SHA-256
`afa332ed0559771a0b531ac350ee5454f89ba3aa4bd43a3b7a55b5f0b9fafb8e`.
A separate review authenticates the already emitted sanitized ENV lines: both
rootless lanes report driver none/cgroup v2; both rootful lanes cgroupfs/v2.
Supplement SHA-256:
`35234d3db251f0c4ef65006b8aa40d6a1db3f97cbca90b17189ec42c4d66b962`.
Those reports do not prove enforcement absence, a runtime cause or cleanup.

[Official Docker rootless resource-limit documentation](https://github.com/docker/docs/blob/31d174d090fd7111ca2199ed54a3978e0d4ac74d/content/manuals/engine/security/rootless/tips.md#limiting-resources),
commit `31d174d090fd7111ca2199ed54a3978e0d4ac74d`, lines 137–149,
requires cgroup v2 and systemd for rootless --cpus, --memory and --pids-limit;
the documented driver-none case lacks those conditions and ignores the flags.
This reference is not an executed runtime oracle or a generic unsupported-Docker
verdict. Current pinned upstream-29 rootless image provenance is containers
revision `0b136a13a8bb612d91960ae5d07e72f449c89ec1`: Alpine 3.24 with its
native launcher executing dockerd-rootless.sh. No image, launcher, external
repository or pin change is authorized here; no external source is copied or
redistributed.

## Decision

After the existing sanitized ENV line, before fixture pull and all 28 native
invocations, require both already collected values for rootless lanes:
inner_cgroup_driver must be systemd and inner_cgroup must be 2. Other, unknown or
unavailable values fail closed with one fixed actionable prerequisite diagnostic:

`DOCKERLENS_NATIVE_PREREQUISITE: rootless_positive_pids_requires_systemd_cgroup_v2`

Exit nonzero through the existing owned-resource EXIT cleanup. Add no runtime
query, separate cleanup route, fallback, skip, unsupported grant or negative
qualification. Rootful behavior is unchanged. The diagnostic never attests that
cleanup completed.

Systemd/v2 is necessary, never sufficient: all positive effects, controller,
namespace/ownership, request/proof and cleanup assertions remain mandatory. This
guard does not fix PIDs or admit a capability. The rootful procfs/PID-coordinate
and controller-reader evidence gap and the authenticated exact owned 512-PID/4-GiB
boundary gap remain unresolved. The rootless fixture still needs actual delegation
and all independent positive proofs; merely reporting systemd/v2 proves neither.
Four-profile positive qualification stays open. A new native campaign must wait
for the actual rootless fixture prerequisite to be resolved and reviewed.

## Consumers, preservation and validation

Local execution, main-push check.yml, trusted native-validation.yml dispatch and
release-validation.yml share scripts/native-conformance.sh; no workflow changes
are needed. No product/API consumer change is introduced for BoxFerry, other Lens
libraries or the website; their independent consumer/application gates remain.
All 28 invocation lines, six owner blocks, proof protocols/readers, twelve-argument
reader and nineteen-argument emitter interfaces and budgets remain unchanged.

The five image tag/digest pins and canonical extraction locations are unchanged.
Renovate's existing scripts/native-conformance.sh regex manager, native-image
grouping and automerge=false review policy still own exactly those five matches;
no configuration, grouping or approval change or duplicate manager is needed.

Independent fault injection covers none/unknown/unavailable rootless drivers,
systemd with v1/unavailable versions, mock-only systemd/v2 continuation and
unchanged rootful continuation. Actual sanitized-observation and guard code runs
with fakes and the existing EXIT cleanup: exact owned resources are removed,
foreign resources preserved and fixture/native continuation absent on refusal.
These checks prove no native effect, compatibility, genuine cleanup, application
acceptance or release readiness. Main retains independent review and the complete
final-edit gate; fresh exact-candidate positive native and required consumer gates
remain mandatory.
