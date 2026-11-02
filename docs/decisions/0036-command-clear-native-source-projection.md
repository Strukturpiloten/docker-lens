# ADR 0036: Guarded CommandClear raw-source projection

Status: accepted source-projection contract, not changed-candidate native
qualification, completed independent review or catalogue admission.

## Decision

Supersede only the current command-clear recovery's observation-only emitter
rule. Preserve private `command-clear-v1`, its twelve-fact strict reader, all
four ordered controls/two roles, invocation 23, canonical 26 order, nineteen-argument
emitter, cleanup, limits, runtime and pins. The exact ordered reader return
`(ClearCommand, ClearEntrypoint)` covers controls, not two grants. Append only
available CommandClear/[ClearCommand] to the complete existing raw maps.

Retain `command_clear_contract: command-clear-v1` as private-proof identification.
Add public discriminator `command_clear_projection_contract: command-clear-native-source-v1`.
Only under it, require closed outcomes: source admission `raw_source_only`,
catalogue admission `unadmitted`, capability `CommandClear`, shapes `[ClearCommand]`,
scope `explicit_exec_entrypoint_required`, outcome `all_four_process_controls_verified`.
Unknown versions, mixed/extra fields, types, scope/status or contradictory maps
refuse before publication. Historical discriminator-absent unadmitted payloads
retain their original observation-only meaning; they are never upgraded.

Raw top-level schema 1 and reviewed-record root schema 1 remain unchanged. The
disconnected raw subset documents the extension; executable emitter and accepting
policy validation couple fields/version to exact full maps. Context comes from
independent closed lane/identity selection and validated port outcomes, not an
arbitrary baseline or untrusted receipt. Identity-v1 and synthetic fully observed
IPv6 controls retain their existing behavior under explicit contexts; canonical
tests require independent full baseline-plus-singleton maps and Debian negatives.

## Semantics and authority tiers

Independent CLI/literal-rendered controls compare image defaults, explicit
entrypoint/omitted Cmd, the same entrypoint/empty Cmd, and empty entrypoint/explicit
command. Configured effective vectors and actual PID1 marker/NUL argv plus verified
cleanup remain mandatory. The middle two process effects intentionally agree.
The claim is retained/accepted authored Cmd `[]` and the independently expected
absence of image command under the explicit Exec-entrypoint guard, not a new
effect relative to omission or arbitrary-image/application success.

Existing Exec argument semantics supply composition; no scalar, lookup or shell
semantics are added. Preserve the public guard rejecting command Clear without
an explicit Exec entrypoint. EntrypointClear remains withheld because its native
explicit-command control does not cover Clear+Inherit. Do not tighten that public
contract to avoid missing evidence. No adjacent source family is promoted.

ADR 0019's accepted tier stays trusted-harness execution/source assertions plus
independently authenticated public projection, not private-payload replay, host
inventory or daemon attestation. The emitter cannot declare review complete.
Native26 run 40104150853/attempt 1 at 5fef54d22b62b22304b963748fee45d5a18595c7 is a
semantic prerequisite only. Its original observation-only bytes cannot qualify
the changed projection/provider-integrated candidate or acquire missing fields.

## Catalogue and verification boundaries

ADR 0019's compiled cohort and ADR 0012 consumer gates remain unchanged. Both
clear capabilities still fail on current sealed profiles. Historical raw/reviewed/
provenance files, exact cohort source/run/hash/file bindings, complete required
groups and raw-to-envelope equality remain mandatory and byte-exact. A later
admission candidate must bind fresh exact source/run/lane/artifact bytes carrying
this family version, baseline-plus-singleton maps and scope together. No generic
promotion switch, forged matching envelope or old source marker bypasses them.

Independent controls cover full maps, versions, status/scope/types/keys/shapes,
context/IPv6 boundaries, ordered reader return, all controls/roles, cleanup and
private canaries. Focused tests are not qualification: final-edit complete gates,
fresh four-lane26 execution/review and inherited actual consumer gates remain due.
No new native I/O, case, privilege, policy, pin or PIDs/nofile authority is added.

Affected consumers are native-evidence/command-clear, external-network,
lifecycle/default-effect, hostname, runtime-cohort, Shm, health-boundary and port tests, plus the
reviewed-catalogue accepting policy. Exact expectations gain only the singleton;
historical and neighboring-family refusals remain. Other Lens/BoxFerry consumers
use sealed profiles, not this unselected raw projection, so need no definition change.

Renovate no-change evidence: no operational dependency/pin, integrity record,
workflow/task definition or extraction path changes. Native image tag/digest pairs
remain solely in unchanged `scripts/native-conformance.sh`, owned by the existing
regex manager/group/manual approvals. Cargo, toolchain and Action managers are
unchanged; the new pure helper is stdlib-only. No new manager or approval rule.

## Number reservation

Current accepted decisions end 0021. Preserved unpublished f406cb22 has 0022–0034
and 0035-docker-gated-entry-custody. Reserve those numbers without adopting their
decisions; 0036 is the first free number for this distinct contract.
