# ADR 0024: Raw-only disabled-health source projection

Status: accepted source integration; fresh native and consumer qualification pending.

## Context

ADR 0022 separately selects the reviewed lifecycle cohort at Debian 34
capabilities/56 shapes and upstream 36/60. ADR 0023's process-source slice added
three raw-only singleton groups, bringing its raw totals to 37/59 and 39/63,
while explicitly excluding HealthDisabled. That exclusion and those counts
remain historical facts about the slice; no accepted ADR or evidence bytes are
rewritten here. The existing complete `health-metadata-v1` proof already checks
inherited failing-health and disabled CLI/rendered controls, in addition to its
label, shell-health and start-period cases.

The pending PR #124 campaign `39130478489` binds source
`e7995ecfa9cadaae0bc7bc1685e5e1f320c907ff`. Whatever its later result, it cannot
qualify this changed emitter. Mock fixtures and closed outcome definitions are
not independently authenticated native evidence.

## Decision

After the existing unchanged complete `read_health_metadata_proof` validation
succeeds, derive only the raw singleton `HealthDisabled: [DisabledHealthcheck]`.
The strict reader still requires all four ordered cases and both roles per
case, exact candidate/lane/Engine/API/mode/image context, effects, identities,
ownership and cleanup. Its return and the public `health_metadata_probes` remain
the same four legacy source-shape names; neither gains DisabledHealthcheck.

The native producer remains unchanged: inherited controls execute the owned
image's failing health command and become unhealthy after two actual attempts,
with the sentinel present. CLI `--no-healthcheck` and the rendered literal
`Test: [NONE]` must both remain running with no health state twice at least two
configured intervals apart and no sentinel. Native exact-NONE assertions and
all bounded ownership/cleanup checks stay with that existing producer. The
private protocol retains closed configured-effect completion markers; no new
self-declared field substitutes for the complete strict proof.

Keep the nineteen-positional-argument emitter and every prior strict reader.
All validation still precedes any public output. Missing, partial, foreign,
failed-effect, malformed or cleanup-uncertain health input refuses the whole
manifest, never merely withholding the singleton and emitting other groups.

Add only the fixed public fields:

- `health_disabled_contract: health-metadata-v1`.
- `health_disabled_outcomes` with `admission: raw_source_only`,
  `catalogue_admission: unadmitted` and
  `outcome: disabled_health_suppression_verified`.

The disconnected `$defs.health_disabled_source_projection` closes both fields
and every nested key/value without changing historical reviewed-record root
acceptance. No native IDs, authored health commands, sentinel paths/payloads,
logs, observations, timestamps or private proof bytes are projected.

Current raw projection totals become Debian 38 capabilities/60 shapes and
upstream 40/64. Compiled catalogue selection remains ADR 0022's 34/56 and 36/60;
HealthDisabled and the three process groups remain unselected. No new public
target profile, API, renderer behavior or admission is introduced.

## Consequences, maintenance and gates

All 23 canonical native invocations retain their exact order and requirements.
No producer, strict-reader behavior/return/API, private protocol, historical
record, receipt, dependency, pin, operational definition or workflow changes.
There is no new native probe, extra privilege, cleanup path or renewed budget.

Local/main/trusted-dispatch/release callers still consume the same canonical
`native-conformance.sh` and emitter. The unchanged Renovate manager owns the
same five canonical image pins/extraction paths, grouping and disabled
automerge; no manager update is needed. No other Lens product or website
consumer changes. BoxFerry's separate exact-source/script binding and actual
consumer acceptance cannot be established by older receipts or this raw mapping.

Independently authored inert fixtures cover all four exact profiles, unchanged
legacy return/probe names, exact new raw groups/counts, absent compiled selection,
closed metadata, historical schema acceptance and whole-manifest refusal for
missing or corrupt inherited/disabled effects and cleanup. They establish only
source validation. Independent final-diff review, complete final-edit gates,
fresh exact-final-candidate 23-invocation four-lane native execution and review,
all six actual authored-fixture volume-only rehearsals and required actual
Nextcloud/Supabase bind and desired-external consumer review remain mandatory.
No native compatibility, full migration acceptance, catalogue admission,
release, publication or deployment is established here.
