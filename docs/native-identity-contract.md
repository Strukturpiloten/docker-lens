# Parameterized identity proof

This documents the private version-2 producer/consumer seam for #86, under
[ADR 0013](decisions/0013-parameterized-container-identity.md). Source and mocked
controls do not establish Engine compatibility. Fresh exact-candidate native
evidence and a separately reviewed sealed cohort remain required.

The canonical tenth native check remains
`native_identity::live_container_process_identity_matches_engine`. It executes
ten independently authored CLI/inert-renderer pairs against the unchanged pinned
BusyBox image. Both roles first check the image's root account/group, missing
test names and numeric ID, non-default `bin` account/group (literal UID/GID 2),
absent future directory, and regular-file premise.
The fixtures establish only their own inheritance, not an arbitrary image's
defaults. Omitted fields, literal wire configuration, actual PID1 identity and
resolved directory, and successful exited state are separate assertions.

The ordered cases are:

| Case | Required result |
| --- | --- |
| `inherit` | Inherited fixture identity/directory, successful exit |
| `numeric_uid_gid` | Original explicit numeric pair, successful exit |
| `numeric_uid` | Explicit numeric UID, initially absent directory created, successful exit |
| `named_user` | Image-resolved named user, successful exit |
| `named_user_group` | Image-resolved named pair, successful exit |
| `named_user_numeric_group` | Named user with numeric group, successful exit |
| `numeric_user_named_group` | Numeric user with named group, successful exit |
| `missing_user` | Attributed account rejection, no process started |
| `missing_group` | Attributed group rejection, no process started |
| `nondirectory_workdir` | Attributed regular-file directory rejection, no process started |

Transport failure, timeout or arbitrary nonzero status cannot satisfy a negative.
Both roles must reject at the same phase (`create` or `start`). No successful
`docker exec --user` override substitutes for actual PID1 evidence.

## Private file

The fresh mode-0600 owner-private, single-link regular file is capped at 16 KiB, read
without following symlinks, and checked for metadata stability. Duplicate JSON
keys, missing/extra fields, reordering, wrong types and stale bindings reject the
whole lane. Version 2 binds `candidate_sha`, `lane`, `mode`, `rendering_api` and
`run_id`; its fixed `identity_contract` is `container-identity-v1`. It retains
the five historical ordered `probes` and adds exactly ten `cases`.

Each case has `case`, `expected_outcome`, `wire = passed` and two ordered
`containers` (`oracle`, `rendered`). Every container has `role`, immutable `id`,
exact case/run/role `name`, run `owner`, `configured`, `outcome`,
`rejection_phase`, `runtime_uid`, `runtime_gid`, `runtime_workdir` and `cleanup`.
Positive runtime checks are `passed`, with null rejection phase. Negative
runtime checks are `not_started`, with a closed attributable outcome. IDs must
be canonical and globally distinct across all twenty records. A null ID is
required for a create rejection with `configured = not_created` and
independent exact-name absence; all other configuration checks are `passed`.

Attempted resources enter the ownership ledger before mutation. Cleanup verifies
name/ID/run ownership, removes only immutable IDs, and checks genuine name and
ID absence twice. Cleanup uncertainty is sticky and cannot write positive proof.
The producer has a 120-second internal deadline and reserves 40 seconds for
cleanup, including command kill grace. SIGKILL or host failure may prevent
cleanup; no positive proof may be inferred from interruption or missing records.

## Raw mapping, not catalogue admission

Only complete v2 validation maps raw singleton `ContainerUser`/`ContainerWorkdir`
shape groups. The sanitized manifest adds fixed `identity_contract` and
`identity_cases`; it never exports names, IDs, run tokens, user values, paths,
process output or native errors. Filesystem and external binding checks establish
trusted-harness provenance, not attestation against a privileged writer.

Version-1 numeric-only proof retains its 4-KiB limit and non-admission meaning.
Its definitions and historical records remain unchanged. The reviewed-record
schema root remains unchanged; new private v2 definitions are disconnected
from it. Other runtime settings, supplementary groups and ports remain separately
gated. This change does not grant arbitrary-image startup, namespace mapping,
host ownership, data migration, application acceptance or release readiness.

## Consumer and pin audit

DockerLens local/main/dispatch/Release native lanes consume the same canonical
producer and emitter. No external workspace raw-manifest parser is introduced:
BoxFerry consumes sealed digest-bound records and keeps its positive application
contracts; the remaining Lens products and website do not consume this seam.
No operational software pin, package dependency, action SHA, image tag/digest,
download or canonical Renovate extraction path changes. The five existing image
pins stay in `scripts/native-conformance.sh`; the existing Renovate managers and
their regression coverage remain applicable. Historical fixtures are not moved
or automatically updated.
