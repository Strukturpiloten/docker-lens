# Native health and container metadata contract

`health-metadata-v1` is an independently authored, test-only source-proof
definition for DockerLens #93, registered as a mandatory canonical native
test. It does not admit a sealed catalogue capability or establish
BoxFerry application acceptance. The product planner and renderer remain inert.
Historical JSON, the current catalogue and operational pins are unchanged.
The dev-only libc pin uses its already locked version/checksum and existing
Cargo Renovate ownership; product dependencies are unchanged. No release,
publication or deployment is authorized by this contract.

## Finite contract

The ordered source shapes are exactly `ContainerCreateLabels`,
`ShellHealthcheck`, `HealthStartPeriodPositive`, and `HealthStartPeriodZero`.
Explicit raw group mapping after full private validation associates the first two with
`ContainerLabels` and `HealthShell`, and the last two together with
`HealthStartPeriod`. None is admitted merely by this definition. Disabled and
inherited controls grant no additional group; `StartInterval` is excluded.

Four ordered cases each contain an independent CLI oracle and an ordinary
sealed test planner/renderer fixture:

| Case | Independent required native observations |
| --- | --- |
| `grace_positive` | Identical `CMD-SHELL` ready-file command, one-second interval/timeout, two retries and authored 20-second period. Two distinct completed exit-1 attempts, each bound to the same actual `StartedAt` and completed strictly inside that period, while still running/starting with zero failing streak. A ready-file transition then produces a completed success and healthy state inside the period; removing the file produces two subsequent actual failures, counted streak and unhealthy state, all strictly before the original 20-second window ends. An independent Engine `SystemTime` read after the unhealthy inspect supplies its observation upper bound. |
| `period_zero` | Both roles actually start with the same shell command and explicit wire zero. Two completed failures produce unhealthy with counted streak, then real recovery and subsequent failure/unhealthy transitions. The pinned base image's effective health start period is independently inspected as exactly zero before the request (a missing health configuration has native zero default); zero cannot silently inherit a positive period. |
| `inherited_failure` | Both roles inherit the owned committed image's identical failing shell health check without an override. Both become unhealthy after two actual completed attempts. The health command's sentinel exists, proving execution separately from metadata. |
| `disabled` | CLI `--no-healthcheck` and rendered `Test: [NONE]` both start, remain running and have no health state twice at least two configured intervals apart. Neither creates the sentinel touched by the inherited health command. This is a control, not automatic `HealthDisabled` admission. |

Stage barriers observe both roles' initial failures before making either ready,
then recover both before removing either ready file. This avoids spending the
second role's authored grace window on the first role's complete lifecycle.
There is no timing-uncertainty pass or failure retry. Current official Engine
semantics inform the expectations; only genuine exact-version runs can prove
them in the four maintained lanes. A success during the period ends grace, so
later failures must count. Native zero `StartPeriod` may be omitted by JSON
`omitempty`; explicit rendered wire zero and independent base-image inspection
are checked separately from the no-grace runtime effect.

Each role's direct `Config.Labels` must retain independently authored simple,
empty and escaped/non-ASCII examples. The run ownership label is checked
separately. Every emitted request is compared against a literal expected body
before the actual renderer body is sent. Finite examples do not promise all
label key/value or length boundaries.

## Budget, ownership and private proof

The ignored test has one epoch-bound 180-second suite deadline, clipped at entry
without resetting it. Work reserves 45 seconds for cleanup plus a one-second
command kill margin. Commands have at most eight seconds plus the bounded KILL
grace; optional waits never override the suite cutoff. At most 400 commands and
4 MiB of retained command streams are allowed. Inside those same aggregate caps,
work stops before 300 calls or 2 MiB; 100 calls and 2 MiB remain reserved for
authenticated cleanup/absence readbacks without resetting any counter. Work
stdout/stderr caps are 65,550/8,192 bytes; cleanup caps are 8,192/2,048 bytes.
Each command requires capacity for its complete bounded envelope before I/O;
overflow rejects the test. The separate actual
read-only acquisition has 16 requests, 8 expansions, 2 selected resources,
256 KiB per response, 2 MiB total and at most 15 seconds inside the work budget.

Context binds exact observed Engine/API/package/mode facts from independent
direct and CLI reads, an exact-one dockerd effective-UID oracle and actual
bounded acquisition. Rendering uses the independently verified advertised API
(1.41 Debian, 1.56 upstream); acquisition retains its separate 1.49 ceiling.
The unchanged canonical BusyBox pin is supplied by the harness, not duplicated
or replaced. A stopped run-owned seed is committed to one exact owned image
tag; direct image inspection verifies its health configuration, label, tag and
canonical ID. That image is never a published or production image.

Only allowlisted create/start/inspect/delete requests for registered names and
IDs are sent. Container cleanup immediately revalidates name, canonical ID,
image and run label before ID-only removal. The derived image is removed only
after every attempted container's cleanup is verified; its ID/tag/label/health
are independently revalidated. Two final direct ID/name and image-ID/tag 404
rounds are mandatory. Failed work cannot continue into a positive proof.
Catchable failures use the same remaining cleanup budget; SIGKILL, host failure
or unverified teardown can prevent cleanup and never establish evidence.

The fresh mode-0600 `health-metadata.json` must be a direct child of the held
mode-0700 `NATIVE_CAPTURE_DIR`; existing paths, links, wrong owners, extra hard
links, unstable file/directory identities and partial or oversized contents are
rejected. Publication uses exclusive creation only after all assertions and
cleanup. The private version-1 proof binds candidate, lane, observed Engine,
rendering/acquisition APIs, mode, pinned base image and independently observed
zero base period, exact run token, all cases, derived image, seed and absence.
It retains only bounded health `StartedAt` and completed-attempt timestamps and
exit codes, never raw health output. The stdlib reader independently checks
nanosecond ordering, two distinct failures, grace/recovery/regression effects,
ownership, completion and cleanup, and returns only the four fixed shape names.
This is trusted-harness completion, not attestation against a privileged writer.

## Integrator-owned seams

The primary integrator has wired the module, runner and emitter while retaining
every existing mandatory native test. The reviewed-record schema root is
unchanged. These definitions remain separate from genuine native qualification:

- Register `native_health_metadata_tests` under `cfg(test)` and its exact ignored
  `live_health_metadata_matches_engine` runner selection.
- Set `NATIVE_HEALTH_METADATA_CANDIDATE_SHA`,
  `NATIVE_HEALTH_METADATA_DEADLINE_EPOCH` and
  `NATIVE_HEALTH_METADATA_PROOF_PATH` for each exact lane. The path must be the
  fresh direct `health-metadata.json` capture child; existing context/fixture
  environment names remain unchanged.
- Register closed stage/source diagnostics without leaking panic values,
  native logs, file paths, IDs or label contents.
- Invoke `read_health_metadata_proof` with independently bound lane, Engine,
  rendering API, mode, exact candidate/run token and pinned base image. Catch
  errors using the existing closed rejection boundary; do not print exceptions.
- Extend future raw output only through explicit complete-group mappings after
  validation, never by generic marker promotion. Any schema definitions must
  remain disconnected from historical reviewed-record admission.
- Audit canonical local/main/reviewed-PR/release consumers and unchanged
  Renovate pin extraction/ownership. No new image or tool pin is added; the
  dev-only libc pin retains the existing locked version/checksum and Cargo owner.

The new stdlib controls are discovered by the existing offline test discovery;
Rust controls run only after module registration. Neither synthetic controls
nor these source definitions qualify compatibility. Fresh exact-head complete
gates, all four genuine native lanes, authenticated independent evidence review
and separate later catalogue/consumer gates remain required.
