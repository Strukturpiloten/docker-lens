# ADR 0038: Maintain the userns profile for the exact Box consumer

Status: accepted bounded test-helper contract; integrated exact-candidate native
and consumer qualification pending. Supersedes only ADR 0004's native-only
maintained-profile consumer restriction. Historical decisions/evidence, native
contexts, native state and native receipt semantics remain unchanged.

## Context

BoxFerry's reviewed volume consumer uses the canonical Lens-owned outer runtime
but not the native coordinator. Its actual GitHub repository, job, private run
directory, container owner and guest socket differ. Merely authorizing source
bytes does not activate a missing prerequisite, and impersonating a native
workflow or broadening an arbitrary profile interface is not acceptable.

## Decision

Add exactly one separate test-only consumer mapping: actual repository
`Strukturpiloten/boxferry`, workflow
`Strukturpiloten/boxferry/.github/workflows/reviewed-docker-consumer-validation.yml@refs/heads/main`,
job `lanes`, `workflow_dispatch`, `refs/heads/main`, GitHub-hosted Ubuntu 24/Linux,
and the `upstream-rootless` lane under explicitly selected outer Docker. Require
positive bounded decimal actual run/attempt strings and the actual admitted Lens
candidate SHA in the existing `DOCKERLENS_NATIVE_CANDIDATE_SHA` field. These are
accident guards, not actor/PR/source authentication; Box's trusted exact-pair
admission and held complete source closure remain the authority. No fake native
context, `GITHUB_SHA`, caller-selected regex/profile/path or new environment
selector is introduced.

The Box run directory is exactly `/tmp/boxferry-docker-core.<alphanumeric8>`;
its suffix is the run label, the daemon name is `bf-docker-core-<suffix>`, its
owner key is `io.boxferry.docker-core-run`, and the socket mount is the held
directory's `socket` child at `/boxferry-core`. The fixed derived profile prefix
is `boxferry-343-upstream-rootless-<workflow-run>-<attempt>-<nonce>`, with separate
root custody `/run/boxferry-apparmor.<nonce>`. Native identity remains unchanged.
Every held state read revalidates the separately discriminated mode, original
directory identity, candidate, actual run/attempt, nonce, profile digest and
daemon binding. Native and Box state cannot substitute for each other.

Reuse the same finite ABI-4.0 `flags=(unconfined)`/`userns,` policy and original
prepare/load/create/verify/cleanup operations, parser/ABI byte custody,
read-only prerequisite refusal, exclusive locks, durable mutation intent,
creation-bound kernel-label and exact host cgroup checks. Unknown creation or
mutation completion retains custody; authenticated exact daemon absence is
required before unloading a used profile. No new image, dependency, pin,
installation, native invocation, resource limit, timer, host policy/sysctl/service
change, fallback or assertion exemption is introduced.

Native schema-1 cleanup receipts and `validate-receipt` remain unchanged. The
Box-only closed schema-1 variant adds exactly `consumer` with literal value
`boxferry-reviewed-docker-consumer`, plus `workflow_run` and `attempt` strings.
The canonical `DOCKERLENS_NATIVE_APPARMOR_PROFILE: ` output prefix is retained.
The pure read-only `validate-box-consumer-receipt <LensSHA> <run> <attempt>`
validator accepts only a current-context Box receipt with verified label and
proven profile removal. It rejects native, duplicate, extra, missing, malformed
and cross-attempt records without using runner environment or privileged I/O.
A valid receipt is not source authorization or proof of a full application.

## Consequences and verification

Box owns its trusted lifecycle, fixed source/import closure, actor/head checks,
current-attempt evidence binding and aggregate. Its existing work/cleanup owners
must encompass all phases; the Lens native watchdog is not a new Box allowance.
Other lanes must not fabricate profile success. This helper addition alone does
not deliver Box integration, native compatibility, cgroup/PIDs authority,
application acceptance, publication or deployment permission.

Hermetic tests exercise both fixed contexts and the same custody, parser,
uncertain completion, cancellation, effective-label/cgroup and absence/unload
controls, with explicit cross-mode and current-attempt refusals. All three native
workflow consumers remain unchanged. Other Box workflows, local/self-hosted
runners and other products gain no profile operation. The primary integrates the
separately reviewed patch before one final combined Lens freeze, complete gate
and fresh four-lane native campaign, followed by the required exact-pair Box
consumer qualification. Old or intermediate evidence qualifies none of these
changed final-source obligations.
