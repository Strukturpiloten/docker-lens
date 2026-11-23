# ADR 0024: Protected DockerLens crate publication

Status: accepted for staged adoption

Amends the publication-disabled boundary of [ADR 0022](0022-shared-development-automation.md)
and [ADR 0023](0023-development-and-published-api-checks.md). Retains their
standalone validation entry point, complete native and offline prerequisites,
published API policy and exact-current-main checks.

DockerLens reuses its validation workflow inside an explicit Release dispatch.
A credential-free job binds the required version and finalized notes to the
validated commit. Only an explicit first-attempt approval check on main enters the
existing GitHub `release` environment, which retains its main and `v*` rules and
administrator bypass setting. The check requires one approved review for the live
environment ID from TheRealBecks, with a statement binding the run, first attempt,
SHA, version and notes digest. It rechecks main, version and notes after reading the
review. A subsequent attempt requires a new run and review.

## Maintainer-adopted DockerLens amendment (#242)

The maintainer approved publication under the existing settings for DockerLens
only. The protected job invokes the immutable shared BoxFerry crate publisher
selected by `.github/automation.json`, after complete offline, dependency,
published API and four native Engine checks, credential-free inventory, exact
personal review evidence and a final source/version/notes recheck. A credential-free admission job verifies first-attempt protected current main
before expensive validation in both modes. Only the protected publication job
has `id-token: write`; validate-only remains the default and requests neither
environment admission nor registry credentials. Retries require a fresh dispatch.
Preflight and review verify protected current main and the existing environment
ID `22952362673`, with TheRealBecks (`1497405`) as sole required reviewer.

The owner confirmed the crates.io tuple `docker-lens`, GitHub repository
`Strukturpiloten/docker-lens`, workflow `release.yml`, environment `release`.
This registration is owner-confirmed and independently API-unavailable; the
historical API 403 does not invalidate that confirmation. Existing settings stay
unchanged. The maintainer accepts these limits:

- GitHub permits administrator bypass. Review history has state, reviewer,
  environment and comment, but no approval-method marker or attempt field.
  Exactly one matching approved record and the exact first-attempt statement
  bind run, SHA, version and notes; they cannot distinguish ordinary approval
  from bypass. The human must use **Approve and deploy**, never agent approval.
- The environment also admits `v*` tags, and the registry registration has no
  Git-ref selector. This caller refuses tag dispatch and reruns. Another eligible
  workflow definition on a `v*` ref can satisfy the same registration outside
  this caller's main guard. No global ref or administrator restriction is claimed.

Policy adoption does not establish activation or publication. Record the merged
caller source and its integrated qualification separately, then the first real
publication run, human approval and canonical registry visibility as separate
evidence. No release dispatch or publication is authorized by implementation.

Product, manifest, lockfile and native qualification remain with their existing
owners. This change adds neither Git tag nor GitHub release creation. The
workflow change itself leaves candidate selection and publication decisions with
the maintainer.
