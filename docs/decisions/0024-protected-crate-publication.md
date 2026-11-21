# ADR 0024: Protected DockerLens crate publication

Status: accepted for staged adoption

Amends the publication-disabled boundary of [ADR 0022](0022-shared-development-automation.md)
and [ADR 0023](0023-development-and-published-api-checks.md). Retains their
standalone validation entry point, complete native and offline prerequisites,
published API policy and exact-current-main checks.

DockerLens reuses its validation workflow inside an explicit Release dispatch.
A credential-free job binds the required version and finalized notes to the
validated commit. Only an explicitly requested publishing run on main enters the
existing GitHub `release` environment. The publisher checks its live main-only
branch policy and disabled administrator bypass, requires the record of
TheRealBecks's approval, compares the commit with live main, and rechecks version
and notes before calling the admitted shared crate publisher. Repeated attempts
require a new run and approval. Before registry activation the maintainer must
remove tag eligibility and disable bypass. The external Trusted Publisher must match
DockerLens, `release.yml`, and `release`, as described in [the release guide](../releasing.md).

Product, manifest, lockfile and native qualification remain with their existing
owners. This change adds neither Git tag nor GitHub release creation. The
workflow change itself leaves candidate selection and publication decisions with
the maintainer.
