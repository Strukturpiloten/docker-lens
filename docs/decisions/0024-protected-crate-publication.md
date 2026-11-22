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

The workflow restricts its own dispatch to main. GitHub's environment policy
applies independently to other eligible workflow definitions and refs. The
review-history API supplies reviewer, environment, state and comment. GitHub
allows a comment during approval and bypass, and the history schema has neither
an approval-method marker nor an attempt field. The statement binds the evidence
to this attempt. It cannot prove which action admitted the job. Publication stays
closed and this workflow has no registry credentials. A future enablement will
require evidence distinguishing genuine personal approval from bypass, and the
registry and eligible-ref verification in [the release guide](../releasing.md).

Product, manifest, lockfile and native qualification remain with their existing
owners. This change adds neither Git tag nor GitHub release creation. The
workflow change itself leaves candidate selection and publication decisions with
the maintainer.
