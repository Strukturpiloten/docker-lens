# Repository guidance for coding agents

This file applies to the entire DockerLens repository.

## Product scope

DockerLens contains native contracts and a pure Docker Engine capture decoder, not a live
transport or proven Engine compatibility. Read this file,
`README.md`, `docs/architecture.md`, `docs/verification.md`, and relevant decisions before editing.
No acquisition transport, target planner/renderer, or Engine conformance is implemented yet.
Pure decoder tests do not establish native compatibility. Product libraries must not depend on BoxFerry.

## Workspace scope and standing GitHub authorization

The maintainer grants standing authorization for task-related Git and GitHub work only in these
workspace repositories:

- `Strukturpiloten/boxferry`
- `Strukturpiloten/compose-lens`
- `Strukturpiloten/podman-lens`
- `Strukturpiloten/quadlet-lens`
- `Strukturpiloten/boxferry-website`
- `Strukturpiloten/docker-lens`

Do not work on or modify any repository outside this explicit allowlist, including its issues,
pull requests, branches, settings, or workflows. An upstream documentation reference is not
permission to operate on that upstream repository. A newly discovered checkout is not implicitly
in scope.

For user-requested work within this scope, the primary agent may create issues, branches, commits,
pushes, and pull requests and merge verified task-related pull requests without asking for renewed
approval. This permission does not authorize unrelated backlog work, implementation of
discussion-only proposals, or expansion of the requested product scope. A later user instruction
may narrow or revoke this permission.

Immediately before merging, read back the exact head commit and verify that the pull request is
ready, mergeable, independently reviewed, and has every required check successful. Use the normal
merge method with an exact-head safeguard; never bypass branch protection or use an administrator
override. Read back the merged state and merge commit, synchronize local `main` with `origin/main`,
and remove the task's recorded worktrees and verified merged local branches while preserving
unrelated work.

This standing permission does not authorize releases, publication, deployment operations, or
merging release/publication/deployment pull requests; those require a separate explicit request.
The primary agent owns all Git and GitHub writes. Subagents remain within their assigned task and
checkout and must not perform those writes.

## GitHub issue-to-PR workflow

1. Inspect status and the complete diff; preserve unrelated changes.
2. Search for duplicates, then create or reuse one focused issue.
3. Fetch `origin/main`, synchronize local `main`, and create `TheRealBecks/issue<NUMBER>`.
4. Implement the bounded change and obtain an independent read-only review.
5. Run the complete scaffold gate below after the final edit. A failed or incomplete run is a hard gate
   against commit, push, and pull-request creation; any later edit invalidates the result.
6. Stage explicit paths, run `git diff --cached --check`, review the staged diff, and create one
   intentional Conventional Commit. Use a product type for product changes and `docs`, `test`,
   `ci`, `build`, `style`, or `chore` for non-release work.
7. Push and open a ready pull request containing `Closes #<NUMBER>`. Read back the issue, commit,
   pull request, and available checks.
8. Apply the standing authorization and exact-head safeguards above before merging.
9. After verifying the merged state and merge commit, synchronize the primary checkout with
   `origin/main`. Remove only the recorded task worktree with
   `git worktree remove <recorded-path>`, delete the verified merged local issue branch with
   `git branch --delete --force TheRealBecks/issue<NUMBER>`, and run
   `git worktree prune --verbose`. Read back `git worktree list --porcelain` and
   `git status --short --branch`.

## Agent roles and verification

Model defaults belong in [`.codex/config.toml`](.codex/config.toml); task-specific models and
reasoning belong in [`.codex/agents/`](.codex/agents/). The primary manager always uses
`gpt-6-sol` with `xhigh` reasoning. Implementation, specification research, and independent review
use `gpt-6-sol` with `high` reasoning; check-only verification uses `gpt-6-luna` with `high`
reasoning. Use Luna for bounded read-only exploration and Sol for difficult failure diagnosis;
reserve Astra at `xhigh` for particularly difficult architectural questions.
These model settings do not expand the workspace scope or grant additional permissions.

- Delegate bounded tasks when independent work can usefully proceed in parallel. Define the shared
  contract and explicit repository, checkout, and file ownership before delegation.
- Use up to nine concurrent subagents plus the primary manager, subject to the session's actual
  runtime limit. Nine is a ceiling, not a target or nine distinct roles: several subagents may use
  the same role for independent tasks. Do not create nested agents to evade the limit.
- Never run two writers in one checkout. Use separate assigned repositories or worktrees for
  concurrent implementation. Research and review remain read-only.
- The reviewer checks the original requirements and independent expected results, not just agreement
  between the implementation and its tests.
- After writing finishes, the verifier runs the complete scaffold gate listed below. It reports
  failures without formatting or editing tracked files; ignored caches are allowed.
- Run at most one complete gate or heavy runtime suite at a time across this workspace. Agent
  concurrency is not permission for competing builds. The primary owns integration, the final
  complete gate, and every authorized Git or GitHub write.

## Complete scaffold validation

Run `./scripts/format-lint.sh --fix`, then `./scripts/check-all.sh --check` after the final edit.
The complete gate covers formatting, Clippy, unit and documentation tests, policy tests, and docs.
The release validation workflow must also pass native Engine conformance for the exact candidate;
its native script deliberately fails until the separately reviewed suite is implemented. Never
silently skip a required check or claim native compatibility from scaffold tests.

## Shared workflow and dependency changes

Before changing shared task definitions, identify all consumers in the six authorized workspace
repositories. Reuse common logic without making independently published Lens libraries depend on
BoxFerry. Coordinate affected consumers and record justified no-change decisions in the issue or
PR. Review Renovate ownership whenever an operational pin or its location changes; preserve
immutable action pins, least privilege, evidence boundaries, budgets, and cleanup. This scaffold
adds a pinned toolchain, GitHub Action, and Renovate configuration. Agent model choices
are maintainer-owned routing policy, not automatically updated software release versions.

## Cross-repository workflow and version policy

- Keep equivalent local development tasks and GitHub PR, main, and release workflow definitions
  aligned across BoxFerry, ComposeLens, PodmanLens, QuadletLens, DockerLens, and the website where
  their responsibilities match. Before a change, identify the canonical definition and every
  affected consumer; coordinate updates and document justified repository-specific differences.
- Reuse common scripts, actions, and workflows without making Lens product libraries depend on
  BoxFerry. Preserve native conformance, least privilege, exact-candidate evidence, resource budgets,
  and cleanup. One repository passing does not establish that the shared rollout is complete.
- Every added or changed software dependency or operational tool/runtime pin needs an explicit
  version and immutable integrity information where the ecosystem supports it:
  - Container images: a readable version tag plus an immutable digest.
  - GitHub Actions and reusable workflows: a full commit SHA plus an exact release-tag comment.
  - Downloaded tools: a version plus a verified checksum for the selected artifact.
  - Package dependencies: policy-compliant version declarations and lockfile integrity records.
  Document justified exceptions when integrity metadata is unavailable; never invent a checksum,
  replace a reviewed pin with a floating reference, or weaken existing admission controls.
- Whenever a pin or definition is added, changed, moved, or removed, review Renovate in the same
  change: canonical ownership, manager paths and extraction, grouping, approvals, and regression
  coverage. Update configuration and affected consumers together. If no configuration edit is
  needed, record verified extraction evidence and the reason in the issue or PR. Avoid duplicate
  managers for the same operational pin; keep historical evidence and intentional fixtures outside
  automatic update streams.
- These rules do not change current validation gates or grant release, publication, deployment,
  or out-of-workspace authority. Agent model choices remain maintainer-owned routing policy, not
  automatically updated software dependencies.

## Code discovery

Use an available codebase-memory graph for structural exploration, or an existing usable CodeGraph
index. Do not create an index without user authorization. Use `rg` and targeted reads when no graph
can answer the question, and directly for configuration and documentation.
