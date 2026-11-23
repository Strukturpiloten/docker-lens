#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  --preflight | --review) ;;
  *)
    echo "Expected --preflight or --review." >&2
    exit 1
    ;;
esac

test "${GITHUB_REPOSITORY}" = Strukturpiloten/docker-lens
test "${GITHUB_EVENT_NAME}" = workflow_dispatch
test "${GITHUB_REF}" = refs/heads/main
if [[ "${GITHUB_RUN_ATTEMPT}" != 1 ]]; then
  echo "Publication requires a new release dispatch and review." >&2
  exit 1
fi
[[ "${GITHUB_RUN_ID}" =~ ^[1-9][0-9]*$ ]]
[[ "${EXPECTED_SHA}" =~ ^[0-9a-f]{40}$ ]]
test "${GITHUB_SHA}" = "${EXPECTED_SHA}"

repository="repos/${GITHUB_REPOSITORY}"
environment="${repository}/environments/release"
if ! gh api "${repository}/branches/main" | jq -se --arg sha "${EXPECTED_SHA}" '
  select(length == 1) | .[0] |
  .name == "main" and .protected == true and .commit.sha == $sha
' > /dev/null; then
  echo "The release candidate must be the current protected main." >&2
  exit 1
fi
if ! environment_id="$(gh api "${environment}" | jq -ser '
  select(length == 1) | .[0] |
  select(.name == "release"
    and .deployment_branch_policy.custom_branch_policies == true
    and .deployment_branch_policy.protected_branches == false
    and ([.protection_rules[] | select(.type == "required_reviewers")
          | .reviewers[] | [.type, .reviewer.type, .reviewer.login, .reviewer.id]]
         == [["User", "User", "TheRealBecks", 1497405]]))
  | .id | select(type == "number" and . == 22952362673)
')"; then
  echo "The release environment must require TheRealBecks and verify its live identity." >&2
  exit 1
fi
if ! gh api "${environment}/deployment-branch-policies" |
  jq -se 'select(length == 1) | .[0] |
    .branch_policies | type == "array" and
    any(.[]; .type == "branch" and .name == "main")' > /dev/null; then
  echo "The release environment must admit the main branch." >&2
  exit 1
fi
if [[ "$1" == --preflight ]]; then
  printf 'environment_id=%s\n' "${environment_id}" >> "${GITHUB_OUTPUT}"
  exit 0
fi

test "${environment_id}" = "${PREPARED_ENVIRONMENT_ID}"
test -n "${APPROVAL_COMMENT}"
if ! gh api "${repository}/actions/runs/${GITHUB_RUN_ID}/approvals" |
  jq -se --argjson id "${environment_id}" --arg comment "${APPROVAL_COMMENT}" '
    def identified_environment:
      (.name | type == "string" and length > 0) and
      (.id | type == "number" and . > 0 and . == floor);
    select(length == 1) | .[0] | type == "array" and
    all(.[]; .environments | type == "array" and length > 0 and
      all(.[]; identified_environment)) and
    ([.[] | select(any(.environments[];
      (.name | ascii_downcase) == "release" or .id == $id))]
      | length == 1
      and ([.[0].environments[] | [.name, .id]] == [["release", $id]])
      and .[0].state == "approved"
      and .[0].user.type == "User"
      and .[0].user.login == "TheRealBecks"
      and .[0].user.id == 1497405
      and .[0].comment == $comment)
  ' > /dev/null; then
  echo "This attempt needs an exact personal release approval from TheRealBecks." >&2
  exit 1
fi
