#!/usr/bin/env bash
set -euo pipefail

unset DOCKERLENS_METADATA_UNCHANGED

mode="${1:---fix}"
case "$mode" in
  --fix | --check) ;;
  *)
    echo "usage: $0 [--fix|--check]" >&2
    exit 2
    ;;
esac
"$(dirname "$0")/format-lint.sh" "$mode"
"$(dirname "$0")/check-msrv.sh"
cargo test --all-targets --locked
cargo test --doc --locked
cargo doc --no-deps --locked
# Run repository policy suites through the immutable shared Python project.
if [[ "${GITHUB_ACTIONS:-false}" == true ]]; then
  python3 scripts/validation-plan.py run --task setup-tools-hosted
else
  python3 scripts/validation-plan.py run --task setup-tools
fi
export PATH="$PWD/target/shared-tools/bin:$PATH"
python3 scripts/validation-plan.py run --task documentation
python3 scripts/validation-plan.py run --task python-quality
cargo deny --all-features check
# The canonical helper owns trusted development baseline and exact tool/compiler selection.
python3 scripts/validation-plan.py run --task api-development \
  --report-json target/api-development-task.json
git diff --check
