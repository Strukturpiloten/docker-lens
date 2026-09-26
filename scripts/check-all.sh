#!/usr/bin/env bash
set -euo pipefail

mode="${1:---fix}"
case "$mode" in
  --fix|--check) ;;
  *) echo "usage: $0 [--fix|--check]" >&2; exit 2 ;;
esac
"$(dirname "$0")/format-lint.sh" "$mode"
cargo test --all-targets --locked
cargo test --doc --locked
cargo doc --no-deps --locked
python3 -m unittest discover -s tests -v
git diff --check
