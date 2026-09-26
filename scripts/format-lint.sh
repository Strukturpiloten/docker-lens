#!/usr/bin/env bash
set -euo pipefail

mode="${1:---fix}"
case "$mode" in
  --fix) cargo fmt --all ;;
  --check) cargo fmt --all -- --check ;;
  *) echo "usage: $0 [--fix|--check]" >&2; exit 2 ;;
esac
cargo clippy --all-targets --locked -- -D warnings
