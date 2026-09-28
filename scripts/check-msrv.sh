#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
msrv=$(python3 - "$script_dir/../Cargo.toml" <<'PY'
import re
import sys
import tomllib

with open(sys.argv[1], "rb") as manifest:
    version = tomllib.load(manifest).get("package", {}).get("rust-version")
if not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
    raise SystemExit("Cargo package.rust-version must be an exact Rust release")
print(version)
PY
)

# rustup verifies the official Rust distribution; keep the advertised minimum
# separate from the newer pinned lint/doc toolchain.
rustup toolchain install "$msrv" --profile minimal
rustup run "$msrv" cargo check --all-targets --locked
