# Dependency and pin policy

The decoder pins `serde_json = 1.0.149` for pure Engine JSON parsing. The
committed `Cargo.lock` records its dependency graph and registry checksums.
Renovate's existing Cargo manager owns this package and lockfile; no duplicate
regex manager or extraction path is needed. `rust-toolchain.toml` pins Rust 1.98.1;
`Cargo.toml` declares MSRV 1.85.0. Cargo/rustup distribution uses its standard
toolchain integrity mechanism; no independently verified download checksum is
claimed here.

GitHub Actions use full commit SHAs with exact release-tag comments. The
runner is `ubuntu-24.04`. Renovate owns Cargo, GitHub Actions, and the pinned
Rust toolchain through `renovate.json`. Native test images and downloaded tools
must be added with readable versions and verified immutable integrity records
before their workflows are enabled. Historical captures and fixtures are
immutable and must not be auto-updated.

Shared workflow rollout decisions: this repository adopts the workspace's
canonical `scripts/format-lint.sh` and `scripts/check-all.sh` entry points.
No change is needed in the other five repositories for this independent scaffold;
their native/product gates retain their own responsibilities. Any future shared
definition change requires reviewing every consumer and Renovate ownership.
