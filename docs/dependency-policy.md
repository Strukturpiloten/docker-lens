# Dependency and pin policy

The scaffold has no third-party Rust package dependencies. `Cargo.lock` is
committed for repeatable validation. `rust-toolchain.toml` pins Rust 1.98.1;
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
