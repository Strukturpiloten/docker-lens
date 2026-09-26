# Dependency and pin policy

The decoder pins `serde_json = 1.0.149` for pure Engine JSON parsing. The
bounded Unix-socket connector pins `socket2 = 0.6.5` for its safe
`connect_timeout` operation. The committed `Cargo.lock` records their dependency
graphs and registry checksums. Renovate's existing Cargo manager owns both
manifest pins and the lockfile (`enabledManagers` includes `cargo`); the
custom regex manager only extracts `rust-toolchain.toml`, so there is no
duplicate manager or new extraction path. `rust-toolchain.toml` pins Rust 1.98.1;
`Cargo.toml` declares MSRV 1.85.0. Cargo/rustup distribution uses its standard
toolchain integrity mechanism; no independently verified download checksum is
claimed here.

GitHub Actions use full commit SHAs with exact release-tag comments. The
runner is `ubuntu-24.04`. Renovate owns Cargo, GitHub Actions, and the pinned
Rust toolchain through `renovate.json`. Native test images and downloaded tools
must be added with readable versions and verified immutable integrity records
before their workflows are enabled. Historical captures and fixtures are
immutable and must not be auto-updated.

The manual native dispatcher reuses the existing checkout Action SHA and exact
tag, which Renovate's GitHub Actions manager already extracts from every
`.github/workflows/*.yml` file; `tests/test_scaffold_policy.py` checks all
workflow Action pins. No new Renovate manager or extraction path is needed.
The admission helper uses the Ubuntu runner's Python standard library and
introduces no downloaded binary. The dispatcher introduces no native image
pin; #13 must add its reviewed version-plus-digest pins with its own suite.

Shared workflow rollout decisions: this repository adopts the workspace's
canonical `scripts/format-lint.sh` and `scripts/check-all.sh` entry points.
No change is needed in the other five repositories for this independent scaffold;
their native/product gates retain their own responsibilities. Any future shared
definition change requires reviewing every consumer and Renovate ownership.
