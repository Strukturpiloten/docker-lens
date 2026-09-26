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
Rust toolchain through `renovate.json`. Its one native-image regex manager owns
the four version-tag plus manifest-digest pairs in
`scripts/native-conformance.sh`; the policy test checks exact extraction and
avoids duplicate manager ownership. These registry digests were verified with
`skopeo inspect` on 2026-09-26. Image updates need native reruns and independent
review; automerge is disabled for them.

Debian 11 `docker.io=20.10.5+dfsg1-1+deb11u4`,
`ca-certificates=20250419~deb12u1~deb11u1`,
`rootlesskit=0.14.2-1+b3` (the Debian 11 amd64 binary revision),
`slirp4netns=1.0.1-2`,
`uidmap=1:4.8.1-1+deb11u1`, and `fuse-overlayfs=1.4.0-1` were checked against
Debian package listings on 2026-09-26. The harness installs them through
Debian's signed APT metadata inside the pinned Debian 11 image and asserts
each installed revision. The guest replaces that image's live APT sources with
the official `20260824T000000Z` Debian Snapshot for Bullseye, Bullseye
security, and Bullseye updates. The live security index still lists the pinned
`docker.io` revision but its package URL returned 404 on 2026-09-26; the same
artifact and all three signed snapshot `InRelease` files were available at the
fixed snapshot. Only historical `Valid-Until` expiry is disabled; APT signature
and package-hash verification remain enabled. This is a frozen compatibility
baseline, not evidence that Debian 11 still receives security maintenance.
Renovate has no supported manager for Debian APT
package revisions in shell variables here; the repository maintainer owns a
manual check of these six pins before every native release candidate and
if an archive or package revision changes. The check compares the fixed
snapshot's package listing and `apt-cache policy` in the pinned image, updates
the exact revision or snapshot date in the harness and policy tests, and reruns
both Debian native lanes. The immutable archive timestamp is not a software
version and has no Renovate manager; the image pin still has one regex manager.
Never change only the upstream Engine tag to represent a distribution update.

`podman`, `curl`, `python3`, `timeout`, and core utilities are provided
by the Ubuntu 24.04 runner; no binary download is introduced. Historical
captures and fixtures remain immutable and are not auto-updated.

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
