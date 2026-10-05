# Dependency and pin policy

The decoder pins serde_json 1.0.151 for pure Engine JSON parsing and BoxFerry's
reviewed consumer floor. The bounded Unix-socket connector pins socket2 0.6.5
for connect_timeout. Cargo.lock
records their dependency graphs and registry checksums. Renovate owns Cargo
manifest pins and lockfile through its Cargo manager. rust-toolchain.toml pins
Rust 1.98.1; Cargo.toml declares MSRV 1.85.0. Rust distribution uses its
standard toolchain integrity mechanism; no separate checksum is claimed.
`scripts/check-msrv.sh` derives that minimum from `Cargo.toml` and asks
rustup to install its verified distribution before checking all targets. The
serde_json pin remains owned by Renovate's existing Cargo manager; no regex
manager, manager path, grouping rule, or additional dependency is needed.

GitHub Actions use full commit SHAs with exact release-tag comments on
ubuntu-24.04. Renovate owns Cargo, GitHub Actions, and the pinned Rust toolchain.
One native-image regex manager extracts the five distinct version-tag plus
manifest-digest pairs in scripts/native-conformance.sh: four GHCR Engine images
and the BusyBox fixture. The policy test checks exact extraction and unique
ownership. Image updates require full native reruns and independent review;
automerge is disabled.

The four Engine images were published by containers#260 at commit
0b136a13a8bb612d91960ae5d07e72f449c89ec1. Their AMD64 and ARM64
manifests were verified on 2026-09-28. Debian 11 rootful and rootless are
tagged v1.0.0; upstream Engine 29 rootful and rootless are tagged v29.8.1.
The readable tags and immutable manifest digests are both required. Their
native entrypoints, package lists, and runtime provenance are owned by the
published images. DockerLens does no runtime APT installation.

Both Debian images contain native docker.io
20.10.5+dfsg1-1+deb11u2. The harness checks that exact installed revision
and reports the Engine release separately. It is a historical Debian 11
compatibility baseline, not a security support claim. The retired snapshot
install procedure selected a different +deb11u4 revision; its files are no
longer part of the harness. On image updates, review the published package
provenance and rerun both Debian modes. Never infer the Debian package
revision from the v1.0.0 image tag.

The harness uses an explicit named Podman volume at each image's declared
Docker data root and disables automatic image volumes. It checks the exact
mounted volume. The Debian 11 rootless profile also requires the privileged
rootful outer Podman process to set --oom-score-adj=0. This is confined to
the validation-only test harness.

The native workflows upload only a closed, sanitized per-lane JSON record
after all native checks pass. actions/upload-artifact is pinned to a full
commit SHA with exact v4.6.2 release-tag comment, extracted by Renovate's
GitHub Actions manager. The record contains exact candidate SHA, image
reference, observed Engine/API bounds, acquisition and rendering API versions,
reported containerd and runc component versions, mode, Debian package revision
when applicable, and tested capability names.
A green offline PR check does not create native evidence. A reviewed native
run and independent readback are still required before any compatibility
catalog entry can be admitted.

podman, curl, python3, timeout, util-linux `nsenter`, and core utilities are
supplied by the Ubuntu runner; no binary download or independent pin is
introduced. The native helper preflights namespace entry before relying on
it. Historical captures and
fixtures remain immutable and outside automatic updates. The manual native
dispatcher uses the existing checkout Action and runner Python standard
library, so it needs no separate tool or manager. Shared workflow rollout
decisions remain repository-specific: the scaffold uses the workspace's
canonical scripts/format-lint.sh and scripts/check-all.sh entry points; the
other five repositories retain their independent native and product gates.

The native bridge prerequisite uses the Ubuntu runner's kernel-provided
`br_netfilter` and its installed `sudo`/`modprobe`; it downloads no tool and
pins no independently versioned module. Kernel/module bytes follow the
version-selected but mutable `ubuntu-24.04` GitHub-hosted runner image;
GitHub exposes no stable per-image or per-module digest to this repository.
This is an explicit unavailable-integrity and manual-review exception, not
a floating new package dependency: no package or
module installation, sysctl write, or fallback pin is introduced. Renovate's
existing GitHub Actions manager continues to own full Action refs, and the
native-image regex manager continues to extract the same five references
from `scripts/native-conformance.sh`; neither gains a moved or duplicate pin.
The canonical harness is consumed by `check.yml` main push,
`native-validation.yml` trusted-main dispatch, and `release-validation.yml`
exact-main dispatch. All three inherit the same prerequisite without a
workflow edit. The other five workspace repositories do not invoke this
DockerLens native harness, so no cross-repository consumer changes are needed.
