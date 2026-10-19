# Dependency and pin policy

The decoder pins serde_json 1.0.154 for pure Engine JSON parsing and BoxFerry's
reviewed consumer floor. The bounded Unix-socket connector pins socket2 0.6.5
for connect_timeout. Cargo.lock
records their dependency graphs and registry checksums. Renovate owns Cargo
manifest pins and lockfile through its Cargo manager. rust-toolchain.toml pins
Rust 1.98.1; Cargo.toml declares the same MSRV, 1.98.1. Clippy derives its MSRV
from that manifest without a separate override. Rust distribution uses its
standard toolchain integrity mechanism; no separate checksum is claimed.
`scripts/check-msrv.sh` derives that minimum from `Cargo.toml` and asks
rustup to install its verified distribution before checking all targets, using
`--no-self-update` so compiler installation does not update the separately
managed rustup executable or depend on it residing in the current `CARGO_HOME`.
The flag applies only to this invocation; distribution verification and exact
compiler selection remain required. The
serde_json pin remains owned by Renovate's existing Cargo manager; no regex
manager, manager path, grouping rule, or additional dependency is needed.

The next runtime-source milestone aligns this exact pin with BoxFerry's reviewed
upstream dependency update (BoxFerry PR #113). Its locked 1.0.154 cannot unify
with DockerLens's earlier exact 1.0.151 requirement; the failed downstream
source rehearsal is not passing evidence. The registry checksum is the same
published checksum already recorded by that upstream lockfile, not an invented
integrity value. Complete parser/decoder, source-consumer and native gates must
be rerun for the changed candidate. Historical source records retain the
dependencies used at execution. Renovate's enabled native Cargo manager still
owns exactly this manifest pin and lockfile; neither location, manager, grouping
nor approval policy changes, so no Renovate configuration edit is needed.

The Rust 1.98.1 minimum alignment changes no extraction path or dependency
resolution. The existing toolchain regex extracts exactly one 1.98.1 channel;
the enabled Cargo manager owns the manifest and lockfile, and GitHub Actions
owns Action refs. No new or duplicate manager is needed. Existing native-image
grouping and manual review remain unchanged. Local validation, PR/main Check,
reviewed native dispatch, and Release validation consume the same
`scripts/check-all.sh` and manifest-derived `scripts/check-msrv.sh`; no workflow
pin or definition needs a separate version edit. Historical evidence and native
Engine baselines retain their recorded versions.

The ignored health-metadata proof uses the dev-only exact `libc = 0.2.189`
declaration for platform-correct no-follow/directory open flags. That version
and its registry checksum already existed in the locked socket2 graph; no
package version or checksum was invented or changed. Product dependencies
remain serde_json/socket2. Renovate's enabled Cargo manager owns this new
`Cargo.toml` dev pin and the existing lockfile; no custom manager/path/grouping
or approval rule is added. The policy regression checks its unique native Cargo
ownership. The crate's Linux-only native validation is unchanged.

The dev-only `rustix` pin in `Cargo.toml` enables only `std` and `time` for a
safe absolute `CLOCK_MONOTONIC` reading in the private PIDs harness. It does not
enter the product dependency graph or relax `forbid(unsafe_code)`. The original
absolute phase deadline remains authoritative; wall-clock timestamps and a fresh
relative duration cannot renew it. `Cargo.lock` records the registry versions and
published checksums, not hand-authored integrity values. The existing enabled
Cargo manager uniquely owns this manifest declaration and its lockfile; the two
regex managers match only the toolchain and native-image script, not Cargo files.
No manager, extraction path, grouping or approval setting changes. The scaffold
policy regression verifies this ownership, the minimal features, exact version
and locked registry integrity. No other repository consumes this test-only pin;
their independent native gates and product dependencies remain unchanged.

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

podman, curl, python3, timeout, and core utilities are supplied by the
Ubuntu runner; no binary download is introduced. Historical captures and
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

The scaffold-only outer-runtime identity diagnostic uses installed `sudo`,
`timeout`, Podman, Git, `dpkg-query`, and Python from the same mutable
`ubuntu-24.04` runner. The unavailable-integrity/manual-review exception above
also applies to these runner-provided tools: no installation, download, new pin,
or independently authenticated binary provenance is introduced. Strictly parsed
distro package metadata is only reported metadata, not proof of custom binary
ownership. Only `check.yml`'s scaffold job consumes this diagnostic; native jobs,
main's native harness, trusted-main native dispatch, release validation, and the
other workspace products do not gain a shared native qualification step and need
no corresponding change. Existing complete and native gates remain unchanged.

Renovate ownership, extraction paths, grouping, approvals, and regression review
are unchanged: the native-image manager still extracts exactly the same five
tag/digest references and the GitHub Actions manager still owns the same full-SHA
Action refs. No manifest, toolchain, image, Action pin, or Renovate configuration
changes are required; existing scaffold policy extraction checks cover those
five references and manager ownership.
