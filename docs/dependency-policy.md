# Dependency and pin policy

Common Cargo, Rust toolchain, Action and source-adoption update policy lives in
immutable BoxFerry common/Rust presets. See [shared automation](shared-automation.md)
for staged trust, the 72-hour rule, exact first-party exception and rollback.
The native-image regex still owns exactly five tag/digest pairs; no image or
historical native evidence is changed by this adoption. Downloaded development
tools have one version/checksum inventory in the immutable shared source, with
both Linux architectures validated and partial updates rejected.

The following records preserve product-specific ownership and historical source
provenance. Their recorded versions are not a second shared development-tool pin
list.

The [hosted prerequisite diagnostic](hosted-prerequisite-diagnostic.md) adds no
software installation, product dependency or operational version pin. Its sole
consumer is Check's main-only diagnostic job; normal PR/main validation, native
dispatch, release validation and the other workspace products retain their gates.
The diagnostic uses the same full checkout and upload-artifact SHAs as the
canonical native workflow. Renovate's GitHub Actions manager owns those Action
refs and the `ubuntu-26.04` `runs-on` label advanced in #188. The collector's
`ubuntu26` and `26.04` values check runner metadata and do not select software.
Shared adoption keeps common policy in immutable presets and preserves the five
native-image extractions. Runner Python/coreutils/dpkg/systemd follow the existing
mutable Ubuntu 26.04 runner unavailable-integrity boundary. Observed installed
package versions and hash-only helper/control/unit metadata are not new pins,
authenticated publisher integrity or permission to update/install them.
No third-party source is redistributed; copyright hashes and fixed provenance
references support later independent source/license review. Historical evidence
is not rewritten or added to automatic update streams.

The decoder pins serde_json 1.0.151 for pure Engine JSON parsing and BoxFerry's
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

The Rust 1.98.1 minimum alignment changes no extraction path or dependency
resolution. The existing toolchain regex extracts exactly one 1.98.1 channel;
the enabled Cargo manager owns the manifest and lockfile, and GitHub Actions
owns Action refs. No new or duplicate manager is needed. The exact qualified native-image tuples
remain fixed during this overhaul. Local validation, PR/main Check,
reviewed native dispatch, and Release validation consume the same
`scripts/check-all.sh` and manifest-derived `scripts/check-msrv.sh`; no workflow
pin or definition needs a separate version edit. Historical evidence and native
Engine baselines retain their recorded versions.

The ignored health-metadata proof uses a dev-only exact `libc` requirement
for platform-correct no-follow/directory open flags. Its initial `0.2.189`
version and checksum already existed in the locked socket2 graph; that is
historical introduction evidence, not a fixed native-runtime target. Ordinary
Renovate Cargo updates may advance the exact manifest requirement and matching
unique crates.io lock entry together, retaining its registry checksum. The
policy regression checks that coupling, valid checksum metadata and sole native
Cargo ownership instead of freezing the historical version or checksum. Product
dependencies remain serde_json/socket2; no custom manager, grouping or approval
rule is added. The crate's Linux-only native validation is unchanged.

DockerLens's direct hosted jobs select `ubuntu-26.04`. Action refs use full
commit SHAs with exact release-tag comments. Renovate owns Cargo, GitHub Actions,
and the pinned Rust toolchain.
One native-image regex manager extracts the five distinct version-tag plus
manifest-digest pairs in scripts/native-conformance.sh: four GHCR Engine images
and the BusyBox fixture. The policy test checks exact extraction and unique
ownership. Native image changes remain subject to the separately owned exact-candidate
qualification policy and fresh native evidence; shared automatic dependency
mechanics do not grant compatibility admission.

The four Engine images were published by containers#260 at commit
0b136a13a8bb612d91960ae5d07e72f449c89ec1. Their AMD64 and ARM64
manifests were verified on 2026-09-28. Debian 11 rootful and rootless are
tagged v1.0.0; upstream Engine 29 rootful and rootless are tagged v29.8.1.
The readable tags and immutable manifest digests are both required. Their
native entrypoints, package lists, and runtime provenance are owned by the
published images. The four-lane native harness does no runtime APT installation.

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
version-selected but mutable `ubuntu-26.04` GitHub-hosted runner image;
GitHub exposes no stable per-image or per-module digest to this repository.
This is an explicit unavailable-integrity prerequisite exception, not
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

The [fixed-fixture inventory](shared-automation.md#fixed-qualified-native-fixtures)
records the exact five disabled native-image/path tuples; other dependency
updates inherit the shared automatic policy.


The [hosted zero-swap boot trial](hosted-zero-swap-trial.md) is the sole consumer
of its own fixed pin file. GitHub Actions owns the workflow's checkout and
upload-artifact SHAs and release comments. Two path-scoped regex managers own
the dated Ubuntu image/hash and Debian fixture tag/index digest. The Noble
release directory supplies version discovery. Both image records are held
together with the signed archive snapshot and exact package versions, and with
the fixture's audited product SHA, platform manifest and config. The trial's
group requires a reviewed coherent refresh before routine replacement.
A release index alone cannot supply the verified signed image row or the
fixture's audited source and platform binding. The Ubuntu snapshot's signed
indexes provide package hashes and dependency provenance. The listed package
versions and snapshot date are a single reviewed update. The existing five
native-image pins and cross-repository workflow call sites retain their
ownership.
