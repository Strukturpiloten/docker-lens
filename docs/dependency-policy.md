# Dependency and pin policy

The [hosted prerequisite diagnostic](hosted-prerequisite-diagnostic.md) adds no
software installation, product dependency or operational version pin. Its sole
consumer is Check's main-only diagnostic job; normal PR/main validation, native
dispatch, release validation and the other workspace products retain their gates.
The new Action occurrences reuse the existing full checkout v4.2.2 and
upload-artifact v4.6.2 SHAs and remain uniquely extracted by the enabled GitHub
Actions manager. The two regex-manager paths, five native-image extractions,
grouping/manual approvals, Cargo and toolchain ownership are unchanged; dedicated
policy regressions verify no duplicate or moved extraction, so Renovate needs no
configuration edit. The `Required CI` display correction changes no job identity
or software pin. Runner Python/coreutils/dpkg/systemd follow the existing mutable
Ubuntu 24.04 runner unavailable-integrity/manual-review boundary. Observed
installed package versions and hash-only helper/control/unit metadata are not
new pins, authenticated publisher integrity or permission to update/install them.
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

The harness uses an explicit owned named volume at each image's declared Docker
data root. Podman disables automatic image volumes; the hosted Docker backend
validates/overrides the sole declared volume and checks the complete actual mount
roster. Debian 11 rootless retains --oom-score-adj=0 in both privileged outer
backends. These are validation-only prerequisites, not product capabilities.

The [canonical outer runtime](native-outer-runtime.md) verifies the preinstalled
GitHub ubuntu-24.04 Docker CLI/daemon without package installation, restart or
global configuration changes. Actual client/server and ImageVersion values plus
the local root dockerd executable identity are observed in private unqualified
receipts; sanitized versions appear in job logs. The runner image is version-selected
but mutable. Its Docker installation has no independently stable distribution
checksum supplied to this repository: this is an explicit unavailable-integrity,
manual-review exception like the existing runner Podman/kernel tools, not an
invented pinned distribution or a native compatibility claim. Runner updates can
change this prerequisite and need fresh native review. No downloaded tool is added.

The standalone `scripts/native-unix-http.py` supplied for BoxFerry's reviewed
test closure imports only the existing runner Python standard library. Its
independent socket tests add no dependency, software pin or extraction path;
existing DockerLens HTTP consumers are not migrated in this change.

Renovate ownership remains unchanged: the five version/digest image references
stay uniquely extracted from scripts/native-conformance.sh and retain their
native-conformance grouping/manual review with automerge disabled. Action SHAs,
Cargo and toolchain managers are unchanged. The three native workflow consumers
share the same setup/helper definitions; no duplicate manager, moved software pin
or historical evidence rewrite is needed. Policy tests retain exact extraction
and verify all three consumers explicitly select Docker and verify setup. BoxFerry
uses the reviewed test-only source seam separately; other Lens products and the
website do not consume this harness. The containers product retains its distinct
private-store Python adapter rather than weakening that contract to share lifecycle.

The stable `Required CI` display context belongs to the existing Check workflow's
`check-gate` aggregate; its job ID, dependencies and fail-closed event logic remain
unchanged. This display-name correction adds or moves no pin/extraction location.
The existing GitHub Actions manager and five native-image regex extractions remain
verified by scaffold policy tests; no Renovate configuration change is needed.

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
