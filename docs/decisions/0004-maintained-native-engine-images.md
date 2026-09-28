# ADR 0004: Run native conformance against maintained Engine images

Status: accepted harness contract; DockerLens compatibility evidence pending.

The four independent native lanes use the published, version-tagged and
digest-pinned containers#260 GHCR images: Debian 11 packaged Engine in
rootful and rootless mode, and upstream Engine 29 in rootful and rootless
mode. The harness invokes each image's native launcher, mounts one exact
task-owned data-root volume, and binds a private Unix socket for capture.
Image-declared volumes are disabled and the actual mount is checked. The
Debian 11 rootless lane sets outer Podman's OOM score to zero to support its
historical Engine 20.10 nested workload. That already-privileged outer
container explicitly disables its local AppArmor profile in this lane,
without changing host policy. Only Debian 11 rootless uses suid,dev on its
task-owned outer data-root volume, and the harness verifies the effective
mount flags. Independent CLI probes isolated the need to this historical
rootless runc's read-only named-volume remount under outer nosuid,nodev;
other lanes retain their default data-volume and AppArmor options. This does not claim
conformance under restrictive outer storage mounts or enforcing outer
AppArmor. No guest APT provisioning occurs.

The replaced harness installed a historical Debian package snapshot at
runtime into a generic base image. It could select a package revision
different from the maintained image and mixed package acquisition failure
with Engine conformance. The maintained Debian images contain native
docker.io 20.10.5+dfsg1-1+deb11u2, which the harness checks directly.
Their package provenance remains tied to the published image digest.

An image build, pinned reference, passing offline suite, or local harness
definition does not establish DockerLens compatibility. Each lane must run
its exact native acquisition, capture, and target checks. Only after these
checks pass does the workflow upload a sanitized manifest of observed
identity, API range and selected APIs, mode, package revision, and tested
capabilities. The reviewed run attempt and artifact digest must be bound to
an exact candidate before an offline catalog entry is admitted. This keeps
ADR 0001's native evidence boundary and ADR 0003's per-shape capability
requirement intact.
