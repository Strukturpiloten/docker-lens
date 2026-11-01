# ADR 0004: Run native conformance against maintained Engine images

Status: accepted harness contract; historical four-lane source evidence reviewed.
Each changed candidate and release requires fresh complete and native gates.

Scope amendment: [ADR 0038](0038-maintained-profile-for-box-consumer.md) supersedes
only the maintained profile helper's native-only consumer restriction with one
separately enumerated BoxFerry reviewed-consumer context. The native lifecycle,
receipts, historical evidence and qualification obligations below are unchanged.

The current [test-only outer runtime](../native-outer-runtime.md) additionally
selects verified rootful local Docker in admitted hosted jobs while retaining
local default Podman. This updates orchestration, not the four maintained inner
images or this ADR's native evidence/admission obligation. Historical Podman source
evidence below remains historical; it does not qualify the new Docker backend.
The maintained GitHub-runner userns prerequisite applies only to the owned
upstream-rootless fixture under hosted outer Docker in the exact main-push,
trusted-main native-dispatch and standalone exact-main release-validation jobs.
It may
compile and add one run-owned named AppArmor userns profile after read-only
host/parser/ABI checks, bind it to the unchanged privileged launch, and verify
the creation-bound task's effective kernel label. Original-directory custody,
durable intent and authenticated daemon absence govern removal; uncertainty
retains evidence until disposable-runner teardown. No installation, ambient
policy change, fallback, new native assertion or acceptance exemption is allowed.
The complete mandatory native sequence, owned resource cleanup, and a validated
verified-label/removed-profile receipt now permit ordinary evidence and job
success. Missing or uncertain prerequisites still fail the lane and aggregate.
This supersedes only the former issue127 experiment's mandatory non-success
barrier and dispatcher-only scope. Earlier experimental and failed-run evidence
retains its original status; it does not qualify the maintained successor.
Local host restrictions, cgroup/PIDs authority, product capability admission and
release obligations are unchanged. See the bounded lifecycle and source
provenance in [outer runtime](../native-outer-runtime.md#maintained-github-runner-upstream-rootless-userns-prerequisite).

Both use owned inner container/data-volume/socket identities in the existing
shared host store; the host Docker daemon/socket is never the fixture itself.

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
other lanes retain their default data-volume and AppArmor options outside the
explicit maintained prerequisite above. This does not claim
conformance under restrictive outer storage mounts or enforcing outer
AppArmor. No guest APT provisioning occurs.

The replaced harness installed a historical Debian package snapshot at
runtime into a generic base image. It could select a package revision
different from the maintained image and mixed package acquisition failure
with Engine conformance. The maintained Debian images contain native
docker.io 20.10.5+dfsg1-1+deb11u2, which the harness checks directly.
Their package provenance remains tied to the published image digest.

The network native gate has one validation-only host prerequisite outside the
image: `br_netfilter` and both bridge netfilter iptables sysctls must read back
enabled before any run-owned resources are created. The harness reads these
values in every environment. It may attempt only the bounded, exact
`sudo -n timeout --signal=TERM --kill-after=2s 10s modprobe br_netfilter`
when the module is absent and the job is
positively identified as the GitHub-hosted Linux DockerLens native matrix on
trusted `main` push or workflow dispatch. The exact load uses root-owned GNU
`timeout` around `modprobe br_netfilter` with TERM and a two-second KILL
fallback; an outer deadline cannot reliably signal root children. It rechecks
the module and both sysctls afterward. The environment guard prevents accidental local mutation,
not root-caller impersonation. Already-ready hosts never load, while local or
unknown contexts remain read-only and fail closed. This narrowly extends the
host-side harness preflight; it does not change sysctls, unload modules,
install packages, alter forwarding policy, or waive any inner Engine assertion.

An image build, pinned reference, passing offline suite, or local harness
definition does not establish DockerLens compatibility. Each lane must run
its exact native acquisition, capture, and target checks. Only after these
checks pass does the workflow upload a sanitized manifest of observed
identity, API range and selected APIs, mode, package revision, and tested
capabilities. The reviewed run attempt and artifact digest must be bound to
an exact candidate before an offline catalog entry is admitted. This keeps
ADR 0001's native evidence boundary and ADR 0003's per-shape capability
requirement intact.
