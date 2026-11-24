# Hosted zero-swap boot trial

Run **Hosted zero-swap boot trial** manually on protected DockerLens `main`.
The workflow has no inputs. It checks out its exact workflow SHA with
read-only contents permission and without persisting credentials. It is a
separate infrastructure trial on the standard x64 `ubuntu-26.04` runner, whose
official runner image identity is `ImageOS=ubuntu26`. The disposable cloud
guest remains Ubuntu 24.04 (Noble); the host label does not select its release.
The existing Check diagnostic, native dispatch, release validation and their
evidence formats retain their own gates.

The collector checks the run, attempt, runner image version, workflow ref,
dispatch/checkout SHA and protected-main state. It requires 9 GiB available
memory, 12 GiB free disk and two available CPUs before provisioning.
The runner must open the KVM character device and create a VM descriptor
through the KVM API. QEMU must boot with KVM acceleration. GitHub documents
nested virtualization as experimental on its hosted runners.
[GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners#preinstalled-software-for-github-owned-images)

The receipt's optional `host.kvm_probe` records the first failed operation or
a completed probe. It distinguishes opening the device, reading its metadata,
its type and identity, getting API version 12, creating a probe VM, and
closing either descriptor. The outcome uses closed details for permission
denial, absence, unsupported operations, other errors, and mismatches.
Descriptor cleanup is recorded separately, even when a close also fails.
The probe uses the ordinary non-root runner identity. It does not change
device permissions or groups. A successful probe proceeds to the same
KVM-only boot trial.
[Linux KVM API](https://docs.kernel.org/virt/kvm/api.html)

A denied open also records `group_observation`. A separate no-follow
metadata read checks for the root-owned KVM character device, the named
`kvm` owning group, group read/write mode bits and no world-write bit.
For that layout, `group_rw_held` or `group_rw_not_held` reports whether
the job's effective primary or supplementary groups contain the owning group.
`other_layout` records a mismatch, and `unobserved` records a missing
observation. These facts describe the later metadata and process membership.
They do not establish why the earlier open was denied or whether changing
membership would allow access. The original refusal is preserved.

The fixed cloud-image release and tool versions are in
[scripts/hosted-zero-swap-pins.json](../scripts/hosted-zero-swap-pins.json).
The collector verifies Ubuntu's signed checksum file against the pinned
cloud-image signing fingerprint, checks the exact image row, hashes the image
bytes, and checks that QEMU recognizes a standalone QCOW2 image. A fresh 8 GiB
overlay over the read-only base boots with 7 GiB RAM and two vCPUs. Exact host
QEMU/xorriso resolve from the signed Resolute/Resolute-updates/Resolute-security
indexes for Ubuntu 26.04 amd64. Guest Docker/containerd/runc resolve separately
from Noble/Noble-updates/Noble-security for the unchanged Ubuntu 24.04 guest.
Both scopes use the pinned dated Ubuntu APT snapshot. The package plans must
avoid removing or upgrading installed packages. The archive keyring supplied
by Ubuntu authenticates the snapshot package indexes and acquisition. The fixed
historical snapshot uses its signed file identities instead of the rolling
archive freshness deadline.
[Dated Ubuntu cloud images](https://cloud-images.ubuntu.com/releases/noble/release-20261017/) ·
[Ubuntu snapshot service](https://snapshot.ubuntu.com/) ·
[Ubuntu archive verification](https://documentation.ubuntu.com/security/software-integrity/archive-verification/)

The workflow label, admitted `ImageOS`, separate APT suites and exact package
plans are covered together by the owning regression. A runner-label-only bump
must fail that contract until admission and the signed host package selection
are reviewed together. GitHub's runner image version remains an observation,
not an immutable runner-image pin.
[Official Ubuntu 26.04 runner metadata](https://github.com/actions/runner-images/blob/e015a08e7601a17f5d9a2938136537aab0f66b6c/images/ubuntu/Ubuntu2604-Readme.md) ·
[Official runner identity mapping](https://github.com/actions/runner-images/blob/e015a08e7601a17f5d9a2938136537aab0f66b6c/helpers/GenerateResourcesAndImage.ps1)

A per-run NoCloud seed configures a fresh SSH client identity and a pinned
guest host key. The host forwards SSH on loopback and sends the fixed observer
over that connection. The host retries a reaped readiness timeout after the
usual one-second pause while QEMU is still running. Each probe has up to seven
seconds within the original 100-second boot window and the host deadline.
Deadline expiry, cancellation, QEMU exit or unverified command cleanup ends
readiness.
Cloud-init status is checked separately after SSH becomes ready.
The VM gets no checkout mount, host credentials or host
Docker socket. The observer uses the guest kernel's global swap table and
`SwapTotal` and ties its hashed boot identity to the observed kernel. It binds
the local Docker socket and the listening rootful systemd-owned Docker process
by peer, PID, descriptor and socket identities. Runner-supplied OS tools and
installed keyrings form the hosted prerequisite. The runner image version and
host boot hash are observations of this run.
[NoCloud datasource](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html)

The guest pulls the exact Debian 11 rootful index used by product source
`bd7461e584b3686123ac7534626c88333c5af39c`, verifies the Linux/amd64 manifest and
config, and creates one owned container running a fixed idle process with
networking disabled. The observer checks the configured limits and private
cgroup namespace. It binds the container's mounted cgroup inode to the same
node from the VM, reads the effective 4 GiB memory, 512 PID and two-CPU quota,
verifies zero global swap in both contexts, and reads the installed Debian
Engine package revision. Docker reports a canonical repository digest and
a typed security option list. An index-based image store must expose matching
index and selected platform descriptors, including the container's platform
descriptor. A config-based store has an absent or null descriptor.
The idle container provides the boot prerequisite
observation. No inner daemon, memory workload or native proof reader runs in
this trial.

The sole artifact is a small versioned JSON result with scoped host and guest
observations, bounded outcomes, sampled disk use, elapsed and VM active time,
and separate work/cleanup results. The trial writes privately in a fresh
directory, publishes the completed file without replacing an existing file,
and then hands its exact path to the uploader through this step's output.
The handoff ends at the closing delimiter, which the runner accepts at EOF.
A short write leaves an incomplete output command.
A fresh failure result can be uploaded. A missing handoff leaves no selected
artifact. The guest requires the owned container to be absent by ID and name.
Cancellation during guest cleanup fails completed work, while an earlier
work failure keeps its result and the cleanup outcome remains separate.
The host stops and reaps the owned VM group, then
removes the overlay, seed, keys and scratch. Command output is captured
privately and bounded. An interrupted transfer, unclear absence, failed cleanup
or missing result leaves the trial incomplete. GitHub may forcibly stop a
canceled job before artifact upload. No raw stdout/stderr, inventories,
credentials, filesystem content or VM disks enter the artifact.

A completed trial establishes the observed hosted boot and container
prerequisite. The exact candidate still needs all four native lanes and their
independent readers before compatibility can be claimed.
