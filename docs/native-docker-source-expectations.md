# Prepared Docker explicit source expectations

`scripts/native_outer_docker_source.py` is a pure, test-private preparation for
DockerLens issue 31. It performs no I/O, launch, inspection, discovery, default
resolution, source acquisition, publication or cleanup. It imports only Python
stdlib helpers. The existing Podman refusal and current 26-call coordinator are
unchanged. It is not connected to strict PIDs27, its readers or the emitter;
unresolved PIDs27 still blocks canonical nofile28.

## Independent inputs, not a self-oracle

Every entrypoint requires the separately chosen built-in string `docker`.
Neither the lane nor an OCI/claim member can choose a backend. Missing, unknown
and Podman selections refuse without fallback.

`prepare_docker_launch_projection` takes separate frozen, repr-redacted records:

- `DockerLaunchIntent`: session/candidate/run/lane/created ID, owner/network/
  volume, pinned image/config/platform selection, explicit effective argv/env/
  cwd/hostname, owned mount destinations, resources and Docker logging intent.
- `DockerImageFacts`: independently bound pin, image ID, config digest and Linux
  platform, which must agree with the caller's chosen image facts in the intent.
- `DockerAccountFacts`: explicit numeric UID/GID and ordered supplementary groups.
- `DockerMountFacts`: the complete ordered mount projection, independently bound
  source, destination, type and option vectors, including both owned destinations.
- `DockerPolicyFacts`: explicit OCI version, absolute root, root-readonly flag,
  namespaces, cgroup-path string, annotations and expected AppArmor profile (or
  explicitly expected absence). The sole local projection shape is named
  `explicit-linux-oci-projection-v1`; it is not a Docker/containerd storage layout.

Each input requires a `DockerSourceBasis` declaration with the exact
`independent-explicit-docker-source-v1` kind, a nonempty revision and SHA-256
record digest. Missing declarations and Podman-source kinds refuse. These
declarations are **not authenticated source records**. A digest-shaped string
does not establish provenance, review, license or an independent origin. No
actual Docker default/runtime source record is introduced or admitted here.
The caller remains responsible for those independently owned facts; deriving
them from the observed OCI or inspect/peer/audit JSON violates this contract.

There is no Docker image-config/account merge algorithm. Effective process
values must already be supplied independently under an explicit reviewed recipe;
missing values are not filled from image, OCI, environment or familiar defaults.
No Docker/containerd bundle path, namespace default, cgroup naming convention,
mount baseline, supported runtime revision or standard security policy is guessed.
Relative root/bind-source layouts and Podman `U`/`:U` mount options are unsupported.
Synthetic test paths and profile/version strings are not runtime prescriptions.

The present explicit resource recipe is exactly PIDs512, memory4294967296,
CPU quota200000 and period100000. Different values or Boolean-as-integer refuse,
even if both caller intent and OCI change. Logging intent is separately fixed
to Docker `json-file`, `max-size=1m`, `max-file=1`; it is not fabricated as an OCI
field and this helper cannot prove the actual log configuration. Likewise,
owner/network/volume and image identities are caller-intent bindings, not facts
authenticated by an OCI projection match.

## Precisely checked and unchecked OCI scope

`validate_docker_explicit_projection` takes raw UTF-8 JSON bytes and the separate
prepared expectations. It compares exact OCI version/hostname/root, effective
args/env/user/cwd and expected AppArmor presence/value, the entire mount vector,
namespace vector, cgroup-path string, complete PIDs/memory/CPU resource members,
and the annotation map. Argument, environment, group, mount, mount-option and
namespace array order is significant. Environment keys, group IDs, mount
destinations/options, namespace kinds and annotation keys cannot be duplicated.
Missing/extra checked members, unknown fields, hooks and inspect/audit substitutes
refuse. No expected field is copied from the document being checked.

This is **not full OCI validation**. These optional members are explicitly
outside the compared projection, although their JSON trees remain bounded:

- Process: `terminal`, `noNewPrivileges`, `capabilities`, `rlimits`,
  `selinuxLabel`, `oomScoreAdj`.
- Linux: `devices`, `seccomp`, `maskedPaths`, `readonlyPaths`,
  `rootfsPropagation`, `uidMappings`, `gidMappings`, `mountLabel`, `sysctl`.

They are neither interpreted nor accepted as reviewed security/default facts.
Their presence, absence or value cannot authorize a process, privilege, mapping,
namespace, controller or root boundary. Required semantics beyond this projection
remain unverified and must refuse in any future authority consumer. Additional
top-level or unnamed process/Linux fields are unsupported rather than discarded.

The raw source and independently constructed expected projection each have a
65536-byte ceiling. Exact-limit raw input is allowed; one byte more refuses.
JSON rejects duplicate keys at every depth, floats, nonfinite values, malformed
UTF-8, invalid surrogates, NUL strings, wrong types and Boolean numeric substitutes.
Trees allow at most depth16, 4096 value nodes and 128 members/items per object/
array; strings are at most4096 UTF-8 bytes and object keys256 bytes. Input vectors
further cap argv64, env128, groups64, mounts32, options32, namespaces7 and
annotations64. Paths must be absolute and lexically component-canonical, without
filesystem normalization or access. Source revisions/session fields are bounded;
the implementation deliberately supports only this small explicit shape.

## Claim agreement is not custody

`validate_source_claim_binding` compares a closed claim to a separately supplied
frozen `DockerSourceOwnerFacts` record: session/candidate/run/lane/created ID,
image and source digests, original PID/start/UID, PID/mount/cgroup namespace
inodes, source-file tuple, ordered ancestor tuples, original root tuple,
PIDs-controller tuple and log-file tuple. It does not accept a claim dictionary
as its expected-owner record, infer coordinates or deserialize an authority.

Tuple order is explicit: file tuples are device/inode/size/mtime-ns/ctime-ns;
ancestor/controller tuples are device/inode; original root is mount-ID/device/
inode; namespace tuple is PID/mount/cgroup. Integers are bounded unsigned64,
PID1..2147483647 and UID0..4294967295. Namespace/object inode and mount IDs are
positive, device/timestamp/log-size zero is allowed, source size is1..65536,
and source ancestry has1..8 entries. This is exact typed agreement, not live
file, ancestor, root, namespace, controller or log ownership verification.

All comparison successes return only
`Match.ExpectationMatchOriginalAuthorityUnverified`, with empty capability
admission and false catalogue admission. Preparing a projection returns only
frozen expectation data, not a selector, receipt, live credential, boundary vector
or producer permission. Even fabricated but matching independent caller records
can produce only that unverified result. Failures emit no output and raise one
fixed value-free error. These data/result types must never be treated as an
original-authority parameter by strict PIDs or other native consumers.

## Verification and outstanding work

The owned hermetic tests independently author a literal OCI document and separate
expected records for all four inner lanes; they do not generate positive OCI
from the expectation builder. Controls cover exact recipe numbers, anti-self-oracle
mutations, selectors, provenance/type/layout failures, private errors, raw/expected
bounds, matching-but-unverified forged owner facts and the stdlib-only/no-I/O
module closure. They launch no client, container or host probe.

This preparation introduces no packet, transport, dependency, pin, policy or
capability change; the original16KiB PIDs proof/15KiB main-context bounds remain
unchanged. It implements none of the later gated launch, original consumed-source
and log-handle custody, bootstrap release, original-root rechecks, physical budget
accounting, strict reader delivery or systemd/cgroup-v2 delegation. Rootless
delegation and all native qualification remain unresolved. A pure expectation
match is not source custody, PIDs enforcement, native evidence or milestone
completion. Parent integration, complete gates and independent review remain due.
