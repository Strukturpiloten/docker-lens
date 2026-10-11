# ADR 0019: Select reviewed configured StopSignal for candidate rehearsal

Status: accepted candidate rehearsal admission; fresh final-candidate and actual
consumer gates remain required before ready/merge/main admission or release.

## Decision and authenticated source

DockerLens #112 selects four exact reviewed records from native run `38106164571`,
attempt 1, executed source `ef8b40c2d392c3983a3ebdc54730812352fe6b39`.
Trusted-main dispatcher `dd8c29435ff7734a567eb1ed4cda7d422d946bcb` is a distinct
identity, never a substitute for that source. The primary and independent Sol
authenticated same-repository source PR #113, successful run/attempt, all seven
jobs and steps, four artifact identities/API ZIP digests, and all sixteen exact
tests once/in-order on every lane. The bounded strict reader verified single
archive members, duplicate-free/nonfinite-free canonical public bytes and hashes.
[Sanitized provenance](../evidence/stop-signal-cohort-38106164571.json) binds the
raw records, reviewed envelopes and the independently supplied review receipt.

This is trusted-harness execution and public-projection review, not direct
private-proof inspection, independent host inventory or cryptographic daemon
attestation. Inner two-round cleanup and borrowed-image/outer-context readback
are established by reviewed source assertions and successful exact tests/closed
logs. Private effect timestamps, IDs, UIDs, proof payloads and log bodies are not
redistributed or independently measured by the public projection.

This supersedes only ADR 0018's active-cohort selection. All six previous raw,
reviewed and provenance cohorts remain byte-exact. ADR 0018/0017's external
None/false/true and snapshot boundaries, ADR 0015's conditional bind/source and
unverified SELinux obligations, and ADR 0012's actual consumer gates remain.

## Exact admission boundary

Every prior field/group is retained apart from the executed source SHA; only
public `stop_signal_contract`, `stop_signal_probes`, and the complete StopSignal
capability/shape singleton are added. The independent native oracle compares
literal CLI/rendered SIGTERM/SIGINT settings and requires actual ready PID1 traps
to exit 41/42 after bounded stop without a signal override. Wrong exit, SIGKILL,
timeout, uncertain cleanup or changed borrowed image cannot pass. The existing
inert planner/renderer may retain explicit StopSignal on these four sealed
profiles; absence still omits it. This does not promise arbitrary-image signal
handling or application shutdown behavior.

Debian is exactly 30 capabilities/47 shapes; upstream retains only its existing
additional complete IPv6 port group, for 31/49. Both Debian IPv6 outcomes remain
`nested_default_bridge_ipv6_runtime_binding_absent`. HealthStartInterval,
StopTimeout and every other unadmitted group remain withheld. Configured binds
still prove no SELinux effect. Four exact raw members and four reviewed envelopes
are appended under their SHA-256 paths; compiled lane/digest sets and complete
`required_for` groups must agree. Partial, duplicate, wrong-group or nonpositive
evidence fails closed. No executor, runtime preflight, file writer or artifact
schema change is introduced.

## Remaining gates without exemption

Source admission enables candidate rehearsal only. Before ready/merge/main
admission or release, the changed candidate still requires:

- Complete gates after the final edit on a stable candidate.
- Fresh authenticated exact-final-candidate sixteen-test four-lane native proof
  and independent source/artifact/cleanup review.
- Fresh isolated volume-only rehearsals for all six actual authored Forgejo,
  Nextcloud, Paperless-ngx, Immich, Observability and Supabase fixtures, retaining
  protected labels, external prerequisites and explicit unsupported/loss outcomes.
- Fresh reviewed BoxFerry consumers of actual Nextcloud/Supabase binds and desired
  external expectations, retaining full source/unverified SELinux obligations,
  privacy and explicit conditional/loss outcomes.

BoxFerry source-bound profile/producer receipts and full application acceptance
remain separate. Old source runs/consumer receipts cannot qualify this changed
candidate. No BoxFerry native API/parser/renderer workaround, Lens product
dependency, release, publication, deployment or full migration claim is permitted.

## Provenance and unchanged maintenance

The oracle remains `./scripts/native-conformance.sh <lane>` with exact Debian
docker.io `20.10.5+dfsg1-1+deb11u2` (Engine `20.10.5+dfsg1`) and upstream Engine
`29.8.1`. Debian acquisition/rendering API is 1.41; upstream acquisition is 1.49
and advertised/rendering API is 1.56. Existing Moby/Debian Apache-2.0 provenance
and references remain under ADR 0015. No oracle source or binaries are copied or
redistributed; only sanitized public metadata is stored under MPL-2.0.

Local/main/reviewed-dispatch/release retain the same canonical sixteen-test
harness and nineteen-argument emitter. No version/package, lockfile, workflow,
image, toolchain, downloaded tool or operational pin changes. Renovate readback
confirms unchanged unique Cargo/GitHub Actions ownership and toolchain/five-image
regex paths, grouping and manual approval; historical evidence is outside update
streams. Other Lens products and the website do not consume this Docker-only
source contract and remain independent of BoxFerry.
