# Finite rootless PIDs destination prerequisite

This is an inert planning and observation contract, not native qualification or
public PIDs capability admission. It recovers the existing #125 contract from
DockerLens source `f406cb22efc53fc7df04c24ea44a9ecd7900f41b`; it introduces no
executor, destination acquisition, host configuration or additional daemon read.

`ResourceSupportObservation` retains independent `PidsLimit`, `CgroupDriver` and
`CgroupVersion` reports from the already captured `/info` response. The boolean
report is distinct from the integer container `HostConfig.PidsLimit` setting.
Missing, null, empty and explicitly redacted values remain distinct; malformed
present types fail with the existing value-free resource-limit error. The
`missing(observation_id)` constructor supplies missing/effective states, never
schema defaults. Public struct-literal consumers must supply the added fields or
use this constructor. Raw cgroup strings remain protected in Debug output.

`assess(observation_id)` checks the explicitly supplied observation scope. Only
present, effective, valued reports can be classified. Cgroup spellings are exact
bytes: `none`, `cgroupfs`, `systemd`, and `1` or `2`. There is no trimming, case
folding, numeric conversion, cross-field inference or release-derived default.
Positive boolean reports remain available/unverified, never capabilities.

After the existing capability gate, rendering an authored finite
`PidsLimit::Count` in a rootless context adds a `DestinationPidsPrerequisite`.
It binds the protected container identity, caller-local reference, exact finite
count and immutable planning context. Absent and explicit unlimited settings
remain distinct; neither adds this finite-enforcement obligation. Rootful
settings do not acquire a rootless-specific obligation. All sealed profiles and
capability gates remain unchanged.

Use `destination_pids_prerequisites()` for typed obligations and
`complete_bytes()` for complete review output. `bytes()` remains the unchanged,
incomplete request-only stream. An artifact containing a finite rootless PIDs
obligation uses schema 4. Each closed `rootless_pids` row contains `reference`,
`identity`, decimal-string `pids_limit`, `required_cgroup_driver: "systemd"`,
`required_cgroup_version: "2"`, `required_pids_report: true`, and explicit
`delegation: "unverified"` and `enforcement: "unverified"`. Rows follow planning
order, before their owning container's bind-source rows. Existing network,
volume and bind obligations survive unchanged. Without a PIDs obligation,
schema 1/2/3 selection and bytes are unchanged. Consumers must reject unknown
versions or obligations rather than discard them; downstream schema-4 support
is a separate integration requirement.

`DestinationPidsPrerequisite::assess` is pure. The caller must explicitly select
a destination `DecodedInventory` and `ObservationId`; inventory, daemon and
resource-report scopes must match. Observed planning scope must match too.
Release, advertised API and rootless mode must match the planning context.
Rendering and actual request APIs must fit the reported range; missing minimum
API remains unknown. Request-version collections are bounded to 4096 entries
and must be nonempty. Offline target contexts additionally require every
actual request to use their chosen acquisition API; they invent no destination
observation identity.

Only present/effective `true`/`systemd`/`2` reports are metadata-compatible.
The sole positive result is
`MetadataCompatibleDelegationAndEnforcementUnverified`. It changes no unresolved
artifact state and proves neither delegation nor enforcement, exact build or
package provenance, authenticated daemon identity, atomicity, current/future
state or readiness. Publicly assembled snapshots remain caller assertions.
Errors are closed and value-free. Pure controls and test-local capability
records are not native evidence or catalogue grants.

See [ADR 0020](decisions/0020-observation-scoped-cgroup-reports.md) and
[ADR 0021](decisions/0021-rootless-pids-destination-obligation.md).
