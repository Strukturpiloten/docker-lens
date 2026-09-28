# Standalone Docker migration ledger

This is the finite checkpoint for DockerLens #3, not a completed migration or a
compatibility claim. DockerLens 0.1.0 supplies the foundation: bounded explicit
read-only Unix-socket acquisition, pure typed inspection, and inert standalone
planning/rendering for four exact reviewed historical profiles. The source and
target contracts are separate. A captured effective `Config.*` value does not
prove authored intent, and a target field is never inferred from it without a
BoxFerry loss decision.

The required migration set is the six repository-owned application scenarios
(Forgejo, Immich, Nextcloud, Observability, Paperless-ngx, and Supabase),
plus a small four-lane standalone
rehearsal. The BoxFerry fixture files are the scenario authority; this ledger
records native prerequisites and ownership, not a duplicate of their manifests.
In particular, Supabase's loopback Kong publication and internal backend plus
edge attachment, Forgejo's loopback ports and external network, Observability's
structured host IP and read-only shared mount, and Nextcloud's explicit command
and private plus edge networks must survive conversion or produce an actionable
loss outcome. The small rehearsal may use one pinned BusyBox service, one
declared bridge, and one named volume. It does not certify the larger apps.
All six application contract rehearsals remain prerequisites for BoxFerry's
full standalone application claim through #343/#366; the BusyBox rehearsal
is only an intermediate native smoke.

| Contract | 0.1.0 source / target shape | Required shape and independent evidence | Owner |
| --- | --- | --- | --- |
| Acquisition and provenance | Explicit bounded Unix-socket GET set, API 1.41–1.49 negotiation, selected container/network/volume inspections, opaque local references. Decoder keeps availability and origin separate. | #28 must prove each newly needed inspect field and request/API boundary from real Engine responses, including missing/null/empty/redacted cases. Never infer authoring from effective `Config.*` or treat socket contact as authentication. | DockerLens #28 |
| Host publication | Decoder represents a port key with a list of bindings, each with observed `HostIp` and `HostPort`. Target has one nonzero host port per container port/protocol and emits no `HostIp`; exposed-only ports have no target shape. | Preserve loopback `127.0.0.1` versus all-interface binding, multiple bindings per port, TCP/UDP, and exposed-only versus published. Validate duplicate/conflicting binding rules. Native assertions must inspect the exact request and resulting host bindings in each claimed API/mode lane; BoxFerry must retain or diagnose the value. | DockerLens #30; BoxFerry #343 |
| Networks | Decoder retains named attachments, aliases, runtime IP, mode, and observed network `Internal`; target creates one bridge and attaches one network. | Multiple/internal networks, per-endpoint aliases, explicit IPAM where authored and supported, and external network references without accidentally creating them. Distinguish effective/runtime IPAM from authored network configuration. Prove create/attach/inspect behavior and rootless differences per exact lane. | DockerLens #29; BoxFerry #343 |
| Health | Decoder distinguishes `CMD`, `CMD-SHELL`, `NONE`, start period, and start interval. Target emits only exec `CMD` with interval/timeout/retries. | Typed shell and disabled forms plus start period, with version-boundary behavior and protected command bytes. Do not silently map `NONE` to an absent check. Native assertions must inspect and exercise each emitted form. | DockerLens #30; BoxFerry #343 |
| Container runtime | Decoder has image, environment, user, working directory, hostname, labels, mounts, command, entrypoint, restart and effective/runtime port/network data. Target has image, env, fixed TCP/UDP ports, bind/named-volume mounts, exec command/entrypoint, exec health, restart. | Typed settings required by BoxFerry's neutral `Service`: identity, root filesystem mode, limits, security, mounts, name resolution, stop and logging settings listed below. Missing required core fields block a full standalone migration claim even when a lossy route diagnoses them. No generic JSON escape hatch; each admitted branch needs independent native behavior evidence. | DockerLens #30; BoxFerry #343 |
| Graph and loss | Graph validates declared references, cycles, API floor and catalog facts; rendered output is inert newline-delimited POST descriptions. | Multi-network and external-reference dependency rules, per-setting capability decisions, explicit source evidence, protected values and actionable loss diagnostics. No executor, build context, Swarm service, Kubernetes, or Windows contract is added. | DockerLens #3 integrator; BoxFerry #343 |
| Native conformance | Four historical records cover Debian 11 and upstream Engine 29, each rootful/rootless, for the 0.1.0 closed shapes only. | #31 adds independent request/result assertions for each new shape and boundary, then fresh complete and all four native lanes for the exact candidate. Only independently reviewed per-lane manifests may extend the catalog. A green offline test, old record, or one lane cannot promote new capability facts. | DockerLens #31 |
| Consumer and application behavior | DockerLens does not depend on BoxFerry and does not start containers. | BoxFerry #343 owns neutral import/export, protected-value handling, structured loss policy, and route tests. #366 owns the bounded four-lane app rehearsal: the BoxFerry-owned isolated test harness applies generated create requests and separately starts the resulting test containers, seeds prerequisites, checks peer traffic and reacquisition, then grows to six apps as native shapes arrive. The product never executes output. | BoxFerry #343 and #366 |

## Required source-to-target decisions

Each row is required for the full standalone claim unless marked as a
deliberate out-of-scope domain. The source path identifies native evidence,
not an automatic promotion rule. `BoxFerry #343` must decide whether an
observed value is authored, effective, or runtime-assigned and emit a
structured loss outcome where authorship cannot be recovered. DockerLens
#31 must independently exercise every newly rendered branch on each exact
version and daemon mode before the catalog admits it.

| Native source → required target decision | Neutral/app contract | Owner and release blocker |
| --- | --- | --- |
| `Config.ExposedPorts` versus `HostConfig.PortBindings[*].HostIp/HostPort` and runtime `NetworkSettings.Ports` → exposed-only, loopback, wildcard, IPv4/IPv6 and multiple bindings per port/protocol, with no inferred authored host port | `Service.ports`, including `Port.host_address`; loopback in all six fixture apps | #28 source; #30 target; #343 promotion; #31 native evidence. Missing host IP/multiple bindings blocks full claim. |
| `NetworkSettings.Networks` names/aliases/runtime IP, `HostConfig.NetworkMode`, network inspect `Internal` → multiple named attachments, endpoint aliases, internal bridge, and explicit network mode | `Network` and `NetworkAttachment`; Supabase and Nextcloud private plus edge | #28 source; #29 target; #343 promotion; #31 evidence. One-network-only blocks full claim. |
| Network inspect `Driver`, `EnableIPv6`, `IPAM.Driver/Config`, `Options`, `Labels` and endpoint IP fields → typed driver, address families, subnet/gateway/static address, options, labels and explicit ownership where the exact API/mode supports them | Neutral `Network` driver, IPv6, IPAM, options, labels and ownership; attachment addresses | #28/#29/#343/#31. Effective or runtime-assigned IPAM cannot become authored intent silently. Each required neutral field needs exact support or a reviewed, version-specific unsupported diagnostic; unexplained gaps block the full claim. |
| Declared network reference versus locally created network → external reference with no create request, checked dependency and explicit missing-resource outcome | Forgejo external network | #29 target; #3 graph; #343 ownership; #31 evidence. Accidental creation blocks full claim. |
| `Config.Healthcheck.Test` (`CMD`, `CMD-SHELL`, `NONE`), `StartPeriod`, `StartInterval` → typed exec, shell and disabled health with duration/version rules | Neutral health command/form, disabled flag and grace period | #28 source; #30 target; #343 promotion; #31 evidence. Dropping `NONE` or start period blocks full claim. |
| `Config.User`, `WorkingDir`, `Hostname`, `Labels` → typed protected identity and metadata settings | `Service` user, working directory, hostname and labels; Forgejo user | #28/#30/#343/#31. Missing required fields blocks full claim. |
| `HostConfig.ReadonlyRootfs` → read-only root filesystem flag; alternate root source is a separate unsupported/source decision | `Service.read_only_root_filesystem` versus `Service.rootfs` | #28/#30/#343/#31. Conflation blocks full claim; an alternate root source needs an explicit diagnostic if Docker cannot represent it. |
| `HostConfig.Mounts` / inspected mounts → bind, named volume, read-only access, tmpfs, and device settings as distinct typed forms | `Service` mounts, tmpfs, devices; Observability read-only shared mount | #28/#30/#343/#31. Missing required mount form blocks full claim. |
| `HostConfig.Memory`, `PidsLimit`, `ShmSize`, `Ulimits` → checked numeric resource settings and zero/unlimited semantics | `Service.memory_limit`, `pids_limit`, `shm_size`, `ulimits` | #28/#30/#343/#31. No silent overflow, unit change, or omission. |
| `HostConfig.CapAdd/CapDrop/SecurityOpt`, `Sysctls`, `GroupAdd` → typed security and process identity settings with closed unsupported cases | `Service.cap_add`, `cap_drop`, `security_options`, `sysctls`, supplementary groups | #28/#30/#343/#31. A missing required core field blocks full claim; privileged/host escape behavior needs separately reviewed native scope. |
| `HostConfig.Dns/ExtraHosts/Init` and related inspect values → explicit resolver/host mappings and init setting | `Service` DNS, host mappings and `run_init` | #28/#30/#343/#31. Protected host data remains redacted in findings. |
| `Config.StopSignal/StopTimeout`, `HostConfig.LogConfig`, restart policy → typed lifecycle and logging request fields | `Service.stop_signal`, `stop_timeout`, logging and restart | #28/#30/#343/#31. Distinct absent/default/explicit values need boundary tests; confirm exact per-version field location from native responses. |
| Container dependencies and readiness observed at application level → ordered inert graph and independently started test resources, with no DockerLens executor | `Service` dependencies, health readiness, data prerequisites, peer traffic and reacquisition | #3 graph; BoxFerry #343/#366 consumer. Missing app behavior blocks full scenario claim. |

Swarm services, Dockerfile/build-context execution, Kubernetes, mutating
DockerLens runtime requests, and Windows behavior are outside this ledger.
Other setting variants that cannot be represented exactly still require
explicit unsupported/loss outcomes; they cannot be counted as completed
required core support. The four historical profiles admit only their existing
twenty closed renderer shapes, not any row above merely because it is listed.

## File ownership for parallel implementation

DockerLens #3's integrator owns `src/target.rs` public reexports and tests,
`src/target_modules/intent.rs` resource enum, identities and shared validation,
`src/target_modules/graph.rs`, and `src/target_modules/render.rs` dispatch
and common JSON encoding. These are shared contract files: #29 and #30 should
propose precise interface edits to the integrator rather than write them in
parallel. #29 owns `src/target_modules/render/network.rs` and future
network-specific intent files. #30 owns `src/target_modules/container.rs` and
`src/target_modules/render/container.rs`. #28 owns acquisition and decoder
field work, with shared `lib.rs` wiring coordinated by the integrator. #31
owns native assertions/harness extensions; the integrator alone wires reviewed
catalog, capability vocabulary and evidence records after independent review.
The BoxFerry issues own only their own checkout. No two writers share a checkout.

Existing public `docker_lens::target::*` paths and struct-literal shapes remain
unchanged at this checkpoint. New target fields, constructors, capability names,
or cross-repository API changes require an explicit reviewed contract before
parallel edits. The historical four catalog profiles and native harness
definitions are untouched. DockerLens #3 remains open after this checkpoint.
