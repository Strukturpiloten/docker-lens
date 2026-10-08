# Standalone Docker migration ledger

This is the finite checkpoint for DockerLens #3, not a completed migration or a
compatibility claim. DockerLens 0.1.0 supplies the foundation: bounded explicit
read-only Unix-socket acquisition, pure typed inspection, and inert standalone
planning/rendering for four exact reviewed historical profiles. The source and
target contracts are separate. A captured effective `Config.*` value does not
prove authored intent, and a target field is never inferred from it without a
BoxFerry loss decision.

DockerLens #29 now has typed bridge creation, application-default identity,
external-reference prerequisites, independent per-container aliases and
addresses, and ordered secondary connect requests. These are inert target
contracts, not executed output. The original historical cohort admits no new
network shape; the separately reviewed #68 cohort admits only the external
bridge prerequisite and internal bridge creation singleton groups. ADR 0016
now admits only complete network-label, primary/secondary-alias and
multiple-attachment groups from the coherent application cohort. Other network
groups still require independent exact-lane evidence, and BoxFerry's six-scenario
consumer checks remain required before a full migration claim.

The following authored topology anchors are read from BoxFerry's
`fixtures/conformance/{forgejo,nextcloud,paperless-ngx,immich,observability,supabase}-application/compose.yaml`
(and Supabase's `graph.tsv`).
They define required target shapes, not evidence that DockerLens or BoxFerry
already reproduces the running applications:

| Scenario | Required network graph and ownership boundary | DockerLens target contract |
| --- | --- | --- |
| Forgejo | `db` uses the created internal backend; `forgejo` joins backend and the external edge with independent `forgejo` aliases. The fixture peer is separately owned on edge. | `NetworkIntent` with `NetworkSource::Create` and `internal`, `NetworkSource::External` prerequisite, and two `NetworkAttachmentIntent` values for Forgejo; the second emits a connect step. |
| Nextcloud | Database, cache, app, init and cron remain on the created internal backend; frontend joins backend and external edge with aliases on both. Shared proxy and second app on edge are boundary resources, not implicit members of the Nextcloud application. | Created internal backend, external edge prerequisite, and frontend's two independent alias-bearing attachments; proxy and second are excluded. |
| Paperless-ngx | Database, broker, Gotenberg and Tika remain on the created internal backend; webserver joins backend and a created edge with `webserver` and `paperless` endpoint aliases. | Two created bridges, internal backend, and webserver attachments with distinct aliases and an ordered edge connect step. |
| Immich | Database, Redis and machine learning remain on the created internal backend; server joins backend and a created edge with its own alias. | Two created bridges, internal backend, and server's second attachment with its own alias. |
| Observability | Metrics/log producers, Prometheus, Loki and Alloy remain on the created internal backend; Grafana joins backend and external edge with its edge alias. | Created internal backend, external edge prerequisite, and Grafana's two attachments with an edge-only alias. |
| Supabase | All eleven application services remain in scope: `db`, `auth`, `rest`, `realtime`, `imgproxy`, `storage`, `meta`, `supavisor`, `functions` and `studio` are backend-only; Kong joins internal backend and external edge with independent aliases. The `boundary-peer` from `peer.compose.yaml` is an external-edge probe, excluded from the application target graph. | Created internal backend, external edge prerequisite, ten backend-only attachments, and Kong's backend `kong` plus edge `supabase` aliases; Kong's edge connect is ordered after create. |

This map identifies available inert types, not a completed BoxFerry consumer
mapping or a native compatibility claim. None of these six fixtures authors
IPAM or static endpoint addresses; those typed branches need separate small
native probes. IPv4 `/31` and `/32` bridge subnet pools remain explicitly
unsupported by planning as library policy. The current offline rejection is
not evidence that Engine rejects them; changing this policy requires separate
exact API/mode native evidence.

DockerLens #30 adds an inert typed container target contract for the six
fixtures' loopback-only publications, labels, Forgejo/Nextcloud user values,
explicit commands, shell health checks, and read-only mounts. The full six-app
route still requires BoxFerry #343 promotion decisions and #366 runtime
rehearsal. The historical four-profile catalog admits only its former fixed
TCP/UDP, exec command/entrypoint/health, bind/volume and restart shapes.
No new container capability is positive merely because a target type and
renderer branch exists.

DockerLens #94 adds closed bind-relabel source interpretation and optional
shared/private target intent under [ADR 0015](decisions/0015-bind-relabel-intent.md).
ADR 0016 now admits only complete configured-retention groups on all four
candidate profiles. Conditional schema-2 source/SELinux obligations remain
unchanged. Fresh final-candidate native proof and reviewed actual authored
Nextcloud/Supabase BoxFerry bind consumers remain required; no source existence,
host label, SELinux enforcement or full migration claim follows from admission.

DockerLens #44 adds an inert existing named-volume target contract:
`TargetResource::ExternalVolume` binds a caller-supplied destination name to a
`RequireExisting(Volume)` graph step and protected `VolumePrerequisite`, with no
volume-create request. `Mount::volume` still renders the exact declared target
name. Inspected source identity is not authored destination ownership or proof
that data exists there. The original historical cohort remains unadmitted for
this branch; the separately reviewed #68 cohort admits its singleton reference
group after independent four-lane absence, mount-data and persistence proof.
BoxFerry #343 must still make an explicit promotion or loss decision and verify
the destination prerequisite; this admission does not close the wider #44
consumer contract. The target
checkpoint does not transfer data or close the migration issue.

DockerLens #49 adds bounded protected labels to created named-volume intent,
with a separate `VolumeLabels` capability and exact `Labels` create body.
Unlabelled requests remain byte-identical and external-volume prerequisites
cannot carry or mutate labels. All six BoxFerry fixtures author volume labels.
The #49 candidate selects the complete label group from independently reviewed
#70 source evidence for pre-merge consumer rehearsal only. [ADR 0012](decisions/0012-candidate-volume-label-admission.md)
supersedes ADR 0010's sequencing clause, not its protected-value or inert-target
contract. Production merge/main/release remain blocked on fresh exact-final-candidate
four-lane native proof, independent review of all six actual authored fixture
volume-only mappings and consumer rehearsal, and complete gates. A volume-only
rehearsal cannot establish six-application or full migration acceptance; wider
#31/#343/#366 evidence remains open.

ADR 0016 selects the fifth coherent application source cohort for candidate
pre-merge rehearsal: exactly Debian 28/44 and upstream 29/46. It retains
parameterized identity and labelled volumes, then adds only complete common
port, health/metadata, network attachment and configured-bind retention groups.
All four historical cohorts remain byte-exact. Production merge/main/release
still require fresh complete and exact-final-candidate fourteen-test four-lane
native gates, all six actual authored fixture volume-only consumer rehearsals,
and reviewed actual Nextcloud/Supabase schema-2 bind consumers. No full application
or migration acceptance is established; #31/#343/#366 remain open.

| #30 target branch | Typed request contract | Remaining proof / owner |
| --- | --- | --- |
| Publication | `PortPublication` has exposed-only or ordered `HostBinding` values; each binding distinguishes omitted/explicit IPv4 or IPv6 `HostIp` and fixed/ephemeral `HostPort`. Duplicate or wildcard-overlapping fixed bindings fail before planning. | #31 must inspect resulting fixed/repeated/dynamic bindings, loopback isolation and IPv6 behavior per exact lane; #343 must retain authored address versus observed assigned port. |
| Process and health | Command and entrypoint distinguish native omission, clear intent and exec. Command clear with inherited or cleared entrypoint fails intent validation; explicit exec entrypoint plus clear command remains capability-gated. Health test distinguishes exec, one shell string, disabled and inherited absence; timing retains omitted versus explicit start values. | #31 must prove the conditional command-clear request against independent literal Engine behavior and compare an entrypoint-only control; `EntrypointClear` needs separate proof. #343 must not infer authored clear from effective source `Config.Cmd`. No empty-string argument workaround, generic API floor, or claim from offline bytes. |
| Identity and runtime | Protected labels/user/workdir/hostname; typed tmpfs, read-only rootfs, init, stop settings, limits, devices, caps/security/sysctls/groups, DNS/extra hosts and logging render behind individual capabilities. | #31 checks resulting process, mount, resolver and security/resource behavior. #343 maps each neutral field or records actionable loss; a typed branch alone does not close the full application contract. |

The existing source-to-target rows below remain the finite release blockers.
The current named runtime subset is `nofile` ulimit, `NET_BIND_SERVICE` add,
`SYS_ADMIN` drop, `net.ipv4.ip_forward` (`0`/`1`), and `json-file` `max-size`
(positive `k`/`m`/`g` size). Other capability names or directions, ulimit and
sysctl names, and log option keys fail intent validation; each supported name
still requires its own positive exact-profile fact. These deliberately
unsupported values remain #30/#31/#343 follow-up whenever the six application
routes require them, not evidence of completed native migration.

Host user namespace is still a closed unadmitted request, and alternative
rootfs sources and declarative health-readiness/dependency execution are not
claimed by this target contract. These gaps cannot be marked complete solely
through a generic unsupported result.

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
The later #68 cohort adds three complete singleton groups; this #49 candidate
added the fourth, `VolumeLabels` / `VolumeCreateLabels`, through the
pre-merge-only #70 cohort. The #88 cohort added only two parameterized identity singleton groups under
ADR 0014. ADR 0016 selects the coherent fifth cohort with the bounded application
groups; none of these rows is a full migration claim.

## File ownership for parallel implementation

DockerLens #29 owns the merged network target contract; #30 is the sole writer
of its separate issue checkout for container intent/rendering, shared target
validation and graph gates, public target tests/reexports, baseline native-test
constructor updates, and delegated capability vocabulary/closed shapes. The
primary integrator reviews those shared changes and alone updates reviewed
catalog records after independent #31 evidence. #28 owns acquisition and
decoder source fields; #31 owns new native assertions and harness extensions
in its own checkout. The BoxFerry issues own only their own checkout. No two
writers share a checkout.

The initial module checkpoint preserved public `docker_lens::target::*` paths
and struct-literal shapes. The subsequent #29 contract intentionally replaces
the single network field with typed network resources and attachments under
ADR 0006; native baseline test constructors follow the new contract. Further
target fields, constructors, capability names, or cross-repository API changes
require explicit reviewed contracts before parallel edits. ADR 0007 records
the reviewed #30 container contract. Historical catalog records remain
unchanged; remaining network and additional container-setting shapes remain
unadmitted. DockerLens
#3 remains open after this checkpoint.
