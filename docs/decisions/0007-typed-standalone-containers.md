# ADR 0007: Keep standalone container settings explicit and capability-gated

Status: accepted target contract; new shapes await independent native evidence.

This supersedes ADR 0003's fixed-only host publication and exec-only health
target subset. Its inert renderer, privacy, API floor, and reviewed-catalog
requirements remain in force. This also supersedes ADR 0005's public container
checkpoint: the next milestone intentionally changes fixed-only port and
exec-only command/health field types, requiring downstream construction-code
migration. This is a contract decision, not a version or release action.
ADR 0006's network contract is unchanged.

A target container distinguishes an exposed-only port from one or more host
bindings. Each binding distinguishes an omitted host address from an explicit
IPv4 or IPv6 address, and a fixed host port from an authored request for an
ephemeral allocation. The latter renders an empty Engine `HostPort` string;
an observed runtime-assigned port is never promoted to this intent
automatically. The renderer groups bindings by container port and protocol.
Intent validation rejects duplicate or overlapping fixed host bindings across
all containers in one target intent,
including omitted or wildcard addresses that could widen exposure.
Rootless low fixed host ports still fail before rendering. Historical fixed
TCP/UDP request shapes stay byte-compatible, while each new publication
branch requires its own capability.

Command and entrypoint each distinguish omitted/inherited, explicitly
cleared, and exec-argument forms. Health checks distinguish exec, one
shell-command string, disabled, and omitted/inherited. Checked timing fields
retain absence separately from an explicit zero start period or start
interval. The renderer does not execute shell text. `StartInterval` has no
inferred generic API floor: only an exact profile with independently reviewed
native evidence can admit that branch. All new command and health branches
likewise remain unadmitted by the historical profiles.

The native `ClearCommand` oracle is conditional. An isolated Engine request
with `Cmd:[]` and inherited entrypoint must retain the image command and its
exit-7 behavior; no generic clear claim follows from that JSON field. The
positive native shape instead pairs `Cmd:[]` with an explicitly authored,
nonempty `/bin/sh` entrypoint and requires an empty effective command, exact
runtime no-argument path, and exit 0 from both literal and rendered requests.
A separate explicit-entrypoint request omitting `Cmd` distinguishes the
entrypoint override's default effect, so the paired result is not attributed
to `Cmd:[]` alone. Before any production `CommandClear` admission, #30 must
reject that intent with inherited or cleared entrypoint and an independent
review must accept exact passing native evidence. This does not alter or admit
the separate `EntrypointClear` shape.

Protected typed target fields cover labels, user, working directory, hostname,
tmpfs mounts, read-only root filesystem, init, stop behavior, resource limits,
devices, security and identity settings, resolver entries, and logging. They
are never inferred from effective or runtime-assigned source values.
Constructors and intent validation reject malformed or conflicting values;
Debug and error paths retain no authored values. Each rendered branch is
capability-gated. Host user namespace remains closed and unadmitted.

Only `nofile` ulimits, `NET_BIND_SERVICE` capability additions, `SYS_ADMIN`
capability drops, `net.ipv4.ip_forward` sysctl values `0`/`1`, and positive
`k`/`m`/`g` `json-file` `max-size` log options are currently accepted named
settings. Other names, directions, keys, and values fail intent validation.
Each admitted name/key also needs its own exact-profile capability and native
evidence; a positive fact for one cannot admit another. This finite subset
does not close the full application migration contract: #30/#31 must extend
it where the ledger and application rehearsal require further settings.

This contract does not claim declarative readiness, external data, image building,
Swarm, or execution of any request.

The four historical catalog profiles and evidence files remain unchanged.
DockerLens #31 must independently verify exact request and resulting Engine
behavior in each claimed API and daemon mode, including loopback isolation,
repeated and ephemeral bindings, command clear behavior, shell/disabled
health, timing, mount access, and resource/security outcomes. BoxFerry owns
promotion of authored intent and structured loss decisions. Offline tests
establish only local request and rejection behavior.

The native Debian 11 nested default-bridge fixture may report a test-only
`nested_default_bridge_ipv6_unavailable` outcome for fixed or ephemeral `::1`
publication only after independently checking CLI and rendered configured and
runtime bindings, running state, same-container local and published IPv4
canaries, pinned outer TCP6 availability, inner IPv6-disabled state, and exact
kernel `ECONNREFUSED` at the requested or assigned host port across five
250 ms-spaced probes and one final post-control probe. Before a negative, the
running/default-bridge state, bindings, IPv4 canaries, and outer TCP6 control
are rechecked; a later connection is a positive candidate, never a negative.
Both fixtures
must agree. A connection requires successful IPv6 HTTP instead; all other
outcomes fail. Upstream lanes retain positive IPv6 assertions. This scoped
native fixture outcome does not admit or reject a production capability for
Engine 20.10, API 1.41, or any general daemon mode.
