# Finite hostname and resolver source contract

[ADR 0046](decisions/0046-hostname-resolver-source-proof-v2.md) expands mandatory
invocation 22, `native_health_metadata_tests::lifecycle::hostname::live_hostname_matches_engine`,
under its existing owner. The same 28 invocation names and seven delegated cleanup
scopes remain ordered. Invocation 22 now includes resolver observations; resolver
failure can prevent reaching PIDs27. PIDs27 and its immediate reader must still
succeed before nofile28. Earlier qualification cannot qualify this changed source.
This is test-only source preparation, not native qualification, catalogue admission,
application acceptance or publication authority.

## Independent hostname requests and effects

The four original hostname fixtures, commands, complete independently authored
request literals and assertions remain intact. Each case has independent CLI and
literal-rendered containers borrowing the existing digest-pinned BusyBox image.

| Case | Authored intent | Independent configured/process expectation |
| --- | --- | --- |
| Omitted | CLI omits `--hostname`; rendered body omits `Hostname`. | First twelve hexadecimal characters of that container's validated ID. This is a daemon default, never portable authored intent. |
| Explicit | CLI and typed target specify `dl-hostname-<run>`. | Exactly that synthetic run-owned value. |

The explicit target uses existing `ContainerSettings.hostname` and
`ContainerHostname`. Complete rendered requests must equal independent literals
before submission; CLI intent is not represented as an observed CLI HTTP body.
Inspect confirms configured hostname before start and while running. API-pinned
`docker exec ID hostname` returns the exact expected bytes with one newline.
Later inspect retains StartedAt, hostname/image/owner, running state, positive PID,
zero restarts and no paused/dead/restarting/OOM/error state. No arbitrary hostname
syntax, application identity or generated-hostname promotion is certified.

## Four fresh resolver fixtures

Four additional containers cover IPv4/IPv6 times independent CLI/rendered roles.
They are separate from the hostname controls; no DNS settings are added to the
original four. All eight names, ID slots and attempted flags are registered before
mutation under one original HealthRun, deadline, counters and bound outer owner.

| Family | Authored DNS server | Authored extra-host mapping |
| --- | --- | --- |
| IPv4 | `192.0.2.53` | `fixture-v4.local` to `192.0.2.10` |
| IPv6 | `2001:4860:4860::8888` | `fixture-v6.local` to `2001:db8::10` |

CLI `--dns`/`--add-host` and complete rendered request literals are independently
authored. The actual unlabelled IPv6 typed fixture is also used by the offline
API 1.41/Debian 20.10.5+dfsg1 and API 1.56/upstream 29.8.1, rootful/rootless matrix.
Each of StandaloneContainer, Command, DnsServers and ExtraHosts is independently
withheld. Native owner labels and their separate capability are bookkeeping,
not a hidden dependency of the unlabelled regression. Scoped test facts are not
fabricated reviewed profiles or public catalogue grants.

Before start and around observation, inspect must retain exact HostConfig.Dns
and ExtraHosts, canonical ownership, image and stable running process identity.
Two API-pinned execs read `/etc/resolv.conf` and `/etc/hosts` through a fixed
4097-byte sentinel read. More than 4096 bytes, non-ASCII/NUL/control content,
more than 64 lines or 16 tokens per line, over 255-byte tokens or malformed records
refuse. Parse complete records, never substring matches. Retain the complete
ordered nameserver array and every exact target-alias hosts row as finite
observations. Missing, duplicate, wrong-address or ambiguous target rows refuse;
unrelated hosts rows require valid IPs and bounded DNS-style names for every alias,
but never supply an inferred target mapping. Root-only names are not host aliases.
Comments cannot supply records. Public diagnostics never include file contents.
The accepted surrounding grammar is deliberately finite: one bounded DNS-style
`domain`, bounded DNS-style `search` names (also root/trailing-dot forms), and
unique options `ndots:0..15`, `timeout:1..30`, `attempts:1..5`, `edns0`, `trust-ad`
and `rotate`. Numeric spellings are canonical decimal. Other directives/options,
including sortlist, refuse even when the required nameserver is present.
This proves finite configured-file retention only: no DNS lookup, external DNS
reachability, connectivity or IPv6 network support is claimed.

Missing hostname/head applets, permission/runtime/transport failures, unsupported
behavior or unexpected content refuse the cell and lane. No fallback, skip,
retry or successful-unsupported reclassification is provided.

## Complete accounting and cleanup

The original 180-second invocation deadline,400-call/4 MiB aggregate,
100-call/2 MiB cleanup reserve,46-second ordinary cleanup margin, <=8-second
command timeout,7-second curl timeout and 1800-second lane watchdog remain.
Native command output/error caps and4096-byte request input cap do not change.

| Complete successful work | HealthRun captures, Podman / Docker |
| --- | --- |
| Initial authenticated outer snapshot | 1 / 2 |
| Context version/CLI version/info/CLI security/UID/base-image reads | 6 / 6 |
| Debian package read, Debian only | 1 / 1 |
| Independent borrowed-image snapshot | 1 / 1 |
| Four original hostname containers, eight calls each | 32 / 32 |
| Four resolver containers, nine calls each | 36 / 36 |
| Eight known-ID removals, five calls each | 40 / 40 |
| Two full ID/name absence rounds | 32 / 32 |
| Final borrowed-image snapshot | 1 / 1 |
| Final authenticated outer snapshot | 1 / 2 |
| Total upstream / Debian | 150/151 / 152/153 |

Ordinary calls total 78/79 Podman or 80/81 Docker; cleanup totals 72. Each selected
Docker outer snapshot additionally charges 65536 bytes; both snapshots are charged
by existing I/O, never an estimate substituted for actual charges. Cleanup's
whole capture envelope is 72 *(8192+2048)=737280 bytes. A pre-cleanup admission
check reserves those existing envelopes plus the two final ordinary envelopes
and pending backend extra, using existing checked final-snapshot accounting.
Before-cleanup calls must be <= 226 Podman or 225 Docker, and bytes <= 1212388
Podman or 1146852 Docker. These are derived restrictions within existing limits,
not extra allowances. Refusal remains inside the original caught work and still
runs original cleanup/terminal handoff; no proof publishes after refusal.

Each ordinary capture admits at most 65550 stdout plus 8192 stderr bytes, but
all calls cannot each consume that maximum within the aggregate. The preceding
four-container path already had this conditional aggregate behavior. Actual
bytes are counted and excess refuses. Eight bounded file payloads add <= 32768
bytes; original hostname exec output totals 68 bytes. Engine context/inspect
sizes and actual timing require genuine measurements. No universal maximum-size
or wall-clock success is claimed, and 72 cleanup calls cannot each spend 8 seconds
inside the 46-second margin.

Existing context acquisition is separately bounded: <= 16 requests,256 KiB per
response,2 MiB total bodies,2 selected resources,8 expansions and 15 seconds clipped
to the original remaining deadline. These direct acquisition reads are not
HealthRun captures/bytes. No limit or counter is reset or increased.

Eight globally distinct IDs also differ from the authenticated outer ID. Exact
names are `dl-host-<run>-{omitted,explicit}-{oracle,rendered}` and
`dl-resolver-<run>-{ipv4,ipv6}-{oracle,rendered}`. The borrowed image is neither
created nor removed. Before once-only removal, recheck ID/name/image/owner.
Two complete ID/name absence rounds precede publication. Unknown ownership or
cleanup uncertainty preserves failure and requests the bound outer teardown;
the marker is not proof of completed outer teardown. Final image/outer snapshots
must match. The existing five-child lifecycle block and all other owner scopes
retain their authority and obligations.

## Exclusive private v2 and unchanged public projection

Only `hostname-v2.json`, private schema_version 2, is accepted for the new
candidate. Its semantic contract remains `hostname-v1`; a mandatory closed
`resolver` subsection has contract `resolver-files-v1`, exactly both families
and both roles, finite configured/file observations and stable identity/state.
One independently supplied context and global ID set cover all eight records.
Old filename/schema, missing/mixed/extra/partial/stale/malformed resolver data,
wrong context and uncertain cleanup refuse. No old-proof fallback exists.
Historical v1 evidence retains its original meaning.

Existing ProofTarget publication remains exclusive 0600, single-link and held-
directory bound. Both publisher and stable direct-child reader enforce the
original 16384-byte serialized-file limit, with 0700 canonical ancestry,
owner/identity/stability/duplicate-key checks. Local publication and reader
filesystem operations add no native command calls. No nofile size exception is
selected. Oversize serialization or reads refuse instead of truncating.

The existing 12-argument immediate reader always runs, including without public
emission; its context comes from independent harness facts. The existing
19-argument emitter rereads against its independently built context before any
record is written. Reader success still returns precisely hostname-v1, empty
capability_admission and false catalogue_admission. Public additions remain
`hostname_contract: hostname-v1` and `hostname_outcomes` with admission
`unadmitted` and outcome `omitted_and_explicit_verified`. No resolver/private-v2
field, native value, DNS/extra-host/hostname capability, shape-map or sealed
catalogue admission is added. Emitter code/ABI and compiled catalogue stay intact.

## Qualification and consumers

Fresh complete final-source gates, independent review and genuine exact-head
four-lane qualification remain required. Existing baselines remain Debian 11
Docker 20.10.5+dfsg1/package20.10.5+dfsg1-1+deb11u2/API 1.41 and upstream 29.8.1/
rendering API 1.56/acquisition API 1.49, each rootful/rootless. Synthetic and offline
checks establish no native byte/time fit, compatibility or application acceptance.
Docker networking documentation is the existing semantic reference; no oracle
source/binary is copied or redistributed. Existing Apache-2.0 provenance applies.

Saved BoxFerry b24fb69b92236c6aa7becca3f2602b421d583ce2 has no private-hostname or
public-hostname-field consumer in its scripts/crates/tests. Its closed reviewed-
profile reader consumes the unchanged digest-bound four-lane catalogue and
schema 1 identity records. This bounded source inspection requires no consumer
edit; it is not a new source-pair test or application acceptance. Saved receipts
remain bound to their original sources. Other Lens/website consumers are not
changed. No dependencies, software pins, shared workflows or Renovate ownership/
extraction locations change. Publication and wider application gates stay separate.
