# Finite device mapping native source contract

[ADR 0047](decisions/0047-device-mapping-native-source-proof.md) appends one
mandatory device child as invocation 29 after PIDs27 and its strict reader, then
nofile28 and its strict reader. The original 28 names, order, owner scopes and
reader failure dominance remain intact. Invocation 22 retains ADR 0046's resolver
semantics. Eight delegated cleanup scopes now exist. This is unadmitted source
preparation, not native qualification or application acceptance.

## Independent controls and actual read

Both run-owned containers borrow the existing digest-pinned BusyBox image.
The oracle uses API-pinned CLI `--device /dev/null:/dev/native-null:r`; the other
uses the existing typed `DeviceMapping` renderer. The entire rendered create
request must equal an independently authored literal, including exact
`HostConfig.Devices` source path, target path and `CgroupPermissions: r`.
No new image, capability catalogue fact or public schema is introduced.

Inspect before start and twice while running binds canonical unique ID,
name/run/owner label, image reference and immutable image ID, exact configured
command and inherited entrypoint, exact Devices array, running status and
positive stable PID. Privileged, extra capabilities, mounts, restart, pause,
dead, OOM and error states cannot pass. Start failure, unknown state and transport
uncertainty are failures, including in rootless lanes; there is no refusal-to-pass
conversion.

Each API-pinned `docker exec --user 0:0` runs the same fixed bounded observation.
It requires source and target to be nonsymlink character devices, observes
source/null device numbers 1:3, opens the target on descriptor 3 and compares
target and held descriptor device/inode before and after the read. A direct
`dd bs=1 count=1` reads only the held descriptor; its successful result must
contain exactly zero bytes. A temporary run-container-local file retains the
bounded result; failures propagate through the original command timeout. The
five-line report retains actual source identity, target/opened/after inode
identity and read byte count, with SHA-256 binding. The independent reader checks
the complete grammar and semantics after checking the hash; recomputing a hash
cannot legitimize a false report. At most 1024 report bytes are accepted.

This proves configured retention and a character-device read only. It does not
prove denial of writes or device creation, general device access enforcement,
arbitrary devices or broader DeviceMappings support.

## Liability, custody and fixed accounting

The existing HealthRun owns all calls, captured bytes and the original absolute
deadline. Both slots are registered before mutation. Each actual create publishes
attempted liability first; attempted slots without a canonical bound ID prevent
all inner cleanup attempts and require the existing verified outer teardown path.
The existing bound owner, two absence rounds and terminal-cleanup primitive are
reused. The borrowed image never becomes owned and is never removed; its final
snapshot must match. The authenticated outer's final snapshot must also match.
No counters, deadline or cleanup reserve are reset.

| Component | Ordinary calls | Captured-output allowance |
| --- | --- | --- |
| Bound outer, context and borrowed image | 8 upstream / 9 Debian, plus selected Docker backend extra 1 | Existing shared bounded captures; actual charges retained |
| Oracle control | 8: fresh name, create, bound name, configured-before, start, running, exec/read, running-after | Five inspect captures at 65550+8192; three successful CLI create/start/read outputs at most 1024+8192 each |
| Rendered control | The same 8 calls | Five inspect captures and API create at 65550+8192; empty API start and exec/read at most 1024+8192 each |
| Final daemon health | 1 | 65550+8192 |
| Final borrowed image and outer reads | 2 plus selected Docker backend extra 1 | 2*(65550+8192), plus Docker extra 65536 |
| Terminal cleanup | Separate 18 = 2*(5+2*2) | At most 18*(8192+2048) = 184320 |

Ordinary totals are 27/28 calls for Podman upstream/Debian and 29/30 for Docker
upstream/Debian. Existing snapshot code alone charges the selected backend; its
two 65536-byte extras remain in actual ordinary accounting. Before mutation a
checked guard reserves the complete pending success-path work and final reads
within the existing 300-call/2-MiB ordinary ceiling. A second checked guard
reserves final ordinary reads before cleanup. Eighteen cleanup calls and their
184320-byte envelope fit the unchanged 100-call/2-MiB cleanup reserve. Unexpected
output or failures still use the original bounded capture and terminal cleanup;
the success-path envelope cannot establish successful native aggregate fit.

The original aggregate remains 400 calls/4 MiB, exact-test deadline 180 seconds,
ordinary-work cutoff with 46 seconds remaining (134 seconds maximum), and
46-second cleanup envelope. Final ordinary reads remain ordinary work. Existing
context acquisition keeps its separately bounded 16-request/2-MiB/15-second
contract and rendering/acquisition API distinction. The whole-lane watchdog
remains 1800 seconds. No new decoder acquisition or host probe is added.

`device-mapping-v1.json` is a private closed schema-1 direct child of the held
0700 capture directory, owned by the current UID, regular 0600, singly linked,
nonsymlink, stable and at most 16384 serialized bytes. The existing publisher and
held-descriptor reader provide custody; there is no alternative reader protocol.
The proof binds independent candidate/run/lane, release, both API dimensions,
mode, daemon UID, fixture image, selected backend and authenticated outer
identity, both ordered roles, configured/read observations, exact counters,
measured byte/time bounds and verified cleanup. Missing, duplicate, swapped,
malformed, oversized, substituted or semantically false private evidence fails.

## Consumers and qualification

The exact wrapper selects only
`native_health_metadata_tests::lifecycle::device_mapping::live_device_mapping_matches_engine`
and binds its deadline once to the existing timeout. Only closed stage/site and
cleanup-handoff diagnostics may escape. The immediate strict 12-argument reader
runs whether or not public evidence is requested. The unchanged 19-argument
emitter repeats device custody/context/semantic validation and accepts only the
exact typed three-key unadmitted reader result before any public output.
No device projection, admission shape, capability bit or historical evidence is
added or rewritten.

Independent synthetic controls cover all four lanes and both selected backends,
rebound hashes, false configuration/role/device/rdev/read/process/context,
private-file and directory replacement, malformed/oversized custody, timeout and
cancellation dispositions, exact counters, cleanup uncertainty, selection,
original deadline and strict invocation/reader order. These are offline source
checks, not genuine device reads. Final-source complete gates, independent review
and fresh exact-candidate Debian11 API1.41 and upstream API1.56 rootful/rootless
whole-29-call runs with actual reads and verified cleanup remain required.
Memory effects, named capability add/drop and logging proofs remain open; this
slice closes none of them. Catalogue admission, historical 57-shape preservation,
BoxFerry application acceptance and publication remain separate obligations.
