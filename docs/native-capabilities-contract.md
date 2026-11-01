# Named capabilities native source contract

[ADR 0049](decisions/0049-named-capabilities-native-source-proof.md) appends
capabilities31 after the unchanged thirty invocations and their immediate readers.
There are eleven delegated cleanup owners. PIDs27/read → nofile28/read → device29/read
→ memory30/read → capabilities31/read → logging32/read remains mandatory before
optional publication. [ADR 0050](decisions/0050-logging-native-source-proof.md)
adds the final logging scope without changing the capability behavior below.
This is test-only, non-admitting source preparation. Fresh native qualification,
whole-lane time/output fit, independent review and final complete gates remain due.

## Representable artifacts and independent CLI oracles

The product permits only NET_BIND_SERVICE in CapAdd and SYS_ADMIN in CapDrop.
Add-only, drop-only and both distinct names are three representable shapes. ALL,
opposite-direction tokens and duplicates remain rejected before rendering.
LinuxCapabilities and every applicable named fact remain independently mandatory.
Test-local facts permit source experiments; no public catalogue fact is promoted.

All controls borrow the existing pinned BusyBox and use direct idle `sleep 180`
PID1 with namespace-local effective root UID. Inspect validates inherited empty
entrypoint/init and root user rather than assuming image defaults. No image is
built, owned or removed; no extra mount, device, port, inner privileged flag,
privileged exec, setns, capsh or setcap is introduced.

| Ordered role | Explicit source configuration | Independently required PID1 CapEff |
| --- | --- | --- |
| default-cli | No cap flags | Measure D; bit 10 present, bit 21 absent |
| add-cli | `--cap-add=NET_BIND_SERVICE` | D |
| add-rendered | CapAdd singleton; no CapDrop | D |
| drop-cli | `--cap-drop=SYS_ADMIN` | D |
| drop-rendered | CapDrop singleton; no CapAdd | D |
| both-cli | Both named flags | D |
| both-rendered | Both named singleton fields | D |
| drop-all-cli | `--cap-drop=ALL` | 0 |
| netbind-only-cli | `--cap-drop=ALL --cap-add=NET_BIND_SERVICE` | Exactly 1024 |
| all-cli | `--cap-add=ALL` | Measure A; bit 21 present |
| all-minus-sysadmin-cli | `--cap-add=ALL --cap-drop=SYS_ADMIN` | Exactly A with only bit 21 removed |

There are eight CLI controls and three unmodified rendered artifacts. The CLI
ALL/drop/add-back controls establish independent transitions. Default presence
of NET_BIND_SERVICE and default absence of SYS_ADMIN make product requests
redundant against D. Artifact evidence therefore means exact request/native
configuration retention and consistent kernel state, never unique causal change
by the artifact itself. Never inject ALL into a rendered request or regenerate
its expected literal from the renderer. A lane contradicting an expected mask
fails; do not reorder flags, skip rootless or relax a required field.

Docker's [runtime privilege documentation](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
and CLI docs were consulted through Context7 `/docker/docs` and `/docker/cli`:
ALL is supported in both flags; NET_BIND_SERVICE is a default capability;
SYS_ADMIN is addable and not default. Linux UAPI names bit 10 and bit 21.
Documentation supplies expectations, not native evidence for these pinned lanes.

## Actual source observation and strict private reader

Every slot is bound by canonical ID/name/run label/borrowed image and exact
command/cap lists before start. Closed projections retain raw CapAdd/CapDrop,
start/PID/running state, restart/OOM/error/paused/dead state, user/init/entrypoint
and absence of additional mounts/devices/ports/privilege. Under the four exact
profiles only, empty lists may be null/empty; a singleton named token may retain
its exact spelling or a CAP_ prefix. ALL must be literal ALL. Other aliases,
extra tokens and replacements fail. Raw configuration is retained in the proof.

The kernel hostname is observed, never authored: inspect must show the default
short canonical CID and a regular API-pinned, nonprivileged root observer reads
`/proc/sys/kernel/hostname` from that CID. This binds the raw report to its slot;
it adds no product Hostname field or hostname capability. A held `/proc/1`
directory is checked against current PID1 before and after. The report includes
PID1/start ticks, proc device/inode, PID1 and observer user-namespace objects,
actual comm `sleep`, four root UIDs, and CapInh/CapPrm/CapEff/CapBnd/CapAmb twice.
Identity and all mask fields must stay stable. Namespace IDs may differ between
containers; each target must match its observer's user namespace. This does not
claim host-root powers, low-port binding, mounting or FUSE behavior.

Independent Rust and Python parsers require closed ordered rows, complete
sixteen-digit lowercase u64 hexadecimal masks and bounded canonical decimal
identities. They reject malformed, overflow, partial or duplicate fields. The
reader hashes actual raw bytes and recomputes every pair/default and causal
comparison. A rebound hash cannot legitimize a false mask or stale identity.

`named-capabilities-v1.json` is a closed schema 1 direct child of the held 0700
capture directory, at most 64 KiB, regular 0600, singly linked, nonsymlink and stable.
Existing `read_private_proof` custody is reused. Context/backend are independently
caller-bound. All eleven ordered roles, observations, accounting and verified
cleanup are mandatory. Immediate private validation runs even without public
output; the existing nineteen-argument emitter repeats it and requires exactly
`contract`, empty `capability_admission`, and `catalogue_admission=false` with
strict types. No public capability projection/schema/admission or historical
receipt is changed.

## Exact accounting and cleanup

One HealthRun owns the unchanged absolute 180-second deadline,46-second reserve,
300 ordinary calls/2 MiB,100 cleanup calls/2 MiB and400 aggregate calls/4 MiB. No counter,
timer or per-role reset occurs. Each small capture checks the actual combined
stdout/stderr delta is at most 8192. Binding and configured/running observations
use the closed CLI inspect projection, never a full shared inspect billed small.
The generic full-capture precheck remains unchanged. Full envelope F=73742;
small S=8192. Docker outer snapshots add one call and65536 bytes each, already
charged by the shared helper; Podman adds none.

| Stage | Calls | Captured-byte reservation |
| --- | --- | --- |
| Context including bound initial outer, context and borrowed image | Debian9 / upstream8, plus backend extra | Same number without extra × F, plus backend extra bytes |
| Each of eleven slots | Fresh404, create, small canonical bind, configured-before, start, running, raw report, running-after =8 | 8 × S |
| Final daemon health | 1 | F |
| Final borrowed-image and bound outer readbacks | 2 plus backend extra | 2 × F plus backend extra bytes |
| Verified inner cleanup | 11 ×9 =99 | 99 ×10240 =1013760 |

| Lane family / outer backend | Ordinary calls | Ordinary maximum captured bytes |
| --- | --- | --- |
| Debian / Podman | 100 | 1605800 |
| Upstream / Podman | 99 | 1532058 |
| Debian / Docker | 102 | 1736872 |
| Upstream / Docker | 101 | 1663130 |

These are source reservations, not measured runtime totals or wire-byte claims.
All pending work and final reads are reserved before mutation; final actual
per-slot 8, small 88, whole ordinary and cleanup 99 counters and deltas are checked.
Ordinary elapsed including final reads is at most 134 seconds; cleanup at most 46;
whole exact test at most 180. Initial acquisition retains its separate existing
16-request/2 MiB/15-second bound. The1800-second whole 32 lane fit is unmeasured.

Attempt liability is published before every create. A finite eleven-slot guard
requires canonical IDs for all attempted creates before entering common inner
cleanup. An unknown response forces the bound outer-owner teardown and cannot
enter name-based deletion. Nine calls per successful cleanup comprise five
configured/delete/absence calls plus two ID+name absence rounds. Verified-absent
terminal bookkeeping adds no command. Any uncertainty, panic, launch failure,
timeout or cancellation remains nonpositive, propagates to the original lane
EXIT teardown, and cannot publish success. Borrowed images remain unowned.

No software dependency, runtime/tool/image/action pin or shared workflow changes.
Existing Renovate managers, paths/extraction, groups and approvals stay intact;
source registration is confined to DockerLens's existing native test harness.
Memory30/device29 producer and strict-reader semantics are preserved.
