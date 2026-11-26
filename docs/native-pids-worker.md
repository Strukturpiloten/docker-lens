# Prepared test-only fork/errno witness

This unwired helper implements the syscall side of [ADR 0039](decisions/0039-measured-pids-boundary.md).
It adds no canonical invocation, product executor, public capability, controller
authority or native qualification. PIDs27 and subsequent nofile28 remain pending.
The separate root-side collector must independently establish each live leaf,
membership, controller limit, event delta, competing-limit headroom and runtime
binding. Worker JSON cannot establish those facts or replace the collector.

## Isolation and original owner

`examples/native-pids-worker.rs` is an ordinary Cargo example using the existing
dev-only libc dependency. It never executes commands or discovers a runtime. Do
not invoke it on the development host. Actual fork tests require the explicitly
owned isolated native fixtures and the original harness cleanup/deadline owner.
No native run or compilation is established by the pure controls in this change.

The PID1 worker mode takes exactly three positional values: the closed case, a
32-character lowercase hexadecimal run nonce, and the original absolute
`CLOCK_MONOTONIC` terminal deadline in nanoseconds. Cases are exactly `cli16`,
`cli64`, `cli_unlimited`, `rendered16`, `rendered64`, `rendered_unlimited`. The
independently authored harness supplies the expected PIDs setting; the name is
only context, never proof of an actual controller setting. Startup refuses a
remaining budget above 180 seconds or at/below 46 seconds. Work and protocol
operations stop before the original deadline minus the 46-second cleanup
reserve; cleanup may use the remaining original time. Neither stage renews time.

The worker guard requires Linux, namespace PID 1, parent PID 0 and exactly one thread.
The trusted fixture setup must mount its owned private directory at the fixed
absolute `/dl-pids-control`, with mode 0700 and worker UID ownership. Before
starting the worker, create two distinct single-link 0600 FIFOs named `commands`
and `events` under it, owned by the same UID. Hold the event reader open before
startup. The worker opens only these fixed control names, rejects symlinks, and
rechecks held/name inode identities and modes during communication. Fixed proc
reads verify its one thread and exact child ledger. There is no arbitrary path,
environment setting, namespace entry, controller-write or command API.

## Fixed outer-guest controller mode

The same verified static binary also accepts exactly
`serve RUN LANE NONCE DEADLINE_NS`. This selects the fixed helper in
`examples/native-pids-controller/mod.rs`; it requires outer-guest UID0 and a PID
other than 1. RUN is eight ASCII alphanumeric characters. LANE is one of
`debian11-rootful`, `debian11-rootless`, `upstream-rootful`, `upstream-rootless`;
nonce and original monotonic deadline retain the worker bounds. Dispatch accepts
only that exact mode and bounded UTF-8 arguments; the six PID1 case paths keep
their existing guard. The helper performs no fork, exec, runtime request,
namespace entry or kernel-controller write, and requires no guest Python/tool
installation.

The original Rust actor starts this mode outside the measured inner leaves. Its
fixed private root is `/dockerlens-native/pids-control`, with six case-named slot
directories. Setup exclusively creates 0700 root/slot directories and distinct
0600 single-link FIFOs, all owned by the lane's selected guest UID. It records
inode identities before later fallible setup, and
holds both FIFO sides open before any inner worker starts. Slot ownership is
UID0 in rootful lanes and UID1000 in rootless lanes; the inner worker still runs
as UID0 in its own namespace. Selected ownership also permits rootless traversal
of the private root. The helper reads only its held `/proc/self/exe` source and
creates one exclusive 0700 selected-UID copy at the fixed
`/tmp/dockerlens-pids-worker-RUN/native-pids-worker` path. It verifies exact bytes,
SHA-256, size, modes and source/copy inode identity before worker startup. Prepare
returns the fixed artifact path, size, hash and source/copy ownership metadata;
the actor independently binds them to the original verified build artifact.
That same copy mounts readonly at `/dl-pids-worker`, and each slot directory
mounts at `/dl-pids-control`. Actual runtime ownership, mounts and launch remain
the independently validated actor's responsibility. This creates no new image
or published artifact.

The controller consumes version-1 newline JSON with strictly increasing integer
sequences and closed `Prepare`, `Event`, `Seal`, `Close` operations. Prepare,
Seal and Close have only `op`, `version`, `sequence`; Event adds a closed `slot`
and the next worker `command`. Each slot requires
`identity`, `baseline`, `attempt`, `hold-failure` or `hold-control`, `release`,
`reuse`, `finish`. Identity reads the startup event; other stages send the fixed
nonce-bound command and return the actual worker JSON. Responses retain the
version/sequence/op, with prepared/sealed/closed status or slot/worker event.
Prepare additionally carries the verified artifact custody fields. Duplicate,
extra, replayed, noninteger, malformed and out-of-order data refuses. Every line
is at most 4096 bytes, there are at most 45 requests (Prepare, 42 events, Seal, Close),
and local combined framing/FIFO I/O is bounded to 64 KiB. This grants no extra
parent budget.

After all six slots finish and the actor seals the original live root-side
measurement, Seal switches only the cleanup cutoff to two seconds before the
original terminal deadline. After Seal, only Close is allowed; no experiment time
is renewed. After Close, the actor closes controller stdin. The helper requires EOF without
trailing bytes, closes held descriptors and verifies/removes only its recorded
owned FIFO/directory and guest-copy inodes before acknowledging closed. Missing completion of
any slot or cleanup uncertainty refuses. Controller work stops at the original
deadline minus 46 seconds. Worker PID1s continue their completed idle lifetime
through the root-side measurement seal and intentional fixture removal.

## Closed protocol and synchronized holds

Every UTF-8 JSON line including its newline is bounded by 4096 bytes. Commands
have exactly the string fields `command` and `nonce`; extra, duplicate, stale,
malformed and out-of-order fields/commands refuse. The identity event is emitted
first. Then use this sequence once:

| Command | Successful event and actual state |
| --- | --- |
| `baseline` | `baseline`: PID 1, no children, one thread |
| `attempt` | `attempt`: 15 children for finite16, 32 children for either control; every child acknowledged its anonymous-pipe barrier |
| `hold-failure` (finite16 only) | `hold-failure`: exactly one additional actual `libc::fork()` returned -1 and immediately captured errno equalled the linked `libc::EAGAIN` constant; retained children remain blocked |
| `hold-control` (finite64/unlimited only) | `hold-control`: all 32 children remain blocked; no additional fork |
| `release` | `release`: hold writer closed, every exact known child successfully reaped, child ledger empty |
| `reuse` | `reuse`: one actual successful fork and exact successful reap after release, empty ledger |
| `finish` | `finished`: empty ledger; PID 1 then remains alive and idle for the root-side measurement seal |

The `attempt` event is the **pre-failure saturated barrier**, allowing the root
collector to sample the actual finite16 leaf at 16 TIDs/current before sending
`hold-failure`. The subsequent hold event retains the same successful children
for post-attempt sampling. A failed initial fill, unexpected errno, unexpected
successful extra fork, early child exit, unknown child, identity change,
cancellation or cleanup uncertainty cannot produce successful completion. Controls
retain 33 total tasks, deliberately exceeding 16 and staying below 64. Unlimited
is only this bounded control; it makes no infinite-capacity claim.

Every state event has exactly `schema`, `case`, `nonce`, `phase`, `pid`, `threads`,
`children`, `child_count`, `fork_return`, `errno`, `eagain`. Schema is
`dockerlens-pids-worker-v1`. The child list contains the exact unreaped namespace
PIDs. `fork_return`/`errno` are null except the successful failure witness
(-1/EAGAIN) and successful recovery fork (actual child PID/0). The independently
held collector must bind these namespace PIDs to its actual TID accounting.
After `finished`, the worker accepts no further operation and retains zero
children. It stays alive so the root collector can seal all six original init
identities before the owner intentionally stops/removes the known fixtures.
TERM/INT after completion permits successful idle shutdown; TERM/INT before
completion requires cleanup and failure. Expiry of the original terminal deadline
ends idle with failure. No successful workload or cleanup renews that deadline.
Successful atomic publication of the `finished` line commits completion. The
worker briefly masks TERM/INT around the pending-cancellation check and that one
nonblocking write, then restores the signal mask before polling or idling. An
owner signal delivered immediately after publication follows completed-idle
semantics; it cannot retroactively cancel the completed experiment.
The harness must establish the seal while each original init is still alive;
an early exit, even after a `finished` line, cannot satisfy that custody contract.

The identity event instead carries exactly `schema`, `case`, `nonce`, `phase`,
`pid`, `threads`, `rlimit_nproc_soft`, `rlimit_nproc_hard`, `kernel_sysname`,
`kernel_release`, `kernel_version`, `kernel_machine`. These kernel fields come
from the same actual `uname` result and must match the root collector's measured
release/version/machine tuple. They select no static kernel allowlist or software
pin. RLIMIT infinity retains its native unsigned
value. It does not establish competing global/ancestor limits or scheduling
policy; those remain collector requirements. Error events use the same state
shape with a closed failure phase and always accompany a nonzero exit; receipt
presence is never success. The outer harness must require the exact sequence,
successful completion event, live original PID through the seal, intentional
owner shutdown and its independent live evidence.

Children reset TERM/INT/PIPE dispositions, close the inherited writer, acknowledge
readiness and block on an inherited anonymous pipe. After fork, their branch
uses only async-signal-safe libc calls and `_exit`, with no allocation, Rust
destructors, formatting or panic path. Parent TERM/INT handlers request cleanup
and nonzero exit. The parent never signals a PID, executes another program,
waits on `-1`, or retries a failed fork. Release/error cleanup closes the writer
and reaps only exact known children; an unknown child or uncertain reap refuses.

## Conditional native static build

`scripts/build-native-pids-worker.py` is a stdlib-only builder, never a runner.
Its required options are `--output-directory`, `--candidate`, `--deadline-ns`.
The output must already be an owned 0700 absolute directory without symlink
ancestors. Candidate is the harness-supplied 40-character lowercase commit
context; the source and lockfile hashes separately bind actual build inputs.
This does not authenticate a Git revision or make dirty inputs that revision.

It reads the existing canonical toolchain pin from `rust-toolchain.toml`, disables
automatic toolchain installation, selects only the actual native GNU target
(`x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu`), checks compiler
release/host, and invokes locked offline Cargo with explicit `--target`, release
mode, `+crt-static`, aborting panic and symbol stripping. Target flags therefore
do not become host build-script/proc-macro flags. The private temporary target
directory and bounded private compiler log are separate from ordinary builds.
The build always passes `--jobs 2`; inherited Cargo job settings are removed, so
caller environment cannot raise this fixed concurrency cap.
Repeated Cargo `--config` overrides select release `opt-level="z"`, `lto="fat"`
and `codegen-units=1`. Cargo coordinates LTO and embedded bitcode; the builder
adds neither LTO nor embedded-bitcode flags to `RUSTFLAGS`. The manifest's
required `profile` object records exactly `name="release"`, `opt-level="z"`,
`lto="fat"`, `codegen-units=1`. Inherited profile environment overrides are
removed. This targets smaller artifacts while retaining the two-job cap and
original deadline; only an actual measured build can establish the resulting
size or original aggregate budget fit. There is no allowance increase, alternate
profile retry or dynamic fallback.
CLI TERM/INT handling records cancellation and ignores repeated requests while
owned cleanup runs. Safe checkpoints refuse after compiler startup, during
bounded I/O and at most 50-millisecond process-exit waits, then unwind through
the existing owned process-group kill/reap and artifact rollback. The handler
returns during subprocess construction so the child can first become owned by
that cleanup path. Cleanup keeps the original terminal deadline, and handlers
are restored after the scoped build finishes. Cancellation during log or artifact
publication removes the new executable/manifest and returns fixed nonzero status.
Missing toolchain, target, linker or static CRT fails closed. There is no install,
musl fallback, dynamic fallback, new image, package or published binary artifact.

Before output, a bounded ELF64 little-endian parser validates the exact machine,
program-header and segment bounds, rejects `PT_INTERP` and `DT_NEEDED`, and permits
static PIE relocation metadata. It uses no external `readelf` dependency. Binary
input is bounded to 8 MiB and compiler output to 1 MiB. These are **local build
caps**, not evidence that six-role build/copy/experiment accounting fits the
existing parent budgets. Integration must charge actual source, build/copy,
report bytes, operations and elapsed time to that original owner and refuse a
budget shortfall. No helper allowance or enlarged experiment budget is granted.

Outputs use exclusive no-follow creation: owned single-link executable
`native-pids-worker`, private `native-pids-worker.json` and private
`native-pids-worker-build.log`. The closed schema
`dockerlens-pids-worker-build-v1` manifest records candidate context, compiler
metadata, toolchain, explicit target/flags, exact binary size/SHA-256, ELF result,
worker-source/controller-source/lockfile/Cargo-manifest hashes, log size/hash and
original deadline. `controller_source_sha256` is mandatory and binds the fixed
`examples/native-pids-controller/mod.rs`; a missing module refuses before
compilation, and any change across the build refuses artifact publication. The
worker source, controller source, lockfile, Cargo manifest and canonical toolchain file must remain byte-exact
across the build. Compiler metadata has the fixed fields `release`, `host`,
`commit_hash`, `commit_date`, `llvm_version`. A missing manifest
or build error grants no usable artifact. The independent harness must recheck
manifest schema and expected source/candidate, binary bytes/hash/size/architecture,
and fixed copy destination before use in an exact known-created stopped fixture.
The independent actor owns runtime copy and fixture startup.
The mandatory private compiler log is written, fsynced and verified before
publishing an executable or success manifest. Write, verification and fsync
failures roll back newly created executable/manifest inodes; preexisting names
and replacements owned by another operation are preserved.

## Fresh linker and static-CRT receipt

Every new accepted build requires a closed `build_tools` object using schema
`dockerlens-pids-build-tools-v1`, policy `native-gcc-bfd-v1`, and scope
`installed-tools-and-consumed-crt-only-v1`. The builder must run unprivileged.
It selects existing GCC and GNU BFD entry programs from trusted system prefixes,
records actual version/native-target queries, entrypoint file kind, stable regular-file identities and
SHA-256 hashes, and rechecks selected files before publishing. It clears inherited
GCC/search-path injections along with the existing Cargo/Rust wrapper settings.
There is no tool installation, default-linker guess or alternate-family retry.
Native target correspondence accepts the same exact CPU (`x86_64` or `aarch64`)
with `CPU-linux-gnu` or `CPU-VENDOR-linux-gnu`, plus only the known native GNU
vendor shorthands `CPU-suse-linux` and `CPU-redhat-linux`. The optional explicit
vendor is a single ASCII alphanumeric/underscore/dot/plus token. The entire
reported triplet is ASCII and at most 128 bytes; any case-insensitive embedded
musl, uclibc or android marker refuses. Other suffixless Linux targets, non-GNU ABI suffixes,
extra ABI components and different CPUs refuse. The receipt retains the raw
reported `driver.native_target`; the manifest's separate Rust `target` stays
the exact selected native GNU Rust target. No reported triplet is rewritten.

Cargo's exact target linker points to an owned private driver wrapper. That
wrapper forces a private `-B` prefix and `-fuse-ld=bfd`; the x86_64 target also
disables Rust's documented LLD preference, while aarch64 receives no x86-only
flag. The private `ld.bfd` shim records the actual final-example invocation with
exclusive creation, then executes only the selected absolute linker with a fixed
GNU dependency-file path. A bypassed prefix, absent/duplicate final witness,
wrong backend/output, unsupported dependency option or failed link refuses.
Manifest `flags` is the exact effective target `RUSTFLAGS` passed to Cargo:
the static/panic/strip settings plus `-C linker-flavor=gcc` for both targets and
`-C linker-features=-lld` only for x86_64. The environment and receipt use one
effective value; a legacy base-flags-only receipt is refused by strict consumers.
After successful Cargo completion, the invocation's output must be the same
inode and exact bytes as the compiled artifact. This is new evidence for that
build; earlier ELF/size results cannot recover an unrecorded linker chain.

Fixed GCC print-file queries pre-resolve/hash only allowed startup/end CRT
objects, static libc and optional static GCC runtime archives. The actual GNU
dependency record must confirm consumption of exactly one start/init/fini/
begin/end/libc role; only `gcc-runtime` and `gcc-eh` are optional additional
roles. Static PIE may select `rcrt1.o` and `crtbeginS.o`; no T-object assumption
is made. Dependency escaping/continuations and phony rules are parsed as bounded
data, never evaluated. Only prehashed allowlisted CRT paths are opened from that
record; Rust sysroot/plugin/full input closure is outside the receipt scope.

The required object contains driver/linker path, version, size, SHA-256, full
`st_mode`/inode/timestamp/ownership identity, wrapper hashes, invocation count/
size/hash and binary size/hash binding, dependency size/hash, consumed CRT
records, and total pre/post hashed input bytes. Installed-tool hashes are
observations of actual installed bytes. Package metadata is explicitly
`unavailable` with reason `os-bootstrap-not-queried`; a Nix store component may
appear only as an `unverified_path_hint`, never verified package/version or
publisher-integrity evidence. OS-provided tool versions are an explicit trusted
bootstrap exception. No package/configuration/credential database is read.

Successful builds retain these mandatory owned, single-link 0600 files beside
the artifact in the private 0700 output directory:

| Fixed file | Bound | Binding |
| --- | --- | --- |
| `native-pids-worker-driver.py` | 16 KiB | `wrappers.driver_sha256` |
| `native-pids-worker-ld.py` | 16 KiB | `wrappers.linker_sha256` |
| `native-pids-worker-link.json` | 64 KiB | `invocation.size` / `sha256` |
| `native-pids-worker-link.d` | 128 KiB | `dependencies.size` / `sha256` |

Metadata capture is checked during bounded compiler polls and before reading;
publication failure rolls back new records and executable/manifest. Each selected
system file is at most 32 MiB; unique prehashed tool/CRT inputs total at most
128 MiB, with recorded pre/post hash reads at most 256 MiB. These host-build
guards grant no additional experiment or capture allowance. Metadata bytes,
queries, hashing and linking remain charged to the original owner/deadline,
alongside the unchanged profile, two-job cap, log limit and cleanup reserve.
Raw paths/argv remain private. This is concrete selected-tool/CRT provenance,
not hermetic host or supply-chain attestation; further OS-wrapper/interpreter
and toolchain implementation dependencies are not traversed. Required
`implementation_closure="unresolved"` retains that limit. A `file_kind="script"`
hash identifies the actual selected OS-wrapper entrypoint, never the underlying
ELF BFD backend or interpreter. Tool kinds are `elf`/`script`; startup objects
require `elf`, static archives require `archive`, and thin/script archives refuse.

## Validation and remaining native work

Python controls synthesize inert ELF headers and mock compiler calls. They cover
both machines, static PIE, dynamic-loader/library refusal, malformed/truncated
headers, source/output custody, deadline boundaries, flag injection removal,
manifest fields/hashes and refusal before binary publication. Rust unit controls
exercise only pure argument/command parsing and ledger insertion. None calls
fork. Unit/control tests cannot establish actual syscall, thread, barrier,
signal, static-CRT or native fixture behavior.

Reserved integration work must compile/inspect each selected native architecture
and run baseline, both controls, finite16 EAGAIN/counter attribution, recovery,
TERM/INT cleanup and timeout/early-exit/unknown-child failure controls inside the
explicit fixtures. All six roles, rootless delegated leaf behavior, original
aggregate budget fit, exact-final-candidate complete/native gates and independent
review remain pending. Current coordinator26, emitter, public API, capability
maps and future nofile28 are untouched.

Current Rust/libc references were consulted through Context7 on 2026-10-25:
[Rust C runtime linkage](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes)
and [libc](https://github.com/rust-lang/libc). Current libc documentation selects
0.2.191; this is API guidance, not validation of the locked 0.2.189 artifact.
Implementation is independently authored rather than copied oracle source.
No upstream binary, source implementation or oracle fixture is redistributed;
new repository files follow the repository MPL-2.0 license. No external oracle
command was executed. The combined native-owner integration adds pinned dev-only
`sha2` 0.11.1 with default features disabled for the fixed guest-copy digest;
the primary owns its shared manifest/lockfile changes and checksum review.
Renovate's existing Cargo manager owns this dependency, libc, serde/serde_json
and lock integrity. Its existing regex manager owns `rust-toolchain.toml`. The
builder reads the canonical pin and introduces no duplicate extraction location
or manager; existing Cargo grouping/approvals and native-image extraction remain
in force. Image, workflow and toolchain pins are unchanged.
The release profile overrides are operational build settings, rather than
software-version pins; they move no Renovate extraction location. Cargo's
[profile settings](https://doc.rust-lang.org/cargo/reference/profiles.html) and
[command-line configuration](https://doc.rust-lang.org/cargo/reference/config.html#command-line-overrides)
were checked through Context7 on 2026-10-26. The settings optimize size without
claiming a measured result or compatibility qualification.
GCC's [target query](https://gcc.gnu.org/onlinedocs/gcc/Developer-Options.html)
retains the configured machine spelling. Its
[GNU/Linux options](https://gcc.gnu.org/onlinedocs/gcc/GNU_002fLinux-Options.html)
document glibc as the default except explicit musl/uClibc/Android targets; these
references were checked through Context7 on 2026-10-26 for the narrow native
SUSE/Red Hat alias rule. This grants no generic unknown-Linux-ABI fallback and
does not replace consumed-CRT or final-ELF validation.
GCC's [directory search](https://gcc.gnu.org/onlinedocs/gcc/Directory-Options.html)
and GNU ld's [dependency-file option](https://sourceware.org/binutils/docs/ld/Options.html)
were checked through Context7 on 2026-10-26. The existing OS tool selection is
recorded per fresh build under the bootstrap exception above; it adds no
downloaded-tool pin, package installation or duplicate Renovate manager. Actual
kernel identity is runtime evidence and adds no operational version pin either.
