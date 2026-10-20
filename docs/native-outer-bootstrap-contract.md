# Original-PID1 bootstrap source component

Status: connected validation-source component; no native or boundary qualification.
Continues DockerLens #39/#31 under #3.
[ADR 0033](decisions/0033-original-outer-custody.md) connects this component to
the canonical original-object owners and private consumers. All mandatory tests,
public output and selected capabilities retain their existing requirements;
complete-path fit and fresh native qualification remain open.

`scripts/native_outer_bootstrap.py` prepares inert bootstrap arguments and
strictly decodes a caller-supplied private k8s-file log snapshot. Calling its
Python functions does not execute the returned shell source, launch a runtime,
read host `/proc`, change the host, or create native evidence. The tests author
their observations independently; parsing a synthetic frame does not prove its
origin or truth.

## Original-PID1 handoff contract

The inline shell is intended to run as the original outer PID1, before the
image's Docker/rootlesskit launcher. It checks inline shell/proc/single-NSpid
identity; original PID1 start ticks, UID and PID/mount/cgroup namespace links;
one exact `0::/` membership and one cgroup2 mount rooted `/` at
`/sys/fs/cgroup`; and the held/named original controller directory's device,
inode and exact 512-PID/4-GiB ceilings. It rechecks these identities before one
bounded stdout frame and an exact original-argv exec tail. Unknown, split or
changed mapping fails; there is no ancestor search, rebase or numerical-limit
fallback.

The wrapper necessarily changes the initial OCI argv. Its effective-spec
expectation binds the approved wrapper prefix and byte-exact original argv tail,
not claim unchanged OCI args. User, environment, working directory and original
stdin/stdout/stderr must survive handoff. Observation failures are suppressed;
an ordinary original-command exec failure can remain in the private startup log
and is not native success. No mailbox, permission widening, extra mount, install
or shared mutable daemon store is added. The existing pinned images must supply
compatible `stat` and `readlink`, and a dash/BusyBox-ash-compatible `local`
builtin. All helper-written variables are dynamically scoped within the
bootstrap function so colliding exported image variables are restored before
handoff; this is not a generic POSIX-shell portability claim. Their actual image
execution is not tested here. Fake-environment shell-scope controls do not
execute the bootstrap or probe host `/proc`.

## Decoder and custody limits

The pure decoder accepts at most 16 KiB of complete private log records and
requires the nonce-bound bootstrap frame as the first complete stdout record;
the marker, JSON and newline together are capped at 1024 bytes. It rejects
fragments, truncation, duplicate frames/JSON keys,
unknown fields, invalid timestamps, typed numeric violations and ambiguous
controller mappings using closed exception text. Returned data stays private.
It authenticates neither a container nor the log inode, OCI spec, runtime,
original boundary or later controller object.

The connected lifecycle coordinator must bind
fresh exact-ID create/init/Created/start continuity, the actual runtime/handler
profile, held effective configuration and runtime-consumed config relationship,
absent later hooks/resource overrides, image/owner/user/env/cwd/argv expectations,
held original log inode and immutable frame prefix, and final rechecks. The
failure-only port diagnostic and its short prefix hash are not proof and must
not be promoted into this role.

The Rust producer and independent mandatory reader require the same bounded
lifecycle context and original-object rechecks, all 37 existing reader-coordinate
witnesses and every original positive effect/cleanup predicate. Actual compact
serialization must fit the unchanged 16-KiB custody ceiling including the
reserved 1 KiB; a parsed startup frame alone does not prove that fit. Preserve
the original 120-second outer startup allowance, 180-second PIDs deadline and
46-second cleanup reserve with explicit call/byte accounting.

## Verification and consumers

Focused synthetic controls, isolated fake-environment scope/mount-predicate
checks and shell syntax checks are source evidence only; none execute the full
bootstrap or probe host `/proc`.
Fresh exact-final-candidate complete and genuine four-lane/28-invocation native
validation, independent review, actual six-authored-fixture consumers, real
application migrations and package checks remain required. Rootless systemd/user
manager/delegation fixtures remain unresolved. No release is ready/requested.

Local/main/trusted-dispatch/release use the same canonical validation harness.
Its connected source is not qualified by the component tests above; the
experimental same-envelope partition needs genuine whole-harness/native fit
despite passing the authored scenarios in ADR 0033. Other Lens
products and the website have no consumer, and BoxFerry has no product dependency
on this private helper. Existing toolchain, Action and five-image extraction
locations remain unchanged. The separate safe-clock dev pin is Cargo-owned as
documented in dependency-policy.md; reviewed source-oracle versions remain
evidence constraints, not floating installation pins.
