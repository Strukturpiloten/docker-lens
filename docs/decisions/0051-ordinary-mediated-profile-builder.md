# ADR 0051: Fixed ordinary mediated profile builder

Status: accepted bounded source-only test-helper contract; consumer opt-in and
native qualification pending. Adds a distinct policy builder alongside ADRs
0004 and 0038; their active legacy policy and lifecycle remain unchanged.

## Decision

Add only `mediated_profile_bytes(name)` beside `profile_bytes`. It accepts the
existing strict finite generated name and emits one attachment-free ordinary
enforce profile with thirteen fixed AppArmor 5.0.2 family rules supported by the
declared ABI4. The complete
[source contract](../ordinary-mediated-profile-contract.md) freezes its reviewed
permission vector: ordinary file access and inherit-only exec, capabilities,
network/Unix, explicit D-Bus bind/send/receive, mount/remount/unmount/pivot-root,
signal send/receive, ptrace, userns create, and exactly seven explicit POSIX queue
permissions (create/read/write/open/delete/setattr/getattr with type=posix).
No all-rule, io_uring, generic/SysV queue or D-Bus eavesdrop permission is emitted
or claimed. Omission is not a denial or mediation claim. No self-directed profile/hat
transition, exec target, configurable rule, mode, attachment or child profile is
part of this contract.

This is a permissive test-only prerequisite, not a security sandbox or
restriction-equivalence claim. Ordinary mediated execution makes the reviewed
inherit permission meaningful, but source semantics do not prove post-exec label
retention on the admitted host or establish the cause of any earlier attachment.

The earlier all-rule candidate had a static ABI incompatibility: its implied
io_uring rule requires a feature absent from ABI4 and triggers the unchanged
fatal rule-not-enforced path. That candidate and its source-only gate remain
historical evidence, with no successful parser/native claim. This explicit
family selection is a separately reviewed correction, not equivalent all-rule
authority. An intermediate six-permission proposal incorrectly stated POSIX
delete was absent from ABI4; the supported seventh permission is explicitly
approved here. Keep all parser/ABI/cohort pins and fatal warnings unchanged.

## Boundaries and consequences

Keep legacy builder bytes, all current callers, `RunnerProfile`, exact
unconfined checks, parser 4.0.1 guards, immutable pins and receipts unchanged.
The pure builder introduces no policy-loading, runtime or cleanup authority and
does not change SDK admission by either BoxFerry or Containers.

A later consumer opt-in must bind immutable SDK source/hash records and sealed
invocation guards together with one exact enforce registry/task/receipt/unload
contract. Preserve existing identity, held-task, failure, budget and cleanup
boundaries. No alternate-mode acceptance, foreign-label acceptance, automatic
fallback, host attachment changes or new cleanup powers follow from this ADR.

Independent source review and complete serial producer/consumer gates remain
required. Fresh exact-source native behavior, label and cleanup evidence for
every affected existing matrix row remains mandatory. This change runs only
hermetic source controls and claims no native compatibility, release,
publication, deployment or new product capability.
