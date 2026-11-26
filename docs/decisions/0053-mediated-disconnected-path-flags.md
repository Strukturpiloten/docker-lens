# ADR 0053: Fixed path flags for the mediated prerequisite

Status: accepted bounded source-candidate contract; parser/kernel interpretation
and fresh native qualification remain on hold. Supersedes only ADR 0051's
flag-free `mediated_profile_bytes` declaration. Preserve earlier decisions and
evidence at their original scope.

## Forward-port provenance

This decision carries the approved PR 162 / issue 158 contract from immutable
DockerLens commit `d7f18d756fe754adea3c57e6c0cba2a906e2a780`, where it was
numbered ADR 0052. It uses local ADR 0053 because ADR 0052 here already records
controlled PIDs CREATE observations. That decision and the original component's
evidence remain unchanged; this forward-port grants no new qualification.

## Decision

Emit exactly `flags=(attach_disconnected,mediate_deleted)` on that builder's
ordinary enforce declaration. Preserve its sole name argument, strict grammar,
ABI4 and exact thirteen-rule vector, including all seven POSIX queue permissions
and type=posix. No selectable flags, mode, policy fragment, new class permission,
attachment expression, transition, alternate label or fallback is added.

The [source contract](../ordinary-mediated-profile-contract.md) records the
conditional RootlessKit/Go/upstream-Linux self-exec explanation, the reviewed
mask/naming distinction and source provenance. AppArmor's existing bare file rule
already includes inherit-exec; adding ix would not address an earlier pathname
lookup refusal. Namespace-disconnected lookup is a strong conditional explanation,
not a proved native syscall, profile or Ubuntu Azure kernel attribution.

## Examined guard and risk

The pinned parser omits a zero path-flags field; examined upstream v7.0 defaults
that missing field to `0x20000`. Selecting attach_disconnected alone serializes
`0x00004` and changes the examined unlinked-positive-dentry guard to ENOENT.
The chosen pair serializes `0x10004` and preserves that guard's continuation.
Parser mediate_deleted is `0x10000`; the examined kernel names that bit
PATH_DELEGATE_DELETED and names `0x20000` PATH_MEDIATE_DELETED. The guard accepts
either deleted bit. This is one examined behavioral preservation, not bit identity
or global equivalence. Prior absence of the textual parser flag did not establish
absence of deleted-path mediation.

Path connection expands reachability and can cause pathname aliasing. The current
all-file/ix permission vector does not erase that change or prove sandbox safety.
Keep this one fixed permissive test prerequisite and its exact ownership boundary.

## Delivery and unchanged boundaries

Legacy `profile_bytes`, every active `RunnerProfile` path/caller, exact unconfined
guards and parser 4.0.1 behavior remain byte-identical. No SDK/consumer pin,
software version, warning, ABI, cohort, timer, size bound or cleanup power changes.
The maximum fixed policies are 422/420 bytes, below the unchanged 1024-byte bound.

Independent source review and both complete serial producer gates precede an
immutable reviewed commit. Consumers then opt in coherently to real source
commit/file hashes and their fixed enforce contract. Actual parser/kernel flags,
connected/deleted/disconnected execution boundaries, postexec held-task labels,
original affected ordinary/systemd workloads and complete private cleanup still
require fresh trusted evidence. No compile, one-row success, lost error message,
old receipt or source gate qualifies that matrix. Failure remains closed without
fallback or new cleanup authority. This decision adds no native experiment,
release, image publication, deployment or product capability claim.
