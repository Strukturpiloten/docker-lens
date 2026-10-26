# ADR 0042: Finite sudo ancestor UID shape

Status: accepted test-only source credential correction; native qualification
pending. Supplements ADRs 0040/0041 without changing their protocol, authority,
budget or capability boundaries.

## Context

The root source walks a bounded, held parent chain from its fixed supervisor to
the authenticated socket peer. Its ancestor predicate previously required every
UID field to equal root or every field to equal the peer. Linux reports these
fields in real, effective, saved-set, filesystem order. A set-user-ID-root sudo
parent can legitimately retain the invoking real UID with the other three root.
The previous predicate therefore excludes a documented sudo credential shape.

Run `40414194534`, candidate `354a50c3fd6cccf526d2d87ca2c9504412c88a48`,
passed the preceding 26 calls in four lanes, then reported `pids-read`,
`ready/reset`, and `w_anc_uid`/`guard`. This identifies the failed predicate;
it does not reveal the vector, ancestor role or hosted sudo version. The
correction below is justified independently and is not a claim about that
unobserved tuple or a passing PIDs27 result.

## Decision

Preserve the existing ancestor UID alternatives and their short-circuit order.
Add only real UID equal to a **positive** authenticated peer UID, effective UID0,
saved-set UID0 and filesystem UID0, and only for a non-supervisor ancestor.

Passing this predicate is provisional. Every non-supervisor link still needs
the existing held executable device/inode comparison to fixed `/usr/bin/sudo`,
valid PPid traversal and all held process/start/full-UID/root/cgroup/namespace/
time/liveness and final PPid rechecks. Keep the original eight-link bound.
The original socket peer remains subject to its four-equal-to-peer check; the
supervisor's uniform forms and prior root-effective-UID requirement are unchanged.
A root peer gains no new alternative: its existing all-root case is unchanged.
No arbitrary root/peer mixture, foreign UID, saved/filesystem exception or
`SUDO_UID`/environment identity fallback is allowed.

| Role, with positive peer UID P | Locally eligible UID forms | Additional required acceptance checks |
| --- | --- | --- |
| Authenticated original peer | P/P/P/P only | Existing peer/process/namespace checks |
| Fixed supervisor | Existing uniform root or peer forms | Existing launch and held-process checks |
| Other ancestor | Existing uniform forms; additionally P/0/0/0 | Fixed sudo inode, complete parent chain and original final rechecks |

Do not hoist an executable open or another source read before the UID predicate.
No new source operation, syscall, FD, reservation, deadline, poll, wait, retry,
privilege, runtime request, diagnostic vocabulary or protocol field is needed.
Previously accepted and still-rejected paths retain their original source call
order/counts. A newly eligible vector can now reach the original PPid/executable/
recheck operations that the old predicate refused before; its actual budget fit
still requires complete native qualification under unchanged limits.

## Reference basis and trust limits

Linux [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
defines the UID field order.
[execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) preserves real UID,
applies an effective UID change when the set-user-ID transition takes effect,
and copies the resulting effective UID to saved-set UID.
[credentials(7)](https://man7.org/linux/man-pages/man7/credentials.7.html)
describes filesystem UID following effective UID changes. These semantics permit
the exact additional shape; they do not require every sudo invocation to use it.

Official sudo tag `SUDO_1_9_15p5` is a historical implementation reference:
[`set_perms.c`](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/set_perms.c)
preserves/restores initial real/effective/saved credentials;
[`sudoers.c`](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/sudoers.c#L803)
rewinds policy permissions, while
[`exec_nopty.c`](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/src/exec_nopty.c#L562)
performs command setup in the forked child. The reference tag is **not** an
assertion of the installed hosted version, build/plugin configuration or observed
ancestor's state. Source headers identify ISC licensing. References were read
only; no sudo/oracle command ran, no upstream implementation was copied or
mechanically translated, and no upstream source is redistributed here.

The tuple alone proves neither sudo identity nor privilege provenance. This
correction retains the trusted original harness/host-root/bootstrap model.
The existing executable comparison is a one-time held inode witness: final
`check_process` does not reopen `exe`. Same-PID, same-credential exec can remain
unseen, and repeated process snapshots are not atomic. An additional executable
recheck or stronger hostile-root guarantee needs a separately reviewed I/O and
threat-model change; neither is part of this decision.

## Consequences and validation

Independent inert controls exercise the full guard with authored process facts:
legacy and exact new UID forms, original-peer/supervisor rejection, the complete
root/peer/foreign UID product, fixed executable device/inode mismatch, missing
sudo, invalid PPid, bounded chains and held process/UID/root/cgroup/namespace/
time/liveness drift. They also compare source call order/counts and preserve
original exception propagation. They do not execute sudo or prove host behavior.

The actual failed UID vector and role remain unknown. A fresh failure must not
trigger arbitrary widening by guess. A closed relative-UID observation could be
separately reviewed if needed; no such observation is added here. Complete
final-source gates, independent review and fresh exact-source four-lane native
execution are still required. No PIDs capability, compatibility, cleanup or
release admission follows from this correction alone.

No dependency or operational tool/image/action pin is added or changed. The
versioned source links are historical reference provenance, not runtime selectors;
Renovate ownership/extraction/grouping therefore require no change. Existing
source budgets, pins, capability evidence and all other consumers stay unchanged.
