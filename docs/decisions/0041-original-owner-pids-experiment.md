# ADR 0041: Original-owner PIDs27 source integration

Status: accepted for test-only source integration; native qualification pending.

## Context

ADRs0039/0040 established measured kernel custody and the fixed in-process
runtime locator/root protocol. A root acknowledgment alone cannot bind a
serialized outer snapshot, execute controlled effects or establish cleanup.
The original runtime owner must retain its actor, authority, accounting and
terminal deadline throughout the actual six-case experiment.

## Decision

Adopt the Linux-only Rust PIDs producer, fixed static guest controller and
independent private reader described in [the owner contract](../native-pids-owner.md).
Canonical invocation27 follows the unchanged first26 calls and kernel reader;
its own immediate reader always runs. Keep the existing nineteen-argument
emitter and publish only an unadmitted source outcome after independent rereading.
The separate prebuild never renews the live experiment's original deadline.

Actual selected-actor outer inspections bracket root acquisition and final
cleanup. A single exclusive socketpair and one SCM_RIGHTS directory bootstrap
bind the fixed privileged source. Parent API reservations precede reverse
acknowledgments; shared physical-source limits include externally preflighted
costs. Bounded copy I/O has actual operation receipts. Retain every required
effect/control/identity/headroom check and fail closed on uncertainty.

Case27 proves only its known inner cleanup and supervised source/controller
closure. It retains the outer fixture for later prepared nofile28. Original
lane EXIT cleanup and fresh aggregate remain required for outer teardown and
native admission. No product executor, public API change, PidsLimit capability,
catalogue entry or compatibility/release claim is authorized by this ADR.

## Consequences

The earlier ADRs' source authority and measured-window restrictions remain.
Only their statement that original-owner integration is absent is superseded;
historical first26 evidence remains immutable and does not qualify the new
candidate. Prepared nofile28 remains a later, separately reviewed integration.
Complete final-source validation and genuine four-lane27 native qualification
are mandatory before readiness can be claimed. Existing platform and Renovate
policies remain effective.
