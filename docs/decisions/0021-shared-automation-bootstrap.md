# ADR 0021: Seed the trusted shared automation reader

Status: accepted for staged adoption

## Decision

Build on ADR 0020's already merged validation policy. Seed the interface-1
manifest and default-branch eligibility service before selective callers, so
candidate changes cannot supply their own admission authority. Existing offline,
native, reviewed-dispatch and release gates remain complete and unchanged.

The initial internal source has no published release tag. Permit its reviewed,
completely validated merged commit by full SHA with honest automation-v1
interface-v1 provenance, following the shared infrastructure exception. This
authorizes no tag, release, package/image publication or deployment. The
materialized pins reference the reviewed [BoxFerry foundation](https://github.com/Strukturpiloten/boxferry/pull/561).

Bootstrap Renovate owns and groups the new manifest/input/reusable refs. Shared
source upgrades remain held until #174 installs the exact-candidate age reader
and common automatic policy together. Keep the exact five qualified
native fixture tuples fixed; #127 owns separately qualified replacements.

See [shared development automation](../shared-automation.md). Missing trusted base
policy never authorizes candidate fallback.
