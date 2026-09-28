# ADR 0008: Keep existing named volumes as explicit target prerequisites

Status: accepted target contract; native admission and consumer proof remain open.

This extends ADR 0003's created named-volume target shape without changing its
inert renderer or reviewed-catalog boundary. `TargetResource::Volume` still
declares a volume to create. `TargetResource::ExternalVolume` declares an exact
caller-supplied destination identity that must already exist. Both are named
volumes for `Mount::volume`, but the latter is a graph `RequireExisting(Volume)`
step and a protected `VolumePrerequisite`, never a `volumes/create` request.
The container mount uses that exact target identity and depends on the
prerequisite step. Duplicate created/external target names, undeclared mount
references, wrong dependency kinds, and a forged create action on an external
volume fail closed. The external branch has its own capability and closed
native shape; historical profiles do not admit it.

The new public `TargetResource` variant requires downstream exhaustive matches
to handle it explicitly; this pre-1.0 contract change does not claim a release.

An inspected source volume name or other native identity does not establish
the destination name, application authorship or ownership. The consumer must
choose the target identity explicitly, verify destination existence and data
availability independently, and reject a missing prerequisite. Neither this
target contract nor read-only inspection copies data, asserts a populated
volume, or applies output. DockerLens #44 remains open for exact rootful and
rootless Debian/upstream native proof and BoxFerry #343 consumer mapping.
