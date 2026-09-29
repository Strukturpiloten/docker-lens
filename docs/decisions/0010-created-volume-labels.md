# ADR 0010: Keep created-volume labels protected and independently gated

Status: accepted target contract; native admission and consumer rehearsal remain open.

This extends ADR 0003's created named-volume target without changing its
unlabelled request bytes, inert-rendering boundary or reviewed-catalog rule.
`TargetResource::Volume` carries explicit `VolumeLabel` values. A label key is
nonempty UTF-8 without NUL and at most 128 bytes; a value is UTF-8 without NUL,
may be empty and is at most 4096 bytes. A created volume accepts at most 64
labels and 16 KiB total key-plus-value bytes, with duplicate keys rejected
before planning. Debug and errors do not reveal authored values.

Only nonempty created-volume labels render Docker Engine's `Labels` object.
They require the separate `VolumeLabels` capability and
`VolumeCreateLabels` native shape. Historical evidence for unlabelled
`NamedVolumeCreate` cannot admit that branch. `ExternalVolume` retains only
its caller-supplied identity and reference; as ADR 0008 requires, it emits a
prerequisite, never a create or relabel operation. This change does not add
volume drivers or options, data transfer, execution or a release boundary.

An independent exact-version rootful/rootless native probe and BoxFerry's six
authored fixture mappings and consumer rehearsal must be reviewed before a
positive production capability record is considered.
