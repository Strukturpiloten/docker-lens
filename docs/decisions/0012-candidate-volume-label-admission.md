# ADR 0012: Permit bounded candidate volume-label admission before consumer rehearsal

Status: accepted candidate sequencing contract; production merge/main/release
admission and consumer rehearsal remain blocked pending the gates below.

This explicitly supersedes only ADR 0010's final sequencing clause requiring
six authored fixture mappings and consumer rehearsal before considering a
positive production capability record. ADR 0010's bounded labels, protected
values, duplicate rejection, separate capability, label-free external volumes
and inert-rendering rules remain unchanged. ADRs 0003, 0008 and 0009 remain in
force. No new capability API, bypass or caller-authored positive claim is added.

The consumer must rehearse the real sealed planner/renderer path; a catalogue
that permanently withholds the label group cannot exercise that positive path.
Therefore the #49 candidate may select four crate-owned reviewed records from
the independently authenticated #70 native run `37214738475`, attempt 1, source
candidate `0d8268155a5aacddaeb501adf7f8b2fe06a718ca`, solely for pre-merge
volume-only consumer rehearsal. These records include the full
`VolumeLabels` / `VolumeCreateLabels` group for each exact Debian/upstream and
rootful/rootless identity. The fourteen capabilities/twenty-four shapes are
the original ten/twenty, the three #68 singleton groups, and that label group;
no other topology, resource, security or container-setting group is admitted.
Both earlier cohorts' native and reviewed bytes stay immutable.

This is candidate admission, not production clearance. The candidate must not
merge, enter main or be released until all of these have passed and been
independently reviewed:

- Complete final-candidate gates; any edit invalidates the prior result.
- Fresh four-lane native proof for the exact final candidate, not substitution
  of the historical #70 source SHA or a dispatcher workflow SHA.
- The six actual repository-owned authored fixture volume-only mappings and
  consumer rehearsals (Forgejo, Nextcloud, Paperless-ngx, Immich, Observability
  and Supabase), including protected labels, external prerequisites and
  structured unsupported/loss outcomes where required.

Historical source evidence and offline public tests cannot satisfy these
remaining gates. The primary owns exact-head admission and integration. Neither
DockerLens nor this decision executes output, contacts a destination, applies
labels to external volumes, copies data or establishes destination ownership.
A passing volume-only rehearsal is not acceptance of the six applications or
the full standalone migration; broader #31/#343/#366 work remains open. No
release, publication or deployment permission is granted.
