# ADR 0016: Select a coherent reviewed application source cohort

Status: accepted candidate sequencing contract; production merge, main admission
and release remain blocked until the final-candidate and consumer gates below pass.

This supersedes only ADR 0014's active-cohort selection and ADR 0015's
unadmitted-bind/root-schema-vocabulary sequencing. ADR 0012's six actual authored
fixture volume-only consumer gate remains a hard requirement. ADR 0015's source
review, protected values, request bytes and unverified SELinux obligations remain
unchanged. All four earlier raw and reviewed evidence cohorts stay immutable.

## Source and closed admission

The candidate selects four reviewed envelopes from independently authenticated
native run `37706460127`, attempt 1, whose executed source is
`6df951eb9e112becf8124fe9f8624b1df0dfbf2e`. Trusted dispatcher
`719aeedf58f81a578b27649a81a2f26065115374` is a separate workflow identity.
GitHub API archive/artifact/job identities, downloaded ZIP digests, fourteen
exact passing tests per lane and strict sanitized public projections received
independent review. Public receipt and digest bindings are recorded in
[application cohort provenance](../evidence/application-cohort-37706460127.json).
Manifest assertions alone do not authenticate a run. Review establishes trusted
harness execution and public projections, not direct inspection of private proof
files or SELinux effects.

Every lane retains the previous sixteen capabilities/twenty-six shapes and adds
only complete available groups:

- Four common port groups/six shapes: `PortHostIpv4`,
  `PortMultipleBindings`, `PortExposeOnly`, `PortEphemeral`.
- Three health/metadata groups/four shapes: `ContainerLabels`, `HealthShell`,
  `HealthStartPeriod`.
- Three network attachment groups/four shapes: `NetworkLabels`,
  `NetworkAliases`, `NetworkMultipleAttachment`.
- Two configured-retention bind groups/four shapes: `BindRelabelShared`,
  `BindRelabelPrivate`, each requiring both read-only and read-write evidence.

Debian is exactly 28 capabilities/44 shapes. Upstream adds only the complete
`PortHostIpv6` group/two shapes, for exactly 29/46. The prescribed Debian
negative withholds the entire IPv6 port group; it is not a universal statement
about Docker IPv6. Earlier twenty-two network markers, /info reports and health
controls do not admit IPAM/options/static addresses/network IPv6, resource,
device, init, disabled health or start-interval groups.

The compiled catalogue, raw/reviewed digest bindings and `required_for` checks
enforce these exact per-lane sets and complete groups. Schema/parser recognition
alone and caller-manufactured positive facts never grant planning authority.
No public API, request renderer, schema-1 representation or dependency changes
are needed.

## Conditional bind meaning and remaining gates

Configured retention keeps case-sensitive `z`/`Z` and read-only access. Schema-2
bind prerequisites must retain container identity, original mount index, source,
target, access/relabel, all five source conditions and all four SELinux conditions.
Every condition remains a requirement to review, not an observed satisfied fact.
Unknown conditions stay conditional; known unsatisfied conditions must be refused.
No DockerLens host inspection, source creation, execution, relabeling or daemon
contact is introduced. Ordinary request and schema-1 bytes remain unchanged
apart from the explicitly selected context/evidence key.

This is pre-merge candidate admission for sealed consumer rehearsal. Before
production merge, main admission or release, the primary must obtain and
independently review all of:

- Complete gates after the final edit and a stable final candidate.
- Fresh four-lane native proof of all fourteen exact tests on that final candidate.
  This source run cannot qualify a changed admission candidate.
- Volume-only mappings and isolated consumer rehearsals for all six actual
  authored Forgejo, Nextcloud, Paperless-ngx, Immich, Observability and Supabase
  fixtures, including protected labels, external prerequisites and explicit loss.
- Reviewed BoxFerry schema-2 consumption of the actual authored Nextcloud and
  Supabase bind scenarios, preserving association, source and SELinux obligations,
  privacy and explicit conditional/loss outcomes.

Admission does not complete #31, BoxFerry #343/#366, arbitrary-image startup,
host UID mapping or full application migration. Lens products remain independent
of BoxFerry. No library release, publication, deployment or host change is authorized.

## Provenance and maintenance

The native oracle versions and existing license provenance remain the exact
Debian docker.io 20.10.5+dfsg1-1+deb11u2 (Engine 20.10.5+dfsg1) and upstream
29.8.1 profiles. The command is the canonical
`./scripts/native-conformance.sh <lane>` in the authenticated source run.
The implementation is authored from scratch; no oracle source or binaries are
copied or mechanically translated. Only sanitized public metadata is stored;
private proofs/log bodies, resource IDs, daemon UIDs and credentials are not
redistributed. Existing Apache-2.0 Moby/Debian source references remain documented
by ADR 0015; this repository's evidence metadata follows its MPL-2.0 license.

No software pin, workflow, extraction path or dependency changes. Readback of
`renovate.json` confirms unique existing Cargo/GitHub Actions ownership and the
toolchain plus five-image regex managers. Their grouping and manual approval
rules stay effective; historical evidence is outside operational update streams.
