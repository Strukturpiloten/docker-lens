# ADR 0014: Select the reviewed parameterized identity source cohort

Status: accepted candidate sequencing contract; final-candidate validation and
consumer rehearsal remain required before merge, main admission or release.

This explicitly refines ADR 0013's separate sealed-cohort sequencing. It does
not borrow ADR 0012's volume-only exception to establish identity evidence.
ADR 0013's syntax, privacy, parameter semantics and native proof obligations
remain unchanged. ADR 0012's six-authored-fixture volume-only consumer gate
remains effective because the selected cohort retains `VolumeLabels`.

The #89 candidate selects four crate-owned reviewed envelopes from source
candidate `032b1510524f391f08a795dab4da73f6fa8f7213`, native run
`37439627551`, attempt 1. All four Debian/upstream rootful/rootless source
lanes passed. Independently reviewed archive digests, exact manifests and
the complete version-2 ten-pair proof establish the two singleton
`ContainerUser` / `ContainerWorkdir` groups. The selected set is exactly
sixteen capabilities and twenty-six shapes: the #70 cohort's fourteen /
twenty-four plus those two groups. The original, #68 and #70 bytes and keys
stay immutable; only four active profile identities are selected.

This permits the real sealed planner/renderer to be exercised before merge.
It does not claim that source evidence validates a later candidate. The #89
candidate must not merge, enter main or be released until all of these pass
and receive independent review:

- Complete gates after the final edit, with source stability verified.
- Fresh four-lane native validation of the exact final candidate, not the
  source evidence SHA or trusted dispatcher's workflow SHA.
- Volume-only consumer mappings and rehearsals of all six actual authored
  Forgejo, Nextcloud, Paperless-ngx, Immich, Observability and Supabase
  fixtures, including protected labels, external prerequisites and explicit
  unsupported/loss decisions required by ADR 0012.

Identity support means parameterized native field semantics, not successful
startup for every image, account, directory or user namespace. Account lookup,
namespace representability, executable access and directory traversability
remain destination obligations. Supplementary groups, host UID/ownership,
loopback publication and other runtime/network groups are not admitted.

BoxFerry's positive identity and loopback assertions stay intact. Volume-only
consumer success is not full application acceptance; #39/#31/#343/#366 remain
separate unfinished work. No product executor, Lens dependency on BoxFerry,
release, publication or deployment authority is introduced. Historical
evidence remains outside Renovate's operational update streams; no dependency
or operational pin or manager extraction path changes in this selection.
