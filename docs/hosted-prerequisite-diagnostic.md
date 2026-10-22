# Hosted prerequisite diagnostic

DockerLens #129 adds a read-only bootstrap to the existing Check workflow. It
does not import the unmerged runtime integration, run the native cohort, activate
a Docker backend, install packages, change services/policy, or qualify a runtime.
Main's nineteen native tests in each of four lanes remain unchanged. No package
release, publication or deployment is part of this diagnostic.

## Dispatch and evidence binding

Only `workflow_dispatch` on `refs/heads/main` runs the diagnostic job. There are
no candidate, command, path or other inputs. The existing pinned checkout Action
checks out `github.sha`, not a movable ref, without persisted credentials. The
collector accepts no arguments and checks repository, workflow ref/SHA, event,
main ref, job, run/attempt, hosted Linux/X64 runner and Ubuntu image metadata.
Its actual `git rev-parse HEAD` must equal the dispatch and workflow SHA. It reads
the fixed `/usr/lib/os-release` data rather than executing a shell or following
Ubuntu's standard `/etc/os-release` symlink. Environment labels and installed
hashes are observations, not authenticated publisher integrity or OS attestation.

Normal PR and main-push validation keep their complete offline/native gates and
fail-closed aggregate. Only main's diagnostic event excludes scaffold and
aggregate. Every diagnostic dispatch excludes scaffold, so another ref cannot run
candidate validation or select this diagnostic; it retains an unexpected-event
aggregate failure. The native/release dispatchers are unchanged.
The aggregate job ID remains `check-gate`, with the existing dependencies. Its
display name is `Required CI`: the maintainer's live rules read for #129 from
`GET repos/Strukturpiloten/docker-lens/rules/branches/main` identified that exact
required context and strict up-to-date policy. No protection setting, bypass or
extra token permission is changed. A diagnostic is not a PR validation substitute.

## Finite read-only collection

The four fixed command vectors are bounded `git rev-parse HEAD`, `dpkg-query
--show`, `dpkg-query --search`, and `systemctl --no-pager --no-ask-password show`.
Only ten explicit package names, seven startup/query helpers, and
`docker.service`, `docker.socket`, `containerd.service` are queried. There is no
Docker/Podman command or socket query, sudo, journal, helper/script execution,
start/stop/restart/reload, package installation or arbitrary caller path. Child
commands inherit only a fixed PATH and C locale, never credentials or daemon
selectors. `systemctl show` reads systemd metadata, not Docker daemon state.

The fixed source inventory hashes helpers, relevant installed pre/post-install
and removal scripts, trigger/conffile declarations, vendor unit files and package
copyright records as data. Plain and `:amd64` dpkg control paths are separately
allowlisted; there is no glob/discovery-based control-file selection. Only the
reviewed `/lib/systemd/system` versus `/usr/lib/systemd/system` and two helper
package-owner aliases are normalized. Reported systemd paths are classified,
never opened. Fixed `/etc` and `/run` unit override/mask paths and three fixed
drop-in directories report presence/count only, without filenames or contents.
Symlinks are never followed; a fixed override symlink to `/dev/null` is a mask
observation, not permission to change it. Unknown links stay explicit/partial.

Every source read walks fixed components using held no-follow directory/file
descriptors, requires root ownership and no group/other write permission, and
rechecks identities/metadata after reading. Regular files must have one link.
Input replacement, untrusted ownership, malformed data, missing records and
unknown fields cannot become a trusted profile. Only SHA-256, bounded numeric
metadata and closed status fields escape; raw helper/control/override source,
command stdout/stderr, environment and credentials are never uploaded.

Package status/version/architecture and package-database ownership are reported
metadata only. The manifest always says `admission: unadmitted` and
`provenance: unverified_installed_observation`. Missing/unavailable records and
partial diagnostics remain explicit. `observed` means the finite diagnostic
completed, not native compatibility, an installed binary's publisher identity,
safe maintainer-script behavior, or a complete dpkg trigger execution set. The
latter is always `not_established`; no recursive whole-OS attestation is attempted.

The manifest retains package names/versions, fixed Ubuntu/Docker/helper source
references, and installed copyright hashes for independent version/source/license
comparison. It does not redistribute third-party source or infer a license from
a hash. Hash equality alone does not authenticate packages, helpers or history.

## Schema 2: closed failure context

Schema 2 preserves the observation/status/reason and unadmitted semantics, adding
only optional validated `failure_detail` on existing unavailable records. Schema
1's historical main run `39805004506` and its artifact remain unchanged. Its
package `invalid_metadata` and copyright `custody_failure` outcomes do not reveal
their cause; this change neither guesses that cause nor loosens validation.

Package failure detail has exactly `field`, `category` and `row`. Fields are
`encoding`, `framing`, `columns`, `package`, `status`, `version`, `architecture`.
Categories are `empty`, `invalid_syntax`, `unrecognized`, `duplicate`,
`invalid_count`, `invalid_encoding`, `oversize`, `missing_terminator`. Row 0 means
a failure before row parsing; 1–10 identify a bounded row and 11 is the capped
first-outside-ten marker. The same predicates run in the same order, rejecting
the whole package parse at its first failure; no valid rows are salvaged. Empty
payload behavior and successful package representations are unchanged. Rejected
package names, statuses, versions, architectures and raw rows are never echoed.

Fixed-source custody failure detail has exactly `guard`, `component`, `category`.
Guards are `open`, `metadata`, `owner`, `mode`, `kind`, `links`, `stability`,
`close`. Components are `root`, `ancestor_1` through `ancestor_4`, or `leaf`,
relative to the existing fixed source inventory; the record's existing key
identifies that source. Categories are `check_failed`, `symlink_refused`,
`not_directory`, `permission_denied`, `io_error`, `other_io`. These identify an
existing guard or syscall category, not new paths or permission to traverse a
refused link. No dynamic component/path text, owner value, exception message or
source bytes are added. Constructor validation refuses unknown fields, values,
types and out-of-bound ordinals, and returns copies of immutable detail data.

Schema 2 emitted manifest version 2, including cancellation/unavailable envelopes.
Successful observations differed only in that explicit version. Existing commands,
source paths, predicate order, deadlines, byte caps, private cleanup and cancellation
remain unchanged, as do the main-only dispatch, Action pins and Renovate ownership.
Fake controls establish only localization/privacy; a fresh independently reviewed
main diagnostic is still needed to learn the actual missing prerequisite facts.

## Schema 3: validated dpkg status context

The emitted manifest version is now 3, including cancellation/unavailable
envelopes. Package `failure_detail` may additionally contain
`validated_dpkg_state`, and only for a later `version` or `architecture` failure
on a positive row ordinal. The parser derives this value from the third token
only after the existing full dpkg Status grammar has passed, without stripping,
normalization or a new acceptance rule. Its exact closed values are
`not-installed`, `config-files`, `half-installed`, `unpacked`, `half-configured`,
`triggers-awaited`, `triggers-pending`, `installed`. Earlier/at-status failures
omit this context: the status is then not established, not an inferred class.
The constructor refuses other values, types, fields, reasons or row-zero context.

This is solely a reported package-database declaration, not actual package
presence/absence, binary ownership, safe installation or native qualification.
The whole package parse still becomes unavailable at its first failure, with no
row salvage or name/raw Status/version/architecture exposure. Successful fields,
source custody and mode guards, helper-owner timeout handling, commands, paths,
predicate order, caps, deadlines and cleanup remain unchanged. Successful
observations differ only in the manifest version; admission remains unadmitted.

Historical schema-1 and schema-2 artifacts remain unchanged. Schema-2 main run
`39813217449` localized empty version at row 2 but did not establish that row's
package name, full Status or architecture. Its copyright ancestor-2 mode refusals
remain refusals; its helper-owner timeout cannot inherit older owner reports.
A fresh schema-3 diagnostic and independent review are required for new facts;
the missing status context must not be inferred from the historical empty value.

## Limits, containment and cleanup

The collector reuses the reviewed runtime sampler's incremental duplex capture,
private-output ownership and cooperative TERM/INT cancellation. Its job has a
five-minute limit; collection has one 45-second absolute deadline and an outer
55-second watchdog with a two-second kill fallback. Each fixed child has a
two-second timeout plus one-second kill fallback, under a maximum four-second
capture cutoff within that original deadline. No allowance or retry is renewed.
The final staged stdout read must match the already-counted captured byte length;
an incomplete read is a collection failure, never evidence of absent packages.

Two private mode-0600 raw capture files in a mode-0700 owned directory are reused;
each stream retains at most 64 KiB. Each source file is at most 2 MiB, all read
bytes together are at most 8 MiB, each fixed drop-in directory has at most sixteen
entries, and the serialized manifest is at most 64 KiB. Raw files are removed by
held identity, not recursively; changed/replaced files are preserved and cleanup
is failed. Cancellation removes raw files before the bounded child wait. Unknown
completion and cleanup failure never become a successful collection. SIGKILL,
runner loss or an uninterruptible kernel read can prevent cleanup; no claim of
verified host-wide or privileged-child termination is made.

The workflow writes only the sanitized JSON to its fixed runner-temp filename,
with private umask and no-clobber output, then uploads that exact file using the
existing pinned upload Action with seven-day retention. Cancellation/nonzero
collector completion does not upload a possibly partial output. A green job or
uploaded partial diagnostic never changes package policy or grants admission.
After merge, a maintainer must run the main-only diagnostic and independently
review its exact artifact/run/SHA before changing prerequisite policy.

## Consumers and Renovate

Only DockerLens Check consumes this collector. Its native harness, reviewed
native dispatcher and release validator do not; the other workspace products
gain no dependency or workflow change. Both added Action occurrences reuse the
existing exact checkout v4.2.2 and upload-artifact v4.6.2 SHAs, uniquely owned by
Renovate's GitHub Actions manager. The existing Cargo/toolchain owners, two regex
managers, and five native-image extractions/grouping/manual approvals are
unchanged. No new or moved package/image/toolchain pin, download or manager is
introduced; policy tests check these extraction and ownership facts. Installed
Python/core utilities, dpkg and systemd follow the existing mutable Ubuntu 24.04
runner unavailable-integrity/manual-review boundary, not invented checksums.
Historical native evidence stays immutable. Focused fake controls establish only
source behavior; independent review and final complete gates remain required.
