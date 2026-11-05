# Shared development automation

DockerLens owns its product tests, native admission, four exact native lanes,
privacy, budgets and cleanup. BoxFerry owns common development mechanics only.
The Cargo product graph does not acquire a BoxFerry dependency.

The immutable source is selected once in `.github/automation.json`. Reusable
workflow refs, their explicit source inputs, source checkouts and common/Rust
Renovate preset refs must select that same commit. `scripts/validation-plan.py`
is the byte-identical interface-1 frontloader; ordinary argument forwarding and
uv/project setup belong to the selected shared implementation.

## Trusted adoption

The ADR 0020 policy and ADR 0021 manifest and metadata service precede selective
adoption. Candidate admission reads the trusted base manifest and its immutable
reader. Missing base evidence fails closed, with no candidate fallback. The
source uses the reviewed, merged
[BoxFerry foundation](https://github.com/Strukturpiloten/boxferry/pull/561)
under the untagged infrastructure exception; no release or tag is created.

## Local and hosted checks

Use `./scripts/check-all.sh --check` for complete local validation. It retains
Rust formatting/Clippy, declared MSRV failure propagation, all target and
doctest suites, Rustdoc and the complete Python policy suite. The shared source
supplies locked Python, Ruff, ty, native Renovate/RE2, downloaded file tools,
dependency policy and purpose-specific API checks. Setup resolves tool versions
from that source, not a second consumer pin list. The complete gate invokes the
canonical `api-development` leaf through the selected locked project. The shared
helper owns trusted Git comparison, actual Cargo dispatch and compiler
verification; Cargo home/target settings remain inherited. The manifest selects
an admitted immutable source, aligned with workflow and Renovate preset pins.
Complete local and exact-candidate hosted validation of this adoption remain
pending. A first run may need development-tool downloads.

### Node before tool setup

The hosted documentation job and the candidate jobs in reviewed native and release
validation use one local setup composite before provisioning tools. It reads the
exact CI Node declaration from the manifest-selected producer, installs that version
with a separately pinned setup-node Action, and verifies the actual executable.
The Action pin has its own ordinary 72-hour Renovate rule; it does not have to match
the producer's setup-node Action pin.

Local setup accepts only the exact CI or Dev Container Node versions from that same
immutable source. These two reviewed contexts currently differ; a semver-compatible
ambient version is not an extra fallback. Query the hosted requirement without Node:

```console
python3 scripts/validation-plan.py run --task node-toolchain
```

The stable frontloader acquires and verifies the shared Python project first, so
native and release runners need no pre-existing shared checkout or Node. Selection
hands only a validated numeric version to setup-node. Actual setup repeats preflight
before downloading tools, extracting Renovate or installing Cargo tools, and binds
the verified absolute Node to Renovate's mandatory native RE2 check. Missing or
incompatible Node stops setup with a prerequisite message; use the reviewed shared
Dev Container or provide a source-selected local Node installation and rerun.

The helper reads fixed regular CI and Dockerfile Git blobs after identity, type,
mode and size checks. Producer CI layout is an explicitly tested coupling, not a
new version inventory or public metadata API. Missing or ambiguous metadata fails
without falling back to current main, unverified files or arbitrary Node versions.
A source upgrade must review this coupling and the existing two contexts together.
A failed child still has an unknown cause when its bounded stderr was discarded;
setup reports its stage and verified prerequisites without inventing a reason.

For development feedback, use
`python3 scripts/validation-plan.py plan --event local` or `run-local`. Prose
runs repository policy checks. Changes confined to Rust tests select Rust,
repository policy and dependency eligibility; mixed known changes select their
union. Unknown, source, policy, decision and evidence changes select all checks.
Focused feedback never replaces the complete gate.

Check binds every PR/queue comparison to its independently checked-out base and
actual tested merge revision. Main is complete. Its one Required CI aggregate
rejects missing/failed/cancelled jobs and unexpected skips. PR/queue native
skips are intentional and claim no native compatibility. Main requires the
unchanged four-lane native result. The existing main-only hosted prerequisite
diagnostic and reviewed exact-PR native dispatcher retain their separate
authority.

The default-branch metadata service never executes candidate code. Ordinary
updates retain 72-hour eligibility and compatibility/integrity gates. Exact
first-party source updates retain the narrow trusted exception. Renovate groups
all source adoption pins and uses its merge-queue API with platform automerge
waiting disabled; repository `allow_auto_merge` is not a prerequisite for that
queue path. Native fixture qualification remains a separate product boundary.

## Native and release limitations

The current harness still requires outer Podman on local and hosted callers.
DockerLens #127 / held PR #128 and BoxFerry #469 own the required hosted Docker
backend rollout and fresh qualification. The Renovate test-container extractor
separately selects Docker on GitHub and Podman locally; this proves no native
Engine behavior.

Release validation explicitly selects published API against the canonical
registry baseline and actual chosen manifest version. Its final required guard
checks the distinct `published_api_candidate_sha` against the exact candidate;
the generic shared release gate still checks ordinary candidate outputs. The
publication policy remains disabled, and DockerLens's published `0.1.0` is not
an initial release exception. See
[ADR 0023](decisions/0023-development-and-published-api-checks.md) and
[release guidance](releasing.md).

## Fixed qualified native fixtures

During this overhaul, routine Renovate updates are disabled only for the five
qualified tag/digest tuples in `scripts/native-conformance.sh`: the GHCR
`docker-29-rootful`, `docker-29-rootless`, `docker-debian-11-rootful` and
`docker-debian-11-rootless` images under `strukturpiloten`, plus
`docker.io/library/busybox`. This follows the same temporary qualified-fixture
choice as the workspace's FCOS/Podman targets. Docker #127 owns separately
reviewed replacements and fresh native qualification. No manual-review-only
Renovate PR stream is retained. Ordinary Rust dependencies, development tools,
shared sources, nearby image names and other paths remain automatic under the
shared integrity, age and compatibility rules.

## Admitted API source and pending consumer validation

The manifest, reusable workflow, checkout/input and preset refs select the same
admitted BoxFerry API producer. Its canonical helper supports the explicit API
purpose and local task contract. DockerLens adoption still requires independent
review, both complete gates and required hosted checks; focused schema and
frontloader checks do not establish readiness. Check's manual dispatch remains
diagnostic-only; release validation always requires published evidence. Existing
published incompatibilities remain release failures.
