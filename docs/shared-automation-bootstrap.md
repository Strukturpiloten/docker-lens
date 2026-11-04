# Trusted automation seed

The already merged ADR 0020 policy is unchanged. This seed adds the immutable
interface-1 manifest and default-branch metadata service before selective CI
adoption. Check, local validation, native dispatch and release validation keep
all existing gates. Candidate code receives no service write token.

The pins use the reviewed, merged [BoxFerry foundation](https://github.com/Strukturpiloten/boxferry/pull/561).
The source has no published release tag and uses the reviewed immutable
infrastructure-pin exception with honest automation-v1 provenance. No tag,
release or deployment is authorized.

Bootstrap Renovate owns and groups the manifest/input pins and native shared
workflow refs. Shared source upgrades are held during this seed stage until the
final #174 change adopts common/Rust presets and enables automatic updates
together with exact-candidate eligibility and the fail-closed aggregate. The
exact five qualified native fixture tuples remain fixed; #127 owns separately
qualified replacements.

Merge this seed through the normal complete gate first. Then rebase #174 so its
PR and queue base contain the trusted manifest, service and ADR 0020 policy.
Do not fall back to candidate admission policy when the trusted seed is missing.
Docker #127 / held PR #128 and BoxFerry #469 separately own the still-pending
hosted outer-Docker rollout. This seed does not change or qualify native backends.
