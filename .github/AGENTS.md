# Workflow guidance

The [root guidance](../AGENTS.md) remains authoritative. Bind workflow refs, manifest inputs, checkouts and presets to one reviewed immutable source;
follow [shared automation](../docs/shared-automation.md) and trusted admission rules.
Preserve complete gates and the user-selected fixed qualified images. ADR 0079 requires hosted outer Docker and local outer Podman. The current harness still uses
outer Podman on both; Docker #127/#128 and BoxFerry #469 track the hosted gap and qualification.
Preserve native admission, evidence and cleanup. Publication requires separate approval;
see [release guidance](../docs/releasing.md).
