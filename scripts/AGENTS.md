# Script guidance

The [root guidance](../AGENTS.md) remains authoritative. For Python, use pinned shared `uv`, Ruff and ty through
`scripts/validation-plan.py`; avoid local version inventories. Preserve the Bash native harness, its fixed qualified images, admission,
evidence and cleanup. ADR 0079 requires hosted outer Docker and local outer Podman; the current harness still uses
outer Podman on both. Docker #127/#128 and BoxFerry #469 track the hosted gap and qualification. Focused checks do not replace the complete gate. See
[shared automation](../docs/shared-automation.md) and [verification](../docs/verification.md).
