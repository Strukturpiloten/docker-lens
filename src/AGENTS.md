# Rust source guidance

The [root guidance](../AGENTS.md) remains authoritative. Keep DockerLens product libraries
independent of BoxFerry, and preserve the inert planning and rendering boundary described in
[architecture](../docs/architecture.md) and the [crate API](lib.rs). Native admission requires
reviewed evidence for the exact candidate; offline tests alone do not establish compatibility.
Preserve native evidence and cleanup requirements in [verification](../docs/verification.md).
Run the complete gate after final changes; release requires separate approval.
