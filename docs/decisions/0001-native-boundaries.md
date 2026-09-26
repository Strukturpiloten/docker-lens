# ADR 0001: Separate native evidence, inventory, and target planning

Status: accepted; independent native conformance remains pending.

The library separates capture, observed inventory, desired target intent,
operation graph, and rendered artifact. Origin and availability are independent
facts. Native values, daemon identifiers, paths, and endpoints must not enter
Debug output or findings. A closed request vocabulary and explicit limits
prevent accidental arbitrary Engine calls. The target types have no executor.

The alternative of a generic HTTP request or JSON map would make read-only
enforcement, privacy review, and version boundaries harder to verify. The
explicit socket transport, decoder, planner, and renderer implement these
seams; native conformance must review their behavior against real Engine
versions and modes before release validation can succeed.
