# ADR 0001: Separate native evidence, inventory, and target planning

Status: accepted; historical four-lane source evidence reviewed. Each changed
candidate and release requires fresh complete and native gates.

The library separates capture, observed inventory, desired target intent,
operation graph, and rendered artifact. Origin and availability are independent
facts. Container inspect `Name`, `Config.Labels`, `Config.User`,
`Config.WorkingDir`, and `Config.Hostname` are typed effective observations,
including their missing, null, empty, and redacted states. Label keys and
values remain protected; observed metadata does not claim authorship. Native
container inspect `Id` is a protected, runtime-assigned typed observation only
after request-versus-response validation; it is not an authored identity,
ownership proof, or reason to inspect another container. Socket selection uses
canonical IDs, while matching noncanonical strings in caller-assembled captures
remain accepted. Missing, unavailable, wrong-shape, or mismatched inspect IDs
fail closed without exposing source values or adding acquisition requests.
Native values, daemon identifiers, paths, and endpoints must not enter
Debug output or findings. A closed request vocabulary and explicit limits
prevent accidental arbitrary Engine calls. The target types have no executor.

The alternative of a generic HTTP request or JSON map would make read-only
enforcement, privacy review, and version boundaries harder to verify. The
explicit socket transport, decoder, planner, and renderer implement these
seams; native conformance must review their behavior against real Engine
versions and modes before release validation can succeed.
