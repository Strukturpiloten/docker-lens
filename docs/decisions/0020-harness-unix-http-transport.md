# ADR 0020: Use an independent test-only Unix-HTTP transport

Status: accepted implementation contract; fresh native qualification pending.
Amends ADR 0004's harness transport only and explicitly supersedes the narrow
curl-only executable/argv preservation wording previously in verification docs.
ADRs 0001/0002's independent acquisition, protected values and evidence boundaries
remain unchanged.

DockerLens #119 and BoxFerry #366 replace host Engine Unix-HTTP curl consumers
with one DockerLens-owned standard-library Python helper. Engine behavior,
Docker CLI, real Rust acquisition and independent expected values are the
semantic oracles; curl itself is replaceable harness transport. The product
library must not acquire a dependency on this helper or on BoxFerry.

The [versioned transport contract](../native-unix-http.md) defines explicit
AF_UNIX-only contact, exact bytes, complete bounded HTTP framing, one absolute
deadline and closed value-free failures. Route ownership, mutation uncertainty,
overall request/byte/deadline budgets, process control and cleanup remain caller
responsibilities. Real HTTP status and transport failure are distinct; readiness
requires actual 200 and absence requires an actual complete 404.

All host Engine Unix-HTTP consumers migrate consistently. Independent CLI,
Compose, product acquisition, TCP/UDP and network-namespace curl probes remain
mandatory. Twenty-one exact native test invocations are retained. BoxFerry must
bind the reviewed helper revision and digest; frozen producer receipts require
new reviewed builds. There is no curl fallback or proxy/DNS/TCP/ambient endpoint,
auth/config, host-security, image, launcher or software-pin change.

Executable-specific AppArmor mediation differs between Python and curl. The
historical curl failure remains failed; this decision does not repair curl or
promise equivalent confinement. Historical source/evidence records and product
capability admission are immutable. Offline controls qualify transport behavior
only. Independent final-diff review, complete final-edit gates, fresh exact-head
four-lane native proof and required BoxFerry application gates remain required
before a compatibility claim or merge. No release or native retry is authorized
by this ADR.
