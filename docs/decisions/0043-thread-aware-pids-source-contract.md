# ADR 0043: Prepare thread-aware PIDs source coverage

Status: accepted PREPARATION only. Positive collector wiring, proof v2,
complete physical budget fit and native qualification remain deferred.

## Context

ADRs 0039–0041 retain the measured PIDs source, original runtime owner, complete
effect attribution and fixed accounting. Threaded cgroup descendants cannot be
treated as ordinary local `cgroup.procs` sources. Aggregate thread-root process
coverage also does not establish a leader's local membership. A changed source
algorithm needs explicit custody, observation and proof boundaries before it
can replace an existing positive source guard.

## Decision

Adopt the [prepared thread-aware contract](../native-pids-threaded-contract.md)
and a small private pure topology helper with independent literal controls.
Parse only exact valid newline-terminated types. For a supplied connected tree
bounded by the existing 128 directories/depth 12, require configured outer512
to be domain or domain-threaded. Ordinary nodes contribute local procs, thread
roots aggregate procs, and threaded descendants inherit their unique enclosing
thread root without requesting procs. Retain the explicit non-root edge grammar;
no global-root exception belongs to this pure route.

The helper validates supplied shapes and necessary observed type transitions.
It performs no source I/O, authenticates no configured root, detects no omitted
kernel subtree and emits no accepted/verified evidence. All actual held-object,
complete-walk, process/namespace, leader/local-membership, worker-leaf and
enforcement duties remain with a separately reviewed future implementation.

Prepare the two-pass discovery lease, provisional local leader relation,
existing consumer acquisition, second-pass revalidation and explicit witness
transfer described in the contract. Stable aggregate leaders cannot substitute
for observed local membership. Phase-scoped type stability remains necessary;
permitted domain/domain-threaded changes require complete role revalidation.
Observation endpoints do not exclude transition/movement-and-return between
reads, and provisional records are not process lifetime authority.

## Prepared implementation boundary

The unwired lease prototype and focused controls implement this preparation's
candidate and descriptor-custody schedule. An initial real-I/O synthetic owner
transcript preserves the original loop and ceilings for one daemon task in a
mixed topology. Its fixed adapters are test-local; kernel and Engine facts and
the source clock remain simulated. The linked contract defines the precise
envelope and remaining multithreaded-daemon, typed worker/ancestor, proof-v2 and
production-integration obligations. No native or universal budget claim follows.

## Gates before positive integration

Require independent review of actual lease ownership/exception cleanup,
descriptor transfers, operation order and exact total ledger. Require a complete
authored real-I/O IPC transcript of both discoveries, multithreaded daemon
groups, all six worker phases, output and closure. Retain every existing source,
FD/open, API/capture, frame/proof and time/cleanup ceiling. No 512-leader or
128-directory successful physical fit is promised by a pure plan.

Future wiring requires explicit proof v2 with typed source attribution and
controller rows, independently checked by Rust and the private Python reader;
mixed versions refuse. Keep root framing and worker/controller protocols
separate. No current proof emission or acceptance changes in this preparation.

Before intentionally changing collector semantics, explicitly supersede only
inapplicable current-versus-historical diagnostic AST-equivalence requirements,
including locator/type-detail support controls, with independent semantic,
operation-order, accounting and diagnostic tests. Preserve historical fixtures,
hashes, frozen implementation equivalence and mutant negatives. Do not widen
normalization erasure, overwrite fixtures or silently remove assertions. This
ADR identifies that future migration gate; it supersedes no current positive
guard or test requirement.

## Consequences

Current collector behavior, proof v1, source vocabulary, rootless systemd and
PidsLimit guards, all 27 calls and historical evidence remain unchanged. No
capability, catalogue, native compatibility or nofile28 admission follows.
Complete final-source checks, independent review and fresh exact-candidate
four-lane native evidence with original whole-lane cleanup remain required.
There is no dependency, runtime pin, operational extraction-path or workflow
change; Renovate ownership, grouping and approvals remain unchanged.
