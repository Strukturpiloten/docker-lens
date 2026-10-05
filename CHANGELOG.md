# Changelog

## Unreleased

- Keep Linux Unix-socket acquisition waiting on a full listener queue until
  its bounded deadline or caller cancellation, rather than misclassifying
  socket2 timeout polling's disconnected-socket hangup as terminal I/O failure.
  Retry with fresh nonblocking sockets and bounded backoff; restore blocking
  only after successful connection. Preserve other Unix transport behavior,
  terminal I/O failures, HTTP framing, privacy, budgets and the public API.
  Add independent saturated-queue, cancellation, refusal and delayed-drain
  HTTP controls; these are not Engine compatibility or peer-authentication claims.
- Admit only the reviewed #68 external-volume, external-network and internal
  bridge singleton groups on the four exact profiles, preserving historical
  evidence. Volume labels and other topology/runtime groups remain unadmitted;
  final-candidate native gates and consumer milestones remain separate.
- Define three bounded prerequisite groups for future raw native evidence after
  complete validated volume, volume-label and network proofs. This does not
  admit reviewed catalogue capabilities; fresh four-lane runs, independent
  review and the required consumer gates remain pending.
- Preserve observation-scoped `/info` memory and swap support reports as
  independently available typed fields. Pure assessment distinguishes reported
  unavailable, reported available but unverified, and unknown without granting
  target capabilities or proving resource enforcement.
- Define an independent native source assertion against the existing direct
  `/info` oracle and a closed non-admission evidence marker. This adds no request
  or capability; passing native runs and independent review remain required.
