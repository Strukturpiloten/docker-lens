# Architecture decisions

Durable native boundaries and evidence/admission contracts:

ADR 0004 now maintains the narrowly scoped GitHub-runner upstream-rootless
userns profile prerequisite. Proven native completion and profile cleanup may
produce ordinary evidence; the former experiment's deliberate non-success
barrier is superseded while its historical evidence keeps its original status.

- [0001: Native boundaries](0001-native-boundaries.md)
- [0002: Capture and offline target profiles](0002-capture-and-offline-target-profiles.md)
- [0003: Inert standalone targets](0003-inert-standalone-targets.md)
- [0004: Maintained native Engine images](0004-maintained-native-engine-images.md)
- [0005: Standalone migration checkpoint](0005-standalone-migration-checkpoint.md)
- [0006: Typed standalone networks](0006-typed-standalone-networks.md)
- [0007: Typed standalone containers](0007-typed-standalone-containers.md)
- [0008: External volume prerequisites](0008-external-volume-prerequisites.md)
- [0009: Complete inert artifact](0009-complete-inert-artifact.md)
- [0010: Created volume labels](0010-created-volume-labels.md)
- [0011: Network membership observation](0011-network-membership-observation.md)
- [0012: Candidate volume-label admission](0012-candidate-volume-label-admission.md)
- [0013: Parameterized container identity](0013-parameterized-container-identity.md)
- [0014: Reviewed identity cohort](0014-reviewed-identity-cohort.md)
- [0015: Bind-relabel intent](0015-bind-relabel-intent.md)
- [0016: Reviewed application cohort](0016-reviewed-application-cohort.md)
- [0017: External-network internal expectation](0017-external-network-internal-expectation.md)
- [0018: Reviewed external-network cohort](0018-reviewed-external-network-cohort.md)
- [0019: Reviewed configured stop-signal cohort](0019-reviewed-stop-signal-cohort.md)
- [0020: Observation-scoped cgroup and PIDs reports](0020-observation-scoped-cgroup-reports.md)
- [0021: Unresolved rootless PIDs destination obligation](0021-rootless-pids-destination-obligation.md)

ADRs 0020/0021 recover inert observation and destination-prerequisite contracts.
They do not admit PIDs capabilities or authenticate delegation/enforcement.
Schema 4 is selected only for the new finite rootless obligation; legacy artifact
and request representations retain their existing bytes otherwise.

ADR 0019 selects only the complete StopSignal singleton beyond ADR 0018's
retained groups for candidate rehearsal. ADR 0017's None/false/true, conditional
schema-3 and pure snapshot boundaries remain; fresh final-candidate sixteen-test
native and actual consumer gates still block ready/merge/main admission and
release. Historical evidence and earlier obligations are preserved.
