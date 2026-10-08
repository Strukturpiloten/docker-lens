# Architecture decisions

Durable native boundaries and evidence/admission contracts:

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

ADR 0017 changes only the external expectation and conditional schema-3 contract;
its native admission remains pending; pure snapshot matching makes no native
compatibility claim. Historical evidence and
the earlier decisions' remaining obligations are preserved.
