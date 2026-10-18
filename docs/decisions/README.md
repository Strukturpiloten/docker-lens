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
- [0018: Reviewed external-network cohort](0018-reviewed-external-network-cohort.md)
- [0019: Reviewed configured stop-signal cohort](0019-reviewed-stop-signal-cohort.md)
- [0020: Independent harness Unix-HTTP transport](0020-harness-unix-http-transport.md)
- [0021: Complete lifecycle raw source projection](0021-lifecycle-raw-source-projection.md)
- [0022: Reviewed lifecycle successor cohort](0022-reviewed-lifecycle-cohort.md)
- [0023: Mandatory process-source probes and closed raw projection](0023-process-source-proof-wiring.md)
- [0024: Raw-only disabled-health source projection](0024-health-disabled-raw-source-projection.md)
- [0025: Mandatory ShmSize source integration](0025-shm-size-source-integration.md)
- [0026: Mandatory runtime-settings source integration](0026-runtime-settings-source-integration.md)

ADR 0022 supersedes ADR 0019's active-cohort selection for candidate rehearsal:
complete StopTimeout/init/rootfs/tmpfs groups on all lanes, with
HealthStartInterval upstream-only, at Debian 34/56 and upstream 36/60.
ADR 0021's raw source markers remain unchanged and do not grant admission.
ADR 0017's None/false/true, conditional
schema-3 and pure snapshot boundaries remain; fresh final-candidate twenty-six-test
native and actual consumer gates still block ready/merge/main admission and
release. Historical evidence and earlier obligations are preserved.
ADR 0023 adds mandatory hostname and command-clear invocations 22 and 23, with
both strict readers required before closed source-only raw projection. Its
slice's raw totals were Debian 37/59 and upstream 39/63; the three process singleton
groups remain outside ADR 0022's unchanged compiled selection.
ADR 0024 additionally derives only HealthDisabled/DisabledHealthcheck after the
unchanged complete health-metadata-v1 proof validates, with closed raw-source/
unadmitted outcome metadata. That health-only slice's raw totals were Debian
38/60 and upstream 40/64 with the original 23 native invocations unchanged.
ADR 0025 appends mandatory ShmSize invocation 24 with a separate one-child
cleanup-owner scope, complete private gate and raw-only ShmSize singleton.
ADR 0026 appends supplementary groups and kernel settings as invocations 25/26,
with separate one-child owner scopes and mandatory independent strict readers.
Only complete SupplementaryGroups, SecurityOptions, Sysctls and SysctlIpv4Forward
raw groups are added; all four remain unselected and host capture stays deferred.
Current combined raw totals are Debian 43/66 and upstream 45/70; compiled
selection stays 34/56 and 36/60. These nine raw groups remain unselected.
