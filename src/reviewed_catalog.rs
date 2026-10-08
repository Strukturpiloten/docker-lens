//! Crate-owned candidate admission of four independently reviewed native records.
//! The JSON is part of the published crate; no caller-supplied bytes enter here.
//! Source evidence covers closed configured fields and bounded native behavior.
//! SELinux effects, final-candidate and actual consumer gates remain separate.

use std::{collections::HashSet, num::NonZeroU16};

use serde_json::Value;

use crate::version::{
    ApiVersion, Capability, CapabilityEvidenceKey, CapabilityState, DaemonMode,
    DebianPackageRevision, EngineBuild, EngineRelease, NativeCapabilityShape, NativeEvidenceLane,
    NativeEvidenceReference, TargetCapabilityFact, TargetCapabilityRecord, TargetProfile,
    TargetProfileIdentity,
};

const SOURCE_CANDIDATE: &str = "6df951eb9e112becf8124fe9f8624b1df0dfbf2e";
const SOURCE_RUN: &str =
    "https://github.com/Strukturpiloten/docker-lens/actions/runs/37706460127/attempts/1";

// This is the exact admission set for the currently compiled cohort. A later
// reviewed cohort must explicitly replace the set for each lane; extending the
// schema vocabulary or checking in a native probe never changes this list.
const REVIEWED_CAPABILITIES: &[Capability] = &[
    Capability::StandaloneContainer,
    Capability::NamedVolume,
    Capability::BridgeNetwork,
    Capability::PortPublish,
    Capability::BindMount,
    Capability::EnvironmentAssignment,
    Capability::Command,
    Capability::Entrypoint,
    Capability::Healthcheck,
    Capability::RestartPolicy,
    Capability::VolumeExternalReference,
    Capability::NetworkExternalReference,
    Capability::NetworkInternal,
    Capability::VolumeLabels,
    Capability::ContainerUser,
    Capability::ContainerWorkdir,
    Capability::PortHostIpv4,
    Capability::PortMultipleBindings,
    Capability::PortExposeOnly,
    Capability::PortEphemeral,
    Capability::ContainerLabels,
    Capability::HealthShell,
    Capability::HealthStartPeriod,
    Capability::NetworkLabels,
    Capability::NetworkAliases,
    Capability::NetworkMultipleAttachment,
    Capability::BindRelabelShared,
    Capability::BindRelabelPrivate,
];
const REVIEWED_SHAPES: &[NativeCapabilityShape] = &[
    NativeCapabilityShape::StandaloneCreate,
    NativeCapabilityShape::NamedVolumeCreate,
    NativeCapabilityShape::NamedVolumeMountReadWrite,
    NativeCapabilityShape::NamedVolumeMountReadOnly,
    NativeCapabilityShape::BridgeNetworkCreate,
    NativeCapabilityShape::BridgeNetworkAttach,
    NativeCapabilityShape::FixedTcpPort,
    NativeCapabilityShape::FixedUdpPort,
    NativeCapabilityShape::BindMountReadWrite,
    NativeCapabilityShape::BindMountReadOnly,
    NativeCapabilityShape::EnvironmentValue,
    NativeCapabilityShape::EnvironmentEmptyValue,
    NativeCapabilityShape::ExecCommand,
    NativeCapabilityShape::ExecEntrypoint,
    NativeCapabilityShape::ExecHealthcheck,
    NativeCapabilityShape::RestartNo,
    NativeCapabilityShape::RestartAlways,
    NativeCapabilityShape::RestartUnlessStopped,
    NativeCapabilityShape::RestartOnFailureUnlimited,
    NativeCapabilityShape::RestartOnFailureLimited,
    NativeCapabilityShape::ExternalVolumeReference,
    NativeCapabilityShape::ExternalNetworkReference,
    NativeCapabilityShape::InternalBridgeNetworkCreate,
    NativeCapabilityShape::VolumeCreateLabels,
    NativeCapabilityShape::ContainerUser,
    NativeCapabilityShape::ContainerWorkdir,
    NativeCapabilityShape::FixedIpv4HostPort,
    NativeCapabilityShape::EphemeralIpv4HostPort,
    NativeCapabilityShape::MultipleFixedPortBindings,
    NativeCapabilityShape::MultipleEphemeralPortBindings,
    NativeCapabilityShape::ExposedOnlyPort,
    NativeCapabilityShape::EphemeralHostPort,
    NativeCapabilityShape::ContainerCreateLabels,
    NativeCapabilityShape::ShellHealthcheck,
    NativeCapabilityShape::HealthStartPeriodZero,
    NativeCapabilityShape::HealthStartPeriodPositive,
    NativeCapabilityShape::NetworkCreateLabels,
    NativeCapabilityShape::NetworkPrimaryAliases,
    NativeCapabilityShape::NetworkSecondaryAliases,
    NativeCapabilityShape::NetworkSecondaryConnect,
    NativeCapabilityShape::BindMountSharedRelabelReadWrite,
    NativeCapabilityShape::BindMountSharedRelabelReadOnly,
    NativeCapabilityShape::BindMountPrivateRelabelReadWrite,
    NativeCapabilityShape::BindMountPrivateRelabelReadOnly,
];
const UPSTREAM_CAPABILITIES: &[Capability] = &[
    Capability::StandaloneContainer,
    Capability::NamedVolume,
    Capability::BridgeNetwork,
    Capability::PortPublish,
    Capability::BindMount,
    Capability::EnvironmentAssignment,
    Capability::Command,
    Capability::Entrypoint,
    Capability::Healthcheck,
    Capability::RestartPolicy,
    Capability::VolumeExternalReference,
    Capability::NetworkExternalReference,
    Capability::NetworkInternal,
    Capability::VolumeLabels,
    Capability::ContainerUser,
    Capability::ContainerWorkdir,
    Capability::PortHostIpv4,
    Capability::PortMultipleBindings,
    Capability::PortExposeOnly,
    Capability::PortEphemeral,
    Capability::ContainerLabels,
    Capability::HealthShell,
    Capability::HealthStartPeriod,
    Capability::NetworkLabels,
    Capability::NetworkAliases,
    Capability::NetworkMultipleAttachment,
    Capability::BindRelabelShared,
    Capability::BindRelabelPrivate,
    Capability::PortHostIpv6,
];
const UPSTREAM_SHAPES: &[NativeCapabilityShape] = &[
    NativeCapabilityShape::StandaloneCreate,
    NativeCapabilityShape::NamedVolumeCreate,
    NativeCapabilityShape::NamedVolumeMountReadWrite,
    NativeCapabilityShape::NamedVolumeMountReadOnly,
    NativeCapabilityShape::BridgeNetworkCreate,
    NativeCapabilityShape::BridgeNetworkAttach,
    NativeCapabilityShape::FixedTcpPort,
    NativeCapabilityShape::FixedUdpPort,
    NativeCapabilityShape::BindMountReadWrite,
    NativeCapabilityShape::BindMountReadOnly,
    NativeCapabilityShape::EnvironmentValue,
    NativeCapabilityShape::EnvironmentEmptyValue,
    NativeCapabilityShape::ExecCommand,
    NativeCapabilityShape::ExecEntrypoint,
    NativeCapabilityShape::ExecHealthcheck,
    NativeCapabilityShape::RestartNo,
    NativeCapabilityShape::RestartAlways,
    NativeCapabilityShape::RestartUnlessStopped,
    NativeCapabilityShape::RestartOnFailureUnlimited,
    NativeCapabilityShape::RestartOnFailureLimited,
    NativeCapabilityShape::ExternalVolumeReference,
    NativeCapabilityShape::ExternalNetworkReference,
    NativeCapabilityShape::InternalBridgeNetworkCreate,
    NativeCapabilityShape::VolumeCreateLabels,
    NativeCapabilityShape::ContainerUser,
    NativeCapabilityShape::ContainerWorkdir,
    NativeCapabilityShape::FixedIpv4HostPort,
    NativeCapabilityShape::EphemeralIpv4HostPort,
    NativeCapabilityShape::MultipleFixedPortBindings,
    NativeCapabilityShape::MultipleEphemeralPortBindings,
    NativeCapabilityShape::ExposedOnlyPort,
    NativeCapabilityShape::EphemeralHostPort,
    NativeCapabilityShape::ContainerCreateLabels,
    NativeCapabilityShape::ShellHealthcheck,
    NativeCapabilityShape::HealthStartPeriodZero,
    NativeCapabilityShape::HealthStartPeriodPositive,
    NativeCapabilityShape::NetworkCreateLabels,
    NativeCapabilityShape::NetworkPrimaryAliases,
    NativeCapabilityShape::NetworkSecondaryAliases,
    NativeCapabilityShape::NetworkSecondaryConnect,
    NativeCapabilityShape::BindMountSharedRelabelReadWrite,
    NativeCapabilityShape::BindMountSharedRelabelReadOnly,
    NativeCapabilityShape::BindMountPrivateRelabelReadWrite,
    NativeCapabilityShape::BindMountPrivateRelabelReadOnly,
    NativeCapabilityShape::FixedIpv6HostPort,
    NativeCapabilityShape::EphemeralIpv6HostPort,
];

fn expected_admission(
    lane: NativeEvidenceLane,
) -> (&'static [Capability], &'static [NativeCapabilityShape]) {
    match lane {
        NativeEvidenceLane::Debian11Rootful | NativeEvidenceLane::Debian11Rootless => {
            (REVIEWED_CAPABILITIES, REVIEWED_SHAPES)
        }
        NativeEvidenceLane::UpstreamRootful | NativeEvidenceLane::UpstreamRootless => {
            (UPSTREAM_CAPABILITIES, UPSTREAM_SHAPES)
        }
    }
}

const RECORDS: [(NativeEvidenceLane, &str, &str); 4] = [
    (
        NativeEvidenceLane::Debian11Rootful,
        "edc6276b2caf91be8057430159524563f59dae1528cda8f342f37c1336d2fdc2",
        include_str!(
            "../docs/evidence/reviewed/sha256/edc6276b2caf91be8057430159524563f59dae1528cda8f342f37c1336d2fdc2.json"
        ),
    ),
    (
        NativeEvidenceLane::Debian11Rootless,
        "bf3b2374782342abda9bc13f07f273f22a262f1412afb16376efcf376dceac17",
        include_str!(
            "../docs/evidence/reviewed/sha256/bf3b2374782342abda9bc13f07f273f22a262f1412afb16376efcf376dceac17.json"
        ),
    ),
    (
        NativeEvidenceLane::UpstreamRootful,
        "7eacfd00927374220e2bbe6340b62595803e8db2842b29034dc6145f73401cac",
        include_str!(
            "../docs/evidence/reviewed/sha256/7eacfd00927374220e2bbe6340b62595803e8db2842b29034dc6145f73401cac.json"
        ),
    ),
    (
        NativeEvidenceLane::UpstreamRootless,
        "c2f380eaf9cbb8f4cdd8ca380afe350f6f97a39aeb98fc2211d531c3320d1d4a",
        include_str!(
            "../docs/evidence/reviewed/sha256/c2f380eaf9cbb8f4cdd8ca380afe350f6f97a39aeb98fc2211d531c3320d1d4a.json"
        ),
    ),
];

pub(crate) fn records() -> Vec<TargetCapabilityRecord> {
    RECORDS
        .iter()
        .map(|(lane, record_hash, source)| record(*lane, record_hash, source))
        .collect()
}

fn record(lane: NativeEvidenceLane, record_hash: &str, source: &str) -> TargetCapabilityRecord {
    let data: Value = serde_json::from_str(source).expect("reviewed record JSON");
    assert_eq!(data["schema_version"], 1);
    assert_eq!(data["candidate_sha"], SOURCE_CANDIDATE);
    assert_eq!(data["run_url"], SOURCE_RUN);
    assert_eq!(data["native_manifest_artifact_name"], lane.artifact_name());
    assert_eq!(
        format!("dockerlens-native-{}", required(&data, "lane")),
        lane.artifact_name()
    );

    let identity = &data["identity"];
    let build = if matches!(
        lane,
        NativeEvidenceLane::Debian11Rootful | NativeEvidenceLane::Debian11Rootless
    ) {
        assert_eq!(identity["build"]["kind"], "debian-package");
        assert_eq!(identity["build"]["distribution"], "debian11");
        assert_eq!(identity["build"]["package_name"], "docker.io");
        EngineBuild::DebianPackage(
            DebianPackageRevision::new(required(&identity["build"], "package_revision").to_owned())
                .expect("reviewed Debian package revision"),
        )
    } else {
        assert_eq!(identity["build"]["kind"], "upstream");
        EngineBuild::Upstream
    };
    let mode = match required(identity, "mode") {
        "rootful" => DaemonMode::Rootful,
        "rootless" => DaemonMode::Rootless,
        _ => panic!("unrecognized reviewed daemon mode"),
    };
    let identity = TargetProfileIdentity::new(
        build,
        EngineRelease::new(required(identity, "engine_release").to_owned())
            .expect("reviewed Engine release"),
        api(required(identity, "advertised_api")),
        api(required(identity, "acquisition_api")),
        api(required(identity, "rendering_api")),
        mode,
    )
    .expect("reviewed target identity");
    let record_key = digest(record_hash);
    let manifest_key = digest(required(&data, "native_manifest_sha256"));
    let evidence = NativeEvidenceReference::new(
        lane,
        SOURCE_RUN.to_owned(),
        SOURCE_CANDIDATE.to_owned(),
        lane.artifact_name().to_owned(),
        manifest_key,
        record_key.clone(),
    )
    .expect("reviewed native evidence reference");

    let capabilities = data["capabilities"]
        .as_array()
        .expect("reviewed capability array");
    let (expected_capabilities, expected_shapes) = expected_admission(lane);
    assert_eq!(
        capabilities.len(),
        expected_capabilities.len(),
        "exact reviewed capability count"
    );
    let mut facts = Vec::with_capacity(expected_capabilities.len());
    let mut shapes = Vec::with_capacity(expected_shapes.len());
    for entry in capabilities {
        assert_eq!(entry["state"], "available");
        let name = capability(required(entry, "name"));
        facts.push(TargetCapabilityFact {
            capability: name,
            state: CapabilityState::Available,
        });
        let entry_shapes = entry["admitted_shapes"]
            .as_array()
            .expect("reviewed shape array")
            .iter()
            .map(|shape| native_shape(shape.as_str().expect("reviewed shape name")))
            .collect::<Vec<_>>();
        let required =
            NativeCapabilityShape::required_for(name).expect("closed reviewed capability shape");
        assert_eq!(
            entry_shapes.len(),
            required.len(),
            "complete reviewed capability shape count"
        );
        assert_eq!(
            entry_shapes.iter().copied().collect::<HashSet<_>>(),
            required.iter().copied().collect(),
            "complete reviewed capability shapes"
        );
        shapes.extend(entry_shapes);
    }
    assert_eq!(
        facts
            .iter()
            .map(|fact| fact.capability)
            .collect::<HashSet<_>>(),
        expected_capabilities.iter().copied().collect(),
        "exact reviewed capability set"
    );
    assert_eq!(
        shapes.len(),
        expected_shapes.len(),
        "exact reviewed shape count"
    );
    assert_eq!(
        shapes.iter().copied().collect::<HashSet<_>>(),
        expected_shapes.iter().copied().collect(),
        "exact reviewed shape set"
    );
    TargetCapabilityRecord {
        profile: TargetProfile::new(identity, record_key),
        evidence,
        capabilities: facts,
        admitted_shapes: shapes,
    }
}

fn required<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().expect("reviewed string field")
}

fn api(value: &str) -> ApiVersion {
    let (major, minor) = value.split_once('.').expect("reviewed API version");
    ApiVersion::new(
        NonZeroU16::new(major.parse().expect("reviewed API major")).expect("nonzero API"),
        minor.parse().expect("reviewed API minor"),
    )
}

fn digest(value: &str) -> CapabilityEvidenceKey {
    assert_eq!(value.len(), 64, "reviewed digest length");
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(
            std::str::from_utf8(pair).expect("reviewed digest encoding"),
            16,
        )
        .expect("reviewed digest hex");
    }
    CapabilityEvidenceKey::sha256(bytes).expect("nonempty reviewed digest")
}

macro_rules! closed_name {
    ($name:expr, $kind:ident, $($variant:ident),+ $(,)?) => {
        match $name {
            $(stringify!($variant) => $kind::$variant,)+
            _ => panic!("unreviewed catalogue name"),
        }
    };
}

fn capability(name: &str) -> Capability {
    closed_name!(
        name,
        Capability,
        StandaloneContainer,
        BindMount,
        BindRelabelShared,
        BindRelabelPrivate,
        TmpfsMount,
        NamedVolume,
        VolumeLabels,
        VolumeExternalReference,
        BridgeNetwork,
        NetworkExternalReference,
        NetworkExternalInternalExpectation,
        NetworkInternal,
        NetworkIpv6,
        NetworkIpam,
        NetworkIpamDriver,
        NetworkOptions,
        NetworkLabels,
        NetworkAliases,
        NetworkStaticAddress,
        NetworkMultipleAttachment,
        HostNetwork,
        PortPublish,
        PortExposeOnly,
        PortHostIpv4,
        PortHostIpv6,
        PortMultipleBindings,
        PortEphemeral,
        UserNamespace,
        EnvironmentAssignment,
        Command,
        CommandClear,
        Entrypoint,
        EntrypointClear,
        Healthcheck,
        HealthShell,
        HealthDisabled,
        HealthStartPeriod,
        HealthStartInterval,
        RestartPolicy,
        ContainerLabels,
        ContainerUser,
        ContainerWorkdir,
        ContainerHostname,
        ReadOnlyRootfs,
        ContainerInit,
        StopSignal,
        StopTimeout,
        MemoryLimit,
        PidsLimit,
        ShmSize,
        Ulimits,
        UlimitNofile,
        DeviceMappings,
        LinuxCapabilities,
        CapAddNetBindService,
        CapDropSysAdmin,
        SecurityOptions,
        Sysctls,
        SysctlIpv4Forward,
        SupplementaryGroups,
        DnsServers,
        ExtraHosts,
        LogConfig,
        LogOptionMaxSize,
    )
}

fn native_shape(name: &str) -> NativeCapabilityShape {
    closed_name!(
        name,
        NativeCapabilityShape,
        StandaloneCreate,
        NamedVolumeCreate,
        VolumeCreateLabels,
        NamedVolumeMountReadWrite,
        NamedVolumeMountReadOnly,
        ExternalVolumeReference,
        BridgeNetworkCreate,
        BridgeNetworkAttach,
        ExternalNetworkReference,
        ExternalNetworkInternalFalse,
        ExternalNetworkInternalTrue,
        InternalBridgeNetworkCreate,
        Ipv6BridgeNetworkCreate,
        NetworkIpamV4,
        NetworkIpamV6,
        NetworkIpamGateway,
        NetworkIpamRange,
        NetworkIpamAuxiliary,
        NetworkIpamDefaultDriver,
        NetworkBridgeMtu,
        NetworkBridgeIcc,
        NetworkBridgeIccDisabled,
        NetworkBridgeMasquerade,
        NetworkBridgeMasqueradeEnabled,
        NetworkBridgeHostBindingIp,
        NetworkCreateLabels,
        NetworkPrimaryAliases,
        NetworkSecondaryAliases,
        NetworkStaticIpv4,
        NetworkStaticIpv6,
        NetworkSecondaryConnect,
        FixedTcpPort,
        FixedUdpPort,
        ExposedOnlyPort,
        FixedIpv4HostPort,
        EphemeralIpv4HostPort,
        FixedIpv6HostPort,
        EphemeralIpv6HostPort,
        MultipleFixedPortBindings,
        MultipleEphemeralPortBindings,
        EphemeralHostPort,
        BindMountReadWrite,
        BindMountReadOnly,
        BindMountSharedRelabelReadWrite,
        BindMountSharedRelabelReadOnly,
        BindMountPrivateRelabelReadWrite,
        BindMountPrivateRelabelReadOnly,
        TmpfsMountReadWrite,
        TmpfsMountReadOnly,
        TmpfsMountOptions,
        EnvironmentValue,
        EnvironmentEmptyValue,
        ExecCommand,
        ClearCommand,
        ExecEntrypoint,
        ClearEntrypoint,
        ExecHealthcheck,
        ShellHealthcheck,
        DisabledHealthcheck,
        HealthStartPeriodZero,
        HealthStartPeriodPositive,
        HealthStartIntervalZero,
        HealthStartIntervalPositive,
        ContainerCreateLabels,
        ContainerUser,
        ContainerWorkdir,
        ContainerHostname,
        ReadOnlyRootfsTrue,
        ReadOnlyRootfsFalse,
        ContainerInitTrue,
        ContainerInitFalse,
        StopSignal,
        StopTimeoutZero,
        StopTimeoutPositive,
        MemoryBytes,
        MemoryUnlimited,
        PidsCount,
        PidsUnlimited,
        ShmSize,
        UlimitsFinite,
        UlimitsUnlimited,
        UlimitNofile,
        DeviceMappings,
        LinuxCapAdd,
        LinuxCapDrop,
        CapAddNetBindService,
        CapDropSysAdmin,
        NoNewPrivilegesEnabled,
        NoNewPrivilegesDisabled,
        Sysctls,
        SysctlIpv4Forward,
        SupplementaryGroups,
        DnsIpv4,
        DnsIpv6,
        ExtraHostsIpv4,
        ExtraHostsIpv6,
        LogJsonFile,
        LogLocal,
        LogNone,
        LogOptions,
        LogOptionMaxSize,
        RestartNo,
        RestartAlways,
        RestartUnlessStopped,
        RestartOnFailureUnlimited,
        RestartOnFailureLimited,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        RECORDS, REVIEWED_CAPABILITIES, REVIEWED_SHAPES, capability, native_shape, record,
    };
    use crate::version::{
        Capability, CapabilityError, NativeCapabilityShape, TargetCapabilityCatalog,
    };
    use serde_json::Value;

    fn rejected(mut change: impl FnMut(&mut Value)) {
        let (lane, digest, source) = RECORDS[0];
        let mut value: Value = serde_json::from_str(source).unwrap();
        change(&mut value);
        let changed = serde_json::to_string(&value).unwrap();
        assert!(std::panic::catch_unwind(|| record(lane, digest, &changed)).is_err());
    }

    #[test]
    fn bind_relabel_groups_are_explicitly_admitted_but_remain_complete() {
        for (name, expected, shapes) in [
            (
                "BindRelabelShared",
                Capability::BindRelabelShared,
                [
                    "BindMountSharedRelabelReadWrite",
                    "BindMountSharedRelabelReadOnly",
                ],
            ),
            (
                "BindRelabelPrivate",
                Capability::BindRelabelPrivate,
                [
                    "BindMountPrivateRelabelReadWrite",
                    "BindMountPrivateRelabelReadOnly",
                ],
            ),
        ] {
            assert_eq!(capability(name), expected);
            assert!(REVIEWED_CAPABILITIES.contains(&expected));
            rejected(|value| {
                value["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({
                        "name":name, "state":"available", "admitted_shapes":[],
                    }))
            });
            rejected(|value| {
                let bind = value["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry["name"] == "BindMount")
                    .unwrap();
                *bind =
                    serde_json::json!({"name":name,"state":"available","admitted_shapes":shapes});
            });
        }
        for (name, expected) in [
            (
                "BindMountSharedRelabelReadWrite",
                NativeCapabilityShape::BindMountSharedRelabelReadWrite,
            ),
            (
                "BindMountSharedRelabelReadOnly",
                NativeCapabilityShape::BindMountSharedRelabelReadOnly,
            ),
            (
                "BindMountPrivateRelabelReadWrite",
                NativeCapabilityShape::BindMountPrivateRelabelReadWrite,
            ),
            (
                "BindMountPrivateRelabelReadOnly",
                NativeCapabilityShape::BindMountPrivateRelabelReadOnly,
            ),
        ] {
            assert_eq!(native_shape(name), expected);
            assert!(REVIEWED_SHAPES.contains(&expected));
        }
    }

    #[test]
    fn rejects_unreviewed_or_incomplete_capability_groups() {
        rejected(|value| value["capabilities"][0]["name"] = "NotACapability".into());
        rejected(|value| value["capabilities"][0]["name"] = "VolumeLabels".into());
        rejected(|value| {
            let entry = value["capabilities"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|entry| entry["name"] == "Command")
                .unwrap();
            entry["name"] = "CommandClear".into();
            entry["admitted_shapes"] = serde_json::json!(["ClearCommand"]);
        });
        rejected(|value| {
            let entries = value["capabilities"].as_array_mut().unwrap();
            entries[1] = entries[0].clone();
        });
        rejected(|value| {
            value["capabilities"][1]["admitted_shapes"]
                .as_array_mut()
                .unwrap()
                .pop();
        });
        rejected(|value| {
            let shapes = value["capabilities"][1]["admitted_shapes"]
                .as_array_mut()
                .unwrap();
            shapes[1] = shapes[0].clone();
        });
        rejected(|value| {
            value["capabilities"][1]["admitted_shapes"][0] = "FixedTcpPort".into();
        });
        rejected(|value| {
            value["capabilities"][1]["admitted_shapes"][0] = "NotAShape".into();
        });
    }

    #[test]
    fn rejects_forged_source_run_and_candidate() {
        rejected(|value| value["candidate_sha"] = "a".repeat(40).into());
        rejected(|value| value["run_url"] = "https://example.invalid/run".into());
        rejected(|value| value["lane"] = "debian11-rootless".into());
        rejected(|value| {
            value["native_manifest_artifact_name"] = "dockerlens-native-debian11-rootless".into();
        });
    }

    #[test]
    fn rejects_partial_application_groups_and_unreviewed_network_options() {
        for name in [
            "VolumeExternalReference",
            "NetworkExternalReference",
            "NetworkInternal",
            "VolumeLabels",
            "ContainerUser",
            "ContainerWorkdir",
            "PortHostIpv4",
            "PortMultipleBindings",
            "PortExposeOnly",
            "PortEphemeral",
            "ContainerLabels",
            "HealthShell",
            "HealthStartPeriod",
            "NetworkLabels",
            "NetworkAliases",
            "NetworkMultipleAttachment",
            "BindRelabelShared",
            "BindRelabelPrivate",
        ] {
            rejected(|value| {
                value["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|entry| entry["name"] != name);
            });
            rejected(|value| {
                let entry = value["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry["name"] == name)
                    .unwrap();
                entry["admitted_shapes"] = serde_json::json!([]);
            });
            rejected(|value| {
                let entry = value["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry["name"] == name)
                    .unwrap();
                let shape = entry["admitted_shapes"][0].clone();
                entry["admitted_shapes"].as_array_mut().unwrap().push(shape);
            });
            rejected(|value| {
                let entry = value["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry["name"] == name)
                    .unwrap();
                entry["state"] = "unavailable".into();
            });
            rejected(|value| {
                let entry = value["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry["name"] == name)
                    .unwrap();
                entry["state"] = "unknown".into();
            });
            rejected(|value| {
                let entry = value["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry["name"] == name)
                    .unwrap();
                entry["admitted_shapes"] = serde_json::json!(["StandaloneCreate"]);
            });
        }
        rejected(|value| {
            value["capabilities"].as_array_mut().unwrap().push(serde_json::json!({
                "name": "NetworkOptions", "state": "available", "admitted_shapes": ["NetworkBridgeMtu"]
            }));
        });
    }

    #[test]
    fn every_lane_requires_each_complete_application_group() {
        for (lane, digest, source) in RECORDS {
            let original: Value = serde_json::from_str(source).unwrap();
            for name in [
                "PortHostIpv4",
                "PortMultipleBindings",
                "PortExposeOnly",
                "PortEphemeral",
                "ContainerLabels",
                "HealthShell",
                "HealthStartPeriod",
                "NetworkLabels",
                "NetworkAliases",
                "NetworkMultipleAttachment",
                "BindRelabelShared",
                "BindRelabelPrivate",
            ]
            .into_iter()
            .chain(
                matches!(
                    lane,
                    crate::version::NativeEvidenceLane::UpstreamRootful
                        | crate::version::NativeEvidenceLane::UpstreamRootless
                )
                .then_some("PortHostIpv6"),
            ) {
                let mut value = original.clone();
                let entry = value["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry["name"] == name)
                    .unwrap();
                entry["admitted_shapes"].as_array_mut().unwrap().pop();
                let changed = serde_json::to_string(&value).unwrap();
                assert!(std::panic::catch_unwind(|| record(lane, digest, &changed)).is_err());
            }
        }
    }

    #[test]
    fn debian_never_borrows_upstream_ipv6_admission() {
        for (lane, digest, source) in &RECORDS[..2] {
            let mut value: Value = serde_json::from_str(source).unwrap();
            value["capabilities"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "name":"PortHostIpv6", "state":"available",
                    "admitted_shapes":["FixedIpv6HostPort","EphemeralIpv6HostPort"],
                }));
            let changed = serde_json::to_string(&value).unwrap();
            assert!(std::panic::catch_unwind(|| record(*lane, digest, &changed)).is_err());
        }
    }

    #[test]
    fn swapped_mode_is_rejected_by_final_catalog_admission() {
        let (lane, digest, source) = RECORDS[0];
        let mut value: Value = serde_json::from_str(source).unwrap();
        value["identity"]["mode"] = "rootless".into();
        let source = serde_json::to_string(&value).unwrap();
        let parsed = record(lane, digest, &source);
        assert!(matches!(
            TargetCapabilityCatalog::from_test_records(vec![parsed]),
            Err(CapabilityError::EvidenceLaneMismatch)
        ));
    }
}
