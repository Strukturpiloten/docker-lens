//! Crate-owned candidate admission of four independently reviewed native records.
//! The JSON is part of the published crate; no caller-supplied bytes enter here.
//! Source evidence binds parameterized identity fields, not arbitrary-image startup
//! or namespace representability. Final-candidate and consumer gates remain separate.

use std::{collections::HashSet, num::NonZeroU16};

use serde_json::Value;

use crate::version::{
    ApiVersion, Capability, CapabilityEvidenceKey, CapabilityState, DaemonMode,
    DebianPackageRevision, EngineBuild, EngineRelease, NativeCapabilityShape, NativeEvidenceLane,
    NativeEvidenceReference, TargetCapabilityFact, TargetCapabilityRecord, TargetProfile,
    TargetProfileIdentity,
};

const SOURCE_CANDIDATE: &str = "032b1510524f391f08a795dab4da73f6fa8f7213";
const SOURCE_RUN: &str =
    "https://github.com/Strukturpiloten/docker-lens/actions/runs/37439627551/attempts/1";

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
];

fn expected_admission(
    lane: NativeEvidenceLane,
) -> (&'static [Capability], &'static [NativeCapabilityShape]) {
    match lane {
        NativeEvidenceLane::Debian11Rootful
        | NativeEvidenceLane::Debian11Rootless
        | NativeEvidenceLane::UpstreamRootful
        | NativeEvidenceLane::UpstreamRootless => (REVIEWED_CAPABILITIES, REVIEWED_SHAPES),
    }
}

const RECORDS: [(NativeEvidenceLane, &str, &str); 4] = [
    (
        NativeEvidenceLane::Debian11Rootful,
        "24313f10b84b8a3410906d5ad4721d3ef389ad2e09be5b59416929ef57e86b78",
        include_str!(
            "../docs/evidence/reviewed/sha256/24313f10b84b8a3410906d5ad4721d3ef389ad2e09be5b59416929ef57e86b78.json"
        ),
    ),
    (
        NativeEvidenceLane::Debian11Rootless,
        "c9800d722f1b505f5b1e5a54d9c60e68502fceaa0779f690c5504623ec473333",
        include_str!(
            "../docs/evidence/reviewed/sha256/c9800d722f1b505f5b1e5a54d9c60e68502fceaa0779f690c5504623ec473333.json"
        ),
    ),
    (
        NativeEvidenceLane::UpstreamRootful,
        "b6cebf2f71be5992b112661650e37e69270d45f7d1b8e89843e843bded325020",
        include_str!(
            "../docs/evidence/reviewed/sha256/b6cebf2f71be5992b112661650e37e69270d45f7d1b8e89843e843bded325020.json"
        ),
    ),
    (
        NativeEvidenceLane::UpstreamRootless,
        "81a1ee33c3a02d83fe6cd0f1683e1bb9b6c8774dc8aa192b2160c6ee44ba0943",
        include_str!(
            "../docs/evidence/reviewed/sha256/81a1ee33c3a02d83fe6cd0f1683e1bb9b6c8774dc8aa192b2160c6ee44ba0943.json"
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
        TmpfsMount,
        NamedVolume,
        VolumeLabels,
        VolumeExternalReference,
        BridgeNetwork,
        NetworkExternalReference,
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
    use super::{RECORDS, record};
    use crate::version::{CapabilityError, TargetCapabilityCatalog};
    use serde_json::Value;

    fn rejected(mut change: impl FnMut(&mut Value)) {
        let (lane, digest, source) = RECORDS[0];
        let mut value: Value = serde_json::from_str(source).unwrap();
        change(&mut value);
        let changed = serde_json::to_string(&value).unwrap();
        assert!(std::panic::catch_unwind(|| record(lane, digest, &changed)).is_err());
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
    fn rejects_partial_prerequisite_label_and_identity_groups_and_unreviewed_network_labels() {
        for name in [
            "VolumeExternalReference",
            "NetworkExternalReference",
            "NetworkInternal",
            "VolumeLabels",
            "ContainerUser",
            "ContainerWorkdir",
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
                "name": "NetworkLabels", "state": "available", "admitted_shapes": ["NetworkCreateLabels"]
            }));
        });
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
