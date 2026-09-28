//! Crate-owned admission of four independently reviewed native records.
//! The JSON is part of the published crate; no caller-supplied bytes enter here.

use std::num::NonZeroU16;

use serde_json::Value;

use crate::version::{
    ApiVersion, Capability, CapabilityEvidenceKey, CapabilityState, DaemonMode,
    DebianPackageRevision, EngineBuild, EngineRelease, NativeCapabilityShape, NativeEvidenceLane,
    NativeEvidenceReference, TargetCapabilityFact, TargetCapabilityRecord, TargetProfile,
    TargetProfileIdentity,
};

const SOURCE_CANDIDATE: &str = "d51d7dbfda5ee6f8fefe92605afe8baea3dc504e";
const SOURCE_RUN: &str =
    "https://github.com/Strukturpiloten/docker-lens/actions/runs/36451790131/attempts/1";

const RECORDS: [(NativeEvidenceLane, &str, &str); 4] = [
    (
        NativeEvidenceLane::Debian11Rootful,
        "f4a68bec2605814b9ff9c3942adc60cee88255775f17c101cc0b72767fe03e0f",
        include_str!(
            "../docs/evidence/reviewed/sha256/f4a68bec2605814b9ff9c3942adc60cee88255775f17c101cc0b72767fe03e0f.json"
        ),
    ),
    (
        NativeEvidenceLane::Debian11Rootless,
        "7445b521282ded2e1d07f2478a7d7812ed51b27a488861483fe228b85b114986",
        include_str!(
            "../docs/evidence/reviewed/sha256/7445b521282ded2e1d07f2478a7d7812ed51b27a488861483fe228b85b114986.json"
        ),
    ),
    (
        NativeEvidenceLane::UpstreamRootful,
        "063d5ea178ff754d16fc3ce1db99855907a0b6a93b924f241fcf8b14c2811362",
        include_str!(
            "../docs/evidence/reviewed/sha256/063d5ea178ff754d16fc3ce1db99855907a0b6a93b924f241fcf8b14c2811362.json"
        ),
    ),
    (
        NativeEvidenceLane::UpstreamRootless,
        "a9620c6a3b94c31e662e11b14de7688290eec8f2532dd5a061652ef01b2639ee",
        include_str!(
            "../docs/evidence/reviewed/sha256/a9620c6a3b94c31e662e11b14de7688290eec8f2532dd5a061652ef01b2639ee.json"
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
    assert_eq!(capabilities.len(), 10, "all ten reviewed capabilities");
    let mut facts = Vec::with_capacity(10);
    let mut shapes = Vec::with_capacity(20);
    for entry in capabilities {
        assert_eq!(entry["state"], "available");
        facts.push(TargetCapabilityFact {
            capability: capability(required(entry, "name")),
            state: CapabilityState::Available,
        });
        shapes.extend(
            entry["admitted_shapes"]
                .as_array()
                .expect("reviewed shape array")
                .iter()
                .map(|shape| native_shape(shape.as_str().expect("reviewed shape name"))),
        );
    }
    assert_eq!(shapes.len(), 20, "all twenty reviewed renderer shapes");
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

fn capability(name: &str) -> Capability {
    match name {
        "StandaloneContainer" => Capability::StandaloneContainer,
        "NamedVolume" => Capability::NamedVolume,
        "BridgeNetwork" => Capability::BridgeNetwork,
        "PortPublish" => Capability::PortPublish,
        "BindMount" => Capability::BindMount,
        "EnvironmentAssignment" => Capability::EnvironmentAssignment,
        "Command" => Capability::Command,
        "Entrypoint" => Capability::Entrypoint,
        "Healthcheck" => Capability::Healthcheck,
        "RestartPolicy" => Capability::RestartPolicy,
        _ => panic!("unreviewed capability name"),
    }
}

fn native_shape(name: &str) -> NativeCapabilityShape {
    match name {
        "StandaloneCreate" => NativeCapabilityShape::StandaloneCreate,
        "NamedVolumeCreate" => NativeCapabilityShape::NamedVolumeCreate,
        "NamedVolumeMountReadWrite" => NativeCapabilityShape::NamedVolumeMountReadWrite,
        "NamedVolumeMountReadOnly" => NativeCapabilityShape::NamedVolumeMountReadOnly,
        "BridgeNetworkCreate" => NativeCapabilityShape::BridgeNetworkCreate,
        "BridgeNetworkAttach" => NativeCapabilityShape::BridgeNetworkAttach,
        "FixedTcpPort" => NativeCapabilityShape::FixedTcpPort,
        "FixedUdpPort" => NativeCapabilityShape::FixedUdpPort,
        "BindMountReadWrite" => NativeCapabilityShape::BindMountReadWrite,
        "BindMountReadOnly" => NativeCapabilityShape::BindMountReadOnly,
        "EnvironmentValue" => NativeCapabilityShape::EnvironmentValue,
        "EnvironmentEmptyValue" => NativeCapabilityShape::EnvironmentEmptyValue,
        "ExecCommand" => NativeCapabilityShape::ExecCommand,
        "ExecEntrypoint" => NativeCapabilityShape::ExecEntrypoint,
        "ExecHealthcheck" => NativeCapabilityShape::ExecHealthcheck,
        "RestartNo" => NativeCapabilityShape::RestartNo,
        "RestartAlways" => NativeCapabilityShape::RestartAlways,
        "RestartUnlessStopped" => NativeCapabilityShape::RestartUnlessStopped,
        "RestartOnFailureUnlimited" => NativeCapabilityShape::RestartOnFailureUnlimited,
        "RestartOnFailureLimited" => NativeCapabilityShape::RestartOnFailureLimited,
        _ => panic!("unreviewed renderer shape"),
    }
}
