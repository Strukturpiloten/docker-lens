use super::*;
use crate::observation::ResourceRef;
use crate::target::{
    ContainerIntent, ContainerSettings, DockerPlanner, EnvironmentAssignment, ImageCommand,
    ImageReference, Mount, NetworkAttachmentIntent, NetworkDriver, NetworkIntent, NetworkRole,
    NetworkSource, Planner, TargetIdentity, TargetIntent, TargetResource,
};
use crate::version::{
    ApiVersion, Capability, CapabilityEvidenceKey, CapabilityFact, CapabilityScope,
    CapabilityState, DaemonFacts, DaemonMode, DebianPackageRevision, EngineBuild, EngineRelease,
    FactProvenance, ObservationId, TargetProfile, TargetProfileIdentity, ValidatedCapabilities,
};
use serde_json::{Value, json};
use std::num::NonZeroU16;

fn facts(capabilities: &[Capability]) -> DaemonFacts {
    let observation_id = ObservationId::fresh().unwrap();
    let release = EngineRelease::new("29.8.1".to_owned()).unwrap();
    let api_version = ApiVersion::new(NonZeroU16::new(1).unwrap(), 49);
    let mode = DaemonMode::Rootless;
    let scope = CapabilityScope {
        observation_id,
        release: release.clone(),
        api_version,
        mode,
    };
    DaemonFacts {
        observation_id,
        release: Some(release),
        api_version: Some(api_version),
        minimum_api_version: None,
        mode,
        capabilities: capabilities
            .iter()
            .map(|capability| CapabilityFact {
                capability: *capability,
                state: CapabilityState::Available,
                provenance: FactProvenance::NativeConformance,
                scope: Some(scope.clone()),
            })
            .collect(),
    }
}

fn render(intent: &TargetIntent, capabilities: &[Capability]) -> RenderedArtifact {
    let daemon = facts(capabilities);
    let validated = ValidatedCapabilities::new(&daemon).unwrap();
    let graph = DockerPlanner.plan(intent, &validated).unwrap();
    DockerApiRenderer.render(&graph).unwrap()
}

fn external_network() -> TargetResource {
    TargetResource::Network(NetworkIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(b"edge_net-1".to_vec()).unwrap(),
        role: NetworkRole::Declared,
        source: NetworkSource::External {
            expected_driver: NetworkDriver::Bridge,
            expected_internal: None,
        },
    })
}

fn external_volume() -> TargetResource {
    TargetResource::ExternalVolume {
        reference: ResourceRef::new(2),
        identity: TargetIdentity::new(b"data.volume_2".to_vec()).unwrap(),
    }
}

fn container() -> TargetResource {
    TargetResource::Container(Box::new(ContainerIntent {
        reference: ResourceRef::new(3),
        identity: TargetIdentity::new(b"review-app".to_vec()).unwrap(),
        image: ImageReference::new(b"image:1".to_vec()).unwrap(),
        environment: vec![
            EnvironmentAssignment::new(b"SECRET".to_vec(), b"quote\"slash\\line\n".to_vec())
                .unwrap(),
        ],
        ports: vec![],
        mounts: vec![Mount::volume(ResourceRef::new(2), b"/data".to_vec(), true).unwrap()],
        networks: vec![NetworkAttachmentIntent {
            network: ResourceRef::new(1),
            aliases: vec![],
            ipv4_address: None,
            ipv6_address: None,
        }],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Inherit,
        healthcheck: None,
        restart: None,
        settings: ContainerSettings::default(),
    }))
}

const EXTERNAL_CAPABILITIES: &[Capability] = &[
    Capability::StandaloneContainer,
    Capability::BridgeNetwork,
    Capability::NetworkExternalReference,
    Capability::NamedVolume,
    Capability::VolumeExternalReference,
    Capability::EnvironmentAssignment,
];

#[test]
fn complete_created_volume_has_exact_versioned_schema_and_legacy_bytes() {
    let intent = TargetIntent::new(vec![TargetResource::Volume {
        reference: ResourceRef::new(7),
        identity: TargetIdentity::new(b"created_data".to_vec()).unwrap(),
        labels: vec![],
    }])
    .unwrap();
    let artifact = render(&intent, &[Capability::NamedVolume]);
    assert_eq!(
        artifact.bytes(),
        b"{\"method\":\"POST\",\"path\":\"/v1.49/volumes/create\",\"body\":{\"Name\":\"created_data\"}}\n"
    );
    assert_eq!(
        artifact.complete_bytes().unwrap(),
        b"{\"schema_version\":1,\"context\":{\"kind\":\"observed\",\"provenance\":\"process_local_only\",\"engine_release\":\"29.8.1\",\"api_version\":\"1.49\",\"daemon_mode\":\"rootless\"},\"requests\":[{\"method\":\"POST\",\"path\":\"/v1.49/volumes/create\",\"body\":{\"Name\":\"created_data\"}}],\"prerequisites\":[]}\n"
    );
    assert!(matches!(
        artifact.context(),
        Some(PlanningContext::Observed(_))
    ));
    assert!(!format!("{artifact:?}").contains("created_data"));
}

#[test]
fn network_only_and_volume_only_remain_complete_without_requests() {
    for (resource, capabilities, expected) in [
        (
            external_network(),
            EXTERNAL_CAPABILITIES,
            json!({"kind":"network","reference":"1","identity":"edge_net-1","expected_driver":"bridge"}),
        ),
        (
            external_volume(),
            EXTERNAL_CAPABILITIES,
            json!({"kind":"volume","reference":"2","identity":"data.volume_2"}),
        ),
    ] {
        let intent = TargetIntent::new(vec![resource]).unwrap();
        let artifact = render(&intent, capabilities);
        assert!(artifact.bytes().is_empty());
        let complete: Value = serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
        assert_eq!(complete["schema_version"], 1);
        assert_eq!(complete["requests"], json!([]));
        assert_eq!(complete["prerequisites"], json!([expected]));
    }
}

#[test]
fn combined_prerequisites_keep_native_order_exact_identity_and_private_bytes() {
    let intent =
        TargetIntent::new(vec![container(), external_network(), external_volume()]).unwrap();
    let artifact = render(&intent, EXTERNAL_CAPABILITIES);
    let complete_bytes = artifact.complete_bytes().unwrap();
    let complete: Value = serde_json::from_slice(&complete_bytes).unwrap();
    assert_eq!(
        complete["prerequisites"],
        json!([
            {"kind":"network","reference":"1","identity":"edge_net-1","expected_driver":"bridge"},
            {"kind":"volume","reference":"2","identity":"data.volume_2"}
        ])
    );
    let requests: Vec<Value> = artifact
        .bytes()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(complete["requests"], json!(requests));
    assert_eq!(complete["requests"].as_array().unwrap().len(), 1);
    assert_eq!(
        complete["requests"][0]["path"],
        "/v1.49/containers/create?name=review-app"
    );
    assert_eq!(
        complete["requests"][0]["body"]["HostConfig"]["Mounts"][0]["Source"],
        "data.volume_2"
    );
    assert_eq!(
        complete["requests"][0]["body"]["NetworkingConfig"]["EndpointsConfig"]["edge_net-1"],
        json!({})
    );
    assert!(
        std::str::from_utf8(&complete_bytes)
            .unwrap()
            .contains("quote\\\"slash\\\\line\\n")
    );
    assert!(!format!("{artifact:?}").contains("data.volume_2"));
    assert!(!format!("{artifact:?}").contains("quote"));
}

#[test]
fn complete_references_preserve_full_u64_precision_as_decimal_strings() {
    let references = [9_007_199_254_740_992, 9_007_199_254_740_993, u64::MAX];
    let intent = TargetIntent::new(
        references
            .into_iter()
            .enumerate()
            .map(|(index, reference)| TargetResource::ExternalVolume {
                reference: ResourceRef::new(reference),
                identity: TargetIdentity::new(format!("volume_{index}").into_bytes()).unwrap(),
            })
            .collect(),
    )
    .unwrap();
    let artifact = render(
        &intent,
        &[Capability::NamedVolume, Capability::VolumeExternalReference],
    );
    assert!(artifact.bytes().is_empty());
    let expected = b"{\"schema_version\":1,\"context\":{\"kind\":\"observed\",\"provenance\":\"process_local_only\",\"engine_release\":\"29.8.1\",\"api_version\":\"1.49\",\"daemon_mode\":\"rootless\"},\"requests\":[],\"prerequisites\":[{\"kind\":\"volume\",\"reference\":\"9007199254740992\",\"identity\":\"volume_0\"},{\"kind\":\"volume\",\"reference\":\"9007199254740993\",\"identity\":\"volume_1\"},{\"kind\":\"volume\",\"reference\":\"18446744073709551615\",\"identity\":\"volume_2\"}]}\n";
    let complete = artifact.complete_bytes().unwrap();
    assert_eq!(complete, expected);
    let parsed: Value = serde_json::from_slice(&complete).unwrap();
    for (index, reference) in references.into_iter().enumerate() {
        let decimal = reference.to_string();
        assert_eq!(
            parsed["prerequisites"][index]["reference"].as_str(),
            Some(decimal.as_str())
        );
        assert_eq!(
            artifact.volume_prerequisites()[index]
                .reference
                .local_index(),
            reference
        );
    }
}

#[test]
fn debian_target_context_preserves_exact_package_evidence_and_redacts_debug() {
    let api = ApiVersion::new(NonZeroU16::new(1).unwrap(), 41);
    let identity = TargetProfileIdentity::new(
        EngineBuild::DebianPackage(
            DebianPackageRevision::new("20.10.5+dfsg1-1+deb11u2".to_owned()).unwrap(),
        ),
        EngineRelease::new("20.10.5+dfsg1".to_owned()).unwrap(),
        api,
        api,
        api,
        DaemonMode::Rootful,
    )
    .unwrap();
    let profile = TargetProfile::new(identity, CapabilityEvidenceKey::sha256([0xab; 32]).unwrap());
    // A serializer-only fixture, not a public capability or native admission.
    let artifact = RenderedArtifact {
        bytes: vec![],
        network_prerequisites: vec![],
        volume_prerequisites: vec![],
        bind_source_prerequisites: vec![],
        native: Some(NativeRenderState {
            context: PlanningContext::Target(profile),
            requests: vec![],
            prerequisite_order: vec![],
        }),
    };
    let expected = b"{\"schema_version\":1,\"context\":{\"kind\":\"target\",\"build\":{\"kind\":\"debian_package\",\"revision\":\"20.10.5+dfsg1-1+deb11u2\"},\"engine_release\":\"20.10.5+dfsg1\",\"advertised_api_version\":\"1.41\",\"acquisition_api_version\":\"1.41\",\"rendering_api_version\":\"1.41\",\"daemon_mode\":\"rootful\",\"evidence_sha256\":\"abababababababababababababababababababababababababababababababab\"},\"requests\":[],\"prerequisites\":[]}\n";
    assert_eq!(artifact.complete_bytes().unwrap(), expected);
    let debug = format!("{artifact:?} {:?}", artifact.context());
    assert!(!debug.contains("20.10.5"));
    assert!(!debug.contains("deb11u2"));
    assert!(!debug.contains("abababab"));
}

#[test]
fn opaque_bytes_and_invalid_identity_cannot_be_completed() {
    let opaque = RenderedArtifact::new(
        b"{\"method\":\"POST\",\"path\":\"/v1.49/volumes/create\",\"body\":{}}\n".to_vec(),
    );
    assert_eq!(opaque.context(), None);
    assert_eq!(
        opaque.complete_bytes(),
        Err(CompleteArtifactError::MissingNativeProvenance)
    );
    assert_eq!(
        TargetIdentity::new(b"invalid%volume".to_vec()).unwrap_err(),
        crate::target::IntentError::InvalidIdentity
    );
    let intent = TargetIntent::new(vec![external_volume()]).unwrap();
    let daemon = facts(&[]);
    let validated = ValidatedCapabilities::new(&daemon).unwrap();
    assert!(DockerPlanner.plan(&intent, &validated).is_err());
}
