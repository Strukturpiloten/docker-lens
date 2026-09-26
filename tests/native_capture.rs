//! Live Engine API responses are test-only protected inputs, never committed fixtures.

use std::fs;
use std::num::NonZeroU16;
use std::path::Path;
use std::time::Duration;

use docker_lens::acquisition::{Budget, Limits, NativeId, ReadRequest};
use docker_lens::decoder::{
    CommandValue, HealthcheckTest, MountKind, TransportProtocol, decode_capture,
};
use docker_lens::evidence::HttpStatus;
use docker_lens::observation::{Origin, ResourceRef};
use docker_lens::version::{ApiVersion, DaemonMode};
use serde_json::Value;

#[test]
#[ignore = "requires an isolated inner Docker Engine and protected live API responses"]
fn live_engine_capture_decodes() {
    eprintln!("DOCKERLENS_NATIVE_CHECK: capture_input");
    let dir = std::env::var("NATIVE_CAPTURE_DIR").expect("harness supplies capture directory");
    let container_id = std::env::var("NATIVE_CONTAINER_ID").expect("harness supplies container ID");
    let network_id = std::env::var("NATIVE_NETWORK_ID").expect("harness supplies network ID");
    let volume_name = std::env::var("NATIVE_VOLUME_NAME").expect("harness supplies volume name");
    let expected_version =
        std::env::var("NATIVE_ENGINE_VERSION").expect("harness supplies Engine version");
    let expected_mode = std::env::var("NATIVE_DAEMON_MODE").expect("harness supplies daemon mode");
    assert!(
        matches!(expected_mode.as_str(), "rootful" | "rootless"),
        "closed native daemon mode"
    );
    let api = std::env::var("NATIVE_API_VERSION").expect("harness supplies API version");
    let (major, minor) = api.split_once('.').expect("major.minor API version");
    let api = ApiVersion::new(
        NonZeroU16::new(major.parse().expect("API major")).expect("nonzero API major"),
        minor.parse().expect("API minor"),
    );

    let mut budget = Budget::new(Limits {
        max_requests: 5,
        max_selected_resources: 1,
        max_expansions: 3,
        max_response_bytes: 8 * 1024 * 1024,
        max_total_bytes: 16 * 1024 * 1024,
        max_elapsed: Duration::from_secs(60),
    })
    .expect("bounded capture");
    budget.record_selection(1).expect("one selected container");
    for (file, request, reference, version) in [
        ("version.json", ReadRequest::DaemonVersion, None, None),
        ("info.json", ReadRequest::DaemonInfo, None, Some(api)),
        (
            "container.json",
            ReadRequest::InspectContainer(
                NativeId::new(container_id).expect("native container ID"),
            ),
            Some(ResourceRef::new(1)),
            Some(api),
        ),
        (
            "network.json",
            ReadRequest::InspectNetwork(NativeId::new(network_id).expect("native network ID")),
            Some(ResourceRef::new(2)),
            Some(api),
        ),
        (
            "volume.json",
            ReadRequest::InspectVolume(
                NativeId::new(volume_name.clone()).expect("native volume name"),
            ),
            Some(ResourceRef::new(3)),
            Some(api),
        ),
    ] {
        let path = Path::new(&dir).join(file);
        let bytes = fs::read(&path).expect("protected native response exists");
        let status: u16 = fs::read_to_string(path.with_extension("status"))
            .expect("native HTTP status exists")
            .trim()
            .parse()
            .expect("valid native HTTP status");
        assert_eq!(status, 200);
        budget
            .record_request(request, reference, version)
            .expect("closed read request");
        budget
            .read_response(HttpStatus::new(status).unwrap(), bytes.as_slice())
            .expect("bounded response");
    }
    let capture = budget.into_capture().expect("complete bounded capture");
    eprintln!("DOCKERLENS_NATIVE_CHECK: capture_decode");
    let decoded = decode_capture(&capture).expect("live API capture decodes");
    eprintln!("DOCKERLENS_NATIVE_CHECK: capture_daemon");
    let info: Value = serde_json::from_slice(
        &fs::read(Path::new(&dir).join("info.json")).expect("private direct info response"),
    )
    .expect("direct info JSON");
    let option_rootless = info["SecurityOptions"].as_array().is_some_and(|options| {
        options.iter().any(|option| {
            option.as_str().is_some_and(|value| {
                value == "name=rootless" || value.starts_with("name=rootless,")
            })
        })
    });
    let explicit_rootless = info["Rootless"].as_bool();
    assert!(
        !(option_rootless && explicit_rootless == Some(false)),
        "conflicting daemon mode oracle"
    );
    let oracle_mode = match (option_rootless, explicit_rootless) {
        (true, _) | (_, Some(true)) => DaemonMode::Rootless,
        (_, Some(false)) => DaemonMode::Rootful,
        _ => DaemonMode::Unknown,
    };
    assert_eq!(
        expected_mode == "rootless",
        oracle_mode == DaemonMode::Rootless
    );
    assert_eq!(
        decoded.version.daemon.release.as_ref().unwrap().as_str(),
        expected_version
    );
    assert_eq!(decoded.version.daemon.api_version, Some(api));
    assert_eq!(decoded.version.daemon.mode, oracle_mode);
    eprintln!("DOCKERLENS_NATIVE_CHECK: capture_counts");
    assert_eq!(decoded.containers.len(), 1);
    assert_eq!(decoded.networks.len(), 1);
    assert_eq!(decoded.volumes.len(), 1);
    let container = &decoded.containers[0];
    eprintln!("DOCKERLENS_NATIVE_CHECK: capture_image");
    assert_eq!(container.image.origin, Origin::Effective);
    eprintln!("DOCKERLENS_NATIVE_CHECK: capture_ports");
    for (container_port, protocol, host_port) in [
        (8080, TransportProtocol::Tcp, 18080),
        (8081, TransportProtocol::Udp, 18081),
    ] {
        let port = container
            .configured_ports
            .value()
            .unwrap()
            .iter()
            .find(|port| port.key.container_port == container_port && port.key.protocol == protocol)
            .expect("native port shape exists");
        let bindings = port.bindings.value().expect("native host binding exists");
        assert!(!bindings.is_empty());
        for binding in bindings {
            assert_eq!(binding.host_port.value(), Some(&host_port));
            let ip = binding
                .host_ip
                .value()
                .map(|value| value.as_bytes())
                .unwrap_or_default();
            assert!([b"".as_slice(), b"0.0.0.0".as_slice(), b"::".as_slice()].contains(&ip));
        }
    }
    eprintln!("DOCKERLENS_NATIVE_CHECK: capture_mounts");
    let mount = container
        .mounts
        .value()
        .unwrap()
        .iter()
        .find(|mount| mount.kind == MountKind::Volume)
        .expect("named volume mount exists");
    assert_eq!(
        mount.name.value().unwrap().as_bytes(),
        volume_name.as_bytes()
    );
    assert_eq!(mount.destination.value().unwrap().as_bytes(), b"/data");
    assert_eq!(mount.read_write.value(), Some(&true));
    let bind = container
        .mounts
        .value()
        .unwrap()
        .iter()
        .find(|mount| mount.kind == MountKind::Bind)
        .expect("read-only bind mount exists");
    assert_eq!(
        bind.source.value().unwrap().as_bytes(),
        b"/run/dockerlens/native-bind"
    );
    assert_eq!(bind.destination.value().unwrap().as_bytes(), b"/readonly");
    assert_eq!(bind.read_write.value(), Some(&false));
    eprintln!("DOCKERLENS_NATIVE_CHECK: capture_environment");
    let assignment = container
        .environment
        .value()
        .unwrap()
        .iter()
        .find(|assignment| assignment.name.as_bytes() == b"DL_CONFORMANCE")
        .expect("synthetic environment exists");
    assert_eq!(
        assignment.value.as_ref().unwrap().as_bytes(),
        b"synthetic-secret"
    );
    for (name, value) in [
        (b"EMPTY".as_slice(), b"".as_slice()),
        (b"QUOTED", b"a\"b\\c"),
    ] {
        let assignment = container
            .environment
            .value()
            .unwrap()
            .iter()
            .find(|assignment| assignment.name.as_bytes() == name)
            .expect("independent environment shape exists");
        assert_eq!(assignment.value.as_ref().unwrap().as_bytes(), value);
    }
    eprintln!("DOCKERLENS_NATIVE_CHECK: capture_command");
    assert!(
        matches!(container.entrypoint.value(), Some(CommandValue::Exec(parts)) if parts.len() == 1 && parts[0].as_bytes() == b"/bin/sh")
    );
    assert!(
        matches!(container.command.value(), Some(CommandValue::Exec(parts)) if parts.len() == 2 && parts[0].as_bytes() == b"-c" && parts[1].as_bytes().starts_with(b"httpd -f -p 8080"))
    );
    assert!(
        matches!(container.healthcheck.value().unwrap().test.value(), Some(HealthcheckTest::CmdShell(value)) if value.as_bytes() == b"true")
    );
    let restart = container
        .restart_policy
        .value()
        .expect("restart policy exists");
    assert_eq!(restart.name.value().unwrap().as_bytes(), b"on-failure");
    assert_eq!(restart.maximum_retry_count.value(), Some(&3));
    eprintln!("DOCKERLENS_NATIVE_CHECK: capture_privacy");
    let debug = format!("{decoded:?}");
    assert!(!debug.contains("synthetic-secret"));
}
