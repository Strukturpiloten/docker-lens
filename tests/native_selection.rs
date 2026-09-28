//! Independent live source probes in the isolated four-lane Engine harness.
//! The harness supplies CLI-created fixtures and direct GET responses as oracles.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use docker_lens::acquisition::{
    Endpoint, Limits, NativeId, ReadRequest, RootKind, SelectionReason, Selector, acquire,
};
use docker_lens::decoder::{
    CommandValue, ContainerSummary, DecodedInventory, HealthcheckTest, MountKind,
    TransportProtocol, decode_capture,
};
use docker_lens::evidence::{Capture, CaptureRoute, ProtectedValue};
use docker_lens::observation::{Availability, Observed, Origin};
use docker_lens::version::DaemonMode;
use serde_json::Value;

const SOURCE_PROBES: [&str; 15] = [
    "DiscoveryMetadata",
    "ExactContainerId",
    "ExactContainerName",
    "LiteralNamePrefix",
    "ExactLabel",
    "ExplicitAllContainers",
    "ExactNetworkRoot",
    "ExactVolumeRoot",
    "UnrelatedInspectExcluded",
    "IdentityFieldsOracle",
    "PortBindingsOracle",
    "MultipleHostIpBindingsOracle",
    "MountEnvironmentOracle",
    "HealthRestartOracle",
    "SelectedFieldOrigins",
];

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing native harness input {name}"))
}

fn direct_json(directory: &Path, name: &str) -> Value {
    serde_json::from_slice(&fs::read(directory.join(name)).expect("private direct GET exists"))
        .expect("direct GET is JSON")
}

fn limits() -> Limits {
    Limits {
        max_requests: 16,
        max_selected_resources: 3,
        max_expansions: 8,
        max_response_bytes: 8 * 1024 * 1024,
        max_total_bytes: 40 * 1024 * 1024,
        max_elapsed: Duration::from_secs(30),
    }
}

fn capture(endpoint: &Endpoint, selector: Selector) -> (Capture, DecodedInventory) {
    let capture = acquire(endpoint, selector, limits(), &AtomicBool::new(false))
        .expect("bounded native source acquisition");
    assert_eq!(capture.route(), CaptureRoute::ExplicitUnixSocket);
    assert!(
        capture
            .exchanges()
            .iter()
            .all(|exchange| exchange.status().code() == 200)
    );
    let decoded = decode_capture(&capture).expect("closed native source decode");
    (capture, decoded)
}

fn inspected_container_ids(capture: &Capture) -> HashSet<&str> {
    capture
        .exchanges()
        .iter()
        .filter_map(|exchange| match exchange.request() {
            ReadRequest::InspectContainer(id) => Some(id.as_str()),
            _ => None,
        })
        .collect()
}

fn expected_availability(value: Option<&Value>) -> Availability {
    match value {
        None => Availability::Missing,
        Some(Value::Null) => Availability::Null,
        Some(Value::String(text)) if text.is_empty() => Availability::Empty,
        Some(_) => Availability::Present,
    }
}

fn effective_string(observed: &Observed<ProtectedValue>, raw: Option<&Value>) {
    assert_eq!(observed.origin, Origin::Effective);
    assert_eq!(observed.availability, expected_availability(raw));
    if let Some(Value::String(text)) = raw {
        assert!(
            observed
                .value()
                .is_some_and(|value| value.as_bytes() == text.as_bytes())
        );
    }
}

fn summary_matches_direct(summary: &ContainerSummary, direct: &Value) {
    assert!(
        direct["Id"]
            .as_str()
            .is_some_and(|id| summary.id.as_bytes() == id.as_bytes())
    );
    assert_eq!(summary.names.origin, Origin::Effective);
    assert_eq!(
        summary.names.availability,
        expected_availability(direct.get("Names"))
    );
    let direct_names = direct["Names"].as_array().expect("direct list names");
    let names = summary.names.value().expect("typed list names");
    assert_eq!(names.len(), direct_names.len());
    assert!(
        direct_names
            .iter()
            .all(|name| name.as_str().is_some_and(|name| names
                .iter()
                .any(|value| value.as_bytes() == name.as_bytes())))
    );
    assert_eq!(summary.labels.origin, Origin::Effective);
    assert_eq!(
        summary.labels.availability,
        expected_availability(direct.get("Labels"))
    );
    let direct_labels = direct["Labels"].as_object().expect("direct list labels");
    let labels = summary.labels.value().expect("typed list labels");
    assert_eq!(labels.len(), direct_labels.len());
    assert!(
        direct_labels
            .iter()
            .all(
                |(key, value)| value
                    .as_str()
                    .is_some_and(|value| labels.iter().any(|label| label.key.as_bytes()
                        == key.as_bytes()
                        && label.value.origin == Origin::Effective
                        && label
                            .value
                            .value()
                            .is_some_and(|item| item.as_bytes() == value.as_bytes())))
            )
    );
    effective_string(&summary.image, direct.get("Image"));
}

#[test]
#[ignore = "requires the isolated native Engine harness"]
fn live_native_selection_and_source_observations() {
    eprintln!("DOCKERLENS_NATIVE_CHECK: source_fixture_oracles");
    let endpoint = Endpoint::unix_socket(PathBuf::from(required("NATIVE_ENGINE_SOCKET")));
    let directory = PathBuf::from(required("NATIVE_CAPTURE_DIR"));
    let selected_id = required("NATIVE_CONTAINER_ID");
    let peer_id = required("NATIVE_PEER_ID");
    let ports_id = required("NATIVE_PORTS_ID");
    let selected_name = required("NATIVE_SELECTED_NAME");
    let peer_name = required("NATIVE_PEER_NAME");
    let ports_name = required("NATIVE_PORTS_NAME");
    let network_id = required("NATIVE_NETWORK_ID");
    let volume_name = required("NATIVE_VOLUME_NAME");
    let fixture_image = required("NATIVE_FIXTURE_IMAGE");
    let mode = required("NATIVE_DAEMON_MODE");
    let oracle_list = direct_json(&directory, "list.json");
    let oracle_container = direct_json(&directory, "container.json");
    let oracle_ports = direct_json(&directory, "ports-container.json");
    let oracle_network = direct_json(&directory, "network.json");
    let oracle_volume = direct_json(&directory, "volume.json");
    assert!(selected_id != peer_id && selected_id != ports_id && peer_id != ports_id);
    assert!(selected_name != peer_name && selected_name != ports_name);
    assert!(oracle_container["Id"].as_str() == Some(selected_id.as_str()));
    assert!(oracle_ports["Id"].as_str() == Some(ports_id.as_str()));
    assert!(oracle_container["Name"].as_str() == Some(format!("/{selected_name}").as_str()));
    assert!(oracle_network["Id"].as_str() == Some(network_id.as_str()));
    assert!(oracle_volume["Name"].as_str() == Some(volume_name.as_str()));
    assert!(oracle_container["Config"]["Image"].as_str() == Some(fixture_image.as_str()));
    assert!(
        oracle_container["Config"]["Labels"]["io.dockerlens.fixture"].as_str() == Some("synthetic")
    );
    let entries = oracle_list.as_array().expect("direct container list array");
    assert_eq!(entries.len(), 3);
    let selected_entry = entries
        .iter()
        .find(|entry| entry["Id"].as_str() == Some(selected_id.as_str()))
        .expect("selected list entry");
    let peer_entry = entries
        .iter()
        .find(|entry| entry["Id"].as_str() == Some(peer_id.as_str()))
        .expect("peer list entry");
    let ports_entry = entries
        .iter()
        .find(|entry| entry["Id"].as_str() == Some(ports_id.as_str()))
        .expect("ports list entry");
    assert!(selected_entry["Names"].as_array().is_some_and(|names| {
        names
            .iter()
            .any(|name| name.as_str() == Some(format!("/{selected_name}").as_str()))
    }));
    assert!(peer_entry["Names"].as_array().is_some_and(|names| {
        names
            .iter()
            .any(|name| name.as_str() == Some(format!("/{peer_name}").as_str()))
    }));
    assert!(peer_entry["Labels"]["io.dockerlens.fixture"].as_str() == Some("decoy"));
    assert!(ports_entry["Labels"]["io.dockerlens.fixture"].as_str() == Some("ports"));
    assert!(selected_entry["Labels"]["com.docker.compose.project"].as_str() == Some("source-app"));
    let prefix = selected_name
        .strip_suffix('x')
        .expect("selected fixture name ends in box");
    assert!(prefix.len() < selected_name.len() && selected_name.starts_with(prefix));
    assert!(!peer_name.starts_with(prefix) && !ports_name.starts_with(prefix));

    eprintln!("DOCKERLENS_NATIVE_CHECK: source_discovery");
    let (discovery, discovered) = capture(&endpoint, Selector::Discovery);
    assert!(discovery.discovery_only());
    assert!(inspected_container_ids(&discovery).is_empty());
    assert!(discovered.containers.is_empty());
    assert!(discovered.selected_roots.is_empty());
    let discovered_ids: HashSet<_> = discovered
        .discovered_containers
        .iter()
        .map(|item| item.id.as_bytes())
        .collect();
    assert_eq!(discovered_ids.len(), 3);
    assert!(
        discovered_ids.contains(selected_id.as_bytes())
            && discovered_ids.contains(peer_id.as_bytes())
            && discovered_ids.contains(ports_id.as_bytes())
    );
    for direct in entries {
        let id = direct["Id"].as_str().expect("direct list ID");
        let summary = discovered
            .discovered_containers
            .iter()
            .find(|summary| summary.id.as_bytes() == id.as_bytes())
            .expect("typed discovery summary");
        summary_matches_direct(summary, direct);
    }
    assert!(!format!("{discovery:?}{discovered:?}").contains("decoy-secret"));

    eprintln!("DOCKERLENS_NATIVE_CHECK: source_narrow_selectors");
    let selectors = [
        (
            Selector::ContainerIds(vec![NativeId::new(selected_id.clone()).unwrap()]),
            SelectionReason::ExactId,
            false,
        ),
        (
            Selector::ContainerNames(vec![NativeId::new(selected_name.clone()).unwrap()]),
            SelectionReason::ExactName,
            true,
        ),
        (
            Selector::NamePrefix(NativeId::new(prefix.to_owned()).unwrap()),
            SelectionReason::NamePrefix,
            true,
        ),
        (
            Selector::Label {
                key: ProtectedValue::new(b"io.dockerlens.fixture".to_vec()),
                value: Some(ProtectedValue::new(b"synthetic".to_vec())),
            },
            SelectionReason::Label,
            true,
        ),
    ];
    for (selector, reason, listed) in selectors {
        let (run, inventory) = capture(&endpoint, selector);
        assert_eq!(run.bounds().selected_resources, 1);
        assert_eq!(run.selected_roots().len(), 1);
        assert_eq!(run.selected_roots()[0].kind, RootKind::Container);
        assert_eq!(run.selected_roots()[0].reason, reason);
        assert_eq!(inventory.containers.len(), 1);
        assert_eq!(
            inspected_container_ids(&run),
            HashSet::from([selected_id.as_str()])
        );
        assert_eq!(
            run.exchanges()
                .iter()
                .filter(|exchange| matches!(exchange.request(), ReadRequest::ListContainers))
                .count(),
            usize::from(listed)
        );
        assert!(!format!("{run:?}{inventory:?}").contains("decoy-secret"));
    }

    eprintln!("DOCKERLENS_NATIVE_CHECK: source_all_and_resource_roots");
    let (all, all_inventory) = capture(&endpoint, Selector::AllContainers);
    assert_eq!(all.bounds().selected_resources, 3);
    assert_eq!(
        inspected_container_ids(&all),
        HashSet::from([selected_id.as_str(), peer_id.as_str(), ports_id.as_str()])
    );
    assert_eq!(all_inventory.containers.len(), 3);
    assert!(
        all.selected_roots()
            .iter()
            .all(|root| root.reason == SelectionReason::ExplicitAll)
    );
    let (network_root, network_inventory) = capture(
        &endpoint,
        Selector::NetworkIds(vec![NativeId::new(network_id.clone()).unwrap()]),
    );
    assert_eq!(network_inventory.networks.len(), 1);
    assert!(network_inventory.containers.is_empty());
    assert_eq!(network_root.selected_roots()[0].kind, RootKind::Network);
    assert_eq!(
        network_root.selected_roots()[0].reason,
        SelectionReason::ExactNetworkId
    );
    assert!(network_root.exchanges().iter().all(|exchange| !matches!(
        exchange.request(),
        ReadRequest::ListContainers | ReadRequest::InspectContainer(_)
    )));
    let (volume_root, volume_inventory) = capture(
        &endpoint,
        Selector::VolumeNames(vec![NativeId::new(volume_name.clone()).unwrap()]),
    );
    assert_eq!(volume_inventory.volumes.len(), 1);
    assert!(volume_inventory.containers.is_empty());
    assert_eq!(volume_root.selected_roots()[0].kind, RootKind::Volume);
    assert_eq!(
        volume_root.selected_roots()[0].reason,
        SelectionReason::ExactVolumeName
    );
    assert!(volume_root.exchanges().iter().all(|exchange| !matches!(
        exchange.request(),
        ReadRequest::ListContainers | ReadRequest::InspectContainer(_)
    )));

    eprintln!("DOCKERLENS_NATIVE_CHECK: source_multiple_bindings");
    let (_, ports_inventory) = capture(
        &endpoint,
        Selector::ContainerIds(vec![NativeId::new(ports_id).unwrap()]),
    );
    assert_eq!(ports_inventory.containers.len(), 1);
    let port_container = &ports_inventory.containers[0];
    assert_eq!(port_container.configured_ports.origin, Origin::Effective);
    let direct_multi = oracle_ports["HostConfig"]["PortBindings"]["8080/tcp"]
        .as_array()
        .expect("direct multiple bindings");
    let typed_multi = port_container
        .configured_ports
        .value()
        .expect("typed ports")
        .iter()
        .find(|port| port.key.container_port == 8080 && port.key.protocol == TransportProtocol::Tcp)
        .expect("typed multiple-binding key")
        .bindings
        .value()
        .expect("typed multiple bindings");
    assert_eq!(direct_multi.len(), 2);
    assert_eq!(typed_multi.len(), 2);
    for (ip, port) in [("127.0.0.1", 18082), ("127.0.0.2", 18083)] {
        assert!(direct_multi.iter().any(|binding| {
            binding["HostIp"].as_str() == Some(ip)
                && binding["HostPort"]
                    .as_str()
                    .and_then(|value| value.parse::<u16>().ok())
                    == Some(port)
        }));
        assert!(typed_multi.iter().any(|binding| {
            binding.host_ip.origin == Origin::Effective
                && binding
                    .host_ip
                    .value()
                    .is_some_and(|value| value.as_bytes() == ip.as_bytes())
                && binding.host_port.value() == Some(&port)
        }));
    }

    eprintln!("DOCKERLENS_NATIVE_CHECK: source_typed_oracle");
    let (_, inventory) = capture(
        &endpoint,
        Selector::ContainerIds(vec![NativeId::new(selected_id).unwrap()]),
    );
    if mode == "rootless" {
        assert_eq!(inventory.version.daemon.mode, DaemonMode::Rootless);
    } else {
        assert_eq!(mode, "rootful");
        assert_ne!(inventory.version.daemon.mode, DaemonMode::Rootless);
    }
    let observed = &inventory.containers[0];
    let config = &oracle_container["Config"];
    let host = &oracle_container["HostConfig"];
    effective_string(&observed.name, oracle_container.get("Name"));
    effective_string(&observed.image, config.get("Image"));
    effective_string(&observed.user, config.get("User"));
    effective_string(&observed.working_directory, config.get("WorkingDir"));
    effective_string(&observed.hostname, config.get("Hostname"));
    effective_string(&observed.runtime.userns_mode, host.get("UsernsMode"));
    effective_string(&observed.runtime.stop_signal, config.get("StopSignal"));
    assert_eq!(observed.runtime.stop_timeout.origin, Origin::Effective);
    assert_eq!(
        observed.runtime.stop_timeout.availability,
        expected_availability(config.get("StopTimeout"))
    );
    assert_eq!(
        observed.runtime.read_only_rootfs.availability,
        expected_availability(host.get("ReadonlyRootfs"))
    );
    assert!(
        observed
            .user
            .value()
            .is_some_and(|value| value.as_bytes() == b"0:0")
    );
    assert!(
        observed
            .working_directory
            .value()
            .is_some_and(|value| value.as_bytes() == b"/tmp")
    );
    assert!(
        observed
            .hostname
            .value()
            .is_some_and(|value| value.as_bytes() == b"dockerlens-native")
    );
    assert_eq!(observed.image_id.origin, Origin::RuntimeAssigned);
    assert_eq!(observed.configured_ports.origin, Origin::Effective);
    assert_eq!(observed.runtime_ports.origin, Origin::RuntimeAssigned);
    assert_eq!(observed.networks.origin, Origin::RuntimeAssigned);
    let network_name = oracle_network["Name"]
        .as_str()
        .expect("direct network name");
    let direct_endpoint = &oracle_container["NetworkSettings"]["Networks"][network_name];
    let attached = observed
        .networks
        .value()
        .expect("runtime network attachment")
        .iter()
        .find(|attachment| attachment.name.as_bytes() == network_name.as_bytes())
        .expect("selected container attached to direct network");
    assert_eq!(attached.ip_address.origin, Origin::RuntimeAssigned);
    assert_eq!(
        attached.ip_address.availability,
        expected_availability(direct_endpoint.get("IPAddress"))
    );
    assert_eq!(observed.runtime.memory_bytes.origin, Origin::Effective);
    assert_eq!(
        observed.runtime.memory_bytes.availability,
        expected_availability(host.get("Memory"))
    );
    let ports = observed.configured_ports.value().expect("configured ports");
    for (internal, protocol, published) in [
        (8080, TransportProtocol::Tcp, 18080),
        (8081, TransportProtocol::Udp, 18081),
    ] {
        let port = ports
            .iter()
            .find(|port| port.key.container_port == internal && port.key.protocol == protocol)
            .expect("fixed CLI port");
        assert!(port.bindings.value().is_some_and(|bindings| {
            bindings
                .iter()
                .any(|binding| binding.host_port.value() == Some(&published))
        }));
        let key = format!(
            "{internal}/{}",
            if protocol == TransportProtocol::Tcp {
                "tcp"
            } else {
                "udp"
            }
        );
        let direct_bindings = host["PortBindings"][key.as_str()]
            .as_array()
            .expect("direct configured bindings");
        let typed_bindings = port.bindings.value().expect("typed configured bindings");
        assert_eq!(typed_bindings.len(), direct_bindings.len());
        for direct in direct_bindings {
            let direct_ip = direct.get("HostIp").and_then(Value::as_str);
            let direct_port = direct["HostPort"]
                .as_str()
                .and_then(|value| value.parse::<u16>().ok())
                .expect("direct binding host port");
            assert!(typed_bindings.iter().any(|binding| {
                binding.host_ip.origin == Origin::Effective
                    && binding.host_ip.availability == expected_availability(direct.get("HostIp"))
                    && match direct_ip {
                        Some(ip) => binding
                            .host_ip
                            .value()
                            .is_some_and(|value| value.as_bytes() == ip.as_bytes()),
                        None => binding.host_ip.value().is_none(),
                    }
                    && binding.host_port.value() == Some(&direct_port)
            }));
        }
        assert!(direct_bindings.iter().any(|binding| {
            binding["HostPort"]
                .as_str()
                .and_then(|value| value.parse::<u16>().ok())
                == Some(published)
        }));
    }
    let mounts = observed.mounts.value().expect("native mounts");
    let direct_mounts = oracle_container["Mounts"]
        .as_array()
        .expect("direct native mounts");
    assert!(
        direct_mounts
            .iter()
            .any(|mount| mount["Type"].as_str() == Some("volume")
                && mount["Name"].as_str() == Some(volume_name.as_str())
                && mount["Destination"].as_str() == Some("/data")
                && mount["RW"].as_bool() == Some(true))
    );
    assert!(
        direct_mounts
            .iter()
            .any(|mount| mount["Type"].as_str() == Some("bind")
                && mount["Destination"].as_str() == Some("/readonly")
                && mount["RW"].as_bool() == Some(false))
    );
    assert!(mounts.iter().any(|mount| {
        mount.kind == MountKind::Volume
            && mount
                .name
                .value()
                .is_some_and(|name| name.as_bytes() == volume_name.as_bytes())
            && mount.read_write.value() == Some(&true)
    }));
    assert!(mounts.iter().any(|mount| {
        mount.kind == MountKind::Bind
            && mount
                .destination
                .value()
                .is_some_and(|path| path.as_bytes() == b"/readonly")
            && mount.read_write.value() == Some(&false)
    }));
    assert!(config["Env"].as_array().is_some_and(|env| {
        env.iter()
            .any(|entry| entry.as_str() == Some("DL_CONFORMANCE=synthetic-secret"))
    }));
    assert!(
        observed
            .environment
            .value()
            .is_some_and(|env| env
                .iter()
                .any(|entry| entry.name.as_bytes() == b"DL_CONFORMANCE"
                    && entry
                        .value
                        .as_ref()
                        .is_some_and(|value| value.as_bytes() == b"synthetic-secret")))
    );
    assert!(
        observed
            .labels
            .value()
            .is_some_and(|labels| labels.iter().any(|label| label.key.as_bytes()
                == b"io.dockerlens.fixture"
                && label
                    .value
                    .value()
                    .is_some_and(|value| value.as_bytes() == b"synthetic")))
    );
    assert!(
        matches!(observed.entrypoint.value(), Some(CommandValue::Exec(parts))
        if parts.len() == 1 && parts[0].as_bytes() == b"/bin/sh")
    );
    assert!(
        matches!(observed.command.value(), Some(CommandValue::Exec(parts))
        if parts.len() == 2 && parts[0].as_bytes() == b"-c")
    );
    assert!(
        config["Healthcheck"]["Test"]
            .as_array()
            .is_some_and(|test| test.len() == 2
                && test[0].as_str() == Some("CMD-SHELL")
                && test[1].as_str() == Some("true"))
    );
    assert!(
        matches!(observed.healthcheck.value().and_then(|health| health.test.value()),
        Some(HealthcheckTest::CmdShell(value)) if value.as_bytes() == b"true")
    );
    assert!(host["RestartPolicy"]["Name"].as_str() == Some("on-failure"));
    assert!(host["RestartPolicy"]["MaximumRetryCount"].as_u64() == Some(3));
    let restart = observed
        .restart_policy
        .value()
        .expect("native restart policy");
    assert!(
        restart
            .name
            .value()
            .is_some_and(|name| name.as_bytes() == b"on-failure")
    );
    assert_eq!(restart.maximum_retry_count.value(), Some(&3));
    assert_eq!(inventory.networks.len(), 1);
    assert_eq!(inventory.volumes.len(), 1);
    assert!(inventory.networks[0].name.value().is_some_and(|value| {
        oracle_network["Name"]
            .as_str()
            .is_some_and(|name| value.as_bytes() == name.as_bytes())
    }));
    assert!(
        inventory.volumes[0]
            .name
            .value()
            .is_some_and(|value| value.as_bytes() == volume_name.as_bytes())
    );

    let source_path = PathBuf::from(required("NATIVE_SOURCE_PROBES_PATH"));
    assert_eq!(source_path.parent(), Some(directory.as_path()));
    fs::write(source_path, serde_json::to_vec(&SOURCE_PROBES).unwrap())
        .expect("private source evidence write");
}
