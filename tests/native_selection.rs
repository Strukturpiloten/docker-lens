//! Independent live source probes in the isolated four-lane Engine harness.
//! The harness supplies CLI-created fixtures and direct GET responses as oracles.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
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

fn canonical_container_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn membership_run_id() -> String {
    let outer = required("NATIVE_OUTER_CONTAINER");
    let run_id = outer
        .strip_prefix("dl-native-")
        .expect("task-owned outer container name");
    assert!(
        !run_id.is_empty()
            && run_id.len() <= 32
            && run_id.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "bounded native run ID"
    );
    run_id.to_owned()
}

// Both pipes and elapsed time are bounded; no native CLI output enters a panic.
fn bounded_output(command: &mut Command) -> (bool, Vec<u8>) {
    const MAX_OUTPUT: u64 = 1024 * 1024;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("native membership command available");
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .expect("private command stdout")
        .take(MAX_OUTPUT + 1)
        .read_to_end(&mut output)
        .expect("bounded private command stdout");
    if output.len() as u64 > MAX_OUTPUT {
        let _ = child.kill();
        let _ = child.wait();
        panic!("native membership command exceeded output budget");
    }
    let status = child.wait().expect("bounded native membership command");
    (status.success(), output)
}

fn membership_cli(args: &[&str]) -> (bool, Vec<u8>) {
    let mut command = Command::new("timeout");
    command.args(["--kill-after=1s", "20s"]);
    match required("NATIVE_PODMAN_USE_SUDO").as_str() {
        "1" => {
            command.args(["sudo", "-n", "podman"]);
        }
        "0" => {
            command.arg("podman");
        }
        _ => panic!("invalid native Podman privilege mode"),
    }
    command.args([
        "exec",
        &required("NATIVE_OUTER_CONTAINER"),
        "docker",
        "-H",
        "unix:///dockerlens-native/docker.sock",
    ]);
    bounded_output(command.args(args))
}

fn membership_cli_ok(args: &[&str]) -> Vec<u8> {
    let (success, output) = membership_cli(args);
    assert!(success, "isolated native membership CLI failed");
    output
}

fn direct_network_membership(socket: &Path, api: &str, network_id: &str) -> Value {
    let mut command = Command::new("timeout");
    command.args(["--kill-after=1s", "18s", "curl", "-fsS", "--max-time", "15"]);
    command.arg("--unix-socket").arg(socket);
    command.arg(format!("http://localhost/v{api}/networks/{network_id}"));
    let (success, body) = bounded_output(&mut command);
    assert!(success, "bounded direct network GET failed");
    let direct: Value = serde_json::from_slice(&body).expect("direct network GET is JSON");
    assert!(
        direct["Id"].as_str() == Some(network_id),
        "direct network identity changed"
    );
    direct
}

fn membership_matches_direct(inventory: &DecodedInventory, direct: &Value) -> HashSet<String> {
    assert_eq!(inventory.networks.len(), 1);
    let network = &inventory.networks[0];
    assert_eq!(network.id.origin, Origin::RuntimeAssigned);
    assert!(network.id.value().is_some_and(|id| {
        direct["Id"]
            .as_str()
            .is_some_and(|raw| id.as_bytes() == raw.as_bytes())
    }));
    assert_eq!(network.active_endpoints.origin, Origin::RuntimeAssigned);
    let raw = direct.get("Containers");
    let expected = match raw {
        None => Availability::Missing,
        Some(Value::Null) => Availability::Null,
        Some(Value::Object(entries)) if entries.is_empty() => Availability::Empty,
        Some(Value::Object(_)) => Availability::Present,
        _ => panic!("direct network membership has unexpected shape"),
    };
    assert_eq!(network.active_endpoints.availability, expected);
    let entries = network.active_endpoints.value();
    let raw_entries = raw.and_then(Value::as_object);
    match (entries, raw_entries) {
        (None, None) => HashSet::new(),
        (Some(entries), Some(raw_entries)) => {
            assert_eq!(entries.len(), raw_entries.len());
            let mut ids = HashSet::new();
            for entry in entries {
                assert_eq!(entry.container_id.origin, Origin::RuntimeAssigned);
                assert_eq!(entry.container_id.availability, Availability::Present);
                let id = entry.container_id.value().expect("active member ID");
                assert!(canonical_container_id(
                    std::str::from_utf8(id.as_bytes()).expect("ASCII native member ID")
                ));
                let raw_entry = raw_entries
                    .iter()
                    .find(|(key, _)| id.as_bytes() == key.as_bytes())
                    .map(|(_, value)| value)
                    .expect("typed member matches direct map key");
                assert_eq!(entry.endpoint.origin, Origin::RuntimeAssigned);
                match raw_entry {
                    Value::Null => {
                        assert_eq!(entry.endpoint.availability, Availability::Null);
                        assert!(entry.endpoint.value().is_none());
                    }
                    Value::Object(details) => {
                        assert_eq!(
                            entry.endpoint.availability,
                            if details.is_empty() {
                                Availability::Empty
                            } else {
                                Availability::Present
                            }
                        );
                        effective_string(
                            &entry.endpoint.value().expect("typed endpoint").name,
                            details.get("Name"),
                        );
                    }
                    _ => panic!("direct endpoint has unexpected shape"),
                }
                ids.insert(String::from_utf8(id.as_bytes().to_vec()).expect("ASCII native ID"));
            }
            assert_eq!(ids.len(), raw_entries.len());
            ids
        }
        _ => panic!("typed and direct membership availability differ"),
    }
}

struct MembershipFixtures {
    run_id: String,
    names: [String; 2],
    cleaned: bool,
}

impl MembershipFixtures {
    fn new(run_id: String) -> Self {
        let names = [
            format!("dl-{run_id}-membership-selected"),
            format!("dl-{run_id}-membership-peer"),
        ];
        for name in &names {
            assert!(
                Self::listed_ids(name).is_empty(),
                "native fixture name is occupied"
            );
        }
        Self {
            run_id,
            names,
            cleaned: false,
        }
    }

    fn listed_ids(name: &str) -> Vec<String> {
        let filter = format!("name=^/{name}$");
        let output =
            membership_cli_ok(&["container", "ls", "-aq", "--no-trunc", "--filter", &filter]);
        let text = std::str::from_utf8(&output).expect("ASCII native container IDs");
        text.lines()
            .map(|id| {
                assert!(canonical_container_id(id), "canonical native container ID");
                id.to_owned()
            })
            .collect()
    }

    fn cleanup(&mut self) -> Result<(), &'static str> {
        let mut success = true;
        for name in &self.names {
            if !matches!(
                std::panic::catch_unwind(|| self.cleanup_one(name)),
                Ok(true)
            ) {
                success = false;
            }
        }
        self.cleaned = success;
        if success {
            Ok(())
        } else {
            Err("native membership fixture cleanup unverified")
        }
    }

    fn cleanup_one(&self, name: &str) -> bool {
        let ids = Self::listed_ids(name);
        if ids.is_empty() {
            return true;
        }
        if ids.len() != 1 {
            return false;
        }
        let identity = membership_cli_ok(&[
            "container",
            "inspect",
            "--format",
            "{{.Name}}|{{index .Config.Labels \"io.dockerlens.native-run\"}}",
            name,
        ]);
        let expected = format!("/{name}|{}\n", self.run_id);
        if identity != expected.as_bytes() {
            return false;
        }
        let (removed, _) = membership_cli(&["container", "rm", "-f", name]);
        let absent = Self::listed_ids(name).is_empty();
        removed && absent
    }
}

impl Drop for MembershipFixtures {
    fn drop(&mut self) {
        if !self.cleaned
            && !matches!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup())),
                Ok(Ok(()))
            )
        {
            // A concurrent assertion panic still reaches here. Keep the diagnostic
            // closed and leave exact names for the harness operator's readback.
            eprintln!("DOCKERLENS_NATIVE_CHECK: membership_cleanup_unverified");
            if !std::thread::panicking() {
                panic!("native membership fixture cleanup unverified");
            }
        }
    }
}

#[test]
#[ignore = "requires the isolated native Engine harness"]
fn live_network_membership_matches_engine() {
    eprintln!("DOCKERLENS_NATIVE_CHECK: source_network_membership");
    let directory = PathBuf::from(required("NATIVE_CAPTURE_DIR"));
    let socket = PathBuf::from(required("NATIVE_ENGINE_SOCKET"));
    let api = required("NATIVE_API_VERSION");
    assert!(
        api.split_once('.').is_some_and(|(major, minor)| {
            !major.is_empty()
                && !minor.is_empty()
                && major.bytes().all(|byte| byte.is_ascii_digit())
                && minor.bytes().all(|byte| byte.is_ascii_digit())
        }),
        "bounded native API version"
    );
    let network_id = required("NATIVE_NETWORK_ID");
    assert!(
        canonical_container_id(&network_id),
        "canonical native network ID"
    );
    let endpoint = Endpoint::unix_socket(socket.clone());
    let image = required("NATIVE_FIXTURE_IMAGE");
    let mut fixtures = MembershipFixtures::new(membership_run_id());
    let label = format!("io.dockerlens.native-run={}", fixtures.run_id);

    let mut ids = Vec::new();
    for name in &fixtures.names {
        let created = membership_cli_ok(&[
            "container",
            "create",
            "--name",
            name,
            "--label",
            &label,
            "--network",
            &network_id,
            &image,
            "sleep",
            "900",
        ]);
        let id = std::str::from_utf8(&created)
            .expect("ASCII native create ID")
            .trim();
        assert!(canonical_container_id(id), "canonical native create ID");
        ids.push(id.to_owned());
        membership_cli_ok(&["container", "start", name]);
        assert!(
            membership_cli_ok(&[
                "container",
                "inspect",
                "--format",
                "{{.State.Running}}",
                name
            ]) == b"true\n",
            "native membership fixture did not start"
        );
    }
    assert!(ids[0] != ids[1], "native membership fixture IDs differ");
    let selected_id = &ids[0];
    let peer_id = &ids[1];

    let direct_active_before = direct_network_membership(&socket, &api, &network_id);
    let direct_active_members = direct_active_before["Containers"]
        .as_object()
        .expect("direct active endpoint map");
    assert!(
        direct_active_members.contains_key(selected_id)
            && direct_active_members.contains_key(peer_id),
        "both running fixtures must be direct active members"
    );
    let (active_capture, active_inventory) = capture(
        &endpoint,
        Selector::ContainerIds(vec![NativeId::new(selected_id.clone()).unwrap()]),
    );
    let direct_active_after = direct_network_membership(&socket, &api, &network_id);
    assert!(
        direct_active_before.get("Containers") == direct_active_after.get("Containers"),
        "direct active membership changed during acquisition"
    );
    assert!(
        inspected_container_ids(&active_capture) == HashSet::from([selected_id.as_str()]),
        "active acquisition inspected outside exact selected root"
    );
    assert_eq!(active_inventory.containers.len(), 1);
    assert!(
        active_inventory.containers[0]
            .name
            .value()
            .is_some_and(|name| {
                name.as_bytes() == format!("/{}", fixtures.names[0]).as_bytes()
            })
    );
    let active_ids = membership_matches_direct(&active_inventory, &direct_active_before);
    assert!(active_ids.contains(selected_id) && active_ids.contains(peer_id));

    membership_cli_ok(&["container", "stop", "-t", "2", &fixtures.names[1]]);
    assert!(
        membership_cli_ok(&[
            "container",
            "inspect",
            "--format",
            "{{.State.Running}}",
            &fixtures.names[1],
        ]) == b"false\n",
        "native membership peer did not stop"
    );
    let direct_stopped_before = direct_network_membership(&socket, &api, &network_id);
    let (stopped_capture, stopped_inventory) = capture(
        &endpoint,
        Selector::ContainerIds(vec![NativeId::new(selected_id.clone()).unwrap()]),
    );
    let direct_stopped_after = direct_network_membership(&socket, &api, &network_id);
    assert!(
        direct_stopped_before.get("Containers") == direct_stopped_after.get("Containers"),
        "direct stopped-boundary membership changed during acquisition"
    );
    assert!(
        inspected_container_ids(&stopped_capture) == HashSet::from([selected_id.as_str()]),
        "stopped-boundary acquisition inspected outside exact selected root"
    );
    assert_eq!(stopped_inventory.containers.len(), 1);
    let stopped_ids = membership_matches_direct(&stopped_inventory, &direct_stopped_before);
    assert!(
        stopped_ids.contains(selected_id),
        "selected fixture remains active"
    );
    // The peer's stopped-state membership is read from this Engine response;
    // no historical or cross-lane assumption decides whether its key remains.
    fixtures
        .cleanup()
        .expect("exact membership fixture cleanup");
    append_membership_probes(&directory);
}

fn append_membership_probes(directory: &Path) {
    let source_path = PathBuf::from(required("NATIVE_SOURCE_PROBES_PATH"));
    assert!(
        source_path.parent() == Some(directory),
        "private probe path changed"
    );
    let metadata = fs::symlink_metadata(&source_path).expect("private source probes exist");
    assert!(metadata.file_type().is_file() && metadata.len() <= 4096);
    let mut existing = Vec::new();
    fs::File::open(&source_path)
        .expect("private source probes readable")
        .take(4097)
        .read_to_end(&mut existing)
        .expect("bounded private source probes");
    assert_eq!(existing.len() as u64, metadata.len());
    let probes: Vec<String> =
        serde_json::from_slice(&existing).expect("private source probes JSON");
    assert!(
        probes.iter().map(String::as_str).eq(SOURCE_PROBES),
        "existing source probes differ from the baseline"
    );
    let mut completed = SOURCE_PROBES.to_vec();
    completed.extend([
        "NetworkActiveMembership",
        "NetworkStoppedMembershipBoundary",
        "ContainerInspectIdOracle",
    ]);
    fs::write(source_path, serde_json::to_vec(&completed).unwrap())
        .expect("private membership source evidence write");
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
        let inspected_id = run
            .exchanges()
            .iter()
            .find_map(|exchange| match exchange.request() {
                ReadRequest::InspectContainer(id) => Some(id.as_str()),
                _ => None,
            })
            .expect("narrow selection inspects the canonical container ID");
        let observed_id = &inventory.containers[0].id;
        assert_eq!(observed_id.origin, Origin::RuntimeAssigned);
        assert_eq!(observed_id.availability, Availability::Present);
        assert!(canonical_container_id(inspected_id));
        assert_eq!(
            observed_id.value().unwrap().as_bytes(),
            inspected_id.as_bytes()
        );
        assert_eq!(
            observed_id.value().unwrap().as_bytes(),
            oracle_container["Id"]
                .as_str()
                .expect("direct inspect ID")
                .as_bytes()
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
    assert_eq!(inventory.networks[0].id.origin, Origin::RuntimeAssigned);
    assert_eq!(inventory.networks[0].id.availability, Availability::Present);
    assert!(inventory.networks[0].id.value().is_some_and(|value| {
        oracle_network["Id"]
            .as_str()
            .is_some_and(|id| value.as_bytes() == id.as_bytes())
    }));
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
