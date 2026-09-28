//! Test-only network executor. Product rendering remains inert and catalog admission unchanged.

use std::fs;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use serde_json::{Value, json};

use crate::acquisition::{Endpoint, Limits, NativeId, Selector, acquire};
use crate::decoder::decode_capture;
use crate::observation::ResourceRef;
use crate::target::{
    Argument, BridgeOption, ContainerIntent, ContainerSettings, DockerApiRenderer, DockerPlanner,
    ImageCommand, ImageReference, IntentError, NetworkAddress, NetworkAlias,
    NetworkAttachmentIntent, NetworkAuxAddress, NetworkCreate, NetworkDriver, NetworkIntent,
    NetworkIpam, NetworkIpamDriver, NetworkIpamPool, NetworkLabel, NetworkRole, NetworkSource,
    NetworkSubnet, Planner, PlanningError, Renderer, TargetIdentity, TargetIntent, TargetResource,
};
use crate::version::{
    Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonMode, FactProvenance,
    ValidatedCapabilities,
};

const PROBES: [&str; 19] = [
    "ExternalNetworkReference",
    "InternalBridgeNetworkCreate",
    "Ipv6BridgeNetworkCreate",
    "NetworkIpamV4",
    "NetworkIpamV6",
    "NetworkIpamGateway",
    "NetworkIpamRange",
    "NetworkIpamAuxiliary",
    "NetworkIpamDefaultDriver",
    "NetworkBridgeMtu",
    "NetworkBridgeIcc",
    "NetworkBridgeMasquerade",
    "NetworkBridgeHostBindingIp",
    "NetworkCreateLabels",
    "NetworkPrimaryAliases",
    "NetworkSecondaryAliases",
    "NetworkStaticIpv4",
    "NetworkStaticIpv6",
    "NetworkSecondaryConnect",
];

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("native harness must supply {name}"))
}

fn run_id() -> String {
    let outer = required("NATIVE_OUTER_CONTAINER");
    validated_run_id(&outer)
        .expect("task-owned outer container")
        .to_owned()
}

fn validated_run_id(outer: &str) -> Option<&str> {
    let id = outer.strip_prefix("dl-native-")?;
    (!id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
    .then_some(id)
}

fn addr(text: &str) -> NetworkAddress {
    NetworkAddress::new(text).expect("fixed test address")
}

fn subnet(text: &str, prefix: u8) -> NetworkSubnet {
    NetworkSubnet::new(addr(text), prefix).expect("fixed test subnet")
}

fn alias(text: &str) -> NetworkAlias {
    NetworkAlias::new(text.as_bytes().to_vec()).expect("fixed test alias")
}

fn identity(text: &str) -> TargetIdentity {
    TargetIdentity::new(text.as_bytes().to_vec()).expect("fixed test identity")
}

fn cli(args: &[&str]) -> (bool, Vec<u8>) {
    let mut command = Command::new("timeout");
    command.arg("45");
    if required("NATIVE_PODMAN_USE_SUDO") == "1" {
        command.args(["sudo", "-n", "podman"]);
    } else {
        command.arg("podman");
    }
    command.args([
        "exec",
        &required("NATIVE_OUTER_CONTAINER"),
        "docker",
        "-H",
        "unix:///dockerlens-native/docker.sock",
    ]);
    command.args(args).stderr(Stdio::null());
    let output = command.output().expect("isolated Docker CLI available");
    (output.status.success(), output.stdout)
}

fn cli_ok(args: &[&str]) -> Vec<u8> {
    let (success, output) = cli(args);
    assert!(success, "independent isolated Docker CLI probe failed");
    output
}

struct BoundedDnsCliOutput {
    success: bool,
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    output_limit: bool,
}

fn bounded_dns_stream<R: Read>(reader: R) -> (Vec<u8>, bool) {
    const LIMIT: usize = 8192;
    let mut bytes = Vec::new();
    reader
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .expect("bounded private DNS stream");
    let exceeded = bytes.len() > LIMIT;
    bytes.truncate(LIMIT);
    (bytes, exceeded)
}

fn cli_dns(args: &[&str]) -> BoundedDnsCliOutput {
    let mut command = Command::new("timeout");
    // Four DNS commands and four three-second state reads plus conditional
    // pauses sum to under 45 seconds of configured timeout within the exact
    // native test's 180-second budget.
    command.arg("8");
    if required("NATIVE_PODMAN_USE_SUDO") == "1" {
        command.args(["sudo", "-n", "podman"]);
    } else {
        command.arg("podman");
    }
    command.args([
        "exec",
        &required("NATIVE_OUTER_CONTAINER"),
        "docker",
        "-H",
        "unix:///dockerlens-native/docker.sock",
    ]);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("isolated DNS CLI available");
    let stdout = child.stdout.take().expect("private DNS stdout");
    let stderr = child.stderr.take().expect("private DNS stderr");
    let stdout_reader = std::thread::spawn(move || bounded_dns_stream(stdout));
    let stderr_reader = std::thread::spawn(move || bounded_dns_stream(stderr));
    let status = child.wait().expect("bounded isolated DNS CLI");
    let (stdout, stdout_limit) = stdout_reader.join().expect("private DNS stdout reader");
    let (stderr, stderr_limit) = stderr_reader.join().expect("private DNS stderr reader");
    BoundedDnsCliOutput {
        success: status.success(),
        code: status.code(),
        stdout,
        stderr,
        output_limit: stdout_limit || stderr_limit,
    }
}

fn dns_failure_category(
    result: &BoundedDnsCliOutput,
    alias: &str,
    expected: Ipv4Addr,
) -> &'static str {
    if result.output_limit {
        return "output_limit";
    }
    if !result.success {
        if result.code == Some(124) {
            return "cli_timeout";
        }
        if result.code == Some(125) {
            return "cli_docker";
        }
        if matches!(result.code, Some(126 | 127)) {
            return "cli_exec";
        }
        let private = [&result.stdout[..], &result.stderr[..]].concat();
        let message = String::from_utf8_lossy(&private).to_ascii_lowercase();
        if message.contains("error response from daemon") || message.contains("no such container") {
            return "cli_docker";
        }
        match named_dns_answer_category(&result.stdout, alias, expected) {
            "answer_inconsistent" => return "cli_answer_present",
            "answer_wrong_ip" => return "answer_wrong_ip",
            "answer_malformed" => return "answer_malformed",
            _ => {}
        }
        if message.contains("no servers could be reached")
            || message.contains("connection timed out")
        {
            return "cli_resolver";
        }
        if message.contains("can't resolve")
            || message.contains("server can't find")
            || message.contains("nxdomain")
        {
            return "cli_lookup";
        }
        return "cli_unclassified";
    }
    named_dns_answer_category(&result.stdout, alias, expected)
}

fn named_dns_answer_category(output: &[u8], alias: &str, expected: Ipv4Addr) -> &'static str {
    let Ok(output) = std::str::from_utf8(output) else {
        return "answer_malformed";
    };
    let mut named_answer = false;
    let mut matching_name = false;
    let mut address_seen = false;
    let mut ipv4_seen = false;
    for line in output.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("Name:") {
            named_answer = name.trim().trim_end_matches('.') == alias;
            matching_name |= named_answer;
            continue;
        }
        if !named_answer {
            continue;
        }
        let address = line.strip_prefix("Address:").or_else(|| {
            line.strip_prefix("Address ")
                .and_then(|numbered| numbered.split_once(':').map(|(_, value)| value))
        });
        if let Some(address) = address {
            address_seen = true;
            if let Some(Ok(address)) = address
                .split_whitespace()
                .next()
                .map(str::parse::<Ipv4Addr>)
            {
                ipv4_seen = true;
                if address == expected {
                    return "answer_inconsistent";
                }
            }
        }
    }
    if !matching_name {
        "alias_missing"
    } else if !address_seen {
        "answer_missing"
    } else if ipv4_seen {
        "answer_wrong_ip"
    } else {
        "answer_malformed"
    }
}

fn wait_for_exact_dns_answer<P, R, W>(
    alias: &str,
    expected: Ipv4Addr,
    attempts: usize,
    mut probe: P,
    mut still_running: R,
    mut wait: W,
) -> Result<(), &'static str>
where
    P: FnMut() -> BoundedDnsCliOutput,
    R: FnMut() -> bool,
    W: FnMut(),
{
    assert!(attempts > 0, "DNS readiness budget must be nonzero");
    for attempt in 0..attempts {
        let result = probe();
        if result.success && nslookup_has_ipv4_answer(&result.stdout, alias, expected) {
            return Ok(());
        }
        let category = dns_failure_category(&result, alias, expected);
        // A newly started endpoint may not yet have its A record. No other
        // error is retried, and every success requires the exact inspected IP.
        if category != "cli_lookup" {
            return Err(category);
        }
        if !still_running() {
            return Err("fixture_exited");
        }
        if attempt + 1 == attempts {
            return Err("readiness_exhausted");
        }
        wait();
    }
    unreachable!("nonzero DNS readiness budget")
}

fn nslookup_has_ipv4_answer(output: &[u8], alias: &str, expected: Ipv4Addr) -> bool {
    let Ok(output) = std::str::from_utf8(output) else {
        return false;
    };
    let mut named_answer = false;
    for line in output.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("Name:") {
            named_answer = name.trim().trim_end_matches('.') == alias;
            continue;
        }
        if !named_answer {
            continue;
        }
        let address = line.strip_prefix("Address:").or_else(|| {
            line.strip_prefix("Address ")
                .and_then(|numbered| numbered.split_once(':').map(|(_, value)| value))
        });
        if address
            .and_then(|value| value.split_whitespace().next())
            .and_then(|token| token.parse::<Ipv4Addr>().ok())
            == Some(expected)
        {
            return true;
        }
    }
    false
}

#[test]
fn nslookup_ipv4_answer_requires_exact_named_address_not_prefix_or_resolver() {
    let answer = b"Server: 127.0.0.11\nAddress: 127.0.0.11:53\n\nName: edge-sentinel\nAddress: 172.29.244.20\n";
    assert!(nslookup_has_ipv4_answer(
        answer,
        "edge-sentinel",
        Ipv4Addr::new(172, 29, 244, 20)
    ));
    assert!(!nslookup_has_ipv4_answer(
        answer,
        "edge-sentinel",
        Ipv4Addr::new(172, 29, 244, 2)
    ));
    assert!(!nslookup_has_ipv4_answer(
        answer,
        "edge-sentinel",
        Ipv4Addr::new(127, 0, 0, 11)
    ));
    assert!(!nslookup_has_ipv4_answer(
        answer,
        "other-alias",
        Ipv4Addr::new(172, 29, 244, 20)
    ));
    assert!(nslookup_has_ipv4_answer(
        b"Name: backend-app.\nAddress 1: 172.29.244.130 backend-app\n",
        "backend-app",
        Ipv4Addr::new(172, 29, 244, 130)
    ));
}

#[test]
fn edge_dns_failure_categories_are_closed_and_value_free() {
    let expected = Ipv4Addr::new(172, 29, 244, 2);
    let mut result = BoundedDnsCliOutput {
        success: false,
        code: Some(1),
        stdout: b"can't resolve private-value".to_vec(),
        stderr: Vec::new(),
        output_limit: false,
    };
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "cli_lookup"
    );
    result.stdout = b"Name: edge-sentinel\nAddress: 172.29.244.2\n".to_vec();
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "cli_answer_present"
    );
    result.stdout.clear();
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "cli_unclassified"
    );
    result.code = Some(125);
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "cli_docker"
    );
    result.code = Some(127);
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "cli_exec"
    );
    result.code = Some(124);
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "cli_timeout"
    );
    result.success = true;
    result.code = Some(0);
    result.stdout = b"Server: 172.29.244.2\nAddress: 172.29.244.2\n".to_vec();
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "alias_missing"
    );
    result.stdout = b"Name: edge-sentinel\n".to_vec();
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "answer_missing"
    );
    result.stdout = b"Name: edge-sentinel\nAddress: 172.29.244.20\n".to_vec();
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "answer_wrong_ip"
    );
    result.stdout = b"Name: edge-sentinel\nAddress: not-an-ip\n".to_vec();
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "answer_malformed"
    );
    result.success = false;
    result.code = Some(1);
    result.stdout = b"Name: edge-sentinel\nAddress: 172.29.244.20\ncan't resolve\n".to_vec();
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "answer_wrong_ip"
    );
    result.stdout = b"Name: edge-sentinel\nAddress: not-an-ip\ncan't resolve\n".to_vec();
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "answer_malformed"
    );
    result.stdout = b"can't resolve\n".to_vec();
    result.stderr = b"Error response from daemon".to_vec();
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "cli_docker"
    );
    result.output_limit = true;
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "output_limit"
    );
}

#[test]
fn exact_dns_readiness_retries_only_transient_lookup_with_finite_budget() {
    let expected = Ipv4Addr::new(172, 29, 244, 2);
    let synthetic = |success: bool, stdout: &[u8]| BoundedDnsCliOutput {
        success,
        code: Some(if success { 0 } else { 1 }),
        stdout: stdout.to_vec(),
        stderr: Vec::new(),
        output_limit: false,
    };
    let probes = std::cell::Cell::new(0);
    let pauses = std::cell::Cell::new(0);
    let outcome = wait_for_exact_dns_answer(
        "edge-sentinel",
        expected,
        4,
        || {
            probes.set(probes.get() + 1);
            if probes.get() == 1 {
                synthetic(false, b"can't resolve edge-sentinel")
            } else {
                synthetic(true, b"Name: edge-sentinel\nAddress: 172.29.244.2\n")
            }
        },
        || true,
        || pauses.set(pauses.get() + 1),
    );
    assert_eq!(outcome, Ok(()));
    assert_eq!(probes.get(), 2);
    assert_eq!(pauses.get(), 1);

    probes.set(0);
    pauses.set(0);
    let exhausted = wait_for_exact_dns_answer(
        "edge-sentinel",
        expected,
        2,
        || {
            probes.set(probes.get() + 1);
            synthetic(false, b"can't resolve edge-sentinel")
        },
        || true,
        || pauses.set(pauses.get() + 1),
    );
    assert_eq!(exhausted, Err("readiness_exhausted"));
    assert_eq!(probes.get(), 2);
    assert_eq!(pauses.get(), 1);

    probes.set(0);
    pauses.set(0);
    let wrong = wait_for_exact_dns_answer(
        "edge-sentinel",
        expected,
        4,
        || {
            probes.set(probes.get() + 1);
            synthetic(true, b"Name: edge-sentinel\nAddress: 172.29.244.20\n")
        },
        || true,
        || pauses.set(pauses.get() + 1),
    );
    assert_eq!(wrong, Err("answer_wrong_ip"));
    assert_eq!(probes.get(), 1);
    assert_eq!(pauses.get(), 0);

    probes.set(0);
    let mixed_wrong = wait_for_exact_dns_answer(
        "edge-sentinel",
        expected,
        4,
        || {
            probes.set(probes.get() + 1);
            synthetic(
                false,
                b"Name: edge-sentinel\nAddress: 172.29.244.20\ncan't resolve\n",
            )
        },
        || true,
        || panic!("mixed wrong answer must not be retried"),
    );
    assert_eq!(mixed_wrong, Err("answer_wrong_ip"));
    assert_eq!(probes.get(), 1);

    probes.set(0);
    let exited = wait_for_exact_dns_answer(
        "edge-sentinel",
        expected,
        4,
        || {
            probes.set(probes.get() + 1);
            synthetic(false, b"can't resolve edge-sentinel")
        },
        || false,
        || panic!("exited fixture must not be retried"),
    );
    assert_eq!(exited, Err("fixture_exited"));
    assert_eq!(probes.get(), 1);
}

fn expected_post_bodies(run_id: &str, image: &str) -> [Value; 5] {
    let backend = format!("dl-network-{run_id}-backend");
    let edge = format!("dl-network-{run_id}-edge");
    let app = format!("dl-network-{run_id}-app");
    let mut endpoints = serde_json::Map::new();
    endpoints.insert(
        backend.clone(),
        json!({
            "Aliases": ["backend-app"],
            "IPAMConfig": {"IPv4Address": "172.29.244.130", "IPv6Address": "fd00:dead:beef:31::10"},
        }),
    );
    [
        json!({
            "Name": backend.as_str(), "Driver": "bridge", "Internal": true, "EnableIPv6": true,
            "IPAM": {"Driver": "default", "Config": [
                {"Subnet": "172.29.244.0/24", "IPRange": "172.29.244.128/25",
                 "Gateway": "172.29.244.1", "AuxiliaryAddresses": {"reserved": "172.29.244.2"}},
                {"Subnet": "fd00:dead:beef:31::/64", "Gateway": "fd00:dead:beef:31::1"},
            ]},
            "Options": {
                "com.docker.network.driver.mtu": "1400",
                "com.docker.network.bridge.enable_icc": "true",
                "com.docker.network.bridge.enable_ip_masquerade": "false",
                "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
            },
            "Labels": {"io.dockerlens.network": "synthetic"},
        }),
        json!({"Name": edge.as_str(), "Driver": "bridge"}),
        json!({
            "Image": image,
            "Cmd": ["sh", "-c", "printf network-canary > /tmp/index.html; httpd -f -p 8080 -h /tmp"],
            "HostConfig": {"NetworkMode": backend.as_str()},
            "NetworkingConfig": {"EndpointsConfig": endpoints},
        }),
        json!({"Container": app.as_str(), "EndpointConfig": {"Aliases": ["edge-app"]}}),
        json!({"Container": app.as_str(), "EndpointConfig": {"Aliases": ["external-app"]}}),
    ]
}

fn allowed_request(
    method: &str,
    path: &str,
    api_version: &str,
    run_id: &str,
    image: &str,
    body: Option<&Value>,
) -> bool {
    let Some(suffix) = path.strip_prefix(&format!("/v{api_version}/")) else {
        return false;
    };
    let backend = format!("dl-network-{run_id}-backend");
    let edge = format!("dl-network-{run_id}-edge");
    let external = format!("dl-network-{run_id}-external");
    let oracle = format!("dl-network-{run_id}-oracle");
    let app = format!("dl-network-{run_id}-app");
    let isolated = format!("dl-network-{run_id}-isolated");
    let edge_only = format!("dl-network-{run_id}-edge-only");
    let path_allowed = match method {
        "GET" => {
            [
                backend.as_str(),
                edge.as_str(),
                external.as_str(),
                oracle.as_str(),
            ]
            .iter()
            .any(|name| suffix == format!("networks/{name}"))
                || [app.as_str(), isolated.as_str(), edge_only.as_str()]
                    .iter()
                    .any(|name| suffix == format!("containers/{name}/json"))
        }
        "POST" => {
            suffix == "networks/create"
                || suffix == format!("containers/create?name={app}")
                || suffix == format!("networks/{edge}/connect")
                || suffix == format!("networks/{external}/connect")
        }
        _ => false,
    };
    if !path_allowed {
        return false;
    }
    if method != "POST" {
        return body.is_none();
    }
    let expected = expected_post_bodies(run_id, image);
    match suffix {
        "networks/create" => body == Some(&expected[0]) || body == Some(&expected[1]),
        _ if suffix == format!("containers/create?name={app}") => body == Some(&expected[2]),
        _ if suffix == format!("networks/{edge}/connect") => body == Some(&expected[3]),
        _ if suffix == format!("networks/{external}/connect") => body == Some(&expected[4]),
        _ => false,
    }
}

fn api(method: &str, path: &str, body: Option<&Value>) -> (u16, Vec<u8>) {
    api_with_timeout(method, path, body, "15")
}

fn api_with_timeout(
    method: &str,
    path: &str,
    body: Option<&Value>,
    max_time: &str,
) -> (u16, Vec<u8>) {
    let run_id = run_id();
    assert!(
        allowed_request(
            method,
            path,
            &required("NATIVE_API_VERSION"),
            &run_id,
            &required("NATIVE_FIXTURE_IMAGE"),
            body
        ),
        "network executor request outside closed allowlist"
    );
    let mut command = Command::new("curl");
    command.args([
        "-sS",
        "--max-time",
        max_time,
        "--unix-socket",
        &required("NATIVE_ENGINE_SOCKET"),
        "-X",
        method,
        "-H",
        "Content-Type: application/json",
    ]);
    if body.is_some() {
        command.args(["--data-binary", "@-"]).stdin(Stdio::piped());
    } else if method == "POST" {
        command.args(["--data-binary", ""]);
    }
    command.args(["-w", "\n%{http_code}", &format!("http://localhost{path}")]);
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().expect("test-only curl available");
    if let Some(body) = body {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(body).unwrap())
            .unwrap();
    }
    let output = child.wait_with_output().expect("bounded Engine response");
    assert!(output.status.success(), "isolated Engine request failed");
    let split = output
        .stdout
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap();
    let status = std::str::from_utf8(&output.stdout[split + 1..])
        .unwrap()
        .parse()
        .unwrap();
    (status, output.stdout[..split].to_vec())
}

fn inspect(path: &str) -> Value {
    let (status, response) = api("GET", path, None);
    assert_eq!(status, 200, "independent Engine inspect succeeds");
    serde_json::from_slice(&response).expect("native inspect JSON")
}

fn inspect_running_with_dns_budget(path: &str) -> bool {
    let (status, response) = api_with_timeout("GET", path, None, "3");
    assert!(
        status == 200,
        "bounded independent Engine state inspect succeeds"
    );
    let inspected: Value = serde_json::from_slice(&response).expect("private state inspect JSON");
    inspected["State"]["Running"] == true
}

fn rich_create() -> NetworkCreate {
    let mut create = NetworkCreate::bridge();
    create.internal = true;
    create.enable_ipv6 = true;
    create.ipam = Some(NetworkIpam {
        driver: Some(NetworkIpamDriver::Default),
        pools: vec![
            NetworkIpamPool {
                subnet: subnet("172.29.244.0", 24),
                gateway: Some(addr("172.29.244.1")),
                ip_range: Some(subnet("172.29.244.128", 25)),
                auxiliary_addresses: vec![NetworkAuxAddress {
                    name: alias("reserved"),
                    address: addr("172.29.244.2"),
                }],
            },
            NetworkIpamPool {
                subnet: subnet("fd00:dead:beef:31::", 64),
                gateway: Some(addr("fd00:dead:beef:31::1")),
                ip_range: None,
                auxiliary_addresses: vec![],
            },
        ],
    });
    create.options = vec![
        BridgeOption::Mtu(NonZeroU32::new(1400).unwrap()),
        BridgeOption::InterContainerCommunication(true),
        BridgeOption::IpMasquerade(false),
        BridgeOption::HostBindingIp(addr("127.0.0.1")),
    ];
    create.labels =
        vec![NetworkLabel::new(b"io.dockerlens.network".to_vec(), b"synthetic".to_vec()).unwrap()];
    create
}

fn container(name: &str, image: &str, networks: Vec<NetworkAttachmentIntent>) -> TargetResource {
    TargetResource::Container(Box::new(ContainerIntent {
        reference: ResourceRef::new(4),
        identity: identity(name),
        image: ImageReference::new(image.as_bytes().to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![],
        networks,
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Exec(vec![
            Argument::new(b"sh".to_vec()).unwrap(),
            Argument::new(b"-c".to_vec()).unwrap(),
            Argument::new(
                b"printf network-canary > /tmp/index.html; httpd -f -p 8080 -h /tmp".to_vec(),
            )
            .unwrap(),
        ]),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings::default(),
    }))
}

fn intent(backend: &str, edge: &str, external: &str, app: &str, image: &str) -> TargetIntent {
    TargetIntent::new(vec![
        TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(1),
            identity: identity(backend),
            role: NetworkRole::ApplicationDefault,
            source: NetworkSource::Create(rich_create()),
        }),
        TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(2),
            identity: identity(edge),
            role: NetworkRole::Declared,
            source: NetworkSource::Create(NetworkCreate::bridge()),
        }),
        TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(3),
            identity: identity(external),
            role: NetworkRole::Declared,
            source: NetworkSource::External {
                expected_driver: NetworkDriver::Bridge,
            },
        }),
        container(
            app,
            image,
            vec![
                NetworkAttachmentIntent {
                    network: ResourceRef::new(1),
                    aliases: vec![alias("backend-app")],
                    ipv4_address: Some(addr("172.29.244.130")),
                    ipv6_address: Some(addr("fd00:dead:beef:31::10")),
                },
                NetworkAttachmentIntent {
                    network: ResourceRef::new(2),
                    aliases: vec![alias("edge-app")],
                    ipv4_address: None,
                    ipv6_address: None,
                },
                NetworkAttachmentIntent {
                    network: ResourceRef::new(3),
                    aliases: vec![alias("external-app")],
                    ipv4_address: None,
                    ipv6_address: None,
                },
            ],
        ),
    ])
    .expect("valid authored network topology")
}

#[test]
fn network_run_identity_preserves_mixed_case_mktemp_suffix() {
    assert_eq!(validated_run_id("dl-native-aB12-zY"), Some("aB12-zY"));
    for invalid in [
        "dl-native-",
        "other-aB12",
        "dl-native-../escape",
        "dl-native-a b",
    ] {
        assert_eq!(validated_run_id(invalid), None);
    }
    assert_eq!(
        validated_run_id(&format!("dl-native-{}", "a".repeat(65))),
        None
    );
}

#[test]
fn network_probe_names_are_distinct_from_historical_admission() {
    let names: std::collections::HashSet<_> = PROBES.into_iter().collect();
    assert_eq!(names.len(), 19);
    assert!(!names.contains("BridgeNetworkCreate"));
    assert!(!names.contains("BridgeNetworkAttach"));
}

#[test]
fn network_executor_allowlist_is_closed() {
    let expected = expected_post_bodies("test", "fixture-image");
    assert!(allowed_request(
        "POST",
        "/v1.41/networks/create",
        "1.41",
        "test",
        "fixture-image",
        Some(&expected[0])
    ));
    assert!(allowed_request(
        "POST",
        "/v1.41/networks/create",
        "1.41",
        "test",
        "fixture-image",
        Some(&expected[1])
    ));
    assert!(allowed_request(
        "POST",
        "/v1.41/containers/create?name=dl-network-test-app",
        "1.41",
        "test",
        "fixture-image",
        Some(&expected[2])
    ));
    assert!(allowed_request(
        "POST",
        "/v1.41/networks/dl-network-test-edge/connect",
        "1.41",
        "test",
        "fixture-image",
        Some(&expected[3])
    ));
    assert!(allowed_request(
        "POST",
        "/v1.41/networks/dl-network-test-external/connect",
        "1.41",
        "test",
        "fixture-image",
        Some(&expected[4])
    ));
    assert!(allowed_request(
        "GET",
        "/v1.41/networks/dl-network-test-edge",
        "1.41",
        "test",
        "fixture-image",
        None
    ));
    assert!(allowed_request(
        "GET",
        "/v1.41/containers/dl-network-test-edge-only/json",
        "1.41",
        "test",
        "fixture-image",
        None
    ));
    for (path, body, extra) in [
        (
            "/v1.41/networks/create",
            &expected[0],
            json!({"Privileged": true}),
        ),
        (
            "/v1.41/containers/create?name=dl-network-test-app",
            &expected[2],
            json!({"HostConfig": {"NetworkMode": "dl-network-test-backend", "Privileged": true}}),
        ),
        (
            "/v1.41/networks/dl-network-test-edge/connect",
            &expected[3],
            json!({"EndpointConfig": {"Aliases": ["edge-app"], "IPAMConfig": {"IPv4Address": "1.2.3.4"}}}),
        ),
    ] {
        let mut altered = body.clone();
        altered
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert!(!allowed_request(
            "POST",
            path,
            "1.41",
            "test",
            "fixture-image",
            Some(&altered)
        ));
    }
    assert!(!allowed_request(
        "POST",
        "/v1.41/networks/create",
        "1.41",
        "test",
        "fixture-image",
        Some(&json!({"Name": "unowned"}))
    ));
    assert!(!allowed_request(
        "POST",
        "/v1.41/networks/dl-network-test-edge/connect",
        "1.41",
        "test",
        "fixture-image",
        Some(&json!({"Container": "unowned"}))
    ));
    for (method, path) in [
        ("POST", "/v1.41/containers/synthetic/start"),
        ("DELETE", "/v1.41/networks/synthetic"),
        ("POST", "/v1.41/networks/synthetic/disconnect"),
        ("POST", "/v1.42/networks/synthetic/connect"),
        ("POST", "/v1.41/networks/synthetic/connect/extra"),
        ("POST", "/v1.41/networks/unowned/connect"),
        ("POST", "/v1.41/containers/create?name=unowned"),
    ] {
        assert!(!allowed_request(
            method,
            path,
            "1.41",
            "test",
            "fixture-image",
            Some(&expected[3])
        ));
    }
}

fn assert_invalid_topologies() {
    let network = |create| {
        TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(1),
            identity: identity("invalid-backend"),
            role: NetworkRole::Declared,
            source: NetworkSource::Create(create),
        })
    };
    let mut overlap = rich_create();
    overlap.ipam.as_mut().unwrap().pools.push(NetworkIpamPool {
        subnet: subnet("172.29.244.128", 25),
        gateway: None,
        ip_range: None,
        auxiliary_addresses: vec![],
    });
    assert_eq!(
        TargetIntent::new(vec![network(overlap)]).unwrap_err(),
        IntentError::InvalidNetworkIpam
    );
    for reserved in ["172.29.244.0", "172.29.244.255"] {
        let mut gateway = rich_create();
        gateway.ipam.as_mut().unwrap().pools[0].gateway = Some(addr(reserved));
        assert_eq!(
            TargetIntent::new(vec![network(gateway)]).unwrap_err(),
            IntentError::InvalidNetworkIpam
        );
        let mut auxiliary = rich_create();
        auxiliary.ipam.as_mut().unwrap().pools[0].auxiliary_addresses[0].address = addr(reserved);
        assert_eq!(
            TargetIntent::new(vec![network(auxiliary)]).unwrap_err(),
            IntentError::InvalidNetworkIpam
        );
        let endpoint = NetworkAttachmentIntent {
            network: ResourceRef::new(1),
            aliases: vec![],
            ipv4_address: Some(addr(reserved)),
            ipv6_address: None,
        };
        assert_eq!(
            TargetIntent::new(vec![
                network(rich_create()),
                container("invalid-app", "busybox", vec![endpoint])
            ])
            .unwrap_err(),
            IntentError::InvalidNetworkAttachment
        );
    }
    let endpoint = || NetworkAttachmentIntent {
        network: ResourceRef::new(1),
        aliases: vec![],
        ipv4_address: Some(addr("172.29.244.130")),
        ipv6_address: None,
    };
    let mut second = container("collision-two", "busybox", vec![endpoint()]);
    let TargetResource::Container(second_body) = &mut second else {
        unreachable!()
    };
    second_body.reference = ResourceRef::new(5);
    assert_eq!(
        TargetIntent::new(vec![
            network(rich_create()),
            container("collision-one", "busybox", vec![endpoint()]),
            second,
        ])
        .unwrap_err(),
        IntentError::DuplicateNetworkAddress
    );
}

#[test]
fn invalid_network_topologies_fail_before_native_requests() {
    assert_invalid_topologies();
}

#[test]
#[ignore = "requires isolated rootful/rootless inner Engine and test-only network resources"]
fn live_network_render_matches_engine() {
    let run_id = run_id();
    let api_version = required("NATIVE_API_VERSION");
    let image = required("NATIVE_FIXTURE_IMAGE");
    let backend = format!("dl-network-{run_id}-backend");
    let edge = format!("dl-network-{run_id}-edge");
    let external = format!("dl-network-{run_id}-external");
    let oracle = format!("dl-network-{run_id}-oracle");
    let app = format!("dl-network-{run_id}-app");

    // The CLI oracle is independent of the inert renderer. Direct GETs check
    // Engine normalization, including options, labels, both IP families and IPAM.
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_oracle");
    cli_ok(&[
        "network",
        "create",
        "--driver",
        "bridge",
        "--internal",
        "--ipv6",
        "--subnet",
        "172.29.245.0/24",
        "--gateway",
        "172.29.245.1",
        "--ip-range",
        "172.29.245.128/25",
        "--aux-address",
        "reserved=172.29.245.2",
        "--subnet",
        "fd00:dead:beef:32::/64",
        "--gateway",
        "fd00:dead:beef:32::1",
        "--opt",
        "com.docker.network.driver.mtu=1400",
        "--opt",
        "com.docker.network.bridge.enable_icc=true",
        "--opt",
        "com.docker.network.bridge.enable_ip_masquerade=false",
        "--opt",
        "com.docker.network.bridge.host_binding_ipv4=127.0.0.1",
        "--label",
        "io.dockerlens.network=synthetic",
        &oracle,
    ]);
    let oracle_body = inspect(&format!("/v{api_version}/networks/{oracle}"));
    assert_eq!(oracle_body["Driver"], "bridge");
    assert_eq!(oracle_body["Internal"], true);
    assert_eq!(oracle_body["EnableIPv6"], true);
    assert_eq!(oracle_body["IPAM"]["Driver"], "default");
    assert_eq!(
        oracle_body["IPAM"]["Config"][0]["Subnet"],
        "172.29.245.0/24"
    );
    assert_eq!(
        oracle_body["IPAM"]["Config"][0]["IPRange"],
        "172.29.245.128/25"
    );
    assert_eq!(oracle_body["IPAM"]["Config"][0]["Gateway"], "172.29.245.1");
    assert_eq!(
        oracle_body["IPAM"]["Config"][0]["AuxiliaryAddresses"]["reserved"],
        "172.29.245.2"
    );
    assert_eq!(
        oracle_body["IPAM"]["Config"][1]["Subnet"],
        "fd00:dead:beef:32::/64"
    );
    assert_eq!(
        oracle_body["IPAM"]["Config"][1]["Gateway"],
        "fd00:dead:beef:32::1"
    );
    assert_eq!(
        oracle_body["Options"]["com.docker.network.driver.mtu"],
        "1400"
    );
    assert_eq!(
        oracle_body["Options"]["com.docker.network.bridge.enable_icc"],
        "true"
    );
    assert_eq!(
        oracle_body["Options"]["com.docker.network.bridge.enable_ip_masquerade"],
        "false"
    );
    assert_eq!(
        oracle_body["Options"]["com.docker.network.bridge.host_binding_ipv4"],
        "127.0.0.1"
    );
    assert_eq!(oracle_body["Labels"]["io.dockerlens.network"], "synthetic");
    cli_ok(&["network", "create", "--driver", "bridge", &external]);
    let external_before = inspect(&format!("/v{api_version}/networks/{external}"));
    let external_id = external_before["Id"].as_str().unwrap().to_owned();

    eprintln!("DOCKERLENS_NATIVE_CHECK: network_identity");
    let source_id = required("NATIVE_CONTAINER_ID");
    let capture = acquire(
        &Endpoint::unix_socket(PathBuf::from(required("NATIVE_ENGINE_SOCKET"))),
        Selector::ContainerIds(vec![NativeId::new(source_id).unwrap()]),
        Limits {
            max_requests: 16,
            max_selected_resources: 2,
            max_expansions: 6,
            max_response_bytes: 8 * 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_elapsed: Duration::from_secs(30),
        },
        &AtomicBool::new(false),
    )
    .expect("live bounded source acquisition");
    let mut facts = decode_capture(&capture)
        .expect("native source decode")
        .version
        .daemon;
    assert_eq!(
        facts.release.as_ref().unwrap().as_str(),
        required("NATIVE_ENGINE_VERSION")
    );
    let observed_api = facts.api_version.unwrap();
    assert_eq!(
        format!("{}.{}", observed_api.major, observed_api.minor),
        api_version
    );
    match required("NATIVE_DAEMON_MODE").as_str() {
        "rootless" => assert_eq!(facts.mode, DaemonMode::Rootless),
        "rootful" => {
            assert_ne!(facts.mode, DaemonMode::Rootless);
            // The preceding exact native_target test proves the single dockerd UID.
            facts.mode = DaemonMode::Rootful;
        }
        _ => panic!("invalid native lane mode"),
    }
    let intent = intent(&backend, &edge, &external, &app, &image);
    let absent = ValidatedCapabilities::new(&facts).expect("observed identity");
    assert!(matches!(
        DockerPlanner.plan(&intent, &absent),
        Err(PlanningError::MissingCapability { .. })
    ));
    let scope = CapabilityScope {
        observation_id: capture.observation_id(),
        release: facts.release.clone().unwrap(),
        api_version: facts.api_version.unwrap(),
        mode: facts.mode,
    };
    facts.capabilities = [
        Capability::StandaloneContainer,
        Capability::BridgeNetwork,
        Capability::NetworkExternalReference,
        Capability::NetworkInternal,
        Capability::NetworkIpv6,
        Capability::NetworkIpam,
        Capability::NetworkIpamDriver,
        Capability::NetworkOptions,
        Capability::NetworkLabels,
        Capability::NetworkAliases,
        Capability::NetworkStaticAddress,
        Capability::NetworkMultipleAttachment,
        Capability::Command,
    ]
    .into_iter()
    .map(|capability| CapabilityFact {
        capability,
        state: CapabilityState::Available,
        provenance: FactProvenance::NativeConformance,
        scope: Some(scope.clone()),
    })
    .collect();
    let supported = ValidatedCapabilities::new(&facts).expect("test-local scoped network facts");

    eprintln!("DOCKERLENS_NATIVE_CHECK: network_negative");
    assert_invalid_topologies();
    for prefix in [31, 32] {
        let mut tiny = NetworkCreate::bridge();
        tiny.ipam = Some(NetworkIpam {
            driver: Some(NetworkIpamDriver::Default),
            pools: vec![NetworkIpamPool {
                subnet: subnet("172.29.246.0", prefix),
                gateway: None,
                ip_range: None,
                auxiliary_addresses: vec![],
            }],
        });
        let tiny_intent = TargetIntent::new(vec![TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(9),
            identity: identity("tiny-network"),
            role: NetworkRole::Declared,
            source: NetworkSource::Create(tiny),
        })])
        .unwrap();
        assert!(matches!(
            DockerPlanner.plan(&tiny_intent, &supported),
            Err(PlanningError::UnsupportedNetworkIpam { .. })
        ));
    }

    eprintln!("DOCKERLENS_NATIVE_CHECK: network_render");
    let graph = DockerPlanner
        .plan(&intent, &supported)
        .expect("native network plan");
    let artifact = DockerApiRenderer
        .render(&graph)
        .expect("inert network requests");
    assert_eq!(artifact.network_prerequisites().len(), 1);
    assert_eq!(
        artifact.network_prerequisites()[0].identity(),
        external.as_bytes()
    );
    assert_eq!(
        artifact.network_prerequisites()[0].expected_driver,
        NetworkDriver::Bridge
    );
    let requests: Vec<Value> = artifact
        .bytes()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("rendered request JSON"))
        .collect();
    assert_eq!(requests.len(), 5);
    assert_eq!(
        requests[0]["path"],
        format!("/v{api_version}/networks/create")
    );
    assert_eq!(
        requests[1]["path"],
        format!("/v{api_version}/networks/create")
    );
    assert_eq!(requests[0]["body"]["Name"], backend);
    assert_eq!(requests[1]["body"]["Name"], edge);
    assert_eq!(requests[0]["body"]["Internal"], true);
    assert_eq!(requests[0]["body"]["EnableIPv6"], true);
    assert_eq!(requests[0]["body"]["IPAM"]["Driver"], "default");
    assert_eq!(
        requests[0]["body"]["IPAM"]["Config"][0],
        json!({
            "Subnet": "172.29.244.0/24", "IPRange": "172.29.244.128/25",
            "Gateway": "172.29.244.1", "AuxiliaryAddresses": {"reserved": "172.29.244.2"},
        })
    );
    assert_eq!(
        requests[0]["body"]["IPAM"]["Config"][1]["Subnet"],
        "fd00:dead:beef:31::/64"
    );
    assert_eq!(
        requests[0]["body"]["Options"],
        json!({
            "com.docker.network.driver.mtu": "1400",
            "com.docker.network.bridge.enable_icc": "true",
            "com.docker.network.bridge.enable_ip_masquerade": "false",
            "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
        })
    );
    assert_eq!(
        requests[0]["body"]["Labels"]["io.dockerlens.network"],
        "synthetic"
    );
    assert_eq!(
        requests[2]["path"],
        format!("/v{api_version}/containers/create?name={app}")
    );
    assert_eq!(
        requests[2]["body"]["NetworkingConfig"]["EndpointsConfig"][backend.as_str()]["Aliases"],
        json!(["backend-app"])
    );
    assert_eq!(
        requests[2]["body"]["NetworkingConfig"]["EndpointsConfig"][backend.as_str()]["IPAMConfig"],
        json!({"IPv4Address": "172.29.244.130", "IPv6Address": "fd00:dead:beef:31::10"})
    );
    assert_eq!(
        requests[3]["path"],
        format!("/v{api_version}/networks/{edge}/connect")
    );
    assert_eq!(
        requests[3]["body"],
        json!({"Container": app, "EndpointConfig": {"Aliases": ["edge-app"]}})
    );
    assert_eq!(
        requests[4]["path"],
        format!("/v{api_version}/networks/{external}/connect")
    );
    assert_eq!(
        requests[4]["body"],
        json!({"Container": app, "EndpointConfig": {"Aliases": ["external-app"]}})
    );
    assert!(
        requests
            .iter()
            .all(|request| request["body"]["Name"] != external)
    );

    eprintln!("DOCKERLENS_NATIVE_CHECK: network_apply");
    let mut app_id = None;
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request["method"], "POST");
        let path = request["path"].as_str().unwrap();
        let (status, response) = api("POST", path, Some(&request["body"]));
        assert_eq!(
            status,
            if index < 3 { 201 } else { 200 },
            "Engine accepts exact inert request"
        );
        if index == 2 {
            let created: Value = serde_json::from_slice(&response).unwrap();
            app_id = Some(created["Id"].as_str().unwrap().to_owned());
        }
    }
    let app_id = app_id.unwrap();
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_inspect");
    let backend_body = inspect(&format!("/v{api_version}/networks/{backend}"));
    let edge_body = inspect(&format!("/v{api_version}/networks/{edge}"));
    let external_after = inspect(&format!("/v{api_version}/networks/{external}"));
    cli_ok(&["start", &app_id]);
    let app_body = inspect(&format!("/v{api_version}/containers/{app}/json"));
    assert_eq!(backend_body["Internal"], true);
    assert_eq!(backend_body["EnableIPv6"], true);
    assert_eq!(backend_body["IPAM"]["Driver"], "default");
    assert_eq!(
        backend_body["IPAM"]["Config"][0]["Subnet"],
        "172.29.244.0/24"
    );
    assert_eq!(
        backend_body["IPAM"]["Config"][1]["Subnet"],
        "fd00:dead:beef:31::/64"
    );
    assert_eq!(
        backend_body["IPAM"]["Config"][1]["Gateway"],
        "fd00:dead:beef:31::1"
    );
    assert_eq!(backend_body["IPAM"]["Config"][0]["Gateway"], "172.29.244.1");
    assert_eq!(
        backend_body["IPAM"]["Config"][0]["IPRange"],
        "172.29.244.128/25"
    );
    assert_eq!(
        backend_body["IPAM"]["Config"][0]["AuxiliaryAddresses"]["reserved"],
        "172.29.244.2"
    );
    for (option, value) in [
        ("com.docker.network.driver.mtu", "1400"),
        ("com.docker.network.bridge.enable_icc", "true"),
        ("com.docker.network.bridge.enable_ip_masquerade", "false"),
        ("com.docker.network.bridge.host_binding_ipv4", "127.0.0.1"),
    ] {
        assert_eq!(backend_body["Options"][option], value);
    }
    assert_eq!(backend_body["Labels"]["io.dockerlens.network"], "synthetic");
    assert_eq!(edge_body["Name"], edge);
    assert_eq!(external_after["Id"], external_id);
    assert_eq!(external_after["Driver"], "bridge");
    assert_eq!(
        app_body["NetworkSettings"]["Networks"][backend.as_str()]["IPAddress"],
        "172.29.244.130"
    );
    assert_eq!(
        app_body["NetworkSettings"]["Networks"][backend.as_str()]["GlobalIPv6Address"],
        "fd00:dead:beef:31::10"
    );
    for (network, alias) in [
        (&backend, "backend-app"),
        (&edge, "edge-app"),
        (&external, "external-app"),
    ] {
        assert!(
            app_body["NetworkSettings"]["Networks"][network.as_str()]["Aliases"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == alias)
        );
    }

    eprintln!("DOCKERLENS_NATIVE_CHECK: network_traffic");
    for (network, alias) in [
        (&backend, "backend-app"),
        (&edge, "edge-app"),
        (&external, "external-app"),
    ] {
        let url = format!("http://{alias}:8080/");
        let mut received = false;
        for _ in 0..5 {
            let (success, output) = cli(&[
                "run",
                "--rm",
                "--network",
                network,
                &image,
                "wget",
                "-qO-",
                &url,
            ]);
            if success && output == b"network-canary" {
                received = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        assert!(
            received,
            "network-specific alias DNS and HTTP traffic must work"
        );
    }
    let ipv6 = app_body["NetworkSettings"]["Networks"][backend.as_str()]["GlobalIPv6Address"]
        .as_str()
        .expect("rendered backend has a static IPv6 address");
    let ipv6_url = format!("http://[{ipv6}]:8080/");
    let (v6_success, v6_output) = cli(&[
        "run",
        "--rm",
        "--network",
        &backend,
        &image,
        "wget",
        "-T",
        "2",
        "-qO-",
        &ipv6_url,
    ]);
    assert!(
        v6_success && v6_output == b"network-canary",
        "backend peer must reach the rendered static IPv6 endpoint"
    );
    let mtu = cli_ok(&[
        "run",
        "--rm",
        "--network",
        &backend,
        &image,
        "cat",
        "/sys/class/net/eth0/mtu",
    ]);
    assert_eq!(
        mtu.as_slice(),
        b"1400\n",
        "bridge MTU must reach the peer interface"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation");
    // The rendered app is dual-homed. An edge address on that same app could
    // answer packets arriving over its backend interface, so isolation needs
    // a separate, genuinely edge-only destination.
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_edge_fixture");
    let edge_only = format!("dl-network-{run_id}-edge-only");
    cli_ok(&[
        "create",
        "--name",
        &edge_only,
        "--network",
        &edge,
        "--network-alias",
        "edge-sentinel",
        &image,
        "sh",
        "-c",
        "printf edge-canary > /tmp/index.html; httpd -f -p 8080 -h /tmp",
    ]);
    cli_ok(&["start", &edge_only]);
    let edge_only_body = inspect(&format!("/v{api_version}/containers/{edge_only}/json"));
    assert_eq!(
        edge_only_body["NetworkSettings"]["Networks"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert!(
        edge_only_body["NetworkSettings"]["Networks"]
            .get(edge.as_str())
            .is_some()
    );
    let edge_alias_present =
        edge_only_body["NetworkSettings"]["Networks"][edge.as_str()]["Aliases"]
            .as_array()
            .is_some_and(|aliases| aliases.iter().any(|alias| alias == "edge-sentinel"));
    if !edge_alias_present {
        eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_edge_alias_missing");
    }
    assert!(
        edge_alias_present,
        "independent edge-only CLI fixture must register its alias"
    );
    if edge_only_body["State"]["Running"] != true {
        eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_edge_fixture_exited");
    }
    assert!(
        edge_only_body["State"]["Running"] == true,
        "edge-only fixture must remain running before DNS control"
    );
    let edge_ip = edge_only_body["NetworkSettings"]["Networks"][edge.as_str()]["IPAddress"]
        .as_str()
        .expect("edge-only peer has runtime IPv4")
        .parse::<Ipv4Addr>()
        .expect("bounded edge-only IPv4");
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_edge_dns");
    let edge_dns_outcome = wait_for_exact_dns_answer(
        "edge-sentinel",
        edge_ip,
        4,
        || {
            cli_dns(&[
                "run",
                "--rm",
                "--network",
                &edge,
                &image,
                "nslookup",
                "-type=A",
                "edge-sentinel",
            ])
        },
        || inspect_running_with_dns_budget(&format!("/v{api_version}/containers/{edge_only}/json")),
        || std::thread::sleep(Duration::from_millis(250)),
    );
    if let Err(category) = edge_dns_outcome {
        eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_edge_dns_{category}");
    }
    assert!(
        edge_dns_outcome.is_ok(),
        "edge-side peer must resolve edge-only alias to its inspected IPv4"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_edge_http");
    let mut edge_http_ok = false;
    for _ in 0..5 {
        let (success, output) = cli(&[
            "run",
            "--rm",
            "--network",
            &edge,
            &image,
            "wget",
            "-T",
            "2",
            "-qO-",
            "http://edge-sentinel:8080/",
        ]);
        if success && output == b"edge-canary" {
            edge_http_ok = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    assert!(edge_http_ok, "edge-side peer must reach edge-only endpoint");
    let backend_only = format!("dl-network-{run_id}-isolated");
    cli_ok(&[
        "create",
        "--name",
        &backend_only,
        "--network",
        &backend,
        &image,
        "sleep",
        "60",
    ]);
    cli_ok(&["start", &backend_only]);
    let isolated = inspect(&format!("/v{api_version}/containers/{backend_only}/json"));
    assert_eq!(
        isolated["NetworkSettings"]["Networks"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert!(
        isolated["NetworkSettings"]["Networks"]
            .get(backend.as_str())
            .is_some()
    );
    let backend_ip = app_body["NetworkSettings"]["Networks"][backend.as_str()]["IPAddress"]
        .as_str()
        .expect("rendered backend runtime IPv4")
        .parse::<Ipv4Addr>()
        .expect("bounded rendered backend IPv4");
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_local_dns");
    let (backend_resolved, backend_answer) =
        cli(&["exec", &backend_only, "nslookup", "-type=A", "backend-app"]);
    assert!(
        backend_resolved && nslookup_has_ipv4_answer(&backend_answer, "backend-app", backend_ip),
        "same backend-only peer must resolve its local alias to its inspected IPv4"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_local_http");
    let backend_http = cli_ok(&[
        "exec",
        &backend_only,
        "wget",
        "-T",
        "2",
        "-qO-",
        "http://backend-app:8080/",
    ]);
    assert_eq!(
        backend_http.as_slice(),
        b"network-canary",
        "same backend-only peer must reach the backend endpoint"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_foreign_dns");
    let (exec_ok, resolved) = cli(&[
        "exec",
        &backend_only,
        "sh",
        "-c",
        "if nslookup -type=A edge-sentinel >/dev/null 2>&1; then printf resolved; else printf absent; fi",
    ]);
    assert!(
        exec_ok && resolved == b"absent",
        "running backend-only peer must not resolve edge-only alias"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_foreign_route");
    let edge_url = format!("http://{edge_ip}:8080/");
    let route_probe = format!(
        "if wget -T 2 -qO- {edge_url} >/dev/null 2>&1; then printf reachable; else printf blocked; fi"
    );
    let (exec_ok, routed) = cli(&["exec", &backend_only, "sh", "-c", &route_probe]);
    assert!(
        exec_ok && routed == b"blocked",
        "running backend-only peer must not route to the edge endpoint"
    );

    eprintln!("DOCKERLENS_NATIVE_CHECK: network_external");
    assert_eq!(
        inspect(&format!("/v{api_version}/networks/{external}"))["Id"],
        external_id
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_evidence");
    fs::write(
        required("NATIVE_NETWORK_PROBES_PATH"),
        serde_json::to_vec(&PROBES).unwrap(),
    )
    .expect("private closed network evidence");
}
