//! Test-only network executor. Product rendering remains inert and catalog admission unchanged.

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    NativeCapabilityShape, ValidatedCapabilities,
};

const PROBES: [&str; 22] = [
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
    "NetworkBridgeIccDisabled",
    "NetworkBridgeMasqueradeEnabled",
    "NetworkCreateLabelsValueDomain",
];

const DNS_CLI_HARD_LIMIT_SECS: u64 = 9;
const EMBEDDED_DNS_SERVER: &str = "127.0.0.11";
const EMPTY_LABEL_KEY: &str = "io.dockerlens.network.empty";
const SPECIAL_LABEL_KEY: &str = "io.dockerlens.network.special";
const SPECIAL_LABEL_VALUE: &str = "Grüße \"quoted\" \\ path";

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

fn canonical_inspected_container_id(value: &Value) -> Option<&str> {
    let id = value["Id"].as_str()?;
    (id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(id)
}

#[test]
fn isolation_fixture_ids_require_distinct_canonical_docker_values() {
    let canonical = "a".repeat(64);
    assert_eq!(
        canonical_inspected_container_id(&json!({"Id": canonical.as_str()})),
        Some(canonical.as_str())
    );
    assert!(canonical_inspected_container_id(&json!({"Id": "a".repeat(63)})).is_none());
    assert!(canonical_inspected_container_id(&json!({"Id": "A".repeat(64)})).is_none());
    assert!(canonical_inspected_container_id(&json!({"Id": "z".repeat(64)})).is_none());
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
    let output = bounded_cli(args, "45");
    assert!(!output.output_limit, "bounded native CLI output limit");
    (output.success, output.stdout)
}

fn network_cli_failure_category(stderr: &[u8]) -> &'static str {
    let message = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if message.contains("br_netfilter") || message.contains("bridge-nf-call") {
        "bridge_filter"
    } else if message.contains("inter-container communication")
        || message.contains("inter container communication")
        || message.contains("enable_icc")
    {
        "icc_configuration"
    } else if message.contains("iptables is disabled") || message.contains("ip6tables is disabled")
    {
        "firewall_disabled"
    } else if message.contains("iptables") || message.contains("ip6tables") {
        "firewall"
    } else if message.contains("permission denied") || message.contains("operation not permitted") {
        "permission"
    } else if message.contains("overlap") || message.contains("address pool") {
        "address_pool"
    } else if message.contains("invalid label") {
        "invalid_label"
    } else if message.contains("invalid option") || message.contains("unknown flag") {
        "invalid_option"
    } else {
        "unknown"
    }
}

#[test]
fn network_cli_failure_categories_never_disclose_native_values() {
    for (message, expected) in [
        (
            "Cannot restrict communication if iptables is disabled: private-canary",
            "firewall_disabled",
        ),
        (
            "iptables cannot load br_netfilter private-canary",
            "bridge_filter",
        ),
        ("bridge-nf-call-iptables private-canary", "bridge_filter"),
        (
            "cannot disable inter-container communication private-canary",
            "icc_configuration",
        ),
        ("ip6tables private-canary failed", "firewall"),
        ("operation not permitted private-canary", "permission"),
        ("address pool overlaps private-canary", "address_pool"),
        ("invalid label private-canary", "invalid_label"),
        ("unknown flag private-canary", "invalid_option"),
        ("private-canary", "unknown"),
    ] {
        assert_eq!(network_cli_failure_category(message.as_bytes()), expected);
    }
}

fn cli_ok(args: &[&str]) -> Vec<u8> {
    let output = bounded_cli(args, "45");
    assert!(!output.output_limit, "bounded native CLI output limit");
    if !output.success {
        let exit = if matches!(output.code, Some(124 | 137)) {
            "timeout"
        } else {
            "other"
        };
        eprintln!(
            "DOCKERLENS_NATIVE_NETWORK_CLI_DIAG: exit={exit} category={}",
            network_cli_failure_category(&output.stderr)
        );
    }
    assert!(
        output.success,
        "independent isolated Docker CLI probe failed"
    );
    output.stdout
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

fn private_docker_command(seconds: &str) -> Command {
    let mut command = Command::new("timeout");
    // One second after TERM, force a stubborn CLI process to exit so the
    // diagnostic can still run its exact-peer cleanup before the outer gate.
    command.args(["--kill-after=1", seconds]);
    if required("NATIVE_PODMAN_USE_SUDO") == "1" {
        command.args(["sudo", "-n"]);
        command.args(crate::native_outer_test_command::prefix());
    } else {
        command.args(crate::native_outer_test_command::prefix());
    }
    command.args([
        "exec",
        &required("NATIVE_OUTER_CONTAINER_ID"),
        "docker",
        "-H",
        "unix:///dockerlens-native/docker.sock",
    ]);
    command
}

fn cli_dns(args: &[&str]) -> BoundedDnsCliOutput {
    // The DNS readiness loop has four at-most-nine-second CLI calls and four
    // three-second state reads, plus three 250-ms waits in the retry case.
    let mut command = private_docker_command("8");
    bounded_cli_command(&mut command, args)
}

fn bounded_cli(args: &[&str], seconds: &str) -> BoundedDnsCliOutput {
    let mut command = private_docker_command(seconds);
    bounded_cli_command(&mut command, args)
}

fn bounded_cli_command(command: &mut Command, args: &[&str]) -> BoundedDnsCliOutput {
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
        if matches!(result.code, Some(124 | 137)) {
            return "cli_timeout";
        }
        if result.code == Some(42) {
            return "cli_resolver";
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

fn nslookup_has_only_exact_named_a(output: &[u8], alias: &str, expected: Ipv4Addr) -> bool {
    let Ok(output) = std::str::from_utf8(output) else {
        return false;
    };
    let mut named = false;
    let mut resolver_address_seen = false;
    let mut answers = Vec::new();
    for line in output.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix("Name:") {
            if named || name.trim().trim_end_matches('.') != alias {
                return false;
            }
            named = true;
            continue;
        }
        let address = line.strip_prefix("Address:").or_else(|| {
            line.strip_prefix("Address ")
                .and_then(|numbered| numbered.split_once(':'))
                .and_then(|(ordinal, value)| {
                    ordinal
                        .parse::<u32>()
                        .ok()
                        .filter(|ordinal| *ordinal > 0)
                        .map(|_| value)
                })
        });
        if let Some(address) = address {
            if !named {
                let server = address.split_whitespace().next();
                if resolver_address_seen || !matches!(server, Some("127.0.0.11" | "127.0.0.11:53"))
                {
                    return false;
                }
                resolver_address_seen = true;
                continue;
            }
            let mut fields = address.split_whitespace();
            let Some(Ok(ip)) = fields.next().map(str::parse::<Ipv4Addr>) else {
                return false;
            };
            let suffix = fields.next();
            if fields.next().is_some()
                || suffix.is_some_and(|name| name.trim_end_matches('.') != alias)
            {
                return false;
            }
            answers.push(ip);
            continue;
        }
        if !named && (line.starts_with("Server:") || line == "Non-authoritative answer:") {
            continue;
        }
        return false; // Status, malformed line, or unparsed answer.
    }
    named && answers.len() == 1 && answers[0] == expected
}

#[test]
fn nslookup_exact_named_a_rejects_extra_foreign_and_malformed_answers() {
    let local = Ipv4Addr::new(172, 29, 244, 20);
    let header = "Server: 127.0.0.11\nAddress: 127.0.0.11:53\n\n";
    for answer in [
        "Name: edge-sentinel\nAddress: 172.29.244.20\n",
        "Name: edge-sentinel.\nAddress 1: 172.29.244.20 edge-sentinel.\n",
    ] {
        assert!(nslookup_has_only_exact_named_a(
            format!("{header}{answer}").as_bytes(),
            "edge-sentinel",
            local,
        ));
    }
    for answer in [
        "Name: edge-sentinel\nAddress: 172.29.244.20\nAddress: 172.29.245.20\n",
        "Name: edge-sentinel\nAddress: 172.29.244.20\nAddress: 172.29.244.20\n",
        "Name: edge-sentinel\nAddress: 172.29.244.20\nName: edge-sentinel\n",
        "Name: edge-sentinel\nAddress: 172.29.244.20\nName: edge-sentinel\nAddress: 172.29.244.20\n",
        "Name: edge-sentinel\nAddress: 172.29.245.20\n",
        "Name: edge-sentinel\nAddress: not-an-ip\n",
        "Name: edge-sentinel\nAddress invalid: 172.29.244.20\n",
        "Name: edge-sentinel\nAddress 1: 172.29.244.20 edge-sentinel edge-sentinel\n",
        "Name: edge-sentinel\n",
        "Name: other-name\nAddress: 172.29.244.20\n",
        "Name: edge-sentinel\nAddress: 172.29.244.20\nSERVFAIL\n",
    ] {
        assert!(!nslookup_has_only_exact_named_a(
            format!("{header}{answer}").as_bytes(),
            "edge-sentinel",
            local,
        ));
    }
    assert!(!nslookup_has_only_exact_named_a(
        b"Name: edge-sentinel\nAddress: 172.29.244.20\xff",
        "edge-sentinel",
        local,
    ));
}

fn foreign_dns_exit_category(result: &BoundedDnsCliOutput, category: &str) -> &'static str {
    if result.success {
        "success"
    } else if matches!(result.code, Some(124 | 137)) {
        "timeout"
    } else if category == "cli_lookup" {
        "lookup"
    } else {
        "other"
    }
}

fn foreign_dns_response_indicator(
    result: &BoundedDnsCliOutput,
    alias: &str,
    expected: Ipv4Addr,
) -> &'static str {
    if result.output_limit {
        return "other";
    }
    let (Ok(stdout), Ok(stderr)) = (
        std::str::from_utf8(&result.stdout),
        std::str::from_utf8(&result.stderr),
    ) else {
        return "other";
    };
    let output = format!("{stdout}\n{stderr}");
    if nslookup_has_ipv4_answer(output.as_bytes(), alias, expected) {
        return "has_expected_a";
    }
    // A conflicting or malformed named answer must not be called no-A even
    // when another line contains an apparent DNS status.
    if matches!(
        named_dns_answer_category(output.as_bytes(), alias, expected),
        "answer_wrong_ip" | "answer_malformed"
    ) {
        return "other";
    }
    let words: Vec<String> = output
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_uppercase)
        .collect();
    let statuses = ["NXDOMAIN", "SERVFAIL", "REFUSED"]
        .into_iter()
        .filter(|status| words.iter().any(|word| word.as_str() == *status))
        .collect::<Vec<_>>();
    if statuses.len() == 1 {
        return match statuses[0] {
            "NXDOMAIN" => "nxdomain",
            "SERVFAIL" => "servfail",
            "REFUSED" => "refused",
            _ => unreachable!(),
        };
    }
    if statuses.is_empty()
        && (words.iter().any(|word| word.as_str() == "NOERROR")
            || words
                .windows(2)
                .any(|pair| pair[0].as_str() == "NO" && pair[1].as_str() == "ANSWER"))
    {
        return "no_error_no_a";
    }
    "other"
}

#[test]
fn foreign_dns_diagnostic_categories_are_closed_and_conservative() {
    let expected = Ipv4Addr::new(172, 29, 244, 20);
    let mut result = BoundedDnsCliOutput {
        success: false,
        code: Some(1),
        stdout: b"*** Can't find edge-sentinel.: NXDOMAIN\n".to_vec(),
        stderr: Vec::new(),
        output_limit: false,
    };
    assert_eq!(foreign_dns_exit_category(&result, "cli_lookup"), "lookup");
    assert_eq!(
        foreign_dns_response_indicator(&result, "edge-sentinel", expected),
        "nxdomain"
    );
    for (message, indicator) in [
        ("SERVFAIL", "servfail"),
        ("REFUSED", "refused"),
        ("No answer", "no_error_no_a"),
        ("NOERROR", "no_error_no_a"),
    ] {
        result.stdout = format!("*** Can't find edge-sentinel.: {message}\n").into_bytes();
        assert_eq!(
            foreign_dns_response_indicator(&result, "edge-sentinel", expected),
            indicator
        );
    }
    result.stdout = b"Name: edge-sentinel\nAddress: 172.29.244.20\n".to_vec();
    assert_eq!(
        foreign_dns_response_indicator(&result, "edge-sentinel", expected),
        "has_expected_a"
    );
    result.stdout = b"Name: edge-sentinel\nAddress: 172.29.244.21\nNOERROR\n".to_vec();
    assert_eq!(
        foreign_dns_response_indicator(&result, "edge-sentinel", expected),
        "other"
    );
    result.stdout = b"NXDOMAIN SERVFAIL\n".to_vec();
    assert_eq!(
        foreign_dns_response_indicator(&result, "edge-sentinel", expected),
        "other"
    );
    result.output_limit = true;
    assert_eq!(
        foreign_dns_response_indicator(&result, "edge-sentinel", expected),
        "other"
    );
    result.output_limit = false;
    result.stdout = b"\xff NXDOMAIN".to_vec();
    assert_eq!(
        foreign_dns_response_indicator(&result, "edge-sentinel", expected),
        "other"
    );
    result.code = Some(124);
    assert_eq!(foreign_dns_exit_category(&result, "cli_timeout"), "timeout");
    result.code = Some(2);
    assert_eq!(
        foreign_dns_exit_category(&result, "cli_unclassified"),
        "other"
    );
    result.success = true;
    assert_eq!(
        foreign_dns_exit_category(&result, "alias_missing"),
        "success"
    );
}

struct DnsDiagnostic {
    peer: &'static str,
    resolver: &'static str,
    default_a: &'static str,
    explicit_a: &'static str,
    dotted_a: &'static str,
    name_http: &'static str,
    ip_http: &'static str,
    edge_app: &'static str,
    cleanup: &'static str,
}

impl DnsDiagnostic {
    fn new() -> Self {
        Self {
            peer: "unavailable",
            resolver: "unrun",
            default_a: "unrun",
            explicit_a: "unrun",
            dotted_a: "unrun",
            name_http: "unrun",
            ip_http: "unrun",
            edge_app: "unrun",
            cleanup: "fail",
        }
    }

    fn emit(&self) {
        // Every interpolated value is selected from the fixed categories below.
        eprintln!(
            "DOCKERLENS_NATIVE_DNS_DIAG: peer={} resolver={} default_a={} explicit_a={} dotted_a={} name_http={} ip_http={} edge_app={} cleanup={}",
            self.peer,
            self.resolver,
            self.default_a,
            self.explicit_a,
            self.dotted_a,
            self.name_http,
            self.ip_http,
            self.edge_app,
            self.cleanup,
        );
    }
}

fn resolver_category(bytes: &[u8]) -> &'static str {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return "unavailable";
    };
    let mut embedded = false;
    let mut search = false;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") => embedded |= words.next() == Some("127.0.0.11"),
            Some("search") => search |= words.next().is_some(),
            _ => {}
        }
    }
    match (embedded, search) {
        (true, true) => "embedded_search",
        (true, false) => "embedded_plain",
        (false, true) => "other_search",
        (false, false) => "other_plain",
    }
}

#[test]
fn resolver_configuration_classification_remains_closed() {
    assert_eq!(
        resolver_category(b"nameserver 127.0.0.11\nsearch private.example\n"),
        "embedded_search"
    );
    assert_eq!(
        resolver_category(b"nameserver 127.0.0.11\n"),
        "embedded_plain"
    );
    assert_eq!(
        resolver_category(b"nameserver 192.0.2.1\nsearch private.example\n"),
        "other_search"
    );
    assert_eq!(resolver_category(b"\xff"), "unavailable");
}

fn remove_exact_network_container(name: &str) -> bool {
    private_docker_command("8")
        .args(["rm", "-f", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

struct DnsPeerGuard<'a> {
    name: &'a str,
    cleaned: bool,
    deadline: Instant,
}

impl DnsPeerGuard<'_> {
    fn cleanup(&mut self) -> bool {
        self.cleaned = remove_exact_network_container(self.name);
        if !self.cleaned && diagnostic_has_budget(self.deadline, DNS_CLI_HARD_LIMIT_SECS, 0) {
            self.cleaned = remove_exact_network_container(self.name);
        }
        self.cleaned
    }
}

impl Drop for DnsPeerGuard<'_> {
    fn drop(&mut self) {
        if !self.cleaned && diagnostic_has_budget(self.deadline, DNS_CLI_HARD_LIMIT_SECS, 0) {
            let _ = remove_exact_network_container(self.name);
        }
    }
}

struct ExactNetworkFixture<'a> {
    name: &'a str,
    cleaned: bool,
}

impl ExactNetworkFixture<'_> {
    fn cleanup(&mut self) -> bool {
        self.cleaned = remove_exact_network_container(self.name);
        self.cleaned
    }
}

impl Drop for ExactNetworkFixture<'_> {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = remove_exact_network_container(self.name);
        }
    }
}

struct InternalProofResources {
    run_id: String,
    containers: Vec<String>,
    networks: Vec<String>,
    subnet_diagnostics: Option<ProofSubnetContext>,
    fixture_subnet: Option<FixtureSubnetContext>,
}

impl InternalProofResources {
    fn new(run_id: &str) -> Self {
        Self {
            run_id: run_id.to_owned(),
            containers: Vec::new(),
            networks: Vec::new(),
            subnet_diagnostics: None,
            fixture_subnet: None,
        }
    }

    fn engine_absent(run_id: &str, kind: &str, name: &str) -> bool {
        let api_version = required("NATIVE_API_VERSION");
        let path = if kind == "container" {
            format!("/v{api_version}/containers/{name}/json")
        } else {
            format!("/v{api_version}/networks/{name}")
        };
        if !allowed_request(
            "GET",
            &path,
            &api_version,
            run_id,
            &required("NATIVE_FIXTURE_IMAGE"),
            None,
        ) {
            return false;
        }
        let result = Command::new("timeout")
            .args([
                "--kill-after=1",
                "3",
                "curl",
                "-sS",
                "--max-time",
                "2",
                "--unix-socket",
                &required("NATIVE_ENGINE_SOCKET"),
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                &format!("http://localhost{path}"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();
        result.is_ok_and(|result| exact_http_absence(result.status.success(), &result.stdout))
    }

    fn remove_owned(run_id: &str, kind: &str, name: &str) -> bool {
        let format = if kind == "container" {
            "{{index .Config.Labels \"io.dockerlens.native-run\"}}"
        } else {
            "{{index .Labels \"io.dockerlens.native-run\"}}"
        };
        let inspected = bounded_cli(&[kind, "inspect", "--format", format, name], "2");
        if !inspected.success || inspected.output_limit {
            // A previous removal may have succeeded despite an inconclusive
            // readback. Only Engine's exact 404 can clear that retained name.
            return Self::engine_absent(run_id, kind, name);
        }
        if inspected.stdout != format!("{run_id}\n").as_bytes() {
            return false;
        }
        let removed = if kind == "container" {
            bounded_cli(&[kind, "rm", "-f", name], "2")
        } else {
            bounded_cli(&[kind, "rm", name], "2")
        };
        // CLI removal can report failure after the daemon completed it; the
        // independent exact Engine readback determines the final outcome.
        let _ = removed;
        Self::engine_absent(run_id, kind, name)
    }

    fn cleanup(&mut self) -> bool {
        let run_id = self.run_id.clone();
        let mut remove = |kind: &str, name: &str| Self::remove_owned(&run_id, kind, name);
        let containers = retain_unremoved(&mut self.containers, "container", &mut remove);
        let networks = retain_unremoved(&mut self.networks, "network", &mut remove);
        containers && networks
    }

    fn require_budget(&self, next_operation_secs: u64) {
        let deadline: u64 = required("NATIVE_NETWORK_TEST_DEADLINE_EPOCH")
            .parse()
            .expect("bounded native deadline epoch");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current native clock")
            .as_secs();
        let outstanding = self.containers.len() + self.networks.len();
        assert!(
            proof_budget_sufficient(
                deadline.saturating_sub(now),
                outstanding,
                next_operation_secs,
            ),
            "native proof reserves exact cleanup before its 180-second deadline"
        );
    }
}

fn exact_http_absence(command_succeeded: bool, status: &[u8]) -> bool {
    command_succeeded && status == b"404"
}

fn proof_required_remaining(outstanding: usize, next_operation_secs: u64) -> u64 {
    // At most two three-second CLI calls and one four-second status-only GET
    // per registered resource, with ten seconds for process teardown.
    outstanding as u64 * 10 + 10 + next_operation_secs
}

fn proof_budget_sufficient(remaining_secs: u64, outstanding: usize, next_secs: u64) -> bool {
    remaining_secs >= proof_required_remaining(outstanding, next_secs)
}

fn retain_unremoved<F>(names: &mut Vec<String>, kind: &str, remove: &mut F) -> bool
where
    F: FnMut(&str, &str) -> bool,
{
    let mut failed = Vec::new();
    for name in std::mem::take(names).into_iter().rev() {
        if !remove(kind, &name) {
            failed.push(name);
        }
    }
    *names = failed;
    names.is_empty()
}

fn proof_cli(resources: &InternalProofResources, args: &[&str]) -> BoundedDnsCliOutput {
    resources.require_budget(8);
    bounded_cli(args, "6")
}

fn proof_podman(resources: &InternalProofResources, args: &[&str]) -> BoundedDnsCliOutput {
    resources.require_budget(8);
    let mut command = Command::new("timeout");
    command.args(["--kill-after=1", "6"]);
    if required("NATIVE_PODMAN_USE_SUDO") == "1" {
        command.args(["sudo", "-n"]);
        command.args(crate::native_outer_test_command::prefix());
    } else {
        command.args(crate::native_outer_test_command::prefix());
    }
    bounded_cli_command(&mut command, args)
}

fn proof_podman_ok(resources: &InternalProofResources, args: &[&str]) -> Vec<u8> {
    let result = proof_podman(resources, args);
    assert!(
        result.success && !result.output_limit,
        "bounded task-owned Podman read succeeds"
    );
    result.stdout
}

fn private_sidecar_ipv4(text: &str) -> Option<Ipv4Addr> {
    let address = text.parse::<Ipv4Addr>().ok()?;
    (address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_unspecified())
    .then_some(address)
}

fn outer_attachment_ipv4(
    resources: &InternalProofResources,
    name: &str,
    network: &str,
) -> Ipv4Addr {
    let bytes = proof_podman_ok(
        resources,
        &[
            "inspect",
            "--format",
            "{{json .NetworkSettings.Networks}}",
            name,
        ],
    );
    let value: Value = serde_json::from_slice(&bytes).expect("private outer network JSON");
    let networks = value.as_object().expect("outer network map");
    assert_eq!(networks.len(), 1, "outer fixture is single-homed");
    let address = networks[network]["IPAddress"]
        .as_str()
        .expect("outer IPv4 text");
    private_sidecar_ipv4(address).expect("private task-owned outer IPv4")
}

fn outer_namespace(resources: &InternalProofResources, name: &str) -> String {
    let bytes = proof_podman_ok(resources, &["exec", name, "readlink", "/proc/self/ns/net"]);
    let text = std::str::from_utf8(&bytes).expect("outer network namespace text");
    let inode = text
        .strip_prefix("net:[")
        .and_then(|text| text.strip_suffix("]\n"))
        .expect("outer network namespace shape");
    assert!(!inode.is_empty() && inode.bytes().all(|byte| byte.is_ascii_digit()));
    inode.to_owned()
}

fn assert_outer_sidecar_topology(
    resources: &InternalProofResources,
    run_id: &str,
    sidecar_ip: Ipv4Addr,
) {
    let outer = required("NATIVE_OUTER_CONTAINER");
    let sidecar = format!("dl-native-egress-{run_id}");
    let network = format!("dl-native-net-{run_id}");
    assert_eq!(outer, format!("dl-native-{run_id}"));
    let observed_sidecar = outer_attachment_ipv4(resources, &sidecar, &network);
    let daemon_ip = outer_attachment_ipv4(resources, &outer, &network);
    assert_eq!(observed_sidecar, sidecar_ip);
    assert_ne!(daemon_ip, sidecar_ip, "sidecar is not daemon address");
    assert_ne!(
        outer_namespace(resources, &outer),
        outer_namespace(resources, &sidecar),
        "sidecar and daemon have distinct network namespaces"
    );
    assert_eq!(
        proof_podman_ok(
            resources,
            &["inspect", "--format", "{{.State.Running}}", &sidecar]
        ),
        b"true\n"
    );
}

#[test]
fn outer_sidecar_address_rejects_host_and_nonprivate_addresses() {
    assert_eq!(
        private_sidecar_ipv4("10.88.0.3"),
        Some(Ipv4Addr::new(10, 88, 0, 3))
    );
    for address in [
        "127.0.0.1",
        "169.254.1.1",
        "0.0.0.0",
        "8.8.8.8",
        "private-value",
    ] {
        assert_eq!(private_sidecar_ipv4(address), None);
    }
}

fn wget_failure_category(stderr: &[u8]) -> &'static str {
    let message = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if message.contains("connection refused") {
        "connection_refused"
    } else if message.contains("no route to host") || message.contains("network is unreachable") {
        "no_route"
    } else if message.contains("timed out") || message.contains("timeout") {
        "timeout"
    } else if message.contains("server returned error") || message.contains("http/1.") {
        "http_error"
    } else {
        "unknown"
    }
}

// A pure observation of ONE target IPv4 against ONE already-inspected network.
// Never prints addresses or claims outer/inner network disjointness.
enum SubnetMatch {
    Ipv4(bool),
    Ipv6,
}

fn ipv4_in_subnet(address: Ipv4Addr, subnet: &str) -> Option<SubnetMatch> {
    let (network, prefix) = subnet.split_once('/')?;
    if prefix.is_empty()
        || prefix.len() > 3
        || !prefix.bytes().all(|byte| byte.is_ascii_digit())
        || (prefix.len() > 1 && prefix.starts_with('0'))
    {
        return None;
    }
    let prefix = prefix.parse::<u8>().ok()?;
    match network.parse::<IpAddr>().ok()? {
        IpAddr::V4(network) if prefix <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            let network = u32::from(network);
            if network & mask != network {
                return None;
            }
            Some(SubnetMatch::Ipv4(u32::from(address) & mask == network))
        }
        IpAddr::V6(network) if prefix <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            let network = u128::from(network);
            if network & mask != network {
                return None;
            }
            Some(SubnetMatch::Ipv6)
        }
        _ => None,
    }
}

fn sidecar_on_subnet(address: Ipv4Addr, network: &Value) -> &'static str {
    let Some(configs) = network
        .get("IPAM")
        .and_then(|ipam| ipam.get("Config"))
        .and_then(Value::as_array)
    else {
        return "unknown";
    };
    let mut ipv4_seen = false;
    let mut contains = false;
    for config in configs {
        let Some(subnet) = config.get("Subnet").and_then(Value::as_str) else {
            return "unknown";
        };
        match ipv4_in_subnet(address, subnet) {
            Some(SubnetMatch::Ipv4(found)) => {
                ipv4_seen = true;
                contains |= found;
            }
            Some(SubnetMatch::Ipv6) => {}
            None => return "unknown",
        }
    }
    if !ipv4_seen {
        "unknown"
    } else if contains {
        "true"
    } else {
        "false"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SidecarSubnetDiagnostics {
    internal: &'static str,
    control: &'static str,
}

impl SidecarSubnetDiagnostics {
    const fn new() -> Self {
        Self {
            internal: "unknown",
            control: "unknown",
        }
    }

    fn record(&mut self, is_internal: bool, address: Ipv4Addr, network: &Value) {
        let observation = sidecar_on_subnet(address, network);
        if is_internal {
            self.internal = observation;
        } else {
            self.control = observation;
        }
    }
}

// Held only around the ordinary control wget, never a general request capability.
struct ProofSubnetContext {
    observations: SidecarSubnetDiagnostics,
    default_bridge: Option<DefaultBridgeContext>,
    address: Ipv4Addr,
    client: String,
}

struct DefaultBridgeContext {
    api: crate::version::ApiVersion,
    socket: PathBuf,
}

const DEFAULT_BRIDGE_RESPONSE_CAP: usize = 64 * 1024;
const TOPOLOGY_RESPONSE_CAP: usize = 1024 * 1024;

fn exact_topology_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn bounded_topology_json(value: &Value) -> bool {
    let mut pending = vec![(value, 0)];
    let mut count = 0;
    while let Some((value, depth)) = pending.pop() {
        count += 1;
        if count > 8192 || depth > 20 {
            return false;
        }
        match value {
            Value::Array(values) => pending.extend(values.iter().map(|value| (value, depth + 1))),
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)))
            }
            _ => {}
        }
    }
    true
}

#[derive(Clone, Copy)]
struct TopologyPool {
    address: IpAddr,
    prefix: u8,
}

impl TopologyPool {
    fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = text.split_once('/')?;
        let address: IpAddr = address.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        if format!("{address}/{prefix}") != text {
            return None;
        }
        let pool = Self { address, prefix };
        let canonical = match address {
            IpAddr::V4(address) if prefix <= 32 => u32::from(address) & !pool.mask4() == 0,
            IpAddr::V6(address) if prefix <= 128 => {
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                u128::from(address) & !mask == 0
            }
            _ => false,
        };
        canonical.then_some(pool)
    }

    fn mask4(self) -> u32 {
        u32::MAX
            .checked_shl(32 - u32::from(self.prefix))
            .unwrap_or(0)
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(pool), IpAddr::V4(address)) => {
                u32::from(address) & self.mask4() == u32::from(pool)
            }
            (IpAddr::V6(pool), IpAddr::V6(address)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(address) & mask == u128::from(pool)
            }
            _ => false,
        }
    }

    fn overlaps(self, other: Self) -> bool {
        self.contains(other.address) || other.contains(self.address)
    }
}

fn topology_ipam(configs: &Value) -> Option<Vec<TopologyPool>> {
    let configs = configs.as_array()?;
    if configs.is_empty() || configs.len() > 64 {
        return None;
    }
    let mut pools = Vec::new();
    for config in configs {
        let object = config.as_object()?;
        if object.keys().any(|key| {
            !["Subnet", "Gateway", "IPRange", "AuxiliaryAddresses"].contains(&key.as_str())
        }) {
            return None;
        }
        let pool = TopologyPool::parse(config.get("Subnet")?.as_str()?)?;
        if let Some(gateway) = config.get("Gateway") {
            let gateway = gateway.as_str()?;
            if !gateway.is_empty() && !pool.contains(gateway.parse().ok()?) {
                return None;
            }
        }
        if let Some(range) = config.get("IPRange") {
            let range = range.as_str()?;
            if !range.is_empty() {
                let range = TopologyPool::parse(range)?;
                if range.prefix < pool.prefix || !pool.contains(range.address) {
                    return None;
                }
            }
        }
        if let Some(auxiliary) = config.get("AuxiliaryAddresses") {
            let auxiliary = auxiliary.as_object()?;
            if auxiliary.len() > 256
                || auxiliary.values().any(|address| {
                    address
                        .as_str()
                        .and_then(|address| address.parse::<IpAddr>().ok())
                        .is_none_or(|address| !pool.contains(address))
                })
            {
                return None;
            }
        }
        if pools.iter().any(|other| pool.overlaps(*other)) {
            return None;
        }
        pools.push(pool);
    }
    pools
        .iter()
        .any(|pool| pool.address.is_ipv4())
        .then_some(pools)
}

fn topology_record_pools(
    value: &Value,
    run: &str,
    candidate: &str,
    backend: &str,
    daemon_id: &str,
    sidecar_ip: Ipv4Addr,
) -> Option<Vec<TopologyPool>> {
    if !bounded_topology_json(value)
        || !exact_topology_keys(
            value,
            &[
                "schema_version",
                "kind",
                "candidate",
                "run",
                "backend",
                "network",
                "endpoints",
            ],
        )
        || value["schema_version"].as_u64() != Some(1)
        || value["kind"] != "test-only-outer-network-topology"
        || value["candidate"] != candidate
        || value["run"] != run
        || value["backend"] != backend
    {
        return None;
    }
    let network = &value["network"];
    let id = network.get("id")?.as_str()?;
    if !exact_topology_keys(
        network,
        &["id", "name", "driver", "scope", "ipam_driver", "ipv4_pools"],
    ) || canonical_inspected_container_id(&json!({"Id": id})).is_none()
        || network["name"] != format!("dl-native-net-{run}")
        || network["driver"] != "bridge"
    {
        return None;
    }
    match backend {
        "docker" if network["scope"] == "local" && network["ipam_driver"] == "default" => {}
        crate::native_outer_test_command::PODMAN_ENGINE
            if network["scope"].is_null() && network["ipam_driver"] == "host-local" => {}
        _ => return None,
    }
    let texts = network["ipv4_pools"].as_array()?;
    if texts.is_empty() || texts.len() > 64 {
        return None;
    }
    let pools: Vec<_> = texts
        .iter()
        .map(|value| TopologyPool::parse(value.as_str()?))
        .collect::<Option<_>>()?;
    if pools.iter().any(|pool| !pool.address.is_ipv4())
        || pools
            .iter()
            .enumerate()
            .any(|(index, pool)| pools[index + 1..].iter().any(|other| pool.overlaps(*other)))
        || (backend == "docker" && texts != &vec![json!("10.253.253.0/24")])
    {
        return None;
    }
    let endpoints = &value["endpoints"];
    if !exact_topology_keys(endpoints, &["daemon", "sidecar"]) {
        return None;
    }
    for (role, name) in [
        ("daemon", format!("dl-native-{run}")),
        ("sidecar", format!("dl-native-egress-{run}")),
    ] {
        let endpoint = &endpoints[role];
        let id = endpoint.get("id")?.as_str()?;
        let address: Ipv4Addr = endpoint.get("ipv4")?.as_str()?.parse().ok()?;
        if !exact_topology_keys(endpoint, &["id", "name", "ipv4"])
            || canonical_inspected_container_id(&json!({"Id": id})).is_none()
            || endpoint["name"] != name
            || !pools.iter().any(|pool| pool.contains(address.into()))
        {
            return None;
        }
    }
    if endpoints["daemon"]["id"] != daemon_id
        || endpoints["daemon"]["id"] == endpoints["sidecar"]["id"]
        || endpoints["daemon"]["ipv4"] == endpoints["sidecar"]["ipv4"]
        || endpoints["sidecar"]["ipv4"] != sidecar_ip.to_string()
    {
        return None;
    }
    Some(pools)
}

fn read_topology_record(directory: &std::path::Path, run: &str) -> Option<Value> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if directory.file_name()?.to_str()? != format!("dockerlens-native.{run}")
        || fs::canonicalize(directory).ok()? != directory
    {
        return None;
    }
    let parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(directory)
        .ok()?;
    let parent_info = parent.metadata().ok()?;
    if parent_info.mode() & 0o777 != 0o700
        || parent_info.uid() != fs::metadata("/proc/self").ok()?.uid()
    {
        return None;
    }
    let anchored = PathBuf::from(format!(
        "/proc/self/fd/{}/outer-network-topology-v1.json",
        parent.as_raw_fd()
    ));
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&anchored)
        .ok()?;
    let before = file.metadata().ok()?;
    let identity = |info: &fs::Metadata| {
        (
            info.dev(),
            info.ino(),
            info.uid(),
            info.gid(),
            info.mode(),
            info.nlink(),
            info.len(),
            info.mtime(),
            info.mtime_nsec(),
            info.ctime(),
            info.ctime_nsec(),
        )
    };
    if !before.is_file()
        || before.uid() != parent_info.uid()
        || before.mode() & 0o777 != 0o600
        || before.nlink() != 1
        || before.len() > DEFAULT_BRIDGE_RESPONSE_CAP as u64
    {
        return None;
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((DEFAULT_BRIDGE_RESPONSE_CAP + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    let current_parent = fs::symlink_metadata(directory).ok()?;
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata().ok()?)
        || identity(&before) != identity(&fs::symlink_metadata(&anchored).ok()?)
        || (
            parent_info.dev(),
            parent_info.ino(),
            parent_info.uid(),
            parent_info.mode(),
        ) != (
            current_parent.dev(),
            current_parent.ino(),
            current_parent.uid(),
            current_parent.mode(),
        )
    {
        return None;
    }
    let UniqueDiagnosticJson(value) = serde_json::from_slice(&bytes).ok()?;
    bounded_topology_json(&value).then_some(value)
}

fn retained_topology_names(run: &str) -> Vec<String> {
    let mut names = vec![
        "bridge".to_owned(),
        format!("dl-{run}-net"),
        format!("dl-target-{run}-net"),
    ];
    for suffix in [
        "backend",
        "edge",
        "external",
        "oracle",
        "proof-internal",
        "proof-control",
        "proof-cli-internal",
        "proof-cli-control",
    ] {
        names.push(format!("dl-network-{run}-{suffix}"));
    }
    names
}

fn inner_topology_disjoint(
    networks: &Value,
    run: &str,
    held_ids: &[(String, String)],
    outer: &[TopologyPool],
) -> bool {
    assess_inner_topology(networks, run, held_ids, outer).is_ok()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InnerTopologyRefusal {
    SnapshotArray,
    SnapshotBounds,
    NetworkCount,
    HeldCount,
    OuterPools,
    HeldRoles,
    HeldIds,
    NativeId,
    NativeName,
    DuplicateId,
    DuplicateName,
    Scope,
    IpamDriver,
    BuiltinPools,
    BridgeMembership,
    BridgeDriver,
    HeldBinding,
    BridgeIpam,
    Ipv4Overlap,
    RetainedSet,
}

impl InnerTopologyRefusal {
    fn diagnostic(self) -> &'static [u8] {
        match self {
            Self::SnapshotArray => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=snapshot_array\n",
            Self::SnapshotBounds => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=snapshot_bounds\n",
            Self::NetworkCount => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=network_count\n",
            Self::HeldCount => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=held_count\n",
            Self::OuterPools => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=outer_pools\n",
            Self::HeldRoles => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=held_roles\n",
            Self::HeldIds => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=held_ids\n",
            Self::NativeId => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=native_id\n",
            Self::NativeName => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=native_name\n",
            Self::DuplicateId => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=duplicate_id\n",
            Self::DuplicateName => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=duplicate_name\n",
            Self::Scope => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=scope\n",
            Self::IpamDriver => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=ipam_driver\n",
            Self::BuiltinPools => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=builtin_pools\n",
            Self::BridgeMembership => {
                b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=bridge_membership\n"
            }
            Self::BridgeDriver => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=bridge_driver\n",
            Self::HeldBinding => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=held_binding\n",
            Self::BridgeIpam => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=bridge_ipam\n",
            Self::Ipv4Overlap => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=ipv4_overlap\n",
            Self::RetainedSet => b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=retained_set\n",
        }
    }
}

fn emit_inner_topology_refusal(output: &mut impl Write, reason: InnerTopologyRefusal) {
    // Presentation is best effort; an I/O error must not replace the assertion
    // or interrupt the existing panic-time resource cleanup owner.
    let _ = output.write_all(reason.diagnostic());
}

fn assess_inner_topology(
    networks: &Value,
    run: &str,
    held_ids: &[(String, String)],
    outer: &[TopologyPool],
) -> Result<(), InnerTopologyRefusal> {
    let Some(networks) = networks.as_array() else {
        return Err(InnerTopologyRefusal::SnapshotArray);
    };
    let expected = retained_topology_names(run);
    if !bounded_topology_json(&Value::Array(networks.clone())) {
        return Err(InnerTopologyRefusal::SnapshotBounds);
    }
    if networks.len() != expected.len() + 2 {
        return Err(InnerTopologyRefusal::NetworkCount);
    }
    if held_ids.len() != 5 {
        return Err(InnerTopologyRefusal::HeldCount);
    }
    if outer.is_empty() {
        return Err(InnerTopologyRefusal::OuterPools);
    }
    let held_names: std::collections::HashSet<_> =
        held_ids.iter().map(|(name, _)| name.as_str()).collect();
    if held_names.len() != 5
        || !held_names.contains(format!("dl-{run}-net").as_str())
        || [
            "proof-internal",
            "proof-control",
            "proof-cli-internal",
            "proof-cli-control",
        ]
        .iter()
        .any(|suffix| !held_names.contains(format!("dl-network-{run}-{suffix}").as_str()))
    {
        return Err(InnerTopologyRefusal::HeldRoles);
    }
    let held_values: std::collections::HashSet<_> =
        held_ids.iter().map(|(_, id)| id.as_str()).collect();
    if held_values.len() != 5
        || held_values
            .iter()
            .any(|id| canonical_inspected_container_id(&json!({"Id": id})).is_none())
    {
        return Err(InnerTopologyRefusal::HeldIds);
    }
    let mut ids = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    for network in networks {
        let Some(id) = canonical_inspected_container_id(network) else {
            return Err(InnerTopologyRefusal::NativeId);
        };
        let Some(name) = network.get("Name").and_then(Value::as_str) else {
            return Err(InnerTopologyRefusal::NativeName);
        };
        if !ids.insert(id) {
            return Err(InnerTopologyRefusal::DuplicateId);
        }
        if !names.insert(name) {
            return Err(InnerTopologyRefusal::DuplicateName);
        }
        if network["Scope"] != "local" {
            return Err(InnerTopologyRefusal::Scope);
        }
        if network["IPAM"]["Driver"] != "default" {
            return Err(InnerTopologyRefusal::IpamDriver);
        }
        let builtin = matches!(
            (name, network["Driver"].as_str()),
            ("host", Some("host")) | ("none", Some("null"))
        );
        if builtin {
            if !network["IPAM"].get("Config").is_some_and(|config| {
                config.is_null() || config.as_array().is_some_and(Vec::is_empty)
            }) {
                return Err(InnerTopologyRefusal::BuiltinPools);
            }
            continue;
        }
        if !expected.iter().any(|expected| expected == name) {
            return Err(InnerTopologyRefusal::BridgeMembership);
        }
        if network["Driver"] != "bridge" {
            return Err(InnerTopologyRefusal::BridgeDriver);
        }
        if held_ids
            .iter()
            .any(|(held_name, held_id)| held_name == name && held_id != id)
        {
            return Err(InnerTopologyRefusal::HeldBinding);
        }
        let Some(pools) = topology_ipam(&network["IPAM"]["Config"]) else {
            return Err(InnerTopologyRefusal::BridgeIpam);
        };
        if pools
            .iter()
            .filter(|pool| pool.address.is_ipv4())
            .any(|pool| outer.iter().any(|other| pool.overlaps(*other)))
        {
            return Err(InnerTopologyRefusal::Ipv4Overlap);
        }
    }
    if !(expected.iter().all(|name| names.contains(name.as_str()))
        && names.contains("host")
        && names.contains("none")
        && held_ids.iter().all(|(name, _)| expected.contains(name)))
    {
        return Err(InnerTopologyRefusal::RetainedSet);
    }
    Ok(())
}

fn read_inner_topology(context: &DefaultBridgeContext) -> Option<Value> {
    // This fixed test-only read is deliberately outside the generic executor's
    // allowlist and product Discovery API. Its caller owns the original budget.
    let command = default_bridge_command(context);
    // Rebuild the sole URL, retaining all reviewed timeout/socket restrictions.
    let args: Vec<_> = command.get_args().map(|arg| arg.to_owned()).collect();
    let mut command = Command::new("timeout");
    command.args(&args[..args.len() - 1]).arg(format!(
        "http://localhost/v{}.{}/networks",
        context.api.major, context.api.minor
    ));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take((TOPOLOGY_RESPONSE_CAP + 6) as u64)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() <= TOPOLOGY_RESPONSE_CAP + 5).then_some(bytes)
    });
    let status = child.wait();
    let bytes = reader.join().ok()??;
    if !status.ok()?.success() {
        return None;
    }
    decode_inner_topology_response(&bytes)
}

fn decode_inner_topology_response(bytes: &[u8]) -> Option<Value> {
    let body = bytes.strip_suffix(b"\n200")?;
    if body.len() > TOPOLOGY_RESPONSE_CAP {
        return None;
    }
    let UniqueDiagnosticJson(value) = serde_json::from_slice(body).ok()?;
    bounded_topology_json(&value).then_some(value)
}

mod topology_tests {
    use super::*;

    fn fixture() -> (Value, Vec<(String, String)>, Vec<TopologyPool>) {
        // Independent lifetime expectation: three deliberately removed test-6
        // controls must NOT be required at this boundary.
        let names = [
            "bridge",
            "dl-test-net",
            "dl-target-test-net",
            "dl-network-test-backend",
            "dl-network-test-edge",
            "dl-network-test-external",
            "dl-network-test-oracle",
            "dl-network-test-proof-internal",
            "dl-network-test-proof-control",
            "dl-network-test-proof-cli-internal",
            "dl-network-test-proof-cli-control",
        ];
        let mut networks: Vec<_> = names.iter().enumerate().map(|(index, name)| json!({
            "Id": format!("{:064x}", index + 1), "Name": name, "Driver": "bridge", "Scope": "local",
            "IPAM": {"Driver": "default", "Config": [{"Subnet": format!("172.20.{index}.0/24")}]}
        })).collect();
        let held = [1, 7, 8, 9, 10]
            .iter()
            .map(|index| (names[*index].to_owned(), format!("{:064x}", index + 1)))
            .collect();
        for (name, driver, id) in [("host", "host", 12), ("none", "null", 13)] {
            networks.push(json!({"Id": format!("{id:064x}"), "Name": name, "Driver": driver, "Scope": "local", "IPAM": {"Driver": "default", "Config": []}}));
        }
        (
            json!(networks),
            held,
            vec![TopologyPool::parse("10.253.253.0/24").unwrap()],
        )
    }

    fn record() -> Value {
        json!({"schema_version": 1, "kind": "test-only-outer-network-topology", "candidate": "c".repeat(40), "run": "test", "backend": "docker",
            "network": {"id": "a".repeat(64), "name": "dl-native-net-test", "driver": "bridge", "scope": "local", "ipam_driver": "default", "ipv4_pools": ["10.253.253.0/24"]},
            "endpoints": {"daemon": {"id": "b".repeat(64), "name": "dl-native-test", "ipv4": "10.253.253.2"}, "sidecar": {"id": "d".repeat(64), "name": "dl-native-egress-test", "ipv4": "10.253.253.3"}}})
    }

    fn record_valid(value: &Value) -> bool {
        topology_record_pools(
            value,
            "test",
            &"c".repeat(40),
            "docker",
            &"b".repeat(64),
            Ipv4Addr::new(10, 253, 253, 3),
        )
        .is_some()
    }

    #[test]
    fn topology_exact_retained_set_and_mixed_family_are_required() {
        let (mut networks, held, outer) = fixture();
        assert_eq!(retained_topology_names("test").len(), 11);
        assert!(inner_topology_disjoint(&networks, "test", &held, &outer));
        networks[0]["IPAM"]["Config"]
            .as_array_mut()
            .unwrap()
            .push(json!({"Subnet": "fd00::/64", "Gateway": "fd00::1"}));
        assert!(inner_topology_disjoint(&networks, "test", &held, &outer));
        for index in 0..13 {
            let mut partial = networks.clone();
            partial.as_array_mut().unwrap().remove(index);
            assert!(!inner_topology_disjoint(&partial, "test", &held, &outer));
        }
        for case in 0..9 {
            let mut changed = networks.clone();
            match case {
                0 => changed[0]["Name"] = json!("unknown-network"),
                1 => changed[0]["Driver"] = json!("overlay"),
                2 => changed[0]["Id"] = changed[1]["Id"].clone(),
                3 => changed[0]["Name"] = changed[1]["Name"].clone(),
                4 => changed[11]["Driver"] = json!("bridge"),
                5 => changed[12]["IPAM"]["Config"] = json!("invalid"),
                6 => changed[0]["IPAM"]["Config"] = json!([]),
                7 => changed[0]["IPAM"]["Driver"] = json!("other"),
                _ => changed[0]["Scope"] = json!("swarm"),
            }
            assert!(
                !inner_topology_disjoint(&changed, "test", &held, &outer),
                "case {case}"
            );
        }
    }

    #[test]
    fn topology_both_builtin_configs_require_present_null_or_empty_array() {
        let (networks, held, outer) = fixture();
        for host_config in [Value::Null, json!([])] {
            for none_config in [Value::Null, json!([])] {
                let mut changed = networks.clone();
                changed[11]["IPAM"]["Config"] = host_config.clone();
                changed[12]["IPAM"]["Config"] = none_config;
                assert!(assess_inner_topology(&changed, "test", &held, &outer).is_ok());
                assert!(inner_topology_disjoint(&changed, "test", &held, &outer));
            }
        }
        for index in [11, 12] {
            let mut missing = networks.clone();
            missing[index]["IPAM"]
                .as_object_mut()
                .unwrap()
                .remove("Config");
            assert!(
                assess_inner_topology(&missing, "test", &held, &outer)
                    == Err(InnerTopologyRefusal::BuiltinPools)
            );
            for config in [
                json!([{}]),
                json!([{"Subnet": "192.0.2.0/24"}]),
                json!([{"Subnet": "fd00::/64"}]),
                json!([null]),
                json!("private-config-canary"),
                json!(0),
                json!(1.5),
                json!(false),
                json!(true),
                json!({}),
            ] {
                let mut changed = networks.clone();
                changed[index]["IPAM"]["Config"] = config;
                assert!(
                    assess_inner_topology(&changed, "test", &held, &outer)
                        == Err(InnerTopologyRefusal::BuiltinPools)
                );
            }
        }
    }

    #[test]
    fn topology_builtin_null_does_not_relax_pairs_metadata_or_bridge_pools() {
        let (networks, held, outer) = fixture();
        for index in [11, 12] {
            for (field, value, reason) in [
                (
                    "Name",
                    json!("not-a-builtin"),
                    InnerTopologyRefusal::BridgeMembership,
                ),
                (
                    "Driver",
                    json!("bridge"),
                    InnerTopologyRefusal::BridgeMembership,
                ),
                ("Scope", json!("swarm"), InnerTopologyRefusal::Scope),
                ("Id", json!("invalid"), InnerTopologyRefusal::NativeId),
            ] {
                let mut changed = networks.clone();
                changed[index]["IPAM"]["Config"] = Value::Null;
                changed[index][field] = value;
                assert!(assess_inner_topology(&changed, "test", &held, &outer) == Err(reason));
            }
            let mut changed = networks.clone();
            changed[index]["IPAM"]["Config"] = Value::Null;
            changed[index]["IPAM"]["Driver"] = json!("other");
            assert!(
                assess_inner_topology(&changed, "test", &held, &outer)
                    == Err(InnerTopologyRefusal::IpamDriver)
            );
            let mut changed = networks.clone();
            changed[index]["IPAM"]["Config"] = Value::Null;
            changed[index]["Driver"] = json!(if index == 11 { "null" } else { "host" });
            assert!(
                assess_inner_topology(&changed, "test", &held, &outer)
                    == Err(InnerTopologyRefusal::BridgeMembership)
            );
        }
        for index in 0..11 {
            for config in [Value::Null, json!([]), json!([{}]), json!(false)] {
                let mut changed = networks.clone();
                changed[11]["IPAM"]["Config"] = Value::Null;
                changed[12]["IPAM"]["Config"] = Value::Null;
                changed[index]["IPAM"]["Config"] = config;
                assert!(
                    assess_inner_topology(&changed, "test", &held, &outer)
                        == Err(InnerTopologyRefusal::BridgeIpam)
                );
            }
            let mut changed = networks.clone();
            changed[index]["IPAM"]
                .as_object_mut()
                .unwrap()
                .remove("Config");
            assert!(
                assess_inner_topology(&changed, "test", &held, &outer)
                    == Err(InnerTopologyRefusal::BridgeIpam)
            );
        }
        // Earlier bridge failure still wins; a later builtin exception cannot
        // mask actual overlap or change the original traversal order.
        let mut changed = networks;
        changed[0]["IPAM"]["Config"] = json!([{"Subnet": "10.253.253.0/24"}]);
        changed[11]["IPAM"]["Config"] = Value::Null;
        changed[12]["IPAM"]["Config"] = json!(false);
        assert!(
            assess_inner_topology(&changed, "test", &held, &outer)
                == Err(InnerTopologyRefusal::Ipv4Overlap)
        );
    }

    #[test]
    fn topology_all_five_held_roles_and_canonical_distinct_ids_are_bound() {
        let (networks, held, outer) = fixture();
        for case in 0..5 {
            let mut changed = held.clone();
            match case {
                0 => {
                    changed.pop();
                }
                1 => changed[4] = changed[0].clone(),
                2 => changed[4].0 = "dl-target-test-net".to_owned(),
                3 => changed[4].1 = "f".repeat(64),
                _ => changed[4].1 = "F".repeat(64),
            }
            assert!(!inner_topology_disjoint(
                &networks, "test", &changed, &outer
            ));
        }
        // Earlier IDs are intentionally snapshot/name-bound, not invented
        // creation-bound evidence; valid alternate IDs for these roles pass.
        let mut earlier = networks;
        earlier[2]["Id"] = json!("e".repeat(64));
        assert!(inner_topology_disjoint(&earlier, "test", &held, &outer));
        assert!(!inner_topology_disjoint(&earlier, "test", &held, &[]));
    }

    #[test]
    fn topology_refusal_categories_preserve_first_failed_predicate() {
        let (networks, held, outer) = fixture();
        let check = |value: &Value, ids: &[(String, String)], pools: &[TopologyPool], reason| {
            assert!(assess_inner_topology(value, "test", ids, pools) == Err(reason));
            assert!(!inner_topology_disjoint(value, "test", ids, pools));
        };
        check(&Value::Null, &[], &[], InnerTopologyRefusal::SnapshotArray);
        let mut excessive = networks.clone();
        excessive[0]["unrelated"] = json!(vec![0; 8193]);
        check(&excessive, &[], &[], InnerTopologyRefusal::SnapshotBounds);
        check(&json!([]), &[], &[], InnerTopologyRefusal::NetworkCount);
        check(&networks, &[], &[], InnerTopologyRefusal::HeldCount);
        check(&networks, &held, &[], InnerTopologyRefusal::OuterPools);
        let mut wrong_roles = held.clone();
        wrong_roles[0].0 = "private-role-canary".to_owned();
        wrong_roles[0].1 = "invalid-id-canary".to_owned();
        check(
            &networks,
            &wrong_roles,
            &outer,
            InnerTopologyRefusal::HeldRoles,
        );
        let mut wrong_ids = held.clone();
        wrong_ids[0].1 = wrong_ids[1].1.clone();
        check(&networks, &wrong_ids, &outer, InnerTopologyRefusal::HeldIds);
        for (field, value, reason) in [
            (
                "Id",
                json!("private-id-canary"),
                InnerTopologyRefusal::NativeId,
            ),
            ("Name", Value::Null, InnerTopologyRefusal::NativeName),
            ("Scope", json!("swarm"), InnerTopologyRefusal::Scope),
            ("IPAM", Value::Null, InnerTopologyRefusal::IpamDriver),
            (
                "Name",
                json!("private-name-canary"),
                InnerTopologyRefusal::BridgeMembership,
            ),
            (
                "Driver",
                json!("overlay"),
                InnerTopologyRefusal::BridgeDriver,
            ),
        ] {
            let mut changed = networks.clone();
            changed[0][field] = value;
            check(&changed, &held, &outer, reason);
        }
        let mut duplicate = networks.clone();
        duplicate[1]["Id"] = duplicate[0]["Id"].clone();
        duplicate[1]["Name"] = duplicate[0]["Name"].clone();
        duplicate[1]["Scope"] = Value::Null;
        check(&duplicate, &held, &outer, InnerTopologyRefusal::DuplicateId);
        duplicate[1]["Id"] = networks[1]["Id"].clone();
        check(
            &duplicate,
            &held,
            &outer,
            InnerTopologyRefusal::DuplicateName,
        );
        let mut binding = networks.clone();
        binding[1]["Id"] = json!("e".repeat(64));
        binding[1]["IPAM"]["Config"] = Value::Null;
        check(&binding, &held, &outer, InnerTopologyRefusal::HeldBinding);
        for pools in [json!(false), json!([{}]), json!([{"Subnet": "fd00::/64"}])] {
            let mut changed = networks.clone();
            changed[11]["IPAM"]["Config"] = pools;
            check(&changed, &held, &outer, InnerTopologyRefusal::BuiltinPools);
        }
        for (pools, reason) in [
            (
                json!([{"Subnet": "10.253.253.0/24"}]),
                InnerTopologyRefusal::Ipv4Overlap,
            ),
            // An overlapping prefix followed by incomplete data is a schema
            // refusal: no overlap category until the whole IPAM passes.
            (
                json!([{"Subnet": "10.253.253.0/24"}, {}]),
                InnerTopologyRefusal::BridgeIpam,
            ),
            (
                json!([{"Subnet": "fd00::/64"}]),
                InnerTopologyRefusal::BridgeIpam,
            ),
            (
                json!([{"Subnet": "172.20.0.1/24"}]),
                InnerTopologyRefusal::BridgeIpam,
            ),
        ] {
            let mut changed = networks.clone();
            changed[0]["IPAM"]["Config"] = pools;
            check(&changed, &held, &outer, reason);
        }
        let mut second_outer = outer.clone();
        second_outer.push(TopologyPool::parse("10.88.0.0/16").unwrap());
        let mut changed = networks.clone();
        changed[0]["IPAM"]["Config"] = json!([
            {"Subnet": "172.20.0.0/24"}, {"Subnet": "fd00::/64"}, {"Subnet": "10.88.3.0/24"}
        ]);
        check(
            &changed,
            &held,
            &second_outer,
            InnerTopologyRefusal::Ipv4Overlap,
        );
        for (subnet, refused) in [
            ("0.0.0.0/0", true),
            ("10.253.253.255/32", true),
            ("10.253.252.0/24", false),
            ("10.253.254.0/32", false),
        ] {
            let mut changed = networks.clone();
            changed[0]["IPAM"]["Config"] = json!([{"Subnet": subnet}, {"Subnet": "fd00::/64"}]);
            if refused {
                check(&changed, &held, &outer, InnerTopologyRefusal::Ipv4Overlap);
            } else {
                assert!(assess_inner_topology(&changed, "test", &held, &outer).is_ok());
                assert!(inner_topology_disjoint(&changed, "test", &held, &outer));
            }
        }
    }

    #[test]
    fn topology_diagnostic_io_failure_preserves_assertion_and_unwind_cleanup() {
        struct BrokenOutput;
        impl Write for BrokenOutput {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic output failure"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        struct Cleanup<'a>(&'a std::cell::Cell<bool>);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let cleaned = std::cell::Cell::new(false);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _cleanup = Cleanup(&cleaned);
            assert!(
                {
                    let result = assess_inner_topology(&Value::Null, "test", &[], &[]);
                    if let Err(reason) = result {
                        emit_inner_topology_refusal(&mut BrokenOutput, reason);
                    }
                    result.is_ok()
                },
                "all retained inner bridge pools are disjoint from actual outer pools"
            );
        }));
        assert!(cleaned.get());
        let payload = panic.expect_err("original assertion remains a failure");
        assert_eq!(
            payload.downcast_ref::<&str>().copied(),
            Some("all retained inner bridge pools are disjoint from actual outer pools")
        );
        let mut output = Vec::new();
        emit_inner_topology_refusal(&mut output, InnerTopologyRefusal::BridgeIpam);
        assert_eq!(
            output,
            b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=bridge_ipam\n"
        );
    }

    #[test]
    fn topology_whole_ipam_and_every_outer_interval_are_checked() {
        let (networks, held, mut outer) = fixture();
        outer.push(TopologyPool::parse("10.88.0.0/16").unwrap());
        for configs in [
            json!([{"Subnet": "10.253.253.0/24"}]),
            json!([{"Subnet": "172.20.0.0/24"}, {"Subnet": "10.88.3.0/24"}]),
            json!([{"Subnet": "172.20.0.0/24"}, {}]),
            json!([{"Subnet": "172.20.0.0/24"}, {"Subnet": "broken"}]),
            json!([{"Subnet": "fd00::/64"}]),
            json!([{"Subnet": "172.20.0.1/24"}]),
            json!([{"Subnet": "172.20.0.0/24", "Gateway": "192.0.2.1"}]),
            json!([{"Subnet": "172.20.0.0/24", "IPRange": "172.21.0.0/24"}]),
            json!([{"Subnet": "172.20.0.0/24", "AuxiliaryAddresses": {"x": "192.0.2.1"}}]),
        ] {
            let mut changed = networks.clone();
            changed[0]["IPAM"]["Config"] = configs;
            assert!(!inner_topology_disjoint(&changed, "test", &held, &outer));
        }
        for (left, right, overlap) in [
            ("0.0.0.0/0", "10.253.253.0/24", true),
            ("10.253.252.0/24", "10.253.253.0/24", false),
            ("10.253.253.255/32", "10.253.253.0/24", true),
            ("10.253.254.0/32", "10.253.253.0/24", false),
        ] {
            assert_eq!(
                TopologyPool::parse(left)
                    .unwrap()
                    .overlaps(TopologyPool::parse(right).unwrap()),
                overlap
            );
        }
        assert!(proof_budget_sufficient(58, 4, 8));
        assert!(!proof_budget_sufficient(57, 4, 8));
    }

    #[test]
    fn topology_response_rejects_partial_duplicate_trailing_status_and_cap() {
        let (networks, _, _) = fixture();
        let mut bytes = serde_json::to_vec(&networks).unwrap();
        bytes.extend_from_slice(b"\n200");
        assert!(decode_inner_topology_response(&bytes).is_some());
        for bytes in [
            b"[]\n404".to_vec(),
            b"[\n200".to_vec(),
            b"[] {}\n200".to_vec(),
            b"[{\"Id\":1,\"Id\":2}]\n200".to_vec(),
            b"[{\"x\":{\"k\":1,\"\\u006b\":2}}]\n200".to_vec(),
            [vec![b' '; TOPOLOGY_RESPONSE_CAP + 1], b"\n200".to_vec()].concat(),
        ] {
            assert!(decode_inner_topology_response(&bytes).is_none());
        }
    }

    #[test]
    fn topology_private_record_is_exact_candidate_run_backend_and_endpoint_bound() {
        assert!(record_valid(&record()));
        for case in 0..10 {
            let mut value = record();
            match case {
                0 => value["candidate"] = json!("e".repeat(40)),
                1 => value["run"] = json!("other"),
                2 => value["backend"] = json!(crate::native_outer_test_command::PODMAN_ENGINE),
                3 => value["network"]["id"] = json!("A".repeat(64)),
                4 => value["network"]["name"] = json!("other"),
                5 => value["network"]["ipv4_pools"] = json!(["192.0.2.0/24"]),
                6 => value["endpoints"]["daemon"]["id"] = json!("f".repeat(64)),
                7 => value["endpoints"]["sidecar"]["ipv4"] = json!("10.253.253.2"),
                8 => value["endpoints"]["sidecar"]["name"] = json!("other"),
                _ => value["private-canary"] = json!("unrecognized"),
            }
            assert!(!record_valid(&value), "case {case}");
        }
    }

    #[test]
    fn topology_private_read_rejects_symlinks_modes_hardlinks_and_duplicates() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let run = format!(
            "topology-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(format!("dockerlens-native.{run}"));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let file = directory.join("outer-network-topology-v1.json");
        fs::write(&file, b"{}").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_topology_record(&directory, &run).is_some());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_topology_record(&directory, &run).is_none());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = directory.join("alias");
        fs::hard_link(&file, &alias).unwrap();
        assert!(read_topology_record(&directory, &run).is_none());
        fs::remove_file(&alias).unwrap();
        fs::write(&file, b"{\"x\":1,\"x\":2}").unwrap();
        assert!(read_topology_record(&directory, &run).is_none());
        fs::remove_file(&file).unwrap();
        symlink(&alias, &file).unwrap();
        assert!(read_topology_record(&directory, &run).is_none());
        fs::remove_file(&file).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureSubnetObservation {
    Membership(bool),
    Unavailable,
}

impl FixtureSubnetObservation {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::Membership(true) => "sidecar_on_fixture_subnet=true",
            Self::Membership(false) => "sidecar_on_fixture_subnet=false",
            Self::Unavailable => "sidecar_on_fixture_subnet=unknown reason=unavailable",
        }
    }
}

// Closed observation only: this context grants no additional read capability.
struct FixtureSubnetContext {
    observation: FixtureSubnetObservation,
    address: Ipv4Addr,
    client: String,
}

fn failed_fixture_subnet(
    context: Option<&FixtureSubnetContext>,
    args: &[&str],
    result: &BoundedDnsCliOutput,
) -> Option<FixtureSubnetObservation> {
    let context = context?;
    let url = format!("http://{}:18084/", context.address);
    (!result.success
        && args
            == [
                "exec",
                context.client.as_str(),
                "wget",
                "-Y",
                "off",
                "-T",
                "2",
                "-qO-",
                url.as_str(),
            ])
    .then_some(context.observation)
}

fn captured_fixture_subnet(
    capture: &crate::evidence::Capture,
    source_id: &str,
    network_id: Option<&str>,
    run_id: &str,
    address: Ipv4Addr,
) -> FixtureSubnetObservation {
    captured_fixture_membership(capture, source_id, network_id, run_id, address).map_or(
        FixtureSubnetObservation::Unavailable,
        FixtureSubnetObservation::Membership,
    )
}

fn captured_fixture_membership(
    capture: &crate::evidence::Capture,
    source_id: &str,
    network_id: Option<&str>,
    run_id: &str,
    address: Ipv4Addr,
) -> Option<bool> {
    use crate::acquisition::{ReadRequest, RootKind, SelectionReason};
    use crate::evidence::CaptureRoute;

    let network_id = network_id?;
    if capture.route() != CaptureRoute::ExplicitUnixSocket
        || !matches!(capture.selector(), Some(Selector::ContainerIds(ids))
            if ids.len() == 1 && ids[0].as_str() == source_id)
    {
        return None;
    }
    let [root] = capture.selected_roots() else {
        return None;
    };
    if root.kind != RootKind::Container || root.reason != SelectionReason::ExactId {
        return None;
    }
    let mut containers = capture
        .exchanges()
        .iter()
        .filter(|exchange| matches!(exchange.request(), ReadRequest::InspectContainer(_)));
    let container = containers.next()?;
    if containers.next().is_some()
        || !matches!(container.request(), ReadRequest::InspectContainer(id) if id.as_str() == source_id)
        || container.resource() != Some(root.resource)
        || container.status().code() != 200
        || container.body().as_bytes().len() > DEFAULT_BRIDGE_RESPONSE_CAP
    {
        return None;
    }
    let api = container.api_version()?;
    let UniqueDiagnosticJson(source) = serde_json::from_slice(container.body().as_bytes()).ok()?;
    let network_name = format!("dl-{run_id}-net");
    if canonical_inspected_container_id(&source)? != source_id
        || source.get("Name")?.as_str()? != format!("/dl-{run_id}-box")
    {
        return None;
    }
    let attachment = source
        .get("NetworkSettings")?
        .get("Networks")?
        .as_object()?
        .get(&network_name)?
        .as_object()?;
    // Acquisition sanctions a name expansion for stopped endpoints with no ID.
    // Null/non-string and a nonempty foreign ID are deliberately not salvaged.
    let by_name = match attachment.get("NetworkID") {
        None => true,
        Some(Value::String(id)) if id.is_empty() => true,
        Some(Value::String(id)) if id == network_id => false,
        _ => return None,
    };
    let request_id = if by_name {
        network_name.as_str()
    } else {
        network_id
    };
    let mut networks = capture.exchanges().iter().filter(|exchange| {
        matches!(exchange.request(), ReadRequest::InspectNetwork(id) if id.as_str() == request_id)
    });
    let network = networks.next()?;
    let reference = network.resource()?;
    if networks.next().is_some()
        || reference == root.resource
        || capture.network_name_fallbacks().contains(&reference) != by_name
        || network.api_version() != Some(api)
        || network.status().code() != 200
        || network.body().as_bytes().len() > DEFAULT_BRIDGE_RESPONSE_CAP
    {
        return None;
    }
    let UniqueDiagnosticJson(body) = serde_json::from_slice(network.body().as_bytes()).ok()?;
    if canonical_inspected_container_id(&body)? != network_id
        || body.get("Name")?.as_str()? != network_name
        || body.get("Driver")?.as_str()? != "bridge"
    {
        return None;
    }
    match sidecar_on_subnet(address, &body) {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

mod fixture_subnet_tests {
    use super::*;
    use crate::acquisition::{ReadRequest, RootKind, SelectedRoot, SelectionReason};
    use crate::evidence::{Capture, CaptureBounds, CapturedExchange, HttpStatus, ProtectedValue};
    use crate::version::{ApiVersion, ObservationId};

    struct Input {
        source: Vec<u8>,
        network: Vec<u8>,
        request: String,
        fallback: bool,
        apis: [Option<ApiVersion>; 2],
        statuses: [u16; 2],
        references: [Option<ResourceRef>; 2],
        duplicates: [bool; 2],
        explicit_socket: bool,
    }

    impl Input {
        fn new(by_name: bool) -> Self {
            Self {
                source: serde_json::to_vec(&json!({
                    "Id": "a".repeat(64), "Name": "/dl-test-box",
                    "NetworkSettings": {"Networks": {"dl-test-net": {
                        "NetworkID": if by_name { String::new() } else { "b".repeat(64) }
                    }}}
                }))
                .unwrap(),
                network: serde_json::to_vec(&json!({
                    "Id": "b".repeat(64), "Name": "dl-test-net", "Driver": "bridge",
                    "IPAM": {"Config": [{"Subnet": "10.23.7.0/24"}]}
                }))
                .unwrap(),
                request: if by_name {
                    "dl-test-net".to_owned()
                } else {
                    "b".repeat(64)
                },
                fallback: by_name,
                // Captured request API, deliberately not advertised API 1.56.
                apis: [Some(ApiVersion {
                    major: std::num::NonZeroU16::new(1).unwrap(),
                    minor: 49,
                }); 2],
                statuses: [200; 2],
                references: [Some(ResourceRef::new(1)), Some(ResourceRef::new(2))],
                duplicates: [false; 2],
                explicit_socket: true,
            }
        }

        fn capture(&self) -> Capture {
            let mut exchanges = Vec::new();
            for index in 0..2 {
                for _ in 0..=usize::from(self.duplicates[index]) {
                    exchanges.push(CapturedExchange::new(
                        if index == 0 {
                            ReadRequest::InspectContainer(NativeId::new("a".repeat(64)).unwrap())
                        } else {
                            ReadRequest::InspectNetwork(
                                NativeId::new(self.request.clone()).unwrap(),
                            )
                        },
                        self.references[index],
                        self.apis[index],
                        HttpStatus::new(self.statuses[index]).unwrap(),
                        ProtectedValue::new(if index == 0 {
                            self.source.clone()
                        } else {
                            self.network.clone()
                        }),
                    ));
                }
            }
            // The source fixture also expands its named volume. It is not a
            // network observation and must neither hide nor invalidate one.
            exchanges.push(CapturedExchange::new(
                ReadRequest::InspectVolume(NativeId::new("dl-test-vol".to_owned()).unwrap()),
                Some(ResourceRef::new(3)),
                self.apis[0],
                HttpStatus::new(200).unwrap(),
                ProtectedValue::new(
                    br#"{"Name":"dl-test-vol","Driver":"local","Mountpoint":"/private-canary"}"#
                        .to_vec(),
                ),
            ));
            let capture = Capture::from_completed(
                ObservationId::fresh().unwrap(),
                CaptureBounds {
                    request_count: exchanges.len(),
                    selected_resources: 1,
                    expansions: 2,
                    bytes_read: exchanges
                        .iter()
                        .map(|exchange| exchange.body().as_bytes().len())
                        .sum(),
                },
                exchanges,
            )
            .unwrap()
            .with_selector(Selector::ContainerIds(vec![
                NativeId::new("a".repeat(64)).unwrap(),
            ]))
            .with_selected_roots(vec![SelectedRoot {
                resource: ResourceRef::new(1),
                kind: RootKind::Container,
                reason: SelectionReason::ExactId,
            }])
            .with_network_name_fallbacks(if self.fallback {
                [ResourceRef::new(2)].into()
            } else {
                Default::default()
            });
            if self.explicit_socket {
                capture.with_explicit_socket()
            } else {
                capture
            }
        }

        fn source(&mut self, change: impl FnOnce(&mut Value)) {
            let mut body: Value = serde_json::from_slice(&self.source).unwrap();
            change(&mut body);
            self.source = serde_json::to_vec(&body).unwrap();
        }

        fn network(&mut self, change: impl FnOnce(&mut Value)) {
            let mut body: Value = serde_json::from_slice(&self.network).unwrap();
            change(&mut body);
            self.network = serde_json::to_vec(&body).unwrap();
        }
    }

    fn observe(capture: &Capture) -> FixtureSubnetObservation {
        captured_fixture_subnet(
            capture,
            &"a".repeat(64),
            Some(&"b".repeat(64)),
            "test",
            Ipv4Addr::new(10, 23, 7, 9),
        )
    }

    #[test]
    fn fixture_subnet_binds_normal_id_and_stopped_name_fallback_without_new_reads() {
        for by_name in [false, true] {
            let mut input = Input::new(by_name);
            assert_eq!(
                observe(&input.capture()),
                FixtureSubnetObservation::Membership(true)
            );
            input.apis = [Some(ApiVersion {
                major: std::num::NonZeroU16::new(1).unwrap(),
                minor: 41,
            }); 2];
            assert_eq!(
                observe(&input.capture()),
                FixtureSubnetObservation::Membership(true)
            );
        }
        let mut input = Input::new(true);
        input.source(|body| {
            body["NetworkSettings"]["Networks"]["dl-test-net"]
                .as_object_mut()
                .unwrap()
                .remove("NetworkID");
        });
        assert_eq!(
            observe(&input.capture()),
            FixtureSubnetObservation::Membership(true)
        );
        assert_eq!(
            captured_fixture_subnet(
                &input.capture(),
                &"a".repeat(64),
                None,
                "test",
                Ipv4Addr::LOCALHOST
            ),
            FixtureSubnetObservation::Unavailable
        );
    }

    #[test]
    fn fixture_subnet_requires_exact_source_network_and_fallback_custody() {
        for case in 0..21 {
            let mut input = Input::new(case >= 15);
            match case {
                0 => input.source(|body| body["Id"] = json!("c".repeat(64))),
                1 => input.source(|body| body["Name"] = json!("/dl-other-box")),
                2 => input.source(|body| {
                    body["NetworkSettings"]["Networks"] =
                        json!({"dl-other-net": {"NetworkID": "b".repeat(64)}})
                }),
                3 => input.source(|body| {
                    body["NetworkSettings"]["Networks"]["dl-test-net"]["NetworkID"] =
                        json!("c".repeat(64))
                }),
                4 => input.network(|body| body["Id"] = json!("c".repeat(64))),
                5 => input.network(|body| body["Id"] = json!("B".repeat(64))),
                6 => input.network(|body| body["Name"] = json!("dl-other-net")),
                7 => input.network(|body| body["Driver"] = json!("overlay")),
                8 => input.apis[0] = None,
                9 => input.apis[1] = None,
                10 => {
                    input.apis[1] = Some(ApiVersion {
                        major: std::num::NonZeroU16::new(1).unwrap(),
                        minor: 56,
                    })
                }
                11 => input.statuses[0] = 404,
                12 => input.statuses[1] = 500,
                13 => input.fallback = true,
                14 => input.request = "dl-test-net".to_owned(),
                15 => input.fallback = false,
                16 => input.request = "b".repeat(64),
                17 => input.request = "dl-other-net".to_owned(),
                18 => input.source(|body| {
                    body["NetworkSettings"]["Networks"]["dl-test-net"]["NetworkID"] = Value::Null
                }),
                19 => input.source(|body| {
                    body["NetworkSettings"]["Networks"]["dl-test-net"]["NetworkID"] = json!(42)
                }),
                _ => input.source(|body| {
                    body["NetworkSettings"]["Networks"]["dl-test-net"]["NetworkID"] =
                        json!("c".repeat(64))
                }),
            }
            assert_eq!(
                observe(&input.capture()),
                FixtureSubnetObservation::Unavailable,
                "case {case}"
            );
        }
        for index in 0..2 {
            let mut input = Input::new(false);
            input.references[index] = None;
            assert_eq!(
                observe(&input.capture()),
                FixtureSubnetObservation::Unavailable
            );
            input = Input::new(false);
            input.duplicates[index] = true;
            assert_eq!(
                observe(&input.capture()),
                FixtureSubnetObservation::Unavailable
            );
        }
        let input = Input::new(false);
        let source = NativeId::new("c".repeat(64)).unwrap();
        assert_eq!(
            observe(
                &input
                    .capture()
                    .with_selector(Selector::ContainerIds(vec![source]))
            ),
            FixtureSubnetObservation::Unavailable
        );
        assert_eq!(
            observe(&input.capture().with_selected_roots(Vec::new())),
            FixtureSubnetObservation::Unavailable
        );
        let root = SelectedRoot {
            resource: ResourceRef::new(9),
            kind: RootKind::Container,
            reason: SelectionReason::ExactId,
        };
        assert_eq!(
            observe(&input.capture().with_selected_roots(vec![root])),
            FixtureSubnetObservation::Unavailable
        );
        for (kind, reason) in [
            (RootKind::Network, SelectionReason::ExactId),
            (RootKind::Container, SelectionReason::ExactName),
        ] {
            let root = SelectedRoot {
                resource: ResourceRef::new(1),
                kind,
                reason,
            };
            assert_eq!(
                observe(&input.capture().with_selected_roots(vec![root])),
                FixtureSubnetObservation::Unavailable
            );
        }
        let roots = input.capture().selected_roots().repeat(2);
        assert_eq!(
            observe(&input.capture().with_selected_roots(roots)),
            FixtureSubnetObservation::Unavailable
        );
        let mut input = Input::new(false);
        input.explicit_socket = false;
        assert_eq!(
            observe(&input.capture()),
            FixtureSubnetObservation::Unavailable
        );
        input.explicit_socket = true;
        input.references[1] = input.references[0];
        assert_eq!(
            observe(&input.capture()),
            FixtureSubnetObservation::Unavailable
        );
        let input = Input::new(false);
        assert_eq!(
            observe(
                &input
                    .capture()
                    .with_network_name_fallbacks([ResourceRef::new(9)].into())
            ),
            FixtureSubnetObservation::Membership(true)
        );
        let input = Input::new(true);
        assert_eq!(
            observe(
                &input
                    .capture()
                    .with_network_name_fallbacks([ResourceRef::new(9)].into())
            ),
            FixtureSubnetObservation::Unavailable
        );
    }

    #[test]
    fn fixture_subnet_requires_complete_unique_json_and_strict_whole_ipam() {
        for source in [true, false] {
            for suffix in [b" {}".as_slice(), b" private-canary", b"\0"] {
                let mut input = Input::new(false);
                if source {
                    input.source.extend_from_slice(suffix);
                } else {
                    input.network.extend_from_slice(suffix);
                }
                assert_eq!(
                    observe(&input.capture()),
                    FixtureSubnetObservation::Unavailable
                );
            }
            let mut input = Input::new(false);
            if source {
                input.source.pop();
            } else {
                input.network.pop();
            }
            assert_eq!(
                observe(&input.capture()),
                FixtureSubnetObservation::Unavailable
            );
            for metadata in [
                r#""ignored":{"key":1,"key":2}"#,
                r#""ignored":{"key":1,"\u006bey":2}"#,
                r#""ignored":{"\u006bey":1,"key":2}"#,
            ] {
                let mut input = Input::new(false);
                let body = if source {
                    &mut input.source
                } else {
                    &mut input.network
                };
                body.pop();
                body.extend_from_slice(format!(",{metadata}}}").as_bytes());
                assert_eq!(
                    observe(&input.capture()),
                    FixtureSubnetObservation::Unavailable
                );
            }
            let mut input = Input::new(false);
            if source {
                input.source = vec![b' '; DEFAULT_BRIDGE_RESPONSE_CAP + 1];
            } else {
                input.network = vec![b' '; DEFAULT_BRIDGE_RESPONSE_CAP + 1];
            }
            assert_eq!(
                observe(&input.capture()),
                FixtureSubnetObservation::Unavailable
            );
        }
        for endpoint in [
            format!(
                r#"{{"NetworkID":"{}","NetworkID":"foreign"}}"#,
                "b".repeat(64)
            ),
            format!(
                r#"{{"NetworkID":"foreign","\u004eetworkID":"{}"}}"#,
                "b".repeat(64)
            ),
        ] {
            let mut input = Input::new(false);
            input.source = format!(r#"{{"Id":"{}","Name":"/dl-test-box","NetworkSettings":{{"Networks":{{"dl-test-net":{endpoint}}}}}}}"#, "a".repeat(64)).into_bytes();
            assert_eq!(
                observe(&input.capture()),
                FixtureSubnetObservation::Unavailable
            );
        }
        let mut input = Input::new(false);
        input.source = format!(r#"{{"Id":"{}","Name":"/dl-test-box","NetworkSettings":{{"Networks":{{"dl-test-net":{{"NetworkID":"{}"}},"dl-test-net":{{"NetworkID":"foreign"}}}}}}}}"#, "a".repeat(64), "b".repeat(64)).into_bytes();
        assert_eq!(
            observe(&input.capture()),
            FixtureSubnetObservation::Unavailable
        );
        input = Input::new(false);
        input.network = format!(r#"{{"Id":"{}","Name":"dl-test-net","Driver":"bridge","IPAM":{{"Config":[{{"Subnet":"10.23.7.0/24","Subnet":"10.23.8.0/24"}}]}}}}"#, "b".repeat(64)).into_bytes();
        assert_eq!(
            observe(&input.capture()),
            FixtureSubnetObservation::Unavailable
        );
        for (subnets, expected) in [
            (json!([{"Subnet": "0.0.0.0/0"}]), Some(true)),
            (json!([{"Subnet": "10.23.7.9/32"}]), Some(true)),
            (json!([{"Subnet": "10.23.7.10/32"}]), Some(false)),
            (json!([{"Subnet": "10.23.8.0/24"}]), Some(false)),
            (json!([{"Subnet": "10.23.7.8/31"}]), Some(true)),
            (json!([{"Subnet": "10.23.7.10/31"}]), Some(false)),
            (json!([{"Subnet": "10.23.7.9/24"}]), None),
            (json!([{"Subnet": "10.23.7.0/024"}]), None),
            (json!([{"Subnet": "10.23.7.0/33"}]), None),
            (json!([{"Subnet": "2001:db8::/64"}]), None),
            (
                json!([{"Subnet": "10.23.7.0/24"}, {"Subnet": "broken"}]),
                None,
            ),
            (json!([{"Subnet": "10.23.7.0/24"}, {}]), None),
            (json!([]), None),
            (Value::Null, None),
        ] {
            let mut input = Input::new(false);
            input.network(|body| body["IPAM"]["Config"] = subnets);
            assert_eq!(
                observe(&input.capture()),
                expected.map_or(
                    FixtureSubnetObservation::Unavailable,
                    FixtureSubnetObservation::Membership
                )
            );
        }
    }

    #[test]
    fn fixture_subnet_marker_is_exact_failed_cli_positive_only() {
        let context = FixtureSubnetContext {
            observation: FixtureSubnetObservation::Membership(true),
            address: Ipv4Addr::new(10, 23, 7, 9),
            client: "dl-network-test-proof-cli-control-client".to_owned(),
        };
        let args = [
            "exec",
            context.client.as_str(),
            "wget",
            "-Y",
            "off",
            "-T",
            "2",
            "-qO-",
            "http://10.23.7.9:18084/",
        ];
        let mut result = BoundedDnsCliOutput {
            success: false,
            code: Some(1),
            stdout: Vec::new(),
            stderr: b"private-canary".to_vec(),
            output_limit: false,
        };
        assert_eq!(
            failed_fixture_subnet(Some(&context), &args, &result),
            Some(FixtureSubnetObservation::Membership(true))
        );
        assert_eq!(failed_fixture_subnet(None, &args, &result), None);
        for index in 0..args.len() {
            let mut wrong = args;
            wrong[index] = "other-private-canary";
            assert_eq!(failed_fixture_subnet(Some(&context), &wrong, &result), None);
        }
        for client in [
            "dl-network-test-proof-control-client",
            "dl-network-other-proof-cli-control-client",
        ] {
            let mut wrong = args;
            wrong[1] = client;
            assert_eq!(failed_fixture_subnet(Some(&context), &wrong, &result), None);
        }
        assert_eq!(
            failed_fixture_subnet(Some(&context), &args[..8], &result),
            None
        );
        let mut extra = args.to_vec();
        extra.push("extra-private-canary");
        assert_eq!(failed_fixture_subnet(Some(&context), &extra, &result), None);
        result.success = true;
        assert_eq!(failed_fixture_subnet(Some(&context), &args, &result), None);
        assert_eq!(
            FixtureSubnetObservation::Unavailable.diagnostic(),
            "sidecar_on_fixture_subnet=unknown reason=unavailable"
        );
        assert_eq!(
            FixtureSubnetObservation::Membership(false).diagnostic(),
            "sidecar_on_fixture_subnet=false"
        );
    }
}

fn default_bridge_eligible(mode: DaemonMode, selected_engine: Option<&str>) -> bool {
    mode == DaemonMode::Rootless && selected_engine == Some("docker")
}

fn default_bridge_context(
    mode: DaemonMode,
    selected_engine: Option<&str>,
    api: Option<crate::version::ApiVersion>,
    socket: PathBuf,
) -> Option<DefaultBridgeContext> {
    if !default_bridge_eligible(mode, selected_engine) {
        return None;
    }
    Some(DefaultBridgeContext { api: api?, socket })
}

// Test-only JSON wrapper: every object, including ignored nested metadata, has
// unique decoded keys. Serde supplies JSON parsing, recursion and end checks.
struct UniqueDiagnosticJson(Value);

impl<'de> serde::Deserialize<'de> for UniqueDiagnosticJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UniqueVisitor;

        impl<'de> serde::de::Visitor<'de> for UniqueVisitor {
            type Value = UniqueDiagnosticJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value with unique object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueDiagnosticJson(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueDiagnosticJson(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueDiagnosticJson(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(|number| UniqueDiagnosticJson(Value::Number(number)))
                    .ok_or_else(|| E::custom("invalid diagnostic JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueDiagnosticJson(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueDiagnosticJson(Value::String(value)))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueDiagnosticJson(Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueDiagnosticJson>()? {
                    values.push(value.0);
                }
                Ok(UniqueDiagnosticJson(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate diagnostic JSON key"));
                    }
                    let value: UniqueDiagnosticJson = map.next_value()?;
                    values.insert(key, value.0);
                }
                Ok(UniqueDiagnosticJson(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(UniqueVisitor)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DefaultBridgeObservation {
    Membership(bool),
    Unavailable,
    BudgetExhausted,
}

impl DefaultBridgeObservation {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::Membership(true) => "sidecar_on_default_bridge_subnet=true",
            Self::Membership(false) => "sidecar_on_default_bridge_subnet=false",
            Self::Unavailable => "sidecar_on_default_bridge_subnet=unknown reason=unavailable",
            Self::BudgetExhausted => {
                "sidecar_on_default_bridge_subnet=unknown reason=budget_exhausted"
            }
        }
    }
}

fn default_bridge_membership(address: Ipv4Addr, output: &[u8]) -> Option<bool> {
    if output.len() > DEFAULT_BRIDGE_RESPONSE_CAP {
        return None;
    }
    let body = output.strip_suffix(b"\n200")?;
    let UniqueDiagnosticJson(network) = serde_json::from_slice(body).ok()?;
    if network.get("Name")?.as_str()? != "bridge"
        || network.get("Driver")?.as_str()? != "bridge"
        || canonical_inspected_container_id(&network).is_none()
    {
        return None;
    }
    match sidecar_on_subnet(address, &network) {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn default_bridge_command(context: &DefaultBridgeContext) -> Command {
    let mut command = Command::new("timeout");
    command.args([
        "--foreground",
        "--kill-after=1",
        "6",
        "curl",
        // Disable user curl configuration, proxies and retries; this capability
        // has exactly one method, one path and the already-held inner socket.
        "--disable",
        "-sS",
        "--noproxy",
        "*",
        "--retry",
        "0",
        "--proto",
        "=http",
        "--max-time",
        "6",
        "--unix-socket",
    ]);
    command.arg(&context.socket).args([
        "-X",
        "GET",
        "-w",
        "\n%{http_code}",
        &format!(
            "http://localhost/v{}.{}/networks/bridge",
            context.api.major, context.api.minor
        ),
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

fn read_default_bridge_stream(reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((DEFAULT_BRIDGE_RESPONSE_CAP + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > DEFAULT_BRIDGE_RESPONSE_CAP {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    Ok(bytes)
}

fn read_default_bridge(context: &DefaultBridgeContext) -> Option<Vec<u8>> {
    let mut child = default_bridge_command(context).spawn().ok()?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.wait();
        return None;
    };
    let reader = match std::thread::Builder::new().spawn(move || read_default_bridge_stream(stdout))
    {
        Ok(reader) => reader,
        Err(_) => {
            let _ = child.wait();
            return None;
        }
    };
    // The reader drains at most cap+1 bytes. On overflow it closes the pipe;
    // otherwise the original command group ends after six seconds plus kill.
    // No new process group, cancellation handler or deadline is installed.
    let status = child.wait();
    if status.is_err() {
        let _ = child.wait();
    }
    let output = reader.join().ok()?.ok()?;
    status.ok()?.success().then_some(output)
}

fn optional_default_bridge<F>(
    context: Option<&ProofSubnetContext>,
    args: &[&str],
    result: &BoundedDnsCliOutput,
    remaining: Option<u64>,
    outstanding: usize,
    read: F,
) -> Option<DefaultBridgeObservation>
where
    F: FnOnce(&DefaultBridgeContext) -> Option<Vec<u8>>,
{
    let context = context?;
    let default_bridge = context.default_bridge.as_ref()?;
    let url = format!("http://{}:18084/", context.address);
    if result.success
        || args
            != [
                "exec",
                &context.client,
                "wget",
                "-Y",
                "off",
                "-T",
                "2",
                "-qO-",
                &url,
            ]
    {
        return None;
    }
    // Eight liabilities require 90 seconds of cleanup, plus eight for this
    // optional read. Re-evaluate AFTER wget; never assert or renew a budget.
    if !remaining.is_some_and(|remaining| proof_budget_sufficient(remaining, outstanding, 8)) {
        return Some(DefaultBridgeObservation::BudgetExhausted);
    }
    Some(
        read(default_bridge)
            .and_then(|bytes| default_bridge_membership(context.address, &bytes))
            .map_or(
                DefaultBridgeObservation::Unavailable,
                DefaultBridgeObservation::Membership,
            ),
    )
}

fn optional_remaining(deadline: Option<&str>, now: Option<u64>) -> Option<u64> {
    let deadline = deadline?;
    if deadline.is_empty() || !deadline.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    deadline.parse::<u64>().ok()?.checked_sub(now?)
}

fn optional_proof_remaining() -> Option<u64> {
    let deadline = std::env::var("NATIVE_NETWORK_TEST_DEADLINE_EPOCH").ok();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|now| now.as_secs());
    optional_remaining(deadline.as_deref(), now)
}

fn default_bridge_test_context() -> ProofSubnetContext {
    ProofSubnetContext {
        observations: SidecarSubnetDiagnostics::new(),
        default_bridge: default_bridge_context(
            DaemonMode::Rootless,
            Some("docker"),
            Some(crate::version::ApiVersion::new(
                std::num::NonZeroU16::new(1).unwrap(),
                41,
            )),
            PathBuf::from("/held-private-canary/inner.sock"),
        ),
        address: Ipv4Addr::new(10, 23, 7, 9),
        client: "held-private-canary-control".to_owned(),
    }
}

fn default_bridge_test_response(subnet: &str) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "Name": "bridge", "Driver": "bridge", "Id": "a".repeat(64),
        "IPAM": {"Config": [{"Subnet": subnet}]}, "private": "private-canary"
    }))
    .unwrap();
    bytes.extend_from_slice(b"\n200");
    bytes
}

#[test]
fn default_bridge_read_has_one_exact_readonly_endpoint_and_finite_capture() {
    let context = default_bridge_test_context();
    let command = default_bridge_command(context.default_bridge.as_ref().unwrap());
    assert_eq!(command.get_program(), "timeout");
    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_str().unwrap())
        .collect();
    assert_eq!(
        args,
        [
            "--foreground",
            "--kill-after=1",
            "6",
            "curl",
            "--disable",
            "-sS",
            "--noproxy",
            "*",
            "--retry",
            "0",
            "--proto",
            "=http",
            "--max-time",
            "6",
            "--unix-socket",
            "/held-private-canary/inner.sock",
            "-X",
            "GET",
            "-w",
            "\n%{http_code}",
            "http://localhost/v1.41/networks/bridge"
        ]
    );
    for method in ["GET", "POST", "DELETE"] {
        assert!(!allowed_request(
            method,
            "/v1.41/networks/bridge",
            "1.41",
            "owned",
            "image",
            None
        ));
        assert!(!allowed_request(
            method,
            "/v1.41/networks/arbitrary",
            "1.41",
            "owned",
            "image",
            None
        ));
    }
    assert_eq!(read_default_bridge_stream(&b"held"[..]).unwrap(), b"held");
    assert!(read_default_bridge_stream(std::io::repeat(b'x')).is_err());
    struct FailedReader;
    impl Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("private-canary"))
        }
    }
    assert!(read_default_bridge_stream(FailedReader).is_err());
}

#[test]
fn default_bridge_optional_query_requires_observed_rootless_and_explicit_outer_docker() {
    let mut context = default_bridge_test_context();
    let result = BoundedDnsCliOutput {
        success: false,
        code: Some(124),
        stdout: Vec::new(),
        stderr: Vec::new(),
        output_limit: false,
    };
    let api = crate::version::ApiVersion::new(std::num::NonZeroU16::new(1).unwrap(), 49);
    context.observations = SidecarSubnetDiagnostics {
        internal: "true",
        control: "false",
    };
    let original_observations = context.observations;
    let url = format!("http://{}:18084/", context.address);
    for (mode, engine, observed_api, expected) in [
        (DaemonMode::Rootless, Some("docker"), Some(api), true),
        (DaemonMode::Rootful, Some("docker"), Some(api), false),
        (DaemonMode::Unknown, Some("docker"), Some(api), false),
        (
            DaemonMode::Rootless,
            Some(crate::native_outer_test_command::PODMAN_ENGINE),
            Some(api),
            false,
        ),
        (DaemonMode::Rootless, None, Some(api), false),
        (DaemonMode::Rootless, Some(""), Some(api), false),
        (DaemonMode::Rootless, Some("Docker"), Some(api), false),
        (DaemonMode::Rootless, Some("docker"), None, false),
        (DaemonMode::Rootful, Some("docker"), None, false),
        (
            DaemonMode::Rootless,
            Some(crate::native_outer_test_command::PODMAN_ENGINE),
            None,
            false,
        ),
    ] {
        context.default_bridge = default_bridge_context(
            mode,
            engine,
            observed_api,
            PathBuf::from("/held-private-canary/inner.sock"),
        );
        assert_eq!(context.default_bridge.is_some(), expected);
        let args = [
            "exec",
            context.client.as_str(),
            "wget",
            "-Y",
            "off",
            "-T",
            "2",
            "-qO-",
            &url,
        ];
        let calls = std::cell::Cell::new(0);
        let observation =
            optional_default_bridge(Some(&context), &args, &result, Some(98), 8, |held| {
                calls.set(calls.get() + 1);
                assert_eq!(held.api, api);
                assert_eq!(
                    held.socket,
                    PathBuf::from("/held-private-canary/inner.sock")
                );
                assert_eq!(
                    default_bridge_command(held).get_args().last().unwrap(),
                    "http://localhost/v1.49/networks/bridge"
                );
                Some(default_bridge_test_response("10.23.7.0/24"))
            });
        assert_eq!(calls.get(), usize::from(expected));
        assert_eq!(
            observation,
            expected.then_some(DefaultBridgeObservation::Membership(true))
        );
        assert_eq!(context.observations, original_observations);
    }
}

#[test]
fn default_bridge_rejects_duplicate_decoded_keys_recursively_in_both_orders() {
    let address = default_bridge_test_context().address;
    // Raw authored fields, never a Value/json! roundtrip that erases duplicates.
    // Each context has exactly one FIRST/SECOND pair at the tested depth.
    for (template, first, second) in [
        (
            r#"{FIRST,SECOND,"Driver":"bridge","Id":"NATIVE_ID","IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]}}"#,
            r#""Name":"private-canary""#,
            r#""Name":"bridge""#,
        ),
        (
            r#"{"Name":"bridge",FIRST,SECOND,"Id":"NATIVE_ID","IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]}}"#,
            r#""Driver":"private-canary""#,
            r#""Driver":"bridge""#,
        ),
        (
            r#"{"Name":"bridge","Driver":"bridge",FIRST,SECOND,"IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]}}"#,
            r#""Id":"private-canary""#,
            r#""Id":"NATIVE_ID""#,
        ),
        (
            r#"{"Name":"bridge","Driver":"bridge","Id":"NATIVE_ID",FIRST,SECOND}"#,
            r#""IPAM":{"Config":[{"Subnet":"private-canary"}]}"#,
            r#""IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]}"#,
        ),
        (
            r#"{"Name":"bridge","Driver":"bridge","Id":"NATIVE_ID","IPAM":{FIRST,SECOND}}"#,
            r#""Config":[{"Subnet":"private-canary"}]"#,
            r#""Config":[{"Subnet":"10.23.7.0/24"}]"#,
        ),
        (
            r#"{"Name":"bridge","Driver":"bridge","Id":"NATIVE_ID","IPAM":{"Config":[{FIRST,SECOND}]}}"#,
            r#""Subnet":"private-canary""#,
            r#""Subnet":"10.23.7.0/24""#,
        ),
        (
            r#"{FIRST,SECOND,"Driver":"bridge","Id":"NATIVE_ID","IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]}}"#,
            r#""Name":"private-canary""#,
            r#""Na\u006de":"bridge""#,
        ),
        (
            r#"{"Name":"bridge","Driver":"bridge","Id":"NATIVE_ID","IPAM":{"Config":[{FIRST,SECOND}]}}"#,
            r#""Subnet":"private-canary""#,
            r#""Sub\u006eet":"10.23.7.0/24""#,
        ),
        (
            r#"{"Name":"bridge","Driver":"bridge","Id":"NATIVE_ID","IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]},"ignored":{"nested":[{FIRST,SECOND}]}}"#,
            r#""private-canary":true"#,
            r#""private-canary":false"#,
        ),
        (
            r#"{"Name":"bridge","Driver":"bridge","Id":"NATIVE_ID","IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]},"ignored":{"nested":[{FIRST,SECOND}]}}"#,
            r#""private-canary":null"#,
            r#""private-\u0063anary":17"#,
        ),
        (
            r#"{FIRST,SECOND,"Driver":"bridge","Id":"NATIVE_ID","IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]}}"#,
            r#""Name":"bridge""#,
            r#""Name":"bridge""#,
        ),
    ] {
        for (first, second) in [(first, second), (second, first)] {
            let body = template
                .replace("FIRST", first)
                .replace("SECOND", second)
                .replace("NATIVE_ID", &"a".repeat(64));
            let response = [body.as_bytes(), b"\n200"].concat();
            assert_eq!(default_bridge_membership(address, &response), None);
        }
    }
    // Unique escaped keys are legal; only decoded-key collisions refuse.
    let escaped = r#"{"Na\u006de":"bridge","Driver":"bridge","Id":"NATIVE_ID","IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]},"ignored":[null,true,false,1,-1,1.5,"private-canary",{"unique":[]}]}"#
        .replace("NATIVE_ID", &"a".repeat(64));
    assert_eq!(
        default_bridge_membership(address, &[escaped.as_bytes(), b"\n200"].concat()),
        Some(true)
    );
    assert_eq!(
        default_bridge_membership(address, &[escaped.as_bytes(), b" {}\n200"].concat()),
        None
    );
    let nested = format!("{}0{}\n200", "[".repeat(256), "]".repeat(256));
    assert_eq!(default_bridge_membership(address, nested.as_bytes()), None);
}

#[test]
fn default_bridge_requires_exact_identity_complete_response_and_valid_whole_ipam() {
    let context = default_bridge_test_context();
    assert_eq!(
        default_bridge_membership(
            context.address,
            &default_bridge_test_response("10.23.7.0/24")
        ),
        Some(true)
    );
    assert_eq!(
        default_bridge_membership(
            context.address,
            &default_bridge_test_response("10.23.8.0/24")
        ),
        Some(false)
    );
    assert_eq!(
        default_bridge_membership(
            context.address,
            &default_bridge_test_response("10.23.7.9/24")
        ),
        None
    );
    let valid = default_bridge_test_response("10.23.7.0/24");
    let body = valid.strip_suffix(b"\n200").unwrap();
    for (field, values) in [
        (
            "Name",
            vec![Value::Null, json!("private-canary"), json!(17)],
        ),
        (
            "Driver",
            vec![Value::Null, json!("private-canary"), json!(true)],
        ),
        (
            "Id",
            vec![
                Value::Null,
                json!("a".repeat(63)),
                json!("A".repeat(64)),
                json!("private-canary"),
            ],
        ),
        (
            "IPAM",
            vec![
                Value::Null,
                json!({"Config":[]}),
                json!({"Config":[{"Subnet":"fd00::/64"}]}),
                json!({"Config":[{"Subnet":"10.23.7.0/24"},{"Subnet":"private-canary"}]}),
            ],
        ),
    ] {
        for replacement in values.into_iter().map(Some).chain([None]) {
            let mut network: Value = serde_json::from_slice(body).unwrap();
            if let Some(value) = replacement {
                network[field] = value;
            } else {
                network.as_object_mut().unwrap().remove(field);
            }
            let mut response = serde_json::to_vec(&network).unwrap();
            response.extend_from_slice(b"\n200");
            assert_eq!(default_bridge_membership(context.address, &response), None);
        }
    }
    for response in [
        Vec::new(),
        body.to_vec(),
        b"private-canary\n200".to_vec(),
        b"{\n200".to_vec(),
        b"\xff\n200".to_vec(),
        [body, b"\n404"].concat(),
        [body, b"\n200\n"].concat(),
        [body, b" trailing\n200"].concat(),
        vec![b'x'; DEFAULT_BRIDGE_RESPONSE_CAP + 1],
    ] {
        assert_eq!(default_bridge_membership(context.address, &response), None);
    }
}

#[test]
fn default_bridge_optional_budget_checks_after_wget_and_never_renews_cleanup() {
    let context = default_bridge_test_context();
    let url = format!("http://{}:18084/", context.address);
    let args = [
        "exec",
        context.client.as_str(),
        "wget",
        "-Y",
        "off",
        "-T",
        "2",
        "-qO-",
        &url,
    ];
    let mut failure = BoundedDnsCliOutput {
        success: false,
        code: Some(124),
        stdout: b"private-canary-out".to_vec(),
        stderr: b"private-canary-error".to_vec(),
        output_limit: false,
    };
    assert_eq!(proof_required_remaining(8, 8), 98);
    for remaining in [None, Some(0), Some(97)] {
        assert_eq!(
            optional_default_bridge(Some(&context), &args, &failure, remaining, 8, |_| panic!(
                "must not launch without original cleanup reserve"
            )),
            Some(DefaultBridgeObservation::BudgetExhausted)
        );
    }
    let calls = std::cell::Cell::new(0);
    assert_eq!(
        optional_default_bridge(Some(&context), &args, &failure, Some(98), 8, |_| {
            calls.set(calls.get() + 1);
            Some(default_bridge_test_response("10.23.7.0/24"))
        }),
        Some(DefaultBridgeObservation::Membership(true))
    );
    assert_eq!(calls.get(), 1);
    for output in [
        None,
        Some(b"private-canary\n200".to_vec()),
        Some(b"{\n200".to_vec()),
    ] {
        assert_eq!(
            optional_default_bridge(Some(&context), &args, &failure, Some(98), 8, |_| output),
            Some(DefaultBridgeObservation::Unavailable)
        );
    }
    assert!(!failure.success);
    assert_eq!(failure.code, Some(124));
    assert_eq!(failure.stdout, b"private-canary-out");
    assert_eq!(failure.stderr, b"private-canary-error");
    assert!(!failure.output_limit);
    assert_eq!(
        optional_default_bridge(None, &args, &failure, Some(98), 8, |_| panic!("no context")),
        None
    );
    assert_eq!(
        optional_default_bridge(
            Some(&context),
            &["exec", "other", "wget"],
            &failure,
            Some(98),
            8,
            |_| panic!("not the held ordinary control")
        ),
        None
    );
    failure.success = true;
    assert_eq!(
        optional_default_bridge(Some(&context), &args, &failure, Some(98), 8, |_| panic!(
            "successful wget"
        )),
        None
    );
    for deadline in [
        None,
        Some(""),
        Some("private-canary"),
        Some("+200"),
        Some("18446744073709551616"),
    ] {
        assert_eq!(optional_remaining(deadline, Some(100)), None);
    }
    assert_eq!(optional_remaining(Some("99"), Some(100)), None);
    assert_eq!(optional_remaining(Some("198"), Some(100)), Some(98));
    assert_eq!(optional_remaining(Some("198"), None), None);
}

#[test]
fn default_bridge_membership_is_independent_of_all_internal_control_pairs_and_private() {
    let mut context = default_bridge_test_context();
    let mut result = BoundedDnsCliOutput {
        success: false,
        code: Some(1),
        stdout: Vec::new(),
        stderr: b"private-canary".to_vec(),
        output_limit: false,
    };
    for internal in ["true", "false", "unknown"] {
        for control in ["true", "false", "unknown"] {
            for (subnet, expected) in [
                ("10.23.7.0/24", DefaultBridgeObservation::Membership(true)),
                ("10.23.8.0/24", DefaultBridgeObservation::Membership(false)),
                ("private-canary", DefaultBridgeObservation::Unavailable),
            ] {
                context.observations = SidecarSubnetDiagnostics { internal, control };
                let url = format!("http://{}:18084/", context.address);
                let args = [
                    "exec",
                    context.client.as_str(),
                    "wget",
                    "-Y",
                    "off",
                    "-T",
                    "2",
                    "-qO-",
                    &url,
                ];
                assert_eq!(
                    optional_default_bridge(Some(&context), &args, &result, Some(98), 8, |_| Some(
                        default_bridge_test_response(subnet)
                    )),
                    Some(expected)
                );
                assert_eq!(
                    context.observations,
                    SidecarSubnetDiagnostics { internal, control }
                );
                let diagnostic = expected.diagnostic();
                assert!(!diagnostic.contains("private-canary"));
                assert!(!diagnostic.contains("10.23"));
                assert!(!diagnostic.contains("inner.sock"));
                assert!(matches!(
                    diagnostic,
                    "sidecar_on_default_bridge_subnet=true"
                        | "sidecar_on_default_bridge_subnet=false"
                        | "sidecar_on_default_bridge_subnet=unknown reason=unavailable"
                ));
                // Nonzero exit, timeout, kill, and unknown wait status all retain
                // the same original failure, independently of optional evidence.
                for code in [Some(1), Some(124), Some(137), None] {
                    result.code = code;
                    assert!(!result.success);
                }
            }
        }
    }
    assert_eq!(
        DefaultBridgeObservation::BudgetExhausted.diagnostic(),
        "sidecar_on_default_bridge_subnet=unknown reason=budget_exhausted"
    );
}

#[test]
fn sidecar_subnet_pair_retains_independent_internal_and_control_inspections() {
    let address = Ipv4Addr::new(10, 23, 7, 9);
    let matching = json!({"IPAM": {"Config": [{"Subnet": "10.23.7.0/24"}]}});
    let disjoint = json!({"IPAM": {"Config": [{"Subnet": "192.168.50.0/24"}]}});
    let missing = json!({});
    let malformed = json!({"IPAM": {"Config": [{"Subnet": "10.23.7.9/24"}]}});
    for (internal, control, expected_internal, expected_control) in [
        (&matching, &matching, "true", "true"),
        (&matching, &disjoint, "true", "false"),
        (&disjoint, &matching, "false", "true"),
        (&disjoint, &disjoint, "false", "false"),
        (&missing, &matching, "unknown", "true"),
        (&matching, &missing, "true", "unknown"),
        (&malformed, &disjoint, "unknown", "false"),
        (&disjoint, &malformed, "false", "unknown"),
    ] {
        let expected = SidecarSubnetDiagnostics {
            internal: expected_internal,
            control: expected_control,
        };
        for internal_first in [true, false] {
            let mut observations = SidecarSubnetDiagnostics::new();
            assert_eq!(observations.internal, "unknown");
            assert_eq!(observations.control, "unknown");
            for is_internal in [internal_first, !internal_first] {
                observations.record(
                    is_internal,
                    address,
                    if is_internal { internal } else { control },
                );
            }
            assert_eq!(observations, expected);
        }
    }
}

#[test]
fn control_subnet_membership_is_closed_and_uses_only_held_control_metadata() {
    let address = Ipv4Addr::new(10, 23, 7, 9);
    for (network, expected) in [
        (
            json!({"IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]}}),
            "true",
        ),
        (
            json!({"IPAM":{"Config":[{"Subnet":"10.23.8.0/24"}]}}),
            "false",
        ),
        (
            json!({"IPAM":{"Config":[{"Subnet":"10.23.8.0/24"},{"Subnet":"10.23.7.0/24"}]}}),
            "true",
        ),
        (json!({"IPAM":{"Config":[{"Subnet":"0.0.0.0/0"}]}}), "true"),
        (
            json!({"IPAM":{"Config":[{"Subnet":"10.23.7.9/32"}]}}),
            "true",
        ),
        (
            json!({"IPAM":{"Config":[{"Subnet":"10.23.7.10/32"}]}}),
            "false",
        ),
        (
            json!({"IPAM":{"Config":[{"Subnet":"10.23.7.8/31"}]}}),
            "true",
        ),
        (
            json!({"IPAM":{"Config":[{"Subnet":"10.23.7.10/31"}]}}),
            "false",
        ),
        (json!({}), "unknown"),
        (json!({"IPAM":null}), "unknown"),
        (json!({"IPAM":{}}), "unknown"),
        (json!({"IPAM":{"Config":null}}), "unknown"),
        (json!({"IPAM":{"Config":[]}}), "unknown"),
        (json!({"IPAM":{"Config":[{}]}}), "unknown"),
        (json!({"IPAM":{"Config":[{"Subnet":null}]}}), "unknown"),
        (json!({"IPAM":{"Config":[{"Subnet":17}]}}), "unknown"),
        (
            json!({"IPAM":{"Config":[{"Subnet":"fd00::/64"}]}}),
            "unknown",
        ),
        (
            json!({"IPAM":{"Config":[{"Subnet":"fd00::/64"},{"Subnet":"10.23.7.0/24"}]}}),
            "true",
        ),
        (
            json!({"IPAM":{"Config":[{"Subnet":"10.23.7.0/24"},{"Subnet":"protected-canary"}]}}),
            "unknown",
        ),
        (
            json!({"IPAM":{"Config":[{"Subnet":"protected-canary"},{"Subnet":"10.23.7.0/24"}]}}),
            "unknown",
        ),
        (
            json!({"IPAM":{"Config":[{"Subnet":"10.23.8.0/24"}]},"other_network":{"IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]}}}),
            "false",
        ),
    ] {
        let observation = sidecar_on_subnet(address, &network);
        assert!(matches!(observation, "true" | "false" | "unknown"));
        assert_eq!(observation, expected);
    }
}

#[test]
fn control_subnet_malformed_noncanonical_and_boundary_cidrs_do_not_panic_or_claim_certainty() {
    let address = Ipv4Addr::new(10, 23, 7, 9);
    for subnet in [
        "",
        "private-canary",
        "10.23.7.0",
        "10.23.7.0/",
        "10.23.7.0/33",
        "10.23.7.0/-1",
        "10.23.7.0/+24",
        "10.23.7.0/024",
        "10.23.7.0/999",
        "10.23.7.0/24/1",
        " 10.23.7.0/24",
        "10.23.7.0/24 ",
        "010.23.7.0/24",
        "10.23.7.9/24",
        "fd00::1/64",
        "fd00::/129",
    ] {
        let network = json!({"IPAM":{"Config":[{"Subnet":subnet}]}});
        assert_eq!(sidecar_on_subnet(address, &network), "unknown");
    }
    let network = json!({"IPAM":{"Config":[{"Subnet":"10.23.7.0/24"}]}});
    for (address, expected) in [
        (Ipv4Addr::new(10, 23, 6, 255), "false"),
        (Ipv4Addr::new(10, 23, 7, 0), "true"),
        (Ipv4Addr::new(10, 23, 7, 255), "true"),
        (Ipv4Addr::new(10, 23, 8, 0), "false"),
    ] {
        assert_eq!(sidecar_on_subnet(address, &network), expected);
    }
}

#[test]
fn wget_failure_categories_are_closed_and_private() {
    for (message, expected) in [
        (
            "wget: connection refused private-canary",
            "connection_refused",
        ),
        ("wget: No route to host private-canary", "no_route"),
        ("wget: Network is unreachable private-canary", "no_route"),
        ("wget: download timed out private-canary", "timeout"),
        ("wget: timeout private-canary", "timeout"),
        (
            "wget: server returned error: HTTP/1.1 500 private-canary",
            "http_error",
        ),
        ("private-canary", "unknown"),
        ("", "unknown"),
    ] {
        assert_eq!(wget_failure_category(message.as_bytes()), expected);
    }
    assert_eq!(wget_failure_category(&[0xff]), "unknown");
}

fn proof_cli_ok(resources: &InternalProofResources, args: &[&str]) -> Vec<u8> {
    let result = proof_cli(resources, args);
    if let Some(observation) =
        failed_fixture_subnet(resources.fixture_subnet.as_ref(), args, &result)
    {
        eprintln!(
            "DOCKERLENS_NATIVE_FIXTURE_SUBNET_DIAG: {}",
            observation.diagnostic()
        );
    }
    if !result.success && args.first() == Some(&"exec") && args.get(2) == Some(&"wget") {
        eprintln!(
            "DOCKERLENS_NATIVE_WGET_DIAG: category={}",
            wget_failure_category(&result.stderr)
        );
        if let Some(context) = &resources.subnet_diagnostics {
            eprintln!(
                "DOCKERLENS_NATIVE_INTERNAL_SUBNET_DIAG: sidecar_on_internal_subnet={}",
                context.observations.internal
            );
            eprintln!(
                "DOCKERLENS_NATIVE_CONTROL_SUBNET_DIAG: sidecar_on_control_subnet={}",
                context.observations.control
            );
            if let Some(observation) = optional_default_bridge(
                Some(context),
                args,
                &result,
                optional_proof_remaining(),
                resources.containers.len() + resources.networks.len(),
                read_default_bridge,
            ) {
                eprintln!(
                    "DOCKERLENS_NATIVE_DEFAULT_BRIDGE_SUBNET_DIAG: {}",
                    observation.diagnostic()
                );
            }
        }
    }
    assert!(!result.output_limit, "bounded proof CLI output");
    if !result.success {
        eprintln!(
            "DOCKERLENS_NATIVE_NETWORK_CLI_DIAG: exit={} category={}",
            if matches!(result.code, Some(124 | 137)) {
                "timeout"
            } else {
                "other"
            },
            network_cli_failure_category(&result.stderr)
        );
    }
    assert!(result.success, "isolated proof CLI succeeds");
    result.stdout
}

fn proof_api(
    resources: &InternalProofResources,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> (u16, Vec<u8>) {
    resources.require_budget(8);
    api_with_timeout_and_cap(method, path, body, "6", Some(1024 * 1024))
}

fn proof_inspect(resources: &InternalProofResources, path: &str) -> Value {
    let (status, response) = proof_api(resources, "GET", path, None);
    assert_eq!(status, 200, "exact proof resource inspect succeeds");
    serde_json::from_slice(&response).expect("private proof inspect JSON")
}

fn proof_external_blocked(result: &BoundedDnsCliOutput) -> bool {
    result.success
        && result.code == Some(0)
        && !result.output_limit
        && result.stdout == b"blocked"
        && result.stderr.is_empty()
}

#[test]
fn internal_proof_cleanup_retains_failed_resources_and_requires_exact_404() {
    assert!(exact_http_absence(true, b"404"));
    for (success, status) in [
        (false, &b"404"[..]),
        (true, &b"500"[..]),
        (true, &b"000"[..]),
        (true, &b"404\n"[..]),
        (true, &b"protected-private"[..]),
    ] {
        assert!(!exact_http_absence(success, status));
    }
    let mut names = vec!["owned-one".to_owned(), "owned-two".to_owned()];
    let mut first = |kind: &str, name: &str| kind == "container" && name == "owned-one";
    assert!(!retain_unremoved(&mut names, "container", &mut first));
    assert_eq!(names, ["owned-two"]);
    let mut retry = |kind: &str, name: &str| kind == "container" && name == "owned-two";
    assert!(retain_unremoved(&mut names, "container", &mut retry));
    assert!(names.is_empty());
    assert_eq!(proof_required_remaining(9, 8), 108);
    assert!(!proof_budget_sufficient(107, 9, 8));
    assert!(proof_budget_sufficient(108, 9, 8));
}

#[test]
fn internal_proof_rejects_outer_timeout_or_failed_docker_exec() {
    let mut result = BoundedDnsCliOutput {
        success: true,
        code: Some(0),
        stdout: b"blocked".to_vec(),
        stderr: Vec::new(),
        output_limit: false,
    };
    assert!(proof_external_blocked(&result));
    for code in [Some(124), Some(137), Some(125), Some(126), Some(127), None] {
        result.success = false;
        result.code = code;
        assert!(!proof_external_blocked(&result));
    }
    result.success = true;
    result.code = Some(0);
    result.stdout = b"reachable".to_vec();
    assert!(!proof_external_blocked(&result));
    result.stdout = b"blocked".to_vec();
    result.output_limit = true;
    assert!(!proof_external_blocked(&result));
    result.output_limit = false;
    result.stderr = b"private Docker failure".to_vec();
    assert!(!proof_external_blocked(&result));
}

impl Drop for InternalProofResources {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let cleaned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if self.containers.is_empty() && self.networks.is_empty() {
                    true
                } else {
                    self.cleanup()
                }
            }))
            .unwrap_or(false);
            eprintln!(
                "DOCKERLENS_NATIVE_CLEANUP: internal_proof={}",
                closed_cleanup_result(cleaned)
            );
        } else if !self.containers.is_empty() || !self.networks.is_empty() {
            let _ = self.cleanup();
        }
    }
}

fn closed_cleanup_result(cleaned: bool) -> &'static str {
    if cleaned { "pass" } else { "fail" }
}

#[test]
fn internal_proof_cleanup_markers_are_closed() {
    assert_eq!(closed_cleanup_result(true), "pass");
    assert_eq!(closed_cleanup_result(false), "fail");
}

fn diagnostic_remaining(deadline_epoch: u64, now: Duration) -> Option<Duration> {
    // The shell's 180-second timeout includes Cargo startup. Stop optional
    // work twenty seconds early for process teardown and fixed-marker output.
    Duration::from_secs(deadline_epoch)
        .checked_sub(now)?
        .checked_sub(Duration::from_secs(20))
}

fn diagnostic_has_budget(deadline: Instant, operation_secs: u64, cleanup_secs: u64) -> bool {
    deadline
        .checked_duration_since(Instant::now())
        .is_some_and(|remaining| {
            remaining >= Duration::from_secs(operation_secs + cleanup_secs + 2)
        })
}

#[test]
fn dns_diagnostic_deadline_fails_closed_and_reserves_cleanup() {
    assert_eq!(diagnostic_remaining(180, Duration::from_secs(161)), None);
    assert_eq!(
        diagnostic_remaining(180, Duration::from_secs(159)),
        Some(Duration::from_secs(1))
    );
    let deadline = Instant::now() + Duration::from_secs(17);
    assert!(!diagnostic_has_budget(
        deadline,
        DNS_CLI_HARD_LIMIT_SECS,
        DNS_CLI_HARD_LIMIT_SECS,
    ));
    let deadline = Instant::now() + Duration::from_secs(25);
    assert!(diagnostic_has_budget(
        deadline,
        DNS_CLI_HARD_LIMIT_SECS,
        DNS_CLI_HARD_LIMIT_SECS,
    ));
}

fn exact_a_probe(args: &[&str], alias: &str, expected: Ipv4Addr) -> &'static str {
    let result = cli_dns(args);
    if result.success
        && !result.output_limit
        && nslookup_has_ipv4_answer(&result.stdout, alias, expected)
    {
        "pass"
    } else {
        "fail"
    }
}

fn exact_http_probe(args: &[&str], expected: &[u8]) -> &'static str {
    let result = cli_dns(args);
    if result.success && !result.output_limit && result.stdout.as_slice() == expected {
        "pass"
    } else {
        "fail"
    }
}

fn diagnose_edge_dns(run_id: &str, api_version: &str, edge: &str, image: &str, edge_ip: Ipv4Addr) {
    // The runner supplies the absolute deadline for its 180-second cargo
    // invocation. Missing, invalid, or nearly expired deadlines skip optional
    // commands; the mandatory failed DNS assertion still fails below.
    let mut summary = DnsDiagnostic::new();
    let remaining = std::env::var("NATIVE_NETWORK_TEST_DEADLINE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .zip(SystemTime::now().duration_since(UNIX_EPOCH).ok())
        .and_then(|(deadline, now)| diagnostic_remaining(deadline, now));
    let Some(remaining) = remaining else {
        summary.cleanup = "pass"; // No diagnostic peer was created.
        summary.emit();
        return;
    };
    let deadline = Instant::now() + remaining.min(Duration::from_secs(75));
    if !diagnostic_has_budget(deadline, DNS_CLI_HARD_LIMIT_SECS, DNS_CLI_HARD_LIMIT_SECS) {
        summary.cleanup = "pass"; // No diagnostic peer was created.
        summary.emit();
        return;
    }
    let peer = format!("dl-network-{run_id}-dns-peer");
    let mut guard = DnsPeerGuard {
        name: &peer,
        cleaned: false,
        deadline,
    };
    let created = cli_dns(&[
        "run",
        "--detach",
        "--rm",
        "--name",
        &peer,
        "--network",
        edge,
        image,
        "sleep",
        "120",
    ]);
    if created.success
        && !created.output_limit
        && diagnostic_has_budget(deadline, 3, DNS_CLI_HARD_LIMIT_SECS)
    {
        let path = format!("/v{api_version}/containers/{peer}/json");
        let inspected = std::panic::catch_unwind(|| {
            api_with_timeout_and_cap("GET", &path, None, "3", Some(1024 * 1024))
        });
        if let Ok((200, response)) = inspected {
            if let Ok(inspected) = serde_json::from_slice::<Value>(&response) {
                let networks = inspected["NetworkSettings"]["Networks"].as_object();
                if inspected["State"]["Running"] == true
                    && networks
                        .is_some_and(|networks| networks.len() == 1 && networks.contains_key(edge))
                {
                    summary.peer = "ready";
                } else {
                    summary.peer = "invalid";
                }
            } else {
                summary.peer = "invalid";
            }
        }
    }
    if summary.peer == "ready" {
        if diagnostic_has_budget(deadline, DNS_CLI_HARD_LIMIT_SECS, DNS_CLI_HARD_LIMIT_SECS) {
            let resolv = cli_dns(&["exec", &peer, "cat", "/etc/resolv.conf"]);
            if resolv.success && !resolv.output_limit {
                summary.resolver = resolver_category(&resolv.stdout);
            } else {
                summary.resolver = "unavailable";
            }
        }
        if diagnostic_has_budget(deadline, DNS_CLI_HARD_LIMIT_SECS, DNS_CLI_HARD_LIMIT_SECS) {
            summary.default_a = exact_a_probe(
                &["exec", &peer, "nslookup", "-type=A", "edge-sentinel"],
                "edge-sentinel",
                edge_ip,
            );
        }
        if diagnostic_has_budget(deadline, DNS_CLI_HARD_LIMIT_SECS, DNS_CLI_HARD_LIMIT_SECS) {
            summary.explicit_a = exact_a_probe(
                &[
                    "exec",
                    &peer,
                    "nslookup",
                    "-type=A",
                    "edge-sentinel",
                    "127.0.0.11",
                ],
                "edge-sentinel",
                edge_ip,
            );
        }
        if diagnostic_has_budget(deadline, DNS_CLI_HARD_LIMIT_SECS, DNS_CLI_HARD_LIMIT_SECS) {
            summary.dotted_a = exact_a_probe(
                &[
                    "exec",
                    &peer,
                    "nslookup",
                    "-type=A",
                    "edge-sentinel.",
                    "127.0.0.11",
                ],
                "edge-sentinel",
                edge_ip,
            );
        }
        if diagnostic_has_budget(deadline, DNS_CLI_HARD_LIMIT_SECS, DNS_CLI_HARD_LIMIT_SECS) {
            summary.name_http = exact_http_probe(
                &[
                    "exec",
                    &peer,
                    "wget",
                    "-T",
                    "2",
                    "-qO-",
                    "http://edge-sentinel:8080/",
                ],
                b"edge-canary",
            );
        }
        let ip_url = format!("http://{edge_ip}:8080/");
        if diagnostic_has_budget(deadline, DNS_CLI_HARD_LIMIT_SECS, DNS_CLI_HARD_LIMIT_SECS) {
            summary.ip_http = exact_http_probe(
                &["exec", &peer, "wget", "-T", "2", "-qO-", &ip_url],
                b"edge-canary",
            );
        }
        if diagnostic_has_budget(deadline, DNS_CLI_HARD_LIMIT_SECS, DNS_CLI_HARD_LIMIT_SECS) {
            summary.edge_app = exact_http_probe(
                &[
                    "exec",
                    &peer,
                    "wget",
                    "-T",
                    "2",
                    "-qO-",
                    "http://edge-app:8080/",
                ],
                b"network-canary",
            );
        }
    }
    summary.cleanup = if guard.cleanup() { "pass" } else { "fail" };
    summary.emit();
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
    result.code = Some(137);
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "cli_timeout"
    );
    result.code = Some(42);
    assert_eq!(
        dns_failure_category(&result, "edge-sentinel", expected),
        "cli_resolver"
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
            "Labels": {
                "io.dockerlens.network": "synthetic",
                (EMPTY_LABEL_KEY): "",
                (SPECIAL_LABEL_KEY): SPECIAL_LABEL_VALUE,
            },
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

fn expected_option_control_body(name: &str, icc: bool) -> Value {
    json!({
        "Name": name,
        "Driver": "bridge",
        "Options": {
            "com.docker.network.bridge.enable_icc": icc.to_string(),
            "com.docker.network.bridge.enable_ip_masquerade": "true",
        },
        "Labels": {
            "io.dockerlens.network": "synthetic",
            (EMPTY_LABEL_KEY): "",
            (SPECIAL_LABEL_KEY): SPECIAL_LABEL_VALUE,
        },
    })
}

fn internal_proof_body(name: &str, run_id: &str, internal: bool) -> Value {
    let mut body = json!({
        "Name": name,
        "Driver": "bridge",
        "Options": {
            "com.docker.network.bridge.enable_icc": "true",
            "com.docker.network.bridge.enable_ip_masquerade": "true",
        },
        "Labels": {"io.dockerlens.native-run": run_id},
    });
    if internal {
        body["Internal"] = json!(true);
    }
    body
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
    let oracle_control = format!("dl-network-{run_id}-oracle-control");
    let control = format!("dl-network-{run_id}-control");
    let control_enabled = format!("dl-network-{run_id}-control-enabled");
    let app = format!("dl-network-{run_id}-app");
    let isolated = format!("dl-network-{run_id}-isolated");
    let edge_only = format!("dl-network-{run_id}-edge-only");
    let dns_peer = format!("dl-network-{run_id}-dns-peer");
    let control_server = format!("dl-network-{run_id}-control-server");
    let control_client = format!("dl-network-{run_id}-control-client");
    let enabled_server = format!("dl-network-{run_id}-enabled-server");
    let enabled_client = format!("dl-network-{run_id}-enabled-client");
    let proof_internal = format!("dl-network-{run_id}-proof-internal");
    let proof_control = format!("dl-network-{run_id}-proof-control");
    let proof_cli_internal = format!("dl-network-{run_id}-proof-cli-internal");
    let proof_cli_control = format!("dl-network-{run_id}-proof-cli-control");
    let proof_internal_server = format!("dl-network-{run_id}-proof-internal-server");
    let proof_internal_client = format!("dl-network-{run_id}-proof-internal-client");
    let proof_control_server = format!("dl-network-{run_id}-proof-control-server");
    let proof_control_client = format!("dl-network-{run_id}-proof-control-client");
    let proof_cli_control_client = format!("dl-network-{run_id}-proof-cli-control-client");
    let path_allowed = match method {
        "GET" => {
            [
                backend.as_str(),
                edge.as_str(),
                external.as_str(),
                oracle.as_str(),
                oracle_control.as_str(),
                control.as_str(),
                control_enabled.as_str(),
                proof_internal.as_str(),
                proof_control.as_str(),
                proof_cli_internal.as_str(),
                proof_cli_control.as_str(),
            ]
            .iter()
            .any(|name| suffix == format!("networks/{name}"))
                || [
                    app.as_str(),
                    isolated.as_str(),
                    edge_only.as_str(),
                    dns_peer.as_str(),
                    control_server.as_str(),
                    control_client.as_str(),
                    enabled_server.as_str(),
                    enabled_client.as_str(),
                    proof_internal_server.as_str(),
                    proof_internal_client.as_str(),
                    proof_control_server.as_str(),
                    proof_control_client.as_str(),
                    proof_cli_control_client.as_str(),
                ]
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
        "networks/create" => {
            body == Some(&expected[0])
                || body == Some(&expected[1])
                || body == Some(&expected_option_control_body(&control, false))
                || body == Some(&expected_option_control_body(&control_enabled, true))
                || body == Some(&internal_proof_body(&proof_internal, run_id, true))
                || body == Some(&internal_proof_body(&proof_control, run_id, false))
        }
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
    api_with_timeout_and_cap(method, path, body, max_time, None)
}

fn api_with_timeout_and_cap(
    method: &str,
    path: &str,
    body: Option<&Value>,
    max_time: &str,
    response_cap: Option<usize>,
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
    let (success, output) = if let Some(cap) = response_cap {
        let stdout = child.stdout.take().expect("private Engine stdout");
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take((cap + 1) as u64)
                .read_to_end(&mut bytes)
                .expect("bounded private Engine response");
            (bytes.len() > cap, bytes)
        });
        let status = child.wait().expect("bounded Engine request");
        let (exceeded, bytes) = reader.join().expect("private Engine reader");
        assert!(!exceeded, "private Engine response exceeded diagnostic cap");
        (status.success(), bytes)
    } else {
        let output = child.wait_with_output().expect("bounded Engine response");
        (output.status.success(), output.stdout)
    };
    assert!(success, "isolated Engine request failed");
    let split = output.iter().rposition(|byte| *byte == b'\n').unwrap();
    let status = std::str::from_utf8(&output[split + 1..])
        .unwrap()
        .parse()
        .unwrap();
    (status, output[..split].to_vec())
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
    create.labels = vec![
        NetworkLabel::new(b"io.dockerlens.network".to_vec(), b"synthetic".to_vec()).unwrap(),
        NetworkLabel::new(EMPTY_LABEL_KEY.as_bytes().to_vec(), Vec::new()).unwrap(),
        NetworkLabel::new(
            SPECIAL_LABEL_KEY.as_bytes().to_vec(),
            SPECIAL_LABEL_VALUE.as_bytes().to_vec(),
        )
        .unwrap(),
    ];
    create
}

fn option_control_create(icc: bool) -> NetworkCreate {
    let mut create = NetworkCreate::bridge();
    create.options = vec![
        BridgeOption::InterContainerCommunication(icc),
        BridgeOption::IpMasquerade(true),
    ];
    create.labels = vec![
        NetworkLabel::new(b"io.dockerlens.network".to_vec(), b"synthetic".to_vec()).unwrap(),
        NetworkLabel::new(EMPTY_LABEL_KEY.as_bytes().to_vec(), Vec::new()).unwrap(),
        NetworkLabel::new(
            SPECIAL_LABEL_KEY.as_bytes().to_vec(),
            SPECIAL_LABEL_VALUE.as_bytes().to_vec(),
        )
        .unwrap(),
    ];
    create
}

fn option_control_intent(name: &str, icc: bool) -> TargetIntent {
    TargetIntent::new(vec![TargetResource::Network(NetworkIntent {
        reference: ResourceRef::new(1),
        identity: identity(name),
        role: NetworkRole::Declared,
        source: NetworkSource::Create(option_control_create(icc)),
    })])
    .expect("valid authored network option control")
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
                expected_internal: None,
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
    assert_eq!(names.len(), 22);
    assert_eq!(
        &PROBES[19..],
        &[
            "NetworkBridgeIccDisabled",
            "NetworkBridgeMasqueradeEnabled",
            "NetworkCreateLabelsValueDomain",
        ]
    );
    assert!(!names.contains("BridgeNetworkCreate"));
    assert!(!names.contains("BridgeNetworkAttach"));
    let options = NativeCapabilityShape::required_for(Capability::NetworkOptions).unwrap();
    assert!(options.contains(&NativeCapabilityShape::NetworkBridgeIcc));
    assert!(options.contains(&NativeCapabilityShape::NetworkBridgeIccDisabled));
    assert!(options.contains(&NativeCapabilityShape::NetworkBridgeMasquerade));
    assert!(options.contains(&NativeCapabilityShape::NetworkBridgeMasqueradeEnabled));
}

#[test]
fn network_executor_allowlist_is_closed() {
    let expected = expected_post_bodies("test", "fixture-image");
    let control = expected_option_control_body("dl-network-test-control", false);
    let enabled = expected_option_control_body("dl-network-test-control-enabled", true);
    let mut matched = control.clone();
    matched["Name"] = enabled["Name"].clone();
    matched["Options"]["com.docker.network.bridge.enable_icc"] = json!("true");
    assert_eq!(
        matched, enabled,
        "ICC controls differ only in name and value"
    );
    assert!(allowed_request(
        "POST",
        "/v1.41/networks/create",
        "1.41",
        "test",
        "fixture-image",
        Some(&control)
    ));
    assert!(allowed_request(
        "POST",
        "/v1.41/networks/create",
        "1.41",
        "test",
        "fixture-image",
        Some(&enabled)
    ));
    assert!(!allowed_request(
        "POST",
        "/v1.41/networks/create",
        "1.41",
        "test",
        "fixture-image",
        Some(&expected_option_control_body(
            "dl-network-other-control",
            false
        ))
    ));
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

#[test]
fn internal_proof_requests_are_exact_and_differ_only_by_internal_flag() {
    let run_id = "test";
    let internal = "dl-network-test-proof-internal";
    let control = "dl-network-test-proof-control";
    let internal_body = internal_proof_body(internal, run_id, true);
    let control_body = internal_proof_body(control, run_id, false);
    let mut matched = internal_body.clone();
    matched["Name"] = json!(control);
    matched.as_object_mut().unwrap().remove("Internal");
    assert_eq!(matched, control_body);
    for (name, body) in [(internal, &internal_body), (control, &control_body)] {
        assert!(allowed_request(
            "POST",
            "/v1.41/networks/create",
            "1.41",
            run_id,
            "fixture-image",
            Some(body)
        ));
        assert!(allowed_request(
            "GET",
            &format!("/v1.41/networks/{name}"),
            "1.41",
            run_id,
            "fixture-image",
            None
        ));
    }
    for altered in [
        json!({"Internal": false}),
        json!({"Options": {"com.docker.network.bridge.enable_icc": "false",
                            "com.docker.network.bridge.enable_ip_masquerade": "true"}}),
        json!({"Labels": {"io.dockerlens.native-run": "other"}}),
        json!({"Name": "unowned"}),
    ] {
        let mut candidate = internal_body.clone();
        candidate
            .as_object_mut()
            .unwrap()
            .extend(altered.as_object().unwrap().clone());
        assert!(!allowed_request(
            "POST",
            "/v1.41/networks/create",
            "1.41",
            run_id,
            "fixture-image",
            Some(&candidate)
        ));
    }
    assert!(!allowed_request(
        "GET",
        "/v1.41/networks/dl-network-other-proof-internal",
        "1.41",
        run_id,
        "fixture-image",
        None
    ));
}

#[test]
fn internal_cli_control_inspect_admission_requires_exact_context_and_no_body() {
    let path = "/v1.41/containers/dl-network-test-proof-cli-control-client/json";
    assert!(allowed_request(
        "GET",
        path,
        "1.41",
        "test",
        "fixture-image",
        None
    ));
    for (method, api_version, run_id) in [
        ("POST", "1.41", "test"),
        ("DELETE", "1.41", "test"),
        ("get", "1.41", "test"),
        ("GET", "1.42", "test"),
        ("GET", "1.41", "other"),
    ] {
        assert!(!allowed_request(
            method,
            path,
            api_version,
            run_id,
            "fixture-image",
            None
        ));
    }
    for wrong_path in [
        "/v1.41/containers/json",
        "/v1.41/containers/dl-network-test-proof-cli-control-client",
        "/v1.41/containers/dl-network-test-proof-cli-control-client-extra/json",
        "/v1.41/containers/dl-network-other-proof-cli-control-client/json",
        "/v1.42/containers/dl-network-test-proof-cli-control-client/json",
        "/v1.41/containers/dl-network-test-proof-cli-control-client/json?all=true",
        "/v1.41/containers/create?name=dl-network-test-proof-cli-control-client",
    ] {
        for method in ["GET", "POST", "DELETE"] {
            assert!(!allowed_request(
                method,
                wrong_path,
                "1.41",
                "test",
                "fixture-image",
                None
            ));
        }
    }
    for body in [json!(null), json!({}), json!({"Name": "private-other"})] {
        assert!(!allowed_request(
            "GET",
            path,
            "1.41",
            "test",
            "fixture-image",
            Some(&body)
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
    let oracle_control = format!("dl-network-{run_id}-oracle-control");
    let control = format!("dl-network-{run_id}-control");
    let control_enabled = format!("dl-network-{run_id}-control-enabled");
    let app = format!("dl-network-{run_id}-app");

    // The CLI oracle is independent of the inert renderer. Direct GETs check
    // Engine normalization, including options, labels, both IP families and IPAM.
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_oracle");
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_oracle_primary_create");
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
        "--label",
        "io.dockerlens.network.empty=",
        "--label",
        "io.dockerlens.network.special=Grüße \"quoted\" \\ path",
        &oracle,
    ]);
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_oracle_primary_inspect");
    let oracle_body = inspect(&format!("/v{api_version}/networks/{oracle}"));
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_oracle_primary_assert");
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
    let expected_labels = json!({
        "io.dockerlens.network": "synthetic",
        (EMPTY_LABEL_KEY): "",
        (SPECIAL_LABEL_KEY): SPECIAL_LABEL_VALUE,
    });
    assert!(
        oracle_body["Labels"] == expected_labels,
        "closed CLI network label oracle"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_oracle_alternate_create");
    cli_ok(&[
        "network",
        "create",
        "--driver",
        "bridge",
        "--opt",
        "com.docker.network.bridge.enable_icc=false",
        "--opt",
        "com.docker.network.bridge.enable_ip_masquerade=true",
        "--label",
        "io.dockerlens.network=synthetic",
        "--label",
        "io.dockerlens.network.empty=",
        "--label",
        "io.dockerlens.network.special=Grüße \"quoted\" \\ path",
        &oracle_control,
    ]);
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_oracle_alternate_inspect");
    let oracle_control_body = inspect(&format!("/v{api_version}/networks/{oracle_control}"));
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_oracle_alternate_assert");
    assert_eq!(oracle_control_body["Driver"], "bridge");
    assert_eq!(
        oracle_control_body["Options"]["com.docker.network.bridge.enable_icc"],
        "false"
    );
    assert_eq!(
        oracle_control_body["Options"]["com.docker.network.bridge.enable_ip_masquerade"],
        "true"
    );
    assert!(
        oracle_control_body["Labels"] == expected_labels,
        "closed CLI control labels"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_oracle_external_create");
    cli_ok(&["network", "create", "--driver", "bridge", &external]);
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_oracle_external_inspect");
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
    assert!(
        requests[0]["body"]["Labels"] == expected_labels,
        "closed rendered labels"
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
    assert!(
        backend_body["Labels"] == expected_labels,
        "closed backend labels"
    );
    let control_intent = option_control_intent(&control, false);
    let control_graph = DockerPlanner
        .plan(&control_intent, &supported)
        .expect("native option control plan");
    let control_artifact = DockerApiRenderer
        .render(&control_graph)
        .expect("inert option control request");
    assert!(
        !format!("{control_intent:?} {control_graph:?} {control_artifact:?}")
            .contains(SPECIAL_LABEL_VALUE)
    );
    let control_request: Value = serde_json::from_slice(
        control_artifact
            .bytes()
            .strip_suffix(b"\n")
            .expect("one request"),
    )
    .expect("inert option control JSON");
    assert_eq!(control_request["method"], "POST");
    assert_eq!(
        control_request["path"],
        format!("/v{api_version}/networks/create")
    );
    assert!(
        control_request["body"] == expected_option_control_body(&control, false),
        "closed opposite-value rendered body"
    );
    let (control_status, _) = api(
        "POST",
        &format!("/v{api_version}/networks/create"),
        Some(&control_request["body"]),
    );
    assert_eq!(
        control_status, 201,
        "Engine accepts opposite-value option control"
    );
    let control_body = inspect(&format!("/v{api_version}/networks/{control}"));
    for (option, value) in [
        ("com.docker.network.bridge.enable_icc", "false"),
        ("com.docker.network.bridge.enable_ip_masquerade", "true"),
    ] {
        assert_eq!(control_body["Options"][option], value);
        assert_eq!(oracle_control_body["Options"][option], value);
    }
    assert!(
        control_body["Labels"] == expected_labels,
        "closed control labels"
    );
    let enabled_intent = option_control_intent(&control_enabled, true);
    let enabled_graph = DockerPlanner
        .plan(&enabled_intent, &supported)
        .expect("native enabled control plan");
    let enabled_artifact = DockerApiRenderer
        .render(&enabled_graph)
        .expect("inert enabled control request");
    let enabled_request: Value = serde_json::from_slice(
        enabled_artifact
            .bytes()
            .strip_suffix(b"\n")
            .expect("one enabled request"),
    )
    .expect("inert enabled control JSON");
    assert_eq!(enabled_request["method"], "POST");
    assert_eq!(
        enabled_request["path"],
        format!("/v{api_version}/networks/create")
    );
    assert!(
        enabled_request["body"] == expected_option_control_body(&control_enabled, true),
        "closed matched enabled-control body"
    );
    let (enabled_status, _) = api(
        "POST",
        &format!("/v{api_version}/networks/create"),
        Some(&enabled_request["body"]),
    );
    assert_eq!(enabled_status, 201, "Engine accepts matched ICC control");
    let enabled_body = inspect(&format!("/v{api_version}/networks/{control_enabled}"));
    assert_eq!(
        enabled_body["Options"]["com.docker.network.bridge.enable_icc"],
        "true"
    );
    assert_eq!(
        enabled_body["Options"]["com.docker.network.bridge.enable_ip_masquerade"],
        "true"
    );
    assert!(
        enabled_body["Labels"] == expected_labels,
        "closed matched labels"
    );
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
    let mut edge_fixture = ExactNetworkFixture {
        name: &edge_only,
        cleaned: false,
    };
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
    let edge_id = canonical_inspected_container_id(&edge_only_body)
        .expect("edge-only fixture has canonical container ID");
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
                "sh",
                "-c",
                "grep -Eq '^[[:space:]]*nameserver[[:space:]]+127[.]0[.]0[.]11([[:space:]]|$)' /etc/resolv.conf || exit 42; exec nslookup -type=A edge-sentinel 127.0.0.11",
            ])
        },
        || inspect_running_with_dns_budget(&format!("/v{api_version}/containers/{edge_only}/json")),
        || std::thread::sleep(Duration::from_millis(250)),
    );
    if let Err(category) = edge_dns_outcome {
        eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_edge_dns_{category}");
        diagnose_edge_dns(&run_id, &api_version, &edge, &image, edge_ip);
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
    let mut backend_fixture = ExactNetworkFixture {
        name: &backend_only,
        cleaned: false,
    };
    cli_ok(&[
        "create",
        "--name",
        &backend_only,
        "--network",
        &backend,
        "--network-alias",
        "edge-sentinel",
        &image,
        "sh",
        "-c",
        "printf backend-canary > /tmp/index.html; httpd -f -p 8080 -h /tmp",
    ]);
    cli_ok(&["start", &backend_only]);
    let isolated = inspect(&format!("/v{api_version}/containers/{backend_only}/json"));
    let backend_id = canonical_inspected_container_id(&isolated)
        .expect("backend-only fixture has canonical container ID");
    assert!(edge_id != backend_id, "isolation fixtures must be distinct");
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
    assert_eq!(isolated["State"]["Running"], true);
    let backend_alias_present =
        isolated["NetworkSettings"]["Networks"][backend.as_str()]["Aliases"]
            .as_array()
            .is_some_and(|aliases| aliases.iter().any(|alias| alias == "edge-sentinel"));
    if !backend_alias_present {
        eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_backend_alias_missing");
    }
    assert!(
        backend_alias_present,
        "backend-only fixture must register its shared alias"
    );
    let backend_canary_ip = isolated["NetworkSettings"]["Networks"][backend.as_str()]["IPAddress"]
        .as_str()
        .expect("backend-only fixture has runtime IPv4")
        .parse::<Ipv4Addr>()
        .expect("bounded backend-only IPv4");
    assert!(
        edge_ip != backend_canary_ip,
        "isolation fixture IPs must differ"
    );
    let backend_ip = app_body["NetworkSettings"]["Networks"][backend.as_str()]["IPAddress"]
        .as_str()
        .expect("rendered backend runtime IPv4")
        .parse::<Ipv4Addr>()
        .expect("bounded rendered backend IPv4");
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_local_dns");
    let backend_resolver = cli_dns(&["exec", &backend_only, "cat", "/etc/resolv.conf"]);
    assert!(
        backend_resolver.success
            && !backend_resolver.output_limit
            && matches!(
                resolver_category(&backend_resolver.stdout),
                "embedded_search" | "embedded_plain"
            ),
        "backend-only peer must have the embedded DNS resolver"
    );
    let backend_answer = cli_dns(&[
        "exec",
        &backend_only,
        "nslookup",
        "-type=A",
        "backend-app",
        EMBEDDED_DNS_SERVER,
    ]);
    assert!(
        backend_answer.success
            && !backend_answer.output_limit
            && nslookup_has_ipv4_answer(&backend_answer.stdout, "backend-app", backend_ip),
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
    // The matched controls have the same authored bridge options and labels,
    // differing only in ICC. Both use healthy direct-IP peer HTTP, avoiding
    // DNS and egress as explanations for a blocked cross-peer request.
    let enabled_server = format!("dl-network-{run_id}-enabled-server");
    let enabled_client = format!("dl-network-{run_id}-enabled-client");
    let mut enabled_server_fixture = ExactNetworkFixture {
        name: &enabled_server,
        cleaned: false,
    };
    let mut enabled_client_fixture = ExactNetworkFixture {
        name: &enabled_client,
        cleaned: false,
    };
    for (name, canary) in [
        (&enabled_server, "control-server"),
        (&enabled_client, "control-client"),
    ] {
        let command = format!("printf {canary} > /tmp/index.html; httpd -f -p 8080 -h /tmp");
        cli_ok(&[
            "create",
            "--name",
            name,
            "--network",
            &control_enabled,
            &image,
            "sh",
            "-c",
            &command,
        ]);
        cli_ok(&["start", name]);
    }
    let enabled_server_body = inspect(&format!("/v{api_version}/containers/{enabled_server}/json"));
    let enabled_client_body = inspect(&format!("/v{api_version}/containers/{enabled_client}/json"));
    let enabled_server_id = canonical_inspected_container_id(&enabled_server_body)
        .expect("enabled server has canonical container ID");
    let enabled_client_id = canonical_inspected_container_id(&enabled_client_body)
        .expect("enabled client has canonical container ID");
    assert!(
        enabled_server_id != enabled_client_id,
        "enabled peers must differ"
    );
    for inspected in [&enabled_server_body, &enabled_client_body] {
        assert_eq!(inspected["State"]["Running"], true);
        let networks = inspected["NetworkSettings"]["Networks"]
            .as_object()
            .expect("enabled peer network map");
        assert!(networks.len() == 1 && networks.contains_key(control_enabled.as_str()));
    }
    let enabled_server_ip = enabled_server_body["NetworkSettings"]["Networks"]
        [control_enabled.as_str()]["IPAddress"]
        .as_str()
        .expect("enabled server IPv4")
        .parse::<Ipv4Addr>()
        .expect("enabled server address");
    let enabled_client_ip = enabled_client_body["NetworkSettings"]["Networks"]
        [control_enabled.as_str()]["IPAddress"]
        .as_str()
        .expect("enabled client IPv4")
        .parse::<Ipv4Addr>()
        .expect("enabled client address");
    assert!(
        enabled_server_ip != enabled_client_ip,
        "enabled peer IPv4 addresses must differ"
    );
    for (name, canary) in [
        (&enabled_server, &b"control-server"[..]),
        (&enabled_client, &b"control-client"[..]),
    ] {
        let own_http = cli_ok(&[
            "exec",
            name,
            "wget",
            "-T",
            "2",
            "-qO-",
            "http://127.0.0.1:8080/",
        ]);
        assert_eq!(
            own_http.as_slice(),
            canary,
            "enabled peer local HTTP health"
        );
    }
    let enabled_cross_url = format!("http://{enabled_server_ip}:8080/");
    let (enabled_cross_success, enabled_cross_body) = cli(&[
        "exec",
        &enabled_client,
        "wget",
        "-T",
        "2",
        "-qO-",
        &enabled_cross_url,
    ]);
    assert!(
        enabled_cross_success && enabled_cross_body.as_slice() == b"control-server",
        "ICC-enabled matched peers must connect by direct IPv4"
    );
    assert!(
        enabled_client_fixture.cleanup(),
        "exact enabled client cleanup"
    );
    assert!(
        enabled_server_fixture.cleanup(),
        "exact enabled server cleanup"
    );
    cli_ok(&["network", "rm", &control_enabled]);
    assert!(!cli(&["network", "inspect", &control_enabled]).0);
    // On the separately rendered ICC-disabled bridge, both peers must be
    // independently running and able to serve themselves before a direct-IP
    // cross-peer request can count as an ICC-negative observation.
    let control_server = format!("dl-network-{run_id}-control-server");
    let control_client = format!("dl-network-{run_id}-control-client");
    let mut control_server_fixture = ExactNetworkFixture {
        name: &control_server,
        cleaned: false,
    };
    let mut control_client_fixture = ExactNetworkFixture {
        name: &control_client,
        cleaned: false,
    };
    for (name, canary) in [
        (&control_server, "control-server"),
        (&control_client, "control-client"),
    ] {
        let command = format!("printf {canary} > /tmp/index.html; httpd -f -p 8080 -h /tmp");
        cli_ok(&[
            "create",
            "--name",
            name,
            "--network",
            &control,
            &image,
            "sh",
            "-c",
            &command,
        ]);
        cli_ok(&["start", name]);
    }
    let server_body = inspect(&format!("/v{api_version}/containers/{control_server}/json"));
    let client_body = inspect(&format!("/v{api_version}/containers/{control_client}/json"));
    let server_id = canonical_inspected_container_id(&server_body)
        .expect("control server has canonical container ID");
    let client_id = canonical_inspected_container_id(&client_body)
        .expect("control client has canonical container ID");
    assert!(server_id != client_id, "control peers must differ");
    for inspected in [&server_body, &client_body] {
        assert_eq!(inspected["State"]["Running"], true);
        let networks = inspected["NetworkSettings"]["Networks"]
            .as_object()
            .expect("control peer network map");
        assert!(networks.len() == 1 && networks.contains_key(control.as_str()));
    }
    let server_ip = server_body["NetworkSettings"]["Networks"][control.as_str()]["IPAddress"]
        .as_str()
        .expect("control server IPv4")
        .parse::<Ipv4Addr>()
        .expect("control server address");
    let client_ip = client_body["NetworkSettings"]["Networks"][control.as_str()]["IPAddress"]
        .as_str()
        .expect("control client IPv4")
        .parse::<Ipv4Addr>()
        .expect("control client address");
    assert!(
        server_ip != client_ip,
        "control peer IPv4 addresses must differ"
    );
    for (name, canary) in [
        (&control_server, &b"control-server"[..]),
        (&control_client, &b"control-client"[..]),
    ] {
        let own_http = cli_ok(&[
            "exec",
            name,
            "wget",
            "-T",
            "2",
            "-qO-",
            "http://127.0.0.1:8080/",
        ]);
        assert_eq!(
            own_http.as_slice(),
            canary,
            "control peer local HTTP health"
        );
    }
    let cross_url = format!("http://{server_ip}:8080/");
    let (cross_success, cross_body) = cli(&[
        "exec",
        &control_client,
        "wget",
        "-T",
        "2",
        "-qO-",
        &cross_url,
    ]);
    assert!(
        !cross_success && cross_body.is_empty(),
        "ICC-disabled control must block healthy same-bridge peers"
    );
    assert!(
        control_client_fixture.cleanup(),
        "exact control client cleanup"
    );
    assert!(
        control_server_fixture.cleanup(),
        "exact control server cleanup"
    );
    cli_ok(&["network", "rm", &control]);
    cli_ok(&["network", "rm", &oracle_control]);
    assert!(!cli(&["network", "inspect", &control]).0);
    assert!(!cli(&["network", "inspect", &oracle_control]).0);
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_collision_dns");
    let edge_resolver = cli_dns(&["exec", &edge_only, "cat", "/etc/resolv.conf"]);
    assert!(
        edge_resolver.success
            && !edge_resolver.output_limit
            && matches!(
                resolver_category(&edge_resolver.stdout),
                "embedded_search" | "embedded_plain"
            ),
        "edge-only peer must have the embedded DNS resolver"
    );
    let edge_collision = cli_dns(&[
        "exec",
        &edge_only,
        "nslookup",
        "-type=A",
        "edge-sentinel.",
        EMBEDDED_DNS_SERVER,
    ]);
    let edge_exact = edge_collision.success
        && !edge_collision.output_limit
        && nslookup_has_only_exact_named_a(&edge_collision.stdout, "edge-sentinel", edge_ip);
    if !edge_exact {
        let category = dns_failure_category(&edge_collision, "edge-sentinel", backend_canary_ip);
        eprintln!(
            "DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=edge category={} exit={} response={}",
            category,
            foreign_dns_exit_category(&edge_collision, category),
            foreign_dns_response_indicator(&edge_collision, "edge-sentinel", backend_canary_ip),
        );
    }
    assert!(
        edge_exact,
        "edge-only peer must receive only its own alias IPv4 A"
    );
    let backend_collision = cli_dns(&[
        "exec",
        &backend_only,
        "nslookup",
        "-type=A",
        "edge-sentinel.",
        EMBEDDED_DNS_SERVER,
    ]);
    let backend_exact = backend_collision.success
        && !backend_collision.output_limit
        && nslookup_has_only_exact_named_a(
            &backend_collision.stdout,
            "edge-sentinel",
            backend_canary_ip,
        );
    if !backend_exact {
        let category = dns_failure_category(&backend_collision, "edge-sentinel", edge_ip);
        eprintln!(
            "DOCKERLENS_NATIVE_COLLISION_DNS_DIAG: peer=backend category={} exit={} response={}",
            category,
            foreign_dns_exit_category(&backend_collision, category),
            foreign_dns_response_indicator(&backend_collision, "edge-sentinel", edge_ip),
        );
    }
    assert!(
        backend_exact,
        "backend-only peer must receive only its own alias IPv4 A"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_collision_http");
    let edge_named_http = cli_dns(&[
        "exec",
        &edge_only,
        "wget",
        "-T",
        "2",
        "-qO-",
        "http://edge-sentinel:8080/",
    ]);
    assert!(
        edge_named_http.success
            && !edge_named_http.output_limit
            && edge_named_http.stdout.as_slice() == b"edge-canary",
        "edge-only peer must reach only its local shared-alias canary"
    );
    let backend_named_http = cli_dns(&[
        "exec",
        &backend_only,
        "wget",
        "-T",
        "2",
        "-qO-",
        "http://edge-sentinel:8080/",
    ]);
    assert!(
        backend_named_http.success
            && !backend_named_http.output_limit
            && backend_named_http.stdout.as_slice() == b"backend-canary",
        "backend-only peer must reach only its local shared-alias canary"
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
    let backend_cleaned = backend_fixture.cleanup();
    let edge_cleaned = edge_fixture.cleanup();
    if !backend_cleaned || !edge_cleaned {
        eprintln!("DOCKERLENS_NATIVE_CHECK: network_isolation_cleanup_unverified");
    }
    assert!(
        backend_cleaned && edge_cleaned,
        "exact isolation fixture cleanup succeeds"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_evidence");
    fs::write(
        required("NATIVE_NETWORK_PROBES_PATH"),
        serde_json::to_vec(&PROBES).unwrap(),
    )
    .expect("private closed network evidence");
}

fn internal_proof_create(name: &str, run_id: &str, internal: bool) -> NetworkIntent {
    let mut create = NetworkCreate::bridge();
    create.internal = internal;
    create.options = vec![
        BridgeOption::InterContainerCommunication(true),
        BridgeOption::IpMasquerade(true),
    ];
    create.labels = vec![
        NetworkLabel::new(
            b"io.dockerlens.native-run".to_vec(),
            run_id.as_bytes().to_vec(),
        )
        .expect("task-owned proof label"),
    ];
    NetworkIntent {
        reference: ResourceRef::new(if internal { 1 } else { 2 }),
        identity: identity(name),
        role: NetworkRole::Declared,
        source: NetworkSource::Create(create),
    }
}

fn assert_single_homed_running(
    resources: &InternalProofResources,
    name: &str,
    network: &str,
    api_version: &str,
) {
    let body = proof_inspect(
        resources,
        &format!("/v{api_version}/containers/{name}/json"),
    );
    assert_eq!(body["State"]["Running"], true);
    assert_eq!(
        body["Config"]["Labels"]["io.dockerlens.native-run"],
        run_id()
    );
    let networks = body["NetworkSettings"]["Networks"]
        .as_object()
        .expect("proof peer network map");
    assert!(networks.len() == 1 && networks.contains_key(network));
    assert!(canonical_inspected_container_id(&body).is_some());
}

#[test]
#[ignore = "requires isolated rootful/rootless inner Engine and task-owned external endpoint"]
fn live_internal_network_blocks_external_egress() {
    let run_id = run_id();
    let api_version = required("NATIVE_API_VERSION");
    let image = required("NATIVE_FIXTURE_IMAGE");
    let engine_socket = PathBuf::from(required("NATIVE_ENGINE_SOCKET"));
    let proof_path = required("NATIVE_NETWORK_PROBES_PATH");
    let prior: Value = serde_json::from_slice(&fs::read(&proof_path).expect("prior network proof"))
        .expect("closed prior network proof");
    assert_eq!(prior, json!(PROBES), "base network suite must pass first");
    let mut resources = InternalProofResources::new(&run_id);
    let sidecar_ip = private_sidecar_ipv4(&required("NATIVE_EGRESS_SIDECAR_IPV4"))
        .expect("private task-owned sidecar IPv4");
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_topology");
    assert_outer_sidecar_topology(&resources, &run_id, sidecar_ip);
    let internal = format!("dl-network-{run_id}-proof-internal");
    let control = format!("dl-network-{run_id}-proof-control");
    let cli_internal = format!("dl-network-{run_id}-proof-cli-internal");
    let cli_control = format!("dl-network-{run_id}-proof-cli-control");
    let internal_server = format!("dl-network-{run_id}-proof-internal-server");
    let internal_client = format!("dl-network-{run_id}-proof-internal-client");
    let control_server = format!("dl-network-{run_id}-proof-control-server");
    let control_client = format!("dl-network-{run_id}-proof-control-client");

    let cli_control_client = format!("dl-network-{run_id}-proof-cli-control-client");

    // Independent CLI creates show the daemon's native interpretation of the
    // exact two matched settings before the inert bodies are sent to Engine.
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_oracle");
    let mut held_network_ids = Vec::new();
    for (name, is_internal) in [(&cli_control, false), (&cli_internal, true)] {
        let owner = format!("io.dockerlens.native-run={run_id}");
        let mut args = vec!["network", "create", "--driver", "bridge"];
        if is_internal {
            args.push("--internal");
        }
        args.extend([
            "--opt",
            "com.docker.network.bridge.enable_icc=true",
            "--opt",
            "com.docker.network.bridge.enable_ip_masquerade=true",
            "--label",
            &owner,
            name,
        ]);
        resources.networks.push(name.clone());
        let created = proof_cli_ok(&resources, &args);
        let id = std::str::from_utf8(&created)
            .ok()
            .and_then(|text| text.strip_suffix('\n'))
            .filter(|id| canonical_inspected_container_id(&json!({"Id": id})).is_some())
            .expect("CLI proof create returns canonical network identity");
        held_network_ids.push((name.clone(), id.to_owned()));
    }
    let cli_internal_body = proof_inspect(
        &resources,
        &format!("/v{api_version}/networks/{cli_internal}"),
    );
    let cli_control_body = proof_inspect(
        &resources,
        &format!("/v{api_version}/networks/{cli_control}"),
    );
    assert_eq!(cli_internal_body["Internal"], true);
    assert_eq!(cli_control_body["Internal"], false);
    for body in [&cli_internal_body, &cli_control_body] {
        assert_eq!(body["Labels"]["io.dockerlens.native-run"], run_id);
    }

    let source_id = required("NATIVE_CONTAINER_ID");
    resources.require_budget(32);
    let capture = acquire(
        &Endpoint::unix_socket(engine_socket.clone()),
        Selector::ContainerIds(vec![NativeId::new(source_id.clone()).unwrap()]),
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
    .expect("bounded proof identity acquisition");
    let mut facts = decode_capture(&capture)
        .expect("proof identity decode")
        .version
        .daemon;
    assert_eq!(
        facts.release.as_ref().unwrap().as_str(),
        required("NATIVE_ENGINE_VERSION")
    );
    assert_eq!(
        format!(
            "{}.{}",
            facts.api_version.unwrap().major,
            facts.api_version.unwrap().minor
        ),
        api_version
    );
    match required("NATIVE_DAEMON_MODE").as_str() {
        "rootless" => assert_eq!(facts.mode, DaemonMode::Rootless),
        "rootful" => {
            assert_ne!(facts.mode, DaemonMode::Rootless);
            facts.mode = DaemonMode::Rootful;
        }
        _ => panic!("invalid native lane mode"),
    }
    let fixture_subnet = captured_fixture_subnet(
        &capture,
        &source_id,
        std::env::var("NATIVE_NETWORK_ID").ok().as_deref(),
        &run_id,
        sidecar_ip,
    );
    let source_network_id = required("NATIVE_NETWORK_ID");
    held_network_ids.push((format!("dl-{run_id}-net"), source_network_id.clone()));
    let intent = TargetIntent::new(vec![
        TargetResource::Network(internal_proof_create(&internal, &run_id, true)),
        TargetResource::Network(internal_proof_create(&control, &run_id, false)),
    ])
    .expect("matched proof networks");
    let absent = ValidatedCapabilities::new(&facts).expect("observed proof identity");
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
        Capability::BridgeNetwork,
        Capability::NetworkInternal,
        Capability::NetworkOptions,
        Capability::NetworkLabels,
    ]
    .into_iter()
    .map(|capability| CapabilityFact {
        capability,
        state: CapabilityState::Available,
        provenance: FactProvenance::NativeConformance,
        scope: Some(scope.clone()),
    })
    .collect();
    let supported = ValidatedCapabilities::new(&facts).expect("test-local scoped proof facts");
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_render");
    let graph = DockerPlanner
        .plan(&intent, &supported)
        .expect("inert proof plan");
    let artifact = DockerApiRenderer
        .render(&graph)
        .expect("inert proof requests");
    let requests: Vec<Value> = artifact
        .bytes()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("proof request JSON"))
        .collect();
    assert_eq!(requests.len(), 2);
    for (request, name, is_internal) in [
        (&requests[0], &internal, true),
        (&requests[1], &control, false),
    ] {
        assert_eq!(request["method"], "POST");
        assert_eq!(request["path"], format!("/v{api_version}/networks/create"));
        assert_eq!(
            request["body"],
            internal_proof_body(name, &run_id, is_internal)
        );
        resources.networks.push(name.clone());
        let (status, response) = proof_api(
            &resources,
            "POST",
            &format!("/v{api_version}/networks/create"),
            Some(&request["body"]),
        );
        assert_eq!(status, 201, "Engine accepts exact inert proof request");
        let UniqueDiagnosticJson(created) =
            serde_json::from_slice(&response).expect("private proof create JSON");
        let id = canonical_inspected_container_id(&created)
            .expect("proof create returns canonical network identity");
        held_network_ids.push((name.clone(), id.to_owned()));
    }
    let mut subnet_diagnostics = SidecarSubnetDiagnostics::new();
    for (name, is_internal, cli_body) in [
        (&internal, true, &cli_internal_body),
        (&control, false, &cli_control_body),
    ] {
        let body = proof_inspect(&resources, &format!("/v{api_version}/networks/{name}"));
        assert!(
            held_network_ids
                .iter()
                .any(|(held_name, id)| held_name == name && body["Id"] == *id),
            "proof inspect binds its creation identity"
        );
        subnet_diagnostics.record(is_internal, sidecar_ip, &body);
        assert_eq!(body["Internal"], is_internal);
        assert_eq!(body["Driver"], "bridge");
        assert_eq!(body["Labels"]["io.dockerlens.native-run"], run_id);
        for option in [
            "com.docker.network.bridge.enable_icc",
            "com.docker.network.bridge.enable_ip_masquerade",
        ] {
            assert_eq!(body["Options"][option], "true");
            assert_eq!(body["Options"][option], cli_body["Options"][option]);
        }
    }

    // Mandatory fixture isolation snapshot, while only four cleanup liabilities
    // exist. This one read debits eight seconds of the ORIGINAL 180-second owner
    // (58 required, 57 refused), before any peers or new network are created.
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_topology");
    resources.require_budget(8);
    assert!(
        captured_fixture_membership(
            &capture,
            &source_id,
            Some(&source_network_id),
            &run_id,
            sidecar_ip
        )
        .is_some(),
        "captured source fixture identity is available"
    );
    let directory = std::path::Path::new(&proof_path)
        .parent()
        .expect("private proof directory");
    let topology =
        read_topology_record(directory, &run_id).expect("private creation-bound outer topology");
    let pools = topology_record_pools(
        &topology,
        &run_id,
        &required("NATIVE_IDENTITY_CANDIDATE_SHA"),
        &required("NATIVE_OUTER_ENGINE"),
        &required("NATIVE_OUTER_CONTAINER_ID"),
        sidecar_ip,
    )
    .expect("complete actual outer network pools and endpoints");
    let networks = read_inner_topology(&DefaultBridgeContext {
        api: facts.api_version.unwrap(),
        socket: engine_socket.clone(),
    })
    .expect("complete bounded inner network snapshot");
    assert!(
        {
            let result = assess_inner_topology(&networks, &run_id, &held_network_ids, &pools);
            if let Err(reason) = result {
                emit_inner_topology_refusal(&mut std::io::stderr().lock(), reason);
            }
            result.is_ok()
        },
        "all retained inner bridge pools are disjoint from actual outer pools"
    );

    // The external endpoint lives in a separate outer Podman namespace, so
    // packets from the inner bridge must traverse Docker's FORWARD path.
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_sidecar");
    let owner = format!("io.dockerlens.native-run={run_id}");
    let sidecar = format!("dl-native-egress-{run_id}");
    let local_health = proof_podman_ok(
        &resources,
        &[
            "exec",
            &sidecar,
            "wget",
            "-Y",
            "off",
            "-T",
            "2",
            "-qO-",
            "http://127.0.0.1:18084/",
        ],
    );
    assert_eq!(local_health, b"proof-egress");

    eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_peers");
    for (name, network, is_server) in [
        (&control_server, &control, true),
        (&control_client, &control, false),
        (&internal_server, &internal, true),
        (&internal_client, &internal, false),
    ] {
        let command = if is_server {
            "printf proof-peer > /tmp/index.html; httpd -f -p 8080 -h /tmp"
        } else {
            "sleep 180"
        };
        resources.containers.push(name.clone());
        proof_cli_ok(
            &resources,
            &[
                "create",
                "--name",
                name,
                "--label",
                &owner,
                "--network",
                network,
                &image,
                "sh",
                "-c",
                command,
            ],
        );
        proof_cli_ok(&resources, &["start", name]);
        assert_single_homed_running(&resources, name, network, &api_version);
    }
    for (client, server, network) in [
        (&control_client, &control_server, &control),
        (&internal_client, &internal_server, &internal),
    ] {
        let url = format!("http://{server}:8080/");
        let response = proof_cli_ok(
            &resources,
            &["exec", client, "wget", "-Y", "off", "-T", "2", "-qO-", &url],
        );
        assert_eq!(response, b"proof-peer", "healthy same-bridge HTTP");
        assert_single_homed_running(&resources, client, network, &api_version);
    }
    let external_url = format!("http://{sidecar_ip}:18084/");
    // Strict independent positive precontrol on the CLI-created ordinary
    // bridge. A failure stops here, before the rendered-control probe.
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_cli_control");
    resources.containers.push(cli_control_client.clone());
    proof_cli_ok(
        &resources,
        &[
            "create",
            "--name",
            &cli_control_client,
            "--label",
            &owner,
            "--network",
            &cli_control,
            &image,
            "sh",
            "-c",
            "sleep 180",
        ],
    );
    proof_cli_ok(&resources, &["start", &cli_control_client]);
    assert_single_homed_running(&resources, &cli_control_client, &cli_control, &api_version);
    resources.fixture_subnet = Some(FixtureSubnetContext {
        observation: fixture_subnet,
        address: sidecar_ip,
        client: cli_control_client.clone(),
    });
    let cli_control_response = proof_cli_ok(
        &resources,
        &[
            "exec",
            &cli_control_client,
            "wget",
            "-Y",
            "off",
            "-T",
            "2",
            "-qO-",
            &external_url,
        ],
    );
    resources.fixture_subnet = None;
    assert_eq!(
        cli_control_response, b"proof-egress",
        "independent CLI ordinary bridge reaches task endpoint"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_control");
    resources.subnet_diagnostics = Some(ProofSubnetContext {
        observations: subnet_diagnostics,
        default_bridge: default_bridge_context(
            facts.mode,
            std::env::var("NATIVE_OUTER_ENGINE").ok().as_deref(),
            facts.api_version,
            engine_socket,
        ),
        address: sidecar_ip,
        client: control_client.clone(),
    });
    let control_response = proof_cli_ok(
        &resources,
        &[
            "exec",
            &control_client,
            "wget",
            "-Y",
            "off",
            "-T",
            "2",
            "-qO-",
            &external_url,
        ],
    );
    resources.subnet_diagnostics = None;
    assert_eq!(
        control_response, b"proof-egress",
        "ordinary bridge reaches task endpoint"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_blocked");
    let blocked_command = format!(
        "if wget -Y off -T 2 -qO- {external_url} >/dev/null 2>&1; then printf reachable; else printf blocked; fi"
    );
    let blocked = proof_cli(
        &resources,
        &["exec", &internal_client, "sh", "-c", &blocked_command],
    );
    assert!(
        proof_external_blocked(&blocked),
        "internal peer must fail direct-IP external HTTP"
    );
    assert_single_homed_running(&resources, &internal_client, &internal, &api_version);
    let sidecar_after = proof_podman_ok(
        &resources,
        &["inspect", "--format", "{{.State.Running}}", &sidecar],
    );
    assert_eq!(sidecar_after, b"true\n");
    assert!(
        proof_cli_ok(
            &resources,
            &[
                "exec",
                &control_client,
                "wget",
                "-Y",
                "off",
                "-T",
                "2",
                "-qO-",
                &external_url
            ]
        ) == b"proof-egress",
        "endpoint remains reachable after negative probe"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_cleanup");
    assert!(resources.cleanup(), "exact owned proof resource cleanup");
    fs::write(
        proof_path,
        serde_json::to_vec(&json!({
            "probes": PROBES,
            "internal_shape": {"InternalBridgeNetworkCreate": "passed"},
        }))
        .unwrap(),
    )
    .expect("private closed internal network evidence");
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_evidence");
}
