//! Test-only network executor. Product rendering remains inert and catalog admission unchanged.

use std::fs;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
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

fn private_docker_command(seconds: &str) -> Command {
    let mut command = Command::new("timeout");
    // One second after TERM, force a stubborn CLI process to exit so the
    // diagnostic can still run its exact-peer cleanup before the outer gate.
    command.args(["--kill-after=1", seconds]);
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
}

fn cli_dns(args: &[&str]) -> BoundedDnsCliOutput {
    // The DNS readiness loop has four at-most-nine-second CLI calls and four
    // three-second state reads, plus three 250-ms waits in the retry case.
    let mut command = private_docker_command("8");
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
    let expected_labels = json!({
        "io.dockerlens.network": "synthetic",
        (EMPTY_LABEL_KEY): "",
        (SPECIAL_LABEL_KEY): SPECIAL_LABEL_VALUE,
    });
    assert!(
        oracle_body["Labels"] == expected_labels,
        "closed CLI network label oracle"
    );
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
    let oracle_control_body = inspect(&format!("/v{api_version}/networks/{oracle_control}"));
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
