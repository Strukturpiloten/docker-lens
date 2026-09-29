//! Test-only, isolated Engine probes for the typed container target contract.
//! The product renderer remains inert; this module alone applies synthetic requests.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const NATIVE_CLI_STREAM_LIMIT: usize = 8192;
const NAMESPACE_PROBE_MODES: &[&str] = &[
    "identity",
    "curl_version",
    "bash_version",
    "http",
    "udp",
    "tcp_refusal",
    "tcp6_refusal",
    "ipv6_socket",
];

fn require_namespace_probe_mode(mode: &str) {
    assert!(
        NAMESPACE_PROBE_MODES.contains(&mode),
        "closed namespace probe mode"
    );
}

#[test]
fn every_static_namespace_probe_mode_is_allowed() {
    let source = include_str!("native_container_tests.rs");
    let used: BTreeSet<_> = source
        .split("namespace_probe(\"")
        .skip(1)
        .map(|tail| tail.split_once('"').expect("literal mode").0)
        .collect();
    let allowed: BTreeSet<_> = NAMESPACE_PROBE_MODES.iter().copied().collect();
    assert_eq!(
        used, allowed,
        "static probe uses and closed allowlist drifted"
    );
    for mode in used {
        require_namespace_probe_mode(mode);
    }
    for invalid in ["", "private", "tcp6_refusal; private"] {
        assert!(std::panic::catch_unwind(|| require_namespace_probe_mode(invalid)).is_err());
    }
}

fn cli_failure_exit(status: std::process::ExitStatus) -> &'static str {
    match status.code() {
        Some(124) => "timeout",
        Some(137) | None => "signal",
        _ => "other",
    }
}

fn closed_http_exit(status: std::process::ExitStatus) -> &'static str {
    match status.code() {
        Some(0) => "0",
        Some(6) => "6",
        Some(7) => "7",
        Some(22) => "22",
        Some(28) => "28",
        Some(35) => "35",
        Some(52) => "52",
        Some(56) => "56",
        Some(60) => "60",
        Some(124) => "124",
        Some(137) => "137",
        _ => "other",
    }
}

fn closed_ipv6_disable_values(output: &[u8]) -> (&'static str, &'static str) {
    let mut lines = output.split(|byte| *byte == b'\n');
    let state = |line: Option<&[u8]>| {
        if line == Some(b"0".as_slice()) {
            "enabled"
        } else if line == Some(b"1".as_slice()) {
            "disabled"
        } else {
            "unavailable"
        }
    };
    let all = state(lines.next());
    let lo = state(lines.next());
    if all == "unavailable"
        || lo == "unavailable"
        || lines.next() != Some(b"".as_slice())
        || lines.next().is_some()
    {
        return ("unavailable", "unavailable");
    }
    (all, lo)
}

fn best_effort_ipv6_diagnostics(
    inner: impl FnOnce() -> (&'static str, &'static str),
    outer: impl FnOnce() -> &'static str,
) -> ((&'static str, &'static str), &'static str) {
    // These follow-up checks must not mask the already failed published HTTP
    // assertion, even when exact inspect or namespace identity fails closed.
    let inner = std::panic::catch_unwind(std::panic::AssertUnwindSafe(inner))
        .unwrap_or(("unavailable", "unavailable"));
    let outer =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(outer)).unwrap_or("probe_failed");
    (inner, outer)
}

#[test]
fn ipv6_disable_diagnostic_accepts_only_two_closed_values() {
    assert_eq!(
        closed_ipv6_disable_values(b"0\n1\n"),
        ("enabled", "disabled")
    );
    assert_eq!(
        closed_ipv6_disable_values(b"1\n0\n"),
        ("disabled", "enabled")
    );
    for malformed in [
        b"protected-secret\n0\n".as_slice(),
        b"0\nprotected-secret\n",
        b"0\n1\nextra\n",
        b"0\n1",
    ] {
        assert_eq!(
            closed_ipv6_disable_values(malformed),
            ("unavailable", "unavailable")
        );
    }
}

#[test]
fn failed_ipv6_follow_up_checks_keep_independent_closed_results() {
    let (inner, outer) =
        best_effort_ipv6_diagnostics(|| panic!("synthetic failed inspect"), || "available");
    assert_eq!(inner, ("unavailable", "unavailable"));
    assert_eq!(outer, "available");
    let (inner, outer) = best_effort_ipv6_diagnostics(
        || ("enabled", "disabled"),
        || panic!("synthetic failed pinned probe"),
    );
    assert_eq!(inner, ("enabled", "disabled"));
    assert_eq!(outer, "probe_failed");
}

fn cli_failure_stderr(stderr: &[u8]) -> &'static str {
    let message = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if message.contains("connection refused") || message.contains("could not connect to server") {
        "connection_refused"
    } else if message.contains("executable file not found")
        || message.contains("executable not found")
        || message.contains("command not found")
    {
        "missing_tool"
    } else if message.contains("address family not supported") {
        "address_family"
    } else if message.contains("cannot assign requested address")
        || message.contains("invalid address")
        || message.contains("bad address")
    {
        "invalid_address"
    } else if message.contains("no route to host") || message.contains("network is unreachable") {
        "no_route"
    } else if message.contains("permission denied") || message.contains("operation not permitted") {
        "permission"
    } else if message.contains("no space left on device") || message.contains("disk quota exceeded")
    {
        "storage_exhausted"
    } else if message.contains("invalid reference format") {
        "invalid_reference"
    } else if message.contains("no such container") || message.contains("no such image") {
        "missing_resource"
    } else if message.contains("failed to register layer")
        || message.contains("failed to save image")
    {
        "image_storage"
    } else {
        "unknown"
    }
}

fn namespace_failure_category(stderr: &[u8]) -> Option<&'static str> {
    let message = std::str::from_utf8(stderr).ok()?;
    [
        "input",
        "inspect",
        "identity",
        "changed",
        "process",
        "missing_tool",
        "probe",
    ]
    .into_iter()
    .find(|category| {
        message
            .lines()
            .any(|line| line == format!("DOCKERLENS_NATIVE_NAMESPACE_DIAG: category={category}"))
    })
}

fn api_status_category(status: u16) -> &'static str {
    match status {
        400 | 422 => "invalid_request",
        404 => "not_found",
        409 => "conflict",
        500..=599 => "server",
        _ => "other",
    }
}

fn mark_container_flow(phase: &'static str, outcome: &'static str) {
    assert!(matches!(
        phase,
        "mutation" | "cleanup_tracked" | "cleanup_inventory" | "cleanup_readback" | "decision"
    ));
    assert!(match phase {
        "mutation" => matches!(outcome, "timeout" | "uncertain"),
        "decision" => matches!(
            outcome,
            "merge" | "probe_failed" | "cleanup_unverified" | "mutation_uncertain"
        ),
        _ => matches!(outcome, "begin" | "pass" | "fail"),
    });
    eprintln!("DOCKERLENS_NATIVE_CONTAINER_FLOW: phase={phase} outcome={outcome}");
}

fn resource_control_start_outcome(status: Option<i32>) -> (&'static str, bool) {
    match status {
        Some(0) => ("started", false),
        Some(124 | 137) | None => ("timeout", true),
        Some(_) => ("uncertain", true),
    }
}

fn resource_control_may_continue(uncertain: bool, seconds_remaining: u64) -> bool {
    !uncertain && seconds_remaining >= 75
}

fn start_failure_body_diagnostic(body: &[u8]) -> String {
    let (shape, message) = if body.len() > 8192 {
        ("oversize", None)
    } else {
        match serde_json::from_slice::<Value>(body) {
            Ok(value) => match value.get("message").and_then(Value::as_str) {
                Some(message) if message.len() <= 4096 => ("message", Some(message.to_owned())),
                Some(_) => ("oversize", None),
                None => ("missing", None),
            },
            Err(_) => ("malformed", None),
        }
    };
    let category = |matched: bool| if matched { "present" } else { "absent" };
    if let Some(message) = message {
        // These are lexical mentions only; protected paths can contain the same words.
        let lower = message.to_ascii_lowercase();
        return format!(
            "DOCKERLENS_NATIVE_START_BODY_DIAG: shape={shape} cgroup_mention={} device_mention={} sysctl_mention={} ulimit_mention={} apparmor_mention={} permission_phrase={} errno_mention={} controller_mention={} bpf_mention={}",
            category(lower.contains("cgroup")),
            category(lower.contains("device")),
            category(lower.contains("sysctl")),
            category(lower.contains("ulimit") || lower.contains("rlimit")),
            category(lower.contains("apparmor")),
            category(
                lower.contains("permission denied")
                    || lower.contains("operation not permitted")
                    || lower.contains("access denied")
            ),
            category(lower.contains("errno")),
            category(lower.contains("controller")),
            category(lower.contains("bpf")),
        );
    }
    format!(
        "DOCKERLENS_NATIVE_START_BODY_DIAG: shape={shape} cgroup_mention=unknown device_mention=unknown sysctl_mention=unknown ulimit_mention=unknown apparmor_mention=unknown permission_phrase=unknown errno_mention=unknown controller_mention=unknown bpf_mention=unknown"
    )
}

#[test]
fn start_failure_body_diagnostic_is_structured_closed_and_private() {
    let body = br#"{"message":"cgroup device sysctl ulimit AppArmor operation not permitted errno controller bpf protected-secret"}"#;
    let diagnostic = start_failure_body_diagnostic(body);
    assert_eq!(
        diagnostic,
        "DOCKERLENS_NATIVE_START_BODY_DIAG: shape=message cgroup_mention=present device_mention=present sysctl_mention=present ulimit_mention=present apparmor_mention=present permission_phrase=present errno_mention=present controller_mention=present bpf_mention=present"
    );
    assert!(!diagnostic.contains("protected-secret"));
    for (word, field) in [
        ("cgroup", "cgroup_mention=present"),
        ("device", "device_mention=present"),
        ("sysctl", "sysctl_mention=present"),
        ("rlimit", "ulimit_mention=present"),
        ("apparmor", "apparmor_mention=present"),
        ("permission denied", "permission_phrase=present"),
        ("errno", "errno_mention=present"),
        ("controller", "controller_mention=present"),
        ("bpf", "bpf_mention=present"),
    ] {
        let body = json!({"message":word}).to_string();
        assert!(start_failure_body_diagnostic(body.as_bytes()).contains(field));
    }
    assert!(start_failure_body_diagnostic(b"not json").contains("shape=malformed"));
    assert!(start_failure_body_diagnostic(br#"{}"#).contains("shape=missing"));
    assert!(start_failure_body_diagnostic(&vec![b'x'; 8193]).contains("shape=oversize"));
    let protected_path =
        br#"{"message":"/private/cgroup-device-sysctl-ulimit-apparmor/permission denied/token"}"#;
    let path_diagnostic = start_failure_body_diagnostic(protected_path);
    assert!(path_diagnostic.contains("cgroup_mention=present"));
    assert!(path_diagnostic.contains("permission_phrase=present"));
    assert!(!path_diagnostic.contains("/private/"));
    assert!(!path_diagnostic.contains("token"));
}

fn assert_native_api_status(actual: u16, expected: u16) {
    if actual != expected {
        eprintln!(
            "DOCKERLENS_NATIVE_API_DIAG: status={}",
            api_status_category(actual)
        );
    }
    assert!(actual == expected, "closed native API status mismatch");
}

#[test]
fn native_failure_categories_remain_closed_and_private() {
    for (private, expected) in [
        ("connection refused protected-secret", "connection_refused"),
        (
            "could not connect to server protected-secret",
            "connection_refused",
        ),
        ("executable file not found protected-secret", "missing_tool"),
        (
            "address family not supported protected-secret",
            "address_family",
        ),
        (
            "cannot assign requested address protected-secret",
            "invalid_address",
        ),
        ("no route to host protected-secret", "no_route"),
        ("permission denied protected-secret", "permission"),
        (
            "no space left on device protected-secret",
            "storage_exhausted",
        ),
        (
            "invalid reference format protected-secret",
            "invalid_reference",
        ),
        ("no such container protected-secret", "missing_resource"),
        ("failed to register layer protected-secret", "image_storage"),
        ("protected-secret", "unknown"),
    ] {
        assert_eq!(cli_failure_stderr(private.as_bytes()), expected);
    }
    assert_eq!(api_status_category(409), "conflict");
    assert_eq!(api_status_category(500), "server");
}

fn bounded_native_cli_stream<R: Read>(mut reader: R) -> (Vec<u8>, bool) {
    let mut bytes = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let count = reader
            .read(&mut buffer)
            .expect("private native CLI stream read");
        if count == 0 {
            break;
        }
        let remaining = NATIVE_CLI_STREAM_LIMIT - bytes.len();
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        exceeded |= count > remaining;
    }
    (bytes, exceeded)
}

fn bounded_native_cli_output(command: &mut Command) -> std::process::Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .expect("bounded private native CLI available");
    let stdout = child.stdout.take().expect("private native CLI stdout");
    let stderr = child.stderr.take().expect("private native CLI stderr");
    let stdout_reader = std::thread::spawn(move || bounded_native_cli_stream(stdout));
    let stderr_reader = std::thread::spawn(move || bounded_native_cli_stream(stderr));
    let status = child.wait().expect("time-bounded private native CLI");
    let (stdout, stdout_exceeded) = stdout_reader
        .join()
        .expect("private native CLI stdout reader");
    let (stderr, stderr_exceeded) = stderr_reader
        .join()
        .expect("private native CLI stderr reader");
    assert!(
        !stdout_exceeded && !stderr_exceeded,
        "native CLI output exceeded closed byte limit"
    );
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

#[test]
fn oversized_fake_native_cli_output_fails_closed() {
    for redirection in ["", " >&2"] {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            &format!("head -c 1048576 /dev/zero{redirection}; printf private-canary{redirection}"),
        ]);
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            bounded_native_cli_output(&mut command);
        }))
        .unwrap_err();
        let text = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .unwrap();
        assert!(text.contains("native CLI output exceeded closed byte limit"));
        assert!(!text.contains("private-canary"));
    }
}

use crate::observation::ResourceRef;
use crate::target::{
    Argument, ContainerHostname, ContainerIntent, ContainerLabel, ContainerSettings,
    ContainerToken, ContainerUser, DeviceMapping, DevicePermissions, DockerApiRenderer,
    DockerPlanner, ExtraHost, HealthTest, Healthcheck, HostBinding, ImageCommand, ImageReference,
    LogConfig, LogDriver, MemoryLimit, Mount, PidsLimit, Planner, PlanningError, PortHostIp,
    PortHostPort, PortPublication, Protocol, Renderer, SecurityOption, TargetIdentity,
    TargetIntent, TargetResource, TmpfsOptions, Ulimit, UlimitValue, WorkingDirectory,
};
use crate::version::{
    ApiVersion, Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonFacts,
    DaemonMode, EngineRelease, FactProvenance, ObservationId, ValidatedCapabilities,
};
use serde_json::{Value, json};

// Native and authored values must never enter libtest panic text. These local
// equality macros keep exact comparisons while emitting only closed messages.
macro_rules! assert_eq {
    ($left:expr, $right:expr $(, $($message:tt)+)? $(,)?) => {{
        assert!(&$left == &$right, "closed native equality assertion failed");
    }};
}

macro_rules! assert_ne {
    ($left:expr, $right:expr $(, $($message:tt)+)? $(,)?) => {{
        assert!(
            &$left != &$right,
            "closed native inequality assertion failed"
        );
    }};
}

const EXPECTED_SHAPES: &[&str] = &[
    "ExposedOnlyPort",
    "FixedIpv4HostPort",
    "FixedIpv6HostPort",
    "EphemeralIpv6HostPort",
    "EphemeralIpv4HostPort",
    "MultipleFixedPortBindings",
    "MultipleEphemeralPortBindings",
    "EphemeralHostPort",
    "ClearCommand",
    "ClearEntrypoint",
    "ShellHealthcheck",
    "DisabledHealthcheck",
    "HealthStartPeriodPositive",
    "HealthStartPeriodZero",
    "HealthStartIntervalPositive",
    "HealthStartIntervalZero",
    "ContainerCreateLabels",
    "ContainerUser",
    "ContainerWorkdir",
    "ContainerHostname",
    "TmpfsMountReadWrite",
    "TmpfsMountReadOnly",
    "TmpfsMountOptions",
    "ReadOnlyRootfsTrue",
    "ReadOnlyRootfsFalse",
    "ContainerInitTrue",
    "ContainerInitFalse",
    "StopSignal",
    "StopTimeoutPositive",
    "StopTimeoutZero",
    "MemoryBytes",
    "MemoryUnlimited",
    "PidsCount",
    "PidsUnlimited",
    "ShmSize",
    "UlimitsFinite",
    "UlimitsUnlimited",
    "UlimitNofile",
    "DeviceMappings",
    "LinuxCapDrop",
    "LinuxCapAdd",
    "CapAddNetBindService",
    "CapDropSysAdmin",
    "NoNewPrivilegesEnabled",
    "NoNewPrivilegesDisabled",
    "Sysctls",
    "SysctlIpv4Forward",
    "SupplementaryGroups",
    "DnsIpv4",
    "DnsIpv6",
    "ExtraHostsIpv4",
    "ExtraHostsIpv6",
    "LogJsonFile",
    "LogLocal",
    "LogNone",
    "LogOptions",
    "LogOptionMaxSize",
];

#[derive(Default)]
struct ProbeEvidence {
    positive: BTreeSet<&'static str>,
    expected_negative: BTreeSet<(&'static str, &'static str)>,
}

impl ProbeEvidence {
    fn positive(&mut self, shape: &'static str) {
        assert!(EXPECTED_SHAPES.contains(&shape), "unknown closed shape");
        assert!(self.positive.insert(shape), "duplicate positive shape");
    }

    fn expected_negative(&mut self, shape: &'static str, reason: &'static str) {
        assert!(EXPECTED_SHAPES.contains(&shape), "unknown closed shape");
        assert!(matches!(
            (shape, reason),
            ("HealthStartIntervalPositive", "api_1_41_no_start_interval")
                | (
                    "HealthStartIntervalZero",
                    "api_1_41_start_interval_zero_unobservable"
                )
                | (
                    "FixedIpv6HostPort" | "EphemeralIpv6HostPort",
                    "nested_default_bridge_ipv6_unavailable"
                )
                | (
                    "FixedIpv6HostPort" | "EphemeralIpv6HostPort",
                    "nested_default_bridge_ipv6_runtime_binding_absent"
                )
        ));
        assert!(
            self.expected_negative.insert((shape, reason)),
            "duplicate expected negative"
        );
    }

    fn merge(&mut self, group: ProbeEvidence) {
        for shape in group.positive {
            self.positive(shape);
        }
        for (shape, reason) in group.expected_negative {
            self.expected_negative(shape, reason);
        }
    }

    fn complete(&self) -> Value {
        let observed: BTreeSet<_> = self
            .positive
            .iter()
            .copied()
            .chain(self.expected_negative.iter().map(|(shape, _)| *shape))
            .collect();
        assert_eq!(
            observed,
            EXPECTED_SHAPES.iter().copied().collect(),
            "native container probe set must be complete"
        );
        assert_eq!(
            self.positive.len() + self.expected_negative.len(),
            EXPECTED_SHAPES.len(),
            "a shape cannot have both outcomes"
        );
        json!({
            "schema_version": 1,
            "positive": self.positive,
            "expected_negative": self.expected_negative.iter().map(|(shape, reason)| {
                json!({"shape":shape,"reason":reason})
            }).collect::<Vec<_>>(),
        })
    }
}

#[test]
fn closed_container_probe_evidence_rejects_gaps_and_overlap() {
    assert_eq!(EXPECTED_SHAPES.len(), 57, "original closed shape count");
    let mut evidence = ProbeEvidence::default();
    evidence.positive("ExposedOnlyPort");
    assert!(std::panic::catch_unwind(|| evidence.complete()).is_err());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evidence.expected_negative("ExposedOnlyPort", "api_1_41_no_start_interval");
        }))
        .is_err()
    );
    assert_eq!(
        EXPECTED_SHAPES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len(),
        EXPECTED_SHAPES.len(),
        "expected shape list must be unique"
    );
    let mut complete = ProbeEvidence::default();
    for shape in EXPECTED_SHAPES {
        if *shape == "HealthStartIntervalPositive" {
            complete.expected_negative(shape, "api_1_41_no_start_interval");
        } else if *shape == "HealthStartIntervalZero" {
            complete.expected_negative(shape, "api_1_41_start_interval_zero_unobservable");
        } else {
            complete.positive(shape);
        }
    }
    let output = complete.complete();
    assert_eq!(output["schema_version"], 1);
    assert_eq!(
        output["positive"].as_array().unwrap().len(),
        EXPECTED_SHAPES.len() - 2
    );
    assert_eq!(
        output["expected_negative"],
        json!([
            {"shape":"HealthStartIntervalPositive", "reason":"api_1_41_no_start_interval"},
            {"shape":"HealthStartIntervalZero", "reason":"api_1_41_start_interval_zero_unobservable"}
        ])
    );
    let mut debian = ProbeEvidence::default();
    for shape in EXPECTED_SHAPES {
        match *shape {
            "FixedIpv6HostPort" | "EphemeralIpv6HostPort" => {
                debian.expected_negative(shape, "nested_default_bridge_ipv6_unavailable");
            }
            "HealthStartIntervalPositive" => {
                debian.expected_negative(shape, "api_1_41_no_start_interval");
            }
            "HealthStartIntervalZero" => {
                debian.expected_negative(shape, "api_1_41_start_interval_zero_unobservable");
            }
            _ => debian.positive(shape),
        }
    }
    let debian_output = debian.complete();
    assert_eq!(
        debian_output["expected_negative"].as_array().unwrap().len(),
        4
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            complete.positive("HealthStartIntervalPositive");
            complete.complete();
        }))
        .is_err()
    );
}

#[test]
fn native_assertion_failure_text_never_echoes_authored_values() {
    let caught = std::panic::catch_unwind(|| {
        assert_eq!("protected-secret", "different");
    })
    .unwrap_err();
    let message = caught
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| caught.downcast_ref::<&str>().copied())
        .expect("closed panic text");
    assert!(!message.contains("protected-secret"));
    assert!(message.contains("closed native equality assertion failed"));
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("native harness must supply {name}"))
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

fn valid_container_suffix(suffix: &str) -> bool {
    !suffix.is_empty()
        && suffix.len() <= 64
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn task_image_reference(role: &str, run_id: &str) -> Option<String> {
    if !matches!(
        role,
        "health-default" | "command-default" | "entrypoint-default"
    ) || run_id.is_empty()
        || run_id.len() > 64
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    // Docker repository components are lowercase; a tag retains the exact
    // mixed-case run ID without collision-inducing case folding.
    Some(format!("dockerlens-native-{role}:r{run_id}"))
}

#[test]
fn task_image_names_keep_lowercase_repository_and_exact_run_identity() {
    for role in ["health-default", "command-default", "entrypoint-default"] {
        let upper = task_image_reference(role, "hn5gNseb").unwrap();
        let lower = task_image_reference(role, "hn5gnseb").unwrap();
        assert_eq!(upper, format!("dockerlens-native-{role}:rhn5gNseb"));
        assert_ne!(upper, lower);
    }
    for role in ["", "Health-Default", "health_default", "../health", "other"] {
        assert!(task_image_reference(role, "hn5gNseb").is_none());
    }
    for run_id in ["", "invalid/name", "private:tag"] {
        assert!(task_image_reference("health-default", run_id).is_none());
    }
    assert!(task_image_reference("health-default", &"a".repeat(65)).is_none());
}

#[test]
fn native_container_suffix_accepts_ipv6_probe_without_widening_names() {
    assert!(valid_container_suffix("ipv6-oracle"));
    assert!(valid_container_suffix("ipv6-dynamic-rendered"));
    for invalid in [
        "",
        "Ipv6-oracle",
        "ipv6_oracle",
        "ipv6/oracle",
        "ipv6.oracle",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(!valid_container_suffix(invalid));
    }
}

#[test]
fn native_container_run_id_requires_exact_prefix_and_bounded_safe_suffix() {
    assert_eq!(validated_run_id("dl-native-AbC9-z"), Some("AbC9-z"));
    for invalid in [
        "dl-native-",
        "xdl-native-AbC9-z",
        "dl-native-a_b",
        "dl-native-a/b",
        "dl-native-é",
        "dl-native-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
    ] {
        assert_eq!(validated_run_id(invalid), None);
    }
}

struct NativeRun {
    api_version: String,
    image: String,
    run_id: String,
    mode: DaemonMode,
    outer_identity: Option<String>,
    created: Vec<(String, String)>,
    images: Vec<String>,
    uncertain_mutation: Cell<bool>,
}

#[derive(Default)]
struct OwnedInventory {
    containers: Vec<(String, String)>,
    images: Vec<(String, String)>,
}

impl OwnedInventory {
    fn is_empty(&self) -> bool {
        self.containers.is_empty() && self.images.is_empty()
    }
}

fn canonical_container_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_image_id(id: &str) -> bool {
    id.strip_prefix("sha256:")
        .is_some_and(canonical_container_id)
}

fn checked_labelled_image_row<'a>(
    line: &'a str,
    references: &BTreeSet<String>,
) -> (&'a str, &'a str) {
    let (id, found) = line.split_once(' ').expect("closed labelled image row");
    assert!(canonical_image_id(id), "canonical labelled image ID");
    assert!(
        references.contains(found),
        "exact task-owned labelled image tag"
    );
    (id, found)
}

fn cli_is_read_only(args: &[String]) -> bool {
    matches!(args, [first, second, ..] if first == "container" && matches!(second.as_str(), "ls" | "wait" | "inspect"))
        || matches!(args, [first, second, ..] if first == "image" && matches!(second.as_str(), "ls" | "inspect"))
        || matches!(args.first().map(String::as_str), Some("logs"))
}

#[test]
fn failed_native_cli_mutations_are_conservative() {
    for args in [
        vec!["container", "create"],
        vec!["container", "stop"],
        vec!["commit", "source", "target"],
        vec!["image", "rm"],
        vec!["exec", "container", "sh"],
        vec!["unknown", "operation"],
    ] {
        assert!(!cli_is_read_only(
            &args.into_iter().map(str::to_owned).collect::<Vec<_>>()
        ));
    }
    for args in [
        vec!["container", "ls"],
        vec!["container", "wait"],
        vec!["image", "ls"],
        vec!["image", "inspect"],
        vec!["logs", "container"],
    ] {
        assert!(cli_is_read_only(
            &args.into_iter().map(str::to_owned).collect::<Vec<_>>()
        ));
    }
}

#[test]
fn owned_inventory_ids_are_exact_and_closed() {
    assert!(canonical_container_id(&"a".repeat(64)));
    assert!(canonical_image_id(&format!("sha256:{}", "b".repeat(64))));
    for invalid in [
        "",
        "a",
        &"z".repeat(64),
        &format!("{} extra", "a".repeat(64)),
    ] {
        assert!(!canonical_container_id(invalid));
    }
    assert!(!canonical_image_id(&"a".repeat(64)));
}

#[test]
fn unexpected_run_labelled_image_prevents_verified_cleanup() {
    let expected = "localhost/dl-container-test-health-default:latest".to_owned();
    let references = BTreeSet::from([expected.clone()]);
    let id = format!("sha256:{}", "a".repeat(64));
    assert_eq!(
        checked_labelled_image_row(&format!("{id} {expected}"), &references),
        (id.as_str(), expected.as_str())
    );
    for found in ["<none>:<none>", "localhost/unexpected:latest"] {
        let result = std::panic::catch_unwind(|| {
            checked_labelled_image_row(&format!("{id} {found}"), &references);
        });
        assert!(
            result.is_err(),
            "unexpected labelled image must fail inventory"
        );
        assert_eq!(
            group_decision(true, result.is_ok(), false),
            GroupDecision::StopCleanup
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tcp6Boundary {
    Refused,
    Connected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ipv6FixtureOutcome {
    Assigned(Tcp6Boundary),
    RuntimeBindingAbsent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DebianIpv6Runtime {
    Assigned { ipv4_port: u16, ipv6_port: u16 },
    BindingAbsent { ipv4_port: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tcp6Probe {
    Refused,
    Connected,
    Timeout,
    Other,
    Malformed,
}

fn closed_tcp6_probe(status: Option<i32>, output: &[u8]) -> Tcp6Probe {
    match (status, output) {
        (Some(0), b"refused\n") => Tcp6Probe::Refused,
        (Some(1), b"connected\n") => Tcp6Probe::Connected,
        (Some(1), b"timeout\n") => Tcp6Probe::Timeout,
        (Some(1), b"other\n") => Tcp6Probe::Other,
        _ => Tcp6Probe::Malformed,
    }
}

fn require_tcp6_probe(probe: Tcp6Probe) -> Tcp6Boundary {
    match probe {
        Tcp6Probe::Refused => Tcp6Boundary::Refused,
        Tcp6Probe::Connected => Tcp6Boundary::Connected,
        Tcp6Probe::Timeout | Tcp6Probe::Other | Tcp6Probe::Malformed => {
            let category = match probe {
                Tcp6Probe::Timeout => "timeout",
                Tcp6Probe::Other => "other",
                _ => "malformed",
            };
            eprintln!("DOCKERLENS_NATIVE_IPV6_BOUNDARY_DIAG: result={category}");
            panic!("default-bridge TCP6 boundary is not a kernel refusal or connection");
        }
    }
}

fn stable_tcp6_boundary(
    mut probe: impl FnMut() -> Tcp6Probe,
    mut pause: impl FnMut(),
) -> Tcp6Boundary {
    // Match the former published-HTTP five-attempt, 250 ms readiness window.
    // A transient refusal can never authorize an expected negative.
    for attempt in 0..5 {
        match require_tcp6_probe(probe()) {
            Tcp6Boundary::Connected => return Tcp6Boundary::Connected,
            Tcp6Boundary::Refused if attempt < 4 => pause(),
            Tcp6Boundary::Refused => return Tcp6Boundary::Refused,
        }
    }
    unreachable!("closed five-attempt TCP6 window")
}

#[test]
fn stable_tcp6_refusal_requires_full_window_and_reclassifies_late_connection() {
    let mut attempts = 0;
    let mut pauses = 0;
    assert_eq!(
        stable_tcp6_boundary(
            || {
                attempts += 1;
                if attempts == 5 {
                    Tcp6Probe::Connected
                } else {
                    Tcp6Probe::Refused
                }
            },
            || pauses += 1,
        ),
        Tcp6Boundary::Connected
    );
    assert_eq!((attempts, pauses), (5, 4));
    let mut attempts = 0;
    assert_eq!(
        stable_tcp6_boundary(
            || {
                attempts += 1;
                Tcp6Probe::Refused
            },
            || {},
        ),
        Tcp6Boundary::Refused
    );
    assert_eq!(attempts, 5);
}

#[test]
fn tcp6_timeout_unknown_and_malformed_fail_closed() {
    assert_eq!(closed_tcp6_probe(Some(1), b"timeout\n"), Tcp6Probe::Timeout);
    assert_eq!(closed_tcp6_probe(Some(1), b"other\n"), Tcp6Probe::Other);
    assert_eq!(closed_tcp6_probe(Some(0), b"refused\n"), Tcp6Probe::Refused);
    assert_eq!(
        closed_tcp6_probe(Some(1), b"connected\n"),
        Tcp6Probe::Connected
    );
    assert_eq!(closed_tcp6_probe(None, b"refused\n"), Tcp6Probe::Malformed);
    for failure in [Tcp6Probe::Timeout, Tcp6Probe::Other, Tcp6Probe::Malformed] {
        let mut attempts = 0;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                stable_tcp6_boundary(
                    || {
                        attempts += 1;
                        failure
                    },
                    || {},
                );
            }))
            .is_err()
        );
        assert_eq!(attempts, 1, "non-refusal cannot be retried into a negative");
    }
}

impl NativeRun {
    fn new() -> Self {
        let lane = required("NATIVE_LANE");
        let api_version = required("NATIVE_API_VERSION");
        let mode = match required("NATIVE_DAEMON_MODE").as_str() {
            "rootful" => DaemonMode::Rootful,
            "rootless" => DaemonMode::Rootless,
            _ => panic!("unknown native daemon mode"),
        };
        assert!(
            matches!(lane.as_str(), "debian11-rootful" | "debian11-rootless")
                && api_version == "1.41"
                || matches!(lane.as_str(), "upstream-rootful" | "upstream-rootless")
                    && api_version == "1.56",
            "native lane must use its exact advertised API"
        );
        let outer = required("NATIVE_OUTER_CONTAINER");
        let run_id = validated_run_id(&outer)
            .expect("invalid task-owned run identifier")
            .to_owned();
        Self {
            api_version,
            image: required("NATIVE_FIXTURE_IMAGE"),
            run_id,
            mode,
            outer_identity: None,
            created: Vec::new(),
            images: Vec::new(),
            uncertain_mutation: Cell::new(false),
        }
    }

    fn name(&self, suffix: &str) -> String {
        assert!(valid_container_suffix(suffix));
        format!("dl-container-{}-{suffix}", self.run_id)
    }

    fn debian_default_bridge_boundary(&self) -> bool {
        // NativeRun::new binds these exact Debian lanes to API 1.41.
        self.api_version == "1.41"
    }

    fn image_name(&self, role: &str) -> String {
        task_image_reference(role, &self.run_id).expect("fixed task-owned image reference")
    }

    fn api(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Vec<u8>) {
        assert!(matches!(method, "GET" | "POST" | "DELETE"));
        assert!(path.starts_with(&format!("/v{}/containers/", self.api_version)));
        let previous_uncertainty = self.uncertain_mutation.get();
        if method != "GET" {
            self.uncertain_mutation.set(true);
        }
        let mut command = Command::new("curl");
        command.args([
            "-sS",
            "--max-time",
            "15",
            "--max-filesize",
            "1048576",
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
                .write_all(serde_json::to_string(body).unwrap().as_bytes())
                .expect("write bounded synthetic request");
        }
        let output = child
            .wait_with_output()
            .expect("bounded Engine API request");
        if !output.status.success() {
            if method != "GET" {
                self.uncertain_mutation.set(true);
            }
            let category = if output.status.code() == Some(28) {
                "timeout"
            } else {
                "other"
            };
            eprintln!("DOCKERLENS_NATIVE_API_DIAG: transport={category}");
            if method != "GET" {
                mark_container_flow(
                    "mutation",
                    if category == "timeout" {
                        "timeout"
                    } else {
                        "uncertain"
                    },
                );
            }
        }
        assert!(
            output.status.success(),
            "bounded Engine API transport failed"
        );
        let split = output
            .stdout
            .iter()
            .rposition(|byte| *byte == b'\n')
            .unwrap_or_else(|| {
                if method != "GET" {
                    self.uncertain_mutation.set(true);
                }
                panic!("HTTP status")
            });
        let status = std::str::from_utf8(&output.stdout[split + 1..])
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| {
                if method != "GET" {
                    self.uncertain_mutation.set(true);
                }
                panic!("numeric HTTP status")
            });
        if (100..=599).contains(&status) {
            self.uncertain_mutation.set(previous_uncertainty);
        }
        (status, output.stdout[..split].to_vec())
    }

    fn cli(&self, args: &[String]) -> String {
        self.cli_with_timeout(args, "45")
    }

    fn cli_with_timeout(&self, args: &[String], limit: &'static str) -> String {
        assert!(matches!(limit, "10" | "45"));
        let mutating = !cli_is_read_only(args);
        let previous_uncertainty = self.uncertain_mutation.get();
        if mutating {
            self.uncertain_mutation.set(true);
        }
        let mut command = Command::new("timeout");
        command.args(["--kill-after=1", limit]);
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
        command.args(args);
        let output = bounded_native_cli_output(&mut command);
        if !output.status.success() {
            eprintln!(
                "DOCKERLENS_NATIVE_CLI_DIAG: exit={} stderr={}",
                cli_failure_exit(output.status),
                cli_failure_stderr(&output.stderr)
            );
            if mutating {
                mark_container_flow(
                    "mutation",
                    if output.status.code() == Some(124) {
                        "timeout"
                    } else {
                        "uncertain"
                    },
                );
            }
        }
        assert!(output.status.success(), "independent CLI oracle failed");
        self.uncertain_mutation.set(previous_uncertainty);
        String::from_utf8(output.stdout).expect("CLI output UTF-8")
    }

    fn resource_control_create(&mut self, control: &'static str) -> Value {
        let options: &[&str] = match control {
            "baseline" => &[],
            "resource" => &["--memory=67108864", "--pids-limit=32"],
            "device" => &["--device=/dev/null:/dev/native-null:r"],
            _ => panic!("closed resource control"),
        };
        let name = self.name(&format!("resource-control-{control}"));
        let mut args = vec![
            "container".to_owned(),
            "create".to_owned(),
            "--name".to_owned(),
            name.clone(),
            "--label".to_owned(),
            format!("io.dockerlens.native-run={}", self.run_id),
        ];
        args.extend(options.iter().map(|option| (*option).to_owned()));
        args.extend([
            self.image.clone(),
            "sh".into(),
            "-c".into(),
            "sleep 120".into(),
        ]);
        let id = self.cli_with_timeout(&args, "10").trim().to_owned();
        assert!(canonical_container_id(&id), "CLI-created control ID");
        self.created.push((name, id.clone()));
        mark_resource_control(control, "create", "ready");
        mark_resource_control(control, "inspect", "begin");
        self.inspect(&id)
    }

    fn resource_control_start(&self, id: &str) -> &'static str {
        assert!(canonical_container_id(id));
        assert!(self.created.iter().any(|(_, created_id)| created_id == id));
        let mut command = Command::new("timeout");
        command.args(["--kill-after=1", "10"]);
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
            "container",
            "start",
            id,
        ]);
        let previous_uncertainty = self.uncertain_mutation.replace(true);
        let output = bounded_native_cli_output(&mut command);
        let (outcome, uncertain) = resource_control_start_outcome(output.status.code());
        if !uncertain {
            self.uncertain_mutation.set(previous_uncertainty);
        }
        outcome
    }

    fn namespace_probe(&self, mode: &str, argument: Option<&str>) -> std::process::Output {
        require_namespace_probe_mode(mode);
        let mut command = Command::new("timeout");
        command.args(["--kill-after=1", "16"]);
        if required("NATIVE_PODMAN_USE_SUDO") == "1" {
            command.args(["sudo", "-n"]);
        }
        let outer = format!("dl-native-{}", self.run_id);
        command.args([
            "python3",
            concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/native-net-probe.py"),
            mode,
            &outer,
        ]);
        if mode != "identity" {
            command.arg(
                self.outer_identity
                    .as_deref()
                    .expect("verified outer identity"),
            );
        }
        if let Some(argument) = argument {
            command.arg(argument);
        }
        let output = bounded_native_cli_output(&mut command);
        if !output.status.success() {
            if let Some(category) = namespace_failure_category(&output.stderr) {
                eprintln!("DOCKERLENS_NATIVE_NAMESPACE_DIAG: category={category}");
                panic!("closed outer namespace identity or probe failed");
            }
        }
        output
    }

    fn require_outer_identity(&mut self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: container_outer_identity");
        let output = self.namespace_probe("identity", None);
        assert!(
            output.status.success(),
            "outer namespace identity unavailable"
        );
        let identity = std::str::from_utf8(&output.stdout)
            .expect("bounded outer identity UTF-8")
            .trim_end_matches('\n');
        let fields: Vec<_> = identity.split('|').collect();
        assert!(
            fields.len() == 4
                && fields[0].len() == 64
                && fields[0].bytes().all(|byte| byte.is_ascii_hexdigit())
                && fields[1].parse::<u32>().is_ok_and(|pid| pid > 1)
                && !fields[2].is_empty()
                && fields[2].len() <= 128
                && fields[2].len() % 2 == 0
                && fields[2].bytes().all(|byte| byte.is_ascii_hexdigit())
                && fields[3].parse::<u64>().is_ok_and(|ticks| ticks > 0),
            "closed outer identity is malformed"
        );
        self.outer_identity = Some(identity.to_owned());
    }

    fn require_outer_curl(&self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: container_host_curl_preflight");
        let output = self.namespace_probe("curl_version", None);
        if !output.status.success() {
            eprintln!(
                "DOCKERLENS_NATIVE_HTTP_DIAG: exit={} category={}",
                cli_failure_exit(output.status),
                cli_failure_stderr(&output.stderr)
            );
        }
        assert!(
            output.status.success(),
            "host curl namespace probe is required"
        );
    }

    fn require_outer_bash(&self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: container_host_bash_preflight");
        let output = self.namespace_probe("bash_version", None);
        if !output.status.success() {
            eprintln!(
                "DOCKERLENS_NATIVE_CLI_DIAG: exit={} stderr={}",
                cli_failure_exit(output.status),
                cli_failure_stderr(&output.stderr)
            );
        }
        assert!(
            output.status.success(),
            "host Bash namespace probe is required"
        );
    }

    fn try_outer_http(
        &self,
        url: &str,
    ) -> Result<String, (&'static str, &'static str, &'static str)> {
        let output = self.namespace_probe("http", Some(url));
        if !output.status.success() {
            return Err((
                cli_failure_exit(output.status),
                cli_failure_stderr(&output.stderr),
                closed_http_exit(output.status),
            ));
        }
        Ok(String::from_utf8(output.stdout).expect("bounded outer HTTP UTF-8"))
    }

    fn inner_ipv6_state(&self, id: &str) -> (&'static str, &'static str) {
        assert!(
            id.len() == 64
                && id.bytes().all(|byte| byte.is_ascii_hexdigit())
                && self.created.iter().any(|(_, created_id)| created_id == id),
            "exact task-owned IPv6 diagnostic container"
        );
        let inspected = self.inspect(id);
        assert_eq!(
            inspected["Config"]["Labels"]["io.dockerlens.native-run"],
            self.run_id
        );
        let mut command = Command::new("timeout");
        command.args(["--kill-after=1", "12"]);
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
            "exec",
            id,
            "sh",
            "-c",
            "cat /proc/sys/net/ipv6/conf/all/disable_ipv6 /proc/sys/net/ipv6/conf/lo/disable_ipv6",
        ]);
        let output = bounded_native_cli_output(&mut command);
        if !output.status.success() {
            return ("unavailable", "unavailable");
        }
        closed_ipv6_disable_values(&output.stdout)
    }

    fn assert_published_http(&self, url: &str, expected: &str, local_ipv6: Option<(&str, bool)>) {
        let mut outcome = ("other", "unknown", "other");
        for attempt in 0..5 {
            match self.try_outer_http(url) {
                Ok(body) if body == expected => return,
                Ok(_) => outcome = ("success", "body_mismatch", "0"),
                Err(category) => outcome = category,
            }
            if attempt < 4 {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
        eprintln!(
            "DOCKERLENS_NATIVE_HTTP_DIAG: exit={} category={}",
            outcome.0, outcome.1
        );
        if let Some((id, local_ipv6)) = local_ipv6 {
            let ((inner_all, inner_lo), outer_tcp6) = best_effort_ipv6_diagnostics(
                || self.inner_ipv6_state(id),
                || {
                    let outer = self.namespace_probe("ipv6_socket", None);
                    if outer.status.success() {
                        match outer.stdout.as_slice() {
                            b"available\n" => "available",
                            b"tcp6_unavailable\n" => "tcp6_unavailable",
                            b"bind_unavailable\n" => "bind_unavailable",
                            b"loopback_unavailable\n" => "loopback_unavailable",
                            _ => "probe_failed",
                        }
                    } else {
                        "probe_failed"
                    }
                },
            );
            eprintln!(
                "DOCKERLENS_NATIVE_IPV6_DIAG: local_service={} inner_all={inner_all} inner_lo={inner_lo} outer_tcp6={outer_tcp6} curl_exit={}",
                if local_ipv6 { "pass" } else { "fail" },
                outcome.2
            );
        }
        panic!("closed published endpoint HTTP assertion failed");
    }

    fn assert_default_bridge_ipv6_context(&self, id: &str) {
        let inspected = self.inspect(id);
        assert_eq!(inspected["State"]["Running"], true);
        assert!(matches!(
            inspected["HostConfig"]["NetworkMode"].as_str(),
            Some("default" | "bridge")
        ));
        assert!(inspected["NetworkSettings"]["Networks"]["bridge"].is_object());
        let outer = self.namespace_probe("ipv6_socket", None);
        assert!(
            outer.status.success() && outer.stdout == b"available\n",
            "verified outer TCP6 loopback positive control failed"
        );
    }

    fn tcp6_probe(&self, port: u16) -> Tcp6Probe {
        let output = self.namespace_probe("tcp6_refusal", Some(&port.to_string()));
        closed_tcp6_probe(output.status.code(), &output.stdout)
    }

    fn assert_default_bridge_ipv6_boundary(&self, id: &str, port: u16) -> Tcp6Boundary {
        self.assert_default_bridge_ipv6_context(id);
        let result = stable_tcp6_boundary(
            || self.tcp6_probe(port),
            || std::thread::sleep(std::time::Duration::from_millis(250)),
        );
        eprintln!(
            "DOCKERLENS_NATIVE_IPV6_BOUNDARY_DIAG: result={}",
            match result {
                Tcp6Boundary::Refused => "refused",
                Tcp6Boundary::Connected => "connected",
            }
        );
        result
    }

    fn cli_create(&mut self, suffix: &str, options: &[String], command: &[&str]) -> Value {
        let image = self.image.clone();
        self.cli_create_image(suffix, options, &image, command)
    }

    fn cli_create_image(
        &mut self,
        suffix: &str,
        options: &[String],
        image: &str,
        command: &[&str],
    ) -> Value {
        let name = self.name(suffix);
        let mut args = vec![
            "container".to_owned(),
            "create".to_owned(),
            "--name".to_owned(),
            name.clone(),
            "--label".to_owned(),
            format!("io.dockerlens.native-run={}", self.run_id),
        ];
        args.extend_from_slice(options);
        args.push(image.to_owned());
        args.extend(command.iter().map(|arg| (*arg).to_owned()));
        if suffix == "health-default-source" {
            eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_source_create");
        }
        let id = self.cli(&args).trim().to_owned();
        assert_eq!(id.len(), 64, "CLI-created container ID");
        self.created.push((name, id.clone()));
        mark_port_stage(suffix, "cli_inspect");
        mark_resolver_suffix_stage(suffix, "inspect");
        if suffix == "health-default-source" {
            eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_source_inspect");
        }
        self.inspect(&id)
    }

    fn inspect(&self, id: &str) -> Value {
        let (status, response) = self.api(
            "GET",
            &format!("/v{}/containers/{id}/json", self.api_version),
            None,
        );
        assert_native_api_status(status, 200);
        serde_json::from_slice(&response).expect("private Engine inspect JSON")
    }

    fn rendered_create(
        &mut self,
        suffix: &str,
        container: ContainerIntent,
        required_capabilities: &[Capability],
        expected_body: Value,
    ) -> (String, Value, Value) {
        let name = self.name(suffix);
        mark_port_stage(suffix, "render");
        let body = self.render_only(suffix, container, required_capabilities);
        mark_port_stage(suffix, "render_body");
        mark_resolver_suffix_stage(suffix, "body");
        assert_eq!(
            body, expected_body,
            "closed independently authored create body"
        );
        let expected_path = format!("/v{}/containers/create?name={name}", self.api_version);
        mark_port_stage(suffix, "api_create");
        mark_resolver_suffix_stage(suffix, "create");
        let (status, response) = self.api("POST", &expected_path, Some(&body));
        assert_native_api_status(status, 201);
        let created: Value = serde_json::from_slice(&response).expect("private create response");
        let id = created["Id"]
            .as_str()
            .expect("created container ID")
            .to_owned();
        self.created.push((name, id.clone()));
        mark_port_stage(suffix, "api_inspect");
        mark_resolver_suffix_stage(suffix, "inspect");
        let inspected = self.inspect(&id);
        (id, body, inspected)
    }

    fn render_only(
        &self,
        suffix: &str,
        mut container: ContainerIntent,
        required_capabilities: &[Capability],
    ) -> Value {
        let name = self.name(suffix);
        container.identity = TargetIdentity::new(name.as_bytes().to_vec()).unwrap();
        container.settings.labels.push(
            ContainerLabel::new(
                b"io.dockerlens.native-run".to_vec(),
                self.run_id.as_bytes().to_vec(),
            )
            .unwrap(),
        );
        let intent =
            TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
        let mut capabilities = vec![Capability::StandaloneContainer, Capability::ContainerLabels];
        for capability in required_capabilities {
            if !capabilities.contains(capability) {
                capabilities.push(*capability);
            }
        }
        let observed = self.scoped_facts(&capabilities);
        let validated = ValidatedCapabilities::new(&observed).expect("test-only scoped facts");
        let graph = DockerPlanner
            .plan(&intent, &validated)
            .expect("native container intent plans");
        let artifact = DockerApiRenderer
            .render(&graph)
            .expect("inert request renders");
        assert!(
            !format!("{intent:?} {graph:?} {artifact:?}").contains(&self.run_id),
            "task-owned authored values stay redacted in Debug"
        );
        let lines: Vec<Value> = artifact
            .bytes()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("rendered JSON line"))
            .collect();
        assert_eq!(lines.len(), 1, "one standalone create request");
        let request = &lines[0];
        let expected_path = format!("/v{}/containers/create?name={name}", self.api_version);
        assert_eq!(request["method"], "POST");
        assert_eq!(request["path"], expected_path);
        assert_eq!(request.as_object().unwrap().len(), 3);
        request["body"].clone()
    }

    fn literal_create(&mut self, suffix: &str, mut body: Value) -> (String, Value) {
        let name = self.name(suffix);
        body["Labels"] = json!({"io.dockerlens.native-run":self.run_id});
        let path = format!("/v{}/containers/create?name={name}", self.api_version);
        let (status, response) = self.api("POST", &path, Some(&body));
        assert_eq!(status, 201, "independent literal Engine create succeeds");
        let created: Value = serde_json::from_slice(&response).expect("literal create JSON");
        let id = created["Id"]
            .as_str()
            .expect("literal container ID")
            .to_owned();
        self.created.push((name, id.clone()));
        let inspected = self.inspect(&id);
        (id, inspected)
    }

    fn scoped_facts(&self, available: &[Capability]) -> DaemonFacts {
        let observation_id = ObservationId::fresh().expect("test-only observation ID");
        let release = EngineRelease::new(required("NATIVE_ENGINE_VERSION")).unwrap();
        let (major, minor) = self.api_version.split_once('.').unwrap();
        let api_version = ApiVersion::new(
            NonZeroU16::new(major.parse().unwrap()).unwrap(),
            minor.parse().unwrap(),
        );
        let scope = CapabilityScope {
            observation_id,
            release: release.clone(),
            api_version,
            mode: self.mode,
        };
        DaemonFacts {
            observation_id,
            release: Some(release),
            api_version: Some(api_version),
            minimum_api_version: None,
            mode: self.mode,
            capabilities: available
                .iter()
                .copied()
                .map(|capability| CapabilityFact {
                    capability,
                    state: CapabilityState::Available,
                    provenance: FactProvenance::NativeConformance,
                    scope: Some(scope.clone()),
                })
                .collect(),
        }
    }

    fn delete(&mut self, id: &str) {
        let name = self
            .created
            .iter()
            .find(|(_, created_id)| created_id == id)
            .map(|(name, _)| name.clone())
            .expect("tracked task-owned container ID");
        self.delete_owned(&name, id);
    }

    fn delete_owned(&mut self, name: &str, id: &str) {
        assert!(canonical_container_id(id), "canonical owned container ID");
        assert!(name.starts_with(&format!("dl-container-{}-", self.run_id)));
        let inspected = self.inspect(id);
        assert_eq!(inspected["Id"], id);
        assert_eq!(inspected["Name"], format!("/{name}"));
        assert_eq!(
            inspected["Config"]["Labels"]["io.dockerlens.native-run"],
            self.run_id
        );
        let (status, _) = self.api(
            "DELETE",
            &format!("/v{}/containers/{id}?force=1", self.api_version),
            None,
        );
        assert_eq!(status, 204, "remove only task-owned container");
        self.created.retain(|(_, created_id)| created_id != id);
    }

    fn cleanup_tracked_containers(&mut self) {
        while let Some((_, id)) = self.created.last().cloned() {
            self.delete(&id);
        }
    }

    fn owned_inventory(&self) -> OwnedInventory {
        let prefix = format!("dl-container-{}-", self.run_id);
        let mut rows = BTreeSet::new();
        for (filter, require_prefix) in [
            (format!("name=^/{prefix}"), true),
            (
                format!("label=io.dockerlens.native-run={}", self.run_id),
                false,
            ),
        ] {
            let listed = self.cli(&[
                "container".into(),
                "ls".into(),
                "--all".into(),
                "--no-trunc".into(),
                "--filter".into(),
                filter,
                "--format".into(),
                "{{.ID}} {{.Names}}".into(),
            ]);
            for line in listed.lines() {
                let (id, name) = line
                    .split_once(' ')
                    .expect("closed container inventory row");
                if require_prefix {
                    assert!(name.starts_with(&prefix), "exact container-test namespace");
                }
                if name.starts_with(&prefix) {
                    rows.insert((id.to_owned(), name.to_owned()));
                }
            }
        }
        let mut inventory = OwnedInventory::default();
        for (id, name) in rows {
            assert!(canonical_container_id(&id), "canonical inventory ID");
            assert!(name.starts_with(&prefix), "exact container-test namespace");
            assert!(valid_container_suffix(&name[prefix.len()..]));
            let inspected = self.inspect(&id);
            assert_eq!(inspected["Id"], id);
            assert_eq!(inspected["Name"], format!("/{name}"));
            assert_eq!(
                inspected["Config"]["Labels"]["io.dockerlens.native-run"],
                self.run_id
            );
            inventory.containers.push((name, id));
        }
        let references: BTreeSet<_> = ["health-default", "command-default", "entrypoint-default"]
            .into_iter()
            .map(|role| self.image_name(role))
            .collect();
        let mut image_rows = BTreeSet::new();
        let labelled = self.cli(&[
            "image".into(),
            "ls".into(),
            "--all".into(),
            "--no-trunc".into(),
            "--filter".into(),
            format!("label=io.dockerlens.native-run={}", self.run_id),
            "--format".into(),
            "{{.ID}} {{.Repository}}:{{.Tag}}".into(),
        ]);
        for line in labelled.lines() {
            let (id, found) = checked_labelled_image_row(line, &references);
            image_rows.insert((id.to_owned(), found.to_owned()));
        }
        for reference in &references {
            let filter = format!("reference={reference}");
            let listed = self.cli(&[
                "image".into(),
                "ls".into(),
                "--no-trunc".into(),
                "--filter".into(),
                filter,
                "--format".into(),
                "{{.ID}} {{.Repository}}:{{.Tag}}".into(),
            ]);
            for line in listed.lines() {
                let (id, found) = line.split_once(' ').expect("closed image inventory row");
                assert_eq!(found, reference);
                image_rows.insert((id.to_owned(), found.to_owned()));
            }
        }
        for (id, found) in image_rows {
            assert!(canonical_image_id(&id), "canonical image inventory ID");
            let inspected = self.cli(&["image".into(), "inspect".into(), found.clone()]);
            let inspected: Value = serde_json::from_str(&inspected).expect("private image inspect");
            assert_eq!(inspected[0]["Id"], id);
            assert_eq!(
                inspected[0]["Config"]["Labels"]["io.dockerlens.native-run"],
                self.run_id
            );
            assert!(
                inspected[0]["RepoTags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == &found)),
                "exact task-owned image tag"
            );
            inventory.images.push((found, id));
        }
        inventory
    }

    fn cleanup_verified(&mut self) -> bool {
        mark_container_flow("cleanup_tracked", "begin");
        let tracked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.cleanup_tracked_containers()
        }))
        .is_ok();
        mark_container_flow("cleanup_tracked", if tracked { "pass" } else { "fail" });
        mark_container_flow("cleanup_inventory", "begin");
        let inventoried = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let inventory = self.owned_inventory();
            for expected in &self.images {
                assert!(
                    inventory
                        .images
                        .iter()
                        .any(|(reference, _)| reference == expected),
                    "tracked owned image present before cleanup"
                );
            }
            for (name, id) in inventory.containers {
                self.delete_owned(&name, &id);
            }
            for (reference, id) in inventory.images {
                self.cli(&["image".into(), "rm".into(), reference]);
                let remaining = self.cli(&[
                    "image".into(),
                    "ls".into(),
                    "--all".into(),
                    "--no-trunc".into(),
                    "--filter".into(),
                    format!("label=io.dockerlens.native-run={}", self.run_id),
                    "--format".into(),
                    "{{.ID}}".into(),
                ]);
                assert!(
                    !remaining.lines().any(|line| line == id),
                    "owned image ID removed"
                );
            }
        }))
        .is_ok();
        mark_container_flow(
            "cleanup_inventory",
            if inventoried { "pass" } else { "fail" },
        );
        mark_container_flow("cleanup_readback", "begin");
        let readback = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(self.owned_inventory().is_empty(), "owned resources absent");
            std::thread::sleep(std::time::Duration::from_millis(200));
            assert!(self.owned_inventory().is_empty(), "owned absence stable");
        }))
        .is_ok();
        mark_container_flow("cleanup_readback", if readback { "pass" } else { "fail" });
        tracked && inventoried && readback
    }

    fn image_with_defaults(
        &mut self,
        suffix: &str,
        entrypoint: &str,
        cmd: &str,
        expected_entrypoint: Value,
        expected_cmd: Value,
    ) -> String {
        let source = self.cli_create(&format!("{suffix}-source"), &[], &["true"]);
        let source_id = source["Id"].as_str().unwrap().to_owned();
        let image = self.image_name(suffix);
        self.cli(&[
            "commit".into(),
            "--change".into(),
            format!("ENTRYPOINT {entrypoint}"),
            "--change".into(),
            format!("CMD {cmd}"),
            "--change".into(),
            format!("LABEL io.dockerlens.native-run={}", self.run_id),
            source_id.clone(),
            image.clone(),
        ]);
        self.images.push(image.clone());
        self.delete(&source_id);
        let inspected = self.cli(&["image".into(), "inspect".into(), image.clone()]);
        let inspected: Value = serde_json::from_str(&inspected).unwrap();
        assert_eq!(inspected[0]["Config"]["Entrypoint"], expected_entrypoint);
        assert_eq!(inspected[0]["Config"]["Cmd"], expected_cmd);
        image
    }

    fn image_with_failing_health(&mut self) -> String {
        let source = self.cli_create(
            "health-default-source",
            &[
                "--health-cmd=/bin/false".into(),
                "--health-interval=1s".into(),
                "--health-timeout=1s".into(),
                "--health-retries=2".into(),
            ],
            &["sh", "-c", "sleep 120"],
        );
        let source_id = source["Id"].as_str().expect("health source ID").to_owned();
        let expected_health = json!({
            "Test": ["CMD-SHELL", "/bin/false"],
            "Interval": 1_000_000_000_i64,
            "Timeout": 1_000_000_000_i64,
            "Retries": 2,
        });
        for key in ["Test", "Interval", "Timeout", "Retries"] {
            assert_eq!(source["Config"]["Healthcheck"][key], expected_health[key]);
        }
        let image = self.image_name("health-default");
        eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_image_commit");
        self.cli(&[
            "commit".into(),
            "--change".into(),
            format!("LABEL io.dockerlens.native-run={}", self.run_id),
            source_id.clone(),
            image.clone(),
        ]);
        self.images.push(image.clone());
        eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_image_inspect");
        let inspected = self.cli(&["image".into(), "inspect".into(), image.clone()]);
        let inspected: Value = serde_json::from_str(&inspected).unwrap();
        for key in ["Test", "Interval", "Timeout", "Retries"] {
            assert_eq!(
                inspected[0]["Config"]["Healthcheck"][key],
                expected_health[key]
            );
        }
        assert_eq!(
            inspected[0]["Config"]["Labels"]["io.dockerlens.native-run"],
            self.run_id
        );
        eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_source_cleanup");
        self.delete(&source_id);
        image
    }
}

fn argument(value: &str) -> Argument {
    Argument::new(value.as_bytes().to_vec()).unwrap()
}

fn bare_container(image: &str) -> ContainerIntent {
    ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(b"placeholder".to_vec()).unwrap(),
        image: ImageReference::new(image.as_bytes().to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Exec(vec![argument("sh"), argument("-c"), argument("sleep 120")]),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings::default(),
    }
}

fn record_many(evidence: &mut ProbeEvidence, shapes: &[&'static str]) {
    for shape in shapes {
        evidence.positive(shape);
    }
}

fn assert_exact_mode_boundary(run: &NativeRun) {
    let mut container = bare_container(&run.image);
    container.ports = vec![
        PortPublication::published(
            NonZeroU16::new(8080).unwrap(),
            Protocol::Tcp,
            vec![HostBinding {
                host_ip: PortHostIp::Address("127.0.0.1".parse().unwrap()),
                host_port: PortHostPort::Fixed(NonZeroU16::new(80).unwrap()),
            }],
        )
        .unwrap(),
    ];
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
    let facts = run.scoped_facts(&[
        Capability::StandaloneContainer,
        Capability::Command,
        Capability::PortPublish,
        Capability::PortHostIpv4,
    ]);
    let validated = ValidatedCapabilities::new(&facts).unwrap();
    let planned = DockerPlanner.plan(&intent, &validated);
    if run.mode == DaemonMode::Rootless {
        assert!(matches!(planned, Err(PlanningError::RestrictedPort { .. })));
    } else {
        planned.expect("rootful low-port mode boundary does not reject planning");
    }
}

fn assert_port_binding(inspected: &Value, key: &str, host_ip: &str, host_port: &str) {
    let bindings = inspected["HostConfig"]["PortBindings"][key]
        .as_array()
        .expect("native host bindings");
    assert!(
        bindings
            .iter()
            .any(|binding| { binding["HostIp"] == host_ip && binding["HostPort"] == host_port })
    );
}

fn assert_configured_binding_count(inspected: &Value, key: &str, count: usize) {
    assert_eq!(
        inspected["HostConfig"]["PortBindings"][key]
            .as_array()
            .expect("configured port bindings")
            .len(),
        count,
        "exact configured binding count"
    );
}

fn binding_cardinality(count: usize) -> &'static str {
    match count {
        0 => "zero",
        1 => "one",
        2 => "two",
        _ => "many",
    }
}

fn runtime_port_shape(bindings: &[&Value]) -> &'static str {
    match bindings {
        [] => "absent",
        [binding] => match binding["HostPort"].as_str() {
            Some("") => "empty",
            Some("0") => "zero",
            Some(value) if value.parse::<u16>().is_ok_and(|port| port > 0) => "nonzero",
            _ => "malformed",
        },
        _ => "multiple",
    }
}

fn closed_runtime_binding_diagnostic(inspected: &Value, key: &str) -> String {
    let binding = inspected["NetworkSettings"]["Ports"].get(key);
    let state = match binding {
        None => "missing",
        Some(Value::Null) => "null",
        Some(Value::Array(_)) => "array",
        Some(_) => "other",
    };
    let entries = binding.and_then(Value::as_array);
    let ipv4: Vec<_> = entries
        .into_iter()
        .flatten()
        .filter(|item| item["HostIp"] == "127.0.0.1")
        .collect();
    let ipv6: Vec<_> = entries
        .into_iter()
        .flatten()
        .filter(|item| item["HostIp"] == "::1")
        .collect();
    let count = entries.map_or(0, Vec::len);
    let other = count.saturating_sub(ipv4.len() + ipv6.len());
    format!(
        "DOCKERLENS_NATIVE_PORT_BINDINGS_DIAG: key={state} count={} ipv4={} ipv6={} other={} v4_port={} v6_port={}",
        binding_cardinality(count),
        binding_cardinality(ipv4.len()),
        binding_cardinality(ipv6.len()),
        binding_cardinality(other),
        runtime_port_shape(&ipv4),
        runtime_port_shape(&ipv6),
    )
}

#[test]
fn runtime_binding_diagnostic_is_closed_and_value_free() {
    let inspected = json!({"NetworkSettings":{"Ports":{"8083/tcp":[
        {"HostIp":"127.0.0.1","HostPort":"18113","Secret":"protected-secret"},
        {"HostIp":"protected-secret","HostPort":"protected-secret"}
    ],"8084/tcp":null}}});
    let diagnostic = closed_runtime_binding_diagnostic(&inspected, "8083/tcp");
    assert_eq!(
        diagnostic,
        "DOCKERLENS_NATIVE_PORT_BINDINGS_DIAG: key=array count=two ipv4=one ipv6=zero other=one v4_port=nonzero v6_port=absent"
    );
    assert!(!diagnostic.contains("protected-secret"));
    assert!(!diagnostic.contains("18113"));
    assert!(closed_runtime_binding_diagnostic(&inspected, "8084/tcp").contains("key=null"));
    assert!(closed_runtime_binding_diagnostic(&inspected, "8085/tcp").contains("key=missing"));
    assert_eq!(
        runtime_port_shape(&[&json!({"HostPort":"private"})]),
        "malformed"
    );
}

fn assigned_port(inspected: &Value, key: &str, host_ip: &str, expected_bindings: usize) -> u16 {
    let bindings = inspected["NetworkSettings"]["Ports"][key]
        .as_array()
        .unwrap_or_else(|| {
            eprintln!("{}", closed_runtime_binding_diagnostic(inspected, key));
            panic!("runtime port bindings are absent or malformed");
        });
    if bindings.len() != expected_bindings {
        eprintln!("{}", closed_runtime_binding_diagnostic(inspected, key));
    }
    assert_eq!(
        bindings.len(),
        expected_bindings,
        "exact runtime binding count"
    );
    let matches: Vec<_> = bindings
        .iter()
        .filter(|binding| binding["HostIp"] == host_ip)
        .collect();
    if matches.len() != 1 {
        eprintln!("{}", closed_runtime_binding_diagnostic(inspected, key));
    }
    assert_eq!(
        matches.len(),
        1,
        "one runtime binding for exact host address"
    );
    let port: u16 = matches[0]["HostPort"]
        .as_str()
        .and_then(|value| value.parse().ok())
        .filter(|port| *port > 0)
        .unwrap_or_else(|| {
            eprintln!("{}", closed_runtime_binding_diagnostic(inspected, key));
            panic!("nonzero numeric runtime host port required");
        });
    port
}

fn classify_debian_ipv6_runtime(
    inspected: &Value,
    key: &str,
    fixed_ipv6_port: Option<u16>,
) -> DebianIpv6Runtime {
    assert_eq!(inspected["State"]["Running"], true);
    assert_configured_binding_count(inspected, key, 2);
    let configured_port = fixed_ipv6_port.map_or_else(String::new, |port| port.to_string());
    let configured_ipv4_port = fixed_ipv6_port.map_or("", |_| "18113");
    assert_port_binding(inspected, key, "::1", &configured_port);
    assert_port_binding(inspected, key, "127.0.0.1", configured_ipv4_port);
    let bindings = inspected["NetworkSettings"]["Ports"][key]
        .as_array()
        .unwrap_or_else(|| {
            eprintln!("{}", closed_runtime_binding_diagnostic(inspected, key));
            panic!("runtime port binding array required");
        });
    let runtime = match bindings.len() {
        2 => {
            // Preserve the original assigned-port oracle in this branch.
            let ipv4_port = assigned_port(inspected, key, "127.0.0.1", 2);
            let ipv6_port = assigned_port(inspected, key, "::1", 2);
            DebianIpv6Runtime::Assigned {
                ipv4_port,
                ipv6_port,
            }
        }
        1 => {
            // This is an independent boundary, never an inferred IPv6 port.
            if bindings[0]["HostIp"] != "127.0.0.1" {
                eprintln!("{}", closed_runtime_binding_diagnostic(inspected, key));
                panic!("only the exact IPv4 control binding may remain");
            }
            let ipv4_port = assigned_port(inspected, key, "127.0.0.1", 1);
            DebianIpv6Runtime::BindingAbsent { ipv4_port }
        }
        _ => {
            eprintln!("{}", closed_runtime_binding_diagnostic(inspected, key));
            panic!("unexpected runtime binding cardinality");
        }
    };
    if let Some(fixed) = fixed_ipv6_port {
        assert_eq!(
            runtime.ipv4_port(),
            18113,
            "exact fixed IPv4 control binding"
        );
        if let DebianIpv6Runtime::Assigned { ipv6_port, .. } = runtime {
            assert_eq!(ipv6_port, fixed, "exact fixed IPv6 runtime binding");
        }
    }
    runtime
}

impl DebianIpv6Runtime {
    fn ipv4_port(self) -> u16 {
        match self {
            Self::Assigned { ipv4_port, .. } | Self::BindingAbsent { ipv4_port } => ipv4_port,
        }
    }
}

#[test]
fn debian_ipv6_runtime_absence_requires_exact_single_ipv4_binding() {
    let fixture = |runtime: Value| {
        json!({
            "State":{"Running":true},
            "HostConfig":{"PortBindings":{"8083/tcp":[
                {"HostIp":"::1","HostPort":"18112"},
                {"HostIp":"127.0.0.1","HostPort":"18113"}
            ]}},
            "NetworkSettings":{"Ports":{"8083/tcp":runtime}}
        })
    };
    let absent = fixture(json!([{"HostIp":"127.0.0.1","HostPort":"18113"}]));
    assert_eq!(
        classify_debian_ipv6_runtime(&absent, "8083/tcp", Some(18112)),
        DebianIpv6Runtime::BindingAbsent { ipv4_port: 18113 }
    );
    let assigned = fixture(json!([
        {"HostIp":"127.0.0.1","HostPort":"18113"},
        {"HostIp":"::1","HostPort":"18112"}
    ]));
    assert_eq!(
        classify_debian_ipv6_runtime(&assigned, "8083/tcp", Some(18112)),
        DebianIpv6Runtime::Assigned {
            ipv4_port: 18113,
            ipv6_port: 18112,
        }
    );
    assert_ne!(
        classify_debian_ipv6_runtime(&absent, "8083/tcp", Some(18112)),
        classify_debian_ipv6_runtime(&assigned, "8083/tcp", Some(18112)),
        "absence-to-assigned transition cannot remain a negative"
    );
    for runtime in [
        Value::Null,
        json!([]),
        json!([{"HostIp":"::1","HostPort":"18112"}]),
        json!([{"HostIp":"127.0.0.2","HostPort":"18113"}]),
        json!([{"HostIp":"127.0.0.1","HostPort":""}]),
        json!([{"HostIp":"127.0.0.1","HostPort":"18113"},
               {"HostIp":"private","HostPort":"18112"}]),
    ] {
        let inspected = fixture(runtime);
        assert!(
            std::panic::catch_unwind(|| {
                classify_debian_ipv6_runtime(&inspected, "8083/tcp", Some(18112));
            })
            .is_err()
        );
    }
}

fn assert_debian_ipv6_controls(
    run: &NativeRun,
    id: &str,
    key: &str,
    expected: &str,
    suffix: &str,
    fixed_ipv6_port: Option<u16>,
) -> DebianIpv6Runtime {
    let inspected = run.inspect(id);
    let runtime = classify_debian_ipv6_runtime(&inspected, key, fixed_ipv6_port);
    let container_port = key
        .split_once('/')
        .expect("closed TCP port key")
        .0
        .parse()
        .expect("numeric container TCP port");
    assert_local_service(run, id, container_port, expected, suffix);
    mark_port_stage(suffix, "cli_http");
    run.assert_published_http(
        &format!("http://127.0.0.1:{}/index.html", runtime.ipv4_port()),
        expected,
        None,
    );
    mark_port_stage(suffix, "http_assert");
    runtime
}

fn assert_debian_ipv6_fixture(
    run: &NativeRun,
    id: &str,
    key: &str,
    expected: &str,
    suffix: &str,
    fixed_ipv6_port: Option<u16>,
) -> Ipv6FixtureOutcome {
    let runtime = assert_debian_ipv6_controls(run, id, key, expected, suffix, fixed_ipv6_port);
    match runtime {
        DebianIpv6Runtime::Assigned { ipv6_port, .. } => {
            mark_port_stage(suffix, "tcp6_boundary");
            let mut outcome = run.assert_default_bridge_ipv6_boundary(id, ipv6_port);
            if outcome == Tcp6Boundary::Refused {
                mark_port_stage(suffix, "negative_recheck");
                let rechecked =
                    assert_debian_ipv6_controls(run, id, key, expected, suffix, fixed_ipv6_port);
                assert_eq!(rechecked, runtime, "runtime binding must remain stable");
                run.assert_default_bridge_ipv6_context(id);
                outcome = require_tcp6_probe(run.tcp6_probe(ipv6_port));
                if outcome == Tcp6Boundary::Refused {
                    assert_eq!(
                        run.inner_ipv6_state(id),
                        ("disabled", "disabled"),
                        "only the reviewed nested default-bridge IPv6-disabled fixture admits a refusal"
                    );
                }
            }
            if outcome == Tcp6Boundary::Connected {
                mark_port_stage(suffix, "cli_http_secondary");
                run.assert_published_http(
                    &format!("http://[::1]:{ipv6_port}/index.html"),
                    expected,
                    None,
                );
                mark_port_stage(suffix, "http_assert_secondary");
            }
            Ipv6FixtureOutcome::Assigned(outcome)
        }
        DebianIpv6Runtime::BindingAbsent { .. } => {
            run.assert_default_bridge_ipv6_context(id);
            assert_eq!(run.inner_ipv6_state(id), ("disabled", "disabled"));
            for attempt in 0..5 {
                mark_port_stage(suffix, "runtime_absence");
                let inspected = run.inspect(id);
                assert_eq!(
                    classify_debian_ipv6_runtime(&inspected, key, fixed_ipv6_port),
                    runtime,
                    "runtime IPv6 binding absence and IPv4 control must stay exact"
                );
                if let Some(port) = fixed_ipv6_port {
                    mark_port_stage(suffix, "tcp6_boundary");
                    assert_exact_unassigned_refusal(run, port);
                }
                if attempt < 4 {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            }
            mark_port_stage(suffix, "negative_recheck");
            let rechecked =
                assert_debian_ipv6_controls(run, id, key, expected, suffix, fixed_ipv6_port);
            assert_eq!(
                rechecked, runtime,
                "runtime binding absence must remain stable"
            );
            run.assert_default_bridge_ipv6_context(id);
            assert_eq!(run.inner_ipv6_state(id), ("disabled", "disabled"));
            let final_inspected = run.inspect(id);
            assert_eq!(
                classify_debian_ipv6_runtime(&final_inspected, key, fixed_ipv6_port),
                runtime,
                "final runtime absence and IPv4 control must remain exact"
            );
            if let Some(port) = fixed_ipv6_port {
                assert_exact_unassigned_refusal(run, port);
            }
            Ipv6FixtureOutcome::RuntimeBindingAbsent
        }
    }
}

fn assert_exact_unassigned_refusal(run: &NativeRun, requested_port: u16) {
    let outcome = require_tcp6_probe(run.tcp6_probe(requested_port));
    eprintln!(
        "DOCKERLENS_NATIVE_IPV6_BOUNDARY_DIAG: result={}",
        match outcome {
            Tcp6Boundary::Refused => "refused",
            Tcp6Boundary::Connected => "connected",
        }
    );
    assert_eq!(
        outcome,
        Tcp6Boundary::Refused,
        "an unassigned fixed IPv6 binding must refuse at its requested port"
    );
}

fn record_ipv6_fixture_outcomes(
    evidence: &mut ProbeEvidence,
    shape: &'static str,
    oracle: Ipv6FixtureOutcome,
    rendered: Ipv6FixtureOutcome,
) {
    assert_eq!(
        oracle, rendered,
        "CLI and rendered IPv6 outcomes must agree"
    );
    match oracle {
        Ipv6FixtureOutcome::Assigned(Tcp6Boundary::Connected) => evidence.positive(shape),
        Ipv6FixtureOutcome::Assigned(Tcp6Boundary::Refused) => {
            evidence.expected_negative(shape, "nested_default_bridge_ipv6_unavailable");
        }
        Ipv6FixtureOutcome::RuntimeBindingAbsent => {
            evidence.expected_negative(shape, "nested_default_bridge_ipv6_runtime_binding_absent");
        }
    }
}

#[test]
fn ipv6_fixture_outcome_requires_agreement() {
    let mut evidence = ProbeEvidence::default();
    record_ipv6_fixture_outcomes(
        &mut evidence,
        "FixedIpv6HostPort",
        Ipv6FixtureOutcome::Assigned(Tcp6Boundary::Refused),
        Ipv6FixtureOutcome::Assigned(Tcp6Boundary::Refused),
    );
    assert!(evidence.expected_negative.contains(&(
        "FixedIpv6HostPort",
        "nested_default_bridge_ipv6_unavailable"
    )));
    let mut absent = ProbeEvidence::default();
    record_ipv6_fixture_outcomes(
        &mut absent,
        "EphemeralIpv6HostPort",
        Ipv6FixtureOutcome::RuntimeBindingAbsent,
        Ipv6FixtureOutcome::RuntimeBindingAbsent,
    );
    assert!(absent.expected_negative.contains(&(
        "EphemeralIpv6HostPort",
        "nested_default_bridge_ipv6_runtime_binding_absent"
    )));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            record_ipv6_fixture_outcomes(
                &mut evidence,
                "EphemeralIpv6HostPort",
                Ipv6FixtureOutcome::RuntimeBindingAbsent,
                Ipv6FixtureOutcome::Assigned(Tcp6Boundary::Refused),
            );
        }))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            record_ipv6_fixture_outcomes(
                &mut evidence,
                "EphemeralIpv6HostPort",
                Ipv6FixtureOutcome::Assigned(Tcp6Boundary::Connected),
                Ipv6FixtureOutcome::Assigned(Tcp6Boundary::Refused),
            );
        }))
        .is_err()
    );
}

// Only fixed, test-authored stage names cross the native output boundary.
fn mark_port_stage(suffix: &str, phase: &'static str) {
    let group = match suffix {
        "port-oracle" => "fixed_ipv4_oracle",
        "port-rendered" => "fixed_ipv4_rendered",
        "ipv6-oracle" => "fixed_ipv6_oracle",
        "ipv6-rendered" => "fixed_ipv6_rendered",
        "ipv6-dynamic-oracle" => "dynamic_ipv6_oracle",
        "ipv6-dynamic-rendered" => "dynamic_ipv6_rendered",
        "multi-dynamic-oracle" => "repeated_dynamic_ipv4_oracle",
        "multi-dynamic-rendered" => "repeated_dynamic_ipv4_rendered",
        _ => return,
    };
    assert!(matches!(
        phase,
        "cli_create"
            | "cli_inspect"
            | "oracle_bindings"
            | "oracle_cleanup"
            | "oracle_start"
            | "cli_http"
            | "cli_http_secondary"
            | "local_service"
            | "http_assert"
            | "http_assert_secondary"
            | "render"
            | "render_body"
            | "api_create"
            | "api_inspect"
            | "rendered_bindings"
            | "api_start"
            | "dynamic_binding"
            | "dynamic_binding_secondary"
            | "isolated_http"
            | "isolated_assert"
            | "udp_assignment"
            | "udp_send"
            | "udp_receive"
            | "udp_assert"
            | "tcp6_boundary"
            | "negative_recheck"
            | "runtime_absence"
    ));
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_port_{group}_{phase}");
}

fn assert_local_service(run: &NativeRun, id: &str, port: u16, expected: &str, suffix: &str) {
    mark_port_stage(suffix, "local_service");
    let url = format!("http://127.0.0.1:{port}/index.html");
    let body = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "for attempt in 1 2 3 4 5; do if body=$(wget -qO- -T 2 \"$1\"); then printf '%s' \"$body\"; exit 0; fi; [ \"$attempt\" = 5 ] || sleep 1; done; exit 1".into(),
        "service-probe".into(),
        url,
    ]);
    assert_eq!(body, expected);
}

fn assert_fixed_ipv4_http(run: &NativeRun, id: &str, suffix: &str, secondary: bool) {
    let (url, request_stage, assertion_stage) = if secondary {
        (
            "http://127.0.0.2:18111/index.html",
            "cli_http_secondary",
            "http_assert_secondary",
        )
    } else {
        (
            "http://127.0.0.1:18110/index.html",
            "cli_http",
            "http_assert",
        )
    };
    assert_local_service(run, id, 8080, "native-tcp-canary", suffix);
    mark_port_stage(suffix, request_stage);
    run.assert_published_http(url, "native-tcp-canary", None);
    mark_port_stage(suffix, assertion_stage);
}

fn probe_ports(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_ports");
    run.require_outer_identity();
    run.require_outer_curl();
    run.require_outer_bash();
    let script = "printf native-tcp-canary >/tmp/index.html; httpd -f -p 8080 -h /tmp & nc -u -l -p 8081 > /tmp/udp-received & wait";
    mark_port_stage("port-oracle", "cli_create");
    let oracle = run.cli_create(
        "port-oracle",
        &[
            "--publish=127.0.0.1:18110:8080/tcp".to_owned(),
            "--publish=127.0.0.2:18111:8080/tcp".to_owned(),
            "--publish=127.0.0.1::8081/udp".to_owned(),
            "--expose=8082/tcp".to_owned(),
        ],
        &["sh", "-c", script],
    );
    mark_port_stage("port-oracle", "oracle_bindings");
    assert_port_binding(&oracle, "8080/tcp", "127.0.0.1", "18110");
    assert_port_binding(&oracle, "8080/tcp", "127.0.0.2", "18111");
    assert_eq!(oracle["Config"]["ExposedPorts"]["8082/tcp"], json!({}));
    assert!(
        oracle["HostConfig"]["PortBindings"]
            .get("8082/tcp")
            .is_none()
    );
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    mark_port_stage("port-oracle", "oracle_start");
    start_container(run, &oracle_id);
    assert_fixed_ipv4_http(run, &oracle_id, "port-oracle", false);
    assert_fixed_ipv4_http(run, &oracle_id, "port-oracle", true);
    mark_port_stage("port-oracle", "oracle_cleanup");
    run.delete(&oracle_id);

    let mut container = bare_container(&run.image);
    container.command = ImageCommand::Exec(vec![argument("sh"), argument("-c"), argument(script)]);
    container.ports = vec![
        PortPublication::published(
            NonZeroU16::new(8080).unwrap(),
            Protocol::Tcp,
            vec![
                HostBinding {
                    host_ip: PortHostIp::Address("127.0.0.1".parse().unwrap()),
                    host_port: PortHostPort::Fixed(NonZeroU16::new(18110).unwrap()),
                },
                HostBinding {
                    host_ip: PortHostIp::Address("127.0.0.2".parse().unwrap()),
                    host_port: PortHostPort::Fixed(NonZeroU16::new(18111).unwrap()),
                },
            ],
        )
        .unwrap(),
        PortPublication::published(
            NonZeroU16::new(8081).unwrap(),
            Protocol::Udp,
            vec![HostBinding {
                host_ip: PortHostIp::Address("127.0.0.1".parse().unwrap()),
                host_port: PortHostPort::Ephemeral,
            }],
        )
        .unwrap(),
        PortPublication::exposed(NonZeroU16::new(8082).unwrap(), Protocol::Tcp),
    ];
    let expected_body = json!({
        "Image":run.image, "Cmd":["sh","-c",script],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "ExposedPorts":{"8080/tcp":{},"8081/udp":{},"8082/tcp":{}},
        "HostConfig":{"PortBindings":{
            "8080/tcp":[
                {"HostIp":"127.0.0.1","HostPort":"18110"},
                {"HostIp":"127.0.0.2","HostPort":"18111"}
            ],
            "8081/udp":[{"HostIp":"127.0.0.1","HostPort":""}]
        }}
    });
    let (id, body, inspected) = run.rendered_create(
        "port-rendered",
        container,
        &[
            Capability::Command,
            Capability::PortPublish,
            Capability::PortHostIpv4,
            Capability::PortMultipleBindings,
            Capability::PortEphemeral,
            Capability::PortExposeOnly,
        ],
        expected_body,
    );
    mark_port_stage("port-rendered", "rendered_bindings");
    assert_eq!(body["ExposedPorts"]["8082/tcp"], json!({}));
    assert_eq!(
        body["HostConfig"]["PortBindings"]["8080/tcp"],
        json!([
            {"HostIp":"127.0.0.1","HostPort":"18110"},
            {"HostIp":"127.0.0.2","HostPort":"18111"}
        ])
    );
    assert_eq!(
        body["HostConfig"]["PortBindings"]["8081/udp"],
        json!([
            {"HostIp":"127.0.0.1","HostPort":""}
        ])
    );
    assert_port_binding(&inspected, "8080/tcp", "127.0.0.1", "18110");
    assert_port_binding(&inspected, "8080/tcp", "127.0.0.2", "18111");
    assert_eq!(inspected["Config"]["ExposedPorts"]["8082/tcp"], json!({}));
    assert!(
        inspected["HostConfig"]["PortBindings"]
            .get("8082/tcp")
            .is_none()
    );
    mark_port_stage("port-rendered", "api_start");
    let (status, _) = run.api(
        "POST",
        &format!("/v{}/containers/{id}/start", run.api_version),
        None,
    );
    assert_native_api_status(status, 204);
    assert_fixed_ipv4_http(run, &id, "port-rendered", false);
    assert_fixed_ipv4_http(run, &id, "port-rendered", true);
    mark_port_stage("port-rendered", "isolated_http");
    let isolated = run.namespace_probe("tcp_refusal", None);
    let isolation_result = match isolated.stdout.as_slice() {
        b"refused\n" => "refused",
        b"connected\n" => "connected",
        b"timeout\n" => "timeout",
        _ => "other",
    };
    if !isolated.status.success() || isolation_result != "refused" {
        eprintln!("DOCKERLENS_NATIVE_ISOLATION_DIAG: result={isolation_result}");
    }
    mark_port_stage("port-rendered", "isolated_assert");
    assert!(
        isolated.status.success() && isolation_result == "refused",
        "127.0.0.1 publication must not widen to 127.0.0.2"
    );
    mark_port_stage("port-rendered", "udp_assignment");
    let assigned = run.inspect(&id)["NetworkSettings"]["Ports"]["8081/udp"][0]["HostPort"]
        .as_str()
        .expect("runtime-assigned ephemeral UDP port")
        .to_owned();
    let assigned: u16 = assigned.parse().expect("numeric dynamic UDP port");
    assert!(assigned > 0);
    mark_port_stage("port-rendered", "udp_send");
    let assigned = assigned.to_string();
    let sent = run.namespace_probe("udp", Some(&assigned));
    if !sent.status.success() {
        eprintln!(
            "DOCKERLENS_NATIVE_CLI_DIAG: exit={} stderr={}",
            cli_failure_exit(sent.status),
            cli_failure_stderr(&sent.stderr)
        );
    }
    assert!(sent.status.success(), "outer namespace UDP send failed");
    mark_port_stage("port-rendered", "udp_receive");
    let mut received = String::new();
    for _ in 0..10 {
        received = run.cli(&[
            "exec".into(),
            id.clone(),
            "sh".into(),
            "-c".into(),
            "cat /tmp/udp-received 2>/dev/null || true".into(),
        ]);
        if received == "native-udp-canary" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    mark_port_stage("port-rendered", "udp_assert");
    assert_eq!(received, "native-udp-canary");
    record_many(
        evidence,
        &[
            "ExposedOnlyPort",
            "FixedIpv4HostPort",
            "EphemeralIpv4HostPort",
            "MultipleFixedPortBindings",
            "EphemeralHostPort",
        ],
    );

    eprintln!("DOCKERLENS_NATIVE_CHECK: container_ports_ipv6");
    let ipv6_script = "printf native-ipv6-canary >/tmp/index.html; httpd -f -p 8083 -h /tmp";
    let mut oracle_options = vec!["--publish=[::1]:18112:8083/tcp".to_owned()];
    if run.debian_default_bridge_boundary() {
        oracle_options.push("--publish=127.0.0.1:18113:8083/tcp".to_owned());
    }
    mark_port_stage("ipv6-oracle", "cli_create");
    let oracle = run.cli_create("ipv6-oracle", &oracle_options, &["sh", "-c", ipv6_script]);
    mark_port_stage("ipv6-oracle", "oracle_bindings");
    assert_configured_binding_count(&oracle, "8083/tcp", oracle_options.len());
    assert_port_binding(&oracle, "8083/tcp", "::1", "18112");
    if run.debian_default_bridge_boundary() {
        assert_port_binding(&oracle, "8083/tcp", "127.0.0.1", "18113");
    }
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    mark_port_stage("ipv6-oracle", "oracle_start");
    start_container(run, &oracle_id);
    let oracle_outcome = if run.debian_default_bridge_boundary() {
        Some(assert_debian_ipv6_fixture(
            run,
            &oracle_id,
            "8083/tcp",
            "native-ipv6-canary",
            "ipv6-oracle",
            Some(18112),
        ))
    } else {
        assert_ipv6_traffic(run, &oracle_id, "ipv6-oracle");
        None
    };
    mark_port_stage("ipv6-oracle", "oracle_cleanup");
    run.delete(&oracle_id);
    let mut container = bare_container(&run.image);
    container.command =
        ImageCommand::Exec(vec![argument("sh"), argument("-c"), argument(ipv6_script)]);
    let mut host_bindings = vec![HostBinding {
        host_ip: PortHostIp::Address("::1".parse().unwrap()),
        host_port: PortHostPort::Fixed(NonZeroU16::new(18112).unwrap()),
    }];
    let mut expected_bindings = vec![json!({"HostIp":"::1","HostPort":"18112"})];
    if run.debian_default_bridge_boundary() {
        host_bindings.push(HostBinding {
            host_ip: PortHostIp::Address("127.0.0.1".parse().unwrap()),
            host_port: PortHostPort::Fixed(NonZeroU16::new(18113).unwrap()),
        });
        expected_bindings.push(json!({"HostIp":"127.0.0.1","HostPort":"18113"}));
    }
    container.ports = vec![
        PortPublication::published(NonZeroU16::new(8083).unwrap(), Protocol::Tcp, host_bindings)
            .unwrap(),
    ];
    let expected_body = json!({
        "Image":run.image, "Cmd":["sh","-c",ipv6_script],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "ExposedPorts":{"8083/tcp":{}},
        "HostConfig":{"PortBindings":{"8083/tcp":expected_bindings}}
    });
    let mut required_capabilities = vec![
        Capability::Command,
        Capability::PortPublish,
        Capability::PortHostIpv6,
    ];
    if run.debian_default_bridge_boundary() {
        required_capabilities.extend([Capability::PortHostIpv4, Capability::PortMultipleBindings]);
    }
    let (id, body, inspected) = run.rendered_create(
        "ipv6-rendered",
        container,
        &required_capabilities,
        expected_body,
    );
    mark_port_stage("ipv6-rendered", "rendered_bindings");
    assert_configured_binding_count(&body, "8083/tcp", oracle_options.len());
    assert_configured_binding_count(&inspected, "8083/tcp", oracle_options.len());
    assert_port_binding(&inspected, "8083/tcp", "::1", "18112");
    if run.debian_default_bridge_boundary() {
        assert_port_binding(&inspected, "8083/tcp", "127.0.0.1", "18113");
    }
    mark_port_stage("ipv6-rendered", "api_start");
    let (status, _) = run.api(
        "POST",
        &format!("/v{}/containers/{id}/start", run.api_version),
        None,
    );
    assert_native_api_status(status, 204);
    if let Some(oracle_outcome) = oracle_outcome {
        let rendered_outcome = assert_debian_ipv6_fixture(
            run,
            &id,
            "8083/tcp",
            "native-ipv6-canary",
            "ipv6-rendered",
            Some(18112),
        );
        record_ipv6_fixture_outcomes(
            evidence,
            "FixedIpv6HostPort",
            oracle_outcome,
            rendered_outcome,
        );
    } else {
        assert_ipv6_traffic(run, &id, "ipv6-rendered");
        evidence.positive("FixedIpv6HostPort");
    }
}

fn assert_ipv6_traffic(run: &NativeRun, id: &str, suffix: &str) {
    mark_port_stage(suffix, "local_service");
    let local_body = run.cli(&[
        "exec".into(), id.into(), "sh".into(), "-c".into(),
        "for attempt in 1 2 3 4 5; do for url in http://127.0.0.1:8083/index.html http://[::1]:8083/index.html; do if body=$(wget -qO- -T 2 \"$url\"); then printf '%s' \"$body\"; exit 0; fi; done; [ \"$attempt\" = 5 ] || sleep 1; done; exit 1".into(),
    ]);
    assert_eq!(local_body, "native-ipv6-canary");
    let local_ipv6 = run.cli(&[
        "exec".into(), id.into(), "sh".into(), "-c".into(),
        "if wget -qO- -T 2 http://[::1]:8083/index.html >/dev/null 2>&1; then printf pass; else printf fail; fi".into(),
    ]) == "pass";
    mark_port_stage(suffix, "cli_http");
    run.assert_published_http(
        "http://[::1]:18112/index.html",
        "native-ipv6-canary",
        Some((id, local_ipv6)),
    );
    mark_port_stage(suffix, "http_assert");
}

fn assert_dynamic_http(run: &NativeRun, id: &str, key: &str, host_ip: &str, suffix: &str) {
    let secondary = host_ip == "127.0.0.2";
    mark_port_stage(
        suffix,
        if secondary {
            "dynamic_binding_secondary"
        } else {
            "dynamic_binding"
        },
    );
    let inspected = run.inspect(id);
    let binding = inspected["NetworkSettings"]["Ports"][key]
        .as_array()
        .unwrap()
        .iter()
        .find(|binding| binding["HostIp"] == host_ip)
        .expect("exact dynamic host address binding");
    let port: u16 = binding["HostPort"].as_str().unwrap().parse().unwrap();
    assert!(port > 0, "Engine allocates a nonzero host port");
    let address = if host_ip.contains(':') {
        format!("[{host_ip}]")
    } else {
        host_ip.to_owned()
    };
    let container_port: u16 = key
        .split_once('/')
        .expect("closed TCP port key")
        .0
        .parse()
        .expect("numeric container TCP port");
    assert_local_service(run, id, container_port, "native-dynamic-canary", suffix);
    mark_port_stage(
        suffix,
        if secondary {
            "cli_http_secondary"
        } else {
            "cli_http"
        },
    );
    run.assert_published_http(
        &format!("http://{address}:{port}/index.html"),
        "native-dynamic-canary",
        None,
    );
    mark_port_stage(
        suffix,
        if secondary {
            "http_assert_secondary"
        } else {
            "http_assert"
        },
    );
}

fn probe_complementary_ports(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_ports_ipv6");
    let ipv6_script = "printf native-dynamic-canary >/tmp/index.html; httpd -f -p 8084 -h /tmp";
    let mut oracle_options = vec!["--publish=[::1]::8084/tcp".to_owned()];
    if run.debian_default_bridge_boundary() {
        oracle_options.push("--publish=127.0.0.1::8084/tcp".to_owned());
    }
    mark_port_stage("ipv6-dynamic-oracle", "cli_create");
    let ipv6_oracle = run.cli_create(
        "ipv6-dynamic-oracle",
        &oracle_options,
        &["sh", "-c", ipv6_script],
    );
    mark_port_stage("ipv6-dynamic-oracle", "oracle_bindings");
    assert_configured_binding_count(&ipv6_oracle, "8084/tcp", oracle_options.len());
    assert_port_binding(&ipv6_oracle, "8084/tcp", "::1", "");
    if run.debian_default_bridge_boundary() {
        assert_port_binding(&ipv6_oracle, "8084/tcp", "127.0.0.1", "");
    }
    let ipv6_oracle_id = ipv6_oracle["Id"].as_str().unwrap().to_owned();
    mark_port_stage("ipv6-dynamic-oracle", "oracle_start");
    start_container(run, &ipv6_oracle_id);
    let oracle_outcome = if run.debian_default_bridge_boundary() {
        Some(assert_debian_ipv6_fixture(
            run,
            &ipv6_oracle_id,
            "8084/tcp",
            "native-dynamic-canary",
            "ipv6-dynamic-oracle",
            None,
        ))
    } else {
        assert_dynamic_http(
            run,
            &ipv6_oracle_id,
            "8084/tcp",
            "::1",
            "ipv6-dynamic-oracle",
        );
        None
    };
    let mut container = bare_container(&run.image);
    container.command =
        ImageCommand::Exec(vec![argument("sh"), argument("-c"), argument(ipv6_script)]);
    let mut host_bindings = vec![HostBinding {
        host_ip: PortHostIp::Address("::1".parse().unwrap()),
        host_port: PortHostPort::Ephemeral,
    }];
    let mut expected_bindings = vec![json!({"HostIp":"::1","HostPort":""})];
    if run.debian_default_bridge_boundary() {
        host_bindings.push(HostBinding {
            host_ip: PortHostIp::Address("127.0.0.1".parse().unwrap()),
            host_port: PortHostPort::Ephemeral,
        });
        expected_bindings.push(json!({"HostIp":"127.0.0.1","HostPort":""}));
    }
    container.ports = vec![
        PortPublication::published(NonZeroU16::new(8084).unwrap(), Protocol::Tcp, host_bindings)
            .unwrap(),
    ];
    let expected = json!({
        "Image":run.image,"Cmd":["sh","-c",ipv6_script],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "ExposedPorts":{"8084/tcp":{}},
        "HostConfig":{"PortBindings":{"8084/tcp":expected_bindings}}
    });
    let mut required_capabilities = vec![
        Capability::Command,
        Capability::PortPublish,
        Capability::PortHostIpv6,
        Capability::PortEphemeral,
    ];
    if run.debian_default_bridge_boundary() {
        required_capabilities.extend([Capability::PortHostIpv4, Capability::PortMultipleBindings]);
    }
    let (id, body, inspected) = run.rendered_create(
        "ipv6-dynamic-rendered",
        container,
        &required_capabilities,
        expected,
    );
    mark_port_stage("ipv6-dynamic-rendered", "rendered_bindings");
    assert_configured_binding_count(&body, "8084/tcp", oracle_options.len());
    assert_configured_binding_count(&inspected, "8084/tcp", oracle_options.len());
    assert_port_binding(&inspected, "8084/tcp", "::1", "");
    if run.debian_default_bridge_boundary() {
        assert_port_binding(&inspected, "8084/tcp", "127.0.0.1", "");
    }
    mark_port_stage("ipv6-dynamic-rendered", "api_start");
    start_container(run, &id);
    if let Some(oracle_outcome) = oracle_outcome {
        let rendered_outcome = assert_debian_ipv6_fixture(
            run,
            &id,
            "8084/tcp",
            "native-dynamic-canary",
            "ipv6-dynamic-rendered",
            None,
        );
        record_ipv6_fixture_outcomes(
            evidence,
            "EphemeralIpv6HostPort",
            oracle_outcome,
            rendered_outcome,
        );
    } else {
        assert_dynamic_http(run, &id, "8084/tcp", "::1", "ipv6-dynamic-rendered");
        evidence.positive("EphemeralIpv6HostPort");
    }

    eprintln!("DOCKERLENS_NATIVE_CHECK: container_ports");
    let multiple_script = "printf native-dynamic-canary >/tmp/index.html; httpd -f -p 8085 -h /tmp";
    mark_port_stage("multi-dynamic-oracle", "cli_create");
    let multiple_oracle = run.cli_create(
        "multi-dynamic-oracle",
        &[
            "--publish=127.0.0.1::8085/tcp".into(),
            "--publish=127.0.0.2::8085/tcp".into(),
        ],
        &["sh", "-c", multiple_script],
    );
    mark_port_stage("multi-dynamic-oracle", "oracle_bindings");
    for ip in ["127.0.0.1", "127.0.0.2"] {
        assert_port_binding(&multiple_oracle, "8085/tcp", ip, "");
    }
    let multiple_oracle_id = multiple_oracle["Id"].as_str().unwrap().to_owned();
    mark_port_stage("multi-dynamic-oracle", "oracle_start");
    start_container(run, &multiple_oracle_id);
    for ip in ["127.0.0.1", "127.0.0.2"] {
        assert_dynamic_http(
            run,
            &multiple_oracle_id,
            "8085/tcp",
            ip,
            "multi-dynamic-oracle",
        );
    }
    let mut container = bare_container(&run.image);
    container.command = ImageCommand::Exec(vec![
        argument("sh"),
        argument("-c"),
        argument(multiple_script),
    ]);
    container.ports = vec![
        PortPublication::published(
            NonZeroU16::new(8085).unwrap(),
            Protocol::Tcp,
            ["127.0.0.1", "127.0.0.2"]
                .into_iter()
                .map(|ip| HostBinding {
                    host_ip: PortHostIp::Address(ip.parse().unwrap()),
                    host_port: PortHostPort::Ephemeral,
                })
                .collect(),
        )
        .unwrap(),
    ];
    let expected = json!({
        "Image":run.image,"Cmd":["sh","-c",multiple_script],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "ExposedPorts":{"8085/tcp":{}},
        "HostConfig":{"PortBindings":{"8085/tcp":[
            {"HostIp":"127.0.0.1","HostPort":""},
            {"HostIp":"127.0.0.2","HostPort":""}
        ]}}
    });
    let (id, body, inspected) = run.rendered_create(
        "multi-dynamic-rendered",
        container,
        &[
            Capability::Command,
            Capability::PortPublish,
            Capability::PortHostIpv4,
            Capability::PortMultipleBindings,
            Capability::PortEphemeral,
        ],
        expected,
    );
    mark_port_stage("multi-dynamic-rendered", "rendered_bindings");
    assert_eq!(
        body["HostConfig"]["PortBindings"],
        multiple_oracle["HostConfig"]["PortBindings"]
    );
    assert_eq!(
        inspected["HostConfig"]["PortBindings"],
        multiple_oracle["HostConfig"]["PortBindings"]
    );
    mark_port_stage("multi-dynamic-rendered", "api_start");
    start_container(run, &id);
    for ip in ["127.0.0.1", "127.0.0.2"] {
        assert_dynamic_http(run, &id, "8085/tcp", ip, "multi-dynamic-rendered");
    }
    evidence.positive("MultipleEphemeralPortBindings");
}

fn assert_identity_health_effects(run: &NativeRun, id: &str) {
    start_container(run, id);
    let uid = run.cli(&["exec".into(), id.into(), "id".into(), "-u".into()]);
    assert_eq!(uid.trim(), "1000");
    let hostname = run.cli(&["exec".into(), id.into(), "hostname".into()]);
    assert_eq!(hostname.trim(), "container-probe");
    let workdir = run.cli(&["exec".into(), id.into(), "pwd".into()]);
    assert_eq!(workdir.trim(), "/tmp");
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(
        run.inspect(id)["State"]["Health"]["Status"],
        "starting",
        "failed checks must remain in the authored start grace period"
    );
    assert_eq!(
        run.inspect(id)["State"]["Health"]["FailingStreak"],
        0,
        "grace-period failures must not consume retries"
    );
    run.cli(&[
        "exec".into(),
        id.into(),
        "touch".into(),
        "/tmp/ready".into(),
    ]);
    for _ in 0..10 {
        if run.inspect(id)["State"]["Health"]["Status"] == "healthy" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert_eq!(run.inspect(id)["State"]["Health"]["Status"], "healthy");
}

fn probe_identity_and_health(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_identity_health");
    let oracle = run.cli_create(
        "identity-oracle",
        &[
            "--label=io.dockerlens.probe=identity".into(),
            "--user=1000:1000".into(),
            "--workdir=/tmp".into(),
            "--hostname=container-probe".into(),
            "--health-cmd=test -f /tmp/ready".into(),
            "--health-interval=1s".into(),
            "--health-timeout=1s".into(),
            "--health-retries=2".into(),
            "--health-start-period=20s".into(),
        ],
        &["sh", "-c", "sleep 120"],
    );
    assert_eq!(
        oracle["Config"]["Labels"]["io.dockerlens.probe"],
        "identity"
    );
    assert_eq!(oracle["Config"]["User"], "1000:1000");
    assert_eq!(oracle["Config"]["WorkingDir"], "/tmp");
    assert_eq!(oracle["Config"]["Hostname"], "container-probe");
    assert_eq!(
        oracle["Config"]["Healthcheck"]["Test"],
        json!(["CMD-SHELL", "test -f /tmp/ready"])
    );
    assert_eq!(
        oracle["Config"]["Healthcheck"]["StartPeriod"],
        20_000_000_000_i64
    );
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    assert_identity_health_effects(run, &oracle_id);

    let mut container = bare_container(&run.image);
    container
        .settings
        .labels
        .push(ContainerLabel::new(b"io.dockerlens.probe".to_vec(), b"identity".to_vec()).unwrap());
    container.settings.user = Some(ContainerUser::new(b"1000:1000".to_vec()).unwrap());
    container.settings.working_dir = Some(WorkingDirectory::new(b"/tmp".to_vec()).unwrap());
    container.settings.hostname =
        Some(ContainerHostname::new(b"container-probe".to_vec()).unwrap());
    container.healthcheck = Some(
        Healthcheck::configured(
            HealthTest::Shell(argument("test -f /tmp/ready")),
            NonZeroU64::new(1_000_000_000),
            NonZeroU64::new(1_000_000_000),
            NonZeroU32::new(2),
        )
        .unwrap()
        .with_start_period(20_000_000_000)
        .unwrap(),
    );
    let expected_body = json!({
        "Image":run.image, "Cmd":["sh","-c","sleep 120"],
        "Labels":{"io.dockerlens.native-run":run.run_id,"io.dockerlens.probe":"identity"},
        "User":"1000:1000", "WorkingDir":"/tmp", "Hostname":"container-probe",
        "Healthcheck":{
            "Test":["CMD-SHELL","test -f /tmp/ready"], "Interval":1_000_000_000_i64,
            "Timeout":1_000_000_000_i64, "Retries":2,
            "StartPeriod":20_000_000_000_i64
        },
        "HostConfig":{}
    });
    let (id, body, inspected) = run.rendered_create(
        "identity-rendered",
        container,
        &[
            Capability::Command,
            Capability::ContainerUser,
            Capability::ContainerWorkdir,
            Capability::ContainerHostname,
            Capability::HealthShell,
            Capability::HealthStartPeriod,
        ],
        expected_body,
    );
    assert_eq!(body["User"], "1000:1000");
    assert_eq!(body["WorkingDir"], "/tmp");
    assert_eq!(body["Hostname"], "container-probe");
    assert_eq!(
        body["Healthcheck"]["Test"],
        json!(["CMD-SHELL", "test -f /tmp/ready"])
    );
    assert_eq!(body["Healthcheck"]["StartPeriod"], 20_000_000_000_i64);
    for key in ["User", "WorkingDir", "Hostname"] {
        assert_eq!(inspected["Config"][key], oracle["Config"][key]);
    }
    assert_eq!(
        inspected["Config"]["Healthcheck"]["Test"],
        oracle["Config"]["Healthcheck"]["Test"]
    );
    assert_eq!(
        inspected["Config"]["Healthcheck"]["StartPeriod"],
        oracle["Config"]["Healthcheck"]["StartPeriod"]
    );
    assert_identity_health_effects(run, &id);
    record_many(
        evidence,
        &[
            "ContainerCreateLabels",
            "ContainerUser",
            "ContainerWorkdir",
            "ContainerHostname",
            "ShellHealthcheck",
            "HealthStartPeriodPositive",
        ],
    );

    eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled");
    let health_image = run.image_with_failing_health();
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_inherited_create");
    let inherited = run.cli_create_image(
        "health-inherited-oracle",
        &[],
        &health_image,
        &["sh", "-c", "sleep 120"],
    );
    let inherited_id = inherited["Id"].as_str().unwrap().to_owned();
    assert_eq!(
        inherited["Config"]["Healthcheck"]["Test"],
        json!(["CMD-SHELL", "/bin/false"])
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_inherited_start");
    start_container(run, &inherited_id);
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_inherited_wait");
    for _ in 0..10 {
        if run.inspect(&inherited_id)["State"]["Health"]["Status"] == "unhealthy" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert_eq!(
        run.inspect(&inherited_id)["State"]["Health"]["Status"],
        "unhealthy"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_oracle_create");
    let oracle = run.cli_create_image(
        "disabled-oracle",
        &["--no-healthcheck".into()],
        &health_image,
        &["sh", "-c", "sleep 120"],
    );
    assert_eq!(oracle["Config"]["Healthcheck"]["Test"], json!(["NONE"]));
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_oracle_start");
    start_container(run, &oracle_id);
    assert!(run.inspect(&oracle_id)["State"]["Health"].is_null());
    let mut container = bare_container(&health_image);
    container.healthcheck =
        Some(Healthcheck::configured(HealthTest::Disabled, None, None, None).unwrap());
    let expected_body = json!({
        "Image":health_image, "Cmd":["sh","-c","sleep 120"],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "Healthcheck":{"Test":["NONE"]}, "HostConfig":{}
    });
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_rendered_create");
    let (id, body, inspected) = run.rendered_create(
        "disabled-rendered",
        container,
        &[Capability::Command, Capability::HealthDisabled],
        expected_body,
    );
    assert_eq!(body["Healthcheck"]["Test"], json!(["NONE"]));
    assert_eq!(
        inspected["Config"]["Healthcheck"]["Test"],
        oracle["Config"]["Healthcheck"]["Test"]
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_rendered_start");
    start_container(run, &id);
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_rendered_wait");
    assert!(run.inspect(&id)["State"]["Health"].is_null());
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(run.inspect(&id)["State"]["Health"].is_null());
    evidence.positive("DisabledHealthcheck");
}

fn probe_health_start_period_zero(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_start_interval");
    let health = json!({
        "Test":["CMD", "/bin/true"],
        "Interval":1_000_000_000_i64,
        "Timeout":1_000_000_000_i64,
        "Retries":2,
        "StartPeriod":0,
    });
    let oracle = run.cli_create(
        "period-zero-oracle",
        &[
            "--health-cmd=/bin/true".into(),
            "--health-interval=1s".into(),
            "--health-timeout=1s".into(),
            "--health-retries=2".into(),
            "--health-start-period=0s".into(),
        ],
        &["sh", "-c", "sleep 120"],
    );
    let (literal_id, literal) = run.literal_create(
        "period-zero-literal",
        json!({"Image":run.image,"Cmd":["sh","-c","sleep 120"],"Healthcheck":health}),
    );
    let mut container = bare_container(&run.image);
    container.healthcheck = Some(
        Healthcheck::configured(
            HealthTest::Exec(vec![argument("/bin/true")]),
            NonZeroU64::new(1_000_000_000),
            NonZeroU64::new(1_000_000_000),
            NonZeroU32::new(2),
        )
        .unwrap()
        .with_start_period(0)
        .unwrap(),
    );
    let expected_body = json!({
        "Image":run.image,"Cmd":["sh","-c","sleep 120"],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "Healthcheck":health,"HostConfig":{}
    });
    let (rendered_id, body, rendered) = run.rendered_create(
        "period-zero-rendered",
        container,
        &[
            Capability::Command,
            Capability::Healthcheck,
            Capability::HealthStartPeriod,
        ],
        expected_body,
    );
    assert_eq!(body["Healthcheck"]["StartPeriod"], 0);
    let oracle_health = &oracle["Config"]["Healthcheck"];
    for inspected in [&literal, &rendered] {
        assert_eq!(
            inspected["Config"]["Healthcheck"]["StartPeriod"],
            oracle_health["StartPeriod"]
        );
        assert_eq!(
            inspected["Config"]["Healthcheck"]["Test"],
            json!(["CMD", "/bin/true"])
        );
    }
    for id in [literal_id, rendered_id] {
        start_container(run, &id);
        for _ in 0..5 {
            if run.inspect(&id)["State"]["Health"]["Status"] == "healthy" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        assert_eq!(run.inspect(&id)["State"]["Health"]["Status"], "healthy");
    }
    evidence.positive("HealthStartPeriodZero");
}

fn explicit_no_arg_shell(inspected: &Value) -> bool {
    let cmd_empty = match inspected["Config"].get("Cmd") {
        Some(Value::Null) => true,
        Some(Value::Array(values)) => values.is_empty(),
        _ => false,
    };
    cmd_empty
        && inspected["Config"]["Entrypoint"] == json!(["/bin/sh"])
        && inspected["Path"] == "/bin/sh"
        && inspected["Args"] == json!([])
}

fn closed_clear_diagnostic(inspected: &Value, phase: &'static str) -> String {
    assert!(matches!(
        phase,
        "alone" | "override_omit" | "paired" | "rendered"
    ));
    let cmd = match inspected["Config"].get("Cmd") {
        None => "missing",
        Some(Value::Null) => "null",
        Some(Value::Array(values)) if values.is_empty() => "empty_array",
        Some(value) if *value == json!(["-c", "exit 7"]) => "image_default",
        Some(_) => "other",
    };
    let entrypoint = match inspected["Config"].get("Entrypoint") {
        None => "missing",
        Some(value) if *value == json!(["/bin/sh"]) => "shell",
        Some(_) => "other",
    };
    let path = match inspected.get("Path") {
        None => "missing",
        Some(Value::String(value)) if value == "/bin/sh" => "shell",
        Some(_) => "other",
    };
    let args = match inspected.get("Args") {
        None => "missing",
        Some(Value::Array(values)) if values.is_empty() => "empty",
        Some(value) if *value == json!(["-c", "exit 7"]) => "image_default",
        Some(_) => "other",
    };
    format!(
        "DOCKERLENS_NATIVE_CLEAR_DIAG: phase={phase} cmd={cmd} entrypoint={entrypoint} path={path} args={args}"
    )
}

fn mark_clear_stage(phase: &'static str) {
    assert!(matches!(
        phase,
        "baseline" | "cmd_alone" | "override_omit" | "paired_literal" | "rendered" | "entrypoint"
    ));
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_clear_{phase}");
}

#[test]
fn command_clear_requires_explicit_no_arg_runtime_and_closed_diagnostic() {
    for command in [json!([]), Value::Null] {
        let inspected = json!({
            "Config":{"Cmd":command,"Entrypoint":["/bin/sh"]},
            "Path":"/bin/sh","Args":[]
        });
        assert!(explicit_no_arg_shell(&inspected));
    }
    for inspected in [
        json!({"Config":{"Entrypoint":["/bin/sh"]},"Path":"/bin/sh","Args":[]}),
        json!({"Config":{"Cmd":[""],"Entrypoint":["/bin/sh"]},"Path":"/bin/sh","Args":[]}),
        json!({"Config":{"Cmd":[],"Entrypoint":["/bin/sh"]},"Path":"/bin/sh","Args":["private"]}),
        json!({"Config":{"Cmd":[],"Entrypoint":["/bin/sh"]},"Path":"private","Args":[]}),
    ] {
        assert!(!explicit_no_arg_shell(&inspected));
    }
    let private = json!({"Config":{"Cmd":["protected-secret"],"Entrypoint":["protected-secret"]},"Path":"protected-secret","Args":["protected-secret"]});
    let diagnostic = closed_clear_diagnostic(&private, "paired");
    assert_eq!(
        diagnostic,
        "DOCKERLENS_NATIVE_CLEAR_DIAG: phase=paired cmd=other entrypoint=other path=other args=other"
    );
    assert!(!diagnostic.contains("protected-secret"));
}

fn probe_clear_and_start_interval(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_clear");
    // Two separate task-owned derivatives make image inheritance observable.
    // CLI baselines prove the defaults; literal API requests are the oracle for
    // the empty arrays that the CLI cannot express without ambiguity.
    let command_image = run.image_with_defaults(
        "command-default",
        "[\"/bin/sh\"]",
        "[\"-c\",\"exit 7\"]",
        json!(["/bin/sh"]),
        json!(["-c", "exit 7"]),
    );
    mark_clear_stage("baseline");
    let default = run.cli_create_image("command-default-oracle", &[], &command_image, &[]);
    let default_id = default["Id"].as_str().unwrap().to_owned();
    assert_eq!(default["Config"]["Cmd"], json!(["-c", "exit 7"]));
    assert_eq!(start_and_wait(run, &default_id), 7);
    mark_clear_stage("cmd_alone");
    let (literal_id, literal) = run.literal_create(
        "clear-command-literal",
        json!({"Image":command_image,"Cmd":[]}),
    );
    eprintln!("{}", closed_clear_diagnostic(&literal, "alone"));
    assert_eq!(literal["Config"]["Cmd"], default["Config"]["Cmd"]);
    assert_eq!(
        literal["Config"]["Entrypoint"],
        default["Config"]["Entrypoint"]
    );
    assert_eq!(literal["Path"], "/bin/sh");
    assert_eq!(literal["Args"], json!(["-c", "exit 7"]));
    assert_eq!(start_and_wait(run, &literal_id), 7);
    mark_clear_stage("override_omit");
    let (omitted_id, omitted) = run.literal_create(
        "clear-command-override-omit",
        json!({"Image":command_image,"Entrypoint":["/bin/sh"]}),
    );
    eprintln!("{}", closed_clear_diagnostic(&omitted, "override_omit"));
    assert_eq!(omitted["Config"]["Entrypoint"], json!(["/bin/sh"]));
    if omitted["Config"]["Cmd"] == default["Config"]["Cmd"] {
        assert_eq!(omitted["Path"], "/bin/sh");
        assert_eq!(omitted["Args"], json!(["-c", "exit 7"]));
        assert_eq!(start_and_wait(run, &omitted_id), 7);
    } else {
        assert!(explicit_no_arg_shell(&omitted));
        assert_eq!(start_and_wait(run, &omitted_id), 0);
    }
    mark_clear_stage("paired_literal");
    let (paired_id, paired) = run.literal_create(
        "clear-command-paired-literal",
        json!({"Image":command_image,"Entrypoint":["/bin/sh"],"Cmd":[]}),
    );
    eprintln!("{}", closed_clear_diagnostic(&paired, "paired"));
    assert!(explicit_no_arg_shell(&paired));
    assert_eq!(start_and_wait(run, &paired_id), 0);
    let mut container = bare_container(&command_image);
    container.command = ImageCommand::Clear;
    container.entrypoint = ImageCommand::Exec(vec![argument("/bin/sh")]);
    let expected_body = json!({
        "Image":command_image, "Cmd":[], "Entrypoint":["/bin/sh"],
        "Labels":{"io.dockerlens.native-run":run.run_id}, "HostConfig":{}
    });
    mark_clear_stage("rendered");
    let (id, body, inspected) = run.rendered_create(
        "clear-command-rendered",
        container,
        &[Capability::CommandClear, Capability::Entrypoint],
        expected_body,
    );
    assert_eq!(body["Cmd"], json!([]));
    assert_eq!(body["Entrypoint"], json!(["/bin/sh"]));
    eprintln!("{}", closed_clear_diagnostic(&inspected, "rendered"));
    assert!(explicit_no_arg_shell(&inspected));
    assert_eq!(start_and_wait(run, &id), 0);
    evidence.positive("ClearCommand");

    mark_clear_stage("entrypoint");
    let entrypoint_image = run.image_with_defaults(
        "entrypoint-default",
        "[\"/bin/false\"]",
        "[\"/bin/true\"]",
        json!(["/bin/false"]),
        json!(["/bin/true"]),
    );
    let default = run.cli_create_image("entrypoint-default-oracle", &[], &entrypoint_image, &[]);
    let default_id = default["Id"].as_str().unwrap().to_owned();
    assert_eq!(default["Config"]["Entrypoint"], json!(["/bin/false"]));
    assert_eq!(start_and_wait(run, &default_id), 1);
    let (literal_id, literal) = run.literal_create(
        "clear-entrypoint-literal",
        json!({"Image":entrypoint_image,"Entrypoint":[]}),
    );
    assert_ne!(
        literal["Config"]["Entrypoint"],
        default["Config"]["Entrypoint"]
    );
    assert_eq!(literal["Config"]["Cmd"], default["Config"]["Cmd"]);
    assert_eq!(start_and_wait(run, &literal_id), 0);
    let mut container = bare_container(&entrypoint_image);
    container.command = ImageCommand::Inherit;
    container.entrypoint = ImageCommand::Clear;
    let expected_body = json!({
        "Image":entrypoint_image, "Entrypoint":[],
        "Labels":{"io.dockerlens.native-run":run.run_id}, "HostConfig":{}
    });
    let (id, body, inspected) = run.rendered_create(
        "clear-entrypoint-rendered",
        container,
        &[Capability::EntrypointClear],
        expected_body,
    );
    assert_eq!(body["Entrypoint"], json!([]));
    assert!(body.get("Cmd").is_none());
    assert_eq!(
        inspected["Config"]["Entrypoint"],
        literal["Config"]["Entrypoint"]
    );
    assert_eq!(inspected["Config"]["Cmd"], literal["Config"]["Cmd"]);
    assert_eq!(start_and_wait(run, &id), 0);
    evidence.positive("ClearEntrypoint");

    eprintln!("DOCKERLENS_NATIVE_CHECK: container_start_interval");
    let basic_health = json!({
        "Test":["CMD", "/bin/true"],
        "Interval":1_000_000_000_i64,
        "Timeout":1_000_000_000_i64,
        "Retries":2,
    });
    let mut extended_health = basic_health.clone();
    extended_health["StartInterval"] = json!(1_000_000_000_i64);
    let (_, baseline) = run.literal_create(
        "interval-baseline",
        json!({
            "Image":run.image,
            "Cmd":["sh","-c","sleep 30"],
            "Healthcheck":basic_health,
        }),
    );
    assert_eq!(
        baseline["Config"]["Healthcheck"]["Interval"],
        1_000_000_000_i64
    );
    let mut container = bare_container(&run.image);
    container.healthcheck = Some(
        Healthcheck::configured(
            HealthTest::Exec(vec![argument("/bin/true")]),
            NonZeroU64::new(1_000_000_000),
            NonZeroU64::new(1_000_000_000),
            NonZeroU32::new(2),
        )
        .unwrap()
        .with_start_interval(1_000_000_000)
        .unwrap(),
    );
    let body = run.render_only(
        "interval-rendered",
        container,
        &[
            Capability::Command,
            Capability::Healthcheck,
            Capability::HealthStartInterval,
        ],
    );
    assert_eq!(body["Healthcheck"], extended_health);
    assert_eq!(
        body,
        json!({
            "Image":run.image,
            "Cmd":["sh","-c","sleep 120"],
            "Healthcheck":extended_health,
            "Labels":{"io.dockerlens.native-run":run.run_id},
            "HostConfig":{}
        }),
        "closed StartInterval renderer body before native apply"
    );
    let literal_name = run.name("interval-literal");
    let literal_body = json!({
        "Image":run.image,
        "Cmd":["sh","-c","sleep 30"],
        "Healthcheck":extended_health,
        "Labels":{"io.dockerlens.native-run":run.run_id},
    });
    let literal_path = format!(
        "/v{}/containers/create?name={literal_name}",
        run.api_version
    );
    let (literal_status, literal_response) = run.api("POST", &literal_path, Some(&literal_body));
    let rendered_path = format!(
        "/v{}/containers/create?name={}",
        run.api_version,
        run.name("interval-rendered")
    );
    let (rendered_status, rendered_response) = run.api("POST", &rendered_path, Some(&body));
    assert_eq!(
        rendered_status, literal_status,
        "literal and rendered interval requests agree"
    );
    match run.api_version.as_str() {
        "1.41" => {
            if literal_status == 201 {
                let literal: Value = serde_json::from_slice(&literal_response).unwrap();
                let rendered: Value = serde_json::from_slice(&rendered_response).unwrap();
                let literal_id = literal["Id"].as_str().unwrap().to_owned();
                let rendered_id = rendered["Id"].as_str().unwrap().to_owned();
                run.created.push((literal_name, literal_id.clone()));
                run.created
                    .push((run.name("interval-rendered"), rendered_id.clone()));
                let baseline_interval = baseline["Config"]["Healthcheck"]
                    .as_object()
                    .unwrap()
                    .get("StartInterval");
                assert_ne!(baseline_interval, Some(&json!(1_000_000_000_i64)));
                let literal_inspected = run.inspect(&literal_id);
                let ignored = literal_inspected["Config"]["Healthcheck"]
                    .as_object()
                    .unwrap()
                    .get("StartInterval");
                assert_eq!(
                    ignored, baseline_interval,
                    "API 1.41 must ignore the field exactly as absent baseline"
                );
                let rendered_inspected = run.inspect(&rendered_id);
                assert_eq!(
                    rendered_inspected["Config"]["Healthcheck"]
                        .as_object()
                        .unwrap()
                        .get("StartInterval"),
                    baseline_interval,
                );
            } else {
                assert_eq!(literal_status, 400, "expected API 1.41 field rejection");
                let literal_error: Value = serde_json::from_slice(&literal_response)
                    .expect("structured private Engine rejection");
                let rendered_error: Value = serde_json::from_slice(&rendered_response)
                    .expect("structured private Engine rejection");
                for error in [&literal_error, &rendered_error] {
                    let message = error["message"]
                        .as_str()
                        .expect("Engine rejection must identify its field");
                    assert!(
                        message.to_ascii_lowercase().contains("startinterval"),
                        "only a StartInterval-specific rejection is expected"
                    );
                }
            }
            evidence.expected_negative("HealthStartIntervalPositive", "api_1_41_no_start_interval");
        }
        "1.56" => {
            assert_eq!(
                literal_status, 201,
                "upstream exact API accepts StartInterval"
            );
            let literal: Value = serde_json::from_slice(&literal_response).unwrap();
            let rendered: Value = serde_json::from_slice(&rendered_response).unwrap();
            let literal_id = literal["Id"].as_str().unwrap().to_owned();
            let rendered_id = rendered["Id"].as_str().unwrap().to_owned();
            run.created.push((literal_name, literal_id.clone()));
            run.created
                .push((run.name("interval-rendered"), rendered_id.clone()));
            assert_eq!(
                run.inspect(&literal_id)["Config"]["Healthcheck"]["StartInterval"],
                1_000_000_000_i64
            );
            assert_eq!(
                run.inspect(&rendered_id)["Config"]["Healthcheck"]["StartInterval"],
                1_000_000_000_i64
            );
            evidence.positive("HealthStartIntervalPositive");
        }
        _ => unreachable!("exact native API checked at test entry"),
    }

    // Zero is an explicit authored request even when its effective value is
    // indistinguishable from absence. The nonzero witness above independently
    // establishes whether this exact API recognizes the field at all.
    let mut zero_health = basic_health.clone();
    zero_health["StartInterval"] = json!(0);
    let mut zero_container = bare_container(&run.image);
    zero_container.healthcheck = Some(
        Healthcheck::configured(
            HealthTest::Exec(vec![argument("/bin/true")]),
            NonZeroU64::new(1_000_000_000),
            NonZeroU64::new(1_000_000_000),
            NonZeroU32::new(2),
        )
        .unwrap()
        .with_start_interval(0)
        .unwrap(),
    );
    let zero_body = run.render_only(
        "interval-zero-rendered",
        zero_container,
        &[
            Capability::Command,
            Capability::Healthcheck,
            Capability::HealthStartInterval,
        ],
    );
    assert_eq!(zero_body["Healthcheck"], zero_health);
    assert_eq!(
        zero_body,
        json!({
            "Image":run.image,"Cmd":["sh","-c","sleep 120"],
            "Healthcheck":zero_health,
            "Labels":{"io.dockerlens.native-run":run.run_id},
            "HostConfig":{}
        })
    );
    let zero_literal_name = run.name("interval-zero-literal");
    let zero_literal_path = format!(
        "/v{}/containers/create?name={zero_literal_name}",
        run.api_version
    );
    let zero_literal_body = json!({
        "Image":run.image,"Cmd":["sh","-c","sleep 30"],
        "Healthcheck":zero_health,
        "Labels":{"io.dockerlens.native-run":run.run_id}
    });
    let (zero_literal_status, zero_literal_response) =
        run.api("POST", &zero_literal_path, Some(&zero_literal_body));
    let zero_rendered_name = run.name("interval-zero-rendered");
    let zero_rendered_path = format!(
        "/v{}/containers/create?name={zero_rendered_name}",
        run.api_version
    );
    let (zero_rendered_status, zero_rendered_response) =
        run.api("POST", &zero_rendered_path, Some(&zero_body));
    assert_eq!(
        zero_literal_status, 201,
        "zero literal is accepted by exact API"
    );
    assert_eq!(
        zero_rendered_status, 201,
        "zero renderer is accepted by exact API"
    );
    let zero_literal: Value = serde_json::from_slice(&zero_literal_response).unwrap();
    let zero_rendered: Value = serde_json::from_slice(&zero_rendered_response).unwrap();
    let zero_literal_id = zero_literal["Id"].as_str().unwrap().to_owned();
    let zero_rendered_id = zero_rendered["Id"].as_str().unwrap().to_owned();
    run.created
        .push((zero_literal_name, zero_literal_id.clone()));
    run.created
        .push((zero_rendered_name, zero_rendered_id.clone()));
    let baseline_interval = baseline["Config"]["Healthcheck"]
        .as_object()
        .unwrap()
        .get("StartInterval");
    for id in [&zero_literal_id, &zero_rendered_id] {
        let inspected = run.inspect(id);
        let actual = inspected["Config"]["Healthcheck"]
            .as_object()
            .unwrap()
            .get("StartInterval");
        assert_eq!(
            actual, baseline_interval,
            "zero has exact baseline normalization"
        );
        assert_eq!(
            inspected["Config"]["Healthcheck"]["Test"],
            json!(["CMD", "/bin/true"])
        );
    }
    match run.api_version.as_str() {
        "1.41" => {
            assert!(
                evidence
                    .expected_negative
                    .contains(&("HealthStartIntervalPositive", "api_1_41_no_start_interval"))
            );
            evidence.expected_negative(
                "HealthStartIntervalZero",
                "api_1_41_start_interval_zero_unobservable",
            );
        }
        "1.56" => {
            for id in [&zero_literal_id, &zero_rendered_id] {
                start_container(run, id);
                for _ in 0..5 {
                    if run.inspect(id)["State"]["Health"]["Status"] == "healthy" {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                assert_eq!(run.inspect(id)["State"]["Health"]["Status"], "healthy");
            }
            evidence.positive("HealthStartIntervalZero");
        }
        _ => unreachable!("exact native API checked at test entry"),
    }
}

fn start_container(run: &NativeRun, id: &str) {
    let (status, body) = run.api(
        "POST",
        &format!("/v{}/containers/{id}/start", run.api_version),
        None,
    );
    if status != 204 {
        eprintln!("{}", start_failure_body_diagnostic(&body));
    }
    assert_native_api_status(status, 204);
}

fn start_and_wait(run: &NativeRun, id: &str) -> u32 {
    start_container(run, id);
    run.cli(&["container".into(), "wait".into(), id.into()])
        .trim()
        .parse()
        .expect("closed numeric process exit status")
}

fn assert_tmpfs_effects(run: &NativeRun, id: &str) {
    let write_probe =
        |path: &str| {
            run.cli(&[
        "exec".into(), id.into(), "sh".into(), "-c".into(),
        format!("if printf test >{path} 2>/dev/null; then printf allowed; else printf denied; fi"),
    ])
        };
    assert_eq!(write_probe("/scratch/write-check"), "allowed");
    assert_eq!(write_probe("/sealed/write-check"), "denied");
    assert_eq!(write_probe("/rootfs-write-check"), "denied");
    let comm = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "cat /proc/1/comm".into(),
    ]);
    assert!(comm.trim().contains("init"), "enabled init is PID 1");
}

fn assert_signal_effect(run: &NativeRun, id: &str) {
    assert_eq!(run.inspect(id)["State"]["Running"], true);
    run.cli(&["container".into(), "stop".into(), id.into()]);
    let exit = run.cli(&["container".into(), "wait".into(), id.into()]);
    assert_eq!(
        exit.trim(),
        "42",
        "authored stop signal reached the process trap"
    );
    assert_eq!(run.inspect(id)["State"]["Running"], false);
}

fn assert_timed_stop(run: &NativeRun, id: &str) {
    start_container(run, id);
    assert_eq!(
        run.cli(&[
            "exec".into(),
            id.into(),
            "sh".into(),
            "-c".into(),
            "printf running".into(),
        ]),
        "running"
    );
    let started = std::time::Instant::now();
    run.cli(&["container".into(), "stop".into(), id.into()]);
    let elapsed = started.elapsed();
    assert!(elapsed >= std::time::Duration::from_secs(1));
    assert!(
        elapsed < std::time::Duration::from_secs(7),
        "authored two-second stop timeout must beat Engine's default ten seconds"
    );
    let exit = run.cli(&["container".into(), "wait".into(), id.into()]);
    assert_eq!(exit.trim(), "137", "ignored TERM reaches the timeout kill");
}

fn assert_stop_timeout_effect(run: &mut NativeRun) {
    let script = "trap '' TERM; while :; do sleep 1; done";
    let oracle = run.cli_create(
        "timeout-oracle",
        &["--stop-timeout=2".into()],
        &["sh", "-c", script],
    );
    assert_eq!(oracle["Config"]["StopTimeout"], 2);
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    assert_timed_stop(run, &oracle_id);
    let mut container = bare_container(&run.image);
    container.command = ImageCommand::Exec(vec![argument("sh"), argument("-c"), argument(script)]);
    container.settings.stop_timeout_seconds = Some(2);
    let expected_body = json!({
        "Image":run.image,"Cmd":["sh","-c",script],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "StopTimeout":2,"HostConfig":{}
    });
    let (id, _, inspected) = run.rendered_create(
        "timeout-rendered",
        container,
        &[Capability::Command, Capability::StopTimeout],
        expected_body,
    );
    assert_eq!(
        inspected["Config"]["StopTimeout"],
        oracle["Config"]["StopTimeout"]
    );
    assert_timed_stop(run, &id);
}

fn probe_storage_and_lifecycle(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_storage_lifecycle");
    let signal_script = "trap 'exit 42' USR1; while :; do sleep 1; done";
    let oracle = run.cli_create(
        "storage-oracle",
        &[
            "--read-only".into(),
            "--tmpfs=/scratch:rw,size=4096,mode=0700".into(),
            "--tmpfs=/sealed:ro,size=4096,mode=0700".into(),
            "--init".into(),
            "--stop-signal=SIGUSR1".into(),
            "--stop-timeout=2".into(),
        ],
        &["sh", "-c", signal_script],
    );
    assert_eq!(oracle["HostConfig"]["ReadonlyRootfs"], true);
    assert_eq!(oracle["HostConfig"]["Init"], true);
    assert_eq!(oracle["Config"]["StopSignal"], "SIGUSR1");
    assert_eq!(oracle["Config"]["StopTimeout"], 2);
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    start_container(run, &oracle_id);
    assert_tmpfs_effects(run, &oracle_id);
    assert_signal_effect(run, &oracle_id);

    let mut container = bare_container(&run.image);
    container.command = ImageCommand::Exec(vec![
        argument("sh"),
        argument("-c"),
        argument(signal_script),
    ]);
    container.mounts = vec![
        Mount::tmpfs(
            b"/scratch".to_vec(),
            false,
            TmpfsOptions {
                size_bytes: NonZeroU64::new(4096),
                mode: Some(0o700),
            },
        )
        .unwrap(),
        Mount::tmpfs(
            b"/sealed".to_vec(),
            true,
            TmpfsOptions {
                size_bytes: NonZeroU64::new(4096),
                mode: Some(0o700),
            },
        )
        .unwrap(),
    ];
    container.settings.read_only_rootfs = Some(true);
    container.settings.init = Some(true);
    container.settings.stop_signal = Some(argument("SIGUSR1"));
    container.settings.stop_timeout_seconds = Some(2);
    let expected_body = json!({
        "Image":run.image, "Cmd":["sh","-c",signal_script],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "StopSignal":"SIGUSR1", "StopTimeout":2,
        "HostConfig":{
            "Mounts":[
                {"Type":"tmpfs","Target":"/scratch","ReadOnly":false,
                 "TmpfsOptions":{"SizeBytes":4096,"Mode":448}},
                {"Type":"tmpfs","Target":"/sealed","ReadOnly":true,
                 "TmpfsOptions":{"SizeBytes":4096,"Mode":448}}
            ],
            "ReadonlyRootfs":true,"Init":true
        }
    });
    let (id, body, inspected) = run.rendered_create(
        "storage-rendered",
        container,
        &[
            Capability::Command,
            Capability::TmpfsMount,
            Capability::ReadOnlyRootfs,
            Capability::ContainerInit,
            Capability::StopSignal,
            Capability::StopTimeout,
        ],
        expected_body,
    );
    assert_eq!(body["HostConfig"]["ReadonlyRootfs"], true);
    assert_eq!(body["HostConfig"]["Init"], true);
    assert_eq!(body["StopSignal"], "SIGUSR1");
    assert_eq!(body["StopTimeout"], 2);
    assert_eq!(body["HostConfig"]["Mounts"][0]["Type"], "tmpfs");
    assert_eq!(body["HostConfig"]["Mounts"][0]["ReadOnly"], false);
    assert_eq!(body["HostConfig"]["Mounts"][1]["ReadOnly"], true);
    assert_eq!(
        body["HostConfig"]["Mounts"][0]["TmpfsOptions"],
        json!({
            "SizeBytes":4096,"Mode":448
        })
    );
    for (section, key) in [
        ("HostConfig", "ReadonlyRootfs"),
        ("HostConfig", "Init"),
        ("Config", "StopSignal"),
        ("Config", "StopTimeout"),
    ] {
        assert_eq!(inspected[section][key], oracle[section][key]);
    }
    start_container(run, &id);
    assert_tmpfs_effects(run, &id);
    assert_signal_effect(run, &id);
    assert_stop_timeout_effect(run);
    record_many(
        evidence,
        &[
            "TmpfsMountReadWrite",
            "TmpfsMountReadOnly",
            "TmpfsMountOptions",
            "ReadOnlyRootfsTrue",
            "ContainerInitTrue",
            "StopSignal",
            "StopTimeoutPositive",
        ],
    );
}

fn assert_false_storage_and_zero_stop(run: &NativeRun, id: &str) {
    start_container(run, id);
    let root_write = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "printf writable >/rootfs-write-check && cat /rootfs-write-check".into(),
    ]);
    assert_eq!(root_write, "writable");
    let pid_one = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "cat /proc/1/comm".into(),
    ]);
    assert_eq!(pid_one.trim(), "sh", "init=false leaves shell as PID 1");
    let started = std::time::Instant::now();
    run.cli(&["container".into(), "stop".into(), id.into()]);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(7),
        "zero stop timeout must beat Engine default ten seconds"
    );
    let exit = run.cli(&["container".into(), "wait".into(), id.into()]);
    assert_eq!(exit.trim(), "137", "ignored TERM is killed at zero timeout");
}

fn probe_false_storage_and_zero_stop(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_storage_lifecycle");
    let script = "trap '' TERM; while :; do sleep 1; done";
    // A literal Engine request independently proves that explicit false/zero
    // fields are sent, even when a CLI would omit default-valued flags.
    let (literal_id, literal) = run.literal_create(
        "storage-false-literal",
        json!({
            "Image":run.image,"Cmd":["sh","-c",script],"StopTimeout":0,
            "HostConfig":{"ReadonlyRootfs":false,"Init":false}
        }),
    );
    let mut container = bare_container(&run.image);
    container.command = ImageCommand::Exec(vec![argument("sh"), argument("-c"), argument(script)]);
    container.settings.read_only_rootfs = Some(false);
    container.settings.init = Some(false);
    container.settings.stop_timeout_seconds = Some(0);
    let expected = json!({
        "Image":run.image,"Cmd":["sh","-c",script],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "StopTimeout":0,
        "HostConfig":{"ReadonlyRootfs":false,"Init":false}
    });
    let (rendered_id, body, rendered) = run.rendered_create(
        "storage-false-rendered",
        container,
        &[
            Capability::Command,
            Capability::ReadOnlyRootfs,
            Capability::ContainerInit,
            Capability::StopTimeout,
        ],
        expected,
    );
    assert_eq!(body["HostConfig"]["ReadonlyRootfs"], false);
    assert_eq!(body["HostConfig"]["Init"], false);
    assert_eq!(body["StopTimeout"], 0);
    for (section, key) in [
        ("HostConfig", "ReadonlyRootfs"),
        ("HostConfig", "Init"),
        ("Config", "StopTimeout"),
    ] {
        assert_eq!(rendered[section][key], literal[section][key]);
    }
    assert_false_storage_and_zero_stop(run, &literal_id);
    assert_false_storage_and_zero_stop(run, &rendered_id);
    record_many(
        evidence,
        &[
            "ReadOnlyRootfsFalse",
            "ContainerInitFalse",
            "StopTimeoutZero",
        ],
    );
}

fn runtime_status(run: &NativeRun, id: &str) -> String {
    run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "cat /proc/self/status".into(),
    ])
}

fn mark_resource_stage(side: &'static str, phase: &'static str) {
    assert!(matches!(side, "oracle" | "rendered"));
    assert!(matches!(
        phase,
        "create"
            | "inspect"
            | "start"
            | "ulimit"
            | "status"
            | "groups"
            | "sysctl"
            | "device"
            | "memory"
            | "pids"
            | "shm"
    ));
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_resources_security_{side}_{phase}");
}

fn mark_resource_control(control: &'static str, phase: &'static str, outcome: &'static str) {
    assert!(matches!(control, "baseline" | "resource" | "device"));
    assert!(matches!(phase, "create" | "inspect" | "start"));
    assert!(matches!(
        outcome,
        "begin" | "ready" | "started" | "timeout" | "uncertain" | "invalid" | "budget"
    ));
    eprintln!(
        "DOCKERLENS_NATIVE_RESOURCE_CONTROL: control={control} phase={phase} outcome={outcome}"
    );
}

fn resource_control_seconds_remaining() -> u64 {
    let Ok(deadline) = required("NATIVE_NETWORK_TEST_DEADLINE_EPOCH").parse::<u64>() else {
        return 0;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    // Keep time for the three exact probes and verified task-owned cleanup.
    deadline.saturating_sub(now.as_secs())
}

fn resource_start_control_matrix(run: &mut NativeRun) {
    for control in ["baseline", "resource", "device"] {
        let uncertain = run.uncertain_mutation.get();
        if !resource_control_may_continue(uncertain, resource_control_seconds_remaining()) {
            if !uncertain {
                mark_resource_control(control, "create", "budget");
            }
            break;
        }
        mark_resource_control(control, "create", "begin");
        let created = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run.resource_control_create(control)
        }));
        let Ok(inspected) = created else {
            let phase = if run
                .created
                .iter()
                .any(|(name, _)| name == &run.name(&format!("resource-control-{control}")))
            {
                "inspect"
            } else {
                "create"
            };
            mark_resource_control(
                control,
                phase,
                if run.uncertain_mutation.get() {
                    "uncertain"
                } else {
                    "invalid"
                },
            );
            break;
        };
        mark_resource_control(control, "inspect", "ready");
        let Some(id) = inspected["Id"].as_str() else {
            mark_resource_control(control, "inspect", "invalid");
            break;
        };
        mark_resource_control(control, "start", "begin");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run.resource_control_start(id)
        }))
        .unwrap_or("uncertain");
        mark_resource_control(control, "start", outcome);
        if run.uncertain_mutation.get() {
            break;
        }
    }
}

fn assert_resource_effects(run: &NativeRun, id: &str, side: &'static str) {
    mark_resource_stage(side, "ulimit");
    let limits = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "ulimit -Sn; ulimit -Hn".into(),
    ]);
    assert_eq!(limits.lines().collect::<Vec<_>>(), ["1024", "2048"]);
    mark_resource_stage(side, "status");
    let status = runtime_status(run, id);
    assert!(status.lines().any(|line| line.trim() == "NoNewPrivs:\t1"));
    let bounding = status
        .lines()
        .find_map(|line| line.strip_prefix("CapBnd:\t"))
        .expect("runtime bounding capability mask");
    let bounding = u64::from_str_radix(bounding.trim(), 16).expect("hex capability mask");
    assert_eq!(
        bounding & (1 << 21),
        0,
        "SYS_ADMIN absent from capability bound"
    );
    mark_resource_stage(side, "groups");
    let groups = run.cli(&["exec".into(), id.into(), "id".into(), "-G".into()]);
    assert!(groups.split_whitespace().any(|group| group == "27"));
    mark_resource_stage(side, "sysctl");
    let sysctl = run.cli(&[
        "exec".into(),
        id.into(),
        "cat".into(),
        "/proc/sys/net/ipv4/ip_forward".into(),
    ]);
    assert_eq!(sysctl.trim(), "0");
    mark_resource_stage(side, "device");
    let device = run.cli(&[
        "exec".into(), id.into(), "sh".into(), "-c".into(),
        "if test -c /dev/native-null && cat /dev/native-null >/dev/null; then printf present; else printf absent; fi".into(),
    ]);
    assert_eq!(device, "present");
    mark_resource_stage(side, "memory");
    let memory = run.cli(&[
        "exec".into(), id.into(), "sh".into(), "-c".into(),
        "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes".into(),
    ]);
    assert_eq!(
        memory.trim(),
        "67108864",
        "memory cgroup limit is effective"
    );
    mark_resource_stage(side, "pids");
    let pids = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max".into(),
    ]);
    assert_eq!(pids.trim(), "32", "PID cgroup limit is effective");
    mark_resource_stage(side, "shm");
    let shm = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "df -k /dev/shm | tail -n 1 | awk '{print $2}'".into(),
    ]);
    assert_eq!(shm.trim(), "32768", "shared-memory mount size is effective");
}

fn singleton_sys_admin_cap_drop(value: &Value) -> bool {
    matches!(
        value.as_array(),
        Some(items)
            if items.len() == 1
                && matches!(items[0].as_str(), Some("SYS_ADMIN" | "CAP_SYS_ADMIN"))
    )
}

fn closed_cap_drop_diagnostic(value: &Value, phase: &'static str) -> String {
    assert!(matches!(phase, "oracle" | "rendered"));
    let (state, count, spelling) = match value {
        Value::Array(items) => {
            let spelling = match items.as_slice() {
                [Value::String(name)] if name == "SYS_ADMIN" => "sys_admin",
                [Value::String(name)] if name == "CAP_SYS_ADMIN" => "cap_sys_admin",
                [_] => "other",
                [] => "absent",
                _ => "multiple",
            };
            ("array", binding_cardinality(items.len()), spelling)
        }
        Value::Null => ("null", "zero", "absent"),
        _ => ("other", "zero", "other"),
    };
    format!(
        "DOCKERLENS_NATIVE_CAP_DROP_DIAG: phase={phase} state={state} count={count} spelling={spelling}"
    )
}

#[test]
fn cap_drop_alias_requires_one_exact_documented_name() {
    for name in ["SYS_ADMIN", "CAP_SYS_ADMIN"] {
        assert!(singleton_sys_admin_cap_drop(&json!([name])));
    }
    for value in [
        json!([]),
        json!(["NET_ADMIN"]),
        json!(["cap_sys_admin"]),
        json!(["SYS_ADMIN", "CAP_SYS_ADMIN"]),
        json!("SYS_ADMIN"),
        Value::Null,
    ] {
        assert!(!singleton_sys_admin_cap_drop(&value));
    }
    let private = json!(["protected-secret"]);
    let diagnostic = closed_cap_drop_diagnostic(&private, "oracle");
    assert_eq!(
        diagnostic,
        "DOCKERLENS_NATIVE_CAP_DROP_DIAG: phase=oracle state=array count=one spelling=other"
    );
    assert!(!diagnostic.contains("protected-secret"));
}

fn probe_resources_and_security(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_resources_security");
    mark_resource_stage("oracle", "create");
    let oracle = run.cli_create(
        "resource-oracle",
        &[
            "--memory=67108864".into(),
            "--pids-limit=32".into(),
            "--shm-size=33554432".into(),
            "--ulimit=nofile=1024:2048".into(),
            "--device=/dev/null:/dev/native-null:r".into(),
            "--cap-drop=SYS_ADMIN".into(),
            "--security-opt=no-new-privileges:true".into(),
            "--sysctl=net.ipv4.ip_forward=0".into(),
            "--group-add=27".into(),
        ],
        &["sh", "-c", "sleep 120"],
    );
    mark_resource_stage("oracle", "inspect");
    let host = &oracle["HostConfig"];
    assert_eq!(host["Memory"], 67_108_864);
    assert_eq!(host["PidsLimit"], 32);
    assert_eq!(host["ShmSize"], 33_554_432);
    assert_eq!(
        host["Ulimits"][0],
        json!({"Name":"nofile","Soft":1024,"Hard":2048})
    );
    eprintln!("{}", closed_cap_drop_diagnostic(&host["CapDrop"], "oracle"));
    assert!(singleton_sys_admin_cap_drop(&host["CapDrop"]));
    assert_eq!(host["Sysctls"]["net.ipv4.ip_forward"], "0");
    assert!(
        host["SecurityOpt"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item == "no-new-privileges:true" })
    );
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    mark_resource_stage("oracle", "start");
    let (oracle_start_status, oracle_start_body) = run.api(
        "POST",
        &format!("/v{}/containers/{oracle_id}/start", run.api_version),
        None,
    );
    if oracle_start_status != 204 {
        eprintln!("{}", start_failure_body_diagnostic(&oracle_start_body));
        resource_start_control_matrix(run);
    }
    assert_native_api_status(oracle_start_status, 204);
    assert_resource_effects(run, &oracle_id, "oracle");

    let mut container = bare_container(&run.image);
    container.settings.memory_limit =
        Some(MemoryLimit::Bytes(NonZeroU64::new(67_108_864).unwrap()));
    container.settings.pids_limit = Some(PidsLimit::Count(NonZeroU64::new(32).unwrap()));
    container.settings.shm_size_bytes = NonZeroU64::new(33_554_432);
    container.settings.ulimits = vec![Ulimit {
        name: ContainerToken::new(b"nofile".to_vec()).unwrap(),
        soft: UlimitValue::Value(1024),
        hard: UlimitValue::Value(2048),
    }];
    container.settings.devices = vec![DeviceMapping {
        host_path: WorkingDirectory::new(b"/dev/null".to_vec()).unwrap(),
        container_path: WorkingDirectory::new(b"/dev/native-null".to_vec()).unwrap(),
        permissions: DevicePermissions {
            read: true,
            write: false,
            create: false,
        },
    }];
    container.settings.cap_drop = vec![ContainerToken::new(b"SYS_ADMIN".to_vec()).unwrap()];
    container.settings.security_options = vec![SecurityOption::NoNewPrivileges(true)];
    container.settings.sysctls =
        vec![ContainerLabel::new(b"net.ipv4.ip_forward".to_vec(), b"0".to_vec()).unwrap()];
    container.settings.group_add = vec![ContainerUser::new(b"27".to_vec()).unwrap()];
    let expected_body = json!({
        "Image":run.image, "Cmd":["sh","-c","sleep 120"],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "HostConfig":{
            "Memory":67_108_864,"PidsLimit":32,"ShmSize":33_554_432,
            "Ulimits":[{"Name":"nofile","Soft":1024,"Hard":2048}],
            "Devices":[{"PathOnHost":"/dev/null","PathInContainer":"/dev/native-null",
                        "CgroupPermissions":"r"}],
            "CapDrop":["SYS_ADMIN"],
            "SecurityOpt":["no-new-privileges:true"],
            "Sysctls":{"net.ipv4.ip_forward":"0"},
            "GroupAdd":["27"]
        }
    });
    mark_resource_stage("rendered", "create");
    let (id, body, inspected) = run.rendered_create(
        "resource-rendered",
        container,
        &[
            Capability::Command,
            Capability::MemoryLimit,
            Capability::PidsLimit,
            Capability::ShmSize,
            Capability::Ulimits,
            Capability::UlimitNofile,
            Capability::DeviceMappings,
            Capability::LinuxCapabilities,
            Capability::CapDropSysAdmin,
            Capability::SecurityOptions,
            Capability::Sysctls,
            Capability::SysctlIpv4Forward,
            Capability::SupplementaryGroups,
        ],
        expected_body,
    );
    mark_resource_stage("rendered", "inspect");
    let body = &body["HostConfig"];
    assert_eq!(body["Memory"], 67_108_864);
    assert_eq!(body["PidsLimit"], 32);
    assert_eq!(body["ShmSize"], 33_554_432);
    assert_eq!(
        body["Ulimits"][0],
        json!({"Name":"nofile","Soft":1024,"Hard":2048})
    );
    assert_eq!(body["CapDrop"], json!(["SYS_ADMIN"]));
    assert_eq!(body["SecurityOpt"], json!(["no-new-privileges:true"]));
    assert_eq!(body["Sysctls"]["net.ipv4.ip_forward"], "0");
    assert_eq!(body["GroupAdd"], json!(["27"]));
    for key in ["Memory", "PidsLimit", "ShmSize", "Ulimits", "Sysctls"] {
        assert_eq!(inspected["HostConfig"][key], oracle["HostConfig"][key]);
    }
    eprintln!(
        "{}",
        closed_cap_drop_diagnostic(&inspected["HostConfig"]["CapDrop"], "rendered")
    );
    assert!(singleton_sys_admin_cap_drop(
        &inspected["HostConfig"]["CapDrop"]
    ));
    mark_resource_stage("rendered", "start");
    start_container(run, &id);
    assert_resource_effects(run, &id, "rendered");
    record_many(
        evidence,
        &[
            "MemoryBytes",
            "PidsCount",
            "ShmSize",
            "UlimitsFinite",
            "UlimitNofile",
            "DeviceMappings",
            "LinuxCapDrop",
            "CapDropSysAdmin",
            "NoNewPrivilegesEnabled",
            "Sysctls",
            "SysctlIpv4Forward",
            "SupplementaryGroups",
        ],
    );
}

fn runtime_unlimited_cgroups(run: &NativeRun, id: &str) -> String {
    run.cli(&[
        "exec".into(), id.into(), "sh".into(), "-c".into(),
        "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes; cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max".into(),
    ])
}

fn net_bind_service_effective(run: &NativeRun, id: &str) -> bool {
    let status = runtime_status(run, id);
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .expect("runtime effective capability mask");
    let effective = u64::from_str_radix(effective.trim(), 16).expect("hex capability mask");
    effective & (1 << 10) != 0
}

fn assert_unlimited_nofile(value: &str) {
    let limits = value.lines().collect::<Vec<_>>();
    assert_eq!(limits.len(), 2, "soft and hard nofile values required");
    for limit in limits {
        assert!(
            limit == "unlimited" || limit.parse::<u64>().is_ok_and(|number| number > 2048),
            "unlimited nofile must exceed independent finite control"
        );
    }
}

#[test]
fn unlimited_nofile_rejects_finite_control_and_malformed_values() {
    for value in ["1024\n2048\n", "unlimited\n2048\n", "abc\n4096\n", "4096\n"] {
        assert!(std::panic::catch_unwind(|| assert_unlimited_nofile(value)).is_err());
    }
    assert_unlimited_nofile("4096\nunlimited\n");
}

fn assert_unlimited_resource_effects(run: &NativeRun, id: &str, baseline: &str) -> String {
    start_container(run, id);
    assert_eq!(runtime_unlimited_cgroups(run, id), baseline);
    let status = runtime_status(run, id);
    assert!(status.lines().any(|line| line.trim() == "NoNewPrivs:\t0"));
    assert!(
        net_bind_service_effective(run, id),
        "NET_BIND_SERVICE is effective"
    );
    let nofile = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "ulimit -Sn; ulimit -Hn".into(),
    ]);
    assert_unlimited_nofile(&nofile);
    nofile
}

fn probe_unlimited_resources_and_cap_add(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_resources_security");
    let baseline = run.cli_create("unlimited-baseline", &[], &["sh", "-c", "sleep 120"]);
    let baseline_id = baseline["Id"].as_str().unwrap().to_owned();
    start_container(run, &baseline_id);
    let baseline_cgroups = runtime_unlimited_cgroups(run, &baseline_id);
    // NET_BIND_SERVICE belongs to Docker's default capability set. A present
    // bit in the rendered container alone cannot prove that CapAdd caused it.
    // These independent CLI controls establish the exact Engine/mode delta
    // without expanding the product's finite cap-drop contract to ALL.
    let dropped = run.cli_create(
        "cap-drop-all-control",
        &["--cap-drop=ALL".into()],
        &["sh", "-c", "sleep 120"],
    );
    assert_eq!(dropped["HostConfig"]["CapDrop"], json!(["ALL"]));
    let dropped_id = dropped["Id"].as_str().unwrap().to_owned();
    start_container(run, &dropped_id);
    assert!(!net_bind_service_effective(run, &dropped_id));
    let restored = run.cli_create(
        "cap-add-back-control",
        &["--cap-drop=ALL".into(), "--cap-add=NET_BIND_SERVICE".into()],
        &["sh", "-c", "sleep 120"],
    );
    assert_eq!(restored["HostConfig"]["CapDrop"], json!(["ALL"]));
    assert_eq!(
        restored["HostConfig"]["CapAdd"],
        json!(["NET_BIND_SERVICE"])
    );
    let restored_id = restored["Id"].as_str().unwrap().to_owned();
    start_container(run, &restored_id);
    assert!(net_bind_service_effective(run, &restored_id));
    let oracle = run.cli_create(
        "unlimited-oracle",
        &[
            "--memory=0".into(),
            "--pids-limit=-1".into(),
            "--ulimit=nofile=-1:-1".into(),
            "--cap-add=NET_BIND_SERVICE".into(),
            "--security-opt=no-new-privileges:false".into(),
        ],
        &["sh", "-c", "sleep 120"],
    );
    let host = &oracle["HostConfig"];
    assert_eq!(host["Memory"], 0);
    assert_eq!(host["PidsLimit"], -1);
    assert_eq!(
        host["Ulimits"][0],
        json!({"Name":"nofile","Soft":-1,"Hard":-1})
    );
    assert_eq!(host["CapAdd"], json!(["NET_BIND_SERVICE"]));
    assert!(
        host["SecurityOpt"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "no-new-privileges:false")
    );
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    let oracle_ulimit = assert_unlimited_resource_effects(run, &oracle_id, &baseline_cgroups);

    let mut container = bare_container(&run.image);
    container.settings.memory_limit = Some(MemoryLimit::Unlimited);
    container.settings.pids_limit = Some(PidsLimit::Unlimited);
    container.settings.ulimits = vec![Ulimit {
        name: ContainerToken::new(b"nofile".to_vec()).unwrap(),
        soft: UlimitValue::Unlimited,
        hard: UlimitValue::Unlimited,
    }];
    container.settings.cap_add = vec![ContainerToken::new(b"NET_BIND_SERVICE".to_vec()).unwrap()];
    container.settings.security_options = vec![SecurityOption::NoNewPrivileges(false)];
    let expected = json!({
        "Image":run.image,"Cmd":["sh","-c","sleep 120"],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "HostConfig":{
            "Memory":0,"PidsLimit":-1,
            "Ulimits":[{"Name":"nofile","Soft":-1,"Hard":-1}],
            "CapAdd":["NET_BIND_SERVICE"],
            "SecurityOpt":["no-new-privileges:false"]
        }
    });
    let (id, body, inspected) = run.rendered_create(
        "unlimited-rendered",
        container,
        &[
            Capability::Command,
            Capability::MemoryLimit,
            Capability::PidsLimit,
            Capability::Ulimits,
            Capability::UlimitNofile,
            Capability::LinuxCapabilities,
            Capability::CapAddNetBindService,
            Capability::SecurityOptions,
        ],
        expected,
    );
    for key in ["Memory", "PidsLimit", "Ulimits", "CapAdd", "SecurityOpt"] {
        assert_eq!(body["HostConfig"][key], host[key]);
        assert_eq!(inspected["HostConfig"][key], host[key]);
    }
    let rendered_ulimit = assert_unlimited_resource_effects(run, &id, &baseline_cgroups);
    assert_eq!(rendered_ulimit, oracle_ulimit);
    record_many(
        evidence,
        &[
            "MemoryUnlimited",
            "PidsUnlimited",
            "UlimitsUnlimited",
            "LinuxCapAdd",
            "CapAddNetBindService",
            "NoNewPrivilegesDisabled",
        ],
    );
}

fn mark_resolver_stage(lane: &'static str, side: &'static str, phase: &'static str) {
    assert!(matches!(lane, "ipv4" | "ipv6" | "local" | "none"));
    assert!(matches!(side, "oracle" | "rendered"));
    assert!(matches!(
        phase,
        "create" | "inspect" | "body" | "start" | "resolver" | "hosts" | "logs"
    ));
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_resolver_logging_{lane}_{side}_{phase}");
}

fn mark_resolver_suffix_stage(suffix: &str, phase: &'static str) {
    let (lane, side) = match suffix {
        "resolver-oracle" => ("ipv4", "oracle"),
        "resolver-rendered" => ("ipv4", "rendered"),
        "resolver-ipv6-oracle" => ("ipv6", "oracle"),
        "resolver-ipv6-rendered" => ("ipv6", "rendered"),
        "log-local-oracle" => ("local", "oracle"),
        "log-local-rendered" => ("local", "rendered"),
        "log-none-oracle" => ("none", "oracle"),
        "log-none-rendered" => ("none", "rendered"),
        _ => return,
    };
    mark_resolver_stage(lane, side, phase);
}

fn assert_resolver_and_logging(run: &NativeRun, id: &str, side: &'static str) {
    mark_resolver_stage("ipv4", side, "resolver");
    let resolver = run.cli(&[
        "exec".into(),
        id.into(),
        "cat".into(),
        "/etc/resolv.conf".into(),
    ]);
    assert!(
        resolver
            .lines()
            .any(|line| line.trim() == "nameserver 1.1.1.1")
    );
    mark_resolver_stage("ipv4", side, "hosts");
    let hosts = run.cli(&["exec".into(), id.into(), "cat".into(), "/etc/hosts".into()]);
    assert!(hosts.lines().any(|line| {
        line.split_whitespace().collect::<Vec<_>>() == ["10.0.0.2", "fixture.local"]
    }));
    mark_resolver_stage("ipv4", side, "logs");
    let logs = run.cli(&["logs".into(), id.into()]);
    assert!(logs.contains("native-log-canary"));
}

fn probe_resolver_and_logging(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_resolver_logging");
    let command = "printf native-log-canary; sleep 120";
    mark_resolver_stage("ipv4", "oracle", "create");
    let oracle = run.cli_create(
        "resolver-oracle",
        &[
            "--dns=1.1.1.1".into(),
            "--add-host=fixture.local:10.0.0.2".into(),
            "--log-driver=json-file".into(),
            "--log-opt=max-size=10m".into(),
        ],
        &["sh", "-c", command],
    );
    mark_resolver_stage("ipv4", "oracle", "inspect");
    assert_eq!(oracle["HostConfig"]["Dns"], json!(["1.1.1.1"]));
    assert_eq!(
        oracle["HostConfig"]["ExtraHosts"],
        json!(["fixture.local:10.0.0.2"])
    );
    assert_eq!(oracle["HostConfig"]["LogConfig"]["Type"], "json-file");
    assert_eq!(
        oracle["HostConfig"]["LogConfig"]["Config"]["max-size"],
        "10m"
    );
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    mark_resolver_stage("ipv4", "oracle", "start");
    start_container(run, &oracle_id);
    assert_resolver_and_logging(run, &oracle_id, "oracle");

    let mut container = bare_container(&run.image);
    container.command = ImageCommand::Exec(vec![argument("sh"), argument("-c"), argument(command)]);
    container.settings.dns = vec!["1.1.1.1".parse().unwrap()];
    container.settings.extra_hosts = vec![ExtraHost {
        name: ContainerHostname::new(b"fixture.local".to_vec()).unwrap(),
        address: "10.0.0.2".parse().unwrap(),
    }];
    container.settings.log_config = Some(LogConfig {
        driver: LogDriver::JsonFile,
        options: vec![ContainerLabel::new(b"max-size".to_vec(), b"10m".to_vec()).unwrap()],
    });
    let expected_body = json!({
        "Image":run.image, "Cmd":["sh","-c",command],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "HostConfig":{
            "Dns":["1.1.1.1"], "ExtraHosts":["fixture.local:10.0.0.2"],
            "LogConfig":{"Type":"json-file","Config":{"max-size":"10m"}}
        }
    });
    mark_resolver_stage("ipv4", "rendered", "create");
    let (id, body, inspected) = run.rendered_create(
        "resolver-rendered",
        container,
        &[
            Capability::Command,
            Capability::DnsServers,
            Capability::ExtraHosts,
            Capability::LogConfig,
            Capability::LogOptionMaxSize,
        ],
        expected_body,
    );
    mark_resolver_stage("ipv4", "rendered", "body");
    assert_eq!(body["HostConfig"]["Dns"], json!(["1.1.1.1"]));
    assert_eq!(
        body["HostConfig"]["ExtraHosts"],
        json!(["fixture.local:10.0.0.2"])
    );
    assert_eq!(
        body["HostConfig"]["LogConfig"],
        json!({
            "Type":"json-file","Config":{"max-size":"10m"}
        })
    );
    mark_resolver_stage("ipv4", "rendered", "inspect");
    for key in ["Dns", "ExtraHosts", "LogConfig"] {
        assert_eq!(inspected["HostConfig"][key], oracle["HostConfig"][key]);
    }
    mark_resolver_stage("ipv4", "rendered", "start");
    start_container(run, &id);
    assert_resolver_and_logging(run, &id, "rendered");
    record_many(
        evidence,
        &[
            "DnsIpv4",
            "ExtraHostsIpv4",
            "LogJsonFile",
            "LogOptions",
            "LogOptionMaxSize",
        ],
    );
}

fn assert_ipv6_resolver_effects(run: &NativeRun, id: &str, side: &'static str) {
    mark_resolver_stage("ipv6", side, "start");
    start_container(run, id);
    mark_resolver_stage("ipv6", side, "resolver");
    let resolver = run.cli(&[
        "exec".into(),
        id.into(),
        "cat".into(),
        "/etc/resolv.conf".into(),
    ]);
    assert!(
        resolver
            .lines()
            .any(|line| line.trim() == "nameserver 2001:4860:4860::8888")
    );
    mark_resolver_stage("ipv6", side, "hosts");
    let hosts = run.cli(&["exec".into(), id.into(), "cat".into(), "/etc/hosts".into()]);
    assert!(hosts.lines().any(|line| {
        line.split_whitespace().collect::<Vec<_>>() == ["2001:db8::10", "fixture-v6.local"]
    }));
}

fn probe_ipv6_resolver(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_resolver_logging");
    mark_resolver_stage("ipv6", "oracle", "create");
    let oracle = run.cli_create(
        "resolver-ipv6-oracle",
        &[
            "--dns=2001:4860:4860::8888".into(),
            "--add-host=fixture-v6.local:2001:db8::10".into(),
        ],
        &["sh", "-c", "sleep 120"],
    );
    mark_resolver_stage("ipv6", "oracle", "inspect");
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    assert_eq!(oracle["HostConfig"]["Dns"], json!(["2001:4860:4860::8888"]));
    assert_eq!(
        oracle["HostConfig"]["ExtraHosts"],
        json!(["fixture-v6.local:2001:db8::10"])
    );
    assert_ipv6_resolver_effects(run, &oracle_id, "oracle");

    let mut container = bare_container(&run.image);
    container.settings.dns = vec!["2001:4860:4860::8888".parse().unwrap()];
    container.settings.extra_hosts = vec![ExtraHost {
        name: ContainerHostname::new(b"fixture-v6.local".to_vec()).unwrap(),
        address: "2001:db8::10".parse().unwrap(),
    }];
    let expected = json!({
        "Image":run.image,"Cmd":["sh","-c","sleep 120"],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "HostConfig":{
            "Dns":["2001:4860:4860::8888"],
            "ExtraHosts":["fixture-v6.local:2001:db8::10"]
        }
    });
    mark_resolver_stage("ipv6", "rendered", "create");
    let (id, body, inspected) = run.rendered_create(
        "resolver-ipv6-rendered",
        container,
        &[Capability::DnsServers, Capability::ExtraHosts],
        expected,
    );
    mark_resolver_stage("ipv6", "rendered", "body");
    mark_resolver_stage("ipv6", "rendered", "inspect");
    for key in ["Dns", "ExtraHosts"] {
        assert_eq!(body["HostConfig"][key], oracle["HostConfig"][key]);
        assert_eq!(inspected["HostConfig"][key], oracle["HostConfig"][key]);
    }
    assert_ipv6_resolver_effects(run, &id, "rendered");
    record_many(evidence, &["DnsIpv6", "ExtraHostsIpv6"]);
}

fn assert_no_log_output(_run: &NativeRun, id: &str) {
    let mut command = Command::new("timeout");
    command.args(["--kill-after=1", "45"]);
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
        "logs",
        id,
    ]);
    let output = bounded_native_cli_output(&mut command);
    assert!(
        !output.status.success(),
        "none driver must reject log reads"
    );
    assert!(
        output.stdout.is_empty(),
        "none driver must not expose container logs"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("configured logging driver does not support reading"),
        "only the expected none-driver log-read rejection is accepted"
    );
}

fn probe_alternative_logging(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_resolver_logging");
    let command = "printf native-log-canary; sleep 120";
    for (suffix, driver, name) in [
        ("local", LogDriver::Local, "local"),
        ("none", LogDriver::None, "none"),
    ] {
        mark_resolver_stage(suffix, "oracle", "create");
        let oracle = run.cli_create(
            &format!("log-{suffix}-oracle"),
            &[format!("--log-driver={name}")],
            &["sh", "-c", command],
        );
        mark_resolver_stage(suffix, "oracle", "inspect");
        let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
        assert_eq!(
            oracle["HostConfig"]["LogConfig"],
            json!({"Type":name,"Config":{}})
        );
        mark_resolver_stage(suffix, "oracle", "start");
        start_container(run, &oracle_id);
        mark_resolver_stage(suffix, "oracle", "logs");
        if suffix == "none" {
            assert_no_log_output(run, &oracle_id);
        } else {
            assert!(
                run.cli(&["logs".into(), oracle_id])
                    .contains("native-log-canary")
            );
        }

        let mut container = bare_container(&run.image);
        container.command =
            ImageCommand::Exec(vec![argument("sh"), argument("-c"), argument(command)]);
        container.settings.log_config = Some(LogConfig {
            driver,
            options: vec![],
        });
        let expected = json!({
            "Image":run.image,"Cmd":["sh","-c",command],
            "Labels":{"io.dockerlens.native-run":run.run_id},
            "HostConfig":{"LogConfig":{"Type":name,"Config":{}}}
        });
        mark_resolver_stage(suffix, "rendered", "create");
        let (id, body, inspected) = run.rendered_create(
            &format!("log-{suffix}-rendered"),
            container,
            &[Capability::Command, Capability::LogConfig],
            expected,
        );
        mark_resolver_stage(suffix, "rendered", "body");
        assert_eq!(
            body["HostConfig"]["LogConfig"],
            oracle["HostConfig"]["LogConfig"]
        );
        mark_resolver_stage(suffix, "rendered", "inspect");
        assert_eq!(
            inspected["HostConfig"]["LogConfig"],
            oracle["HostConfig"]["LogConfig"]
        );
        mark_resolver_stage(suffix, "rendered", "start");
        start_container(run, &id);
        mark_resolver_stage(suffix, "rendered", "logs");
        if suffix == "none" {
            assert_no_log_output(run, &id);
            evidence.positive("LogNone");
        } else {
            assert!(run.cli(&["logs".into(), id]).contains("native-log-canary"));
            evidence.positive("LogLocal");
        }
    }
}

#[test]
#[ignore = "requires the isolated exact-version native Engine harness"]
fn live_container_settings_match_engine() {
    let path = PathBuf::from(required("NATIVE_CONTAINER_PROBES_PATH"));
    assert_eq!(
        path.parent(),
        Some(PathBuf::from(required("NATIVE_CAPTURE_DIR")).as_path())
    );
    assert!(!path.exists(), "fresh private probe artifact path");
    let mut evidence = ProbeEvidence::default();
    let mut failed = false;
    for (name, probe) in GROUPS {
        let mut run = NativeRun::new();
        let initial = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run.owned_inventory().is_empty()
        }));
        if !matches!(initial, Ok(true)) {
            eprintln!("DOCKERLENS_NATIVE_GROUP_FAILURE: group={name} reason=preflight");
            failed = true;
            break;
        }
        let mut group_evidence = ProbeEvidence::default();
        let probe_ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            probe(&mut run, &mut group_evidence);
        }))
        .is_ok();
        let cleaned = run.cleanup_verified();
        let uncertain = run.uncertain_mutation.get();
        let decision = group_decision(probe_ok, cleaned, uncertain);
        mark_container_flow("decision", group_decision_outcome(decision));
        match decision {
            GroupDecision::Merge => evidence.merge(group_evidence),
            GroupDecision::ContinueFailed => {
                eprintln!("DOCKERLENS_NATIVE_GROUP_FAILURE: group={name} reason=probe");
                failed = true;
            }
            GroupDecision::StopCleanup => {
                eprintln!(
                    "DOCKERLENS_NATIVE_GROUP_FAILURE: group={name} reason=cleanup_unverified"
                );
                failed = true;
                break;
            }
            GroupDecision::StopUncertain => {
                eprintln!(
                    "DOCKERLENS_NATIVE_GROUP_FAILURE: group={name} reason=mutation_uncertain"
                );
                failed = true;
                break;
            }
        }
    }
    assert!(!failed, "closed native group failure");
    let closed = evidence.complete();
    fs::write(path, serde_json::to_vec(&closed).unwrap()).expect("private closed probe output");
}

type GroupProbe = fn(&mut NativeRun, &mut ProbeEvidence);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupDecision {
    Merge,
    ContinueFailed,
    StopCleanup,
    StopUncertain,
}

fn group_decision(probe_ok: bool, cleaned: bool, uncertain: bool) -> GroupDecision {
    if !cleaned {
        GroupDecision::StopCleanup
    } else if uncertain {
        GroupDecision::StopUncertain
    } else if probe_ok {
        GroupDecision::Merge
    } else {
        GroupDecision::ContinueFailed
    }
}

fn group_decision_outcome(decision: GroupDecision) -> &'static str {
    match decision {
        GroupDecision::Merge => "merge",
        GroupDecision::ContinueFailed => "probe_failed",
        GroupDecision::StopCleanup => "cleanup_unverified",
        GroupDecision::StopUncertain => "mutation_uncertain",
    }
}

#[test]
fn failed_control_start_and_failed_probe_cannot_become_continuation_or_pass() {
    for status in [Some(1), Some(125), Some(124), Some(137), None] {
        let (outcome, uncertain) = resource_control_start_outcome(status);
        assert!(matches!(outcome, "timeout" | "uncertain"));
        assert!(uncertain);
        assert!(!resource_control_may_continue(uncertain, 180));
        let decision = group_decision(false, true, uncertain);
        assert_eq!(decision, GroupDecision::StopUncertain);
        assert_eq!(group_decision_outcome(decision), "mutation_uncertain");
    }
    let (outcome, uncertain) = resource_control_start_outcome(Some(0));
    assert_eq!(outcome, "started");
    assert!(!uncertain);
    assert!(resource_control_may_continue(uncertain, 75));
    assert!(!resource_control_may_continue(uncertain, 74));
    assert_eq!(
        group_decision_outcome(group_decision(false, true, false)),
        "probe_failed"
    );
    assert_eq!(
        group_decision_outcome(group_decision(true, true, false)),
        "merge"
    );
}

#[test]
fn group_failure_never_merges_or_continues_without_proven_cleanup() {
    assert_eq!(group_decision(true, true, false), GroupDecision::Merge);
    assert_eq!(
        group_decision(false, true, false),
        GroupDecision::ContinueFailed
    );
    for probe_ok in [true, false] {
        for uncertain in [true, false] {
            assert_eq!(
                group_decision(probe_ok, false, uncertain),
                GroupDecision::StopCleanup
            );
        }
        assert_eq!(
            group_decision(probe_ok, true, true),
            GroupDecision::StopUncertain
        );
    }
}

const GROUPS: [(&str, GroupProbe); 5] = [
    ("ports", probe_port_group),
    ("identity_health_clear", probe_identity_health_clear_group),
    ("storage_lifecycle", probe_storage_lifecycle_group),
    ("resources_security", probe_resources_security_group),
    ("resolver_logging", probe_resolver_logging_group),
];

fn probe_port_group(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    assert_exact_mode_boundary(run);
    probe_ports(run, evidence);
    probe_complementary_ports(run, evidence);
}

fn probe_identity_health_clear_group(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    probe_identity_and_health(run, evidence);
    probe_health_start_period_zero(run, evidence);
    probe_clear_and_start_interval(run, evidence);
}

fn probe_storage_lifecycle_group(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    probe_storage_and_lifecycle(run, evidence);
    probe_false_storage_and_zero_stop(run, evidence);
}

fn probe_resources_security_group(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    probe_resources_and_security(run, evidence);
    probe_unlimited_resources_and_cap_add(run, evidence);
}

fn probe_resolver_logging_group(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    probe_resolver_and_logging(run, evidence);
    probe_ipv6_resolver(run, evidence);
    probe_alternative_logging(run, evidence);
}
