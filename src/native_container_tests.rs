//! Test-only, isolated Engine probes for the typed container target contract.
//! The product renderer remains inert; this module alone applies synthetic requests.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const NATIVE_CLI_STREAM_LIMIT: usize = 8192;

fn cli_failure_exit(status: std::process::ExitStatus) -> &'static str {
    match status.code() {
        Some(124) => "timeout",
        Some(137) | None => "signal",
        _ => "other",
    }
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
    } else {
        "unknown"
    }
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

fn bounded_native_cli_output(command: &mut Command, input: Option<&[u8]>) -> std::process::Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .expect("bounded private native CLI available");
    if let Some(input) = input {
        assert!(input.len() <= 4096, "bounded synthetic CLI input");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input)
            .expect("write bounded CLI input");
    }
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
            bounded_native_cli_output(&mut command, None);
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
        ));
        assert!(
            self.expected_negative.insert((shape, reason)),
            "duplicate expected negative"
        );
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
    created: Vec<(String, String)>,
    images: Vec<String>,
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
            created: Vec::new(),
            images: Vec::new(),
        }
    }

    fn name(&self, suffix: &str) -> String {
        assert!(valid_container_suffix(suffix));
        format!("dl-container-{}-{suffix}", self.run_id)
    }

    fn api(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Vec<u8>) {
        assert!(matches!(method, "GET" | "POST" | "DELETE"));
        assert!(path.starts_with(&format!("/v{}/containers/", self.api_version)));
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
            let category = if output.status.code() == Some(28) {
                "timeout"
            } else {
                "other"
            };
            eprintln!("DOCKERLENS_NATIVE_API_DIAG: transport={category}");
        }
        assert!(
            output.status.success(),
            "bounded Engine API transport failed"
        );
        let split = output
            .stdout
            .iter()
            .rposition(|byte| *byte == b'\n')
            .expect("HTTP status");
        let status = std::str::from_utf8(&output.stdout[split + 1..])
            .unwrap()
            .parse()
            .expect("numeric HTTP status");
        (status, output.stdout[..split].to_vec())
    }

    fn cli(&self, args: &[String]) -> String {
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
        ]);
        command.args(args);
        let output = bounded_native_cli_output(&mut command, None);
        if !output.status.success() {
            eprintln!(
                "DOCKERLENS_NATIVE_CLI_DIAG: exit={} stderr={}",
                cli_failure_exit(output.status),
                cli_failure_stderr(&output.stderr)
            );
        }
        assert!(output.status.success(), "independent CLI oracle failed");
        String::from_utf8(output.stdout).expect("CLI output UTF-8")
    }

    fn outer_exec(&self, args: &[&str], seconds: &str) -> std::process::Output {
        let mut command = Command::new("timeout");
        command.args(["--kill-after=1", seconds]);
        if required("NATIVE_PODMAN_USE_SUDO") == "1" {
            command.args(["sudo", "-n", "podman"]);
        } else {
            command.arg("podman");
        }
        let outer = format!("dl-native-{}", self.run_id);
        command.args(["exec", &outer]);
        command.args(args);
        bounded_native_cli_output(&mut command, None)
    }

    fn require_outer_curl(&self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: container_outer_curl_preflight");
        let output = self.outer_exec(&["curl", "--version"], "8");
        if !output.status.success() {
            eprintln!(
                "DOCKERLENS_NATIVE_HTTP_DIAG: exit={} category={}",
                cli_failure_exit(output.status),
                cli_failure_stderr(&output.stderr)
            );
        }
        assert!(output.status.success(), "outer namespace curl is required");
    }

    fn require_outer_bash(&self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: container_outer_bash_preflight");
        let output = self.outer_exec(&["bash", "--version"], "8");
        if !output.status.success() {
            eprintln!(
                "DOCKERLENS_NATIVE_CLI_DIAG: exit={} stderr={}",
                cli_failure_exit(output.status),
                cli_failure_stderr(&output.stderr)
            );
        }
        assert!(output.status.success(), "outer namespace bash is required");
    }

    fn try_outer_http(&self, url: &str) -> Result<String, (&'static str, &'static str)> {
        let output = self.outer_exec(
            &[
                "curl",
                "--noproxy",
                "*",
                "--proxy",
                "",
                "--globoff",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "2",
                "--max-time",
                "3",
                "--max-filesize",
                "8192",
                url,
            ],
            "8",
        );
        if !output.status.success() {
            return Err((
                cli_failure_exit(output.status),
                cli_failure_stderr(&output.stderr),
            ));
        }
        Ok(String::from_utf8(output.stdout).expect("bounded outer HTTP UTF-8"))
    }

    fn assert_published_http(&self, url: &str, expected: &str, local_ipv6: Option<bool>) {
        let mut outcome = ("other", "unknown");
        for attempt in 0..5 {
            match self.try_outer_http(url) {
                Ok(body) if body == expected => return,
                Ok(_) => outcome = ("success", "body_mismatch"),
                Err(category) => outcome = category,
            }
            if attempt < 4 {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
        if let Some(local_ipv6) = local_ipv6 {
            eprintln!(
                "DOCKERLENS_NATIVE_IPV6_DIAG: local_service={}",
                if local_ipv6 { "pass" } else { "fail" }
            );
        }
        eprintln!(
            "DOCKERLENS_NATIVE_HTTP_DIAG: exit={} category={}",
            outcome.0, outcome.1
        );
        panic!("closed published endpoint HTTP assertion failed");
    }

    fn cli_with_stdin(&self, args: &[String], input: &[u8]) -> String {
        assert!(input.len() <= 4096, "bounded synthetic Dockerfile");
        let mut command = Command::new("timeout");
        command.args(["--kill-after=1", "60"]);
        if required("NATIVE_PODMAN_USE_SUDO") == "1" {
            command.args(["sudo", "-n", "podman"]);
        } else {
            command.arg("podman");
        }
        command.args([
            "exec",
            "-i",
            &required("NATIVE_OUTER_CONTAINER"),
            "docker",
            "-H",
            "unix:///dockerlens-native/docker.sock",
        ]);
        command.args(args);
        let output = bounded_native_cli_output(&mut command, Some(input));
        if !output.status.success() {
            eprintln!(
                "DOCKERLENS_NATIVE_CLI_DIAG: exit={} stderr={}",
                cli_failure_exit(output.status),
                cli_failure_stderr(&output.stderr)
            );
        }
        assert!(
            output.status.success(),
            "independent derived image build failed"
        );
        String::from_utf8(output.stdout).expect("bounded CLI build output UTF-8")
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
        let id = self.cli(&args).trim().to_owned();
        assert_eq!(id.len(), 64, "CLI-created container ID");
        self.created.push((name, id.clone()));
        mark_port_stage(suffix, "cli_inspect");
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
        assert_eq!(
            body, expected_body,
            "closed independently authored create body"
        );
        let expected_path = format!("/v{}/containers/create?name={name}", self.api_version);
        mark_port_stage(suffix, "api_create");
        let (status, response) = self.api("POST", &expected_path, Some(&body));
        assert_native_api_status(status, 201);
        let created: Value = serde_json::from_slice(&response).expect("private create response");
        let id = created["Id"]
            .as_str()
            .expect("created container ID")
            .to_owned();
        self.created.push((name, id.clone()));
        mark_port_stage(suffix, "api_inspect");
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
        let inspected = self.inspect(id);
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

    fn cleanup(mut self) {
        while let Some((_, id)) = self.created.last().cloned() {
            self.delete(&id);
        }
        while let Some(image) = self.images.pop() {
            let inspected = self.cli(&["image".into(), "inspect".into(), image.clone()]);
            let inspected: Value = serde_json::from_str(&inspected).unwrap();
            assert_eq!(
                inspected[0]["Config"]["Labels"]["io.dockerlens.native-run"],
                self.run_id
            );
            self.cli(&["image".into(), "rm".into(), image]);
        }
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
        let image = format!("{}:local", self.name(&format!("{suffix}-image")));
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
        let image = format!("{}:local", self.name("health-default-image"));
        let dockerfile = format!(
            "FROM {}\nLABEL io.dockerlens.native-run={}\nHEALTHCHECK --interval=1s --timeout=1s --retries=2 CMD /bin/false\n",
            self.image, self.run_id
        );
        self.cli_with_stdin(
            &[
                "build".into(),
                "--pull=false".into(),
                "--network=none".into(),
                "-t".into(),
                image.clone(),
                "-".into(),
            ],
            dockerfile.as_bytes(),
        );
        self.images.push(image.clone());
        let inspected = self.cli(&["image".into(), "inspect".into(), image.clone()]);
        let inspected: Value = serde_json::from_str(&inspected).unwrap();
        assert_eq!(
            inspected[0]["Config"]["Healthcheck"]["Test"],
            json!(["CMD-SHELL", "/bin/false"])
        );
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
    let isolated = run.try_outer_http("http://127.0.0.2:18110/index.html");
    mark_port_stage("port-rendered", "isolated_assert");
    assert!(
        matches!(isolated, Err((_, "connection_refused"))),
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
    let sent = run.outer_exec(
        &[
            "bash",
            "-c",
            "printf '%s' \"$1\" >\"/dev/udp/127.0.0.1/$2\"",
            "udp-probe",
            "native-udp-canary",
            &assigned,
        ],
        "8",
    );
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
    mark_port_stage("ipv6-oracle", "cli_create");
    let oracle = run.cli_create(
        "ipv6-oracle",
        &["--publish=[::1]:18112:8083/tcp".to_owned()],
        &["sh", "-c", ipv6_script],
    );
    mark_port_stage("ipv6-oracle", "oracle_bindings");
    assert_port_binding(&oracle, "8083/tcp", "::1", "18112");
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    mark_port_stage("ipv6-oracle", "oracle_start");
    start_container(run, &oracle_id);
    assert_ipv6_traffic(run, &oracle_id, "ipv6-oracle");
    mark_port_stage("ipv6-oracle", "oracle_cleanup");
    run.delete(&oracle_id);
    let mut container = bare_container(&run.image);
    container.command =
        ImageCommand::Exec(vec![argument("sh"), argument("-c"), argument(ipv6_script)]);
    container.ports = vec![
        PortPublication::published(
            NonZeroU16::new(8083).unwrap(),
            Protocol::Tcp,
            vec![HostBinding {
                host_ip: PortHostIp::Address("::1".parse().unwrap()),
                host_port: PortHostPort::Fixed(NonZeroU16::new(18112).unwrap()),
            }],
        )
        .unwrap(),
    ];
    let expected_body = json!({
        "Image":run.image, "Cmd":["sh","-c",ipv6_script],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "ExposedPorts":{"8083/tcp":{}},
        "HostConfig":{"PortBindings":{"8083/tcp":[
            {"HostIp":"::1","HostPort":"18112"}
        ]}}
    });
    let (id, body, inspected) = run.rendered_create(
        "ipv6-rendered",
        container,
        &[
            Capability::Command,
            Capability::PortPublish,
            Capability::PortHostIpv6,
        ],
        expected_body,
    );
    mark_port_stage("ipv6-rendered", "rendered_bindings");
    assert_eq!(
        body["HostConfig"]["PortBindings"]["8083/tcp"],
        json!([
            {"HostIp":"::1","HostPort":"18112"}
        ])
    );
    assert_port_binding(&inspected, "8083/tcp", "::1", "18112");
    mark_port_stage("ipv6-rendered", "api_start");
    let (status, _) = run.api(
        "POST",
        &format!("/v{}/containers/{id}/start", run.api_version),
        None,
    );
    assert_native_api_status(status, 204);
    assert_ipv6_traffic(run, &id, "ipv6-rendered");
    evidence.positive("FixedIpv6HostPort");
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
        Some(local_ipv6),
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
    mark_port_stage("ipv6-dynamic-oracle", "cli_create");
    let ipv6_oracle = run.cli_create(
        "ipv6-dynamic-oracle",
        &["--publish=[::1]::8084/tcp".into()],
        &["sh", "-c", ipv6_script],
    );
    mark_port_stage("ipv6-dynamic-oracle", "oracle_bindings");
    assert_port_binding(&ipv6_oracle, "8084/tcp", "::1", "");
    let ipv6_oracle_id = ipv6_oracle["Id"].as_str().unwrap().to_owned();
    mark_port_stage("ipv6-dynamic-oracle", "oracle_start");
    start_container(run, &ipv6_oracle_id);
    assert_dynamic_http(
        run,
        &ipv6_oracle_id,
        "8084/tcp",
        "::1",
        "ipv6-dynamic-oracle",
    );
    let mut container = bare_container(&run.image);
    container.command =
        ImageCommand::Exec(vec![argument("sh"), argument("-c"), argument(ipv6_script)]);
    container.ports = vec![
        PortPublication::published(
            NonZeroU16::new(8084).unwrap(),
            Protocol::Tcp,
            vec![HostBinding {
                host_ip: PortHostIp::Address("::1".parse().unwrap()),
                host_port: PortHostPort::Ephemeral,
            }],
        )
        .unwrap(),
    ];
    let expected = json!({
        "Image":run.image,"Cmd":["sh","-c",ipv6_script],
        "Labels":{"io.dockerlens.native-run":run.run_id},
        "ExposedPorts":{"8084/tcp":{}},
        "HostConfig":{"PortBindings":{"8084/tcp":[{"HostIp":"::1","HostPort":""}]}}
    });
    let (id, body, inspected) = run.rendered_create(
        "ipv6-dynamic-rendered",
        container,
        &[
            Capability::Command,
            Capability::PortPublish,
            Capability::PortHostIpv6,
            Capability::PortEphemeral,
        ],
        expected,
    );
    mark_port_stage("ipv6-dynamic-rendered", "rendered_bindings");
    assert_eq!(
        body["HostConfig"]["PortBindings"],
        ipv6_oracle["HostConfig"]["PortBindings"]
    );
    assert_eq!(
        inspected["HostConfig"]["PortBindings"],
        ipv6_oracle["HostConfig"]["PortBindings"]
    );
    mark_port_stage("ipv6-dynamic-rendered", "api_start");
    start_container(run, &id);
    assert_dynamic_http(run, &id, "8084/tcp", "::1", "ipv6-dynamic-rendered");
    evidence.positive("EphemeralIpv6HostPort");

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
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_health_disabled_image_build");
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
    let default = run.cli_create_image("command-default-oracle", &[], &command_image, &[]);
    let default_id = default["Id"].as_str().unwrap().to_owned();
    assert_eq!(default["Config"]["Cmd"], json!(["-c", "exit 7"]));
    assert_eq!(start_and_wait(run, &default_id), 7);
    let (literal_id, literal) = run.literal_create(
        "clear-command-literal",
        json!({"Image":command_image,"Cmd":[]}),
    );
    assert_ne!(literal["Config"]["Cmd"], default["Config"]["Cmd"]);
    assert_eq!(
        literal["Config"]["Entrypoint"],
        default["Config"]["Entrypoint"]
    );
    assert_eq!(start_and_wait(run, &literal_id), 0);
    let mut container = bare_container(&command_image);
    container.command = ImageCommand::Clear;
    let expected_body = json!({
        "Image":command_image, "Cmd":[],
        "Labels":{"io.dockerlens.native-run":run.run_id}, "HostConfig":{}
    });
    let (id, body, inspected) = run.rendered_create(
        "clear-command-rendered",
        container,
        &[Capability::CommandClear],
        expected_body,
    );
    assert_eq!(body["Cmd"], json!([]));
    assert!(body.get("Entrypoint").is_none());
    assert_eq!(inspected["Config"]["Cmd"], literal["Config"]["Cmd"]);
    assert_eq!(
        inspected["Config"]["Entrypoint"],
        literal["Config"]["Entrypoint"]
    );
    assert_eq!(start_and_wait(run, &id), 0);
    evidence.positive("ClearCommand");

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
    let (status, _) = run.api(
        "POST",
        &format!("/v{}/containers/{id}/start", run.api_version),
        None,
    );
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

fn assert_resource_effects(run: &NativeRun, id: &str) {
    let limits = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "ulimit -Sn; ulimit -Hn".into(),
    ]);
    assert_eq!(limits.lines().collect::<Vec<_>>(), ["1024", "2048"]);
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
        "SYS_ADMIN removed from capability bound"
    );
    let groups = run.cli(&["exec".into(), id.into(), "id".into(), "-G".into()]);
    assert!(groups.split_whitespace().any(|group| group == "27"));
    let sysctl = run.cli(&[
        "exec".into(),
        id.into(),
        "cat".into(),
        "/proc/sys/net/ipv4/ip_forward".into(),
    ]);
    assert_eq!(sysctl.trim(), "0");
    let device = run.cli(&[
        "exec".into(), id.into(), "sh".into(), "-c".into(),
        "if test -c /dev/native-null && cat /dev/native-null >/dev/null; then printf present; else printf absent; fi".into(),
    ]);
    assert_eq!(device, "present");
    let memory = run.cli(&[
        "exec".into(), id.into(), "sh".into(), "-c".into(),
        "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes".into(),
    ]);
    assert_eq!(
        memory.trim(),
        "67108864",
        "memory cgroup limit is effective"
    );
    let pids = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max".into(),
    ]);
    assert_eq!(pids.trim(), "32", "PID cgroup limit is effective");
    let shm = run.cli(&[
        "exec".into(),
        id.into(),
        "sh".into(),
        "-c".into(),
        "df -k /dev/shm | tail -n 1 | awk '{print $2}'".into(),
    ]);
    assert_eq!(shm.trim(), "32768", "shared-memory mount size is effective");
}

fn probe_resources_and_security(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_resources_security");
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
    let host = &oracle["HostConfig"];
    assert_eq!(host["Memory"], 67_108_864);
    assert_eq!(host["PidsLimit"], 32);
    assert_eq!(host["ShmSize"], 33_554_432);
    assert_eq!(
        host["Ulimits"][0],
        json!({"Name":"nofile","Soft":1024,"Hard":2048})
    );
    assert_eq!(host["CapDrop"], json!(["SYS_ADMIN"]));
    assert_eq!(host["Sysctls"]["net.ipv4.ip_forward"], "0");
    assert!(
        host["SecurityOpt"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item == "no-new-privileges:true" })
    );
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    start_container(run, &oracle_id);
    assert_resource_effects(run, &oracle_id);

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
    for key in [
        "Memory",
        "PidsLimit",
        "ShmSize",
        "Ulimits",
        "CapDrop",
        "Sysctls",
    ] {
        assert_eq!(inspected["HostConfig"][key], oracle["HostConfig"][key]);
    }
    start_container(run, &id);
    assert_resource_effects(run, &id);
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

fn assert_resolver_and_logging(run: &NativeRun, id: &str) {
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
    let hosts = run.cli(&["exec".into(), id.into(), "cat".into(), "/etc/hosts".into()]);
    assert!(hosts.lines().any(|line| {
        line.split_whitespace().collect::<Vec<_>>() == ["10.0.0.2", "fixture.local"]
    }));
    let logs = run.cli(&["logs".into(), id.into()]);
    assert!(logs.contains("native-log-canary"));
}

fn probe_resolver_and_logging(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_resolver_logging");
    let command = "printf native-log-canary; sleep 120";
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
    start_container(run, &oracle_id);
    assert_resolver_and_logging(run, &oracle_id);

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
    for key in ["Dns", "ExtraHosts", "LogConfig"] {
        assert_eq!(inspected["HostConfig"][key], oracle["HostConfig"][key]);
    }
    start_container(run, &id);
    assert_resolver_and_logging(run, &id);
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

fn assert_ipv6_resolver_effects(run: &NativeRun, id: &str) {
    start_container(run, id);
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
    let hosts = run.cli(&["exec".into(), id.into(), "cat".into(), "/etc/hosts".into()]);
    assert!(hosts.lines().any(|line| {
        line.split_whitespace().collect::<Vec<_>>() == ["2001:db8::10", "fixture-v6.local"]
    }));
}

fn probe_ipv6_resolver(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: container_resolver_logging");
    let oracle = run.cli_create(
        "resolver-ipv6-oracle",
        &[
            "--dns=2001:4860:4860::8888".into(),
            "--add-host=fixture-v6.local:2001:db8::10".into(),
        ],
        &["sh", "-c", "sleep 120"],
    );
    let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
    assert_eq!(oracle["HostConfig"]["Dns"], json!(["2001:4860:4860::8888"]));
    assert_eq!(
        oracle["HostConfig"]["ExtraHosts"],
        json!(["fixture-v6.local:2001:db8::10"])
    );
    assert_ipv6_resolver_effects(run, &oracle_id);

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
    let (id, body, inspected) = run.rendered_create(
        "resolver-ipv6-rendered",
        container,
        &[Capability::DnsServers, Capability::ExtraHosts],
        expected,
    );
    for key in ["Dns", "ExtraHosts"] {
        assert_eq!(body["HostConfig"][key], oracle["HostConfig"][key]);
        assert_eq!(inspected["HostConfig"][key], oracle["HostConfig"][key]);
    }
    assert_ipv6_resolver_effects(run, &id);
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
    let output = bounded_native_cli_output(&mut command, None);
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
        let oracle = run.cli_create(
            &format!("log-{suffix}-oracle"),
            &[format!("--log-driver={name}")],
            &["sh", "-c", command],
        );
        let oracle_id = oracle["Id"].as_str().unwrap().to_owned();
        assert_eq!(
            oracle["HostConfig"]["LogConfig"],
            json!({"Type":name,"Config":{}})
        );
        start_container(run, &oracle_id);
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
        let (id, body, inspected) = run.rendered_create(
            &format!("log-{suffix}-rendered"),
            container,
            &[Capability::Command, Capability::LogConfig],
            expected,
        );
        assert_eq!(
            body["HostConfig"]["LogConfig"],
            oracle["HostConfig"]["LogConfig"]
        );
        assert_eq!(
            inspected["HostConfig"]["LogConfig"],
            oracle["HostConfig"]["LogConfig"]
        );
        start_container(run, &id);
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
    let mut run = NativeRun::new();
    let mut evidence = ProbeEvidence::default();
    assert_exact_mode_boundary(&run);
    probe_ports(&mut run, &mut evidence);
    probe_complementary_ports(&mut run, &mut evidence);
    probe_identity_and_health(&mut run, &mut evidence);
    probe_health_start_period_zero(&mut run, &mut evidence);
    probe_clear_and_start_interval(&mut run, &mut evidence);
    probe_storage_and_lifecycle(&mut run, &mut evidence);
    probe_false_storage_and_zero_stop(&mut run, &mut evidence);
    probe_resources_and_security(&mut run, &mut evidence);
    probe_unlimited_resources_and_cap_add(&mut run, &mut evidence);
    probe_resolver_and_logging(&mut run, &mut evidence);
    probe_ipv6_resolver(&mut run, &mut evidence);
    probe_alternative_logging(&mut run, &mut evidence);
    let closed = evidence.complete();
    run.cleanup();
    let path = PathBuf::from(required("NATIVE_CONTAINER_PROBES_PATH"));
    assert_eq!(
        path.parent(),
        Some(PathBuf::from(required("NATIVE_CAPTURE_DIR")).as_path())
    );
    fs::write(path, serde_json::to_vec(&closed).unwrap()).expect("private closed probe output");
}
