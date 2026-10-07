//! Ports-only native proof extracted from repository-owned #39 candidate 7345ea3.
//! Ignored live assertions do not admit a catalogue capability or run in product builds.
//! Rootful/rootless and every address-family shape require independent evidence.

use crate::acquisition::{
    AcquisitionError, DIAGNOSTIC_GET_BODY_LIMIT, DIAGNOSTIC_GET_WIRE_LIMIT, DiagnosticGetBudget,
    Endpoint, LimitError, Limits, NativeId, ReadRequest, Selector, acquire, diagnostic_get,
};
use crate::decoder::decode_capture;
use crate::evidence::CaptureRoute;
use crate::observation::ResourceRef;
use crate::target::{
    Argument, ContainerIntent, ContainerLabel, ContainerSettings, DockerApiRenderer, DockerPlanner,
    HostBinding, ImageCommand, ImageReference, Planner, PlanningError, PortHostIp, PortHostPort,
    PortPublication, Protocol, Renderer, TargetIdentity, TargetIntent, TargetResource,
};
use crate::version::{
    ApiVersion, Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonFacts,
    DaemonMode, EngineRelease, FactProvenance, ObservationId, ValidatedCapabilities,
};
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroU16;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing closed native ports input"))
}

fn canonical_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn owned(value: &Value, id: Option<&str>, name: &str, run: &str, image: &str) -> bool {
    value["Id"]
        .as_str()
        .is_some_and(|actual| canonical_id(actual) && id.is_none_or(|expected| actual == expected))
        && value["Name"] == format!("/{name}")
        && value["Config"]["Labels"][OWNER] == run
        && value["Config"]["Image"] == image
}

enum OwnedPortRemoval<'a> {
    Inspect(&'a str),
    Delete(&'a str),
}

fn verified_port_removal(
    name: &str,
    id: &str,
    run: &str,
    image: &str,
    mut request: impl FnMut(OwnedPortRemoval<'_>) -> (u16, Value),
) -> bool {
    let (status, value) = request(OwnedPortRemoval::Inspect(id));
    if status == 404 {
        return request(OwnedPortRemoval::Inspect(name)).0 == 404;
    }
    if status != 200 || !owned(&value, Some(id), name, run, image) {
        return false;
    }
    // Immediate immutable identity revalidation precedes ID-only removal.
    if request(OwnedPortRemoval::Delete(id)).0 != 204 {
        return false;
    }
    request(OwnedPortRemoval::Inspect(id)).0 == 404
        && request(OwnedPortRemoval::Inspect(name)).0 == 404
}

fn port_assertions_then_delete<S, T>(
    state: &mut S,
    assertions: impl FnOnce(&mut S) -> T,
    delete: impl FnOnce(&mut S),
) -> T {
    let outcome = assertions(state);
    delete(state);
    outcome
}

#[derive(Default)]
struct PortRemovalControl {
    live: bool,
    lingering_name: bool,
    trace: Vec<&'static str>,
}

fn fake_port_removal(
    control: &mut PortRemovalControl,
    name: &str,
    id: &str,
    inspected: &Value,
) -> bool {
    verified_port_removal(name, id, "Control01", "fixture", |request| match request {
        OwnedPortRemoval::Inspect(key) => {
            assert!(key == id || key == name);
            control.trace.push(if key == id {
                "inspect_id"
            } else {
                "inspect_name"
            });
            if control.live || (key == name && control.lingering_name) {
                (200, inspected.clone())
            } else {
                (404, Value::Null)
            }
        }
        OwnedPortRemoval::Delete(key) => {
            assert_eq!(key, id);
            control.trace.push("delete_id");
            control.live = false;
            (204, Value::Null)
        }
    })
}

#[test]
fn isolated_port_fixture_trace_checks_then_removes_before_next_create() {
    let fixtures: &[&[&str]] = &[
        &["http_primary", "http_secondary", "exposed_runtime", "udp"],
        &[
            "http_primary",
            "http_secondary",
            "exposed_runtime",
            "namespace_refusal",
            "udp",
        ],
        &["fixed_ipv6_oracle_boundary"],
        &["fixed_ipv6_rendered_boundary"],
        &["dynamic_ipv6_oracle_boundary"],
        &["dynamic_ipv6_rendered_boundary"],
        &["dynamic_http_primary", "dynamic_http_secondary"],
        &["dynamic_http_primary", "dynamic_http_secondary"],
    ];
    let mut control = PortRemovalControl::default();
    let mut ledger = Vec::new();
    for (index, checks) in fixtures.iter().enumerate() {
        assert!(!control.live);
        let id = format!("{index:064x}");
        let name = format!("dl-port-Control01-{index}");
        let inspected = json!({"Id":id,"Name":format!("/{name}"),
            "Config":{"Image":"fixture","Labels":{OWNER:"Control01"}}});
        control.trace.push("create");
        control.live = true;
        let start = control.trace.len();
        let outcome = port_assertions_then_delete(
            &mut control,
            |control| {
                control.trace.extend(checks.iter().copied());
                "independent_outcome"
            },
            |control| assert!(fake_port_removal(control, &name, &id, &inspected)),
        );
        assert_eq!(outcome, "independent_outcome");
        let mut expected = checks.to_vec();
        expected.extend(["inspect_id", "delete_id", "inspect_id", "inspect_name"]);
        assert_eq!(control.trace[start..], expected);
        ledger.push((name, id, inspected));
    }
    // Completed fixtures remain in the ledger. Two final absence rounds are idempotent.
    let completed = control.trace.len();
    for _ in 0..2 {
        for (name, id, inspected) in &ledger {
            assert!(fake_port_removal(&mut control, name, id, inspected));
        }
    }
    assert_eq!(control.trace[completed..].len(), fixtures.len() * 4);
    assert!(!control.trace[completed..].contains(&"delete_id"));
}

#[test]
fn isolated_port_fixture_failed_assertion_never_deletes_or_continues() {
    for failure in [
        "http_primary",
        "http_secondary",
        "exposed_runtime",
        "namespace_refusal",
        "udp",
    ] {
        let mut control = PortRemovalControl {
            live: true,
            ..PortRemovalControl::default()
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            port_assertions_then_delete(
                &mut control,
                |control| {
                    control.trace.push(failure);
                    panic!("closed fixture assertion failure");
                },
                |control| control.trace.push("delete_id"),
            );
            control.trace.push("next_create");
        }));
        assert!(result.is_err());
        assert!(control.live);
        assert_eq!(control.trace, vec![failure]);
    }
}

#[test]
fn isolated_port_fixture_removal_rejects_foreign_identity_and_incomplete_absence() {
    let id = "a".repeat(64);
    let name = "dl-port-Control01-fixture";
    let inspected = json!({"Id":id,"Name":format!("/{name}"),
        "Config":{"Image":"fixture","Labels":{OWNER:"Control01"}}});
    for pointer in [
        "/Id",
        "/Name",
        "/Config/Image",
        "/Config/Labels/io.dockerlens.native-run",
    ] {
        let mut foreign = inspected.clone();
        *foreign
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("closed control pointer")) = json!("foreign");
        let mut control = PortRemovalControl {
            live: true,
            ..PortRemovalControl::default()
        };
        assert!(!fake_port_removal(&mut control, name, &id, &foreign));
        assert!(control.live);
        assert_eq!(control.trace, vec!["inspect_id"]);
    }
    let mut control = PortRemovalControl {
        live: true,
        lingering_name: true,
        ..PortRemovalControl::default()
    };
    assert!(!fake_port_removal(&mut control, name, &id, &inspected));
    assert_eq!(
        control.trace,
        vec!["inspect_id", "delete_id", "inspect_id", "inspect_name"]
    );
}

fn private_stream(mut reader: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut overflow = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let count = reader
            .read(&mut buffer)
            .unwrap_or_else(|_| panic!("private port stream read"));
        if count == 0 {
            break;
        }
        let retain = count.min(cap - kept.len());
        kept.extend_from_slice(&buffer[..retain]);
        overflow |= retain < count;
    }
    (kept, overflow)
}

const PORT_SUFFIXES: [&str; 8] = [
    "port-oracle",
    "port-rendered",
    "ipv6-oracle",
    "ipv6-rendered",
    "ipv6-dynamic-oracle",
    "ipv6-dynamic-rendered",
    "multi-dynamic-oracle",
    "multi-dynamic-rendered",
];

fn repeated_start_timeouts(remaining: Duration) -> Option<(u64, u64)> {
    // Reserve forty seconds for cleanup, the existing one-second KILL grace,
    // and one further second for setup/reporting. Keep curl two seconds below
    // its outer timer, including when the shared deadline clips both limits.
    let outer = remaining.as_secs().checked_sub(42)?.min(26);
    let curl = outer.checked_sub(2)?.min(24);
    (curl > 0).then_some((curl, outer))
}

struct NativeRun {
    api_version: String,
    image: String,
    run_id: String,
    lane: String,
    candidate: String,
    mode: DaemonMode,
    engine_release: String,
    socket: String,
    outer_identity: Option<String>,
    attempted: BTreeSet<String>,
    created: Vec<(String, String)>,
    fact_source: Option<DaemonFacts>,
    deadline: Instant,
    epoch_deadline: SystemTime,
    calls: Cell<usize>,
    bytes: Cell<usize>,
    uncertain_mutation: Cell<bool>,
    cleaned: bool,
}

impl NativeRun {
    fn new() -> Self {
        let outer = required("NATIVE_OUTER_CONTAINER");
        let run_id = outer
            .strip_prefix("dl-native-")
            .unwrap_or_else(|| panic!("closed outer prefix"));
        assert!(
            run_id.len() == 8 && run_id.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "closed run token"
        );
        let lane = required("NATIVE_LANE");
        let api_version = required("NATIVE_API_VERSION");
        let mode = match required("NATIVE_DAEMON_MODE").as_str() {
            "rootful" => DaemonMode::Rootful,
            "rootless" => DaemonMode::Rootless,
            _ => panic!("closed daemon mode"),
        };
        assert!(
            matches!(lane.as_str(), "debian11-rootful" | "debian11-rootless")
                && api_version == "1.41"
                || matches!(lane.as_str(), "upstream-rootful" | "upstream-rootless")
                    && api_version == "1.56",
            "exact port lane/API"
        );
        assert!(
            lane.ends_with(if mode == DaemonMode::Rootless {
                "-rootless"
            } else {
                "-rootful"
            }),
            "exact port mode pairing"
        );
        let candidate = required("NATIVE_PORT_CANDIDATE_SHA");
        assert!(
            candidate.len() == 40
                && candidate
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "exact candidate token"
        );
        let cutoff = required("NATIVE_NETWORK_TEST_DEADLINE_EPOCH")
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("closed port deadline"));
        let epoch_deadline = UNIX_EPOCH + Duration::from_secs(cutoff);
        let remaining = epoch_deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .min(Duration::from_secs(180));
        assert!(
            remaining > Duration::from_secs(40),
            "shared port startup reserve"
        );
        let socket = required("NATIVE_ENGINE_SOCKET");
        assert!(socket.starts_with('/'), "explicit private engine socket");
        Self {
            api_version,
            image: required("NATIVE_FIXTURE_IMAGE"),
            run_id: run_id.into(),
            lane,
            candidate,
            mode,
            engine_release: String::new(),
            socket,
            outer_identity: None,
            attempted: BTreeSet::new(),
            created: Vec::new(),
            fact_source: None,
            deadline: Instant::now() + remaining,
            epoch_deadline,
            calls: Cell::new(0),
            bytes: Cell::new(0),
            uncertain_mutation: Cell::new(false),
            cleaned: false,
        }
    }

    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now()).min(
            self.epoch_deadline
                .duration_since(SystemTime::now())
                .unwrap_or_default(),
        )
    }

    fn timer(&self, cleanup: bool, elevated: bool, limit: u64) -> Command {
        let remaining = self.remaining().as_secs();
        assert!(
            remaining > if cleanup { 1 } else { 40 },
            "shared native port deadline/reserve"
        );
        let mut command = Command::new(if elevated { "sudo" } else { "timeout" });
        if elevated {
            command.args(["-n", "timeout"]);
        }
        command.args([
            "--signal=TERM",
            "--kill-after=1",
            &(remaining - 1).min(limit).to_string(),
        ]);
        command
    }

    fn elevated() -> bool {
        match required("NATIVE_PODMAN_USE_SUDO").as_str() {
            "0" => false,
            "1" => true,
            _ => panic!("closed Podman selector"),
        }
    }

    fn capture(
        &self,
        command: &mut Command,
        input: Option<&[u8]>,
        cap: usize,
    ) -> std::process::Output {
        self.calls.set(self.calls.get() + 1);
        assert!(self.calls.get() <= 512, "bounded port command count");
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .unwrap_or_else(|_| panic!("private port command spawn"));
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let out = std::thread::spawn(move || private_stream(stdout, cap));
        let err = std::thread::spawn(move || private_stream(stderr, NATIVE_CLI_STREAM_LIMIT));
        if let Some(input) = input {
            assert!(input.len() <= 8192, "bounded synthetic port request");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input)
                .unwrap_or_else(|_| panic!("private port request write"));
        }
        let status = child
            .wait()
            .unwrap_or_else(|_| panic!("bounded port command wait"));
        let (stdout, overflow) = out.join().unwrap();
        let (stderr, error_overflow) = err.join().unwrap();
        self.bytes
            .set(self.bytes.get() + stdout.len() + stderr.len());
        assert!(
            !overflow && !error_overflow && self.bytes.get() <= 8 * 1024 * 1024,
            "bounded private port output"
        );
        std::process::Output {
            status,
            stdout,
            stderr,
        }
    }

    fn name(&self, suffix: &str) -> String {
        assert!(
            PORT_SUFFIXES.contains(&suffix),
            "closed port fixture suffix"
        );
        format!("dl-port-{}-{suffix}", self.run_id)
    }

    fn debian_default_bridge_boundary(&self) -> bool {
        self.api_version == "1.41"
    }

    fn known_id(&self, id: &str) -> Option<&str> {
        self.created
            .iter()
            .find(|(_, registered)| registered == id)
            .map(|(name, _)| name.as_str())
    }

    fn start_window_identity(
        &self,
        method: &str,
        path: &str,
        cleanup: bool,
    ) -> Option<(&str, &str)> {
        if cleanup || method != "POST" {
            return None;
        }
        self.created
            .iter()
            .find(|(name, id)| {
                canonical_id(id)
                    && *name == self.name("multi-dynamic-oracle")
                    && path == format!("/v{}/containers/{id}/start", self.api_version)
            })
            .map(|(name, id)| (name.as_str(), id.as_str()))
    }

    fn repeated_start_uses_proxy_allowance(&self, method: &str, path: &str, cleanup: bool) -> bool {
        if cleanup
            || method != "POST"
            || self.lane != "debian11-rootless"
            || self.mode != DaemonMode::Rootless
            || self.api_version != "1.41"
            || !matches!(self.engine_release.as_str(), "20.10.5" | "20.10.5+dfsg1")
            || !self.fact_source.as_ref().is_some_and(|facts| {
                facts.mode == DaemonMode::Rootless
                    && facts.api_version == Some(ApiVersion::new(NonZeroU16::new(1).unwrap(), 41))
                    && facts
                        .release
                        .as_ref()
                        .is_some_and(|release| release.as_str() == self.engine_release)
            })
        {
            return false;
        }
        self.created.iter().any(|(name, id)| {
            canonical_id(id)
                && (name == &self.name("multi-dynamic-oracle")
                    || name == &self.name("multi-dynamic-rendered"))
                && self.known_id(id) == Some(name.as_str())
                && self
                    .created
                    .iter()
                    .filter(|(_, registered)| registered == id)
                    .count()
                    == 1
                && self
                    .created
                    .iter()
                    .filter(|(registered, _)| registered == name)
                    .count()
                    == 1
                && path == format!("/v1.41/containers/{id}/start")
        })
    }

    fn api_with_cleanup(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        cleanup: bool,
    ) -> (u16, Vec<u8>) {
        let prefix = format!("/v{}", self.api_version);
        let names = PORT_SUFFIXES
            .iter()
            .map(|suffix| self.name(suffix))
            .collect::<Vec<_>>();
        let read = names
            .iter()
            .map(String::as_str)
            .chain(self.created.iter().map(|(_, id)| id.as_str()))
            .any(|key| path == format!("{prefix}/containers/{key}/json"));
        let create = names.iter().any(|name| {
            path == format!("{prefix}/containers/create?name={name}")
                && self.attempted.contains(name)
        });
        let start = self
            .created
            .iter()
            .any(|(_, id)| path == format!("{prefix}/containers/{id}/start"));
        let delete = self
            .created
            .iter()
            .any(|(_, id)| path == format!("{prefix}/containers/{id}?force=1"));
        assert!(
            method == "GET" && (path == "/version" || path == format!("{prefix}/info") || read)
                || method == "POST" && (create || start)
                || method == "DELETE" && delete,
            "closed port API route"
        );
        let proxy_allowance = self.repeated_start_uses_proxy_allowance(method, path, cleanup);
        let request_timeouts = || {
            if proxy_allowance {
                repeated_start_timeouts(self.remaining())
                    .unwrap_or_else(|| panic!("shared repeated port start cleanup reserve"))
            } else {
                (8, 10)
            }
        };
        let _ = request_timeouts();
        let previous = self.uncertain_mutation.get();
        if method != "GET" {
            self.uncertain_mutation.set(true);
        }
        let input = body.map(|value| serde_json::to_vec(value).unwrap());
        // This private record is observation context, never a native proof.
        // Publication is best effort and must not change the original request.
        let start_window = self
            .start_window_identity(method, path, cleanup)
            .and_then(|(name, id)| PrivateStartWindow::begin(self, name, id));
        // Recompute after publication so its elapsed time cannot consume the
        // extended request's cleanup reserve. This check precedes request I/O.
        let (curl_seconds, outer_seconds) = request_timeouts();
        let mut command = self.timer(cleanup, false, outer_seconds);
        command.args([
            "curl",
            "-q",
            "--noproxy",
            "*",
            "-sS",
            "--max-time",
            &curl_seconds.to_string(),
            "--max-filesize",
            "131072",
            "--unix-socket",
            &self.socket,
            "-X",
            method,
            "-H",
            "Content-Type: application/json",
        ]);
        if input.is_some() {
            command.args(["--data-binary", "@-"]);
        } else if method == "POST" {
            command.args(["--data-binary", ""]);
        }
        command.args(["-w", "\n%{http_code}", &format!("http://localhost{path}")]);
        let output = self.capture(&mut command, input.as_deref(), 131080);
        if !output.status.success() && matches!(output.status.code(), Some(28 | 124)) {
            if let Some(window) = start_window {
                window.finish_timeout();
            }
        }
        if !output.status.success() {
            let action = if method == "GET" && path == "/version" {
                "version"
            } else if method == "GET" && path == format!("{prefix}/info") {
                "info"
            } else if method == "GET"
                && names
                    .iter()
                    .any(|name| path == format!("{prefix}/containers/{name}/json"))
            {
                "inspect_name"
            } else if method == "GET" {
                "inspect_id"
            } else if method == "DELETE" {
                "delete"
            } else if create {
                "create"
            } else {
                "start"
            };
            eprintln!(
                "{}",
                closed_api_failure_diagnostic(action, cleanup, output.status.code())
            );
            eprintln!(
                "DOCKERLENS_NATIVE_API_DIAG: transport={}",
                if output.status.code() == Some(28) || output.status.code() == Some(124) {
                    "timeout"
                } else {
                    "other"
                }
            );
            if !cleanup && method == "POST" && start {
                if let Some((name, id)) = self.created.iter().find(|(name, id)| {
                    *name == self.name("multi-dynamic-oracle")
                        && path == format!("{prefix}/containers/{id}/start")
                }) {
                    eprintln!("DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: begin");
                    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.repeated_start_diagnostics(name, id)
                    }));
                    eprintln!("DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: end");
                    let (outcome, diagnostic) = match observed {
                        Ok(value) => value,
                        Err(_) => ("panic", StartDiagnostic::unknown()),
                    };
                    eprintln!(
                        "{}",
                        diagnostic.summary(outcome, self.uncertain_mutation.get())
                    );
                }
            }
        }
        assert!(
            output.status.success(),
            "completed port API transport required"
        );
        let split = output
            .stdout
            .iter()
            .rposition(|byte| *byte == b'\n')
            .unwrap_or_else(|| panic!("closed port HTTP framing"));
        let status = std::str::from_utf8(&output.stdout[split + 1..])
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|status| (100..=599).contains(status))
            .unwrap_or_else(|| panic!("closed port HTTP status"));
        if method != "GET" {
            self.uncertain_mutation.set(previous);
        }
        (status, output.stdout[..split].to_vec())
    }

    fn repeated_start_diagnostics(&self, name: &str, id: &str) -> (&'static str, StartDiagnostic) {
        let started = Instant::now();
        let Some(total) = start_diagnostic_budget(self.remaining()) else {
            return ("skipped", StartDiagnostic::unknown());
        };
        if !canonical_id(id)
            || self.known_id(id) != Some(name)
            || name != self.name("multi-dynamic-oracle")
        {
            return ("skipped", StartDiagnostic::unknown());
        }
        let api_minor = match self.api_version.as_str() {
            "1.41" => 41,
            "1.56" => 56,
            _ => return ("skipped", StartDiagnostic::unknown()),
        };
        let allowance = StartReadAllowance::new();
        let mut diagnostic = StartDiagnostic::unknown();
        diagnostic.version = match self.start_diagnostic_read(
            ReadRequest::DaemonVersion,
            None,
            started,
            total,
            &allowance,
        ) {
            Ok((value, limit))
                if value["Version"] == self.engine_release
                    && value["ApiVersion"] == self.api_version
                    && started.elapsed() < limit
                    && self.remaining() > Duration::from_secs(40) =>
            {
                "responsive"
            }
            Ok(_) => "unknown",
            Err(error) => diagnostic_read_outcome(error),
        };
        let api = ApiVersion::new(NonZeroU16::new(1).unwrap(), api_minor);
        match self.start_diagnostic_read(
            ReadRequest::InspectContainer(NativeId::new(id.to_owned()).unwrap()),
            Some(api),
            started,
            total,
            &allowance,
        ) {
            Ok((value, limit)) => {
                diagnostic.observe_container(&value, id, name, &self.run_id, &self.image);
                if started.elapsed() >= limit || self.remaining() <= Duration::from_secs(40) {
                    let version = diagnostic.version;
                    diagnostic = StartDiagnostic::unknown();
                    diagnostic.version = version;
                }
            }
            Err(error) => diagnostic.object = diagnostic_read_outcome(error),
        }
        if started.elapsed() >= total || self.remaining() <= Duration::from_secs(40) {
            // Preserve already completed version/error observations, but never
            // project a container classified after its shared window as live.
            if diagnostic.object == "responsive" {
                let version = diagnostic.version;
                diagnostic = StartDiagnostic::unknown();
                diagnostic.version = version;
            }
        }
        ("observed", diagnostic)
    }

    fn start_diagnostic_read(
        &self,
        request: ReadRequest,
        api: Option<ApiVersion>,
        started: Instant,
        total: Duration,
        allowance: &StartReadAllowance,
    ) -> Result<(Value, Duration), AcquisitionError> {
        let elapsed = started.elapsed();
        let reserve = self
            .remaining()
            .checked_sub(Duration::from_secs(40))
            .unwrap_or_default();
        let limit = total
            .min(elapsed.saturating_add(reserve))
            .min(elapsed.saturating_add(Duration::from_secs(2)));
        if allowance
            .cancelled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(AcquisitionError::Cancelled);
        }
        if reserve.is_zero() || limit <= elapsed {
            return Err(AcquisitionError::Deadline);
        }
        // Never spend the existing mutation/probe/cleanup counters.
        allowance.charge()?;
        let result = diagnostic_get(
            &Endpoint::unix_socket(PathBuf::from(&self.socket)),
            &request,
            api,
            DiagnosticGetBudget {
                started,
                total: limit,
                per_read: Duration::from_secs(2),
                max_body: DIAGNOSTIC_GET_BODY_LIMIT,
            },
            &allowance.cancelled,
        );
        if matches!(result, Err(AcquisitionError::Budget(_))) {
            allowance
                .cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let (status, bytes) = result?;
        if status.code() != 200 {
            return Err(AcquisitionError::Status);
        }
        let value = serde_json::from_slice(&bytes).map_err(|_| AcquisitionError::Protocol)?;
        if started.elapsed() >= limit || self.remaining() <= Duration::from_secs(40) {
            return Err(AcquisitionError::Deadline);
        }
        Ok((value, limit))
    }

    fn api(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Vec<u8>) {
        self.api_with_cleanup(method, path, body, false)
    }

    fn inspect_with_cleanup(&self, key: &str, cleanup: bool) -> (u16, Value) {
        let (status, body) = self.api_with_cleanup(
            "GET",
            &format!("/v{}/containers/{key}/json", self.api_version),
            None,
            cleanup,
        );
        let body = if status == 200 {
            serde_json::from_slice(&body).unwrap_or_else(|_| panic!("private port inspect JSON"))
        } else {
            Value::Null
        };
        (status, body)
    }

    fn inspect(&self, id: &str) -> Value {
        let name = self
            .known_id(id)
            .unwrap_or_else(|| panic!("registered port inspect ID"));
        let (status, value) = self.inspect_with_cleanup(id, false);
        assert_native_api_status(NativeApiOperation::Inspect, status, 200);
        assert!(
            owned(&value, Some(id), name, &self.run_id, &self.image),
            "current exact port identity"
        );
        value
    }

    fn cli_output(&self, args: &[String]) -> std::process::Output {
        assert!(
            matches!(
                args.first().map(String::as_str),
                Some("container" | "exec" | "info" | "version")
            ),
            "closed port CLI operation"
        );
        if args.first().is_some_and(|arg| arg == "exec") {
            self.inspect(args.get(1).unwrap_or_else(|| panic!("owned port exec ID")));
        }
        let previous = self.uncertain_mutation.get();
        let mutating = args
            .first()
            .is_some_and(|arg| matches!(arg.as_str(), "container" | "exec"));
        if mutating {
            self.uncertain_mutation.set(true);
        }
        let mut command = self.timer(false, Self::elevated(), 16);
        command.args([
            "podman",
            "exec",
            &required("NATIVE_OUTER_CONTAINER"),
            "docker",
            "-H",
            "unix:///dockerlens-native/docker.sock",
        ]);
        command.args(args);
        let output = self.capture(&mut command, None, NATIVE_CLI_STREAM_LIMIT);
        if output.status.success() {
            self.uncertain_mutation.set(previous);
        }
        output
    }

    fn cli(&self, args: &[String]) -> String {
        let output = self.cli_output(args);
        if !output.status.success() {
            eprintln!(
                "DOCKERLENS_NATIVE_CLI_DIAG: exit={} stderr={}",
                cli_failure_exit(output.status),
                cli_failure_stderr(&output.stderr)
            );
        }
        assert!(
            output.status.success(),
            "completed independent port CLI oracle"
        );
        String::from_utf8(output.stdout).unwrap_or_else(|_| panic!("private port CLI UTF-8"))
    }

    fn bind(&mut self, name: &str, id: &str) -> Value {
        assert!(canonical_id(id), "canonical port create ID");
        let (status, value) = self.inspect_with_cleanup(name, false);
        assert_eq!(status, 200);
        assert!(
            owned(&value, Some(id), name, &self.run_id, &self.image),
            "create response binds exact port name/owner/image"
        );
        assert!(
            self.created.iter().all(|(_, registered)| registered != id),
            "distinct port resource IDs"
        );
        self.created.push((name.into(), id.into()));
        value
    }

    fn cli_create(&mut self, suffix: &str, options: &[String], command: &[&str]) -> Value {
        let name = self.name(suffix);
        assert_eq!(self.inspect_with_cleanup(&name, false).0, 404);
        self.attempted.insert(name.clone());
        let mut args = vec![
            "container".into(),
            "create".into(),
            "--name".into(),
            name.clone(),
            "--label".into(),
            format!("{OWNER}={}", self.run_id),
        ];
        args.extend_from_slice(options);
        args.push(self.image.clone());
        args.extend(command.iter().map(|argument| (*argument).to_owned()));
        let id = self.cli(&args).trim().to_owned();
        mark_port_stage(suffix, "cli_inspect");
        self.bind(&name, &id)
    }

    fn rendered_create(
        &mut self,
        suffix: &str,
        container: ContainerIntent,
        capabilities: &[Capability],
        expected: Value,
    ) -> (String, Value, Value) {
        let name = self.name(suffix);
        mark_port_stage(suffix, "render");
        let body = self.render_only(suffix, container, capabilities);
        assert_eq!(body, expected);
        assert_eq!(self.inspect_with_cleanup(&name, false).0, 404);
        self.attempted.insert(name.clone());
        mark_port_stage(suffix, "api_create");
        let (status, response) = self.api(
            "POST",
            &format!("/v{}/containers/create?name={name}", self.api_version),
            Some(&body),
        );
        assert_native_api_status(NativeApiOperation::Create, status, 201);
        let response: Value = serde_json::from_slice(&response)
            .unwrap_or_else(|_| panic!("private port create JSON"));
        let id = response["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical rendered port ID"))
            .to_owned();
        mark_port_stage(suffix, "api_inspect");
        let inspected = self.bind(&name, &id);
        (id, body, inspected)
    }

    fn scoped_facts(&self, available: &[Capability]) -> DaemonFacts {
        let mut facts = self
            .fact_source
            .as_ref()
            .unwrap_or_else(|| panic!("actual port capture scope required"))
            .clone();
        let scope = CapabilityScope {
            observation_id: facts.observation_id,
            release: facts.release.clone().unwrap(),
            api_version: facts.api_version.unwrap(),
            mode: facts.mode,
        };
        facts.capabilities = available
            .iter()
            .copied()
            .map(|capability| CapabilityFact {
                capability,
                state: CapabilityState::Available,
                provenance: FactProvenance::NativeConformance,
                scope: Some(scope.clone()),
            })
            .collect();
        facts
    }

    fn remove_owned(&mut self, name: &str, id: &str, cleanup: bool) -> bool {
        verified_port_removal(
            name,
            id,
            &self.run_id,
            &self.image,
            |request| match request {
                OwnedPortRemoval::Inspect(key) => self.inspect_with_cleanup(key, cleanup),
                OwnedPortRemoval::Delete(id) => (
                    self.api_with_cleanup(
                        "DELETE",
                        &format!("/v{}/containers/{id}?force=1", self.api_version),
                        None,
                        cleanup,
                    )
                    .0,
                    Value::Null,
                ),
            },
        )
    }

    fn delete(&mut self, id: &str) {
        let name = self
            .known_id(id)
            .unwrap_or_else(|| panic!("registered port delete ID"))
            .to_owned();
        assert!(
            self.remove_owned(&name, id, false),
            "verified exact port oracle removal"
        );
    }

    fn complete_port_fixture<T>(&mut self, id: &str, assertions: impl FnOnce(&mut Self) -> T) -> T {
        port_assertions_then_delete(self, assertions, |run| run.delete(id))
    }

    fn cleanup(&mut self) -> bool {
        for name in self.attempted.clone() {
            let registered = self
                .created
                .iter()
                .find(|(known, _)| *known == name)
                .map(|(_, id)| id.clone());
            let (status, value) = self.inspect_with_cleanup(&name, true);
            if status == 404 {
                continue;
            }
            if status != 200
                || !owned(
                    &value,
                    registered.as_deref(),
                    &name,
                    &self.run_id,
                    &self.image,
                )
            {
                return false;
            }
            let id = value["Id"].as_str().unwrap().to_owned();
            if registered.is_none() {
                self.created.push((name.clone(), id.clone()));
            }
            if !self.remove_owned(&name, &id, true) {
                return false;
            }
        }
        for _ in 0..2 {
            for name in &self.attempted {
                if self.inspect_with_cleanup(name, true).0 != 404 {
                    return false;
                }
            }
            for (_, id) in &self.created {
                if self.inspect_with_cleanup(id, true).0 != 404 {
                    return false;
                }
            }
        }
        self.cleaned = true;
        true
    }

    fn cleanup_attempt(&mut self, attempt: &'static str) -> bool {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup()));
        let outcome = match &result {
            Ok(true) => "pass",
            Ok(false) => "fail",
            Err(_) => "panic",
        };
        eprintln!(
            "{}",
            closed_cleanup_diagnostic(
                attempt,
                outcome,
                self.remaining(),
                self.uncertain_mutation.get(),
            )
        );
        result.unwrap_or(false)
    }
}

fn closed_cleanup_diagnostic(
    attempt: &'static str,
    outcome: &'static str,
    remaining: Duration,
    uncertain: bool,
) -> String {
    assert!(matches!(attempt, "primary" | "drop"));
    assert!(matches!(outcome, "pass" | "fail" | "panic"));
    let reserve = match remaining.as_secs() {
        0..=1 => "exhausted",
        2..=40 => "low",
        _ => "reserved",
    };
    let mutation = if uncertain { "uncertain" } else { "clear" };
    format!(
        "DOCKERLENS_NATIVE_PORT_CLEANUP_DIAG: attempt={attempt} outcome={outcome} reserve={reserve} mutation={mutation}"
    )
}

#[test]
fn port_cleanup_summary_is_closed_and_uses_the_existing_reserve_thresholds() {
    for (seconds, reserve) in [
        (0, "exhausted"),
        (1, "exhausted"),
        (2, "low"),
        (40, "low"),
        (41, "reserved"),
    ] {
        for attempt in ["primary", "drop"] {
            for outcome in ["pass", "fail", "panic"] {
                for uncertain in [false, true] {
                    let diagnostic = closed_cleanup_diagnostic(
                        attempt,
                        outcome,
                        Duration::from_secs(seconds),
                        uncertain,
                    );
                    let mutation = if uncertain { "uncertain" } else { "clear" };
                    assert_eq!(
                        diagnostic,
                        format!(
                            "DOCKERLENS_NATIVE_PORT_CLEANUP_DIAG: attempt={attempt} outcome={outcome} reserve={reserve} mutation={mutation}"
                        )
                    );
                }
            }
        }
    }
    assert!(
        std::panic::catch_unwind(|| closed_cleanup_diagnostic(
            "protected-secret",
            "pass",
            Duration::ZERO,
            false
        ))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| closed_cleanup_diagnostic(
            "primary",
            "protected-secret",
            Duration::ZERO,
            false
        ))
        .is_err()
    );
}

impl Drop for NativeRun {
    fn drop(&mut self) {
        if !self.cleaned && !self.cleanup_attempt("drop") {
            eprintln!("DOCKERLENS_NATIVE_CHECK: port_cleanup_unverified");
        }
    }
}

impl NativeRun {
    fn context(&mut self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: port_context");
        self.require_outer_identity();
        let (status, bytes) = self.api("GET", "/version", None);
        assert_eq!(status, 200);
        let version: Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("private port version JSON"));
        let release = version["Version"]
            .as_str()
            .unwrap_or_else(|| panic!("observed Engine release"));
        assert_eq!(release, required("NATIVE_ENGINE_VERSION"));
        assert_eq!(version["ApiVersion"], self.api_version);
        assert!(
            if self.lane.starts_with("debian11-") {
                matches!(release, "20.10.5" | "20.10.5+dfsg1")
            } else {
                release == "29.8.1"
            },
            "exact observed Engine release"
        );
        self.engine_release = release.to_owned();
        let cli_version = self.cli(&[
            "version".into(),
            "--format".into(),
            "{{.Server.Version}}|{{.Server.APIVersion}}".into(),
        ]);
        assert_eq!(
            cli_version.trim_end_matches('\n'),
            format!("{}|{}", self.engine_release, self.api_version)
        );
        let (status, bytes) = self.api("GET", &format!("/v{}/info", self.api_version), None);
        assert_eq!(status, 200);
        let info: Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("private port info JSON"));
        let observed_rootless = info["Rootless"] == true
            || info["SecurityOptions"].as_array().is_some_and(|items| {
                items.iter().any(|item| {
                    item.as_str().is_some_and(|value| {
                        value == "name=rootless" || value.starts_with("name=rootless,")
                    })
                })
            });
        let cli_security: Vec<String> = serde_json::from_str(&self.cli(&[
            "info".into(),
            "--format".into(),
            "{{json .SecurityOptions}}".into(),
        ]))
        .unwrap_or_else(|_| panic!("private port CLI mode JSON"));
        assert_eq!(
            cli_security
                .iter()
                .any(|value| value == "name=rootless" || value.starts_with("name=rootless,")),
            observed_rootless
        );
        assert_eq!(observed_rootless, self.mode == DaemonMode::Rootless);
        let effective = self.dockerd_effective_uid();
        assert!(
            if observed_rootless {
                effective > 0
            } else {
                effective == 0
            },
            "exact-one dockerd effective UID corroborates mode"
        );
        let elapsed = self
            .remaining()
            .checked_sub(Duration::from_secs(40))
            .unwrap_or_else(|| panic!("capture cleanup reserve"));
        let capture = acquire(
            &Endpoint::unix_socket(PathBuf::from(&self.socket)),
            Selector::ContainerIds(vec![
                NativeId::new(required("NATIVE_CONTAINER_ID")).unwrap(),
            ]),
            Limits {
                max_requests: 16,
                max_selected_resources: 2,
                max_expansions: 8,
                max_response_bytes: 256 * 1024,
                max_total_bytes: 2 * 1024 * 1024,
                max_elapsed: elapsed.min(Duration::from_secs(15)),
            },
            &AtomicBool::new(false),
        )
        .unwrap_or_else(|_| panic!("actual bounded native port acquisition"));
        assert_eq!(capture.route(), CaptureRoute::ExplicitUnixSocket);
        assert!(
            capture
                .exchanges()
                .iter()
                .all(|exchange| exchange.status().code() == 200),
            "completed port capture exchanges"
        );
        let decoded = decode_capture(&capture)
            .unwrap_or_else(|_| panic!("actual native port capture decode"));
        let mut facts = decoded.version.daemon;
        assert_eq!(facts.observation_id, capture.observation_id());
        assert_eq!(
            facts.release.as_ref().unwrap().as_str(),
            self.engine_release
        );
        let api = facts.api_version.unwrap();
        assert_eq!(format!("{}.{}", api.major, api.minor), self.api_version);
        if observed_rootless {
            assert_eq!(facts.mode, DaemonMode::Rootless);
        } else {
            assert_ne!(facts.mode, DaemonMode::Rootless);
            // The independently observed zero effective UID above supplies
            // rootful mode without replacing observed release/API/capture ID.
            facts.mode = DaemonMode::Rootful;
        }
        self.fact_source = Some(facts);
    }

    fn dockerd_effective_uid(&self) -> u32 {
        // Same independent process oracle as the existing native target proof,
        // under this test's privilege-aware shared timer/output budget.
        let mut command = self.timer(false, Self::elevated(), 15);
        command.args([
            "podman",
            "exec",
            &required("NATIVE_OUTER_CONTAINER"),
            "sh",
            "-ec",
            r#"count=0; effective=
for status in /proc/[0-9]*/status; do
  [ -f "$status" ] || continue
  IFS= read -r comm < "${status%/status}/comm" || continue
  [ "$comm" = dockerd ] || continue
  count=$((count + 1))
  while read -r key real uid saved filesystem; do
    if [ "$key" = Uid: ]; then effective=$uid; break; fi
  done < "$status"
done
printf '%s:%s\n' "$count" "$effective""#,
        ]);
        let output = self.capture(&mut command, None, NATIVE_CLI_STREAM_LIMIT);
        assert!(
            output.status.success(),
            "completed inner dockerd UID oracle"
        );
        let text = std::str::from_utf8(&output.stdout)
            .unwrap_or_else(|_| panic!("private dockerd UID UTF-8"));
        let (count, effective) = text
            .trim_end_matches('\n')
            .split_once(':')
            .unwrap_or_else(|| panic!("closed dockerd UID framing"));
        assert!(
            count == "1"
                && !effective.is_empty()
                && effective.bytes().all(|value| value.is_ascii_digit()),
            "exactly-one numeric dockerd UID"
        );
        effective
            .parse()
            .unwrap_or_else(|_| panic!("bounded dockerd UID"))
    }

    fn namespace_probe(&self, mode: &str, argument: Option<&str>) -> std::process::Output {
        require_namespace_probe_mode(mode);
        let mut command = self.timer(false, Self::elevated(), 16);
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
        let output = self.capture(&mut command, None, NATIVE_CLI_STREAM_LIMIT);
        if !output.status.success() {
            if let Some(category) = namespace_failure_category(&output.stderr) {
                eprintln!("DOCKERLENS_NATIVE_NAMESPACE_DIAG: category={category}");
                panic!("closed outer namespace identity or probe failed");
            }
        }
        output
    }

    fn require_outer_identity(&mut self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: port_outer_identity");
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
        if let Some(previous) = &self.outer_identity {
            assert_eq!(
                previous.as_str(),
                identity,
                "outer identity must not refresh across port groups"
            );
        }
        self.outer_identity = Some(identity.to_owned());
    }

    fn require_outer_curl(&self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: port_host_curl_preflight");
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
        eprintln!("DOCKERLENS_NATIVE_CHECK: port_host_bash_preflight");
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
        Ok(String::from_utf8(output.stdout).unwrap_or_else(|_| panic!("private outer HTTP UTF-8")))
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
        let output = self.cli_output(&[
            "exec".into(),
            id.into(),
            "sh".into(),
            "-c".into(),
            "cat /proc/sys/net/ipv6/conf/all/disable_ipv6 /proc/sys/net/ipv6/conf/lo/disable_ipv6"
                .into(),
        ]);
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
            eprintln!("DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: begin");
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
            eprintln!("DOCKERLENS_NATIVE_PORT_DIAGNOSTIC_SCOPE: end");
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
}

const OWNER: &str = "io.dockerlens.native-run";

const START_WINDOW_FILE: &str = "port-start-window.json";

struct PrivateStartWindow {
    directory: PathBuf,
    held: File,
    file: File,
    record: Value,
    initial: Vec<u8>,
}

impl PrivateStartWindow {
    fn begin(run: &NativeRun, name: &str, id: &str) -> Option<Self> {
        let path = PathBuf::from(std::env::var("NATIVE_PORT_START_DIAGNOSTIC_PATH").ok()?);
        let capture = PathBuf::from(std::env::var("NATIVE_CAPTURE_DIR").ok()?);
        Self::begin_at(run, name, id, &capture, &path)
    }

    fn begin_at(
        run: &NativeRun,
        name: &str,
        id: &str,
        capture: &Path,
        path: &Path,
    ) -> Option<Self> {
        let outer_id = run.outer_identity.as_deref()?.split('|').next()?;
        if !canonical_id(outer_id)
            || !canonical_id(id)
            || run.known_id(id) != Some(name)
            || name != run.name("multi-dynamic-oracle")
        {
            return None;
        }
        if path.file_name()?.to_str()? != START_WINDOW_FILE {
            return None;
        }
        let directory = capture.join("diagnostics");
        if path != directory.join(START_WINDOW_FILE) {
            return None;
        }
        if !directory.is_absolute() || directory.canonicalize().ok()? != directory {
            return None;
        }
        let before = fs::symlink_metadata(&directory).ok()?;
        let owner = fs::metadata("/proc/self").ok()?.uid();
        if !before.is_dir() || before.uid() != owner || before.mode() & 0o7777 != 0o700 {
            return None;
        }
        let held = File::open(&directory).ok()?;
        if !same_start_metadata(&before, &held.metadata().ok()?) {
            return None;
        }
        let start = realtime_ns()?;
        let cutoff = run
            .epoch_deadline
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs();
        if start >= cutoff.checked_mul(1_000_000_000)? {
            return None;
        }
        let record = json!({
            "schemaVersion": 1,
            "phase": "multi_dynamic_oracle_start",
            "status": "pending",
            "runId": run.run_id,
            "lane": run.lane,
            "candidateSha": run.candidate,
            "outerId": outer_id,
            "outerName": format!("dl-native-{}", run.run_id),
            "createdId": id,
            "createdName": name,
            "apiVersion": run.api_version,
            "startRealtimeNs": start,
            "endRealtimeNs": null,
            "cutoffEpoch": cutoff,
        });
        let initial = serde_json::to_vec(&record).ok()?;
        let relative =
            PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd())).join(START_WINDOW_FILE);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(relative)
            .ok()?;
        file.write_all(&initial).ok()?;
        file.sync_all().ok()?;
        let window = Self {
            directory,
            held,
            file,
            record,
            initial,
        };
        window.unchanged().then_some(window)
    }

    fn unchanged(&self) -> bool {
        let checked = || -> Option<bool> {
            if self.directory.canonicalize().ok()? != self.directory {
                return None;
            }
            let parent = fs::symlink_metadata(&self.directory).ok()?;
            if !same_start_metadata(&parent, &self.held.metadata().ok()?) {
                return None;
            }
            let actual = self.file.metadata().ok()?;
            let named = fs::symlink_metadata(self.directory.join(START_WINDOW_FILE)).ok()?;
            Some(
                actual.is_file()
                    && actual.uid() == parent.uid()
                    && actual.mode() & 0o7777 == 0o600
                    && actual.nlink() == 1
                    && actual.len() <= 4096
                    && same_start_metadata(&actual, &named)
                    && actual.len() == named.len()
                    && actual.mtime() == named.mtime()
                    && actual.mtime_nsec() == named.mtime_nsec(),
            )
        };
        checked() == Some(true)
    }

    fn finish_timeout(mut self) {
        let mut finish = || -> Option<()> {
            let end = realtime_ns()?;
            let start = self.record["startRealtimeNs"].as_u64()?;
            let cutoff = self.record["cutoffEpoch"]
                .as_u64()?
                .checked_mul(1_000_000_000)?;
            if end < start || end > cutoff || !self.unchanged() {
                return None;
            }
            self.file.seek(SeekFrom::Start(0)).ok()?;
            let mut current = Vec::new();
            Read::by_ref(&mut self.file)
                .take(4097)
                .read_to_end(&mut current)
                .ok()?;
            if current != self.initial {
                return None;
            }
            let record = self.record.as_object_mut()?;
            record.insert("status".into(), json!("timeout"));
            record.insert("endRealtimeNs".into(), json!(end));
            let bytes = serde_json::to_vec(&self.record).ok()?;
            if bytes.len() > 4096 {
                return None;
            }
            self.file.seek(SeekFrom::Start(0)).ok()?;
            self.file.set_len(0).ok()?;
            self.file.write_all(&bytes).ok()?;
            self.file.sync_all().ok()?;
            self.unchanged().then_some(())
        };
        let _ = finish();
    }
}

fn same_start_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    (
        left.dev(),
        left.ino(),
        left.uid(),
        left.mode(),
        left.nlink(),
    ) == (
        right.dev(),
        right.ino(),
        right.uid(),
        right.mode(),
        right.nlink(),
    )
}

fn realtime_ns() -> Option<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos(),
    )
    .ok()
}

fn start_window_control_run() -> NativeRun {
    NativeRun {
        api_version: "1.41".into(),
        image: "protected-image".into(),
        run_id: "Test0001".into(),
        lane: "debian11-rootless".into(),
        candidate: "b".repeat(40),
        mode: DaemonMode::Rootless,
        engine_release: "20.10.5".into(),
        socket: "/private-unused".into(),
        outer_identity: Some(format!("{}|2|aa|1", "a".repeat(64))),
        attempted: BTreeSet::new(),
        created: vec![(
            "dl-port-Test0001-multi-dynamic-oracle".into(),
            "c".repeat(64),
        )],
        fact_source: None,
        deadline: Instant::now() + Duration::from_secs(180),
        epoch_deadline: SystemTime::now() + Duration::from_secs(180),
        calls: Cell::new(0),
        bytes: Cell::new(0),
        uncertain_mutation: Cell::new(true),
        cleaned: true,
    }
}

fn repeated_start_control_run() -> NativeRun {
    let mut run = start_window_control_run();
    run.fact_source = Some(offline_facts(DaemonMode::Rootless, 41));
    run.created
        .push((run.name("multi-dynamic-rendered"), "d".repeat(64)));
    run
}

#[test]
fn repeated_start_proxy_allowance_requires_exact_registered_roles_and_routes() {
    let run = repeated_start_control_run();
    for (name, id) in &run.created {
        let path = format!("/v1.41/containers/{id}/start");
        assert!(run.repeated_start_uses_proxy_allowance("POST", &path, false));
        assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, true));
        for method in ["GET", "DELETE", "post"] {
            assert!(!run.repeated_start_uses_proxy_allowance(method, &path, false));
        }
        for other in [
            format!("/v1.41/containers/{name}/start"),
            format!("/v1.56/containers/{id}/start"),
            format!("/v1.41/containers/{id}/json"),
            format!("/v1.41/containers/{id}/start?retry=1"),
            format!("/v1.41/containers/{}/start", "e".repeat(64)),
        ] {
            assert!(!run.repeated_start_uses_proxy_allowance("POST", &other, false));
        }
    }
    for suffix in PORT_SUFFIXES {
        let mut run = repeated_start_control_run();
        let name = run.name(suffix);
        run.created = vec![(name, "c".repeat(64))];
        assert_eq!(
            run.repeated_start_uses_proxy_allowance(
                "POST",
                &format!("/v1.41/containers/{}/start", "c".repeat(64)),
                false
            ),
            matches!(suffix, "multi-dynamic-oracle" | "multi-dynamic-rendered")
        );
    }
    let mut run = repeated_start_control_run();
    run.created[0].1 = "C".repeat(64);
    assert!(!run.repeated_start_uses_proxy_allowance(
        "POST",
        &format!("/v1.41/containers/{}/start", "C".repeat(64)),
        false
    ));
    let mut run = repeated_start_control_run();
    let path = format!("/v1.41/containers/{}/start", "c".repeat(64));
    run.created.push((run.name("port-oracle"), "c".repeat(64)));
    assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
    let mut run = repeated_start_control_run();
    run.created
        .push((run.name("multi-dynamic-oracle"), "e".repeat(64)));
    assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
}

#[test]
fn repeated_start_proxy_allowance_needs_observed_matching_rootless_release_api_facts() {
    let path = format!("/v1.41/containers/{}/start", "c".repeat(64));
    for lane in [
        "debian11-rootful",
        "upstream-rootful",
        "upstream-rootless",
        "debian11-rootless-extra",
    ] {
        let mut run = repeated_start_control_run();
        run.lane = lane.into();
        assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
    }
    for mode in [DaemonMode::Rootful, DaemonMode::Unknown] {
        let mut run = repeated_start_control_run();
        run.mode = mode;
        assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
        let mut run = repeated_start_control_run();
        run.fact_source.as_mut().unwrap().mode = mode;
        assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
    }
    for api in ["1.40", "1.56", "1.041", "2.41"] {
        let mut run = repeated_start_control_run();
        run.api_version = api.into();
        assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
    }
    for release in ["", "20.10.4", "20.10.50", "29.8.1", "20.10.5+unverified"] {
        let mut run = repeated_start_control_run();
        run.engine_release = release.into();
        assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
    }
    let mut run = repeated_start_control_run();
    run.fact_source = None;
    assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
    let mut run = repeated_start_control_run();
    run.fact_source.as_mut().unwrap().release = None;
    assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
    for api in [
        None,
        Some(ApiVersion::new(NonZeroU16::new(1).unwrap(), 40)),
        Some(ApiVersion::new(NonZeroU16::new(2).unwrap(), 41)),
    ] {
        let mut run = repeated_start_control_run();
        run.fact_source.as_mut().unwrap().api_version = api;
        assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
    }
    let mut run = repeated_start_control_run();
    run.fact_source.as_mut().unwrap().release = EngineRelease::new("20.10.4".into());
    assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
    run.engine_release = "20.10.5+dfsg1".into();
    assert!(!run.repeated_start_uses_proxy_allowance("POST", &path, false));
    run.fact_source.as_mut().unwrap().release = EngineRelease::new(run.engine_release.clone());
    assert!(run.repeated_start_uses_proxy_allowance("POST", &path, false));
}

#[test]
fn repeated_start_proxy_timeouts_clip_both_limits_and_never_borrow_cleanup_reserve() {
    for seconds in [0, 1, 40, 41, 42, 43, 44] {
        assert_eq!(repeated_start_timeouts(Duration::from_secs(seconds)), None);
    }
    for (seconds, expected) in [
        (45, (1, 3)),
        (46, (2, 4)),
        (50, (6, 8)),
        (67, (23, 25)),
        (68, (24, 26)),
        (180, (24, 26)),
    ] {
        let limits = repeated_start_timeouts(Duration::from_secs(seconds)).unwrap();
        assert_eq!(limits, expected);
        assert!(limits.0 > 0 && limits.0 + 2 == limits.1);
        assert!(seconds - limits.1 > 41);
    }
    assert_eq!(
        repeated_start_timeouts(Duration::from_secs(45) - Duration::from_nanos(1)),
        None
    );
    assert_eq!(
        repeated_start_timeouts(Duration::from_secs(68) - Duration::from_nanos(1)),
        Some((23, 25))
    );
}

#[test]
fn repeated_start_insufficient_reserve_prevents_request_and_mutation_uncertainty() {
    let mut run = repeated_start_control_run();
    run.deadline = Instant::now() + Duration::from_secs(44);
    run.epoch_deadline = SystemTime::now() + Duration::from_secs(44);
    run.uncertain_mutation.set(false);
    let path = format!("/v1.41/containers/{}/start", "c".repeat(64));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run.api_with_cleanup("POST", &path, None, false)
        }))
        .is_err()
    );
    assert_eq!(run.calls.get(), 0);
    assert_eq!(run.bytes.get(), 0);
    assert!(!run.uncertain_mutation.get());
}

#[test]
fn start_window_is_only_the_registered_canonical_oracle_post_without_cleanup() {
    let mut run = start_window_control_run();
    let name = run.name("multi-dynamic-oracle");
    let id = "c".repeat(64);
    let path = format!("/v1.41/containers/{id}/start");
    assert_eq!(
        run.start_window_identity("POST", &path, false),
        Some((name.as_str(), id.as_str()))
    );
    assert!(run.start_window_identity("POST", &path, true).is_none());
    assert!(run.start_window_identity("GET", &path, false).is_none());
    for other in [
        format!("/v1.41/containers/{name}/start"),
        format!("/v1.56/containers/{id}/start"),
        format!("/v1.41/containers/{id}/json"),
        format!("/v1.41/containers/{id}/start?retry=1"),
        format!("/v1.41/containers/{}/start", "d".repeat(64)),
    ] {
        assert!(run.start_window_identity("POST", &other, false).is_none());
    }
    run.created[0].0 = run.name("multi-dynamic-rendered");
    assert!(run.start_window_identity("POST", &path, false).is_none());
    run.created[0] = (name, "C".repeat(64));
    assert!(
        run.start_window_identity(
            "POST",
            &format!("/v1.41/containers/{}/start", "C".repeat(64)),
            false
        )
        .is_none()
    );
    assert_eq!(run.calls.get(), 0);
    assert_eq!(run.bytes.get(), 0);
    assert!(run.uncertain_mutation.get());
}

#[test]
fn private_start_window_is_separate_pending_then_timeout_without_overwrite_or_proof() {
    let run = start_window_control_run();
    let directory = std::env::temp_dir().join(format!(
        "dockerlens-start-test-{}-{}",
        std::process::id(),
        realtime_ns().unwrap()
    ));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let diagnostics = directory.join("diagnostics");
    fs::create_dir(&diagnostics).unwrap();
    fs::set_permissions(&diagnostics, fs::Permissions::from_mode(0o700)).unwrap();
    let path = diagnostics.join(START_WINDOW_FILE);
    let name = run.name("multi-dynamic-oracle");
    let id = "c".repeat(64);
    assert!(
        PrivateStartWindow::begin_at(
            &run,
            &name,
            &id,
            &directory,
            &directory.join(START_WINDOW_FILE)
        )
        .is_none()
    );
    let window = PrivateStartWindow::begin_at(&run, &name, &id, &directory, &path).unwrap();
    let pending: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["endRealtimeNs"], Value::Null);
    assert_eq!(pending["createdId"], id);
    assert_eq!(pending["createdName"], name);
    assert_eq!(pending["outerId"], "a".repeat(64));
    assert_eq!(pending["candidateSha"], "b".repeat(40));
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o600);
    assert!(PrivateStartWindow::begin_at(&run, &name, &id, &directory, &path).is_none());
    window.finish_timeout();
    let finalized: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(finalized["status"], "timeout");
    assert!(
        finalized["endRealtimeNs"].as_u64().unwrap()
            >= finalized["startRealtimeNs"].as_u64().unwrap()
    );
    assert!(!directory.join("port-probes.json").exists());
    assert_eq!(run.calls.get(), 0);
    assert_eq!(run.bytes.get(), 0);
    assert!(run.uncertain_mutation.get());
    fs::remove_file(&path).unwrap();
    let window = PrivateStartWindow::begin_at(&run, &name, &id, &directory, &path).unwrap();
    let mut drift = pending;
    drift["status"] = json!("private-drift");
    fs::write(&path, serde_json::to_vec(&drift).unwrap()).unwrap();
    window.finish_timeout();
    let unchanged: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(unchanged["status"], "private-drift");
    fs::remove_dir_all(&directory).unwrap();
}

const EXPECTED_SHAPES: [&str; 8] = [
    "FixedIpv4HostPort",
    "EphemeralIpv4HostPort",
    "FixedIpv6HostPort",
    "EphemeralIpv6HostPort",
    "MultipleFixedPortBindings",
    "MultipleEphemeralPortBindings",
    "ExposedOnlyPort",
    "EphemeralHostPort",
];

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
    let source = include_str!("native_port_tests.rs");
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

struct StartReadAllowance {
    requests: Cell<usize>,
    wire_bytes: Cell<usize>,
    cancelled: AtomicBool,
}

impl StartReadAllowance {
    fn new() -> Self {
        Self {
            requests: Cell::new(0),
            wire_bytes: Cell::new(0),
            cancelled: AtomicBool::new(false),
        }
    }

    fn charge(&self) -> Result<(), AcquisitionError> {
        if self.cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(AcquisitionError::Cancelled);
        }
        if self.requests.get() >= 2 {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(AcquisitionError::Budget(LimitError::Requests));
        }
        if self.wire_bytes.get() > DIAGNOSTIC_GET_WIRE_LIMIT {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(AcquisitionError::Budget(LimitError::Bytes));
        }
        self.requests.set(self.requests.get() + 1);
        self.wire_bytes
            .set(self.wire_bytes.get() + DIAGNOSTIC_GET_WIRE_LIMIT);
        Ok(())
    }
}

fn start_diagnostic_budget(remaining: Duration) -> Option<Duration> {
    let available = remaining.checked_sub(Duration::from_secs(40))?;
    (available >= Duration::from_secs(4)).then_some(available.min(Duration::from_secs(4)))
}

fn diagnostic_read_outcome(error: AcquisitionError) -> &'static str {
    match error {
        AcquisitionError::Deadline => "timeout",
        AcquisitionError::Io | AcquisitionError::Status => "other",
        _ => "unknown",
    }
}

struct StartDiagnostic {
    version: &'static str,
    object: &'static str,
    identity: &'static str,
    state: &'static str,
    primary: &'static str,
    secondary: &'static str,
    allocation_relation: &'static str,
}

impl StartDiagnostic {
    fn unknown() -> Self {
        Self {
            version: "unknown",
            object: "unknown",
            identity: "unknown",
            state: "unknown",
            primary: "unknown",
            secondary: "unknown",
            allocation_relation: "unknown",
        }
    }

    fn observe_container(&mut self, value: &Value, id: &str, name: &str, run: &str, image: &str) {
        self.allocation_relation = "unknown";
        if !value.is_object() {
            return;
        }
        self.object = "responsive";
        if !value["Id"].as_str().is_some_and(canonical_id)
            || !value["Name"].is_string()
            || !value["Config"]["Labels"][OWNER].is_string()
            || !value["Config"]["Image"].is_string()
        {
            return;
        }
        if !owned(value, Some(id), name, run, image) {
            self.identity = "mismatch";
            return;
        }
        self.identity = "same";
        self.state = match value["State"]["Status"].as_str() {
            Some("created") => "created",
            Some("running") => "running",
            Some("restarting") => "restarting",
            Some("paused") => "paused",
            Some("exited") => "exited",
            Some("dead") => "dead",
            Some("removing") => "removing",
            _ => "unknown",
        };
        let Some(ports) = value["NetworkSettings"]["Ports"].as_object() else {
            return;
        };
        let binding = ports.get("8085/tcp");
        let bindings = match binding {
            None | Some(Value::Null) => {
                self.primary = "zero";
                self.secondary = "zero";
                return;
            }
            Some(Value::Array(values)) => values,
            _ => return,
        };
        let (mut primary, mut secondary) = (0, 0);
        let (mut primary_port, mut secondary_port) = (None, None);
        for binding in bindings {
            let ip = binding["HostIp"].as_str();
            let Some(port) = binding["HostPort"].as_str() else {
                return;
            };
            let assigned = match port {
                "" | "0" => false,
                value if value.parse::<u16>().is_ok_and(|port| port > 0) => true,
                _ => return,
            };
            let numeric_port = if port
                .bytes()
                .next()
                .is_some_and(|byte| (b'1'..=b'9').contains(&byte))
                && port.bytes().all(|byte| byte.is_ascii_digit())
            {
                port.parse::<u16>().ok().filter(|port| *port > 0)
            } else {
                None
            };
            match ip {
                Some("127.0.0.1") => {
                    primary += usize::from(assigned);
                    primary_port = numeric_port;
                }
                Some("127.0.0.2") => {
                    secondary += usize::from(assigned);
                    secondary_port = numeric_port;
                }
                _ => return,
            }
        }
        self.primary = binding_cardinality(primary);
        self.secondary = binding_cardinality(secondary);
        // Equality on different host addresses is valid. This observation
        // neither requires distinct ports nor establishes a proxy collision.
        self.allocation_relation = match (
            bindings.len(),
            primary,
            secondary,
            primary_port,
            secondary_port,
        ) {
            (2, 1, 1, Some(primary), Some(secondary)) if primary == secondary => "same",
            (2, 1, 1, Some(_), Some(_)) => "different",
            _ => "unknown",
        };
    }

    fn summary(&self, outcome: &'static str, uncertain: bool) -> String {
        assert!(matches!(outcome, "observed" | "skipped" | "panic"));
        let mutation = if uncertain { "uncertain" } else { "clear" };
        format!(
            "DOCKERLENS_NATIVE_PORT_START_DIAG: outcome={outcome} version={} object={} identity={} state={} primary={} secondary={} allocation_relation={} mutation={mutation}",
            self.version,
            self.object,
            self.identity,
            self.state,
            self.primary,
            self.secondary,
            self.allocation_relation
        )
    }
}

#[test]
fn start_diagnostic_budget_never_borrows_cleanup_or_adds_unbounded_io() {
    for seconds in [0, 1, 39, 40, 41, 43] {
        assert!(start_diagnostic_budget(Duration::from_secs(seconds)).is_none());
    }
    assert_eq!(
        start_diagnostic_budget(Duration::from_secs(44)),
        Some(Duration::from_secs(4))
    );
    assert_eq!(
        start_diagnostic_budget(Duration::from_secs(180)),
        Some(Duration::from_secs(4))
    );
    assert!(start_diagnostic_budget(Duration::from_secs(44) - Duration::from_nanos(1)).is_none());
}

#[test]
fn insufficient_start_followup_reserve_skips_both_reads_without_clearing_uncertainty() {
    let id = "a".repeat(64);
    let name = "dl-port-Test0001-multi-dynamic-oracle".to_owned();
    let mut run = NativeRun {
        api_version: "1.41".into(),
        image: "private-image".into(),
        run_id: "Test0001".into(),
        lane: "debian11-rootless".into(),
        candidate: "b".repeat(40),
        mode: DaemonMode::Rootless,
        engine_release: "20.10.5".into(),
        socket: "/nonexistent-port-diagnostic.sock".into(),
        outer_identity: None,
        attempted: BTreeSet::new(),
        created: vec![(name.clone(), id.clone())],
        fact_source: None,
        deadline: Instant::now() + Duration::from_secs(43),
        epoch_deadline: SystemTime::now() + Duration::from_secs(43),
        calls: Cell::new(0),
        bytes: Cell::new(0),
        uncertain_mutation: Cell::new(true),
        cleaned: true,
    };
    let (outcome, diagnostic) = run.repeated_start_diagnostics(&name, &id);
    assert_eq!(outcome, "skipped");
    assert_eq!(run.calls.get(), 0);
    assert_eq!(run.bytes.get(), 0);
    assert!(run.uncertain_mutation.get());
    assert!(
        diagnostic
            .summary(outcome, run.uncertain_mutation.get())
            .contains("mutation=uncertain")
    );
    // Even with the original counters at their boundaries, a diagnostic error
    // uses only its dedicated allowance and cannot spend cleanup counter room.
    run.deadline = Instant::now() + Duration::from_secs(60);
    run.epoch_deadline = SystemTime::now() + Duration::from_secs(60);
    run.calls.set(512);
    run.bytes.set(8 * 1024 * 1024);
    let allowance = StartReadAllowance::new();
    assert!(
        run.start_diagnostic_read(
            ReadRequest::DaemonVersion,
            None,
            Instant::now(),
            Duration::from_secs(4),
            &allowance
        )
        .is_err()
    );
    assert_eq!(allowance.requests.get(), 1);
    assert_eq!(allowance.wire_bytes.get(), DIAGNOSTIC_GET_WIRE_LIMIT);
    assert_eq!(run.calls.get(), 512);
    assert_eq!(run.bytes.get(), 8 * 1024 * 1024);
    assert!(run.uncertain_mutation.get());
}

#[test]
fn dedicated_start_allowance_has_exact_request_wire_and_cancellation_boundaries() {
    let allowance = StartReadAllowance::new();
    assert!(allowance.charge().is_ok());
    assert_eq!(allowance.requests.get(), 1);
    assert!(allowance.charge().is_ok());
    assert_eq!(allowance.requests.get(), 2);
    assert_eq!(allowance.wire_bytes.get(), 2 * DIAGNOSTIC_GET_WIRE_LIMIT);
    assert_eq!(
        allowance.charge().err(),
        Some(AcquisitionError::Budget(LimitError::Requests))
    );
    assert_eq!(allowance.requests.get(), 2);
    assert_eq!(allowance.charge().err(), Some(AcquisitionError::Cancelled));
    let full = StartReadAllowance::new();
    full.wire_bytes.set(DIAGNOSTIC_GET_WIRE_LIMIT + 1);
    assert_eq!(
        full.charge().err(),
        Some(AcquisitionError::Budget(LimitError::Bytes))
    );
    assert_eq!(full.requests.get(), 0);
    let exact = StartReadAllowance::new();
    exact.wire_bytes.set(DIAGNOSTIC_GET_WIRE_LIMIT);
    assert!(exact.charge().is_ok());
    assert_eq!(exact.wire_bytes.get(), 2 * DIAGNOSTIC_GET_WIRE_LIMIT);
}

#[test]
fn late_start_snapshot_retains_uncertainty_and_never_authorizes_foreign_identity() {
    let id = "a".repeat(64);
    let mut value = json!({"Id":id.clone(),"Name":"/owned-name","Config":{"Labels":{"io.dockerlens.native-run":"private-run"},"Image":"private-image"},
        "State":{"Status":"running"},"NetworkSettings":{"Ports":{"8085/tcp":[
            {"HostIp":"127.0.0.1","HostPort":"32000"},{"HostIp":"127.0.0.2","HostPort":"32000"}]}}});
    let mut diagnostic = StartDiagnostic::unknown();
    diagnostic.version = "responsive";
    diagnostic.observe_container(&value, &id, "owned-name", "private-run", "private-image");
    let uncertainty = Cell::new(true);
    let summary = diagnostic.summary("observed", uncertainty.get());
    assert_eq!(diagnostic.identity, "same");
    assert_eq!(diagnostic.primary, "one");
    assert_eq!(diagnostic.secondary, "one");
    assert_eq!(diagnostic.allocation_relation, "same");
    assert!(summary.contains("mutation=uncertain"));
    for secret in [
        id.as_str(),
        "private-run",
        "private-image",
        "owned-name",
        "32000",
    ] {
        assert!(!summary.contains(secret));
    }
    assert!(uncertainty.get());
    value["Id"] = Value::String("b".repeat(64));
    let mut foreign = StartDiagnostic::unknown();
    foreign.observe_container(&value, &id, "owned-name", "private-run", "private-image");
    assert_eq!(foreign.identity, "mismatch");
    assert_eq!(foreign.state, "unknown");
    assert_eq!(foreign.primary, "unknown");
    assert_eq!(foreign.allocation_relation, "unknown");
    value["Id"] = Value::String(id.clone());
    value["NetworkSettings"]["Ports"]["8085/tcp"][0]["HostPort"] =
        Value::String("protected-secret".into());
    let mut malformed = StartDiagnostic::unknown();
    malformed.observe_container(&value, &id, "owned-name", "private-run", "private-image");
    assert_eq!(malformed.primary, "unknown");
    assert_eq!(malformed.allocation_relation, "unknown");
    assert!(
        !malformed
            .summary("observed", true)
            .contains("protected-secret")
    );
}

#[test]
fn start_allocation_relation_observes_equal_and_different_ports_without_revealing_values() {
    let id = "a".repeat(64);
    for (secondary_port, relation) in [
        ("32000", "same"),
        ("32001", "different"),
        ("1", "different"),
        ("65535", "different"),
    ] {
        for reversed in [false, true] {
            let mut bindings = vec![
                json!({"HostIp":"127.0.0.1","HostPort":"32000"}),
                json!({"HostIp":"127.0.0.2","HostPort":secondary_port}),
            ];
            if reversed {
                bindings.reverse();
            }
            let value = json!({"Id":id,"Name":"/owned-name",
                "Config":{"Labels":{"io.dockerlens.native-run":"private-run"},"Image":"private-image"},
                "State":{"Status":"created"},"NetworkSettings":{"Ports":{"8085/tcp":bindings}}});
            let mut diagnostic = StartDiagnostic::unknown();
            diagnostic.observe_container(&value, &id, "owned-name", "private-run", "private-image");
            assert_eq!(diagnostic.allocation_relation, relation);
            assert_eq!(diagnostic.primary, "one");
            assert_eq!(diagnostic.secondary, "one");
            let summary = diagnostic.summary("observed", true);
            assert!(summary.contains(&format!("allocation_relation={relation}")));
            assert!(summary.contains("mutation=uncertain"));
            for secret in [
                id.as_str(),
                "owned-name",
                "private-run",
                "private-image",
                "32000",
                "32001",
                "65535",
            ] {
                assert!(!summary.contains(secret));
            }
            let mut foreign = value.clone();
            foreign["Id"] = Value::String("b".repeat(64));
            diagnostic.observe_container(
                &foreign,
                &id,
                "owned-name",
                "private-run",
                "private-image",
            );
            assert_eq!(diagnostic.allocation_relation, "unknown");
        }
    }
}

#[test]
fn start_allocation_relation_keeps_partial_foreign_duplicate_and_malformed_data_unknown() {
    let id = "a".repeat(64);
    let primary = json!({"HostIp":"127.0.0.1","HostPort":"32000"});
    let secondary = json!({"HostIp":"127.0.0.2","HostPort":"32001"});
    let invalid = [
        Value::Null,
        json!({}),
        json!([]),
        json!([primary]),
        json!([secondary]),
        json!([primary, primary]),
        json!([secondary, secondary]),
        json!([primary, secondary, primary]),
        json!([primary, secondary, {"HostIp":"127.0.0.1","HostPort":""}]),
        json!([primary, {"HostIp":"127.0.0.3","HostPort":"32001"}]),
        json!([primary, {"HostIp":"127.0.0.2","HostPort":""}]),
        json!([primary, {"HostIp":"127.0.0.2","HostPort":"0"}]),
        json!([primary, {"HostIp":"127.0.0.2","HostPort":"65536"}]),
        json!([primary, {"HostIp":"127.0.0.2","HostPort":"+32001"}]),
        json!([primary, {"HostIp":"127.0.0.2","HostPort":32001}]),
        json!([primary, {"HostIp":"127.0.0.2"}]),
        json!([primary, {"HostPort":"32001"}]),
        json!([primary, {"HostIp":"protected-secret","HostPort":"protected-secret"}]),
    ];
    for bindings in invalid {
        let value = json!({"Id":id,"Name":"/owned-name",
            "Config":{"Labels":{"io.dockerlens.native-run":"private-run"},"Image":"private-image"},
            "State":{"Status":"created"},"NetworkSettings":{"Ports":{"8085/tcp":bindings}}});
        let mut diagnostic = StartDiagnostic::unknown();
        diagnostic.observe_container(&value, &id, "owned-name", "private-run", "private-image");
        assert_eq!(diagnostic.allocation_relation, "unknown");
        assert!(
            !diagnostic
                .summary("observed", true)
                .contains("protected-secret")
        );
    }
    let value = json!({"Id":id,"Name":"/owned-name",
        "Config":{"Labels":{"io.dockerlens.native-run":"private-run"},"Image":"private-image"},
        "State":{"Status":"created"},"NetworkSettings":{"Ports":{"8085/udp":[primary, secondary]}}});
    let mut diagnostic = StartDiagnostic::unknown();
    diagnostic.observe_container(&value, &id, "owned-name", "private-run", "private-image");
    assert_eq!(diagnostic.allocation_relation, "unknown");
}

#[test]
fn start_allocation_relation_rejects_zero_padding_and_resets_reused_observations() {
    let id = "a".repeat(64);
    let valid = json!({"Id":id,"Name":"/owned-name",
        "Config":{"Labels":{"io.dockerlens.native-run":"private-run"},"Image":"private-image"},
        "State":{"Status":"created"},"NetworkSettings":{"Ports":{"8085/tcp":[
            {"HostIp":"127.0.0.1","HostPort":"32000"},
            {"HostIp":"127.0.0.2","HostPort":"32001"}]}}});
    let mut diagnostic = StartDiagnostic::unknown();
    for index in [0, 1] {
        for padded in ["032000", "00032000"] {
            diagnostic.observe_container(&valid, &id, "owned-name", "private-run", "private-image");
            assert_eq!(diagnostic.allocation_relation, "different");
            let mut value = valid.clone();
            value["NetworkSettings"]["Ports"]["8085/tcp"][index]["HostPort"] =
                Value::String(padded.into());
            diagnostic.observe_container(&value, &id, "owned-name", "private-run", "private-image");
            assert_eq!(diagnostic.allocation_relation, "unknown");
            // The pre-existing cardinalities retain their original parsing.
            assert_eq!(diagnostic.primary, "one");
            assert_eq!(diagnostic.secondary, "one");
            assert!(!diagnostic.summary("observed", true).contains(padded));
        }
    }
    diagnostic.observe_container(&valid, &id, "owned-name", "private-run", "private-image");
    assert_eq!(diagnostic.allocation_relation, "different");
    diagnostic.observe_container(
        &Value::Null,
        &id,
        "owned-name",
        "private-run",
        "private-image",
    );
    assert_eq!(diagnostic.allocation_relation, "unknown");
}

fn closed_api_failure_diagnostic(action: &'static str, cleanup: bool, code: Option<i32>) -> String {
    assert!(matches!(
        action,
        "version" | "info" | "create" | "start" | "inspect_name" | "inspect_id" | "delete"
    ));
    let phase = if cleanup { "cleanup" } else { "probe" };
    let exit = match code {
        Some(28) => "curl_timeout",
        Some(124) => "outer_timeout",
        Some(137 | 143) | None => "signal",
        _ => "other",
    };
    format!("DOCKERLENS_NATIVE_PORT_API_DIAG: action={action} phase={phase} exit={exit}")
}

#[test]
fn failed_api_diagnostic_closes_routes_phases_and_timeout_sources() {
    for action in [
        "version",
        "info",
        "create",
        "start",
        "inspect_name",
        "inspect_id",
        "delete",
    ] {
        for (cleanup, phase) in [(false, "probe"), (true, "cleanup")] {
            for (code, exit) in [
                (Some(28), "curl_timeout"),
                (Some(124), "outer_timeout"),
                (Some(137), "signal"),
                (Some(143), "signal"),
                (None, "signal"),
                (Some(7), "other"),
                (Some(0), "other"),
            ] {
                assert_eq!(
                    closed_api_failure_diagnostic(action, cleanup, code),
                    format!(
                        "DOCKERLENS_NATIVE_PORT_API_DIAG: action={action} phase={phase} exit={exit}"
                    )
                );
            }
        }
    }
    assert!(
        std::panic::catch_unwind(|| closed_api_failure_diagnostic(
            "protected-secret",
            false,
            Some(28)
        ))
        .is_err()
    );
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

#[derive(Clone, Copy)]
enum NativeApiOperation {
    Inspect,
    Create,
    Start,
}

impl NativeApiOperation {
    fn label(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Create => "create",
            Self::Start => "start",
        }
    }
}

fn assert_native_api_status(operation: NativeApiOperation, actual: u16, expected: u16) {
    if actual != expected {
        eprintln!(
            "DOCKERLENS_NATIVE_API_DIAG: operation={} status={}",
            operation.label(),
            api_status_category(actual)
        );
    }
    assert!(actual == expected, "closed native API status mismatch");
}

#[derive(Default)]
struct ProbeEvidence {
    positive: BTreeSet<&'static str>,
    expected_negative: BTreeSet<(&'static str, &'static str)>,
}

impl ProbeEvidence {
    fn positive(&mut self, shape: &'static str) {
        assert!(
            EXPECTED_SHAPES.contains(&shape),
            "unknown closed port shape"
        );
        assert!(
            !self
                .expected_negative
                .iter()
                .any(|(name, _)| *name == shape),
            "a withheld family cannot become positive"
        );
        assert!(self.positive.insert(shape), "duplicate positive port shape");
    }

    fn expected_negative(&mut self, shape: &'static str, reason: &'static str) {
        assert!(
            matches!(
                (shape, reason),
                (
                    "FixedIpv6HostPort" | "EphemeralIpv6HostPort",
                    "nested_default_bridge_ipv6_unavailable"
                        | "nested_default_bridge_ipv6_runtime_binding_absent"
                )
            ),
            "only independently controlled Debian IPv6 boundaries are recognized"
        );
        assert!(
            !self.positive.contains(shape),
            "a positive shape cannot also be withheld"
        );
        assert!(
            !self
                .expected_negative
                .iter()
                .any(|(name, _)| *name == shape),
            "duplicate negative port shape regardless of reason"
        );
        assert!(
            self.expected_negative.insert((shape, reason)),
            "duplicate withheld port shape"
        );
    }

    fn complete(&self, lane: &str) -> Value {
        assert!(
            matches!(
                lane,
                "debian11-rootful" | "debian11-rootless" | "upstream-rootful" | "upstream-rootless"
            ),
            "exact closed port evidence lane"
        );
        assert!(
            self.expected_negative.is_empty()
                || matches!(lane, "debian11-rootful" | "debian11-rootless"),
            "upstream port negatives cannot be admitted as observed boundaries"
        );
        let mut observed = self.positive.clone();
        for (shape, reason) in &self.expected_negative {
            assert!(
                matches!(
                    (*shape, *reason),
                    (
                        "FixedIpv6HostPort" | "EphemeralIpv6HostPort",
                        "nested_default_bridge_ipv6_unavailable"
                            | "nested_default_bridge_ipv6_runtime_binding_absent"
                    )
                ),
                "closed independently controlled Debian IPv6 boundary"
            );
            assert!(
                observed.insert(*shape),
                "each port shape has exactly one outcome"
            );
        }
        assert_eq!(
            observed,
            EXPECTED_SHAPES.into_iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            self.positive.len() + self.expected_negative.len(),
            EXPECTED_SHAPES.len()
        );
        let positive = EXPECTED_SHAPES
            .into_iter()
            .filter(|shape| self.positive.contains(*shape))
            .collect::<Vec<_>>();
        let expected_negative = EXPECTED_SHAPES
            .into_iter()
            .filter_map(|shape| {
                self.expected_negative
                    .iter()
                    .find(|(name, _)| *name == shape)
                    .map(|(name, reason)| json!({"shape":name,"reason":reason}))
            })
            .collect::<Vec<_>>();
        json!({"schema_version":1,"positive":positive,"expected_negative":expected_negative})
    }
}

fn private_port_proof(run: &NativeRun, evidence: &ProbeEvidence) -> Value {
    assert!(
        run.cleaned && !run.uncertain_mutation.get(),
        "verified port cleanup required for publication"
    );
    assert!(
        run.run_id.len() == 8 && run.run_id.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "exact private run token"
    );
    assert!(
        matches!(run.mode, DaemonMode::Rootful | DaemonMode::Rootless),
        "closed private daemon mode"
    );
    json!({"schema_version":1,"kind":"dockerlens-native-port-probes","candidate_sha":run.candidate,
        "lane":run.lane,"engine_release":run.engine_release,"rendering_api":run.api_version,
        "daemon_mode":if run.mode == DaemonMode::Rootless { "rootless" } else { "rootful" },
        "run_id":run.run_id,"cleanup":"absent","probes":evidence.complete(&run.lane)})
}

fn record_many(evidence: &mut ProbeEvidence, shapes: &[&'static str]) {
    for shape in shapes {
        evidence.positive(shape);
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
    eprintln!("DOCKERLENS_NATIVE_CHECK: port_{group}_{phase}");
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
    let inspected = run.inspect(id);
    assert_eq!(assigned_port(&inspected, "8080/tcp", "127.0.0.1", 2), 18110);
    assert_eq!(assigned_port(&inspected, "8080/tcp", "127.0.0.2", 2), 18111);
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

fn assert_exposed_only_runtime(run: &NativeRun, id: &str) {
    let value = run.inspect(id);
    assert_eq!(value["State"]["Running"], true);
    assert_eq!(value["Config"]["ExposedPorts"]["8082/tcp"], json!({}));
    assert!(
        value["HostConfig"]["PortBindings"]
            .get("8082/tcp")
            .is_none(),
        "exposed-only is not configured as published"
    );
    assert!(
        matches!(
            value["NetworkSettings"]["Ports"].get("8082/tcp"),
            None | Some(Value::Null)
        ),
        "exposed-only has no runtime host assignment"
    );
}

fn assert_ephemeral_udp(run: &NativeRun, id: &str, suffix: &str) {
    let value = run.inspect(id);
    assert_configured_binding_count(&value, "8081/udp", 1);
    assert_port_binding(&value, "8081/udp", "127.0.0.1", "");
    assert_eq!(assigned_port(&value, "8081/udp", "127.0.0.1", 1) > 0, true);
    mark_port_stage(suffix, "udp_assignment");
    let assigned = run.inspect(id)["NetworkSettings"]["Ports"]["8081/udp"][0]["HostPort"]
        .as_str()
        .expect("runtime-assigned ephemeral UDP port")
        .to_owned();
    let assigned: u16 = assigned.parse().expect("numeric dynamic UDP port");
    assert!(assigned > 0);
    mark_port_stage(suffix, "udp_send");
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
    mark_port_stage(suffix, "udp_receive");
    let mut received = String::new();
    for _ in 0..10 {
        received = run.cli(&[
            "exec".into(),
            id.to_owned(),
            "sh".into(),
            "-c".into(),
            "cat /tmp/udp-received 2>/dev/null || true".into(),
        ]);
        if received == "native-udp-canary" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    mark_port_stage(suffix, "udp_assert");
    assert_eq!(received, "native-udp-canary");
}

fn probe_ipv4_ports(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: port_ipv4");
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
    assert_exposed_only_runtime(run, &oracle_id);
    assert_ephemeral_udp(run, &oracle_id, "port-oracle");
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
    assert_native_api_status(NativeApiOperation::Start, status, 204);
    run.complete_port_fixture(&id, |run| {
        assert_fixed_ipv4_http(run, &id, "port-rendered", false);
        assert_fixed_ipv4_http(run, &id, "port-rendered", true);
        assert_exposed_only_runtime(run, &id);
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
        assert_ephemeral_udp(run, &id, "port-rendered");
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
    });
}

fn probe_fixed_ipv6_ports(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: port_ipv6");
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
    assert_native_api_status(NativeApiOperation::Start, status, 204);
    run.complete_port_fixture(&id, |run| {
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
    });
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

fn probe_ephemeral_ipv6_ports(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: port_ipv6");
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
    let oracle_outcome = run.complete_port_fixture(&ipv6_oracle_id, |run| {
        if run.debian_default_bridge_boundary() {
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
        }
    });
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
    run.complete_port_fixture(&id, |run| {
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
    });
}

fn probe_multiple_ephemeral_ports(run: &mut NativeRun, evidence: &mut ProbeEvidence) {
    eprintln!("DOCKERLENS_NATIVE_CHECK: port_ipv4");
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
    run.complete_port_fixture(&multiple_oracle_id, |run| {
        for ip in ["127.0.0.1", "127.0.0.2"] {
            assert_dynamic_http(
                run,
                &multiple_oracle_id,
                "8085/tcp",
                ip,
                "multi-dynamic-oracle",
            );
        }
    });
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
    run.complete_port_fixture(&id, |run| {
        for ip in ["127.0.0.1", "127.0.0.2"] {
            assert_dynamic_http(run, &id, "8085/tcp", ip, "multi-dynamic-rendered");
        }
        evidence.positive("MultipleEphemeralPortBindings");
    });
}

fn start_container(run: &NativeRun, id: &str) {
    let (status, _body) = run.api(
        "POST",
        &format!("/v{}/containers/{id}/start", run.api_version),
        None,
    );
    assert_native_api_status(NativeApiOperation::Start, status, 204);
}

fn proof_directory(directory: &Path) -> File {
    assert!(
        directory.is_absolute(),
        "absolute private capture directory"
    );
    assert_eq!(
        directory
            .canonicalize()
            .unwrap_or_else(|_| panic!("private capture ancestry")),
        directory
    );
    let metadata = fs::symlink_metadata(directory)
        .unwrap_or_else(|_| panic!("private capture directory metadata"));
    let owner = fs::metadata("/proc/self")
        .unwrap_or_else(|_| panic!("native test process owner"))
        .uid();
    assert!(
        metadata.is_dir()
            && metadata.uid() == owner
            && metadata.permissions().mode() & 0o777 == 0o700,
        "owner-private capture directory"
    );
    let held = File::open(directory).unwrap_or_else(|_| panic!("held private proof directory"));
    let after = held
        .metadata()
        .unwrap_or_else(|_| panic!("held proof directory metadata"));
    assert_eq!(
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.mode()
        ),
        (after.dev(), after.ino(), after.uid(), after.mode())
    );
    held
}

fn write_private_proof(path: &Path, directory: &Path, proof: &Value) {
    assert_eq!(path.parent(), Some(directory));
    let name = path
        .file_name()
        .unwrap_or_else(|| panic!("one direct proof filename"));
    let held = proof_directory(directory);
    let before = held
        .metadata()
        .unwrap_or_else(|_| panic!("held proof parent metadata"));
    let relative = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd())).join(name);
    let bytes = serde_json::to_vec(proof).unwrap();
    assert!(bytes.len() <= 4096, "bounded private port proof");
    // The held parent selects the original directory; exclusive creation never
    // follows/replaces an existing leaf or trusts a later pathname substitution.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&relative)
        .unwrap_or_else(|_| panic!("fresh exclusive port proof"));
    let identity = file
        .metadata()
        .unwrap_or_else(|_| panic!("fresh port proof metadata"));
    let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(
            identity.is_file()
                && identity.uid() == before.uid()
                && identity.permissions().mode() & 0o777 == 0o600
                && identity.nlink() == 1,
            "regular owner-private single-link proof"
        );
        file.write_all(&bytes)
            .unwrap_or_else(|_| panic!("private port proof write"));
        file.sync_all()
            .unwrap_or_else(|_| panic!("private port proof sync"));
        let after = file
            .metadata()
            .unwrap_or_else(|_| panic!("completed proof metadata"));
        let named =
            fs::symlink_metadata(path).unwrap_or_else(|_| panic!("completed proof path metadata"));
        assert_eq!((identity.dev(), identity.ino()), (after.dev(), after.ino()));
        assert_eq!(
            (
                after.dev(),
                after.ino(),
                after.uid(),
                after.mode(),
                after.nlink(),
                after.len()
            ),
            (
                named.dev(),
                named.ino(),
                named.uid(),
                named.mode(),
                named.nlink(),
                named.len()
            )
        );
        assert_eq!(after.len(), bytes.len() as u64);
        let parent =
            fs::symlink_metadata(directory).unwrap_or_else(|_| panic!("proof parent recheck"));
        assert_eq!(
            (parent.dev(), parent.ino(), parent.uid(), parent.mode()),
            (before.dev(), before.ino(), before.uid(), before.mode())
        );
        assert_eq!(
            directory
                .canonicalize()
                .unwrap_or_else(|_| panic!("proof ancestry recheck")),
            directory
        );
    }))
    .is_ok();
    if !passed {
        // Remove only the exact still-owned fresh leaf. Never scan, replace,
        // or remove a foreign pathname when identity is uncertain.
        if fs::symlink_metadata(&relative).is_ok_and(|named| {
            named.is_file() && named.dev() == identity.dev() && named.ino() == identity.ino()
        }) {
            fs::remove_file(&relative).unwrap_or_else(|_| panic!("partial private proof removal"));
        }
    }
    assert!(passed, "private port proof publication failed");
}

#[test]
#[ignore = "requires the isolated exact-version native Engine harness"]
fn live_port_publications_match_engine() {
    let mut run = NativeRun::new();
    let directory = PathBuf::from(required("NATIVE_CAPTURE_DIR"));
    let path = PathBuf::from(required("NATIVE_PORT_PROBES_PATH"));
    assert_eq!(path.parent(), Some(directory.as_path()));
    let _held = proof_directory(&directory);
    assert!(
        fs::symlink_metadata(&path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "new port proof path"
    );
    let mut evidence = ProbeEvidence::default();
    let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run.context();
        probe_ipv4_ports(&mut run, &mut evidence);
        probe_fixed_ipv6_ports(&mut run, &mut evidence);
        probe_ephemeral_ipv6_ports(&mut run, &mut evidence);
        probe_multiple_ephemeral_ports(&mut run, &mut evidence);
    }))
    .is_ok();
    eprintln!("DOCKERLENS_NATIVE_CHECK: port_cleanup");
    let cleaned = run.cleanup_attempt("primary");
    assert!(
        passed && cleaned && !run.uncertain_mutation.get(),
        "closed native port assertions/cleanup failed"
    );
    assert!(
        run.remaining() > Duration::from_secs(1),
        "port proof publication deadline"
    );
    let proof = private_port_proof(&run, &evidence);
    write_private_proof(&path, &directory, &proof);
    eprintln!("DOCKERLENS_NATIVE_CHECK: port_evidence");
}

fn complete_positive_evidence() -> ProbeEvidence {
    let mut evidence = ProbeEvidence::default();
    for shape in EXPECTED_SHAPES {
        evidence.positive(shape);
    }
    evidence
}

fn controlled_debian_evidence() -> ProbeEvidence {
    let mut evidence = ProbeEvidence::default();
    for shape in EXPECTED_SHAPES
        .into_iter()
        .filter(|shape| !matches!(*shape, "FixedIpv6HostPort" | "EphemeralIpv6HostPort"))
    {
        evidence.positive(shape);
    }
    // Deliberately insert in reverse canonical order: serialization must not
    // inherit insertion order or lexical reason/shape ordering.
    evidence.expected_negative(
        "EphemeralIpv6HostPort",
        "nested_default_bridge_ipv6_runtime_binding_absent",
    );
    evidence.expected_negative(
        "FixedIpv6HostPort",
        "nested_default_bridge_ipv6_unavailable",
    );
    evidence
}

#[test]
fn complete_port_outcomes_are_closed_ordered_and_lane_bound() {
    let positive = complete_positive_evidence();
    for lane in [
        "debian11-rootful",
        "debian11-rootless",
        "upstream-rootful",
        "upstream-rootless",
    ] {
        assert_eq!(
            positive.complete(lane),
            json!({"schema_version":1,"positive":["FixedIpv4HostPort","EphemeralIpv4HostPort","FixedIpv6HostPort","EphemeralIpv6HostPort","MultipleFixedPortBindings","MultipleEphemeralPortBindings","ExposedOnlyPort","EphemeralHostPort"],"expected_negative":[]})
        );
    }
    let negative = controlled_debian_evidence();
    let expected = json!({"schema_version":1,
    "positive":["FixedIpv4HostPort","EphemeralIpv4HostPort","MultipleFixedPortBindings","MultipleEphemeralPortBindings","ExposedOnlyPort","EphemeralHostPort"],
    "expected_negative":[
        {"shape":"FixedIpv6HostPort","reason":"nested_default_bridge_ipv6_unavailable"},
        {"shape":"EphemeralIpv6HostPort","reason":"nested_default_bridge_ipv6_runtime_binding_absent"}
    ]});
    for lane in ["debian11-rootful", "debian11-rootless"] {
        let actual = negative.complete(lane);
        assert_eq!(actual, expected);
        assert_eq!(
            actual
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["schema_version", "positive", "expected_negative"]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }
    for lane in [
        "upstream-rootful",
        "upstream-rootless",
        "debian11-other",
        "protected-private-lane",
    ] {
        assert!(std::panic::catch_unwind(|| negative.complete(lane)).is_err());
    }
    assert!(std::panic::catch_unwind(|| positive.complete("unknown")).is_err());
}

#[test]
fn incomplete_duplicate_overlap_and_unrecognized_port_outcomes_never_publish() {
    for missing in EXPECTED_SHAPES {
        let mut partial = complete_positive_evidence();
        partial.positive.remove(missing);
        assert!(std::panic::catch_unwind(|| partial.complete("debian11-rootful")).is_err());
    }
    let mut evidence = ProbeEvidence::default();
    evidence.expected_negative(
        "FixedIpv6HostPort",
        "nested_default_bridge_ipv6_unavailable",
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evidence.expected_negative(
                "FixedIpv6HostPort",
                "nested_default_bridge_ipv6_runtime_binding_absent",
            );
        }))
        .is_err()
    );
    assert_eq!(evidence.expected_negative.len(), 1);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || evidence.positive("FixedIpv6HostPort")
        ))
        .is_err()
    );
    let mut positive = complete_positive_evidence();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || positive.positive("ExposedOnlyPort")
        ))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| positive.expected_negative(
            "FixedIpv6HostPort",
            "nested_default_bridge_ipv6_unavailable"
        )))
        .is_err()
    );
    for (shape, reason) in [
        (
            "FixedIpv4HostPort",
            "nested_default_bridge_ipv6_unavailable",
        ),
        ("FixedIpv6HostPort", "timeout"),
        ("EphemeralIpv6HostPort", "unknown"),
        ("unknown-shape", "unknown"),
    ] {
        let mut invalid = ProbeEvidence::default();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || invalid.expected_negative(shape, reason)
            ))
            .is_err()
        );
    }
    // Completion revalidates the private collection independently of setters.
    let mut overlap = complete_positive_evidence();
    overlap.expected_negative.insert((
        "FixedIpv6HostPort",
        "nested_default_bridge_ipv6_unavailable",
    ));
    assert!(std::panic::catch_unwind(|| overlap.complete("debian11-rootless")).is_err());
    let mut duplicate = controlled_debian_evidence();
    duplicate.expected_negative.insert((
        "FixedIpv6HostPort",
        "nested_default_bridge_ipv6_runtime_binding_absent",
    ));
    assert!(std::panic::catch_unwind(|| duplicate.complete("debian11-rootful")).is_err());
    let mut unknown = complete_positive_evidence();
    unknown.positive.insert("protected-private-shape");
    assert!(std::panic::catch_unwind(|| unknown.complete("debian11-rootful")).is_err());
    let mut reason = controlled_debian_evidence();
    reason.expected_negative.remove(&(
        "FixedIpv6HostPort",
        "nested_default_bridge_ipv6_unavailable",
    ));
    reason
        .expected_negative
        .insert(("FixedIpv6HostPort", "protected-private-reason"));
    assert!(std::panic::catch_unwind(|| reason.complete("debian11-rootful")).is_err());
}

#[test]
fn private_port_envelope_retains_only_exact_private_context_and_verified_cleanup() {
    // Construct pure metadata only; no NativeRun::new/environment, commands,
    // acquisition, namespace entry, file publication or Drop cleanup runs.
    let mut run = NativeRun {
        api_version: "1.41".into(),
        image: "fixture".into(),
        run_id: "Ab12Cd34".into(),
        lane: "debian11-rootful".into(),
        candidate: "a".repeat(40),
        mode: DaemonMode::Rootful,
        engine_release: "20.10.5+dfsg1".into(),
        socket: "/private-unused".into(),
        outer_identity: None,
        attempted: BTreeSet::new(),
        created: Vec::new(),
        fact_source: None,
        deadline: Instant::now() + Duration::from_secs(60),
        epoch_deadline: SystemTime::now() + Duration::from_secs(60),
        calls: Cell::new(0),
        bytes: Cell::new(0),
        uncertain_mutation: Cell::new(false),
        cleaned: true,
    };
    let evidence = controlled_debian_evidence();
    let proof = private_port_proof(&run, &evidence);
    assert_eq!(
        proof
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        [
            "schema_version",
            "kind",
            "candidate_sha",
            "lane",
            "engine_release",
            "rendering_api",
            "daemon_mode",
            "run_id",
            "cleanup",
            "probes"
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
    assert_eq!(proof["kind"], "dockerlens-native-port-probes");
    assert_eq!(proof["schema_version"], 1);
    assert_eq!(proof["run_id"], "Ab12Cd34");
    assert_eq!(proof["cleanup"], "absent");
    assert_eq!(proof["probes"], evidence.complete("debian11-rootful"));
    assert!(!proof.as_object().unwrap().contains_key("engine_version"));
    assert!(serde_json::to_vec(&proof).unwrap().len() <= 4096);
    run.uncertain_mutation.set(true);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| private_port_proof(
            &run, &evidence
        )))
        .is_err()
    );
    run.uncertain_mutation.set(false);
    run.cleaned = false;
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        private_port_proof(&run, &evidence)
    }))
    .is_err();
    run.cleaned = true; // Even an assertion failure cannot trigger native Drop I/O.
    assert!(failed);
    run.run_id = "wrong-token".into();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| private_port_proof(
            &run, &evidence
        )))
        .is_err()
    );
}

#[test]
fn port_ownership_requires_exact_canonical_id_name_label_and_image() {
    let id = "a".repeat(64);
    let name = "dl-port-Ab12Cd34-port-oracle";
    let image = "busybox-fixture";
    let good = json!({"Id":id,"Name":format!("/{name}"),"Config":{"Image":image,"Labels":{(OWNER):"Ab12Cd34"}}});
    assert!(owned(&good, Some(&id), name, "Ab12Cd34", image));
    for key in ["Id", "Name", "Config"] {
        let mut bad = good.clone();
        bad[key] = json!("protected-private-value");
        assert!(!owned(&bad, Some(&id), name, "Ab12Cd34", image));
    }
    assert!(!owned(
        &good,
        Some(&"b".repeat(64)),
        name,
        "Ab12Cd34",
        image
    ));
    assert!(!owned(&good, None, name, "foreign", image));
    assert!(!owned(&good, None, name, "Ab12Cd34", "foreign"));
    assert!(!canonical_id(&"A".repeat(64)));
}

#[test]
fn private_port_stream_bound_retains_no_overflow_as_success() {
    let (kept, overflow) = private_stream(std::io::Cursor::new(vec![b'x'; 8193]), 8192);
    assert_eq!(kept.len(), 8192);
    assert!(overflow);
}

fn offline_facts(mode: DaemonMode, minor: u16) -> DaemonFacts {
    // Pure planner boundary fixtures only; never used by the live proof.
    let observation_id = ObservationId::fresh().unwrap();
    let release = EngineRelease::new("20.10.5".to_owned()).unwrap();
    let api_version = ApiVersion::new(NonZeroU16::new(1).unwrap(), minor);
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
        capabilities: [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::PortPublish,
            Capability::PortHostIpv4,
        ]
        .into_iter()
        .map(|capability| CapabilityFact {
            capability,
            state: CapabilityState::Available,
            provenance: FactProvenance::NativeConformance,
            scope: Some(scope.clone()),
        })
        .collect(),
    }
}

#[test]
fn rootless_low_fixed_ports_missing_capability_and_api_floor_remain_pre_io_rejections() {
    let mut container = bare_container("busybox-fixture");
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
    let rootful = offline_facts(DaemonMode::Rootful, 41);
    assert!(
        DockerPlanner
            .plan(&intent, &ValidatedCapabilities::new(&rootful).unwrap())
            .is_ok()
    );
    let rootless = offline_facts(DaemonMode::Rootless, 41);
    assert!(matches!(
        DockerPlanner.plan(&intent, &ValidatedCapabilities::new(&rootless).unwrap()),
        Err(PlanningError::RestrictedPort { .. })
    ));
    let mut missing = rootful.clone();
    missing
        .capabilities
        .retain(|fact| fact.capability != Capability::PortPublish);
    assert!(matches!(
        DockerPlanner.plan(&intent, &ValidatedCapabilities::new(&missing).unwrap()),
        Err(PlanningError::MissingCapability {
            capability: Capability::PortPublish,
            ..
        })
    ));
    let old = offline_facts(DaemonMode::Rootful, 40);
    assert!(matches!(
        DockerPlanner.plan(&intent, &ValidatedCapabilities::new(&old).unwrap()),
        Err(PlanningError::UnsupportedApi { .. })
    ));
    let mut foreign_scope = rootful;
    foreign_scope.capabilities[0]
        .scope
        .as_mut()
        .unwrap()
        .observation_id = ObservationId::fresh().unwrap();
    assert!(ValidatedCapabilities::new(&foreign_scope).is_err());
}
