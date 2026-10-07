//! Independent health-metadata-v1 native proof; no catalogue admission.
//! All mutation is confined to exact run-owned fixtures in the ignored test.

use crate::acquisition::{Endpoint, Limits, NativeId, Selector, acquire};
use crate::decoder::decode_capture;
use crate::evidence::CaptureRoute;
use crate::observation::ResourceRef;
use crate::target::{
    Argument, ContainerIntent, ContainerLabel, ContainerSettings, DockerApiRenderer, DockerPlanner,
    HealthTest, Healthcheck, ImageCommand, ImageReference, Planner, Renderer, TargetIdentity,
    TargetIntent, TargetResource,
};
use crate::version::{
    ApiVersion, Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonFacts,
    DaemonMode, FactProvenance, ValidatedCapabilities,
};
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const OWNER: &str = "io.dockerlens.native-run";
const HEALTH: &str = "touch /tmp/dl-health-attempt; test -f /tmp/dl-health-ready";
const PROCESS: &str = "while :; do sleep 1; done";
const SECOND: u64 = 1_000_000_000;
const MAX_CALLS: usize = 400;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const CLEANUP_CALLS: usize = 100;
const CLEANUP_BYTES: usize = 2 * 1024 * 1024;
const CASES: [&str; 4] = [
    "grace_positive",
    "period_zero",
    "inherited_failure",
    "disabled",
];
const SHAPES: [&str; 4] = [
    "ContainerCreateLabels",
    "ShellHealthcheck",
    "HealthStartPeriodPositive",
    "HealthStartPeriodZero",
];
const LABELS: [(&str, &str); 3] = [
    ("io.dockerlens.health.simple", "present"),
    ("io.dockerlens.health.empty", ""),
    ("io.dockerlens.health.special", "Grüße \"quoted\" \\ path"),
];

// Native values never enter assertion Debug or panic messages.
macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        assert!(&$left == &$right, "closed health metadata equality failed");
    };
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("closed health metadata environment"))
}

fn api_dimensions_match(
    advertised: Option<ApiVersion>,
    observed_requests: &[ApiVersion],
    expected_advertised: ApiVersion,
    expected_acquisition: ApiVersion,
) -> bool {
    advertised == Some(expected_advertised)
        && !observed_requests.is_empty()
        && observed_requests
            .iter()
            .all(|version| *version == expected_acquisition)
}

fn identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn image_identifier(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(identifier)
}

fn timestamp_ns(text: &str) -> Option<u128> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    if date.len() != 10 || date.as_bytes()[4] != b'-' || date.as_bytes()[7] != b'-' {
        return None;
    }
    let number = |text: &str| -> Option<u32> {
        (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse().ok())
            .flatten()
    };
    let year = number(date.get(..4)?)?;
    let month = number(date.get(5..7)?)?;
    let day = number(date.get(8..10)?)?;
    let leap = |year: u32| year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [
        31,
        28 + u32::from(leap(year)),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > months[usize::try_from(month - 1).ok()?]
    {
        return None;
    }
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    if clock.len() != 8
        || clock.as_bytes()[2] != b':'
        || clock.as_bytes()[5] != b':'
        || fraction.len() > 9
        || time.contains('.') && fraction.is_empty()
    {
        return None;
    }
    let hour = number(clock.get(..2)?)?;
    let minute = number(clock.get(3..5)?)?;
    let second = number(clock.get(6..8)?)?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let fraction_ns = if fraction.is_empty() {
        0
    } else {
        number(fraction)? * 10_u32.pow(9 - u32::try_from(fraction.len()).ok()?)
    };
    let mut days = 0_u128;
    for previous in 1970..year {
        days += 365 + u128::from(leap(previous));
    }
    days += months
        .iter()
        .take(usize::try_from(month - 1).ok()?)
        .map(|days| u128::from(*days))
        .sum::<u128>();
    days += u128::from(day - 1);
    Some(
        ((days * 24 + u128::from(hour)) * 3600 + u128::from(minute) * 60 + u128::from(second))
            * u128::from(SECOND)
            + u128::from(fraction_ns),
    )
}

fn health_configuration(config: &Value, period: u64) -> bool {
    config["Test"] == json!(["CMD-SHELL", HEALTH])
        && config["Interval"] == SECOND
        && config["Timeout"] == SECOND
        && config["Retries"] == 2
        && match config.get("StartPeriod") {
            Some(value) => value.as_u64() == Some(period),
            None => period == 0, // Native omitempty zero; emitted wire zero is checked separately.
        }
}

fn image_start_period(image: &Value) -> Option<u64> {
    match image["Config"].get("Healthcheck") {
        None | Some(Value::Null) => Some(0),
        Some(Value::Object(health)) => match health.get("StartPeriod") {
            None => Some(0),
            Some(period) => period.as_u64(),
        },
        _ => None,
    }
}

fn completed_attempts(
    inspected: &Value,
    started: &str,
    exit_code: i64,
    lower: u128,
    upper: Option<u128>,
) -> Vec<Value> {
    assert_eq!(inspected["State"]["StartedAt"], started);
    let started_ns = timestamp_ns(started).unwrap_or_else(|| panic!("actual started timestamp"));
    let logs = match inspected["State"]["Health"].get("Log") {
        None | Some(Value::Null) => return Vec::new(),
        Some(Value::Array(logs)) => logs,
        _ => panic!("closed health log shape"),
    };
    assert!(logs.len() <= 5, "bounded native health log");
    let mut attempts = Vec::new();
    let mut seen = BTreeSet::new();
    let mut previous_end = started_ns;
    for log in logs {
        let start = log["Start"]
            .as_str()
            .unwrap_or_else(|| panic!("health log start"));
        let end = log["End"]
            .as_str()
            .unwrap_or_else(|| panic!("health log end"));
        let start_ns = timestamp_ns(start).unwrap_or_else(|| panic!("health attempt timestamp"));
        let end_ns = timestamp_ns(end).unwrap_or_else(|| panic!("health completion timestamp"));
        let code = log["ExitCode"]
            .as_i64()
            .unwrap_or_else(|| panic!("completed health exit"));
        assert!(
            matches!(code, 0 | 1)
                && start_ns >= previous_end
                && start_ns < end_ns
                && end_ns <= started_ns + 180 * u128::from(SECOND)
                && seen.insert((start_ns, end_ns)),
            "completed distinct health attempts bound to this start"
        );
        previous_end = end_ns;
        if code == exit_code && start_ns >= lower && upper.is_none_or(|upper| end_ns < upper) {
            attempts.push(json!({"start":start, "end":end, "exit_code":code}));
        }
    }
    attempts
}

fn stream(mut source: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut bytes = Vec::new();
    let mut overflow = false;
    let mut buffer = [0; 4096];
    loop {
        let count = source
            .read(&mut buffer)
            .unwrap_or_else(|_| panic!("private native stream"));
        if count == 0 {
            break;
        }
        let kept = count.min(cap - bytes.len());
        bytes.extend_from_slice(&buffer[..kept]);
        overflow |= kept != count;
    }
    (bytes, overflow)
}

fn capture_room(calls: usize, bytes: usize, cleanup: bool) -> bool {
    let calls_limit = if cleanup {
        MAX_CALLS
    } else {
        MAX_CALLS - CLEANUP_CALLS
    };
    let bytes_limit = if cleanup {
        MAX_BYTES
    } else {
        MAX_BYTES - CLEANUP_BYTES
    };
    let envelope = if cleanup { 8192 + 2048 } else { 65550 + 8192 };
    calls < calls_limit
        && bytes
            .checked_add(envelope)
            .is_some_and(|total| total <= bytes_limit)
}

struct HealthRun {
    run: String,
    lane: String,
    candidate: String,
    api: String,
    engine: String,
    mode: DaemonMode,
    socket: String,
    outer: String,
    base: String,
    derived_tag: String,
    derived_id: Option<String>,
    image_attempted: bool,
    names: Vec<String>,
    ids: Vec<Option<String>>,
    attempted: Vec<bool>,
    deadline: Instant,
    calls: Cell<usize>,
    bytes: Cell<usize>,
    facts: Option<DaemonFacts>,
    cleaned: bool,
}

struct HealthExpectation {
    state: &'static str,
    exit: i64,
    lower: u128,
    upper: Option<u128>,
    count: usize,
}

impl HealthRun {
    fn new() -> Self {
        let outer = required("NATIVE_OUTER_CONTAINER");
        let run = outer
            .strip_prefix("dl-native-")
            .unwrap_or_else(|| panic!("owned outer prefix"))
            .to_owned();
        assert!(
            run.len() == 8 && run.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "closed run token"
        );
        let lane = required("NATIVE_LANE");
        assert!(
            matches!(
                lane.as_str(),
                "debian11-rootful" | "debian11-rootless" | "upstream-rootful" | "upstream-rootless"
            ),
            "exact native lane"
        );
        let api = required("NATIVE_API_VERSION");
        assert_eq!(
            api,
            if lane.starts_with("debian11-") {
                "1.41"
            } else {
                "1.56"
            }
        );
        let mode = match required("NATIVE_DAEMON_MODE").as_str() {
            "rootful" => DaemonMode::Rootful,
            "rootless" => DaemonMode::Rootless,
            _ => panic!("exact native daemon mode"),
        };
        assert_eq!(
            lane.rsplit('-').next(),
            Some(if mode == DaemonMode::Rootless {
                "rootless"
            } else {
                "rootful"
            })
        );
        let candidate = required("NATIVE_HEALTH_METADATA_CANDIDATE_SHA");
        assert!(
            candidate.len() == 40
                && candidate
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "exact candidate"
        );
        let cutoff = required("NATIVE_HEALTH_METADATA_DEADLINE_EPOCH")
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("shared suite cutoff"));
        let remaining = (UNIX_EPOCH + Duration::from_secs(cutoff))
            .duration_since(SystemTime::now())
            .unwrap_or_else(|_| panic!("expired suite cutoff"))
            .min(Duration::from_secs(180));
        assert!(
            remaining > Duration::from_secs(46),
            "cleanup reserve at entry"
        );
        let socket = required("NATIVE_ENGINE_SOCKET");
        assert!(
            PathBuf::from(&socket).is_absolute(),
            "explicit native socket"
        );
        let base = required("NATIVE_FIXTURE_IMAGE");
        assert!(
            base.rsplit_once("@sha256:")
                .is_some_and(
                    |(name, digest)| name.starts_with("docker.io/library/busybox:")
                        && !name.bytes().any(|byte| byte.is_ascii_whitespace())
                        && identifier(digest)
                ),
            "unchanged digest-pinned BusyBox fixture"
        );
        let mut names = CASES
            .into_iter()
            .flat_map(|case| {
                ["oracle", "rendered"].map(|role| format!("dl-health-{run}-{case}-{role}"))
            })
            .collect::<Vec<_>>();
        names.push(format!("dl-health-{run}-seed"));
        Self {
            derived_tag: format!("dl-health-{}:inherited", run.to_ascii_lowercase()),
            run,
            lane,
            candidate,
            api,
            engine: String::new(),
            mode,
            socket,
            outer,
            base,
            derived_id: None,
            image_attempted: false,
            names,
            ids: vec![None; 9],
            attempted: vec![false; 9],
            deadline: Instant::now() + remaining,
            calls: Cell::new(0),
            bytes: Cell::new(0),
            facts: None,
            cleaned: false,
        }
    }

    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    fn timer(&self, cleanup: bool, elevated: bool) -> Command {
        let reserved = Duration::from_secs(if cleanup { 1 } else { 46 });
        let seconds = self
            .remaining()
            .checked_sub(reserved)
            .map(|left| left.as_secs().min(8))
            .filter(|seconds| *seconds > 0)
            .unwrap_or_else(|| panic!("shared health metadata deadline"));
        let mut command = Command::new(if elevated { "sudo" } else { "timeout" });
        if elevated {
            command.args(["-n", "timeout"]);
        }
        command.args(["--signal=TERM", "--kill-after=1s", &format!("{seconds}s")]);
        command
    }

    fn capture(&self, command: &mut Command, input: Option<&[u8]>, cleanup: bool) -> Vec<u8> {
        assert!(
            capture_room(self.calls.get(), self.bytes.get(), cleanup),
            "reserved native command/byte budget"
        );
        self.calls.set(self.calls.get() + 1);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .unwrap_or_else(|_| panic!("private native command spawn"));
        let stdout = child
            .stdout
            .take()
            .unwrap_or_else(|| panic!("private stdout"));
        let stderr = child
            .stderr
            .take()
            .unwrap_or_else(|| panic!("private stderr"));
        let out = std::thread::spawn(move || stream(stdout, if cleanup { 8192 } else { 65550 }));
        let err = std::thread::spawn(move || stream(stderr, if cleanup { 2048 } else { 8192 }));
        if let Some(input) = input {
            assert!(input.len() <= 4096, "bounded native request");
            child
                .stdin
                .take()
                .unwrap_or_else(|| panic!("private stdin"))
                .write_all(input)
                .unwrap_or_else(|_| panic!("private native request write"));
        }
        let status = child
            .wait()
            .unwrap_or_else(|_| panic!("bounded native command wait"));
        let (output, overflow) = out.join().unwrap_or_else(|_| panic!("private stdout join"));
        let (error, error_overflow) = err.join().unwrap_or_else(|_| panic!("private stderr join"));
        self.bytes
            .set(self.bytes.get() + output.len() + error.len());
        assert!(
            !overflow && !error_overflow && self.bytes.get() <= MAX_BYTES,
            "private stream budget"
        );
        assert!(
            status.success(),
            "original native command must complete successfully"
        );
        output
    }

    fn outer(&self, args: &[String], cleanup: bool) -> Vec<u8> {
        let elevated = match required("NATIVE_PODMAN_USE_SUDO").as_str() {
            "0" => false,
            "1" => true,
            _ => panic!("closed privilege selector"),
        };
        let mut command = self.timer(cleanup, elevated);
        command.args(["podman", "exec", &self.outer]);
        command.args(args);
        self.capture(&mut command, None, cleanup)
    }

    fn docker(&self, args: &[String], cleanup: bool) -> Vec<u8> {
        let mut command = vec![
            "docker".to_owned(),
            "-H".to_owned(),
            "unix:///dockerlens-native/docker.sock".to_owned(),
        ];
        command.extend_from_slice(args);
        self.outer(&command, cleanup)
    }

    fn api(&self, method: &str, path: &str, body: Option<&Value>, cleanup: bool) -> (u16, Value) {
        let prefix = format!("/v{}", self.api);
        let keys = self
            .names
            .iter()
            .map(String::as_str)
            .chain(self.ids.iter().filter_map(Option::as_deref));
        let container_read = keys
            .clone()
            .any(|key| path == format!("{prefix}/containers/{key}/json"));
        let container_start = self
            .ids
            .iter()
            .flatten()
            .any(|id| path == format!("{prefix}/containers/{id}/start"));
        let container_delete = self
            .ids
            .iter()
            .flatten()
            .any(|id| path == format!("{prefix}/containers/{id}?force=1"));
        let create = self
            .names
            .iter()
            .any(|name| path == format!("{prefix}/containers/create?name={name}"));
        let image_read = [self.base.as_str(), self.derived_tag.as_str()]
            .into_iter()
            .chain(self.derived_id.as_deref())
            .any(|key| path == format!("{prefix}/images/{key}/json"));
        let image_delete = self
            .derived_id
            .as_ref()
            .is_some_and(|id| path == format!("{prefix}/images/{id}?force=0"));
        assert!(
            method == "GET"
                && (path == "/version"
                    || path == format!("{prefix}/info")
                    || container_read
                    || image_read)
                || method == "POST" && (create || container_start)
                || method == "DELETE" && (container_delete || image_delete),
            "allowlisted exact native request"
        );
        let input = body.map(|body| {
            serde_json::to_vec(body).unwrap_or_else(|_| panic!("private request encoding"))
        });
        let mut command = self.timer(cleanup, false);
        command.args([
            "curl",
            "-q",
            "--noproxy",
            "*",
            "--silent",
            "--show-error",
            "--max-time",
            "7",
            "--max-filesize",
            "65536",
            "--unix-socket",
            &self.socket,
            "--request",
            method,
            "--header",
            "Content-Type: application/json",
        ]);
        if input.is_some() {
            command.args(["--data-binary", "@-"]);
        } else if method == "POST" {
            command.args(["--data-binary", ""]);
        }
        command.args([
            "--write-out",
            "\n%{http_code}",
            &format!("http://localhost{path}"),
        ]);
        let output = self.capture(&mut command, input.as_deref(), cleanup);
        let at = output
            .iter()
            .rposition(|byte| *byte == b'\n')
            .unwrap_or_else(|| panic!("closed HTTP frame"));
        let status = std::str::from_utf8(&output[at + 1..])
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or_else(|| panic!("closed HTTP status"));
        let value = if status == 200 || status == 201 {
            serde_json::from_slice(&output[..at])
                .unwrap_or_else(|_| panic!("bounded private native JSON"))
        } else {
            Value::Null
        };
        (status, value)
    }

    fn inspect(&self, key: &str, cleanup: bool) -> (u16, Value) {
        self.api(
            "GET",
            &format!("/v{}/containers/{key}/json", self.api),
            None,
            cleanup,
        )
    }

    fn image_for(&self, index: usize) -> &str {
        if index < 4 || index == 8 {
            &self.base
        } else {
            self.derived_id
                .as_deref()
                .unwrap_or_else(|| panic!("bound derived image"))
        }
    }

    fn owned(&self, value: &Value, index: usize, id: Option<&str>) -> bool {
        value["Id"]
            .as_str()
            .is_some_and(|actual| identifier(actual) && id.is_none_or(|id| id == actual))
            && value["Name"] == format!("/{}", self.names[index])
            && value["Config"]["Image"] == self.image_for(index)
            && value["Config"]["Labels"][OWNER] == self.run
    }

    fn sample(&self, index: usize) -> Value {
        let id = self.ids[index]
            .as_deref()
            .unwrap_or_else(|| panic!("bound fixture ID"));
        let (status, value) = self.inspect(id, false);
        assert_eq!(status, 200);
        assert!(
            self.owned(&value, index, Some(id)),
            "current exact native fixture ownership"
        );
        for (key, expected) in LABELS {
            assert_eq!(value["Config"]["Labels"][key], expected);
        }
        assert_eq!(value["Config"]["Cmd"], json!(["sh", "-c", PROCESS]));
        let case = index / 2;
        if case == 3 {
            assert_eq!(value["Config"]["Healthcheck"]["Test"], json!(["NONE"]));
        } else {
            assert!(
                health_configuration(
                    &value["Config"]["Healthcheck"],
                    if case == 0 { 20 * SECOND } else { 0 }
                ),
                "literal shell health configuration on both roles"
            );
        }
        assert_eq!(value["State"]["Running"], true);
        assert_eq!(value["State"]["Status"], "running");
        assert_eq!(value["State"]["Restarting"], false);
        assert_eq!(value["RestartCount"], 0);
        value
    }

    fn bind(&mut self, index: usize, id: &str) {
        assert!(identifier(id), "canonical created fixture ID");
        let (status, value) = self.inspect(&self.names[index], false);
        assert_eq!(status, 200);
        assert!(
            self.owned(&value, index, Some(id))
                && self.ids.iter().flatten().all(|other| other != id),
            "fresh exact created ownership"
        );
        self.ids[index] = Some(id.to_owned());
    }

    fn labels(&self) -> Value {
        let mut labels = serde_json::Map::new();
        labels.insert(OWNER.to_owned(), json!(self.run));
        for (key, value) in LABELS {
            labels.insert(key.to_owned(), json!(value));
        }
        Value::Object(labels)
    }

    fn cli_create(&mut self, index: usize) {
        assert_eq!(self.inspect(&self.names[index], false).0, 404);
        self.attempted[index] = true;
        let mut args = vec![
            "create".to_owned(),
            "--name".to_owned(),
            self.names[index].clone(),
            format!("--label={OWNER}={}", self.run),
        ];
        for (key, value) in LABELS {
            args.push(format!("--label={key}={value}"));
        }
        if index / 2 == 0 || index / 2 == 1 || index == 8 {
            args.extend([
                format!("--health-cmd={HEALTH}"),
                "--health-interval=1s".to_owned(),
                "--health-timeout=1s".to_owned(),
                "--health-retries=2".to_owned(),
                format!(
                    "--health-start-period={}s",
                    if index / 2 == 0 { 20 } else { 0 }
                ),
            ]);
        } else if index / 2 == 3 {
            args.push("--no-healthcheck".to_owned());
        }
        args.extend([
            self.image_for(index).to_owned(),
            "sh".to_owned(),
            "-c".to_owned(),
            PROCESS.to_owned(),
        ]);
        let output = self.docker(&args, false);
        let id = std::str::from_utf8(&output)
            .unwrap_or_else(|_| panic!("private CLI create ID"))
            .trim_end_matches('\n');
        self.bind(index, id);
    }

    fn rendered_create(&mut self, index: usize) {
        assert_eq!(self.inspect(&self.names[index], false).0, 404);
        let case = index / 2;
        let healthcheck = match case {
            0 | 1 => Some(
                Healthcheck::configured(
                    HealthTest::Shell(
                        Argument::new(HEALTH.as_bytes().to_vec())
                            .unwrap_or_else(|_| panic!("typed health command")),
                    ),
                    NonZeroU64::new(SECOND),
                    NonZeroU64::new(SECOND),
                    NonZeroU32::new(2),
                )
                .and_then(|health| {
                    health.with_start_period(if case == 0 { 20 * SECOND } else { 0 })
                })
                .unwrap_or_else(|_| panic!("typed authored health configuration")),
            ),
            2 => None,
            3 => Some(
                Healthcheck::configured(HealthTest::Disabled, None, None, None)
                    .unwrap_or_else(|_| panic!("typed disabled control")),
            ),
            _ => panic!("closed health case"),
        };
        let labels = std::iter::once((OWNER, self.run.as_str()))
            .chain(LABELS)
            .map(|(key, value)| {
                ContainerLabel::new(key.as_bytes().to_vec(), value.as_bytes().to_vec())
                    .unwrap_or_else(|_| panic!("typed native label"))
            })
            .collect();
        let container = ContainerIntent {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(self.names[index].as_bytes().to_vec())
                .unwrap_or_else(|_| panic!("typed fixture identity")),
            image: ImageReference::new(self.image_for(index).as_bytes().to_vec())
                .unwrap_or_else(|_| panic!("typed fixture image")),
            environment: vec![],
            ports: vec![],
            mounts: vec![],
            networks: vec![],
            entrypoint: ImageCommand::Inherit,
            command: ImageCommand::Exec(
                ["sh", "-c", PROCESS]
                    .map(|value| {
                        Argument::new(value.as_bytes().to_vec())
                            .unwrap_or_else(|_| panic!("typed command"))
                    })
                    .into(),
            ),
            healthcheck,
            restart: None,
            settings: ContainerSettings {
                labels,
                ..ContainerSettings::default()
            },
        };
        let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))])
            .unwrap_or_else(|_| panic!("closed target intent"));
        let facts = self
            .facts
            .as_ref()
            .unwrap_or_else(|| panic!("observed daemon context"));
        let graph = DockerPlanner
            .plan(
                &intent,
                &ValidatedCapabilities::new(facts)
                    .unwrap_or_else(|_| panic!("sealed native scope")),
            )
            .unwrap_or_else(|_| panic!("ordinary sealed native planner"));
        let artifact = DockerApiRenderer
            .render(&graph)
            .unwrap_or_else(|_| panic!("ordinary inert native renderer"));
        let request: Value = serde_json::from_slice(artifact.bytes())
            .unwrap_or_else(|_| panic!("single inert native request"));
        let mut expected = json!({"Image":self.image_for(index), "Cmd":["sh","-c",PROCESS], "Labels":self.labels(), "HostConfig":{}});
        if case < 2 {
            expected["Healthcheck"] = json!({"Test":["CMD-SHELL",HEALTH], "Interval":SECOND, "Timeout":SECOND, "Retries":2,
            "StartPeriod":if case == 0 { 20 * SECOND } else { 0 }});
        } else if case == 3 {
            expected["Healthcheck"] = json!({"Test":["NONE"]});
        }
        let path = format!(
            "/v{}/containers/create?name={}",
            self.api, self.names[index]
        );
        assert_eq!(
            request,
            json!({"method":"POST", "path":path, "body":expected})
        );
        self.attempted[index] = true;
        let (status, created) = self.api("POST", &path, Some(&request["body"]), false);
        assert_eq!(status, 201);
        let id = created["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("private created ID"));
        self.bind(index, id);
    }

    fn start(&self, index: usize) -> String {
        let id = self.ids[index]
            .as_deref()
            .unwrap_or_else(|| panic!("bound start ID"));
        let (status, before) = self.inspect(id, false);
        assert!(
            status == 200 && self.owned(&before, index, Some(id)),
            "ownership immediately before start"
        );
        if index % 2 == 0 {
            self.docker(&["start".to_owned(), id.to_owned()], false);
        } else {
            assert_eq!(
                self.api(
                    "POST",
                    &format!("/v{}/containers/{id}/start", self.api),
                    None,
                    false
                )
                .0,
                204
            );
        }
        let value = self.sample(index);
        let started = value["State"]["StartedAt"]
            .as_str()
            .unwrap_or_else(|| panic!("actual start timestamp"))
            .to_owned();
        assert!(
            timestamp_ns(&started).is_some(),
            "running process actually started"
        );
        started
    }

    fn exec(&self, index: usize, script: &'static str) {
        assert!(
            matches!(
                script,
                "touch /tmp/dl-health-ready"
                    | "rm /tmp/dl-health-ready"
                    | "test -e /tmp/dl-health-attempt"
                    | "test ! -e /tmp/dl-health-attempt"
            ),
            "fixed health transition/sentinel command"
        );
        self.sample(index);
        self.docker(
            &[
                "exec".to_owned(),
                self.ids[index]
                    .clone()
                    .unwrap_or_else(|| panic!("bound exec ID")),
                "sh".to_owned(),
                "-ec".to_owned(),
                script.to_owned(),
            ],
            false,
        );
    }

    fn wait_health(
        &self,
        index: usize,
        started: &str,
        expectation: HealthExpectation,
    ) -> (Value, Vec<Value>) {
        let end = Instant::now() + Duration::from_secs(16);
        loop {
            assert!(
                Instant::now() < end && self.remaining() > Duration::from_secs(46),
                "bounded actual health effect wait"
            );
            let value = self.sample(index);
            let attempts = completed_attempts(
                &value,
                started,
                expectation.exit,
                expectation.lower,
                expectation.upper,
            );
            let streak = value["State"]["Health"]["FailingStreak"]
                .as_u64()
                .unwrap_or_else(|| panic!("actual failing streak"));
            let expected_streak = if expectation.state == "unhealthy" {
                streak >= 2
            } else {
                streak == 0
            };
            if value["State"]["Health"]["Status"] == expectation.state
                && expected_streak
                && attempts.len() >= expectation.count
            {
                return (
                    value,
                    attempts.into_iter().take(expectation.count).collect(),
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

impl HealthRun {
    fn context(&mut self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: health_metadata_context");
        let (status, version) = self.api("GET", "/version", None, false);
        assert_eq!(status, 200);
        let engine = version["Version"]
            .as_str()
            .unwrap_or_else(|| panic!("observed Engine release"))
            .to_owned();
        assert_eq!(engine, required("NATIVE_ENGINE_VERSION"));
        assert!(
            if self.lane.starts_with("debian11-") {
                matches!(engine.as_str(), "20.10.5" | "20.10.5+dfsg1")
            } else {
                engine == "29.8.1"
            },
            "exact observed Engine"
        );
        assert_eq!(version["ApiVersion"], self.api);
        let cli = self.docker(
            &[
                "version".to_owned(),
                "--format".to_owned(),
                "{{.Server.Version}}|{{.Server.APIVersion}}".to_owned(),
            ],
            false,
        );
        assert_eq!(
            cli.as_slice(),
            format!("{engine}|{}\n", self.api).as_bytes()
        );
        let (status, info) = self.api("GET", &format!("/v{}/info", self.api), None, false);
        assert_eq!(status, 200);
        let rootless = info["Rootless"] == true
            || info["SecurityOptions"].as_array().is_some_and(|options| {
                options.iter().any(|option| {
                    option.as_str().is_some_and(|option| {
                        option == "name=rootless" || option.starts_with("name=rootless,")
                    })
                })
            });
        assert_eq!(rootless, self.mode == DaemonMode::Rootless);
        let security = self.docker(
            &[
                "info".to_owned(),
                "--format".to_owned(),
                "{{json .SecurityOptions}}".to_owned(),
            ],
            false,
        );
        let security: Vec<String> =
            serde_json::from_slice(&security).unwrap_or_else(|_| panic!("private CLI mode JSON"));
        assert_eq!(
            security
                .iter()
                .any(|option| option == "name=rootless" || option.starts_with("name=rootless,")),
            rootless
        );
        let uid = self.outer(&["sh".to_owned(), "-ec".to_owned(),
            "count=0; uid=; for status in /proc/[0-9]*/status; do [ -f \"$status\" ] || continue; IFS= read -r comm < \"${status%/status}/comm\" || continue; [ \"$comm\" = dockerd ] || continue; count=$((count+1)); while read -r key real effective saved filesystem; do if [ \"$key\" = Uid: ]; then uid=$effective; break; fi; done < \"$status\"; done; printf '%s:%s\\n' \"$count\" \"$uid\"".to_owned()], false);
        let uid = std::str::from_utf8(&uid)
            .ok()
            .and_then(|text| text.trim_end_matches('\n').strip_prefix("1:"))
            .and_then(|text| text.parse::<u32>().ok())
            .unwrap_or_else(|| panic!("exact-one dockerd UID oracle"));
        assert!(
            if rootless { uid > 0 } else { uid == 0 },
            "independent effective daemon mode"
        );
        if self.lane.starts_with("debian11-") {
            let package = self.outer(
                &[
                    "dpkg-query".to_owned(),
                    "-W".to_owned(),
                    "-f=${Version}".to_owned(),
                    "docker.io".to_owned(),
                ],
                false,
            );
            assert_eq!(package.as_slice(), b"20.10.5+dfsg1-1+deb11u2".as_slice());
        }
        // Engine zero means inherit. Independently establish that this pinned
        // base has no inherited health/default positive period before zero cases.
        let (status, base_image) = self.api(
            "GET",
            &format!("/v{}/images/{}/json", self.api, self.base),
            None,
            false,
        );
        assert_eq!(status, 200);
        assert!(
            base_image["Id"].as_str().is_some_and(image_identifier),
            "inspected pinned image ID"
        );
        assert_eq!(image_start_period(&base_image), Some(0));
        let elapsed = self
            .remaining()
            .checked_sub(Duration::from_secs(46))
            .unwrap_or_else(|| panic!("capture cleanup reserve"));
        let selected = NativeId::new(required("NATIVE_CONTAINER_ID"))
            .unwrap_or_else(|| panic!("known context fixture ID"));
        let capture = acquire(
            &Endpoint::unix_socket(PathBuf::from(&self.socket)),
            Selector::ContainerIds(vec![selected]),
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
        .unwrap_or_else(|_| panic!("actual bounded native acquisition"));
        assert_eq!(capture.route(), CaptureRoute::ExplicitUnixSocket);
        assert!(
            capture
                .exchanges()
                .iter()
                .all(|exchange| exchange.status().code() == 200),
            "complete actual capture"
        );
        let decoded =
            decode_capture(&capture).unwrap_or_else(|_| panic!("actual native capture decode"));
        let mut facts = decoded.version.daemon;
        assert_eq!(facts.observation_id, capture.observation_id());
        assert_eq!(
            facts.release.as_ref().map(|release| release.as_str()),
            Some(engine.as_str())
        );
        let major = NonZeroU16::new(1).unwrap_or_else(|| panic!("API major"));
        let advertised_api = ApiVersion::new(major, if self.api == "1.41" { 41 } else { 56 });
        let acquired_api = ApiVersion::new(
            major,
            if self.lane.starts_with("debian11-") {
                41
            } else {
                49
            },
        );
        let actual_requests: Vec<_> = capture
            .exchanges()
            .iter()
            .filter_map(|exchange| exchange.api_version())
            .collect();
        assert!(
            api_dimensions_match(
                facts.api_version,
                &actual_requests,
                advertised_api,
                acquired_api
            ),
            "separate actual advertised and negotiated request APIs"
        );
        assert_eq!(decoded.version.requested_api_versions, vec![acquired_api]);
        if rootless {
            assert_eq!(facts.mode, DaemonMode::Rootless);
        }
        // Rendering uses the separately verified advertised API, not the 1.49 acquisition cap.
        facts.api_version = Some(advertised_api);
        facts.mode = self.mode;
        let scope = CapabilityScope {
            observation_id: facts.observation_id,
            release: facts
                .release
                .clone()
                .unwrap_or_else(|| panic!("observed release scope")),
            api_version: facts
                .api_version
                .unwrap_or_else(|| panic!("observed rendering scope")),
            mode: self.mode,
        };
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::Healthcheck,
            Capability::HealthShell,
            Capability::HealthStartPeriod,
            Capability::HealthDisabled,
        ]
        .into_iter()
        .map(|capability| CapabilityFact {
            capability,
            state: CapabilityState::Available,
            provenance: FactProvenance::NativeConformance,
            scope: Some(scope.clone()),
        })
        .collect();
        self.engine = engine;
        self.facts = Some(facts);
    }

    fn owned_image(&self, image: &Value, id: Option<&str>) -> bool {
        image["Id"]
            .as_str()
            .is_some_and(|actual| image_identifier(actual) && id.is_none_or(|id| id == actual))
            && image["RepoTags"] == json!([self.derived_tag])
            && image["Config"]["Labels"][OWNER] == self.run
            && health_configuration(&image["Config"]["Healthcheck"], 0)
    }

    fn derive_image(&mut self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: health_metadata_derive");
        assert_eq!(
            self.api(
                "GET",
                &format!("/v{}/images/{}/json", self.api, self.derived_tag),
                None,
                false
            )
            .0,
            404
        );
        self.cli_create(8);
        let seed = self.ids[8]
            .clone()
            .unwrap_or_else(|| panic!("owned image seed"));
        let (status, before) = self.inspect(&seed, false);
        assert!(
            status == 200 && self.owned(&before, 8, Some(&seed)),
            "seed ownership before commit"
        );
        assert_eq!(before["State"]["Running"], false);
        self.image_attempted = true;
        let output = self.docker(
            &["commit".to_owned(), seed, self.derived_tag.clone()],
            false,
        );
        let id = std::str::from_utf8(&output)
            .unwrap_or_else(|_| panic!("private committed image ID"))
            .trim_end_matches('\n');
        assert!(image_identifier(id), "canonical task-derived image ID");
        let (status, image) = self.api(
            "GET",
            &format!("/v{}/images/{}/json", self.api, self.derived_tag),
            None,
            false,
        );
        assert!(
            status == 200 && self.owned_image(&image, Some(id)),
            "exact derived image health/label/tag"
        );
        self.derived_id = Some(id.to_owned());
        assert!(self.remove_container(8), "exact stopped seed removal");
    }

    fn remove_container(&mut self, index: usize) -> bool {
        let (status, value) = self.inspect(&self.names[index], true);
        if status == 404 {
            return self.ids[index].is_some();
        }
        if status != 200 || !self.owned(&value, index, self.ids[index].as_deref()) {
            return false;
        }
        let id = value["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("owned cleanup ID"))
            .to_owned();
        if self
            .ids
            .iter()
            .enumerate()
            .any(|(other, registered)| other != index && registered.as_deref() == Some(&id))
        {
            return false;
        }
        self.ids[index] = Some(id.clone());
        let (status, immediate) = self.inspect(&id, true);
        if status != 200 || !self.owned(&immediate, index, Some(&id)) {
            return false;
        }
        self.api(
            "DELETE",
            &format!("/v{}/containers/{id}?force=1", self.api),
            None,
            true,
        )
        .0 == 204
            && self.inspect(&id, true).0 == 404
            && self.inspect(&self.names[index], true).0 == 404
    }

    fn remove_image(&mut self) -> bool {
        if !self.image_attempted {
            return true;
        }
        let (status, image) = self.api(
            "GET",
            &format!("/v{}/images/{}/json", self.api, self.derived_tag),
            None,
            true,
        );
        if status == 404 {
            return self.derived_id.is_some();
        }
        if status != 200 || !self.owned_image(&image, self.derived_id.as_deref()) {
            return false;
        }
        let id = image["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("owned image cleanup ID"))
            .to_owned();
        self.derived_id = Some(id.clone());
        let (status, immediate) = self.api(
            "GET",
            &format!("/v{}/images/{id}/json", self.api),
            None,
            true,
        );
        if status != 200 || !self.owned_image(&immediate, Some(&id)) {
            return false;
        }
        self.api(
            "DELETE",
            &format!("/v{}/images/{id}?force=0", self.api),
            None,
            true,
        )
        .0 == 200
    }

    fn cleanup(&mut self) -> bool {
        let mut verified = true;
        for index in 0..self.names.len() {
            if self.attempted[index] {
                verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.remove_container(index)
                }))
                .unwrap_or(false);
            }
        }
        // Never remove a derived image while any child ownership/removal is uncertain.
        if verified {
            verified &=
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.remove_image()))
                    .unwrap_or(false);
        }
        for _ in 0..2 {
            for index in 0..self.names.len() {
                if self.attempted[index] {
                    verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.ids[index]
                            .as_ref()
                            .is_some_and(|id| self.inspect(id, true).0 == 404)
                            && self.inspect(&self.names[index], true).0 == 404
                    }))
                    .unwrap_or(false);
                }
            }
            if self.image_attempted {
                verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.derived_id.as_ref().is_some_and(|id| {
                        self.api(
                            "GET",
                            &format!("/v{}/images/{id}/json", self.api),
                            None,
                            true,
                        )
                        .0 == 404
                    }) && self
                        .api(
                            "GET",
                            &format!("/v{}/images/{}/json", self.api, self.derived_tag),
                            None,
                            true,
                        )
                        .0
                        == 404
                }))
                .unwrap_or(false);
            }
        }
        self.cleaned = verified;
        verified
    }

    fn observe_pair(&mut self, case: usize) -> Value {
        match case {
            0 => eprintln!("DOCKERLENS_NATIVE_CHECK: health_metadata_grace_positive"),
            1 => eprintln!("DOCKERLENS_NATIVE_CHECK: health_metadata_period_zero"),
            2 => eprintln!("DOCKERLENS_NATIVE_CHECK: health_metadata_inherited_failure"),
            3 => eprintln!("DOCKERLENS_NATIVE_CHECK: health_metadata_disabled"),
            _ => panic!("closed health case index"),
        }
        let first = 2 * case;
        self.cli_create(first);
        self.rendered_create(first + 1);
        let started = [self.start(first), self.start(first + 1)];
        let mut records = Vec::new();
        let gap = Instant::now();
        if case == 3 {
            for offset in 0..2 {
                let value = self.sample(first + offset);
                assert!(
                    value["State"].get("Health").is_none_or(Value::is_null),
                    "disabled control has no health state"
                );
                self.exec(first + offset, "test ! -e /tmp/dl-health-attempt");
            }
            assert!(
                self.remaining() > Duration::from_secs(49),
                "disabled observation cleanup reserve"
            );
            std::thread::sleep(Duration::from_secs(3));
        }
        for (offset, started_at) in started.iter().enumerate() {
            let index = first + offset;
            let start_ns = timestamp_ns(started_at).unwrap_or_else(|| panic!("bound actual start"));
            let mut record = json!({"role":if offset == 0 { "oracle" } else { "rendered" },
                "id":self.ids[index], "name":self.names[index], "owner":self.run, "image":self.image_for(index),
                "labels":"passed", "health_config":"passed", "running":"passed", "started_at":started_at,
                "initial_state":"disabled", "initial_streak":0, "initial_attempts":[],
                "recovery_attempt":null, "recovery":"not_applicable", "regression":"not_applicable",
                "regression_attempts":[], "regression_streak":0, "regression_observed_at":null, "health_sentinel":"absent",
                "disabled_gap_ns":null, "cleanup":"absent"});
            if case == 3 {
                let value = self.sample(index);
                assert_eq!(value["State"]["StartedAt"], started_at.as_str());
                assert!(
                    value["State"].get("Health").is_none_or(Value::is_null),
                    "disabled still has no health state"
                );
                self.exec(index, "test ! -e /tmp/dl-health-attempt");
                record["disabled_gap_ns"] = json!(
                    u64::try_from(gap.elapsed().as_nanos())
                        .unwrap_or_else(|_| panic!("bounded disabled interval"))
                );
            } else {
                let state = if case == 0 { "starting" } else { "unhealthy" };
                let upper = (case == 0).then_some(start_ns + 20 * u128::from(SECOND));
                let (initial, failures) = self.wait_health(
                    index,
                    started_at,
                    HealthExpectation {
                        state,
                        exit: 1,
                        lower: start_ns,
                        upper,
                        count: 2,
                    },
                );
                self.exec(index, "test -e /tmp/dl-health-attempt");
                let last_failure = timestamp_ns(
                    failures[1]["end"]
                        .as_str()
                        .unwrap_or_else(|| panic!("completed initial failure")),
                )
                .unwrap_or_else(|| panic!("bound failure completion"));
                record["initial_state"] = json!(state);
                record["initial_streak"] = initial["State"]["Health"]["FailingStreak"].clone();
                record["initial_attempts"] = json!(failures);
                record["health_sentinel"] = json!("present");
                assert!(
                    last_failure >= start_ns,
                    "initial failure actual completion"
                );
            }
            records.push(record);
        }
        if case < 2 {
            // Paired stage barriers preserve both roles' authored twenty-second
            // window; do not finish one lifecycle while the other waits unready.
            for index in first..first + 2 {
                self.exec(index, "touch /tmp/dl-health-ready");
            }
            let mut recovered = Vec::new();
            for (offset, started_at) in started.iter().enumerate() {
                let lower = timestamp_ns(
                    records[offset]["initial_attempts"][1]["end"]
                        .as_str()
                        .unwrap_or_else(|| panic!("observed initial failure")),
                )
                .unwrap_or_else(|| panic!("failure bound"));
                let start_ns =
                    timestamp_ns(started_at).unwrap_or_else(|| panic!("actual process start"));
                let (_, successes) = self.wait_health(
                    first + offset,
                    started_at,
                    HealthExpectation {
                        state: "healthy",
                        exit: 0,
                        lower,
                        upper: (case == 0).then_some(start_ns + 20 * u128::from(SECOND)),
                        count: 1,
                    },
                );
                records[offset]["recovery_attempt"] = successes[0].clone();
                records[offset]["recovery"] = json!("healthy");
                recovered.push(
                    timestamp_ns(
                        successes[0]["end"]
                            .as_str()
                            .unwrap_or_else(|| panic!("actual recovery log")),
                    )
                    .unwrap_or_else(|| panic!("recovery completion bound")),
                );
            }
            for index in first..first + 2 {
                self.exec(index, "rm /tmp/dl-health-ready");
            }
            for (offset, started_at) in started.iter().enumerate() {
                let start_ns =
                    timestamp_ns(started_at).unwrap_or_else(|| panic!("bound regression start"));
                let upper = (case == 0).then_some(start_ns + 20 * u128::from(SECOND));
                let (unhealthy, regressions) = self.wait_health(
                    first + offset,
                    started_at,
                    HealthExpectation {
                        state: "unhealthy",
                        exit: 1,
                        lower: recovered[offset],
                        upper,
                        count: 2,
                    },
                );
                let (status, clock) = self.api("GET", &format!("/v{}/info", self.api), None, false);
                assert_eq!(status, 200);
                let observed_at = clock["SystemTime"]
                    .as_str()
                    .unwrap_or_else(|| panic!("actual Engine observation clock"));
                let observed_ns = timestamp_ns(observed_at)
                    .unwrap_or_else(|| panic!("Engine observation clock bound"));
                let last_end = timestamp_ns(
                    regressions[1]["end"]
                        .as_str()
                        .unwrap_or_else(|| panic!("completed regression log")),
                )
                .unwrap_or_else(|| panic!("regression end clock"));
                assert!(
                    observed_ns >= last_end && upper.is_none_or(|upper| observed_ns < upper),
                    "actual unhealthy observation before authored grace ends"
                );
                records[offset]["regression"] = json!("unhealthy");
                records[offset]["regression_attempts"] = json!(regressions);
                records[offset]["regression_streak"] =
                    unhealthy["State"]["Health"]["FailingStreak"].clone();
                records[offset]["regression_observed_at"] = json!(observed_at);
            }
        }
        // Never continue the independent next case after a failed observation/removal.
        assert!(
            self.remove_container(first) && self.remove_container(first + 1),
            "owned completed pair removal"
        );
        json!({"case":CASES[case], "wire":"passed", "containers":records})
    }

    fn proof(&self, cases: &[Value]) -> Value {
        assert!(
            self.cleaned && cases.len() == 4 && self.ids.iter().all(Option::is_some),
            "complete verified health proof"
        );
        json!({"schema_version":1, "kind":"dockerlens-native-health-metadata-proof", "contract":"health-metadata-v1",
            "candidate_sha":self.candidate, "lane":self.lane, "engine_release":self.engine, "rendering_api":self.api,
            "acquisition_api":if self.lane.starts_with("debian11-") { "1.41" } else { "1.49" },
            "daemon_mode":if self.mode == DaemonMode::Rootless { "rootless" } else { "rootful" },
            "base_image":self.base, "base_health_start_period_ns":0,
            "debian_package":if self.lane.starts_with("debian11-") { Some("20.10.5+dfsg1-1+deb11u2") } else { None },
            "run_id":self.run, "cleanup":"absent", "shapes":SHAPES, "cases":cases,
            "derived_image":{"id":self.derived_id, "tag":self.derived_tag, "owner":self.run, "configured":"passed", "cleanup":"absent"},
            "seed_container":{"id":self.ids[8], "name":self.names[8], "owner":self.run, "image":self.base, "cleanup":"absent"}})
    }
}

impl Drop for HealthRun {
    fn drop(&mut self) {
        if !self.cleaned {
            let clean = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup()))
                .unwrap_or(false);
            if !clean {
                eprintln!("DOCKERLENS_NATIVE_CHECK: health_metadata_cleanup_unverified");
            }
        }
    }
}

struct ProofTarget {
    directory: PathBuf,
    path: PathBuf,
    held: File,
}

impl ProofTarget {
    fn new() -> Self {
        let directory = PathBuf::from(required("NATIVE_CAPTURE_DIR"));
        let path = PathBuf::from(required("NATIVE_HEALTH_METADATA_PROOF_PATH"));
        assert!(
            directory.is_absolute()
                && directory.canonicalize().is_ok_and(|real| real == directory)
                && path == directory.join("health-metadata.json"),
            "exact private proof location"
        );
        assert!(
            fs::symlink_metadata(&path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "exclusive new proof"
        );
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&directory)
            .unwrap_or_else(|_| panic!("held private proof directory"));
        let target = Self {
            directory,
            path,
            held,
        };
        target.check();
        target
    }

    fn check(&self) {
        let held = self
            .held
            .metadata()
            .unwrap_or_else(|_| panic!("private directory metadata"));
        let named = fs::symlink_metadata(&self.directory)
            .unwrap_or_else(|_| panic!("private directory identity"));
        let uid = fs::metadata("/proc/self")
            .unwrap_or_else(|_| panic!("native process owner"))
            .uid();
        assert!(
            held.is_dir()
                && named.is_dir()
                && held.uid() == uid
                && held.mode() & 0o777 == 0o700
                && held.dev() == named.dev()
                && held.ino() == named.ino()
                && self
                    .directory
                    .canonicalize()
                    .is_ok_and(|real| real == self.directory),
            "stable private proof ancestry"
        );
    }

    fn publish(&self, proof: &Value) {
        self.check();
        let bytes = serde_json::to_vec(proof).unwrap_or_else(|_| panic!("private proof encoding"));
        assert!(
            !bytes.is_empty() && bytes.len() <= 16384,
            "bounded private proof"
        );
        let relative = PathBuf::from(format!(
            "/proc/self/fd/{}/health-metadata.json",
            std::os::fd::AsRawFd::as_raw_fd(&self.held)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&relative)
            .unwrap_or_else(|_| panic!("exclusive private proof publication"));
        let identity = file
            .metadata()
            .unwrap_or_else(|_| panic!("new proof identity"));
        let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            file.write_all(&bytes)
                .unwrap_or_else(|_| panic!("complete private proof write"));
            file.sync_all()
                .unwrap_or_else(|_| panic!("private proof sync"));
            self.check();
            let named = fs::symlink_metadata(&self.path)
                .unwrap_or_else(|_| panic!("published proof identity"));
            assert!(
                named.is_file()
                    && named.dev() == identity.dev()
                    && named.ino() == identity.ino()
                    && named.nlink() == 1
                    && named.uid() == identity.uid()
                    && named.mode() & 0o777 == 0o600
                    && named.len()
                        == u64::try_from(bytes.len()).unwrap_or_else(|_| panic!("proof size")),
                "exclusive stable private proof"
            );
        }))
        .is_ok();
        if !passed
            && fs::symlink_metadata(&relative).is_ok_and(|named| {
                named.is_file() && named.dev() == identity.dev() && named.ino() == identity.ino()
            })
        {
            fs::remove_file(&relative).unwrap_or_else(|_| panic!("partial owned proof removal"));
        }
        assert!(passed, "private health proof publication failed");
    }
}

#[test]
#[ignore = "requires the isolated exact-version native Engine harness"]
fn live_health_metadata_matches_engine() {
    let target = ProofTarget::new();
    let mut run = HealthRun::new();
    let mut cases = Vec::new();
    let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run.context();
        run.derive_image();
        for case in 0..4 {
            cases.push(run.observe_pair(case));
        }
    }))
    .is_ok();
    eprintln!("DOCKERLENS_NATIVE_CHECK: health_metadata_cleanup");
    let cleaned =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.cleanup())).unwrap_or(false);
    assert!(
        passed && cleaned && run.remaining() > Duration::from_secs(1),
        "closed native health assertions and cleanup required"
    );
    target.publish(&run.proof(&cases));
    eprintln!("DOCKERLENS_NATIVE_CHECK: health_metadata_evidence");
}

#[test]
fn health_metadata_configuration_and_clock_controls_reject_mismatched_shell_and_period() {
    let health = json!({"Test":["CMD-SHELL",HEALTH], "Interval":SECOND, "Timeout":SECOND, "Retries":2, "StartPeriod":20 * SECOND});
    assert!(health_configuration(&health, 20 * SECOND));
    let mut exec = health.clone();
    exec["Test"] = json!(["CMD", "true"]);
    assert!(!health_configuration(&exec, 20 * SECOND));
    assert!(!health_configuration(&health, 0));
    assert_eq!(image_start_period(&json!({"Config":{}})), Some(0));
    assert_eq!(
        image_start_period(&json!({"Config":{"Healthcheck":{"StartPeriod":0}}})),
        Some(0)
    );
    assert_eq!(
        image_start_period(&json!({"Config":{"Healthcheck":{"StartPeriod":20 * SECOND}}})),
        Some(20 * SECOND)
    );
    assert_eq!(timestamp_ns("1970-01-01T00:00:00.000000001Z"), Some(1));
    for invalid in [
        "0001-01-01T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-10-07T00:00:60Z",
        "2026-10-07T00:00:00+00:00",
    ] {
        assert!(timestamp_ns(invalid).is_none());
    }
}

#[test]
fn health_metadata_api_controls_keep_advertised_and_requested_dimensions_separate() {
    let major = NonZeroU16::new(1).unwrap_or_else(|| panic!("control API major"));
    let debian = ApiVersion::new(major, 41);
    let advertised = ApiVersion::new(major, 56);
    let acquisition = ApiVersion::new(major, 49);
    assert!(api_dimensions_match(
        Some(debian),
        &[debian, debian],
        debian,
        debian
    ));
    assert!(api_dimensions_match(
        Some(advertised),
        &[acquisition, acquisition],
        advertised,
        acquisition
    ));
    assert!(!api_dimensions_match(
        Some(acquisition),
        &[acquisition],
        advertised,
        acquisition
    ));
    assert!(!api_dimensions_match(
        Some(advertised),
        &[advertised],
        advertised,
        acquisition
    ));
    assert!(!api_dimensions_match(
        Some(advertised),
        &[],
        advertised,
        acquisition
    ));
    assert!(!api_dimensions_match(
        Some(advertised),
        &[acquisition, advertised],
        advertised,
        acquisition
    ));
}

#[test]
fn health_metadata_attempt_controls_require_completed_distinct_start_bound_failures() {
    let start = "2026-10-07T00:00:00Z";
    let value = json!({"State":{"StartedAt":start, "Health":{"Log":[
        {"Start":"2026-10-07T00:00:05Z", "End":"2026-10-07T00:00:05.001Z", "ExitCode":1},
        {"Start":"2026-10-07T00:00:10Z", "End":"2026-10-07T00:00:10.001Z", "ExitCode":1}]}}});
    let bound = timestamp_ns(start).unwrap_or_else(|| panic!("control timestamp"));
    assert_eq!(
        completed_attempts(
            &value,
            start,
            1,
            bound,
            Some(bound + 20 * u128::from(SECOND))
        )
        .len(),
        2
    );
    assert_eq!(
        completed_attempts(
            &value,
            start,
            1,
            bound,
            Some(bound + 10 * u128::from(SECOND))
        )
        .len(),
        1
    );
    let mut duplicate = value.clone();
    duplicate["State"]["Health"]["Log"][1] = duplicate["State"]["Health"]["Log"][0].clone();
    assert!(
        std::panic::catch_unwind(|| completed_attempts(&duplicate, start, 1, bound, None)).is_err()
    );
    let mut unstarted = value;
    unstarted["State"]["StartedAt"] = json!("0001-01-01T00:00:00Z");
    assert!(
        std::panic::catch_unwind(|| completed_attempts(&unstarted, start, 1, bound, None)).is_err()
    );
}

#[test]
fn health_metadata_exhausted_work_budget_preserves_authenticated_cleanup_capacity() {
    let mut calls = MAX_CALLS - CLEANUP_CALLS;
    let mut bytes = MAX_BYTES - CLEANUP_BYTES;
    assert!(!capture_room(calls, bytes, false));
    // One owned inspect, immutable revalidation, ID-only delete, ID/name404,
    // and two final ID/name404 rounds; no budget reset or anonymous removal.
    for _step in [
        "owned_name",
        "owned_id",
        "delete_id",
        "id404",
        "name404",
        "id404",
        "name404",
        "id404",
        "name404",
    ] {
        assert!(capture_room(calls, bytes, true));
        calls += 1;
        bytes += 8192 + 2048;
        assert!(!capture_room(calls, bytes, false));
    }
    assert!(calls <= MAX_CALLS && bytes <= MAX_BYTES);
    assert!(!capture_room(MAX_CALLS, bytes, true));
    assert!(!capture_room(calls, MAX_BYTES, true));
}
