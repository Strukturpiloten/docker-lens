//! Test-only `container-identity-v1` proof; production rendering stays inert.
//!
//! Each ordered case has an independent CLI/renderer pair. Only attributed
//! create/start rejections with no started process are negative evidence. The
//! private V2 proof is written only after double name/ID absence readback.

use crate::observation::ResourceRef;
use crate::target::{
    Argument, ContainerIntent, ContainerLabel, ContainerSettings, ContainerUser, DockerApiRenderer,
    DockerPlanner, ImageCommand, ImageReference, Planner, Renderer, TargetIdentity, TargetIntent,
    TargetResource, WorkingDirectory,
};
use crate::version::{
    ApiVersion, Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonFacts,
    DaemonMode, EngineRelease, FactProvenance, ObservationId, ValidatedCapabilities,
};
use serde_json::{Value, json};
use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::num::NonZeroU16;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const OWNER: &str = "io.dockerlens.native-run";
const PROCESS: &str = "set -eu; id -u; id -g; pwd -P";
const CASE_IDS: [&str; 10] = [
    "inherit",
    "numeric_uid_gid",
    "numeric_uid",
    "named_user",
    "named_user_group",
    "named_user_numeric_group",
    "numeric_user_named_group",
    "missing_user",
    "missing_group",
    "nondirectory_workdir",
];
const ROLES: [&str; 2] = ["oracle", "rendered"];
const PROBES: [&str; 5] = [
    "ContainerUser",
    "ContainerWorkdir",
    "ContainerNumericUidGid",
    "ContainerProcessWorkingDirectory",
    "ContainerIdentityOwnershipCleanup",
];

// Native identifiers, authored settings and command output are always private.
macro_rules! assert_eq {
    ($left:expr, $right:expr $(, $($message:tt)+)? $(,)?) => {{
        assert!(&$left == &$right, "closed native process identity mismatch");
    }};
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing native identity harness input"))
}

fn canonical_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn owned(inspected: &Value, id: Option<&str>, name: &str, run: &str) -> bool {
    inspected["Id"]
        .as_str()
        .is_some_and(|actual| canonical_id(actual) && id.is_none_or(|id| actual == id))
        && inspected["Name"] == format!("/{name}")
        && inspected["Config"]["Labels"][OWNER] == run
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    ExitedZero,
    MissingUser,
    MissingGroup,
    WorkdirNotDirectory,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::ExitedZero => "exited_zero",
            Self::MissingUser => "missing_user",
            Self::MissingGroup => "missing_group",
            Self::WorkdirNotDirectory => "workdir_not_directory",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Create,
    Start,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Start => "start",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ResultRecord {
    outcome: Outcome,
    phase: Option<Phase>,
}

struct Case {
    id: &'static str,
    user: Option<String>,
    workdir: Option<String>,
    uid: u32,
    gid: u32,
    outcome: Outcome,
    process: String,
}

fn cases(run: &str) -> Vec<Case> {
    let fresh = format!("/dl-identity-{run}/fresh/nested");
    let missing_user = format!("dlmissinguser{run}");
    let missing_group = format!("dlmissinggroup{run}");
    // Fixture assumptions are independent of authored identity settings. Both
    // inherited PID1 controls verify them before any subsequent case is created.
    let fixture = format!(
        "set -eu; test \"$(id -u root)\" = 0; test \"$(id -g root)\" = 0; \
         awk -F: '$1 == \"root\" && $3 == 0 {{ ok=1 }} END {{ exit !ok }}' /etc/group; \
         test \"$(id -u bin)\" = 2; test \"$(id -g bin)\" = 2; \
         awk -F: '$1 == \"bin\" && $3 == 2 && $4 == 2 {{ ok=1 }} END {{ exit !ok }}' /etc/passwd; \
         awk -F: '$1 == \"bin\" && $3 == 2 {{ ok=1 }} END {{ exit !ok }}' /etc/group; \
         awk -F: '$3 == 1001 || $1 == \"{missing_user}\" {{ bad=1 }} END {{ exit bad }}' /etc/passwd; \
         awk -F: '$1 == \"{missing_group}\" {{ bad=1 }} END {{ exit bad }}' /etc/group; \
         test -f /etc/passwd; test ! -e '{fresh}'; id -u; id -g; pwd -P"
    );
    [
        (None, None, 0, 0, Outcome::ExitedZero),
        (
            Some("1000:1000".into()),
            Some("/tmp".into()),
            1000,
            1000,
            Outcome::ExitedZero,
        ),
        (
            Some("1001".into()),
            Some(fresh),
            1001,
            0,
            Outcome::ExitedZero,
        ),
        (
            Some("bin".into()),
            Some("/tmp".into()),
            2,
            2,
            Outcome::ExitedZero,
        ),
        (
            Some("bin:bin".into()),
            Some("/tmp".into()),
            2,
            2,
            Outcome::ExitedZero,
        ),
        (
            Some("bin:1001".into()),
            Some("/tmp".into()),
            2,
            1001,
            Outcome::ExitedZero,
        ),
        (
            Some("1000:bin".into()),
            Some("/tmp".into()),
            1000,
            2,
            Outcome::ExitedZero,
        ),
        (
            Some(missing_user),
            Some("/tmp".into()),
            0,
            0,
            Outcome::MissingUser,
        ),
        (
            Some(format!("root:{missing_group}")),
            Some("/tmp".into()),
            0,
            0,
            Outcome::MissingGroup,
        ),
        (
            Some("1000:1000".into()),
            Some("/etc/passwd".into()),
            0,
            0,
            Outcome::WorkdirNotDirectory,
        ),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (user, workdir, uid, gid, outcome))| Case {
        id: CASE_IDS[index],
        user,
        workdir,
        uid,
        gid,
        outcome,
        process: if index == 0 {
            fixture.clone()
        } else {
            PROCESS.into()
        },
    })
    .collect()
}

fn process_matches(case: &Case, output: &[u8]) -> bool {
    output
        == format!(
            "{}\n{}\n{}\n",
            case.uid,
            case.gid,
            case.workdir.as_deref().unwrap_or("/")
        )
        .as_bytes()
}

fn attributed(case: &Case, bytes: &[u8]) -> bool {
    let Ok(message) = std::str::from_utf8(bytes) else {
        return false;
    };
    if message.len() > 8192
        || message.contains("Cannot connect")
        || message.contains("connection refused")
        || message.contains("context deadline")
        || message.contains("timed out")
    {
        return false;
    }
    match case.outcome {
        Outcome::MissingUser => message.contains(&format!(
            "unable to find user {}: no matching entries in passwd file",
            case.user.as_deref().unwrap()
        )),
        Outcome::MissingGroup => message.contains(&format!(
            "unable to find group {}: no matching entries in group file",
            case.user.as_deref().unwrap().strip_prefix("root:").unwrap()
        )),
        Outcome::WorkdirNotDirectory => {
            message.contains("/etc/passwd")
                && message.contains("not a directory")
                && (message.contains("mkdir")
                    || message.contains("chdir")
                    || message.contains("working directory"))
        }
        Outcome::ExitedZero => false,
    }
}

fn cli_rejection(case: &Case, code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> bool {
    matches!(code, Some(1 | 125)) && stdout.is_empty() && attributed(case, stderr)
}

fn never_started(inspected: &Value) -> bool {
    inspected["State"]["Status"] == "created"
        && inspected["State"]["Running"] == false
        && inspected["State"]["Restarting"] == false
        && inspected["State"]["Pid"] == 0
        && inspected["State"]["StartedAt"] == "0001-01-01T00:00:00Z"
}

fn pair_matches(case: &Case, pair: &[Option<ResultRecord>]) -> bool {
    pair.len() == 2
        && pair[0].is_some_and(|record| {
            record.outcome == case.outcome
                && (record.phase.is_none() == (case.outcome == Outcome::ExitedZero))
        })
        && pair[0] == pair[1]
}

fn command_seconds(remaining: Duration, cleanup: bool) -> Option<u64> {
    // Timeout's TERM deadline and its one-second KILL grace must both fit
    // outside the work-only cleanup reserve. Zero disables timeout, so refuse
    // a command rather than ever passing zero near either deadline.
    let reserved = Duration::from_secs(if cleanup { 1 } else { 41 });
    let seconds = remaining.checked_sub(reserved)?.as_secs().min(10);
    (seconds > 0).then_some(seconds)
}

fn stream(mut reader: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut overflow = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let count = reader
            .read(&mut buffer)
            .unwrap_or_else(|_| panic!("private stream read failed"));
        if count == 0 {
            break;
        }
        let retain = count.min(cap - kept.len());
        kept.extend_from_slice(&buffer[..retain]);
        overflow |= retain < count;
    }
    (kept, overflow)
}

struct IdentityRun {
    run: String,
    lane: String,
    candidate: String,
    api_version: String,
    mode: DaemonMode,
    names: Vec<String>,
    ids: Vec<Option<String>>,
    attempted: Vec<bool>,
    create_rejected: Vec<bool>,
    results: Vec<Option<ResultRecord>>,
    image: String,
    socket: String,
    deadline: Instant,
    calls: Cell<usize>,
    bytes: Cell<usize>,
    cleaned: bool,
    cleanup_uncertain: bool,
}

impl IdentityRun {
    fn new() -> Self {
        let outer = required("NATIVE_OUTER_CONTAINER");
        let run = outer
            .strip_prefix("dl-native-")
            .unwrap_or_else(|| panic!("owned outer prefix"));
        assert!(
            run.len() == 8 && run.bytes().all(|byte| byte.is_ascii_alphanumeric()),
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
            "exact identity lane/API"
        );
        assert!(
            lane.ends_with(if mode == DaemonMode::Rootless {
                "-rootless"
            } else {
                "-rootful"
            }),
            "exact mode pairing"
        );
        let candidate = required("NATIVE_IDENTITY_CANDIDATE_SHA");
        assert!(
            candidate.len() == 40
                && candidate
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "exact candidate token"
        );
        let cutoff = required("NATIVE_NETWORK_TEST_DEADLINE_EPOCH")
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("closed native deadline"));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let remaining = cutoff.saturating_sub(now).min(120);
        assert!(remaining > 40, "native identity startup budget");
        let socket = required("NATIVE_ENGINE_SOCKET");
        assert!(socket.starts_with('/'), "explicit private socket");
        Self {
            run: run.into(),
            lane,
            candidate,
            api_version,
            mode,
            names: CASE_IDS
                .into_iter()
                .flat_map(|case| ROLES.map(|role| format!("dl-identity-{run}-{case}-{role}")))
                .collect(),
            ids: vec![None; 20],
            attempted: vec![false; 20],
            create_rejected: vec![false; 20],
            results: vec![None; 20],
            image: required("NATIVE_FIXTURE_IMAGE"),
            socket,
            deadline: Instant::now() + Duration::from_secs(remaining),
            calls: Cell::new(0),
            bytes: Cell::new(0),
            cleaned: false,
            cleanup_uncertain: false,
        }
    }

    fn timer(&self, cleanup: bool, elevated: bool) -> Command {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let seconds = command_seconds(remaining, cleanup)
            .unwrap_or_else(|| panic!("shared native identity budget"));
        let mut command = Command::new(if elevated { "sudo" } else { "timeout" });
        if elevated {
            command.args(["-n", "timeout"]);
        }
        command.args(["--signal=TERM", "--kill-after=1", &seconds.to_string()]);
        command
    }

    fn capture_result(
        &self,
        command: &mut Command,
        input: Option<&[u8]>,
        cap: usize,
    ) -> (Option<i32>, Vec<u8>, Vec<u8>) {
        self.calls.set(self.calls.get() + 1);
        assert!(self.calls.get() <= 400, "native identity command count");
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .unwrap_or_else(|_| panic!("private native command spawn"));
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let out = std::thread::spawn(move || stream(stdout, cap));
        let err = std::thread::spawn(move || stream(stderr, 8192));
        if let Some(input) = input {
            assert!(input.len() <= 4096, "closed native identity request size");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input)
                .unwrap_or_else(|_| panic!("private request write"));
        }
        let status = child
            .wait()
            .unwrap_or_else(|_| panic!("bounded private command wait"));
        let (output, overflow) = out.join().unwrap();
        let (error, error_overflow) = err.join().unwrap();
        self.bytes
            .set(self.bytes.get() + output.len() + error.len());
        assert!(
            !overflow && !error_overflow && self.bytes.get() <= 1024 * 1024,
            "private native stream budget"
        );
        (status.code(), output, error)
    }

    fn capture(&self, command: &mut Command, input: Option<&[u8]>, cap: usize) -> Vec<u8> {
        let (code, output, _) = self.capture_result(command, input, cap);
        assert_eq!(code, Some(0));
        output
    }

    fn cli(&self, args: &[String], cleanup: bool) -> Vec<u8> {
        let (code, output, _) = self.cli_result(args, cleanup);
        assert_eq!(code, Some(0));
        output
    }

    fn cli_result(&self, args: &[String], cleanup: bool) -> (Option<i32>, Vec<u8>, Vec<u8>) {
        let elevated = match required("NATIVE_PODMAN_USE_SUDO").as_str() {
            "0" => false,
            "1" => true,
            _ => panic!("closed Podman selector"),
        };
        let mut command = self.timer(cleanup, elevated);
        command.args([
            "podman",
            "exec",
            &required("NATIVE_OUTER_CONTAINER"),
            "docker",
            "-H",
            "unix:///dockerlens-native/docker.sock",
        ]);
        command.args(args);
        self.capture_result(&mut command, None, 8192)
    }

    fn api(&self, method: &str, path: &str, body: Option<&Value>, cleanup: bool) -> (u16, Vec<u8>) {
        let prefix = format!("/v{}", self.api_version);
        let known = self
            .names
            .iter()
            .map(String::as_str)
            .chain(self.ids.iter().filter_map(Option::as_deref));
        let read = known
            .clone()
            .any(|key| path == format!("{prefix}/containers/{key}/json"));
        let id = self.ids.iter().flatten().any(|id| {
            path == format!("{prefix}/containers/{id}/start")
                || path == format!("{prefix}/containers/{id}?force=1")
        });
        let create = self
            .names
            .iter()
            .any(|name| path == format!("{prefix}/containers/create?name={name}"));
        assert!(
            method == "GET" && (path == "/version" || read)
                || method == "POST" && (create || id && path.ends_with("/start"))
                || method == "DELETE" && id && path.ends_with("?force=1"),
            "closed identity API route"
        );
        let input = body.map(|body| serde_json::to_vec(body).unwrap());
        let mut command = self.timer(cleanup, false);
        command.args([
            "curl",
            "-sS",
            "--max-time",
            "8",
            "--max-filesize",
            "65536",
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
        let output = self.capture(&mut command, input.as_deref(), 65550);
        let split = output
            .iter()
            .rposition(|byte| *byte == b'\n')
            .unwrap_or_else(|| panic!("closed HTTP reply"));
        let status = std::str::from_utf8(&output[split + 1..])
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("closed HTTP status"));
        (status, output[..split].to_vec())
    }

    fn inspect(&self, key: &str, cleanup: bool) -> (u16, Value) {
        let (status, body) = self.api(
            "GET",
            &format!("/v{}/containers/{key}/json", self.api_version),
            None,
            cleanup,
        );
        let body = if status == 200 {
            serde_json::from_slice(&body)
                .unwrap_or_else(|_| panic!("private identity inspect JSON"))
        } else {
            Value::Null
        };
        (status, body)
    }

    fn bind(&mut self, index: usize, id: &str, case: &Case) {
        assert!(canonical_id(id), "canonical identity container ID");
        // A create response does not grant inspection/removal authority. First
        // bind it through the already-allowlisted exact name and literal owner.
        let (status, inspected) = self.inspect(&self.names[index], false);
        assert_eq!(status, 200);
        assert!(
            owned(&inspected, Some(id), &self.names[index], &self.run),
            "exact identity ownership"
        );
        assert_eq!(inspected["Config"]["Image"], self.image);
        assert!(
            self.ids.iter().flatten().all(|registered| registered != id),
            "distinct identity container IDs"
        );
        self.ids[index] = Some(id.into());
        self.check_configuration(case, &inspected);
    }

    fn check_configuration(&self, case: &Case, inspected: &Value) {
        assert_eq!(
            inspected["Config"]["User"],
            case.user.as_deref().unwrap_or("")
        );
        assert_eq!(
            inspected["Config"]["WorkingDir"],
            case.workdir.as_deref().unwrap_or("")
        );
        assert_eq!(
            inspected["Config"]["Cmd"],
            json!(["sh", "-c", case.process])
        );
        assert!(
            inspected["Config"]["Entrypoint"].is_null()
                || inspected["Config"]["Entrypoint"] == json!([]),
            "unmodified image entrypoint"
        );
    }

    fn cleanup(&mut self) -> bool {
        let mut verified = true;
        for index in 0..self.names.len() {
            if !self.attempted[index] {
                continue;
            }
            // One unhealthy exchange must not hide the other attempted names.
            verified &=
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.remove_owned(index)))
                    .unwrap_or(false);
        }
        for _ in 0..2 {
            for index in 0..self.names.len() {
                if !self.attempted[index] {
                    continue;
                }
                verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let name_absent = self.inspect(&self.names[index], true).0 == 404;
                    let id_absent = match &self.ids[index] {
                        Some(id) => self.inspect(id, true).0 == 404,
                        None => self.create_rejected[index],
                    };
                    name_absent && id_absent
                }))
                .unwrap_or(false);
            }
        }
        self.cleaned = verified;
        self.cleanup_uncertain |= !verified;
        verified && !self.cleanup_uncertain
    }

    fn remove_owned(&mut self, index: usize) -> bool {
        let name = self.names[index].clone();
        let (status, inspected) = self.inspect(&name, true);
        if status == 404 {
            // A lost/unbound create cannot become successful absence evidence.
            return self.ids[index].is_some() || self.create_rejected[index];
        }
        if status != 200 || !owned(&inspected, self.ids[index].as_deref(), &name, &self.run) {
            return false;
        }
        let id = inspected["Id"].as_str().unwrap().to_owned();
        if self
            .ids
            .iter()
            .enumerate()
            .any(|(other, registered)| other != index && registered.as_deref() == Some(&id))
        {
            return false;
        }
        self.ids[index] = Some(id.clone());
        // Revalidate immutable identity immediately before ID-only removal.
        let (status, before) = self.inspect(&id, true);
        if status != 200 || !owned(&before, Some(&id), &name, &self.run) {
            return false;
        }
        let deleted =
            self.api(
                "DELETE",
                &format!("/v{}/containers/{id}?force=1", self.api_version),
                None,
                true,
            )
            .0 == 204;
        // Finding a container after attributed create rejection invalidates proof
        // even when its run-owned resource can safely be removed.
        deleted && !self.create_rejected[index]
    }

    fn facts(&self) -> DaemonFacts {
        let observation_id = ObservationId::fresh().unwrap();
        let release = EngineRelease::new(required("NATIVE_ENGINE_VERSION")).unwrap();
        let minor = if self.api_version == "1.41" { 41 } else { 56 };
        let api_version = ApiVersion::new(NonZeroU16::new(1).unwrap(), minor);
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
            capabilities: [
                Capability::StandaloneContainer,
                Capability::Command,
                Capability::ContainerLabels,
                Capability::ContainerUser,
                Capability::ContainerWorkdir,
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

    fn check_process(&self, index: usize, case: &Case, output: &[u8]) {
        assert!(
            process_matches(case, output),
            "actual numeric container UID/GID and working directory"
        );
        let id = self.ids[index].as_deref().unwrap();
        let (status, inspected) = self.inspect(id, false);
        assert_eq!(status, 200);
        assert!(
            owned(&inspected, Some(id), &self.names[index], &self.run),
            "identity readback ownership"
        );
        self.check_configuration(case, &inspected);
        assert!(
            matches!(inspected["Path"].as_str(), Some("sh" | "/bin/sh")),
            "PID1 shell process"
        );
        assert_eq!(inspected["Args"], json!(["-c", case.process]));
        assert_eq!(inspected["State"]["Status"], "exited");
        assert_eq!(inspected["State"]["Running"], false);
        assert_eq!(inspected["State"]["ExitCode"], 0);
    }

    fn healthy(&self) {
        let (status, body) = self.api("GET", "/version", None, false);
        assert_eq!(status, 200);
        let version: Value =
            serde_json::from_slice(&body).unwrap_or_else(|_| panic!("private health JSON"));
        assert_eq!(version["Version"], required("NATIVE_ENGINE_VERSION"));
        assert_eq!(version["ApiVersion"], self.api_version);
    }

    fn check_negative(&self, index: usize, case: &Case) {
        self.healthy();
        let id = self.ids[index].as_deref().unwrap();
        let (status, inspected) = self.inspect(id, false);
        assert_eq!(status, 200);
        assert!(
            owned(&inspected, Some(id), &self.names[index], &self.run),
            "negative identity ownership"
        );
        self.check_configuration(case, &inspected);
        assert!(never_started(&inspected), "negative identity never started");
        let error = inspected["State"]["Error"]
            .as_str()
            .unwrap_or_else(|| panic!("closed state error shape"));
        assert!(
            error.is_empty() || attributed(case, error.as_bytes()),
            "attributed state error"
        );
        assert!(
            self.cli(&["logs".into(), id.into()], false).is_empty(),
            "no negative workload output"
        );
    }

    fn reject_create(&mut self, index: usize, case: &Case) {
        self.create_rejected[index] = true;
        self.healthy();
        assert_eq!(self.inspect(&self.names[index], false).0, 404);
        self.results[index] = Some(ResultRecord {
            outcome: case.outcome,
            phase: Some(Phase::Create),
        });
    }

    fn oracle(&mut self, index: usize, case: &Case) {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            self.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", self.run),
        ];
        if let Some(user) = &case.user {
            args.push(format!("--user={user}"));
        }
        if let Some(workdir) = &case.workdir {
            args.push(format!("--workdir={workdir}"));
        }
        args.extend([
            self.image.clone(),
            "sh".into(),
            "-c".into(),
            case.process.clone(),
        ]);
        self.attempted[index] = true;
        let (code, created, error) = self.cli_result(&args, false);
        if code != Some(0) {
            assert!(
                cli_rejection(case, code, &created, &error),
                "attributed CLI create rejection"
            );
            self.reject_create(index, case);
            return;
        }
        let id = std::str::from_utf8(&created)
            .unwrap_or_else(|_| panic!("private canonical ID"))
            .trim()
            .to_owned();
        self.bind(index, &id, case);
        let (code, output, error) =
            self.cli_result(&["start".into(), "--attach".into(), id], false);
        if case.outcome == Outcome::ExitedZero {
            assert_eq!(code, Some(0));
            self.check_process(index, case, &output);
            self.results[index] = Some(ResultRecord {
                outcome: case.outcome,
                phase: None,
            });
        } else {
            assert!(
                cli_rejection(case, code, &output, &error),
                "attributed CLI start rejection"
            );
            self.check_negative(index, case);
            self.results[index] = Some(ResultRecord {
                outcome: case.outcome,
                phase: Some(Phase::Start),
            });
        }
    }

    fn rendered(&mut self, index: usize, case: &Case) {
        let settings = ContainerSettings {
            user: case
                .user
                .as_ref()
                .map(|value| ContainerUser::new(value.as_bytes().to_vec()).unwrap()),
            working_dir: case
                .workdir
                .as_ref()
                .map(|value| WorkingDirectory::new(value.as_bytes().to_vec()).unwrap()),
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), self.run.as_bytes().to_vec())
                    .unwrap(),
            ],
            ..ContainerSettings::default()
        };
        let container = ContainerIntent {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(self.names[index].as_bytes().to_vec()).unwrap(),
            image: ImageReference::new(self.image.as_bytes().to_vec()).unwrap(),
            environment: vec![],
            ports: vec![],
            mounts: vec![],
            networks: vec![],
            entrypoint: ImageCommand::Inherit,
            command: ImageCommand::Exec(
                ["sh", "-c", &case.process]
                    .into_iter()
                    .map(|arg| Argument::new(arg.as_bytes().to_vec()).unwrap())
                    .collect(),
            ),
            healthcheck: None,
            restart: None,
            settings,
        };
        let intent =
            TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
        let facts = self.facts();
        let graph = DockerPlanner
            .plan(&intent, &ValidatedCapabilities::new(&facts).unwrap())
            .unwrap();
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        assert!(
            !format!("{intent:?} {graph:?} {artifact:?}").contains(&self.run),
            "protected identity intent Debug"
        );
        let bytes = artifact.bytes().strip_suffix(b"\n").unwrap();
        let request: Value =
            serde_json::from_slice(bytes).unwrap_or_else(|_| panic!("private renderer JSON"));
        let mut expected = json!({"Image":self.image,"Cmd":["sh","-c",case.process],"Labels":{(OWNER):self.run},"HostConfig":{}});
        if let Some(user) = &case.user {
            expected["User"] = json!(user);
        }
        if let Some(workdir) = &case.workdir {
            expected["WorkingDir"] = json!(workdir);
        }
        assert_eq!(
            request,
            json!({"method":"POST","path":format!("/v{}/containers/create?name={}",self.api_version,self.names[index]),"body":expected})
        );
        self.attempted[index] = true;
        let (status, created) = self.api(
            "POST",
            request["path"].as_str().unwrap(),
            Some(&request["body"]),
            false,
        );
        if status != 201 {
            assert!(
                api_rejection(case, status, &created),
                "attributed Engine create rejection"
            );
            self.reject_create(index, case);
            return;
        }
        let created: Value =
            serde_json::from_slice(&created).unwrap_or_else(|_| panic!("private create JSON"));
        let id = created["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical rendered ID"))
            .to_owned();
        self.bind(index, &id, case);
        let (status, output) = self.api(
            "POST",
            &format!("/v{}/containers/{id}/start", self.api_version),
            None,
            false,
        );
        if case.outcome == Outcome::ExitedZero {
            assert_eq!(status, 204);
            assert_eq!(self.cli(&["wait".into(), id.clone()], false), b"0\n");
            let output = self.cli(&["logs".into(), id], false);
            self.check_process(index, case, &output);
            self.results[index] = Some(ResultRecord {
                outcome: case.outcome,
                phase: None,
            });
        } else {
            assert!(
                api_rejection(case, status, &output),
                "attributed Engine start rejection"
            );
            self.check_negative(index, case);
            self.results[index] = Some(ResultRecord {
                outcome: case.outcome,
                phase: Some(Phase::Start),
            });
        }
    }
}

fn api_rejection(case: &Case, status: u16, body: &[u8]) -> bool {
    matches!(status, 400 | 500)
        && serde_json::from_slice::<Value>(body).ok().and_then(|body| {
            body["message"]
                .as_str()
                .map(|message| attributed(case, message.as_bytes()))
        }) == Some(true)
}

fn proof_cases(run: &IdentityRun, cases: &[Case]) -> Vec<Value> {
    assert_eq!(cases.len(), CASE_IDS.len());
    assert_eq!(run.names.len(), 20);
    assert_eq!(run.ids.len(), 20);
    assert_eq!(run.attempted.len(), 20);
    assert_eq!(run.create_rejected.len(), 20);
    assert_eq!(run.results.len(), 20);
    assert!(
        run.cleaned && !run.cleanup_uncertain && run.attempted.iter().all(|attempted| *attempted),
        "complete cleaned identity ledger"
    );
    let ids = run.ids.iter().flatten().collect::<Vec<_>>();
    assert!(
        ids.iter()
            .enumerate()
            .all(|(index, id)| canonical_id(id) && !ids[..index].contains(id)),
        "globally unique proof IDs"
    );
    cases.iter().enumerate().map(|(case_index, case)| {
        assert_eq!(case.id, CASE_IDS[case_index]);
        assert!(pair_matches(case, &run.results[case_index * 2..case_index * 2 + 2]), "matching complete identity pair");
        let containers = ROLES.into_iter().enumerate().map(|(role_index, role)| {
            let index = case_index * 2 + role_index;
            let record = run.results[index].unwrap();
            let rejected = record.phase == Some(Phase::Create);
            assert_eq!(run.create_rejected[index], rejected);
            assert_eq!(run.ids[index].is_none(), rejected);
            assert_eq!(run.names[index], format!("dl-identity-{}-{}-{role}", run.run, case.id));
            let runtime = if record.outcome == Outcome::ExitedZero { "passed" } else { "not_started" };
            json!({"role":role,"id":run.ids[index],"name":run.names[index],"owner":run.run,
                "configured":if rejected { "not_created" } else { "passed" },"outcome":record.outcome.label(),
                "rejection_phase":record.phase.map(Phase::label),"runtime_uid":runtime,"runtime_gid":runtime,"runtime_workdir":runtime,"cleanup":"absent"})
        }).collect::<Vec<_>>();
        json!({"case":case.id,"expected_outcome":case.outcome.label(),"wire":"passed","containers":containers})
    }).collect()
}

fn proof_bytes(run: &IdentityRun, cases: &[Case]) -> Vec<u8> {
    let mode = if run.mode == DaemonMode::Rootful {
        "rootful"
    } else {
        assert_eq!(run.mode, DaemonMode::Rootless);
        "rootless"
    };
    let proof = json!({"schema_version":2,"candidate_sha":run.candidate,"lane":run.lane,"mode":mode,
        "rendering_api":run.api_version,"run_id":run.run,"identity_contract":"container-identity-v1","cases":proof_cases(run, cases),"probes":PROBES});
    let bytes = serde_json::to_vec(&proof).unwrap();
    assert!(bytes.len() <= 16 * 1024, "closed proof bytes");
    bytes
}

impl Drop for IdentityRun {
    fn drop(&mut self) {
        if !self.cleaned
            && !std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup()))
                .unwrap_or(false)
        {
            eprintln!("DOCKERLENS_NATIVE_CHECK: identity_cleanup_unverified");
        }
    }
}

#[test]
fn process_identity_requires_actual_uid_gid_and_pwd_not_configuration() {
    let table = cases("Ab12Cd34");
    let case = &table[1];
    assert!(process_matches(case, b"1000\n1000\n/tmp\n"));
    for wrong in [
        b"0\n1000\n/tmp\n".as_slice(),
        b"1000\n0\n/tmp\n",
        b"1000\n1000\n/\n",
        b"1000\n1000\n",
        b"1000\n1000\n/tmp\nprotected-secret\n",
    ] {
        assert!(!process_matches(case, wrong));
    }
}

#[test]
fn identity_cleanup_never_accepts_foreign_or_replaced_ids_names_or_labels() {
    let id = "a".repeat(64);
    let good = json!({"Id":id,"Name":"/dl-identity-Ab12Cd34-inherit-oracle","Config":{"Labels":{(OWNER):"Ab12Cd34"}}});
    assert!(owned(
        &good,
        Some(&id),
        "dl-identity-Ab12Cd34-inherit-oracle",
        "Ab12Cd34"
    ));
    for field in ["Id", "Name", "Config"] {
        let mut wrong = good.clone();
        wrong[field] = json!("protected-secret");
        assert!(!owned(
            &wrong,
            Some(&id),
            "dl-identity-Ab12Cd34-inherit-oracle",
            "Ab12Cd34"
        ));
    }
    let mut replaced = good;
    replaced["Id"] = json!("b".repeat(64));
    assert!(!owned(
        &replaced,
        Some(&id),
        "dl-identity-Ab12Cd34-inherit-oracle",
        "Ab12Cd34"
    ));
}

#[test]
fn identity_capture_keeps_fixed_stream_bounds() {
    let (saved, overflow) = stream(std::io::Cursor::new(vec![b'x'; 8193]), 8192);
    assert_eq!(saved.len(), 8192);
    assert!(overflow);
}

#[test]
fn identity_timer_preserves_cleanup_reserve_including_kill_grace() {
    // Independent literal boundary table: the former 41-second work launch
    // could consume eleven seconds; it must now be refused entirely.
    for (milliseconds, expected) in [
        (0, None),
        (40_000, None),
        (41_000, None),
        (41_999, None),
        (42_000, Some(1)),
        (42_999, Some(1)),
        (43_000, Some(2)),
        (50_000, Some(9)),
        (51_000, Some(10)),
        (120_000, Some(10)),
    ] {
        assert_eq!(
            command_seconds(Duration::from_millis(milliseconds), false),
            expected
        );
    }
    for seconds in 42..=180 {
        let budget = Duration::from_secs(seconds);
        let timeout = command_seconds(budget, false).unwrap();
        assert!(budget - Duration::from_secs(timeout + 1) >= Duration::from_secs(40));
        assert!(timeout <= 10);
    }
    // Cleanup consumes its own remaining budget; it does not inherit a
    // forty-second work reserve, but still includes the fixed KILL grace.
    for (milliseconds, expected) in [
        (0, None),
        (1_000, None),
        (1_999, None),
        (2_000, Some(1)),
        (10_000, Some(9)),
        (11_000, Some(10)),
        (40_000, Some(10)),
    ] {
        assert_eq!(
            command_seconds(Duration::from_millis(milliseconds), true),
            expected
        );
    }
}

#[test]
fn identity_contract_has_literal_order_and_independent_runtime_expectations() {
    let table = cases("Ab12Cd34");
    let expected = [
        ("inherit", None, None, b"0\n0\n/\n".as_slice()),
        (
            "numeric_uid_gid",
            Some("1000:1000"),
            Some("/tmp"),
            b"1000\n1000\n/tmp\n",
        ),
        (
            "numeric_uid",
            Some("1001"),
            Some("/dl-identity-Ab12Cd34/fresh/nested"),
            b"1001\n0\n/dl-identity-Ab12Cd34/fresh/nested\n",
        ),
        ("named_user", Some("bin"), Some("/tmp"), b"2\n2\n/tmp\n"),
        (
            "named_user_group",
            Some("bin:bin"),
            Some("/tmp"),
            b"2\n2\n/tmp\n",
        ),
        (
            "named_user_numeric_group",
            Some("bin:1001"),
            Some("/tmp"),
            b"2\n1001\n/tmp\n",
        ),
        (
            "numeric_user_named_group",
            Some("1000:bin"),
            Some("/tmp"),
            b"1000\n2\n/tmp\n",
        ),
    ];
    assert_eq!(table.len(), 10);
    for (case, (id, user, workdir, output)) in table.iter().zip(expected) {
        assert_eq!(case.id, id);
        assert_eq!(case.user.as_deref(), user);
        assert_eq!(case.workdir.as_deref(), workdir);
        assert_eq!(case.outcome.label(), "exited_zero");
        assert!(process_matches(case, output));
        assert!(!process_matches(case, b"protected-secret"));
    }
    assert_eq!(table[7].id, "missing_user");
    assert_eq!(table[8].id, "missing_group");
    assert_eq!(table[9].id, "nondirectory_workdir");
    assert_eq!(table[9].workdir.as_deref(), Some("/etc/passwd"));
    assert!(
        table[0]
            .process
            .contains("test ! -e '/dl-identity-Ab12Cd34/fresh/nested'")
    );
    assert!(table[0].process.contains("$3 == 1001"));
    assert!(
        table[0]
            .process
            .contains("test \"$(id -u bin)\" = 2; test \"$(id -g bin)\" = 2")
    );
    assert!(
        table[0].process.contains(
            "'$1 == \"bin\" && $3 == 2 && $4 == 2 { ok=1 } END { exit !ok }' /etc/passwd"
        )
    );
    assert!(
        table[0]
            .process
            .contains("'$1 == \"bin\" && $3 == 2 { ok=1 } END { exit !ok }' /etc/group")
    );
    assert!(table[0].process.contains("/etc/passwd; test ! -e"));
    assert!(table[1..].iter().all(|case| case.process == PROCESS));
}

#[test]
fn identity_named_settings_must_change_inherited_uid_and_gid() {
    let table = cases("Ab12Cd34");
    // These literal negatives model a runtime ignoring a named principal while
    // still applying the other authored fields, including the working directory.
    for (index, ignored_user, ignored_group) in [
        (3, b"0\n2\n/tmp\n".as_slice(), b"2\n0\n/tmp\n".as_slice()),
        (4, b"0\n2\n/tmp\n", b"2\n0\n/tmp\n"),
        (5, b"0\n1001\n/tmp\n", b"2\n0\n/tmp\n"),
        (6, b"0\n2\n/tmp\n", b"1000\n0\n/tmp\n"),
    ] {
        assert!(!process_matches(&table[index], ignored_user));
        assert!(!process_matches(&table[index], ignored_group));
        assert!(!process_matches(&table[index], b"0\n0\n/tmp\n"));
    }
    assert_eq!(table[0].uid, 0);
    assert_eq!(table[0].gid, 0);
    assert_eq!(table[3].uid, 2);
    assert_eq!(table[3].gid, 2);
    assert_eq!(table[4].uid, 2);
    assert_eq!(table[4].gid, 2);
    assert_eq!(table[5].uid, 2);
    assert_eq!(table[5].gid, 1001);
    assert_eq!(table[6].uid, 1000);
    assert_eq!(table[6].gid, 2);
}

#[test]
fn identity_rejection_requires_native_cause_healthy_status_and_no_timeout() {
    let table = cases("Ab12Cd34");
    let messages = [
        "Error response from daemon: unable to find user dlmissinguserAb12Cd34: no matching entries in passwd file",
        "Error response from daemon: unable to find group dlmissinggroupAb12Cd34: no matching entries in group file",
        "OCI runtime create failed: chdir to cwd (\"/etc/passwd\") set in config.json failed: not a directory: unknown",
    ];
    for (index, message) in messages.into_iter().enumerate() {
        let case = &table[index + 7];
        assert!(cli_rejection(case, Some(1), b"", message.as_bytes()));
        assert!(cli_rejection(case, Some(125), b"", message.as_bytes()));
        for code in [
            None,
            Some(0),
            Some(2),
            Some(124),
            Some(126),
            Some(127),
            Some(137),
            Some(143),
        ] {
            assert!(!cli_rejection(case, code, b"", message.as_bytes()));
        }
        assert!(!cli_rejection(
            case,
            Some(1),
            b"0\n0\n/tmp\n",
            message.as_bytes()
        ));
        let body = serde_json::to_vec(&json!({"message":message})).unwrap();
        assert!(api_rejection(case, 400, &body));
        assert!(api_rejection(case, 500, &body));
        for status in [0, 200, 201, 204, 404, 409, 503] {
            assert!(!api_rejection(case, status, &body));
        }
        assert!(!api_rejection(case, 500, b"protected-secret"));
        assert!(!attributed(
            case,
            format!("{message}: context deadline exceeded").as_bytes()
        ));
        assert!(!attributed(case, b"Cannot connect to the Docker daemon"));
        assert!(!attributed(case, b"exit status 1"));
        assert!(!attributed(case, messages[(index + 1) % 3].as_bytes()));
    }
    assert!(!attributed(
        &table[7],
        b"unable to find user foreign: no matching entries in passwd file"
    ));
    assert!(!attributed(
        &table[8],
        b"unable to find group foreign: no matching entries in group file"
    ));
    assert!(!attributed(&table[9], b"chdir /foreign: not a directory"));
    assert!(!attributed(&table[9], b"/etc/passwd: permission denied"));
}

#[test]
fn identity_negative_state_rejects_any_started_or_running_process() {
    let good = json!({"State":{"Status":"created","Running":false,"Restarting":false,"Pid":0,"StartedAt":"0001-01-01T00:00:00Z"}});
    assert!(never_started(&good));
    for (field, value) in [
        ("Status", json!("exited")),
        ("Running", json!(true)),
        ("Restarting", json!(true)),
        ("Pid", json!(1)),
        ("StartedAt", json!("2026-01-01T00:00:00Z")),
    ] {
        let mut wrong = good.clone();
        wrong["State"][field] = value;
        assert!(!never_started(&wrong));
        wrong["State"].as_object_mut().unwrap().remove(field);
        assert!(!never_started(&wrong));
    }
}

#[test]
fn identity_pairs_require_both_roles_expected_outcome_and_identical_phase() {
    let table = cases("Ab12Cd34");
    let positive = Some(ResultRecord {
        outcome: Outcome::ExitedZero,
        phase: None,
    });
    let create = Some(ResultRecord {
        outcome: Outcome::MissingUser,
        phase: Some(Phase::Create),
    });
    let start = Some(ResultRecord {
        outcome: Outcome::MissingUser,
        phase: Some(Phase::Start),
    });
    assert!(pair_matches(&table[0], &[positive, positive]));
    assert!(pair_matches(&table[7], &[create, create]));
    assert!(pair_matches(&table[7], &[start, start]));
    for pair in [
        vec![],
        vec![create],
        vec![create, create, create],
        vec![None, None],
        vec![create, None],
        vec![create, start],
        vec![positive, positive],
    ] {
        assert!(!pair_matches(&table[7], &pair));
    }
    assert!(!pair_matches(&table[0], &[create, create]));
    let invalid = Some(ResultRecord {
        outcome: Outcome::MissingUser,
        phase: None,
    });
    assert!(!pair_matches(&table[7], &[invalid, invalid]));
}

fn synthetic_run() -> IdentityRun {
    let run = "Ab12Cd34";
    let table = cases(run);
    IdentityRun {
        run: run.into(),
        lane: "upstream-rootful".into(),
        candidate: "a".repeat(40),
        api_version: "1.56".into(),
        mode: DaemonMode::Rootful,
        names: table
            .iter()
            .flat_map(|case| ROLES.map(|role| format!("dl-identity-{run}-{}-{role}", case.id)))
            .collect(),
        ids: (0..20).map(|index| Some(format!("{index:064x}"))).collect(),
        attempted: vec![true; 20],
        create_rejected: vec![false; 20],
        results: table
            .iter()
            .flat_map(|case| {
                [Some(ResultRecord {
                    outcome: case.outcome,
                    phase: (case.outcome != Outcome::ExitedZero).then_some(Phase::Start),
                }); 2]
            })
            .collect(),
        image: "private-image".into(),
        socket: "/private/socket".into(),
        deadline: Instant::now(),
        calls: Cell::new(0),
        bytes: Cell::new(0),
        cleaned: true,
        cleanup_uncertain: false,
    }
}

#[test]
fn identity_v2_proof_is_exact_closed_bounded_and_allows_only_real_create_rejection_null_ids() {
    let mut run = synthetic_run();
    let table = cases(&run.run);
    let bytes = proof_bytes(&run, &table);
    assert!(bytes.len() <= 16 * 1024);
    let proof: Value = serde_json::from_slice(&bytes).unwrap();
    let keys = proof
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        vec![
            "candidate_sha",
            "cases",
            "identity_contract",
            "lane",
            "mode",
            "probes",
            "rendering_api",
            "run_id",
            "schema_version"
        ]
    );
    assert_eq!(proof["schema_version"], 2);
    assert_eq!(proof["identity_contract"], "container-identity-v1");
    assert_eq!(proof["probes"], json!(PROBES));
    for (index, case) in proof["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            case.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["case", "containers", "expected_outcome", "wire"]
        );
        assert_eq!(case["case"], CASE_IDS[index]);
        assert_eq!(case["wire"], "passed");
        assert_eq!(case["containers"].as_array().unwrap().len(), 2);
        for (role_index, container) in case["containers"].as_array().unwrap().iter().enumerate() {
            assert_eq!(
                container
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                vec![
                    "cleanup",
                    "configured",
                    "id",
                    "name",
                    "outcome",
                    "owner",
                    "rejection_phase",
                    "role",
                    "runtime_gid",
                    "runtime_uid",
                    "runtime_workdir"
                ]
            );
            assert_eq!(container["role"], ROLES[role_index]);
            assert_eq!(container["configured"], "passed");
            assert_eq!(container["cleanup"], "absent");
            assert_eq!(container["outcome"], case["expected_outcome"]);
        }
    }
    let text = std::str::from_utf8(&bytes).unwrap();
    for private in [
        "private-image",
        "/private/socket",
        "/tmp",
        "/etc/passwd",
        "1000:1000",
        "dlmissing",
        PROCESS,
    ] {
        assert!(!text.contains(private));
    }
    for index in 14..16 {
        run.ids[index] = None;
        run.create_rejected[index] = true;
        run.results[index].as_mut().unwrap().phase = Some(Phase::Create);
    }
    let proof: Value = serde_json::from_slice(&proof_bytes(&run, &table)).unwrap();
    assert!(proof["cases"][7]["containers"][0]["id"].is_null());
    assert_eq!(
        proof["cases"][7]["containers"][0]["configured"],
        "not_created"
    );
    assert_eq!(
        proof["cases"][7]["containers"][0]["runtime_uid"],
        "not_started"
    );
    assert_eq!(
        proof["cases"][7]["containers"][0]["rejection_phase"],
        "create"
    );
}

#[test]
fn identity_proof_rejects_incomplete_foreign_duplicate_and_uncertain_ledgers() {
    for mutation in 0..9 {
        let mut run = synthetic_run();
        let table = cases(&run.run);
        match mutation {
            0 => {
                run.ids[0] = run.ids[1].clone();
            }
            1 => {
                run.ids[0] = None;
            }
            2 => {
                run.names[0] = "foreign".into();
            }
            3 => {
                run.attempted[0] = false;
            }
            4 => {
                run.results[0] = None;
            }
            5 => {
                run.create_rejected[0] = true;
            }
            6 => {
                run.cleanup_uncertain = true;
            }
            7 => {
                run.ids.pop();
            }
            8 => {
                run.results[15].as_mut().unwrap().phase = Some(Phase::Create);
            }
            _ => unreachable!(),
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| proof_bytes(&run, &table)))
                .is_err()
        );
    }
}

#[test]
#[ignore = "requires the isolated exact-version native Engine harness"]
fn live_container_process_identity_matches_engine() {
    let mut run = IdentityRun::new();
    let cases = cases(&run.run);
    let path = PathBuf::from(required("NATIVE_IDENTITY_PROBES_PATH"));
    assert_eq!(
        path.parent(),
        Some(PathBuf::from(required("NATIVE_CAPTURE_DIR")).as_path())
    );
    assert!(!path.exists(), "fresh identity proof path");
    let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: identity_context");
        let (status, version) = run.api("GET", "/version", None, false);
        assert_eq!(status, 200);
        let version: Value = serde_json::from_slice(&version)
            .unwrap_or_else(|_| panic!("private daemon version JSON"));
        assert_eq!(version["Version"], required("NATIVE_ENGINE_VERSION"));
        assert_eq!(version["ApiVersion"], run.api_version);
        assert!(
            if run.lane.starts_with("debian11-") {
                matches!(
                    version["Version"].as_str(),
                    Some("20.10.5" | "20.10.5+dfsg1")
                )
            } else {
                version["Version"] == "29.8.1"
            },
            "exact Engine release"
        );
        let security: Vec<String> = serde_json::from_slice(&run.cli(
            &[
                "info".into(),
                "--format".into(),
                "{{json .SecurityOptions}}".into(),
            ],
            false,
        ))
        .unwrap_or_else(|_| panic!("private daemon mode JSON"));
        assert_eq!(
            security.iter().any(|option| option == "name=rootless"),
            run.mode == DaemonMode::Rootless
        );
        for (case_index, case) in cases.iter().enumerate() {
            for index in case_index * 2..case_index * 2 + 2 {
                assert_eq!(run.inspect(&run.names[index], false).0, 404);
            }
            eprintln!("DOCKERLENS_NATIVE_CHECK: identity_oracle");
            run.oracle(case_index * 2, case);
            eprintln!("DOCKERLENS_NATIVE_CHECK: identity_render");
            run.rendered(case_index * 2 + 1, case);
            assert!(
                pair_matches(case, &run.results[case_index * 2..case_index * 2 + 2]),
                "matching native identity pair"
            );
        }
    }))
    .is_ok();
    eprintln!("DOCKERLENS_NATIVE_CHECK: identity_cleanup");
    let cleaned =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.cleanup())).unwrap_or(false);
    if !cleaned {
        eprintln!("DOCKERLENS_NATIVE_CHECK: identity_cleanup_unverified");
    }
    assert!(passed && cleaned, "closed native identity proof failed");
    let bytes = proof_bytes(&run, &cases);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|_| panic!("fresh private identity proof"));
    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    file.write_all(&bytes)
        .unwrap_or_else(|_| panic!("private identity proof write"));
    file.sync_all()
        .unwrap_or_else(|_| panic!("private identity proof sync"));
    eprintln!("DOCKERLENS_NATIVE_CHECK: identity_evidence");
}
