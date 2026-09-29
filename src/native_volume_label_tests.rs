//! Test-only exact Engine probe for protected created-volume labels.
//! The production renderer emits inert requests and never contacts Docker.

use crate::observation::ResourceRef;
use crate::target::{
    DockerApiRenderer, DockerPlanner, Planner, Renderer, TargetIdentity, TargetIntent,
    TargetResource, VolumeLabel,
};
use crate::version::{
    ApiVersion, Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonFacts,
    DaemonMode, EngineRelease, FactProvenance, ObservationId, ValidatedCapabilities,
};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};

const OWNER_KEY: &str = "io.dockerlens.native-run";
const APP_KEY: &str = "io.boxferry.fixture";
const APP_VALUE: &str = "volume-label-check";
const EMPTY_KEY: &str = "io.boxferry.fixture.empty";
const SPECIAL_KEY: &str = "io.boxferry.fixture.special";
const SPECIAL_VALUE: &str = "Grüße \"quoted\" \\ path";
const CANARY: &str = "native-volume-label-canary";
const PROBES: &[&str] = &[
    "VolumeCreateLabels",
    "VolumeLabelInspect",
    "VolumeLabelPersistence",
    "VolumeLabelOwnershipCleanup",
];

// Native values and task-owned names must never enter libtest failure text.
macro_rules! assert_eq {
    ($left:expr, $right:expr $(, $($message:tt)+)? $(,)?) => {{
        assert!(
            &$left == &$right,
            "closed native volume-label equality assertion failed"
        );
    }};
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("native harness must supply {name}"))
}

fn bounded_stream(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut saved = Vec::new();
    let mut overflow = false;
    let mut chunk = [0_u8; 4096];
    loop {
        let count = reader.read(&mut chunk).expect("private native stream read");
        if count == 0 {
            break;
        }
        let remaining = limit - saved.len();
        saved.extend_from_slice(&chunk[..count.min(remaining)]);
        overflow |= count > remaining;
    }
    (saved, overflow)
}

#[test]
fn native_label_stream_drains_but_never_retains_beyond_limit() {
    let exact = vec![b'x'; 8192];
    let (saved, overflow) = bounded_stream(std::io::Cursor::new(&exact), 8192);
    assert_eq!(saved.len(), 8192);
    assert!(!overflow);
    let oversized = vec![b'x'; 1024 * 1024];
    let (saved, overflow) = bounded_stream(std::io::Cursor::new(&oversized), 8192);
    assert_eq!(saved.len(), 8192);
    assert!(overflow);
}

fn bounded_command(
    command: &mut Command,
    input: Option<&[u8]>,
    limit: usize,
) -> (ExitStatus, Vec<u8>) {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().expect("private native command spawn");
    let stdout = child.stdout.take().expect("private stdout");
    let stderr = child.stderr.take().expect("private stderr");
    let stdout_reader = std::thread::spawn(move || bounded_stream(stdout, limit));
    let stderr_reader = std::thread::spawn(move || bounded_stream(stderr, 8192));
    if let Some(input) = input {
        assert!(input.len() <= 16 * 1024, "bounded synthetic request");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input)
            .expect("write synthetic request");
    }
    let status = child.wait().expect("time-bounded private native command");
    let (stdout, stdout_overflow) = stdout_reader.join().expect("private stdout reader");
    let (_, stderr_overflow) = stderr_reader.join().expect("private stderr reader");
    assert!(
        !stdout_overflow && !stderr_overflow,
        "private native output limit"
    );
    (status, stdout)
}

struct LabelRun {
    run_id: String,
    api_version: String,
    socket: String,
    image: String,
    volumes: [String; 2],
    containers: Vec<String>,
    cleaned: bool,
}

impl LabelRun {
    fn new() -> Self {
        let outer = required("NATIVE_OUTER_CONTAINER");
        let run_id = outer
            .strip_prefix("dl-native-")
            .expect("task-owned outer prefix");
        assert!(
            run_id.len() == 8 && run_id.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "closed native run identifier"
        );
        let lane = required("NATIVE_LANE");
        let api_version = required("NATIVE_API_VERSION");
        assert!(
            matches!(lane.as_str(), "debian11-rootful" | "debian11-rootless")
                && api_version == "1.41"
                || matches!(lane.as_str(), "upstream-rootful" | "upstream-rootless")
                    && api_version == "1.56",
            "exact native lane/API pairing"
        );
        let socket = required("NATIVE_ENGINE_SOCKET");
        assert!(socket.starts_with('/'), "absolute native socket");
        Self {
            run_id: run_id.to_owned(),
            api_version,
            socket,
            image: required("NATIVE_FIXTURE_IMAGE"),
            volumes: [
                format!("dl-volume-label-{run_id}-oracle"),
                format!("dl-volume-label-{run_id}-rendered"),
            ],
            containers: Vec::new(),
            cleaned: false,
        }
    }

    fn cli(&self, args: &[String]) -> Vec<u8> {
        let mut command = Command::new("timeout");
        command.args(["--kill-after=1", "60"]);
        match required("NATIVE_PODMAN_USE_SUDO").as_str() {
            "0" => {
                command.arg("podman");
            }
            "1" => {
                command.args(["sudo", "-n", "podman"]);
            }
            _ => panic!("closed Podman selector"),
        }
        command.args([
            "exec",
            &required("NATIVE_OUTER_CONTAINER"),
            "docker",
            "-H",
            "unix:///dockerlens-native/docker.sock",
        ]);
        command.args(args);
        let (status, stdout) = bounded_command(&mut command, None, 8192);
        assert!(status.success(), "independent inner Docker CLI failure");
        stdout
    }

    fn api(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Vec<u8>) {
        let prefix = format!("/v{}", self.api_version);
        let volume_path = self
            .volumes
            .iter()
            .any(|name| path == format!("{prefix}/volumes/{name}"));
        let container_inspect = self
            .containers
            .iter()
            .any(|name| path == format!("{prefix}/containers/{name}/json"));
        let container_delete = self
            .containers
            .iter()
            .any(|name| path == format!("{prefix}/containers/{name}?force=1"));
        assert!(
            method == "POST" && path == format!("{prefix}/volumes/create")
                || method == "GET" && (volume_path || container_inspect)
                || method == "DELETE" && (volume_path || container_delete),
            "closed native label API path"
        );
        let input = body.map(|value| serde_json::to_vec(value).expect("synthetic JSON"));
        let mut command = Command::new("timeout");
        command.args([
            "--kill-after=1",
            "20",
            "curl",
            "-sS",
            "--max-time",
            "15",
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
        }
        command.args(["-w", "\n%{http_code}", &format!("http://localhost{path}")]);
        let (status, stdout) = bounded_command(&mut command, input.as_deref(), 65_550);
        assert!(
            status.success(),
            "closed native label API transport failure"
        );
        let split = stdout
            .iter()
            .rposition(|byte| *byte == b'\n')
            .expect("HTTP status marker");
        let status = std::str::from_utf8(&stdout[split + 1..])
            .expect("HTTP status UTF-8")
            .parse::<u16>()
            .expect("numeric HTTP status");
        (status, stdout[..split].to_vec())
    }

    fn inspect_volume(&self, name: &str) -> Value {
        let (status, bytes) = self.api(
            "GET",
            &format!("/v{}/volumes/{name}", self.api_version),
            None,
        );
        assert_eq!(status, 200, "task-owned volume inspect");
        serde_json::from_slice(&bytes).expect("private volume inspect JSON")
    }

    fn data_persists(&mut self, index: usize) {
        let volume = self.volumes[index].clone();
        for (phase, command, read_only) in [
            (
                "write",
                "printf native-volume-label-canary > /data/label-probe",
                false,
            ),
            ("read", "cat /data/label-probe", true),
        ] {
            let name = format!("dl-volume-label-{}-{index}-{phase}", self.run_id);
            self.containers.push(name.clone());
            let mount = format!(
                "type=volume,source={volume},target=/data{}",
                if read_only { ",readonly" } else { "" }
            );
            let output = self.cli(&[
                "run".into(),
                "--rm".into(),
                "--name".into(),
                name,
                "--label".into(),
                format!("{OWNER_KEY}={}", self.run_id),
                "--mount".into(),
                mount,
                self.image.clone(),
                "sh".into(),
                "-c".into(),
                command.into(),
            ]);
            if read_only {
                assert_eq!(
                    output,
                    CANARY.as_bytes(),
                    "data survives consumer recreation"
                );
            } else {
                assert!(output.is_empty(), "synthetic write has no output");
            }
        }
    }

    fn cleanup(&mut self) -> bool {
        let mut complete = true;
        for name in &self.containers {
            let path = format!("/v{}/containers/{name}/json", self.api_version);
            let (status, bytes) = self.api("GET", &path, None);
            if status == 404 {
                continue;
            }
            if status != 200 {
                complete = false;
                continue;
            }
            let Ok(inspected) = serde_json::from_slice::<Value>(&bytes) else {
                complete = false;
                continue;
            };
            if inspected["Config"]["Labels"][OWNER_KEY] != self.run_id {
                complete = false;
                continue;
            }
            let remove = format!("/v{}/containers/{name}?force=1", self.api_version);
            complete &= self.api("DELETE", &remove, None).0 == 204;
            complete &= self.api("GET", &path, None).0 == 404;
        }
        for name in &self.volumes {
            let path = format!("/v{}/volumes/{name}", self.api_version);
            let (status, bytes) = self.api("GET", &path, None);
            if status == 404 {
                continue;
            }
            if status != 200 {
                complete = false;
                continue;
            }
            let Ok(inspected) = serde_json::from_slice::<Value>(&bytes) else {
                complete = false;
                continue;
            };
            if inspected["Name"] != name.as_str() || inspected["Labels"][OWNER_KEY] != self.run_id {
                complete = false;
                continue;
            }
            complete &= self.api("DELETE", &path, None).0 == 204;
            complete &= self.api("GET", &path, None).0 == 404;
        }
        self.cleaned = complete;
        complete
    }
}

impl Drop for LabelRun {
    fn drop(&mut self) {
        if !self.cleaned {
            let cleaned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup()))
                .unwrap_or(false);
            if !cleaned {
                eprintln!("DOCKERLENS_NATIVE_CHECK: volume_labels_cleanup_unverified");
            }
        }
    }
}

fn scoped_capabilities(run: &LabelRun) -> DaemonFacts {
    let observation_id = ObservationId::fresh().expect("test-only observation ID");
    let release = EngineRelease::new(required("NATIVE_ENGINE_VERSION")).unwrap();
    let (major, minor) = run.api_version.split_once('.').unwrap();
    let api_version = ApiVersion::new(
        NonZeroU16::new(major.parse().unwrap()).unwrap(),
        minor.parse().unwrap(),
    );
    let mode = match required("NATIVE_DAEMON_MODE").as_str() {
        "rootful" => DaemonMode::Rootful,
        "rootless" => DaemonMode::Rootless,
        _ => panic!("closed daemon mode"),
    };
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
        capabilities: [Capability::NamedVolume, Capability::VolumeLabels]
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
#[ignore = "requires the isolated exact-version native Engine harness"]
fn live_created_volume_labels_match_engine() {
    let mut run = LabelRun::new();
    eprintln!("DOCKERLENS_NATIVE_CHECK: volume_labels_create");
    let oracle = run.volumes[0].clone();
    let rendered = run.volumes[1].clone();
    let owner = format!("{OWNER_KEY}={}", run.run_id);
    let app = format!("{APP_KEY}={APP_VALUE}");
    let empty = format!("{EMPTY_KEY}=");
    let special = format!("{SPECIAL_KEY}={SPECIAL_VALUE}");
    let created = run.cli(&[
        "volume".into(),
        "create".into(),
        "--label".into(),
        owner,
        "--label".into(),
        app,
        "--label".into(),
        empty,
        "--label".into(),
        special,
        oracle.clone(),
    ]);
    assert_eq!(
        created,
        format!("{oracle}\n").as_bytes(),
        "CLI-created oracle name"
    );
    let expected_labels = json!({
        (OWNER_KEY):run.run_id,
        (APP_KEY):APP_VALUE,
        (EMPTY_KEY):"",
        (SPECIAL_KEY):SPECIAL_VALUE,
    });
    let oracle_inspect = run.inspect_volume(&oracle);
    assert_eq!(oracle_inspect["Name"], oracle);
    assert_eq!(oracle_inspect["Labels"], expected_labels);

    let intent = TargetIntent::new(vec![TargetResource::Volume {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(rendered.as_bytes().to_vec()).unwrap(),
        labels: vec![
            VolumeLabel::new(
                OWNER_KEY.as_bytes().to_vec(),
                run.run_id.as_bytes().to_vec(),
            )
            .unwrap(),
            VolumeLabel::new(APP_KEY.as_bytes().to_vec(), APP_VALUE.as_bytes().to_vec()).unwrap(),
            VolumeLabel::new(EMPTY_KEY.as_bytes().to_vec(), Vec::new()).unwrap(),
            VolumeLabel::new(
                SPECIAL_KEY.as_bytes().to_vec(),
                SPECIAL_VALUE.as_bytes().to_vec(),
            )
            .unwrap(),
        ],
    }])
    .unwrap();
    let facts = scoped_capabilities(&run);
    let caps = ValidatedCapabilities::new(&facts).unwrap();
    let graph = DockerPlanner.plan(&intent, &caps).unwrap();
    let artifact = DockerApiRenderer.render(&graph).unwrap();
    let request: Value = serde_json::from_slice(artifact.bytes().strip_suffix(b"\n").unwrap())
        .expect("one exact inert volume request");
    let expected_body = json!({"Name":rendered,"Labels":expected_labels});
    assert_eq!(request.as_object().unwrap().len(), 3);
    assert_eq!(request["method"], "POST");
    assert_eq!(
        request["path"],
        format!("/v{}/volumes/create", run.api_version)
    );
    assert_eq!(
        request["body"], expected_body,
        "independently authored label body"
    );
    assert!(!format!("{intent:?} {graph:?} {artifact:?}").contains(APP_VALUE));
    assert!(!format!("{intent:?} {graph:?} {artifact:?}").contains(SPECIAL_VALUE));
    let (status, _) = run.api(
        "POST",
        &format!("/v{}/volumes/create", run.api_version),
        Some(&request["body"]),
    );
    assert_eq!(status, 201, "Engine accepts labelled volume create");
    let rendered_inspect = run.inspect_volume(&rendered);
    assert_eq!(rendered_inspect["Name"], rendered);
    assert_eq!(rendered_inspect["Labels"], oracle_inspect["Labels"]);

    eprintln!("DOCKERLENS_NATIVE_CHECK: volume_labels_persistence");
    for index in 0..2 {
        run.data_persists(index);
        let inspect = run.inspect_volume(&run.volumes[index]);
        assert_eq!(
            inspect["Labels"], expected_labels,
            "labels persist with data"
        );
    }
    eprintln!("DOCKERLENS_NATIVE_CHECK: volume_labels_ownership");
    assert!(run.cleanup(), "exact label-verified cleanup required");
    let path = PathBuf::from(required("NATIVE_VOLUME_LABEL_PROBES_PATH"));
    assert_eq!(
        path.parent(),
        Some(PathBuf::from(required("NATIVE_CAPTURE_DIR")).as_path())
    );
    fs::write(path, serde_json::to_vec(PROBES).unwrap()).expect("private closed label evidence");
}
