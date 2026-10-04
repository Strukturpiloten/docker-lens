//! Test-only process identity proof; production planning/rendering stays inert.

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
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const OWNER: &str = "io.dockerlens.native-run";
const PROCESS: &str = "set -eu; id -u; id -g; pwd -P";
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

fn process_matches(output: &[u8]) -> bool {
    output == b"1000\n1000\n/tmp\n"
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
    names: [String; 2],
    ids: [Option<String>; 2],
    attempted: [bool; 2],
    image: String,
    socket: String,
    deadline: Instant,
    calls: Cell<usize>,
    bytes: Cell<usize>,
    cleaned: bool,
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
            names: [
                format!("dl-identity-{run}-oracle"),
                format!("dl-identity-{run}-rendered"),
            ],
            ids: [None, None],
            attempted: [false; 2],
            image: required("NATIVE_FIXTURE_IMAGE"),
            socket,
            deadline: Instant::now() + Duration::from_secs(remaining),
            calls: Cell::new(0),
            bytes: Cell::new(0),
            cleaned: false,
        }
    }

    fn timer(&self, cleanup: bool, elevated: bool) -> Command {
        let remaining = self
            .deadline
            .saturating_duration_since(Instant::now())
            .as_secs();
        assert!(
            remaining > if cleanup { 1 } else { 40 },
            "shared native identity budget"
        );
        let mut command = Command::new(if elevated { "sudo" } else { "timeout" });
        if elevated {
            command.args(["-n", "timeout"]);
        }
        command.args([
            "--signal=TERM",
            "--kill-after=1",
            &(remaining - 1).min(10).to_string(),
        ]);
        command
    }

    fn capture(&self, command: &mut Command, input: Option<&[u8]>, cap: usize) -> Vec<u8> {
        self.calls.set(self.calls.get() + 1);
        assert!(self.calls.get() <= 48, "native identity command count");
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
        assert!(status.success(), "bounded private command failed");
        output
    }

    fn cli(&self, args: &[String], cleanup: bool) -> Vec<u8> {
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
        self.capture(&mut command, None, 8192)
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

    fn bind(&mut self, index: usize, id: &str) {
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
        assert_eq!(inspected["Config"]["User"], "1000:1000");
        assert_eq!(inspected["Config"]["WorkingDir"], "/tmp");
        assert_eq!(inspected["Config"]["Cmd"], json!(["sh", "-c", PROCESS]));
        assert!(
            inspected["Config"]["Entrypoint"].is_null()
                || inspected["Config"]["Entrypoint"] == json!([]),
            "unmodified image entrypoint"
        );
    }

    fn cleanup(&mut self) -> bool {
        for index in 0..2 {
            if !self.attempted[index] {
                continue;
            }
            let name = self.names[index].clone();
            let (status, inspected) = self.inspect(&name, true);
            if status == 404 {
                continue;
            }
            if status != 200 || !owned(&inspected, self.ids[index].as_deref(), &name, &self.run) {
                return false;
            }
            let id = inspected["Id"].as_str().unwrap().to_owned();
            self.ids[index] = Some(id.clone());
            // Revalidate immutable identity immediately before ID-only removal.
            let (status, before) = self.inspect(&id, true);
            if status != 200 || !owned(&before, Some(&id), &name, &self.run) {
                return false;
            }
            if self
                .api(
                    "DELETE",
                    &format!("/v{}/containers/{id}?force=1", self.api_version),
                    None,
                    true,
                )
                .0
                != 204
            {
                return false;
            }
        }
        for _ in 0..2 {
            for index in 0..2 {
                if self.inspect(&self.names[index], true).0 != 404 {
                    return false;
                }
                if let Some(id) = &self.ids[index] {
                    if self.inspect(id, true).0 != 404 {
                        return false;
                    }
                }
            }
        }
        self.cleaned = true;
        true
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

    fn check_process(&self, index: usize, output: &[u8]) {
        assert!(
            process_matches(output),
            "actual numeric container UID/GID and working directory"
        );
        let id = self.ids[index].as_deref().unwrap();
        let (status, inspected) = self.inspect(id, false);
        assert_eq!(status, 200);
        assert!(
            owned(&inspected, Some(id), &self.names[index], &self.run),
            "identity readback ownership"
        );
        assert_eq!(inspected["Config"]["User"], "1000:1000");
        assert_eq!(inspected["Config"]["WorkingDir"], "/tmp");
        assert_eq!(inspected["Config"]["Cmd"], json!(["sh", "-c", PROCESS]));
        assert!(
            matches!(inspected["Path"].as_str(), Some("sh" | "/bin/sh")),
            "PID1 shell process"
        );
        assert_eq!(inspected["Args"], json!(["-c", PROCESS]));
        assert_eq!(inspected["State"]["Status"], "exited");
        assert_eq!(inspected["State"]["Running"], false);
        assert_eq!(inspected["State"]["ExitCode"], 0);
    }
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
    assert!(process_matches(b"1000\n1000\n/tmp\n"));
    for wrong in [
        b"0\n1000\n/tmp\n".as_slice(),
        b"1000\n0\n/tmp\n",
        b"1000\n1000\n/\n",
        b"1000\n1000\n",
        b"1000\n1000\n/tmp\nprotected-secret\n",
    ] {
        assert!(!process_matches(wrong));
    }
}

#[test]
fn identity_cleanup_never_accepts_foreign_or_replaced_ids_names_or_labels() {
    let id = "a".repeat(64);
    let good = json!({"Id":id,"Name":"/dl-identity-Ab12Cd34-oracle","Config":{"Labels":{(OWNER):"Ab12Cd34"}}});
    assert!(owned(
        &good,
        Some(&id),
        "dl-identity-Ab12Cd34-oracle",
        "Ab12Cd34"
    ));
    for field in ["Id", "Name", "Config"] {
        let mut wrong = good.clone();
        wrong[field] = json!("protected-secret");
        assert!(!owned(
            &wrong,
            Some(&id),
            "dl-identity-Ab12Cd34-oracle",
            "Ab12Cd34"
        ));
    }
    let mut replaced = good;
    replaced["Id"] = json!("b".repeat(64));
    assert!(!owned(
        &replaced,
        Some(&id),
        "dl-identity-Ab12Cd34-oracle",
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
#[ignore = "requires the isolated exact-version native Engine harness"]
fn live_container_process_identity_matches_engine() {
    let mut run = IdentityRun::new();
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
        let version: Value = serde_json::from_slice(&version).unwrap_or_else(|_| panic!("private daemon version JSON"));
        assert_eq!(version["Version"], required("NATIVE_ENGINE_VERSION"));
        assert_eq!(version["ApiVersion"], run.api_version);
        assert!(if run.lane.starts_with("debian11-") { matches!(version["Version"].as_str(), Some("20.10.5" | "20.10.5+dfsg1")) } else { version["Version"] == "29.8.1" }, "exact Engine release");
        let security: Vec<String> = serde_json::from_slice(&run.cli(&["info".into(), "--format".into(), "{{json .SecurityOptions}}".into()], false)).unwrap_or_else(|_| panic!("private daemon mode JSON"));
        assert_eq!(security.iter().any(|option| option == "name=rootless"), run.mode == DaemonMode::Rootless);
        for name in &run.names { assert_eq!(run.inspect(name, false).0, 404); }
        eprintln!("DOCKERLENS_NATIVE_CHECK: identity_oracle");
        run.attempted[0] = true;
        let created = run.cli(&["create".into(), "--name".into(), run.names[0].clone(), "--label".into(), format!("{OWNER}={}", run.run),
            "--user=1000:1000".into(), "--workdir=/tmp".into(), run.image.clone(), "sh".into(), "-c".into(), PROCESS.into()], false);
        let id = std::str::from_utf8(&created).unwrap_or_else(|_| panic!("private canonical ID")).trim().to_owned();
        run.bind(0, &id);
        let output = run.cli(&["start".into(), "--attach".into(), id], false);
        run.check_process(0, &output);
        eprintln!("DOCKERLENS_NATIVE_CHECK: identity_render");
        let settings = ContainerSettings { user: Some(ContainerUser::new(b"1000:1000".to_vec()).unwrap()),
            working_dir: Some(WorkingDirectory::new(b"/tmp".to_vec()).unwrap()),
            labels: vec![ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec()).unwrap()], ..ContainerSettings::default() };
        let container = ContainerIntent { reference: ResourceRef::new(1), identity: TargetIdentity::new(run.names[1].as_bytes().to_vec()).unwrap(),
            image: ImageReference::new(run.image.as_bytes().to_vec()).unwrap(), environment: vec![], ports: vec![], mounts: vec![], networks: vec![],
            entrypoint: ImageCommand::Inherit, command: ImageCommand::Exec(["sh", "-c", PROCESS].into_iter().map(|arg| Argument::new(arg.as_bytes().to_vec()).unwrap()).collect()),
            healthcheck: None, restart: None, settings };
        let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
        let facts = run.facts();
        let graph = DockerPlanner.plan(&intent, &ValidatedCapabilities::new(&facts).unwrap()).unwrap();
        let artifact = DockerApiRenderer.render(&graph).unwrap();
        assert!(!format!("{intent:?} {graph:?} {artifact:?}").contains(&run.run), "protected identity intent Debug");
        let bytes = artifact.bytes().strip_suffix(b"\n").unwrap();
        let request: Value = serde_json::from_slice(bytes).unwrap();
        let expected = json!({"Image":run.image,"Cmd":["sh","-c",PROCESS],"Labels":{(OWNER):run.run},"User":"1000:1000","WorkingDir":"/tmp","HostConfig":{}});
        assert_eq!(request, json!({"method":"POST","path":format!("/v{}/containers/create?name={}",run.api_version,run.names[1]),"body":expected}));
        run.attempted[1] = true;
        let (status, created) = run.api("POST", request["path"].as_str().unwrap(), Some(&request["body"]), false);
        assert_eq!(status, 201);
        let created: Value = serde_json::from_slice(&created).unwrap_or_else(|_| panic!("private create JSON"));
        let id = created["Id"].as_str().unwrap_or_else(|| panic!("canonical rendered ID")).to_owned();
        run.bind(1, &id);
        assert_eq!(run.api("POST", &format!("/v{}/containers/{id}/start",run.api_version), None, false).0, 204);
        assert_eq!(run.cli(&["wait".into(), id.clone()], false), b"0\n");
        let output = run.cli(&["logs".into(), id], false);
        run.check_process(1, &output);
    })).is_ok();
    eprintln!("DOCKERLENS_NATIVE_CHECK: identity_cleanup");
    let cleaned =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.cleanup())).unwrap_or(false);
    if !cleaned {
        eprintln!("DOCKERLENS_NATIVE_CHECK: identity_cleanup_unverified");
    }
    assert!(passed && cleaned, "closed native identity proof failed");
    let records = ["oracle", "rendered"].into_iter().enumerate().map(|(index, role)| json!({
        "role":role,"id":run.ids[index],"name":run.names[index],"owner":run.run,
        "configured_user":"passed","configured_workdir":"passed","runtime_uid":"passed","runtime_gid":"passed","runtime_workdir":"passed","cleanup":"absent"
    })).collect::<Vec<_>>();
    let proof = json!({"schema_version":1,"candidate_sha":run.candidate,"lane":run.lane,"mode":required("NATIVE_DAEMON_MODE"),
        "rendering_api":run.api_version,"run_id":run.run,"probes":PROBES,"containers":records});
    let bytes = serde_json::to_vec(&proof).unwrap();
    assert!(bytes.len() <= 4096, "closed proof bytes");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|_| panic!("fresh private identity proof"));
    file.write_all(&bytes)
        .unwrap_or_else(|_| panic!("private identity proof write"));
    file.sync_all()
        .unwrap_or_else(|_| panic!("private identity proof sync"));
    eprintln!("DOCKERLENS_NATIVE_CHECK: identity_evidence");
}
