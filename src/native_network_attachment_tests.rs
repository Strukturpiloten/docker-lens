//! Independent, test-only network-attachments-v1 proof. Product rendering stays inert.
use crate::acquisition::{Endpoint, Limits, NativeId, Selector, acquire};
use crate::decoder::decode_capture;
use crate::evidence::CaptureRoute;
use crate::observation::ResourceRef;
use crate::target::{
    Argument, ContainerIntent, ContainerLabel, ContainerSettings, DockerApiRenderer, DockerPlanner,
    ImageCommand, ImageReference, NetworkAlias, NetworkAttachmentIntent, NetworkCreate,
    NetworkIntent, NetworkLabel, NetworkRole, NetworkSource, Planner, Renderer, TargetIdentity,
    TargetIntent, TargetResource,
};
use crate::version::{
    ApiVersion, Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonFacts,
    DaemonMode, FactProvenance, ValidatedCapabilities,
};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        assert!(&$left == &$right, "closed attachment equality failed")
    };
}
const OWNER: &str = "io.dockerlens.native-run";
const CONTRACT: &str = "network-attachments-v1";
const SLOTS: [&str; 5] = [
    "primary_network",
    "secondary_network",
    "server",
    "primary_peer",
    "secondary_peer",
];
const SHAPES: [&str; 4] = [
    "NetworkCreateLabels",
    "NetworkPrimaryAliases",
    "NetworkSecondaryAliases",
    "NetworkSecondaryConnect",
];
const CANARY: &str = "network-attachments-canary";
const SERVER: &str = "printf network-attachments-canary >/tmp/index.html; httpd -f -p 8080 -h /tmp";
const PEER: &str = "sleep 160";
const SPECIAL: &str = "Grüße \"quoted\" \\ path\nline";
const OUTPUT_BUDGET: usize = 4 * 1024 * 1024;

fn with_output_capacity<T>(used: usize, stream_cap: usize, start: impl FnOnce() -> T) -> Option<T> {
    if stream_cap == 0 || used.checked_add(stream_cap.checked_mul(2)?)? > OUTPUT_BUDGET {
        return None;
    }
    Some(start())
}

fn required(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("closed attachment harness input missing"))
}
fn canonical(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn pin(value: &str) -> bool {
    value.split_once("@sha256:").is_some_and(|(tag, digest)| {
        tag.contains(':')
            && !tag.contains('@')
            && !tag.bytes().any(|b| b.is_ascii_whitespace())
            && canonical(digest, 64)
    })
}
fn private_stream(mut stream: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut data = Vec::new();
    let mut overflow = false;
    let mut chunk = [0; 4096];
    loop {
        let count = stream
            .read(&mut chunk)
            .unwrap_or_else(|_| panic!("closed attachment stream read"));
        if count == 0 {
            break;
        }
        let keep = count.min(limit - data.len());
        data.extend_from_slice(&chunk[..keep]);
        overflow |= keep != count;
    }
    (data, overflow)
}

#[derive(Clone)]
struct Resource {
    role: String,
    slot: String,
    name: String,
    network: bool,
    id: Option<String>,
    live: bool,
    deleted: bool,
}
impl Resource {
    fn new(run: &str, role: &str, slot: &str) -> Self {
        assert!(
            matches!(role, "oracle" | "rendered") && SLOTS.contains(&slot),
            "closed attachment role/slot"
        );
        Self {
            role: role.into(),
            slot: slot.into(),
            name: format!("dl-na-{run}-{role}-{}", slot.replace('_', "-")),
            network: slot.ends_with("network"),
            id: None,
            live: false,
            deleted: false,
        }
    }
    fn kind(&self) -> &'static str {
        if self.network {
            "networks"
        } else {
            "containers"
        }
    }
}

fn cleanup_reserve(history: usize, outstanding: usize) -> Duration {
    // Each live resource needs ownership + delete; all known ID/name pairs
    // receive two final absence rounds. Cleanup calls have a 1s outer bound
    // including KILL grace. Five seconds remain for context and publication.
    Duration::from_secs((2 * outstanding + 4 * history + 5).max(45) as u64)
}

fn exact_acquisition_versions(
    captured: &[ApiVersion],
    decoded: &[ApiVersion],
    expected: ApiVersion,
) -> bool {
    !captured.is_empty() && captured.iter().all(|api| *api == expected) && decoded == [expected]
}

struct Run {
    token: String,
    lane: String,
    mode: DaemonMode,
    api: String,
    release: String,
    package: String,
    image: String,
    outer_image: String,
    outer_id: String,
    outer_name: String,
    socket: String,
    directory: PathBuf,
    path: PathBuf,
    candidate: String,
    elevated: bool,
    deadline: Instant,
    epoch: SystemTime,
    work_calls: usize,
    work_bytes: usize,
    cleanup_calls: usize,
    cleanup_bytes: usize,
    resources: Vec<Resource>,
    facts: Option<DaemonFacts>,
    context: Value,
    mutation_uncertain: bool,
    cleanup_uncertain: bool,
    finished: bool,
}
impl Run {
    fn new() -> Self {
        let outer_name = required("NATIVE_OUTER_CONTAINER");
        let token = outer_name
            .strip_prefix("dl-native-")
            .unwrap_or_else(|| panic!("closed attachment outer prefix"))
            .to_owned();
        assert!(
            token.len() == 8 && token.bytes().all(|b| b.is_ascii_alphanumeric()),
            "closed attachment run token"
        );
        let lane = required("NATIVE_LANE");
        let api = required("NATIVE_API_VERSION");
        let mode = match required("NATIVE_DAEMON_MODE").as_str() {
            "rootful" => DaemonMode::Rootful,
            "rootless" => DaemonMode::Rootless,
            _ => panic!("closed attachment mode"),
        };
        assert!(
            matches!(lane.as_str(), "debian11-rootful" | "debian11-rootless") && api == "1.41"
                || matches!(lane.as_str(), "upstream-rootful" | "upstream-rootless")
                    && api == "1.56",
            "closed attachment lane/API"
        );
        assert_eq!(lane.ends_with("-rootless"), mode == DaemonMode::Rootless);
        let candidate = required("NATIVE_NETWORK_ATTACHMENT_CANDIDATE_SHA");
        let outer_id = required("NATIVE_OUTER_CONTAINER_ID");
        assert!(
            canonical(&candidate, 40) && canonical(&outer_id, 64),
            "closed attachment exact identities"
        );
        let image = required("NATIVE_FIXTURE_IMAGE");
        let outer_image = required("NATIVE_OUTER_IMAGE");
        assert!(
            pin(&image) && pin(&outer_image),
            "closed attachment immutable images"
        );
        let directory = PathBuf::from(required("NATIVE_CAPTURE_DIR"));
        let path = PathBuf::from(required("NATIVE_NETWORK_ATTACHMENT_PROOF_PATH"));
        assert_eq!(path, directory.join("network-attachments-v1.json"));
        let _ = held_directory(&directory);
        assert!(
            fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "new attachment proof only"
        );
        let socket = required("NATIVE_ENGINE_SOCKET");
        assert_eq!(PathBuf::from(&socket), directory.join("socket/docker.sock"));
        let epoch = UNIX_EPOCH
            + Duration::from_secs(
                required("NATIVE_NETWORK_TEST_DEADLINE_EPOCH")
                    .parse()
                    .unwrap_or_else(|_| panic!("closed attachment cutoff")),
            );
        let remaining = epoch
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .min(Duration::from_secs(180));
        assert!(
            remaining > Duration::from_secs(60),
            "closed attachment startup reserve"
        );
        let elevated = match required("NATIVE_PODMAN_USE_SUDO").as_str() {
            "0" => false,
            "1" => true,
            _ => panic!("closed attachment privilege selector"),
        };
        Self {
            token,
            lane,
            mode,
            api,
            release: required("NATIVE_ENGINE_VERSION"),
            package: required("NATIVE_DOCKER_PACKAGE"),
            image,
            outer_image,
            outer_id,
            outer_name,
            socket,
            directory,
            path,
            candidate,
            elevated,
            deadline: Instant::now() + remaining,
            epoch,
            work_calls: 0,
            work_bytes: 0,
            cleanup_calls: 0,
            cleanup_bytes: 0,
            resources: Vec::new(),
            facts: None,
            context: Value::Null,
            mutation_uncertain: false,
            cleanup_uncertain: false,
            finished: false,
        }
    }
    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now()).min(
            self.epoch
                .duration_since(SystemTime::now())
                .unwrap_or_default(),
        )
    }
    fn capture(
        &mut self,
        cleanup: bool,
        elevated: bool,
        seconds: u64,
        args: &[String],
        input: Option<&[u8]>,
        cap: usize,
    ) -> std::process::Output {
        let remaining = self.remaining();
        if cleanup {
            assert!(
                remaining > Duration::from_secs(2),
                "attachment cleanup deadline"
            );
            self.cleanup_calls += 1;
            assert!(self.cleanup_calls <= 160, "attachment cleanup call budget");
        } else {
            let outstanding = self.resources.iter().filter(|r| r.live).count();
            assert!(outstanding <= 5, "attachment live resource bound");
            assert!(
                remaining
                    > cleanup_reserve(self.resources.len(), outstanding)
                        + Duration::from_secs(seconds + 1),
                "attachment work cleanup reserve"
            );
            self.work_calls += 1;
            assert!(self.work_calls <= 200, "attachment work call budget");
        }
        let mut command = Command::new(if elevated { "sudo" } else { "timeout" });
        if elevated {
            command.args(["-n", "timeout"]);
        }
        command.args([
            "--signal=TERM",
            "--kill-after=0.25s",
            if cleanup { "0.75s" } else { "3s" },
        ]);
        // Work callers request only 2s curl/CLI operations, with a 3s outer
        // bound. Cleanup is 0.5s curl with 0.75s TERM + 0.25s KILL.
        assert!(seconds <= 3, "closed attachment command bound");
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let used = if cleanup {
            self.cleanup_bytes
        } else {
            self.work_bytes
        };
        let mut child = with_output_capacity(used, cap, || command.spawn())
            .unwrap_or_else(|| panic!("closed attachment output capacity"))
            .unwrap_or_else(|_| panic!("closed attachment command spawn"));
        if let Some(bytes) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(bytes)
                .unwrap_or_else(|_| panic!("closed attachment input write"));
        }
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let out = std::thread::spawn(move || private_stream(stdout, cap));
        let err = std::thread::spawn(move || private_stream(stderr, cap));
        let status = child
            .wait()
            .unwrap_or_else(|_| panic!("closed attachment command wait"));
        let (stdout, out_over) = out
            .join()
            .unwrap_or_else(|_| panic!("closed attachment output join"));
        let (stderr, err_over) = err
            .join()
            .unwrap_or_else(|_| panic!("closed attachment error join"));
        let retained = stdout.len() + stderr.len();
        if cleanup {
            self.cleanup_bytes += retained;
            assert!(
                self.cleanup_bytes <= OUTPUT_BUDGET,
                "attachment cleanup byte budget"
            );
        } else {
            self.work_bytes += retained;
            assert!(
                self.work_bytes <= OUTPUT_BUDGET,
                "attachment work byte budget"
            );
        }
        assert!(!out_over && !err_over, "attachment output overflow");
        std::process::Output {
            status,
            stdout,
            stderr,
        }
    }
    fn podman(&mut self, cleanup: bool, args: &[String]) -> std::process::Output {
        let mut command = vec!["podman".into(), "--remote=false".into()];
        command.extend_from_slice(args);
        self.capture(cleanup, self.elevated, 3, &command, None, 64 * 1024)
    }
    fn cli(&mut self, args: &[String], mutation: bool) -> Vec<u8> {
        let previous = self.mutation_uncertain;
        if mutation {
            self.mutation_uncertain = true;
        }
        let mut command = vec![
            "exec".into(),
            self.outer_id.clone(),
            "docker".into(),
            "-H".into(),
            format!("unix://{}", "/dockerlens-native/docker.sock"),
        ];
        command.extend_from_slice(args);
        let output = self.podman(false, &command);
        assert!(
            output.status.success(),
            "attachment CLI completed positive required"
        );
        if mutation {
            self.mutation_uncertain = previous;
        }
        output.stdout
    }
    fn route_allowed(&self, method: &str, path: &str, body: Option<&Value>) -> bool {
        let prefix = format!("/v{}", self.api);
        if method == "GET" && (path == "/version" || path == format!("{prefix}/info")) {
            return true;
        }
        self.resources.iter().any(|r| {
            let keys = std::iter::once(r.name.as_str()).chain(r.id.as_deref());
            if method == "GET"
                && keys.into_iter().any(|key| {
                    path == format!(
                        "{prefix}/{}/{key}{}",
                        r.kind(),
                        if r.network { "" } else { "/json" }
                    )
                })
            {
                return true;
            }
            if method == "DELETE" {
                return r.id.as_ref().is_some_and(|id| {
                    path == format!(
                        "{prefix}/{}/{id}{}",
                        r.kind(),
                        if r.network { "" } else { "?force=1" }
                    )
                });
            }
            if method != "POST" {
                return false;
            }
            if r.network && path == format!("{prefix}/networks/create") {
                return body.is_some_and(|v| v["Name"] == r.name);
            }
            if !r.network && path == format!("{prefix}/containers/create?name={}", r.name) {
                return body
                    .is_some_and(|v| v["Labels"][OWNER] == self.token && v["Image"] == self.image);
            }
            if !r.network
                && r.id
                    .as_ref()
                    .is_some_and(|id| path == format!("{prefix}/containers/{id}/start"))
            {
                return body.is_none();
            }
            r.network
                && r.id.is_some()
                && path == format!("{prefix}/networks/{}/connect", r.name)
                && body.is_some_and(|v| {
                    self.resources.iter().any(|server| {
                        server.role == r.role
                            && server.slot == "server"
                            && server.id.is_some()
                            && v["Container"] == server.name
                    })
                })
        })
    }
    fn api(
        &mut self,
        cleanup: bool,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> (u16, Vec<u8>) {
        assert!(
            self.route_allowed(method, path, body),
            "closed attachment API allowlist"
        );
        let previous = self.mutation_uncertain;
        if method != "GET" {
            self.mutation_uncertain = true;
        }
        let input = body.map(|v| serde_json::to_vec(v).unwrap());
        let mut args = vec![
            "curl".into(),
            "-q".into(),
            "--noproxy".into(),
            "*".into(),
            "-sS".into(),
            "--max-time".into(),
            if cleanup { "0.5".into() } else { "2".into() },
            "--max-filesize".into(),
            "16384".into(),
            "--unix-socket".into(),
            self.socket.clone(),
            "-X".into(),
            method.into(),
            "-H".into(),
            "Content-Type: application/json".into(),
        ];
        if input.is_some() {
            args.extend(["--data-binary".into(), "@-".into()]);
        } else if method == "POST" {
            args.extend(["--data-binary".into(), String::new()]);
        }
        args.extend([
            "-w".into(),
            "\n%{http_code}".into(),
            format!("http://localhost{path}"),
        ]);
        let output = self.capture(cleanup, false, 3, &args, input.as_deref(), 16 * 1024 + 8);
        assert!(
            output.status.success(),
            "attachment API transport must complete"
        );
        let split = output
            .stdout
            .iter()
            .rposition(|b| *b == b'\n')
            .unwrap_or_else(|| panic!("closed attachment HTTP framing"));
        let code = std::str::from_utf8(&output.stdout[split + 1..])
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("closed attachment HTTP code"));
        if method != "GET" {
            self.mutation_uncertain = previous;
        }
        (code, output.stdout[..split].to_vec())
    }
    fn inspect(&mut self, index: usize, cleanup: bool) -> (u16, Value) {
        let r = &self.resources[index];
        let key = r.id.as_deref().unwrap_or(&r.name);
        let path = format!(
            "/v{}/{}/{key}{}",
            self.api,
            r.kind(),
            if r.network { "" } else { "/json" }
        );
        let (code, bytes) = self.api(cleanup, "GET", &path, None);
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("closed attachment inspect JSON"));
        (code, value)
    }
    fn authenticate(&self, index: usize, value: &Value) -> bool {
        let r = &self.resources[index];
        let Some(id) = value["Id"].as_str() else {
            return false;
        };
        canonical(id, 64)
            && r.id.as_ref().is_none_or(|expected| expected == id)
            && value["Name"]
                == if r.network {
                    r.name.clone()
                } else {
                    format!("/{}", r.name)
                }
            && if r.network {
                value["Driver"] == "bridge" && value["Labels"][OWNER] == self.token
            } else {
                value["Config"]["Labels"][OWNER] == self.token
                    && value["Config"]["Image"] == self.image
            }
    }
    fn owned(&mut self, index: usize) -> Value {
        let (code, value) = self.inspect(index, false);
        assert_eq!(code, 200);
        assert!(
            self.authenticate(index, &value),
            "attachment exact owned resource required"
        );
        if !self.resources[index].network {
            assert_eq!(value["Config"]["Labels"], json!({OWNER:self.token}));
            assert_eq!(
                value["Config"]["Cmd"],
                json!([
                    "sh",
                    "-c",
                    if self.resources[index].slot == "server" {
                        SERVER
                    } else {
                        PEER
                    }
                ])
            );
        }
        value
    }
    fn add(&mut self, role: &str, slot: &str) -> usize {
        let r = Resource::new(&self.token, role, slot);
        assert!(
            self.resources.iter().filter(|r| r.live).count() < 5,
            "attachment maximum five live resources"
        );
        assert!(
            !self.resources.iter().any(|known| known.name == r.name),
            "attachment unique attempted name"
        );
        self.resources.push(r);
        self.resources.len() - 1
    }
    fn bind(&mut self, index: usize, id: &str) {
        assert!(
            canonical(id, 64)
                && id != self.outer_id
                && !self.resources.iter().any(|r| r.id.as_deref() == Some(id)),
            "attachment unique canonical creation ID"
        );
        self.resources[index].id = Some(id.into());
        let _ = self.owned(index);
    }
    fn start(&mut self, index: usize) {
        let _ = self.owned(index);
        let path = format!(
            "/v{}/containers/{}/start",
            self.api,
            self.resources[index].id.as_ref().unwrap()
        );
        assert_eq!(self.api(false, "POST", &path, None).0, 204);
        let value = self.owned(index);
        assert!(
            value["State"]["Running"] == true && value["State"]["Status"] == "running",
            "attachment running positive required"
        );
    }
    fn absent(&mut self, index: usize, id: bool) -> bool {
        let r = &self.resources[index];
        let key = if id {
            r.id.as_deref().unwrap()
        } else {
            &r.name
        };
        let path = format!(
            "/v{}/{}/{key}{}",
            self.api,
            r.kind(),
            if r.network { "" } else { "/json" }
        );
        self.api(true, "GET", &path, None).0 == 404
    }
    fn cleanup(&mut self) -> bool {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(
                self.outer_snapshot(true, false).is_some(),
                "attachment outer ownership for cleanup"
            );
            let mut all = true;
            for index in (0..self.resources.len()).rev() {
                if !self.resources[index].live || self.resources[index].deleted {
                    continue;
                }
                let removed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let (code, value) = self.inspect(index, true);
                    if code == 404 {
                        assert!(
                            self.resources[index].id.is_none(),
                            "unexpected attachment disappearance"
                        );
                        self.resources[index].deleted = true;
                        return;
                    }
                    assert_eq!(code, 200);
                    assert!(
                        self.authenticate(index, &value),
                        "attachment cleanup refuses foreign ownership"
                    );
                    if self.resources[index].id.is_none() {
                        self.resources[index].id = value["Id"].as_str().map(str::to_owned);
                    }
                    let r = &self.resources[index];
                    let path = format!(
                        "/v{}/{}/{}{}",
                        self.api,
                        r.kind(),
                        r.id.as_ref().unwrap(),
                        if r.network { "" } else { "?force=1" }
                    );
                    assert_eq!(self.api(true, "DELETE", &path, None).0, 204);
                    self.resources[index].deleted = true;
                }))
                .is_ok();
                all &= removed;
            }
            for _ in 0..2 {
                for index in 0..self.resources.len() {
                    let absent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        assert!(self.absent(index, false), "attachment final name absence");
                        if self.resources[index].id.is_some() {
                            assert!(self.absent(index, true), "attachment final ID absence");
                        }
                    }))
                    .is_ok();
                    all &= absent;
                }
            }
            if all {
                for r in &mut self.resources {
                    r.live = false;
                }
            }
            all
        }))
        .unwrap_or(false);
        self.cleanup_uncertain |= !result;
        result
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        if !self.finished && self.resources.iter().any(|r| r.live) && !self.cleanup() {
            eprintln!("DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup_unverified");
        }
    }
}

impl Run {
    fn outer_snapshot(&mut self, cleanup: bool, full: bool) -> Option<Value> {
        let output = self.podman(
            cleanup,
            &[
                "inspect".into(),
                "--format".into(),
                "{{json .}}".into(),
                self.outer_id.clone(),
            ],
        );
        if !output.status.success() || !output.stderr.is_empty() {
            return None;
        }
        let value: Value = serde_json::from_slice(&output.stdout).ok()?;
        if value["Id"] != self.outer_id
            || value["Name"] != self.outer_name
            || value["Config"]["Labels"][OWNER] != self.token
            || value["ImageDigest"] != self.outer_image.split_once('@')?.1
        {
            return None;
        }
        if full {
            let h = &value["HostConfig"];
            let mounts = value["Mounts"].as_array()?;
            let volume: Vec<_> = mounts.iter().filter(|m| m["Type"] == "volume").collect();
            let bind: Vec<_> = mounts.iter().filter(|m| m["Type"] == "bind").collect();
            let networks = value["NetworkSettings"]["Networks"].as_object()?;
            let root = if self.mode == DaemonMode::Rootless {
                "/home/docker/.local/share/docker"
            } else {
                "/var/lib/docker"
            };
            if value["State"]["Running"] != true
                || h["Privileged"] != true
                || h["Memory"] != 4294967296_u64
                || h["CpuQuota"] != 200000
                || h["CpuPeriod"] != 100000
                || h["PidsLimit"] != 512
                || mounts.len() != 2
                || volume.len() != 1
                || bind.len() != 1
                || volume[0]["Name"] != format!("dl-native-data-{}", self.token)
                || volume[0]["Destination"] != root
                || volume[0]["RW"] != true
                || bind[0]["Source"] != self.directory.join("socket").to_str()?
                || bind[0]["Destination"] != "/dockerlens-native"
                || bind[0]["RW"] != true
                || networks.len() != 1
                || !networks.contains_key(&format!("dl-native-net-{}", self.token))
            {
                return None;
            }
        }
        Some(
            json!({"id":self.outer_id,"name":self.outer_name,"owner":self.token,"image":self.outer_image,
            "data_volume":format!("dl-native-data-{}",self.token),"socket_source":self.directory.join("socket"),
            "privileged":true,"memory_bytes":4294967296_u64,"cpu_quota":200000,"cpu_period":100000,"pids_limit":512}),
        )
    }
    fn observe_context(&mut self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: network_attachment_context");
        let outer = self
            .outer_snapshot(false, true)
            .unwrap_or_else(|| panic!("attachment exact native outer setup"));
        let (code, bytes) = self.api(false, "GET", "/version", None);
        assert_eq!(code, 200);
        let version: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("closed attachment version JSON"));
        assert_eq!(version["Version"], self.release);
        assert_eq!(version["ApiVersion"], self.api);
        if self.lane.starts_with("debian11-") {
            assert!(
                matches!(self.release.as_str(), "20.10.5" | "20.10.5+dfsg1"),
                "exact attachment Debian release"
            );
            let package = self.podman(
                false,
                &[
                    "exec".into(),
                    self.outer_id.clone(),
                    "dpkg-query".into(),
                    "-W".into(),
                    "-f=${Version}".into(),
                    "docker.io".into(),
                ],
            );
            assert!(package.status.success(), "attachment exact package query");
            assert_eq!(package.stdout, b"20.10.5+dfsg1-1+deb11u2".to_vec());
            assert_eq!(self.package, "20.10.5+dfsg1-1+deb11u2");
        } else {
            assert_eq!(self.release, "29.8.1");
            assert_eq!(self.package, "");
        }
        let client = self.cli(
            &[
                "version".into(),
                "--format".into(),
                "{{.Server.Version}}|{{.Server.APIVersion}}".into(),
            ],
            false,
        );
        assert_eq!(
            client,
            format!("{}|{}\n", self.release, self.api).into_bytes()
        );
        let (code, bytes) = self.api(false, "GET", &format!("/v{}/info", self.api), None);
        assert_eq!(code, 200);
        let info: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("closed attachment info JSON"));
        let rootless = info["Rootless"] == true
            || info["SecurityOptions"].as_array().is_some_and(|options| {
                options.iter().any(|v| {
                    v.as_str()
                        .is_some_and(|s| s == "name=rootless" || s.starts_with("name=rootless,"))
                })
            });
        assert_eq!(rootless, self.mode == DaemonMode::Rootless);
        let cli_security = self.cli(
            &[
                "info".into(),
                "--format".into(),
                "{{json .SecurityOptions}}".into(),
            ],
            false,
        );
        let cli_security: Vec<String> = serde_json::from_slice(&cli_security)
            .unwrap_or_else(|_| panic!("closed attachment CLI mode JSON"));
        assert_eq!(
            cli_security
                .iter()
                .any(|s| s == "name=rootless" || s.starts_with("name=rootless,")),
            rootless
        );
        let process = self.podman(false, &["exec".into(), self.outer_id.clone(), "sh".into(), "-ec".into(),
            "count=0; uid=; for p in /proc/[0-9]*/comm; do [ -r \"$p\" ] || continue; read -r n <\"$p\" || continue; [ \"$n\" = dockerd ] || continue; count=$((count+1)); uid=$(awk '/^Uid:/ {print $3}' \"${p%/comm}/status\"); done; [ \"$count\" -eq 1 ]; printf '%s\\n' \"$uid\"".into()]);
        assert!(
            process.status.success(),
            "attachment unique dockerd process query"
        );
        let uid = std::str::from_utf8(&process.stdout)
            .ok()
            .and_then(|s| s.trim_end_matches('\n').parse::<u32>().ok())
            .unwrap_or_else(|| panic!("closed attachment daemon UID"));
        assert_eq!(uid != 0, rootless);
        self.work_calls += 16;
        self.work_bytes += 1024 * 1024;
        assert!(
            self.work_calls <= 200 && self.work_bytes <= 4 * 1024 * 1024,
            "attachment capture work budget"
        );
        let max_elapsed = self
            .remaining()
            .checked_sub(Duration::from_secs(45))
            .unwrap()
            .min(Duration::from_secs(10));
        let capture = acquire(
            &Endpoint::unix_socket(PathBuf::from(&self.socket)),
            Selector::ContainerIds(vec![
                NativeId::new(required("NATIVE_CONTAINER_ID")).unwrap(),
            ]),
            Limits {
                max_requests: 16,
                max_selected_resources: 2,
                max_expansions: 8,
                max_response_bytes: 128 * 1024,
                max_total_bytes: 1024 * 1024,
                max_elapsed,
            },
            &AtomicBool::new(false),
        )
        .unwrap_or_else(|_| panic!("actual attachment socket capture required"));
        assert_eq!(capture.route(), CaptureRoute::ExplicitUnixSocket);
        assert!(
            capture.exchanges().iter().all(|e| e.status().code() == 200),
            "attachment complete capture exchanges"
        );
        let decoded = decode_capture(&capture)
            .unwrap_or_else(|_| panic!("actual attachment decode required"));
        let expected_acquisition = ApiVersion::new(
            std::num::NonZeroU16::new(1).unwrap(),
            if self.lane.starts_with("debian11-") {
                41
            } else {
                49
            },
        );
        let versions: Vec<_> = capture
            .exchanges()
            .iter()
            .filter_map(|e| e.api_version())
            .collect();
        assert!(
            exact_acquisition_versions(
                &versions,
                &decoded.version.requested_api_versions,
                expected_acquisition
            ),
            "attachment exact lane acquisition API required"
        );
        let mut facts = decoded.version.daemon;
        assert_eq!(facts.observation_id, capture.observation_id());
        assert_eq!(facts.release.as_ref().unwrap().as_str(), self.release);
        assert_eq!(
            format!(
                "{}.{}",
                facts.api_version.unwrap().major,
                facts.api_version.unwrap().minor
            ),
            self.api
        );
        if rootless {
            assert_eq!(facts.mode, DaemonMode::Rootless);
        } else {
            assert!(
                facts.mode != DaemonMode::Rootless,
                "attachment rootful corroboration"
            );
            facts.mode = DaemonMode::Rootful;
        }
        let acquisition_api = format!("{}.{}", versions[0].major, versions[0].minor);
        self.context = json!({"candidate_sha":self.candidate,"run_id":self.token,"lane":self.lane,
            "engine_release":self.release,"rendering_api":self.api,"acquisition_api":acquisition_api,
            "mode":if rootless {"rootless"} else {"rootful"},"docker_package":self.package,"fixture_image":self.image,"outer":outer});
        self.facts = Some(facts);
    }
    fn create_network(&mut self, role: &str, slot: &str, request: Option<&Value>) -> usize {
        let index = self.add(role, slot);
        let name = self.resources[index].name.clone();
        // Check genuine exact-name absence before mutation; a collision can
        // never be adopted from a creation response or removed as this role.
        assert_eq!(self.inspect(index, false).0, 404);
        self.resources[index].live = true;
        let id = if let Some(request) = request {
            let (code, bytes) = self.api(
                false,
                "POST",
                request["path"].as_str().unwrap(),
                Some(&request["body"]),
            );
            assert_eq!(code, 201);
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            value["Id"].as_str().unwrap().to_owned()
        } else {
            let labels = labels(&self.token);
            let mut args = vec![
                "network".into(),
                "create".into(),
                "--driver".into(),
                "bridge".into(),
            ];
            for (key, value) in labels.as_object().unwrap() {
                args.extend([
                    "--label".into(),
                    format!("{key}={}", value.as_str().unwrap()),
                ]);
            }
            args.push(name);
            String::from_utf8(self.cli(&args, true))
                .unwrap_or_else(|_| panic!("closed attachment network ID"))
                .trim_end_matches('\n')
                .into()
        };
        self.bind(index, &id);
        index
    }
    fn create_container(
        &mut self,
        role: &str,
        slot: &str,
        network: usize,
        aliases: &[String],
        request: Option<&Value>,
    ) -> usize {
        let _ = self.owned(network);
        let index = self.add(role, slot);
        assert_eq!(self.inspect(index, false).0, 404);
        self.resources[index].live = true;
        let name = self.resources[index].name.clone();
        let script = if slot == "server" { SERVER } else { PEER };
        let id = if let Some(request) = request {
            let (code, bytes) = self.api(
                false,
                "POST",
                request["path"].as_str().unwrap(),
                Some(&request["body"]),
            );
            assert_eq!(code, 201);
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            value["Id"].as_str().unwrap().to_owned()
        } else {
            let mut args = vec![
                "container".into(),
                "create".into(),
                "--name".into(),
                name,
                "--label".into(),
                format!("{OWNER}={}", self.token),
                "--network".into(),
                self.resources[network].id.as_ref().unwrap().clone(),
            ];
            for alias in aliases {
                args.extend(["--network-alias".into(), alias.clone()]);
            }
            args.extend([self.image.clone(), "sh".into(), "-c".into(), script.into()]);
            String::from_utf8(self.cli(&args, true))
                .unwrap_or_else(|_| panic!("closed attachment container ID"))
                .trim_end_matches('\n')
                .into()
        };
        self.bind(index, &id);
        index
    }
    fn connect(
        &mut self,
        server: usize,
        network: usize,
        aliases: &[String],
        request: Option<&Value>,
    ) {
        let _ = self.owned(server);
        let _ = self.owned(network);
        if let Some(request) = request {
            assert_eq!(
                self.api(
                    false,
                    "POST",
                    request["path"].as_str().unwrap(),
                    Some(&request["body"])
                )
                .0,
                200
            );
        } else {
            let mut args = vec!["network".into(), "connect".into()];
            for alias in aliases {
                args.extend(["--alias".into(), alias.clone()]);
            }
            args.extend([
                self.resources[network].id.as_ref().unwrap().clone(),
                self.resources[server].id.as_ref().unwrap().clone(),
            ]);
            let _ = self.cli(&args, true);
        }
    }
    fn membership(&mut self, network: usize, expected: &[usize]) {
        let value = self.owned(network);
        let map = value["Containers"]
            .as_object()
            .unwrap_or_else(|| panic!("attachment active membership map"));
        let mut actual: Vec<_> = map.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut expected_ids: Vec<_> = expected
            .iter()
            .map(|i| self.resources[*i].id.as_deref().unwrap())
            .collect();
        expected_ids.sort_unstable();
        assert_eq!(actual, expected_ids);
        for index in expected {
            let r = &self.resources[*index];
            assert_eq!(map[r.id.as_ref().unwrap()]["Name"], r.name);
        }
    }
    fn running_addresses(&mut self, container: usize, networks: &[usize]) -> Vec<Ipv4Addr> {
        let value = self.owned(container);
        assert!(
            value["State"]["Running"] == true && value["State"]["Status"] == "running",
            "attachment actual running state"
        );
        let map = value["NetworkSettings"]["Networks"].as_object().unwrap();
        assert_eq!(map.len(), networks.len());
        networks
            .iter()
            .map(|network| {
                let r = &self.resources[*network];
                let endpoint = &map[&r.name];
                assert_eq!(endpoint["NetworkID"], r.id.as_deref().unwrap());
                let text = endpoint["IPAddress"].as_str().unwrap();
                let ip: Ipv4Addr = text
                    .parse()
                    .unwrap_or_else(|_| panic!("closed attachment IPv4"));
                assert!(
                    ip.is_private() && text == ip.to_string(),
                    "attachment canonical private endpoint IPv4"
                );
                ip
            })
            .collect()
    }
    fn retained_aliases(
        &mut self,
        container: usize,
        network: usize,
        expected: &[String],
        forbidden: &str,
    ) {
        let value = self.owned(container);
        let endpoint = &value["NetworkSettings"]["Networks"][&self.resources[network].name];
        let aliases = endpoint["Aliases"].as_array().unwrap();
        assert!(
            expected
                .iter()
                .all(|name| aliases.iter().any(|a| a.as_str() == Some(name.as_str())))
                && !aliases.iter().any(|a| a.as_str() == Some(forbidden)),
            "attachment retained per-network authored aliases"
        );
    }
    fn effects(&mut self, peer: usize, unique: &str, shared: &str, ip: Ipv4Addr) {
        let _ = self.owned(peer);
        let id = self.resources[peer].id.as_ref().unwrap().clone();
        let resolver = self.cli(
            &[
                "exec".into(),
                id.clone(),
                "cat".into(),
                "/etc/resolv.conf".into(),
            ],
            false,
        );
        assert!(
            resolver
                .split(|b| *b == b'\n')
                .any(|line| line == b"nameserver 127.0.0.11"),
            "attachment embedded DNS premise"
        );
        for alias in [unique, shared] {
            let answer = self.cli(
                &[
                    "exec".into(),
                    id.clone(),
                    "nslookup".into(),
                    "-type=A".into(),
                    format!("{alias}."),
                    "127.0.0.11".into(),
                ],
                false,
            );
            assert!(
                exact_a(&answer, alias, ip),
                "attachment exact complete scoped A answer"
            );
            let body = self.cli(
                &[
                    "exec".into(),
                    id.clone(),
                    "wget".into(),
                    "-Y".into(),
                    "off".into(),
                    "-T".into(),
                    "2".into(),
                    "-qO-".into(),
                    format!("http://{alias}:8080/"),
                ],
                false,
            );
            assert_eq!(body, CANARY.as_bytes().to_vec());
        }
        let body = self.cli(
            &[
                "exec".into(),
                id,
                "wget".into(),
                "-Y".into(),
                "off".into(),
                "-T".into(),
                "2".into(),
                "-qO-".into(),
                format!("http://{ip}:8080/"),
            ],
            false,
        );
        assert_eq!(body, CANARY.as_bytes().to_vec());
    }
    fn role(&mut self, role: &str) -> Value {
        let names: Vec<_> = SLOTS
            .iter()
            .map(|slot| Resource::new(&self.token, role, slot).name)
            .collect();
        let primary_alias = format!("na-{}-{role}-primary", self.token);
        let secondary_alias = format!("na-{}-{role}-secondary", self.token);
        let shared = format!("na-{}-{role}-shared", self.token);
        let primary_aliases = vec![primary_alias.clone(), shared.clone()];
        let secondary_aliases = vec![secondary_alias.clone(), shared.clone()];
        let expected = expected_requests(
            &self.api,
            &self.image,
            &self.token,
            &names,
            &primary_aliases,
            &secondary_aliases,
        );
        let rendered = if role == "rendered" {
            let requests = rendered_requests(
                self.facts.as_ref().unwrap(),
                &self.image,
                &self.token,
                &names,
                &primary_aliases,
                &secondary_aliases,
            );
            assert_eq!(requests, expected);
            Some(requests)
        } else {
            None
        };
        let request = |i| rendered.as_ref().map(|r| &r[i]);
        let a = self.create_network(role, SLOTS[0], request(0));
        let b = self.create_network(role, SLOTS[1], request(1));
        for network in [a, b] {
            let value = self.owned(network);
            assert_eq!(value["Labels"], labels(&self.token));
            assert!(
                value["Internal"] == false && value["EnableIPv6"] == false,
                "attachment ordinary bridge only"
            );
        }
        let server = self.create_container(role, SLOTS[2], a, &primary_aliases, request(2));
        self.start(server);
        let primary_before = self.running_addresses(server, &[a]);
        assert_eq!(primary_before.len(), 1);
        self.membership(a, &[server]);
        self.membership(b, &[]);
        self.retained_aliases(server, a, &primary_aliases, &secondary_alias);
        self.connect(server, b, &secondary_aliases, request(3));
        let connected = self.running_addresses(server, &[a, b]);
        assert!(
            connected[0] != connected[1],
            "attachment separate server endpoint addresses"
        );
        let first = self.create_container(role, SLOTS[3], a, &[], request(4));
        self.start(first);
        let second = self.create_container(role, SLOTS[4], b, &[], request(5));
        self.start(second);
        let peer_a = self.running_addresses(first, &[a])[0];
        let peer_b = self.running_addresses(second, &[b])[0];
        assert!(
            peer_a != connected[0] && peer_b != connected[1] && peer_a != peer_b,
            "attachment distinct scoped peer premises"
        );
        self.retained_aliases(server, a, &primary_aliases, &secondary_alias);
        self.retained_aliases(server, b, &secondary_aliases, &primary_alias);
        self.membership(a, &[server, first]);
        self.membership(b, &[server, second]);
        self.effects(first, &primary_alias, &shared, connected[0]);
        self.effects(second, &secondary_alias, &shared, connected[1]);
        assert_eq!(self.running_addresses(server, &[a, b]), connected);
        assert_eq!(self.running_addresses(first, &[a]), vec![peer_a]);
        assert_eq!(self.running_addresses(second, &[b]), vec![peer_b]);
        self.membership(a, &[server, first]);
        self.membership(b, &[server, second]);
        for network in [a, b] {
            assert_eq!(self.owned(network)["Labels"], labels(&self.token));
        }
        assert!(self.cleanup(), "attachment role verified cleanup");
        let resources: Vec<_> = [a,b,server,first,second].into_iter().map(|i| {
            let r = &self.resources[i]; let mut value = json!({"slot":r.slot,"kind":if r.network {"network"} else {"container"},
                "id":r.id,"name":r.name,"owner":self.token,"configured":"passed","cleanup":"absent"});
            if !r.network { value["image"] = json!(self.image); } value
        }).collect();
        json!({"role":role,"request_check":if role=="oracle" {"independent_cli"} else {"literal_rendered"},"resources":resources,
            "checks":{"primary_only":"passed","secondary_connected":"passed","labels":"passed","aliases":"passed","running":"passed","membership":"passed",
                "primary":{"unique_dns":"passed","shared_dns":"passed","named_http":"passed","shared_http":"passed","direct_http":"passed"},
                "secondary":{"unique_dns":"passed","shared_dns":"passed","named_http":"passed","shared_http":"passed","direct_http":"passed"}},"cleanup":"absent"})
    }
}

fn labels(token: &str) -> Value {
    json!({OWNER:token,"io.dockerlens.attach.simple":"bridge","io.dockerlens.attach.empty":"","io.dockerlens.attach.escaped":SPECIAL})
}
fn expected_requests(
    api: &str,
    image: &str,
    token: &str,
    names: &[String],
    primary: &[String],
    secondary: &[String],
) -> Vec<Value> {
    assert_eq!(names.len(), 5);
    let prefix = format!("/v{api}");
    let create = |index: usize, network: usize, aliases: &[String]| {
        let endpoint = if aliases.is_empty() {
            json!({})
        } else {
            json!({"Aliases":aliases})
        };
        json!({"method":"POST","path":format!("{prefix}/containers/create?name={}",names[index]),
            "body":{"Image":image,"Cmd":["sh","-c",if index == 2 {SERVER} else {PEER}],"Labels":{OWNER:token},
                "HostConfig":{"NetworkMode":names[network]},"NetworkingConfig":{"EndpointsConfig":{(names[network].clone()):endpoint}}}})
    };
    vec![
        json!({"method":"POST","path":format!("{prefix}/networks/create"),"body":{"Name":names[0],"Driver":"bridge","Labels":labels(token)}}),
        json!({"method":"POST","path":format!("{prefix}/networks/create"),"body":{"Name":names[1],"Driver":"bridge","Labels":labels(token)}}),
        create(2, 0, primary),
        json!({"method":"POST","path":format!("{prefix}/networks/{}/connect",names[1]),"body":{"Container":names[2],"EndpointConfig":{"Aliases":secondary}}}),
        create(3, 0, &[]),
        create(4, 1, &[]),
    ]
}
fn identity(name: &str) -> TargetIdentity {
    TargetIdentity::new(name.as_bytes().to_vec()).unwrap()
}
fn attachment(network: usize, aliases: &[String]) -> NetworkAttachmentIntent {
    NetworkAttachmentIntent {
        network: ResourceRef::new(network as u64),
        aliases: aliases
            .iter()
            .map(|name| NetworkAlias::new(name.as_bytes().to_vec()).unwrap())
            .collect(),
        ipv4_address: None,
        ipv6_address: None,
    }
}
fn attachment_intent(
    image: &str,
    token: &str,
    names: &[String],
    primary: &[String],
    secondary: &[String],
) -> TargetIntent {
    let mut resources = Vec::new();
    for (index, name) in names[..2].iter().enumerate() {
        let mut create = NetworkCreate::bridge();
        create.labels = labels(token)
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| {
                NetworkLabel::new(
                    key.as_bytes().to_vec(),
                    value.as_str().unwrap().as_bytes().to_vec(),
                )
                .unwrap()
            })
            .collect();
        resources.push(TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(index as u64),
            identity: identity(name),
            role: NetworkRole::Declared,
            source: NetworkSource::Create(create),
        }));
    }
    for (index, name) in names.iter().enumerate().take(5).skip(2) {
        let settings = ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), token.as_bytes().to_vec()).unwrap(),
            ],
            ..Default::default()
        };
        let networks = match index {
            2 => vec![attachment(0, primary), attachment(1, secondary)],
            3 => vec![attachment(0, &[])],
            _ => vec![attachment(1, &[])],
        };
        resources.push(TargetResource::Container(Box::new(ContainerIntent {
            reference: ResourceRef::new(index as u64),
            identity: identity(name),
            image: ImageReference::new(image.as_bytes().to_vec()).unwrap(),
            environment: vec![],
            ports: vec![],
            mounts: vec![],
            networks,
            entrypoint: ImageCommand::Inherit,
            command: ImageCommand::Exec(
                ["sh", "-c", if index == 2 { SERVER } else { PEER }]
                    .into_iter()
                    .map(|arg| Argument::new(arg.as_bytes().to_vec()).unwrap())
                    .collect(),
            ),
            healthcheck: None,
            restart: None,
            settings,
        })));
    }
    TargetIntent::new(resources).unwrap()
}
fn rendered_requests(
    source: &DaemonFacts,
    image: &str,
    token: &str,
    names: &[String],
    primary: &[String],
    secondary: &[String],
) -> Vec<Value> {
    let mut facts = source.clone();
    let scope = CapabilityScope {
        observation_id: facts.observation_id,
        release: facts.release.clone().unwrap(),
        api_version: facts.api_version.unwrap(),
        mode: facts.mode,
    };
    facts.capabilities = [
        Capability::StandaloneContainer,
        Capability::BridgeNetwork,
        Capability::Command,
        Capability::ContainerLabels,
        Capability::NetworkLabels,
        Capability::NetworkAliases,
        Capability::NetworkMultipleAttachment,
    ]
    .into_iter()
    .map(|capability| CapabilityFact {
        capability,
        state: CapabilityState::Available,
        provenance: FactProvenance::NativeConformance,
        scope: Some(scope.clone()),
    })
    .collect();
    let supported = ValidatedCapabilities::new(&facts)
        .unwrap_or_else(|_| panic!("attachment scoped native facts"));
    let intent = attachment_intent(image, token, names, primary, secondary);
    let graph = DockerPlanner
        .plan(&intent, &supported)
        .unwrap_or_else(|_| panic!("attachment native test-only plan"));
    let artifact = DockerApiRenderer
        .render(&graph)
        .unwrap_or_else(|_| panic!("attachment sealed native renderer"));
    assert!(
        artifact.bytes().len() <= 64 * 1024,
        "attachment bounded inert requests"
    );
    artifact
        .bytes()
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice(line)
                .unwrap_or_else(|_| panic!("closed attachment rendered request JSON"))
        })
        .collect()
}

fn exact_a(bytes: &[u8], alias: &str, expected: Ipv4Addr) -> bool {
    if bytes.len() > 8192 || expected == Ipv4Addr::new(127, 0, 0, 11) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut server = false;
    let mut named = false;
    let mut answers = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(value) = line.strip_prefix("Server:") {
            if server || value.trim() != "127.0.0.11" {
                return false;
            }
            server = true;
            continue;
        }
        if let Some(value) = line.strip_prefix("Name:") {
            if !server
                || !value
                    .trim()
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(alias)
            {
                return false;
            }
            named = true;
            continue;
        }
        if line.starts_with("Address") {
            let Some((head, value)) = line.split_once(':') else {
                return false;
            };
            if head != "Address"
                && !head.strip_prefix("Address ").is_some_and(|number| {
                    number.bytes().all(|b| b.is_ascii_digit()) && !number.is_empty()
                })
            {
                return false;
            }
            let words: Vec<_> = value.split_whitespace().collect();
            if !named {
                if !server
                    || words.len() != 1
                    || !matches!(words[0], "127.0.0.11" | "127.0.0.11:53" | "127.0.0.11#53")
                {
                    return false;
                }
                continue;
            }
            if words.is_empty()
                || words.len() > 2
                || words
                    .get(1)
                    .is_some_and(|name| !name.trim_end_matches('.').eq_ignore_ascii_case(alias))
            {
                return false;
            }
            let Ok(ip) = words[0].parse::<Ipv4Addr>() else {
                return false;
            };
            if ip != expected || words[0] != ip.to_string() {
                return false;
            }
            answers.push(ip);
        } else if !(line.is_empty()
            || line == "Non-authoritative answer:"
            || line == "Authoritative answer:")
        {
            return false;
        }
    }
    server && named && answers == [expected]
}

fn held_directory(path: &Path) -> File {
    assert!(
        path.is_absolute() && path.canonicalize().ok().as_deref() == Some(path),
        "attachment canonical private parent"
    );
    let before =
        fs::symlink_metadata(path).unwrap_or_else(|_| panic!("attachment private parent metadata"));
    let uid = fs::metadata("/proc/self").unwrap().uid();
    assert!(
        before.is_dir() && before.uid() == uid && before.mode() & 0o7777 == 0o700,
        "attachment owner-private parent"
    );
    let held = File::open(path).unwrap_or_else(|_| panic!("attachment held private parent"));
    let after = held.metadata().unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.uid(), before.mode()),
        (after.dev(), after.ino(), after.uid(), after.mode())
    );
    held
}
fn publish(path: &Path, directory: &Path, proof: &Value) {
    assert_eq!(path, directory.join("network-attachments-v1.json"));
    let held = held_directory(directory);
    let parent = held.metadata().unwrap();
    let bytes = serde_json::to_vec(proof).unwrap();
    assert!(bytes.len() <= 16 * 1024, "attachment proof byte bound");
    let selected = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()))
        .join("network-attachments-v1.json");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(selected)
        .unwrap_or_else(|_| panic!("attachment exclusive proof creation"));
    let before = output.metadata().unwrap();
    assert!(
        before.is_file()
            && before.uid() == parent.uid()
            && before.nlink() == 1
            && before.mode() & 0o7777 == 0o600,
        "attachment regular private proof"
    );
    let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        output
            .write_all(&bytes)
            .unwrap_or_else(|_| panic!("attachment private proof write"));
        output.sync_all().unwrap();
        let after = output.metadata().unwrap();
        let named = fs::symlink_metadata(path).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
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
        let parent_after = fs::symlink_metadata(directory).unwrap();
        assert_eq!(
            (parent.dev(), parent.ino(), parent.uid(), parent.mode()),
            (
                parent_after.dev(),
                parent_after.ino(),
                parent_after.uid(),
                parent_after.mode()
            )
        );
        assert_eq!(directory.canonicalize().unwrap(), directory);
    }))
    .is_ok();
    if !completed {
        let _ = output.set_len(0);
    }
    assert!(completed, "attachment complete proof publication");
}

#[test]
#[ignore = "requires the exact isolated four-lane Engine harness"]
fn live_network_attachments_match_engine() {
    let mut run = Run::new();
    let mut roles = Vec::new();
    let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run.observe_context();
        eprintln!("DOCKERLENS_NATIVE_CHECK: network_attachment_oracle");
        roles.push(run.role("oracle"));
        eprintln!("DOCKERLENS_NATIVE_CHECK: network_attachment_rendered");
        roles.push(run.role("rendered"));
        assert_eq!(
            run.outer_snapshot(false, true).unwrap(),
            run.context["outer"]
        );
    }))
    .is_ok();
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup");
    let cleaned = run.cleanup();
    assert!(
        passed && cleaned && !run.mutation_uncertain && !run.cleanup_uncertain,
        "attachment complete assertions and exact cleanup required"
    );
    assert!(
        run.remaining() > Duration::from_secs(2),
        "attachment publication deadline"
    );
    let proof = json!({"schema_version":1,"contract":CONTRACT,"context":run.context,"roles":roles,"shapes":SHAPES,
        "cleanup":{"outcome":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    publish(&run.path, &run.directory, &proof);
    run.finished = true;
    eprintln!("DOCKERLENS_NATIVE_CHECK: network_attachment_evidence");
}

#[test]
fn attachment_acquisition_versions_require_nonempty_exact_capture_and_decoder() {
    let version = |minor| ApiVersion::new(std::num::NonZeroU16::new(1).unwrap(), minor);
    for expected in [version(41), version(49)] {
        assert!(exact_acquisition_versions(
            &[expected],
            &[expected],
            expected
        ));
        assert!(exact_acquisition_versions(
            &[expected, expected],
            &[expected],
            expected
        ));
        assert!(!exact_acquisition_versions(&[], &[expected], expected));
        assert!(!exact_acquisition_versions(&[], &[], expected));
        assert!(!exact_acquisition_versions(&[expected], &[], expected));
        assert!(!exact_acquisition_versions(
            &[expected],
            &[expected, expected],
            expected
        ));
        for wrong in [
            version(40),
            version(41),
            version(48),
            version(49),
            version(50),
            version(56),
            ApiVersion::new(std::num::NonZeroU16::new(2).unwrap(), expected.minor),
        ] {
            if wrong == expected {
                continue;
            }
            assert!(!exact_acquisition_versions(&[wrong], &[wrong], expected));
            assert!(!exact_acquisition_versions(
                &[expected, wrong],
                &[expected, wrong],
                expected
            ));
            assert!(!exact_acquisition_versions(
                &[wrong, expected],
                &[wrong, expected],
                expected
            ));
            assert!(!exact_acquisition_versions(
                &[expected, wrong],
                &[expected],
                expected
            ));
            assert!(!exact_acquisition_versions(&[expected], &[wrong], expected));
        }
    }
}

#[test]
fn attachment_dns_requires_complete_scoped_singleton_and_excludes_resolver() {
    let expected = Ipv4Addr::new(172, 22, 0, 2);
    let valid = b"Server: 127.0.0.11\nAddress: 127.0.0.11:53\n\nNon-authoritative answer:\nName: Shared.\nAddress: 172.22.0.2\n";
    assert!(exact_a(valid, "shared", expected));
    for invalid in [
        "Server: 127.0.0.11\nAddress: 127.0.0.11:53\n",
        "Server: 127.0.0.11\nName: foreign\nAddress: 172.22.0.2\n",
        "Server: 127.0.0.11\nName: shared\nAddress: 172.22.0.20\n",
        "Server: 127.0.0.11\nName: shared\nAddress: 172.22.0.2\nAddress: 172.23.0.2\n",
        "Server: 127.0.0.11\nName: shared\nAddress: 172.22.0.2\nAddress: 172.22.0.2\n",
        "Server: 127.0.0.11\nName: shared\nAddress: 127.0.0.11\n",
        "Server: 127.0.0.11\nName: shared\nAddress: 172.22.0.2 protected-secret\n",
        "Server: 127.0.0.11\nName: shared\nAddress: 172.22.0.2\n*** lookup failed\n",
    ] {
        assert!(!exact_a(invalid.as_bytes(), "shared", expected));
    }
}

#[test]
fn attachment_literal_wire_is_independent_and_contains_only_requested_groups() {
    let token = "Ab12Cd34";
    let image =
        "private/image:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let names: Vec<_> = SLOTS
        .iter()
        .map(|slot| Resource::new(token, "rendered", slot).name)
        .collect();
    let primary = vec!["primary-app".into(), "shared".into()];
    let secondary = vec!["secondary-app".into(), "shared".into()];
    let facts = DaemonFacts {
        observation_id: crate::version::ObservationId::fresh().unwrap(),
        release: crate::version::EngineRelease::new("20.10.5".into()),
        api_version: Some(crate::version::ApiVersion::new(
            std::num::NonZeroU16::new(1).unwrap(),
            41,
        )),
        minimum_api_version: None,
        mode: DaemonMode::Rootless,
        capabilities: vec![],
    };
    let actual = rendered_requests(&facts, image, token, &names, &primary, &secondary);
    assert_eq!(
        actual,
        expected_requests("1.41", image, token, &names, &primary, &secondary)
    );
    assert_eq!(actual.len(), 6);
    assert_eq!(
        actual[2]["body"]["NetworkingConfig"]["EndpointsConfig"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        actual[3]["body"]["EndpointConfig"],
        json!({"Aliases":secondary})
    );
    assert!(!actual.iter().any(|v| v["body"].get("IPAM").is_some()
        || v["body"].get("Options").is_some()
        || v["body"].get("EnableIPv6").is_some()));
}

#[test]
fn attachment_output_capacity_refuses_before_io_and_preserves_cleanup() {
    use std::cell::Cell;

    let starts = Cell::new(0);
    let start = || starts.set(starts.get() + 1);
    let limit = 4 * 1024 * 1024;
    for (used, cap) in [
        (limit - 127, 64),
        (limit - 1, 1),
        (limit, 1),
        (usize::MAX, 1),
        (1, usize::MAX),
        (limit + 1, 1),
        (0, 0),
    ] {
        assert!(with_output_capacity(used, cap, start).is_none());
        assert_eq!(starts.get(), 0);
    }
    assert!(with_output_capacity(limit - 128, 64, start).is_some());
    assert_eq!(starts.get(), 1);
    let work_used = limit;
    let cleanup_used = 0;
    assert!(with_output_capacity(work_used, 64, start).is_none());
    assert_eq!(starts.get(), 1);
    assert!(with_output_capacity(cleanup_used, 64 * 1024, start).is_some());
    assert_eq!(starts.get(), 2);
    assert_eq!((work_used, cleanup_used), (limit, 0));
    assert!(with_output_capacity(limit - 131072, 65536, start).is_some());
    assert_eq!(starts.get(), 3);
}

#[test]
fn attachment_cleanup_budget_and_creation_collision_remain_independent() {
    assert_eq!(cleanup_reserve(5, 5), Duration::from_secs(45));
    assert_eq!(cleanup_reserve(10, 5), Duration::from_secs(55));
    let pending = Resource::new("Ab12Cd34", "oracle", "server");
    assert!(!pending.live && pending.id.is_none());
    assert!(canonical(&"a".repeat(64), 64));
    assert!(!canonical(&"A".repeat(64), 64));
    assert!(!pin("private/image:latest"));
}
