//! Test-only configured z/Z retention proof. Neither admission nor SELinux effects.
use crate::acquisition::{Endpoint, Limits, NativeId, Selector, acquire};
use crate::decoder::{
    DecodedInventory, MountAccess, MountKind, MountModeInterpretation, decode_capture,
};
use crate::evidence::CaptureRoute;
use crate::observation::{Availability, BindRelabel, FieldPath, Origin, ResourceRef};
use crate::target::{
    Argument, ContainerIntent, ContainerLabel, ContainerSettings, DockerApiRenderer, DockerPlanner,
    ImageCommand, ImageReference, Mount, Planner, Renderer, TargetIdentity, TargetIntent,
    TargetResource,
};
use crate::version::{
    ApiVersion, Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonFacts,
    DaemonMode, FactProvenance, ValidatedCapabilities,
};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroU16;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        assert!(&$left == &$right, "closed bind retention mismatch")
    };
}
const OWNER: &str = "io.dockerlens.native-run";
const CONTRACT: &str = "bind-relabel-config-v1";
const FILENAME: &str = "bind-relabel-config-v1.json";
const TARGET: &str = "/configured-bind";
const CASES: [&str; 4] = ["shared-rw", "shared-ro", "private-rw", "private-ro"];
const SHAPES: [&str; 4] = [
    "BindMountSharedRelabelReadWrite",
    "BindMountSharedRelabelReadOnly",
    "BindMountPrivateRelabelReadWrite",
    "BindMountPrivateRelabelReadOnly",
];
const MODES: [&str; 4] = ["rw,z", "ro,z", "rw,Z", "ro,Z"];
const WORK_BYTE_LIMIT: usize = 12 * 1024 * 1024;
const CLEANUP_BYTE_LIMIT: usize = 2 * 1024 * 1024;
const SOURCE_CREATE: &str = r#"set -eu
r=$1; leaf=$2; token=$3; storage=$4
[ "$(readlink -f "$storage")" = "$storage" ]
p=$storage; while [ "$p" != / ]; do [ ! -L "$p" ]; p=${p%/*}; [ -n "$p" ] || p=/; done
[ ! -e "$r" ] && [ ! -L "$r" ]
umask 077
mkdir -- "$r"
printf '%s' "$token" >"$r/.owner"
mkdir -- "$r/$leaf"
chmod 0755 "$r/$leaf"
printf bind-relabel-synthetic-canary >"$r/$leaf/canary"
chmod 0644 "$r/$leaf/canary"
stat -c '%d:%i:%u:%a' "$r" "$r/.owner" "$r/$leaf" "$r/$leaf/canary"
[ "$(stat -c %h "$r/.owner")" = 1 ] && [ "$(stat -c %h "$r/$leaf/canary")" = 1 ]
"#;
const SOURCE_CHECK: &str = r#"set -eu
r=$1; leaf=$2; token=$3; meta=$4
[ "$(readlink -f "$r")" = "$r" ]
[ ! -L "$r" ] && [ ! -L "$r/.owner" ] && [ ! -L "$r/$leaf" ] && [ ! -L "$r/$leaf/canary" ]
[ -d "$r" ] && [ -d "$r/$leaf" ] && [ -f "$r/.owner" ] && [ -f "$r/$leaf/canary" ]
[ "$(stat -c '%d:%i:%u:%a' "$r" "$r/.owner" "$r/$leaf" "$r/$leaf/canary")" = "$meta" ]
[ "$(stat -c %h "$r/.owner")" = 1 ] && [ "$(stat -c %h "$r/$leaf/canary")" = 1 ]
[ "$(cat "$r/.owner")" = "$token" ]
[ "$(cat "$r/$leaf/canary")" = bind-relabel-synthetic-canary ]
"#;
const SOURCE_REMOVE: &str = r#"set -eu
r=$1; leaf=$2; token=$3; meta=$4
[ "$(readlink -f "$r")" = "$r" ]
[ ! -L "$r" ] && [ ! -L "$r/.owner" ] && [ ! -L "$r/$leaf" ] && [ ! -L "$r/$leaf/canary" ]
[ -d "$r" ] && [ -d "$r/$leaf" ] && [ -f "$r/.owner" ] && [ -f "$r/$leaf/canary" ]
[ "$(stat -c '%d:%i:%u:%a' "$r" "$r/.owner" "$r/$leaf" "$r/$leaf/canary")" = "$meta" ]
[ "$(stat -c %h "$r/.owner")" = 1 ] && [ "$(stat -c %h "$r/$leaf/canary")" = 1 ]
[ "$(cat "$r/.owner")" = "$token" ]
[ "$(cat "$r/$leaf/canary")" = bind-relabel-synthetic-canary ]
rm -- "$r/$leaf/canary"
rmdir -- "$r/$leaf"
rm -- "$r/.owner"
rmdir -- "$r"
[ ! -e "$r" ] && [ ! -L "$r" ]
"#;

fn required(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("closed bind retention harness input missing"))
}
fn canonical(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn pinned(value: &str) -> bool {
    value.split_once("@sha256:").is_some_and(|(tag, digest)| {
        tag.contains(':')
            && !tag.contains('@')
            && !tag.bytes().any(|b| b.is_ascii_whitespace())
            && canonical(digest, 64)
    })
}
fn reserve(history: usize) -> Duration {
    // Two global ID/name rounds + repeated outer verification cost five 1s
    // commands per historical container. Fifteen seconds cover the current
    // ownership/delete/source cleanup, source absence rounds and publication.
    Duration::from_secs((5 * history + 15).max(45) as u64)
}
fn drain(mut input: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut bytes = Vec::new();
    let mut overflow = false;
    let mut block = [0; 4096];
    loop {
        let size = input
            .read(&mut block)
            .unwrap_or_else(|_| panic!("closed bind stream read"));
        if size == 0 {
            break;
        }
        let keep = size.min(limit - bytes.len());
        bytes.extend_from_slice(&block[..keep]);
        overflow |= keep != size;
    }
    (bytes, overflow)
}
fn exact_versions(captured: &[ApiVersion], decoded: &[ApiVersion], expected: ApiVersion) -> bool {
    !captured.is_empty() && captured.iter().all(|api| *api == expected) && decoded == [expected]
}
fn admitted_command<T>(
    cleanup: bool,
    work_bytes: usize,
    cleanup_bytes: usize,
    cap: usize,
    start: impl FnOnce() -> T,
) -> T {
    let (current, limit) = if cleanup {
        (cleanup_bytes, CLEANUP_BYTE_LIMIT)
    } else {
        (work_bytes, WORK_BYTE_LIMIT)
    };
    let fits = cap
        .checked_mul(2)
        .and_then(|envelope| current.checked_add(envelope))
        .is_some_and(|maximum| maximum <= limit);
    assert!(fits, "closed bind command output envelope refused");
    start()
}
fn owned_identity(value: &Value, id: Option<&str>, name: &str, run: &str, image: &str) -> bool {
    value["Id"]
        .as_str()
        .is_some_and(|actual| canonical(actual, 64) && id.is_none_or(|expected| actual == expected))
        && value["Name"] == format!("/{name}")
        && value["Config"]["Labels"][OWNER] == run
        && value["Config"]["Image"] == image
}

struct Attempt {
    case: usize,
    role: String,
    name: String,
    leaf: String,
    id: Option<String>,
    container_attempted: bool,
    container_absent: bool,
    source_attempted: bool,
    source_meta: Option<String>,
    source_absent: bool,
}
impl Attempt {
    fn new(run: &str, case: usize, role: &str) -> Self {
        assert!(
            case < 4 && matches!(role, "oracle" | "rendered"),
            "closed bind case/role"
        );
        Self {
            case,
            role: role.into(),
            name: format!("dl-br-{run}-{}-{role}", CASES[case]),
            leaf: format!("{}-{role}", CASES[case]),
            id: None,
            container_attempted: false,
            container_absent: false,
            source_attempted: false,
            source_meta: None,
            source_absent: false,
        }
    }
}
struct Run {
    token: String,
    lane: String,
    mode: DaemonMode,
    api: String,
    acquisition: ApiVersion,
    release: String,
    package: String,
    image: String,
    outer_id: String,
    outer_name: String,
    outer_image: String,
    elevated: bool,
    socket: String,
    directory: PathBuf,
    proof_path: PathBuf,
    candidate: String,
    storage: String,
    source_root: String,
    source_uid: u32,
    deadline: Instant,
    epoch: SystemTime,
    work_calls: usize,
    work_bytes: usize,
    cleanup_calls: usize,
    cleanup_bytes: usize,
    history: Vec<Attempt>,
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
            .unwrap_or_else(|| panic!("closed bind outer name"))
            .to_owned();
        assert!(
            token.len() == 8 && token.bytes().all(|b| b.is_ascii_alphanumeric()),
            "closed bind run token"
        );
        let lane = required("NATIVE_LANE");
        let api = required("NATIVE_API_VERSION");
        let mode = match required("NATIVE_DAEMON_MODE").as_str() {
            "rootful" => DaemonMode::Rootful,
            "rootless" => DaemonMode::Rootless,
            _ => panic!("closed bind daemon mode"),
        };
        assert!(
            matches!(lane.as_str(), "debian11-rootful" | "debian11-rootless") && api == "1.41"
                || matches!(lane.as_str(), "upstream-rootful" | "upstream-rootless")
                    && api == "1.56",
            "closed bind lane API"
        );
        assert_eq!(lane.ends_with("-rootless"), mode == DaemonMode::Rootless);
        let acquisition = ApiVersion::new(
            NonZeroU16::new(1).unwrap(),
            if lane.starts_with("debian11-") {
                41
            } else {
                49
            },
        );
        let candidate = required("NATIVE_BIND_RELABEL_CANDIDATE_SHA");
        let outer_id = required("NATIVE_OUTER_CONTAINER_ID");
        assert!(
            canonical(&candidate, 40) && canonical(&outer_id, 64),
            "closed bind exact identities"
        );
        let image = required("NATIVE_FIXTURE_IMAGE");
        let outer_image = required("NATIVE_OUTER_IMAGE");
        assert!(
            pinned(&image) && pinned(&outer_image),
            "closed bind immutable images"
        );
        let directory = PathBuf::from(required("NATIVE_CAPTURE_DIR"));
        let proof_path = PathBuf::from(required("NATIVE_BIND_RELABEL_PROOF_PATH"));
        assert_eq!(proof_path, directory.join(FILENAME));
        let _ = held_directory(&directory);
        assert!(
            fs::symlink_metadata(&proof_path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "closed bind new proof only"
        );
        let socket = required("NATIVE_ENGINE_SOCKET");
        assert_eq!(PathBuf::from(&socket), directory.join("socket/docker.sock"));
        let storage = if mode == DaemonMode::Rootless {
            "/home/docker/.local/share/docker"
        } else {
            "/var/lib/docker"
        }
        .to_owned();
        let source_root = format!("{storage}/dl-bind-relabel-{token}");
        let epoch = UNIX_EPOCH
            + Duration::from_secs(
                required("NATIVE_NETWORK_TEST_DEADLINE_EPOCH")
                    .parse()
                    .unwrap_or_else(|_| panic!("closed bind deadline")),
            );
        let remaining = epoch
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .min(Duration::from_secs(180));
        assert!(
            remaining > Duration::from_secs(60),
            "closed bind startup reserve"
        );
        let elevated = match required("NATIVE_PODMAN_USE_SUDO").as_str() {
            "0" => false,
            "1" => true,
            _ => panic!("closed bind privilege selector"),
        };
        Self {
            token,
            lane,
            mode,
            api,
            acquisition,
            release: required("NATIVE_ENGINE_VERSION"),
            package: required("NATIVE_DOCKER_PACKAGE"),
            image,
            outer_id,
            outer_name,
            outer_image,
            elevated,
            socket,
            directory,
            proof_path,
            candidate,
            storage,
            source_root,
            source_uid: 0,
            deadline: Instant::now() + remaining,
            epoch,
            work_calls: 0,
            work_bytes: 0,
            cleanup_calls: 0,
            cleanup_bytes: 0,
            history: Vec::new(),
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
    fn command(
        &mut self,
        cleanup: bool,
        elevated: bool,
        args: &[String],
        input: Option<&[u8]>,
        cap: usize,
    ) -> Output {
        // Admit both output streams before call counters, process creation,
        // request writes or stream draining. Work cannot spend cleanup bytes.
        admitted_command(cleanup, self.work_bytes, self.cleanup_bytes, cap, || {
            if cleanup {
                assert!(
                    self.remaining() > Duration::from_secs(2),
                    "closed bind cleanup time"
                );
                self.cleanup_calls += 1;
                assert!(self.cleanup_calls <= 192, "closed bind cleanup call bound");
            } else {
                assert!(
                    self.remaining() > reserve(self.history.len()) + Duration::from_secs(4),
                    "closed bind work reserve"
                );
                self.work_calls += 1;
                assert!(self.work_calls <= 400, "closed bind work call bound");
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
            command
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if input.is_some() {
                command.stdin(Stdio::piped());
            }
            let mut child = command
                .spawn()
                .unwrap_or_else(|_| panic!("closed bind command spawn"));
            if let Some(bytes) = input {
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(bytes)
                    .unwrap_or_else(|_| panic!("closed bind request write"));
            }
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let out = std::thread::spawn(move || drain(stdout, cap));
            let err = std::thread::spawn(move || drain(stderr, cap));
            let status = child
                .wait()
                .unwrap_or_else(|_| panic!("closed bind command wait"));
            let (stdout, large_out) = out.join().unwrap();
            let (stderr, large_err) = err.join().unwrap();
            if cleanup {
                self.cleanup_bytes += stdout.len() + stderr.len();
                assert!(
                    self.cleanup_bytes <= CLEANUP_BYTE_LIMIT,
                    "closed bind cleanup bytes"
                );
            } else {
                self.work_bytes += stdout.len() + stderr.len();
                assert!(self.work_bytes <= WORK_BYTE_LIMIT, "closed bind work bytes");
            }
            assert!(!large_out && !large_err, "closed bind output overflow");
            Output {
                status,
                stdout,
                stderr,
            }
        })
    }
    fn podman(&mut self, cleanup: bool, args: &[String]) -> Output {
        let mut command = vec!["podman".into(), "--remote=false".into()];
        command.extend_from_slice(args);
        self.command(cleanup, self.elevated, &command, None, 64 * 1024)
    }
    fn cli(&mut self, args: &[String], mutation: bool) -> Vec<u8> {
        let old = self.mutation_uncertain;
        if mutation {
            self.mutation_uncertain = true;
        }
        let mut command = vec![
            "exec".into(),
            self.outer_id.clone(),
            "docker".into(),
            "-H".into(),
            "unix:///dockerlens-native/docker.sock".into(),
        ];
        command.extend_from_slice(args);
        let result = self.podman(false, &command);
        assert!(result.status.success(), "closed bind positive CLI required");
        if mutation {
            self.mutation_uncertain = old;
        }
        result.stdout
    }
    fn source_command(&mut self, cleanup: bool, script: &str, args: &[String]) -> Output {
        let mut command = vec![
            "exec".into(),
            "--user".into(),
            self.source_uid.to_string(),
            self.outer_id.clone(),
            "sh".into(),
            "-ec".into(),
            script.into(),
            "--".into(),
        ];
        command.extend_from_slice(args);
        self.podman(cleanup, &command)
    }
    fn allowed(&self, method: &str, path: &str, body: Option<&Value>) -> bool {
        if method == "GET" && (path == "/version" || path == format!("/v{}/info", self.api)) {
            return true;
        }
        self.history.iter().any(|attempt| {
            if method == "GET" {
                return std::iter::once(attempt.name.as_str())
                    .chain(attempt.id.as_deref())
                    .any(|key| path == format!("/v{}/containers/{key}/json", self.api));
            }
            if method == "DELETE" {
                return attempt
                    .id
                    .as_ref()
                    .is_some_and(|id| path == format!("/v{}/containers/{id}?force=1", self.api));
            }
            if method != "POST" {
                return false;
            }
            if path == format!("/v{}/containers/create?name={}", self.api, attempt.name) {
                return body
                    .is_some_and(|v| v["Image"] == self.image && v["Labels"][OWNER] == self.token);
            }
            attempt
                .id
                .as_ref()
                .is_some_and(|id| path == format!("/v{}/containers/{id}/start", self.api))
                && body.is_none()
        })
    }
    fn api(
        &mut self,
        cleanup: bool,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> (u16, Value) {
        assert!(
            self.allowed(method, path, body),
            "closed bind API allowlist"
        );
        let old = self.mutation_uncertain;
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
            "65536".into(),
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
        let output = self.command(cleanup, false, &args, input.as_deref(), 64 * 1024 + 8);
        assert!(
            output.status.success(),
            "closed bind completed transport required"
        );
        let split = output
            .stdout
            .iter()
            .rposition(|b| *b == b'\n')
            .unwrap_or_else(|| panic!("closed bind HTTP boundary"));
        let code = std::str::from_utf8(&output.stdout[split + 1..])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("closed bind HTTP code"));
        let bytes = &output.stdout[..split];
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(bytes).unwrap_or_else(|_| panic!("closed bind HTTP JSON"))
        };
        if method != "GET" {
            self.mutation_uncertain = old;
        }
        (code, value)
    }
    fn outer_snapshot(&mut self, cleanup: bool) -> Option<Value> {
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
        let mounts = value["Mounts"].as_array()?;
        let volumes: Vec<_> = mounts.iter().filter(|v| v["Type"] == "volume").collect();
        let binds: Vec<_> = mounts.iter().filter(|v| v["Type"] == "bind").collect();
        let networks = value["NetworkSettings"]["Networks"].as_object()?;
        let host = &value["HostConfig"];
        if value["Id"] != self.outer_id
            || value["Name"] != self.outer_name
            || value["Config"]["Labels"][OWNER] != self.token
            || value["ImageDigest"] != self.outer_image.split_once('@')?.1
            || value["State"]["Running"] != true
            || host["Privileged"] != true
            || host["Memory"] != 4294967296_u64
            || host["CpuQuota"] != 200000
            || host["CpuPeriod"] != 100000
            || host["PidsLimit"] != 512
            || mounts.len() != 2
            || volumes.len() != 1
            || binds.len() != 1
            || volumes[0]["Name"] != format!("dl-native-data-{}", self.token)
            || volumes[0]["Destination"] != self.storage
            || volumes[0]["RW"] != true
            || binds[0]["Source"] != self.directory.join("socket").to_str()?
            || binds[0]["Destination"] != "/dockerlens-native"
            || binds[0]["RW"] != true
            || networks.len() != 1
            || !networks.contains_key(&format!("dl-native-net-{}", self.token))
        {
            return None;
        }
        Some(
            json!({"id":self.outer_id,"name":self.outer_name,"owner":self.token,"image":self.outer_image,
            "data_volume":format!("dl-native-data-{}",self.token),"socket_source":self.directory.join("socket"),
            "privileged":true,"memory_bytes":4294967296_u64,"cpu_quota":200000,"cpu_period":100000,"pids_limit":512}),
        )
    }
    fn capture_id(&mut self, id: &str) -> DecodedInventory {
        assert!(
            self.remaining() > reserve(self.history.len()) + Duration::from_secs(11),
            "closed bind capture cleanup reserve"
        );
        self.work_calls += 16;
        self.work_bytes += 512 * 1024;
        assert!(
            self.work_calls <= 400 && self.work_bytes <= WORK_BYTE_LIMIT,
            "closed bind capture budget"
        );
        let capture = acquire(
            &Endpoint::unix_socket(PathBuf::from(&self.socket)),
            Selector::ContainerIds(vec![NativeId::new(id.into()).unwrap()]),
            Limits {
                max_requests: 16,
                max_selected_resources: 1,
                max_expansions: 8,
                max_response_bytes: 128 * 1024,
                max_total_bytes: 512 * 1024,
                max_elapsed: Duration::from_secs(10),
            },
            &AtomicBool::new(false),
        )
        .unwrap_or_else(|_| panic!("closed bind fresh explicit capture required"));
        assert_eq!(capture.route(), CaptureRoute::ExplicitUnixSocket);
        assert!(
            capture.exchanges().iter().all(|e| e.status().code() == 200),
            "closed bind capture status"
        );
        let mut decoded = decode_capture(&capture)
            .unwrap_or_else(|_| panic!("closed bind pure decoder required"));
        let versions: Vec<_> = capture
            .exchanges()
            .iter()
            .filter_map(|e| e.api_version())
            .collect();
        assert!(
            exact_versions(
                &versions,
                &decoded.version.requested_api_versions,
                self.acquisition
            ),
            "closed bind exact acquisition API"
        );
        let facts = &mut decoded.version.daemon;
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
        if self.mode == DaemonMode::Rootless {
            assert_eq!(facts.mode, DaemonMode::Rootless);
        } else {
            assert!(
                facts.mode != DaemonMode::Rootless,
                "closed bind rootful capture corroboration"
            );
            facts.mode = DaemonMode::Rootful;
        }
        decoded
    }
    fn observe_context(&mut self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: bind_relabel_context");
        let outer = self
            .outer_snapshot(false)
            .unwrap_or_else(|| panic!("closed bind exact outer boundary"));
        let (code, version) = self.api(false, "GET", "/version", None);
        assert_eq!(code, 200);
        assert_eq!(version["Version"], self.release);
        assert_eq!(version["ApiVersion"], self.api);
        if self.lane.starts_with("debian11-") {
            assert!(
                matches!(self.release.as_str(), "20.10.5" | "20.10.5+dfsg1"),
                "closed bind Debian release"
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
            assert!(package.status.success(), "closed bind package query");
            assert_eq!(package.stdout, b"20.10.5+dfsg1-1+deb11u2".to_vec());
            assert_eq!(self.package, "20.10.5+dfsg1-1+deb11u2");
        } else {
            assert_eq!(self.release, "29.8.1");
            assert_eq!(self.package, "");
        }
        assert_eq!(
            self.cli(
                &[
                    "version".into(),
                    "--format".into(),
                    "{{.Server.Version}}|{{.Server.APIVersion}}".into()
                ],
                false
            ),
            format!("{}|{}\n", self.release, self.api).into_bytes()
        );
        let (code, info) = self.api(false, "GET", &format!("/v{}/info", self.api), None);
        assert_eq!(code, 200);
        let rootless = info["Rootless"] == true
            || info["SecurityOptions"].as_array().is_some_and(|v| {
                v.iter().any(|s| {
                    s.as_str()
                        .is_some_and(|s| s == "name=rootless" || s.starts_with("name=rootless,"))
                })
            });
        assert_eq!(rootless, self.mode == DaemonMode::Rootless);
        assert_eq!(info["DockerRootDir"], self.storage);
        let options: Vec<String> = serde_json::from_slice(&self.cli(
            &[
                "info".into(),
                "--format".into(),
                "{{json .SecurityOptions}}".into(),
            ],
            false,
        ))
        .unwrap_or_else(|_| panic!("closed bind CLI mode"));
        assert_eq!(
            options
                .iter()
                .any(|s| s == "name=rootless" || s.starts_with("name=rootless,")),
            rootless
        );
        let process = self.podman(false, &["exec".into(), self.outer_id.clone(), "sh".into(), "-ec".into(),
            "count=0; uid=; for p in /proc/[0-9]*/comm; do [ -r \"$p\" ] || continue; read -r n <\"$p\" || continue; [ \"$n\" = dockerd ] || continue; count=$((count+1)); uid=$(awk '/^Uid:/ {print $3}' \"${p%/comm}/status\"); done; [ \"$count\" -eq 1 ]; printf '%s\\n' \"$uid\"".into()]);
        assert!(process.status.success(), "closed bind unique daemon UID");
        self.source_uid = std::str::from_utf8(&process.stdout)
            .ok()
            .and_then(|s| s.trim_end_matches('\n').parse().ok())
            .unwrap_or_else(|| panic!("closed bind daemon UID parse"));
        assert_eq!(self.source_uid != 0, rootless);
        let _ = self.capture_id(&required("NATIVE_CONTAINER_ID"));
        self.context = json!({"candidate_sha":self.candidate,"run_id":self.token,"lane":self.lane,
            "engine_release":self.release,"rendering_api":self.api,"acquisition_api":format!("{}.{}",self.acquisition.major,self.acquisition.minor),
            "mode":if rootless {"rootless"} else {"rootful"},"docker_package":self.package,"fixture_image":self.image,"outer":outer,
            "source_boundary":{"kind":"owned_data_volume","volume":format!("dl-native-data-{}",self.token),
                "storage_root":self.storage,"root":self.source_root,"owner":self.token,"owner_uid":self.source_uid,"mode":"0700"}});
    }
    fn source_args(&self, index: usize) -> Vec<String> {
        vec![
            self.source_root.clone(),
            self.history[index].leaf.clone(),
            self.token.clone(),
            self.history[index].source_meta.clone().unwrap_or_default(),
        ]
    }
    fn create_source(&mut self, index: usize) {
        assert!(
            self.outer_snapshot(false).is_some(),
            "closed bind source outer ownership"
        );
        let source_root = self.source_root.clone();
        let preflight = self.source_command(
            false,
            "set -eu; [ ! -e \"$1\" ] && [ ! -L \"$1\" ]",
            std::slice::from_ref(&source_root),
        );
        assert!(
            preflight.status.success(),
            "closed bind source collision refusal"
        );
        self.history[index].source_attempted = true;
        self.mutation_uncertain = true;
        let output = self.source_command(
            false,
            SOURCE_CREATE,
            &[
                self.source_root.clone(),
                self.history[index].leaf.clone(),
                self.token.clone(),
                self.storage.clone(),
            ],
        );
        assert!(
            output.status.success(),
            "closed bind source create complete"
        );
        let metadata = String::from_utf8(output.stdout)
            .unwrap_or_else(|_| panic!("closed bind source metadata"));
        let lines: Vec<_> = metadata.trim_end_matches('\n').lines().collect();
        assert_eq!(lines.len(), 4);
        for (index, line) in lines.iter().enumerate() {
            let parts: Vec<_> = line.split(':').collect();
            assert_eq!(parts.len(), 4);
            assert!(
                parts[0].parse::<u64>().is_ok() && parts[1].parse::<u64>().is_ok(),
                "closed bind source identity metadata"
            );
            assert_eq!(parts[2], self.source_uid.to_string());
            assert_eq!(parts[3], ["700", "600", "755", "644"][index]);
        }
        self.history[index].source_meta = Some(metadata.trim_end_matches('\n').to_owned());
        self.mutation_uncertain = false;
        let checked = self.source_command(false, SOURCE_CHECK, &self.source_args(index));
        assert!(
            checked.status.success(),
            "closed bind synthetic source ownership"
        );
    }
    fn inspect(&mut self, index: usize, cleanup: bool, by_id: bool) -> (u16, Value) {
        let attempt = &self.history[index];
        let key = if by_id {
            attempt.id.as_ref().unwrap()
        } else {
            &attempt.name
        };
        self.api(
            cleanup,
            "GET",
            &format!("/v{}/containers/{key}/json", self.api),
            None,
        )
    }
    fn owned(&self, index: usize, value: &Value) -> bool {
        let attempt = &self.history[index];
        owned_identity(
            value,
            attempt.id.as_deref(),
            &attempt.name,
            &self.token,
            &self.image,
        ) && value["Id"].as_str().is_some_and(|id| {
            id != self.outer_id
                && !self
                    .history
                    .iter()
                    .enumerate()
                    .any(|(other, a)| other != index && a.id.as_deref() == Some(id))
        })
    }
    fn check_native(&mut self, index: usize) -> Value {
        let (code, value) = self.inspect(index, false, true);
        assert_eq!(code, 200);
        assert!(self.owned(index, &value), "closed bind owned inspect");
        let attempt = &self.history[index];
        let source = format!("{}/{}", self.source_root, attempt.leaf);
        assert_eq!(value["Config"]["Labels"], json!({OWNER:self.token}));
        assert_eq!(value["Config"]["Cmd"], json!(["sleep", "160"]));
        assert_eq!(
            value["HostConfig"]["Binds"],
            json!([format!("{source}:{TARGET}:{}", MODES[attempt.case])])
        );
        assert!(
            value["HostConfig"]["Mounts"].is_null() || value["HostConfig"]["Mounts"] == json!([]),
            "closed bind no structured duplicate"
        );
        let mounts = value["Mounts"].as_array().unwrap();
        assert_eq!(mounts.len(), 1);
        let mount = &mounts[0];
        assert_eq!(mount["Type"], "bind");
        assert_eq!(mount["Source"], source);
        assert_eq!(mount["Destination"], TARGET);
        assert_eq!(mount["Mode"], MODES[attempt.case]);
        assert_eq!(mount["RW"], attempt.case % 2 == 0);
        assert!(
            value["State"]["Running"] == true && value["State"]["Status"] == "running",
            "closed bind running positive"
        );
        value
    }
    fn check_decoded(&mut self, index: usize, oracle: &Value) {
        let id = self.history[index].id.clone().unwrap();
        let decoded = self.capture_id(&id);
        assert_eq!(decoded.containers.len(), 1);
        let container = &decoded.containers[0];
        assert_eq!(container.id.value().unwrap().as_bytes(), id.as_bytes());
        let mounts = container.mounts.value().unwrap();
        assert_eq!(mounts.len(), 1);
        let mount = &mounts[0];
        assert!(
            matches!(mount.kind, MountKind::Bind),
            "closed bind typed native kind"
        );
        let native = &oracle["Mounts"][0];
        for (field, key) in [
            (&mount.source, "Source"),
            (&mount.destination, "Destination"),
            (&mount.mode, "Mode"),
        ] {
            assert_eq!(field.availability, Availability::Present);
            assert_eq!(field.origin, Origin::Effective);
            assert_eq!(
                field.value().unwrap().as_bytes(),
                native[key].as_str().unwrap().as_bytes()
            );
        }
        assert_eq!(mount.read_write.availability, Availability::Present);
        assert_eq!(mount.read_write.origin, Origin::Effective);
        assert_eq!(
            *mount.read_write.value().unwrap(),
            self.history[index].case % 2 == 0
        );
        assert_eq!(
            mount.mode_interpretation.availability,
            Availability::Present
        );
        assert_eq!(mount.mode_interpretation.origin, Origin::Effective);
        let case = self.history[index].case;
        assert_eq!(
            mount.mode_interpretation.value(),
            Some(&MountModeInterpretation::Supported {
                access: Some(if case % 2 == 0 {
                    MountAccess::ReadWrite
                } else {
                    MountAccess::ReadOnly
                }),
                relabel: Some(if case < 2 {
                    BindRelabel::Shared
                } else {
                    BindRelabel::Private
                }),
            })
        );
        assert!(
            !decoded
                .findings
                .iter()
                .any(|finding| matches!(finding.field, Some(FieldPath::Mount { .. }))),
            "closed bind decoded retention conflict refusal"
        );
    }
    fn role(&mut self, case: usize, role: &str) -> Value {
        assert!(
            self.history
                .iter()
                .all(|a| (!a.container_attempted || a.container_absent)
                    && (!a.source_attempted || a.source_absent)),
            "closed bind maximum one live container/source"
        );
        let index = self.history.len();
        self.history.push(Attempt::new(&self.token, case, role));
        self.create_source(index);
        let (code, _) = self.inspect(index, false, false);
        assert_eq!(code, 404);
        let source = format!("{}/{}", self.source_root, self.history[index].leaf);
        let expected = literal_request(
            &self.api,
            &self.image,
            &self.token,
            &self.history[index].name,
            &source,
            case,
        );
        let request = if role == "rendered" {
            let decoded = self.capture_id(&required("NATIVE_CONTAINER_ID"));
            let request = rendered_request(
                &decoded.version.daemon,
                &self.image,
                &self.token,
                &self.history[index].name,
                &source,
                case,
            );
            assert_eq!(request, expected);
            Some(request)
        } else {
            None
        };
        self.history[index].container_attempted = true;
        let id = if let Some(request) = request {
            let (code, response) = self.api(
                false,
                "POST",
                request["path"].as_str().unwrap(),
                Some(&request["body"]),
            );
            assert_eq!(code, 201);
            response["Id"].as_str().unwrap().to_owned()
        } else {
            let bytes = self.cli(
                &[
                    "create".into(),
                    "--name".into(),
                    self.history[index].name.clone(),
                    "--label".into(),
                    format!("{OWNER}={}", self.token),
                    "--volume".into(),
                    format!(
                        "{source}:{TARGET}:{}",
                        ["rw,z", "ro,z", "rw,Z", "ro,Z"][case]
                    ),
                    self.image.clone(),
                    "sleep".into(),
                    "160".into(),
                ],
                true,
            );
            String::from_utf8(bytes)
                .unwrap()
                .trim_end_matches('\n')
                .to_owned()
        };
        assert!(
            canonical(&id, 64)
                && id != self.outer_id
                && !self
                    .history
                    .iter()
                    .any(|a| a.id.as_deref() == Some(id.as_str())),
            "closed bind distinct canonical ID"
        );
        self.history[index].id = Some(id.clone());
        let (code, value) = self.inspect(index, false, true);
        assert_eq!(code, 200);
        assert!(self.owned(index, &value), "closed bind pre-start ownership");
        assert_eq!(
            self.api(
                false,
                "POST",
                &format!("/v{}/containers/{id}/start", self.api),
                None
            )
            .0,
            204
        );
        let native = self.check_native(index);
        self.check_decoded(index, &native);
        let _ = self.check_native(index);
        let source_check = self.source_command(false, SOURCE_CHECK, &self.source_args(index));
        assert!(source_check.status.success(), "closed bind source retained");
        assert!(self.cleanup_one(index), "closed bind case cleanup required");
        let attempt = &self.history[index];
        json!({"role":attempt.role,"request_check":if role == "oracle" {"independent_cli"} else {"literal_rendered"},
            "id":attempt.id,"name":attempt.name,"owner":self.token,"image":self.image,"source_leaf":attempt.leaf,
            "checks":{"source_boundary":"passed","literal_bind":"passed","native_mount":"passed","running":"passed","capture":"passed","decoded_mount":"passed"},
            "container_cleanup":"absent","source_cleanup":"absent"})
    }
    fn cleanup_one(&mut self, index: usize) -> bool {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(
                self.outer_snapshot(true).is_some(),
                "closed bind cleanup outer boundary"
            );
            if self.history[index].container_attempted && !self.history[index].container_absent {
                let by_id = self.history[index].id.is_some();
                let (code, value) = self.inspect(index, true, by_id);
                if code == 200 {
                    assert!(self.owned(index, &value), "closed bind cleanup ownership");
                    if self.history[index].id.is_none() {
                        self.history[index].id = value["Id"].as_str().map(str::to_owned);
                    }
                    let id = self.history[index].id.clone().unwrap();
                    assert_eq!(
                        self.api(
                            true,
                            "DELETE",
                            &format!("/v{}/containers/{id}?force=1", self.api),
                            None
                        )
                        .0,
                        204
                    );
                } else {
                    assert_eq!(code, 404);
                }
                for _ in 0..2 {
                    assert_eq!(self.inspect(index, true, false).0, 404);
                    if self.history[index].id.is_some() {
                        assert_eq!(self.inspect(index, true, true).0, 404);
                    }
                }
                self.history[index].container_absent = true;
            }
            if self.history[index].source_attempted && !self.history[index].source_absent {
                assert!(
                    self.history[index].source_meta.is_some(),
                    "closed bind uncertain source never adopted"
                );
                let output = self.source_command(true, SOURCE_REMOVE, &self.source_args(index));
                assert!(
                    output.status.success(),
                    "closed bind exact source file and empty directory removal"
                );
                for _ in 0..2 {
                    let source_root = self.source_root.clone();
                    let absent = self.source_command(
                        true,
                        "set -eu; [ ! -e \"$1\" ] && [ ! -L \"$1\" ]",
                        std::slice::from_ref(&source_root),
                    );
                    assert!(absent.status.success(), "closed bind source absence rounds");
                }
                self.history[index].source_absent = true;
            }
        }))
        .is_ok();
        self.cleanup_uncertain |= !result;
        result
    }
    fn cleanup_all(&mut self) -> bool {
        let mut complete = true;
        for index in 0..self.history.len() {
            complete &= self.cleanup_one(index);
        }
        let absent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(
                self.outer_snapshot(true).is_some(),
                "closed bind final outer ownership"
            );
            for _ in 0..2 {
                for index in 0..self.history.len() {
                    assert_eq!(self.inspect(index, true, false).0, 404);
                    if self.history[index].id.is_some() {
                        assert_eq!(self.inspect(index, true, true).0, 404);
                    }
                }
                let source_root = self.source_root.clone();
                let source = self.source_command(
                    true,
                    "set -eu; [ ! -e \"$1\" ] && [ ! -L \"$1\" ]",
                    std::slice::from_ref(&source_root),
                );
                assert!(source.status.success(), "closed bind final source absence");
            }
        }))
        .is_ok();
        self.cleanup_uncertain |= !absent;
        complete && absent
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        if !self.finished && !self.history.is_empty() {
            let _ = self.cleanup_all();
        }
    }
}

fn literal_request(
    api: &str,
    image: &str,
    run: &str,
    name: &str,
    source: &str,
    case: usize,
) -> Value {
    // Independently authored wire expectation; not extracted from the renderer.
    let suffix = match case {
        0 => "rw,z",
        1 => "ro,z",
        2 => "rw,Z",
        3 => "ro,Z",
        _ => panic!("closed bind literal case"),
    };
    json!({"method":"POST","path":format!("/v{api}/containers/create?name={name}"),
        "body":{"Image":image,"Cmd":["sleep","160"],"Labels":{OWNER:run},"HostConfig":{"Binds":[format!("{source}:/configured-bind:{suffix}")]}}})
}
fn rendered_request(
    source_facts: &DaemonFacts,
    image: &str,
    run: &str,
    name: &str,
    source: &str,
    case: usize,
) -> Value {
    let mut facts = source_facts.clone();
    let scope = CapabilityScope {
        observation_id: facts.observation_id,
        release: facts.release.clone().unwrap(),
        api_version: facts.api_version.unwrap(),
        mode: facts.mode,
    };
    facts.capabilities = [
        Capability::StandaloneContainer,
        Capability::BindMount,
        Capability::Command,
        Capability::ContainerLabels,
        if case < 2 {
            Capability::BindRelabelShared
        } else {
            Capability::BindRelabelPrivate
        },
    ]
    .into_iter()
    .map(|capability| CapabilityFact {
        capability,
        state: CapabilityState::Available,
        provenance: FactProvenance::NativeConformance,
        scope: Some(scope.clone()),
    })
    .collect();
    let supported = ValidatedCapabilities::new(&facts).unwrap();
    let relabel = if case < 2 {
        BindRelabel::Shared
    } else {
        BindRelabel::Private
    };
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(name.as_bytes().to_vec()).unwrap(),
        image: ImageReference::new(image.as_bytes().to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![
            Mount::bind(
                source.as_bytes().to_vec(),
                TARGET.as_bytes().to_vec(),
                case % 2 == 1,
            )
            .unwrap()
            .with_bind_relabel(relabel)
            .unwrap(),
        ],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Exec(
            ["sleep", "160"]
                .into_iter()
                .map(|arg| Argument::new(arg.as_bytes().to_vec()).unwrap())
                .collect(),
        ),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.as_bytes().to_vec()).unwrap(),
            ],
            ..Default::default()
        },
    }))])
    .unwrap();
    let graph = DockerPlanner.plan(&intent, &supported).unwrap();
    let artifact = DockerApiRenderer.render(&graph).unwrap();
    assert_eq!(artifact.bind_source_prerequisites().len(), 1);
    let prerequisite = &artifact.bind_source_prerequisites()[0];
    assert_eq!(prerequisite.identity(), name.as_bytes());
    assert_eq!(prerequisite.source(), source.as_bytes());
    assert_eq!(prerequisite.target(), TARGET.as_bytes());
    assert_eq!(prerequisite.read_only(), case % 2 == 1);
    assert_eq!(prerequisite.relabel(), relabel);
    let complete: Value = serde_json::from_slice(&artifact.complete_bytes().unwrap()).unwrap();
    assert_eq!(complete["schema_version"], 2);
    assert_eq!(complete["prerequisites"].as_array().unwrap().len(), 1);
    assert_eq!(complete["prerequisites"][0]["identity"], name);
    assert_eq!(complete["prerequisites"][0]["selinux_effect"], "unverified");
    serde_json::from_slice(artifact.bytes())
        .unwrap_or_else(|_| panic!("closed bind literal rendered JSON"))
}
fn held_directory(path: &Path) -> File {
    assert!(
        path.is_absolute() && path.canonicalize().ok().as_deref() == Some(path),
        "closed bind canonical private parent"
    );
    let before = fs::symlink_metadata(path).unwrap();
    let uid = fs::metadata("/proc/self").unwrap().uid();
    assert!(
        before.is_dir() && before.uid() == uid && before.mode() & 0o7777 == 0o700,
        "closed bind private parent ownership"
    );
    let held = File::open(path).unwrap();
    let after = held.metadata().unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.uid(), before.mode()),
        (after.dev(), after.ino(), after.uid(), after.mode())
    );
    held
}
fn publish(path: &Path, directory: &Path, proof: &Value) {
    assert_eq!(path, directory.join(FILENAME));
    let held = held_directory(directory);
    let parent = held.metadata().unwrap();
    let bytes = serde_json::to_vec(proof).unwrap();
    assert!(bytes.len() <= 16 * 1024, "closed bind private proof bound");
    let selected = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd())).join(FILENAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(selected)
        .unwrap_or_else(|_| panic!("closed bind exclusive publication"));
    let before = file.metadata().unwrap();
    assert!(
        before.is_file()
            && before.uid() == parent.uid()
            && before.nlink() == 1
            && before.mode() & 0o7777 == 0o600,
        "closed bind regular private proof"
    );
    let finished = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        let after = file.metadata().unwrap();
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
        let current = fs::symlink_metadata(directory).unwrap();
        assert_eq!(
            (parent.dev(), parent.ino(), parent.uid(), parent.mode()),
            (current.dev(), current.ino(), current.uid(), current.mode())
        );
        assert_eq!(directory.canonicalize().unwrap(), directory);
    }))
    .is_ok();
    if !finished {
        let _ = file.set_len(0);
    }
    assert!(finished, "closed bind complete publication");
}

#[test]
#[ignore = "requires the exact isolated four-lane Engine harness"]
fn live_bind_relabel_configuration_matches_engine() {
    let mut run = Run::new();
    let mut cases = Vec::new();
    let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run.observe_context();
        for (case, case_name) in CASES.iter().enumerate() {
            eprintln!("DOCKERLENS_NATIVE_CHECK: bind_relabel_oracle");
            let oracle = run.role(case, "oracle");
            eprintln!("DOCKERLENS_NATIVE_CHECK: bind_relabel_rendered");
            let rendered = run.role(case, "rendered");
            cases.push(json!({"case":case_name,"shape":SHAPES[case],"roles":[oracle,rendered]}));
        }
        assert_eq!(run.outer_snapshot(false).unwrap(), run.context["outer"]);
    }))
    .is_ok();
    eprintln!("DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup");
    let cleaned = run.cleanup_all();
    assert!(
        passed && cleaned && !run.mutation_uncertain && !run.cleanup_uncertain && cases.len() == 4,
        "closed bind assertions and cleanup required"
    );
    assert!(
        run.remaining() > Duration::from_secs(2),
        "closed bind publication deadline"
    );
    publish(
        &run.proof_path,
        &run.directory,
        &json!({"schema_version":1,"contract":CONTRACT,"context":run.context,
        "shapes":SHAPES,"cases":cases,"selinux_effect":"unverified","cleanup":{"containers":"absent","sources":"absent","rounds":2,"outstanding":0,"uncertain":false}}),
    );
    run.finished = true;
    eprintln!("DOCKERLENS_NATIVE_CHECK: bind_relabel_evidence");
}

#[test]
fn configured_bind_output_envelope_refuses_start_before_counters_or_other_pool_change() {
    let cap = 64 * 1024;
    for (cleanup, limit) in [(false, 12 * 1024 * 1024), (true, 2 * 1024 * 1024)] {
        // Exact capacity starts once; one byte short and both arithmetic
        // overflow directions must refuse the same production start seam.
        for (current, selected_cap, starts) in [
            (limit - 2 * cap, cap, true),
            (limit - 2 * cap + 1, cap, false),
            (limit - 1, cap, false),
            (usize::MAX, 1, false),
            (0, usize::MAX, false),
        ] {
            let mut work = if cleanup { 73 } else { current };
            let mut clean = if cleanup { current } else { 91 };
            let before = (work, clean);
            let mut commands = 0;
            let accepted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                admitted_command(cleanup, work, clean, selected_cap, || {
                    commands += 1;
                    if cleanup {
                        clean += 2 * selected_cap;
                    } else {
                        work += 2 * selected_cap;
                    }
                });
            }))
            .is_ok();
            assert_eq!(accepted, starts);
            assert_eq!(commands, usize::from(starts));
            if starts {
                if cleanup {
                    assert_eq!(clean, 2 * 1024 * 1024);
                    assert_eq!(work, before.0);
                } else {
                    assert_eq!(work, 12 * 1024 * 1024);
                    assert_eq!(clean, before.1);
                }
            } else {
                assert_eq!((work, clean), before);
            }
        }
    }
    // Exhausted work does not prevent cleanup from using its own envelope.
    let mut cleanup_starts = 0;
    admitted_command(
        true,
        12 * 1024 * 1024,
        2 * 1024 * 1024 - 2 * cap,
        cap,
        || cleanup_starts += 1,
    );
    assert_eq!(cleanup_starts, 1);
}

#[test]
fn configured_bind_versions_reject_empty_mixed_and_wrong_capture() {
    let api = |minor| ApiVersion::new(NonZeroU16::new(1).unwrap(), minor);
    for expected in [api(41), api(49)] {
        assert!(exact_versions(&[expected, expected], &[expected], expected));
        assert!(!exact_versions(&[], &[expected], expected));
        assert!(!exact_versions(&[expected], &[], expected));
        for wrong in [api(40), api(41), api(49), api(56)] {
            if wrong == expected {
                continue;
            }
            assert!(!exact_versions(&[wrong], &[wrong], expected));
            assert!(!exact_versions(&[expected, wrong], &[expected], expected));
            assert!(!exact_versions(&[expected], &[wrong], expected));
        }
    }
}
#[test]
fn configured_bind_literal_cases_preserve_case_sensitive_modes_and_source_boundary() {
    for (case, suffix) in ["rw,z", "ro,z", "rw,Z", "ro,Z"].into_iter().enumerate() {
        let name = Attempt::new("Ab12Cd34", case, "oracle").name;
        let request = literal_request(
            "1.41",
            "private/image:1",
            "Ab12Cd34",
            &name,
            "/var/lib/docker/dl-bind-relabel-Ab12Cd34/shared-rw-oracle",
            case,
        );
        assert_eq!(
            request["body"]["HostConfig"]["Binds"][0],
            format!(
                "/var/lib/docker/dl-bind-relabel-Ab12Cd34/shared-rw-oracle:/configured-bind:{suffix}"
            )
        );
        assert!(
            request["body"]["HostConfig"].get("Mounts").is_none(),
            "closed bind independent legacy branch"
        );
    }
    assert_eq!(reserve(8), Duration::from_secs(55));
    assert!(
        !SOURCE_REMOVE.contains("rm -r") && !SOURCE_REMOVE.contains("/dockerlens-native"),
        "closed bind removal never recursive or host bound"
    );
}

#[test]
fn configured_bind_ownership_rejects_foreign_identity_and_noncanonical_recovery() {
    let id = "a".repeat(64);
    let name = "dl-br-Ab12Cd34-shared-rw-oracle";
    let value = json!({"Id":id,"Name":format!("/{name}"),"Config":{"Labels":{OWNER:"Ab12Cd34"},"Image":"private/image:1"}});
    assert!(owned_identity(
        &value,
        Some(&id),
        name,
        "Ab12Cd34",
        "private/image:1"
    ));
    assert!(owned_identity(
        &value,
        None,
        name,
        "Ab12Cd34",
        "private/image:1"
    ));
    for pointer in [
        "/Id",
        "/Name",
        "/Config/Image",
        "/Config/Labels/io.dockerlens.native-run",
    ] {
        let mut foreign = value.clone();
        *foreign.pointer_mut(pointer).unwrap() = json!("foreign");
        assert!(!owned_identity(
            &foreign,
            Some(&id),
            name,
            "Ab12Cd34",
            "private/image:1"
        ));
        assert!(!owned_identity(
            &foreign,
            None,
            name,
            "Ab12Cd34",
            "private/image:1"
        ));
    }
    assert!(!owned_identity(
        &value,
        Some(&"b".repeat(64)),
        name,
        "Ab12Cd34",
        "private/image:1"
    ));
}

#[test]
fn configured_bind_renderer_matches_independent_literals_on_exact_modes_and_apis() {
    for (minor, mode) in [
        (41, DaemonMode::Rootful),
        (41, DaemonMode::Rootless),
        (56, DaemonMode::Rootful),
        (56, DaemonMode::Rootless),
    ] {
        let facts = DaemonFacts {
            observation_id: crate::version::ObservationId::fresh().unwrap(),
            release: crate::version::EngineRelease::new(
                if minor == 41 { "20.10.5" } else { "29.8.1" }.into(),
            ),
            api_version: Some(ApiVersion::new(NonZeroU16::new(1).unwrap(), minor)),
            minimum_api_version: None,
            mode,
            capabilities: vec![],
        };
        for (case, case_name) in CASES.iter().enumerate() {
            let name = Attempt::new("Ab12Cd34", case, "rendered").name;
            let source = format!(
                "/var/lib/docker/dl-bind-relabel-Ab12Cd34/{}-rendered",
                case_name
            );
            let rendered =
                rendered_request(&facts, "private/image:1", "Ab12Cd34", &name, &source, case);
            assert_eq!(
                rendered,
                literal_request(
                    &format!("1.{minor}"),
                    "private/image:1",
                    "Ab12Cd34",
                    &name,
                    &source,
                    case
                )
            );
        }
    }
}
