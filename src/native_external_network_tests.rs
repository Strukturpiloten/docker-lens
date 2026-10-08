//! Independent external bridge prerequisite proof. CLI seeds; artifacts stay inert.
//! This test-only producer does not change sealed capability admission.

use crate::acquisition::{
    Endpoint, Limits, NativeId, ReadRequest, RootKind, SelectionReason, Selector, acquire,
};
use crate::decoder::{DecodedInventory, decode_capture};
use crate::evidence::CaptureRoute;
use crate::observation::{Availability, Origin, ResourceRef};
use crate::target::{
    DockerApiRenderer, DockerPlanner, NetworkDriver, NetworkIntent, NetworkPrerequisiteError,
    NetworkRole, NetworkSource, Planner, PlanningContext, Renderer, TargetIdentity, TargetIntent,
    TargetResource,
};
use crate::version::{
    ApiVersion, Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonMode,
    EngineRelease, FactProvenance, ObservationId, ValidatedCapabilities,
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

const CONTRACT: &str = "external-network-internal-v1";
const FILENAME: &str = "external-network-internal-v1.json";
const OWNER: &str = "io.dockerlens.native-run";
const SHAPES: [&str; 2] = [
    "ExternalNetworkInternalFalse",
    "ExternalNetworkInternalTrue",
];
const CHECKS: [&str; 8] = [
    "independent_cli",
    "direct_inspect",
    "fresh_acquisition",
    "selected_root",
    "schema3_empty_requests",
    "expected_assessment",
    "opposite_assessment",
    "identity_unchanged",
];
const WORK_BYTES: usize = 8 * 1024 * 1024;
const CLEANUP_BYTES: usize = 4 * 1024 * 1024;
const RESERVE: Duration = Duration::from_secs(40);
const DAEMON_UID: &str = r#"count=0; uid=; for p in /proc/[0-9]*/comm; do [ -r "$p" ] || continue; read -r n <"$p" || continue; [ "$n" = dockerd ] || continue; count=$((count+1)); uid=$(awk '/^Uid:/ {print $3}' "${p%/comm}/status"); done; [ "$count" -eq 1 ]; printf '%s\n' "$uid""#;

fn check(ok: bool) {
    assert!(ok, "closed external network proof failure");
}
fn admit_pool(cleanup: bool, used: (usize, usize), requested: (usize, usize)) -> bool {
    let (calls, bytes) = if cleanup {
        (64, CLEANUP_BYTES)
    } else {
        (128, WORK_BYTES)
    };
    used.0
        .checked_add(requested.0)
        .zip(used.1.checked_add(requested.1))
        .is_some_and(|(total_calls, total_bytes)| total_calls <= calls && total_bytes <= bytes)
}

fn fresh_mode_matches(fresh: DaemonMode, confirmed: DaemonMode, uid: Option<u32>) -> bool {
    match (confirmed, uid) {
        (DaemonMode::Rootless, Some(uid)) if uid != 0 => fresh == DaemonMode::Rootless,
        (DaemonMode::Rootful, Some(0)) => {
            matches!(fresh, DaemonMode::Rootful | DaemonMode::Unknown)
        }
        _ => false,
    }
}

fn artifact_context_matches(
    typed: Option<&PlanningContext>,
    serialized: &Value,
    expected: &CapabilityScope,
) -> bool {
    if !matches!(typed, Some(PlanningContext::Observed(actual)) if actual == expected) {
        return false;
    }
    let mode = match expected.mode {
        DaemonMode::Rootful => "rootful",
        DaemonMode::Rootless => "rootless",
        DaemonMode::Unknown => return false,
    };
    serialized
        == &json!({"kind":"observed","provenance":"process_local_only",
        "engine_release":expected.release.as_str(),
        "api_version":format!("{}.{}",expected.api_version.major,expected.api_version.minor),
        "daemon_mode":mode})
}
fn required(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("closed external network input"))
}
fn canonical(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Run {
    fn outer(&mut self, cleanup: bool) -> Value {
        let args = vec![
            "inspect".into(),
            "--format".into(),
            "{{json .}}".into(),
            self.outer_id.clone(),
        ];
        let output = self.podman(cleanup, &args);
        check(output.status.success() && output.stderr.is_empty());
        let value = json_bytes(&output.stdout);
        let host = &value["HostConfig"];
        let mounts = value["Mounts"]
            .as_array()
            .unwrap_or_else(|| panic!("closed external mounts"));
        let volume = mounts
            .iter()
            .find(|m| m["Type"] == "volume")
            .unwrap_or_else(|| panic!("closed external volume"));
        let bind = mounts
            .iter()
            .find(|m| m["Type"] == "bind")
            .unwrap_or_else(|| panic!("closed external socket"));
        let storage = if self.mode == DaemonMode::Rootless {
            "/home/docker/.local/share/docker"
        } else {
            "/var/lib/docker"
        };
        let networks = value["NetworkSettings"]["Networks"]
            .as_object()
            .unwrap_or_else(|| panic!("closed external outer network"));
        check(
            value["Id"] == self.outer_id
                && value["Name"] == self.outer_name
                && value["Config"]["Labels"][OWNER] == self.token
                && value["ImageDigest"] == self.outer_image.split_once('@').unwrap().1
                && value["State"]["Running"] == true
                && host["Privileged"] == true
                && host["Memory"] == 4294967296_u64
                && host["CpuQuota"] == 200000
                && host["CpuPeriod"] == 100000
                && host["PidsLimit"] == 512
                && mounts.len() == 2
                && volume["Name"] == format!("dl-native-data-{}", self.token)
                && volume["Destination"] == storage
                && volume["RW"] == true
                && bind["Source"] == self.directory.join("socket").to_str().unwrap()
                && bind["Destination"] == "/dockerlens-native"
                && bind["RW"] == true
                && networks.len() == 1
                && networks.contains_key(&format!("dl-native-net-{}", self.token)),
        );
        json!({"id":self.outer_id,"name":self.outer_name,"owner":self.token,"image":self.outer_image,
            "data_volume":format!("dl-native-data-{}",self.token),"socket_source":self.directory.join("socket"),
            "privileged":true,"memory_bytes":4294967296_u64,"cpu_quota":200000,"cpu_period":100000,"pids_limit":512})
    }
    fn observe_context(&mut self) {
        eprintln!("DOCKERLENS_NATIVE_CHECK: external_network_context");
        let outer = self.outer(false);
        let (code, version) = self.api(false, "GET", "/version");
        check(
            code == 200 && version["Version"] == self.release && version["ApiVersion"] == self.api,
        );
        let cli = self.cli(
            &[
                "version".into(),
                "--format".into(),
                "{{.Server.Version}}|{{.Server.APIVersion}}".into(),
            ],
            false,
        );
        check(cli == format!("{}|{}\n", self.release, self.api).into_bytes());
        if self.lane.starts_with("debian11-") {
            check(
                matches!(self.release.as_str(), "20.10.5" | "20.10.5+dfsg1")
                    && self.package == "20.10.5+dfsg1-1+deb11u2",
            );
            let package = self.podman(
                false,
                &[
                    "exec".into(),
                    self.outer_id.clone(),
                    "dpkg-query".into(),
                    "-W".into(),
                    concat!("-f=$", "{Version}").into(),
                    "docker.io".into(),
                ],
            );
            check(
                package.status.success()
                    && package.stderr.is_empty()
                    && package.stdout == self.package.as_bytes(),
            );
        } else {
            check(self.release == "29.8.1" && self.package.is_empty());
        }
        let (code, info) = self.api(false, "GET", &format!("/v{}/info", self.api));
        let storage = if self.mode == DaemonMode::Rootless {
            "/home/docker/.local/share/docker"
        } else {
            "/var/lib/docker"
        };
        check(code == 200 && info["DockerRootDir"] == storage);
        let rootless = info["Rootless"] == true
            || info["SecurityOptions"].as_array().is_some_and(|v| {
                v.iter().any(|s| {
                    s.as_str()
                        .is_some_and(|s| s == "name=rootless" || s.starts_with("name=rootless,"))
                })
            });
        check(rootless == (self.mode == DaemonMode::Rootless));
        let options = json_bytes(&self.cli(
            &[
                "info".into(),
                "--format".into(),
                "{{json .SecurityOptions}}".into(),
            ],
            false,
        ));
        check(
            options.as_array().is_some_and(|v| {
                v.iter().any(|s| {
                    s.as_str()
                        .is_some_and(|s| s == "name=rootless" || s.starts_with("name=rootless,"))
                })
            }) == rootless,
        );
        let uid = self.podman(
            false,
            &[
                "exec".into(),
                self.outer_id.clone(),
                "sh".into(),
                "-ec".into(),
                DAEMON_UID.into(),
            ],
        );
        check(uid.status.success() && uid.stderr.is_empty());
        let observed: u32 = std::str::from_utf8(&uid.stdout)
            .ok()
            .and_then(|s| s.strip_suffix('\n'))
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("closed external daemon UID"));
        check(
            (observed != 0) == rootless
                && observed.to_string() == required("NATIVE_BIND_RELABEL_DAEMON_UID"),
        );
        self.daemon_uid = Some(observed);
        self.context = json!({"candidate_sha":self.candidate,"run_id":self.token,"lane":self.lane,
            "engine_release":self.release,"rendering_api":self.api,"acquisition_api":format!("1.{}",self.acquisition.minor),
            "mode":if rootless {"rootless"} else {"rootful"},"docker_package":self.package,
            "fixture_image":self.fixture,"outer":outer,"daemon_uid":observed});
    }
}
fn pinned(value: &str) -> bool {
    value.split_once("@sha256:").is_some_and(|(name, digest)| {
        name.contains(':') && !name.chars().any(char::is_whitespace) && canonical(digest, 64)
    })
}
fn json_bytes(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|_| panic!("closed external network JSON"))
}
fn drain(mut reader: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut retained = Vec::new();
    let mut overflow = false;
    let mut chunk = [0; 8192];
    loop {
        let count = reader
            .read(&mut chunk)
            .unwrap_or_else(|_| panic!("closed external network stream"));
        if count == 0 {
            break;
        }
        let keep = count.min(cap.saturating_sub(retained.len()));
        retained.extend_from_slice(&chunk[..keep]);
        overflow |= keep != count;
    }
    (retained, overflow)
}

#[derive(Clone)]
struct Bridge {
    name: String,
    id: Option<String>,
    started: bool,
    absent: bool,
}

struct Run {
    token: String,
    lane: String,
    mode: DaemonMode,
    api: String,
    acquisition: ApiVersion,
    release: String,
    package: String,
    fixture: String,
    outer_id: String,
    outer_name: String,
    outer_image: String,
    elevated: bool,
    directory: PathBuf,
    socket: PathBuf,
    candidate: String,
    deadline: Instant,
    epoch: SystemTime,
    work_calls: usize,
    work_bytes: usize,
    cleanup_calls: usize,
    cleanup_bytes: usize,
    bridges: Vec<Bridge>,
    context: Value,
    daemon_uid: Option<u32>,
    mutation_uncertain: bool,
    finished: bool,
}

impl Run {
    fn new() -> Self {
        let outer_name = required("NATIVE_OUTER_CONTAINER");
        let token = outer_name
            .strip_prefix("dl-native-")
            .unwrap_or_else(|| panic!("closed external run"))
            .to_owned();
        check(token.len() == 8 && token.bytes().all(|b| b.is_ascii_alphanumeric()));
        let lane = required("NATIVE_LANE");
        let api = required("NATIVE_API_VERSION");
        let mode = match required("NATIVE_DAEMON_MODE").as_str() {
            "rootful" => DaemonMode::Rootful,
            "rootless" => DaemonMode::Rootless,
            _ => panic!("closed external mode"),
        };
        check(
            matches!(lane.as_str(), "debian11-rootful" | "debian11-rootless") && api == "1.41"
                || matches!(lane.as_str(), "upstream-rootful" | "upstream-rootless")
                    && api == "1.56",
        );
        check(lane.ends_with("-rootless") == (mode == DaemonMode::Rootless));
        let directory = PathBuf::from(required("NATIVE_CAPTURE_DIR"));
        let _ = held_directory(&directory);
        check(
            Path::new(&required("NATIVE_EXTERNAL_NETWORK_PROOF_PATH")) == directory.join(FILENAME),
        );
        check(
            fs::symlink_metadata(directory.join(FILENAME))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        );
        let socket = PathBuf::from(required("NATIVE_ENGINE_SOCKET"));
        check(socket == directory.join("socket/docker.sock"));
        let candidate = required("NATIVE_EXTERNAL_NETWORK_CANDIDATE_SHA");
        let outer_id = required("NATIVE_OUTER_CONTAINER_ID");
        check(canonical(&candidate, 40) && canonical(&outer_id, 64));
        let fixture = required("NATIVE_FIXTURE_IMAGE");
        let outer_image = required("NATIVE_OUTER_IMAGE");
        check(pinned(&fixture) && pinned(&outer_image));
        let epoch = UNIX_EPOCH
            + Duration::from_secs(
                required("NATIVE_NETWORK_TEST_DEADLINE_EPOCH")
                    .parse()
                    .unwrap_or_else(|_| panic!("closed external deadline")),
            );
        let remaining = epoch
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .min(Duration::from_secs(180));
        check(remaining > RESERVE + Duration::from_secs(20));
        let elevated = match required("NATIVE_PODMAN_USE_SUDO").as_str() {
            "0" => false,
            "1" => true,
            _ => panic!("closed external privilege selector"),
        };
        Self {
            token,
            lane: lane.clone(),
            mode,
            api,
            acquisition: ApiVersion::new(
                NonZeroU16::new(1).unwrap(),
                if lane.starts_with("debian11-") {
                    41
                } else {
                    49
                },
            ),
            release: required("NATIVE_ENGINE_VERSION"),
            package: required("NATIVE_DOCKER_PACKAGE"),
            fixture,
            outer_id,
            outer_name,
            outer_image,
            elevated,
            directory,
            socket,
            candidate,
            deadline: Instant::now() + remaining,
            epoch,
            work_calls: 0,
            work_bytes: 0,
            cleanup_calls: 0,
            cleanup_bytes: 0,
            bridges: vec![],
            context: Value::Null,
            daemon_uid: None,
            mutation_uncertain: false,
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
    fn charge(&mut self, cleanup: bool, calls: usize, bytes: usize) {
        if cleanup {
            check(self.remaining() > Duration::from_secs(2));
            check(admit_pool(
                true,
                (self.cleanup_calls, self.cleanup_bytes),
                (calls, bytes),
            ));
            self.cleanup_calls += calls;
            self.cleanup_bytes += bytes;
        } else {
            check(self.remaining() > RESERVE + Duration::from_secs(6));
            check(admit_pool(
                false,
                (self.work_calls, self.work_bytes),
                (calls, bytes),
            ));
            self.work_calls += calls;
            self.work_bytes += bytes;
        }
    }
    fn command(&mut self, cleanup: bool, elevated: bool, args: &[String]) -> Output {
        const CAP: usize = 64 * 1024;
        self.charge(cleanup, 1, 2 * CAP);
        let mut command = Command::new(if elevated { "sudo" } else { "timeout" });
        if elevated {
            command.args(["-n", "timeout"]);
        }
        command
            .args([
                "--signal=TERM",
                "--kill-after=0.25s",
                if cleanup { "0.75s" } else { "3s" },
            ])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .unwrap_or_else(|_| panic!("closed external command"));
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let out = std::thread::spawn(move || drain(stdout, CAP));
        let err = std::thread::spawn(move || drain(stderr, CAP));
        let status = child
            .wait()
            .unwrap_or_else(|_| panic!("closed external wait"));
        let (stdout, large_out) = out.join().unwrap();
        let (stderr, large_err) = err.join().unwrap();
        check(!large_out && !large_err);
        Output {
            status,
            stdout,
            stderr,
        }
    }
    fn podman(&mut self, cleanup: bool, args: &[String]) -> Output {
        let mut argv = vec!["podman".into(), "--remote=false".into()];
        argv.extend_from_slice(args);
        self.command(cleanup, self.elevated, &argv)
    }
    fn cli(&mut self, args: &[String], mutation: bool) -> Vec<u8> {
        if mutation {
            self.mutation_uncertain = true;
        }
        let mut argv = vec![
            "exec".into(),
            self.outer_id.clone(),
            "docker".into(),
            "-H".into(),
            "unix:///dockerlens-native/docker.sock".into(),
        ];
        argv.extend_from_slice(args);
        let result = self.podman(false, &argv);
        check(result.status.success() && result.stderr.is_empty());
        result.stdout
    }
    fn allowed(&self, cleanup: bool, method: &str, path: &str) -> bool {
        if !cleanup
            && method == "GET"
            && (path == "/version" || path == format!("/v{}/info", self.api))
        {
            return true;
        }
        self.bridges.iter().any(|bridge| {
            method == "GET"
                && (path == format!("/v{}/networks/{}", self.api, bridge.name)
                    || bridge
                        .id
                        .as_ref()
                        .is_some_and(|id| path == format!("/v{}/networks/{id}", self.api)))
                || method == "DELETE"
                    && cleanup
                    && bridge.started
                    && bridge
                        .id
                        .as_ref()
                        .is_some_and(|id| path == format!("/v{}/networks/{id}", self.api))
        })
    }
    fn api(&mut self, cleanup: bool, method: &str, path: &str) -> (u16, Value) {
        check(self.allowed(cleanup, method, path));
        let argv = vec![
            "curl".into(),
            "-q".into(),
            "--noproxy".into(),
            "*".into(),
            "-sS".into(),
            "--max-time".into(),
            if cleanup { "0.5".into() } else { "2".into() },
            "--max-filesize".into(),
            "60000".into(),
            "--unix-socket".into(),
            self.socket.to_string_lossy().into(),
            "-X".into(),
            method.into(),
            "--write-out".into(),
            "\n%{http_code}".into(),
            format!("http://localhost{path}"),
        ];
        let result = self.command(cleanup, false, &argv);
        check(result.status.success() && result.stderr.is_empty());
        let split = result
            .stdout
            .iter()
            .rposition(|b| *b == b'\n')
            .unwrap_or_else(|| panic!("closed external HTTP status"));
        let code = std::str::from_utf8(&result.stdout[split + 1..])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("closed external HTTP status"));
        check((100..=599).contains(&code));
        let body = if split == 0 {
            Value::Null
        } else {
            json_bytes(&result.stdout[..split])
        };
        (code, body)
    }
}

impl Run {
    fn capture(&mut self, id: &str) -> DecodedInventory {
        check(canonical(id, 64) && self.remaining() > RESERVE + Duration::from_secs(7));
        self.charge(false, 3, 384 * 1024);
        let capture = acquire(
            &Endpoint::unix_socket(self.socket.clone()),
            Selector::NetworkIds(vec![NativeId::new(id.into()).unwrap()]),
            Limits {
                max_requests: 3,
                max_selected_resources: 1,
                max_expansions: 1,
                max_response_bytes: 128 * 1024,
                max_total_bytes: 384 * 1024,
                max_elapsed: Duration::from_secs(5),
            },
            &AtomicBool::new(false),
        )
        .unwrap_or_else(|_| panic!("closed external fresh acquisition"));
        check(
            capture.route() == CaptureRoute::ExplicitUnixSocket && capture.exchanges().len() == 3,
        );
        let versioned: Vec<_> = capture
            .exchanges()
            .iter()
            .filter_map(|e| e.api_version())
            .collect();
        check(versioned.len() == 2 && versioned.iter().all(|v| *v == self.acquisition));
        check(capture.exchanges().iter().all(|e| e.status().code() == 200));
        check(capture.exchanges().iter().all(|e| match e.request() {
            ReadRequest::DaemonVersion => e.api_version().is_none(),
            ReadRequest::DaemonInfo => e.api_version() == Some(self.acquisition),
            ReadRequest::InspectNetwork(selected) => {
                selected.as_str() == id && e.api_version() == Some(self.acquisition)
            }
            _ => false,
        }));
        check(
            capture
                .exchanges()
                .iter()
                .filter(|e| matches!(e.request(), ReadRequest::DaemonVersion))
                .count()
                == 1
                && capture
                    .exchanges()
                    .iter()
                    .filter(|e| matches!(e.request(), ReadRequest::DaemonInfo))
                    .count()
                    == 1,
        );
        check(capture.exchanges().iter().filter(|e|
            matches!(e.request(), ReadRequest::InspectNetwork(selected) if selected.as_str() == id)).count() == 1);
        let inventory =
            decode_capture(&capture).unwrap_or_else(|_| panic!("closed external fresh decoding"));
        check(
            inventory.observation_id == capture.observation_id()
                && inventory.version.daemon.observation_id == capture.observation_id(),
        );
        let advertised = ApiVersion::new(
            NonZeroU16::new(1).unwrap(),
            if self.lane.starts_with("debian11-") {
                41
            } else {
                56
            },
        );
        check(
            inventory.version.daemon.api_version == Some(advertised)
                && inventory
                    .version
                    .daemon
                    .release
                    .as_ref()
                    .is_some_and(|v| v.as_str() == self.release),
        );
        check(fresh_mode_matches(
            inventory.version.daemon.mode,
            self.mode,
            self.daemon_uid,
        ));
        check(inventory.version.requested_api_versions == [self.acquisition]);
        check(
            inventory.networks.len() == 1
                && inventory.selected_roots.len() == 1
                && inventory.containers.is_empty()
                && inventory.discovered_containers.is_empty()
                && inventory.volumes.is_empty(),
        );
        let network = &inventory.networks[0];
        let root = inventory.selected_roots[0];
        check(
            root.kind == RootKind::Network
                && root.reason == SelectionReason::ExactNetworkId
                && root.resource == network.reference,
        );
        check(
            network.id.availability == Availability::Present
                && network.id.origin == Origin::RuntimeAssigned
                && network
                    .id
                    .value()
                    .is_some_and(|v| v.as_bytes() == id.as_bytes()),
        );
        inventory
    }
    fn case(&mut self, internal: bool) -> Value {
        let case = if internal { "internal" } else { "ordinary" };
        eprintln!("DOCKERLENS_NATIVE_CHECK: external_network_oracle");
        let name = format!("dl-ext-{}-{case}", self.token);
        self.bridges.push(Bridge {
            name: name.clone(),
            id: None,
            started: false,
            absent: false,
        });
        let index = self.bridges.len() - 1;
        let (code, _) = self.api(false, "GET", &format!("/v{}/networks/{name}", self.api));
        check(code == 404);
        self.bridges[index].started = true;
        let created = self.cli(
            &[
                "network".into(),
                "create".into(),
                "--driver".into(),
                "bridge".into(),
                format!("--internal={internal}"),
                "--label".into(),
                format!("{OWNER}={}", self.token),
                name.clone(),
            ],
            true,
        );
        let id = std::str::from_utf8(&created)
            .ok()
            .and_then(|s| s.strip_suffix('\n'))
            .filter(|s| canonical(s, 64))
            .unwrap_or_else(|| panic!("closed external created ID"))
            .to_owned();
        check(
            self.bridges
                .iter()
                .filter_map(|v| v.id.as_ref())
                .all(|other| *other != id),
        );
        self.bridges[index].id = Some(id.clone());
        let (code, direct) = self.api(false, "GET", &format!("/v{}/networks/{id}", self.api));
        check(code == 200 && owned(&direct, &self.bridges[index], &self.token));
        check(direct["Driver"] == "bridge" && direct["Internal"] == internal);
        self.mutation_uncertain = false;
        let oracle = json_bytes(&self.cli(
            &[
                "network".into(),
                "inspect".into(),
                "--format".into(),
                "{{json .}}".into(),
                id.clone(),
            ],
            false,
        ));
        check(
            owned(&oracle, &self.bridges[index], &self.token)
                && oracle["Driver"] == "bridge"
                && oracle["Internal"] == internal,
        );
        let inventory = self.capture(&id);
        let network = &inventory.networks[0];
        check(
            network.internal.availability == Availability::Present
                && network.internal.origin == Origin::Effective
                && network.internal.value() == Some(&internal),
        );
        eprintln!("DOCKERLENS_NATIVE_CHECK: external_network_assessment");
        let artifact = external_artifact(&inventory, self.mode, &name, internal);
        check(artifact.bytes().is_empty() && artifact.network_prerequisites().len() == 1);
        let complete = json_bytes(
            &artifact
                .complete_bytes()
                .unwrap_or_else(|_| panic!("closed external schema")),
        );
        let expected_scope = self.expected_scope(inventory.observation_id);
        check(artifact_context_matches(
            artifact.context(),
            &complete["context"],
            &expected_scope,
        ));
        check(complete["schema_version"] == 3 && complete["requests"] == json!([]));
        check(
            complete["prerequisites"]
                == json!([{"kind":"network","reference":"9001","identity":name,
            "expected_driver":"bridge","expected_internal":internal}]),
        );
        let selected = NativeId::new(id.clone()).unwrap();
        check(
            artifact.network_prerequisites()[0].expected_internal == Some(internal)
                && artifact.network_prerequisites()[0]
                    .assess(&inventory, inventory.observation_id, &selected)
                    .is_ok(),
        );
        let opposite = external_artifact(&inventory, self.mode, &name, !internal);
        let opposite_complete = json_bytes(
            &opposite
                .complete_bytes()
                .unwrap_or_else(|_| panic!("closed external opposite schema")),
        );
        check(artifact_context_matches(
            opposite.context(),
            &opposite_complete["context"],
            &expected_scope,
        ));
        check(
            opposite_complete["schema_version"] == 3
                && opposite_complete["requests"] == json!([])
                && opposite_complete["prerequisites"]
                    == json!([{"kind":"network","reference":"9001","identity":name,
                "expected_driver":"bridge","expected_internal":!internal}]),
        );
        check(
            opposite.bytes().is_empty()
                && opposite.network_prerequisites()[0].assess(
                    &inventory,
                    inventory.observation_id,
                    &selected,
                ) == Err(NetworkPrerequisiteError::NetworkInternalMismatch),
        );
        let (code, after) = self.api(false, "GET", &format!("/v{}/networks/{id}", self.api));
        check(
            code == 200
                && owned(&after, &self.bridges[index], &self.token)
                && after["Driver"] == "bridge"
                && after["Internal"] == internal,
        );
        json!({"case":case,"shape":SHAPES[usize::from(internal)],"id":id,"name":name,"owner":self.token,
            "internal":internal,"checks":CHECKS.iter().map(|key| ((*key).to_owned(), Value::String("passed".into()))).collect::<serde_json::Map<_,_>>(),
            "cleanup":"absent"})
    }
    fn cleanup(&mut self) -> bool {
        eprintln!("DOCKERLENS_NATIVE_CHECK: external_network_cleanup");
        if self.context.is_null() {
            return self.bridges.is_empty() && !self.mutation_uncertain;
        }
        check(self.outer(true) == self.context["outer"]);
        for index in (0..self.bridges.len()).rev() {
            if self.bridges[index].absent || !self.bridges[index].started {
                continue;
            }
            let bridge = self.bridges[index].clone();
            let key = bridge.id.as_ref().unwrap_or(&bridge.name);
            let (status, value) = self.api(true, "GET", &format!("/v{}/networks/{key}", self.api));
            if status == 200 {
                check(owned(&value, &bridge, &self.token));
                let id = value["Id"].as_str().unwrap().to_owned();
                check(canonical(&id, 64));
                self.bridges[index].id = Some(id.clone());
                let (status, _) =
                    self.api(true, "DELETE", &format!("/v{}/networks/{id}", self.api));
                check(status == 204);
            } else {
                check(status == 404);
            }
        }
        for _ in 0..2 {
            for index in 0..self.bridges.len() {
                let bridge = self.bridges[index].clone();
                if !bridge.started {
                    continue;
                }
                check(bridge.id.is_some());
                for key in [bridge.name.as_str(), bridge.id.as_deref().unwrap()] {
                    let (status, _) =
                        self.api(true, "GET", &format!("/v{}/networks/{key}", self.api));
                    check(status == 404);
                }
                self.bridges[index].absent = true;
            }
        }
        check(self.outer(true) == self.context["outer"]);
        !self.mutation_uncertain && self.bridges.iter().all(|v| !v.started || v.absent)
    }

    fn expected_scope(&self, observation_id: ObservationId) -> CapabilityScope {
        CapabilityScope {
            observation_id,
            release: EngineRelease::new(self.release.clone()).unwrap(),
            api_version: ApiVersion::new(
                NonZeroU16::new(1).unwrap(),
                if self.lane.starts_with("debian11-") {
                    41
                } else {
                    56
                },
            ),
            mode: self.mode,
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if !self.finished {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup()));
        }
    }
}

fn owned(value: &Value, bridge: &Bridge, token: &str) -> bool {
    value["Id"].as_str().is_some_and(|id| {
        canonical(id, 64) && bridge.id.as_ref().is_none_or(|expected| expected == id)
    }) && value["Name"] == bridge.name
        && value["Labels"][OWNER] == token
}

fn external_artifact(
    inventory: &DecodedInventory,
    mode: DaemonMode,
    name: &str,
    internal: bool,
) -> crate::target::RenderedArtifact {
    let target = TargetIntent::new(vec![TargetResource::Network(NetworkIntent {
        reference: ResourceRef::new(9001),
        identity: TargetIdentity::new(name.as_bytes().to_vec()).unwrap(),
        role: NetworkRole::Declared,
        source: NetworkSource::External {
            expected_driver: NetworkDriver::Bridge,
            expected_internal: Some(internal),
        },
    })])
    .unwrap();
    let scope = CapabilityScope {
        observation_id: inventory.observation_id,
        release: inventory.version.daemon.release.clone().unwrap(),
        api_version: inventory.version.daemon.api_version.unwrap(),
        mode,
    };
    // Test-only facts exercise the unadmitted branch in independently verified
    // context. The artifact retains genuine advertised API and observation ID;
    // acquisition request API is independently checked, never rewritten.
    let mut facts = crate::version::DaemonFacts {
        observation_id: scope.observation_id,
        release: Some(scope.release.clone()),
        api_version: Some(scope.api_version),
        minimum_api_version: inventory.version.daemon.minimum_api_version,
        mode,
        capabilities: vec![],
    };
    facts.capabilities = [
        Capability::NetworkExternalReference,
        Capability::NetworkExternalInternalExpectation,
    ]
    .iter()
    .map(|capability| CapabilityFact {
        capability: *capability,
        state: CapabilityState::Available,
        provenance: FactProvenance::NativeConformance,
        scope: Some(scope.clone()),
    })
    .collect();
    let validated = ValidatedCapabilities::new(&facts).unwrap();
    DockerApiRenderer
        .render(&DockerPlanner.plan(&target, &validated).unwrap())
        .unwrap()
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileCustody {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    links: u64,
    regular: bool,
}

fn custody(metadata: &fs::Metadata) -> FileCustody {
    FileCustody {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        group: metadata.gid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        regular: metadata.is_file(),
    }
}

fn private_custody(custody: FileCustody, current_uid: u32) -> bool {
    custody.regular
        && custody.owner == current_uid
        && custody.mode & 0o7777 == 0o600
        && custody.links == 1
}

fn finalized_custody_matches(
    before: FileCustody,
    after: FileCustody,
    named: FileCustody,
    current_uid: u32,
) -> bool {
    private_custody(before, current_uid)
        && private_custody(after, current_uid)
        && private_custody(named, current_uid)
        && before == after
        && after == named
}

fn held_directory(path: &Path) -> File {
    check(path.is_absolute() && path.canonicalize().ok().as_deref() == Some(path));
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .unwrap_or_else(|_| panic!("closed external directory"));
    let info = held.metadata().unwrap();
    let named = fs::symlink_metadata(path).unwrap();
    let uid = fs::metadata("/proc/self").unwrap().uid();
    check(
        info.is_dir()
            && info.uid() == uid
            && info.mode() & 0o7777 == 0o700
            && (info.dev(), info.ino(), info.uid(), info.mode())
                == (named.dev(), named.ino(), named.uid(), named.mode()),
    );
    held
}

fn publish(directory: &Path, proof: &Value) {
    let held = held_directory(directory);
    let parent = held.metadata().unwrap();
    let bytes = serde_json::to_vec(proof).unwrap();
    check(!bytes.is_empty() && bytes.len() <= 16 * 1024);
    let selected = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd())).join(FILENAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(selected)
        .unwrap_or_else(|_| panic!("closed external exclusive proof"));
    let before = file.metadata().unwrap();
    let finished = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check(
            private_custody(custody(&before), fs::metadata("/proc/self").unwrap().uid())
                && before.uid() == parent.uid(),
        );
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        let after = file.metadata().unwrap();
        let named = fs::symlink_metadata(directory.join(FILENAME)).unwrap();
        let current = fs::symlink_metadata(directory).unwrap();
        check(finalized_custody_matches(
            custody(&before),
            custody(&after),
            custody(&named),
            fs::metadata("/proc/self").unwrap().uid(),
        ));
        check(after.len() == bytes.len() as u64 && named.len() == after.len());
        check(
            (parent.dev(), parent.ino(), parent.uid(), parent.mode())
                == (current.dev(), current.ino(), current.uid(), current.mode()),
        );
        check(directory.canonicalize().ok().as_deref() == Some(directory));
    }))
    .is_ok();
    if !finished {
        let _ = file.set_len(0);
    }
    check(finished);
}

#[test]
#[ignore = "requires the exact isolated four-lane Engine harness"]
fn live_external_network_internal_matches_engine() {
    let mut run = Run::new();
    let mut networks = vec![];
    let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run.observe_context();
        networks.push(run.case(false));
        networks.push(run.case(true));
        check(run.outer(false) == run.context["outer"]);
    }))
    .is_ok();
    let cleaned =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.cleanup())).unwrap_or(false);
    if !cleaned {
        eprintln!("DOCKERLENS_NATIVE_CHECK: external_network_cleanup_unverified");
    }
    check(passed && cleaned && networks.len() == 2);
    let proof = json!({"schema_version":1,"contract":CONTRACT,"context":run.context,"shapes":SHAPES,
        "networks":networks,"cleanup":{"networks":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    check(run.remaining() > Duration::from_secs(2));
    publish(&run.directory, &proof);
    run.finished = true;
    eprintln!("DOCKERLENS_NATIVE_CHECK: external_network_evidence");
}

#[test]
fn external_proof_identity_is_exact_owned_and_network_kind_scoped() {
    let bridge = Bridge {
        name: "owned".into(),
        id: Some("a".repeat(64)),
        started: true,
        absent: false,
    };
    check(owned(
        &json!({"Id":"a".repeat(64),"Name":"owned","Labels":{"io.dockerlens.native-run":"run"}}),
        &bridge,
        "run",
    ));
    check(!owned(
        &json!({"Id":"b".repeat(64),"Name":"owned","Labels":{"io.dockerlens.native-run":"run"}}),
        &bridge,
        "run",
    ));
    check(!owned(
        &json!({"Id":"a".repeat(64),"Name":"owned","Labels":{"io.dockerlens.native-run":"foreign"}}),
        &bridge,
        "run",
    ));
    check(!owned(
        &json!({"Id":"a".repeat(64),"Name":"foreign","Labels":{"io.dockerlens.native-run":"run"}}),
        &bridge,
        "run",
    ));
    for invalid in ["a".repeat(63), "g".repeat(64), "A".repeat(64)] {
        check(!canonical(&invalid, 64));
    }
}

#[test]
fn external_proof_work_and_cleanup_pools_are_independent_and_fail_before_use() {
    check(admit_pool(false, (127, WORK_BYTES - 2), (1, 2)));
    check(!admit_pool(false, (128, 0), (1, 0)));
    check(!admit_pool(false, (0, WORK_BYTES), (0, 1)));
    check(admit_pool(true, (63, CLEANUP_BYTES - 2), (1, 2)));
    check(!admit_pool(true, (64, 0), (1, 0)));
    check(!admit_pool(true, (0, CLEANUP_BYTES), (0, 1)));
    check(!admit_pool(false, (usize::MAX, 0), (1, 0)));
    let (retained, overflow) = drain(b"bounded-extra".as_slice(), 7);
    check(retained == b"bounded" && overflow);
}

#[test]
fn external_proof_fresh_mode_requires_independent_uid_and_rejects_contradiction() {
    for (fresh, confirmed, uid, expected) in [
        (DaemonMode::Rootless, DaemonMode::Rootless, Some(1000), true),
        (DaemonMode::Unknown, DaemonMode::Rootless, Some(1000), false),
        (DaemonMode::Rootful, DaemonMode::Rootless, Some(1000), false),
        (DaemonMode::Rootless, DaemonMode::Rootless, Some(0), false),
        (DaemonMode::Rootful, DaemonMode::Rootful, Some(0), true),
        (DaemonMode::Unknown, DaemonMode::Rootful, Some(0), true),
        (DaemonMode::Rootless, DaemonMode::Rootful, Some(0), false),
        (DaemonMode::Unknown, DaemonMode::Rootful, Some(1000), false),
        (DaemonMode::Rootful, DaemonMode::Rootful, None, false),
        (DaemonMode::Rootless, DaemonMode::Rootless, None, false),
    ] {
        check(fresh_mode_matches(fresh, confirmed, uid) == expected);
    }
    for fresh in [
        DaemonMode::Unknown,
        DaemonMode::Rootful,
        DaemonMode::Rootless,
    ] {
        for uid in [None, Some(0), Some(1000)] {
            check(!fresh_mode_matches(fresh, DaemonMode::Unknown, uid));
        }
    }
}

#[test]
fn external_proof_typed_and_serialized_context_refuse_api_scope_mode_and_provenance_drift() {
    let scope = CapabilityScope {
        observation_id: ObservationId::fresh().unwrap(),
        release: EngineRelease::new("29.8.1".into()).unwrap(),
        api_version: ApiVersion::new(NonZeroU16::new(1).unwrap(), 56),
        mode: DaemonMode::Rootless,
    };
    let typed = PlanningContext::Observed(scope.clone());
    // Independent closed wire fixture: acquisition 1.49 must never replace 1.56.
    let serialized = json!({"kind":"observed","provenance":"process_local_only",
        "engine_release":"29.8.1","api_version":"1.56","daemon_mode":"rootless"});
    check(artifact_context_matches(Some(&typed), &serialized, &scope));
    check(!artifact_context_matches(None, &serialized, &scope));
    for mutation in 0..4 {
        let mut wrong = scope.clone();
        match mutation {
            0 => wrong.observation_id = ObservationId::fresh().unwrap(),
            1 => wrong.api_version = ApiVersion::new(NonZeroU16::new(1).unwrap(), 49),
            2 => wrong.mode = DaemonMode::Rootful,
            _ => wrong.release = EngineRelease::new("29.8.0".into()).unwrap(),
        }
        check(!artifact_context_matches(
            Some(&PlanningContext::Observed(wrong)),
            &serialized,
            &scope,
        ));
    }
    for (field, wrong) in [
        ("kind", "target"),
        ("provenance", "authenticated"),
        ("engine_release", "29.8.0"),
        ("api_version", "1.49"),
        ("daemon_mode", "rootful"),
    ] {
        let mut document = serialized.clone();
        document[field] = json!(wrong);
        check(!artifact_context_matches(Some(&typed), &document, &scope));
    }
    let mut durable = serialized;
    durable["observation_id"] = json!("invented-durable-id");
    check(!artifact_context_matches(Some(&typed), &durable, &scope));
}

#[test]
fn external_proof_finalization_refuses_shared_or_named_only_custody_drift() {
    let initial = FileCustody {
        device: 1,
        inode: 2,
        owner: 1000,
        group: 1000,
        mode: libc::S_IFREG | 0o600,
        links: 1,
        regular: true,
    };
    check(finalized_custody_matches(initial, initial, initial, 1000));
    check(!finalized_custody_matches(initial, initial, initial, 1001));
    for mutation in 0..8 {
        let mut changed = initial;
        match mutation {
            0 => changed.device += 1,
            1 => changed.inode += 1,
            2 => changed.owner += 1,
            3 => changed.group += 1,
            4 => changed.mode = libc::S_IFREG | 0o644,
            5 => changed.links = 2,
            6 => changed.regular = false,
            _ => changed.mode |= 0o4000,
        }
        // In particular, matching post-write fd and named metadata must not hide
        // both drifting together away from the original private custody.
        check(!finalized_custody_matches(initial, changed, changed, 1000));
        check(!finalized_custody_matches(initial, initial, changed, 1000));
    }
}
