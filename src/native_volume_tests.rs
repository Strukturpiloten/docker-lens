//! Isolated, test-only evidence for caller-declared existing named volumes.
//! The product planner and renderer never execute these requests or move data.

use crate::observation::ResourceRef;
use crate::target::{
    Argument, ContainerIntent, ContainerLabel, ContainerSettings, DockerApiRenderer, DockerPlanner,
    ImageCommand, ImageReference, Mount, OperationAction, OperationStepAction, Planner,
    RenderedArtifact, Renderer, TargetIdentity, TargetIntent, TargetKind, TargetResource,
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
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const CANARY: &[u8] = b"native-volume-canary\n";
const UPDATED: &[u8] = b"native-volume-updated\n";
const MAX_API_CALLS: usize = 24;
const MAX_API_BYTES: usize = 512 * 1024;
const PROBES: &[&str] = &[
    "ExistingVolumePrerequisite",
    "ExistingVolumeTargetIdentity",
    "ExistingVolumeReadOnlyData",
    "ExistingVolumeReadWriteData",
    "ExistingVolumePersistence",
    "MissingVolumePrecheck",
];

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("native harness must supply {name}"))
}

fn run_id() -> String {
    let outer = required("NATIVE_OUTER_CONTAINER");
    let run = outer
        .strip_prefix("dl-native-")
        .expect("native outer prefix");
    assert!(
        run.len() == 8 && run.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "closed native run id"
    );
    run.to_owned()
}

#[derive(Debug, Eq, PartialEq)]
enum OutputError {
    MissingPipe,
    Read,
    Write,
    TooLarge,
    Deadline,
    Wait,
}

fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>, OutputError> {
    let mut reader = reader;
    let mut bytes = Vec::with_capacity(limit);
    let mut chunk = [0_u8; 4096];
    let mut too_large = false;
    loop {
        let count = reader.read(&mut chunk).map_err(|_| OutputError::Read)?;
        if count == 0 {
            break;
        }
        let retained = (limit - bytes.len()).min(count);
        bytes.extend_from_slice(&chunk[..retained]);
        too_large |= retained < count;
    }
    if too_large {
        return Err(OutputError::TooLarge);
    }
    Ok(bytes)
}

fn bounded_output(
    mut child: Child,
    limit: usize,
    deadline: Duration,
) -> Result<(ExitStatus, Vec<u8>), OutputError> {
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(OutputError::MissingPipe);
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader_thread = thread::spawn(move || {
        let _ = sender.send(read_bounded(stdout, limit));
    });
    let bytes = match receiver.recv_timeout(deadline) {
        Ok(Ok(bytes)) => {
            let _ = reader_thread.join();
            bytes
        }
        Ok(Err(error)) => {
            let _ = reader_thread.join();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            // Usually killing the timed command closes stdout immediately. If
            // an escaped descendant retains the pipe, never wait indefinitely.
            if receiver.recv_timeout(Duration::from_secs(5)).is_ok() {
                let _ = reader_thread.join();
            }
            return Err(OutputError::Deadline);
        }
    };
    let status = child.wait().map_err(|_| OutputError::Wait)?;
    Ok((status, bytes))
}

fn write_request_body(child: &mut Child, body: &[u8]) -> Result<(), OutputError> {
    let write_result = child
        .stdin
        .take()
        .ok_or(OutputError::MissingPipe)
        .and_then(|mut stdin| stdin.write_all(body).map_err(|_| OutputError::Write));
    if write_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    write_result
}

fn inner_docker(args: &[&str]) -> std::process::Output {
    let mut command = Command::new("timeout");
    command.args(["-k", "5s", "60"]);
    match required("NATIVE_PODMAN_USE_SUDO").as_str() {
        "0" => {
            command.arg("podman");
        }
        "1" => {
            command.args(["sudo", "-n", "podman"]);
        }
        _ => panic!("closed Podman privilege selector"),
    }
    command.args([
        "exec",
        &required("NATIVE_OUTER_CONTAINER"),
        "docker",
        "-H",
        "unix:///dockerlens-native/docker.sock",
    ]);
    command.args(args);
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let child = command.spawn().expect("bounded inner Docker CLI spawn");
    let (status, stdout) = bounded_output(child, 4096, Duration::from_secs(70))
        .expect("closed inner Docker output limit");
    std::process::Output {
        status,
        stdout,
        stderr: Vec::new(),
    }
}

fn docker_ok(args: &[&str]) -> Vec<u8> {
    let output = inner_docker(args);
    assert!(output.status.success(), "closed inner Docker CLI failure");
    assert!(
        output.stdout.len() <= 4096,
        "bounded inner Docker CLI output"
    );
    output.stdout
}

fn dockerd_effective_uid() -> u32 {
    let mut command = Command::new("timeout");
    command.args(["-k", "5s", "15"]);
    match required("NATIVE_PODMAN_USE_SUDO").as_str() {
        "0" => {
            command.arg("podman");
        }
        "1" => {
            command.args(["sudo", "-n", "podman"]);
        }
        _ => panic!("closed Podman privilege selector"),
    }
    command.args([
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
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let child = command.spawn().expect("bounded dockerd UID probe spawn");
    let (status, stdout) = bounded_output(child, 128, Duration::from_secs(25))
        .expect("closed dockerd UID output limit");
    assert!(status.success(), "dockerd UID probe failed");
    let text = std::str::from_utf8(&stdout).expect("dockerd UID shape");
    let (count, uid) = text.trim().split_once(':').expect("dockerd UID shape");
    assert!(count == "1", "exactly one inner dockerd required");
    assert!(
        !uid.is_empty() && uid.bytes().all(|byte| byte.is_ascii_digit()),
        "numeric dockerd effective UID required"
    );
    uid.parse().expect("bounded dockerd effective UID")
}

struct NativeApi {
    socket: String,
    version: String,
    volume_names: [String; 2],
    container_names: [String; 3],
    container_ids: Vec<String>,
    calls: usize,
    bytes: usize,
    posts: usize,
}

impl NativeApi {
    fn new(version: String, volume_names: [String; 2], container_names: [String; 3]) -> Self {
        let (major, minor) = version.split_once('.').expect("native API version shape");
        assert!(
            major == "1" && minor.parse::<u16>().is_ok(),
            "closed native API version"
        );
        let socket = required("NATIVE_ENGINE_SOCKET");
        assert!(socket.starts_with('/'), "absolute native socket");
        Self {
            socket,
            version,
            volume_names,
            container_names,
            container_ids: Vec::new(),
            calls: 0,
            bytes: 0,
            posts: 0,
        }
    }

    fn prefix(&self) -> String {
        format!("/v{}", self.version)
    }

    fn allowed(&self, method: &str, path: &str) -> bool {
        if method == "GET" && path == "/version" {
            return true;
        }
        let prefix = self.prefix();
        if method == "GET" && path == format!("{prefix}/info") {
            return true;
        }
        if method == "GET"
            && self
                .volume_names
                .iter()
                .any(|name| path == format!("{prefix}/volumes/{name}"))
        {
            return true;
        }
        if method == "POST"
            && self
                .container_names
                .iter()
                .any(|name| path == format!("{prefix}/containers/create?name={name}"))
        {
            return true;
        }
        self.container_ids.iter().any(|id| {
            (method == "GET" && path == format!("{prefix}/containers/{id}/json"))
                || (method == "POST" && path == format!("{prefix}/containers/{id}/start"))
        })
    }

    fn request(&mut self, method: &str, path: &str, body: Option<&Value>) -> (u16, Vec<u8>) {
        assert!(self.allowed(method, path), "closed volume API request");
        assert!(self.calls < MAX_API_CALLS, "volume API call budget");
        let body = body.map(|value| serde_json::to_vec(value).expect("bounded request JSON"));
        assert!(
            body.as_ref().is_none_or(|bytes| bytes.len() <= 8192),
            "volume API request-body budget"
        );
        self.calls += 1;
        if method == "POST" {
            self.posts += 1;
        }
        let mut command = Command::new("timeout");
        command.args([
            "-k",
            "5s",
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
        if body.is_some() {
            command.args(["--data-binary", "@-"]);
            command.stdin(Stdio::piped());
        } else if method == "POST" {
            command.args(["--data-binary", ""]);
        }
        command.args(["-w", "\n%{http_code}", &format!("http://localhost{path}")]);
        command.stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = command.spawn().expect("bounded volume API curl");
        if let Some(body) = body {
            write_request_body(&mut child, &body).expect("closed volume API body write");
        }
        let (status, stdout) = bounded_output(child, 65_541, Duration::from_secs(30))
            .expect("closed volume API output limit");
        assert!(status.success(), "closed volume API transfer failure");
        let split = stdout
            .iter()
            .rposition(|byte| *byte == b'\n')
            .expect("volume API status marker");
        let status = std::str::from_utf8(&stdout[split + 1..])
            .expect("volume API status UTF-8")
            .parse::<u16>()
            .expect("volume API numeric status");
        let response = stdout[..split].to_vec();
        self.bytes += response.len();
        assert!(self.bytes <= MAX_API_BYTES, "volume API total-byte budget");
        (status, response)
    }

    fn register_container(&mut self, response: &[u8]) -> String {
        let body: Value = serde_json::from_slice(response).expect("container create response JSON");
        let id = body["Id"].as_str().expect("container ID shape");
        assert!(
            id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "closed container ID"
        );
        self.container_ids.push(id.to_owned());
        id.to_owned()
    }
}

struct OwnedResources {
    run_id: String,
    volume: String,
    containers: Vec<String>,
    volume_create_attempted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VolumeCleanupDecision {
    NoOwnedVolume,
    Remove,
    Unverified,
}

fn volume_cleanup_decision(
    create_attempted: bool,
    present: Option<bool>,
    owner_matches: bool,
) -> VolumeCleanupDecision {
    match (create_attempted, present, owner_matches) {
        (false, _, _) | (true, Some(false), _) => VolumeCleanupDecision::NoOwnedVolume,
        (true, Some(true), true) => VolumeCleanupDecision::Remove,
        _ => VolumeCleanupDecision::Unverified,
    }
}

impl OwnedResources {
    fn new(run_id: String, volume: String, containers: Vec<String>) -> Self {
        Self {
            run_id,
            volume,
            containers,
            volume_create_attempted: false,
        }
    }

    fn container_present(&self, name: &str) -> Option<bool> {
        let inspected = inner_docker(&["container", "inspect", "--format", "{{.Name}}", name]);
        if inspected.status.success() {
            return (inspected.stdout == format!("/{name}\n").as_bytes()).then_some(true);
        }
        let filter = format!("name=^/{name}$");
        let output = inner_docker(&[
            "container",
            "ls",
            "-a",
            "--filter",
            &filter,
            "--format",
            "{{.Names}}",
        ]);
        if !output.status.success() || output.stdout.len() > 4096 {
            return None;
        }
        let names = std::str::from_utf8(&output.stdout).ok()?;
        Some(names.lines().any(|found| found == name))
    }

    fn volume_present(&self, name: &str) -> Option<bool> {
        let inspected = inner_docker(&["volume", "inspect", "--format", "{{.Name}}", name]);
        if inspected.status.success() {
            return (inspected.stdout == format!("{name}\n").as_bytes()).then_some(true);
        }
        let filter = format!("name=^{name}$");
        let output = inner_docker(&["volume", "ls", "--filter", &filter, "--format", "{{.Name}}"]);
        if !output.status.success() || output.stdout.len() > 4096 {
            return None;
        }
        let names = std::str::from_utf8(&output.stdout).ok()?;
        Some(names.lines().any(|found| found == name))
    }

    fn remove_container(&self, name: &str) -> bool {
        if self.container_present(name) != Some(true) {
            return self.container_present(name) == Some(false);
        }
        let inspect = inner_docker(&[
            "container",
            "inspect",
            "--format",
            "{{index .Config.Labels \"io.dockerlens.native-run\"}}",
            name,
        ]);
        if !inspect.status.success() || inspect.stdout != format!("{}\n", self.run_id).as_bytes() {
            return false;
        }
        let removed = inner_docker(&["container", "rm", "-f", name]);
        removed.status.success() && self.container_present(name) == Some(false)
    }

    fn remove_volume(&self) -> bool {
        if !self.volume_create_attempted {
            return true;
        }
        let present = self.volume_present(&self.volume);
        let owner_matches = if present == Some(true) {
            let inspect = inner_docker(&[
                "volume",
                "inspect",
                "--format",
                "{{index .Labels \"io.dockerlens.native-run\"}}",
                &self.volume,
            ]);
            inspect.status.success() && inspect.stdout == format!("{}\n", self.run_id).as_bytes()
        } else {
            false
        };
        match volume_cleanup_decision(self.volume_create_attempted, present, owner_matches) {
            VolumeCleanupDecision::NoOwnedVolume => true,
            VolumeCleanupDecision::Remove => {
                let removed = inner_docker(&["volume", "rm", &self.volume]);
                removed.status.success() && self.volume_present(&self.volume) == Some(false)
            }
            VolumeCleanupDecision::Unverified => false,
        }
    }

    fn cleanup(&self) -> bool {
        let mut clean = true;
        for name in &self.containers {
            clean = self.remove_container(name) && clean;
        }
        self.remove_volume() && clean
    }

    fn create_seed_volume(&mut self, create: impl FnOnce() -> Vec<u8>) -> Result<(), ()> {
        // Mark before invoking a command that can succeed and then fail to
        // return the expected output. Drop will inspect the exact owner label.
        self.volume_create_attempted = true;
        let created = create();
        (created == format!("{}\n", self.volume).as_bytes())
            .then_some(())
            .ok_or(())
    }

    fn seed(&mut self, image: &str) {
        assert!(
            self.volume_present(&self.volume) == Some(false),
            "seed volume name unused"
        );
        for name in &self.containers {
            assert!(
                self.container_present(name) == Some(false),
                "probe container name unused"
            );
        }
        let label = format!("io.dockerlens.native-run={}", self.run_id);
        let volume = self.volume.clone();
        self.create_seed_volume(|| docker_ok(&["volume", "create", "--label", &label, &volume]))
            .expect("seed volume identity");
        let seed_mount = format!("type=volume,source={},target=/data", self.volume);
        let seed_name = self.containers.first().expect("seed container name");
        let output = docker_ok(&[
            "run",
            "--rm",
            "--pull=never",
            "--name",
            seed_name,
            "--label",
            &label,
            "--network",
            "none",
            "--mount",
            &seed_mount,
            image,
            "sh",
            "-c",
            "printf 'native-volume-canary\\n' > /data/canary",
        ]);
        assert!(output.is_empty(), "seed command output shape");
        assert!(
            self.container_present(seed_name) == Some(false),
            "seed container removed"
        );
    }
}

impl Drop for OwnedResources {
    fn drop(&mut self) {
        if !matches!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup())),
            Ok(true)
        ) {
            eprintln!("DOCKERLENS_NATIVE_CHECK: volume_cleanup_unverified");
        }
    }
}

#[test]
fn unexpected_seed_create_output_keeps_label_verified_cleanup_armed() {
    // No Engine exists in this offline fault injection; ManuallyDrop prevents
    // the native cleanup command while preserving the state transition.
    let mut owned = std::mem::ManuallyDrop::new(OwnedResources::new(
        "synthetic".to_owned(),
        "dl-volume-synthetic-data".to_owned(),
        vec![],
    ));
    assert!(owned.create_seed_volume(|| b"unexpected".to_vec()).is_err());
    assert!(owned.volume_create_attempted);
    assert_eq!(
        volume_cleanup_decision(owned.volume_create_attempted, Some(true), true),
        VolumeCleanupDecision::Remove
    );
    assert_eq!(
        volume_cleanup_decision(owned.volume_create_attempted, Some(true), false),
        VolumeCleanupDecision::Unverified
    );
    assert_eq!(
        volume_cleanup_decision(false, Some(true), true),
        VolumeCleanupDecision::NoOwnedVolume
    );

    let mut panicking = std::mem::ManuallyDrop::new(OwnedResources::new(
        "synthetic".to_owned(),
        "dl-volume-synthetic-data".to_owned(),
        vec![],
    ));
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = panicking.create_seed_volume(|| panic!("closed synthetic create failure"));
    }));
    assert!(failure.is_err());
    assert!(panicking.volume_create_attempted);
    assert_eq!(
        volume_cleanup_decision(panicking.volume_create_attempted, Some(true), true),
        VolumeCleanupDecision::Remove
    );
}

#[test]
fn bounded_native_output_rejects_excess_without_retaining_private_bytes() {
    let private = b"protected-native-output";
    assert_eq!(
        read_bounded(private.as_slice(), 4),
        Err(OutputError::TooLarge)
    );
    assert_eq!(read_bounded(b"okay".as_slice(), 4), Ok(b"okay".to_vec()));

    let mut command = Command::new("sh");
    command.args(["-c", "printf 'protected-native-output'"]);
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let child = command.spawn().expect("local bounded-output fixture");
    assert_eq!(
        bounded_output(child, 4, Duration::from_secs(5)),
        Err(OutputError::TooLarge)
    );
}

#[test]
fn early_request_stdin_close_is_closed_and_reaps_the_child() {
    let mut command = Command::new("sh");
    command.args(["-c", "exec 0<&-; sleep 1"]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().expect("local early-stdin-close fixture");
    let private = vec![b'x'; 1024 * 1024];
    assert_eq!(
        write_request_body(&mut child, &private),
        Err(OutputError::Write)
    );
    assert!(child.try_wait().expect("child reap state").is_some());
}

fn scoped_facts(api: &mut NativeApi) -> DaemonFacts {
    let (status, raw_version) = api.request("GET", "/version", None);
    assert!(status == 200, "native version status");
    let version: Value = serde_json::from_slice(&raw_version).expect("native version JSON");
    let advertised = version["ApiVersion"].as_str().expect("native API version");
    assert!(
        advertised == api.version,
        "native API version matches harness"
    );
    let release_text = version["Version"].as_str().expect("native Engine release");
    assert!(
        release_text == required("NATIVE_ENGINE_VERSION"),
        "native Engine release matches harness"
    );
    let release = EngineRelease::new(release_text.to_owned()).expect("native release present");
    let (major, minor) = api
        .version
        .split_once('.')
        .expect("native API version parts");
    let version = ApiVersion::new(
        NonZeroU16::new(major.parse().expect("native API major"))
            .expect("native API major nonzero"),
        minor.parse().expect("native API minor"),
    );
    let (status, raw_info) = api.request("GET", &format!("{}/info", api.prefix()), None);
    assert!(status == 200, "native daemon info status");
    let info: Value = serde_json::from_slice(&raw_info).expect("native daemon info JSON");
    let rootless_reported = info["Rootless"] == true
        || info["SecurityOptions"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item.as_str().is_some_and(|value| {
                    value == "name=rootless" || value.starts_with("name=rootless,")
                })
            })
        });
    let uid = dockerd_effective_uid();
    let mode = match (required("NATIVE_DAEMON_MODE").as_str(), uid) {
        ("rootless", 1..) if rootless_reported => DaemonMode::Rootless,
        ("rootful", 0) if !rootless_reported => DaemonMode::Rootful,
        _ => panic!("native volume daemon mode mismatch"),
    };
    let observation_id = ObservationId::fresh().expect("test-local observation ID");
    let scope = CapabilityScope {
        observation_id,
        release: release.clone(),
        api_version: version,
        mode,
    };
    // Test-local provisional facts are scoped to this independently checked daemon.
    // They are not added to the public reviewed catalog or published evidence.
    let capabilities = [
        Capability::StandaloneContainer,
        Capability::NamedVolume,
        Capability::VolumeExternalReference,
        Capability::Command,
        Capability::ContainerLabels,
    ]
    .into_iter()
    .map(|capability| CapabilityFact {
        capability,
        state: CapabilityState::Available,
        provenance: FactProvenance::NativeConformance,
        scope: Some(scope.clone()),
    })
    .collect();
    DaemonFacts {
        observation_id,
        release: Some(release),
        api_version: Some(version),
        minimum_api_version: None,
        mode,
        capabilities,
    }
}

fn rendered_mount(
    name: &str,
    volume: &str,
    image: &str,
    run_id: &str,
    read_only: bool,
    capabilities: &ValidatedCapabilities<'_>,
) -> RenderedArtifact {
    let intent = TargetIntent::new(vec![
        TargetResource::Container(Box::new(ContainerIntent {
            reference: ResourceRef::new(2),
            identity: TargetIdentity::new(name.as_bytes().to_vec()).expect("target container name"),
            image: ImageReference::new(image.as_bytes().to_vec()).expect("pinned fixture image"),
            environment: vec![],
            ports: vec![],
            mounts: vec![
                Mount::volume(ResourceRef::new(1), b"/data".to_vec(), read_only)
                    .expect("exact volume mount"),
            ],
            networks: vec![],
            entrypoint: ImageCommand::Inherit,
            command: ImageCommand::Exec(
                ["sh", "-c", "sleep 120"]
                    .into_iter()
                    .map(|value| Argument::new(value.as_bytes().to_vec()).expect("fixed argument"))
                    .collect(),
            ),
            healthcheck: None,
            restart: None,
            settings: ContainerSettings {
                labels: vec![
                    ContainerLabel::new(
                        b"io.dockerlens.native-run".to_vec(),
                        run_id.as_bytes().to_vec(),
                    )
                    .expect("test ownership label"),
                ],
                ..ContainerSettings::default()
            },
        })),
        TargetResource::ExternalVolume {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(volume.as_bytes().to_vec()).expect("target volume name"),
        },
    ])
    .expect("native external-volume intent");
    let graph = DockerPlanner
        .plan(&intent, capabilities)
        .expect("test-local native volume capability plan");
    assert!(
        graph.nodes()[1].operation.action == OperationAction::RequireExisting,
        "volume graph action"
    );
    assert!(
        graph.steps()[1].action == OperationStepAction::RequireExisting(TargetKind::Volume),
        "volume prerequisite step"
    );
    assert!(
        graph.steps()[0].depends_on == vec![graph.steps()[1].id],
        "container prerequisite ordering"
    );
    DockerApiRenderer
        .render(&graph)
        .expect("native volume inert artifact")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VolumeReject {
    MissingPrerequisite,
    InvalidArtifact,
    NativeResponse,
}

fn execute_mount(
    api: &mut NativeApi,
    artifact: &RenderedArtifact,
    name: &str,
    volume: &str,
    image: &str,
    run_id: &str,
    read_only: bool,
) -> Result<String, VolumeReject> {
    if !artifact.network_prerequisites().is_empty()
        || artifact.volume_prerequisites().len() != 1
        || artifact.volume_prerequisites()[0].reference != ResourceRef::new(1)
        || artifact.volume_prerequisites()[0].identity() != volume.as_bytes()
    {
        return Err(VolumeReject::InvalidArtifact);
    }
    let mut lines = artifact
        .bytes()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    let record: Value = serde_json::from_slice(lines.next().ok_or(VolumeReject::InvalidArtifact)?)
        .map_err(|_| VolumeReject::InvalidArtifact)?;
    if lines.next().is_some() || record.as_object().is_none_or(|object| object.len() != 3) {
        return Err(VolumeReject::InvalidArtifact);
    }
    let path = format!("{}/containers/create?name={name}", api.prefix());
    let expected_body = json!({
        "Image": image,
        "Cmd": ["sh", "-c", "sleep 120"],
        "Labels": {"io.dockerlens.native-run": run_id},
        "HostConfig": {"Mounts": [{
            "Type": "volume", "Source": volume, "Target": "/data", "ReadOnly": read_only
        }]}
    });
    if record["method"] != "POST" || record["path"] != path || record["body"] != expected_body {
        return Err(VolumeReject::InvalidArtifact);
    }

    // A missing named volume can be auto-created by Engine's container-create
    // endpoint. A preflight GET is mandatory before ANY rendered POST.
    let (status, response) =
        api.request("GET", &format!("{}/volumes/{volume}", api.prefix()), None);
    if status == 404 {
        return Err(VolumeReject::MissingPrerequisite);
    }
    if status != 200 {
        return Err(VolumeReject::NativeResponse);
    }
    let inspected: Value =
        serde_json::from_slice(&response).map_err(|_| VolumeReject::NativeResponse)?;
    if inspected["Name"] != volume || inspected["Driver"] != "local" {
        return Err(VolumeReject::NativeResponse);
    }
    let (status, response) = api.request("POST", &path, Some(&record["body"]));
    if status != 201 {
        return Err(VolumeReject::NativeResponse);
    }
    Ok(api.register_container(&response))
}

fn inspected_mount(
    api: &mut NativeApi,
    id: &str,
    name: &str,
    volume: &str,
    run: &str,
    read_only: bool,
) {
    let (status, response) = api.request(
        "GET",
        &format!("{}/containers/{id}/json", api.prefix()),
        None,
    );
    assert!(status == 200, "native mounted container inspect status");
    let inspected: Value =
        serde_json::from_slice(&response).expect("native mounted container JSON");
    assert!(
        inspected["Id"] == id
            && inspected["Name"] == format!("/{name}")
            && inspected["Config"]["Labels"]["io.dockerlens.native-run"] == run,
        "exact owned native container identity"
    );
    let mounts = inspected["Mounts"].as_array().expect("native mount array");
    assert!(mounts.len() == 1, "one exact named-volume mount");
    let mount = &mounts[0];
    assert!(
        mount["Type"] == "volume"
            && mount["Name"] == volume
            && mount["Destination"] == "/data"
            && mount["RW"] == !read_only,
        "exact native named-volume mount binding"
    );
}

fn start_container(api: &mut NativeApi, id: &str) {
    let (status, response) = api.request(
        "POST",
        &format!("{}/containers/{id}/start", api.prefix()),
        None,
    );
    assert!(
        status == 204 && response.is_empty(),
        "native container start response"
    );
}

fn inspect_volume(api: &mut NativeApi, name: &str) -> String {
    let (status, response) = api.request("GET", &format!("{}/volumes/{name}", api.prefix()), None);
    assert!(status == 200, "native named-volume inspect status");
    let inspected: Value = serde_json::from_slice(&response).expect("native named-volume JSON");
    assert!(
        inspected["Name"] == name && inspected["Driver"] == "local",
        "native volume identity and driver"
    );
    let mountpoint = inspected["Mountpoint"]
        .as_str()
        .expect("native volume mountpoint");
    assert!(
        mountpoint.starts_with('/'),
        "native volume mountpoint shape"
    );
    mountpoint.to_owned()
}

// The harness selects only this exact ignored test for native volume evidence.
#[test]
#[ignore = "requires an isolated DockerLens native Engine lane"]
fn live_existing_volume_prerequisite_matches_engine() {
    let run = run_id();
    let prefix = format!("dl-volume-{run}");
    let existing = format!("{prefix}-data");
    let missing = format!("{prefix}-missing");
    let seed = format!("{prefix}-seed");
    let ro = format!("{prefix}-ro");
    let rw = format!("{prefix}-rw");
    let again = format!("{prefix}-again");
    let mut owned = OwnedResources::new(
        run.clone(),
        existing.clone(),
        vec![seed, ro.clone(), rw.clone(), again.clone()],
    );
    let image = required("NATIVE_FIXTURE_IMAGE");
    let mut api = NativeApi::new(
        required("NATIVE_API_VERSION"),
        [existing.clone(), missing.clone()],
        [ro.clone(), rw.clone(), again.clone()],
    );
    let facts = scoped_facts(&mut api);
    let capabilities = ValidatedCapabilities::new(&facts).expect("test-local scoped daemon facts");

    eprintln!("DOCKERLENS_NATIVE_CHECK: volume_missing_precheck");
    assert!(
        owned.volume_present(&missing) == Some(false),
        "missing volume initially absent"
    );
    let missing_artifact = rendered_mount(&ro, &missing, &image, &run, false, &capabilities);
    let posts_before = api.posts;
    assert!(
        execute_mount(
            &mut api,
            &missing_artifact,
            &ro,
            &missing,
            &image,
            &run,
            false
        ) == Err(VolumeReject::MissingPrerequisite),
        "missing prerequisite rejected before container creation"
    );
    assert!(
        api.posts == posts_before,
        "missing prerequisite causes no POST"
    );
    assert!(
        owned.volume_present(&missing) == Some(false),
        "missing volume remains absent"
    );
    let (status, _) = api.request("GET", &format!("{}/volumes/{missing}", api.prefix()), None);
    assert!(status == 404, "missing volume remains absent in Engine");

    eprintln!("DOCKERLENS_NATIVE_CHECK: volume_seed");
    owned.seed(&image);
    let mountpoint = inspect_volume(&mut api, &existing);

    eprintln!("DOCKERLENS_NATIVE_CHECK: volume_read_only");
    let ro_artifact = rendered_mount(&ro, &existing, &image, &run, true, &capabilities);
    assert!(
        !format!("{ro_artifact:?}").contains(&existing),
        "protected volume artifact Debug"
    );
    let ro_id = execute_mount(&mut api, &ro_artifact, &ro, &existing, &image, &run, true)
        .expect("exact existing-volume RO request");
    inspected_mount(&mut api, &ro_id, &ro, &existing, &run, true);
    start_container(&mut api, &ro_id);
    assert!(
        docker_ok(&["exec", &ro_id, "head", "-c", "64", "/data/canary"]) == CANARY,
        "seed canary readable through RO mount"
    );
    let blocked = inner_docker(&["exec", &ro_id, "sh", "-c", "printf blocked > /data/blocked"]);
    assert!(
        !blocked.status.success(),
        "RO volume rejects container write"
    );

    eprintln!("DOCKERLENS_NATIVE_CHECK: volume_read_write");
    let rw_artifact = rendered_mount(&rw, &existing, &image, &run, false, &capabilities);
    let rw_id = execute_mount(&mut api, &rw_artifact, &rw, &existing, &image, &run, false)
        .expect("exact existing-volume RW request");
    inspected_mount(&mut api, &rw_id, &rw, &existing, &run, false);
    start_container(&mut api, &rw_id);
    assert!(
        docker_ok(&["exec", &rw_id, "head", "-c", "64", "/data/canary"]) == CANARY,
        "seed canary readable through RW mount"
    );
    docker_ok(&[
        "exec",
        &rw_id,
        "sh",
        "-c",
        "test ! -e /data/blocked && printf 'native-volume-updated\\n' > /data/updated",
    ]);
    assert!(
        owned.remove_container(&rw),
        "exact owned RW container removed"
    );

    eprintln!("DOCKERLENS_NATIVE_CHECK: volume_persistence");
    assert!(
        inspect_volume(&mut api, &existing) == mountpoint,
        "volume identity and mountpoint retained"
    );
    let again_artifact = rendered_mount(&again, &existing, &image, &run, true, &capabilities);
    let again_id = execute_mount(
        &mut api,
        &again_artifact,
        &again,
        &existing,
        &image,
        &run,
        true,
    )
    .expect("exact recreated consumer request");
    inspected_mount(&mut api, &again_id, &again, &existing, &run, true);
    start_container(&mut api, &again_id);
    assert!(
        docker_ok(&["exec", &again_id, "head", "-c", "64", "/data/canary"]) == CANARY,
        "original seed survives container recreation"
    );
    assert!(
        docker_ok(&["exec", &again_id, "head", "-c", "64", "/data/updated"]) == UPDATED,
        "RW update survives container recreation"
    );
    assert!(
        inspect_volume(&mut api, &existing) == mountpoint,
        "same native volume preserved"
    );

    eprintln!("DOCKERLENS_NATIVE_CHECK: volume_identity");
    assert!(
        owned.cleanup(),
        "exact native volume probe cleanup verified"
    );
    let probe_path = PathBuf::from(required("NATIVE_VOLUME_PROBES_PATH"));
    assert!(
        probe_path == PathBuf::from(required("NATIVE_CAPTURE_DIR")).join("volume-probes.json"),
        "private exact volume probe path"
    );
    fs::write(
        probe_path,
        serde_json::to_vec(PROBES).expect("closed volume probe names"),
    )
    .expect("private volume probe evidence");
}
