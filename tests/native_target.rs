//! Independent live probes admit an observed target context only for this daemon.
//! This test-only executor applies a closed set of inert renderer requests.

use std::fs;
use std::io::Write;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use docker_lens::acquisition::{Endpoint, Limits, NativeId, Selector, acquire};
use docker_lens::decoder::decode_capture;
use docker_lens::evidence::CaptureRoute;
use docker_lens::observation::ResourceRef;
use docker_lens::target::{
    Argument, ContainerIntent, DockerApiRenderer, DockerPlanner, EnvironmentAssignment,
    Healthcheck, ImageReference, Mount, Planner, PortBinding, Protocol, Renderer, RestartPolicy,
    TargetIdentity, TargetIntent, TargetResource,
};
use docker_lens::version::{
    Capability, CapabilityFact, CapabilityScope, CapabilityState, DaemonMode, FactProvenance,
    ValidatedCapabilities,
};
use serde_json::{Value, json};

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("native harness must supply {name}"))
}

fn direct_body(name: &str) -> Value {
    let path = PathBuf::from(required("NATIVE_CAPTURE_DIR")).join(name);
    let status = fs::read_to_string(path.with_extension("status")).expect("direct API status");
    assert_eq!(status.trim(), "200");
    serde_json::from_slice(&fs::read(path).expect("direct API body")).expect("native JSON")
}

fn api(method: &str, path: &str, body: Option<&Value>) -> (u16, Vec<u8>) {
    assert!(path.starts_with("/v") || path == "/version");
    let socket = required("NATIVE_ENGINE_SOCKET");
    let mut command = Command::new("curl");
    command.args(["-fsS", "--max-time", "15", "--unix-socket", &socket]);
    command.args(["-X", method, "-H", "Content-Type: application/json"]);
    if body.is_some() {
        command.args(["--data-binary", "@-"]);
        command.stdin(Stdio::piped());
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
    let output = child.wait_with_output().expect("Engine API response");
    assert!(
        output.status.success(),
        "test-only Engine API request failed"
    );
    let split = output
        .stdout
        .iter()
        .rposition(|byte| *byte == b'\n')
        .expect("HTTP status marker");
    let status = std::str::from_utf8(&output.stdout[split + 1..])
        .unwrap()
        .parse()
        .expect("numeric HTTP status");
    (status, output.stdout[..split].to_vec())
}

fn inner_docker(args: &[&str]) -> Vec<u8> {
    let outer = required("NATIVE_OUTER_CONTAINER");
    let mut command = Command::new("timeout");
    command.arg("60");
    if required("NATIVE_PODMAN_USE_SUDO") == "1" {
        command.args(["sudo", "-n", "podman"]);
    } else {
        command.arg("podman");
    }
    command.args([
        "exec",
        &outer,
        "docker",
        "-H",
        "unix:///run/dockerlens/docker.sock",
    ]);
    command.args(args);
    command.stderr(Stdio::null());
    let output = command.output().expect("isolated inner Docker CLI");
    assert!(
        output.status.success(),
        "independent inner Docker probe failed"
    );
    output.stdout
}

// Test-only independent evidence from the outer container's own /proc view.
// Neither the harness lane name nor a missing /info marker establishes rootful mode.
fn dockerd_effective_uid() -> u32 {
    let outer = required("NATIVE_OUTER_CONTAINER");
    let mut command = Command::new("timeout");
    command.arg("15");
    if required("NATIVE_PODMAN_USE_SUDO") == "1" {
        command.args(["sudo", "-n", "podman"]);
    } else {
        command.arg("podman");
    }
    command.args([
        "exec",
        &outer,
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
    command.stderr(Stdio::null());
    let output = command.output().expect("isolated dockerd UID probe");
    assert!(output.status.success(), "dockerd UID probe failed");
    let result = std::str::from_utf8(&output.stdout).expect("numeric dockerd UID probe");
    let (count, effective) = result
        .trim()
        .split_once(':')
        .expect("dockerd UID probe shape");
    assert!(count == "1", "expected exactly one inner dockerd");
    assert!(
        !effective.is_empty() && effective.bytes().all(|byte| byte.is_ascii_digit()),
        "dockerd effective UID is not numeric"
    );
    effective
        .parse()
        .expect("bounded numeric dockerd effective UID")
}

fn assert_all_interface_binding(container: &Value, key: &str, host_port: &str) {
    let bindings = container["HostConfig"]["PortBindings"][key]
        .as_array()
        .expect("explicit native port bindings");
    assert!(!bindings.is_empty());
    for binding in bindings {
        assert_eq!(binding["HostPort"], host_port);
        assert!(matches!(
            binding["HostIp"].as_str(),
            None | Some("") | Some("0.0.0.0") | Some("::")
        ));
    }
}

fn assert_mount(container: &Value, kind: &str, destination: &str, name: Option<&str>, rw: bool) {
    let mount = container["Mounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|mount| mount["Type"] == kind && mount["Destination"] == destination)
        .expect("native mount shape");
    assert_eq!(mount["RW"], rw);
    if let Some(name) = name {
        assert_eq!(mount["Name"], name);
    }
}

fn probe_traffic(container_id: &str, tcp: u16, udp: u16) {
    let image = required("NATIVE_FIXTURE_IMAGE");
    let tcp_url = format!("http://127.0.0.1:{tcp}/index.html");
    let tcp_output = inner_docker(&[
        "run",
        "--rm",
        "--network",
        "host",
        &image,
        "wget",
        "-qO-",
        &tcp_url,
    ]);
    assert_eq!(tcp_output.as_slice(), b"native-tcp-canary\n");

    let send = format!("printf native-udp-canary | nc -u -w 1 127.0.0.1 {udp}");
    inner_docker(&[
        "run",
        "--rm",
        "--network",
        "host",
        &image,
        "sh",
        "-c",
        &send,
    ]);
    for _ in 0..10 {
        let received = inner_docker(&[
            "exec",
            container_id,
            "sh",
            "-c",
            "cat /data/udp-received 2>/dev/null || true",
        ]);
        if received.as_slice() == b"native-udp-canary" {
            return;
        }
        thread::sleep(Duration::from_secs(1));
    }
    panic!("published UDP traffic did not reach the isolated test container");
}

fn argument(value: &str) -> Argument {
    Argument::new(value.as_bytes().to_vec()).unwrap()
}

#[test]
#[ignore = "requires isolated rootful/rootless inner Engine and exact test-only resources"]
fn live_target_render_matches_engine() {
    let socket = PathBuf::from(required("NATIVE_ENGINE_SOCKET"));
    let source_id = required("NATIVE_CONTAINER_ID");
    let api_version = required("NATIVE_API_VERSION");
    let source_volume = required("NATIVE_VOLUME_NAME");
    let source_network = required("NATIVE_NETWORK_ID");
    let source = direct_body("container.json");
    let network = direct_body("network.json");
    let volume = direct_body("volume.json");
    let info = direct_body("info.json");
    let version = direct_body("version.json");

    // These are independently authored CLI resources and raw Engine GETs, not
    // success claims copied from the DockerLens renderer or an environment flag.
    assert_eq!(source["Id"], source_id);
    assert_eq!(network["Id"], source_network);
    assert_eq!(network["Driver"], "bridge");
    assert_eq!(volume["Name"], source_volume);
    assert_eq!(volume["Driver"], "local");
    assert_eq!(version["ApiVersion"], api_version);
    assert_eq!(version["Version"], required("NATIVE_ENGINE_VERSION"));
    let observed_rootless = info["Rootless"] == true
        || info["SecurityOptions"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item.as_str().is_some_and(|value| {
                    value == "name=rootless" || value.starts_with("name=rootless,")
                })
            })
        });
    eprintln!("DOCKERLENS_NATIVE_CHECK: target_daemon_uid");
    let effective_uid = dockerd_effective_uid();
    if observed_rootless {
        assert!(effective_uid != 0, "rootless dockerd must be unprivileged");
    } else {
        assert!(effective_uid == 0, "rootful dockerd must run as root");
    }
    let lane_mode = required("NATIVE_DAEMON_MODE");
    assert!(
        matches!(lane_mode.as_str(), "rootful" | "rootless"),
        "closed native daemon mode"
    );
    assert_eq!(observed_rootless, lane_mode == "rootless");
    assert_all_interface_binding(&source, "8080/tcp", "18080");
    assert_all_interface_binding(&source, "8081/udp", "18081");
    assert_mount(&source, "volume", "/data", Some(&source_volume), true);
    assert_mount(&source, "bind", "/readonly", None, false);
    assert_eq!(source["HostConfig"]["RestartPolicy"]["Name"], "on-failure");
    assert_eq!(
        source["HostConfig"]["RestartPolicy"]["MaximumRetryCount"],
        3
    );
    assert_eq!(source["Config"]["Entrypoint"], json!(["/bin/sh"]));
    assert_eq!(
        source["Config"]["Healthcheck"]["Test"],
        json!(["CMD-SHELL", "true"])
    );
    let source_env = source["Config"]["Env"].as_array().unwrap();
    assert!(source_env.iter().any(|entry| entry == "EMPTY="));
    assert!(source_env.iter().any(|entry| entry == "QUOTED=a\"b\\c"));
    inner_docker(&["start", &source_id]);
    probe_traffic(&source_id, 18080, 18081);
    let run_id = required("NATIVE_OUTER_CONTAINER")
        .trim_start_matches("dl-native-")
        .to_owned();
    let image = required("NATIVE_FIXTURE_IMAGE");
    let cmd_probe_name = format!("dl-native-cmd-probe-{run_id}");
    let cmd_probe = json!({
        "Image": image.clone(),
        "Cmd": ["sh", "-c", "sleep 30"],
        "Healthcheck": {"Test": ["CMD", "/bin/true"], "Interval": 1_000_000_000_i64,
                        "Timeout": 1_000_000_000_i64, "Retries": 2}
    });
    let (status, created) = api(
        "POST",
        &format!("/v{api_version}/containers/create?name={cmd_probe_name}"),
        Some(&cmd_probe),
    );
    assert_eq!(status, 201);
    let created: Value = serde_json::from_slice(&created).unwrap();
    let cmd_probe_id = created["Id"].as_str().expect("independent health probe ID");
    let (status, inspected) = api(
        "GET",
        &format!("/v{api_version}/containers/{cmd_probe_id}/json"),
        None,
    );
    assert_eq!(status, 200);
    let inspected: Value = serde_json::from_slice(&inspected).unwrap();
    assert_eq!(
        inspected["Config"]["Healthcheck"]["Test"],
        json!(["CMD", "/bin/true"])
    );
    let (status, _) = api(
        "POST",
        &format!("/v{api_version}/containers/{cmd_probe_id}/start"),
        None,
    );
    assert_eq!(status, 204);
    let mut probe_healthy = false;
    for _ in 0..10 {
        let (status, body) = api(
            "GET",
            &format!("/v{api_version}/containers/{cmd_probe_id}/json"),
            None,
        );
        assert_eq!(status, 200);
        let body: Value = serde_json::from_slice(&body).unwrap();
        if body["State"]["Health"]["Status"] == "healthy" {
            probe_healthy = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    assert!(
        probe_healthy,
        "independent exec-form health probe did not pass"
    );

    eprintln!("DOCKERLENS_NATIVE_CHECK: read_only_acquire");
    let capture = acquire(
        &Endpoint::unix_socket(socket),
        Selector::ContainerIds(vec![NativeId::new(source_id).unwrap()]),
        Limits {
            max_requests: 16,
            max_selected_resources: 2,
            max_expansions: 6,
            max_response_bytes: 8 * 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_elapsed: Duration::from_secs(30),
        },
        &AtomicBool::new(false),
    )
    .expect("live bounded read-only acquisition");
    eprintln!("DOCKERLENS_NATIVE_CHECK: read_only_route");
    assert_eq!(capture.route(), CaptureRoute::ExplicitUnixSocket);
    eprintln!("DOCKERLENS_NATIVE_CHECK: read_only_status");
    assert!(
        capture
            .exchanges()
            .iter()
            .all(|exchange| exchange.status().code() == 200)
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: read_only_decode");
    let decoded = decode_capture(&capture).expect("native source inventory");
    eprintln!("DOCKERLENS_NATIVE_CHECK: read_only_daemon");
    assert_eq!(capture.observation_id(), decoded.observation_id);
    let mut facts = decoded.version.daemon;
    assert_eq!(facts.observation_id, capture.observation_id());
    assert_eq!(
        facts.release.as_ref().unwrap().as_str(),
        required("NATIVE_ENGINE_VERSION")
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: read_only_mode");
    if observed_rootless {
        assert_eq!(facts.mode, DaemonMode::Rootless);
    } else {
        assert_ne!(facts.mode, DaemonMode::Rootless);
        // /info may omit Rootless on a rootful daemon. The independent
        // single-process effective UID probe above supplies test-only mode
        // evidence; keep the observed release, API and observation ID intact.
        facts.mode = DaemonMode::Rootful;
    }
    eprintln!("DOCKERLENS_NATIVE_CHECK: read_only_api");
    let observed_api = facts.api_version.expect("observed exact daemon API");
    assert_eq!(
        format!("{}.{}", observed_api.major, observed_api.minor),
        api_version
    );

    let target_network = format!("dl-target-{run_id}-net");
    let target_volume = format!("dl-target-{run_id}-vol");
    let target_container = format!("dl-target-{run_id}-box");
    let service = "httpd -f -p 8080 -h /readonly & nc -u -l -p 8081 > /data/udp-received & wait";
    let intent = TargetIntent::new(vec![
        TargetResource::Network {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(target_network.as_bytes().to_vec()).unwrap(),
        },
        TargetResource::Volume {
            reference: ResourceRef::new(2),
            identity: TargetIdentity::new(target_volume.as_bytes().to_vec()).unwrap(),
        },
        TargetResource::Container(Box::new(ContainerIntent {
            reference: ResourceRef::new(3),
            identity: TargetIdentity::new(target_container.as_bytes().to_vec()).unwrap(),
            image: ImageReference::new(image.as_bytes().to_vec()).unwrap(),
            environment: vec![
                EnvironmentAssignment::new(b"EMPTY".to_vec(), Vec::new()).unwrap(),
                EnvironmentAssignment::new(b"QUOTED".to_vec(), b"a\"b\\c".to_vec()).unwrap(),
            ],
            ports: vec![
                PortBinding {
                    host: NonZeroU16::new(18090).unwrap(),
                    container: NonZeroU16::new(8080).unwrap(),
                    protocol: Protocol::Tcp,
                },
                PortBinding {
                    host: NonZeroU16::new(18091).unwrap(),
                    container: NonZeroU16::new(8081).unwrap(),
                    protocol: Protocol::Udp,
                },
            ],
            mounts: vec![
                Mount::bind(
                    required("NATIVE_BIND_SOURCE").into_bytes(),
                    b"/readonly".to_vec(),
                    true,
                )
                .unwrap(),
                Mount::volume(ResourceRef::new(2), b"/data".to_vec(), false).unwrap(),
            ],
            network: Some(ResourceRef::new(1)),
            entrypoint: Some(vec![argument("/bin/sh")]),
            command: Some(vec![argument("-c"), argument(service)]),
            healthcheck: Some(
                Healthcheck::new(
                    vec![argument("/bin/true")],
                    NonZeroU64::new(1_000_000_000).unwrap(),
                    NonZeroU64::new(1_000_000_000).unwrap(),
                    NonZeroU32::new(2).unwrap(),
                )
                .unwrap(),
            ),
            restart: Some(RestartPolicy::OnFailure { maximum_retries: 3 }),
        })),
    ])
    .unwrap();

    let planner = DockerPlanner;
    let absent = ValidatedCapabilities::new(&facts).expect("observed daemon identity");
    assert!(
        planner.plan(&intent, &absent).is_err(),
        "unknown capability must not plan"
    );

    let scope = CapabilityScope {
        observation_id: capture.observation_id(),
        release: facts.release.clone().unwrap(),
        api_version: observed_api,
        mode: facts.mode,
    };
    facts.capabilities = [
        Capability::StandaloneContainer,
        Capability::NamedVolume,
        Capability::BridgeNetwork,
        Capability::PortPublish,
        Capability::BindMount,
        Capability::EnvironmentAssignment,
        Capability::Command,
        Capability::Entrypoint,
        Capability::Healthcheck,
        Capability::RestartPolicy,
    ]
    .into_iter()
    .map(|capability| CapabilityFact {
        capability,
        state: CapabilityState::Available,
        provenance: FactProvenance::NativeConformance,
        scope: Some(scope.clone()),
    })
    .collect();
    let mut without_port = facts.clone();
    without_port
        .capabilities
        .retain(|fact| fact.capability != Capability::PortPublish);
    let denied = ValidatedCapabilities::new(&without_port).expect("scoped partial native facts");
    assert!(matches!(
        planner.plan(&intent, &denied),
        Err(docker_lens::target::PlanningError::MissingCapability {
            capability: Capability::PortPublish,
            ..
        })
    ));
    let admitted = ValidatedCapabilities::new(&facts).expect("exact observed conformance scope");
    let graph = planner
        .plan(&intent, &admitted)
        .expect("probed shapes plan");
    let artifact = DockerApiRenderer
        .render(&graph)
        .expect("inert native requests");
    assert!(!format!("{artifact:?}").contains("a\"b\\c"));

    let lines: Vec<Value> = artifact
        .bytes()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("rendered JSON record"))
        .collect();
    assert_eq!(lines.len(), 3);
    let expected_paths = [
        format!("/v{api_version}/networks/create"),
        format!("/v{api_version}/volumes/create"),
        format!("/v{api_version}/containers/create?name={target_container}"),
    ];
    let mut target_id = None;
    for (record, expected_path) in lines.iter().zip(expected_paths) {
        assert_eq!(record["method"], "POST");
        assert_eq!(record["path"], expected_path);
        assert_eq!(record.as_object().unwrap().len(), 3);
        let (status, response) = api("POST", &expected_path, Some(&record["body"]));
        assert_eq!(status, 201, "Engine must create the test-only resource");
        let created: Value = serde_json::from_slice(&response).expect("native create response");
        if expected_path.contains("containers/create") {
            target_id = Some(
                created["Id"]
                    .as_str()
                    .expect("created container ID")
                    .to_owned(),
            );
        }
    }
    let target_id = target_id.expect("rendered container created");
    let (status, response) = api(
        "GET",
        &format!("/v{api_version}/networks/{target_network}"),
        None,
    );
    assert_eq!(status, 200);
    let target_network_body: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(target_network_body["Name"], target_network);
    assert_eq!(target_network_body["Driver"], "bridge");
    let (status, response) = api(
        "GET",
        &format!("/v{api_version}/volumes/{target_volume}"),
        None,
    );
    assert_eq!(status, 200);
    let target_volume_body: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(target_volume_body["Name"], target_volume);
    assert_eq!(target_volume_body["Driver"], "local");
    let (status, _) = api(
        "POST",
        &format!("/v{api_version}/containers/{target_id}/start"),
        None,
    );
    assert_eq!(status, 204, "test-only container starts");
    probe_traffic(&target_id, 18090, 18091);
    let (status, response) = api(
        "GET",
        &format!("/v{api_version}/containers/{target_id}/json"),
        None,
    );
    assert_eq!(status, 200);
    let observed: Value = serde_json::from_slice(&response).expect("target inspect JSON");
    assert_eq!(observed["HostConfig"]["NetworkMode"], target_network);
    assert_all_interface_binding(&observed, "8080/tcp", "18090");
    assert_all_interface_binding(&observed, "8081/udp", "18091");
    assert_mount(&observed, "volume", "/data", Some(&target_volume), true);
    assert_mount(&observed, "bind", "/readonly", None, false);
    assert_eq!(
        observed["Config"]["Env"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| *entry == "EMPTY=")
            .count(),
        1
    );
    assert!(
        observed["Config"]["Env"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry == "QUOTED=a\"b\\c")
    );
    assert_eq!(observed["Config"]["Entrypoint"], json!(["/bin/sh"]));
    assert_eq!(observed["Config"]["Cmd"], json!(["-c", service]));
    assert_eq!(
        observed["Config"]["Healthcheck"]["Test"],
        json!(["CMD", "/bin/true"])
    );
    assert_eq!(
        observed["HostConfig"]["RestartPolicy"]["Name"],
        "on-failure"
    );
    assert_eq!(
        observed["HostConfig"]["RestartPolicy"]["MaximumRetryCount"],
        3
    );
    let bind_data = inner_docker(&["exec", &target_id, "cat", "/readonly/index.html"]);
    assert_eq!(bind_data.as_slice(), b"native-tcp-canary\n");
    let mut healthy = false;
    for _ in 0..10 {
        let (status, response) = api(
            "GET",
            &format!("/v{api_version}/containers/{target_id}/json"),
            None,
        );
        assert_eq!(status, 200);
        let current: Value = serde_json::from_slice(&response).unwrap();
        if current["State"]["Health"]["Status"] == "healthy" {
            healthy = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    assert!(
        healthy,
        "rendered exec-form healthcheck must become healthy"
    );
}
