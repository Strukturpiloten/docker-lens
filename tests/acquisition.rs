use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use docker_lens::acquisition::{
    AcquisitionError, Endpoint, LimitError, Limits, NativeId, ReadRequest, Selector, acquire,
};
use docker_lens::decoder::decode_capture;
use docker_lens::evidence::CaptureRoute;
use docker_lens::version::DaemonMode;
use serde_json::Value;

static NEXT_SERVER: AtomicU64 = AtomicU64::new(1);

fn limits() -> Limits {
    Limits {
        max_requests: 12,
        max_selected_resources: 3,
        max_expansions: 5,
        max_response_bytes: 8192,
        max_total_bytes: 32768,
        max_elapsed: Duration::from_secs(2),
    }
}

fn response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn chunked(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{body}\r\n0\r\n\r\n",
        body.len()
    )
    .into_bytes()
}

fn version() -> Vec<u8> {
    response(r#"{"Version":"28.0.0","ApiVersion":"1.50","MinAPIVersion":"1.41"}"#)
}

struct Server {
    directory: PathBuf,
    socket: PathBuf,
    seen: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new(handler: impl Fn(&str) -> Option<Vec<u8>> + Send + 'static) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "docker-lens-acquisition-{}-{}",
            std::process::id(),
            NEXT_SERVER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&directory).unwrap();
        let socket = directory.join("engine.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let seen_thread = Arc::clone(&seen);
        let stop_thread = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                };
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while request.len() < 4096 && !request.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).ok() != Some(1) {
                        break;
                    }
                    request.push(byte[0]);
                }
                let first_line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                seen_thread.lock().unwrap().push(first_line.clone());
                if let Some(bytes) = handler(&first_line) {
                    let _ = stream.write_all(&bytes);
                }
            }
        });
        Self {
            directory,
            socket,
            seen,
            stop,
            thread: Some(thread),
        }
    }

    fn endpoint(&self) -> Endpoint {
        Endpoint::unix_socket(self.socket.clone())
    }

    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = UnixStream::connect(&self.socket);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        fs::remove_file(&self.socket).unwrap();
        fs::remove_dir(&self.directory).unwrap();
    }
}

#[test]
fn bounded_socket_capture_keeps_closed_gets_versions_and_private_values() {
    let server = Server::new(|request| {
        let path = request.split_ascii_whitespace().nth(1)?;
        Some(match path {
            "/version" => version(),
            "/v1.49/info" => response(r#"{"ServerVersion":"28.0.0","Rootless":true}"#),
            "/v1.49/containers/json?all=1" => response(r#"[{"Id":"private/container"}]"#),
            "/v1.49/containers/private%2Fcontainer/json" => response(
                r#"{"Config":{"Env":["TOKEN=private-secret"]},"NetworkSettings":{"Networks":{"private-net":{"NetworkID":"net/id"}}},"Mounts":[{"Type":"volume","Name":"private-volume"}]}"#,
            ),
            "/v1.49/networks/net%2Fid" => response(r#"{"Name":"private-net","Driver":"bridge"}"#),
            "/v1.49/volumes/private-volume" => {
                response(r#"{"Name":"private-volume","Driver":"local"}"#)
            }
            _ => return None,
        })
    });
    let capture = acquire(
        &server.endpoint(),
        Selector::AllContainers,
        limits(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(capture.route(), CaptureRoute::ExplicitUnixSocket);
    assert_eq!(capture.bounds().request_count, 6);
    assert_eq!(capture.bounds().selected_resources, 1);
    assert_eq!(capture.bounds().expansions, 3);
    assert_eq!(capture.exchanges()[0].api_version(), None);
    assert!(
        capture.exchanges()[1..]
            .iter()
            .all(|exchange| exchange.api_version().unwrap().minor == 49)
    );
    assert_eq!(decode_capture(&capture).unwrap().containers.len(), 1);
    assert!(!format!("{capture:?}").contains("private-secret"));
    assert!(!format!("{capture:?}").contains("private/container"));
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    assert!(
        requests
            .iter()
            .any(|request| request.contains("private%2Fcontainer"))
    );
}

#[test]
fn explicit_selection_never_discovers_ambient_containers() {
    let server = Server::new(|request| {
        let path = request.split_ascii_whitespace().nth(1)?;
        Some(match path {
            "/version" => version(),
            "/v1.49/info" => response("{}"),
            "/v1.49/containers/selected/json" => response("{}"),
            _ => return None,
        })
    });
    let capture = acquire(
        &server.endpoint(),
        Selector::ContainerIds(vec![NativeId::new("selected".into()).unwrap()]),
        limits(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(capture.bounds().request_count, 3);
    assert!(
        server
            .requests()
            .iter()
            .all(|request| !request.contains("containers/json"))
    );
}

#[test]
fn cancelled_timeout_malformed_and_exhausted_runs_yield_no_capture() {
    let server = Server::new(|request| {
        let path = request.split_ascii_whitespace().nth(1)?;
        Some(match path {
            "/version" => version(),
            "/v1.49/info" => response("{}"),
            "/v1.49/containers/json?all=1" => response(r#"[{"Id":"a"},{"Id":"b"}]"#),
            _ => response("{}"),
        })
    });
    let cancelled = AtomicBool::new(true);
    assert!(matches!(
        acquire(
            &server.endpoint(),
            Selector::AllContainers,
            limits(),
            &cancelled
        ),
        Err(AcquisitionError::Cancelled)
    ));
    assert!(server.requests().is_empty());

    let mut short = limits();
    short.max_requests = 2;
    assert!(matches!(
        acquire(
            &server.endpoint(),
            Selector::AllContainers,
            short,
            &AtomicBool::new(false)
        ),
        Err(AcquisitionError::Budget(LimitError::Requests))
    ));

    let malformed =
        Server::new(|_| Some(b"HTTP/1.1 200 OK\r\nContent-Length: bad\r\n\r\n".to_vec()));
    assert!(matches!(
        acquire(
            &malformed.endpoint(),
            Selector::AllContainers,
            limits(),
            &AtomicBool::new(false)
        ),
        Err(AcquisitionError::Protocol)
    ));

    let stalled = Server::new(|_| {
        thread::sleep(Duration::from_millis(250));
        None
    });
    let mut short = limits();
    short.max_elapsed = Duration::from_millis(40);
    assert!(matches!(
        acquire(
            &stalled.endpoint(),
            Selector::AllContainers,
            short,
            &AtomicBool::new(false)
        ),
        Err(AcquisitionError::Deadline)
    ));
}

#[test]
fn unsupported_api_range_and_oversized_body_fail_closed() {
    let too_new =
        Server::new(|_| Some(response(r#"{"ApiVersion":"1.50","MinAPIVersion":"1.50"}"#)));
    assert!(matches!(
        acquire(
            &too_new.endpoint(),
            Selector::AllContainers,
            limits(),
            &AtomicBool::new(false)
        ),
        Err(AcquisitionError::Version)
    ));

    let oversized = Server::new(|_| Some(response(&"x".repeat(200))));
    let mut tiny = limits();
    tiny.max_response_bytes = 100;
    assert!(matches!(
        acquire(
            &oversized.endpoint(),
            Selector::AllContainers,
            tiny,
            &AtomicBool::new(false)
        ),
        Err(AcquisitionError::Budget(LimitError::Bytes))
    ));
}

#[test]
fn chunked_replay_and_mid_read_cancellation_are_bounded() {
    let chunked_server = Server::new(|request| {
        let path = request.split_ascii_whitespace().nth(1)?;
        Some(match path {
            "/version" => chunked(r#"{"Version":"20.10.5","ApiVersion":"1.41"}"#),
            "/v1.41/info" => response("{}"),
            _ => return None,
        })
    });
    let capture = acquire(
        &chunked_server.endpoint(),
        Selector::ContainerIds(vec![]),
        limits(),
        &AtomicBool::new(false),
    )
    .unwrap();
    let first = decode_capture(&capture).unwrap();
    let replayed = decode_capture(&capture).unwrap();
    assert_eq!(
        first.version.daemon.api_version,
        replayed.version.daemon.api_version
    );
    assert_eq!(capture.exchanges()[1].api_version().unwrap().minor, 41);

    let stalled = Server::new(|_| {
        thread::sleep(Duration::from_millis(300));
        None
    });
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancelled);
    let trigger = thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        signal.store(true, Ordering::Relaxed);
    });
    let result = acquire(
        &stalled.endpoint(),
        Selector::AllContainers,
        limits(),
        &cancelled,
    );
    trigger.join().unwrap();
    assert!(matches!(result, Err(AcquisitionError::Cancelled)));
}

#[test]
fn malformed_chunk_delimiters_and_trailers_cannot_complete_a_capture() {
    let bad_delimiter = Server::new(|_| {
        Some(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab\r\n0\r\n\r\n".to_vec())
    });
    assert!(matches!(
        acquire(
            &bad_delimiter.endpoint(),
            Selector::AllContainers,
            limits(),
            &AtomicBool::new(false)
        ),
        Err(AcquisitionError::Protocol)
    ));

    let bad_trailer = Server::new(|_| {
        Some(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nnot-a-header\r\n\r\n"
                .to_vec(),
        )
    });
    assert!(matches!(
        acquire(
            &bad_trailer.endpoint(),
            Selector::AllContainers,
            limits(),
            &AtomicBool::new(false)
        ),
        Err(AcquisitionError::Protocol)
    ));
}

#[test]
fn duplicate_related_native_ids_consume_one_expansion_each() {
    let server = Server::new(|request| {
        let path = request.split_ascii_whitespace().nth(1)?;
        Some(match path {
            "/version" => version(),
            "/v1.49/info" => response("{}"),
            "/v1.49/containers/selected/json" => response(
                r#"{"NetworkSettings":{"Networks":{"first":{"NetworkID":"same-net"},"second":{"NetworkID":"same-net"}}},"Mounts":[{"Type":"volume","Name":"same-volume"},{"Type":"volume","Name":"same-volume"}]}"#,
            ),
            "/v1.49/networks/same-net" | "/v1.49/volumes/same-volume" => response("{}"),
            _ => return None,
        })
    });
    let mut exact = limits();
    exact.max_expansions = 3;
    let capture = acquire(
        &server.endpoint(),
        Selector::ContainerIds(vec![NativeId::new("selected".into()).unwrap()]),
        exact,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(capture.bounds().expansions, 3);
    assert_eq!(capture.bounds().request_count, 5);
    assert_eq!(server.requests().len(), 5);
}

/// The native harness supplies a private isolated Engine socket and independent
/// direct-API observations. Fake-socket tests above do not replace this check.
#[test]
#[ignore = "requires the isolated native Engine harness"]
fn live_read_only_acquisition_matches_oracle() {
    let required = |name| std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"));
    let socket = required("NATIVE_ENGINE_SOCKET");
    let capture_dir = required("NATIVE_CAPTURE_DIR");
    let container_id = required("NATIVE_CONTAINER_ID");
    let network_id = required("NATIVE_NETWORK_ID");
    let volume_name = required("NATIVE_VOLUME_NAME");
    let engine_version = required("NATIVE_ENGINE_VERSION");
    let daemon_mode = required("NATIVE_DAEMON_MODE");
    let api_version = required("NATIVE_API_VERSION");
    let capture_dir = PathBuf::from(capture_dir);
    assert!(capture_dir.is_dir());
    let oracle = |name: &str| -> Value {
        serde_json::from_slice(&fs::read(capture_dir.join(name)).unwrap()).unwrap()
    };
    let oracle_version = oracle("version.json");
    let oracle_info = oracle("info.json");
    let oracle_container = oracle("container.json");
    let oracle_network = oracle("network.json");
    let oracle_volume = oracle("volume.json");
    assert!(oracle_version.get("Version").and_then(Value::as_str) == Some(engine_version.as_str()));
    assert!(oracle_container.get("Id").and_then(Value::as_str) == Some(container_id.as_str()));
    assert!(oracle_network.get("Id").and_then(Value::as_str) == Some(network_id.as_str()));
    assert!(oracle_volume.get("Name").and_then(Value::as_str) == Some(volume_name.as_str()));
    assert!(oracle_info.is_object());
    let (major, minor) = api_version.split_once('.').expect("two-part API version");
    assert_eq!(major, "1");
    let expected_minor = minor.parse::<u16>().unwrap().min(49);
    let mut native_limits = limits();
    native_limits.max_requests = 8;
    native_limits.max_selected_resources = 1;
    native_limits.max_expansions = 4;
    native_limits.max_response_bytes = 8 * 1024 * 1024;
    native_limits.max_total_bytes = 32 * 1024 * 1024;
    native_limits.max_elapsed = Duration::from_secs(20);
    let capture = acquire(
        &Endpoint::unix_socket(PathBuf::from(socket)),
        Selector::ContainerIds(vec![NativeId::new(container_id.clone()).unwrap()]),
        native_limits,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(capture.route(), CaptureRoute::ExplicitUnixSocket);
    assert_eq!(capture.bounds().selected_resources, 1);
    assert_eq!(capture.bounds().expansions, 3);
    assert!(
        capture
            .exchanges()
            .iter()
            .all(|exchange| exchange.status().code() == 200)
    );
    assert!(capture.exchanges().iter().any(|exchange| {
        matches!(exchange.request(), ReadRequest::InspectNetwork(id) if id.as_str() == network_id)
    }));
    assert!(capture.exchanges().iter().any(|exchange| {
        matches!(exchange.request(), ReadRequest::InspectVolume(id) if id.as_str() == volume_name)
    }));
    assert!(
        capture.exchanges()[1..]
            .iter()
            .all(|exchange| exchange.api_version().unwrap().minor == expected_minor)
    );
    let decoded = decode_capture(&capture).unwrap();
    assert_eq!(decoded.containers.len(), 1);
    assert_eq!(decoded.networks.len(), 1);
    assert_eq!(decoded.volumes.len(), 1);
    assert!(decoded.version.daemon.release.as_ref().unwrap().as_str() == engine_version);
    if daemon_mode == "rootless" {
        assert_eq!(decoded.version.daemon.mode, DaemonMode::Rootless);
    } else {
        assert_eq!(daemon_mode, "rootful");
        assert_ne!(decoded.version.daemon.mode, DaemonMode::Rootless);
    }
    let container = &decoded.containers[0];
    let oracle_env = oracle_container["Config"]["Env"].as_array().unwrap();
    let synthetic = oracle_env
        .iter()
        .filter_map(Value::as_str)
        .find(|entry| entry.starts_with("DL_CONFORMANCE="))
        .unwrap();
    let (_, expected_value) = synthetic.split_once('=').unwrap();
    assert!(
        container
            .environment
            .value()
            .unwrap()
            .iter()
            .any(|assignment| {
                assignment.name.as_bytes() == b"DL_CONFORMANCE"
                    && assignment
                        .value
                        .as_ref()
                        .is_some_and(|value| value.as_bytes() == expected_value.as_bytes())
            })
    );
    assert!(oracle_container["HostConfig"]["PortBindings"]["8080/tcp"].is_array());
    assert!(
        container
            .configured_ports
            .value()
            .unwrap()
            .iter()
            .any(|port| {
                port.key.container_port == 8080
                    && port.bindings.value().is_some_and(|bindings| {
                        bindings
                            .iter()
                            .any(|binding| binding.host_port.value() == Some(&18080))
                    })
            })
    );
    assert!(container.mounts.value().unwrap().iter().any(|mount| {
        mount
            .name
            .value()
            .is_some_and(|name| name.as_bytes() == volume_name.as_bytes())
            && mount
                .destination
                .value()
                .is_some_and(|path| path.as_bytes() == b"/data")
    }));
    assert!(decoded.networks[0].name.value().is_some_and(|name| {
        oracle_network["Name"]
            .as_str()
            .is_some_and(|expected| name.as_bytes() == expected.as_bytes())
    }));
    assert!(decoded.volumes[0].driver.value().is_some_and(|driver| {
        oracle_volume["Driver"]
            .as_str()
            .is_some_and(|expected| driver.as_bytes() == expected.as_bytes())
    }));
    let replayed = decode_capture(&capture).unwrap();
    assert_eq!(replayed.containers.len(), decoded.containers.len());
}
