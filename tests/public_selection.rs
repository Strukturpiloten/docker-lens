//! Public selection contract using a bounded fake Unix Engine.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use docker_lens::acquisition::{
    AcquisitionError, Endpoint, LimitError, Limits, ReadRequest, RootKind, SelectionReason,
    Selector, acquire,
};
use docker_lens::decoder::decode_capture;
use docker_lens::evidence::ProtectedValue;
use docker_lens::observation::{Availability, Origin};

const SELECTED_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SELECTED_B: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const PEER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROJECT: &str = "private-project-canary";
static NEXT_SOCKET: AtomicU64 = AtomicU64::new(1);

struct FakeEngine {
    directory: PathBuf,
    socket: PathBuf,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl FakeEngine {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "docker-lens-selection-{}-{}-{}",
            std::process::id(),
            NEXT_SOCKET.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let socket = directory.join("engine.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&requests);
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
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
                let line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                observed.lock().unwrap().push(line.clone());
                let path = line.split_ascii_whitespace().nth(1).unwrap_or_default();
                let body = match path {
                    "/version" => {
                        r#"{"Version":"28.0.0","ApiVersion":"1.50","MinAPIVersion":"1.41"}"#
                    }
                    "/v1.49/info" => "{}",
                    "/v1.49/containers/json?all=1" => concat!(
                        "[{\"Id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
                        "\"Names\":[\"/app\"],\"Labels\":{\"com.docker.compose.project\":\"private-project-canary\"}},",
                        "{\"Id\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",",
                        "\"Names\":[\"/app-worker\"],\"Labels\":{\"com.docker.compose.project\":\"private-project-canary\"}},",
                        "{\"Id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
                        "\"Names\":[\"/peer\"],\"Labels\":{\"com.docker.compose.project\":\"other-project\"}}]"
                    ),
                    "/v1.49/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/json" =>
                    {
                        concat!(
                            "{\"Id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
                            "\"Name\":\"/app\",\"Config\":{\"Labels\":{\"com.docker.compose.project\":\"private-project-canary\"}}}"
                        )
                    }
                    "/v1.49/containers/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/json" =>
                    {
                        concat!(
                            "{\"Id\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",",
                            "\"Name\":\"/app-worker\",\"Config\":{\"Labels\":{\"com.docker.compose.project\":\"private-project-canary\"}}}"
                        )
                    }
                    _ => continue,
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        Self {
            directory,
            socket,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn endpoint(&self) -> Endpoint {
        Endpoint::unix_socket(self.socket.clone())
    }
}

impl Drop for FakeEngine {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = UnixStream::connect(&self.socket);
        self.worker.take().unwrap().join().unwrap();
        fs::remove_file(&self.socket).unwrap();
        fs::remove_dir(&self.directory).unwrap();
    }
}

fn project_selector() -> Selector {
    Selector::Label {
        key: ProtectedValue::new(b"com.docker.compose.project".to_vec()),
        value: Some(ProtectedValue::new(PROJECT.as_bytes().to_vec())),
    }
}

fn limits() -> Limits {
    Limits {
        max_requests: 5,
        max_selected_resources: 2,
        max_expansions: 2,
        max_response_bytes: 4096,
        max_total_bytes: 8192,
        max_elapsed: Duration::from_secs(2),
    }
}

#[test]
fn project_label_selects_both_members_without_claiming_authorship_or_inspecting_peer() {
    let server = FakeEngine::new();
    let selector = project_selector();
    assert_eq!(format!("{selector:?}"), "Label");
    let capture = acquire(
        &server.endpoint(),
        selector,
        limits(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(capture.bounds().request_count, 5);
    assert_eq!(capture.bounds().selected_resources, 2);
    assert_eq!(capture.selected_roots().len(), 2);
    assert!(
        capture.selected_roots().iter().all(|root| {
            root.kind == RootKind::Container && root.reason == SelectionReason::Label
        })
    );
    let inspected: Vec<_> = capture
        .exchanges()
        .iter()
        .filter_map(|exchange| match exchange.request() {
            ReadRequest::InspectContainer(id) => Some(id.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(inspected, [SELECTED_A, SELECTED_B]);

    let inventory = decode_capture(&capture).unwrap();
    assert_eq!(inventory.containers.len(), 2);
    assert_eq!(inventory.discovered_containers.len(), 3);
    for (index, expected_id) in [SELECTED_A, SELECTED_B].iter().enumerate() {
        let container = &inventory.containers[index];
        assert_eq!(
            inventory.selected_roots[index].resource,
            container.reference
        );
        assert_eq!(
            container.id.value().unwrap().as_bytes(),
            expected_id.as_bytes()
        );
        assert_eq!(container.labels.origin, Origin::Effective);
        assert_eq!(container.labels.availability, Availability::Present);
        let labels = container.labels.value().unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].key.as_bytes(), b"com.docker.compose.project");
        assert_eq!(labels[0].value.origin, Origin::Effective);
        assert_eq!(
            labels[0].value.value().unwrap().as_bytes(),
            PROJECT.as_bytes()
        );
    }
    // An effective Compose-style label is advisory metadata; it is not authored-intent evidence.
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    assert!(requests.iter().all(|request| !request.contains(PEER)));
    assert!(!format!("{capture:?}{inventory:?}").contains(PROJECT));
    assert!(!format!("{capture:?}{inventory:?}").contains(PEER));
}

#[test]
fn project_label_exceeding_selection_budget_never_inspects_a_container() {
    let server = FakeEngine::new();
    let constrained = Limits {
        max_selected_resources: 1,
        ..limits()
    };
    let error = acquire(
        &server.endpoint(),
        project_selector(),
        constrained,
        &AtomicBool::new(false),
    )
    .expect_err("two project members exceed the one-resource budget");
    assert_eq!(
        error,
        AcquisitionError::Budget(LimitError::SelectedResources)
    );
    assert!(!format!("{error:?}").contains(PROJECT));
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|request| {
        !request.contains(SELECTED_A) && !request.contains(SELECTED_B) && !request.contains(PEER)
    }));
}
