//! Linux transport controls, not Engine compatibility or peer authentication.
#![cfg(target_os = "linux")]

use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use docker_lens::acquisition::{
    AcquisitionError, Endpoint, Limits, ReadRequest, Selector, acquire,
};
use docker_lens::evidence::Capture;
use socket2::{Domain, SockAddr, Socket, Type};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const WATCHDOG: Duration = Duration::from_secs(2);

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity(u64, u64, u32);

fn identity(metadata: &fs::Metadata) -> Identity {
    Identity(metadata.dev(), metadata.ino(), metadata.uid())
}

struct Fixture {
    directory: PathBuf,
    directory_identity: Identity,
    path: PathBuf,
    socket_identity: Option<Identity>,
    listener: Option<UnixListener>,
    queued: Vec<Socket>,
    workers: Vec<JoinHandle<()>>,
    cancellations: Vec<Arc<AtomicBool>>,
    server_start: Option<mpsc::Sender<()>>,
    stop: Arc<AtomicBool>,
    cleaned: bool,
}

impl Fixture {
    fn new(listen: bool) -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| failure("fixture clock unavailable"))?
            .as_nanos();
        let directory = PathBuf::from("/tmp").join(format!(
            "docker-lens-backlog-{}-{}-{nonce}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let directory_identity = identity(&fs::symlink_metadata(&directory)?);
        let mut fixture = Self {
            path: directory.join("private-engine.sock"),
            directory,
            directory_identity,
            socket_identity: None,
            listener: None,
            queued: Vec::new(),
            workers: Vec::new(),
            cancellations: Vec::new(),
            server_start: None,
            stop: Arc::new(AtomicBool::new(false)),
            cleaned: false,
        };
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.bind(&SockAddr::unix(&fixture.path)?)?;
        fixture.socket_identity = Some(identity(&fs::symlink_metadata(&fixture.path)?));
        if listen {
            socket.listen(1)?;
        }
        socket.set_nonblocking(true)?;
        let descriptor: std::os::fd::OwnedFd = socket.into();
        fixture.listener = Some(UnixListener::from(descriptor));
        Ok(fixture)
    }

    fn saturate(&mut self) -> io::Result<()> {
        // Admit and retain real filler connections, stopping at the FIRST
        // refused nonblocking admission. Never mimic the production retry loop.
        let address = SockAddr::unix(&self.path)?;
        for _ in 0..16 {
            let client = Socket::new(Domain::UNIX, Type::STREAM, None)?;
            client.set_nonblocking(true)?;
            match client.connect(&address) {
                Ok(()) => {
                    client.peer_addr()?;
                    self.queued.push(client);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if self.queued.is_empty() {
                        return Err(failure("queue filled without an admitted connection"));
                    }
                    return self.prove_full();
                }
                Err(_) => return Err(failure("queue filler failed unexpectedly")),
            }
        }
        Err(failure("queue saturation exceeded fixture safety bound"))
    }

    fn prove_full(&self) -> io::Result<()> {
        // Separate fresh-descriptor observation proves that listen(1) alone
        // was not mistaken for a full queue. No accept thread is running yet.
        let client = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        client.set_nonblocking(true)?;
        match client.connect(&SockAddr::unix(&self.path)?) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            _ => Err(failure("independent full-queue admission proof failed")),
        }
    }

    fn run(
        &mut self,
        limit: Duration,
        cancelled: Arc<AtomicBool>,
        cancel_after: Option<Duration>,
    ) -> io::Result<(Result<Capture, AcquisitionError>, Duration)> {
        let endpoint = Endpoint::unix_socket(self.path.clone());
        let token = Arc::clone(&cancelled);
        self.cancellations.push(Arc::clone(&cancelled));
        let server_start = self.server_start.take();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        self.workers.push(thread::spawn(move || {
            let limits = Limits {
                max_requests: 4,
                max_selected_resources: 1,
                max_expansions: 1,
                max_response_bytes: 1024,
                max_total_bytes: 4096,
                max_elapsed: limit,
            };
            let started = Instant::now();
            let _ = ready_tx.send(());
            if let Some(server_start) = server_start {
                let _ = server_start.send(());
            }
            let result = acquire(
                &endpoint,
                Selector::ContainerIds(Vec::new()),
                limits,
                &token,
            );
            let _ = result_tx.send((result, started.elapsed()));
        }));
        if let Some(delay) = cancel_after {
            self.workers.push(thread::spawn(move || {
                if ready_rx.recv_timeout(WATCHDOG).is_ok() {
                    thread::sleep(delay);
                    cancelled.store(true, Ordering::Relaxed);
                }
            }));
        }
        result_rx
            .recv_timeout(WATCHDOG)
            .map_err(|_| failure("acquisition exceeded independent watchdog"))
    }

    fn serve_after(&mut self, delay: Duration) -> io::Result<mpsc::Receiver<io::Result<()>>> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| failure("fixture listener absent"))?
            .try_clone()?;
        let queued_count = self.queued.len();
        let stop = Arc::clone(&self.stop);
        let (start_tx, start_rx) = mpsc::channel();
        self.server_start = Some(start_tx);
        let (completed_tx, completed_rx) = mpsc::channel();
        self.workers.push(thread::spawn(move || {
            let result = match start_rx.recv_timeout(WATCHDOG) {
                Ok(()) => serve(listener, queued_count, delay, &stop),
                Err(_) => Err(failure("fixture acquisition-start notification missing")),
            };
            let _ = completed_tx.send(result);
        }));
        Ok(completed_rx)
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        self.stop.store(true, Ordering::Relaxed);
        for token in &self.cancellations {
            token.store(true, Ordering::Relaxed);
        }
        drop(self.listener.take());
        drop(self.server_start.take());
        self.queued.clear();
        let deadline = Instant::now() + WATCHDOG;
        while self.workers.iter().any(|worker| !worker.is_finished()) {
            if Instant::now() >= deadline {
                // Preserve the exact private path if an owned thread survives.
                return Err(failure("fixture worker termination unverified"));
            }
            thread::sleep(Duration::from_millis(1));
        }
        let mut panicked = false;
        for worker in self.workers.drain(..) {
            // Positively finished threads only: no unbounded failure-path join.
            panicked |= worker.join().is_err();
        }
        let directory = fs::symlink_metadata(&self.directory)?;
        if !directory.is_dir() || identity(&directory) != self.directory_identity {
            return Err(failure("fixture directory ownership changed"));
        }
        match fs::symlink_metadata(&self.path) {
            Ok(node) => {
                use std::os::unix::fs::FileTypeExt;
                if !node.file_type().is_socket() || Some(identity(&node)) != self.socket_identity {
                    return Err(failure("fixture socket ownership changed"));
                }
                fs::remove_file(&self.path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // Nonrecursive exact removal refuses unrelated/replaced contents.
        fs::remove_dir(&self.directory)?;
        self.cleaned = true;
        if panicked {
            return Err(failure("fixture worker panicked"));
        }
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.cleanup().is_err() {
            if thread::panicking() {
                eprintln!("fixture cleanup unverified while unwinding");
            } else {
                panic!("fixture cleanup unverified");
            }
        }
    }
}

fn serve(
    listener: UnixListener,
    queued: usize,
    delay: Duration,
    stop: &AtomicBool,
) -> io::Result<()> {
    let deadline = Instant::now() + WATCHDOG;
    thread::sleep(delay);
    // Discard only the counted fixture filler connections before HTTP service.
    for _ in 0..queued {
        drop(accept(&listener, deadline, stop)?);
    }
    for (path, body) in [
        (
            "/version",
            r#"{"Version":"28.0.0","ApiVersion":"1.49","MinAPIVersion":"1.41"}"#,
        ),
        ("/v1.49/info", "{}"),
    ] {
        let mut stream = accept(&listener, deadline, stop)?;
        stream.set_nonblocking(true)?;
        let mut request = Vec::new();
        let mut byte = [0];
        while request.len() < 1024 && !request.ends_with(b"\r\n\r\n") {
            check_fixture_deadline(deadline, stop)?;
            match stream.read(&mut byte) {
                Ok(1) => request.push(byte[0]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                _ => return Err(failure("fixture request framing failed")),
            }
        }
        let expected = format!(
            "GET {path} HTTP/1.1\r\nHost: docker\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        if request != expected.as_bytes() {
            return Err(failure("fixture observed unexpected HTTP request"));
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut bytes = response.as_bytes();
        while !bytes.is_empty() {
            check_fixture_deadline(deadline, stop)?;
            match stream.write(bytes) {
                Ok(0) => return Err(failure("fixture response made no progress")),
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                _ => return Err(failure("fixture response failed")),
            }
        }
    }
    Ok(())
}

fn check_fixture_deadline(deadline: Instant, stop: &AtomicBool) -> io::Result<()> {
    if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
        return Err(failure("fixture stopped or exceeded deadline"));
    }
    Ok(())
}

fn accept(
    listener: &UnixListener,
    deadline: Instant,
    stop: &AtomicBool,
) -> io::Result<std::os::unix::net::UnixStream> {
    loop {
        check_fixture_deadline(deadline, stop)?;
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(_) => return Err(failure("fixture accept failed")),
        }
    }
}

fn check_private_error(error: AcquisitionError, fixture: &Fixture) {
    let text = format!("{error:?}");
    assert!(!text.contains("private-engine"));
    assert!(!text.contains(fixture.directory.to_string_lossy().as_ref()));
}

#[test]
fn full_queue_expires_at_short_deadline_without_capture() -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new(true)?;
    fixture.saturate()?;
    let limit = Duration::from_millis(80);
    let (result, elapsed) = fixture.run(limit, Arc::new(AtomicBool::new(false)), None)?;
    let error = result
        .err()
        .ok_or_else(|| failure("full queue yielded a capture"))?;
    assert_eq!(error, AcquisitionError::Deadline);
    assert!(elapsed >= limit);
    assert!(elapsed < limit + Duration::from_millis(500));
    check_private_error(error, &fixture);
    fixture.prove_full()?;
    fixture.cleanup()?;
    Ok(())
}

#[test]
fn full_queue_pending_and_pre_cancelled_reads_return_cancelled() -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new(true)?;
    fixture.saturate()?;
    for (pre_cancelled, cancel_after) in [(true, None), (false, Some(Duration::from_millis(25)))] {
        fixture.prove_full()?;
        let token = Arc::new(AtomicBool::new(pre_cancelled));
        let (result, elapsed) = fixture.run(Duration::from_secs(5), token, cancel_after)?;
        let error = result
            .err()
            .ok_or_else(|| failure("cancelled queue yielded a capture"))?;
        assert_eq!(error, AcquisitionError::Cancelled);
        assert!(elapsed < Duration::from_millis(500));
        check_private_error(error, &fixture);
    }
    fixture.cleanup()?;
    Ok(())
}

#[test]
fn bound_unlistened_socket_remains_terminal_io_error() -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new(false)?;
    let (result, elapsed) = fixture.run(
        Duration::from_secs(1),
        Arc::new(AtomicBool::new(false)),
        None,
    )?;
    let error = result
        .err()
        .ok_or_else(|| failure("unlistened socket yielded a capture"))?;
    assert_eq!(error, AcquisitionError::Io);
    assert!(elapsed < Duration::from_millis(500));
    check_private_error(error, &fixture);
    fixture.cleanup()?;
    Ok(())
}

#[test]
fn successful_connects_and_delayed_full_queue_drain_preserve_http_capture()
-> Result<(), Box<dyn Error>> {
    for delayed in [false, true] {
        let mut fixture = Fixture::new(true)?;
        let delay = if delayed {
            fixture.saturate()?;
            fixture.prove_full()?;
            Duration::from_millis(60)
        } else {
            Duration::ZERO
        };
        let server = fixture.serve_after(delay)?;
        let (result, elapsed) = fixture.run(WATCHDOG, Arc::new(AtomicBool::new(false)), None)?;
        let capture = result.map_err(|_| failure("serviced socket acquisition failed"))?;
        assert_eq!(capture.exchanges().len(), 2);
        assert!(matches!(
            capture.exchanges()[0].request(),
            ReadRequest::DaemonVersion
        ));
        assert!(matches!(
            capture.exchanges()[1].request(),
            ReadRequest::DaemonInfo
        ));
        assert!(elapsed >= delay);
        assert!(elapsed < WATCHDOG);
        server
            .recv_timeout(WATCHDOG)
            .map_err(|_| failure("HTTP fixture completion unverified"))??;
        fixture.cleanup()?;
    }
    Ok(())
}
