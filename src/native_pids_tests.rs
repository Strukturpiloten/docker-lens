//! Test-only original-owner PIDs experiment. No product executor or capability grant.

use super::*;
use crate::target::{Mount, PidsLimit};
use crate::version::{EngineRelease, ObservationId};
use rustix::net::{
    RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendAncillaryBuffer, SendAncillaryMessage,
    SendFlags, recvmsg, sendmsg,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, ChildStdin, ChildStdout};

const VERSION: u64 = 1;
const FRAME: usize = 16 * 1024;
const HELPER_CAPTURE: usize = 64 * 1024;
const SLOTS: [&str; 6] = [
    "cli16",
    "cli64",
    "cli_unlimited",
    "rendered16",
    "rendered64",
    "rendered_unlimited",
];
const LABEL: &str = "io.dockerlens.native-pids";
const SLOT_LABEL: &str = "io.dockerlens.native-pids-slot";

type PidsResult<T> = Result<T, &'static str>;

fn pids_constructor_refusal_registry_valid(registry: &str) -> bool {
    if !registry.ends_with('\n')
        || registry.len() > 32 * 22
        || !registry
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'-' | b'\n'))
    {
        return false;
    }
    let mut count = 0;
    let mut previous = "";
    for code in registry.lines() {
        if count == 32
            || code.len() > 21
            || code <= previous
            || !code
                .strip_prefix("pids-")
                .is_some_and(|suffix| suffix.split('-').all(|part| !part.is_empty()))
        {
            return false;
        }
        count += 1;
        previous = code;
    }
    count == 32
}

fn pids_constructor_refusal_code(error: &str) -> &'static str {
    // One packaged registry supplies both producer and failure-only projection.
    // Return only a registry-borrowed static slice, never the supplied error.
    // Every unknown value, including a new pids-* string, has the same fallback.
    let registry = include_str!("native_pids_setup_refusals.txt");
    if !pids_constructor_refusal_registry_valid(registry) {
        return "unclassified";
    }
    registry
        .lines()
        .find(|code| *code == error)
        .unwrap_or("unclassified")
}

fn pids_constructor_refusal_diagnostic(error: &str) -> String {
    format!(
        "DOCKERLENS_NATIVE_PIDS_SETUP_REFUSAL: code={}",
        pids_constructor_refusal_code(error)
    )
}

fn pids_constructor_refused(error: &str) -> ! {
    eprintln!("{}", pids_constructor_refusal_diagnostic(error));
    panic!("private native PIDs setup refused");
}

fn closed(value: &Value, fields: &[&str]) -> PidsResult<()> {
    let object = value.as_object().ok_or("pids-schema")?;
    if object.len() != fields.len() || fields.iter().any(|name| !object.contains_key(*name)) {
        return Err("pids-schema");
    }
    Ok(())
}

// serde_json::Value accepts duplicate keys. Refuse them at every object depth
// before using a protocol value, including objects nested in source samples.
struct UniqueValue(Value);
impl<'de> serde::Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("a bounded JSON value with unique object members")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(json!(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(json!(value)))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(json!(value)))
            }
            fn visit_f64<E: serde::de::Error>(self, _value: f64) -> Result<Self::Value, E> {
                Err(E::custom("integer protocol only"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(json!(value)))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate member"));
                    }
                    let UniqueValue(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn unique_json(bytes: &[u8]) -> PidsResult<Value> {
    serde_json::from_slice::<UniqueValue>(bytes)
        .map(|value| value.0)
        .map_err(|_| "pids-json")
}

fn monotonic_ns() -> PidsResult<u64> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(SECOND))
        .and_then(|seconds| {
            u64::try_from(now.tv_nsec)
                .ok()
                .and_then(|fraction| seconds.checked_add(fraction))
        })
        .ok_or("pids-clock")
}

fn reserve(run: &HealthRun, units: usize, bytes: usize, cleanup: bool) -> PidsResult<()> {
    let calls = run.calls.get().checked_add(units).ok_or("pids-budget")?;
    let captured = run.bytes.get().checked_add(bytes).ok_or("pids-budget")?;
    let (max_calls, max_bytes, reserve) = if cleanup {
        (MAX_CALLS, MAX_BYTES, 1)
    } else {
        (MAX_CALLS - CLEANUP_CALLS, MAX_BYTES - CLEANUP_BYTES, 46)
    };
    if calls > max_calls || captured > max_bytes || run.remaining() <= Duration::from_secs(reserve)
    {
        return Err("pids-budget");
    }
    // Debit before the operation. A failed operation never refunds a reservation.
    run.calls.set(calls);
    run.bytes.set(captured);
    Ok(())
}

struct RootWire {
    stream: UnixStream,
    work: Instant,
    terminal: Instant,
    cleanup: bool,
    captured: usize,
    sent: usize,
    received: usize,
    last_frame: usize,
    sequence: u64,
    frames: usize,
}

impl RootWire {
    fn new(stream: UnixStream, terminal: Instant) -> PidsResult<Self> {
        stream.set_nonblocking(true).map_err(|_| "pids-socket")?;
        let work = terminal
            .checked_sub(Duration::from_secs(46))
            .ok_or("pids-deadline")?;
        if Instant::now() >= work {
            return Err("pids-deadline");
        }
        Ok(Self {
            stream,
            work,
            terminal,
            cleanup: false,
            captured: 0,
            sent: 0,
            received: 0,
            last_frame: 0,
            sequence: 0,
            frames: 0,
        })
    }

    fn active(&self) -> PidsResult<()> {
        let deadline = if self.cleanup {
            self.terminal
                .checked_sub(Duration::from_secs(2))
                .ok_or("pids-deadline")?
        } else {
            self.work
        };
        if Instant::now() >= deadline {
            Err("pids-deadline")
        } else {
            Ok(())
        }
    }

    fn charge(&mut self, size: usize) -> PidsResult<()> {
        self.captured = self.captured.checked_add(size).ok_or("pids-capture")?;
        if self.captured > HELPER_CAPTURE {
            return Err("pids-capture");
        }
        Ok(())
    }

    fn pause(&self) -> PidsResult<()> {
        self.active()?;
        std::thread::sleep(Duration::from_millis(1));
        self.active()
    }

    fn send(&mut self, bytes: &[u8]) -> PidsResult<()> {
        self.sent = self.sent.checked_add(bytes.len()).ok_or("pids-input")?;
        if self.sent > 8192 {
            return Err("pids-input");
        }
        let mut offset = 0;
        while offset < bytes.len() {
            self.active()?;
            match self.stream.write(&bytes[offset..]) {
                Ok(0) => return Err("pids-write"),
                Ok(size) => offset += size,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => self.pause()?,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => self.active()?,
                Err(_) => return Err("pids-write"),
            }
        }
        Ok(())
    }

    fn receive(&mut self, bytes: &mut [u8]) -> PidsResult<usize> {
        if bytes.is_empty() {
            return Err("pids-read");
        }
        loop {
            self.active()?;
            // No valid root reply has ancillary data. Zero capacity causes Linux
            // to close excess received rights and report CTRUNC; refuse it even
            // when this is the final EOF read. Never silently use ordinary Read.
            let mut control = RecvAncillaryBuffer::default();
            match recvmsg(
                &self.stream,
                &mut [IoSliceMut::new(bytes)],
                &mut control,
                RecvFlags::CMSG_CLOEXEC,
            ) {
                Ok(message) => {
                    if !(message.flags - ReturnFlags::CMSG_CLOEXEC).is_empty()
                        || message.bytes > bytes.len()
                        || message.address.is_some()
                    {
                        return Err("pids-ancillary");
                    }
                    self.charge(message.bytes)?;
                    self.received = self
                        .received
                        .checked_add(message.bytes)
                        .ok_or("pids-capture")?;
                    return Ok(message.bytes);
                }
                Err(rustix::io::Errno::AGAIN) => self.pause()?,
                Err(rustix::io::Errno::INTR) => self.active()?,
                Err(_) => return Err("pids-read"),
            }
        }
    }

    fn exact(&mut self, bytes: &mut [u8]) -> PidsResult<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let size = self.receive(&mut bytes[offset..])?;
            if size == 0 {
                return Err("pids-eof");
            }
            offset += size;
        }
        Ok(())
    }

    fn bootstrap(&mut self, capture: &File) -> PidsResult<()> {
        let descriptors = [capture.as_fd()];
        let mut space = [MaybeUninit::new(0); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err("pids-bootstrap");
        }
        let boot = b"BFPIDS1\n";
        let sent = loop {
            self.active()?;
            match sendmsg(
                &self.stream,
                &[IoSlice::new(boot)],
                &mut control,
                SendFlags::NOSIGNAL,
            ) {
                Ok(0) => return Err("pids-bootstrap"),
                Ok(size) if size <= boot.len() => break size,
                Ok(_) => return Err("pids-bootstrap"),
                Err(rustix::io::Errno::AGAIN) => self.pause()?,
                Err(rustix::io::Errno::INTR) => self.active()?,
                Err(_) => return Err("pids-bootstrap"),
            }
        };
        // Rights are sent once, even when the stream accepts a short payload.
        self.sent = self.sent.checked_add(sent).ok_or("pids-input")?;
        if self.sent > 8192 {
            return Err("pids-input");
        }
        self.send(&boot[sent..])?;
        let mut ready = [0; 8];
        self.exact(&mut ready)?;
        if &ready != b"BFREADY\n" {
            return Err("pids-bootstrap");
        }
        Ok(())
    }

    fn frame(&mut self, value: &Value) -> PidsResult<()> {
        let bytes = serde_json::to_vec(value).map_err(|_| "pids-json")?;
        if bytes.is_empty() || bytes.len() > FRAME {
            return Err("pids-frame");
        }
        self.frames += 1;
        if self.frames > 64 {
            return Err("pids-frames");
        }
        self.send(&(bytes.len() as u32).to_be_bytes())?;
        self.send(&bytes)
    }

    fn object(&mut self) -> PidsResult<Value> {
        let mut prefix = [0; 4];
        self.exact(&mut prefix)?;
        let size = u32::from_be_bytes(prefix) as usize;
        if size == 0 || size > FRAME {
            return Err("pids-frame");
        }
        if self
            .captured
            .checked_add(size)
            .is_none_or(|bytes| bytes > HELPER_CAPTURE)
        {
            return Err("pids-capture");
        }
        let mut bytes = vec![0; size];
        self.exact(&mut bytes)?;
        self.last_frame = size + 4;
        unique_json(&bytes)
    }
}

struct RootChannel {
    wire: RootWire,
    child: Child,
    stderr: Option<std::thread::JoinHandle<(Vec<u8>, bool)>>,
    reservation: u64,
    inspect_calls: u64,
    inspect_bytes: u64,
    confirmed: bool,
    finished: bool,
}

// Own even the spawn-to-pipe-setup interval. Child is never detached merely
// because taking/configuring a pipe or starting its bounded reader failed.
struct SpawnedChild {
    child: Option<Child>,
    terminal: Instant,
}

impl SpawnedChild {
    fn new(child: Child, terminal: Instant) -> Self {
        Self {
            child: Some(child),
            terminal,
        }
    }

    fn child(&mut self) -> PidsResult<&mut Child> {
        self.child.as_mut().ok_or("pids-child-custody")
    }

    fn transfer(mut self) -> PidsResult<Child> {
        self.child.take().ok_or("pids-child-custody")
    }
}

fn retire_child(child: &mut Child, terminal: Instant) {
    drop(child.stdin.take());
    drop(child.stdout.take());
    drop(child.stderr.take());
    let cutoff = terminal.min(Instant::now() + Duration::from_millis(500));
    while Instant::now() < cutoff {
        if child.try_wait().is_ok_and(|status| status.is_some()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // This is the exact owned spawned child, never a discovered numeric PID.
    // Its independent supervisor/outer deadline remains authoritative when
    // privilege means the original caller cannot signal it successfully.
    let _ = child.kill();
    let _ = child.try_wait();
}

impl Drop for SpawnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            retire_child(child, self.terminal);
        }
    }
}

fn root_source_command(deadline_ns: u64) -> Command {
    let helper =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/native-pids-supervisor.py");
    let mut command = Command::new("/usr/bin/sudo");
    command
        .args(["-n", "/usr/bin/python3", "-I"])
        .arg(helper)
        .arg("supervise")
        .arg(deadline_ns.to_string());
    command
}

impl RootChannel {
    fn launch(run: &HealthRun, capture: &ProofTarget, deadline_ns: u64) -> PidsResult<Self> {
        capture.check();
        reserve(run, 1, HELPER_CAPTURE, false)?;
        let (owner, helper) = UnixStream::pair().map_err(|_| "pids-socket")?;
        let wire = RootWire::new(owner, run.deadline)?;
        let stdin: OwnedFd = helper.into();
        let child = root_source_command(deadline_ns)
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "pids-supervisor")?;
        let mut child = SpawnedChild::new(child, run.deadline);
        let error = child.child()?.stderr.take().ok_or("pids-supervisor")?;
        let stderr = std::thread::Builder::new()
            .spawn(move || stream(error, 1024))
            .map_err(|_| "pids-supervisor")?;
        let mut channel = Self {
            wire,
            child: child.transfer()?,
            stderr: Some(stderr),
            reservation: 0,
            inspect_calls: 0,
            inspect_bytes: 0,
            confirmed: false,
            finished: false,
        };
        channel.wire.bootstrap(&capture.held)?;
        Ok(channel)
    }

    fn request(&mut self, run: &HealthRun, operation: &str, fields: Value) -> PidsResult<Value> {
        if self.finished {
            return Err("pids-sequence");
        }
        self.wire.sequence += 1;
        let mut request = fields.as_object().cloned().ok_or("pids-schema")?;
        for key in ["version", "sequence", "op"] {
            if request.contains_key(key) {
                return Err("pids-schema");
            }
        }
        request.insert("version".into(), json!(VERSION));
        request.insert("sequence".into(), json!(self.wire.sequence));
        request.insert("op".into(), json!(operation));
        self.wire.frame(&Value::Object(request))?;
        if operation == "OuterFinalize" {
            if !self.wire.cleanup {
                return Err("pids-sequence");
            }
            self.wire
                .stream
                .shutdown(std::net::Shutdown::Write)
                .map_err(|_| "pids-shutdown")?;
        }
        loop {
            let response = self.wire.object()?;
            if response["version"].as_u64() != Some(VERSION)
                || response["sequence"].as_u64() != Some(self.wire.sequence)
            {
                return Err("pids-sequence");
            }
            if response["op"] == "ReserveApi" {
                closed(
                    &response,
                    &[
                        "version",
                        "sequence",
                        "op",
                        "reservation",
                        "units",
                        "max_body_bytes",
                    ],
                )?;
                let ordinal = response["reservation"].as_u64().ok_or("pids-reservation")?;
                let bytes = response["max_body_bytes"]
                    .as_u64()
                    .ok_or("pids-reservation")?;
                if ordinal != self.reservation + 1
                    || ordinal > 31
                    || response["units"].as_u64() != Some(1)
                    || (ordinal == 1 && bytes != 4096)
                    || (ordinal != 1 && bytes != 32768)
                    || self.wire.cleanup
                {
                    return Err("pids-reservation");
                }
                reserve(run, 1, bytes as usize, false)?;
                self.reservation = ordinal;
                if bytes == 32768 {
                    self.inspect_calls += 1;
                    self.inspect_bytes += bytes;
                }
                self.wire.frame(&json!({"version":VERSION,"sequence":self.wire.sequence,"op":"ApiReservationAccepted","reservation":ordinal}))?;
                continue;
            }
            if response["op"] != operation {
                return Err("pids-sequence");
            }
            return Ok(response);
        }
    }

    fn status(
        &mut self,
        run: &HealthRun,
        operation: &str,
        fields: Value,
        expected: &str,
    ) -> PidsResult<()> {
        let response = self.request(run, operation, fields)?;
        closed(&response, &["version", "sequence", "op", "status"])?;
        if response["status"] != expected {
            return Err("pids-status");
        }
        if operation == "ConfirmRuntime" {
            self.confirmed = true;
        }
        if operation == "SealMeasurements" {
            self.wire.cleanup = true;
        }
        Ok(())
    }

    fn finalize(&mut self, run: &HealthRun) -> PidsResult<Value> {
        if !self.confirmed || !self.wire.cleanup {
            return Err("pids-sequence");
        }
        let response = self.request(run, "OuterFinalize", json!({}))?;
        closed(
            &response,
            &[
                "version",
                "sequence",
                "op",
                "status",
                "reservations",
                "source_ledger",
            ],
        )?;
        let reservations = &response["reservations"];
        closed(
            reservations,
            &[
                "inspect_calls_reserved",
                "inspect_body_bytes_reserved",
                "runtime_probe_calls_reserved",
                "runtime_probe_body_bytes_reserved",
            ],
        )?;
        if response["status"] != "finalized"
            || reservations["inspect_calls_reserved"] != self.inspect_calls
            || reservations["inspect_body_bytes_reserved"] != self.inspect_bytes
            || reservations["runtime_probe_calls_reserved"] != 1
            || reservations["runtime_probe_body_bytes_reserved"] != 4096
        {
            return Err("pids-reservations");
        }
        let source = &response["source_ledger"];
        closed(
            source,
            &[
                "external_reserved",
                "root_reserved",
                "total_reserved",
                "limits",
                "fds",
                "output_reserved_before_final",
            ],
        )?;
        for section in ["external_reserved", "root_reserved", "total_reserved"] {
            closed(&source[section], &["bytes", "reads"])?;
            unsigned(&source[section]["bytes"])?;
            unsigned(&source[section]["reads"])?;
        }
        closed(
            &source["fds"],
            &[
                "peak_reservations",
                "open_reservations",
                "fixed_overhead_reservations",
                "source_owned_remaining",
            ],
        )?;
        if source["limits"]
            != json!({"bytes":33554432,"reads":65536,"output_bytes":65536,"live_fd_reservations":256,"fd_opens":32768})
            || source["output_reserved_before_final"]
                .as_u64()
                .and_then(|bytes| usize::try_from(bytes).ok())
                .and_then(|bytes| bytes.checked_add(self.wire.last_frame))
                != Some(self.wire.received)
            || source["fds"]["source_owned_remaining"] != 0
            || source["fds"]["fixed_overhead_reservations"] != 16
            || !(16..=256).contains(&unsigned(&source["fds"]["peak_reservations"])?)
            || unsigned(&source["fds"]["open_reservations"])? > 32768
        {
            return Err("pids-source-ledger");
        }
        let mut end = [0; 1];
        if self.wire.receive(&mut end)? != 0 {
            return Err("pids-trailing");
        }
        let status = loop {
            self.wire.active()?;
            if let Some(status) = self.child.try_wait().map_err(|_| "pids-supervisor")? {
                break status;
            }
            self.wire.pause()?;
        };
        let (error, overflow) = self
            .stderr
            .take()
            .ok_or("pids-supervisor")?
            .join()
            .map_err(|_| "pids-supervisor")?;
        self.wire.charge(error.len())?;
        if !status.success() || overflow || !error.is_empty() {
            return Err("pids-supervisor");
        }
        self.finished = true;
        Ok(json!({"api":reservations,"source":source,"captured_output_bytes":self.wire.received}))
    }
}

impl Drop for RootChannel {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.wire.stream.shutdown(std::net::Shutdown::Both);
        // Closing the exclusive channel makes the fixed server refuse. Its root
        // supervisor independently enforces the original absolute terminal time.
        // Never signal a guessed PID, a foreign process group, or a new runtime.
        retire_child(&mut self.child, self.wire.terminal);
    }
}

struct WorkerControl {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
    stderr: Option<std::thread::JoinHandle<(Vec<u8>, bool)>>,
    captured: usize,
    sequence: u64,
    sealed: bool,
    finished: bool,
    terminal: Instant,
}

impl WorkerControl {
    fn active(&self, run: &HealthRun) -> PidsResult<()> {
        if run.remaining() <= Duration::from_secs(if self.sealed { 2 } else { 46 }) {
            return Err("pids-controller-deadline");
        }
        Ok(())
    }

    fn charge(&mut self, bytes: usize) -> PidsResult<()> {
        self.captured = self
            .captured
            .checked_add(bytes)
            .ok_or("pids-controller-capture")?;
        if self.captured > HELPER_CAPTURE {
            return Err("pids-controller-capture");
        }
        Ok(())
    }

    fn launch(run: &HealthRun, nonce: &str, deadline: u64) -> PidsResult<Self> {
        reserve(run, 1, HELPER_CAPTURE, false)?;
        let seconds = run
            .remaining()
            .checked_sub(Duration::from_secs(1))
            .map(|duration| duration.as_secs())
            .filter(|seconds| *seconds > 0)
            .ok_or("pids-controller-deadline")?;
        let elevated = match required("NATIVE_PODMAN_USE_SUDO").as_str() {
            "0" => false,
            "1" => true,
            _ => return Err("pids-actor"),
        };
        let mut command = Command::new(if elevated { "sudo" } else { "timeout" });
        if elevated {
            command.args(["-n", "timeout"]);
        }
        command.args(["--signal=TERM", "--kill-after=1s", &format!("{seconds}s")]);
        command.args(crate::native_outer_test_command::prefix());
        command.args([
            "pids-controller",
            &required("NATIVE_OUTER_CONTAINER_ID"),
            &run.run,
            &run.lane,
            nonce,
            &deadline.to_string(),
        ]);
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "pids-controller")?;
        let mut child = SpawnedChild::new(child, run.deadline);
        let input = child.child()?.stdin.take().ok_or("pids-controller")?;
        let output = child.child()?.stdout.take().ok_or("pids-controller")?;
        // Safe nonblocking pipe operations; no libc/unsafe exception is added
        // to this crate, and neither child I/O nor cancellation can reset time.
        rustix::io::ioctl_fionbio(&input, true).map_err(|_| "pids-controller")?;
        rustix::io::ioctl_fionbio(&output, true).map_err(|_| "pids-controller")?;
        let error = child.child()?.stderr.take().ok_or("pids-controller")?;
        let stderr = std::thread::Builder::new()
            .spawn(move || stream(error, 1024))
            .map_err(|_| "pids-controller")?;
        Ok(Self {
            child: child.transfer()?,
            input: Some(input),
            output,
            stderr: Some(stderr),
            captured: 0,
            sequence: 0,
            sealed: false,
            finished: false,
            terminal: run.deadline,
        })
    }

    fn request(&mut self, run: &HealthRun, operation: &str, fields: Value) -> PidsResult<Value> {
        self.active(run)?;
        if self.finished || (self.sealed && operation != "Close") {
            return Err("pids-controller-sequence");
        }
        reserve(run, 1, 0, self.sealed)?;
        self.sequence += 1;
        if self.sequence > 45 {
            return Err("pids-controller-sequence");
        }
        let mut value = fields.as_object().cloned().ok_or("pids-schema")?;
        for key in ["version", "sequence", "op"] {
            if value.contains_key(key) {
                return Err("pids-schema");
            }
        }
        value.insert("version".into(), json!(VERSION));
        value.insert("sequence".into(), json!(self.sequence));
        value.insert("op".into(), json!(operation));
        let mut bytes = serde_json::to_vec(&value).map_err(|_| "pids-json")?;
        bytes.push(b'\n');
        if bytes.len() > 4096 {
            return Err("pids-controller-frame");
        }
        self.charge(bytes.len())?;
        let mut offset = 0;
        while offset < bytes.len() {
            self.active(run)?;
            let input = self.input.as_ref().ok_or("pids-controller")?;
            match rustix::io::write(input, &bytes[offset..]) {
                Ok(0) => return Err("pids-controller-write"),
                Ok(size) => offset += size,
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return Err("pids-controller-write"),
            }
        }
        if operation == "Close" {
            // Controller cleanup acknowledgment is conditional on terminal EOF.
            // Do not wait for its response while retaining this writer.
            drop(self.input.take());
        }
        let mut captured = Vec::new();
        loop {
            self.active(run)?;
            let mut part = [0; 4097];
            match rustix::io::read(&self.output, &mut part[..]) {
                Ok(0) => return Err("pids-controller-eof"),
                Ok(size) => {
                    self.charge(size)?;
                    captured.extend_from_slice(&part[..size]);
                    if captured.len() > 4096 {
                        return Err("pids-controller-frame");
                    }
                    if captured.contains(&b'\n') {
                        break;
                    }
                }
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return Err("pids-controller-read"),
            }
        }
        if !captured.ends_with(b"\n") || captured.iter().filter(|&&byte| byte == b'\n').count() != 1
        {
            return Err("pids-controller-frame");
        }
        let response = unique_json(&captured)?;
        if response["version"].as_u64() != Some(VERSION)
            || response["sequence"].as_u64() != Some(self.sequence)
            || response["op"] != operation
        {
            return Err("pids-controller-sequence");
        }
        Ok(response)
    }

    fn event(&mut self, run: &HealthRun, slot: &str, command: &str) -> PidsResult<Value> {
        let response = self.request(run, "Event", json!({"slot":slot,"command":command}))?;
        closed(&response, &["version", "sequence", "op", "slot", "event"])?;
        if response["slot"] != slot {
            return Err("pids-controller-slot");
        }
        Ok(response["event"].clone())
    }

    fn seal(&mut self, run: &HealthRun) -> PidsResult<()> {
        let response = self.request(run, "Seal", json!({}))?;
        closed(&response, &["version", "sequence", "op", "status"])?;
        if response["status"] != "sealed" {
            return Err("pids-controller-status");
        }
        self.sealed = true;
        Ok(())
    }

    fn close(&mut self, run: &HealthRun) -> PidsResult<()> {
        let response = self.request(run, "Close", json!({}))?;
        closed(&response, &["version", "sequence", "op", "status"])?;
        if response["status"] != "closed" {
            return Err("pids-controller-status");
        }
        let mut extra = [0; 1];
        loop {
            self.active(run)?;
            match rustix::io::read(&self.output, &mut extra[..]) {
                Ok(0) => break,
                Ok(_) => return Err("pids-controller-trailing"),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return Err("pids-controller-read"),
            }
        }
        let status = loop {
            self.active(run)?;
            if let Some(status) = self.child.try_wait().map_err(|_| "pids-controller-exit")? {
                break status;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let (error, overflow) = self
            .stderr
            .take()
            .ok_or("pids-controller-stderr")?
            .join()
            .map_err(|_| "pids-controller-stderr")?;
        self.charge(error.len())?;
        if !status.success() || overflow || !error.is_empty() {
            return Err("pids-controller-exit");
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for WorkerControl {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        drop(self.input.take());
        retire_child(&mut self.child, self.terminal);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OuterIdentity {
    projection: Value,
    id: String,
    pid: u32,
    start: u64,
    started_at: String,
    restart_count: u64,
    cgroup_namespace: String,
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Eq, PartialEq)]
struct FileVersion {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn file_version(info: &fs::Metadata) -> FileVersion {
    FileVersion {
        device: info.dev(),
        inode: info.ino(),
        size: info.len(),
        mode: info.mode(),
        uid: info.uid(),
        gid: info.gid(),
        links: info.nlink(),
        modified: (info.mtime(), info.mtime_nsec()),
        changed: (info.ctime(), info.ctime_nsec()),
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SourceCost {
    bytes: u64,
    reads: u64,
}

impl SourceCost {
    fn add(self, other: Self) -> PidsResult<Self> {
        let bytes = self
            .bytes
            .checked_add(other.bytes)
            .ok_or("pids-source-budget")?;
        let reads = self
            .reads
            .checked_add(other.reads)
            .ok_or("pids-source-budget")?;
        if bytes > 33554432 || reads > 65536 {
            return Err("pids-source-budget");
        }
        Ok(Self { bytes, reads })
    }

    fn file(size: u64) -> PidsResult<Self> {
        let bytes = size.checked_add(1).ok_or("pids-source-budget")?;
        let reads = size
            .div_ceil(65536)
            .checked_add(1)
            .ok_or("pids-source-budget")?;
        Self::default().add(Self { bytes, reads })
    }

    fn copy(size: u64) -> PidsResult<Self> {
        let bytes = size
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or("pids-source-budget")?;
        let reads = size
            .div_ceil(65536)
            .checked_mul(3)
            .and_then(|reads| reads.checked_add(2))
            .ok_or("pids-source-budget")?;
        Self::default().add(Self { bytes, reads })
    }

    fn value(self) -> Value {
        json!({"bytes":self.bytes,"reads":self.reads})
    }
}

fn owned_bytes(
    path: &std::path::Path,
    maximum: usize,
    mode: Option<u32>,
) -> PidsResult<(Vec<u8>, File)> {
    let mut held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "pids-artifact")?;
    let before = held.metadata().map_err(|_| "pids-artifact")?;
    let uid = fs::metadata("/proc/self")
        .map_err(|_| "pids-artifact")?
        .uid();
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != uid
        || before.len() == 0
        || before.len() > maximum as u64
        || mode.is_some_and(|mode| before.mode() & 0o777 != mode)
    {
        return Err("pids-artifact");
    }
    // Fixed, preflighted reads include an EOF probe. Short or interrupted
    // regular-file reads refuse rather than silently enlarging I/O cost.
    let _cost = SourceCost::file(before.len())?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    let mut part = [0; 65536];
    while bytes.len() < before.len() as usize {
        let size = part.len().min(before.len() as usize - bytes.len());
        if held.read(&mut part[..size]).map_err(|_| "pids-artifact")? != size {
            return Err("pids-artifact");
        }
        bytes.extend_from_slice(&part[..size]);
    }
    if held.read(&mut part[..1]).map_err(|_| "pids-artifact")? != 0 {
        return Err("pids-artifact");
    }
    let after = held.metadata().map_err(|_| "pids-artifact")?;
    let named = fs::symlink_metadata(path).map_err(|_| "pids-artifact")?;
    if file_version(&before) != file_version(&after)
        || file_version(&after) != file_version(&named)
        || bytes.len() as u64 != before.len()
    {
        return Err("pids-artifact");
    }
    Ok((bytes, held))
}

struct PreparedWorker {
    directory: PathBuf,
    held: File,
    version: FileVersion,
    manifest: Value,
    source: SourceCost,
}

fn native_gnu_driver_target(value: &str, architecture: &str) -> bool {
    if value.len() > 128 || !matches!(architecture, "x86_64" | "aarch64") {
        return false;
    }
    let parts: Vec<_> = value.split('-').collect();
    if parts.first().copied() != Some(architecture) {
        return false;
    }
    let vendor = |value: &str| {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+'))
            && !["musl", "uclibc", "android"]
                .iter()
                .any(|abi| value.to_ascii_lowercase().contains(abi))
    };
    match parts.as_slice() {
        [_, "linux", "gnu"] => true,
        [_, middle, "linux", "gnu"] => vendor(middle),
        [_, "suse" | "redhat", "linux"] => true,
        _ => false,
    }
}

fn validate_build_tools(manifest: &Value) -> PidsResult<()> {
    let tools = &manifest["build_tools"];
    closed(
        tools,
        &[
            "schema",
            "policy",
            "driver",
            "linker",
            "wrappers",
            "invocation",
            "dependencies",
            "crt",
            "hashed_input_bytes",
            "scope",
            "implementation_closure",
        ],
    )?;
    if tools["schema"] != "dockerlens-pids-build-tools-v1"
        || tools["policy"] != "native-gcc-bfd-v1"
        || tools["scope"] != "installed-tools-and-consumed-crt-only-v1"
        || tools["implementation_closure"] != "unresolved"
        || unsigned(&tools["hashed_input_bytes"])? > 256 * 1024 * 1024
    {
        return Err("pids-build-tools");
    }
    closed(&tools["wrappers"], &["driver_sha256", "linker_sha256"])?;
    for key in ["driver_sha256", "linker_sha256"] {
        if !tools["wrappers"][key].as_str().is_some_and(identifier) {
            return Err("pids-build-tools");
        }
    }
    closed(
        &tools["invocation"],
        &["count", "size", "sha256", "output_size", "output_sha256"],
    )?;
    closed(&tools["dependencies"], &["size", "sha256"])?;
    if tools["invocation"]["count"] != 1
        || tools["invocation"]["output_size"] != manifest["size"]
        || tools["invocation"]["output_sha256"] != manifest["sha256"]
        || !(1..=65536).contains(&unsigned(&tools["invocation"]["size"])?)
        || !(1..=131072).contains(&unsigned(&tools["dependencies"]["size"])?)
    {
        return Err("pids-build-tools");
    }
    for key in ["invocation", "dependencies"] {
        if !tools[key]["sha256"].as_str().is_some_and(identifier) {
            return Err("pids-build-tools");
        }
    }
    let mut all = vec![("driver", &tools["driver"]), ("linker", &tools["linker"])];
    let crt = tools["crt"]
        .as_array()
        .filter(|rows| (6..=8).contains(&rows.len()))
        .ok_or("pids-build-tools")?;
    let mut roles = BTreeSet::new();
    for row in crt {
        let role = row["role"].as_str().ok_or("pids-build-tools")?;
        if !matches!(
            role,
            "start" | "init" | "fini" | "begin" | "end" | "libc" | "gcc-runtime" | "gcc-eh"
        ) || !roles.insert(role)
        {
            return Err("pids-build-tools");
        }
        all.push(("crt", row));
    }
    if ["start", "init", "fini", "begin", "end", "libc"]
        .iter()
        .any(|role| !roles.contains(role))
    {
        return Err("pids-build-tools");
    }
    let mut inputs = BTreeSet::new();
    let mut input_bytes = 0u64;
    for (kind, tool) in all {
        let crt = kind == "crt";
        closed(
            tool,
            if kind == "driver" {
                &[
                    "path",
                    "size",
                    "sha256",
                    "identity",
                    "package",
                    "version",
                    "native_target",
                    "file_kind",
                ]
            } else if crt {
                &[
                    "path",
                    "size",
                    "sha256",
                    "identity",
                    "package",
                    "role",
                    "file_kind",
                ]
            } else {
                &[
                    "path",
                    "size",
                    "sha256",
                    "identity",
                    "package",
                    "version",
                    "file_kind",
                ]
            },
        )?;
        if kind == "driver" {
            let target = tool["native_target"].as_str().ok_or("pids-build-tools")?;
            if !native_gnu_driver_target(target, std::env::consts::ARCH) {
                return Err("pids-build-tools");
            }
        }
        if (!crt && !matches!(tool["file_kind"].as_str(), Some("elf" | "script")))
            || (crt && !matches!(tool["file_kind"].as_str(), Some("elf" | "archive")))
        {
            return Err("pids-build-tools");
        }
        if crt {
            let archive = matches!(
                tool["role"].as_str(),
                Some("libc" | "gcc-runtime" | "gcc-eh")
            );
            if tool["file_kind"] != if archive { "archive" } else { "elf" } {
                return Err("pids-build-tools");
            }
        }
        let path = tool["path"]
            .as_str()
            .filter(|path| path.starts_with('/') && path.len() <= 4096 && !path.contains('\0'))
            .ok_or("pids-build-tools")?;
        if !inputs.insert(path)
            || !(1..=32 * 1024 * 1024).contains(&unsigned(&tool["size"])?)
            || !tool["sha256"].as_str().is_some_and(identifier)
            || (!crt
                && tool["version"]
                    .as_str()
                    .is_none_or(|version| version.is_empty() || version.len() > 8192))
        {
            return Err("pids-build-tools");
        }
        input_bytes = input_bytes
            .checked_add(unsigned(&tool["size"])?)
            .ok_or("pids-build-tools")?;
        let identity = &tool["identity"];
        closed(
            identity,
            &[
                "device", "inode", "uid", "gid", "mode", "links", "mtime_ns", "ctime_ns",
            ],
        )?;
        for key in [
            "device", "inode", "uid", "gid", "mode", "links", "mtime_ns", "ctime_ns",
        ] {
            unsigned(&identity[key])?;
        }
        if unsigned(&identity["inode"])? == 0
            || unsigned(&identity["links"])? == 0
            || unsigned(&identity["mode"])? & 0o170000 != 0o100000
        {
            return Err("pids-build-tools");
        }
        let package = &tool["package"];
        closed(package, &["status", "reason", "unverified_path_hint"])?;
        if package["status"] != "unavailable"
            || package["reason"] != "os-bootstrap-not-queried"
            || (!package["unverified_path_hint"].is_null()
                && package["unverified_path_hint"]
                    .as_str()
                    .is_none_or(|hint| hint.is_empty() || hint.len() > 255))
        {
            return Err("pids-build-tools");
        }
    }
    if input_bytes > 128 * 1024 * 1024
        || unsigned(&tools["hashed_input_bytes"])?
            < input_bytes.checked_mul(2).ok_or("pids-build-tools")?
    {
        return Err("pids-build-tools");
    }
    Ok(())
}

impl PreparedWorker {
    fn acquire(run: &HealthRun, target: &ProofTarget) -> PidsResult<Self> {
        target.check();
        let directory = target.directory.join("socket/pids-worker");
        let info = fs::symlink_metadata(&directory).map_err(|_| "pids-artifact")?;
        let uid = fs::metadata("/proc/self")
            .map_err(|_| "pids-artifact")?
            .uid();
        if !info.is_dir()
            || info.uid() != uid
            || info.mode() & 0o777 != 0o700
            || directory.canonicalize().map_err(|_| "pids-artifact")? != directory
        {
            return Err("pids-artifact");
        }
        let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let paths = [
            directory.join("native-pids-worker.json"),
            directory.join("native-pids-worker"),
            directory.join("native-pids-worker-build.log"),
            directory.join("native-pids-worker-driver.py"),
            directory.join("native-pids-worker-ld.py"),
            directory.join("native-pids-worker-link.json"),
            directory.join("native-pids-worker-link.d"),
            source_root.join("rust-toolchain.toml"),
            source_root.join("examples/native-pids-worker.rs"),
            source_root.join("examples/native-pids-controller/mod.rs"),
            source_root.join("Cargo.toml"),
            source_root.join("Cargo.lock"),
        ];
        let mut source = SourceCost::default();
        let mut sizes = BTreeMap::new();
        for path in &paths {
            let info = fs::symlink_metadata(path).map_err(|_| "pids-artifact")?;
            if !info.is_file() || info.nlink() != 1 || info.uid() != uid || info.len() == 0 {
                return Err("pids-artifact");
            }
            source = source.add(SourceCost::file(info.len())?)?;
            sizes.insert(path.clone(), info.len());
        }
        let binary_size = fs::symlink_metadata(&paths[1])
            .map_err(|_| "pids-artifact")?
            .len();
        source = source
            .add(SourceCost::copy(binary_size)?)?
            .add(SourceCost {
                bytes: 3 * 4097 + 16,
                reads: 7,
            })?;
        let read = |path: &std::path::Path, maximum: usize, mode: Option<u32>| {
            let planned = sizes.get(path).copied().ok_or("pids-artifact")?;
            owned_bytes(
                path,
                maximum.min(usize::try_from(planned).map_err(|_| "pids-artifact")?),
                mode,
            )
        };
        reserve(run, 1, 0, false)?;
        let (raw, _) = read(
            &directory.join("native-pids-worker.json"),
            32768,
            Some(0o600),
        )?;
        let manifest = unique_json(&raw)?;
        closed(
            &manifest,
            &[
                "schema",
                "candidate",
                "toolchain",
                "compiler",
                "target",
                "flags",
                "profile",
                "binary",
                "size",
                "sha256",
                "elf",
                "source_sha256",
                "controller_source_sha256",
                "cargo_lock_sha256",
                "cargo_manifest_sha256",
                "build_log_sha256",
                "build_log_size",
                "original_deadline_ns",
                "build_tools",
            ],
        )?;
        validate_build_tools(&manifest)?;
        for (file, maximum, expected_size, expected_hash) in [
            (
                "native-pids-worker-driver.py",
                16384,
                None,
                &manifest["build_tools"]["wrappers"]["driver_sha256"],
            ),
            (
                "native-pids-worker-ld.py",
                16384,
                None,
                &manifest["build_tools"]["wrappers"]["linker_sha256"],
            ),
            (
                "native-pids-worker-link.json",
                65536,
                manifest["build_tools"]["invocation"]["size"].as_u64(),
                &manifest["build_tools"]["invocation"]["sha256"],
            ),
            (
                "native-pids-worker-link.d",
                131072,
                manifest["build_tools"]["dependencies"]["size"].as_u64(),
                &manifest["build_tools"]["dependencies"]["sha256"],
            ),
        ] {
            let (data, _) = read(&directory.join(file), maximum, Some(0o600))?;
            if expected_size.is_some_and(|size| data.len() as u64 != size)
                || expected_hash != &hash(&data)
            {
                return Err("pids-build-tools-raw");
            }
        }
        let (declared, _) = read(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rust-toolchain.toml"),
            4096,
            None,
        )?;
        let declared = std::str::from_utf8(&declared).map_err(|_| "pids-artifact")?;
        let channel = declared
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("channel = \"")
                    .and_then(|line| line.strip_suffix('"'))
            })
            .ok_or("pids-artifact")?;
        let target_name = match std::env::consts::ARCH {
            "x86_64" => "x86_64-unknown-linux-gnu",
            "aarch64" => "aarch64-unknown-linux-gnu",
            _ => return Err("pids-artifact"),
        };
        let flags = if std::env::consts::ARCH == "x86_64" {
            "-C target-feature=+crt-static -C panic=abort -C strip=symbols -C linker-flavor=gcc -C linker-features=-lld"
        } else {
            "-C target-feature=+crt-static -C panic=abort -C strip=symbols -C linker-flavor=gcc"
        };
        if manifest["schema"] != "dockerlens-pids-worker-build-v1"
            || manifest["candidate"] != run.candidate
            || manifest["toolchain"] != channel
            || manifest["compiler"]["release"] != channel
            || manifest["compiler"]["host"] != target_name
            || manifest["target"] != target_name
            || manifest["binary"] != "native-pids-worker"
            || manifest["flags"] != flags
            || manifest["profile"]
                != json!({"name":"release","opt-level":"z","lto":"fat","codegen-units":1})
        {
            return Err("pids-artifact");
        }
        closed(
            &manifest["compiler"],
            &[
                "release",
                "host",
                "commit_hash",
                "commit_date",
                "llvm_version",
            ],
        )?;
        closed(
            &manifest["elf"],
            &["class", "endianness", "machine", "pt_interp", "dt_needed"],
        )?;
        if manifest["elf"]
            != json!({"class":64,"endianness":"little","machine":if std::env::consts::ARCH == "x86_64" {62} else {183},"pt_interp":false,"dt_needed":false})
        {
            return Err("pids-artifact");
        }
        for (relative, field, maximum) in [
            (
                "examples/native-pids-worker.rs",
                "source_sha256",
                128 * 1024,
            ),
            (
                "examples/native-pids-controller/mod.rs",
                "controller_source_sha256",
                128 * 1024,
            ),
            ("Cargo.toml", "cargo_manifest_sha256", 65536),
            ("Cargo.lock", "cargo_lock_sha256", 1024 * 1024),
        ] {
            let (source, _) = read(
                &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative),
                maximum,
                None,
            )?;
            if manifest[field] != hash(&source) {
                return Err("pids-artifact-source");
            }
        }
        let size = manifest["size"]
            .as_u64()
            .filter(|size| *size > 0 && *size <= 8 * 1024 * 1024)
            .ok_or("pids-artifact")?;
        // This is an actual source read of an already-bound prebuild, not a
        // claim that the binary travelled over an API or the helper's stdout.
        let (binary, held) = read(
            &directory.join("native-pids-worker"),
            size as usize,
            Some(0o700),
        )?;
        if binary.len() as u64 != size || manifest["sha256"] != hash(&binary) {
            return Err("pids-artifact");
        }
        let info = held.metadata().map_err(|_| "pids-artifact")?;
        let (log, _) = read(
            &directory.join("native-pids-worker-build.log"),
            1024 * 1024,
            Some(0o600),
        )?;
        if manifest["build_log_sha256"] != hash(&log)
            || manifest["build_log_size"].as_u64() != Some(log.len() as u64)
        {
            return Err("pids-artifact");
        }
        Ok(Self {
            directory,
            held,
            version: file_version(&info),
            manifest,
            source,
        })
    }

    fn check(&self) -> PidsResult<()> {
        let current = self.held.metadata().map_err(|_| "pids-artifact")?;
        let named = fs::symlink_metadata(self.directory.join("native-pids-worker"))
            .map_err(|_| "pids-artifact")?;
        if file_version(&current) != self.version || file_version(&named) != self.version {
            return Err("pids-artifact");
        }
        Ok(())
    }

    fn bind_copy(&self, run: &HealthRun, copy: &Value) -> PidsResult<()> {
        self.check()?;
        closed(
            copy,
            &[
                "path",
                "size",
                "sha256",
                "source",
                "copy",
                "directory_uid",
                "directory_mode",
                "io",
            ],
        )?;
        let uid = if run.mode == DaemonMode::Rootless {
            1000
        } else {
            0
        };
        if copy["path"] != format!("/tmp/dockerlens-pids-worker-{}/native-pids-worker", run.run)
            || copy["size"] != self.manifest["size"]
            || copy["sha256"] != self.manifest["sha256"]
            || copy["directory_uid"] != uid
            || copy["directory_mode"] != 0o700
        {
            return Err("pids-artifact-copy");
        }
        validate_copy_io(&copy["io"], unsigned(&self.manifest["size"])?)?;
        for field in ["source", "copy"] {
            closed(
                &copy[field],
                &["device", "inode", "uid", "gid", "mode", "links"],
            )?;
        }
        let held = self.held.metadata().map_err(|_| "pids-artifact")?;
        if copy["source"]["device"] != held.dev()
            || copy["source"]["inode"] != held.ino()
            || copy["source"]["uid"] != held.uid()
            || copy["source"]["gid"] != held.gid()
            || copy["source"]["mode"] != 0o700
            || copy["source"]["links"] != 1
            || copy["copy"]["uid"] != uid
            || copy["copy"]["gid"] != uid
            || copy["copy"]["mode"] != 0o700
            || copy["copy"]["links"] != 1
            || copy["copy"]["device"].as_u64().is_none()
            || copy["copy"]["inode"].as_u64().is_none()
        {
            return Err("pids-artifact-copy");
        }
        Ok(())
    }
}

fn validate_copy_io(io: &Value, size: u64) -> PidsResult<()> {
    closed(
        io,
        &[
            "schema",
            "chunk_bytes",
            "reserved_bytes",
            "reserved_operations",
            "read_bytes",
            "write_bytes",
            "read_operations",
            "write_operations",
            "eof_probes",
        ],
    )?;
    let cost = SourceCost::copy(size)?;
    let chunks = size.div_ceil(65536);
    if size == 0
        || size > 8 * 1024 * 1024
        || io["schema"] != "dockerlens-pids-copy-io-v1"
        || unsigned(&io["chunk_bytes"])? != 65536
        || unsigned(&io["reserved_bytes"])? != cost.bytes
        || unsigned(&io["reserved_operations"])? != cost.reads
        || unsigned(&io["read_bytes"])? != size * 2
        || unsigned(&io["write_bytes"])? != size
        || unsigned(&io["read_operations"])? != chunks * 2 + 2
        || unsigned(&io["write_operations"])? != chunks
        || unsigned(&io["eof_probes"])? != 2
    {
        return Err("pids-artifact-copy-io");
    }
    Ok(())
}

fn proc_start(bytes: &[u8], expected: u32) -> PidsResult<u64> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err("pids-proc");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "pids-proc")?;
    let (prefix, tail) = text.rsplit_once(") ").ok_or("pids-proc")?;
    let (pid, _comm) = prefix.split_once(" (").ok_or("pids-proc")?;
    if pid.parse::<u32>().ok() != Some(expected) {
        return Err("pids-proc");
    }
    let fields: Vec<_> = tail.split_ascii_whitespace().collect();
    if fields.len() < 20 || matches!(fields[0], "Z" | "X" | "x") {
        return Err("pids-proc");
    }
    fields[19]
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or("pids-proc")
}

fn unsigned(value: &Value) -> PidsResult<u64> {
    value.as_u64().ok_or("pids-integer")
}

fn kernel_identity(value: &Value, length: usize) -> PidsResult<Vec<u64>> {
    let values = value
        .as_array()
        .filter(|values| values.len() == length)
        .ok_or("pids-kernel-identity")?;
    values
        .iter()
        .enumerate()
        .map(|(position, value)| {
            let number = unsigned(value)?;
            if position != 0 && number == 0 {
                return Err("pids-kernel-identity");
            }
            Ok(number)
        })
        .collect()
}

fn task_set(sample: &Value, namespace_ids: &BTreeSet<u64>) -> PidsResult<BTreeSet<(u64, u64)>> {
    let rows = sample["tasks"].as_array().ok_or("pids-tasks")?;
    let coordinates = sample["task_namespace_ids"]
        .as_array()
        .ok_or("pids-tasks")?;
    if rows.len() != namespace_ids.len()
        || coordinates.len() != rows.len()
        || unsigned(&sample["current"])? != rows.len() as u64
    {
        return Err("pids-tasks");
    }
    let mut tasks = BTreeSet::new();
    let mut tids = BTreeSet::new();
    let mut observed = BTreeSet::new();
    for row in rows {
        let row = row
            .as_array()
            .filter(|row| row.len() == 2)
            .ok_or("pids-tasks")?;
        let tid = unsigned(&row[0])?;
        let start = unsigned(&row[1])?;
        if tid == 0 || start == 0 || !tids.insert(tid) || !tasks.insert((tid, start)) {
            return Err("pids-tasks");
        }
    }
    for row in coordinates {
        let row = row
            .as_array()
            .filter(|row| row.len() == 3)
            .ok_or("pids-tasks")?;
        let tid = unsigned(&row[0])?;
        let pids = row[1]
            .as_array()
            .filter(|row| row.len() >= 3 && row.len() <= 32)
            .ok_or("pids-tasks")?;
        let groups = row[2].as_array().ok_or("pids-tasks")?;
        if groups != pids
            || pids.iter().any(|value| {
                value
                    .as_u64()
                    .is_none_or(|value| value == 0 || value > i32::MAX as u64)
            })
            || unsigned(&pids[0])? != tid
            || !tids.remove(&tid)
            || !observed.insert(unsigned(pids.last().ok_or("pids-tasks")?)?)
        {
            return Err("pids-tasks");
        }
    }
    if !tids.is_empty() || &observed != namespace_ids {
        return Err("pids-tasks");
    }
    Ok(tasks)
}

fn worker_children(event: &Value, count: usize) -> PidsResult<BTreeSet<u64>> {
    let children = event["children"].as_array().ok_or("pids-worker")?;
    if children.len() != count || unsigned(&event["child_count"])? != count as u64 {
        return Err("pids-worker");
    }
    let mut found = BTreeSet::from([1]);
    for child in children {
        let child = unsigned(child)?;
        if !(2..=i32::MAX as u64).contains(&child) || !found.insert(child) {
            return Err("pids-worker");
        }
    }
    Ok(found)
}

fn validate_case(
    slot: &str,
    nonce: &str,
    events: &[Value],
    samples: &[Value],
) -> PidsResult<Value> {
    if !SLOTS.contains(&slot) || events.len() != 7 || samples.len() != 4 {
        return Err("pids-case");
    }
    let finite = slot.ends_with("16");
    let phases = [
        "identity",
        "baseline",
        "attempt",
        if finite {
            "hold-failure"
        } else {
            "hold-control"
        },
        "release",
        "reuse",
        "finished",
    ];
    let identity = &events[0];
    closed(
        identity,
        &[
            "schema",
            "case",
            "nonce",
            "phase",
            "pid",
            "threads",
            "rlimit_nproc_soft",
            "rlimit_nproc_hard",
            "kernel_sysname",
            "kernel_release",
            "kernel_version",
            "kernel_machine",
        ],
    )?;
    for (position, event) in events.iter().enumerate() {
        if position != 0 {
            closed(
                event,
                &[
                    "schema",
                    "case",
                    "nonce",
                    "phase",
                    "pid",
                    "threads",
                    "children",
                    "child_count",
                    "fork_return",
                    "errno",
                    "eagain",
                ],
            )?;
        }
        if event["schema"] != "dockerlens-pids-worker-v1"
            || event["case"] != slot
            || event["nonce"] != nonce
            || event["phase"] != phases[position]
            || event["pid"] != 1
            || event["threads"] != 1
        {
            return Err("pids-worker");
        }
        if position != 0 && event["eagain"].as_i64() != Some(i64::from(libc::EAGAIN)) {
            return Err("pids-worker");
        }
        if position != 0
            && position != 3
            && position != 5
            && (!event["fork_return"].is_null() || !event["errno"].is_null())
        {
            return Err("pids-worker");
        }
    }
    if identity["kernel_sysname"] != "Linux" {
        return Err("pids-kernel");
    }
    for key in ["kernel_release", "kernel_version", "kernel_machine"] {
        if identity[key]
            .as_str()
            .is_none_or(|value| value.is_empty() || value.len() > 256)
        {
            return Err("pids-kernel");
        }
    }
    let expected_count = if finite { 15 } else { 32 };
    let baseline = worker_children(&events[1], 0)?;
    let held = worker_children(&events[2], expected_count)?;
    if worker_children(&events[3], expected_count)? != held
        || events[2]["children"] != events[3]["children"]
    {
        return Err("pids-worker");
    }
    for position in [4, 5, 6] {
        if worker_children(&events[position], 0)? != baseline {
            return Err("pids-worker");
        }
    }
    if finite {
        if events[3]["fork_return"] != -1
            || events[3]["errno"].as_i64() != Some(i64::from(libc::EAGAIN))
        {
            return Err("pids-fork-effect");
        }
    } else if !events[3]["fork_return"].is_null() || !events[3]["errno"].is_null() {
        return Err("pids-fork-effect");
    }
    if events[5]["fork_return"]
        .as_u64()
        .is_none_or(|pid| !(2..=i32::MAX as u64).contains(&pid))
        || events[5]["errno"] != 0
    {
        return Err("pids-reuse");
    }
    let maximum = if finite {
        json!(16)
    } else if slot.ends_with("64") {
        json!(64)
    } else {
        json!("max")
    };
    let mut bound = Vec::new();
    for (position, sample) in samples.iter().enumerate() {
        closed(
            sample,
            &[
                "maximum",
                "current",
                "events_max",
                "tasks",
                "task_namespace_ids",
                "attribution",
                "globals",
            ],
        )?;
        if sample["maximum"] != maximum {
            return Err("pids-limit");
        }
        bound.push(task_set(
            sample,
            if position == 1 || position == 2 {
                &held
            } else {
                &baseline
            },
        )?);
        let attribution = &sample["attribution"];
        closed(
            attribution,
            &[
                "event_semantics",
                "pids_localevents",
                "complete_chain",
                "outer_index",
                "reader_cgroup_namespace",
                "hierarchy_root",
                "controllers",
            ],
        )?;
        if attribution["event_semantics"] != "hierarchical_with_local_enforcer"
            || attribution["pids_localevents"] != false
            || attribution["complete_chain"] != true
        {
            return Err("pids-attribution");
        }
        let root = &attribution["hierarchy_root"];
        closed(
            root,
            &[
                "identity",
                "pids_max_present",
                "cgroup_type_present",
                "cgroup_events_present",
                "available_pids",
                "mount_root_is_slash",
                "qualification",
            ],
        )?;
        if root["pids_max_present"] != false
            || root["cgroup_type_present"] != false
            || root["cgroup_events_present"] != false
            || root["available_pids"] != true
            || root["mount_root_is_slash"] != true
            || root["qualification"] != "root_exempt"
        {
            return Err("pids-hierarchy-root");
        }
        let hierarchy = kernel_identity(&root["identity"], 3)?;
        kernel_identity(&attribution["reader_cgroup_namespace"], 2)?;
        let rows = attribution["controllers"]
            .as_array()
            .filter(|rows| !rows.is_empty() && rows.len() <= 32)
            .ok_or("pids-ancestors")?;
        let outer = unsigned(&attribution["outer_index"])? as usize;
        if outer == 0
            || outer >= rows.len()
            || rows[outer]["maximum"] != 512
            || rows[0]["maximum"] != maximum
            || rows[0]["current"] != sample["current"]
            || rows[0]["events_max"] != sample["events_max"]
        {
            return Err("pids-ancestors");
        }
        let mut groups = BTreeSet::new();
        for (index, row) in rows.iter().enumerate() {
            closed(
                row,
                &[
                    "identity",
                    "maximum",
                    "current",
                    "events_max",
                    "events_local_max",
                    "current_samples",
                    "events_samples",
                    "events_local_samples",
                ],
            )?;
            let group = kernel_identity(&row["identity"], 3)?;
            if group[0] != hierarchy[0]
                || group[2] != hierarchy[2]
                || group == hierarchy
                || !groups.insert(group)
            {
                return Err("pids-ancestors");
            }
            let current = unsigned(&row["current"])?;
            unsigned(&row["events_max"])?;
            unsigned(&row["events_local_max"])?;
            for (pair, scalar) in [
                ("current_samples", "current"),
                ("events_samples", "events_max"),
                ("events_local_samples", "events_local_max"),
            ] {
                let values = row[pair]
                    .as_array()
                    .filter(|values| values.len() == 2)
                    .ok_or("pids-observation-pair")?;
                let before = unsigned(&values[0])?;
                let after = unsigned(&values[1])?;
                let expected = if pair == "current_samples" {
                    before.max(after)
                } else {
                    after
                };
                if unsigned(&row[scalar])? != expected
                    || (pair != "current_samples" && after < before)
                    || (index == 0 && before != after)
                {
                    return Err("pids-observation-pair");
                }
            }
            if index != 0 {
                let margin = if position == 0 {
                    expected_count as u64 + 1
                } else {
                    1
                };
                if row["maximum"] != "max"
                    && unsigned(&row["maximum"])?
                        .checked_sub(current)
                        .is_none_or(|free| free < margin)
                {
                    return Err("pids-headroom");
                }
            }
        }
        let globals = &sample["globals"];
        closed(
            globals,
            &[
                "threads_max",
                "pid_max",
                "total_tasks",
                "total_tasks_samples",
                "sched_policy",
                "nproc_soft",
                "nproc_hard",
                "kernel_release",
                "kernel_version",
                "kernel_machine",
            ],
        )?;
        for key in ["kernel_release", "kernel_version", "kernel_machine"] {
            if globals[key] != identity[key] {
                return Err("pids-kernel");
            }
        }
        let margin = if position == 0 {
            expected_count as u64 + 1
        } else {
            1
        };
        let observed = globals["total_tasks_samples"]
            .as_array()
            .filter(|values| values.len() == 2)
            .ok_or("pids-observation-pair")?;
        if unsigned(&globals["total_tasks"])?
            != unsigned(&observed[0])?.max(unsigned(&observed[1])?)
        {
            return Err("pids-observation-pair");
        }
        if globals["sched_policy"] != 0
            || unsigned(&globals["pid_max"])? < 33
            || unsigned(&globals["threads_max"])?
                .checked_sub(unsigned(&globals["total_tasks"])?)
                .is_none_or(|free| free < margin)
        {
            return Err("pids-global-headroom");
        }
        for (key, event_key) in [
            ("nproc_soft", "rlimit_nproc_soft"),
            ("nproc_hard", "rlimit_nproc_hard"),
        ] {
            let raw = unsigned(&identity[event_key])?;
            let expected = if raw == u64::MAX {
                json!("unlimited")
            } else {
                json!(raw)
            };
            if globals[key] != expected {
                return Err("pids-nproc");
            }
        }
    }
    if bound[0] != bound[3] || bound[1] != bound[2] || !bound[0].is_subset(&bound[1]) {
        return Err("pids-task-custody");
    }
    let first = &samples[0]["attribution"];
    let first_controllers = first["controllers"].as_array().ok_or("pids-ancestors")?;
    let length = first_controllers.len();
    let outer = unsigned(&first["outer_index"])? as usize;
    for sample in &samples[1..] {
        let next = &sample["attribution"];
        if next["outer_index"] != first["outer_index"]
            || next["reader_cgroup_namespace"] != first["reader_cgroup_namespace"]
            || next["hierarchy_root"] != first["hierarchy_root"]
            || next["controllers"].as_array().map(Vec::len) != Some(length)
        {
            return Err("pids-ancestor-custody");
        }
        for index in 0..length {
            for key in ["identity", "maximum"] {
                if next["controllers"][index][key] != first["controllers"][index][key] {
                    return Err("pids-ancestor-custody");
                }
            }
        }
        for key in [
            "threads_max",
            "pid_max",
            "sched_policy",
            "nproc_soft",
            "nproc_hard",
            "kernel_release",
            "kernel_version",
            "kernel_machine",
        ] {
            if sample["globals"][key] != samples[0]["globals"][key] {
                return Err("pids-global-custody");
            }
        }
    }
    for (index, _) in first_controllers.iter().enumerate() {
        for phase in 1..4 {
            let previous = &samples[phase - 1]["attribution"]["controllers"][index];
            let current = &samples[phase]["attribution"]["controllers"][index];
            let expected_local = u64::from(finite && index == 0 && phase == 2);
            if unsigned(&current["events_local_max"])?
                .checked_sub(unsigned(&previous["events_local_max"])?)
                != Some(expected_local)
            {
                return Err("pids-enforcer");
            }
            if index <= outer {
                let expected_tree = u64::from(finite && phase == 2);
                let delta = unsigned(&current["events_max"])?
                    .checked_sub(unsigned(&previous["events_max"])?)
                    .ok_or("pids-enforcer")?;
                if (index == 0 && delta != expected_tree) || (index != 0 && delta < expected_tree) {
                    return Err("pids-enforcer");
                }
            } else if unsigned(&current["events_max"])? < unsigned(&previous["events_max"])? {
                return Err("pids-enforcer");
            }
        }
    }
    Ok(
        json!({"slot":slot,"worker_events":events,"source_samples":samples,"controlled_limit":maximum,"effect":"enforced_with_controls_unadmitted"}),
    )
}

fn validate_outer_owner_state(raw: &Value, id: &str, run: &str) -> PidsResult<()> {
    // outer_context_observation already binds the selected actor's exact CID,
    // name, image, resources and private socket. Corroborate its canonical outer
    // owner here; LABEL belongs only to the six inner PIDs experiment fixtures.
    if raw["Id"] != id
        || raw["State"]["Running"] != true
        || raw["State"]["Restarting"] != false
        || raw["State"]["Paused"] != false
        || raw["Config"]["Labels"][OWNER] != run
        || raw["RestartCount"].as_u64() != Some(0)
    {
        return Err("pids-outer");
    }
    Ok(())
}

impl OuterIdentity {
    fn acquire(run: &HealthRun, cleanup: bool) -> PidsResult<Self> {
        // This executes the original selected actor's canonical exact-CID
        // inspection now. It never accepts a serialized snapshot or a PID flag.
        let (projection, raw) = outer_context_observation(run, cleanup);
        let id = required("NATIVE_OUTER_CONTAINER_ID");
        let pid = raw["State"]["Pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or("pids-outer")?;
        let started_at = raw["State"]["StartedAt"]
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 64)
            .ok_or("pids-outer")?
            .to_owned();
        let restart_count = raw["RestartCount"].as_u64().ok_or("pids-outer")?;
        let cgroup_namespace = raw["HostConfig"]["CgroupnsMode"]
            .as_str()
            .filter(|mode| *mode == "private")
            .ok_or("pids-cgroup-namespace")?
            .to_owned();
        validate_outer_owner_state(&raw, &id, &run.run)?;
        reserve(run, 1, 0, cleanup)?;
        let mut process = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(format!("/proc/{pid}/stat"))
            .map_err(|_| "pids-proc")?;
        let mut bytes = [0; 4096];
        let size = process.read(&mut bytes).map_err(|_| "pids-proc")?;
        let mut end = [0; 1];
        if size == 0 || process.read(&mut end).map_err(|_| "pids-proc")? != 0 {
            return Err("pids-proc");
        }
        let start = proc_start(&bytes[..size], pid)?;
        Ok(Self {
            projection,
            id,
            pid,
            start,
            started_at,
            restart_count,
            cgroup_namespace,
        })
    }

    fn private_value(&self) -> Value {
        json!({"context":self.projection,"id":self.id,"pid":self.pid,"start_ticks":self.start,
            "runtime_started_at":self.started_at,"restart_count":self.restart_count,"cgroup_namespace_mode":self.cgroup_namespace})
    }
}

struct NativeProducer {
    run: HealthRun,
    target: ProofTarget,
    root: RootChannel,
    original: OuterIdentity,
    confirmed_outer: OuterIdentity,
    deadline_ns: u64,
    observations: Vec<Value>,
    worker: PreparedWorker,
    controller: Option<WorkerControl>,
    nonce: String,
    cleanup_owner: BoundOuterCleanupOwner,
}

impl NativeProducer {
    fn new() -> PidsResult<Self> {
        let mut run = HealthRun::new_for("NATIVE_PIDS_CANDIDATE_SHA", "NATIVE_PIDS_DEADLINE_EPOCH");
        source_outer_backend();
        run.names = SLOTS
            .iter()
            .map(|slot| format!("dl-pids-{}-{slot}", run.run))
            .collect();
        run.ids = vec![None; SLOTS.len()];
        run.attempted = vec![false; SLOTS.len()];
        let target = ProofTarget::new_for("NATIVE_PIDS_PROOF_PATH", "pids-v1.json");
        if std::path::Path::new(&run.socket) != target.directory.join("socket/docker.sock") {
            return Err("pids-socket");
        }
        let worker = PreparedWorker::acquire(&run, &target)?;
        // Read CLOCK_MONOTONIC before taking the original owner's remaining
        // duration: the derived deadline can be earlier, never a renewed window.
        let before = monotonic_ns()?;
        let remaining = u64::try_from(run.remaining().as_nanos()).map_err(|_| "pids-deadline")?;
        let deadline_ns = before.checked_add(remaining).ok_or("pids-deadline")?;
        let original = OuterIdentity::acquire(&run, false)?;
        assert_eq!(required("NATIVE_LIFECYCLE_CLEANUP_OWNER"), CLEANUP_OWNER);
        let cleanup_owner = BoundOuterCleanupOwner {
            snapshot: original.projection.clone(),
        };
        let mut root = RootChannel::launch(&run, &target, deadline_ns)?;
        root.status(&run, "RootBindRuntime", json!({"context":{"backend":required("NATIVE_OUTER_ENGINE"),"candidate":run.candidate,"run":run.run,"lane":run.lane,"outer_id":original.id},
            "outer_pid":original.pid,"outer_start":original.start,"owner_labels":{(LABEL):run.run},"external_source":worker.source.value()}), "pending")?;
        let second = OuterIdentity::acquire(&run, false)?;
        if original != second {
            return Err("pids-outer-changed");
        }
        root.status(&run, "ConfirmRuntime", json!({}), "confirmed")?;
        reserve(&run, 1, 16, false)?;
        let mut random = [0; 16];
        if File::open("/dev/urandom")
            .map_err(|_| "pids-nonce")?
            .read(&mut random)
            .map_err(|_| "pids-nonce")?
            != random.len()
        {
            return Err("pids-nonce");
        }
        let nonce: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            run,
            target,
            root,
            original,
            confirmed_outer: second,
            deadline_ns,
            observations: Vec::new(),
            worker,
            controller: None,
            nonce,
            cleanup_owner,
        })
    }

    fn context(&mut self) -> PidsResult<Value> {
        let (status, version) = self.run.api("GET", "/version", None, false);
        if status != 200 {
            return Err("pids-version");
        }
        let release = version["Version"].as_str().ok_or("pids-version")?;
        if release != required("NATIVE_ENGINE_VERSION") || version["ApiVersion"] != self.run.api {
            return Err("pids-version");
        }
        let release = EngineRelease::new(release.to_owned()).ok_or("pids-version")?;
        let (status, info) = self
            .run
            .api("GET", &format!("/v{}/info", self.run.api), None, false);
        if status != 200 {
            return Err("pids-info");
        }
        let rootless = info["Rootless"] == true
            || info["SecurityOptions"].as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    row.as_str().is_some_and(|row| {
                        row == "name=rootless" || row.starts_with("name=rootless,")
                    })
                })
            });
        if rootless != (self.run.mode == DaemonMode::Rootless)
            || info["PidsLimit"] != true
            || info["CgroupVersion"] != "2"
            || (rootless && info["CgroupDriver"] != "systemd")
            || (!rootless && !matches!(info["CgroupDriver"].as_str(), Some("systemd" | "cgroupfs")))
        {
            return Err("pids-unqualified-destination");
        }
        if self.run.lane.starts_with("debian11-") {
            let package = self.run.outer(
                &[
                    "dpkg-query".into(),
                    "-W".into(),
                    "-f=${Version}".into(),
                    "docker.io".into(),
                ],
                false,
            );
            if package != b"20.10.5+dfsg1-1+deb11u2" {
                return Err("pids-package");
            }
        }
        let observation_id = ObservationId::fresh().map_err(|_| "pids-observation")?;
        let api = ApiVersion::new(
            NonZeroU16::new(1).unwrap(),
            if self.run.api == "1.41" { 41 } else { 56 },
        );
        let scope = CapabilityScope {
            observation_id,
            release: release.clone(),
            api_version: api,
            mode: self.run.mode,
        };
        // These are private native-test request claims, as in the existing
        // lifecycle probes. They drive the renderer under test, never publish a
        // catalogue grant or substitute for the actual effect proof below.
        let capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::Entrypoint,
            Capability::ContainerLabels,
            Capability::BindMount,
            Capability::ContainerInit,
            Capability::PidsLimit,
        ]
        .into_iter()
        .map(|capability| CapabilityFact {
            capability,
            state: CapabilityState::Available,
            provenance: FactProvenance::NativeConformance,
            scope: Some(scope.clone()),
        })
        .collect();
        self.run.engine = release.as_str().to_owned();
        self.run.facts = Some(DaemonFacts {
            observation_id,
            release: Some(release),
            api_version: Some(api),
            minimum_api_version: None,
            mode: self.run.mode,
            capabilities,
        });
        Ok(
            json!({"release":self.run.engine,"advertised_api":self.run.api,"mode":if rootless {"rootless"} else {"rootful"},
            "reported_pids":true,"cgroup_driver":info["CgroupDriver"],"cgroup_version":"2","kernel_identity_source":"held_peer_and_live_worker"}),
        )
    }

    fn prepare_control(&mut self) -> PidsResult<Value> {
        self.worker.check()?;
        let mut controller = WorkerControl::launch(&self.run, &self.nonce, self.deadline_ns)?;
        let response = controller.request(&self.run, "Prepare", json!({}))?;
        closed(
            &response,
            &["version", "sequence", "op", "status", "artifact"],
        )?;
        if response["status"] != "prepared" {
            return Err("pids-controller-status");
        }
        self.worker.bind_copy(&self.run, &response["artifact"])?;
        self.controller = Some(controller);
        Ok(response["artifact"].clone())
    }

    fn create_case(&mut self, index: usize) -> PidsResult<Value> {
        let slot = SLOTS.get(index).copied().ok_or("pids-slot")?;
        if self.run.inspect(&self.run.names[index], false).0 != 404 {
            return Err("pids-fresh-name");
        }
        let maximum: i64 = if slot.ends_with("16") {
            16
        } else if slot.ends_with("64") {
            64
        } else {
            -1
        };
        let worker = format!(
            "/tmp/dockerlens-pids-worker-{}/native-pids-worker",
            self.run.run
        );
        let control = format!("/dockerlens-native/pids-control/{slot}");
        let arguments = vec![
            slot.to_owned(),
            self.nonce.clone(),
            self.deadline_ns.to_string(),
        ];
        let labels = json!({(OWNER):self.run.run,(LABEL):self.run.run,(SLOT_LABEL):slot});
        let literal = json!({"Image":self.run.base,"Entrypoint":["/dl-pids-worker"],"Cmd":arguments,"Labels":labels,
            "HostConfig":{"Init":false,"PidsLimit":maximum,"Mounts":[{"Type":"bind","Source":worker,"Target":"/dl-pids-worker","ReadOnly":true},
            {"Type":"bind","Source":control,"Target":"/dl-pids-control","ReadOnly":false}]}});
        self.run.attempted[index] = true;
        let rendered = slot.starts_with("rendered");
        let document;
        let id = if rendered {
            let intent =
                TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
                    reference: ResourceRef::new(1),
                    identity: TargetIdentity::new(self.run.names[index].as_bytes().to_vec())
                        .map_err(|_| "pids-intent")?,
                    image: ImageReference::new(self.run.base.as_bytes().to_vec())
                        .map_err(|_| "pids-intent")?,
                    environment: vec![],
                    ports: vec![],
                    mounts: vec![
                        Mount::bind(
                            worker.as_bytes().to_vec(),
                            b"/dl-pids-worker".to_vec(),
                            true,
                        )
                        .map_err(|_| "pids-intent")?,
                        Mount::bind(
                            control.as_bytes().to_vec(),
                            b"/dl-pids-control".to_vec(),
                            false,
                        )
                        .map_err(|_| "pids-intent")?,
                    ],
                    networks: vec![],
                    entrypoint: ImageCommand::Exec(vec![
                        Argument::new(b"/dl-pids-worker".to_vec()).map_err(|_| "pids-intent")?,
                    ]),
                    command: ImageCommand::Exec(
                        arguments
                            .iter()
                            .map(|arg| Argument::new(arg.as_bytes().to_vec()))
                            .collect::<Result<_, _>>()
                            .map_err(|_| "pids-intent")?,
                    ),
                    healthcheck: None,
                    restart: None,
                    settings: ContainerSettings {
                        labels: [
                            (OWNER, self.run.run.as_str()),
                            (LABEL, self.run.run.as_str()),
                            (SLOT_LABEL, slot),
                        ]
                        .into_iter()
                        .map(|(name, value)| {
                            ContainerLabel::new(name.as_bytes().to_vec(), value.as_bytes().to_vec())
                        })
                        .collect::<Result<_, _>>()
                        .map_err(|_| "pids-intent")?,
                        init: Some(false),
                        pids_limit: Some(if maximum == -1 {
                            PidsLimit::Unlimited
                        } else {
                            PidsLimit::Count(NonZeroU64::new(maximum as u64).unwrap())
                        }),
                        ..ContainerSettings::default()
                    },
                }))])
                .map_err(|_| "pids-intent")?;
            let facts = self.run.facts.as_ref().ok_or("pids-facts")?;
            let graph = DockerPlanner
                .plan(
                    &intent,
                    &ValidatedCapabilities::new(facts).map_err(|_| "pids-facts")?,
                )
                .map_err(|_| "pids-plan")?;
            let artifact = DockerApiRenderer
                .render(&graph)
                .map_err(|_| "pids-render")?;
            document = unique_json(&artifact.complete_bytes().map_err(|_| "pids-render")?)?;
            let path = format!(
                "/v{}/containers/create?name={}",
                self.run.api, self.run.names[index]
            );
            if document["requests"] != json!([{"method":"POST","path":path,"body":literal}]) {
                return Err("pids-independent-literal");
            }
            let expected = if self.run.mode == DaemonMode::Rootless && maximum > 0 {
                json!([{"kind":"rootless_pids","reference":"1","identity":self.run.names[index],"pids_limit":maximum.to_string(),
                    "required_cgroup_driver":"systemd","required_cgroup_version":"2","required_pids_report":true,"delegation":"unverified","enforcement":"unverified"}])
            } else {
                json!([])
            };
            if document["prerequisites"] != expected
                || document["schema_version"]
                    != if expected == json!([]) {
                        json!(1)
                    } else {
                        json!(4)
                    }
            {
                return Err("pids-prerequisite");
            }
            // Applying this exact request is confined to the isolated native
            // conformance experiment; the obligation stays unadmitted until the
            // actual independent controller/effect/cleanup result is complete.
            let (status, created) = self.run.api("POST", &path, Some(&literal), false);
            if status != 201 || !(created["Warnings"].is_null() || created["Warnings"] == json!([]))
            {
                return Err("pids-create");
            }
            created["Id"].as_str().ok_or("pids-created-id")?.to_owned()
        } else {
            let mut args = vec![
                "create".into(),
                "--name".into(),
                self.run.names[index].clone(),
                "--label".into(),
                format!("{OWNER}={}", self.run.run),
                "--label".into(),
                format!("{LABEL}={}", self.run.run),
                "--label".into(),
                format!("{SLOT_LABEL}={slot}"),
                "--pids-limit".into(),
                maximum.to_string(),
                "--init=false".into(),
                "--entrypoint".into(),
                "/dl-pids-worker".into(),
                "--mount".into(),
                format!("type=bind,src={worker},dst=/dl-pids-worker,readonly"),
                "--mount".into(),
                format!("type=bind,src={control},dst=/dl-pids-control"),
                self.run.base.clone(),
            ];
            args.extend(arguments);
            let bytes = docker(&self.run, &args);
            document = json!({"oracle":"independently_authored_cli","pids_limit":maximum,"entrypoint":"/dl-pids-worker","fixed_mounts":2});
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| text.strip_suffix('\n'))
                .ok_or("pids-created-id")?
                .to_owned()
        };
        if !identifier(&id)
            || id == self.original.id
            || self.run.ids.iter().flatten().any(|other| other == &id)
        {
            return Err("pids-created-id");
        }
        bind(&mut self.run, index, &id);
        let (status, actual) = self.run.inspect(&id, false);
        if status != 200
            || !owned(&self.run, &actual, index, Some(&id))
            || actual["State"]["Running"] != false
            || actual["Config"]["Labels"][LABEL] != self.run.run
            || actual["Config"]["Labels"][SLOT_LABEL] != slot
            || actual["HostConfig"]["PidsLimit"] != maximum
            || actual["HostConfig"]["Init"] != false
            || actual["Config"]["Entrypoint"] != json!(["/dl-pids-worker"])
            || actual["Config"]["Cmd"] != json!([slot, self.nonce, self.deadline_ns.to_string()])
            || actual["RestartCount"] != 0
        {
            return Err("pids-configured-fixture");
        }
        Ok(
            json!({"slot":slot,"id":id,"name":self.run.names[index],"pids_limit":maximum,"definition":document}),
        )
    }
}

impl NativeProducer {
    fn sample(&mut self, slot: &str, phase: &str) -> PidsResult<Value> {
        let response =
            self.root
                .request(&self.run, "Sample", json!({"slot":slot,"phase":phase}))?;
        closed(&response, &["version", "sequence", "op", "sample"])?;
        Ok(response["sample"].clone())
    }

    fn event(&mut self, slot: &str, command: &str) -> PidsResult<Value> {
        self.controller
            .as_mut()
            .ok_or("pids-controller")?
            .event(&self.run, slot, command)
    }

    fn capture_effective(&self) -> PidsResult<Value> {
        // Debit the original owner before this independent product acquisition,
        // including conservative header/request transport reservations. The
        // legacy uncharged general HealthRun.context capture is not reused.
        const REQUESTS: usize = 16;
        const BODIES: usize = 256 * 1024;
        const TRANSPORT: usize = REQUESTS * (16384 + 1024);
        reserve(&self.run, REQUESTS, BODIES + TRANSPORT, false)?;
        let ids = self
            .run
            .ids
            .iter()
            .map(|id| NativeId::new(id.clone().ok_or("pids-id")?).ok_or("pids-id"))
            .collect::<PidsResult<Vec<_>>>()?;
        let duration = self
            .run
            .remaining()
            .checked_sub(Duration::from_secs(46))
            .ok_or("pids-deadline")?
            .min(Duration::from_secs(10));
        let capture = acquire(
            &Endpoint::unix_socket(PathBuf::from(&self.run.socket)),
            Selector::ContainerIds(ids),
            Limits {
                max_requests: REQUESTS,
                max_selected_resources: 6,
                max_expansions: 8,
                max_response_bytes: 32768,
                max_total_bytes: BODIES,
                max_elapsed: duration,
            },
            &AtomicBool::new(false),
        )
        .map_err(|_| "pids-acquisition")?;
        if capture.route() != CaptureRoute::ExplicitUnixSocket
            || capture
                .exchanges()
                .iter()
                .any(|exchange| exchange.status().code() != 200)
            || capture.bounds().request_count > REQUESTS
            || capture.bounds().bytes_read > BODIES
        {
            return Err("pids-acquisition");
        }
        let decoded = decode_capture(&capture).map_err(|_| "pids-decode")?;
        if decoded.containers.len() != 6
            || decoded
                .version
                .daemon
                .release
                .as_ref()
                .map(EngineRelease::as_str)
                != Some(self.run.engine.as_str())
        {
            return Err("pids-decode");
        }
        let mut reported = BTreeMap::new();
        for container in &decoded.containers {
            let id = container
                .id
                .value()
                .and_then(|id| std::str::from_utf8(id.as_bytes()).ok())
                .ok_or("pids-decode")?;
            let limit = container
                .runtime
                .pids_limit
                .value()
                .copied()
                .ok_or("pids-decode")?;
            if container.runtime.pids_limit.availability
                != crate::observation::Availability::Present
                || container.runtime.pids_limit.origin != crate::observation::Origin::Effective
                || reported.insert(id.to_owned(), limit).is_some()
            {
                return Err("pids-decode");
            }
        }
        for (index, slot) in SLOTS.iter().enumerate() {
            let id = self.run.ids[index].as_ref().ok_or("pids-id")?;
            let expected = if slot.ends_with("16") {
                16
            } else if slot.ends_with("64") {
                64
            } else {
                -1
            };
            if reported.get(id) != Some(&expected) {
                return Err("pids-decode");
            }
        }
        Ok(
            json!({"route":"explicit_unix_socket","selected_ids":6,"reserved_calls":REQUESTS,"reserved_body_bytes":BODIES,
            "reserved_transport_bytes":TRANSPORT,"actual_requests":capture.bounds().request_count,"actual_body_bytes":capture.bounds().bytes_read,
            "limits":{"max_requests":REQUESTS,"max_selected_resources":6,"max_expansions":8,"max_response_bytes":32768,"max_total_bytes":BODIES,"max_elapsed_seconds":10},
            "decoded_limits":reported,"origin":"effective","scope":"actual_readonly_product_acquisition"}),
        )
    }

    fn measure(&mut self) -> PidsResult<Value> {
        let daemon = self.context()?;
        let copy = self.prepare_control()?;
        let mut definitions = Vec::new();
        for index in 0..SLOTS.len() {
            definitions.push(self.create_case(index)?);
        }
        for id in self.run.ids.iter().flatten() {
            let (status, _) = self.run.api(
                "POST",
                &format!("/v{}/containers/{id}/start", self.run.api),
                None,
                false,
            );
            if status != 204 {
                return Err("pids-start");
            }
        }
        let mut identities = Vec::new();
        for slot in SLOTS {
            identities.push(self.event(slot, "identity")?);
        }
        let slots: serde_json::Map<String, Value> = SLOTS
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                Ok((
                    (*slot).to_owned(),
                    json!(self.run.ids[index].as_ref().ok_or("pids-id")?),
                ))
            })
            .collect::<PidsResult<_>>()?;
        self.root
            .status(&self.run, "LocateBatch", json!({"slots":slots}), "ok")?;
        for (index, slot) in SLOTS.iter().enumerate() {
            let mut events = vec![identities[index].clone(), self.event(slot, "baseline")?];
            let mut samples = vec![self.sample(slot, "before")?];
            events.push(self.event(slot, "attempt")?);
            samples.push(self.sample(slot, "at_limit")?);
            let finite = slot.ends_with("16");
            events.push(self.event(
                slot,
                if finite {
                    "hold-failure"
                } else {
                    "hold-control"
                },
            )?);
            samples.push(self.sample(slot, if finite { "after_failure" } else { "control" })?);
            events.push(self.event(slot, "release")?);
            events.push(self.event(slot, "reuse")?);
            events.push(self.event(slot, "finish")?);
            samples.push(self.sample(slot, "after_release")?);
            let mut case = validate_case(slot, &self.nonce, &events, &samples)?;
            case["definition"] = definitions[index].clone();
            self.observations.push(case);
        }
        let decoded = self.capture_effective()?;
        self.worker.check()?;
        self.root
            .status(&self.run, "SealMeasurements", json!({}), "sealed")?;
        self.controller
            .as_mut()
            .ok_or("pids-controller")?
            .seal(&self.run)?;
        Ok(json!({"daemon":daemon,"artifact_copy":copy,"decoded":decoded}))
    }
}

impl NativeProducer {
    fn stop_completed(&self, index: usize) -> PidsResult<()> {
        let id = self.run.ids[index]
            .as_deref()
            .filter(|id| identifier(id))
            .ok_or("pids-cleanup-id")?;
        let (status, value) = self.run.inspect(id, true);
        if status != 200
            || !owned(&self.run, &value, index, Some(id))
            || value["Config"]["Labels"][LABEL] != self.run.run
            || value["Config"]["Labels"][SLOT_LABEL] != SLOTS[index]
        {
            return Err("pids-cleanup-ownership");
        }
        let prefix = vec![
            "env".into(),
            format!("DOCKER_API_VERSION={}", self.run.api),
            "docker".into(),
            "-H".into(),
            "unix:///dockerlens-native/docker.sock".into(),
        ];
        let mut stop = prefix.clone();
        stop.extend(["stop".into(), "--time".into(), "2".into(), id.to_owned()]);
        let stopped = self.run.outer(&stop, true);
        if stopped != format!("{id}\n").as_bytes() {
            return Err("pids-cleanup-stop");
        }
        let mut wait = prefix;
        wait.extend(["wait".into(), id.to_owned()]);
        if self.run.outer(&wait, true) != b"0\n" {
            return Err("pids-cleanup-worker-exit");
        }
        let (status, value) = self.run.inspect(id, true);
        if status != 200
            || !owned(&self.run, &value, index, Some(id))
            || value["State"]["Running"] != false
            || value["State"]["ExitCode"] != 0
            || value["State"]["OOMKilled"] != false
            || value["RestartCount"] != 0
        {
            return Err("pids-cleanup-worker-exit");
        }
        Ok(())
    }

    fn cleanup_inner(&mut self, completed: bool) -> CleanupDisposition {
        if self.run.attempted.len() != 6
            || self.run.ids.len() != 6
            || self
                .run
                .attempted
                .iter()
                .zip(&self.run.ids)
                .any(|(attempted, id)| *attempted && !id.as_deref().is_some_and(identifier))
        {
            // Unknown create replies authorize only the already-bound lane
            // finalizer, never a new name lookup or a blind inner mutation.
            return CleanupDisposition::OuterTeardownRequired;
        }
        let mut verified = true;
        for index in 0..SLOTS.len() {
            if self.run.attempted[index] && completed {
                verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.stop_completed(index)
                }))
                .is_ok_and(|result| result.is_ok());
            }
            if self.run.attempted[index] {
                verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    remove_container(&mut self.run, index)
                }))
                .unwrap_or(false);
            }
        }
        for _ in 0..2 {
            for index in 0..SLOTS.len() {
                if self.run.attempted[index] {
                    verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.run.ids[index]
                            .as_ref()
                            .is_some_and(|id| self.run.inspect(id, true).0 == 404)
                            && self.run.inspect(&self.run.names[index], true).0 == 404
                    }))
                    .unwrap_or(false);
                }
            }
        }
        if completed && verified {
            verified &= self
                .controller
                .as_mut()
                .is_some_and(|controller| controller.close(&self.run).is_ok());
        } else {
            drop(self.controller.take());
        }
        cleanup_disposition(verified)
    }

    fn finish(&mut self, measured: Value) -> PidsResult<Value> {
        let final_outer = OuterIdentity::acquire(&self.run, true)?;
        if final_outer != self.original {
            return Err("pids-outer-changed");
        }
        let root = self.root.finalize(&self.run)?;
        if root["api"]
            != json!({"inspect_calls_reserved":18,"inspect_body_bytes_reserved":589824,
            "runtime_probe_calls_reserved":1,"runtime_probe_body_bytes_reserved":4096})
        {
            return Err("pids-final-api-ledger");
        }
        if root["source"]["external_reserved"] != self.worker.source.value() {
            return Err("pids-final-source-ledger");
        }
        for key in ["bytes", "reads"] {
            let external = unsigned(&root["source"]["external_reserved"][key])?;
            let native = unsigned(&root["source"]["root_reserved"][key])?;
            let total = unsigned(&root["source"]["total_reserved"][key])?;
            if external.checked_add(native) != Some(total)
                || total > if key == "bytes" { 33554432 } else { 65536 }
            {
                return Err("pids-final-source-ledger");
            }
        }
        if self.run.calls.get() > MAX_CALLS
            || self.run.bytes.get() > MAX_BYTES
            || self.run.remaining() <= Duration::from_secs(1)
        {
            return Err("pids-final-parent-ledger");
        }
        let context = json!({"candidate_sha":self.run.candidate,"run_id":self.run.run,"lane":self.run.lane,"engine_release":self.run.engine,
            "api_version":self.run.api,"mode":if self.run.mode == DaemonMode::Rootless {"rootless"} else {"rootful"},
            "outer_backend":required("NATIVE_OUTER_ENGINE"),"outer_id":self.original.id,"fixture_image":self.run.base,
            "outer":self.original.projection});
        let proof = json!({"schema_version":1,"contract":"pids-v1","scope":"controlled_live_leaf_enforcement_only",
            "capability_admission":[],"catalogue_admission":false,"context":context,"nonce":self.nonce,
            "outer_before":self.original.private_value(),"outer_after_confirmation":self.confirmed_outer.private_value(),"outer_final":final_outer.private_value(),
            "artifact":self.worker.manifest,"measured":measured,"cases":self.observations,"root":root,
            "cleanup":{"containers":"absent","absence_rounds":2,"worker_exits":"finished_then_owner_term_zero","controller":"closed_and_reaped",
            "guest_copy":"removed","source_handles":"closed_before_final_ack","outer":"retained_for_lane_finalizer","outer_teardown_owner":CLEANUP_OWNER},
            "budgets":{"parent_calls":self.run.calls.get(),"parent_captured_and_reserved_bytes":self.run.bytes.get(),"max_calls":MAX_CALLS,"max_bytes":MAX_BYTES,
            "cleanup_calls_reserved":CLEANUP_CALLS,"cleanup_bytes_reserved":CLEANUP_BYTES,"terminal_monotonic_ns":self.deadline_ns,
            "external_source_reserved":self.worker.source.value(),"root_output_bytes":self.root.wire.received,"root_input_bytes":self.root.wire.sent,
            "native_effect_admission":"requires_complete_lane_exit_and_fresh_aggregate"}});
        Ok(proof)
    }
}

#[test]
#[ignore = "requires exact disposable native harness"]
fn live_pids_limits_and_effects_match_engine() {
    eprintln!("DOCKERLENS_NATIVE_CHECK: pids_context");
    let mut producer =
        NativeProducer::new().unwrap_or_else(|error| pids_constructor_refused(error));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| producer.measure()));
    let completed = result.as_ref().is_ok_and(|result| result.is_ok());
    eprintln!("DOCKERLENS_NATIVE_CHECK: pids_cleanup");
    let disposition = producer.cleanup_inner(completed);
    // Disarm the legacy Drop exactly once, preserving the original failing
    // result and requesting only the already-bound lane owner on uncertainty.
    terminal_cleanup(&mut producer.run, &producer.cleanup_owner, disposition);
    let measured = match result {
        Err(error) => {
            std::panic::resume_unwind(error);
        }
        Ok(Err(_phase)) => {
            panic!("private native PIDs observation refused");
        }
        Ok(Ok(value)) => value,
    };
    if disposition != CleanupDisposition::VerifiedAbsent {
        panic!("private native PIDs cleanup unverified");
    }
    let proof = producer
        .finish(measured)
        .unwrap_or_else(|_| panic!("private native PIDs finalization refused"));
    // Other source families keep their original16KiB proof limit. This one
    // bounded private record includes all24 measured snapshots and seven
    // real worker barriers per role; it is never a public capability record.
    producer.target.publish_bounded(&proof, 128 * 1024);
    eprintln!("DOCKERLENS_NATIVE_CHECK: pids_evidence");
}

#[test]
fn pids_constructor_refusal_preserves_only_explicit_static_codes() {
    // Independent literal expectations include prebuild, outer, resource,
    // supervisor and protocol refusals reachable before producer.measure.
    for code in [
        "pids-ancillary",
        "pids-artifact",
        "pids-artifact-source",
        "pids-bootstrap",
        "pids-budget",
        "pids-build-tools",
        "pids-build-tools-raw",
        "pids-capture",
        "pids-cgroup-namespace",
        "pids-child-custody",
        "pids-clock",
        "pids-deadline",
        "pids-eof",
        "pids-frame",
        "pids-frames",
        "pids-input",
        "pids-integer",
        "pids-json",
        "pids-nonce",
        "pids-outer",
        "pids-outer-changed",
        "pids-proc",
        "pids-read",
        "pids-reservation",
        "pids-schema",
        "pids-sequence",
        "pids-shutdown",
        "pids-socket",
        "pids-source-budget",
        "pids-status",
        "pids-supervisor",
        "pids-write",
    ] {
        assert_eq!(pids_constructor_refusal_code(code), code);
        let line = pids_constructor_refusal_diagnostic(code);
        assert_eq!(
            line,
            format!("DOCKERLENS_NATIVE_PIDS_SETUP_REFUSAL: code={code}")
        );
        assert!(line.len() <= 64);
        assert_eq!(line.lines().count(), 1);
        assert!(line.is_ascii());
    }
}

#[test]
fn pids_constructor_refusal_redacts_every_unknown_input_to_one_bounded_line() {
    let expected = "DOCKERLENS_NATIVE_PIDS_SETUP_REFUSAL: code=unclassified";
    for input in [
        "".to_owned(),
        "unrecognized setup error".to_owned(),
        "/tmp/private-owner/socket/docker.sock".to_owned(),
        "source-token=eyJhbGciOiJIUzI1NiJ9.private-signature".to_owned(),
        "private run 123e4567-e89b-12d3-a456-426614174000".to_owned(),
        "io.dockerlens.native-run=protected-owner".to_owned(),
        "pids-secret-protected-owner".to_owned(),
        "pids-version".to_owned(),
        "pids-outer-private-value".to_owned(),
        "pids-outer\nDOCKERLENS_NATIVE_CHECK: pids_evidence".to_owned(),
        "pids-outer\r\nprivate value".to_owned(),
        "pids-outer\0private value".to_owned(),
        "\u{1b}[31mpids-outer\u{1b}[0m".to_owned(),
        "pids-outer ".to_owned(),
        "pids-secret-".repeat(65536),
        "保護された値".to_owned(),
    ] {
        assert_eq!(pids_constructor_refusal_code(&input), "unclassified");
        let line = pids_constructor_refusal_diagnostic(&input);
        assert_eq!(line, expected);
        assert!(line.len() <= 64);
        assert_eq!(line.lines().count(), 1);
        assert!(!line.contains(['\n', '\r', '\0', '\u{1b}']));
    }
}

#[test]
fn pids_constructor_refusal_registry_refuses_malformed_or_widened_schema() {
    let registry = include_str!("native_pids_setup_refusals.txt");
    assert!(pids_constructor_refusal_registry_valid(registry));
    for changed in [
        registry.trim_end().to_owned(),
        registry.replace('\n', "\r\n"),
        registry.replace("pids-write", "pids-status"),
        registry.replace("pids-write", "pids-secret-xxxxxxxxxx"),
        registry.replace("pids-write", "pids--write"),
        registry.replace("pids-write", "pids-write-"),
        registry.replace("pids-write", "pids-WRITE"),
        registry.replace("pids-write", "pids-writé"),
        format!("{registry}pids-z\n"),
        registry.lines().rev().collect::<Vec<_>>().join("\n") + "\n",
    ] {
        assert!(!pids_constructor_refusal_registry_valid(&changed));
    }
}

#[test]
fn pids_constructor_refusal_keeps_the_original_failure() {
    for error in ["pids-cgroup-namespace", "private setup failure"] {
        let failure = std::panic::catch_unwind(|| pids_constructor_refused(error));
        let payload = failure.expect_err("a diagnostic must not turn setup failure into success");
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"private native PIDs setup refused")
        );
    }
}

#[test]
fn pids_outer_owner_state_accepts_canonical_outer_without_inner_label() {
    // Literal fixture facts come from the native coordinator's outer role,
    // independently of the constants and inner-label constructors above.
    let mut outer = json!({
        "Id": "a".repeat(64),
        "State": {"Running": true, "Restarting": false, "Paused": false},
        "RestartCount": 0,
        "Config": {"Labels": {"io.dockerlens.native-run": "outer-owner-fixture"}}
    });
    let id = "a".repeat(64);
    assert_eq!(
        validate_outer_owner_state(&outer, &id, "outer-owner-fixture"),
        Ok(())
    );
    // An unrelated inner-role label must neither be required nor substitute
    // for the canonical outer ownership binding.
    outer["Config"]["Labels"]["io.dockerlens.native-pids"] = json!("different-inner-owner");
    assert_eq!(
        validate_outer_owner_state(&outer, &id, "outer-owner-fixture"),
        Ok(())
    );
}

#[test]
fn pids_outer_owner_state_refuses_wrong_role_key_and_value() {
    let id = "b".repeat(64);
    let outer = json!({
        "Id": id,
        "State": {"Running": true, "Restarting": false, "Paused": false},
        "RestartCount": 0,
        "Config": {"Labels": {"io.dockerlens.native-run": "outer-owner-fixture"}}
    });
    for labels in [
        json!({"io.dockerlens.native-pids": "outer-owner-fixture"}),
        json!({"io.dockerlens.native-pids-slot": "outer-owner-fixture"}),
        json!({"io.dockerlens.native-run-other": "outer-owner-fixture"}),
        json!({"io.dockerlens.native-run": "other-owner", "io.dockerlens.native-pids": "outer-owner-fixture"}),
        json!({"io.dockerlens.native-run": null}),
        json!({"io.dockerlens.native-run": true}),
        json!({}),
        Value::Null,
    ] {
        let mut changed = outer.clone();
        changed["Config"]["Labels"] = labels;
        assert_eq!(
            validate_outer_owner_state(&changed, &id, "outer-owner-fixture"),
            Err("pids-outer")
        );
    }
}

#[test]
fn pids_outer_owner_state_preserves_exact_cid_running_and_restart_guards() {
    let id = "c".repeat(64);
    let outer = json!({
        "Id": id,
        "State": {"Running": true, "Restarting": false, "Paused": false},
        "RestartCount": 0,
        "Config": {"Labels": {"io.dockerlens.native-run": "outer-owner-fixture"}}
    });
    assert_eq!(
        validate_outer_owner_state(&outer, &id, "outer-owner-fixture"),
        Ok(())
    );
    for (pointer, replacement) in [
        ("/Id", json!("d".repeat(64))),
        ("/Id", Value::Null),
        ("/State/Running", json!(false)),
        ("/State/Running", json!("true")),
        ("/State/Restarting", json!(true)),
        ("/State/Paused", json!(true)),
        ("/RestartCount", json!(1)),
        ("/RestartCount", json!(-1)),
        ("/RestartCount", json!(false)),
        ("/RestartCount", Value::Null),
    ] {
        let mut changed = outer.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert_eq!(
            validate_outer_owner_state(&changed, &id, "outer-owner-fixture"),
            Err("pids-outer")
        );
    }
}

#[test]
fn pids_proc_start_is_kernel_tick_identity_not_runtime_wall_clock() {
    let mut fields = vec!["1"; 20];
    fields[0] = "S";
    fields[19] = "12345";
    let bytes = format!("345 (a ) complicated comm) {}\n", fields.join(" "));
    assert_eq!(proc_start(bytes.as_bytes(), 345), Ok(12345));
    assert!(proc_start(bytes.as_bytes(), 346).is_err());
    fields[0] = "Z";
    assert!(proc_start(format!("345 (x) {}", fields.join(" ")).as_bytes(), 345).is_err());
    assert!(proc_start(b"2026-10-25T22:00:00Z", 345).is_err());
}

fn authored_case(slot: &str) -> (Vec<Value>, Vec<Value>) {
    // Hermetic independent expectations, not native observations. Large reader
    // IDs and a three-row hierarchy exercise coordinate and counter semantics.
    let nonce = "0123456789abcdef0123456789abcdef";
    let finite = slot.ends_with("16");
    let count = if finite { 15 } else { 32 };
    let identity = json!({"schema":"dockerlens-pids-worker-v1","case":slot,"nonce":nonce,"phase":"identity","pid":1,"threads":1,
        "rlimit_nproc_soft":32768,"rlimit_nproc_hard":32768,"kernel_sysname":"Linux","kernel_release":"6.17.0-fixture","kernel_version":"#1 independent authored expectation","kernel_machine":"x86_64"});
    let mut events = vec![identity];
    for (position, phase) in [
        "baseline",
        "attempt",
        if finite {
            "hold-failure"
        } else {
            "hold-control"
        },
        "release",
        "reuse",
        "finished",
    ]
    .iter()
    .enumerate()
    {
        let children: Vec<_> = if position == 1 || position == 2 {
            (2..=count + 1).collect()
        } else {
            vec![]
        };
        events.push(json!({"schema":"dockerlens-pids-worker-v1","case":slot,"nonce":nonce,"phase":phase,"pid":1,"threads":1,
            "child_count":children.len(),"children":children,"fork_return":if position == 2 && finite {json!(-1)} else if position == 4 {json!(99)} else {Value::Null},
            "errno":if position == 2 && finite {json!(libc::EAGAIN)} else if position == 4 {json!(0)} else {Value::Null},"eagain":libc::EAGAIN}));
    }
    let maximum = if finite {
        json!(16)
    } else if slot.ends_with("64") {
        json!(64)
    } else {
        json!("max")
    };
    let mut samples = Vec::new();
    for phase in 0..4 {
        let held = phase == 1 || phase == 2;
        let tasks: Vec<_> = if held {
            (1..=count + 1).collect()
        } else {
            vec![1]
        };
        let reader: Vec<_> = tasks
            .iter()
            .map(|pid| json!([45000 + pid, 9_000_000 + pid]))
            .collect();
        let coordinates: Vec<_> = tasks
            .iter()
            .map(|pid| {
                json!([
                    45000 + pid,
                    [45000 + pid, 1000 + pid, pid],
                    [45000 + pid, 1000 + pid, pid]
                ])
            })
            .collect();
        let event = u64::from(finite && phase >= 2);
        let rows: Vec<_> = (0..3).map(|index| {
            let current = if index == 0 {tasks.len() as u64} else {100+tasks.len() as u64};
            let local = if index == 0 {event} else {0};
            json!({"identity":[28,1001+index,77],"maximum":if index == 0 {maximum.clone()} else if index == 1 {json!(512)} else {json!("max")},
                "current":current,"current_samples":[current,current],"events_max":event,"events_samples":[event,event],"events_local_max":local,"events_local_samples":[local,local]})
        }).collect();
        samples.push(json!({"maximum":maximum,"current":tasks.len(),"events_max":event,"tasks":reader,"task_namespace_ids":coordinates,
            "attribution":{"event_semantics":"hierarchical_with_local_enforcer","pids_localevents":false,"complete_chain":true,"outer_index":1,
                "reader_cgroup_namespace":[5,4026531835_u64],"hierarchy_root":{"identity":[28,2,77],"pids_max_present":false,"cgroup_type_present":false,
                "cgroup_events_present":false,"available_pids":true,"mount_root_is_slash":true,"qualification":"root_exempt"},"controllers":rows},
            "globals":{"threads_max":100000,"pid_max":4194304,"total_tasks":700,"total_tasks_samples":[700,700],"sched_policy":0,"nproc_soft":32768,"nproc_hard":32768,
                "kernel_release":"6.17.0-fixture","kernel_version":"#1 independent authored expectation","kernel_machine":"x86_64"}}));
    }
    (events, samples)
}

#[test]
fn pids_effect_reader_requires_owned_fork_local_enforcer_and_higher_controls() {
    for slot in SLOTS {
        let (events, samples) = authored_case(slot);
        assert!(validate_case(slot, "0123456789abcdef0123456789abcdef", &events, &samples).is_ok());
    }
    let (events, samples) = authored_case("cli16");
    for field in ["events_max", "events_local_max"] {
        let mut altered = samples.clone();
        altered[2]["attribution"]["controllers"][0][field] = json!(0);
        assert!(
            validate_case(
                "cli16",
                "0123456789abcdef0123456789abcdef",
                &events,
                &altered
            )
            .is_err()
        );
    }
    let mut changed = events.clone();
    changed[3]["errno"] = json!(libc::ENOMEM);
    assert!(
        validate_case(
            "cli16",
            "0123456789abcdef0123456789abcdef",
            &changed,
            &samples
        )
        .is_err()
    );
    let mut changed = samples.clone();
    changed[2]["attribution"]["controllers"][1]["events_local_max"] = json!(1);
    changed[2]["attribution"]["controllers"][1]["events_local_samples"] = json!([1, 1]);
    assert!(
        validate_case(
            "cli16",
            "0123456789abcdef0123456789abcdef",
            &events,
            &changed
        )
        .is_err()
    );
}

#[test]
fn pids_effect_reader_preserves_endpoint_pairs_without_claiming_a_global_freeze() {
    let (events, mut samples) = authored_case("cli16");
    samples[1]["globals"]["total_tasks_samples"] = json!([701, 703]);
    samples[1]["globals"]["total_tasks"] = json!(703);
    samples[1]["attribution"]["controllers"][1]["current_samples"] = json!([118, 120]);
    samples[1]["attribution"]["controllers"][1]["current"] = json!(120);
    assert!(
        validate_case(
            "cli16",
            "0123456789abcdef0123456789abcdef",
            &events,
            &samples
        )
        .is_ok()
    );
    samples[1]["globals"]["total_tasks"] = json!(701);
    assert!(
        validate_case(
            "cli16",
            "0123456789abcdef0123456789abcdef",
            &events,
            &samples
        )
        .is_err()
    );
}

#[test]
fn pids_effect_reader_rejects_missing_root_exemption_foreign_tasks_and_kernel_mismatch() {
    let (events, samples) = authored_case("rendered16");
    for position in 0..4 {
        let mut changed = samples.clone();
        changed[position]["attribution"]["complete_chain"] = json!(false);
        assert!(
            validate_case(
                "rendered16",
                "0123456789abcdef0123456789abcdef",
                &events,
                &changed
            )
            .is_err()
        );
        let mut changed = samples.clone();
        changed[position]["globals"]["kernel_version"] = json!("other-kernel");
        assert!(
            validate_case(
                "rendered16",
                "0123456789abcdef0123456789abcdef",
                &events,
                &changed
            )
            .is_err()
        );
    }
    let mut changed = samples.clone();
    changed[1]["task_namespace_ids"][1][1][2] = json!(999);
    assert!(
        validate_case(
            "rendered16",
            "0123456789abcdef0123456789abcdef",
            &events,
            &changed
        )
        .is_err()
    );
}

#[test]
fn pids_root_source_command_fixes_privilege_and_absolute_isolated_interpreter() {
    let command = root_source_command(123456789);
    assert_eq!(command.get_program(), "/usr/bin/sudo");
    let arguments: Vec<_> = command.get_args().collect();
    assert_eq!(arguments.len(), 6);
    assert_eq!(arguments[0], "-n");
    assert_eq!(arguments[1], "/usr/bin/python3");
    assert_eq!(arguments[2], "-I");
    assert_eq!(
        PathBuf::from(arguments[3]),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/native-pids-supervisor.py")
    );
    assert_eq!(arguments[4], "supervise");
    assert_eq!(arguments[5], "123456789");
}

#[test]
fn pids_native_gnu_driver_target_keeps_raw_vendor_aliases_without_abi_fallback() {
    for architecture in ["x86_64", "aarch64"] {
        for suffix in [
            "linux-gnu",
            "unknown-linux-gnu",
            "vendor_1.2+3-linux-gnu",
            "suse-linux",
            "redhat-linux",
        ] {
            assert!(native_gnu_driver_target(
                &format!("{architecture}-{suffix}"),
                architecture
            ));
        }
        for suffix in [
            "linux",
            "unknown-linux",
            "suse-linux-musl",
            "linux-gnux32",
            "linux-gnueabi",
            "android-linux-gnu",
            "musl-linux-gnu",
            "uclibc-linux-gnu",
            "unknown-unknown-linux-gnu",
            "-linux-gnu",
            "custom_musl-linux-gnu",
            "custom_MUSL-linux-gnu",
            "custom_uClibc-linux-gnu",
            "custom_Android-linux-gnu",
            "preandroidpost-linux-gnu",
            "véndor-linux-gnu",
        ] {
            assert!(!native_gnu_driver_target(
                &format!("{architecture}-{suffix}"),
                architecture
            ));
        }
        let prefix = format!("{architecture}-");
        let suffix = "-linux-gnu";
        let boundary = format!(
            "{prefix}{}{suffix}",
            "v".repeat(128 - prefix.len() - suffix.len())
        );
        assert_eq!(boundary.len(), 128);
        assert!(native_gnu_driver_target(&boundary, architecture));
        assert!(!native_gnu_driver_target(
            &format!(
                "{prefix}v{}{suffix}",
                "v".repeat(128 - prefix.len() - suffix.len())
            ),
            architecture
        ));
    }
    assert!(!native_gnu_driver_target("aarch64-linux-gnu", "x86_64"));
    assert!(!native_gnu_driver_target("x86_64-linux-gnu", "aarch64"));
}

#[test]
fn pids_copy_io_requires_actual_complete_fixed_chunk_receipt() {
    // Independent literal one-full-chunk-plus-one-byte expectation.
    let expected = json!({"schema":"dockerlens-pids-copy-io-v1","chunk_bytes":65536,
        "reserved_bytes":196613,"reserved_operations":8,
        "read_bytes":131074,"write_bytes":65537,"read_operations":6,
        "write_operations":2,"eof_probes":2});
    assert_eq!(validate_copy_io(&expected, 65537), Ok(()));
    for key in [
        "chunk_bytes",
        "reserved_bytes",
        "reserved_operations",
        "read_bytes",
        "write_bytes",
        "read_operations",
        "write_operations",
        "eof_probes",
    ] {
        let mut changed = expected.clone();
        changed[key] = json!(0);
        assert!(validate_copy_io(&changed, 65537).is_err(), "{key}");
        changed[key] = json!(true);
        assert!(validate_copy_io(&changed, 65537).is_err(), "{key}");
    }
    let mut extra = expected.clone();
    extra["predicted_only"] = json!(true);
    assert!(validate_copy_io(&extra, 65537).is_err());
    assert!(validate_copy_io(&expected, 0).is_err());
}

#[test]
fn pids_wire_json_rejects_duplicate_nested_keys_and_nonintegers() {
    assert!(unique_json(br#"{"a":1,"a":2}"#).is_err());
    assert!(unique_json(br#"{"a":{"b":1,"b":2}}"#).is_err());
    assert!(unique_json(br#"{"a":1.0}"#).is_err());
    assert!(unique_json(br#"{"a":1} trailing"#).is_err());
    assert_eq!(
        unique_json(br#"{"a":[1,true,null,"x"]}"#).unwrap(),
        json!({"a":[1,true,null,"x"]})
    );
}

#[test]
fn pids_wire_rejects_received_rights_and_requires_clean_eof() {
    let (owner, peer) = UnixStream::pair().unwrap();
    let mut wire = RootWire::new(owner, Instant::now() + Duration::from_secs(50)).unwrap();
    peer.set_nonblocking(true).unwrap();
    let file = File::open("/dev/null").unwrap();
    let descriptors = [file.as_fd()];
    let mut space = [MaybeUninit::new(0); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
    assert_eq!(
        sendmsg(
            &peer,
            &[IoSlice::new(b"x")],
            &mut ancillary,
            SendFlags::NOSIGNAL
        )
        .unwrap(),
        1
    );
    let mut data = [0; 1];
    assert_eq!(wire.receive(&mut data), Err("pids-ancillary"));
}
