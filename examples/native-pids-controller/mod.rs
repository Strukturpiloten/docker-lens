//! Fixed outer-guest FIFO controller for the same static native witness.
//! No fork, command execution, runtime API, path option or cgroup write exists.

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

const ROOT: &str = "/dockerlens-native/pids-control";
const SLOTS: [&str; 6] = [
    "cli16",
    "cli64",
    "cli_unlimited",
    "rendered16",
    "rendered64",
    "rendered_unlimited",
];
const LINE: usize = 4096;
const BYTES: usize = 65536;
const RESERVE_NS: u64 = 46_000_000_000;
const BINARY: usize = 8 * 1024 * 1024;
const COPY_CHUNK: usize = 65536;
static CANCELLED: AtomicBool = AtomicBool::new(false);
type Result<T> = std::result::Result<T, &'static str>;

// This is the guest portion of the original owner's physical-source reserve.
// Charge requested bytes and operations before I/O. Short and interrupted
// operations refuse instead of creating an unbounded retry allowance.
#[derive(Debug)]
struct CopyIo {
    reserved_bytes: u64,
    reserved_operations: u64,
    charged_bytes: u64,
    charged_operations: u64,
    read_bytes: u64,
    write_bytes: u64,
    read_operations: u64,
    write_operations: u64,
    eof_probes: u64,
}

impl CopyIo {
    fn new(size: u64) -> Result<Self> {
        if size == 0 || size > BINARY as u64 {
            return Err("controller-copy-budget");
        }
        Ok(Self {
            reserved_bytes: size * 3 + 2,
            reserved_operations: size.div_ceil(COPY_CHUNK as u64) * 3 + 2,
            charged_bytes: 0,
            charged_operations: 0,
            read_bytes: 0,
            write_bytes: 0,
            read_operations: 0,
            write_operations: 0,
            eof_probes: 0,
        })
    }

    fn charge(&mut self, size: usize) -> Result<()> {
        if size == 0 || size > COPY_CHUNK {
            return Err("controller-copy-budget");
        }
        let bytes = self.charged_bytes + size as u64;
        let operations = self.charged_operations + 1;
        if bytes > self.reserved_bytes || operations > self.reserved_operations {
            return Err("controller-copy-budget");
        }
        self.charged_bytes = bytes;
        self.charged_operations = operations;
        Ok(())
    }

    fn read(&mut self, source: &mut impl Read, part: &mut [u8]) -> Result<()> {
        self.charge(part.len())?;
        self.read_operations += 1;
        let count = source.read(part).map_err(|_| "controller-copy-io")?;
        self.read_bytes += count as u64;
        if count != part.len() {
            return Err("controller-copy-io");
        }
        Ok(())
    }

    fn write(&mut self, destination: &mut impl Write, part: &[u8]) -> Result<()> {
        self.charge(part.len())?;
        self.write_operations += 1;
        let count = destination.write(part).map_err(|_| "controller-copy-io")?;
        self.write_bytes += count as u64;
        if count != part.len() {
            return Err("controller-copy-io");
        }
        Ok(())
    }

    fn eof(&mut self, source: &mut impl Read) -> Result<()> {
        self.charge(1)?;
        self.read_operations += 1;
        let count = source.read(&mut [0]).map_err(|_| "controller-copy-io")?;
        self.read_bytes += count as u64;
        if count != 0 {
            return Err("controller-copy-io");
        }
        self.eof_probes += 1;
        Ok(())
    }

    fn receipt(&self, size: u64) -> Result<Value> {
        let chunks = size.div_ceil(COPY_CHUNK as u64);
        if self.charged_bytes != self.reserved_bytes
            || self.charged_operations != self.reserved_operations
            || self.read_bytes != 2 * size
            || self.write_bytes != size
            || self.read_operations != 2 * chunks + 2
            || self.write_operations != chunks
            || self.eof_probes != 2
        {
            return Err("controller-copy-budget");
        }
        Ok(
            json!({"schema":"dockerlens-pids-copy-io-v1","chunk_bytes":COPY_CHUNK,
            "reserved_bytes":self.reserved_bytes,"reserved_operations":self.reserved_operations,
            "read_bytes":self.read_bytes,"write_bytes":self.write_bytes,
            "read_operations":self.read_operations,"write_operations":self.write_operations,
            "eof_probes":self.eof_probes}),
        )
    }
}

extern "C" fn cancelled(_: libc::c_int) {
    CANCELLED.store(true, Ordering::Relaxed);
}

fn now() -> Result<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err("controller-clock");
    }
    u64::try_from(value.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(value.tv_nsec)
                .ok()
                .and_then(|fraction| seconds.checked_add(fraction))
        })
        .ok_or("controller-clock")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
}
fn identity(info: &fs::Metadata) -> Identity {
    Identity {
        device: info.dev(),
        inode: info.ino(),
        mode: info.mode(),
        uid: info.uid(),
        gid: info.gid(),
        links: if info.is_dir() { 0 } else { info.nlink() },
    }
}

fn version(info: &fs::Metadata) -> (Identity, u64, i64, i64, i64, i64) {
    (
        identity(info),
        info.len(),
        info.mtime(),
        info.mtime_nsec(),
        info.ctime(),
        info.ctime_nsec(),
    )
}

fn identity_value(info: &fs::Metadata) -> Value {
    json!({"device":info.dev(),"inode":info.ino(),"uid":info.uid(),"gid":info.gid(),"mode":info.mode() & 0o777,"links":info.nlink()})
}

fn traversable(info: &fs::Metadata, uid: u32) -> bool {
    searchable(info.is_dir(), info.uid(), info.mode(), uid)
}

fn searchable(directory: bool, owner: u32, mode: u32, uid: u32) -> bool {
    directory && (uid == 0 || (owner == uid && mode & 0o100 != 0) || mode & 0o001 != 0)
}

fn readonly(descriptor: libc::c_int) -> Result<()> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err("controller-readonly");
    }
    Ok(())
}

struct Created {
    path: PathBuf,
    expected: Identity,
    held: Option<File>,
}
struct Pair {
    commands: usize,
    events: usize,
    phase: usize,
}
struct Controller {
    run: String,
    nonce: String,
    uid: u32,
    work: u64,
    terminal: u64,
    sealed: bool,
    artifact: Option<Value>,
    created: Vec<Created>,
    pairs: BTreeMap<String, Pair>,
    bytes: usize,
    sequence: u64,
    closed: bool,
}

enum Request {
    Prepare {
        version: u64,
        sequence: u64,
    },
    Event {
        version: u64,
        sequence: u64,
        slot: String,
        command: String,
    },
    Close {
        version: u64,
        sequence: u64,
    },
    Seal {
        version: u64,
        sequence: u64,
    },
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let WorkerEvent(value) = WorkerEvent::deserialize(deserializer)?;
        let invalid = || <D::Error as serde::de::Error>::custom("closed controller request");
        let version = value["version"].as_u64().ok_or_else(invalid)?;
        let sequence = value["sequence"].as_u64().ok_or_else(invalid)?;
        let operation = value["op"].as_str().ok_or_else(invalid)?;
        let fields: &[&str] = match operation {
            "Prepare" | "Seal" | "Close" => &["version", "sequence", "op"],
            "Event" => &["version", "sequence", "op", "slot", "command"],
            _ => return Err(invalid()),
        };
        let object = value.as_object().ok_or_else(invalid)?;
        if object.len() != fields.len() || fields.iter().any(|name| !object.contains_key(*name)) {
            return Err(invalid());
        }
        match operation {
            "Prepare" => Ok(Self::Prepare { version, sequence }),
            "Close" => Ok(Self::Close { version, sequence }),
            "Seal" => Ok(Self::Seal { version, sequence }),
            "Event" => Ok(Self::Event {
                version,
                sequence,
                slot: value["slot"].as_str().ok_or_else(invalid)?.to_owned(),
                command: value["command"].as_str().ok_or_else(invalid)?.to_owned(),
            }),
            _ => Err(invalid()),
        }
    }
}

// Worker output is flat except an integer children array. Retain duplicate-key
// refusal before parsing away any syntax, so malformed native output is never
// normalized into an apparently valid event for the independent owner reader.
struct WorkerEvent(Value);
impl<'de> Deserialize<'de> for WorkerEvent {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = WorkerEvent;
            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("one flat worker event")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate event field"));
                    }
                    let value: Value = map.next_value()?;
                    if value.is_object()
                        || value
                            .as_array()
                            .is_some_and(|items| items.iter().any(|item| item.as_u64().is_none()))
                        || value.as_number().is_some_and(|number| number.is_f64())
                    {
                        return Err(serde::de::Error::custom("non-flat event"));
                    }
                    values.insert(key, value);
                }
                Ok(WorkerEvent(Value::Object(values)))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

impl Controller {
    fn new(args: &[String]) -> Result<Self> {
        if args.len() != 5
            || args[0] != "serve"
            || args[1].len() != 8
            || !args[1].bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !matches!(
                args[2].as_str(),
                "debian11-rootful" | "debian11-rootless" | "upstream-rootful" | "upstream-rootless"
            )
            || args[3].len() != 32
            || !args[3]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("controller-arguments");
        }
        if args[4].is_empty()
            || args[4].starts_with('0')
            || !args[4].bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("controller-deadline");
        }
        let terminal = args[4].parse::<u64>().map_err(|_| "controller-deadline")?;
        let remaining = terminal.checked_sub(now()?).ok_or("controller-deadline")?;
        if remaining <= RESERVE_NS || remaining > 180_000_000_000 {
            return Err("controller-deadline");
        }
        Ok(Self {
            run: args[1].clone(),
            nonce: args[3].clone(),
            uid: if args[2].ends_with("rootless") {
                1000
            } else {
                0
            },
            work: terminal - RESERVE_NS,
            terminal,
            sealed: false,
            artifact: None,
            created: Vec::new(),
            pairs: BTreeMap::new(),
            bytes: 0,
            sequence: 0,
            closed: false,
        })
    }

    fn active(&self) -> Result<()> {
        let cutoff = if self.sealed {
            self.terminal - 2_000_000_000
        } else {
            self.work
        };
        if CANCELLED.load(Ordering::Relaxed) || now()? >= cutoff {
            Err("controller-deadline")
        } else {
            Ok(())
        }
    }

    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self.bytes.checked_add(bytes).ok_or("controller-bytes")?;
        if self.bytes > BYTES {
            return Err("controller-bytes");
        }
        Ok(())
    }

    fn check(&self) -> Result<()> {
        self.active()?;
        for created in &self.created {
            if identity(&fs::symlink_metadata(&created.path).map_err(|_| "controller-custody")?)
                != created.expected
                || created.held.as_ref().is_some_and(|held| {
                    !held
                        .metadata()
                        .is_ok_and(|actual| identity(&actual) == created.expected)
                })
            {
                return Err("controller-custody");
            }
        }
        Ok(())
    }

    fn record(&mut self, path: PathBuf) -> Result<usize> {
        let expected = identity(&fs::symlink_metadata(&path).map_err(|_| "controller-custody")?);
        self.created.push(Created {
            path,
            expected,
            held: None,
        });
        Ok(self.created.len() - 1)
    }

    fn prepare(&mut self) -> Result<()> {
        self.active()?;
        if !self.created.is_empty() {
            return Err("controller-sequence");
        }
        for path in ["/", "/dockerlens-native"] {
            if !fs::symlink_metadata(path).is_ok_and(|info| info.is_dir()) {
                return Err("controller-root");
            }
        }
        let base = fs::symlink_metadata("/dockerlens-native").map_err(|_| "controller-root")?;
        if !traversable(&base, self.uid) {
            return Err("controller-root");
        }
        self.directory(PathBuf::from(ROOT))?;
        self.copy_worker()?;
        for slot in SLOTS {
            self.active()?;
            let directory = PathBuf::from(ROOT).join(slot);
            let parent = self.directory(directory.clone())?;
            let descriptor = self.created[parent]
                .held
                .as_ref()
                .ok_or("controller-open")?
                .as_raw_fd();
            let mut indices = Vec::new();
            for name in ["commands", "events"] {
                let path = directory.join(name);
                let c_name = CString::new(name).map_err(|_| "controller-path")?;
                if unsafe { libc::mkfifoat(descriptor, c_name.as_ptr(), 0o600) } != 0 {
                    return Err("controller-create");
                }
                let index = self.record(path.clone())?;
                let held = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&path)
                    .map_err(|_| "controller-open")?;
                self.created[index].held = Some(held);
                let held = self.created[index].held.as_ref().unwrap();
                if unsafe { libc::fchown(held.as_raw_fd(), self.uid, self.uid) } != 0 {
                    return Err("controller-owner");
                }
                let info = held.metadata().map_err(|_| "controller-custody")?;
                if !info.file_type().is_fifo()
                    || info.nlink() != 1
                    || info.mode() & 0o777 != 0o600
                    || info.uid() != self.uid
                {
                    return Err("controller-custody");
                }
                self.created[index].expected = identity(&info);
                indices.push(index);
            }
            self.pairs.insert(
                slot.into(),
                Pair {
                    commands: indices[0],
                    events: indices[1],
                    phase: 0,
                },
            );
        }
        self.check()
    }

    fn directory(&mut self, path: PathBuf) -> Result<usize> {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| "controller-create")?;
        let index = self.record(path.clone())?;
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|_| "controller-open")?;
        self.created[index].held = Some(held);
        let held = self.created[index].held.as_ref().ok_or("controller-open")?;
        if unsafe { libc::fchown(held.as_raw_fd(), self.uid, self.uid) } != 0 {
            return Err("controller-owner");
        }
        let info = held.metadata().map_err(|_| "controller-custody")?;
        if !info.is_dir()
            || info.mode() & 0o777 != 0o700
            || info.uid() != self.uid
            || info.gid() != self.uid
        {
            return Err("controller-owner");
        }
        self.created[index].expected = identity(&info);
        Ok(index)
    }

    fn copy_worker(&mut self) -> Result<()> {
        self.active()?;
        // This one fixed magic-link is the already executing static witness,
        // never an input path or a dynamically selected executable.
        let mut source = File::open("/proc/self/exe").map_err(|_| "controller-binary")?;
        let before = source.metadata().map_err(|_| "controller-binary")?;
        if !before.is_file()
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > BINARY as u64
            || before.mode() & 0o777 != 0o700
        {
            return Err("controller-binary");
        }
        let mut io = CopyIo::new(before.len())?;
        let mut bytes = vec![0; before.len() as usize];
        for part in bytes.chunks_mut(COPY_CHUNK) {
            self.active()?;
            io.read(&mut source, part)?;
        }
        io.eof(&mut source)?;
        let after = source.metadata().map_err(|_| "controller-binary")?;
        if version(&before) != version(&after) || bytes.len() as u64 != before.len() {
            return Err("controller-binary");
        }
        self.active()?;
        let tmp = fs::symlink_metadata("/tmp").map_err(|_| "controller-binary")?;
        if !tmp.is_dir() || !traversable(&tmp, self.uid) {
            return Err("controller-binary");
        }
        let directory = PathBuf::from(format!("/tmp/dockerlens-pids-worker-{}", self.run));
        self.directory(directory.clone())?;
        let path = directory.join("native-pids-worker");
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| "controller-binary")?;
        let index = self.record(path.clone())?;
        self.created[index].held = Some(held);
        let held = self.created[index]
            .held
            .as_mut()
            .ok_or("controller-binary")?;
        for part in bytes.chunks(COPY_CHUNK) {
            io.write(held, part)?;
        }
        held.sync_all().map_err(|_| "controller-binary")?;
        if unsafe { libc::fchown(held.as_raw_fd(), self.uid, self.uid) } != 0 {
            return Err("controller-owner");
        }
        let info = held.metadata().map_err(|_| "controller-binary")?;
        if !info.is_file()
            || info.nlink() != 1
            || info.uid() != self.uid
            || info.gid() != self.uid
            || info.mode() & 0o777 != 0o700
            || info.len() != before.len()
        {
            return Err("controller-binary");
        }
        held.seek(SeekFrom::Start(0))
            .map_err(|_| "controller-binary")?;
        let mut actual = vec![0; before.len() as usize];
        for part in actual.chunks_mut(COPY_CHUNK) {
            io.read(held, part)?;
        }
        io.eof(held)?;
        if actual != bytes
            || version(&info) != version(&held.metadata().map_err(|_| "controller-binary")?)
        {
            return Err("controller-binary");
        }
        // A retained writable opener makes Linux execve fail ETXTBSY, even
        // through a read-only bind mount. Close it before preparing any worker,
        // then retain only a no-follow read-only handle to the same version.
        let writer = self.created[index].held.take().ok_or("controller-binary")?;
        let raw = std::os::fd::IntoRawFd::into_raw_fd(std::os::fd::OwnedFd::from(writer));
        if unsafe { libc::close(raw) } != 0 {
            return Err("controller-binary");
        }
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|_| "controller-binary")?;
        let reopened = held.metadata().map_err(|_| "controller-binary")?;
        let named = fs::symlink_metadata(&path).map_err(|_| "controller-binary")?;
        if version(&info) != version(&reopened) || version(&reopened) != version(&named) {
            return Err("controller-binary");
        }
        readonly(held.as_raw_fd())?;
        self.created[index].held = Some(held);
        self.created[index].expected = identity(&reopened);
        let digest = Sha256::digest(&actual);
        let hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        self.artifact = Some(
            json!({"path":path,"size":actual.len(),"sha256":hash,"io":io.receipt(before.len())?,
            "source":identity_value(&before),"copy":identity_value(&info),"directory_uid":self.uid,"directory_mode":448}),
        );
        self.active()?;
        self.check()
    }

    fn wait(&self, descriptor: libc::c_int, events: libc::c_short) -> Result<()> {
        loop {
            self.active()?;
            let mut poll = libc::pollfd {
                fd: descriptor,
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut poll, 1, 10) };
            if result < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err("controller-poll");
            }
            if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err("controller-poll");
            }
            if poll.revents & (events | libc::POLLHUP) != 0 {
                return Ok(());
            }
        }
    }

    fn read_line(&mut self, descriptor: libc::c_int) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        loop {
            self.wait(descriptor, libc::POLLIN)?;
            let mut part = [0u8; LINE + 1];
            let result = unsafe { libc::read(descriptor, part.as_mut_ptr().cast(), part.len()) };
            if result <= 0 {
                if result < 0
                    && matches!(
                        std::io::Error::last_os_error().kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    )
                {
                    continue;
                }
                return Err("controller-read");
            }
            let size = usize::try_from(result).map_err(|_| "controller-read")?;
            self.charge(size)?;
            bytes.extend_from_slice(&part[..size]);
            if bytes.len() > LINE {
                return Err("controller-line");
            }
            if bytes.contains(&b'\n') {
                if !bytes.ends_with(b"\n")
                    || bytes.iter().filter(|&&byte| byte == b'\n').count() != 1
                {
                    return Err("controller-line");
                }
                return Ok(bytes);
            }
        }
    }

    fn write_line(&mut self, descriptor: libc::c_int, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > LINE {
            return Err("controller-line");
        }
        self.charge(bytes.len())?;
        self.wait(descriptor, libc::POLLOUT)?;
        // Every FIFO message fits PIPE_BUF; a partial committed command is a
        // refusal, never retransmitted into a second worker action.
        if unsafe { libc::write(descriptor, bytes.as_ptr().cast(), bytes.len()) }
            != bytes.len() as isize
        {
            return Err("controller-write");
        }
        Ok(())
    }

    fn event(&mut self, slot: &str, command: &str) -> Result<Value> {
        self.check()?;
        let pair = self.pairs.get(slot).ok_or("controller-slot")?;
        let phases = [
            "identity",
            "baseline",
            "attempt",
            if slot.ends_with("16") {
                "hold-failure"
            } else {
                "hold-control"
            },
            "release",
            "reuse",
            "finish",
        ];
        if phases.get(pair.phase).copied() != Some(command) {
            return Err("controller-sequence");
        }
        let commands = self.created[pair.commands]
            .held
            .as_ref()
            .ok_or("controller-open")?
            .as_raw_fd();
        let events = self.created[pair.events]
            .held
            .as_ref()
            .ok_or("controller-open")?
            .as_raw_fd();
        if command != "identity" {
            let mut raw = serde_json::to_vec(&json!({"command":command,"nonce":self.nonce}))
                .map_err(|_| "controller-json")?;
            raw.push(b'\n');
            self.write_line(commands, &raw)?;
        }
        let raw = self.read_line(events)?;
        let WorkerEvent(value) = serde_json::from_slice(&raw).map_err(|_| "controller-json")?;
        let phase = if command == "finish" {
            "finished"
        } else {
            command
        };
        if value["schema"] != "dockerlens-pids-worker-v1"
            || value["case"] != slot
            || value["nonce"] != self.nonce
            || value["phase"] != phase
        {
            return Err("controller-worker");
        }
        self.check()?;
        self.pairs.get_mut(slot).ok_or("controller-slot")?.phase += 1;
        Ok(value)
    }

    fn response(&mut self, request: Request) -> Result<Value> {
        self.active()?;
        let (version, sequence) = match &request {
            Request::Prepare { version, sequence }
            | Request::Event {
                version, sequence, ..
            }
            | Request::Close { version, sequence }
            | Request::Seal { version, sequence } => (*version, *sequence),
        };
        if version != 1 || sequence != self.sequence + 1 || sequence > 45 {
            return Err("controller-sequence");
        }
        self.sequence = sequence;
        if self.sealed && !matches!(request, Request::Close { .. }) {
            return Err("controller-sequence");
        }
        match request {
            Request::Prepare { .. } => {
                self.prepare()?;
                Ok(
                    json!({"version":1,"sequence":sequence,"op":"Prepare","status":"prepared","artifact":self.artifact}),
                )
            }
            Request::Event { slot, command, .. } => {
                let event = self.event(&slot, &command)?;
                Ok(json!({"version":1,"sequence":sequence,"op":"Event","slot":slot,"event":event}))
            }
            Request::Close { .. } => {
                if !self.sealed
                    || self.pairs.len() != SLOTS.len()
                    || self.pairs.values().any(|pair| pair.phase != 7)
                {
                    return Err("controller-sequence");
                }
                self.check()?;
                self.cleanup()?;
                self.closed = true;
                Ok(json!({"version":1,"sequence":sequence,"op":"Close","status":"closed"}))
            }
            Request::Seal { .. } => {
                if self.pairs.len() != SLOTS.len()
                    || self.pairs.values().any(|pair| pair.phase != 7)
                {
                    return Err("controller-sequence");
                }
                self.check()?;
                self.sealed = true;
                Ok(json!({"version":1,"sequence":sequence,"op":"Seal","status":"sealed"}))
            }
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        let mut failed = false;
        for mut created in self.created.drain(..).rev() {
            // Close every held descriptor before acknowledging cleanup.
            if let Some(held) = created.held.take() {
                let descriptor: std::os::fd::OwnedFd = held.into();
                let raw = std::os::fd::IntoRawFd::into_raw_fd(descriptor);
                if unsafe { libc::close(raw) } != 0 {
                    failed = true;
                }
            }
            match fs::symlink_metadata(&created.path) {
                Ok(actual)
                    if actual.dev() == created.expected.device
                        && actual.ino() == created.expected.inode
                        && actual.mode() & libc::S_IFMT == created.expected.mode & libc::S_IFMT =>
                {
                    let result = if actual.is_dir() {
                        fs::remove_dir(&created.path)
                    } else {
                        fs::remove_file(&created.path)
                    };
                    if result.is_err() {
                        failed = true;
                    }
                }
                _ => failed = true, // preserve replacements, uncertainty is failure
            }
        }
        self.pairs.clear();
        if failed {
            Err("controller-cleanup")
        } else {
            Ok(())
        }
    }
}

impl Controller {
    fn terminal_eof(&self) -> Result<()> {
        loop {
            self.wait(0, libc::POLLIN)?;
            let mut byte = 0u8;
            let result = unsafe { libc::read(0, std::ptr::from_mut(&mut byte).cast(), 1) };
            if result == 0 {
                return Ok(());
            }
            if result < 0
                && matches!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                )
            {
                continue;
            }
            return Err("controller-trailing");
        }
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        if !self.created.is_empty() {
            let _ = self.cleanup();
        }
    }
}

pub fn run(args: &[String]) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getpid() } == 1 {
        return Err("controller-identity");
    }
    let mut controller = Controller::new(args)?;
    let mut handler: libc::sigaction = unsafe { std::mem::zeroed() };
    handler.sa_sigaction = cancelled as *const () as usize;
    unsafe {
        libc::sigemptyset(&mut handler.sa_mask);
    }
    for number in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        if unsafe { libc::sigaction(number, &handler, std::ptr::null_mut()) } != 0 {
            return Err("controller-signals");
        }
    }
    handler.sa_sigaction = libc::SIG_IGN;
    if unsafe { libc::sigaction(libc::SIGPIPE, &handler, std::ptr::null_mut()) } != 0 {
        return Err("controller-signals");
    }
    for descriptor in [0, 1] {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
        {
            return Err("controller-descriptor");
        }
    }
    let result = (|| {
        while !controller.closed {
            let raw = controller.read_line(0)?;
            let request: Request = serde_json::from_slice(&raw).map_err(|_| "controller-json")?;
            let response = controller.response(request)?;
            if controller.closed {
                controller.terminal_eof()?;
            }
            let mut raw = serde_json::to_vec(&response).map_err(|_| "controller-json")?;
            raw.push(b'\n');
            controller.write_line(1, &raw)?;
        }
        Ok(())
    })();
    let cleanup = if controller.created.is_empty() {
        Ok(())
    } else {
        controller.cleanup()
    };
    result.and(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn copy_receipt_counts_requested_eof_and_actual_fixed_chunk_operations() {
        for size in [1, 65536, 65537] {
            let mut io = CopyIo::new(size).unwrap();
            let data = vec![42; size as usize];
            let mut source = std::io::Cursor::new(data.clone());
            let mut copied = Vec::new();
            let mut buffer = vec![0; size as usize];
            for part in buffer.chunks_mut(COPY_CHUNK) {
                io.read(&mut source, part).unwrap();
            }
            io.eof(&mut source).unwrap();
            for part in buffer.chunks(COPY_CHUNK) {
                io.write(&mut copied, part).unwrap();
            }
            let mut source = std::io::Cursor::new(copied);
            for part in buffer.chunks_mut(COPY_CHUNK) {
                io.read(&mut source, part).unwrap();
            }
            io.eof(&mut source).unwrap();
            assert_eq!(buffer, data);
            let receipt = io.receipt(size).unwrap();
            assert_eq!(receipt["reserved_bytes"], size * 3 + 2);
            assert_eq!(receipt["read_bytes"], size * 2);
            assert_eq!(receipt["write_bytes"], size);
            assert!(io.charge(1).is_err());
        }
    }

    #[test]
    fn copy_io_precharges_and_rejects_short_interrupted_and_incomplete_operations() {
        let mut io = CopyIo::new(2).unwrap();
        let mut source = std::io::Cursor::new(vec![1]);
        assert!(io.read(&mut source, &mut [0; 2]).is_err());
        assert_eq!(io.charged_bytes, 2);
        assert_eq!(io.charged_operations, 1);
        assert!(io.receipt(2).is_err());
        struct Interrupted;
        impl Read for Interrupted {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::Interrupted.into())
            }
        }
        let mut io = CopyIo::new(1).unwrap();
        assert!(io.read(&mut Interrupted, &mut [0]).is_err());
        assert_eq!(io.charged_operations, 1);
        assert_eq!(io.read_operations, 1);
        assert_eq!(io.read_bytes, 0);
        assert!(io.eof(&mut std::io::Cursor::new(vec![1])).is_err());
        assert!(CopyIo::new(0).is_err());
        assert!(CopyIo::new(BINARY as u64 + 1).is_err());
    }

    #[test]
    fn retained_executable_descriptor_policy_rejects_writable_opener() {
        let directory = std::env::temp_dir().join(format!(
            "dl-pids-controller-readonly-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("inert-data");
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        assert!(readonly(writer.as_raw_fd()).is_err());
        let expected = identity(&writer.metadata().unwrap());
        drop(writer);
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();
        assert_eq!(identity(&held.metadata().unwrap()), expected);
        assert_eq!(readonly(held.as_raw_fd()), Ok(()));
        drop(held);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
    #[test]
    fn private_rootless_access_requires_every_private_parent_to_have_actual_owner_access() {
        assert!(!searchable(true, 0, 0o700, 1000));
        assert!(searchable(true, 1000, 0o700, 1000));
        assert!(searchable(true, 1001, 0o777, 1000));
        assert!(!searchable(false, 1000, 0o700, 1000));
        assert!(!searchable(true, 1001, 0o700, 1000));
        assert!(searchable(true, 0, 0o700, 0));
    }
    #[test]
    fn typed_controller_requests_reject_duplicates_unknowns_and_null_members() {
        for raw in [
            r#"{"op":"Prepare","version":1,"sequence":1,"slot":null}"#,
            r#"{"op":"Prepare","version":1,"sequence":1,"version":1}"#,
            r#"{"op":"Prepare","op":"Close","version":1,"sequence":1}"#,
            r#"{"op":"Event","version":1,"sequence":1,"slot":"cli16","command":"baseline","extra":0}"#,
            r#"{"op":"Prepare","version":1.0,"sequence":1}"#,
        ] {
            assert!(serde_json::from_str::<Request>(raw).is_err());
        }
        assert!(
            serde_json::from_str::<Request>(r#"{"op":"Prepare","version":1,"sequence":1}"#).is_ok()
        );
    }
    #[test]
    fn worker_event_parser_does_not_normalize_duplicate_or_nested_values() {
        for raw in [
            r#"{"phase":"identity","phase":"baseline"}"#,
            r#"{"children":[[1]]}"#,
            r#"{"x":{"a":1}}"#,
            r#"{"pid":1.0}"#,
        ] {
            assert!(serde_json::from_str::<WorkerEvent>(raw).is_err());
        }
        assert!(serde_json::from_str::<WorkerEvent>(r#"{"children":[2,3],"pid":1}"#).is_ok());
    }
}
