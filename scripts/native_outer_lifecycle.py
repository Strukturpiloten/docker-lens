"""Unwired, private lifecycle/custody seam; no runtime adapter or proof writer.

RuntimeOps describes normalized, independently acquired observations, NOT Podman
JSON. Only fake operations are supplied by this component. Expected launches and
runtime facts must come from independent reviewed inputs, never the OCI being
checked. This does not establish actual image defaults or native qualification.

The owner must remain alive while future independent consumers use bounded
copies of candidate data. Final publication and those consumers do not exist
here. The caller owns run-directory disposal and any unknown-create recovery.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from functools import wraps
import hashlib
import json
import math
import os
import re
import stat
from typing import Protocol

from native_outer_bootstrap import build_bootstrap_argv, parse_bootstrap_log

OCI_LIMIT = 65536
LOG_WINDOW = 2048
MAX_RUNTIME_CALLS = 16
MAX_IO_CALLS = 4096
MAX_SOURCE_BYTES = 1048576
OWNER_LABEL = "io.dockerlens.native-run"


class LifecycleError(ValueError):
    def __init__(self):
        super().__init__("outer lifecycle custody refused")


def require(condition):
    if not condition:
        raise LifecycleError()


def integer(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def text(value, limit=4096):
    return type(value) is str and 0 < len(value) <= limit and "\0" not in value and len(value.encode("utf-8")) <= limit


def path_parts(path):
    require(text(path) and path.startswith("/") and not path.endswith("/"))
    parts = path[1:].split("/")
    require(1 <= len(parts) <= 64 and all(part not in ("", ".", "..") and len(part.encode()) <= 255 for part in parts))
    return parts


@dataclass(frozen=True, repr=False)
class MountExpectation:
    destination: str
    kind: str
    source: str
    options: tuple

    def wire(self):
        return {"destination": self.destination, "type": self.kind, "source": self.source, "options": list(self.options)}


@dataclass(frozen=True, repr=False)
class LaunchExpectation:
    lane: str
    name: str
    image_ref: str
    image_digest: str
    owner: str
    nonce: str
    original_argv: tuple
    environment: tuple
    uid: int
    gid: int
    additional_gids: tuple
    cwd: str
    standard_mounts: tuple
    user_mounts: tuple
    cgroup_parent: str = "machine.slice"
    resource_extras: tuple = ()


@dataclass(frozen=True, repr=False)
class RuntimeProfile:
    operating_system: str
    rootless: bool
    remote: bool
    podman_version: str
    runtime_name: str
    runtime_version: str
    cgroup_manager: str
    cgroup_version: str


@dataclass(frozen=True, repr=False)
class InspectSnapshot:
    """Normalized fake seam; no assertion about a production inspect wire schema."""
    container_id: str
    name: str
    image_digest: str
    owner: str
    log_driver: str
    log_path: str
    oci_config_path: str
    state: str
    pid: int
    started_at: str | None
    restart_count: int
    restarting: bool
    restored: bool
    restart_policy: str


@dataclass(frozen=True, repr=False)
class CleanupIdentity:
    container_id: str
    name: str
    image_digest: str
    owner: str


class RuntimeOps(Protocol):
    """Future adapter must bound operations and verify cleanup ownership, never names.

    Every deadline is already absolute; adapters cannot renew it. Normalization
    and actual runtime acquisition are future independently reviewed work.
    """
    def create(self, expectation, log_path, deadline): ...
    def initialize(self, container_id, deadline): ...
    def inspect(self, container_id, deadline): ...
    def start(self, container_id, deadline): ...
    def cleanup(self, identity, deadline): ...


@dataclass(frozen=True, repr=False)
class ObjectRecord:
    device: int
    inode: int
    uid: int
    mode: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int


def record(info):
    return ObjectRecord(info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
                        info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode


@dataclass(frozen=True, repr=False)
class FrameReceipt:
    start: int
    uid: int
    namespaces: tuple
    membership: str
    mount: tuple
    controller: tuple


@dataclass(frozen=True, repr=False)
class CandidateContext:
    """Private source-only candidate; deliberately no serialization/status API."""
    profile: RuntimeProfile
    identity: CleanupIdentity
    init_pid: int
    started_at: str
    oci: ObjectRecord
    oci_raw: bytes
    oci_sha256: str
    launch_sha256: str
    log_object: tuple
    frame_prefix: bytes
    frame_sha256: str
    frame: FrameReceipt


class State(Enum):
    NEW = auto()
    CREATED = auto()
    INITIALIZED = auto()
    ARMED = auto()
    STARTED = auto()
    FRAMED = auto()
    FINALIZED = auto()
    POISONED = auto()
    CLOSED = auto()


def phase(*states):
    def decorate(method):
        @wraps(method)
        def guarded(self, *args, **kwargs):
            try:
                require(self.state in states)
                self._checkpoint()
                result = method(self, *args, **kwargs)
                self._checkpoint()
                return result
            except BaseException:
                self._poison()
                raise LifecycleError() from None
        return guarded
    return decorate


class _Chain:
    """Hold every original ancestor; sibling writes must not invalidate dirs."""
    def __init__(self, owner, path):
        self.owner, self.path = owner, path
        parts = path_parts(path)
        self.leaf = parts[-1]
        self.entries = []
        descriptor = owner._open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.entries.append((None, descriptor, directory_identity(owner._io(os.fstat, descriptor))))
        for part in parts[:-1]:
            descriptor = owner._open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            info = owner._io(os.fstat, descriptor)
            require(stat.S_ISDIR(info.st_mode))
            self.entries.append((part, descriptor, directory_identity(info)))
        self.parent = descriptor
        self.recheck()

    def recheck(self):
        previous = None
        for name, descriptor, original in self.entries:
            held = self.owner._io(os.fstat, descriptor)
            named = self.owner._io(os.stat, "/" if name is None else name,
                                   **({"follow_symlinks": False} if previous is None else {"dir_fd": previous, "follow_symlinks": False}))
            require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(named.st_mode))
            require(directory_identity(held) == original == directory_identity(named))
            previous = descriptor


class _HeldOCI:
    def __init__(self, owner, path):
        self.owner = owner
        self.chain = _Chain(owner, path)
        self.fd = owner._open(self.chain.leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.chain.parent)
        self.original = self._metadata()
        self.raw = self._read()
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        self.recheck()

    def _metadata(self):
        held = self.owner._io(os.fstat, self.fd)
        named = self.owner._io(os.stat, self.chain.leaf, dir_fd=self.chain.parent, follow_symlinks=False)
        for info in (held, named):
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1)
            require(info.st_mode & 0o022 == 0 and 1 <= info.st_size <= OCI_LIMIT)
        require(record(held) == record(named))
        return record(held)

    def _read(self):
        raw = self.owner._read(self.fd, OCI_LIMIT + 1)
        require(len(raw) == self.original.size and len(raw) <= OCI_LIMIT)
        return raw

    def recheck(self):
        self.chain.recheck()
        require(self._metadata() == self.original)
        raw = self._read()
        require(raw == self.raw and hashlib.sha256(raw).hexdigest() == self.sha256)
        require(self._metadata() == self.original)


class _HeldLog:
    def __init__(self, owner, path):
        self.owner = owner
        self.chain = _Chain(owner, path)
        require(len(self.chain.entries) >= 3 and self.chain.entries[-1][0] == "diagnostics")
        caller = os.geteuid()
        for _, descriptor, _ in self.chain.entries[-2:]:
            info = owner._io(os.fstat, descriptor)
            require(info.st_uid == caller and stat.S_IMODE(info.st_mode) == 0o700)
        self.fd = owner._open(self.chain.leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                              mode=0o600, dir_fd=self.chain.parent)
        self.last_size = 0
        self.fixed = None
        self.prefix = None
        self.prefix_sha256 = None
        self.frame = None
        self.recheck()
        require(self.last_size == 0)

    def recheck(self):
        self.chain.recheck()
        for info in (self.owner._io(os.fstat, self.fd),
                     self.owner._io(os.stat, self.chain.leaf, dir_fd=self.chain.parent, follow_symlinks=False)):
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1)
            require(stat.S_IMODE(info.st_mode) == 0o600 and integer(info.st_size) and info.st_size >= self.last_size)
            fixed = (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink)
            if self.fixed is None:
                self.fixed = fixed
            require(fixed == self.fixed)
            self.last_size = info.st_size
        if self.prefix is not None:
            raw = self.owner._read(self.fd, len(self.prefix))
            require(raw == self.prefix and hashlib.sha256(raw).hexdigest() == self.prefix_sha256)

    def _decode(self, raw):
        # Select BEFORE decoding: daemon records after the first stdout frame
        # are outside this immutable authority window, including later P records.
        prefix_end = 0
        found = False
        for line in raw.split(b"\n")[:-1]:
            prefix_end += len(line) + 1
            fields = line.split(b" ", 3)
            if len(fields) >= 2 and fields[1] == b"stdout":
                found = True
                break
        require(found)
        prefix = raw[:prefix_end]
        data = parse_bootstrap_log(prefix, self.owner.expectation.nonce)
        receipt = FrameReceipt(data["start"], data["uid"], tuple(data["namespaces"]), data["membership"],
                               tuple(data["mount"]), tuple(data["controller"]))
        require(receipt.uid == self.owner.expectation.uid)
        if self.prefix is not None:
            require(prefix == self.prefix and receipt == self.frame)
        return prefix, receipt

    def capture(self):
        self.recheck()
        self.prefix, self.frame = self._decode(self.owner._read(self.fd, LOG_WINDOW))
        self.prefix_sha256 = hashlib.sha256(self.prefix).hexdigest()
        self.recheck()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def _nonfinite(_value):
    raise LifecycleError()


def _resource_expectations(expectation):
    """Exact independent fields, never an inference about runtime support."""
    sections = {"pids": {"limit": 512}, "memory": {"limit": 4294967296},
                "cpu": {"period": 100000, "quota": 200000}}
    extras = expectation.resource_extras
    require(type(extras) is tuple and len(extras) <= 3)
    seen, count = set(), 0
    for entry in extras:
        require(type(entry) is tuple and len(entry) == 2)
        section, fields = entry
        require(type(section) is str and section in sections and section not in seen)
        seen.add(section)
        require(type(fields) is tuple)
        for field in fields:
            require(type(field) is tuple and len(field) == 2)
            key, value = field
            count += 1
            require(count <= 32 and type(key) is str
                    and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", key) is not None
                    and key not in sections[section])
            require(type(value) is bool or integer(value, -(1 << 63), (1 << 64) - 1)
                    or (type(value) is str and "\0" not in value
                        and len(value.encode("utf-8")) <= 4096))
            sections[section][key] = value
    return sections


def _validate_oci(raw, expectation, container_id):
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_nonfinite)
    require(type(value) is dict)
    process, linux, annotations = (value.get(key) for key in ("process", "linux", "annotations"))
    require(type(process) is dict and type(linux) is dict and type(annotations) is dict)
    args = build_bootstrap_argv(expectation.nonce, list(expectation.original_argv))
    require(type(process.get("args")) is list and process["args"] == args)
    require(type(process.get("env")) is list and process["env"] == list(expectation.environment))
    require(process.get("cwd") == expectation.cwd and process.get("terminal") is False)
    user = process.get("user")
    require(type(user) is dict and set(user) == {"uid", "gid", "additionalGids"})
    require(integer(user["uid"], 0, (1 << 32) - 1) and integer(user["gid"], 0, (1 << 32) - 1))
    require(type(user["additionalGids"]) is list and all(integer(item, 0, (1 << 32) - 1) for item in user["additionalGids"]))
    require(user == {"uid": expectation.uid, "gid": expectation.gid, "additionalGids": list(expectation.additional_gids)})
    require(linux.get("cgroupsPath") == "machine.slice:libpod:" + container_id)
    namespaces = linux.get("namespaces")
    require(type(namespaces) is list and len(namespaces) <= 8)
    seen = set()
    for namespace in namespaces:
        require(type(namespace) is dict and set(namespace) in ({"type"}, {"type", "path"}))
        kind = namespace["type"]
        require(type(kind) is str and kind in {"pid", "mount", "cgroup", "network", "ipc", "uts", "user", "time"} and kind not in seen)
        seen.add(kind)
        if kind in {"pid", "mount", "cgroup"}:
            require(set(namespace) == {"type"})
        elif "path" in namespace:
            path_parts(namespace["path"])
    require({"pid", "mount", "cgroup"} <= seen)
    require(annotations.get("run.oci.systemd.subgroup") == "container")
    require(annotations.get("run.oci.delegate-cgroup", "") == "")
    require(annotations.get("io.kubernetes.cri.container-type") == "sandbox")
    require(all(type(key) is str and type(item) is str for key, item in annotations.items()))
    hooks = value.get("hooks", {})
    require(type(hooks) is dict and all(key in {"prestart", "createRuntime", "createContainer", "startContainer", "poststart", "poststop"}
                                       and type(items) is list and not items for key, items in hooks.items()))
    resources = linux.get("resources")
    require(type(resources) is dict and resources.get("unified", {}) == {} and type(resources.get("unified", {})) is dict)
    for section, expected in _resource_expectations(expectation).items():
        actual = resources.get(section)
        require(type(actual) is dict and set(actual) == set(expected))
        require(all(type(actual[key]) is type(item) and actual[key] == item for key, item in expected.items()))
    expected_mounts = [mount.wire() for mount in expectation.standard_mounts + expectation.user_mounts]
    require(type(value.get("mounts")) is list and value["mounts"] == expected_mounts)


def _started(value):
    require(type(value) is str and 20 <= len(value) <= 35)
    match = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(?:Z|([+-])([01][0-9]|2[0-3]):([0-5][0-9]))", value)
    require(match is not None)
    instant = datetime(*(int(match[index]) for index in range(1, 7)))
    seconds = ((instant.toordinal() - 1) * 86400 + instant.hour * 3600
               + instant.minute * 60 + instant.second)
    offset = 0 if match[8] is None else (int(match[9]) * 60 + int(match[10])) * 60
    if match[8] == "-":
        offset = -offset
    # Compare the instant, retaining all nine fractional digits: datetime's
    # microsecond truncation must not erase a nonzero nanosecond.
    require(seconds - offset != 0 or int(match[7] or "0") != 0)


class LifecycleCustody:
    """Single-use FD owner, not a runtime launcher or publishable proof.

    All deadlines are independently supplied from existing caller budgets. The
    1800-second hard ceiling is not a new allowance: an existing lane watchdog
    may require strictly less. Nothing resets the 180s PIDs/46s cleanup budgets.
    """
    def __init__(self, expectation, profile, ops, log_path, startup_deadline, custody_deadline, cleanup_deadline, clock, cancelled):
        self.state = State.NEW
        self._fds = []
        self._id = None
        self._cleanup_attempted = False
        self.cleanup_obligation = "none"
        self._create_pending = False
        self.runtime_calls = self.io_calls = self.source_bytes = 0
        self.cleanup_calls = 0
        self.expectation, self.profile, self.ops = expectation, profile, ops
        self.log_path = log_path
        self.startup_deadline, self.custody_deadline, self.cleanup_deadline = startup_deadline, custody_deadline, cleanup_deadline
        self.clock, self.cancelled = clock, cancelled
        self._oci = self._log = self._candidate = None
        self._pid = self._started_at = None
        try:
            now = self.clock()
            require(all(type(item) in (int, float) and math.isfinite(item) for item in (now, startup_deadline, custody_deadline, cleanup_deadline)))
            require(0 < startup_deadline - now <= 120 and startup_deadline <= custody_deadline < cleanup_deadline)
            require(cleanup_deadline - now <= 1800)
            self._last_clock = now
            require(type(profile) is RuntimeProfile)
            require(type(profile.rootless) is bool and type(profile.remote) is bool)
            require(all(type(getattr(profile, key)) is str for key in ("operating_system", "podman_version", "runtime_name", "runtime_version", "cgroup_manager", "cgroup_version")))
            require(profile == RuntimeProfile("linux", False, False, "4.9.3", "crun", "1.14.1", "systemd", "v2"))
            self._expectations()
            path_parts(log_path)
            self._checkpoint()
        except BaseException:
            self._poison()
            raise LifecycleError() from None

    def _expectations(self):
        expected = self.expectation
        require(type(expected) is LaunchExpectation and expected.cgroup_parent == "machine.slice")
        require(expected.lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"))
        require(text(expected.name, 128) and text(expected.owner, 128) and text(expected.image_ref, 512))
        require(type(expected.image_digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", expected.image_digest) is not None)
        require(expected.image_ref.endswith("@" + expected.image_digest))
        require(type(expected.original_argv) is tuple)
        build_bootstrap_argv(expected.nonce, list(expected.original_argv))
        require(type(expected.environment) is tuple and len(expected.environment) <= 128)
        names = set()
        total = 0
        for variable in expected.environment:
            require(text(variable, 4096) and "=" in variable)
            name = variable.split("=", 1)[0]
            require(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) is not None and name not in names)
            names.add(name)
            total += len(variable.encode())
        require(total <= 16384)
        require(integer(expected.uid, 0, (1 << 32) - 1) and integer(expected.gid, 0, (1 << 32) - 1))
        require(type(expected.additional_gids) is tuple and len(expected.additional_gids) <= 32
                and all(integer(item, 0, (1 << 32) - 1) for item in expected.additional_gids))
        path_parts(expected.cwd) if expected.cwd != "/" else None
        require(type(expected.standard_mounts) is tuple and 1 <= len(expected.standard_mounts) <= 16)
        require(type(expected.user_mounts) is tuple and len(expected.user_mounts) == 2)
        destinations = set()
        for mount in expected.standard_mounts + expected.user_mounts:
            require(type(mount) is MountExpectation)
            path_parts(mount.destination)
            require(mount.destination not in destinations and text(mount.kind, 32) and text(mount.source))
            destinations.add(mount.destination)
            require(type(mount.options) is tuple and len(mount.options) <= 32 and all(text(option, 256) for option in mount.options))
        storage = "/home/docker/.local/share/docker" if expected.lane.endswith("rootless") else "/var/lib/docker"
        require({mount.destination for mount in expected.user_mounts} == {storage, "/dockerlens-native"})
        require(all(mount.kind == "bind" and mount.source.startswith("/") for mount in expected.user_mounts))
        _resource_expectations(expected)

    def _checkpoint(self):
        now = self.clock()
        require(type(now) in (int, float) and math.isfinite(now) and self._last_clock <= now < self._deadline())
        self._last_clock = now
        require(self.cancelled() is False)

    def _deadline(self):
        return self.custody_deadline if self.state in (State.FRAMED, State.FINALIZED) else self.startup_deadline

    def _io(self, operation, *args, **kwargs):
        self._checkpoint()
        self.io_calls += 1
        require(self.io_calls <= MAX_IO_CALLS)
        result = operation(*args, **kwargs)
        self._checkpoint()
        return result

    def _open(self, path, flags, mode=0o777, **kwargs):
        self._checkpoint()
        self.io_calls += 1
        require(self.io_calls <= MAX_IO_CALLS)
        descriptor = os.open(path, flags, mode, **kwargs)
        self._fds.append(descriptor)  # Adopt before the post-call cancellation check.
        self._checkpoint()
        return descriptor

    def _read(self, descriptor, size):
        self._checkpoint()
        self.source_bytes += size
        require(self.source_bytes <= MAX_SOURCE_BYTES)
        return self._io(os.pread, descriptor, size, 0)

    def _operation(self, name, *args):
        self._checkpoint()
        self.runtime_calls += 1
        require(self.runtime_calls <= MAX_RUNTIME_CALLS)
        if name == "create":
            self._create_pending = True
        result = getattr(self.ops, name)(*args, self._deadline())
        if name == "create":
            if type(result) is str and re.fullmatch(r"[0-9a-f]{64}", result):
                self._id = result
                self._create_pending = False
            else:
                raise LifecycleError()
        elif name in ("initialize", "start"):
            require(result is None)
        self._checkpoint()
        return result

    def _inspect(self, running):
        snapshot = self._operation("inspect", self._id)
        require(type(snapshot) is InspectSnapshot)
        require(all(type(getattr(snapshot, key)) is str for key in ("container_id", "name", "image_digest", "owner", "log_driver", "log_path", "oci_config_path", "state", "restart_policy")))
        expected = self.expectation
        require((snapshot.container_id, snapshot.name, snapshot.image_digest, snapshot.owner,
                 snapshot.log_driver, snapshot.log_path) ==
                (self._id, expected.name, expected.image_digest, expected.owner, "k8s-file", self.log_path))
        require(integer(snapshot.pid, 1, 4194304) and type(snapshot.restart_count) is int and snapshot.restart_count == 0)
        require(snapshot.restarting is False and snapshot.restored is False and snapshot.restart_policy == "no")
        path_parts(snapshot.oci_config_path)
        if self._oci is not None:
            require(snapshot.oci_config_path == self._oci.chain.path)
        if self._pid is not None:
            require(snapshot.pid == self._pid)
        if running:
            require(snapshot.state == "running")
            _started(snapshot.started_at)
            if self._started_at is not None:
                require(snapshot.started_at == self._started_at)
        else:
            require(snapshot.state == "created" and snapshot.started_at is None)
        return snapshot

    @phase(State.NEW)
    def create(self):
        self._log = _HeldLog(self, self.log_path)
        self._operation("create", self.expectation, self.log_path)
        self.state = State.CREATED

    @phase(State.CREATED)
    def initialize(self):
        self._operation("initialize", self._id)
        snapshot = self._inspect(False)
        self._pid = snapshot.pid
        self._oci = _HeldOCI(self, snapshot.oci_config_path)
        _validate_oci(self._oci.raw, self.expectation, self._id)
        self.state = State.INITIALIZED

    @phase(State.INITIALIZED)
    def arm(self):
        self._oci.recheck()
        self._log.recheck()
        require(self._log.last_size == 0)
        self.state = State.ARMED

    @phase(State.ARMED)
    def start(self):
        self._inspect(False)
        self._oci.recheck()
        self._log.recheck()
        require(self._log.last_size == 0)
        self._operation("start", self._id)
        snapshot = self._inspect(True)
        self._started_at = snapshot.started_at
        self._oci.recheck()
        self.state = State.STARTED

    @phase(State.STARTED)
    def capture_frame(self):
        self._log.capture()
        self._checkpoint()  # Frame acquisition must finish within startup allowance.
        self.state = State.FRAMED

    @phase(State.FRAMED, State.FINALIZED)
    def final_recheck(self):
        self._inspect(True)
        self._oci.recheck()
        self._log.recheck()
        require(self._log.prefix is not None)
        identity = CleanupIdentity(self._id, self.expectation.name, self.expectation.image_digest, self.expectation.owner)
        launch = (tuple(build_bootstrap_argv(self.expectation.nonce, list(self.expectation.original_argv))),
                  self.expectation.environment, self.expectation.uid, self.expectation.gid,
                  self.expectation.additional_gids, self.expectation.cwd)
        self._candidate = CandidateContext(self.profile, identity, self._pid, self._started_at,
                                            self._oci.original, self._oci.raw, self._oci.sha256,
                                            hashlib.sha256(json.dumps(launch, separators=(",", ":")).encode()).hexdigest(),
                                            self._log.fixed, self._log.prefix, hashlib.sha256(self._log.prefix).hexdigest(), self._log.frame)
        self.state = State.FINALIZED

    @phase(State.FINALIZED)
    def candidate_context(self):
        self.final_recheck()
        return self._candidate

    def _dispose(self):
        for descriptor in reversed(self._fds):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._fds.clear()
        if self._create_pending:
            self.cleanup_obligation = "unknown_create"
        if self._id is not None and not self._cleanup_attempted:
            self._cleanup_attempted = True
            self.cleanup_obligation = "unverified"
            try:
                now = self.clock()
                require(type(now) in (int, float) and math.isfinite(now) and self._last_clock <= now < self.cleanup_deadline)
                identity = CleanupIdentity(self._id, self.expectation.name, self.expectation.image_digest, self.expectation.owner)
                self.cleanup_calls += 1
                require(self.ops.cleanup(identity, self.cleanup_deadline) is None)
                after = self.clock()
                require(type(after) in (int, float) and math.isfinite(after) and now <= after < self.cleanup_deadline)
                self.cleanup_obligation = "none"
            except BaseException:
                pass

    def _poison(self):
        self.state = State.POISONED
        self._candidate = None
        self._dispose()

    def close(self):
        self._dispose()
        self._candidate = None
        if self.state is not State.POISONED:
            self.state = State.CLOSED

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
