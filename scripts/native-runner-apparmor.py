"""Maintained, disposable-GitHub-runner-only userns prerequisite.

No generic provisioning interface: one profile, one creation-bound guest, finite
root-owned transient state, and no recovery from uncertain policy mutations.
The original caller's root timeout/process group owns every child invocation.
"""

from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

from native_outer_diagnostic_capture import Cancelled, Cancellation, CaptureContext

SCRIPTS = Path(__file__).resolve().parent
ROOT = Path("/run")
OWNER = 0
PARSER = Path("/usr/sbin/apparmor_parser")
ABI = Path("/etc/apparmor.d/abi/4.0")
PROFILES = Path("/sys/kernel/security/apparmor/profiles")
COMMON = ("--config-file=/dev/null", "--skip-cache", "--jobs=0",
          "--Werror=rule-not-enforced", "--Werror=rule-downgraded", "--Werror=abi")
CONTEXT = ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "GITHUB_REF",
           "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "GITHUB_JOB",
           "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "ImageOS", "ImageVersion",
           "DOCKERLENS_NATIVE_CANDIDATE_SHA")
SELECTORS = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
             "DOCKER_API_VERSION", "CONTAINER_HOST", "CONTAINER_CONNECTION",
             "CONTAINER_SSHKEY", "PODMAN_CONNECTIONS_CONF")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
NONCE = re.compile(r"[0-9a-f]{32}")
CID = re.compile(r"[0-9a-f]{64}")
PIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]+@sha256:[0-9a-f]{64}")
STAGES = frozenset({"admission", "custody", "kernel_enabled", "userns_restriction",
                    "kernel_features", "parser_version", "compile", "load",
                    "daemon_binding", "effective_label", "absence", "unload"})
STATE_KEYS = frozenset({"schema", "lane", "nonce", "profile", "directory", "run_identity",
                        "candidate", "workflow_run", "attempt", "name", "run", "image", "load",
                        "create", "label", "cid", "parser", "abi", "profile_sha256"})
RECEIPT_KEYS = frozenset({"schema", "prerequisite", "outcome", "candidate", "label", "profile_sha256",
                          "parser_sha256", "abi_sha256", "parser_version", "cleanup"})
NATIVE_CONSUMER = "dockerlens-native"
BOX_CONSUMER = "boxferry-reviewed-docker-consumer"
BOX_RECEIPT_KEYS = RECEIPT_KEYS | {"consumer", "workflow_run", "attempt"}


class Refused(Exception):
    """Only closed operation/status labels are emitted, never raw evidence."""


def await_owner():
    """Never disarm the original hard timer while descendant life is unknown."""
    while True:
        signal.pause()


def need(condition):
    if not condition:
        raise Refused("refused")


def consumer_mode(environment):
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux", "GITHUB_REF": "refs/heads/main",
                "ImageOS": "ubuntu24"}
    workflows = {
        "Strukturpiloten/docker-lens/.github/workflows/check.yml@refs/heads/main": "push",
        "Strukturpiloten/docker-lens/.github/workflows/native-validation.yml@refs/heads/main": "workflow_dispatch",
        "Strukturpiloten/docker-lens/.github/workflows/release-validation.yml@refs/heads/main": "workflow_dispatch",
    }
    common = (all(environment.get(key) == value for key, value in expected.items())
            and not any(environment.get(key) for key in SELECTORS)
            and re.fullmatch(r"[0-9]{8}\.[0-9]+\.[0-9]+", environment.get("ImageVersion", "")) is not None
            and re.fullmatch(r"[0-9a-f]{40}", environment.get("DOCKERLENS_NATIVE_CANDIDATE_SHA", "")) is not None
            and all(re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(key, "")) is not None
                    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")))
    if not common:
        return None
    if (environment.get("GITHUB_REPOSITORY") == "Strukturpiloten/docker-lens"
            and environment.get("GITHUB_JOB") == "native-conformance"
            and environment.get("GITHUB_WORKFLOW_REF") in workflows
            and environment.get("GITHUB_EVENT_NAME") == workflows[environment["GITHUB_WORKFLOW_REF"]]):
        return NATIVE_CONSUMER
    if (environment.get("GITHUB_REPOSITORY") == "Strukturpiloten/boxferry"
            and environment.get("GITHUB_JOB") == "lanes"
            and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and environment.get("GITHUB_WORKFLOW_REF") ==
            "Strukturpiloten/boxferry/.github/workflows/reviewed-docker-consumer-validation.yml@refs/heads/main"):
        return BOX_CONSUMER
    return None


def admitted(environment):
    return consumer_mode(environment) is not None


def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def file_record(value):
    need(type(value) is dict and set(value) == {"sha256", "identity", "size", "mtime_ns", "ctime_ns"})
    held = value["identity"]
    need(digest(value["sha256"]) and type(held) is list and len(held) == 3
         and all(type(item) is int and item >= 0 for item in held) and held[1] > 0 and held[2] == OWNER
         and type(value["size"]) is int and value["size"] > 0
         and all(type(value[key]) is int and value[key] >= 0 for key in ("mtime_ns", "ctime_ns")))


def validate_receipt(value, candidate, *, require_verified=False, consumer=NATIVE_CONSUMER,
                     workflow_run=None, attempt=None):
    need(consumer in (NATIVE_CONSUMER, BOX_CONSUMER))
    keys = BOX_RECEIPT_KEYS if consumer == BOX_CONSUMER else RECEIPT_KEYS
    need(type(value) is dict and set(value) == keys
         and type(value["schema"]) is int and value["schema"] == 1
         and all(type(value[key]) is str for key in keys - {"schema"})
         and value["prerequisite"] == "github_runner_userns_v1"
         and value["outcome"] in ("verified", "incomplete")
         and value["candidate"] == candidate and re.fullmatch(r"[0-9a-f]{40}", candidate) is not None
         and value["label"] in ("verified", "unverified")
         and value["parser_version"] in ("4.0.1", "unverified")
         and value["cleanup"] in ("removed", "not_loaded")
         and all(digest(value[key]) for key in ("profile_sha256", "parser_sha256", "abi_sha256")))
    if consumer == BOX_CONSUMER:
        need(value["consumer"] == BOX_CONSUMER
             and all(type(item) is str and re.fullmatch(r"[1-9][0-9]{0,19}", item) is not None
                     for item in (workflow_run, attempt))
             and value["workflow_run"] == workflow_run and value["attempt"] == attempt)
    need((value["cleanup"] != "not_loaded" or value["label"] == "unverified")
         and (value["cleanup"] != "removed" or value["parser_version"] == "4.0.1"))
    verified = value["label"] == "verified" and value["cleanup"] == "removed"
    need((value["outcome"] == "verified") == verified)
    need(not require_verified or verified)


def validate_cleanup_record(raw, candidate):
    """Ordinary acceptance requires the exact closed, completed prerequisite."""
    prefix = "DOCKERLENS_NATIVE_APPARMOR_PROFILE: "
    need(type(raw) is str and len(raw) <= 8192 and raw.startswith(prefix))
    value = json.loads(raw[len(prefix):], object_pairs_hook=unique_object)
    validate_receipt(value, candidate, require_verified=True)


def validate_box_cleanup_record(raw, candidate, workflow_run, attempt):
    """Pure current-attempt Box receipt validation; no runner/profile authority."""
    prefix = "DOCKERLENS_NATIVE_APPARMOR_PROFILE: "
    need(type(raw) is str and len(raw) <= 8192 and raw.startswith(prefix))
    value = json.loads(raw[len(prefix):], object_pairs_hook=unique_object)
    validate_receipt(value, candidate, require_verified=True, consumer=BOX_CONSUMER,
                     workflow_run=workflow_run, attempt=attempt)


def read_fd(descriptor, limit):
    data = bytearray()
    while len(data) <= limit:
        piece = os.read(descriptor, min(65536, limit + 1 - len(data)))
        if not piece:
            return bytes(data)
        data.extend(piece)
    raise Refused("bound")


def read_path(path, limit=65536):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        return read_fd(descriptor, limit)
    finally:
        os.close(descriptor)


def trusted_file(path, limit):
    """No writable or aliased component in preinstalled executable/ABI custody."""
    need(path.is_absolute())
    current = Path("/")
    for part in path.parts[1:-1]:
        current /= part
        info = os.lstat(current)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER and not info.st_mode & 0o022)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == OWNER
             and before.st_nlink == 1 and not before.st_mode & 0o022)
        content = read_fd(descriptor, limit)
        def stable(info):
            return (identity(info), info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        need(stable(os.fstat(descriptor)) == stable(before) == stable(os.lstat(path)))
        return {"sha256": hashlib.sha256(content).hexdigest(), "identity": identity(before),
                "size": before.st_size, "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns}
    finally:
        os.close(descriptor)


def profile_bytes(name):
    need(re.fullmatch(r"(?:dockerlens-127|boxferry-343)-upstream-rootless-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}-[0-9a-f]{32}", name) is not None)
    return f"abi <abi/4.0>,\nprofile {name} flags=(unconfined) {{\n  userns,\n}}\n".encode("ascii")


def loaded(name):
    rows = read_path(PROFILES, 1048576).decode("ascii").splitlines()
    matches = [row for row in rows if row.startswith(name + " ") or row == name]
    need(not matches or matches == [name + " (unconfined)"])
    return bool(matches)


class RunnerProfile:
    def __init__(self, directory, lane, nonce, environment, cancellation):
        self.stage = "admission"
        need(admitted(environment) and os.geteuid() == OWNER and lane == "upstream-rootless"
             and NONCE.fullmatch(nonce) is not None)
        self.consumer = consumer_mode(environment)
        box = self.consumer == BOX_CONSUMER
        self.directory = Path(directory)
        need(self.directory.parent == Path("/tmp")
             and re.fullmatch(r"boxferry-docker-core\.[A-Za-z0-9]{8}" if box else
                              r"dockerlens-native\.[A-Za-z0-9_]{8}", self.directory.name) is not None)
        self.owner_key = "io.boxferry.docker-core-run" if box else "io.dockerlens.native-run"
        self.name_prefix = "bf-docker-core-" if box else "dl-native-"
        self.nonce = nonce
        self.lane = lane
        self.path = ROOT / (("boxferry-apparmor." if box else "dockerlens-apparmor.") + nonce)
        self.environment = ENV | {key: environment[key] for key in CONTEXT}
        self.cancellation = cancellation
        self.deadline = time.monotonic() + 24
        self.held = None
        self.state = None

    def query(self, argv, *, statuses=(0,)):
        self.cancellation.check()
        need(time.monotonic() < self.deadline)
        # No nested timeout/session/group: the fixed bridge's original root
        # owner must retain every descendant through its own KILL fallback.
        command = tuple(argv)
        context = CaptureContext(Refused, Cancelled, ((command, "result"),), self.environment,
                                 SCRIPTS, 65536, 131072, False)
        with context.private_outputs() as files:
            try:
                result = context.capture(command, files, "result", self.deadline,
                                         self.cancellation, allowed_statuses=statuses)
            except Cancelled:
                # Even a reaped immediate child does not prove its descendants
                # died. Original owner, not a fresh timer, terminates the group.
                files.discard()
                await_owner()
            except Refused as error:
                if error.args not in (("command_failed",), ("tool_unavailable",)):
                    files.discard()
                    await_owner()
                raise
            need(os.fstat(files["result.stderr"]).st_size == 0)
            return result

    @contextmanager
    def custody(self, create=False):
        self.stage = "custody"
        run = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        root = os.lstat(ROOT)
        need(stat.S_ISDIR(root.st_mode) and root.st_uid == OWNER and not root.st_mode & 0o022)
        try:
            original = os.fstat(run)
            need(stat.S_IMODE(original.st_mode) == 0o700)
            if create:
                os.mkdir(self.path, 0o700)  # Exclusive; never adopt a prior nonce.
            self.held = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            owned = os.fstat(self.held)
            need(owned.st_uid == OWNER and stat.S_IMODE(owned.st_mode) == 0o700)
            lock = os.open("lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC |
                           (os.O_CREAT | os.O_EXCL if create else 0), 0o600, dir_fd=self.held)
            try:
                info = os.fstat(lock)
                need(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1
                     and stat.S_IMODE(info.st_mode) == 0o600)
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.run_identity = identity(original)
                if not create:
                    self.state = json.loads(self.read_owned("state.json").decode("ascii"), object_pairs_hook=unique_object)
                    self.validate_state()
                    need(self.read_owned("profile") == profile_bytes(self.state["profile"]))
                self.revalidate = lambda: need(identity(os.lstat(self.directory)) == identity(os.fstat(run))
                                                and identity(os.lstat(self.path)) == identity(os.fstat(self.held)))
                self.revalidate()
                yield
                self.revalidate()
            finally:
                os.close(lock)
        finally:
            if self.held is not None:
                os.close(self.held)
                self.held = None
            os.close(run)

    def profile_name(self):
        prefix = "boxferry-343" if self.consumer == BOX_CONSUMER else "dockerlens-127"
        return (prefix + "-upstream-rootless-" + self.environment["GITHUB_RUN_ID"] + "-"
                + self.environment["GITHUB_RUN_ATTEMPT"] + "-" + self.nonce)

    def validate_state(self):
        value = self.state
        need(type(value) is dict and type(value.get("load")) is str)
        extra = {"parser_version"} if value["load"] != "never" else set()
        if self.consumer == BOX_CONSUMER:
            extra |= {"consumer"}
        need(set(value) == STATE_KEYS | extra and type(value["schema"]) is int and value["schema"] == 1)
        need(all(type(value[key]) is str for key in (STATE_KEYS | extra) - {"schema", "run_identity", "parser", "abi"}))
        held = value["run_identity"]
        need(type(held) is list and len(held) == 3 and all(type(item) is int and item >= 0 for item in held)
             and held[1] > 0 and held == self.run_identity
             and value["directory"] == str(self.directory)
             and value["candidate"] == self.environment["DOCKERLENS_NATIVE_CANDIDATE_SHA"]
             and value["workflow_run"] == self.environment["GITHUB_RUN_ID"]
             and value["attempt"] == self.environment["GITHUB_RUN_ATTEMPT"]
             and value["lane"] == self.lane and value["nonce"] == self.nonce
             and value["profile"] == self.profile_name()
             and value["profile_sha256"] == hashlib.sha256(profile_bytes(self.profile_name())).hexdigest()
             and value["run"] == self.directory.name.rsplit(".", 1)[1]
             and value["name"] == self.name_prefix + value["run"] and PIN.fullmatch(value["image"]) is not None
             and (self.consumer != BOX_CONSUMER or value["consumer"] == BOX_CONSUMER))
        file_record(value["parser"])
        file_record(value["abi"])
        need(value["load"] in ("never", "prepared", "intent", "loaded", "unload_intent", "removed")
             and value["create"] in ("never", "intent", "recorded")
             and value["label"] in ("unverified", "verified")
             and (value["load"] == "never" or value["parser_version"] == "4.0.1"))
        if value["create"] == "never":
            need(value["cid"] == "" and value["label"] == "unverified")
        elif value["create"] == "intent":
            need(value["load"] == "loaded" and value["label"] == "unverified"
                 and (value["cid"] == "" or CID.fullmatch(value["cid"]) is not None))
        else:
            need(value["load"] in ("loaded", "unload_intent", "removed") and CID.fullmatch(value["cid"]) is not None)
        if value["load"] in ("never", "prepared", "intent"):
            need(value["create"] == "never")

    def read_owned(self, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=self.held)
        try:
            info = os.fstat(descriptor)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1
                 and stat.S_IMODE(info.st_mode) == 0o600)
            return read_fd(descriptor, 16384)
        finally:
            os.close(descriptor)

    def write_owned(self, name, data):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self.held)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def save(self):
        self.revalidate()
        self.validate_state()
        self.write_owned("state.next", json.dumps(self.state, sort_keys=True).encode("ascii"))
        os.replace("state.next", "state.json", src_dir_fd=self.held, dst_dir_fd=self.held)
        os.fsync(self.held)

    def parser(self, operation):
        need(operation in ("--version", "--skip-kernel-load", "--add", "--remove"))
        self.revalidate()
        need(trusted_file(PARSER, 16777216) == self.state["parser"]
             and trusted_file(ABI, 65536) == self.state["abi"])
        suffix = () if operation == "--version" else (str(self.path / "profile"),)
        result = self.query((str(PARSER), *COMMON, operation, *suffix))
        self.revalidate()
        need(trusted_file(PARSER, 16777216) == self.state["parser"]
             and trusted_file(ABI, 65536) == self.state["abi"])
        return result

    def prepare(self, name, run, image):
        need(name == self.name_prefix + self.directory.name.rsplit(".", 1)[1]
             and run == self.directory.name.rsplit(".", 1)[1] and PIN.fullmatch(image) is not None)
        # Trusted coordinator admission and the unprivileged shell selector
        # already checked clean HEAD. Never run caller-configured Git as root.
        with self.custody(create=True):
            profile = self.profile_name()
            self.state = {"schema": 1, "lane": self.lane, "nonce": self.nonce, "profile": profile, "directory": str(self.directory),
                          "run_identity": self.run_identity, "candidate": self.environment["DOCKERLENS_NATIVE_CANDIDATE_SHA"],
                          "workflow_run": self.environment["GITHUB_RUN_ID"], "attempt": self.environment["GITHUB_RUN_ATTEMPT"],
                          "name": name, "run": run, "image": image, "load": "never", "create": "never",
                          "label": "unverified", "cid": "", "parser": trusted_file(PARSER, 16777216),
                          "abi": trusted_file(ABI, 65536), "profile_sha256": hashlib.sha256(profile_bytes(profile)).hexdigest()}
            if self.consumer == BOX_CONSUMER:
                self.state["consumer"] = BOX_CONSUMER
            self.write_owned("profile", profile_bytes(profile))
            self.save()
            self.stage = "kernel_enabled"
            need(read_path(Path("/sys/module/apparmor/parameters/enabled"), 16) == b"Y\n")
            self.stage = "userns_restriction"
            need(read_path(Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"), 16) == b"1\n")
            self.stage = "kernel_features"
            need(b"userns_create" in read_path(Path("/sys/kernel/security/apparmor/features/namespaces/mask"), 4096).split())
            need(read_path(Path("/sys/kernel/security/apparmor/features/policy/versions/v9"), 16) == b"yes\n")
            self.stage = "parser_version"
            version = self.parser("--version").decode("ascii")
            need(re.fullmatch(r"AppArmor parser version 4\.0\.1\n[^\x00]{0,4096}", version) is not None)
            self.state["parser_version"] = "4.0.1"
            need(not loaded(profile))
            self.stage = "compile"
            self.parser("--skip-kernel-load")
            self.state["load"] = "prepared"
            self.save()

    def load(self):
        with self.custody():
            self.stage = "load"
            need(self.state["load"] == "prepared" and self.state["create"] == "never")
            need(not loaded(self.state["profile"]))
            self.state["load"] = "intent"
            self.save()  # Durable before mutation; failure/timeout is sticky.
            self.parser("--add")
            need(loaded(self.state["profile"]))
            self.state["load"] = "loaded"
            self.save()

    def begin(self, name, run, image):
        with self.custody():
            self.stage = "daemon_binding"
            need(self.state["load"] == "loaded" and self.state["create"] == "never"
                 and (name, run, image) == (self.state["name"], self.state["run"], self.state["image"])
                 and loaded(self.state["profile"]))
            self.state["create"] = "intent"
            self.save()
            return self.state["profile"]

    def created(self, cid):
        with self.custody():
            self.stage = "daemon_binding"
            need(CID.fullmatch(cid) is not None and self.state["load"] == "loaded"
                 and self.state["create"] == "intent")
            self.state["cid"] = cid
            self.save()
            # Bind the actual daemon before marking creation known, even if it
            # has already stopped. Later label/cgroup refusal cannot erase this
            # ownership evidence or require retaining a proven unused profile.
            self.daemon()
            self.state["create"] = "recorded"
            self.save()

    def bridge(self, operation, *args):
        return self.query(("/bin/bash", str(SCRIPTS / "native-outer-command.sh"),
                           "--engine", "docker", "--directory", str(self.directory), operation, *args))

    def daemon(self):
        spec = importlib.util.spec_from_file_location("apparmor_outer_observation", SCRIPTS / "native-outer-observation.py")
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        value = observer.document(self.bridge("snapshot", self.state["cid"]))
        observer.daemon_binding(value, "docker", self.state["cid"], self.state["name"],
                                self.owner_key, self.state["run"], self.state["image"])
        return value

    def snapshot(self):
        value = self.daemon()
        running = value.get("State", {})
        need(running.get("Running") is True and type(running.get("Pid")) is int and running["Pid"] > 1
             and type(running.get("StartedAt")) is str and 1 <= len(running["StartedAt"]) <= 64
             and value.get("HostConfig", {}).get("Privileged") is True)
        return running["Pid"], running["StartedAt"]

    def verify(self):
        with self.custody():
            self.stage = "daemon_binding"
            need(self.state["load"] == "loaded" and self.state["create"] == "recorded")
            before = self.snapshot()
            self.stage = "effective_label"
            process = os.open(f"/proc/{before[0]}", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                ticks = process_ticks(process, before[0])
                cgroup = process_read(process, "cgroup")
                label = process_label(process)
                need(self.snapshot() == before and process_ticks(process, before[0]) == ticks
                     and process_read(process, "cgroup") == cgroup
                     and cgroup == f"0::/system.slice/docker-{self.state['cid']}.scope\n".encode("ascii")
                     and process_label(process) == label
                     and label == (self.state["profile"] + " (unconfined)\n").encode("ascii"))
            finally:
                os.close(process)
            self.state["label"] = "verified"
            self.save()

    def absent(self):
        self.stage = "absence"
        # The ordinary presence supervisor owns a separate process group. This
        # fixed raw projection instead inherits our original cleanup owner.
        for kind, identity_value in (("id", self.state["cid"]), ("name", self.state["name"])):
            raw = self.bridge("apparmor-presence", kind, identity_value)
            rows = raw.splitlines(keepends=True)
            need(all(row == b"other\n" for row in rows))

    def cleanup(self):
        with self.custody():
            phase = self.state["load"]
            need(phase in ("never", "prepared", "loaded"))
            if phase == "loaded":
                need(self.state["create"] in ("never", "recorded"))
                if self.state["create"] == "recorded":
                    need(CID.fullmatch(self.state["cid"]) is not None)
                    self.absent()
                self.stage = "unload"
                need(loaded(self.state["profile"]))
                self.state["load"] = "unload_intent"
                self.save()
                self.parser("--remove")
                need(not loaded(self.state["profile"]))
                self.state["load"] = "removed"
                self.save()
            verified = self.state["label"] == "verified" and phase == "loaded"
            receipt = {"schema": 1, "prerequisite": "github_runner_userns_v1",
                       "outcome": "verified" if verified else "incomplete",
                       "candidate": self.state["candidate"], "label": self.state["label"],
                       "profile_sha256": self.state["profile_sha256"], "parser_sha256": self.state["parser"]["sha256"],
                       "abi_sha256": self.state["abi"]["sha256"], "parser_version": self.state.get("parser_version", "unverified"),
                       "cleanup": "removed" if phase == "loaded" else "not_loaded"}
            if self.consumer == BOX_CONSUMER:
                receipt |= {"consumer": BOX_CONSUMER, "workflow_run": self.environment["GITHUB_RUN_ID"],
                            "attempt": self.environment["GITHUB_RUN_ATTEMPT"]}
                validate_receipt(receipt, self.environment["DOCKERLENS_NATIVE_CANDIDATE_SHA"],
                                 consumer=BOX_CONSUMER, workflow_run=self.environment["GITHUB_RUN_ID"],
                                 attempt=self.environment["GITHUB_RUN_ATTEMPT"])
            else:
                validate_receipt(receipt, self.environment["DOCKERLENS_NATIVE_CANDIDATE_SHA"])
            # Fixed finite leaves only. Unknown files/state are never swept up.
            self.revalidate()
            need(set(os.listdir(self.path)) == {"lock", "state.json", "profile"})
            for name in ("state.json", "profile", "lock"):
                self.read_owned(name)
                os.unlink(name, dir_fd=self.held)
            return receipt


def process_read(process, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=process)
    try:
        return read_fd(descriptor, 4096)
    finally:
        os.close(descriptor)


def process_ticks(process, pid):
    before, after = process_read(process, "stat").decode("ascii").rsplit(") ", 1)
    fields = after.split()
    need(before.startswith(f"{pid} (") and len(fields) >= 20 and fields[0] not in ("Z", "X"))
    ticks = int(fields[19])
    need(ticks > 0)
    return ticks


def process_label(process):
    return process_read(process, "attr/current")


def main(argv):
    operation = argv[0] if argv and argv[0] in {"prepare", "load", "begin", "created", "verify", "cleanup"} else "invalid"
    cancellation = Cancellation()
    profile = None
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, cancellation.request)
    try:
        # Read-only validation in the original, unprivileged coordinator. This
        # grants no profile/runtime operation and consumes no ambient context.
        if argv and argv[0] == "validate-receipt":
            need(len(argv) == 2)
            validate_cleanup_record(sys.stdin.read(8193), argv[1])
            cancellation.check()
            return 0
        if argv and argv[0] == "validate-box-consumer-receipt":
            need(len(argv) == 4)
            validate_box_cleanup_record(sys.stdin.read(8193), *argv[1:])
            cancellation.check()
            return 0
        need(len(argv) >= 4 and operation != "invalid")
        profile = RunnerProfile(argv[1], argv[2], argv[3], os.environ, cancellation)
        args = argv[4:]
        need(len(args) == {"prepare": 3, "begin": 3, "created": 1}.get(operation, 0))
        result = getattr(profile, operation)(*args)
        cancellation.check()
        if operation == "cleanup":
            os.rmdir(profile.path)
            print("DOCKERLENS_NATIVE_APPARMOR_PROFILE: " + json.dumps(result, sort_keys=True, separators=(",", ":")))
        elif operation == "begin":
            print(result)
        return 0
    except Cancelled as error:
        return 128 + error.signum
    except (Refused, OSError, ValueError, KeyError, UnicodeError, TypeError, OverflowError, RecursionError):
        stage = getattr(profile, "stage", "admission")
        if stage not in STAGES:
            stage = "admission"
        print(f"DOCKERLENS_NATIVE_APPARMOR_PROFILE: operation={operation} stage={stage} outcome=refused cleanup=retained", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
