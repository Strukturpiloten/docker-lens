"""Fixed Podman 4.9.3 observation normalization for the private outer owner.

Native JSON is fallible input. The fixed adapter executes only its closed
command vocabulary under prepaid budgets and held executable/config custody.
Expected defaults never come from target OCI. Source binding is not native
qualification or cryptographic binary attestation.
"""

from datetime import datetime
from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import time

from native_outer_bootstrap import build_bootstrap_argv
from native_outer_lifecycle import (InspectSnapshot, LifecycleError, OWNER_LABEL, RuntimeProfile, _Chain, _ReservedDescriptors,
                                    _started, environment_map, integer, path_parts, record, require)
from native_outer_launch import AccountRecord, closed_normalization, digest
from native_outer_broker_protocol import DatabaseReceipt, PreflightReceipt
from native_outer_coordinator import bounded_source_io

INSPECT_BYTES = 65536
CONFIG_FIELDS = ("User", "ExposedPorts", "Env", "Entrypoint", "Cmd", "Volumes", "WorkingDir", "Labels", "StopSignal", "ArgsEscaped")


@closed_normalization
def config_semantics(config, *, audited_raw=False):
    """Podman 4.9.3's ten-field typed OCI projection, not original JSON bytes.

    Its source-proven omitempty zero semantics collapse raw missing/null/empty;
    nonzero arrays retain exact ordering and duplicates. Native inspect output
    cannot contain explicit null/empty values for these omitempty fields.
    Docker-only raw keys are dropped only when projecting audited raw inputs.
    """
    require(type(audited_raw) is bool and type(config) is dict and (audited_raw or set(config) <= set(CONFIG_FIELDS)))
    projection = {}
    for key in CONFIG_FIELDS:
        if key in ("User", "WorkingDir", "StopSignal"):
            zero, expected_type = "", str
        elif key in ("Env", "Entrypoint", "Cmd"):
            zero, expected_type = [], list
        elif key == "ArgsEscaped":
            zero, expected_type = False, bool
        else:
            zero, expected_type = {}, dict
        value = config.get(key, zero)
        if audited_raw and value is None:
            value = zero
        require(type(value) is expected_type)
        if key in config and not audited_raw:
            require(value != zero)
        if expected_type is str:
            require("\0" not in value and len(value.encode("utf-8")) <= 4096)
        elif expected_type is list:
            require(len(value) <= 128 and all(type(item) is str and "\0" not in item
                                             and len(item.encode("utf-8")) <= 4096 for item in value))
        elif expected_type is dict:
            require(len(value) <= 128 and all(type(name) is str and "\0" not in name and len(name.encode()) <= 4096 for name in value))
            if key == "Labels":
                require(all(type(item) is str and "\0" not in item and len(item.encode()) <= 4096 for item in value.values()))
            else:
                require(all(type(item) is dict and not item for item in value.values()))
        projection[key] = value
    return {"config": projection, "healthcheck": None}


def config_semantic_sha256(config, *, audited_raw=False):
    semantic = config_semantics(config, audited_raw=audited_raw)
    raw = json.dumps(semantic, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, repr=False)
class BoundImageObservation:
    """Parsed-semantic corroboration, not a trusted-pull/admission boolean."""
    canonical_reference: str
    index_digest: str
    platform_digest: str
    config_digest: str
    architecture: str
    declared_variant: str
    native_id: str
    native_digest: str
    native_digest_kind: str
    config_semantic_sha256: str
    ordered_diff_ids: tuple
    configuration: bytes

    def launch_image(self):
        return {"digest": self.index_digest, "platform_digest": self.platform_digest,
                "config_digest": self.config_digest, "architecture": self.architecture,
                "config": json.loads(self.configuration)}


@closed_normalization
def normalize_image(raw, account):
    """Corroborate an exact audited chain after the owner's trusted same-run pull.

    This parser alone does not prove that pull occurred or exclude concurrent
    untrusted store mutation. The fixed adapter must enforce those conditions.
    Native index/platform digests remain distinct, explicitly preserved facts.
    """
    require(type(account) is AccountRecord and digest(account.config_semantic_sha256)
            and account.canonical_reference.endswith("@" + account.image_digest)
            and type(account.ordered_layer_diff_ids) is tuple and account.ordered_layer_diff_ids)
    value = inspect_document(raw)
    require(value.get("Id") == account.config_digest[7:] and value.get("Os") == "linux"
            and value.get("Architecture") == account.architecture)
    native_digest = value.get("Digest")
    if native_digest == account.image_digest:
        kind = "index"
    else:
        require(native_digest == account.platform_digest)
        kind = "selected_platform"
    reference = account.canonical_reference.rsplit("@", 1)[0]
    # The canonical maintained pins include a readable tag. RepoDigests strips
    # that tag, preserving a possible registry port before the final slash.
    repository, separator, _tag = reference.rpartition(":")
    require(separator == ":" and "/" in repository)
    digests = value.get("RepoDigests")
    require(type(digests) is list and 1 <= len(digests) <= 64
            and all(type(item) is str and len(item) <= 1024 for item in digests)
            and len(set(digests)) == len(digests)
            and repository + "@" + account.image_digest in digests)
    rootfs = value.get("RootFS")
    require(type(rootfs) is dict and rootfs.get("Type") == "layers" and type(rootfs.get("Layers")) is list
            and rootfs["Layers"] == list(account.ordered_layer_diff_ids))
    require("Healthcheck" not in value)
    config = value.get("Config")
    require(config_semantic_sha256(config) == account.config_semantic_sha256)
    semantic = config_semantics(config)["config"]
    require(semantic["User"] == account.user_text and value.get("User") == account.user_text)
    environment_map(semantic["Env"])  # Never turn duplicate source env into defaults.
    configuration = json.dumps(semantic, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return BoundImageObservation(account.canonical_reference, account.image_digest, account.platform_digest,
                                 account.config_digest, account.architecture, account.declared_variant,
                                 value["Id"], native_digest, kind, account.config_semantic_sha256,
                                 account.ordered_layer_diff_ids, configuration)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def nonfinite(_value):
    require(False)


@closed_normalization
def inspect_document(raw):
    require(type(raw) is bytes and 0 < len(raw) <= INSPECT_BYTES)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)
    require(type(value) is list and len(value) == 1 and type(value[0]) is dict)
    return value[0]


@closed_normalization
def zero_time(value):
    """Go's zero instant, not empty/missing/malformed or truncated nanoseconds."""
    require(type(value) is str)
    match = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(?:Z|([+-])([01][0-9]|2[0-3]):([0-5][0-9]))", value)
    require(match is not None)
    instant = datetime(*(int(match[index]) for index in range(1, 7)))
    seconds = (instant.toordinal() - 1) * 86400 + instant.hour * 3600 + instant.minute * 60 + instant.second
    offset = 0 if match[8] is None else (int(match[9]) * 60 + int(match[10])) * 60
    if match[8] == "-":
        offset = -offset
    return seconds - offset == 0 and int(match[7] or "0") == 0


@closed_normalization
def normalize_inspect(raw, expectation, container_id, log_path, image):
    """Require an actual OCI-initialized or running exact owned instance.

    Podman ``created`` is storage-only; only ``initialized`` maps to the
    lifecycle seam's historical ``created`` state. Config.Entrypoint is a
    joined string and is deliberately never split into original argv.
    """
    value = inspect_document(raw)
    require(type(container_id) is str and re.fullmatch(r"[0-9a-f]{64}", container_id) is not None)
    require(value.get("Id") == container_id and value.get("Name") == expectation.name)
    require(type(image) is BoundImageObservation and image.index_digest == expectation.image_digest
            and image.canonical_reference == expectation.image_ref)
    require(value.get("Image") == image.native_id and value.get("ImageDigest") == image.native_digest
            and value.get("OCIRuntime") == "crun")
    config, host, state = (value.get(key) for key in ("Config", "HostConfig", "State"))
    require(type(config) is dict and type(host) is dict and type(state) is dict)
    labels = config.get("Labels")
    require(type(labels) is dict and labels.get(OWNER_LABEL) == expectation.owner)
    argv = build_bootstrap_argv(expectation.nonce, list(expectation.original_argv))
    require(value.get("Path") == argv[0] and type(value.get("Args")) is list and value["Args"] == argv[1:])
    require(type(config.get("Entrypoint")) is str and config["Entrypoint"] == argv[0])
    require(environment_map(config.get("Env")) == environment_map(expectation.environment))
    require(config.get("WorkingDir") == expectation.cwd and config.get("Tty") is False)
    require(host.get("Privileged") is True)
    for key, expected in (("Memory", 4294967296), ("CpuPeriod", 100000), ("CpuQuota", 200000), ("PidsLimit", 512)):
        require(type(host.get(key)) is int and host[key] == expected)
    log, restart = host.get("LogConfig"), host.get("RestartPolicy")
    require(type(log) is dict and log.get("Type") == "k8s-file" and log.get("Path") == log_path)
    require(type(restart) is dict and restart.get("Name") == "no"
            and type(restart.get("MaximumRetryCount")) is int and restart["MaximumRetryCount"] == 0)
    for key in ("Paused", "Restarting", "OOMKilled", "Dead"):
        require(state.get(key) is False)
    for key in ("Restored", "Checkpointed"):
        require(state.get(key, False) is False)
    require(state.get("Error") == "" and type(state.get("ExitCode")) is int and state["ExitCode"] == 0)
    require(zero_time(state.get("FinishedAt")))
    require(type(value.get("RestartCount")) is int and value["RestartCount"] == 0)
    status, pid, started = (state.get(key) for key in ("Status", "Pid", "StartedAt"))
    require(integer(pid, 1, 4194304))
    if status == "initialized":
        require(state.get("Running") is False and zero_time(started))
        normalized_state, started = "created", None
    else:
        require(status == "running" and state.get("Running") is True)
        _started(started)
        normalized_state = "running"
    oci_path = value.get("OCIConfigPath")
    path_parts(oci_path)
    return InspectSnapshot(container_id, expectation.name, expectation.image_digest, expectation.owner,
                           "k8s-file", log_path, oci_path, normalized_state, pid, started, 0, False, False, "no")


class NativeExecutable(_ReservedDescriptors):
    """Original root-owned fixed executable/ancestor metadata, not binary attestation."""
    def __init__(self, path, budget, deadline, clock, cancelled):
        self.budget, self.clock, self.cancelled, self.deadline = budget, clock, cancelled, deadline
        self._last_clock, self._fds = clock(), []
        try:
            self.chain = _Chain(self, path)
            self.fd = self._open(self.chain.leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.chain.parent)
            self.original = record(self._io(os.fstat, self.fd))
            self.recheck()
        except BaseException:
            self.close()
            raise LifecycleError() from None

    def _deadline(self):
        return self.deadline

    def recheck(self):
        self.chain.recheck()
        for _, descriptor, _ in self.chain.entries:
            info = self._io(os.fstat, descriptor)
            require(info.st_uid == 0 and info.st_mode & 0o022 == 0)
        held = self._io(os.fstat, self.fd)
        named = self._io(os.stat, self.chain.leaf, dir_fd=self.chain.parent, follow_symlinks=False)
        require(record(held) == record(named) == self.original and stat.S_ISREG(held.st_mode)
                and held.st_uid == 0 and held.st_mode & 0o022 == 0 and held.st_mode & 0o111 != 0
                and held.st_nlink == 1)

    def recovery_recheck(self, budget, deadline):
        # Recovery uses its original prepaid cleanup slice, never a reset of a
        # cancelled/expired ordinary reservation or a new full allowance.
        previous = self.budget, self.deadline, self.cancelled
        try:
            self.budget, self.deadline, self.cancelled = budget, deadline, lambda: False
            self.recheck()
        finally:
            self.budget, self.deadline, self.cancelled = previous

    def close(self):
        self._close_descriptors()


class BoundedNativeProcess:
    """Private in-memory stdout/stderr collection with no inherited control FDs."""
    def __init__(self, budget, clock=time.monotonic, cancelled=lambda: False, spawn=subprocess.Popen):
        self.budget, self.clock, self.cancelled, self.spawn = budget, clock, cancelled, spawn

    def run(self, argv, deadline, environment, *, seconds=8, stdout_limit=65536, stderr_limit=4096, allowed=(0,)):
        require(type(argv) is tuple and all(type(item) is str and "\0" not in item for item in argv))
        require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 120
                and integer(stdout_limit, 0, 65536) and integer(stderr_limit, 0, 4096)
                and type(allowed) is tuple and 1 <= len(allowed) <= 2
                and all(integer(status, 0, 255) for status in allowed))
        require(type(deadline) in (int, float) and math.isfinite(deadline)
                and 0 < deadline - self.clock() and type(environment) is dict)
        # The selected root-owned timer shares privileges with its command.
        remaining = min(seconds, deadline - self.clock() - 1)
        require(remaining > 0)
        timed = ("/usr/bin/timeout", "--signal=TERM", "--kill-after=1s", f"{remaining:.3f}s", *argv)
        self.budget.debit(native_calls=1)
        process = None
        streams, output = {}, {"stdout": bytearray(), "stderr": bytearray()}
        try:
            process = self.spawn(timed, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=environment, close_fds=True, start_new_session=True)
            require(process.stdout is not None and process.stderr is not None)
            streams = {process.stdout: ("stdout", stdout_limit), process.stderr: ("stderr", stderr_limit)}
            with selectors.DefaultSelector() as selector:
                for stream in streams:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    self.budget.check()
                    require(self.cancelled() is False and self.clock() < deadline)
                    self.budget.debit(io_calls=1)
                    ready = selector.select(min(0.05, deadline - self.clock()))
                    for key, _ in ready:
                        name, cap = streams[key.fileobj]
                        # Detection lookahead is retained/charged, never drained
                        # indefinitely after an output cap has been exceeded.
                        chunk = bounded_source_io(self.budget, min(4096, cap + 1 - len(output[name])),
                                                  lambda maximum: os.read(key.fd, maximum))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        output[name].extend(chunk)
                        require(len(output[name]) <= cap)
                require(self.cancelled() is False and self.clock() < deadline)
                status = process.wait(timeout=max(0.001, deadline - self.clock()))
            require(status in allowed and not output["stderr"])
            return bytes(output["stdout"]), status
        except BaseException:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=max(0.001, min(1, deadline - self.clock())))
                except (OSError, subprocess.TimeoutExpired):
                    pass
            raise LifecycleError() from None
        finally:
            for stream in streams:
                stream.close()


@closed_normalization
def normalize_profile(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 65536)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)
    require(type(value) is dict and type(value.get("host")) is dict and type(value.get("version")) is dict)
    host, version = value["host"], value["version"]
    security, runtime = host.get("security"), host.get("ociRuntime")
    require(type(security) is dict and type(runtime) is dict)
    require(host.get("os") == "linux" and security.get("rootless") is False and host.get("serviceIsRemote") is False)
    require(version.get("Version") == "4.9.3" and runtime.get("name") == "crun"
            and runtime.get("path") == "/usr/bin/crun" and type(runtime.get("version")) is str
            and runtime["version"].split("\n", 1)[0] == "crun version 1.14.1"
            and host.get("cgroupManager") == "systemd" and host.get("cgroupVersion") == "v2")
    return RuntimeProfile("linux", False, False, "4.9.3", "crun", "1.14.1", "systemd", "v2")


class FixedPodmanRuntime:
    """Closed native command vocabulary; wire requests never supply commands.

    The caller supplies independently derived policy and prepaid budgets, not
    arbitrary executable names. The production broker owns this object alone.
    Its recovery budget is separate from cancellation-poisoned ordinary I/O.
    """
    def __init__(self, intent, account, process, recovery_process, environment,
                 config_path, mounts_path, hooks_directory, executables, configuration, *, clock=time.monotonic):
        self.intent, self.account = intent, account
        self.process, self.recovery_process = process, recovery_process
        self.environment = dict(environment)
        require(set(self.environment) == {"PATH", "HOME", "LANG", "LC_ALL", "CONTAINERS_CONF"}
                and self.environment["CONTAINERS_CONF"] == config_path)
        for path in (config_path, mounts_path, hooks_directory):
            path_parts(path)
        self.config_path, self.mounts_path, self.hooks_directory = config_path, mounts_path, hooks_directory
        self.executables, self.clock = tuple(executables), clock
        self.configuration = configuration
        require(tuple(item.chain.path for item in self.executables) == ("/usr/bin/podman", "/usr/bin/crun", "/usr/bin/timeout"))
        self.image = self.profile = self.expectation = self.last_inspection = None
        self.container_id = None
        self.create_attempted = self.closed = False

    def _command(self, args, deadline, *, recovery=False, cap=65536, seconds=8, allowed=(0,)):
        for executable in self.executables:
            if recovery:
                executable.recovery_recheck(self.recovery_process.budget, deadline)
            else:
                executable.recheck()
        if recovery:
            self.configuration.recovery_recheck(self.recovery_process.budget, deadline)
        else:
            self.configuration.recheck()
        prefix = ("/usr/bin/podman", "--remote=false", "--runtime=/usr/bin/crun", "--cgroup-manager=systemd",
                  "--transient-store=false", "--hooks-dir=" + self.hooks_directory,
                  "--default-mounts-file=" + self.mounts_path)
        collector = self.recovery_process if recovery else self.process
        return collector.run(prefix + tuple(args), deadline, self.environment,
                             stdout_limit=cap, seconds=seconds, allowed=allowed)

    @closed_normalization
    def preflight(self, deadline):
        require(self.image is None and not self.create_attempted)
        # Explicit trusted same-run pull. Merely seeing a matching store object
        # or native Digest field is not accepted as acquisition provenance.
        platform = ("--os=linux", "--arch=" + self.account.architecture)
        if self.account.declared_variant:
            platform += ("--variant=" + self.account.declared_variant,)
        self._command(("pull", "--quiet", *platform, self.intent.image_ref), deadline, seconds=90, cap=4096)
        raw, _ = self._command(("info", "--format=json"), deadline)
        self.profile = normalize_profile(raw)
        raw, _ = self._command(("image", "inspect", self.intent.image_ref), deadline)
        self.image = normalize_image(raw, self.account)
        native = inspect_document(raw)
        return PreflightReceipt(vars(self.profile), self.image.native_id, self.image.native_digest,
                                tuple(native["RepoDigests"]), "linux", self.account.architecture,
                                self.image.ordered_diff_ids, config_semantics(native["Config"]))

    @closed_normalization
    def create(self, expectation, log_path, deadline):
        require(self.image is not None and self.profile is not None and not self.create_attempted)
        require(expectation.image_ref == self.intent.image_ref and expectation.owner == self.intent.owner)
        self.expectation, self.create_attempted = expectation, True
        argv = build_bootstrap_argv(expectation.nonce, list(expectation.original_argv))
        storage = "/home/docker/.local/share/docker" if self.intent.lane.endswith("rootless") else "/var/lib/docker"
        volume = self.intent.data_volume + ":" + storage + ":U"
        lane_flags = ()
        if self.intent.lane == "debian11-rootless":
            volume += ",suid,dev"
            lane_flags = ("--oom-score-adj=0", "--security-opt=apparmor=unconfined")
        env_flags = tuple(flag for entry in expectation.environment for flag in ("--env", entry))
        args = ("create", "--pull=never", "--name=" + expectation.name,
                "--label=" + OWNER_LABEL + "=" + expectation.owner,
                "--log-driver=k8s-file", "--log-opt=path=" + log_path, "--log-opt=max-size=1048576",
                "--network=" + self.intent.network, "--privileged", "--pids-limit=512", "--memory=4g",
                "--memory-swap=8g", "--cpus=2", "--cgroup-parent=machine.slice", "--image-volume=ignore",
                "--restart=no", "--userns=host", "--passwd-entry=", "--group-entry=",
                "--unsetenv-all", "--env-host=false", "--http-proxy=false", *env_flags,
                "--workdir=" + expectation.cwd,
                *lane_flags, "--volume=" + volume, "--volume=" + self.intent.socket_source + ":/dockerlens-native",
                "--entrypoint=" + json.dumps([argv[0]], separators=(",", ":")), self.image.native_id, *argv[1:])
        raw, _ = self._command(args, deadline, seconds=30, cap=65)
        require(re.fullmatch(rb"[0-9a-f]{64}\n", raw) is not None)
        self.container_id = raw[:64].decode("ascii")
        return self.container_id

    @closed_normalization
    def initialize(self, container_id, deadline):
        require(container_id == self.container_id)
        self._command(("container", "init", container_id), deadline, cap=65)

    @closed_normalization
    def inspect(self, container_id, deadline):
        require(container_id == self.container_id and self.expectation is not None)
        raw, _ = self._command(("container", "inspect", container_id), deadline)
        result = normalize_inspect(raw, self.expectation, container_id,
                                   self.intent.run_directory + "/diagnostics/daemon.log", self.image)
        self.last_inspection = inspect_document(raw)
        return result

    @closed_normalization
    def database_receipt(self, deadline):
        require(type(self.last_inspection) is dict and self.last_inspection["State"]["Status"] == "initialized")
        value = self.last_inspection
        volume_raw, _ = self._command(("volume", "inspect", self.intent.data_volume), deadline, cap=8192)
        volume = inspect_document(volume_raw)
        require(volume.get("Name") == self.intent.data_volume and type(volume.get("Labels")) is dict
                and volume["Labels"].get(OWNER_LABEL) == self.intent.owner and volume.get("Driver") == "local"
                and volume.get("Options") in (None, {}))
        names = ("StaticDir", "HostnamePath", "HostsPath", "ResolvConfPath")
        for name in names:
            path_parts(value.get(name))
        parent = os.path.dirname(value["HostnamePath"])
        require(os.path.basename(value["HostnamePath"]) == "hostname"
                and value["HostsPath"] == parent + "/hosts" and value["ResolvConfPath"] == parent + "/resolv.conf")
        path_parts(volume.get("Mountpoint"))
        return DatabaseReceipt(value["State"]["Pid"], self.image.native_id, self.image.native_digest,
                               *(value[name] for name in names),
                               {"name": self.intent.data_volume, "mountpoint": volume["Mountpoint"], "owner": self.intent.owner})

    @closed_normalization
    def start(self, container_id, deadline):
        require(container_id == self.container_id)
        self._command(("start", container_id), deadline, cap=65)

    @closed_normalization
    def cleanup(self, identity, deadline):
        require(identity.container_id == self.container_id and identity.name == self.intent.name
                and identity.owner == self.intent.owner and identity.image_digest == self.account.image_digest)
        # Re-authenticate the exact ID before removal, even on a poisoned
        # ordinary channel. Names are absence checks, never removal authority.
        raw, _ = self._command(("container", "inspect", identity.container_id), deadline, recovery=True)
        value = inspect_document(raw)
        require(value.get("Id") == identity.container_id and value.get("Name") == identity.name
                and value.get("Image") == self.image.native_id and value.get("ImageDigest") == self.image.native_digest
                and type(value.get("Config")) is dict and type(value["Config"].get("Labels")) is dict
                and value["Config"]["Labels"].get(OWNER_LABEL) == identity.owner)
        self._command(("rm", "--force", "--time=0", identity.container_id), deadline, recovery=True, cap=65)
        for handle in (identity.container_id, identity.name):
            output, status = self._command(("container", "exists", handle), deadline,
                                           recovery=True, cap=0, allowed=(0, 1))
            require(status == 1 and output == b"")
        self.closed = True

    def close(self):
        for executable in self.executables:
            executable.close()
        self.configuration.close()


class OwnedRuntimeConfiguration(_ReservedDescriptors):
    """Held empty runtime configuration, not an OCI/context proof sidecar."""
    def __init__(self, run_directory, budget, deadline, clock=time.monotonic):
        self.budget, self.deadline, self.clock, self.cancelled = budget, deadline, clock, lambda: False
        self._last_clock, self._fds, self.files = clock(), [], []
        self.config_path, self.mounts_path, self.hooks_path = (run_directory + suffix for suffix in
                                                           ("/outer-runtime.conf", "/outer-mounts.conf", "/outer-hooks"))
        try:
            for path in (self.config_path, self.mounts_path):
                chain = _Chain(self, path)
                fd = self._open(chain.leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode=0o600,
                                dir_fd=chain.parent)
                self.files.append((chain, fd, record(self._io(os.fstat, fd))))
            chain = _Chain(self, self.hooks_path)
            self._io(os.mkdir, chain.leaf, mode=0o700, dir_fd=chain.parent)
            fd = self._open(chain.leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent)
            self.files.append((chain, fd, record(self._io(os.fstat, fd))))
            self.recheck()
        except BaseException:
            self.close()
            raise LifecycleError() from None

    def _deadline(self):
        return self.deadline

    def recheck(self):
        for chain, fd, original in self.files:
            chain.recheck()
            held = self._io(os.fstat, fd)
            named = self._io(os.stat, chain.leaf, dir_fd=chain.parent, follow_symlinks=False)
            require(record(held) == record(named) == original and held.st_uid == 0 and held.st_nlink == original.links)
            if stat.S_ISDIR(held.st_mode):
                require(stat.S_IMODE(held.st_mode) == 0o700 and self._io(os.listdir, fd) == [])
            else:
                require(stat.S_ISREG(held.st_mode) and stat.S_IMODE(held.st_mode) == 0o600
                        and held.st_nlink == 1 and held.st_size == 0)

    def close(self):
        self._close_descriptors()

    def recovery_recheck(self, budget, deadline):
        previous = self.budget, self.deadline
        try:
            self.budget, self.deadline = budget, deadline
            self.recheck()
        finally:
            self.budget, self.deadline = previous
