"""Canonical validation-only outer lifecycle and private consumer dispatcher.

The shell retains its existing 28-test lane. This parent alone owns the root
broker pipes; children receive a single private stdin context and no broker FD.
ACKs describe completed phases, never independently verified resource absence.
Local runs carry local_process provenance and null CI identifiers. Partial
hosted identities fail before shell startup. Ordinary failure attempts root and
shell cleanup within the original lane deadline; expiry or host death can leave
cleanup incomplete and can never produce a successful qualification receipt.
"""

import base64
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time

from native_outer_broker_protocol import (Binding, Endpoint, ExpectationClaim, Ledger,
                                         PidsTiming, PidsWindow, payload_wire)
from native_outer_coordinator import (PIDS_EXTERNAL_CLEANUP, PIDS_PRODUCER_CLEANUP, ReservedBudget, ScopeBudget, bounded_source_io, candidate_account,
                                      derive_consumer_authority, phase_proxy, phase_read,
                                      phase_relay, phase_write, prepare_reservations, require,
                                      run_private_role, serialize_consumer_context,
                                      socket_mount_options)
from native_outer_launch import CreateIntent, derive_launch, expectation_digest, intent_digest, source_defaults
from native_outer_lifecycle import CallerLogCustody, RuntimeProfile, _validate_oci
from native_outer_runtime import normalize_image

SCRIPTS = Path(__file__).resolve().parent
PIDS_TARGET = "native_pids_limit"
PIDS_TEST = "live_pids_limit_effects_match_engine"


def execution_identity(environment):
    """Classify actual caller provenance before any lane resource is created."""
    names = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    present = [name in environment for name in names]
    if not any(present) and "GITHUB_ACTIONS" not in environment:
        return "local_process", None, None
    require(all(present))
    require("GITHUB_ACTIONS" not in environment or environment["GITHUB_ACTIONS"] == "true")
    values = tuple(environment[name] for name in names)
    require(all(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None for value in values))
    return "github_actions", *values


def image_observation(preflight, account):
    config = preflight.semantic["config"]
    raw = {"Id": preflight.native_image_id, "Digest": preflight.native_image_digest,
           "RepoDigests": list(preflight.native_repo_digests), "Architecture": preflight.architecture,
           "Os": preflight.os, "User": config["User"],
           "Config": {key: value for key, value in config.items() if value},
           "RootFS": {"Type": "layers", "Layers": list(preflight.ordered_diff_ids)}}
    return normalize_image(json.dumps([raw], separators=(",", ":")).encode(), account)


def diagnostic_prepare(directory, owner, lane, descriptor, budget=None):
    spec = importlib.util.spec_from_file_location("canonical_port_diagnostic", SCRIPTS / "native-port-start-diagnostic.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.prepare(Path(directory), owner, lane, descriptor=descriptor, budget=budget)


def fixed_environment():
    # Cargo's reviewed toolchain/cache locations are caller configuration. No
    # runtime selectors, credentials or arbitrary NATIVE_* variables pass through.
    result = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"}
    for name in ("HOME", "CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR"):
        if name in os.environ:
            result[name] = os.environ[name]
    return result


class Canonical:
    def __init__(self, candidate, lane, deadline_ns, *, spawn=subprocess.Popen, identity=None):
        require(re.fullmatch(r"[0-9a-f]{40}", candidate) is not None)
        require(lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"))
        self.candidate, self.lane, self.deadline_ns, self.spawn = candidate, lane, deadline_ns, spawn
        self.execution_origin, self.ci_run_id, self.ci_run_attempt = execution_identity(os.environ) if identity is None else identity
        self.session = os.urandom(32).hex()
        self.book, self.roles = prepare_reservations(self.session, deadline_ns)
        self.cancelled = False
        self.scope = ScopeBudget(self.budget("caller_lane"), self.budget("caller_pids"))
        with open(SCRIPTS / "native-conformance.sh", "rb", buffering=0) as stream:
            shell = bounded_source_io(self.scope, 131073, stream.read)
        require(0 < len(shell) <= 131072)
        pins = re.findall(rb"^FIXTURE_IMAGE='([^']+)'$", shell, re.M)
        require(len(pins) == 1)
        self.fixture_pin = pins[0].decode("ascii")
        self.endpoint = self.broker = self.caller = self.context = None
        self.state = "new"
        self.final_verified = False
        self.phase_stats = {}

    def budget(self, role):
        return ReservedBudget(self.book.claim_before_spawn(self.roles[role]), time.monotonic_ns, lambda: self.cancelled)

    def exchange(self, verb, payload=None):
        self.endpoint.request(verb, payload)
        return self.endpoint.receive().payload

    def setup(self, arguments):
        require(self.state == "new" and len(arguments) == 4)
        directory, owner, lane, image_ref = arguments
        require(lane == self.lane and re.fullmatch(r"[A-Za-z0-9]{8}", owner) is not None)
        require(Path(directory).is_absolute() and Path(directory).resolve() == Path(directory)
                and Path(directory).name == "dockerlens-native." + owner)
        architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
        require(architecture is not None and sys.platform == "linux")
        self.account = candidate_account(lane, architecture, image_ref, budget=self.scope)
        self.intent = CreateIntent(lane, owner, os.urandom(32).hex(), image_ref, "dl-native-" + owner,
                                   "dl-native-data-" + owner, "dl-native-net-" + owner,
                                   directory + "/socket", directory)
        now = time.monotonic_ns()
        startup, custody, cleanup = min(now + 120_000_000_000, self.deadline_ns - 46_000_000_000), self.deadline_ns - 46_000_000_000, self.deadline_ns
        require(now < startup <= custody < cleanup)
        self.startup_ns = startup
        binding = Binding(self.session, self.candidate, self.ci_run_id, self.ci_run_attempt,
                          intent_digest(self.intent, self.account, self.candidate), self.account.image_digest,
                          execution_origin=self.execution_origin)
        for role in ("root_lane", "root_pids", "root_recovery"):
            self.book.claim_before_spawn(self.roles[role])
        argv = ("/usr/bin/python3", "-E", "-s", str(SCRIPTS / "native_outer_broker.py"), self.session,
                self.candidate, self.execution_origin, binding.run_id or "", binding.run_attempt or "", lane, owner, self.intent.nonce, image_ref,
                directory, architecture, str(startup), str(custody), str(cleanup))
        if os.geteuid() != 0:
            argv = ("/usr/bin/sudo", "-n", *argv)
        self.broker = self.spawn(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 close_fds=True, start_new_session=True, env=fixed_environment())
        ledger = Ledger(30000, 1048576, startup / 1e9, custody / 1e9, cleanup / 1e9, cleanup / 1e9,
                        time.monotonic, lambda: self.cancelled, reserved_budget=self.scope)
        self.endpoint = Endpoint("client", binding, self.broker.stdout.fileno(), self.broker.stdin.fileno(), ledger,
                                 pids_window=PidsWindow(custody, time.monotonic_ns))
        self.preflight = self.exchange("preflight")
        require(RuntimeProfile(**self.preflight.runtime_profile) ==
                RuntimeProfile("linux", False, False, "4.9.3", "crun", "1.14.1", "systemd", "v2"))
        self.image = image_observation(self.preflight, self.account)
        options = socket_mount_options(self.intent.socket_source)
        provisional = derive_launch(self.intent, self.image.launch_image(), self.account,
                                    source_defaults(self.intent, self.account, None, options))
        self.caller = CallerLogCustody(provisional, directory + "/diagnostics/daemon.log", self.scope,
                                      startup / 1e9, custody / 1e9, time.monotonic, lambda: self.cancelled)
        duplicate = os.dup(self.caller._log.fd)
        try:
            diagnostic_prepare(directory, owner, lane, duplicate, budget=self.scope)
        finally:
            os.close(duplicate)
        self.caller.empty()
        self.exchange("create")
        self.database = self.exchange("initialize")
        expected = derive_launch(self.intent, self.image.launch_image(), self.account,
                                 source_defaults(self.intent, self.account, self.database, options))
        self.expectation = expectation_digest(expected, self.endpoint.id, binding.intent_digest)
        self.oci = self.exchange("bind_expectation", ExpectationClaim(self.expectation))
        _validate_oci(self.oci.raw, expected, self.endpoint.id)
        self.caller.expectation = expected
        self.exchange("start")
        # Only capture once a complete original stdout frame exists. A partial
        # bootstrap cannot close/reopen the caller's original custody descriptor.
        while True:
            self.scope.check()
            raw = bounded_source_io(self.scope, 2048,
                                    lambda size: os.pread(self.caller._log.fd, size, 0))
            if any(b" stdout " in line for line in raw.split(b"\n")[:-1]):
                break
            require(time.monotonic_ns() < startup)
            time.sleep(0.05)
        self.caller.capture()
        self.state = "started"

    def make_context(self, timing):
        info, prefix, frame = self.caller.recheck()
        boundary = [1, [self.database.init_pid, frame.start, frame.uid], list(frame.namespaces),
                    [frame.mount[0], frame.mount[1], int(frame.mount[2][2:])], list(frame.controller[:2]),
                    self.oci.sha256, hashlib.sha256(prefix).hexdigest(), self.endpoint.binding.intent_digest,
                    self.expectation, [self.image.native_id, self.image.native_digest,
                                       0 if self.image.native_digest_kind == "index" else 1]]
        context = {"schema_version": 1, "contract": "outer-private-context-v1",
                   "binding": {"session": self.session, "candidate_sha": self.candidate,
                               "execution_origin": self.execution_origin,
                               "ci_run_id": self.endpoint.binding.run_id, "ci_run_attempt": self.endpoint.binding.run_attempt,
                               "owner": self.intent.owner, "lane": self.lane, "outer_id": self.endpoint.id,
                               "intent_digest": self.endpoint.binding.intent_digest, "expectation_digest": self.expectation},
                   "source": {"intent": vars(self.intent), "preflight": payload_wire("preflight", self.preflight),
                              "database": payload_wire("initialize", self.database), "oci": payload_wire("bind_expectation", self.oci),
                              "log": {"object": list(info), "prefix": base64.b64encode(prefix).decode("ascii")}},
                   "boundary": boundary,
                   "pids": {"start_ns": timing.start_ns, "deadline_ns": timing.deadline_ns, "deadline_epoch": self.deadline_epoch,
                            "producer_reservation": {"ordinary_calls": self.roles["producer"].allowance.native_calls,
                                                     "ordinary_bytes": self.roles["producer"].allowance.source_bytes,
                                                     "cleanup_calls": PIDS_PRODUCER_CLEANUP[0], "cleanup_bytes": PIDS_PRODUCER_CLEANUP[1]},
                            "external_reservation": {"ordinary_calls": sum(self.roles[role].allowance.native_calls for role in ("root_pids", "caller_pids", "reader")),
                                                     "ordinary_bytes": sum(self.roles[role].allowance.source_bytes for role in ("root_pids", "caller_pids", "reader")),
                                                     "cleanup_calls": PIDS_EXTERNAL_CLEANUP[0], "cleanup_bytes": PIDS_EXTERNAL_CLEANUP[1]}}}
        derive_consumer_authority(context, budget=self.scope)
        return context

    def reader_arguments(self, arguments):
        require(len(arguments) == 12)
        directory, candidate, owner, lane, version, api, mode, package, fixture, image, outer, uid = arguments
        require((directory, candidate, owner, lane, image, outer) ==
                (self.intent.run_directory, self.candidate, self.intent.owner, self.lane, self.intent.image_ref, self.endpoint.id))
        require(version in (("20.10.5", "20.10.5+dfsg1") if lane.startswith("debian11-") else ("29.8.1",))
                and re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}", api) is not None
                and mode == ("rootless" if lane.endswith("rootless") else "rootful")
                and package == ("20.10.5+dfsg1-1+deb11u2" if lane.startswith("debian11-") else "")
                and re.fullmatch(r"0|[1-9][0-9]{0,9}", uid) is not None)
        require(self.fixture_pin == fixture)
        # Rendering uses the observed daemon API, not the acquisition client's
        # independent fixed API. Corroborate the existing owned version record.
        require(self.version_record() == (version, api))
        return arguments

    def version_record(self):
        descriptor = os.open(self.intent.run_directory + "/version.json", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            raw = bounded_source_io(self.scope, 16385,
                                    lambda size: os.read(descriptor, size))
            self.scope.debit(io_calls=3)
            after = os.fstat(descriptor)
            stable = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                                   info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            require(0 < len(raw) <= 16384 and stable(before) == stable(after) and stat.S_ISREG(before.st_mode)
                    and before.st_uid == os.geteuid() and before.st_nlink == 1)
            def unique(pairs):
                result = {}
                for key, item in pairs:
                    require(key not in result)
                    result[key] = item
                return result
            value = json.loads(raw, object_pairs_hook=unique)
            require(type(value) is dict)
            return value["Version"], value["ApiVersion"]
        finally:
            os.close(descriptor)

    def producer(self, arguments):
        require(self.state == "started" and len(arguments) == 13)
        metadata, inner = arguments[:12], arguments[12]
        self.reader_arguments(metadata)
        require(re.fullmatch(r"[0-9a-f]{64}", inner) is not None)
        # Exact listing happened in the shell runner before this once-only S/D.
        start = time.monotonic_ns()
        timing = PidsTiming(start, start + 180_000_000_000)
        self.deadline_epoch = int(time.time()) + 180
        require(timing.deadline_ns <= self.deadline_ns - 46_000_000_000)
        self.scope.begin(timing)
        self.exchange("begin_pids", timing)
        self.exchange("pids_before_producer")
        self.context = self.make_context(timing)
        env = fixed_environment()
        env.update(dict(zip(("NATIVE_CAPTURE_DIR", "NATIVE_PIDS_LIMIT_CANDIDATE_SHA", "_owner", "NATIVE_LANE",
                             "NATIVE_ENGINE_VERSION", "NATIVE_API_VERSION", "NATIVE_DAEMON_MODE", "_package", "NATIVE_FIXTURE_IMAGE",
                             "_image", "_outer", "_uid"), metadata)))
        for key in tuple(env):
            if key.startswith("_"):
                del env[key]
        env.update({"NATIVE_OUTER_CONTAINER": self.intent.name, "NATIVE_OUTER_CONTAINER_ID": self.endpoint.id,
                    "NATIVE_OUTER_IMAGE": self.intent.image_ref, "NATIVE_ENGINE_SOCKET": self.intent.socket_source + "/docker.sock",
                    "NATIVE_CONTAINER_ID": inner, "NATIVE_PIDS_LIMIT_PROOF_PATH": self.intent.run_directory + "/pids-limit-v2.json",
                    "NATIVE_PIDS_LIMIT_DEADLINE_EPOCH": str(self.deadline_epoch), "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1",
                    "NATIVE_PODMAN_USE_SUDO": "1" if os.geteuid() != 0 else "0", "DOCKERLENS_CANONICAL_CHILD": "1"})
        self.book.claim_before_spawn(self.roles["producer"])
        run_private_role(("/bin/bash", str(SCRIPTS / "run-exact-native-test.sh"), PIDS_TARGET, PIDS_TEST), env,
                         serialize_consumer_context(self.context), self.scope, timing.deadline_ns)
        self.exchange("pids_before_reader")
        self.caller.recheck()
        self.metadata, self.state = metadata, "produced"

    def reader(self, arguments):
        require(self.state == "produced" and arguments == self.metadata)
        self.reader_arguments(arguments)
        self.book.claim_before_spawn(self.roles["reader"])
        env = fixed_environment()
        env["NATIVE_PIDS_LIMIT_DEADLINE_EPOCH"] = str(self.context["pids"]["deadline_epoch"])
        run_private_role(("/usr/bin/python3", "-E", "-s", str(SCRIPTS / "native_pids_limit_v2_proof.py"), *arguments), env,
                         serialize_consumer_context(self.context), self.scope, self.context["pids"]["deadline_ns"])
        self.caller.recheck()
        self.exchange("seal_pids")
        self.scope.end()
        self.state = "sealed"

    def emitter(self, arguments):
        require(self.state == "sealed" and len(arguments) == 19)
        directory = self.intent.run_directory
        names = ("version.json", "target-shapes.json", "source-probes.json", "network-probes.json", "volume-probes.json",
                 "volume-label-probes.json", "identity-probes.json", "port-probes.json", "health-metadata.json",
                 "network-attachments-v1.json", "bind-relabel-config-v1.json")
        require(arguments[:12] == [*(directory + "/" + name for name in names), directory]
                and arguments[13:] == [self.lane, self.intent.image_ref, self.metadata[6], self.metadata[7], self.candidate, self.intent.owner])
        evidence = os.environ.get("DOCKERLENS_NATIVE_EVIDENCE_DIR")
        require(evidence is not None and arguments[12] == evidence + "/" + self.lane + ".json")
        self.exchange("recheck")
        self.caller.recheck()
        env = fixed_environment()
        env["DOCKERLENS_OUTER_LANE_DEADLINE_NS"] = str(self.deadline_ns)
        env.update({"NATIVE_FIXTURE_IMAGE": self.fixture_pin,
                    "NATIVE_OUTER_CONTAINER_ID": self.endpoint.id,
                    "NATIVE_BIND_RELABEL_DAEMON_UID": self.metadata[11]})
        self.book.claim_before_spawn(self.roles["emitter"])
        run_private_role(("/usr/bin/python3", "-E", "-s", str(SCRIPTS / "native-evidence.py"), *arguments), env,
                         serialize_consumer_context(self.context), self.scope, self.deadline_ns - 46_000_000_000)
        self.state = "emitted"

    def dispatch(self, request):
        require(type(request) is list and request and all(type(value) is str for value in request))
        phase, arguments = request[0], request[1:]
        if phase in ("setup", "producer", "reader", "emitter"):
            getattr(self, phase)(arguments)
        elif phase == "final":
            require(not arguments and self.state in ("sealed", "emitted"))
            self.exchange("recheck")
            self.caller.recheck()
            self.state = "final"
            self.final_verified = True
        elif phase == "teardown":
            require(not arguments and self.endpoint is not None and self.state != "closed")
            self.exchange("teardown")
            self.state = "closed"
        else:
            require(False)

    def ack_deadline(self, phase):
        if phase == "setup":
            return self.startup_ns
        if phase in ("producer", "reader"):
            return self.context["pids"]["deadline_ns"]
        if phase == "teardown":
            return self.deadline_ns
        return self.deadline_ns - 46_000_000_000

    def close(self):
        errors = []
        try:
            if self.endpoint is not None:
                try:
                    self.endpoint.close()  # EOF leaves exact-ID cleanup with root.
                except BaseException as error:
                    errors.append(error)
            if self.broker is not None:
                # Endpoint failure cannot prevent EOF delivery on its original
                # pipes. The root owns all cleanup observations/removal itself.
                for stream in (self.broker.stdin, self.broker.stdout):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError as error:
                            if error.errno != errno.EBADF:
                                errors.append(error)
                        except BaseException as error:
                            errors.append(error)
                remaining = (self.deadline_ns - time.monotonic_ns()) / 1e9
                require(remaining > 0)
                require(self.broker.wait(timeout=remaining) == 0)
        except BaseException as error:
            errors.append(error)
        finally:
            if self.caller is not None:
                try:
                    self.caller.close()
                except BaseException as error:
                    errors.append(error)
        require(not errors)


def launch(shell, lane):
    require(sys.platform == "linux")
    identity = execution_identity(os.environ)
    candidate = subprocess.run(("git", "-C", str(SCRIPTS.parent), "rev-parse", "HEAD"), check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True).stdout.decode().strip()
    canonical = Canonical(candidate, lane, time.monotonic_ns() + 1800_000_000_000, identity=identity)
    # These are the shell/relay upstream ends, never root broker descriptors.
    requests_read, requests_write = os.pipe()
    replies_read, replies_write = os.pipe()
    open_descriptors = {requests_read, requests_write, replies_read, replies_write}
    def close_descriptor(descriptor):
        if descriptor in open_descriptors:
            open_descriptors.remove(descriptor)
            os.close(descriptor)
    environment = dict(os.environ, DOCKERLENS_CANONICAL_ACTIVE="1", DOCKERLENS_CANONICAL_REQUEST_FD=str(requests_write),
                       DOCKERLENS_CANONICAL_REPLY_FD=str(replies_read))
    process = None
    failure = None
    original_signals = {}
    try:
        process = subprocess.Popen(("/bin/bash", str(Path(shell).resolve()), lane), env=environment,
                                   pass_fds=(requests_write, replies_read), close_fds=True, start_new_session=True)
        close_descriptor(requests_write)
        close_descriptor(replies_read)
        def cancel(_signum, _frame):
            canonical.cancelled = True
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            original_signals[signum] = signal.getsignal(signum)
            signal.signal(signum, cancel)
        while process.poll() is None:
            request = phase_read(requests_read, deadline_ns=canonical.deadline_ns,
                                 alive=lambda: process.poll() is None and not canonical.cancelled,
                                 budget=canonical.scope, stats=canonical.phase_stats)
            canonical.dispatch(request)
            require(time.monotonic_ns() < canonical.ack_deadline(request[0]) and not canonical.cancelled)
            phase_write(replies_write, {"ok": True}, budget=canonical.scope, stats=canonical.phase_stats)
            if request == ["teardown"]:
                break
        remaining = (canonical.deadline_ns - time.monotonic_ns()) / 1e9
        require(remaining > 0)
        require(process.wait(timeout=remaining) == 0
                and canonical.state == "closed" and canonical.final_verified)
    except BaseException as error:
        failure = error
    finally:
        # Ordinary failure first lets the root observe EOF and finish its
        # original cleanup, then releases blocked proxies through EOF. Shell
        # EXIT cleanup may independently establish absence and clean its known
        # resources. No root exit code or ACK substitutes for that observation.
        try:
            canonical.close()
        except BaseException as error:
            failure = failure or error
        for descriptor in tuple(open_descriptors):
            try:
                close_descriptor(descriptor)
            except OSError as error:
                failure = failure or error
        try:
            if process is not None and process.poll() is None:
                # Signal only the shell leader: its foreground proxy has just
                # received EOF, while the shell needs its EXIT trap intact.
                process.send_signal(signal.SIGTERM)
                remaining = (canonical.deadline_ns - time.monotonic_ns()) / 1e9
                require(remaining > 0)
                process.wait(timeout=remaining)
        except BaseException as error:
            failure = failure or error
        finally:
            if process is not None:
                # Always finalize the whole owned group, including surviving
                # relay/proxy descendants. Expiry or unhandled host death can
                # leave cleanup incomplete; neither becomes a success receipt.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    failure = failure or error
                if process.poll() is None:
                    remaining = (canonical.deadline_ns - time.monotonic_ns()) / 1e9
                    if remaining > 0:
                        try:
                            process.wait(timeout=remaining)
                        except BaseException as error:
                            failure = failure or error
                    else:
                        process.poll()  # Nonblocking reap attempt; no renewed D.
            for signum, handler in original_signals.items():
                signal.signal(signum, handler)
    if failure is not None:
        raise failure


def main(arguments):
    require(bool(arguments))
    if arguments[0] == "launch":
        require(len(arguments) == 3)
        launch(*arguments[1:])
    elif arguments[0] == "relay":
        require(len(arguments) == 3)
        phase_relay(int(arguments[1]), int(arguments[2]))
    else:
        phase_proxy(arguments)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception:
        raise SystemExit("canonical outer lifecycle refused") from None
