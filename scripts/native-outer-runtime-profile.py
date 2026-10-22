"""Closed hosted prerequisite diagnostic; installed bytes are DATA, never admission.

Capture, cancellation and private-output ownership are extracted from the reviewed
runtime diagnostic. No native daemon, package install, helper execution or service
mutation exists here. This script has no arguments, command/path selectors or
product dependencies.
"""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

LIMIT = 65536
FILE_LIMIT = 2097152
TOTAL_SOURCE = 8388608
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
RAW_NAMES = ("command.stdout", "command.stderr")
EXPECTED_UID = 0
SOURCE_ROOT = "/"
PACKAGES = ("docker-ce", "docker-ce-cli", "containerd.io", "docker.io", "containerd",
            "runc", "init-system-helpers", "dpkg", "systemd", "apparmor")
UNITS = ("docker.service", "docker.socket", "containerd.service")
HELPERS = {
    "invoke-rc.d": "/usr/sbin/invoke-rc.d",
    "deb-systemd-helper": "/usr/bin/deb-systemd-helper",
    "deb-systemd-invoke": "/usr/bin/deb-systemd-invoke",
    "start-stop-daemon": "/usr/sbin/start-stop-daemon",
    "policy-rc.d": "/usr/sbin/policy-rc.d",
    "dpkg-query": "/usr/bin/dpkg-query",
    "systemctl": "/usr/bin/systemctl",
}
OWNER_ALIASES = {"/sbin/start-stop-daemon": "/usr/sbin/start-stop-daemon",
                 "/bin/systemctl": "/usr/bin/systemctl"}
CONTROL_SUFFIXES = ("preinst", "postinst", "prerm", "postrm", "triggers", "conffiles")
SOURCE_PATHS = {"helper:" + name: path for name, path in HELPERS.items()}
SOURCE_PATHS["os-release"] = "/usr/lib/os-release"
for _package in PACKAGES:
    SOURCE_PATHS["copyright:" + _package] = "/usr/share/doc/" + _package + "/copyright"
    for _suffix in CONTROL_SUFFIXES:
        for _arch in ("", ":amd64"):
            SOURCE_PATHS["control:" + _package + _arch + ":" + _suffix] = (
                "/var/lib/dpkg/info/" + _package + _arch + "." + _suffix)
for _unit in UNITS:
    SOURCE_PATHS["vendor:" + _unit] = "/usr/lib/systemd/system/" + _unit
    for _location in ("etc", "run"):
        SOURCE_PATHS[_location + ":" + _unit] = "/" + _location + "/systemd/system/" + _unit
        SOURCE_PATHS[_location + ":" + _unit + ".d"] = "/" + _location + "/systemd/system/" + _unit + ".d"
    SOURCE_PATHS["vendor:" + _unit + ".d"] = "/usr/lib/systemd/system/" + _unit + ".d"
SOURCE_IDS = frozenset(SOURCE_PATHS)
DIRECTORY_IDS = frozenset(source_id for source_id in SOURCE_IDS
                          if source_id.startswith(("vendor:", "etc:", "run:")) and source_id.endswith(".d"))
PURPOSE = "hosted_prerequisite_diagnostic"
WORKFLOW = "Strukturpiloten/docker-lens/.github/workflows/check.yml@refs/heads/main"
JOB = "hosted-prerequisite-diagnostic"
REASONS = {"complete", "ci_identity_unavailable", "checkout_unavailable", "tool_unavailable",
           "command_failed", "timeout", "output_overflow", "invalid_metadata",
           "custody_failure", "cleanup_failure", "collector_io_failure", "completion_unknown",
           "cancelled", "cancelled_completion_unknown", "manifest_overflow"}

def bounded_command(*arguments):
    return ("/usr/bin/timeout", "--signal=TERM", "--kill-after=1s", "2s", *arguments)

CHECKOUT = bounded_command("/usr/bin/git", "rev-parse", "HEAD")
SHOW_FORMAT = "\t".join("$" + "{" + field + "}" for field in ("Package", "Status", "Version", "Architecture")) + "\n"
PACKAGE_QUERY = bounded_command("/usr/bin/dpkg-query", "--show", "--showformat=" + SHOW_FORMAT, *PACKAGES)
OWNER_QUERY = bounded_command("/usr/bin/dpkg-query", "--search", *HELPERS.values(), *OWNER_ALIASES)
UNIT_QUERY = bounded_command("/usr/bin/systemctl", "--no-pager", "--no-ask-password", "show", *UNITS,
                             "--property=Id", "--property=LoadState", "--property=ActiveState",
                             "--property=SubState", "--property=UnitFileState", "--property=FragmentPath",
                             "--property=DropInPaths")
COMMANDS = (CHECKOUT, PACKAGE_QUERY, OWNER_QUERY, UNIT_QUERY)


class Unavailable(Exception):
    def __init__(self, reason):
        if reason not in REASONS or reason == "complete":
            raise ValueError("invalid diagnostic reason")
        self.reason = reason
        super().__init__(reason)


class Cancelled(Exception):
    def __init__(self, signum):
        self.signum = signum
        self.reason = "cancelled"
        self.cleanup = "complete"


class Cancellation:
    def __init__(self):
        self.signum = None

    def request(self, signum, _frame=None):
        self.signum = signum

    def check(self):
        if self.signum is not None:
            raise Cancelled(self.signum)


class RawFiles(dict):
    def discard(self):
        """Unlink raw names promptly, before any bounded child wait."""
        clean = True
        for name, descriptor in list(self.items()):
            try:
                current = os.stat(name, dir_fd=self.held, follow_symlinks=False)
                if identity(current) != identity(os.fstat(descriptor)) or not stat.S_ISREG(current.st_mode):
                    clean = False
                else:
                    os.unlink(name, dir_fd=self.held)
            except OSError:
                clean = False
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    clean = False
                del self[name]
        self.clean = self.clean and clean


def identity(info):
    return info.st_dev, info.st_ino, info.st_uid


@contextmanager
def private_outputs():
    directory = None
    held = None
    original = None
    files = RawFiles()
    files.clean = True
    files.used = 0
    pending = None
    try:
        directory = Path(tempfile.mkdtemp(prefix="dockerlens-runtime-profile."))
        original = os.lstat(directory)
        held = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        files.held = held
        if (identity(os.fstat(held)) != identity(original) or original.st_uid != os.geteuid()
                or stat.S_IMODE(original.st_mode) != 0o700):
            raise Unavailable("custody_failure")
        for name in RAW_NAMES:
            descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=held)
            files[name] = descriptor
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.geteuid() or info.st_nlink != 1):
                raise Unavailable("custody_failure")
        yield files
    except BaseException as failure:
        pending = failure
        if isinstance(failure, OSError):
            pending = Unavailable("custody_failure")
            raise pending from None
        raise
    finally:
        files.discard()
        clean = files.clean
        if held is not None:
            try:
                os.close(held)
            except OSError:
                clean = False
        if directory is not None and original is not None:
            try:
                if identity(os.lstat(directory)) != identity(original):
                    clean = False
                else:
                    directory.rmdir()
            except OSError:
                clean = False
        if not clean and (pending is None or isinstance(pending, Unavailable)):
            raise Unavailable("cleanup_failure")
        if not clean and isinstance(pending, Cancelled):
            pending.cleanup = "failed"


def capture(command, files, prefix, deadline, cancellation=None, allowed_statuses=(0,)):
    """Reviewed incremental drain/cleanup; every production child is allowlisted."""
    if command not in COMMANDS or prefix != "command":
        raise Unavailable("command_failed")
    if cancellation is not None:
        cancellation.check()
    for descriptor in files.values():
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=ENVIRONMENT,
                                   cwd=Path(__file__).resolve().parents[1])
    except FileNotFoundError:
        raise Unavailable("tool_unavailable") from None
    except OSError:
        raise Unavailable("command_failed") from None
    counts = {"stdout": 0, "stderr": 0}
    overflow = False
    timed_out = False
    selector = None
    status = None
    try:
        selector = selectors.DefaultSelector()
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            if cancellation is not None:
                cancellation.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                files.used += len(chunk)
                if files.used > TOTAL_SOURCE:
                    raise Unavailable("output_overflow")
                available = max(0, LIMIT - counts[key.data])
                retained = memoryview(chunk)[:available]
                while retained:
                    written = os.write(files[prefix + "." + key.data], retained)
                    if written <= 0:
                        raise OSError("collector write failed")
                    retained = retained[written:]
                counts[key.data] += len(chunk)
                if counts[key.data] > LIMIT:
                    overflow = True
                    counts[key.data] = LIMIT + 1
        while time.monotonic() < deadline:
            if cancellation is not None:
                cancellation.check()
            try:
                status = process.wait(timeout=min(0.1, max(0, deadline - time.monotonic())))
                break
            except subprocess.TimeoutExpired:
                pass
        if cancellation is not None:
            cancellation.check()
    except BaseException as failure:
        # Delete private bytes before waiting: CI may escalate cancellation to SIGKILL.
        files.discard()
        process.stdout.close()
        process.stderr.close()
        completed = True
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            completed = False
            if isinstance(failure, Cancelled):
                failure.reason = "cancelled_completion_unknown"
        if isinstance(failure, OSError):
            raise Unavailable("collector_io_failure" if completed else "completion_unknown") from None
        raise
    finally:
        if selector is not None:
            selector.close()
        process.stdout.close()
        process.stderr.close()
    if status is None:
        files.discard()
        raise Unavailable("completion_unknown")
    if overflow:
        raise Unavailable("output_overflow")
    if timed_out or status in (124, 137):
        raise Unavailable("timeout")
    if status in (126, 127):
        raise Unavailable("tool_unavailable")
    if status not in allowed_statuses:
        raise Unavailable("command_failed")
    os.lseek(files[prefix + ".stdout"], 0, os.SEEK_SET)
    raw = os.read(files[prefix + ".stdout"], LIMIT + 1)
    if len(raw) != counts["stdout"]:
        raise Unavailable("collector_io_failure")
    return raw



def require(condition, reason="invalid_metadata"):
    if not condition:
        raise Unavailable(reason)


def checkpoint(deadline, cancellation):
    if cancellation is not None:
        cancellation.check()
    require(time.monotonic() < deadline, "timeout")


def source_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def read_source(source_id, files, deadline, cancellation=None):
    """Only finite, source-owned paths; no native-provided paths are followed."""
    require(source_id in SOURCE_IDS)
    path = SOURCE_PATHS[source_id]
    components = path.split("/")[1:]
    require(path.startswith("/") and all(part not in {"", ".", ".."} for part in components))
    descriptors, ancestors = [], []
    failure = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(SOURCE_ROOT, flags)
        descriptors.append(descriptor)
        root_metadata = directory_identity(os.fstat(descriptor))
        require(root_metadata[3] == EXPECTED_UID and root_metadata[2] & 0o022 == 0, "custody_failure")
        for component in components[:-1]:
            checkpoint(deadline, cancellation)
            child = os.open(component, flags, dir_fd=descriptor)
            descriptors.append(child)
            info = os.fstat(child)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == EXPECTED_UID
                    and info.st_mode & 0o022 == 0, "custody_failure")
            ancestors.append((descriptor, component, child, directory_identity(info)))
            descriptor = child
        checkpoint(deadline, cancellation)
        before = os.stat(components[-1], dir_fd=descriptor, follow_symlinks=False)
        require(before.st_uid == EXPECTED_UID and (stat.S_ISLNK(before.st_mode)
                or before.st_mode & 0o022 == 0), "custody_failure")
        result = {"status": "observed", "uid": before.st_uid, "gid": before.st_gid,
                  "mode": stat.S_IMODE(before.st_mode), "size": before.st_size}
        if stat.S_ISLNK(before.st_mode):
            # Only fixed override paths may describe a mask; never follow it.
            target = os.readlink(components[-1], dir_fd=descriptor)
            result.update(status="symlink", mask=target == "/dev/null")
        elif stat.S_ISDIR(before.st_mode):
            require(source_id in DIRECTORY_IDS, "custody_failure")
            child = os.open(components[-1], flags, dir_fd=descriptor)
            descriptors.append(child)
            require(directory_identity(os.fstat(child)) == directory_identity(before), "custody_failure")
            count = 0
            with os.scandir(child) as entries:
                for _entry in entries:
                    checkpoint(deadline, cancellation)
                    count += 1
                    require(count <= 16, "output_overflow")
            result.update(kind="directory", entries=count)
        else:
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "custody_failure")
            require(0 <= before.st_size <= FILE_LIMIT, "output_overflow")
            child = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            dir_fd=descriptor)
            descriptors.append(child)
            require(source_identity(os.fstat(child)) == source_identity(before), "custody_failure")
            raw = bytearray()
            while len(raw) <= FILE_LIMIT:
                checkpoint(deadline, cancellation)
                part = os.read(child, min(4096, FILE_LIMIT + 1 - len(raw)))
                files.used += len(part)
                require(files.used <= TOTAL_SOURCE, "output_overflow")
                raw.extend(part)
                if not part:
                    break
            require(len(raw) == before.st_size <= FILE_LIMIT, "output_overflow")
            require(source_identity(os.fstat(child)) == source_identity(before), "custody_failure")
            result.update(kind="regular", sha256=hashlib.sha256(raw).hexdigest())
            if source_id == "os-release":
                # Parse data only; never source shell assignments.
                text = bytes(raw).decode("utf-8")
                fields = {}
                for line in text.splitlines():
                    if line.startswith(("ID=", "VERSION_ID=")):
                        key, value = line.split("=", 1)
                        require(key not in fields)
                        require(value in ({"ubuntu", '"ubuntu"'} if key == "ID" else {"24.04", '"24.04"'}))
                        fields[key] = value[1:-1] if value.startswith('"') else value
                require(fields == {"ID": "ubuntu", "VERSION_ID": "24.04"})
                result["distribution"] = "ubuntu"
                result["version_id"] = "24.04"
        checkpoint(deadline, cancellation)
        require(source_identity(os.stat(components[-1], dir_fd=descriptor, follow_symlinks=False))
                == source_identity(before), "custody_failure")
        for parent, component, child, original in ancestors:
            require(directory_identity(os.fstat(child)) == original
                    and directory_identity(os.stat(component, dir_fd=parent, follow_symlinks=False)) == original,
                    "custody_failure")
        require(directory_identity(os.lstat(SOURCE_ROOT)) == root_metadata, "custody_failure")
        return result
    except FileNotFoundError:
        return {"status": "missing"}
    except (OSError, UnicodeError):
        raise Unavailable("custody_failure") from None
    except BaseException as error:
        failure = error
        raise
    finally:
        close_failure = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException as error:
                if close_failure is None:
                    close_failure = error
        if close_failure is not None and failure is None:
            raise Unavailable("custody_failure") from None


def package_metadata(raw):
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise Unavailable("invalid_metadata") from None
    require(len(raw) <= LIMIT and (not text or text.endswith("\n")))
    result = {name: {"status": "missing"} for name in PACKAGES}
    seen = set()
    for line in text.splitlines():
        parts = line.split("\t")
        require(len(parts) == 4)
        name, state, version, architecture = parts
        require(name in PACKAGES and name not in seen
                and re.fullmatch(r"(unknown|install|hold|deinstall|purge) (ok|reinstreq) "
                                 r"(not-installed|config-files|half-installed|unpacked|half-configured|triggers-awaited|triggers-pending|installed)", state)
                and re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]{0,95}", version)
                and architecture in {"amd64", "all"})
        seen.add(name)
        result[name] = {"status": "reported", "package_status": state, "version": version,
                        "architecture": architecture, "provenance": "unverified_installed_metadata",
                        "source_reference": ("https://github.com/docker/docker-ce-packaging" if name in
                                             {"docker-ce", "docker-ce-cli"} else
                                             "https://github.com/docker/containerd-packaging" if name == "containerd.io" else
                                             "https://launchpad.net/ubuntu/+source/" + name),
                        "source_reference_status": "review_required", "license_hash_record": "copyright:" + name}
    return result


def owner_metadata(raw):
    result = {name: {"status": "unavailable"} for name in HELPERS}
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise Unavailable("invalid_metadata") from None
    require(not text or text.endswith("\n"))
    for line in text.splitlines():
        require(": " in line)
        owners, path = line.rsplit(": ", 1)
        path = OWNER_ALIASES.get(path, path)
        require(path in HELPERS.values())
        packages = owners.split(", ")
        require(1 <= len(packages) <= 4 and all(
            re.fullmatch(r"(?:docker-ce|docker-ce-cli|containerd\.io|docker\.io|containerd|runc|"
                         r"init-system-helpers|dpkg|systemd|apparmor)(?::amd64)?", item) for item in packages))
        name = next(name for name, value in HELPERS.items() if value == path)
        record = {"status": "reported", "packages": sorted(set(packages)),
                  "provenance": "package_database_report_only"}
        require(result[name]["status"] == "unavailable" or result[name] == record)
        result[name] = record
    return result


def unit_metadata(raw):
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise Unavailable("invalid_metadata") from None
    require(not text or text.endswith("\n"))
    result = {}
    for block in text.strip().split("\n\n"):
        require(bool(block))
        fields = {}
        for line in block.splitlines():
            require("=" in line)
            key, value = line.split("=", 1)
            require(key not in fields)
            fields[key] = value
        require(set(fields) == {"Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths"})
        name = fields["Id"]
        require(name in UNITS and name not in result)
        record = {"status": "reported"}
        for key, allowed in {
            "LoadState": {"stub", "loaded", "not-found", "bad-setting", "error", "merged", "masked"},
            "ActiveState": {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"},
            "SubState": {"running", "listening", "dead", "exited", "failed", "start-pre", "start", "start-post",
                         "stop", "stop-sigterm", "stop-sigkill", "stop-post", "auto-restart", "condition"},
            "UnitFileState": {"", "enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked",
                              "masked-runtime", "static", "disabled", "indirect", "generated", "transient", "bad"},
        }.items():
            record[key] = fields[key] if fields[key] in allowed else "unrecognized"
        fragment = fields["FragmentPath"]
        aliases = {"/lib/systemd/system/" + name: "vendor", "/usr/lib/systemd/system/" + name: "vendor",
                   "/etc/systemd/system/" + name: "etc", "/run/systemd/system/" + name: "run",
                   "/dev/null": "mask", "": "missing"}
        record["fragment"] = aliases.get(fragment, "unrecognized")
        require(len(fields["DropInPaths"]) <= 4096)
        record["dropins_present"] = bool(fields["DropInPaths"])
        result[name] = record
    require(set(result) == set(UNITS))
    return result


def binding(environment):
    constants = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                 "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens",
                 "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                 "GITHUB_WORKFLOW": "Check", "GITHUB_WORKFLOW_REF": WORKFLOW, "GITHUB_JOB": JOB}
    require(all(environment.get(key) == value for key, value in constants.items()), "ci_identity_unavailable")
    for key, pattern in {"GITHUB_SHA": r"[0-9a-f]{40}", "GITHUB_WORKFLOW_SHA": r"[0-9a-f]{40}",
                         "GITHUB_RUN_ID": r"[1-9][0-9]{0,19}", "GITHUB_RUN_ATTEMPT": r"[1-9][0-9]{0,9}",
                         "ImageVersion": r"[0-9]{8}\.[0-9]{1,5}\.[0-9]{1,5}"}.items():
        require(re.fullmatch(pattern, environment.get(key, "")) is not None, "ci_identity_unavailable")
    require(environment["GITHUB_SHA"] == environment["GITHUB_WORKFLOW_SHA"], "ci_identity_unavailable")
    return {"repository": constants["GITHUB_REPOSITORY"], "workflow_ref": WORKFLOW,
            "workflow_sha": environment["GITHUB_WORKFLOW_SHA"], "event": "workflow_dispatch",
            "ref": "refs/heads/main", "run_id": environment["GITHUB_RUN_ID"],
            "run_attempt": environment["GITHUB_RUN_ATTEMPT"], "job": JOB,
            "checkout_sha": environment["GITHUB_SHA"], "runner_os": "Linux", "runner_arch": "X64",
            "runner_environment": "github-hosted", "image_os": "ubuntu24",
            "image_version": environment["ImageVersion"]}


def sample(environment, cancellation=None):
    result = {"schema_version": 1, "purpose": PURPOSE, "admission": "unadmitted",
              "provenance": "unverified_installed_observation", "status": "unavailable",
              "reason": "ci_identity_unavailable", "binding": None, "observations": None}
    deadline = time.monotonic() + 45
    try:
        result["binding"] = binding(environment)
        with private_outputs() as files:
            head = capture(CHECKOUT, files, "command", min(deadline, time.monotonic() + 4), cancellation)
            require(head == (result["binding"]["checkout_sha"] + "\n").encode(), "checkout_unavailable")
            observations = {"packages": {}, "helper_owners": {}, "units": {}, "files": {},
                            "trigger_execution_set": "not_established",
                            "references": {
                                "ubuntu_packages": "https://launchpad.net/ubuntu/+source/",
                                "docker_packaging": "https://github.com/docker/docker-ce-packaging",
                                "helpers": "https://salsa.debian.org/debian/init-system-helpers",
                                "license": "Installed copyright files are hashed only; licensing/source comparison requires independent review.",
                            }}
            partial = False
            for command, field, parser in ((PACKAGE_QUERY, "packages", package_metadata),
                                            (OWNER_QUERY, "helper_owners", owner_metadata),
                                            (UNIT_QUERY, "units", unit_metadata)):
                checkpoint(deadline, cancellation)
                try:
                    observations[field] = parser(capture(command, files, "command",
                                                          min(deadline, time.monotonic() + 4), cancellation, (0, 1)))
                except Unavailable as error:
                    if error.reason in {"completion_unknown", "cleanup_failure", "collector_io_failure", "output_overflow"}:
                        raise
                    observations[field] = {"status": "unavailable", "reason": error.reason}
                    partial = True
            for source_id in sorted(SOURCE_IDS):
                checkpoint(deadline, cancellation)
                try:
                    record = read_source(source_id, files, deadline, cancellation)
                except Unavailable as error:
                    if error.reason in {"output_overflow", "timeout", "cleanup_failure"}:
                        raise
                    record = {"status": "unavailable", "reason": error.reason}
                observations["files"][source_id] = record
                if record["status"] not in {"observed", "missing"}:
                    # Known masks are observations, not positive policy admission.
                    partial = partial or not (record["status"] == "symlink" and record.get("mask") is True
                                              and source_id.startswith(("etc:", "run:")))
            require(observations["files"]["os-release"].get("distribution") == "ubuntu", "invalid_metadata")
            result["observations"] = observations
        result.update(status="partial" if partial else "observed", reason="complete")
    except Unavailable as error:
        result.update(status="unavailable", reason=error.reason, observations=None)
    return result


def main():
    if len(sys.argv) != 1:
        sys.stderr.write("hosted prerequisite diagnostic expects no arguments\n")
        return 2
    cancellation = Cancellation()
    previous = {number: signal.signal(number, cancellation.request) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        try:
            result = sample(os.environ, cancellation)
            cancellation.check()
        except Cancelled as failure:
            result = {"schema_version": 1, "purpose": PURPOSE, "admission": "unadmitted",
                      "status": "cancelled", "reason": failure.reason, "cleanup": failure.cleanup}
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 128 + failure.signum
        raw = json.dumps(result, sort_keys=True, separators=(",", ":"))
        if len(raw.encode()) > LIMIT:
            result = {"schema_version": 1, "purpose": PURPOSE, "admission": "unadmitted",
                      "status": "unavailable", "reason": "manifest_overflow"}
            raw = json.dumps(result, separators=(",", ":"))
        print(raw)
        return 2 if result.get("reason") in {"ci_identity_unavailable", "checkout_unavailable", "completion_unknown",
                                             "cleanup_failure", "collector_io_failure", "manifest_overflow"} else 0
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    sys.excepthook = lambda *_args: sys.stderr.write("hosted prerequisite diagnostic internal error\n")
    sys.exit(main())
