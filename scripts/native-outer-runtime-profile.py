"""Bounded CI-job identity sample, not native placement or boundary evidence."""

from contextlib import contextmanager
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
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
PODMAN = ("/usr/bin/sudo", "-n", "/usr/bin/timeout", "--signal=TERM", "--kill-after=2s",
          "10s", "/usr/bin/podman", "--remote=false", "info", "--format", "json")
CHECKOUT = ("/usr/bin/timeout", "--signal=TERM", "--kill-after=1s", "2s",
            "/usr/bin/git", "rev-parse", "HEAD")
PACKAGES = ("/usr/bin/timeout", "--signal=TERM", "--kill-after=1s", "2s",
            "/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${Version}\t${Architecture}\n",
            "podman", "crun", "runc")
RAW_NAMES = tuple(prefix + "." + stream for prefix in ("checkout", "podman", "packages")
                  for stream in ("stdout", "stderr"))
REASONS = {"complete", "ci_identity_unavailable", "checkout_unavailable", "tool_unavailable",
           "command_failed", "timeout", "output_overflow", "invalid_json", "invalid_profile",
           "runtime_unavailable", "unknown_runtime", "unexpected_rootless", "unexpected_remote",
           "custody_failure", "cleanup_failure", "collector_io_failure", "completion_unknown",
           "cancelled", "cancelled_completion_unknown"}
CORE_VERSION = r"(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})"
REVISION = r"(?:-[0-9]{1,4}(?:ubuntu[0-9]{1,4}(?:\.[0-9]{1,4}){0,3})?(?:build[0-9]{1,4})?(?:~[0-9]{2}\.[0-9]{2}(?:\.[0-9]{1,4})?)?)?"
VERSION = CORE_VERSION + r"(?:-rc[1-9][0-9]{0,2})?" + REVISION


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
    except OSError:
        raise Unavailable("custody_failure") from None
    finally:
        pending = sys.exc_info()[1]
        files.discard()
        clean = files.clean
        if held is not None:
            os.close(held)
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
    """Drain incrementally; never kill or claim to kill a privileged child."""
    if cancellation is not None:
        cancellation.check()
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
    return os.read(files[prefix + ".stdout"], LIMIT + 1)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Unavailable("invalid_json")
        result[key] = value
    return result


def invalid_constant(_value):
    raise Unavailable("invalid_json")


def profile(payload):
    try:
        value = json.loads(payload, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Unavailable("invalid_json") from None
    if type(value) is not dict or type(value.get("host")) is not dict or type(value.get("version")) is not dict:
        raise Unavailable("invalid_profile")
    host, version = value["host"], value["version"]
    if host.get("os") != "linux":
        raise Unavailable("invalid_profile")
    security = host.get("security")
    if type(security) is not dict or type(security.get("rootless")) is not bool:
        raise Unavailable("invalid_profile")
    if security["rootless"]:
        raise Unavailable("unexpected_rootless")
    if type(host.get("serviceIsRemote")) is not bool:
        raise Unavailable("invalid_profile")
    if host["serviceIsRemote"]:
        raise Unavailable("unexpected_remote")
    runtime = host.get("ociRuntime")
    if type(runtime) is not dict:
        raise Unavailable("runtime_unavailable")
    name = runtime.get("name")
    if name not in ("crun", "runc"):
        raise Unavailable("unknown_runtime")
    podman_version, runtime_text = version.get("Version"), runtime.get("version")
    if (type(podman_version) is not str or re.fullmatch(VERSION, podman_version) is None
            or type(runtime_text) is not str):
        raise Unavailable("invalid_profile")
    first = re.fullmatch(name + r" version (" + VERSION + ")", runtime_text.split("\n", 1)[0])
    if (first is None or host.get("cgroupManager") not in ("systemd", "cgroupfs")
            or host.get("cgroupVersion") not in ("v1", "v2")):
        raise Unavailable("invalid_profile")
    package = {"status": "unavailable"}
    if "package" in runtime:
        package = {"status": "unrecognized"}
        if type(runtime["package"]) is str:
            match = re.fullmatch(name + "_(" + CORE_VERSION + r"(?:\+(?:dfsg|ds)[0-9]{0,3})?" + REVISION + ")_(amd64|arm64)", runtime["package"])
            if match:
                package = {"status": "reported", "name": name, "version": match[1], "architecture": match[2]}
    commit = {"status": "unavailable"}
    if "GitCommit" in version and version["GitCommit"] not in (None, ""):
        commit = {"status": "unrecognized"}
        if type(version["GitCommit"]) is str and re.fullmatch("[0-9a-f]{40}", version["GitCommit"]):
            commit = {"status": "reported", "value": version["GitCommit"]}
    return {"podman_version": podman_version, "runtime": name, "runtime_version": first[1],
            "cgroup_manager": host["cgroupManager"], "cgroup_version": host["cgroupVersion"],
            "rootless": False, "remote": False, "runtime_package": package,
            "podman_git_commit": commit, "podman_package": {"status": "unavailable"},
            "binary_ownership": "unverified"}


def package_metadata(payload):
    """Closed distro records; not proof that an executable belongs to a package."""
    records = {}
    try:
        text = payload.decode("ascii")
    except UnicodeError:
        return records
    lines = text.splitlines()
    if not text.endswith("\n") or not 1 <= len(lines) <= 3:
        return records
    for line in lines:
        match = re.fullmatch(r"(podman|crun|runc)\t((?:[1-9][0-9]{0,2}:)?" + CORE_VERSION
                             + r"(?:\+(?:dfsg|ds)[0-9]{0,3})?" + REVISION + r")\t(amd64|arm64)", line)
        if match is None or match[1] in records:
            return {}
        records[match[1]] = {"status": "reported", "name": match[1], "version": match[2], "architecture": match[3]}
    return records


def sample(environment, cancellation=None):
    result = {"schema_version": 1, "purpose": "ci_job_outer_runtime_identity_sample",
              "status": "unavailable", "reason": "ci_identity_unavailable",
              "binding": {"run_id": None, "run_attempt": None, "job": None, "checkout_sha": None},
              "profile": None}
    run, attempt, job = (environment.get(name, "") for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"))
    if re.fullmatch("[1-9][0-9]{0,19}", run) is None or re.fullmatch("[1-9][0-9]{0,9}", attempt) is None or job != "scaffold":
        return result
    result["binding"].update(run_id=run, run_attempt=attempt, job=job)
    deadline = time.monotonic() + 24
    try:
        with private_outputs() as files:
            try:
                head = capture(CHECKOUT, files, "checkout", min(deadline, time.monotonic() + 4), cancellation)
            except Unavailable:
                raise Unavailable("checkout_unavailable") from None
            if re.fullmatch(b"[0-9a-f]{40}\n", head) is None:
                raise Unavailable("checkout_unavailable")
            result["binding"]["checkout_sha"] = head[:-1].decode("ascii")
            result["profile"] = profile(capture(PODMAN, files, "podman", min(deadline, time.monotonic() + 15), cancellation))
            try:
                # dpkg-query returns 1 when one of these fixed packages is absent;
                # strictly parsed present records remain reported metadata only.
                metadata = package_metadata(capture(PACKAGES, files, "packages", min(deadline, time.monotonic() + 4), cancellation, (0, 1)))
            except Unavailable as failure:
                if failure.reason in ("completion_unknown", "cleanup_failure", "collector_io_failure"):
                    raise
                metadata = {}
            result["profile"]["podman_package"] = metadata.get("podman", {"status": "unavailable"})
            result["profile"]["runtime_distro_package"] = metadata.get(result["profile"]["runtime"], {"status": "unavailable"})
        result.update(status="observed", reason="complete")
    except Unavailable as failure:
        result.update(status="unavailable", reason=failure.reason, profile=None)
    return result


def main():
    if len(sys.argv) != 1:
        raise SystemExit("outer runtime profile expects no arguments")
    cancellation = Cancellation()
    previous = {number: signal.signal(number, cancellation.request) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        try:
            result = sample(os.environ, cancellation)
            cancellation.check()
        except Cancelled as failure:
            print(json.dumps({"schema_version": 1, "purpose": "ci_job_outer_runtime_identity_sample",
                              "status": "cancelled", "reason": failure.reason,
                              "cleanup": failure.cleanup}, sort_keys=True))
            return 128 + failure.signum
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    # Unhandled programming errors remain nonzero, without leaking a raw value
    # or host path in the default exception traceback. They are not unavailable/0.
    sys.excepthook = lambda *_args: sys.stderr.write("outer runtime profile internal error\n")
    sys.exit(main())
