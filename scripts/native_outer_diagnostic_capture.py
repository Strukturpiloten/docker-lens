"""DockerLens-local diagnostic capture mechanics, with no default command authority.

Each fixed frontend supplies its own closed command/prefix policy, exception
class and limits. A context holds no spent counters: every private-output scope
owns its own original counter, which source readers may also debit.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import tempfile
import time
from types import MappingProxyType


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


def identity(info):
    return info.st_dev, info.st_ino, info.st_uid


class RawFiles(dict):
    def __init__(self, context):
        super().__init__()
        self.context = context
        self.clean = True
        self.used = 0

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


@dataclass(frozen=True)
class CaptureContext:
    """Immutable frontend-owned policy; all authority arguments are mandatory.

    ``commands`` contains exact (argv tuple, staging prefix) pairs. Neither an
    allowed argv with another prefix nor another context's files are accepted.
    ``total_source_limit=None`` explicitly preserves a frontend without a
    cumulative source pool; it does not disable per-stream or time bounds.
    """

    unavailable: type
    cancelled_type: type
    commands: tuple
    environment: object
    directory: Path
    stream_limit: int
    total_source_limit: object
    reuse_outputs: bool
    raw_names: tuple = field(init=False)

    def __post_init__(self):
        valid = (isinstance(self.unavailable, type) and issubclass(self.unavailable, Exception)
                 and isinstance(self.cancelled_type, type) and issubclass(self.cancelled_type, Exception)
                 and type(self.commands) is tuple and bool(self.commands)
                 and type(self.stream_limit) is int and self.stream_limit > 0
                 and (self.total_source_limit is None or
                      type(self.total_source_limit) is int and self.total_source_limit > 0)
                 and type(self.reuse_outputs) is bool)
        if not valid:
            raise ValueError("invalid diagnostic capture policy")
        prefixes = []
        for pair in self.commands:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError("invalid diagnostic capture policy")
            command, prefix = pair
            if (type(command) is not tuple or not command or
                    any(type(item) is not str or not item or "\0" in item for item in command) or
                    not command[0].startswith("/") or type(prefix) is not str or
                    re.fullmatch(r"[a-z][a-z_]{0,31}", prefix) is None):
                raise ValueError("invalid diagnostic capture policy")
            if prefix not in prefixes:
                prefixes.append(prefix)
        if len(set(self.commands)) != len(self.commands):
            raise ValueError("invalid diagnostic capture policy")
        environment = dict(self.environment)
        if (any(type(key) is not str or type(value) is not str for key, value in environment.items())
                or not isinstance(self.directory, Path) or not self.directory.is_absolute()):
            raise ValueError("invalid diagnostic capture policy")
        object.__setattr__(self, "commands", frozenset(self.commands))
        object.__setattr__(self, "environment", MappingProxyType(environment))
        object.__setattr__(self, "raw_names", tuple(prefix + "." + stream for prefix in prefixes
                                                 for stream in ("stdout", "stderr")))

    @contextmanager
    def private_outputs(self):
        directory = None
        held = None
        original = None
        files = RawFiles(self)
        pending = None
        try:
            directory = Path(tempfile.mkdtemp(prefix="dockerlens-runtime-profile."))
            original = os.lstat(directory)
            held = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            files.held = held
            if (identity(os.fstat(held)) != identity(original) or original.st_uid != os.geteuid()
                    or stat.S_IMODE(original.st_mode) != 0o700):
                raise self.unavailable("custody_failure")
            for name in self.raw_names:
                descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=held)
                files[name] = descriptor
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_uid != os.geteuid() or info.st_nlink != 1):
                    raise self.unavailable("custody_failure")
            yield files
        except BaseException as failure:
            pending = failure
            if isinstance(failure, OSError):
                pending = self.unavailable("custody_failure")
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
            if not clean and (pending is None or isinstance(pending, self.unavailable)):
                raise self.unavailable("cleanup_failure")
            if not clean and isinstance(pending, self.cancelled_type):
                pending.cleanup = "failed"

    def capture(self, command, files, prefix, deadline, cancellation=None, allowed_statuses=(0,)):
        """Drain incrementally under this purpose's exact command/prefix policy."""
        if (type(command) is not tuple or type(prefix) is not str
                or any(type(argument) is not str for argument in command)
                or (command, prefix) not in self.commands
                or not isinstance(files, RawFiles) or files.context is not self
                or set(files) != set(self.raw_names)):
            raise self.unavailable("command_failed")
        if cancellation is not None:
            cancellation.check()
        if self.reuse_outputs:
            for descriptor in files.values():
                os.lseek(descriptor, 0, os.SEEK_SET)
                os.ftruncate(descriptor, 0)
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=self.environment, cwd=self.directory)
        except FileNotFoundError:
            raise self.unavailable("tool_unavailable") from None
        except OSError:
            raise self.unavailable("command_failed") from None
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
                    if self.total_source_limit is not None:
                        files.used += len(chunk)
                        if files.used > self.total_source_limit:
                            raise self.unavailable("output_overflow")
                    available = max(0, self.stream_limit - counts[key.data])
                    retained = memoryview(chunk)[:available]
                    while retained:
                        written = os.write(files[prefix + "." + key.data], retained)
                        if written <= 0:
                            raise OSError("collector write failed")
                        retained = retained[written:]
                    counts[key.data] += len(chunk)
                    if counts[key.data] > self.stream_limit:
                        overflow = True
                        counts[key.data] = self.stream_limit + 1
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
            # Remove raw bytes before waiting: cancellation may escalate to SIGKILL.
            files.discard()
            process.stdout.close()
            process.stderr.close()
            completed = True
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                completed = False
                if isinstance(failure, self.cancelled_type):
                    failure.reason = "cancelled_completion_unknown"
            if isinstance(failure, OSError):
                raise self.unavailable("collector_io_failure" if completed else "completion_unknown") from None
            raise
        finally:
            if selector is not None:
                selector.close()
            process.stdout.close()
            process.stderr.close()
        if status is None:
            files.discard()
            raise self.unavailable("completion_unknown")
        if overflow:
            raise self.unavailable("output_overflow")
        if timed_out or status in (124, 137):
            raise self.unavailable("timeout")
        if status in (126, 127):
            raise self.unavailable("tool_unavailable")
        if status not in allowed_statuses:
            raise self.unavailable("command_failed")
        os.lseek(files[prefix + ".stdout"], 0, os.SEEK_SET)
        raw = os.read(files[prefix + ".stdout"], self.stream_limit + 1)
        if len(raw) != counts["stdout"]:
            raise self.unavailable("collector_io_failure")
        return raw
