"""Two read-only Docker cleanup queries, under their original GNU timeout owner.

The owner entry performs lexical validation only, samples the conservative deadline
once, then execs the original TERM 8s / KILL +2s owner. Interpreter/sudo startup
before that exec is not claimed as part of its hard envelope. Diagnostics never
authorize removal; the caller still compares the unchanged successful stdout.
"""

import math
import os
import re
import sys
import time

KINDS = ("network-owner-inspect", "volume-identity-inspect")
UNSET = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
         "DOCKER_API_VERSION", "DOCKER_CONFIG", "DOCKER_DEFAULT_PLATFORM", "DOCKER_CUSTOM_HEADERS")
NETWORK_FORMAT = '{{index .Labels "io.dockerlens.native-run"}}'
VOLUME_FORMAT = '{{.Name}}|{{.Driver}}|{{.Mountpoint}}|{{.CreatedAt}}|{{index .Labels "io.dockerlens.native-run"}}'


class Unavailable(Exception):
    """Private closed failure reason; exception text is never projected."""


def arguments(argv):
    """No filesystem access, arbitrary client vector, or generic query grammar."""
    if len(argv) not in (9, 11) or argv[0] not in ("owner", "collect"):
        raise Unavailable("arguments")
    mode = argv[0]
    if (argv[1:3] != ["--engine", "docker"] or argv[3] != "--directory"
            or argv[5] != "--kind" or argv[7] != "--name"):
        raise Unavailable("arguments")
    directory, kind, name = argv[4], argv[6], argv[8]
    if (not directory.startswith("/") or "\0" in directory
            or any(part in ("", ".", "..") for part in directory.split("/")[1:])
            or kind not in KINDS):
        raise Unavailable("arguments")
    match = re.fullmatch(r"dockerlens-native\.([A-Za-z0-9]{8})", directory.rsplit("/", 1)[1])
    if match is None:
        raise Unavailable("arguments")
    suffix = match[1]
    expected = "dl-native-net-" + suffix if kind == KINDS[0] else "dl-native-data-" + suffix
    if name != expected:
        raise Unavailable("arguments")
    if mode == "owner" and len(argv) != 9:
        raise Unavailable("arguments")
    if mode == "collect" and (len(argv) != 11 or argv[9] != "--deadline"):
        raise Unavailable("arguments")
    return mode, directory, kind, name


def owner(argv):
    arguments(argv)
    deadline = repr(time.monotonic() + 8)
    # No fresh timer is minted in the collector, and no new session/group exists.
    command = ("/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", "8s",
               "/usr/bin/python3", os.path.abspath(__file__), "collect", *argv[1:], "--deadline", deadline)
    os.execv(command[0], command)


def held_deadline(value):
    if re.fullmatch(r"[0-9]{1,16}\.[0-9]{1,16}", value) is None:
        raise Unavailable("deadline")
    result = float(value)
    now = time.monotonic()
    if not math.isfinite(result) or not now < result <= now + 8:
        raise Unavailable("deadline")
    return result


def client_context(directory):
    """Reuse the existing read-only attached-client validation, under the owner."""
    import importlib.util
    from pathlib import Path

    script = Path(__file__).with_name("native-outer-observation.py")
    spec = importlib.util.spec_from_file_location("cleanup_observation", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.client_context(directory, "docker")


def command(directory, kind, name):
    # Exactly native_outer_client's Docker vector, with the same PATH lookup.
    import shutil

    executable = shutil.which("env")
    if executable is None:
        raise Unavailable("tool_unavailable")
    client = (executable, *(part for key in UNSET for part in ("-u", key)),
              "docker", "--config", directory + "/docker-client", "--host", "unix:///var/run/docker.sock")
    query = (("network", "inspect", "--format", NETWORK_FORMAT, name) if kind == KINDS[0]
             else ("volume", "inspect", "--format", VOLUME_FORMAT, name))
    return client + query


def stderr_family(raw):
    """Closed observations, never a cleanup decision or raw-error projection."""
    if not raw:
        return "empty"
    lowered = raw.lower()
    families = set()
    if b"permission denied" in lowered:
        families.add("permission_denied")
    if b"cannot connect to the docker daemon" in lowered or b"connection refused" in lowered:
        families.add("connection_unavailable")
    if b"no such network" in lowered or b"no such volume" in lowered:
        families.add("not_found")
    if any(marker in lowered for marker in (b"template parsing error", b"error calling index", b"can't evaluate field")):
        families.add("template_error")
    return families.pop() if len(families) == 1 else "unclassified"


def exit_class(status, signalled=False):
    if signalled:
        return "cancelled" if status in (129, 130, 143) else "other_signal"
    return {0: "success", 1: "one", 2: "two", 124: "timeout", 137: "timeout",
            126: "tool_unavailable", 127: "tool_unavailable"}.get(status, "other")


def collect(argv):
    import signal
    from pathlib import Path
    from native_outer_diagnostic_capture import Cancelled, Cancellation, CaptureContext

    cancellation = Cancellation()
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, cancellation.request)
    _, directory, kind, name = arguments(argv)
    deadline = held_deadline(argv[10])
    client_context(directory)
    query = command(directory, kind, name)
    context = CaptureContext(unavailable=Unavailable, cancelled_type=Cancelled,
                             commands=((query, "inspect"),),
                             environment=dict(os.environ), directory=Path(directory),
                             stream_limit=65536, total_source_limit=131072, reuse_outputs=False)
    cancellation.check()
    if time.monotonic() >= deadline:
        raise Unavailable("deadline")
    with context.private_outputs() as files:
        outcome = context.capture_outcome(query, files, "inspect", deadline, cancellation)
    # Only the successful private-leaf exit permits any projection, including
    # complete error diagnostics. Even an already settled child cannot waive this.
    cancellation.check()
    if time.monotonic() >= deadline:
        raise Unavailable("deadline")
    status = outcome.returncode if outcome.returncode >= 0 else 128 - outcome.returncode
    if not 0 <= status <= 255:
        raise Unavailable("status")
    line = (f"DOCKERLENS_NATIVE_CLEANUP_INSPECT: kind={kind} "
            f"query_exit={exit_class(status, outcome.returncode < 0)} "
            f"stderr_family={stderr_family(outcome.stderr)} collector_completion=complete\n")
    sys.stderr.write(line)
    sys.stderr.flush()
    cancellation.check()
    if time.monotonic() >= deadline:
        raise Unavailable("deadline")
    if status == 0:
        sys.stdout.buffer.write(outcome.stdout)
        sys.stdout.buffer.flush()
    cancellation.check()
    if time.monotonic() >= deadline:
        raise Unavailable("deadline")
    return status


def await_owner():
    """Do not exit and disarm timeout while descendants/custody are uncertain."""
    import signal

    while True:
        signal.pause()


def main(argv):
    if argv and argv[0] == "owner":
        try:
            owner(argv)
        except (Unavailable, OSError):
            return 2
        return 2
    try:
        return collect(argv)
    except BaseException:
        # No exception text, resource identity, stderr or path crosses custody.
        # Catch signal cancellation and unexpected collector faults alike.
        try:
            sys.stderr.write("DOCKERLENS_NATIVE_CLEANUP_INSPECT: query_exit=unavailable "
                             "stderr_family=unavailable collector_completion=unavailable\n")
            sys.stderr.flush()
        finally:
            await_owner()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
