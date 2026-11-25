"""One failure-only, job-window kernel observation; never a causal attribution."""

import json
import os
from pathlib import Path
import re
import signal
import sys
import time

from native_outer_diagnostic_capture import Cancelled, Cancellation, CaptureContext

LIMIT = 32768
CLOCK_SAMPLE_SPAN_NS = 10_000_000
CLOCK_MAPPING_TOLERANCE_NS = 100_000_000
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
UNAVAILABLE = ("unavailable", "unknown", "absent")
AMBIGUOUS = ("ambiguous", "unknown", "absent")
PREFIX = "DOCKERLENS_NATIVE_ROOTLESS_KERNEL_WINDOW: scope=job_window"
TOKEN = re.compile(r'([A-Za-z_][A-Za-z_0-9]*)=(?:"([^"\\\x00-\x1f]*)"|([^\s"\\\x00-\x1f]+))(?: +|$)')
AUDIT_PREFIX = re.compile(r'^(?:audit: )?(?:type=1400 )?audit\([0-9]+\.[0-9]+:[0-9]+\): ')


class Unavailable(Exception):
    """Internal reasons never leave the closed projection."""


def admitted(environment):
    """Canonical hosted accident guard, not dispatcher authentication."""
    if any(environment.get(key) for key in (
            "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION",
            "CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINER_SSHKEY", "PODMAN_CONNECTIONS_CONF")):
        return False
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                "GITHUB_REF": "refs/heads/main", "ImageOS": "ubuntu24"}
    if (any(environment.get(key) != value for key, value in expected.items())
            or environment.get("GITHUB_EVENT_NAME") not in ("push", "workflow_dispatch")
            or re.fullmatch(r"[0-9]{8}\.[0-9]+\.[0-9]+", environment.get("ImageVersion", "")) is None):
        return False
    repository = environment.get("GITHUB_REPOSITORY")
    workflow = environment.get("GITHUB_WORKFLOW_REF", "")
    if repository == "Strukturpiloten/docker-lens":
        return re.fullmatch(r"Strukturpiloten/docker-lens/\.github/workflows/(check|native-validation|release-validation)\.yml@refs/heads/main", workflow) is not None
    return (repository == "Strukturpiloten/boxferry"
            and workflow == "Strukturpiloten/boxferry/.github/workflows/reviewed-docker-consumer-validation.yml@refs/heads/main")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Unavailable("duplicate_json")
        result[key] = value
    return result


def invalid_constant(_value):
    raise Unavailable("invalid_json")


def sample_clocks():
    """One bracketed pair; slow scheduling cannot widen the fixed tolerance."""
    before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    realtime_us = time.time_ns() // 1000
    after = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    if not 0 <= after - before <= CLOCK_SAMPLE_SPAN_NS:
        raise Unavailable("clock_sampling")
    return realtime_us, (before + after) // 2


def verify_clock_mapping(since_us, startup_boot_ns, current_us, current_boot_ns):
    wall_elapsed_ns = (current_us - since_us) * 1000
    boot_elapsed_ns = current_boot_ns - startup_boot_ns
    if (since_us <= 0 or startup_boot_ns <= 0 or wall_elapsed_ns < 0 or boot_elapsed_ns < 0
            or wall_elapsed_ns > 1800 * 1_000_000_000
            or abs(wall_elapsed_ns - boot_elapsed_ns) > CLOCK_MAPPING_TOLERANCE_NS):
        raise Unavailable("clock_mapping")


def event(message):
    # Do not search arbitrary quoted values for denial/comm/errno substrings.
    if "apparmor=" not in message and AUDIT_PREFIX.match(message) is None:
        return None
    text = AUDIT_PREFIX.sub("", message, count=1)
    fields = {}
    quoted = set()
    offset = 0
    while offset < len(text):
        match = TOKEN.match(text, offset)
        if match is None or match[1] in fields:
            raise Unavailable("ambiguous_event")
        fields[match[1]] = match[2] if match[2] is not None else match[3]
        if match[2] is not None:
            quoted.add(match[1])
        offset = match.end()
    if "apparmor" not in quoted or fields["apparmor"] not in ("DENIED", "ALLOWED", "STATUS"):
        raise Unavailable("ambiguous_event")
    if fields["apparmor"] != "DENIED":
        return None
    # Only a complete canonical quoted comm can establish a different task.
    # Missing, empty, binary/unrecognized or unquoted data is not a negative.
    if "comm" not in quoted or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,14}", fields["comm"]) is None:
        raise Unavailable("ambiguous_event")
    if fields["comm"] != "rootlesskit":
        return None
    if "operation" in fields and "operation" not in quoted:
        raise Unavailable("ambiguous_event")
    operation = fields.get("operation")
    operation = operation if operation in ("userns_create", "exec") else "other" if operation else "unknown"
    errors = {fields[name] for name in ("error", "errno") if name in fields}
    projected = {"permission_denied" if value in ("-13", "13", "EACCES") else
                 "operation_not_permitted" if value in ("-1", "1", "EPERM") else "other"
                 for value in errors}
    if len(projected) > 1:
        raise Unavailable("ambiguous_event")
    return operation, next(iter(projected), "absent")


def observe(payload, since_us, until_us, check=lambda: None):
    """Strict complete NDJSON, including independent realtime-window checks."""
    if type(payload) is not bytes or len(payload) > LIMIT or (payload and not payload.endswith(b"\n")):
        raise Unavailable("invalid_framing")
    matches = set()
    uncertain = False
    for line in payload.split(b"\n")[:-1]:
        check()
        if not line or line[:1] != b"{" or line[-1:] != b"}":
            raise Unavailable("invalid_framing")
        try:
            row = json.loads(line.decode("utf-8"), object_pairs_hook=unique_object,
                             parse_constant=invalid_constant)
        except (ValueError, UnicodeError, RecursionError):
            raise Unavailable("invalid_json") from None
        timestamp = row.get("__REALTIME_TIMESTAMP")
        message = row.get("MESSAGE")
        if (type(timestamp) is not str or re.fullmatch(r"[0-9]{1,20}", timestamp) is None
                or not since_us <= int(timestamp) <= until_us or type(message) is not str
                or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in message)):
            raise Unavailable("invalid_record")
        try:
            match = event(message)
        except Unavailable:
            uncertain = True
            continue
        if match is not None:
            matches.add(match)
    check()
    if uncertain or len(matches) > 1:
        return AMBIGUOUS
    if matches:
        operation, error = next(iter(matches))
        return "observed", operation, error
    return "unobserved", "unknown", "absent"


def command(since_us, until_us, euid):
    def stamp(value):
        return f"@{value // 1000000}.{value % 1000000:06d}"
    # sudo is outside timeout: GNU timeout and journalctl share root privilege.
    privilege = () if euid == 0 else ("/usr/bin/sudo", "-n")
    return privilege + ("/usr/bin/timeout", "--signal=TERM", "--kill-after=0.25s", "2s",
                        "/usr/bin/journalctl", "--boot=0", "--dmesg", "--no-pager",
                        "--output=json", "--output-fields=__REALTIME_TIMESTAMP,MESSAGE",
                        "--since=" + stamp(since_us), "--until=" + stamp(until_us))


def collect(directory, since_us, until_us, deadline, cancellation, check):
    argv = command(since_us, until_us, os.geteuid())
    context = CaptureContext(
        unavailable=Unavailable, cancelled_type=Cancelled, commands=((argv, "journal"),),
        environment=ENVIRONMENT, directory=directory, stream_limit=LIMIT,
        total_source_limit=2 * LIMIT, reuse_outputs=False,
    )
    with context.private_outputs() as files:
        raw = context.capture(argv, files, "journal", deadline, cancellation)
        # Even zero-status access/coverage warnings cannot prove absence.
        if os.fstat(files["journal.stderr"]).st_size:
            raise Unavailable("journal_warning")
        check()
        result = observe(raw, since_us, until_us, check)
    check()
    return result


def main(arguments):
    if arguments == ["startup-clock"]:
        # Once-only caller-held clock binding, no journal or runtime authority.
        try:
            if not admitted(os.environ):
                raise Unavailable("admission")
            realtime_us, boot_ns = sample_clocks()
            print(realtime_us, boot_ns)
            return 0
        except (Unavailable, OSError, ValueError, OverflowError):
            return 1
    cancellation = Cancellation()
    previous = {number: signal.signal(number, cancellation.request)
                for number in (signal.SIGINT, signal.SIGTERM)}
    alarm_previous = signal.getsignal(signal.SIGALRM)
    timer_armed = False
    result = UNAVAILABLE
    status = 0
    try:
        # This is an internal helper, not an admission credential. The canonical
        # shell policy must already admit this explicit hosted Docker selection.
        if not admitted(os.environ) or len(arguments) != 8:
            raise Unavailable("arguments")
        engine, mode, directory_text, since_text, startup_boot_text, started_text, remaining_text, watchdog_text = arguments
        if engine != "docker" or mode != "rootless":
            raise Unavailable("lane")
        if any(re.fullmatch(r"[0-9]{1,20}", value) is None
               for value in (since_text, startup_boot_text, started_text, remaining_text, watchdog_text)):
            raise Unavailable("arguments")
        since_us, startup_boot_ns, started_cs, remaining, watchdog = map(
            int, (since_text, startup_boot_text, started_text, remaining_text, watchdog_text))
        directory = Path(directory_text)
        if not directory.is_absolute() or not 5 <= remaining <= 1800 or watchdog <= 1:
            raise Unavailable("budget")
        started = started_cs / 100
        now_boot = time.clock_gettime(time.CLOCK_BOOTTIME)
        elapsed = now_boot - started
        if elapsed < 0 or elapsed >= 2.75:
            raise Unavailable("budget")
        deadline = time.monotonic() + 2.5 - elapsed

        def check():
            cancellation.check()
            age = time.clock_gettime(time.CLOCK_BOOTTIME) - started
            if not 0 <= age < 2.75 or age >= remaining:
                raise Unavailable("budget")
            os.kill(watchdog, 0)

        def expired(_number, _frame):
            raise Unavailable("deadline")

        check()
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 2.75 - elapsed)
        timer_armed = True
        # Bind the query end once. Later clock samples validate the mapping but
        # cannot move this end, requery the journal, or renew any deadline.
        until_us, until_boot_ns = sample_clocks()
        verify_clock_mapping(since_us, startup_boot_ns, until_us, until_boot_ns)
        result = collect(directory, since_us, until_us, deadline, cancellation, check)
        verify_clock_mapping(since_us, startup_boot_ns, *sample_clocks())
        check()
    except Cancelled as failure:
        status = 128 + failure.signum
        result = UNAVAILABLE
    except (Unavailable, OSError, ValueError, OverflowError):
        result = UNAVAILABLE
    finally:
        if timer_armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, alarm_previous)
        # Cancellation is not swallowed by an unrelated collection failure.
        if cancellation.signum is not None:
            status = 128 + cancellation.signum
            result = UNAVAILABLE
        for number, handler in previous.items():
            signal.signal(number, handler)
    print(f"{PREFIX} observation={result[0]} operation={result[1]} errno={result[2]}")
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
