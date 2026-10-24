#!/usr/bin/env python3
"""Private bounded presence evidence for validation-only native cleanup."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


OUTPUT_LIMIT = 16 * 1024
QUERY_SECONDS = 6.0
REAP_SECONDS = 1.0


def classify(status: int | None, output: bytes, complete: bool, mode: str) -> tuple[str, int]:
    if mode == "exact-list":
        if complete and status == 0:
            if output == b"":
                return "absent", 1
            rows = output.splitlines(keepends=True)
            if all(row in (b"present\n", b"other\n") for row in rows) and rows.count(b"present\n") <= 1:
                return ("present", 0) if b"present\n" in rows else ("absent", 1)
        return "unknown", 2
    if not complete or output:
        return "unknown", 2
    if mode == "exists" and status in (0, 1):
        return ("present", 0) if status == 0 else ("absent", 1)
    if mode == "empty-success" and status == 0:
        return "absent", 1
    return "unknown", 2


def terminate_group(process: subprocess.Popen[bytes]) -> tuple[int | None, bool]:
    """Keep the leader unreaped until signaling its group, avoiding PID reuse."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        return None, False
    try:
        status = process.wait(timeout=REAP_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return None, False
    deadline = time.monotonic() + REAP_SECONDS
    while True:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return status, True
        except OSError:
            return status, False
        if time.monotonic() >= deadline:
            return status, False
        time.sleep(0.01)


def query(command: list[str], directory: Path, mode: str, *, seconds: float = QUERY_SECONDS) -> tuple[str, int]:
    process = None
    output = bytearray()
    complete = False
    cancelled = False
    group_finished = False
    stderr_seen = False
    retained_bytes = 0

    def cancel(_number: int, _frame: object) -> None:
        nonlocal cancelled
        cancelled = True

    previous = {number: signal.signal(number, cancel)
                for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        # Each invocation gets fresh mode-0600 evidence; never print its content.
        descriptor, _path = tempfile.mkstemp(prefix="presence-", dir=directory)
        with os.fdopen(descriptor, "wb") as evidence:
            # The child has its own session for teardown. Keep a same-privilege
            # timer around the actual client as well: it survives helper death.
            bounded = ["timeout", "--signal=TERM", "--kill-after=2s", f"{seconds}s", *command]
            process = subprocess.Popen(bounded, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE if mode == "exact-list" else subprocess.STDOUT,
                                       start_new_session=True)
            assert process.stdout is not None
            deadline = time.monotonic() + seconds
            with selectors.DefaultSelector() as selector:
                streams = [process.stdout] + ([process.stderr] if process.stderr is not None else [])
                for stream in streams:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, stream is process.stderr)
                open_streams = {stream.fileno() for stream in streams}
                overflow = False
                while not cancelled and time.monotonic() < deadline:
                    events = selector.select(min(0.05, max(0, deadline - time.monotonic())))
                    if not events:
                        continue
                    for key, _mask in events:
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            open_streams.remove(key.fd)
                            continue
                        if key.data:
                            stderr_seen = True
                        retained = chunk[:max(0, OUTPUT_LIMIT - retained_bytes)]
                        retained_bytes += len(retained)
                        if not key.data:
                            output.extend(retained)
                        evidence.write(retained)
                        if len(retained) != len(chunk):
                            overflow = True
                            break
                    if overflow:
                        break
                    if not open_streams:
                        complete = True
                        break
            exited = None
            # EOF is not process completion: a client can close its streams and
            # keep running. Observe exit without reaping before group teardown.
            while complete and not cancelled and time.monotonic() < deadline:
                exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if exited is not None:
                    break
                time.sleep(0.01)
            status, terminated = terminate_group(process)
            group_finished = True
            process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            return classify(status, bytes(output), complete and exited is not None and terminated and not cancelled and not stderr_seen, mode)
    except (OSError, ValueError, subprocess.SubprocessError):
        if process is not None and not group_finished:
            terminate_group(process)
        if process is not None and process.stdout is not None:
            process.stdout.close()
        if process is not None and process.stderr is not None:
            process.stderr.close()
        return "unknown", 2
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def main() -> int:
    if len(sys.argv) < 5 or sys.argv[1] not in ("exists", "empty-success", "exact-list") or sys.argv[3] != "--":
        print("unknown")
        return 2
    marker, status = query(sys.argv[4:], Path(sys.argv[2]), sys.argv[1])
    print(marker)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
