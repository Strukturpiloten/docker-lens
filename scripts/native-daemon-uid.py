#!/usr/bin/env python3
"""One bounded, read-only outer-container dockerd UID observation."""

import os
import re
import selectors
import signal
import subprocess
import sys
import time

QUERY = ('count=0; uid=; for p in /proc/[0-9]*/comm; do '
         '[ -r "$p" ] || continue; read -r n <"$p" || continue; '
         '[ "$n" = dockerd ] || continue; count=$((count+1)); '
         'uid=$(awk \'/^Uid:/ {print $3}\' "${p%/comm}/status"); '
         'done; [ "$count" -eq 1 ]; printf "%s\\n" "$uid"')


def uid(stdout, stderr, status, mode):
    if (status != 0 or stderr or mode not in ("rootful", "rootless")
            or re.fullmatch(rb"(?:0|[1-9][0-9]{0,9})\n", stdout) is None):
        raise ValueError("invalid daemon UID evidence")
    value = int(stdout)
    if value > 4294967295 or (value != 0) != (mode == "rootless"):
        raise ValueError("invalid daemon UID evidence")
    return value


def command(outer_id):
    if re.fullmatch(r"[0-9a-f]{64}", outer_id) is None:
        raise ValueError("invalid daemon UID context")
    # Root owns the timeout even on a non-root hosted runner. This observes
    # only the selected outer container; it never changes daemon configuration.
    result = ["timeout", "--signal=TERM", "--kill-after=2s", "8s",
              "podman", "exec", outer_id, "sh", "-ec", QUERY]
    return result if os.geteuid() == 0 else ["sudo", "-n", *result]


def observe(outer_id, mode):
    if mode not in ("rootful", "rootless"):
        raise ValueError("invalid daemon UID mode")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    process = subprocess.Popen(command(outer_id), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        with selectors.DefaultSelector() as selected:
            for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selected.register(stream, selectors.EVENT_READ, name)
            deadline = time.monotonic() + 12
            while selected.get_map():
                if time.monotonic() >= deadline:
                    raise ValueError("daemon UID deadline")
                for key, _ in selected.select(max(0, min(0.1, deadline - time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), 256)
                    if not data:
                        selected.unregister(key.fileobj)
                        continue
                    target = buffers[key.data]
                    limit = 32 if key.data == "stdout" else 4096
                    if len(target) + len(data) > limit:
                        raise ValueError("daemon UID output bound")
                    target.extend(data)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("daemon UID deadline")
        status = process.wait(timeout=remaining)
        return uid(bytes(buffers["stdout"]), bytes(buffers["stderr"]), status, mode)
    finally:
        # The root-owned timeout bounds any root child we cannot signal. There
        # is no positive result on overflow, missing EOF, cancellation or error.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait(timeout=12)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for stream in (process.stdout, process.stderr):
            stream.close()


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("invalid daemon UID arguments")
        print(observe(sys.argv[1], sys.argv[2]))
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt):
        raise SystemExit("native daemon UID evidence rejected") from None
