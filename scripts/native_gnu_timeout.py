#!/usr/bin/python3 -I
"""Select a fixed, existing GNU timeout, then exec the original timer unchanged.

This is a host-only test prerequisite. It neither installs a provider nor accepts
an executable from PATH or environment. Selection precedes the timer's original
window; it creates no new session, group, retry, or replacement deadline.
"""

import os
import re
import stat
import subprocess
import sys
import time


PATHS = ("/usr/bin/gnutimeout", "/usr/bin/timeout")
VERSION = re.compile(rb"timeout \(GNU coreutils\) ([0-9]+(?:\.[0-9]+){1,3})")
PREREQUISITE = "DockerLens prerequisite: existing GNU timeout required (/usr/bin/gnutimeout or GNU /usr/bin/timeout)"


def selected_path():
    """Discover in isolated Python even when imported by an ordinary caller."""
    try:
        result = subprocess.run(
            ("/usr/bin/python3", "-I", os.path.abspath(__file__), "--path"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5, check=False,
        )
        if result.returncode == 0:
            path = result.stdout.decode("ascii").removesuffix("\n")
            if path in PATHS:
                return path
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        pass
    raise RuntimeError(PREREQUISITE)


def select(*, deadline=None):
    """Only root-owned, non-writable system executables supply supervision."""
    for path in PATHS:
        try:
            before = os.stat(path)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or before.st_mode & 0o022 or not before.st_mode & 0o111):
                continue
            budget = 2 if deadline is None else min(2, max(0, deadline - time.monotonic()))
            if budget <= 0:
                break
            version = subprocess.run(
                (path, "--version"), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                timeout=budget, check=False,
            )
            after = os.stat(path)
            if ((before.st_dev, before.st_ino, before.st_mode, before.st_uid)
                    != (after.st_dev, after.st_ino, after.st_mode, after.st_uid)
                    or version.returncode != 0 or len(version.stdout) > 4096):
                continue
            match = VERSION.fullmatch(version.stdout.split(b"\n", 1)[0])
            if match:
                return path, match[1].decode("ascii")
        except (OSError, subprocess.TimeoutExpired):
            continue
    raise RuntimeError(PREREQUISITE)


def main(argv):
    try:
        path, version = select()
        if argv == ["--path"]:
            print(path)
            return 0
        if argv == ["--identify"]:
            print(f"DOCKERLENS_GNU_TIMEOUT: path={path} version={version}")
            return 0
        if not argv:
            raise RuntimeError(PREREQUISITE)
        os.execv(path, (path, *argv))
    except (OSError, RuntimeError):
        print(PREREQUISITE, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
