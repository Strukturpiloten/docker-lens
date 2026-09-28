#!/usr/bin/env python3
"""Check effective outer data-root mount flags without exposing mountinfo."""

import sys
from collections.abc import Iterable


def writable_suid_dev_mount(lines: Iterable[str], destination: str) -> bool:
    matches = 0
    allowed = False
    for line in lines:
        fields = line.split()
        if len(fields) < 5 or fields[4] != destination:
            continue
        matches += 1
        if len(fields) < 10:
            return False
        try:
            separator = fields.index("-", 6)
        except ValueError:
            return False
        if len(fields) != separator + 4:
            return False
        options = set(fields[5].split(","))
        allowed = "rw" in options and not options.intersection({"ro", "nosuid", "nodev"})
    return matches == 1 and allowed


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].startswith("/"):
        return 2
    return 0 if writable_suid_dev_mount(sys.stdin, sys.argv[1]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
