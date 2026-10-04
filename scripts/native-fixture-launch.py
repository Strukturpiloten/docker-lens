#!/usr/bin/env python3
"""Closed native fixture declarations and bounded direct-context checks.

This harness helper is not product capability evidence or a fixture registry.
Systemd is deliberately unregistered: its recipe cannot execute until reviewed
fixture-specific units, runtime versions, delegation and shutdown are supplied.
"""

import importlib.util
import os
import re
import select
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


SOCKET = "unix:///dockerlens-native/docker.sock"
START = ("/usr/local/bin/start-dockerd", "--host=" + SOCKET)
LIMIT = 8192
CATEGORIES = frozenset(("contract", "unimplemented", "identity", "context", "budget", "cancelled", "command"))


class Failure(Exception):
    def __init__(self, category):
        assert category in CATEGORIES
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class Lane:
    pin: str
    repository: str
    mode: str
    account: str
    uid: int
    home: str
    data_root: str
    launcher: str = "start-dockerd"
    config: str = "native-launcher-default"
    prerequisites: tuple = ("rootful-outer-podman", "private-unix-socket", "owned-exclusive-volume")

    @property
    def release(self):
        source = Path(__file__).with_name("native-conformance.sh").read_text()
        matches = re.findall(r"^  " + next(name for name, lane in LANES.items() if lane is self) +
                             r"\).*expected_release='([^']+)'", source, re.M)
        if len(matches) != 1 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", matches[0]):
            raise Failure("contract")
        return matches[0]


LANES = {
    "debian11-rootful": Lane("DEBIAN_ROOTFUL_IMAGE", "docker-debian-11-rootful", "rootful", "root", 0, "/root", "/var/lib/docker"),
    "debian11-rootless": Lane("DEBIAN_ROOTLESS_IMAGE", "docker-debian-11-rootless", "rootless", "dockertest", 1000, "/home/docker", "/home/docker/.local/share/docker"),
    "upstream-rootful": Lane("UPSTREAM_ROOTFUL_IMAGE", "docker-29-rootful", "rootful", "root", 0, "/root", "/var/lib/docker"),
    "upstream-rootless": Lane("UPSTREAM_ROOTLESS_IMAGE", "docker-29-rootless", "rootless", "docker", 1000, "/home/docker", "/home/docker/.local/share/docker"),
}
SYSTEMD_REQUIREMENTS = (
    "boot-systemd-pid1", "reviewed-exact-runtime-version", "fixture-specific-account",
    "fixed-daemon-config-private-listener-data-root-systemd-cgroupdriver",
    "account-derived-user-manager-and-bus", "memory-and-pids-writable-delegation",
    "pre-and-post-owned-process-placement", "bounded-stop-request-and-stopped-readback",
)


def lane_contract(name):
    if name not in LANES:
        raise Failure("contract")
    return LANES[name]


def image_for(name):
    lane = lane_contract(name)
    # Operational tag/digest ownership stays in the existing Renovate source.
    source = Path(__file__).with_name("native-conformance.sh").read_text()
    matches = re.findall(r"^" + lane.pin + r"='([^'\n]+)'$", source, re.M)
    pattern = "ghcr.io/strukturpiloten/" + lane.repository + r":v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}"
    if len(matches) != 1 or re.fullmatch(pattern, matches[0]) is None:
        raise Failure("contract")
    return matches[0]


def validate_declaration(name, image, launcher, account, home, mode, release, data_root, config):
    lane = lane_contract(name)
    if (image, launcher, account, home, mode, release, data_root, config) != (
        image_for(name), lane.launcher, lane.account, lane.home, lane.mode,
        lane.release, lane.data_root, lane.config,
    ):
        raise Failure("contract")


def launch_plan(name, kind="start-dockerd"):
    lane = lane_contract(name)
    if kind == "systemd":
        raise Failure("unimplemented")
    if kind != lane.launcher:
        raise Failure("contract")
    return START


class Lifecycle:
    """Pure ordering guard, not an executor or proof of guest observations."""
    NEXT = {"declared": "launched", "launched": "context", "context": "ready",
            "ready": "stop_requested", "stop_requested": "stopped", "stopped": "removed"}

    def __init__(self, deadline):
        self.deadline = deadline
        self.state = "declared"

    def advance(self, phase, *, now, owned, success, cancelled=False):
        if cancelled:
            self.state = "failed"
            raise Failure("cancelled")
        if now >= self.deadline:
            self.state = "failed"
            raise Failure("budget")
        if not owned or not success or self.NEXT.get(self.state) != phase:
            self.state = "failed"
            raise Failure("identity" if not owned else "context")
        self.state = phase


def io_helper():
    spec = importlib.util.spec_from_file_location("fixture_bounded_io", Path(__file__).with_name("native-cgroup-diagnostic.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


IO = io_helper()
INSPECT = '{{.Id}}|{{.Name}}|{{.State.Running}}|{{index .Config.Labels "io.dockerlens.native-run"}}|{{.State.Pid}}|{{json .State.StartedAt}}|{{.Image}}'

# Independently authored read-only guest probe. Only fixed proc metadata and
# passwd records are read; all raw output is private and cumulatively capped.
# Rootless mount/user namespaces may differ, but PID namespace must be owned.
GUEST = r'''
set -eu
LC_ALL=C; export LC_ALL
account=$1; home=$2; mode=$3
read_small() {
  value=$(head -c 8193 "$1" || exit 1; printf '.') || exit 1
  value=${value%.}
  [ "${#value}" -le 8192 ] || exit 1
}
account_record() {
  read_small /etc/passwd
  printf '%s\n' "$value" | awk -F: -v a="$account" -v h="$home" '
    $1 == a { n++; if (NF != 7 || $6 != h || $3 !~ /^[0-9]+$/) bad=1; uid=$3 }
    END { if (n != 1 || bad) exit 1; print uid "|" h }'
}
before_account=$(account_record)
uid=${before_account%%|*}
lookup=$(id -u "$account") || exit 1
[ "$lookup" = "$uid" ] || exit 1
case "$mode:$uid" in rootful:0) ;; rootless:0) exit 1 ;; rootless:*) ;; *) exit 1 ;; esac
count=0; scanned=0; daemon=
for file in /proc/[0-9]*/comm; do
  scanned=$((scanned + 1)); [ "$scanned" -le 1024 ] || exit 1
  [ -f "$file" ] || continue
  IFS= read -r comm < "$file" || continue
  [ "$comm" = dockerd ] || continue
  count=$((count + 1)); daemon=${file%/comm}
done
[ "$count" = 1 ] || exit 1
identity() {
  read_small "$daemon/stat"
  start=$(printf '%s\n' "$value" | awk '$2 == "(dockerd)" && NF >= 22 { print $22 }')
  case "$start" in ''|*[!0-9]*) exit 1 ;; esac
  read_small "$daemon/status"
  actual=$(printf '%s\n' "$value" | awk '$1 == "Uid:" { n++; if (NF != 5) bad=1; u=$3 } END { if (n != 1 || bad) exit 1; print u }')
  [ "$actual" = "$uid" ] || exit 1
  exe=$(readlink "$daemon/exe")
  case "$exe" in */dockerd) ;; *) exit 1 ;; esac
  inode=$(stat -Lc '%d:%i' "$daemon/exe")
  pidns=$(readlink "$daemon/ns/pid")
  init_pidns=$(readlink /proc/1/ns/pid) || exit 1
  [ "$pidns" = "$init_pidns" ] || exit 1
  userns=$(readlink "$daemon/ns/user")
  mountns=$(readlink "$daemon/ns/mnt")
  printf '%s|%s|%s|%s|%s|%s\n' "${daemon##*/}" "$start" "$inode" "$pidns" "$userns" "$mountns"
}
before=$(identity)
# Preserve NUL record boundaries. A newline in some other variable must never
# manufacture a HOME entry; nonterminated/oversized input is also rejected.
actual_home=$({ head -c 8193 "$daemon/environ" || printf '\n'; } |
  { od -An -v -tu1 || printf '\n10\n'; } | awk -v h="$home" '
  { for (i=1; i<=NF; i++) {
      count++; byte=$i
      if (byte == 0) {
        if (substr(record,1,5) == "HOME=") { n++; if (record != "HOME=" h) bad=1 }
        record=""
      } else {
        if (byte == 10 || byte == 13) bad=1
        record=record sprintf("%c",byte)
      }
    }
  }
  END { if (count < 1 || count > 8192 || record != "" || n != 1 || bad) exit 1; print h }')
[ "$actual_home" = "$home" ] || exit 1
after=$(identity)
[ "$before" = "$after" ] || exit 1
[ "$before_account" = "$(account_record)" ] || exit 1
lookup=$(id -u "$account") || exit 1
[ "$lookup" = "$uid" ] || exit 1
printf '%s|%s\n' "$before_account" "$before"
'''


def validate_guest(raw, lane):
    try:
        fields = raw.decode("ascii").rstrip("\n").split("|")
        uid, home, pid, start, inode, pidns, userns, mountns = fields
    except (UnicodeError, ValueError):
        raise Failure("context") from None
    if not re.fullmatch(r"0|[1-9][0-9]{0,9}", uid) or int(uid) > 4294967294:
        raise Failure("context")
    if int(uid) != lane.uid or home != lane.home:
        raise Failure("context")
    if not re.fullmatch(r"[1-9][0-9]{0,9}", pid) or not re.fullmatch(r"[1-9][0-9]{0,19}", start):
        raise Failure("context")
    if not re.fullmatch(r"[0-9]+:[1-9][0-9]*", inode):
        raise Failure("context")
    for value, kind in ((pidns, "pid"), (userns, "user"), (mountns, "mnt")):
        if not re.fullmatch(kind + r":\[[1-9][0-9]*\]", value):
            raise Failure("context")
    return tuple(fields)


def image_identity(raw):
    try:
        value = raw.decode("ascii").strip()
    except UnicodeError:
        raise Failure("identity") from None
    if value.startswith("sha256:"):
        value = value[7:]
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise Failure("identity")
    return value


def validate_owned(raw, name, run_id, image):
    try:
        fields = raw.decode("ascii").strip().split("|")
        if len(fields) != 7:
            raise Failure("identity")
        identity = IO.inspect_identity("|".join(fields[:6]).encode(), name, run_id)
        actual_image = image_identity(fields[6].encode())
    except (UnicodeError, IO.Unavailable):
        raise Failure("identity") from None
    if actual_image != image:
        raise Failure("identity")
    return (*identity, actual_image)


def check_inputs(name, run_id):
    if not re.fullmatch(r"[A-Za-z0-9]{8}", run_id) or name != "dl-native-" + run_id:
        raise Failure("contract")


def boottime():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def collect(name, run_id, lane_name, cutoff, *, runner=None, clock=boottime, cancelled=lambda: False):
    check_inputs(name, run_id)
    lane = lane_contract(lane_name)
    image = image_for(lane_name)
    budget = {"total": 0}
    deadline = time.monotonic() + min(8.0, cutoff - clock())

    def command(argv):
        if cancelled():
            raise Failure("cancelled")
        remaining = min(deadline - time.monotonic(), cutoff - clock()) - 0.5
        if remaining < 0.1:
            raise Failure("budget")
        # Each local root timer is independent of the caller's privileges.
        command_deadline = time.monotonic() + remaining
        result = (runner or IO.bounded_command)(
            ["timeout", "--signal=TERM", "--kill-after=0.2", f"{remaining:.3f}", *argv],
            command_deadline, budget, capture_limit=LIMIT,
        )
        if cancelled():
            raise Failure("cancelled")
        if clock() >= cutoff:
            raise Failure("budget")
        return result

    image_id = image_identity(command(["podman", "image", "inspect", "--format", "{{.Id}}", image]))
    before = validate_owned(command(["podman", "inspect", "--format", INSPECT, name]), name, run_id, image_id)
    guest = ["podman", "exec", "--user", "0", before[0], "timeout", "-k", "0.2", "3", "sh", "-c", GUEST,
             "fixture-context", lane.account, lane.home, lane.mode]
    context = validate_guest(command(guest), lane)
    # Repeat the account/process read, not just the outer container metadata.
    if validate_guest(command(guest), lane) != context:
        raise Failure("context")
    if validate_owned(command(["podman", "inspect", "--format", INSPECT, before[0]]), name, run_id, image_id) != before:
        raise Failure("identity")


def main():
    try:
        args = sys.argv[1:]
        if args and args[0] == "--declaration" and len(args) == 10:
            validate_declaration(*args[1:])
        elif args and args[0] == "--context" and len(args) == 5:
            lane_name, name, run_id, cutoff = args[1:]
            if os.geteuid() != 0:
                raise Failure("identity")
            cutoff = float(cutoff)
            if not 0 < cutoff - boottime() <= 10:
                raise Failure("budget")
            def cancelled():
                readable, _, _ = select.select([sys.stdin], [], [], 0)
                return bool(readable) and os.read(sys.stdin.fileno(), 1) == b""
            collect(name, run_id, lane_name, cutoff, cancelled=cancelled)
        elif args and args[0] == "--collect" and len(args) == 6:
            lane_name, name, run_id, sudo, raw_cutoff = args[1:]
            check_inputs(name, run_id)
            lane_contract(lane_name)
            if sudo not in ("0", "1"):
                raise Failure("contract")
            cutoff = float(raw_cutoff)
            remaining = min(8.5, cutoff - boottime()) - 0.5
            if remaining < 0.1:
                raise Failure("budget")
            command = (["sudo", "-n"] if sudo == "1" else []) + [
                "timeout", "--signal=TERM", "--kill-after=0.2", f"{remaining:.3f}",
                sys.executable, str(Path(__file__).resolve()), "--context", lane_name, name, run_id, raw_cutoff,
            ]
            output = IO.bounded_command(command, time.monotonic() + remaining + 0.3,
                                        elevated_until=time.monotonic() + remaining + 0.2 if sudo == "1" else None,
                                        stdin_lifeline=True, reap_monitor=True, capture_limit=LIMIT)
            if output:
                raise Failure("context")
        else:
            raise Failure("contract")
    except Failure as error:
        print("DOCKERLENS_NATIVE_FIXTURE: category=" + error.category, file=sys.stderr)
        return 1
    except (IO.Unavailable, OSError, ValueError, OverflowError, subprocess.SubprocessError):
        print("DOCKERLENS_NATIVE_FIXTURE: category=command", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(Failure("cancelled")))
    signal.signal(signal.SIGINT, lambda *_: (_ for _ in ()).throw(Failure("cancelled")))
    raise SystemExit(main())
