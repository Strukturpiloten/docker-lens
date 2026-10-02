#!/usr/bin/env python3
"""Bounded read-only cgroup context; never enforcement or compatibility evidence."""

import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from datetime import datetime

CAPTURE_LIMIT = 8192
DIAGNOSTIC_SECONDS = 5
TEARDOWN_SECONDS = 0.2
FIELDS = (
    "memory_controller", "pids_controller", "memory_delegated", "pids_delegated",
    "memory_max", "swap_max",
)
CONTROLLERS = frozenset(("cpu", "cpuset", "io", "memory", "hugetlb", "pids", "rdma", "misc", "dmem"))


class Unavailable(Exception):
    """A private diagnostic could not be established within its bounds."""


def command_with_timeout(command, deadline):
    """Elevated descendants need a root-owned timer, not a user-owned killpg."""
    if command[:3] != ["sudo", "-n", "podman"]:
        return command, None
    now = time.monotonic()
    # Keep TERM/KILL, sudo startup, and local pipe/process teardown inside the
    # original deadline. Timeout starts as root before Podman is executed.
    duration = min(3.0, deadline - now - 0.7)
    if duration < 0.1:
        raise Unavailable()
    duration = int(duration * 1000) / 1000
    wrapped = [
        "sudo", "-n", "timeout", "--signal=TERM", "--kill-after=0.2",
        f"{duration:.3f}", *command[2:],
    ]
    return wrapped, now + duration + TEARDOWN_SECONDS + 0.2


def bounded_command(command, deadline, budget=None):
    """Cap combined private pipes; bound elevated and local teardown separately."""
    if time.monotonic() >= deadline - 0.2:
        raise Unavailable()
    command, elevated_until = command_with_timeout(command, deadline)
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    complete = False
    if budget is None:
        budget = {"total": 0}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic() - 0.2
                if remaining <= 0:
                    raise Unavailable()
                for key, _ in selector.select(min(remaining, 0.05)):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    if budget["total"] + len(chunk) > CAPTURE_LIMIT:
                        raise Unavailable()
                    budget["total"] += len(chunk)
                    buffer.extend(chunk)
            remaining = deadline - time.monotonic() - 0.2
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                raise Unavailable()
            complete = True
            return bytes(buffers["stdout"])
    finally:
        saved_handlers = None
        if not complete and elevated_until is not None:
            saved_handlers = {kind: signal.getsignal(kind) for kind in (signal.SIGTERM, signal.SIGINT)}
            for kind in saved_handlers:
                signal.signal(kind, signal.SIG_IGN)
        try:
            if not complete:
                if elevated_until is None:
                    # A child may retain a pipe after its parent exits. Signal
                    # the group, not only its direct unprivileged parent.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                else:
                    # Do not kill the root-owned timeout while leaving its
                    # elevated child alive. User killpg cannot prove teardown.
                    # Even if sudo's user monitor exited, wait for its bound.
                    process.stdout.close()
                    process.stderr.close()
                    while True:
                        remaining = elevated_until - time.monotonic()
                        if remaining <= 0:
                            break
                        time.sleep(min(0.05, remaining))
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
        finally:
            process.stdout.close()
            process.stderr.close()
            if saved_handlers is not None:
                for kind, handler in saved_handlers.items():
                    signal.signal(kind, handler)


# The guest emits only bounded file contents, never paths or errors. These bytes
# remain private until the host classifier replaces them with closed states.
# RootlessKit may give dockerd a different mount/cgroup namespace: in that case
# its directory cannot safely be inferred from this namespace and stays unknown.
GUEST_SCRIPT = r'''
LC_ALL=C
export LC_ALL
read_file() {
  value=unknown
  [ ! -L "$1" ] || return
  if [ ! -e "$1" ]; then value=missing; return; fi
  [ -f "$1" ] || return
  data=$(head -c 8193 -- "$1" 2>/dev/null) || return
  [ "${#data}" -le 8192 ] || return
  case "$data" in *'
'*) return ;; esac
  value=$data
}
emit_scope() {
  printf '%s\n' "$1"
  if [ "$2" = unavailable ]; then
    printf 'unknown\nunknown\nunknown\nunknown\n'
    return
  fi
  for field in cgroup.controllers cgroup.subtree_control memory.max memory.swap.max; do
    read_file "$2/$field"
    printf '%s\n' "$value"
  done
}
outer=unavailable
daemon=unavailable
mounts=$(head -c 8193 /proc/self/mountinfo 2>/dev/null || exit 1; printf '.') || exit 1
mounts=${mounts%.}
[ "${#mounts}" -le 8192 ] || exit 1
# Require one total mountpoint entry, itself cgroup2 and rooted at this
# namespace's root. A stacked mount hides correspondence even if one entry
# underneath it is valid. Other mount roots
# require correspondence evidence this diagnostic does not possess.
mapped=$(printf '%s\n' "$mounts" | awk '
  $5 == "/sys/fs/cgroup" {
    count++
    if ($4 == "/")
      for (i=7; i<=NF; i++) if ($i == "-" && $(i+1) == "cgroup2") valid++
  }
  END { print (count == 1 && valid == 1) ? 1 : 0 }
')
if [ "$mapped" = 1 ] && [ -d /sys/fs/cgroup ] && [ ! -L /sys/fs/cgroup ]; then
  outer=/sys/fs/cgroup
fi
count=0
scanned=0
pid=
start=
for comm_file in /proc/[0-9]*/comm; do
  scanned=$((scanned + 1))
  [ "$scanned" -le 1024 ] || exit 1
  [ -f "$comm_file" ] || continue
  IFS= read -r comm < "$comm_file" || continue
  [ "$comm" = dockerd ] || continue
  count=$((count + 1))
  pid=${comm_file%/comm}
done
expected_uid() {
  case "$1" in
    rootful) printf '0\n' ;;
    rootless)
      accounts=$(head -c 8193 /etc/passwd 2>/dev/null || exit 1; printf '.') || return 1
      accounts=${accounts%.}
      [ "${#accounts}" -le 8192 ] || return 1
      printf '%s' "$accounts" | awk -F: '
        $1 == "docker" { count++; uid=$3; if (NF != 7) invalid=1 }
        END {
          if (count == 1 && !invalid && uid ~ /^[1-9][0-9]*$/ && length(uid) <= 10 && uid+0 <= 4294967294)
            print uid
          else exit 1
        }
      '
      ;;
    *) return 1 ;;
  esac
}
effective_uid() {
  status=$(head -c 8193 "$1/status" 2>/dev/null || exit 1; printf '.') || return 1
  status=${status%.}
  [ "${#status}" -le 8192 ] || return 1
  printf '%s' "$status" | awk '
    $1 == "Uid:" { count++; uid=$3; if (NF != 5) invalid=1 }
    END {
      if (count == 1 && !invalid && uid ~ /^[0-9]+$/ && length(uid) <= 10 && uid+0 <= 4294967294) print uid
      else exit 1
    }
  '
}
if [ "$count" = 1 ] && [ "$outer" != unavailable ]; then
  expected=$(expected_uid "$1") || exit 1
  uid=$(effective_uid "$pid") || exit 1
  [ "$uid" = "$expected" ] || exit 1
  before=$(head -c 8193 "$pid/stat" 2>/dev/null | awk '$2 == "(dockerd)" { print $22 }')
  case "$before" in ''|*[!0-9]*) exit 1 ;; esac
  own_cgroup=$(readlink /proc/self/ns/cgroup) || exit 1
  own_mount=$(readlink /proc/self/ns/mnt) || exit 1
  peer_cgroup=$(readlink "$pid/ns/cgroup") || exit 1
  peer_mount=$(readlink "$pid/ns/mnt") || exit 1
  if [ "$own_cgroup" = "$peer_cgroup" ] && [ "$own_mount" = "$peer_mount" ]; then
    membership=$(head -c 8193 "$pid/cgroup" 2>/dev/null) || exit 1
    case "$membership" in 0::/*) ;; *) exit 1 ;; esac
    member=${membership#0::}
    case "$member" in *[!a-zA-Z0-9_./@:-]*|*/../*|*/./*|*//*) exit 1 ;; esac
    candidate=/sys/fs/cgroup
    old_ifs=$IFS
    IFS=/
    for component in ${member#/}; do
      [ -n "$component" ] || continue
      [ "$component" != . ] && [ "$component" != .. ] || exit 1
      candidate=$candidate/$component
      [ -d "$candidate" ] && [ ! -L "$candidate" ] || exit 1
    done
    IFS=$old_ifs
    daemon=$candidate
  fi
fi
emit_scope outer "$outer"
emit_scope daemon "$daemon"
if [ "$count" = 1 ]; then
  [ "$uid" = "$(effective_uid "$pid")" ] || exit 1
  [ "$expected" = "$(expected_uid "$1")" ] || exit 1
  after=$(head -c 8193 "$pid/stat" 2>/dev/null | awk '$2 == "(dockerd)" { print $22 }')
  [ "$before" = "$after" ] || exit 1
  [ "$peer_cgroup" = "$(readlink "$pid/ns/cgroup")" ] || exit 1
  [ "$peer_mount" = "$(readlink "$pid/ns/mnt")" ] || exit 1
  if [ "$daemon" != unavailable ]; then
    [ "$membership" = "$(head -c 8193 "$pid/cgroup" 2>/dev/null)" ] || exit 1
  fi
fi
'''


def unknown(scope):
    return {"scope": scope, "outcome": "unavailable", **{field: "unknown" for field in FIELDS}}


def controller_state(value, controller):
    if value in ("unknown", "missing") or not re.fullmatch(r"[a-z ]*", value):
        return "unknown"
    tokens = value.split()
    if len(tokens) != len(set(tokens)) or not set(tokens).issubset(CONTROLLERS):
        return "unknown"
    return "present" if controller in tokens else "absent"


def limit_state(value):
    if value in ("max", "missing"):
        return value
    return "finite" if re.fullmatch(r"[0-9]{1,20}", value) else "unknown"


def classify(payload):
    if len(payload) > CAPTURE_LIMIT:
        raise Unavailable()
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise Unavailable() from error
    if len(lines) != 10 or lines[0] != "outer" or lines[5] != "daemon":
        raise Unavailable()
    records = []
    for offset, scope in ((0, "outer"), (5, "daemon")):
        controllers, delegated, memory, swap = lines[offset + 1:offset + 5]
        record = unknown(scope)
        if (controllers, delegated, memory, swap) != ("unknown",) * 4:
            record.update(
                outcome="observed",
                memory_controller=controller_state(controllers, "memory"),
                pids_controller=controller_state(controllers, "pids"),
                memory_delegated=controller_state(delegated, "memory"),
                pids_delegated=controller_state(delegated, "pids"),
                memory_max=limit_state(memory), swap_max=limit_state(swap),
            )
        records.append(record)
    return records


def inspect_identity(payload, container, run_id):
    if len(payload) > CAPTURE_LIMIT:
        raise Unavailable()
    try:
        fields = payload.decode("ascii").strip().split("|")
    except UnicodeDecodeError as error:
        raise Unavailable() from error
    if (
        len(fields) != 6
        or not re.fullmatch(r"[0-9a-f]{64}", fields[0])
        or fields[1] not in (container, "/" + container)
        or fields[2] != "true" or fields[3] != run_id
        or not re.fullmatch(r"[1-9][0-9]{0,9}", fields[4])
        or len(fields[5]) > 256
    ):
        raise Unavailable()
    try:
        started_at = json.loads(fields[5])
    except json.JSONDecodeError as error:
        raise Unavailable() from error
    if not isinstance(started_at, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})",
        started_at,
    ):
        raise Unavailable()
    try:
        datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise Unavailable() from error
    fields[5] = started_at
    return fields


def diagnose(container, run_id, mode, podman, runner=None):
    records = [unknown("outer"), unknown("daemon")]
    if (
        not re.fullmatch(r"[a-zA-Z0-9]{8}", run_id)
        or container != "dl-native-" + run_id
        or mode not in ("rootful", "rootless")
        or podman not in (["podman"], ["sudo", "-n", "podman"])
    ):
        return records
    deadline = time.monotonic() + DIAGNOSTIC_SECONDS
    if runner is None:
        budget = {"total": 0}

        def runner(command, command_deadline):
            return bounded_command(command, command_deadline, budget)
    template = '{{.Id}}|{{.Name}}|{{.State.Running}}|{{index .Config.Labels "io.dockerlens.native-run"}}|{{.State.Pid}}|{{json .State.StartedAt}}'
    inspection = [*podman, "inspect", "--format", template, container]
    try:
        before = inspect_identity(runner(inspection, deadline), container, run_id)
        # The guest's own timeout bounds its shell and children if the local
        # Podman client dies. Leave time for post-read identity and local cleanup.
        remaining = deadline - time.monotonic() - 0.75
        if remaining <= 0.2:
            raise Unavailable()
        guest_seconds = min(3.0, remaining)
        payload = runner([
            *podman, "exec", before[0], "timeout", "-k", "0.2",
            f"{guest_seconds:.3f}", "sh", "-c", GUEST_SCRIPT, "diagnostic", mode,
        ], deadline)
        after = inspect_identity(runner(inspection, deadline), container, run_id)
        if before != after or time.monotonic() >= deadline:
            raise Unavailable()
        records = classify(payload)
    except (Unavailable, OSError, subprocess.SubprocessError):
        pass
    return records


def main():
    def cancelled(_signal, _frame):
        # A second cancellation must not interrupt the reserved elevated timer
        # teardown interval. SIGKILL/host failure remain outside this guarantee.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise Unavailable()

    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    try:
        if len(sys.argv) != 5 or sys.argv[4] not in ("0", "1"):
            records = [unknown("outer"), unknown("daemon")]
        else:
            podman = ["sudo", "-n", "podman"] if sys.argv[4] == "1" else ["podman"]
            records = diagnose(*sys.argv[1:4], podman)
    except Unavailable:
        records = [unknown("outer"), unknown("daemon")]
    for record in records:
        print("DOCKERLENS_NATIVE_CGROUP_DIAG: " + " ".join(
            f"{field}={record[field]}" for field in ("scope", "outcome", *FIELDS)
        ))


if __name__ == "__main__":
    main()
