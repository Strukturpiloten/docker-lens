#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$script_dir/native-version.sh"

# Published containers#260 manifest digests verified on 2026-09-28 (amd64 and arm64).
# renovate: datasource=docker depName=ghcr.io/strukturpiloten/docker-29-rootful
UPSTREAM_ROOTFUL_IMAGE='ghcr.io/strukturpiloten/docker-29-rootful:v29.8.1@sha256:bc71d19fbcd6d84d1452f61e6c3cbac77b6acaba214d7eb830b79124d1a4d563'
# renovate: datasource=docker depName=ghcr.io/strukturpiloten/docker-29-rootless
UPSTREAM_ROOTLESS_IMAGE='ghcr.io/strukturpiloten/docker-29-rootless:v29.8.1@sha256:075f6b6e6f15960ebf3bca6496331ee6b0e32d96b7824cbac382ae5b296f0d7c'
# renovate: datasource=docker depName=ghcr.io/strukturpiloten/docker-debian-11-rootful
DEBIAN_ROOTFUL_IMAGE='ghcr.io/strukturpiloten/docker-debian-11-rootful:v1.0.0@sha256:656ab906588fcf0acfc66e48ff22e1cd56003495ea43b7066f307db9c7f63124'
# renovate: datasource=docker depName=ghcr.io/strukturpiloten/docker-debian-11-rootless
DEBIAN_ROOTLESS_IMAGE='ghcr.io/strukturpiloten/docker-debian-11-rootless:v1.0.0@sha256:44eadaa886f56d64a3b47fdcee6a812045e0faf6ca207501fd35d1118840f41f'
# renovate: datasource=docker depName=docker.io/library/busybox
FIXTURE_IMAGE='docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e'
# The image's native Debian package revision is distinct from its Engine release.
DEBIAN_DOCKER_PACKAGE='20.10.5+dfsg1-1+deb11u2'

usage() {
  echo "usage: $0 {debian11-rootful|debian11-rootless|upstream-rootful|upstream-rootless}" >&2
  exit 2
}

[[ $# == 1 ]] || usage
lane=$1
case "$lane" in
  debian11-rootful) image=$DEBIAN_ROOTFUL_IMAGE; expected_mode=rootful; expected_release='20.10.5' ;;
  debian11-rootless) image=$DEBIAN_ROOTLESS_IMAGE; expected_mode=rootless; expected_release='20.10.5' ;;
  upstream-rootful) image=$UPSTREAM_ROOTFUL_IMAGE; expected_mode=rootful; expected_release='29.8.1' ;;
  upstream-rootless) image=$UPSTREAM_ROOTLESS_IMAGE; expected_mode=rootless; expected_release='29.8.1' ;;
  *) usage ;;
esac

for tool in podman curl python3 timeout df du mktemp; do
  command -v "$tool" >/dev/null || { echo "missing native test tool: $tool" >&2; exit 1; }
done
if [[ $EUID == 0 ]]; then
  podman_cmd=(podman)
else
  command -v sudo >/dev/null || { echo 'rootful outer Podman requires passwordless sudo' >&2; exit 1; }
  podman_cmd=(sudo -n podman)
fi
"${podman_cmd[@]}" info --format '{{.Host.Security.Rootless}}' | grep -qx false || {
  echo 'native test requires rootful outer Podman; inner rootless mode is separate' >&2
  exit 1
}

# The helper reads host bridge prerequisites before creating run-owned resources.
# Only a positively identified hosted main native job may attempt one bounded
# module load; these environment guards prevent accidents, not impersonation.
python3 "$script_dir/native-bridge-prerequisite.py"

# A random directory, two containers, network, and volume belong to this lane.
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/dockerlens-native.XXXXXXXX")
run_id=${run_dir##*.}
container="dl-native-${run_id}"
volume="dl-native-data-${run_id}"
outer_network="dl-native-net-${run_id}"
sidecar="dl-native-egress-${run_id}"
socket_dir="$run_dir/socket"
socket="$socket_dir/docker.sock"
mkdir -m 0777 "$socket_dir"
# The parent remains private; the synthetic bind source must be writable by
# both rootful and rootless mapped inner-container UIDs for the RW probe.
mkdir -m 0777 "$socket_dir/native-bind"
printf 'native-bind-canary\n' > "$socket_dir/native-bind/canary"
printf 'native-tcp-canary\n' > "$socket_dir/native-bind/index.html"
chmod 0644 "$socket_dir/native-bind/canary" "$socket_dir/native-bind/index.html"
chmod 0700 "$run_dir"
mkdir -m 0700 "$run_dir/diagnostics"
watchdog_pid=
native_success_summary=
preserve_run_dir=0
cleanup_podman() {
  # The deadline must share root privileges with the Podman client; an
  # unprivileged timeout cannot reliably terminate children behind sudo.
  if [[ ${podman_cmd[0]} == sudo ]]; then
    "${podman_cmd[@]:0:2}" timeout --signal=TERM --kill-after=2s 8s "${podman_cmd[@]:2}" "$@" 2>/dev/null
  else
    timeout --signal=TERM --kill-after=2s 8s "${podman_cmd[@]}" "$@" 2>/dev/null
  fi
}
native_presence() {
  local mode=$1 marker result=0
  shift
  # Both the helper and its process-group teardown need the client's privileges.
  # Keep the root-owned GNU timeout even if Python cannot finish its own cleanup.
  if [[ $1 == sudo ]]; then
    shift 2
    marker=$(query_status=0
      sudo -n timeout --signal=TERM --kill-after=2s 8s \
        python3 "$script_dir/native-presence.py" "$mode" "$run_dir" -- "$@" 2>/dev/null || query_status=$?
      printf '\036'; exit "$query_status") || result=$?
  else
    marker=$(query_status=0
      timeout --signal=TERM --kill-after=2s 8s \
        python3 "$script_dir/native-presence.py" "$mode" "$run_dir" -- "$@" 2>/dev/null || query_status=$?
      printf '\036'; exit "$query_status") || result=$?
  fi
  case "$result:$marker" in
    $'0:present\n\036') return 0 ;;
    $'1:absent\n\036') return 1 ;;
    *) preserve_run_dir=1; return 2 ;;
  esac
}
cleanup_remove() {
  local role=$1 result=0 category
  shift
  cleanup_podman "$@" >/dev/null || result=$?
  if (( result == 0 )); then return 0; fi
  case $result in
    124) category=timeout ;;
    137) category=killed ;;
    130 | 143) category=cancelled ;;
    125 | 126 | 127) category=command_error ;;
    *) category=error ;;
  esac
  echo "DOCKERLENS_NATIVE_CLEANUP: role=$role operation=remove category=$category" >&2
  return 1
}
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [[ -n $watchdog_pid ]]; then
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
  fi
  cleanup_container "$container" container || status=1
  cleanup_container "$sidecar" sidecar || status=1
  network_state=0
  native_presence exists "${podman_cmd[@]}" network exists "$outer_network" || network_state=$?
  if (( network_state != 1 )); then
    if (( network_state != 0 )); then
      echo "could not verify whether owned network $outer_network exists (exit $network_state)" >&2
      status=1
    fi
    owner=
    owner_state=0
    owner=$(cleanup_podman network inspect --format '{{index .Labels "io.dockerlens.native-run"}}' "$outer_network") || owner_state=$?
    if (( owner_state == 0 )) && [[ $owner == "$run_id" ]]; then
      cleanup_remove network network rm "$outer_network" || status=1
      removed_state=0
      native_presence exists "${podman_cmd[@]}" network exists "$outer_network" || removed_state=$?
      if (( removed_state != 1 )); then
        echo "owned network cleanup readback failed (exists exit $removed_state)" >&2
        status=1
      fi
    else
      echo "refusing to remove network $outer_network without matching ownership label" >&2
      status=1
    fi
  fi
  volume_state=0
  native_presence exists "${podman_cmd[@]}" volume exists "$volume" || volume_state=$?
  if (( volume_state != 1 )); then
    if (( volume_state != 0 )); then
      echo "could not verify whether owned volume $volume exists (exit $volume_state)" >&2
      status=1
    fi
    owner=
    owner_state=0
    owner=$(cleanup_podman volume inspect --format '{{index .Labels "io.dockerlens.native-run"}}' "$volume") || owner_state=$?
    if (( owner_state == 0 )) && [[ $owner == "$run_id" ]]; then
      cleanup_remove volume volume rm "$volume" || status=1
      removed_state=0
      native_presence exists "${podman_cmd[@]}" volume exists "$volume" || removed_state=$?
      if (( removed_state != 1 )); then
        echo "owned volume cleanup readback failed (exists exit $removed_state)" >&2
        status=1
      fi
    else
      echo "refusing to remove volume $volume without matching ownership label" >&2
      status=1
    fi
  fi
  if (( preserve_run_dir != 0 )); then
    echo 'DOCKERLENS_NATIVE_CLEANUP: private presence evidence retained for review' >&2
  elif [[ $run_dir == "${TMPDIR:-/tmp}"/dockerlens-native.* && -d $run_dir ]]; then
    rm -rf -- "$run_dir" || status=1
  fi
  if (( status != 0 )); then
    echo "native lane $lane failed; verify owned resources $container, $sidecar, $outer_network, and $volume" >&2
  elif [[ -n $native_success_summary ]]; then
    echo "$native_success_summary"
  fi
  exit "$status"
}
cleanup_container() {
  local name=$1 role=$2 container_state owner owner_state removed_state
  container_state=0
  native_presence exists "${podman_cmd[@]}" container exists "$name" || container_state=$?
  if (( container_state == 1 )); then return; fi
  if (( container_state != 0 )); then
    echo "could not verify whether owned $role $name exists (exit $container_state)" >&2
    status=1
  fi
  owner=
  owner_state=0
  owner=$(cleanup_podman inspect --format '{{index .Config.Labels "io.dockerlens.native-run"}}' "$name") || owner_state=$?
  if (( owner_state == 0 )) && [[ $owner == "$run_id" ]]; then
    # Podman's default ten-second stop grace exceeds our eight-second client
    # bound. Only this exact label-verified task container gets immediate stop.
    cleanup_remove "$role" rm --force --time 0 "$name" || status=1
    removed_state=0
    native_presence exists "${podman_cmd[@]}" container exists "$name" || removed_state=$?
    if (( removed_state != 1 )); then
      echo "owned $role cleanup readback failed (exists exit $removed_state)" >&2
      status=1
    fi
  else
    echo "refusing to remove $role $name without matching ownership label" >&2
    status=1
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
echo "native lane $lane owns Podman container $container, sidecar $sidecar, network $outer_network, and volume $volume"

diagnose_native_startup() {
  local state diagnosis
  state=$("${podman_cmd[@]}" inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}' "$container" 2>/dev/null) || state=unavailable
  [[ $state =~ ^(running|exited|created|configured|paused|stopped)\|[0-9]+\|(true|false)$ ]] || state=unavailable
  # Retain only the final 64 KiB of the last 80 lines. Logs can contain protected
  # values, so only fixed stage and category names leave this function.
  diagnosis=$(timeout --signal=TERM --kill-after=2s 10s "${podman_cmd[@]}" logs --tail 80 "$container" 2>/dev/null |
    python3 -c 'import sys
tail = bytearray()
for chunk in iter(lambda: sys.stdin.buffer.read(65536), b""):
    tail.extend(chunk)
    if len(tail) > 65536:
        del tail[:-65536]
s = tail.decode("utf-8", "replace").lower()
stage = "daemon"
# Daemon logs can contain secrets; classifications only emit fixed categories.
lines = s.splitlines()
category_text = "\n".join(line for line in lines
                          if not line.strip().startswith("dockerlens_rootless_trace:"))
checks = (
    ("rootless_launcher_unavailable", ("start-dockerd: not found", "start-dockerd: no such file")),
    ("rootless_uidmap", ("uid_map", "newuidmap", "newgidmap")),
    ("rootless_network", ("rootlesskit", "slirp4netns")),
    ("daemon_storage", ("error initializing graphdriver", "failed to mount overlay", "storage driver")),
    ("daemon_permission", ("operation not permitted", "permission denied")),
    ("daemon_network", ("iptables", "failed to create nat chain", "error creating default bridge")),
    ("daemon_startup", ("failed to start daemon",)),
)
category = next((name for name, needles in checks
                 if any(item in category_text for item in needles)), "unclassified")
trace = "unavailable"
print("stage=" + stage + " category=" + category + " trace=" + trace)' "$lane") || diagnosis='stage=unavailable category=unavailable trace=unavailable'
  echo "inner daemon startup diagnosis: state=$state $diagnosis" >&2
}

graph_root=$("${podman_cmd[@]}" info --format '{{.Store.GraphRoot}}')
[[ $graph_root == /* ]] || { echo 'outer Podman graph root is unavailable' >&2; exit 1; }
if [[ $EUID == 0 ]]; then
  available_kib=$(df -Pk "$graph_root" | awk 'END {print $4}')
else
  available_kib=$(sudo -n df -Pk "$graph_root" | awk 'END {print $4}')
fi
(( available_kib >= 8 * 1024 * 1024 )) || { echo 'native lane needs at least 8 GiB free in Podman storage' >&2; exit 1; }
for resource in container sidecar network volume; do
  case $resource in
    container) name=$container; query=container ;;
    sidecar) name=$sidecar; query=container ;;
    network) name=$outer_network; query=network ;;
    volume) name=$volume; query=volume ;;
  esac
  resource_state=0
  native_presence exists "${podman_cmd[@]}" "$query" exists "$name" || resource_state=$?
  case $resource_state in
    0) echo "generated native $resource name already exists" >&2; exit 1 ;;
    1) ;;
    *) echo "could not verify generated native $resource name (exit $resource_state)" >&2; exit 1 ;;
  esac
done
"${podman_cmd[@]}" volume create --label "io.dockerlens.native-run=$run_id" "$volume" >/dev/null
volume_path=$("${podman_cmd[@]}" volume inspect --format '{{.Mountpoint}}' "$volume")
main_pid=$$
watchdog_measure() {
  local attempt used free used_status free_status
  local -a du_cmd df_cmd
  if [[ $EUID == 0 ]]; then
    du_cmd=(du)
    df_cmd=(df)
  else
    du_cmd=(sudo -n du)
    df_cmd=(sudo -n df)
  fi
  for (( attempt = 1; attempt <= 3; attempt++ )); do
    if (( SECONDS > 1800 )); then
      echo "native lane exceeded its storage, free-space, or 30-minute budget" >&2
      return 1
    fi
    used_status=0
    free_status=0
    used=$("${du_cmd[@]}" -sk "$volume_path" 2>/dev/null | awk '{print $1}') || used_status=$?
    free=$("${df_cmd[@]}" -Pk "$graph_root" 2>/dev/null | awk 'END {print $4}') || free_status=$?
    if (( SECONDS > 1800 )); then
      echo "native lane exceeded its storage, free-space, or 30-minute budget" >&2
      return 1
    fi
    if { (( used_status == 0 )) && [[ ! $used =~ ^[0-9]{1,15}$ ]]; } ||
      { (( free_status == 0 )) && [[ ! $free =~ ^[0-9]{1,15}$ ]]; }; then
      echo 'native lane watchdog invalid measurement' >&2
      return 1
    fi
    # GNU du can print a partial total before reporting a vanished child.
    # Such a total is a lower bound, so an observed breach is conclusive.
    if { [[ $used =~ ^[0-9]{1,15}$ ]] && (( 10#$used > 4 * 1024 * 1024 )); } ||
      { [[ $free =~ ^[0-9]{1,15}$ ]] && (( 10#$free < 2 * 1024 * 1024 )); }; then
      echo "native lane exceeded its storage, free-space, or 30-minute budget" >&2
      return 1
    fi
    if (( used_status == 0 && free_status == 0 )); then return 0; fi
    if (( attempt < 3 )); then sleep 1 || break; fi
  done
  echo 'native lane watchdog measurement failed' >&2
  return 1
}
watchdog() {
  trap - EXIT HUP INT TERM
  while :; do
    sleep 5
    if ! watchdog_measure; then
      kill -TERM "$main_pid"
      return
    fi
  done
}
storage_mount="$volume:$(if [[ $expected_mode == rootless ]]; then printf /home/docker/.local/share/docker; else printf /var/lib/docker; fi):U"
if [[ $lane == debian11-rootless ]]; then
  # Historical Debian rootless runc cannot RO-remount the named volume when
  # its outer data store inherits nosuid,nodev. Scope this to the disposable
  # privileged nesting volume; do not change host mount or AppArmor policy.
  storage_mount+=,suid,dev
fi
# Keep the image's native daemon launcher. Its second Unix listener is bind-mounted
# for explicit local test capture; neither listener is exposed over TCP.
start=(/usr/local/bin/start-dockerd --host=unix:///dockerlens-native/docker.sock)
run_flags=(--image-volume=ignore)
if [[ $lane == debian11-rootless ]]; then
  run_flags+=(--oom-score-adj=0 --security-opt apparmor=unconfined)
fi
validated_outer_ipv4() {
  local role=$1 name=$2 attachment
  case $role in sidecar | daemon) ;; *) return 1 ;; esac
  attachment=$(timeout --signal=TERM --kill-after=2s 10s "${podman_cmd[@]}" inspect \
    --format '{{json .NetworkSettings.Networks}}' "$name" 2>/dev/null) || {
    echo "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=attachment role=$role category=inspect_failed" >&2
    return 1
  }
  (( ${#attachment} <= 4096 )) || {
    echo "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=attachment role=$role category=output_limit" >&2
    return 1
  }
  printf '%s' "$attachment" | python3 -c '
import ipaddress, json, sys

def fail(category):
    print("DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=attachment role=" + sys.argv[2] +
          " category=" + category, file=sys.stderr)
    raise SystemExit(1)

try:
    networks = json.load(sys.stdin)
except (ValueError, UnicodeError):
    fail("json_shape")
if not isinstance(networks, dict):
    fail("json_shape")
if sys.argv[1] not in networks:
    fail("network_missing")
if len(networks) != 1:
    fail("network_extra")
endpoint = networks[sys.argv[1]]
if not isinstance(endpoint, dict):
    fail("json_shape")
raw_address = endpoint.get("IPAddress")
if raw_address is None or raw_address == "":
    fail("ipv4_missing")
if not isinstance(raw_address, str):
    fail("ipv4_malformed")
try:
    address = ipaddress.IPv4Address(raw_address)
except (ValueError, TypeError, AttributeError):
    fail("ipv4_malformed")
if not address.is_private or address.is_loopback or address.is_link_local:
    fail("ipv4_nonprivate")
print(address)
' "$outer_network" "$role"
}
sidecar_setup_failed() {
  echo "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=$1" >&2
  exit 1
}
# Sidecar logs and Podman State.Error can contain authored values. Consume only
# a bounded tail and emit a closed cause category; never print native text.
classify_sidecar_error() {
  python3 -c 'import re, sys
tail = bytearray()
for chunk in iter(lambda: sys.stdin.buffer.read(4096), b""):
    tail.extend(chunk)
    if len(tail) > 8192:
        del tail[:-8192]
output = tail.decode("utf-8", "replace")
message = output.lower()
checks = (
    ("applet_missing", (r"\b(?:httpd|wget|sh): (?:applet )?not found\b",
                        r"\bapplet not found\b", r"\bhttpd: applet not found\b")),
    ("shell_error", (r"\bsyntax error\b", r"\bunexpected (?:token|end of file)\b")),
    ("config_error", (r"\b(?:invalid|unknown|unrecognized) option\b",
                      r"\bconfiguration error\b", r"\busage: httpd\b")),
    ("bind_error", (r"\baddress already in use\b", r"\b(?:cannot|can.t|failed to) bind\b",
                    r"\bbind:.*\b(?:denied|unavailable)\b")),
    ("permission", (r"\bpermission denied\b", r"\boperation not permitted\b")),
    ("storage", (r"\bno space left\b", r"\bdisk quota exceeded\b")),
    ("runtime_error", (r"\berror\b", r"\bfailed\b", r"\bfailure\b")),
)
category = next((category for category, patterns in checks
                 if any(re.search(pattern, message) for pattern in patterns)), "unknown")
if sys.argv[1:] == ["--with-stage"]:
    markers = set(re.findall(
        r"(?m)^DOCKERLENS_SIDECAR_STAGE: (write_ok|write_failed)\r?$", output))
    stage = next(iter(markers)) if len(markers) == 1 else "unknown"
    httpd_markers = set(re.findall(
        r"(?m)^DOCKERLENS_SIDECAR_HTTPD: (invoked|returned_zero|returned_nonzero)\r?$",
        output))
    httpd_stage = "unknown"
    if stage == "write_ok" and "invoked" in httpd_markers:
        returns = httpd_markers & {"returned_zero", "returned_nonzero"}
        if len(returns) == 1:
            httpd_stage = next(iter(returns))
        elif not returns:
            httpd_stage = "invoked"
    causes = re.findall(r"(?m)^DOCKERLENS_SIDECAR_HTTPD_CAUSE: ([^\r\n]*)\r?$", output)
    allowed_causes = {"applet_missing", "shell_error", "permission", "bind_error", "config_error", "unknown"}
    httpd_cause = causes[0] if (httpd_stage == "returned_nonzero" and len(causes) == 1
                               and causes[0] in allowed_causes) else "absent"
    print(f"{stage}|{httpd_stage}|{category}|{httpd_cause}")
else:
    print(category)' "$@"
}
sidecar_failure_diagnostic() {
  local category=unknown source=none write_stage=unknown httpd_stage=unknown state_error=unavailable observed logs_stage logs_httpd_stage logs_category logs_httpd_cause
  # A successful Podman logs query may replay container output on either CLI
  # stream. The query cannot identify which stream supplied the category.
  if observed=$(timeout --signal=TERM --kill-after=2s 5s "${podman_cmd[@]}" logs --tail 32 "$sidecar" 2>&1 |
    classify_sidecar_error --with-stage) &&
    [[ $observed =~ ^(write_ok|write_failed|unknown)\|(invoked|returned_zero|returned_nonzero|unknown)\|(applet_missing|shell_error|config_error|bind_error|permission|storage|runtime_error|unknown)\|(applet_missing|shell_error|permission|bind_error|config_error|unknown|absent)$ ]]; then
    logs_stage=${BASH_REMATCH[1]}
    logs_httpd_stage=${BASH_REMATCH[2]}
    logs_category=${BASH_REMATCH[3]}
    logs_httpd_cause=${BASH_REMATCH[4]}
    write_stage=$logs_stage
    httpd_stage=$logs_httpd_stage
    if [[ $logs_category != unknown ]]; then
      category=$logs_category
      source=logs_query
    fi
  fi
  # Inspect independently: a logs category may come from the Podman CLI rather
  # than the container. Emit only the closed classification, never State.Error.
  if observed=$(timeout --signal=TERM --kill-after=2s 5s "${podman_cmd[@]}" inspect \
    --format '{{.State.Error}}' "$sidecar" 2>/dev/null | classify_sidecar_error) &&
    [[ $observed =~ ^(applet_missing|shell_error|config_error|bind_error|permission|storage|runtime_error|unknown)$ ]]; then
    state_error=$observed
    if [[ $category == unknown && $state_error != unknown ]]; then
      category=$state_error
      source=state_error
    fi
  fi
  if [[ $httpd_stage == returned_nonzero ]]; then
    category=unknown
    source=none
    if [[ $logs_httpd_cause != absent ]]; then
      category=$logs_httpd_cause
      source=httpd_stderr
    fi
  fi
  echo "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=sidecar_failure category=$category source=$source write_stage=$write_stage httpd_stage=$httpd_stage state_error=$state_error" >&2
}
watchdog &
watchdog_pid=$!
# Pull only the reviewed digest under the lane's time and free-space budget.
# Prevent `run` from doing a second unbounded implicit pull.
timeout --signal=TERM --kill-after=2s 180s "${podman_cmd[@]}" pull "$image" >/dev/null
timeout --signal=TERM --kill-after=2s 180s "${podman_cmd[@]}" pull "$FIXTURE_IMAGE" >/dev/null 2>&1 || sidecar_setup_failed image_pull
timeout --signal=TERM --kill-after=2s 30s "${podman_cmd[@]}" network create --driver bridge \
  --label "io.dockerlens.native-run=$run_id" "$outer_network" >/dev/null 2>&1 || sidecar_setup_failed network_create
sidecar_start_category=$(timeout --signal=TERM --kill-after=2s 120s "${podman_cmd[@]}" run --pull=never -d --name "$sidecar" \
  --label "io.dockerlens.native-run=$run_id" --network "$outer_network" \
  --user=65534:65534 --cap-drop=all --security-opt no-new-privileges --pids-limit=64 --memory=128m \
  "$FIXTURE_IMAGE" sh -c \
  'umask 077
   sidecar_tmp=$(mktemp -d /tmp/dockerlens-sidecar.XXXXXX 2>/dev/null) || exit 1
   httpd_root="$sidecar_tmp/public"
   httpd_capture="$sidecar_tmp/httpd.stderr"
   trap '\''rm -f "$httpd_capture" "$httpd_root/index.html" >/dev/null 2>&1; rmdir "$httpd_root" "$sidecar_tmp" >/dev/null 2>&1'\'' EXIT
   if { mkdir "$httpd_root" && printf proof-egress > "$httpd_root/index.html"; } 2>/dev/null; then
     printf "DOCKERLENS_SIDECAR_STAGE: write_ok\n" >&2
   else
     printf "DOCKERLENS_SIDECAR_STAGE: write_failed\n" >&2
     exit 1
   fi
   printf "DOCKERLENS_SIDECAR_HTTPD: invoked\n" >&2
   # POSIX shells use 512-byte or 1-KiB blocks here: at most 8 KiB.
   # Keep the checked file limit inside the HTTP process subshell only.
   if (ulimit -f 8 && exec httpd -f -p 18084 -h "$httpd_root") 2>"$httpd_capture"; then
     printf "DOCKERLENS_SIDECAR_HTTPD: returned_zero\n" >&2
   else
     status=$?
     httpd_error=$(head -c 8192 "$httpd_capture" 2>/dev/null | tr "[:upper:]" "[:lower:]")
     case $httpd_error in
       *applet\ not\ found* | *httpd:\ not\ found*) httpd_cause=applet_missing ;;
       *syntax\ error* | *unexpected\ token* | *unexpected\ end\ of\ file*) httpd_cause=shell_error ;;
       *permission\ denied* | *operation\ not\ permitted*) httpd_cause=permission ;;
       *address\ already\ in\ use* | *can?t\ bind* | *cannot\ bind* | *failed\ to\ bind* | *bind:*) httpd_cause=bind_error ;;
       *invalid\ option* | *unknown\ option* | *unrecognized\ option* | *configuration\ error* | *usage:\ httpd*) httpd_cause=config_error ;;
       *) httpd_cause=unknown ;;
     esac
     rm -f "$httpd_capture" >/dev/null 2>&1
     printf "DOCKERLENS_SIDECAR_HTTPD_CAUSE: %s\n" "$httpd_cause" >&2
     printf "DOCKERLENS_SIDECAR_HTTPD: returned_nonzero\n" >&2
     exit "$status"
   fi' 2>&1 >/dev/null |
  classify_sidecar_error) || {
  case $sidecar_start_category in
    applet_missing | shell_error | config_error | bind_error | permission | storage | runtime_error | unknown) ;;
    *) sidecar_start_category=unknown ;;
  esac
  echo "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=sidecar_failure category=$sidecar_start_category" >&2
  sidecar_setup_failed sidecar_start
}
python3 "$script_dir/native-port-start-diagnostic.py" prepare "$run_dir" "$run_id" "$lane" || {
  echo 'DOCKERLENS_NATIVE_PORT_START_LOG_DIAG: source=none category=unavailable collector=unavailable' >&2
  exit 1
}
# Hold the original caller-owned file; registration checks this descriptor
# against the exclusive no-follow creation before reading any native bytes.
exec {port_start_log_fd}< "$run_dir/diagnostics/daemon.log"
outer_container_id=$(timeout --signal=TERM --kill-after=2s 120s "${podman_cmd[@]}" run --pull=never -d --name "$container" --label "io.dockerlens.native-run=$run_id" \
  --log-driver=k8s-file --log-opt "path=$run_dir/diagnostics/daemon.log" --log-opt max-size=1048576 \
  --network "$outer_network" \
  --privileged --pids-limit=512 --memory=4g --cpus=2 "${run_flags[@]}" \
  --volume "$storage_mount" --volume "$socket_dir:/dockerlens-native" \
  "$image" "${start[@]}" 2>/dev/null) || sidecar_setup_failed daemon_attach
[[ $outer_container_id =~ ^[0-9a-f]{64}$ ]] || sidecar_setup_failed daemon_identity
sidecar_state=$(timeout --signal=TERM --kill-after=2s 10s "${podman_cmd[@]}" inspect \
  --format '{{.State.Running}}|{{.State.Status}}|{{.State.ExitCode}}' "$sidecar" 2>/dev/null) || {
  echo 'DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=sidecar_state category=inspect_failed exit=unavailable' >&2
  exit 1
}
if [[ ! $sidecar_state =~ ^(true|false)\|(running|exited|created|configured|paused|stopped|stopping|removing|unknown)\|([0-9]{1,3})$ ]] ||
  (( 10#${BASH_REMATCH[3]:-999} > 255 )); then
  echo 'DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=sidecar_state category=malformed exit=unavailable' >&2
  exit 1
fi
sidecar_running=${BASH_REMATCH[1]}
sidecar_status=${BASH_REMATCH[2]}
sidecar_exit=${BASH_REMATCH[3]}
if [[ $sidecar_running != true || $sidecar_status != running ]]; then
  if [[ $sidecar_running == true || $sidecar_status == running ]]; then
    sidecar_status=inconsistent
  fi
  if (( 10#$sidecar_exit == 0 )); then exit_class=zero; else exit_class=nonzero; fi
  echo "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=sidecar_state category=$sidecar_status exit=$exit_class" >&2
  sidecar_failure_diagnostic
  exit 1
fi
sidecar_health=
for attempt in 1 2 3 4 5; do
  sidecar_health=$(timeout --signal=TERM --kill-after=2s 3s "${podman_cmd[@]}" exec "$sidecar" wget -Y off -T 1 -qO- \
    http://127.0.0.1:18084/ 2>/dev/null) || sidecar_health=
  if [[ $sidecar_health == proof-egress ]]; then break; fi
  if (( attempt < 5 )); then sleep 0.2; fi
done
[[ $sidecar_health == proof-egress ]] || {
  sidecar_failure_diagnostic
  sidecar_setup_failed sidecar_health
}
sidecar_ip=$(validated_outer_ipv4 sidecar "$sidecar") || exit 1
daemon_ip=$(validated_outer_ipv4 daemon "$container") || exit 1
[[ $sidecar_ip != "$daemon_ip" ]] || {
  sidecar_setup_failed address_collision
}
# JSON tags are stable even when Podman's Go field uses another spelling.
# Keep this one existing query; optional metadata must not break template setup.
outer_setup=$("${podman_cmd[@]}" inspect --format '{{json .}}' "$container")
privileged=$(printf '%s' "$outer_setup" | python3 -c 'import json,sys
try:
    value = json.load(sys.stdin)["HostConfig"]["Privileged"]
except (ValueError, TypeError, KeyError):
    raise SystemExit(1)
if type(value) is not bool:
    raise SystemExit(1)
print("true" if value else "false")')
[[ $privileged == true ]] || { echo 'outer container does not have reviewed nesting privilege' >&2; exit 1; }
# Reuse this existing authorized setup inspection. Registration failures affect
# only optional observations; the original native assertions remain mandatory.
printf '%s' "$outer_setup" | python3 "$script_dir/native-port-start-diagnostic.py" register \
  "$run_dir" "$run_id" "$lane" "$image" "$outer_container_id" "$port_start_log_fd" || true
unset outer_setup
volume_mounts=$("${podman_cmd[@]}" inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}}{{"\n"}}{{end}}{{end}}' "$container")
expected_mount=${storage_mount%:*}
[[ $volume_mounts == "$expected_mount" ]] || {
  echo 'outer container has unexpected image or data-root volumes' >&2
  exit 1
}

deadline=$((SECONDS + 360))
while (( SECONDS < deadline )); do
  if [[ -S $socket ]]; then
    if [[ $EUID == 0 ]]; then chmod 0666 "$socket"; else sudo -n chmod 0666 "$socket"; fi
    if curl -q --noproxy '*' -fs --max-time 5 --unix-socket "$socket" http://localhost/_ping >/dev/null; then break; fi
  fi
  running=$("${podman_cmd[@]}" inspect --format '{{.State.Running}}' "$container" 2>/dev/null) || running=unknown
  if [[ $running != true ]]; then
    echo 'inner daemon exited before readiness' >&2
    diagnose_native_startup
    exit 1
  fi
  sleep 2
done
[[ -S $socket ]] && curl -q --noproxy '*' -fs --max-time 5 --unix-socket "$socket" http://localhost/_ping >/dev/null || {
  echo 'inner daemon did not become ready within six minutes' >&2
  diagnose_native_startup
  exit 1
}
if [[ $lane == debian11-rootless ]]; then
  # Linux mountinfo reports suid/dev by absence of nosuid/nodev. Check the
  # effective mount, not merely the requested Podman volume options.
  if ! timeout --signal=TERM --kill-after=2s 15s "${podman_cmd[@]}" exec "$container" cat /proc/self/mountinfo 2>/dev/null |
    python3 "$script_dir/native-storage-options.py" /home/docker/.local/share/docker; then
    echo 'Debian rootless outer data-root mount lacks required effective options' >&2
    exit 1
  fi
fi

api_get() {
  local path=$1 target=$2
  local status
  status=$(timeout 20 curl -q --noproxy '*' -fsS --max-time 15 --unix-socket "$socket" \
    "http://localhost$path" -o "$target" -w '%{http_code}')
  [[ $status == 200 ]] || { echo "native GET did not return HTTP 200: $path" >&2; exit 1; }
  printf '%s\n' "$status" > "${target%.json}.status"
}
json_key() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}
api_get /version "$run_dir/version.json"
api_version=$(json_key "$run_dir/version.json" ApiVersion)
server_version=$(json_key "$run_dir/version.json" Version)
[[ $api_version =~ ^[0-9]+\.[0-9]+$ ]] && native_engine_release_matches "$lane" "$expected_release" "$server_version" || {
  echo "unexpected Engine release or API in $lane" >&2; exit 1;
}
api_get "/v$api_version/info" "$run_dir/info.json"
if [[ $lane == debian11-* ]]; then
  installed_docker_package=$("${podman_cmd[@]}" exec "$container" dpkg-query -W -f='${Version}' docker.io)
  [[ $installed_docker_package == "$DEBIAN_DOCKER_PACKAGE" ]] || {
    echo 'Debian docker.io revision differs from published image contract' >&2
    exit 1
  }
else
  installed_docker_package=
fi
python3 - "$run_dir/info.json" "$expected_mode" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    info = json.load(stream)
rootless = info.get('Rootless') is True or 'name=rootless' in info.get('SecurityOptions', [])
if rootless != (sys.argv[2] == 'rootless'):
    raise SystemExit('inner daemon mode differs from native lane')
PY

inner_docker=("${podman_cmd[@]}" exec "$container" docker -H unix:///dockerlens-native/docker.sock)
docker_root=$(timeout 15 "${inner_docker[@]}" info --format '{{.DockerRootDir}}')
inner_cgroup=$(timeout 15 "${inner_docker[@]}" info --format '{{.CgroupVersion}}')
# Report only fixed fields and validated package revision strings. In particular,
# never print Docker info or package-manager output containing host/user values.
inner_cgroup_driver=$(timeout 15 "${inner_docker[@]}" info --format '{{.CgroupDriver}}' 2>/dev/null) || inner_cgroup_driver=unavailable
[[ $inner_cgroup =~ ^[12]$ ]] || inner_cgroup=unavailable
[[ $inner_cgroup_driver =~ ^(cgroupfs|systemd|none)$ ]] || inner_cgroup_driver=unavailable
native_package_version() {
  local version
  version=$(timeout 15 "${podman_cmd[@]}" exec "$container" dpkg-query -W -f='${Version}' "$1" 2>/dev/null) || version=unavailable
  [[ ${#version} -le 80 && $version =~ ^[0-9][A-Za-z0-9.+:~_-]*$ ]] || version=unavailable
  printf '%s' "$version"
}
echo "DOCKERLENS_NATIVE_ENV: cgroup_driver=$inner_cgroup_driver cgroup_version=$inner_cgroup runc=$(native_package_version runc) containerd=$(native_package_version containerd) libseccomp2=$(native_package_version libseccomp2)"
if [[ $expected_mode == rootless ]]; then
  [[ $docker_root == /home/docker/.local/share/docker ]] || { echo 'rootless daemon store is outside owned volume' >&2; exit 1; }
else
  [[ $docker_root == /var/lib/docker ]] || { echo 'rootful daemon store is outside owned volume' >&2; exit 1; }
fi
timeout 120 "${inner_docker[@]}" pull "$FIXTURE_IMAGE" >/dev/null
# Docker CLI errors may contain authored values. Drain stderr without retaining
# more than its final 8 KiB, and emit only a fixed cause category.
classify_probe_error() {
  python3 -c 'import re
import sys
tail = bytearray()
for chunk in iter(lambda: sys.stdin.buffer.read(4096), b""):
    tail.extend(chunk)
    if len(tail) > 8192:
        del tail[:-8192]
message = tail.decode("utf-8", "replace").lower()
stage_match = re.search(
    r"(?:unable|failed) to spawn stage-([12])(?:[ \t]*:[ \t]*([^;\r\n]*))?",
    message,
)
stage = stage_match.group(1) if stage_match else None
stage_detail = (stage_match.group(2) or "") if stage_match else ""
if stage is not None:
    if "resource temporarily unavailable" in stage_detail or re.search(r"\beagain\b", stage_detail):
        print("stage" + stage + "_eagain")
        sys.exit(0)
    elif "operation not permitted" in stage_detail or "permission denied" in stage_detail:
        print("stage" + stage + "_permission")
        sys.exit(0)
    elif "invalid argument" in stage_detail:
        print("stage" + stage + "_invalid_argument")
        sys.exit(0)
if "final child pid from pipe" in message:
    if "eof" in message or "unexpected end of file" in message:
        print("final_pid_pipe_eof")
    elif "connection reset by peer" in message:
        print("final_pid_pipe_reset")
    else:
        print("final_pid_pipe_other")
    sys.exit(0)
if stage is not None:
    print("stage" + stage + "_other")
    sys.exit(0)
checks = (
    ("init_pipe_eof", ("init pipe eof", "init-pipe eof", "init-p: eof",
                       "failed to read init pid file", "read init-p: connection reset")),
    ("runtime_state_missing", ("state.json: no such file", "runtime state does not exist",
                               "failed to get container state")),
    ("invalid_argument", ("invalid argument",)),
    ("resource_unavailable", ("resource temporarily unavailable", "eagain")),
    ("file_descriptors", ("too many open files", "emfile", "enfile")),
    ("uidmap", ("newuidmap", "newgidmap", "uidmap", "gidmap")),
    ("userns", ("user namespace", "userns", "unshare")),
    ("cgroup", ("cgroup",)),
    ("network", ("iptables", "slirp", "network namespace", "failed to create network")),
    ("mount", ("mount", "pivot_root", "rootfs", "overlay", "fuse")),
    ("storage", ("no space left", "disk quota", "out of space")),
    ("executable", ("exec format error", "executable file not found")),
    ("security", ("seccomp", "apparmor", "selinux")),
    ("permission", ("permission denied", "operation not permitted")),
    ("oci", ("runc", "oci runtime", "oci runtime error")),
)
print(next((category for category, tokens in checks
            if any(token in message for token in tokens)), "unclassified"))'
}
export -f classify_probe_error
# The validated per-probe --since boundary excludes earlier package output and
# daemon errors. Keep only structured daemon error records, never shell trace
# or raw values; an absent record makes the pipeline fail closed.
filter_daemon_probe_logs() {
  python3 -c 'import re
import sys
tail = bytearray()
for chunk in iter(lambda: sys.stdin.buffer.read(4096), b""):
    tail.extend(chunk)
    if len(tail) > 65536:
        del tail[:-65536]
lines = tail.decode("utf-8", "replace").splitlines()[-160:]
stages = [index for index, line in enumerate(lines)
          if line.strip().lower() == "dockerlens_apt_stage: daemon"]
if stages:
    lines = lines[stages[-1] + 1:]
daemon_record = re.compile(r"^time=\"[^\"\r\n]{1,80}\" level=(?:error|warning|fatal)\b", re.I)
selected = [line for line in lines
            if len(line) <= 2048 and
            (daemon_record.match(line) or
             re.match(r"^(?:failed|error) (?:to )?start daemon:", line, re.I))]
if not selected:
    sys.exit(1)
sys.stdout.write(selected[-1])'
}
export -f filter_daemon_probe_logs
probe_known_categories='^(final_pid_pipe_eof|final_pid_pipe_reset|final_pid_pipe_other|stage[12]_(eagain|permission|invalid_argument|other)|resource_unavailable|file_descriptors|init_pipe_eof|runtime_state_missing|invalid_argument|uidmap|userns|cgroup|network|mount|storage|executable|security|permission|oci|unclassified)$'
probe_log_boundary() {
  python3 -c 'from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"))'
}
probe_daemon_category() {
  local boundary=$1 outer_owner category
  [[ $boundary =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$ ]] || {
    printf unavailable
    return
  }
  outer_owner=$(timeout 10 "${podman_cmd[@]}" inspect \
    --format '{{index .Config.Labels "io.dockerlens.native-run"}}' "$container" 2>/dev/null) || {
    printf unavailable
    return
  }
  [[ $outer_owner == "$run_id" ]] || { printf unavailable; return; }
  category=$(timeout --kill-after=1s 12s bash -c \
    'set -o pipefail; "$@" 2>/dev/null | filter_daemon_probe_logs | classify_probe_error' bash \
    "${podman_cmd[@]}" logs --since "$boundary" --tail 160 "$container") || {
    printf unavailable
    return
  }
  [[ $category =~ $probe_known_categories ]] && printf '%s' "$category" || printf unavailable
}
probe_failure_category() {
  local status=$1 category=$2
  if [[ $status == 124 ]]; then
    printf timeout
  elif [[ $status == 137 ]]; then
    printf terminated
  elif [[ $category =~ $probe_known_categories ]]; then
    printf '%s' "$category"
  else
    printf unclassified
  fi
}
probe_cleanup() {
  local name=$1 owner remaining_state=0
  if owner=$(timeout 10 "${inner_docker[@]}" container inspect \
    --format '{{index .Config.Labels "io.dockerlens.native-run"}}' "$name" 2>/dev/null); then
    [[ $owner == "$run_id" ]] || return 1
    timeout 15 "${inner_docker[@]}" container rm -f "$name" >/dev/null 2>&1 || return 1
  fi
  # A failed inspect alone cannot prove absence. A bounded exact-name listing
  # verifies removal even when create failed after creating the container.
  native_presence empty-success "${inner_docker[@]}" container ls -a \
    --filter "name=^/${name}$" --format '{{.Names}}' || remaining_state=$?
  (( remaining_state == 1 ))
}
run_inert_probe() {
  local network=$1 name="dl-${run_id}-probe-${1}" category=ok status state wait_code owner state_error_category daemon_category probe_started
  # Both modes use the same pinned image and inert command. Keep the container
  # until its bounded state inspection and ownership-verified removal complete.
  # Use the outer Podman host's UTC clock before the attempt, so later probes
  # cannot inherit prior daemon errors from cumulative container logs.
  probe_started=$(probe_log_boundary) || probe_started=unavailable
  [[ $probe_started =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$ ]] || \
    probe_started=unavailable
  if category=$(timeout --kill-after=1s 44s bash -c \
    'set -o pipefail; "$@" 2>&1 >/dev/null | classify_probe_error' bash \
    "${inner_docker[@]}" container create --name "$name" \
    --label "io.dockerlens.native-run=$run_id" --network "$network" \
    --entrypoint /bin/sh "$FIXTURE_IMAGE" -c 'exit 0'); then
    if category=$(timeout --kill-after=1s 44s bash -c \
      'set -o pipefail; "$@" 2>&1 >/dev/null | classify_probe_error' bash \
      "${inner_docker[@]}" container start "$name"); then
      category=ok
      wait_code=$(timeout 20 "${inner_docker[@]}" container wait "$name" 2>/dev/null) || wait_code=unavailable
      [[ $wait_code == 0 ]] || category=wait_failed
    else
      status=$?
      category=$(probe_failure_category "$status" "$category")
    fi
  else
    status=$?
    category="create_$(probe_failure_category "$status" "$category")"
  fi
  owner=$(timeout 10 "${inner_docker[@]}" container inspect \
    --format '{{index .Config.Labels "io.dockerlens.native-run"}}' "$name" 2>/dev/null) || owner=unavailable
  state=unavailable
  state_error_category=unavailable
  if [[ $owner == "$run_id" ]]; then
    state=$(timeout 10 "${inner_docker[@]}" container inspect \
      --format '{{.State.Status}}|{{.State.ExitCode}}' "$name" 2>/dev/null) || state=unavailable
    [[ $state =~ ^(created|running|exited|dead)\|[0-9]+$ ]] || state=unavailable
    # Stream private State.Error directly into the bounded classifier. Shell
    # variables and logs retain only its fixed category, never the raw value.
    state_error_category=$(timeout --kill-after=1s 12s bash -c \
      'set -o pipefail; "$@" 2>/dev/null | classify_probe_error' bash \
      "${inner_docker[@]}" container inspect --format '{{.State.Error}}' "$name") || \
      state_error_category=unavailable
    [[ $state_error_category =~ $probe_known_categories ]] || \
      state_error_category=unavailable
  fi
  if [[ $category == oci || $category == unclassified || $category == wait_failed ]]; then
    if [[ $state_error_category != unavailable && $state_error_category != unclassified ]]; then
      category=$state_error_category
    fi
  fi
  echo "DOCKERLENS_NATIVE_PROBE: ${network}_start_${category} state=$state" >&2
  if [[ $category != ok ]]; then
    echo "DOCKERLENS_NATIVE_PROBE: ${network}_state_error_${state_error_category}" >&2
    if [[ $owner == "$run_id" ]]; then
      daemon_category=$(probe_daemon_category "$probe_started")
    else
      daemon_category=unavailable
    fi
    echo "DOCKERLENS_NATIVE_PROBE: ${network}_daemon_${daemon_category}" >&2
  fi
  if ! probe_cleanup "$name"; then
    echo "DOCKERLENS_NATIVE_PROBE: ${network}_cleanup_unverified state_error=$state_error_category" >&2
    return 1
  fi
  [[ $category == ok ]]
}
probe_failed=0
run_inert_probe none || probe_failed=1
run_inert_probe bridge || probe_failed=1
(( probe_failed == 0 )) || exit 1
network_id=$(timeout 30 "${inner_docker[@]}" network create --driver bridge "dl-${run_id}-net")
volume_name="dl-${run_id}-vol"
timeout 30 "${inner_docker[@]}" volume create "$volume_name" >/dev/null
selected_name="dl-${run_id}-box"
peer_name="dl-${run_id}-peer"
ports_name="dl-${run_id}-ports"
container_id=$(timeout 30 "${inner_docker[@]}" container create --name "$selected_name" \
  --user 0:0 --workdir /tmp --hostname dockerlens-native \
  --label io.dockerlens.fixture=synthetic --label com.docker.compose.project=source-app \
  --network "dl-${run_id}-net" --mount "type=volume,source=$volume_name,target=/data" \
  --mount 'type=bind,source=/dockerlens-native/native-bind,target=/readonly,readonly' \
  -p 18080:8080/tcp -p 18081:8081/udp \
  -e DL_CONFORMANCE=synthetic-secret -e EMPTY= -e 'QUOTED=a"b\c' \
  --health-cmd 'true' --restart on-failure:3 --entrypoint /bin/sh \
  "$FIXTURE_IMAGE" -c 'httpd -f -p 8080 -h /readonly & nc -u -l -p 8081 > /data/udp-received & wait')
peer_id=$(timeout 30 "${inner_docker[@]}" container create --name "$peer_name" \
  --label io.dockerlens.fixture=decoy -e DL_PRIVATE_CANARY=decoy-secret \
  "$FIXTURE_IMAGE" true)
ports_id=$(timeout 30 "${inner_docker[@]}" container create --name "$ports_name" \
  --label io.dockerlens.fixture=ports \
  -p 127.0.0.1:18082:8080/tcp -p 127.0.0.2:18083:8080/tcp \
  "$FIXTURE_IMAGE" true)
[[ $peer_id =~ ^[0-9a-f]{64}$ && $ports_id =~ ^[0-9a-f]{64}$ && $container_id =~ ^[0-9a-f]{64}$ ]] || {
  echo 'native source fixtures have invalid container IDs' >&2
  exit 1
}
api_get "/v$api_version/containers/$container_id/json" "$run_dir/container.json"
api_get "/v$api_version/containers/$ports_id/json" "$run_dir/ports-container.json"
api_get "/v$api_version/containers/json?all=1" "$run_dir/list.json"
api_get "/v$api_version/networks/$network_id" "$run_dir/network.json"
api_get "/v$api_version/volumes/$volume_name" "$run_dir/volume.json"

if [[ $EUID == 0 ]]; then
  used_kib=$(du -sk "$volume_path" | awk '{print $1}')
else
  used_kib=$(sudo -n du -sk "$volume_path" | awk '{print $1}')
fi
(( used_kib <= 4 * 1024 * 1024 )) || { echo 'nested daemon exceeded 4 GiB storage budget' >&2; exit 1; }

export NATIVE_ENGINE_SOCKET="$socket" NATIVE_CAPTURE_DIR="$run_dir" NATIVE_CONTAINER_ID="$container_id"
export NATIVE_NETWORK_ID="$network_id" NATIVE_VOLUME_NAME="$volume_name"
export NATIVE_SELECTED_NAME="$selected_name" NATIVE_PEER_NAME="$peer_name" NATIVE_PEER_ID="$peer_id"
export NATIVE_PORTS_NAME="$ports_name" NATIVE_PORTS_ID="$ports_id"
export NATIVE_ENGINE_VERSION="$server_version" NATIVE_DAEMON_MODE="$expected_mode"
export NATIVE_API_VERSION="$api_version"
export NATIVE_LANE="$lane" NATIVE_DOCKER_PACKAGE="$installed_docker_package"
export NATIVE_FIXTURE_IMAGE="$FIXTURE_IMAGE" NATIVE_OUTER_CONTAINER="$container"
export NATIVE_EGRESS_SIDECAR_IPV4="$sidecar_ip"
export NATIVE_BIND_SOURCE=/dockerlens-native/native-bind
export NATIVE_SHAPES_PATH="$run_dir/target-shapes.json"
export NATIVE_SOURCE_PROBES_PATH="$run_dir/source-probes.json"
export NATIVE_NETWORK_PROBES_PATH="$run_dir/network-probes.json"
export NATIVE_VOLUME_PROBES_PATH="$run_dir/volume-probes.json"
export NATIVE_VOLUME_LABEL_PROBES_PATH="$run_dir/volume-label-probes.json"
export NATIVE_IDENTITY_PROBES_PATH="$run_dir/identity-probes.json"
export NATIVE_PORT_PROBES_PATH="$run_dir/port-probes.json"
export NATIVE_HEALTH_METADATA_PROOF_PATH="$run_dir/health-metadata.json"
export NATIVE_PORT_START_DIAGNOSTIC_PATH="$run_dir/diagnostics/port-start-window.json"
export NATIVE_IDENTITY_CANDIDATE_SHA
NATIVE_IDENTITY_CANDIDATE_SHA=$(git -C "$script_dir/.." rev-parse HEAD)
[[ $NATIVE_IDENTITY_CANDIDATE_SHA =~ ^[0-9a-f]{40}$ ]] || { echo 'native identity requires exact candidate SHA' >&2; exit 1; }
export NATIVE_PORT_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_HEALTH_METADATA_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
if [[ $EUID == 0 ]]; then export NATIVE_PODMAN_USE_SUDO=0; else export NATIVE_PODMAN_USE_SUDO=1; fi

port_start_failure_diagnostic() {
  local remaining=$((1800 - SECONDS)) started ended ignored started_cs ended_cs result diagnostic_status=0
  # Failure-only observation lives inside the existing active 30-minute
  # budget. It is not a new parent cleanup reserve or a timeout extension.
  if (( remaining < 5 )) || [[ -z $watchdog_pid ]] || ! kill -0 "$watchdog_pid" 2>/dev/null; then
    echo 'DOCKERLENS_NATIVE_PORT_START_LOG_DIAG: source=none category=unavailable collector=budget' >&2
    return 0
  fi
  read -r started ignored < /proc/uptime || return 0
  [[ $started =~ ^[0-9]+\.[0-9]{2}$ ]] || return 0
  started_cs=${started/./}
  # Local file reads need no privilege handoff or Podman client. Timeout and
  # helper share the caller's privileges in both root and non-root invocations.
  result=$(timeout --signal=TERM --kill-after=0.25s 3.5s \
    python3 "$script_dir/native-port-start-diagnostic.py" \
    "$run_dir" "$EUID" "$run_id" "$lane" "$NATIVE_PORT_CANDIDATE_SHA" \
    "$port_invocation_us" "$started_cs" "$remaining" "$watchdog_pid" \
    "$port_start_log_fd" "$image" 2>/dev/null) || diagnostic_status=$?
  read -r ended ignored < /proc/uptime || return 0
  [[ $ended =~ ^[0-9]+\.[0-9]{2}$ ]] || return 0
  ended_cs=${ended/./}
  # BOOTTIME includes helper initialization and collection. Centisecond
  # quantization is conservatively below four seconds at the final handoff.
  if (( ended_cs < started_cs || ended_cs - started_cs >= 399 || SECONDS >= 1800 )) ||
      ! kill -0 "$watchdog_pid" 2>/dev/null; then
    echo 'DOCKERLENS_NATIVE_PORT_START_LOG_DIAG: source=none category=unavailable collector=timeout' >&2
  elif (( diagnostic_status != 0 )); then
    echo 'DOCKERLENS_NATIVE_PORT_START_LOG_DIAG: source=none category=unavailable collector=unavailable' >&2
  elif [[ $result =~ ^DOCKERLENS_NATIVE_PORT_START_LOG_DIAG:\ source=(none|daemon|rootless_trace|mixed)\ category=(unavailable|unclassified|ambiguous|rootless_network|port_proxy|uidmap|permission|daemon_network|daemon_runtime)\ collector=(complete|window_unavailable|ownership_unverified|query_failed|output_limit|timeout|cancelled|budget|watchdog|unavailable)$ ]]; then
    printf '%s\n' "$result" >&2
  else
    echo 'DOCKERLENS_NATIVE_PORT_START_LOG_DIAG: source=none category=unavailable collector=unavailable' >&2
  fi
  return 0
}

"$(dirname "$0")/run-exact-native-test.sh" native_capture live_engine_capture_decodes
"$(dirname "$0")/run-exact-native-test.sh" acquisition live_read_only_acquisition_matches_oracle
"$(dirname "$0")/run-exact-native-test.sh" native_selection live_native_selection_and_source_observations
"$(dirname "$0")/run-exact-native-test.sh" native_selection live_network_membership_matches_engine
"$(dirname "$0")/run-exact-native-test.sh" native_target live_target_render_matches_engine
"$(dirname "$0")/run-exact-native-test.sh" native_network live_network_render_matches_engine
"$(dirname "$0")/run-exact-native-test.sh" native_network live_internal_network_blocks_external_egress
"$(dirname "$0")/run-exact-native-test.sh" native_volume live_existing_volume_prerequisite_matches_engine
"$(dirname "$0")/run-exact-native-test.sh" native_volume_label live_created_volume_labels_match_engine
"$(dirname "$0")/run-exact-native-test.sh" native_identity live_container_process_identity_matches_engine
port_invocation_us=${EPOCHREALTIME/./}
port_status=0
{
"$(dirname "$0")/run-exact-native-test.sh" native_port live_port_publications_match_engine
} || port_status=$?
if (( port_status != 0 )); then
  port_start_failure_diagnostic || true
  exit "$port_status"
fi
"$(dirname "$0")/run-exact-native-test.sh" native_health_metadata live_health_metadata_matches_engine

if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]; then
  candidate_sha=$(git -C "$script_dir/.." rev-parse HEAD)
  [[ $candidate_sha =~ ^[0-9a-f]{40}$ && ${DOCKERLENS_NATIVE_CANDIDATE_SHA:-} == "$candidate_sha" ]] || {
    echo 'native evidence candidate SHA does not match reviewed checkout' >&2
    exit 1
  }
  [[ -z $(git -C "$script_dir/.." status --porcelain --untracked-files=all) ]] || {
    echo 'native evidence requires a clean candidate checkout' >&2
    exit 1
  }
  python3 "$script_dir/native-evidence.py" "$run_dir/version.json" "$NATIVE_SHAPES_PATH" "$NATIVE_SOURCE_PROBES_PATH" "$NATIVE_NETWORK_PROBES_PATH" "$NATIVE_VOLUME_PROBES_PATH" "$NATIVE_VOLUME_LABEL_PROBES_PATH" "$NATIVE_IDENTITY_PROBES_PATH" "$NATIVE_PORT_PROBES_PATH" "$NATIVE_HEALTH_METADATA_PROOF_PATH" "$run_dir" \
    "$DOCKERLENS_NATIVE_EVIDENCE_DIR/$lane.json" "$lane" "$image" "$expected_mode" \
    "$installed_docker_package" "$candidate_sha" "$run_id"
fi

native_success_summary="native conformance passed: $lane; Engine $server_version; API $api_version; mode $expected_mode; inner cgroup $inner_cgroup; outer $("${podman_cmd[@]}" --version); kernel $(uname -r); privileged $privileged; nested storage ${used_kib} KiB"
