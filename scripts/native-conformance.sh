#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$script_dir/native-version.sh"

# Registry manifest digests verified with skopeo inspect on 2026-09-26.
# renovate: datasource=docker depName=docker.io/library/docker
UPSTREAM_ROOTFUL_IMAGE='docker.io/library/docker:28.5.1-dind@sha256:ea9d20492ca1caaaba78e68453433895d256173c79281756e88b745647fcbcfd'
# renovate: datasource=docker depName=docker.io/library/docker
UPSTREAM_ROOTLESS_IMAGE='docker.io/library/docker:28.5.1-dind-rootless@sha256:87d03cfe51f2bf87eec6dda1922dc572da4d37a1d21c5ca8e8b22c8a1fa107cc'
# renovate: datasource=docker depName=docker.io/library/debian
DEBIAN_IMAGE='docker.io/library/debian:11.11-slim@sha256:e5b6442dd2e9684cf5e87d8338b5968f3b348636fc0be6d7850a381e3731a2bd'
# renovate: datasource=docker depName=docker.io/library/busybox
FIXTURE_IMAGE='docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e'
# Debian 11 distribution revision, distinct from upstream Engine 28.5.1.
DEBIAN_DOCKER_PACKAGE='20.10.5+dfsg1-1+deb11u4'
DEBIAN_CA_CERTIFICATES_PACKAGE='20250419~deb12u1~deb11u1'
DEBIAN_ROOTLESSKIT_PACKAGE='0.14.2-1+b3'
DEBIAN_SLIRP4NETNS_PACKAGE='1.0.1-2'
DEBIAN_UIDMAP_PACKAGE='1:4.8.1-1+deb11u1'
DEBIAN_FUSE_OVERLAYFS_PACKAGE='1.4.0-1'

usage() {
  echo "usage: $0 {debian11-rootful|debian11-rootless|upstream-rootful|upstream-rootless}" >&2
  exit 2
}

[[ $# == 1 ]] || usage
lane=$1
case "$lane" in
  debian11-rootful) image=$DEBIAN_IMAGE; expected_mode=rootful; expected_release='20.10.5' ;;
  debian11-rootless) image=$DEBIAN_IMAGE; expected_mode=rootless; expected_release='20.10.5' ;;
  upstream-rootful) image=$UPSTREAM_ROOTFUL_IMAGE; expected_mode=rootful; expected_release='28.5.1' ;;
  upstream-rootless) image=$UPSTREAM_ROOTLESS_IMAGE; expected_mode=rootless; expected_release='28.5.1' ;;
  *) usage ;;
esac

for tool in podman curl python3 timeout df du mktemp install; do
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

# A random directory, container, and volume belong to exactly this lane.
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/dockerlens-native.XXXXXXXX")
run_id=${run_dir##*.}
container="dl-native-${run_id}"
volume="dl-native-data-${run_id}"
socket_dir="$run_dir/socket"
socket="$socket_dir/docker.sock"
mkdir -m 0777 "$socket_dir"
mkdir -m 0755 "$socket_dir/native-bind"
install -m 0644 "$script_dir/native-apt-install.sh" "$socket_dir/native-apt-install.sh"
install -m 0644 "$script_dir/native-debian-snapshot.sh" "$socket_dir/native-debian-snapshot.sh"
printf 'native-bind-canary\n' > "$socket_dir/native-bind/canary"
printf 'native-tcp-canary\n' > "$socket_dir/native-bind/index.html"
chmod 0700 "$run_dir"
watchdog_pid=
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [[ -n $watchdog_pid ]]; then
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
  fi
  container_state=0
  "${podman_cmd[@]}" container exists "$container" || container_state=$?
  if (( container_state != 1 )); then
    if (( container_state != 0 )); then
      echo "could not verify whether owned container $container exists (exit $container_state)" >&2
      status=1
    fi
    owner=$("${podman_cmd[@]}" inspect --format '{{index .Config.Labels "io.dockerlens.native-run"}}' "$container") || status=1
    if [[ ${owner:-} == "$run_id" ]]; then
      "${podman_cmd[@]}" rm -f "$container" >/dev/null || status=1
      removed_state=0
      "${podman_cmd[@]}" container exists "$container" || removed_state=$?
      if (( removed_state != 1 )); then
        echo "owned container cleanup readback failed (exists exit $removed_state)" >&2
        status=1
      fi
    else
      echo "refusing to remove container $container without matching ownership label" >&2
      status=1
    fi
  fi
  volume_state=0
  "${podman_cmd[@]}" volume exists "$volume" || volume_state=$?
  if (( volume_state != 1 )); then
    if (( volume_state != 0 )); then
      echo "could not verify whether owned volume $volume exists (exit $volume_state)" >&2
      status=1
    fi
    owner=$("${podman_cmd[@]}" volume inspect --format '{{index .Labels "io.dockerlens.native-run"}}' "$volume") || status=1
    if [[ ${owner:-} == "$run_id" ]]; then
      "${podman_cmd[@]}" volume rm "$volume" >/dev/null || status=1
      removed_state=0
      "${podman_cmd[@]}" volume exists "$volume" || removed_state=$?
      if (( removed_state != 1 )); then
        echo "owned volume cleanup readback failed (exists exit $removed_state)" >&2
        status=1
      fi
    else
      echo "refusing to remove volume $volume without matching ownership label" >&2
      status=1
    fi
  fi
  if [[ $run_dir == "${TMPDIR:-/tmp}"/dockerlens-native.* && -d $run_dir ]]; then
    rm -rf -- "$run_dir" || status=1
  fi
  if (( status != 0 )); then echo "native lane $lane failed; verify owned resources $container and $volume" >&2; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
echo "native lane $lane owns Podman container $container and volume $volume"

diagnose_native_startup() {
  local state diagnosis
  state=$("${podman_cmd[@]}" inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}' "$container" 2>/dev/null) || state=unavailable
  [[ $state =~ ^(running|exited|created|configured|paused|stopped)\|[0-9]+\|(true|false)$ ]] || state=unavailable
  # Retain only the final 64 KiB of the last 80 lines. Logs can contain protected
  # values, so only fixed stage and category names leave this function.
  diagnosis=$(timeout 10 "${podman_cmd[@]}" logs --tail 80 "$container" 2>/dev/null |
    python3 -c 'import sys
tail = bytearray()
for chunk in iter(lambda: sys.stdin.buffer.read(65536), b""):
    tail.extend(chunk)
    if len(tail) > 65536:
        del tail[:-65536]
s = tail.decode("utf-8", "replace").lower()
stages = {"dockerlens_apt_stage: sources": "sources",
          "dockerlens_apt_stage: update": "update",
          "dockerlens_apt_stage: install": "install",
          "dockerlens_apt_stage: daemon": "daemon"}
lines = s.splitlines()
last_stage = next(((index, stages[lines[index].strip()])
                   for index in range(len(lines) - 1, -1, -1)
                   if lines[index].strip() in stages), None)
stage = (last_stage[1] if last_stage else "unavailable") if sys.argv[1].startswith("debian11-") else "daemon"
if last_stage and sys.argv[1].startswith("debian11-"):
    s = "\n".join(lines[last_stage[0] + 1:])
package_checks = (("package_sources_unexpected", ("dockerlens_apt_result: unexpected_sources",)),
                  ("package_version_unavailable", ("dockerlens_apt_result: version-unavailable",)),
                  ("package_post_invoke", ("dockerlens_apt_result: package_post_invoke",)),
                  ("package_signature", ("dockerlens_apt_result: package_signature",)),
                  ("package_time", ("dockerlens_apt_result: package_time",)),
                  ("package_disk", ("dockerlens_apt_result: package_disk",)),
                  ("package_lock", ("dockerlens_apt_result: package_lock",)),
                  ("package_dependency", ("dockerlens_apt_result: package_dependency",)),
                  ("package_download", ("dockerlens_apt_result: package_download",)),
                  ("package_dpkg", ("dockerlens_apt_result: package_dpkg",)),
                  ("package_install", ("dockerlens_apt_result: package_install",)),
                  ("package_post_invoke", ("post-invoke",)),
                  ("package_signature", ("no_pubkey", "expkeysig", "badsig",
                                 "signatures could not be verified", "invalid signature",
                                 "is not signed")),
                  ("package_time", ("not valid yet", "release file is expired",
                            "release file expired", "invalid for another")),
                  ("package_disk", ("no space left on device", "write error - write",)),
                  ("package_lock", ("could not get lock", "unable to acquire the dpkg frontend lock")),
                  ("package_dependency", ("unmet dependencies", "dependency problems",
                                  "unable to correct problems", "held broken packages",
                                  "depends:")),
                  ("package_download", ("failed to fetch", "temporary failure resolving",
                                "does not have a release file", "404 not found")),
                  ("package_dpkg", ("sub-process /usr/bin/dpkg returned an error code",
                                    "dpkg: error processing", "dpkg: error:")),
                  ("package_install", ("unable to locate package",
                                       "was not found", "has no installation candidate")),
                  ("package_apt_failure", ("dockerlens_apt_result: package_apt_failure",
                                           "dockerlens_apt_result: install-failed")))
daemon_checks = (("rootless_home_unwritable", ("dockerlens_daemon_result: home_unwritable",
                                               "home needs to be set and writable")),
                 ("rootless_runtime_unwritable", ("dockerlens_daemon_result: runtime_unwritable",
                                                  "xdg_runtime_dir needs to be set and writable")),
                 ("daemon_storage", ("error initializing graphdriver",
                                     "failed to mount overlay", "storage driver")),
                 ("rootless_uidmap", ("uid_map", "newuidmap", "newgidmap")),
                 ("daemon_permission", ("operation not permitted", "permission denied")),
                 ("rootless_network", ("rootlesskit", "slirp4netns")),
                 ("daemon_network", ("iptables", "failed to create nat chain",
                                     "error creating default bridge")),
                 ("daemon_startup", ("failed to start daemon",)))
if stage in ("sources", "update", "install"):
    checks = package_checks
elif stage == "daemon":
    checks = daemon_checks
else:
    checks = package_checks + daemon_checks
category = next((name for name, needles in checks if any(item in s for item in needles)), "unclassified")
print("stage=" + stage + " category=" + category)' "$lane") || diagnosis='stage=unavailable category=unavailable'
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
for resource in container volume; do
  if [[ $resource == container ]]; then name=$container; else name=$volume; fi
  resource_state=0
  "${podman_cmd[@]}" "$resource" exists "$name" || resource_state=$?
  case $resource_state in
    0) echo "generated native $resource name already exists" >&2; exit 1 ;;
    1) ;;
    *) echo "could not verify generated native $resource name (exit $resource_state)" >&2; exit 1 ;;
  esac
done
"${podman_cmd[@]}" volume create --label "io.dockerlens.native-run=$run_id" "$volume" >/dev/null
volume_path=$("${podman_cmd[@]}" volume inspect --format '{{.Mountpoint}}' "$volume")
main_pid=$$
watchdog() {
  trap - EXIT HUP INT TERM
  local used free
  while :; do
    sleep 5
    if [[ $EUID == 0 ]]; then
      used=$(du -sk "$volume_path" | awk '{print $1}') || { kill -TERM "$main_pid"; return; }
      free=$(df -Pk "$graph_root" | awk 'END {print $4}') || { kill -TERM "$main_pid"; return; }
    else
      used=$(sudo -n du -sk "$volume_path" | awk '{print $1}') || { kill -TERM "$main_pid"; return; }
      free=$(sudo -n df -Pk "$graph_root" | awk 'END {print $4}') || { kill -TERM "$main_pid"; return; }
    fi
    if (( used > 4 * 1024 * 1024 || free < 2 * 1024 * 1024 || SECONDS > 1800 )); then
      echo "native lane exceeded its storage, free-space, or 30-minute budget" >&2
      kill -TERM "$main_pid"
      return
    fi
  done
}
if [[ $lane == debian11-rootful ]]; then
  storage_mount="$volume:/var/lib/docker:U"
  start=(sh -ec '
    printf "DOCKERLENS_APT_STAGE: sources\n"
    sh /run/dockerlens/native-debian-snapshot.sh
    printf "DOCKERLENS_APT_STAGE: update\n"
    apt-get update -qq
    printf "DOCKERLENS_APT_STAGE: install\n"
    for spec in "docker.io=$DEBIAN_DOCKER_PACKAGE" "ca-certificates=$DEBIAN_CA_CERTIFICATES_PACKAGE"; do
      package=${spec%%=*}; pinned=${spec#*=}
      if ! apt-cache madison "$package" | awk -F "|" -v pin="$pinned" '\''
        { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); if ($2 == pin) found = 1 }
        END { exit !found }'\''; then
        printf "DOCKERLENS_APT_RESULT: version-unavailable\n"
        exit 100
      fi
    done
    sh /run/dockerlens/native-apt-install.sh \
      "docker.io=$DEBIAN_DOCKER_PACKAGE" "ca-certificates=$DEBIAN_CA_CERTIFICATES_PACKAGE"
    printf "DOCKERLENS_APT_STAGE: daemon\n"
    exec dockerd --host=unix:///run/dockerlens/docker.sock --storage-driver=vfs
  ')
elif [[ $lane == debian11-rootless ]]; then
  storage_mount="$volume:/home/rootless/.local/share/docker:U"
  start=(sh -ec '
    printf "DOCKERLENS_APT_STAGE: sources\n"
    sh /run/dockerlens/native-debian-snapshot.sh
    printf "DOCKERLENS_APT_STAGE: update\n"
    apt-get update -qq
    printf "DOCKERLENS_APT_STAGE: install\n"
    for spec in "docker.io=$DEBIAN_DOCKER_PACKAGE" "ca-certificates=$DEBIAN_CA_CERTIFICATES_PACKAGE" \
      "rootlesskit=$DEBIAN_ROOTLESSKIT_PACKAGE" \
      "slirp4netns=$DEBIAN_SLIRP4NETNS_PACKAGE" "uidmap=$DEBIAN_UIDMAP_PACKAGE" \
      "fuse-overlayfs=$DEBIAN_FUSE_OVERLAYFS_PACKAGE"; do
      package=${spec%%=*}; pinned=${spec#*=}
      if ! apt-cache madison "$package" | awk -F "|" -v pin="$pinned" '\''
        { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); if ($2 == pin) found = 1 }
        END { exit !found }'\''; then
        printf "DOCKERLENS_APT_RESULT: version-unavailable\n"
        exit 100
      fi
    done
    sh /run/dockerlens/native-apt-install.sh \
      "docker.io=$DEBIAN_DOCKER_PACKAGE" "ca-certificates=$DEBIAN_CA_CERTIFICATES_PACKAGE" \
      "rootlesskit=$DEBIAN_ROOTLESSKIT_PACKAGE" \
      "slirp4netns=$DEBIAN_SLIRP4NETNS_PACKAGE" "uidmap=$DEBIAN_UIDMAP_PACKAGE" \
      "fuse-overlayfs=$DEBIAN_FUSE_OVERLAYFS_PACKAGE"
    useradd --create-home --uid 1000 --shell /bin/sh rootless
    install -d -m 0700 -o rootless -g rootless /home/rootless
    grep -q "^rootless:" /etc/subuid || printf "rootless:100000:65536\n" >> /etc/subuid
    grep -q "^rootless:" /etc/subgid || printf "rootless:100000:65536\n" >> /etc/subgid
    install -d -m 0700 -o rootless -g rootless /run/user/1000
    install -d -m 0700 -o rootless -g rootless /home/rootless/.local/share/docker
    chown -R rootless:rootless /home/rootless/.local/share/docker
    printf "DOCKERLENS_APT_STAGE: daemon\n"
    if ! su -s /bin/sh rootless -c "test -w /home/rootless" >/dev/null 2>&1; then
      printf "DOCKERLENS_DAEMON_RESULT: home_unwritable\n"
      exit 100
    fi
    if ! su -s /bin/sh rootless -c "test -w /run/user/1000" >/dev/null 2>&1; then
      printf "DOCKERLENS_DAEMON_RESULT: runtime_unwritable\n"
      exit 100
    fi
    exec su -s /bin/sh rootless -c "/usr/bin/env XDG_RUNTIME_DIR=/run/user/1000 HOME=/home/rootless /usr/share/docker.io/contrib/dockerd-rootless.sh --host=unix:///run/dockerlens/docker.sock --storage-driver=vfs"
  ')
else
  if [[ $expected_mode == rootless ]]; then
    storage_mount="$volume:/home/rootless/.local/share/docker:U"
  else
    storage_mount="$volume:/var/lib/docker:U"
  fi
  start=(--host=unix:///run/dockerlens/docker.sock --storage-driver=vfs)
fi

watchdog &
watchdog_pid=$!
# Pull only the reviewed digest under the lane's time and free-space budget.
# Prevent `run` from doing a second unbounded implicit pull.
timeout 180 "${podman_cmd[@]}" pull "$image" >/dev/null
timeout 120 "${podman_cmd[@]}" run --pull=never -d --name "$container" --label "io.dockerlens.native-run=$run_id" \
  --privileged --pids-limit=512 --memory=4g --cpus=2 \
  --env DOCKER_TLS_CERTDIR= --env "DEBIAN_DOCKER_PACKAGE=$DEBIAN_DOCKER_PACKAGE" \
  --env "DEBIAN_CA_CERTIFICATES_PACKAGE=$DEBIAN_CA_CERTIFICATES_PACKAGE" \
  --env "DEBIAN_ROOTLESSKIT_PACKAGE=$DEBIAN_ROOTLESSKIT_PACKAGE" \
  --env "DEBIAN_SLIRP4NETNS_PACKAGE=$DEBIAN_SLIRP4NETNS_PACKAGE" \
  --env "DEBIAN_UIDMAP_PACKAGE=$DEBIAN_UIDMAP_PACKAGE" \
  --env "DEBIAN_FUSE_OVERLAYFS_PACKAGE=$DEBIAN_FUSE_OVERLAYFS_PACKAGE" \
  --volume "$storage_mount" --volume "$socket_dir:/run/dockerlens" \
  "$image" "${start[@]}" >/dev/null
privileged=$("${podman_cmd[@]}" inspect --format '{{.HostConfig.Privileged}}' "$container")
[[ $privileged == true ]] || { echo 'outer container does not have reviewed nesting privilege' >&2; exit 1; }

deadline=$((SECONDS + 360))
while (( SECONDS < deadline )); do
  if [[ -S $socket ]]; then
    if [[ $EUID == 0 ]]; then chmod 0666 "$socket"; else sudo -n chmod 0666 "$socket"; fi
    if curl -fs --max-time 5 --unix-socket "$socket" http://localhost/_ping >/dev/null; then break; fi
  fi
  running=$("${podman_cmd[@]}" inspect --format '{{.State.Running}}' "$container" 2>/dev/null) || running=unknown
  if [[ $running != true ]]; then
    echo 'inner daemon exited before readiness' >&2
    diagnose_native_startup
    exit 1
  fi
  sleep 2
done
[[ -S $socket ]] && curl -fs --max-time 5 --unix-socket "$socket" http://localhost/_ping >/dev/null || {
  echo 'inner daemon did not become ready within six minutes' >&2
  diagnose_native_startup
  exit 1
}

api_get() {
  local path=$1 target=$2
  local status
  status=$(timeout 20 curl -fsS --max-time 15 --unix-socket "$socket" \
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
  echo "unexpected Engine version in $lane: $server_version API $api_version" >&2; exit 1;
}
api_get "/v$api_version/info" "$run_dir/info.json"
if [[ $lane == debian11-* ]]; then
  packages=("docker.io:$DEBIAN_DOCKER_PACKAGE" "ca-certificates:$DEBIAN_CA_CERTIFICATES_PACKAGE")
  if [[ $expected_mode == rootless ]]; then
    packages+=("rootlesskit:$DEBIAN_ROOTLESSKIT_PACKAGE" "slirp4netns:$DEBIAN_SLIRP4NETNS_PACKAGE" "uidmap:$DEBIAN_UIDMAP_PACKAGE" "fuse-overlayfs:$DEBIAN_FUSE_OVERLAYFS_PACKAGE")
  fi
  for package in "${packages[@]}"; do
    name=${package%%:*}
    pinned=${package#*:}
    installed=$("${podman_cmd[@]}" exec "$container" dpkg-query -W -f='${Version}' "$name")
    [[ $installed == "$pinned" ]] || { echo "Debian package revision differs from pin: $name" >&2; exit 1; }
  done
fi
python3 - "$run_dir/info.json" "$expected_mode" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    info = json.load(stream)
rootless = info.get('Rootless') is True or 'name=rootless' in info.get('SecurityOptions', [])
if rootless != (sys.argv[2] == 'rootless'):
    raise SystemExit('inner daemon mode differs from native lane')
PY

inner_docker=("${podman_cmd[@]}" exec "$container" docker -H unix:///run/dockerlens/docker.sock)
docker_root=$(timeout 15 "${inner_docker[@]}" info --format '{{.DockerRootDir}}')
inner_cgroup=$(timeout 15 "${inner_docker[@]}" info --format '{{.CgroupVersion}}')
if [[ $expected_mode == rootless ]]; then
  [[ $docker_root == /home/rootless/.local/share/docker ]] || { echo 'rootless daemon store is outside owned volume' >&2; exit 1; }
else
  [[ $docker_root == /var/lib/docker ]] || { echo 'rootful daemon store is outside owned volume' >&2; exit 1; }
fi
timeout 120 "${inner_docker[@]}" pull "$FIXTURE_IMAGE" >/dev/null
network_id=$(timeout 30 "${inner_docker[@]}" network create --driver bridge "dl-${run_id}-net")
volume_name="dl-${run_id}-vol"
timeout 30 "${inner_docker[@]}" volume create "$volume_name" >/dev/null
container_id=$(timeout 30 "${inner_docker[@]}" container create --name "dl-${run_id}-box" \
  --network "dl-${run_id}-net" --mount "type=volume,source=$volume_name,target=/data" \
  --mount 'type=bind,source=/run/dockerlens/native-bind,target=/readonly,readonly' \
  -p 18080:8080/tcp -p 18081:8081/udp \
  -e DL_CONFORMANCE=synthetic-secret -e EMPTY= -e 'QUOTED=a"b\c' \
  --health-cmd 'true' --restart on-failure:3 --entrypoint /bin/sh \
  "$FIXTURE_IMAGE" -c 'httpd -f -p 8080 -h /readonly & nc -u -l -p 8081 > /data/udp-received & wait')
api_get "/v$api_version/containers/$container_id/json" "$run_dir/container.json"
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
export NATIVE_ENGINE_VERSION="$server_version" NATIVE_DAEMON_MODE="$expected_mode"
export NATIVE_API_VERSION="$api_version"
export NATIVE_FIXTURE_IMAGE="$FIXTURE_IMAGE" NATIVE_OUTER_CONTAINER="$container"
export NATIVE_BIND_SOURCE=/run/dockerlens/native-bind
if [[ $EUID == 0 ]]; then export NATIVE_PODMAN_USE_SUDO=0; else export NATIVE_PODMAN_USE_SUDO=1; fi
"$(dirname "$0")/run-exact-native-test.sh" native_capture live_engine_capture_decodes
"$(dirname "$0")/run-exact-native-test.sh" acquisition live_read_only_acquisition_matches_oracle
"$(dirname "$0")/run-exact-native-test.sh" native_target live_target_render_matches_engine

echo "native conformance passed: $lane; Engine $server_version; API $api_version; mode $expected_mode; inner cgroup $inner_cgroup; outer $("${podman_cmd[@]}" --version); kernel $(uname -r); privileged $privileged; nested storage ${used_kib} KiB"
