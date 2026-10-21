#!/usr/bin/env bash
# Test-only canonical outer-engine seam. Sourcing defines functions only; no
# probes, startup, privilege escalation, environment changes or native authority.
# Callers retain aggregate/watchdog/cleanup owners and exact candidate admission.

native_outer_policy() {
  case ${1-podman} in
    podman) native_outer_engine=podman ;;
    docker)
      # Accident guard, not authentication: trusted coordinator admission is
      # still mandatory. Never opt a developer's localhost into Docker.
      [[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
         ${RUNNER_OS:-} == Linux && ${GITHUB_REF:-} == refs/heads/main &&
         ${GITHUB_EVENT_NAME:-} =~ ^(push|workflow_dispatch)$ &&
         ${GITHUB_REPOSITORY:-} =~ ^Strukturpiloten/(docker-lens|boxferry)$ &&
         ${ImageOS:-} == ubuntu24 && ${ImageVersion:-} =~ ^[0-9]{8}\.[0-9]+\.[0-9]+$ ]] || return 2
      [[ -z ${DOCKER_HOST:-}${DOCKER_CONTEXT:-}${DOCKER_TLS_VERIFY:-}${DOCKER_CERT_PATH:-}${DOCKER_API_VERSION:-} ]] || return 2
      case ${GITHUB_REPOSITORY:-} in
        Strukturpiloten/docker-lens)
          [[ ${GITHUB_WORKFLOW_REF:-} =~ ^Strukturpiloten/docker-lens/\.github/workflows/(check|native-validation|release-validation)\.yml@refs/heads/main$ ]] || return 2 ;;
        Strukturpiloten/boxferry)
          [[ ${GITHUB_WORKFLOW_REF:-} == Strukturpiloten/boxferry/.github/workflows/reviewed-docker-consumer-validation.yml@refs/heads/main ]] || return 2 ;;
      esac
      native_outer_engine=docker ;;
    *) return 2 ;;
  esac
  [[ -z ${CONTAINER_HOST:-}${CONTAINER_CONNECTION:-}${CONTAINER_SSHKEY:-}${PODMAN_CONNECTIONS_CONF:-} ]] || return 2
}

native_outer_select() {
  local engine=${1-podman} directory=$2
  native_outer_policy "$engine" || return 2
  [[ $directory == /* && -d $directory && ! -L $directory ]] || return 2
  native_outer_script_dir=${BASH_SOURCE[0]%/*}
  native_outer_directory=$directory
  native_outer_privilege=()
  if [[ $EUID != 0 ]]; then native_outer_privilege=(sudo -n); fi
  if [[ $engine == docker ]]; then mkdir -m 0700 "$directory/docker-client" || return 2; fi
  native_outer_client "$engine" "$directory"
}

native_outer_client() {
  local engine=$1 directory=$2
  if [[ $engine == podman ]]; then
    native_outer_cmd=("${native_outer_privilege[@]}" podman)
  else
    native_outer_cmd=("${native_outer_privilege[@]}" env
      -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH
      -u DOCKER_API_VERSION -u DOCKER_CONFIG -u DOCKER_DEFAULT_PLATFORM -u DOCKER_CUSTOM_HEADERS
      docker --config "$directory/docker-client" --host unix:///var/run/docker.sock)
  fi
}

native_outer_attach() {
  # No preflight, discovery, creation, privilege escalation or renewable timer.
  # The caller's original privilege-aware timeout owns every attached command.
  local engine=$1 directory=$2
  native_outer_policy "$engine" || return 2
  [[ $directory == /* && -d $directory && ! -L $directory ]] || return 2
  native_outer_script_dir=${BASH_SOURCE[0]%/*}
  native_outer_directory=$directory
  native_outer_privilege=()
  native_outer_helper client-context "$directory" "$engine" || return 2
  native_outer_client "$engine" "$directory"
  if [[ $engine == podman ]]; then native_outer_cmd+=(--remote=false); fi
}

native_outer_command() {
  local seconds=$1
  shift
  [[ $seconds =~ ^[1-9][0-9]{0,2}$ ]] || return 2
  if [[ ${native_outer_cmd[0]} == sudo ]]; then
    "${native_outer_cmd[@]:0:2}" timeout --signal=TERM --kill-after=2s "${seconds}s" "${native_outer_cmd[@]:2}" "$@"
  else
    timeout --signal=TERM --kill-after=2s "${seconds}s" "${native_outer_cmd[@]}" "$@"
  fi
}

native_outer_helper() {
  "${native_outer_privilege[@]}" timeout --signal=TERM --kill-after=2s 8s \
    python3 "$native_outer_script_dir/native-outer-observation.py" "$@"
}

native_outer_bridge_command() {
  local seconds=$1 key
  shift
  [[ $seconds =~ ^[1-9][0-9]{0,2}$ ]] || return 2
  local -a context=()
  for key in GITHUB_ACTIONS RUNNER_ENVIRONMENT RUNNER_OS GITHUB_REF GITHUB_EVENT_NAME \
    GITHUB_REPOSITORY GITHUB_WORKFLOW_REF ImageOS ImageVersion DOCKER_HOST DOCKER_CONTEXT \
    DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION CONTAINER_HOST CONTAINER_CONNECTION \
    CONTAINER_SSHKEY PODMAN_CONNECTIONS_CONF; do context+=("$key=${!key-}"); done
  "${native_outer_privilege[@]}" timeout --signal=TERM --kill-after=2s "${seconds}s" \
    env "${context[@]}" bash "$native_outer_script_dir/native-outer-command.sh" \
      --engine "$native_outer_engine" --directory "$native_outer_directory" "$@"
}

native_outer_preflight() {
  if [[ $native_outer_engine == podman ]]; then
    [[ $(native_outer_command 8 info --format '{{.Host.Security.Rootless}}') == false ]] || return 2
    native_outer_store_root=$(native_outer_command 8 info --format '{{.Store.GraphRoot}}') || return 2
  else
    # The explicit Unix peer must positively be a local root dockerd. CLI info
    # checks alone, remote contexts and absence of name=rootless do not suffice.
    local service
    service=$("${native_outer_privilege[@]}" timeout --signal=TERM --kill-after=2s 8s \
      systemctl show docker.service --property=MainPID --property=ActiveState --property=SubState 2>/dev/null) || return 2
    native_outer_peer_identity=$(native_outer_helper docker-peer /var/run/docker.sock "$service") || return 2
    native_outer_store_root=$(set -o pipefail
      native_outer_command 8 info --format '{{json .}}' 2>/dev/null |
        native_outer_helper docker-info) || return 2
    local versions
    versions=$(native_outer_command 8 version --format '{{.Client.Version}}|{{.Server.Version}}' 2>/dev/null) || return 2
    [[ $versions =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9_.-]+)?\|[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9_.-]+)?$ ]] || return 2
    [[ ${ImageOS:-} == ubuntu24 && ${ImageVersion:-} =~ ^[0-9]{8}\.[0-9]+\.[0-9]+$ ]] || return 2
    printf '%s' "$native_outer_peer_identity" | native_outer_helper runtime-receipt \
      "$native_outer_directory/outer-runtime.json" "${versions%%|*}" "${versions#*|}" "$ImageVersion" "$native_outer_store_root" || return 2
    printf 'DOCKERLENS_NATIVE_OUTER: engine=docker client=%s server=%s rootful=true\n' "${versions%%|*}" "${versions#*|}" >&2
  fi
  [[ $native_outer_store_root == /* && $native_outer_store_root != / &&
     $native_outer_store_root != *$'\n'* && $native_outer_store_root != *$'\r'* ]] || return 2
}

native_outer_presence() {
  local kind=$1 identity=$2 directory=$3 mode=exists marker result=0 template filter
  local -a query
  [[ $kind =~ ^(container|network|volume)$ && $identity =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || return 2
  if [[ $native_outer_engine == podman ]]; then
    query=("$kind" exists "$identity")
  else
    mode=exact-list
    if [[ $kind != volume && $identity =~ ^[0-9a-f]{64}$ ]]; then
      filter="id=$identity"
      template="{{if eq .ID \"$identity\"}}present{{else}}other{{end}}"
    else
      # Network/volume name filters are broad matches, not the container-name
      # regex API. Independent formatter equality admits only the exact name.
      filter="name=$identity"
      if [[ $kind == container ]]; then
        template="{{if eq .Names \"$identity\"}}present{{else}}other{{end}}"
      else
        template="{{if eq .Name \"$identity\"}}present{{else}}other{{end}}"
      fi
    fi
    query=("$kind" ls)
    if [[ $kind == container ]]; then query+=(-a); fi
    if [[ $kind != volume ]]; then query+=(--no-trunc); fi
    query+=(--filter "$filter" --format "$template")
  fi
  # Same privilege and existing finite child/reap contract as canonical cleanup.
  if [[ ${native_outer_cmd[0]} == sudo ]]; then
    marker=$(query_status=0
      sudo -n timeout --signal=TERM --kill-after=2s 8s python3 "$native_outer_script_dir/native-presence.py" \
        "$mode" "$directory" -- "${native_outer_cmd[@]:2}" "${query[@]}" 2>/dev/null || query_status=$?
      printf '\036'; exit "$query_status") || result=$?
  else
    marker=$(query_status=0
      timeout --signal=TERM --kill-after=2s 8s python3 "$native_outer_script_dir/native-presence.py" \
        "$mode" "$directory" -- "${native_outer_cmd[@]}" "${query[@]}" 2>/dev/null || query_status=$?
      printf '\036'; exit "$query_status") || result=$?
  fi
  case "$result:$marker" in
    $'0:present\n\036') return 0 ;;
    $'1:absent\n\036') return 1 ;;
    *) return 2 ;;
  esac
}

native_outer_observe() {
  local kind=$1 identity=$2
  [[ $kind =~ ^(container|network|volume)$ && $identity =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || return 2
  (set -o pipefail
    native_outer_command 8 "$kind" inspect --format '{{json .}}' "$identity" |
      native_outer_helper observe "$kind" "$native_outer_engine")
}

native_outer_snapshot() {
  local identity=$1 snapshot image
  if [[ $native_outer_engine == podman ]]; then
    native_outer_observe container "$identity"
    return
  fi
  snapshot=$(native_outer_observe container "$identity") || return 2
  image=$(printf '%s' "$snapshot" | native_outer_helper snapshot-image "$identity") || return 2
  (set -o pipefail
    native_outer_command 8 image inspect --format '{{json .}}' "$image" |
      native_outer_helper snapshot "$snapshot")
}

native_outer_binding() {
  local kind=$1 identity=$2 name=$3 owner_key=$4 run=$5
  (set -o pipefail
    native_outer_observe "$kind" "$identity" |
      native_outer_helper binding "$kind" "$identity" "$name" "$owner_key" "$run")
}

native_outer_daemon_binding() {
  local identity=$1 name=$2 owner=$3 run=$4 image=$5
  (set -o pipefail
    native_outer_snapshot "$identity" |
      native_outer_helper daemon-binding "$native_outer_engine" "$identity" "$name" "$owner" "$run" "$image")
}

native_outer_remove() {
  local identity=$1 name=$2 owner_key=$3 run=$4 directory=$5 state=0
  native_outer_binding container "$identity" "$name" "$owner_key" "$run" >/dev/null || return 2
  if [[ $native_outer_engine == docker ]]; then
    native_outer_command 8 rm --force "$identity" >/dev/null || return 2
  else
    native_outer_command 8 rm --force --time 0 "$identity" >/dev/null || return 2
  fi
  native_outer_presence container "$identity" "$directory" || state=$?
  (( state == 1 )) || return 2
  state=0
  native_outer_presence container "$name" "$directory" || state=$?
  (( state == 1 )) || return 2
}

native_outer_create_daemon() {
  # A caller-held Bash map, not a serialized receipt/qualification authority.
  # Nothing is recovered from a saved context or discovered by resource name.
  local reference=$1 destination mount status=0 creation
  [[ $reference =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 2
  local -n context=$reference
  [[ ${context[lane]} =~ ^(debian11|upstream)-(rootful|rootless)$ &&
     ${context[guest_dir]} =~ ^/(dockerlens-native|boxferry-core)$ &&
     ${context[name]} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ &&
     ${context[run]} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ &&
     ${context[network]} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ &&
     ${context[volume]} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ &&
     ${context[owner_key]} =~ ^io\.(dockerlens\.native-run|boxferry\.docker-core-run)$ &&
     ${context[image]} =~ ^[A-Za-z0-9][A-Za-z0-9_./:-]+@sha256:[0-9a-f]{64}$ &&
     ${context[socket_dir]} == /* && ${context[log_path]} == /* ]] || return 2
  destination=/var/lib/docker
  if [[ ${context[lane]} == *-rootless ]]; then destination=/home/docker/.local/share/docker; fi
  local -a flags start
  flags=()
  start=(/usr/local/bin/start-dockerd "--host=unix://${context[guest_dir]}/docker.sock")
  if [[ ${context[lane]} == debian11-rootless ]]; then
    flags+=(--oom-score-adj=0 --security-opt apparmor=unconfined)
    start+=(--storage-driver=vfs)
  fi
  mount="${context[volume]}:$destination"
  if [[ $native_outer_engine == podman ]]; then
    mount+=:U
    if [[ ${context[lane]} == debian11-rootless ]]; then mount+=,suid,dev; fi
    flags+=(--image-volume=ignore --log-driver=k8s-file --log-opt "path=${context[log_path]}" --log-opt max-size=1048576)
  else
    flags+=(--cpu-period=100000 --cpu-quota=200000 --log-driver=json-file --log-opt max-size=1m --log-opt max-file=1)
  fi
  if [[ $native_outer_engine == podman ]]; then flags+=(--cpus=2); fi
  local cidfile="$native_outer_directory/outer-create.cid"
  [[ ! -e $cidfile && ! -L $cidfile ]] || return 2
  native_outer_command 120 run --pull=never -d --name "${context[name]}" \
    --cidfile "$cidfile" \
    --label "${context[owner_key]}=${context[run]}" --network "${context[network]}" \
    --privileged --pids-limit=512 --memory=4g "${flags[@]}" \
    --volume "$mount" --volume "${context[socket_dir]}:${context[guest_dir]}" \
    "${context[image]}" "${start[@]}" >/dev/null || status=$?
  # The fixed bridge's ORIGINAL caller-owned 120s deadline includes this read.
  # No appended helper timer or retry may renew that invocation after run ends.
  creation=$(python3 "$native_outer_script_dir/native-outer-observation.py" created-cid "$cidfile") || {
    if (( status != 0 )); then return "$status"; else return 2; fi
  }
  printf '%s\n' "$creation"
  return "$status"
}

native_outer_prepare_data() {
  local image=$1 mode=$2 volume=$3 path=$4 root=$5
  [[ $native_outer_engine == docker ]] || return 0
  (set -o pipefail
    native_outer_command 8 image inspect --format '{{json .Config}}' "$image" |
      native_outer_helper image-config "$mode" >/dev/null) || return 2
  native_outer_helper prepare-data "$path" "$root" "$volume" "$mode"
}

native_outer_check_mounts() {
  local identity=$1 volume=$2 mode=$3 socket_dir=$4 guest=$5 destination=/var/lib/docker
  if [[ $mode == rootless ]]; then destination=/home/docker/.local/share/docker; fi
  (set -o pipefail
    native_outer_observe container "$identity" |
      native_outer_helper mounts "$volume" "$destination" "$socket_dir" "$guest" \
        "$native_outer_store_root/volumes/$volume/_data")
}
