#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$script_dir/native-version.sh"
source "$script_dir/native-outer-runtime.sh"
select_outer_engine() {
  local requested=${DOCKERLENS_OUTER_ENGINE-podman} head dirty
  # The already installed trusted-main PR dispatcher predates the explicit env
  # setting. Its exact admitted native job may qualify this new candidate before
  # a workflow rollout. This is one closed policy choice, not runtime fallback.
  if [[ -z ${DOCKERLENS_OUTER_ENGINE+x} && ${GITHUB_JOB:-} == native-conformance &&
        ${GITHUB_REPOSITORY:-} == Strukturpiloten/docker-lens &&
        ${GITHUB_EVENT_NAME:-} == workflow_dispatch && ${GITHUB_REF:-} == refs/heads/main &&
        ${GITHUB_WORKFLOW_REF:-} == Strukturpiloten/docker-lens/.github/workflows/native-validation.yml@refs/heads/main ]]; then
    native_outer_policy docker || return 2
    [[ ${DOCKERLENS_NATIVE_CANDIDATE_SHA:-} =~ ^[0-9a-f]{40}$ ]] || return 2
    head=$(timeout --signal=TERM --kill-after=2s 8s git -C "$script_dir/.." rev-parse HEAD) || return 2
    dirty=$(timeout --signal=TERM --kill-after=2s 8s git -C "$script_dir/.." status --porcelain --untracked-files=all) || return 2
    [[ $head == "$DOCKERLENS_NATIVE_CANDIDATE_SHA" && -z $dirty ]] || return 2
    requested=docker
    echo 'DOCKERLENS_NATIVE_OUTER: selection=legacy-reviewed-main-dispatcher engine=docker' >&2
  fi
  native_outer_policy "$requested"
}
select_outer_engine || {
  echo 'native outer engine selection refused' >&2
  exit 1
}

# Upstream containers#260 digests retain the reviewed 2026-09-28 baseline.
# renovate: datasource=docker depName=ghcr.io/strukturpiloten/docker-29-rootful
UPSTREAM_ROOTFUL_IMAGE='ghcr.io/strukturpiloten/docker-29-rootful:v29.8.1@sha256:bc71d19fbcd6d84d1452f61e6c3cbac77b6acaba214d7eb830b79124d1a4d563'
# renovate: datasource=docker depName=ghcr.io/strukturpiloten/docker-29-rootless
UPSTREAM_ROOTLESS_IMAGE='ghcr.io/strukturpiloten/docker-29-rootless:v29.8.1@sha256:075f6b6e6f15960ebf3bca6496331ee6b0e32d96b7824cbac382ae5b296f0d7c'
# Debian rebuilds: containers#456, publication 39919296714 (2026-10-23).
# Registry/maintenance binding is not native qualification; see dependency-policy.md.
# renovate: datasource=docker depName=ghcr.io/strukturpiloten/docker-debian-11-rootful
DEBIAN_ROOTFUL_IMAGE='ghcr.io/strukturpiloten/docker-debian-11-rootful:v1.0.0@sha256:47faf9e0f13269b9fdbe6e1b167b62a3c02130b6f8d34d785c6234b2c4d02ed3'
# renovate: datasource=docker depName=ghcr.io/strukturpiloten/docker-debian-11-rootless
DEBIAN_ROOTLESS_IMAGE='ghcr.io/strukturpiloten/docker-debian-11-rootless:v1.0.0@sha256:36a16241b6058d163d1ed90549a8ea0aff9e242be62d414e4e75d81629513e77'
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

select_apparmor_profile() {
  # Fixed reviewed source selector, not an environment-provided policy/path.
  # The installed trusted dispatcher supplies the same exact-head admission.
  apparmor_profile=
  [[ $lane == upstream-rootless ]] || return 0
  case ${GITHUB_WORKFLOW_REF:-} in
    Strukturpiloten/docker-lens/.github/workflows/check.yml@refs/heads/main)
      [[ ${GITHUB_EVENT_NAME:-} == push ]] || return 2 ;;
    Strukturpiloten/docker-lens/.github/workflows/native-validation.yml@refs/heads/main | \
    Strukturpiloten/docker-lens/.github/workflows/release-validation.yml@refs/heads/main)
      [[ ${GITHUB_EVENT_NAME:-} == workflow_dispatch ]] || return 2 ;;
    *) return 0 ;;
  esac
  [[ $native_outer_engine == docker &&
     ${GITHUB_JOB:-} == native-conformance && ${GITHUB_REPOSITORY:-} == Strukturpiloten/docker-lens &&
     ${GITHUB_RUN_ID:-} =~ ^[1-9][0-9]{0,19}$ && ${GITHUB_RUN_ATTEMPT:-} =~ ^[1-9][0-9]{0,19}$ &&
     ${DOCKERLENS_NATIVE_CANDIDATE_SHA:-} =~ ^[0-9a-f]{40}$ ]] || return 2
  native_outer_policy docker || return 2
  local head dirty
  head=$(timeout --signal=TERM --kill-after=2s 8s git -C "$script_dir/.." rev-parse HEAD) || return 2
  dirty=$(timeout --signal=TERM --kill-after=2s 8s git -C "$script_dir/.." status --porcelain --untracked-files=all) || return 2
  [[ $head == "$DOCKERLENS_NATIVE_CANDIDATE_SHA" && -z $dirty ]] || return 2
  apparmor_profile=github_runner_userns_v1
}
select_apparmor_profile || { echo 'native AppArmor prerequisite selection refused' >&2; exit 2; }

for tool in "$native_outer_engine" curl python3 timeout df du mktemp; do
  command -v "$tool" >/dev/null || { echo "missing native test tool: $tool" >&2; exit 1; }
done
if [[ $native_outer_engine == podman ]]; then
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
fi

# The helper reads host bridge prerequisites before creating run-owned resources.
# Only a positively identified hosted main native job may attempt one bounded
# module load; these environment guards prevent accidents, not impersonation.
python3 "$script_dir/native-bridge-prerequisite.py"

# A random directory, two containers, network, and volume belong to this lane.
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/dockerlens-native.XXXXXXXX")
run_id=${run_dir##*.}
export NATIVE_IDENTITY_CANDIDATE_SHA
NATIVE_IDENTITY_CANDIDATE_SHA=$(git -C "$script_dir/.." rev-parse HEAD)
[[ $NATIVE_IDENTITY_CANDIDATE_SHA =~ ^[0-9a-f]{40}$ ]] || { echo 'native identity requires exact candidate SHA' >&2; exit 1; }
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
native_outer_select "$native_outer_engine" "$run_dir" || { echo 'native outer engine setup refused' >&2; exit 1; }
# Retain the historical internal variable for the unchanged inner/proof wiring;
# the canonical selector binds its actual backend and explicit endpoint.
podman_cmd=("${native_outer_cmd[@]}")
if [[ $native_outer_engine == docker ]]; then
  native_outer_preflight || { echo 'native outer Docker preflight refused' >&2; exit 1; }
fi
watchdog_pid=
rootless_startup_us=
rootless_startup_boot_ns=
rootless_kernel_attempted=0
apparmor_nonce=
apparmor_attempted=0
apparmor_native_completed=0
native_success_summary=
preserve_run_dir=0
outer_container_id=
sidecar_container_id=
volume_identity=
outer_attempted=0
sidecar_attempted=0
volume_attempted=0
network_attempted=0
network_created=0
outer_network_id=
# Authority belongs only to the original five-child scope and separate source children below.
unset NATIVE_LIFECYCLE_CLEANUP_OWNER
cleanup_podman() {
  if [[ ${native_outer_engine:-podman} == docker ]]; then
    native_outer_command 8 "$@" 2>/dev/null
    return "$?"
  fi
  # The deadline must share root privileges with the Podman client; an
  # unprivileged timeout cannot reliably terminate children behind sudo.
  if [[ ${podman_cmd[0]} == sudo ]]; then
    "${podman_cmd[@]:0:2}" timeout --signal=TERM --kill-after=2s 8s "${podman_cmd[@]:2}" "$@" 2>/dev/null
  else
    timeout --signal=TERM --kill-after=2s 8s "${podman_cmd[@]}" "$@" 2>/dev/null
  fi
}
cleanup_inspect_query() {
  [[ $# == 2 ]] || return 2
  local kind=$1 name=$2
  case $kind in network-owner-inspect|volume-identity-inspect) ;; *) return 2 ;; esac
  if [[ ${native_outer_engine:-podman} == docker ]]; then
    # The fixed entry hands one sampled deadline to the original 8s+2s owner.
    # It does not launch the query until that owner covers the collector too.
    if [[ ${native_outer_cmd[0]} == sudo ]]; then
      "${native_outer_cmd[@]:0:2}" python3 "$script_dir/native-cleanup-inspect-diagnostic.py" owner \
        --engine docker --directory "$run_dir" --kind "$kind" --name "$name"
    else
      python3 "$script_dir/native-cleanup-inspect-diagnostic.py" owner \
        --engine docker --directory "$run_dir" --kind "$kind" --name "$name"
    fi
  elif [[ $kind == network-owner-inspect ]]; then
    cleanup_podman network inspect --format '{{index .Labels "io.dockerlens.native-run"}}' "$name"
  else
    cleanup_podman volume inspect --format '{{.Name}}|{{.Driver}}|{{.Mountpoint}}|{{.CreatedAt}}|{{index .Labels "io.dockerlens.native-run"}}' "$name"
  fi
}
native_presence() {
  local mode=$1 marker result=0
  shift
  if [[ $mode == exists && ${native_outer_engine:-podman} == docker ]]; then
    local offset=${#podman_cmd[@]} index
    local -a arguments=("$@")
    (( ${#arguments[@]} == offset + 3 )) || { preserve_run_dir=1; return 2; }
    for (( index=0; index<offset; index++ )); do
      [[ ${arguments[index]} == "${podman_cmd[index]}" ]] || { preserve_run_dir=1; return 2; }
    done
    [[ ${arguments[offset+1]} == exists ]] || { preserve_run_dir=1; return 2; }
    native_outer_presence "${arguments[offset]}" "${arguments[offset+2]}" "$run_dir" || result=$?
    if (( result == 2 )); then preserve_run_dir=1; fi
    return "$result"
  fi
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
cleanup_refuse() {
  preserve_run_dir=1
  status=1
  echo "DOCKERLENS_NATIVE_CLEANUP: role=$1 operation=retain category=$2" >&2
  return 1
}
cleanup_identity_stage() {
  local role=$1 stage=$2 result=$3 category
  case "$role:$stage" in
    network:network-binding | network:network-owner-inspect | volume:volume-identity-inspect) ;;
    *) return 1 ;;
  esac
  case $result in
    2) category=refused ;;
    124) category=timeout ;;
    137) category=killed ;;
    130 | 143) category=cancelled ;;
    125 | 126 | 127) category=command_error ;;
    *) category=error ;;
  esac
  echo "DOCKERLENS_NATIVE_CLEANUP_STAGE: role=$role stage=$stage category=$category" >&2
}
cleanup_volume() {
  local current state=0
  (( volume_attempted == 1 )) || return 0
  [[ -n $volume_identity ]] || { cleanup_refuse volume identity_unbound; return 1; }
  native_presence exists "${podman_cmd[@]}" volume exists "$volume" || state=$?
  case $state in
    1) return 0 ;;
    0) ;;
    *) cleanup_refuse volume presence_unknown; return 1 ;;
  esac
  current=$(cleanup_inspect_query volume-identity-inspect "$volume") || {
    cleanup_identity_stage volume volume-identity-inspect "$?"
    cleanup_refuse volume identity_unknown; return 1;
  }
  [[ $current == "$volume_identity" ]] || { cleanup_refuse volume identity_mismatch; return 1; }
  cleanup_remove volume volume rm "$volume" || { cleanup_refuse volume remove_failed; return 1; }
  state=0
  native_presence exists "${podman_cmd[@]}" volume exists "$volume" || state=$?
  (( state == 1 )) || { cleanup_refuse volume readback_unknown; return 1; }
}
cleanup_network() {
  local owner state=0
  (( network_attempted == 1 )) || return 0
  (( network_created == 1 )) || { cleanup_refuse network identity_unbound; return 1; }
  native_presence exists "${podman_cmd[@]}" network exists "$outer_network" || state=$?
  case $state in
    1) return 0 ;;
    0) ;;
    *) cleanup_refuse network presence_unknown; return 1 ;;
  esac
  if [[ ${native_outer_engine:-podman} == docker ]]; then
    native_outer_binding network "$outer_network_id" "$outer_network" io.dockerlens.native-run "$run_id" >/dev/null || {
      cleanup_identity_stage network network-binding "$?"
      cleanup_refuse network identity_unknown; return 1;
    }
  fi
  owner=$(cleanup_inspect_query network-owner-inspect "$outer_network") || {
    cleanup_identity_stage network network-owner-inspect "$?"
    cleanup_refuse network identity_unknown; return 1;
  }
  [[ $owner == "$run_id" ]] || { cleanup_refuse network identity_mismatch; return 1; }
  if [[ ${native_outer_engine:-podman} == docker ]]; then
    cleanup_remove network network rm "$outer_network_id" || { cleanup_refuse network remove_failed; return 1; }
  else
    cleanup_remove network network rm "$outer_network" || { cleanup_refuse network remove_failed; return 1; }
  fi
  state=0
  native_presence exists "${podman_cmd[@]}" network exists "$outer_network" || state=$?
  (( state == 1 )) || { cleanup_refuse network readback_unknown; return 1; }
  if [[ ${native_outer_engine:-podman} == docker ]]; then
    state=0
    native_outer_presence network "$outer_network_id" "$run_dir" || state=$?
    (( state == 1 )) || { cleanup_refuse network readback_unknown; return 1; }
  fi
}
native_publication_command() {
  # Cleanup stops storage sampling before removing its volume. Publication still
  # shares the original absolute lane cutoff; reserve the two-second KILL
  # fallback plus one second for the original SECONDS clock's quantization.
  local remaining=$((1800 - SECONDS - 3)) command_status=0
  (( remaining > 0 )) || return 124
  timeout --signal=TERM --kill-after=2s "${remaining}s" "$@" || command_status=$?
  (( command_status == 0 )) || return "$command_status"
  # A delayed/late zero status can never turn an expired lane into acceptance.
  (( SECONDS < 1800 )) || return 124
}

cleanup() {
  status=$?
  local original_status=$status
  local apparmor_cleanup_record= apparmor_verified=0
  trap - EXIT HUP INT TERM
  if [[ -n $watchdog_pid ]]; then
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
  fi
  containers_verified=1
  cleanup_container "$container" container "$outer_container_id" "$outer_attempted" || containers_verified=0
  cleanup_container "$sidecar" sidecar "$sidecar_container_id" "$sidecar_attempted" || containers_verified=0
  if (( containers_verified == 1 )); then
    cleanup_network || status=1
    cleanup_volume || status=1
  else
    cleanup_refuse network container_unverified || true
    cleanup_refuse volume container_unverified || true
  fi
  if (( ${apparmor_attempted:-0} == 1 )); then
    # Daemon absence is re-authenticated independently of network/volume cleanup.
    # Unknown load/create/absence never permits profile removal or custody loss.
    if apparmor_cleanup_record=$(native_outer_bridge_command 30 apparmor cleanup "$lane" "$apparmor_nonce"); then
      printf '%s\n' "$apparmor_cleanup_record"
      if native_publication_command python3 -B "$script_dir/native-runner-apparmor.py" validate-receipt \
          "${DOCKERLENS_NATIVE_CANDIDATE_SHA:-}" <<<"$apparmor_cleanup_record"; then
        apparmor_verified=1
      elif (( status == 0 )); then
        status=1
      fi
    else
      preserve_run_dir=1
      if (( status == 0 )); then status=1; fi
    fi
  fi
  if [[ -n ${apparmor_profile:-} ]]; then
    if (( original_status != 0 )); then status=$original_status; fi
    if (( ${apparmor_native_completed:-0} != 1 || apparmor_verified != 1 || preserve_run_dir != 0 )); then
      if (( status == 0 )); then status=1; fi
    fi
    # Publish only after the exact native sequence, owned resource cleanup and
    # effective-label/profile-removal receipt have all completed successfully.
    if (( status == 0 )); then
      publish_native_evidence || status=$?
    fi
  fi
  if (( preserve_run_dir != 0 )); then
    echo 'DOCKERLENS_NATIVE_CLEANUP: private presence evidence retained for review' >&2
  elif [[ $run_dir == "${TMPDIR:-/tmp}"/dockerlens-native.* && -d $run_dir ]]; then
    rm -rf -- "$run_dir" || status=1
  fi
  if [[ -n ${apparmor_profile:-} ]]; then
    if (( original_status != 0 )); then status=$original_status; fi
    # A later cleanup step cannot turn an expired lane into ordinary success.
    if (( status == 0 && SECONDS >= 1800 )); then status=124; fi
    if (( status != 0 )); then native_success_summary=; fi
    printf 'DOCKERLENS_NATIVE_APPARMOR_RESULT: outcome=%s native_completed=%s\n' \
      "$([[ $status == 0 ]] && echo verified || echo refused)" "${apparmor_native_completed:-0}" >&2
  fi
  if (( status != 0 )); then
    echo "native lane $lane failed; verify owned resources $container, $sidecar, $outer_network, and $volume" >&2
  elif [[ -n $native_success_summary ]]; then
    echo "$native_success_summary"
  fi
  exit "$status"
}
cleanup_container() {
  local name=$1 role=$2 id=${3:-} attempted=${4:-0} current name_state=0 id_state=0
  (( attempted == 1 )) || return 0
  [[ $id =~ ^[0-9a-f]{64}$ ]] || { cleanup_refuse "$role" identity_unbound; return 1; }
  if [[ ${native_outer_engine:-podman} == docker ]]; then
    native_outer_presence container "$name" "$run_dir" || name_state=$?
    if (( name_state == 1 )); then
      native_outer_presence container "$id" "$run_dir" || id_state=$?
      (( id_state == 1 )) || { cleanup_refuse "$role" readback_unknown; return 1; }
      return 0
    fi
    (( name_state == 0 )) || { cleanup_refuse "$role" presence_unknown; return 1; }
    if [[ $role == container && ${creation_status:-0} != 0 ]]; then
      native_outer_daemon_binding "$id" "$name" io.dockerlens.native-run "$run_id" "$image" >/dev/null || {
        cleanup_refuse "$role" identity_unknown; return 1;
      }
    fi
    native_outer_remove "$id" "$name" io.dockerlens.native-run "$run_id" "$run_dir" || {
      cleanup_refuse "$role" remove_failed; return 1;
    }
    return 0
  fi
  native_presence exists "${podman_cmd[@]}" container exists "$name" || name_state=$?
  case $name_state in
    1)
      native_presence exists "${podman_cmd[@]}" container exists "$id" || id_state=$?
      (( id_state == 1 )) || { cleanup_refuse "$role" readback_unknown; return 1; }
      return 0 ;;
    0) ;;
    *) cleanup_refuse "$role" presence_unknown; return 1 ;;
  esac
  if [[ $role == container && ${creation_status:-0} != 0 ]]; then
    native_outer_daemon_binding "$id" "$name" io.dockerlens.native-run "$run_id" "$image" >/dev/null || {
      cleanup_refuse "$role" identity_unknown; return 1;
    }
  fi
  current=$(cleanup_podman inspect --format '{{.ID}}|{{.Name}}|{{index .Config.Labels "io.dockerlens.native-run"}}' "$id") || {
    cleanup_refuse "$role" identity_unknown; return 1;
  }
  [[ $current == "$id|$name|$run_id" ]] || { cleanup_refuse "$role" identity_mismatch; return 1; }
  # Only this exact creation-bound ID gets immediate stop. Never retry an
  # uncertain mutation or recover identity from a possibly reused name.
  cleanup_remove "$role" rm --force --time 0 "$id" || { cleanup_refuse "$role" remove_failed; return 1; }
  id_state=0; name_state=0
  native_presence exists "${podman_cmd[@]}" container exists "$id" || id_state=$?
  native_presence exists "${podman_cmd[@]}" container exists "$name" || name_state=$?
  if (( id_state != 1 || name_state != 1 )); then
    cleanup_refuse "$role" readback_unknown; return 1
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
echo "native lane $lane owns $native_outer_engine container $container, sidecar $sidecar, network $outer_network, and volume $volume"

rootless_kernel_window_diagnostic() {
  # No journal contact locally, for rootful inner lanes, or before exact startup
  # self-reexec evidence. Reuse canonical hosted admission, never add a fallback.
  [[ ${native_outer_engine:-podman} == docker && ${expected_mode:-} == rootless ]] || return 0
  case ${1:-} in permission_denied | operation_not_permitted | ambiguous) ;; *) return 0 ;; esac
  (( ${rootless_kernel_attempted:-0} == 0 )) || return 0
  rootless_kernel_attempted=1
  local unavailable='DOCKERLENS_NATIVE_ROOTLESS_KERNEL_WINDOW: scope=job_window observation=unavailable operation=unknown errno=absent'
  local remaining=$((1800 - SECONDS)) started ignored started_cs ended ended_cs result diagnostic_status=0
  local key
  local -a privilege=() context=()
  if ! native_outer_policy docker || (( remaining < 5 )) ||
    [[ ! ${rootless_startup_us:-} =~ ^[0-9]{1,20}$ || ! ${rootless_startup_boot_ns:-} =~ ^[0-9]{1,20}$ || -z ${watchdog_pid:-} ]] ||
    ! kill -0 "$watchdog_pid" 2>/dev/null; then
    echo "$unavailable" >&2
    return 0
  fi
  read -r started ignored < /proc/uptime || { echo "$unavailable" >&2; return 0; }
  [[ $started =~ ^[0-9]+\.[0-9]{2}$ ]] || { echo "$unavailable" >&2; return 0; }
  started_cs=${started/./}
  if [[ $EUID != 0 ]]; then privilege=(sudo -n); fi
  for key in GITHUB_ACTIONS RUNNER_ENVIRONMENT RUNNER_OS GITHUB_REF GITHUB_EVENT_NAME \
    GITHUB_REPOSITORY GITHUB_WORKFLOW_REF ImageOS ImageVersion; do context+=("$key=${!key-}"); done
  # Root owns the whole helper's TERM/KILL envelope, including parse/cleanup;
  # an unprivileged timeout around sudo cannot provide this containment.
  result=$("${privilege[@]}" timeout --signal=TERM --kill-after=0.5s 3s \
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C "${context[@]}" \
    python3 "$script_dir/native-rootless-kernel-window.py" \
    "$native_outer_engine" "$expected_mode" "$run_dir" "$rootless_startup_us" "$rootless_startup_boot_ns" \
    "$started_cs" "$remaining" "$watchdog_pid" 2>/dev/null) || diagnostic_status=$?
  # Propagate explicit cancellation through the existing lane traps. Timeout
  # or uncertain privileged completion remains unavailable, not child-death proof.
  case $diagnostic_status in 130) kill -INT "$main_pid"; return 130 ;; 143) kill -TERM "$main_pid"; return 143 ;; esac
  read -r ended ignored < /proc/uptime || { echo "$unavailable" >&2; return 0; }
  [[ $ended =~ ^[0-9]+\.[0-9]{2}$ ]] || { echo "$unavailable" >&2; return 0; }
  ended_cs=${ended/./}
  if (( diagnostic_status != 0 || ended_cs < started_cs || ended_cs - started_cs >= 399 || SECONDS >= 1800 )) ||
    ! kill -0 "$watchdog_pid" 2>/dev/null; then
    echo "$unavailable" >&2
  elif [[ $result =~ ^DOCKERLENS_NATIVE_ROOTLESS_KERNEL_WINDOW:\ scope=job_window\ observation=(observed|unobserved|ambiguous|unavailable)\ operation=(userns_create|exec|other|unknown)\ errno=(permission_denied|operation_not_permitted|other|absent)$ ]]; then
    printf '%s\n' "$result" >&2
  else
    echo "$unavailable" >&2
  fi
  return 0
}

diagnose_native_startup() {
  local state diagnosis inspect_reported_apparmor=${2:-unknown}
  case $inspect_reported_apparmor in unconfined | docker_default | other | empty | unknown) ;; *) inspect_reported_apparmor=unknown ;; esac
  if (( $# > 0 )); then
    state=$1
    [[ $state =~ ^running=(true|false|unknown),status=(running|exited|created|configured|paused|stopped|restarting|dead|removing|unknown),exit=(zero|nonzero|unknown),oom=(true|false|unknown),error=(true|false|unknown)$ ]] || state=unavailable
  else
    state=$(native_outer_command 10 inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}' "$container" 2>/dev/null) || state=unavailable
    [[ $state =~ ^(running|exited|created|configured|paused|stopped)\|[0-9]+\|(true|false)$ ]] || state=unavailable
  fi
  # Retain only the final 64 KiB of the last 80 lines. Logs can contain protected
  # values, so only fixed stage and category names leave this function.
  diagnosis=$(native_outer_command 10 logs --tail 80 "$container" 2>&1 |
    python3 -c 'import re, sys
tail = bytearray()
first_retained_line_complete = True
for chunk in iter(lambda: sys.stdin.buffer.read(65536), b""):
    tail.extend(chunk)
    if len(tail) > 65536:
        cut = len(tail) - 65536
        first_retained_line_complete = tail[cut - 1] == 10
        del tail[:-65536]
stage = "daemon"
family_order = ("rootless_launcher_unavailable", "rootless_uidmap", "rootless_network",
                "daemon_storage", "daemon_permission", "daemon_network", "daemon_startup")
preflight_rules = (
    ("xdg", r"xdg_runtime_dir needs to be set and writable"),
    ("home", r"home needs to be set and exist\."),
    ("rootlesskit", r"rootlesskit needs to be installed"),
    ("state", r"dockerd-rootless\.sh conflicts with containerd-rootless\.sh\. stop containerd-rootless\.sh if it\x27s running, and remove .+ if it still exists\."),
    ("uid", r"this script must be executed as a non-privileged user"),
    ("detach", r"unknown dockerd_rootless_rootlesskit_detach_netns value: .*"),
)
# Only anchored default shell xtrace is excluded. Ordinary mentions of tools,
# drivers or successful setup are not error observations or causal evidence.
families = set()
preflights = set()
self_reexec_errors = set()
decoded = tail.decode("utf-8", "replace")
# The exact source-backed line is independent of family/preflight matching.
# Split only at LF; do not strip CR, controls, prefixes, or case-fold it.
for index, raw in enumerate(decoded.split("\n")):
    if index == 0 and not first_retained_line_complete:
        continue
    if re.match(r"^\++ ", raw):
        continue
    self_reexec = re.fullmatch(
        r"\[rootlesskit:parent\] error: failed to start the child: fork/exec /proc/self/exe: (permission denied|operation not permitted)", raw)
    if self_reexec:
        self_reexec_errors.add(self_reexec.group(1).replace(" ", "_"))
for raw in decoded.splitlines():
    if re.match(r"^\++ ", raw):
        continue
    line = raw.lower()
    matched_preflight = {name for name, pattern in preflight_rules if re.fullmatch(pattern, line)}
    if matched_preflight:
        preflights.update(matched_preflight)
        families.add("rootless_launcher_unavailable" if "rootlesskit" in matched_preflight else "daemon_startup")
        # Dynamic state paths/detach values are not additional error evidence.
        continue
    launcher = re.search(r"\bstart-dockerd: (?:not found|no such file(?: or directory)?)\b", line)
    permission = re.search(r"(?:^|:\s*)(?:permission denied|operation not permitted)[. ]*$", line)
    uidmap_command = re.search(r"\b(?:uid_map|newuidmap|newgidmap):", line)
    uidmap = uidmap_command and any(word in line[uidmap_command.end():]
                                   for word in ("failed", "permission denied", "operation not permitted", "not found", "no such file"))
    explicit = re.search(
        r"(?:^|\s)(?:error|fatal|panic)(?::|\s)|\blevel=\"?(?:error|fatal|panic)\b|"
        r"\bfailed to (?:start|setup|set up|initialize|mount|create|launch|open|write|read|run)\b|"
        r"\berror (?:initializing|creating|starting|mounting)\b", line)
    observed = set()
    if launcher:
        observed.add("rootless_launcher_unavailable")
    if uidmap or (explicit and any(word in line for word in ("uid_map", "newuidmap", "newgidmap"))):
        observed.add("rootless_uidmap")
    if explicit:
        if "slirp4netns" in line or ("rootlesskit" in line and "network" in line):
            observed.add("rootless_network")
        if any(word in line for word in ("graphdriver", "overlay", "storage driver")):
            observed.add("daemon_storage")
        if any(word in line for word in ("iptables", "nat chain", "default bridge", "network controller")):
            observed.add("daemon_network")
    # Permission and generic startup wrappers are fallback observations, not
    # extra independent families when the same line names a specific failure.
    if not observed:
        if permission or (explicit and any(word in line for word in ("operation not permitted", "permission denied"))):
            observed.add("daemon_permission")
        elif "failed to start daemon" in line:
            observed.add("daemon_startup")
    families.update(observed)
category = next(iter(families)) if len(families) == 1 else "ambiguous" if families else "unclassified"
family_projection = ",".join(name for name in family_order if name in families) or "none"
preflight_projection = ",".join(name for name, _ in preflight_rules if name in preflights) or "none"
trace = "unavailable"
self_reexec_projection = (next(iter(self_reexec_errors)) if len(self_reexec_errors) == 1 else
                          "ambiguous" if self_reexec_errors else "unobserved")
print("stage=" + stage + " category=" + category + " families=" + family_projection + " preflight=" + preflight_projection + " trace=" + trace + " rootlesskit_self_reexec=" + self_reexec_projection)' "$lane") || diagnosis='stage=unavailable category=unavailable families=unavailable preflight=unavailable trace=unavailable rootlesskit_self_reexec=unavailable'
  echo "inner daemon startup diagnosis: state=$state $diagnosis inspect_reported_apparmor=$inspect_reported_apparmor" >&2
  rootless_kernel_window_diagnostic "${diagnosis##* rootlesskit_self_reexec=}"
}

if [[ $native_outer_engine == docker ]]; then
  graph_root=$native_outer_store_root
else
  graph_root=$("${podman_cmd[@]}" info --format '{{.Store.GraphRoot}}')
fi
[[ $graph_root == /* ]] || { echo 'outer engine storage root is unavailable' >&2; exit 1; }
if [[ $EUID == 0 ]]; then
  available_kib=$(df -Pk "$graph_root" | awk 'END {print $4}')
else
  available_kib=$(sudo -n df -Pk "$graph_root" | awk 'END {print $4}')
fi
(( available_kib >= 8 * 1024 * 1024 )) || { echo 'native lane needs at least 8 GiB free in outer storage' >&2; exit 1; }
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
volume_attempted=1
"${podman_cmd[@]}" volume create --label "io.dockerlens.native-run=$run_id" "$volume" >/dev/null
volume_identity=$(cleanup_podman volume inspect --format '{{.Name}}|{{.Driver}}|{{.Mountpoint}}|{{.CreatedAt}}|{{index .Labels "io.dockerlens.native-run"}}' "$volume") || { volume_identity=; exit 1; }
IFS='|' read -r volume_bound_name volume_driver volume_path volume_created volume_owner volume_extra <<<"$volume_identity"
if [[ $volume_bound_name != "$volume" || $volume_driver != local || $volume_path != /* ||
      ! $volume_created =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2} || $volume_owner != "$run_id" || -n $volume_extra ||
      $volume_identity == *$'\n'* || $volume_identity == *$'\r'* ]]; then
  volume_identity=
  exit 1
fi
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
validated_outer_ipv4() {
  local role=$1 name=$2 attachment observation inspect_format result=0
  case $role in sidecar | daemon) ;; *) return 1 ;; esac
  inspect_format='{{json .NetworkSettings.Networks}}|{{.State.Running}}|{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}|{{if .State.Error}}true{{else}}false{{end}}'
  if [[ ${native_outer_engine:-podman} == docker && $role == daemon ]]; then
    # Project only fixed tokens in the same inspect. Never print profile names;
    # this is reported metadata, not proof of a live process kernel label.
    inspect_format='inspect_reported_apparmor={{if ne (printf "%T" .AppArmorProfile) "string"}}unknown{{else if eq .AppArmorProfile "unconfined"}}unconfined{{else if eq .AppArmorProfile "docker-default"}}docker_default{{else if eq .AppArmorProfile ""}}empty{{else}}other{{end}}{{"\n"}}'"$inspect_format"
  fi
  attachment=$(native_outer_command 10 inspect \
    --format "$inspect_format" "$name" 2>/dev/null) || {
    echo "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=attachment role=$role category=inspect_failed" >&2
    if [[ $role == daemon ]]; then diagnose_native_startup unavailable; fi
    return 1
  }
  (( ${#attachment} <= 4096 )) || {
    echo "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=attachment role=$role category=output_limit" >&2
    if [[ $role == daemon ]]; then diagnose_native_startup unavailable; fi
    return 1
  }
  observation=$(printf '%s' "$attachment" | python3 -c '
import ipaddress, json, sys
sys.path.insert(0, sys.argv[5])
import native_network_topology as topology

raw = sys.stdin.read()
profile = "unknown"
if sys.argv[3] == "docker" and sys.argv[2] == "daemon":
    header, separator, remainder = raw.partition("\n")
    if separator and header.startswith("inspect_reported_apparmor="):
        raw = remainder
        candidate = header.removeprefix("inspect_reported_apparmor=")
        if candidate in ("unconfined", "docker_default", "other", "empty", "unknown"):
            profile = candidate
fields = raw.rsplit("|", 5)
state = "unavailable"
if len(fields) == 6:
    raw, running, status, exit_code, oom, error = fields
    boolean = lambda value: value if value in ("true", "false") else "unknown"
    status = status if status in ("running", "exited", "created", "configured", "paused", "stopped", "restarting", "dead", "removing") else "unknown"
    exit_class = ("zero" if int(exit_code) == 0 else "nonzero") if exit_code.isascii() and exit_code.isdecimal() and len(exit_code) <= 10 else "unknown"
    state = "running=" + boolean(running) + ",status=" + status + ",exit=" + exit_class + ",oom=" + boolean(oom) + ",error=" + boolean(error)

def fail(category):
    print("DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=attachment role=" + sys.argv[2] +
          " category=" + category, file=sys.stderr)
    print(state)
    print(profile)
    raise SystemExit(1)

try:
    networks = topology.document(raw.encode())
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
try:
    projected = topology.document(sys.argv[4].encode())
    topology.attachment(networks, projected, sys.argv[6], sys.argv[7], sys.argv[3])
except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
    fail("network_pool")
print(address)
' "$outer_network" "$role" "${native_outer_engine:-podman}" "$outer_network_projection" "$script_dir" "$run_id" "$NATIVE_IDENTITY_CANDIDATE_SHA") || result=$?
  if (( result != 0 )); then
    # Failure-only: reuse the held closed State; only the existing logs query
    # is added (10s + 2s kill fallback), inside the lane 30m watchdog.
    if [[ $role == daemon ]]; then diagnose_native_startup "${observation%%$'\n'*}" "${observation#*$'\n'}"; fi
    return "$result"
  fi
  printf '%s\n' "$observation"
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

if [[ -n ${apparmor_profile:-} ]]; then
  apparmor_nonce=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
  apparmor_attempted=1
  native_outer_bridge_command 30 apparmor prepare "$lane" "$apparmor_nonce" "$container" "$run_id" "$image" || exit $?
fi
# Pull only the reviewed digest under the lane's time and free-space budget.
# Prevent `run` from doing a second unbounded implicit pull.
native_outer_command 180 pull "$image" >/dev/null
native_outer_command 180 pull "$FIXTURE_IMAGE" >/dev/null 2>&1 || sidecar_setup_failed image_pull
if [[ $native_outer_engine == docker ]]; then
  # One aggregate host observation precedes mutation intent. This maintained
  # reservation is not a promise about all plugins or future host routes.
  host_network_preflight=$(native_outer_helper network-preflight "$run_id" "$NATIVE_IDENTITY_CANDIDATE_SHA") ||
    sidecar_setup_failed host_network_preflight
  printf '%s' "$host_network_preflight" | python3 "$script_dir/native_network_topology.py" \
    publish-host "$run_id" "$NATIVE_IDENTITY_CANDIDATE_SHA" docker "$run_dir" || sidecar_setup_failed host_network_preflight
  unset host_network_preflight
fi
network_attempted=1
if [[ $native_outer_engine == docker ]]; then
  outer_network_id=$(native_outer_command 30 network create --driver bridge --ipam-driver default --subnet 10.253.253.0/24 \
    --label "io.dockerlens.native-run=$run_id" "$outer_network" 2>/dev/null) || sidecar_setup_failed network_create
  [[ $outer_network_id =~ ^[0-9a-f]{64}$ ]] || sidecar_setup_failed network_identity
else
  timeout --signal=TERM --kill-after=2s 30s "${podman_cmd[@]}" network create --driver bridge \
    --label "io.dockerlens.native-run=$run_id" "$outer_network" >/dev/null 2>&1 || sidecar_setup_failed network_create
fi
network_created=1
# Reuse one full inspection for identity and complete native pool projection.
# Docker is bound to its create-reply ID; Podman retains successful name-create
# plus exact run-label binding, never recovery after uncertain creation.
network_identity=$outer_network_id
if [[ $native_outer_engine == podman ]]; then network_identity=$outer_network; fi
outer_network_snapshot=$(native_outer_observe network "$network_identity") || sidecar_setup_failed network_identity
if [[ $native_outer_engine == docker ]]; then
  printf '%s' "$outer_network_snapshot" | native_outer_helper binding network "$outer_network_id" "$outer_network" io.dockerlens.native-run "$run_id" >/dev/null ||
    sidecar_setup_failed network_identity
fi
projection_identity=$outer_network_id
if [[ $native_outer_engine == podman ]]; then projection_identity=successful-name-create; fi
outer_network_projection=$(printf '%s' "$outer_network_snapshot" | python3 "$script_dir/native_network_topology.py" \
  network "$run_id" "$NATIVE_IDENTITY_CANDIDATE_SHA" "$native_outer_engine" "$projection_identity") || sidecar_setup_failed network_pool
unset outer_network_snapshot network_identity projection_identity
# Preserve only the creation reply privately; never recover a bound ID from a
# reused name after a failed/uncertain run. No ambient enumeration or retry.
(umask 077; set -o noclobber; : > "$run_dir/sidecar-create.id") || sidecar_setup_failed sidecar_identity
sidecar_attempted=1
sidecar_log_flags=()
if [[ $native_outer_engine == docker ]]; then
  sidecar_log_flags=(--log-driver=json-file --log-opt max-size=1m --log-opt max-file=1)
fi
sidecar_start_category=$(native_outer_command 120 run --pull=never -d --name "$sidecar" \
  --label "io.dockerlens.native-run=$run_id" --network "$outer_network" \
  --user=65534:65534 --cap-drop=all --security-opt no-new-privileges --pids-limit=64 --memory=128m "${sidecar_log_flags[@]}" \
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
   fi' 2>&1 >"$run_dir/sidecar-create.id" |
  classify_sidecar_error) || {
  case $sidecar_start_category in
    applet_missing | shell_error | config_error | bind_error | permission | storage | runtime_error | unknown) ;;
    *) sidecar_start_category=unknown ;;
  esac
  echo "DOCKERLENS_NATIVE_SIDECAR_SETUP: phase=sidecar_failure category=$sidecar_start_category" >&2
  sidecar_setup_failed sidecar_start
}
sidecar_creation_id=$(head -c 66 "$run_dir/sidecar-create.id")
[[ $sidecar_creation_id =~ ^[0-9a-f]{64}$ && $(wc -c < "$run_dir/sidecar-create.id") == 65 ]] || sidecar_setup_failed sidecar_identity
sidecar_container_id=$sidecar_creation_id
if [[ $native_outer_engine == docker ]]; then
  sidecar_binding=$(native_outer_binding container "$sidecar_container_id" "$sidecar" io.dockerlens.native-run "$run_id") || sidecar_setup_failed sidecar_identity
else
  sidecar_binding=$(cleanup_podman inspect --format '{{.ID}}|{{.Name}}|{{index .Config.Labels "io.dockerlens.native-run"}}' "$sidecar_container_id") || sidecar_setup_failed sidecar_identity
fi
[[ $sidecar_binding == "$sidecar_container_id|$sidecar|$run_id" ]] || sidecar_setup_failed sidecar_identity
python3 "$script_dir/native-port-start-diagnostic.py" prepare "$run_dir" "$run_id" "$lane" || {
  echo 'DOCKERLENS_NATIVE_PORT_START_LOG_DIAG: source=none category=unavailable collector=unavailable' >&2
  exit 1
}
# Hold the original caller-owned file; registration checks this descriptor
# against the exclusive no-follow creation before reading any native bytes.
exec {port_start_log_fd}< "$run_dir/diagnostics/daemon.log"
# Docker has no :U or image-volume suppression. Prepare only the exact empty
# creation-bound named volume and verify the pinned image's complete VOLUME set.
if [[ $native_outer_engine == docker ]]; then
  [[ $(cleanup_podman volume inspect --format '{{.Name}}|{{.Driver}}|{{.Mountpoint}}|{{.CreatedAt}}|{{index .Labels "io.dockerlens.native-run"}}' "$volume") == "$volume_identity" ]] ||
    sidecar_setup_failed volume_identity
  native_outer_prepare_data "$image" "$expected_mode" "$volume" "$volume_path" "$graph_root" ||
    sidecar_setup_failed volume_ownership
fi
apparmor_create_args=()
if [[ -n ${apparmor_profile:-} ]]; then
  native_outer_bridge_command 30 apparmor load "$lane" "$apparmor_nonce" || exit $?
  apparmor_create_args=("$apparmor_nonce")
fi
outer_attempted=1
creation_status=0
# Hold once immediately before actual create/start; failure cannot move this
# boundary forward. No journal query or optional tool preflight occurs here.
if [[ $native_outer_engine == docker && $expected_mode == rootless ]]; then
  rootless_startup_pair=$(python3 "$script_dir/native-rootless-kernel-window.py" startup-clock 2>/dev/null) || rootless_startup_pair=
  if [[ $rootless_startup_pair =~ ^([0-9]{1,20})\ ([0-9]{1,20})$ ]]; then
    rootless_startup_us=${BASH_REMATCH[1]}
    rootless_startup_boot_ns=${BASH_REMATCH[2]}
  fi
  unset rootless_startup_pair
fi
outer_container_id=$(native_outer_bridge_command 120 create-daemon "$container" "$run_id" \
  io.dockerlens.native-run "$outer_network" "$volume" "$socket_dir" /dockerlens-native \
  "$lane" "$image" "$run_dir/diagnostics/daemon.log" "${apparmor_create_args[@]}" 2>/dev/null) || creation_status=$?
if [[ -n ${apparmor_profile:-} && $creation_status =~ ^(130|143)$ ]]; then exit "$creation_status"; fi
(( creation_status == 0 )) || sidecar_setup_failed daemon_attach
[[ $outer_container_id =~ ^[0-9a-f]{64}$ ]] || sidecar_setup_failed daemon_identity
if [[ $native_outer_engine == docker ]]; then
  outer_binding=$(native_outer_binding container "$outer_container_id" "$container" io.dockerlens.native-run "$run_id") || sidecar_setup_failed daemon_identity
else
  outer_binding=$(cleanup_podman inspect --format '{{.ID}}|{{.Name}}|{{index .Config.Labels "io.dockerlens.native-run"}}' "$outer_container_id") || sidecar_setup_failed daemon_identity
fi
[[ $outer_binding == "$outer_container_id|$container|$run_id" ]] || sidecar_setup_failed daemon_identity
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
printf '%s' "$outer_network_projection" | python3 "$script_dir/native_network_topology.py" \
  finalize "$run_id" "$NATIVE_IDENTITY_CANDIDATE_SHA" "$native_outer_engine" "$outer_container_id" "$sidecar_container_id" "$daemon_ip" "$sidecar_ip" |
  python3 "$script_dir/native_network_topology.py" publish "$run_id" "$NATIVE_IDENTITY_CANDIDATE_SHA" "$native_outer_engine" "$run_dir" || sidecar_setup_failed network_pool
unset outer_network_projection
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
if [[ $native_outer_engine == podman ]]; then
  printf '%s' "$outer_setup" | python3 "$script_dir/native-port-start-diagnostic.py" register \
    "$run_dir" "$run_id" "$lane" "$image" "$outer_container_id" "$port_start_log_fd" || true
fi
unset outer_setup
volume_mounts=$("${podman_cmd[@]}" inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}}{{"\n"}}{{end}}{{end}}' "$container")
expected_mount="$volume:$(if [[ $expected_mode == rootless ]]; then printf /home/docker/.local/share/docker; else printf /var/lib/docker; fi)"
[[ $volume_mounts == "$expected_mount" ]] || {
  echo 'outer container has unexpected image or data-root volumes' >&2
  exit 1
}
if [[ $native_outer_engine == docker ]]; then
  native_outer_check_mounts "$outer_container_id" "$volume" "$expected_mode" "$socket_dir" /dockerlens-native || {
    echo 'outer container has unexpected image or data-root volumes' >&2
    exit 1
  }
  native_outer_helper check-data "$volume_path" "$graph_root" "$volume" "$expected_mode" || sidecar_setup_failed volume_ownership
fi

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
if [[ -n ${apparmor_profile:-} ]]; then
  apparmor_label_status=0
  native_outer_bridge_command 30 apparmor verify "$lane" "$apparmor_nonce" || apparmor_label_status=$?
  if (( apparmor_label_status != 0 )); then
    preserve_run_dir=1
    exit "$apparmor_label_status"
  fi
fi

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
python3 - "$run_dir/info.json" "$expected_mode" "$lane" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    info = json.load(stream)
rootless = info.get('Rootless') is True or 'name=rootless' in info.get('SecurityOptions', [])
if rootless != (sys.argv[2] == 'rootless'):
    raise SystemExit('inner daemon mode differs from native lane')
if sys.argv[3] == 'debian11-rootless' and info.get('Driver') != 'vfs':
    raise SystemExit('Debian rootless daemon storage driver differs from native lane')
PY

inner_docker=("${podman_cmd[@]}" exec "$container" docker -H unix:///dockerlens-native/docker.sock)
export NATIVE_BIND_RELABEL_DAEMON_UID
NATIVE_BIND_RELABEL_DAEMON_UID=$(python3 "$script_dir/native-daemon-uid.py" "$outer_container_id" "$expected_mode" \
  "$native_outer_engine" "$run_dir")
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
export NATIVE_OUTER_CONTAINER_ID="$outer_container_id" NATIVE_OUTER_IMAGE="$image"
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
export NATIVE_NETWORK_ATTACHMENT_PROOF_PATH="$run_dir/network-attachments-v1.json"
export NATIVE_BIND_RELABEL_PROOF_PATH="$run_dir/bind-relabel-config-v1.json"
export NATIVE_EXTERNAL_NETWORK_PROOF_PATH="$run_dir/external-network-internal-v1.json"
export NATIVE_STOP_SIGNAL_PROOF_PATH="$run_dir/stop-signal-v1.json"
export NATIVE_LIFECYCLE_PROOF_PATH="$run_dir/lifecycle-v1.json"
export NATIVE_RUNTIME_FILESYSTEM_PROOF_PATH="$run_dir/runtime-filesystem-v1.json"
export NATIVE_TMPFS_EFFECT_PROOF_PATH="$run_dir/tmpfs-effect-v1.json"
export NATIVE_HEALTH_START_INTERVAL_BOUNDARY_PROOF_PATH="$run_dir/health-start-interval-boundary-v1.json"
export NATIVE_LIFECYCLE_DEFAULT_EFFECT_PROOF_PATH="$run_dir/lifecycle-default-effects-v1.json"
export NATIVE_HOSTNAME_PROOF_PATH="$run_dir/hostname-v1.json"
export NATIVE_COMMAND_CLEAR_PROOF_PATH="$run_dir/command-clear-v1.json"
export NATIVE_SHM_SIZE_PROOF_PATH="$run_dir/shm-size-v1.json"
export NATIVE_SHM_SIZE_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_SUPPLEMENTARY_GROUPS_PROOF_PATH="$run_dir/supplementary-groups-v1.json"
export NATIVE_SUPPLEMENTARY_GROUPS_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_KERNEL_SETTINGS_PROOF_PATH="$run_dir/kernel-settings-v1.json"
export NATIVE_KERNEL_SETTINGS_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_PORT_START_DIAGNOSTIC_PATH="$run_dir/diagnostics/port-start-window.json"
export NATIVE_PORT_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_HEALTH_METADATA_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_NETWORK_ATTACHMENT_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_BIND_RELABEL_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_EXTERNAL_NETWORK_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_STOP_SIGNAL_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_LIFECYCLE_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_RUNTIME_FILESYSTEM_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_TMPFS_EFFECT_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_HEALTH_START_INTERVAL_BOUNDARY_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_LIFECYCLE_DEFAULT_EFFECT_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_HOSTNAME_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
export NATIVE_COMMAND_CLEAR_CANDIDATE_SHA=$NATIVE_IDENTITY_CANDIDATE_SHA
if [[ $EUID == 0 ]]; then export NATIVE_PODMAN_USE_SUDO=0; else export NATIVE_PODMAN_USE_SUDO=1; fi
export NATIVE_OUTER_ENGINE="$native_outer_engine" NATIVE_OUTER_RUN_DIRECTORY="$run_dir"

outer_guest_http_failure_diagnostic() {
  [[ ${native_outer_engine:-} == docker && ${expected_mode:-} == rootless ]] || return 0
  local unavailable='DOCKERLENS_NATIVE_OUTER_GUEST_HTTP: status=unavailable
DOCKERLENS_NATIVE_OUTER_GUEST_CURL: tool=unavailable callable=unavailable curl_exit=unavailable'
  local remaining=$((1800 - SECONDS)) started ended ignored started_cs ended_cs result diagnostic_status=0
  # Admit the seven-second timer envelope plus two seconds of lane margin.
  # Pre-timer sudo startup remains the existing privilege boundary, not a new
  # wall-clock guarantee. This is NOT a protected cleanup reserve or renewal.
  if (( remaining < 9 )) || [[ -z ${watchdog_pid:-} ]] || ! kill -0 "$watchdog_pid" 2>/dev/null ||
    [[ ! ${outer_container_id:-} =~ ^[0-9a-f]{64}$ ||
       ! ${sidecar_ip:-} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "$unavailable" >&2
    return 0
  fi
  read -r started ignored < /proc/uptime || { echo "$unavailable" >&2; return 0; }
  [[ $started =~ ^[0-9]+\.[0-9]{2}$ ]] || { echo "$unavailable" >&2; return 0; }
  started_cs=${started/./}
  result=$(
    set +e
    # The already-selected DIRECT client has no attach/custody helper. Its
    # existing privilege-aware owner bounds TERM-resistant clients at 3+2s.
    # One fixed guest shell checks availability and frames the same GET. Curl
    # streams directly into the existing bounded reader; no extra capture,
    # request, timer, session, or command supplied by the guest is admitted.
    # The same reader owner also projects only three captured pre-test reports.
    native_outer_command 3 exec "$outer_container_id" /bin/sh -c '
LC_ALL=C LANG=C
export LC_ALL LANG
if [ ! -e /usr/bin/curl ]; then
  printf "DLHTTP1|absent||-\n"
elif [ ! -x /usr/bin/curl ]; then
  printf "DLHTTP1|not_executable||-\n"
else
  printf "DLHTTP1|executable|"
  /usr/bin/curl --disable -sS --noproxy "*" --retry 0 --proto "=http" \
    --max-time 2 --request GET --output /dev/null --write-out "%{http_code}" "$1"
  curl_status=$?
  case $curl_status in 130 | 143) exit "$curl_status" ;; esac
  printf "|%s\n" "$curl_status"
fi
' dockerlens-guest-http "http://$sidecar_ip:18084/" 2>/dev/null |
      timeout --signal=TERM --kill-after=1s 6s python3 -I -S -c '
import json
import math
import os
import re
import stat
import sys
raw = b""
while len(raw) < 65:
    part = os.read(0, 65 - len(raw))
    if not part:
        break
    raw += part
match = re.fullmatch(rb"DLHTTP1\|(absent|not_executable|executable)\|(000|[1-5][0-9]{2})?\|(-|0|[1-9][0-9]{0,2})\n", raw)
if not match:
    raise SystemExit(1)
tool, http, code = match.groups()
status, callable_status, category = "unavailable", "no", "not_called"
if tool != b"executable":
    if http is not None or code != b"-":
        raise SystemExit(1)
else:
    if code == b"-" or int(code) > 127:
        raise SystemExit(1)
    code = int(code)
    if code in (126, 127):
        if http is not None:
            raise SystemExit(1)
        category = "unavailable"
    else:
        callable_status = "yes"
        category = {0: "success", 5: "resolve_proxy", 6: "resolve_host", 7: "connect_failed",
                    28: "timeout", 52: "empty_reply", 55: "send_failed", 56: "receive_failed"}.get(code, "other")
        if code == 0:
            if http is None or http[:1] not in b"12345":
                raise SystemExit(1)
            status = "http_200" if http == b"200" else "http_other"
def unavailable_info():
    return ("unavailable",) * 3


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def reject(*_args):
    raise ValueError


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def info_reports(directory):
    descriptors = []
    try:
        if not directory or not os.path.isabs(directory) or os.path.normpath(directory) != directory:
            raise ValueError
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(parent)
        before_parent = os.fstat(parent)
        if stat.S_IMODE(before_parent.st_mode) != 0o700 or before_parent.st_uid != os.geteuid():
            raise ValueError
        source = os.open("info.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        descriptors.append(source)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid()
                or before.st_mode & 0o022 or not 0 < before.st_size <= 65536):
            raise ValueError
        captured = b""
        while len(captured) < 65537:
            part = os.read(source, 65537 - len(captured))
            if not part:
                break
            captured += part
        if (len(captured) != before.st_size
                or identity(before) != identity(os.fstat(source))
                or identity(before) != identity(os.stat("info.json", dir_fd=parent, follow_symlinks=False))
                or identity(before_parent) != identity(os.fstat(parent))
                or identity(before_parent) != identity(os.stat(directory, follow_symlinks=False))):
            raise ValueError
        value = json.loads(captured.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject)
        if type(value) is not dict:
            raise ValueError
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 32 or (type(item) is float and not math.isfinite(item)):
                raise ValueError
            if type(item) is dict:
                pending.extend((child, depth + 1) for child in item.values())
            elif type(item) is list:
                pending.extend((child, depth + 1) for child in item)
        fields = [value.get(key) for key in ("IPv4Forwarding", "BridgeNfIptables", "BridgeNfIp6tables")]
        if any(item is not None and type(item) is not bool for item in fields):
            raise ValueError
        return tuple("unavailable" if item is None else "true" if item else "false" for item in fields)
    except (OSError, ValueError, UnicodeError, RecursionError):
        return unavailable_info()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


reports = "|".join(info_reports(sys.argv[1]))
print(f"{status} tool={tool.decode()} callable={callable_status} curl_exit={category} DLINFO1|{reports}")
' "${run_dir:-}" 2>/dev/null
    command_statuses=("${PIPESTATUS[@]}")
    for command_status in "${command_statuses[@]}"; do
      case $command_status in 130 | 143) exit "$command_status" ;; esac
    done
    (( command_statuses[0] == 0 && command_statuses[1] == 0 ))
  ) 2>/dev/null || diagnostic_status=$?
  # This function runs in the coordinator's main shell after the pipeline has
  # completed. Exit through its existing EXIT cleanup owner, even when an
  # asynchronous caller inherited ignored SIGINT; never resume via || true.
  case $diagnostic_status in 130 | 143) exit "$diagnostic_status" ;; esac
  read -r ended ignored < /proc/uptime || { echo "$unavailable" >&2; return 0; }
  [[ $ended =~ ^[0-9]+\.[0-9]{2}$ ]] || { echo "$unavailable" >&2; return 0; }
  ended_cs=${ended/./}
  if (( diagnostic_status != 0 || ended_cs < started_cs || ended_cs - started_cs >= 799 || SECONDS >= 1800 )) ||
      ! kill -0 "$watchdog_pid" 2>/dev/null; then
    echo "$unavailable" >&2
  elif [[ $result =~ ^((http_200|http_other|unavailable)\ tool=(absent|not_executable|executable)\ callable=(yes|no)\ curl_exit=(not_called|unavailable|success|resolve_proxy|resolve_host|connect_failed|timeout|empty_reply|send_failed|receive_failed|other))\ DLINFO1\|(true|false|unavailable)\|(true|false|unavailable)\|(true|false|unavailable)$ ]]; then
    printf 'DOCKERLENS_NATIVE_OUTER_GUEST_HTTP: status=%s\nDOCKERLENS_NATIVE_OUTER_GUEST_CURL: %s\n' \
      "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]#* }" >&2
    local ipv4_report=${BASH_REMATCH[6]} iptables_report=${BASH_REMATCH[7]} ip6tables_report=${BASH_REMATCH[8]}
    [[ $ipv4_report == unavailable ]] || ipv4_report="reported_$ipv4_report"
    [[ $iptables_report == unavailable ]] || iptables_report="reported_$iptables_report"
    [[ $ip6tables_report == unavailable ]] || ip6tables_report="reported_$ip6tables_report"
    printf 'DOCKERLENS_NATIVE_PRE_TEST_NETWORK_REPORT: source=captured_inner_engine_info IPv4Forwarding=%s BridgeNfIptables=%s BridgeNfIp6tables=%s\n' \
      "$ipv4_report" "$iptables_report" "$ip6tables_report" >&2
  else
    echo "$unavailable" >&2
  fi
  return 0
}

port_start_failure_diagnostic() {
  if [[ ${native_outer_engine:-podman} == docker ]]; then
    # Docker's bounded json-file logger cannot register the existing k8s-file
    # descriptor collector. This optional observation is explicitly unavailable;
    # no follower, path substitution, or completed-log claim is introduced.
    echo 'DOCKERLENS_NATIVE_PORT_START_LOG_DIAG: source=none category=unavailable collector=unavailable' >&2
    return 0
  fi
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
internal_network_status=0
{
"$(dirname "$0")/run-exact-native-test.sh" native_network live_internal_network_blocks_external_egress
} || internal_network_status=$?
if (( internal_network_status != 0 )); then
  case $internal_network_status in 130 | 143) exit "$internal_network_status" ;; esac
  outer_guest_http_failure_diagnostic || true
  exit "$internal_network_status"
fi
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
"$(dirname "$0")/run-exact-native-test.sh" native_network_attachment live_network_attachments_match_engine
"$(dirname "$0")/run-exact-native-test.sh" native_bind_relabel live_bind_relabel_configuration_matches_engine
"$(dirname "$0")/run-exact-native-test.sh" native_external_network live_external_network_internal_matches_engine
"$(dirname "$0")/run-exact-native-test.sh" native_stop_signal live_stop_signal_matches_engine
(
  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1
"$(dirname "$0")/run-exact-native-test.sh" native_lifecycle live_lifecycle_matches_engine
"$(dirname "$0")/run-exact-native-test.sh" native_runtime_filesystem live_runtime_filesystem_matches_engine
"$(dirname "$0")/run-exact-native-test.sh" native_tmpfs_effect live_tmpfs_effects_match_engine
"$(dirname "$0")/run-exact-native-test.sh" native_health_start_interval_boundary live_health_start_interval_boundary_matches_engine
"$(dirname "$0")/run-exact-native-test.sh" native_lifecycle_default_effect live_lifecycle_default_effects_match_engine
)

(
  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1
"$(dirname "$0")/run-exact-native-test.sh" native_hostname live_hostname_matches_engine
)
# Validate this fixed private proof even when public evidence is not requested.
# All expected facts are independently supplied by the canonical harness.
python3 "$script_dir/native_hostname_proof.py" "$run_dir" "$NATIVE_HOSTNAME_CANDIDATE_SHA" "$run_id" \
  "$lane" "$server_version" "$api_version" "$expected_mode" "$installed_docker_package" \
  "$NATIVE_FIXTURE_IMAGE" "$image" "$NATIVE_OUTER_CONTAINER_ID" "$NATIVE_BIND_RELABEL_DAEMON_UID"

"$(dirname "$0")/run-exact-native-test.sh" native_command_clear live_command_clear_matches_engine
# Mandatory private validation also applies when no public evidence is requested.
python3 - "$script_dir" "$run_dir" "$NATIVE_COMMAND_CLEAR_CANDIDATE_SHA" "$run_id" \
  "$lane" "$server_version" "$api_version" "$expected_mode" "$installed_docker_package" \
  "$NATIVE_FIXTURE_IMAGE" "$image" "$NATIVE_OUTER_CONTAINER_ID" "$NATIVE_BIND_RELABEL_DAEMON_UID" <<'COMMAND_CLEAR_PROOF'
import re
import sys
from pathlib import Path

try:
    sys.path.insert(0, sys.argv[1])
    from native_command_clear_proof import read_command_clear_proof

    (directory, candidate, run, lane, engine, api, mode, package,
     fixture, outer_image, outer_id, uid) = sys.argv[2:]
    if re.fullmatch(r"0|[1-9][0-9]{0,9}", uid) is None:
        raise ValueError()
    context = {
        "candidate_sha": candidate, "run_id": run, "lane": lane,
        "engine_release": engine, "rendering_api": api,
        "acquisition_api": "1.41" if lane.startswith("debian11-") else "1.49",
        "mode": mode, "docker_package": package, "fixture_image": fixture,
        "daemon_uid": int(uid), "outer": {
            "id": outer_id, "name": f"dl-native-{run}", "owner": run,
            "image": outer_image, "data_volume": f"dl-native-data-{run}",
            "socket_source": str(Path(directory) / "socket"), "privileged": True,
            "memory_bytes": 4294967296, "cpu_quota": 200000,
            "cpu_period": 100000, "pids_limit": 512,
        },
    }
    if read_command_clear_proof(Path(directory) / "command-clear-v1.json", Path(directory), context) != ("ClearCommand", "ClearEntrypoint"):
        raise ValueError()
except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, AttributeError, ImportError):
    raise SystemExit("native command-clear proof rejected") from None
COMMAND_CLEAR_PROOF

(
  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1
"$(dirname "$0")/run-exact-native-test.sh" native_shm_size live_shm_size_effects_match_engine
)
# Always require the fixed private child against independent canonical facts.
python3 "$script_dir/native_shm_size_proof.py" "$run_dir" "$NATIVE_SHM_SIZE_CANDIDATE_SHA" "$run_id" \
  "$lane" "$server_version" "$api_version" "$expected_mode" "$installed_docker_package" \
  "$NATIVE_FIXTURE_IMAGE" "$image" "$NATIVE_OUTER_CONTAINER_ID" "$NATIVE_BIND_RELABEL_DAEMON_UID"

(
  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1
"$(dirname "$0")/run-exact-native-test.sh" native_supplementary_groups live_supplementary_groups_match_engine
)
# Always require the fixed private child against independent canonical facts.
python3 "$script_dir/native_supplementary_groups_proof.py" "$run_dir" "$NATIVE_SUPPLEMENTARY_GROUPS_CANDIDATE_SHA" "$run_id" \
  "$lane" "$server_version" "$api_version" "$expected_mode" "$installed_docker_package" \
  "$NATIVE_FIXTURE_IMAGE" "$image" "$NATIVE_OUTER_CONTAINER_ID" "$NATIVE_BIND_RELABEL_DAEMON_UID"

(
  export NATIVE_LIFECYCLE_CLEANUP_OWNER=native_conformance_outer_v1
"$(dirname "$0")/run-exact-native-test.sh" native_kernel_settings live_kernel_settings_match_engine
)
# Always require the fixed private child against independent canonical facts.
python3 "$script_dir/native_kernel_settings_proof.py" "$run_dir" "$NATIVE_KERNEL_SETTINGS_CANDIDATE_SHA" "$run_id" \
  "$lane" "$server_version" "$api_version" "$expected_mode" "$installed_docker_package" \
  "$NATIVE_FIXTURE_IMAGE" "$image" "$NATIVE_OUTER_CONTAINER_ID" "$NATIVE_BIND_RELABEL_DAEMON_UID"

publish_native_evidence() {
  local candidate_sha dirty
  if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]; then
    candidate_sha=$(native_publication_command git -C "$script_dir/.." rev-parse HEAD) || return $?
    [[ $candidate_sha =~ ^[0-9a-f]{40}$ && ${DOCKERLENS_NATIVE_CANDIDATE_SHA:-} == "$candidate_sha" ]] || {
      echo 'native evidence candidate SHA does not match reviewed checkout' >&2
      return 1
    }
    dirty=$(native_publication_command git -C "$script_dir/.." status --porcelain --untracked-files=all) || return $?
    [[ -z $dirty ]] || {
      echo 'native evidence requires a clean candidate checkout' >&2
      return 1
    }
    native_publication_command python3 "$script_dir/native-evidence.py" "$run_dir/version.json" "$NATIVE_SHAPES_PATH" "$NATIVE_SOURCE_PROBES_PATH" "$NATIVE_NETWORK_PROBES_PATH" "$NATIVE_VOLUME_PROBES_PATH" "$NATIVE_VOLUME_LABEL_PROBES_PATH" "$NATIVE_IDENTITY_PROBES_PATH" "$NATIVE_PORT_PROBES_PATH" "$NATIVE_HEALTH_METADATA_PROOF_PATH" "$NATIVE_NETWORK_ATTACHMENT_PROOF_PATH" "$NATIVE_BIND_RELABEL_PROOF_PATH" "$run_dir" \
      "$DOCKERLENS_NATIVE_EVIDENCE_DIR/$lane.json" "$lane" "$image" "$expected_mode" \
      "$installed_docker_package" "$candidate_sha" "$run_id"
  fi
}

if [[ -n ${apparmor_profile:-} ]]; then
  apparmor_native_completed=1
else
  publish_native_evidence
fi

native_success_summary="native conformance passed: $lane; Engine $server_version; API $api_version; mode $expected_mode; inner cgroup $inner_cgroup; outer $("${podman_cmd[@]}" --version); kernel $(uname -r); privileged $privileged; nested storage ${used_kib} KiB"
