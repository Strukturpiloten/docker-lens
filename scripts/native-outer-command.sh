#!/usr/bin/env bash
# Fixed test-only argv seam. The calling sudo/timeout/capture owns this process.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$script_dir/native-outer-runtime.sh"
refuse() { echo 'native outer command refused' >&2; exit 2; }
[[ $# -ge 5 && $1 == --engine && $3 == --directory ]] || refuse
engine=$2 directory=$4 operation=$5
shift 5
[[ $engine == podman || $engine == docker ]] || refuse
[[ $directory == /* && -d $directory && ! -L $directory ]] || refuse
if [[ $operation == preflight ]]; then
  [[ $# == 0 ]] || refuse
  native_outer_select "$engine" "$directory" || refuse
else
  # Custody validation and later observations share the original caller's
  # privilege, timer and process group, including during attach itself.
  native_outer_helper() { python3 "$native_outer_script_dir/native-outer-observation.py" "$@"; }
  native_outer_attach "$engine" "$directory" || refuse
fi
# Never create a second command/invocation budget. Existing caller timers apply
# to the whole operation, including both observations of a Docker snapshot.
native_outer_command() { shift; "${native_outer_cmd[@]}" "$@"; }
identity() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]]; }
cid() { [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
pin() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_./:-]+@sha256:[0-9a-f]{64}$ ]]; }
case $operation in
  check-context) [[ $# == 0 ]] || refuse ;;
  preflight)
    native_outer_preflight || refuse
    printf '%s\n' "$native_outer_store_root" ;;
  exec)
    flags=()
    if [[ ${1:-} == --user ]]; then
      [[ $# -ge 4 && $2 =~ ^[0-9]{1,10}$ ]] || refuse
      flags=(--user "$2"); shift 2
    fi
    [[ $# -ge 2 ]] && identity "$1" || refuse
    exec "${native_outer_cmd[@]}" exec "${flags[@]}" "$@" ;;
  inspect)
    [[ $# == 3 && $1 == --format ]] && identity "$3" || refuse
    case $2 in
      '{{json .}}') native_outer_snapshot "$3" ;;
      '{{json .NetworkSettings.Networks}}'|'{{.State.Running}}'|'{{.Id}}|{{.State.Pid}}|{{.State.StartedAt}}|{{.State.Running}}|{{index .Config.Labels "io.dockerlens.native-run"}}')
        exec "${native_outer_cmd[@]}" inspect --format "$2" "$3" ;;
      *) refuse ;;
    esac ;;
  snapshot) [[ $# == 1 ]] && cid "$1" || refuse; native_outer_snapshot "$1" ;;
  observe) [[ $# == 2 ]] || refuse; native_outer_observe "$@" ;;
  presence) [[ $# == 2 ]] || refuse; native_outer_presence "$@" "$directory" ;;
  binding) [[ $# == 5 ]] || refuse; native_outer_binding "$@" ;;
  daemon-binding) [[ $# == 5 ]] || refuse; native_outer_daemon_binding "$@" ;;
  remove) [[ $# == 4 ]] || refuse; native_outer_remove "$@" "$directory" ;;
  create-daemon)
    [[ $# == 10 ]] || refuse
    declare -A held=([name]="$1" [run]="$2" [owner_key]="$3" [network]="$4" [volume]="$5"
      [socket_dir]="$6" [guest_dir]="$7" [lane]="$8" [image]="$9" [log_path]="${10}")
    native_outer_create_daemon held ;;
  prepare-data) [[ $# == 5 ]] || refuse; native_outer_prepare_data "$@" ;;
  check-mounts)
    [[ $# == 6 && $6 == /* && $6 != / ]] || refuse
    native_outer_store_root=$6
    native_outer_check_mounts "${@:1:5}" ;;
  pull) [[ $# == 1 ]] && pin "$1" || refuse; exec "${native_outer_cmd[@]}" pull "$1" ;;
  image-info)
    [[ $# == 1 ]] && pin "$1" || refuse
    native_outer_command 8 image inspect --format '{{json .}}' "$1" | native_outer_helper image-info ;;
  image-save)
    [[ $# == 2 ]] && pin "$1" && [[ $2 == "$directory/busybox.tar" && ! -e $2 && ! -L $2 ]] || refuse
    archive=$2
    cleanup_archive() { local status=$?; if (( status != 0 )); then rm -f -- "$archive"; fi; exit "$status"; }
    trap cleanup_archive EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ $engine == podman ]]; then
      native_outer_command 60 save --format docker-archive --output "$archive" "$1"
    else
      native_outer_command 60 save --output "$archive" "$1"
    fi ;;
  copy-into)
    [[ $# == 3 ]] && cid "$1" && [[ $2 == "$directory/busybox.tar" && -f $2 && ! -L $2 && $3 == /tmp/bf-core-busybox.tar ]] || refuse
    exec "${native_outer_cmd[@]}" cp "$2" "$1:$3" ;;
  logs) [[ $# == 1 ]] && cid "$1" || refuse; exec "${native_outer_cmd[@]}" logs --tail 80 "$1" ;;
  volume-create)
    [[ $# == 3 ]] && identity "$1" && identity "$3" && [[ $2 =~ ^io\.(dockerlens\.native-run|boxferry\.docker-core-run)$ ]] || refuse
    exec "${native_outer_cmd[@]}" volume create --label "$2=$3" "$1" ;;
  volume-path)
    [[ $# == 3 ]] || refuse
    native_outer_observe volume "$1" | native_outer_helper volume-path "$@" ;;
  volume-remove)
    [[ $# == 3 ]] || refuse
    native_outer_binding volume "$1" "$1" "$2" "$3" >/dev/null || refuse
    native_outer_command 8 volume rm "$1" >/dev/null || refuse
    status=0
    native_outer_presence volume "$1" "$directory" || status=$?
    (( status == 1 )) || refuse ;;
  *) refuse ;;
esac
