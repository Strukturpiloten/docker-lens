#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$script_dir/native-outer-runtime.sh"

# Verification only: the GitHub ubuntu-24.04 image supplies Docker. There is no
# package installation, daemon restart, context selection or host policy change.
[[ ${DOCKERLENS_OUTER_ENGINE:-} == docker ]] && native_outer_policy docker || {
  echo 'hosted outer Docker setup refused' >&2
  exit 1
}
[[ ${ImageOS:-} == ubuntu24 && ${ImageVersion:-} =~ ^[0-9]{8}\.[0-9]+\.[0-9]+$ ]] || {
  echo 'hosted outer Docker runner identity unavailable' >&2
  exit 1
}
for tool in docker python3 timeout mktemp systemctl; do
  command -v "$tool" >/dev/null || { echo 'hosted outer Docker tool unavailable' >&2; exit 1; }
done
directory=$(mktemp -d /tmp/dockerlens-outer-setup.XXXXXXXX)
cleanup_setup() {
  local status=$?
  trap - EXIT HUP INT TERM
  # Unexpected client configuration retains private evidence rather than
  # recursively deleting a broad/unresolved target or hiding unexpected files.
  if [[ $directory == /tmp/dockerlens-outer-setup.* && -d $directory && ! -L $directory ]]; then
    if [[ -f $directory/outer-runtime.json && ! -L $directory/outer-runtime.json ]]; then
      rm -- "$directory/outer-runtime.json" || status=1
    fi
    if [[ -d $directory/docker-client ]]; then rmdir -- "$directory/docker-client" || status=1; fi
    rmdir -- "$directory" || status=1
  else
    status=1
  fi
  exit "$status"
}
trap cleanup_setup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
native_outer_select docker "$directory"
native_outer_preflight
printf 'DOCKERLENS_NATIVE_OUTER: runner=ubuntu-24.04 image=%s verification=complete\n' "$ImageVersion"
