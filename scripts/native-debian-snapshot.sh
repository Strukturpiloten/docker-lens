#!/bin/sh
set -eu

# This is a historical Debian 11 compatibility fixture, not a live update feed.
# The pinned Debian image has only sources.list; fail if its layout changes.
apt_dir=${DOCKERLENS_APT_DIR:-/etc/apt}
if [ "$apt_dir" = /etc/apt ]; then
    test -f /run/dockerlens/native-bind/canary
fi
if [ -L "$apt_dir/sources.list.d" ] ||
    { [ -d "$apt_dir/sources.list.d" ] &&
      [ -n "$(find "$apt_dir/sources.list.d" -mindepth 1 -maxdepth 1 -print -quit)" ]; }; then
    printf 'DOCKERLENS_APT_RESULT: unexpected_sources\n' >&2
    exit 1
fi

snapshot=20260824T000000Z
mkdir -p "$apt_dir/apt.conf.d"
printf '%s\n' \
    "deb http://snapshot.debian.org/archive/debian/$snapshot bullseye main" \
    "deb http://snapshot.debian.org/archive/debian-security/$snapshot bullseye-security main" \
    "deb http://snapshot.debian.org/archive/debian/$snapshot bullseye-updates main" \
    > "$apt_dir/sources.list"
# Old signed InRelease files may expire; signature and package-hash checks stay enabled.
printf '%s\n' 'Acquire::Check-Valid-Until "false";' \
    > "$apt_dir/apt.conf.d/99dockerlens-snapshot"
