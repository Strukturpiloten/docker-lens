#!/usr/bin/env bash

# Docker's Debian 11 build may report its +dfsg1 source suffix in /version.
# Compare complete releases, never a prefix such as 28.5.1 vs 28.5.10.
native_engine_release_matches() {
  local lane=$1 expected=$2 actual=$3
  case "$lane" in
    debian11-*) [[ $actual == "$expected" || $actual == "$expected+dfsg1" ]] ;;
    upstream-*) [[ $actual == "$expected" ]] ;;
    *) return 1 ;;
  esac
}
