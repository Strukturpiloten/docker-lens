#!/bin/sh
# Run inside the isolated Debian guest. APT output can contain private values;
# only the fixed result marker is allowed to reach the container log.
set -eu

log=$(mktemp "${TMPDIR:-/tmp}/dockerlens-apt.XXXXXXXX")
trap 'rm -f -- "$log"' EXIT HUP INT TERM

if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@" >"$log" 2>&1; then
  exit 0
else
  result=$?
fi

category=package_apt_failure
if grep -Eiq 'post-invoke' "$log"; then
  category=package_post_invoke
elif grep -Eiq 'no_pubkey|expkeysig|badsig|signatures could not be verified|invalid signature|is not signed' "$log"; then
  category=package_signature
elif grep -Eiq 'not valid yet|release file is expired|release file expired|invalid for another' "$log"; then
  category=package_time
elif grep -Eiq 'no space left on device|write error - write' "$log"; then
  category=package_disk
elif grep -Eiq 'could not get lock|unable to acquire the dpkg frontend lock' "$log"; then
  category=package_lock
elif grep -Eiq 'unmet dependencies|dependency problems|unable to correct problems|held broken packages|depends:' "$log"; then
  category=package_dependency
elif grep -Eiq 'failed to fetch|temporary failure resolving|does not have a release file|404 not found' "$log"; then
  category=package_download
elif grep -Eiq 'sub-process /usr/bin/dpkg returned an error code|dpkg: error processing|dpkg: error:' "$log"; then
  category=package_dpkg
elif grep -Eiq 'unable to locate package|was not found|has no installation candidate' "$log"; then
  category=package_install
fi

printf 'DOCKERLENS_APT_RESULT: %s\n' "$category"
exit "$result"
