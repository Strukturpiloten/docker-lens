#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ! $1 =~ ^[a-z_]+$ || ! $2 =~ ^[a-z_]+$ ]]; then
  echo "usage: $0 <integration-test-target> <exact-ignored-test-name>" >&2
  exit 2
fi
target=$1
test_name=$2

# libtest returns success for zero selected tests. Check the ignored-only list
# first, then require exactly one executed success in the final summary.
list_status=0
listing=$(timeout 180 cargo test --locked --test "$target" -- --ignored --list 2>&1) || list_status=$?
if (( list_status != 0 )); then
  echo "failed to list required ignored native test $target::$test_name (exit $list_status)" >&2
  exit 1
fi
if [[ $(grep -Fxc "$test_name: test" <<<"$listing" || true) != 1 ]]; then
  echo "required ignored native test $target::$test_name is absent" >&2
  exit 1
fi
run_status=0
result=$(timeout 180 cargo test --locked --test "$target" -- --ignored --exact "$test_name" 2>&1) || run_status=$?
# Only libtest's numeric summary is safe to print. Test and compiler output can
# contain protected native values, socket payloads, or authored secrets.
summary=$(grep -Eo '^test result: (ok|FAILED)\. [0-9]+ passed; [0-9]+ failed; [0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out;' <<<"$result" | tail -n 1 || true)
# Only constant markers authored by the native tests may pass this boundary.
# Never print arbitrary assertion, compiler, daemon, or captured API output.
marker=$(grep -Eo '^DOCKERLENS_NATIVE_CHECK: (capture_(input|decode|daemon|counts|image|ports|mounts|environment|command|privacy)|acquire_(input|oracle|socket|route|network|decode|mode|settings|replay)|target_daemon_uid|read_only_(acquire|route|status|decode|daemon|mode|api))$' <<<"$result" | tail -n 1 || true)
error_category=$(grep -Eo '^DOCKERLENS_NATIVE_ERROR: (endpoint|cancelled|deadline|io|protocol|status|version|shape|budget)$' <<<"$result" | tail -n 1 || true)
if (( run_status != 0 )); then
  echo "required native test $target::$test_name failed (exit $run_status)" >&2
  if [[ -n $marker ]]; then echo "$marker" >&2; fi
  if [[ -n $error_category ]]; then echo "$error_category" >&2; fi
  if [[ -n $summary ]]; then
    echo "$summary" >&2
  fi
  exit 1
fi
if ! grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;' <<<"$result"; then
  echo "required native test $target::$test_name did not execute exactly once (exit $run_status)" >&2
  if [[ -n $summary ]]; then
    echo "$summary" >&2
  fi
  exit 1
fi
echo "required native test passed: $target::$test_name"
