"""Closed stage labels on existing cleanup calls; no runtime commands."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


def definitions():
    source = (ROOT / "scripts/native-conformance.sh").read_text()
    selected = []
    for name in ("cleanup_identity_stage", "cleanup_refuse", "cleanup_network", "cleanup_volume"):
        start = source.index("\n" + name + "() {") + 1
        end = source.index("\n}\n", start) + 3
        selected.append(source[start:end])
    return "\n".join(selected)


class CleanupStageTests(unittest.TestCase):
    def test_existing_failed_calls_keep_retention_and_map_only_closed_status_classes(self):
        body = r'''
set -euo pipefail
DEFINITIONS
native_outer_engine=docker
run_id=run
outer_network=owned-net
outer_network_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
volume=owned-data
volume_identity=held-identity
network_attempted=1
network_created=1
volume_attempted=1
preserve_run_dir=0
status=0
binding_calls=0
inspect_calls=0
native_presence() { return 0; }
native_outer_binding() {
  binding_calls=$((binding_calls+1))
  if [[ $stage == network-binding ]]; then return "$code"; fi
}
cleanup_podman() {
  # Command substitutions cannot update parent counters; an explicit marker
  # counts the existing native call without running a client.
  printf 'inspect-call\n' >&2
  return "$code"
}
cleanup_remove() { printf 'forbidden-remove\n' >&2; return 97; }
stage=$1
code=$2
result=0
if [[ $stage == volume-identity-inspect ]]; then
  cleanup_volume || result=$?
else
  cleanup_network || result=$?
fi
printf '%s\n' "$result|$preserve_run_dir|$status|$binding_calls"
'''.replace("DEFINITIONS", definitions())
        for stage in ("network-binding", "network-owner-inspect", "volume-identity-inspect"):
            for code, category in ((1, "error"), (2, "refused"), (124, "timeout"), (125, "command_error"),
                                   (126, "command_error"), (127, "command_error"), (130, "cancelled"),
                                   (137, "killed"), (143, "cancelled")):
                with self.subTest(stage=stage, category=category):
                    result = subprocess.run(["/bin/bash", "-c", body, "closed-cleanup", stage, str(code)],
                        env={"PATH": "/nonexistent"}, capture_output=True, text=True, timeout=2)
                    self.assertEqual(result.returncode, 0)
                    role = "volume" if stage.startswith("volume") else "network"
                    self.assertIn(f"DOCKERLENS_NATIVE_CLEANUP_STAGE: role={role} stage={stage} category={category}\n", result.stderr)
                    self.assertIn(f"DOCKERLENS_NATIVE_CLEANUP: role={role} operation=retain category=identity_unknown\n", result.stderr)
                    self.assertEqual(result.stdout, "1|1|1|" + ("0" if role == "volume" else "1") + "\n")
                    self.assertEqual(result.stderr.count("inspect-call\n"), 0 if stage == "network-binding" else 1)
                    self.assertNotIn("forbidden-remove", result.stderr)
                    self.assertNotIn(str(code), result.stderr)

    def test_new_diagnostic_helper_refuses_uninventoried_roles_and_stages(self):
        for role, stage in (("private-canary", "network-binding"), ("network", "private-canary")):
            body = definitions() + '\ncleanup_identity_stage "$1" "$2" 125'
            result = subprocess.run(["/bin/bash", "-c", body, "closed-cleanup", role, stage],
                env={"PATH": "/nonexistent"}, capture_output=True, text=True, timeout=2)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (1, "", ""))
