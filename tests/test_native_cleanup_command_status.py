"""Real EXIT-trap status controls with fake clients, never a native runtime.

Numeric timeout/cancellation statuses below are client exits, not delivered
signals or elapsed timers. The default interpreter is the host Bash; an isolated
test runner may replace BASH to exercise another already-available interpreter.
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = "/bin/bash"


def definition(path, name):
    source = (ROOT / path).read_text()
    start = source.index("\n" + name + "() {") + 1
    return source[start:source.index("\n}\n", start) + 3]


class CleanupCommandStatusTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dockerlens-cleanup-status-")
        self.addCleanup(temporary.cleanup)
        self.private = Path(temporary.name)
        self.tools = self.private / "bin"
        self.tools.mkdir()
        (self.tools / "timeout").symlink_to("/usr/bin/timeout")
        self.trace = self.private / "calls.jsonl"
        self.client = self.tools / "fake-client"
        self.client.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['FAKE_TRACE'], 'a') as trace:\n"
            "    trace.write(json.dumps({'argv': sys.argv[1:], 'status': int(os.environ['FAKE_STATUS'])}) + '\\n')\n"
            "print('fake-client-output')\n"
            "raise SystemExit(int(os.environ['FAKE_STATUS']))\n"
        )
        self.client.chmod(0o700)

    def exercise(self, *, removal):
        definitions = definition("scripts/native-outer-runtime.sh", "native_outer_command")
        definitions += definition("scripts/native-conformance.sh", "cleanup_podman")
        if removal:
            definitions += definition("scripts/native-conformance.sh", "cleanup_remove")
        call = 'cleanup_remove container "${arguments[@]}"' if removal else 'cleanup_podman "${arguments[@]}"'
        body = "set -euo pipefail\n" + definitions + r'''
native_outer_engine=$1
mode=$2
original=$3
native_outer_cmd=("$4")
podman_cmd=("$4")
arguments=(rm --force --time 0 owned-container)
status_owner() {
  status=$?
  local original_status=$status
  trap - EXIT HUP INT TERM
  local observed_status=0 observed_output=
  if [[ $mode == direct ]]; then
    CALL || observed_status=$?
  else
    observed_output=$(CALL) || observed_status=$?
  fi
  printf 'OBSERVED|%s|%s|%s\n' "$observed_status" "$original_status" "$observed_output"
  exit "$original_status"
}
trap status_owner EXIT
exit "$original"
'''.replace("CALL", call)
        categories = {7: "error", 124: "timeout", 130: "cancelled", 143: "cancelled"}
        for engine in ("docker", "podman"):
            for mode in ("direct", "substitution"):
                for original in (0, 1, 101):
                    for client_status in (0, 7, 124, 130, 143):
                        with self.subTest(engine=engine, mode=mode, original=original, client_status=client_status):
                            self.trace.unlink(missing_ok=True)
                            result = subprocess.run(
                                [BASH, "-c", body, "cleanup-status-control", engine, mode,
                                 str(original), str(self.client)],
                                env={"PATH": str(self.tools), "FAKE_TRACE": str(self.trace),
                                     "FAKE_STATUS": str(client_status)},
                                capture_output=True, text=True, timeout=3,
                            )
                            self.assertEqual(result.returncode, original)
                            observed_status = int(client_status != 0) if removal else client_status
                            captured = "fake-client-output" if not removal and mode == "substitution" else ""
                            direct = "fake-client-output\n" if not removal and mode == "direct" else ""
                            self.assertEqual(result.stdout,
                                             f"{direct}OBSERVED|{observed_status}|{original}|{captured}\n")
                            diagnostic = ""
                            if removal and client_status:
                                diagnostic = ("DOCKERLENS_NATIVE_CLEANUP: role=container operation=remove "
                                              f"category={categories[client_status]}\n")
                            self.assertEqual(result.stderr, diagnostic)
                            # Exactly one real-helper client call, including failures;
                            # no extra query, retry or native binary can be resolved.
                            self.assertEqual([json.loads(line) for line in self.trace.read_text().splitlines()],
                                             [{"argv": ["rm", "--force", "--time", "0", "owned-container"],
                                               "status": client_status}])

    def test_real_cleanup_wrapper_preserves_client_status_inside_exit_trap(self):
        self.exercise(removal=False)

    def test_real_cleanup_remove_classifies_only_the_client_status_inside_exit_trap(self):
        self.exercise(removal=True)


if __name__ == "__main__":
    unittest.main()
