"""Fourteenth mandatory invocation and value-free failure-stage controls."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BindRelabelWiringTests(unittest.TestCase):
    def test_every_role_failure_survives_cleanup_without_private_suffix(self):
        selected = "native_bind_relabel_tests::live_bind_relabel_configuration_matches_engine"
        for stage in ("context", "oracle", "rendered"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                cargo = root / "cargo"
                cargo.write_text("#!/usr/bin/env bash\n"
                                 f'if [[ " $* " == *" --list "* ]]; then echo "{selected}: test"; exit 0; fi\n'
                                 f'echo "DOCKERLENS_NATIVE_CHECK: bind_relabel_{stage}"\n'
                                 f'echo "DOCKERLENS_NATIVE_CHECK: bind_relabel_{stage} PRIVATE_BIND_CANARY"\n'
                                 'echo "DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup"\n'
                                 'echo "DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup_unverified"\n'
                                 'echo "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out;"\n'
                                 'exit 101\n')
                cargo.chmod(0o700)
                result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                                         "native_bind_relabel", "live_bind_relabel_configuration_matches_engine"],
                                        env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"]},
                                        capture_output=True, text=True, timeout=10, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: bind_relabel_{stage}\n", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: bind_relabel_cleanup_unverified\n", result.stderr)
                self.assertNotIn("PRIVATE_BIND_CANARY", result.stdout + result.stderr)

    def test_mandatory_invocation_and_independent_uid_precede_emission(self):
        harness = (ROOT / "scripts/native-conformance.sh").read_text()
        command = '"$(dirname "$0")/run-exact-native-test.sh" native_bind_relabel live_bind_relabel_configuration_matches_engine'
        self.assertEqual(harness.count(command), 1)
        self.assertLess(harness.index(command), harness.index('python3 "$script_dir/native-evidence.py"'))
        self.assertLess(harness.index('"$script_dir/native-daemon-uid.py"'), harness.index(command))
        self.assertIn('export NATIVE_BIND_RELABEL_PROOF_PATH="$run_dir/bind-relabel-config-v1.json"', harness)
