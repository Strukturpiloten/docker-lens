"""Runner causality and private-suffix projection controls."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class NetworkAttachmentWiringTests(unittest.TestCase):
    def test_each_role_failure_survives_cleanup_without_native_output(self):
        selected = "native_network_attachment_tests::live_network_attachments_match_engine"
        for stage in ("context", "oracle", "rendered"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                cargo = root / "cargo"
                cargo.write_text("#!/usr/bin/env bash\n"
                                 f'if [[ " $* " == *" --list "* ]]; then echo "{selected}: test"; exit 0; fi\n'
                                 f'echo "DOCKERLENS_NATIVE_CHECK: network_attachment_{stage}"\n'
                                 f'echo "DOCKERLENS_NATIVE_CHECK: network_attachment_{stage} PRIVATE_ATTACHMENT_CANARY"\n'
                                 'echo "DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup"\n'
                                 'echo "DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup_unverified"\n'
                                 'echo "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out;"\n'
                                 'exit 101\n')
                cargo.chmod(0o700)
                result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                                         "native_network_attachment", "live_network_attachments_match_engine"],
                                        env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"]},
                                        capture_output=True, text=True, timeout=10, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: network_attachment_{stage}\n", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: network_attachment_cleanup_unverified\n", result.stderr)
                self.assertNotIn("PRIVATE_ATTACHMENT_CANARY", result.stdout + result.stderr)
