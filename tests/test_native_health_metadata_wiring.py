"""Independent runner privacy, causality and dependency ownership controls."""

import json
import os
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class HealthMetadataWiringTests(unittest.TestCase):
    def test_exact_dev_pin_keeps_existing_locked_integrity_and_cargo_owner(self):
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        renovate = json.loads((ROOT / "renovate.json").read_text())
        self.assertEqual(manifest["dev-dependencies"]["libc"], "=0.2.189")
        self.assertNotIn("libc", manifest["dependencies"])
        package = [item for item in lock["package"] if item["name"] == "libc"]
        self.assertEqual(len(package), 1)
        self.assertEqual(package[0]["version"], "0.2.189")
        self.assertEqual(package[0]["checksum"], "3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2")
        self.assertEqual(renovate["enabledManagers"].count("cargo"), 1)
        self.assertFalse(any(manager.get("depNameTemplate") == "libc" for manager in renovate["customManagers"]))

    def test_each_closed_failure_stage_survives_later_cleanup_without_private_suffix(self):
        selected = "native_health_metadata_tests::live_health_metadata_matches_engine"
        for stage in ("derive", "grace_positive", "period_zero", "inherited_failure", "disabled"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                cargo = root / "cargo"
                cargo.write_text("#!/usr/bin/env bash\n"
                                 f'if [[ " $* " == *" --list "* ]]; then echo "{selected}: test"; exit 0; fi\n'
                                 f'echo "DOCKERLENS_NATIVE_CHECK: health_metadata_{stage}"\n'
                                 f'echo "DOCKERLENS_NATIVE_CHECK: health_metadata_{stage} PRIVATE_HEALTH_CANARY"\n'
                                 'echo "DOCKERLENS_NATIVE_CHECK: health_metadata_cleanup"\n'
                                 'echo "DOCKERLENS_NATIVE_CHECK: health_metadata_cleanup_unverified"\n'
                                 'echo "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out;"\n'
                                 'exit 101\n')
                cargo.chmod(0o700)
                result = subprocess.run(["bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                                         "native_health_metadata", "live_health_metadata_matches_engine"],
                                        env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"]},
                                        capture_output=True, text=True, timeout=10, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: health_metadata_{stage}\n", result.stderr)
                self.assertIn("DOCKERLENS_NATIVE_CHECK: health_metadata_cleanup_unverified\n", result.stderr)
                self.assertNotIn("PRIVATE_HEALTH_CANARY", result.stdout + result.stderr)
