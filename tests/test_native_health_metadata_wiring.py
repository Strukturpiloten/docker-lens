"""Independent runner privacy, causality and dependency ownership controls."""

import hashlib
import json
import os
import re
import subprocess
import tempfile
import tomllib
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class HealthMetadataWiringTests(unittest.TestCase):
    @staticmethod
    def dependency_contract_inputs():
        return (
            tomllib.loads((ROOT / "Cargo.toml").read_text()),
            tomllib.loads((ROOT / "Cargo.lock").read_text()),
            json.loads((ROOT / "renovate.json").read_text()),
        )

    def assert_exact_dev_pin_contract(self, manifest, lock, renovate):
        requirement = manifest.get("dev-dependencies", {}).get("libc")
        self.assertIsInstance(requirement, str)
        self.assertRegex(requirement, r"\A=(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
        for scope in [manifest, *manifest.get("target", {}).values()]:
            for kind in ("dependencies", "build-dependencies"):
                self.assertNotIn("libc", scope.get(kind, {}))
        packages = [item for item in lock.get("package", []) if item["name"] == "libc"]
        self.assertEqual(len(packages), 1)
        package = packages[0]
        self.assertEqual(package["version"], requirement[1:])
        self.assertEqual(
            package.get("source"), "registry+https://github.com/rust-lang/crates.io-index"
        )
        self.assertRegex(package.get("checksum", ""), r"\A[0-9a-f]{64}\Z")
        self.assertEqual(renovate["enabledManagers"].count("cargo"), 1)
        self.assertFalse(
            any(
                manager.get("depNameTemplate") == "libc"
                or any(
                    re.search(r"\blibc\b", pattern) for pattern in manager.get("matchStrings", [])
                )
                for manager in renovate.get("customManagers", [])
            )
        )

    def test_exact_dev_pin_keeps_existing_locked_integrity_and_cargo_owner(self):
        self.assert_exact_dev_pin_contract(*self.dependency_contract_inputs())

    def test_coherent_future_exact_dev_pin_updates_keep_cargo_ownership(self):
        for version in ("0.2.191", "0.3.0", "1.0.0"):
            with self.subTest(version=version):
                manifest, lock, renovate = self.dependency_contract_inputs()
                manifest["dev-dependencies"]["libc"] = "=" + version
                # A mention in unrelated manager prose does not create ownership.
                renovate["customManagers"][0]["description"] = "Historical libc introduction"
                package = next(item for item in lock["package"] if item["name"] == "libc")
                package["version"] = version
                # Synthetic integrity metadata; no claim about published crate bytes.
                package["checksum"] = hashlib.sha256(version.encode()).hexdigest()
                self.assert_exact_dev_pin_contract(manifest, lock, renovate)

    def test_invalid_dev_pin_lock_integrity_and_duplicate_owners_are_rejected(self):
        original_manifest, original_lock, original_renovate = self.dependency_contract_inputs()
        for case in (
            "mismatch",
            "broad",
            "missing_pin",
            "production",
            "build",
            "target_production",
            "unlocked",
            "duplicate_lock",
            "git_source",
            "missing_source",
            "missing_checksum",
            "invalid_checksum",
            "missing_cargo",
            "duplicate_cargo",
            "custom_owner",
            "custom_regex_owner",
        ):
            with self.subTest(case=case):
                manifest, lock, renovate = deepcopy(
                    (original_manifest, original_lock, original_renovate)
                )
                package = next(item for item in lock["package"] if item["name"] == "libc")
                if case == "mismatch":
                    package["version"] += ".1"
                elif case == "broad":
                    manifest["dev-dependencies"]["libc"] = "^" + package["version"]
                elif case == "missing_pin":
                    del manifest["dev-dependencies"]["libc"]
                elif case in ("production", "build"):
                    kind = "dependencies" if case == "production" else "build-dependencies"
                    manifest.setdefault(kind, {})["libc"] = "=" + package["version"]
                elif case == "target_production":
                    manifest["target"] = {
                        "cfg(unix)": {"dependencies": {"libc": "=" + package["version"]}}
                    }
                elif case == "unlocked":
                    lock["package"].remove(package)
                elif case == "duplicate_lock":
                    lock["package"].append(deepcopy(package))
                elif case == "git_source":
                    package["source"] = "git+https://example.invalid/libc"
                elif case == "missing_source":
                    del package["source"]
                elif case == "missing_checksum":
                    del package["checksum"]
                elif case == "invalid_checksum":
                    package["checksum"] = "not-a-sha256"
                elif case == "missing_cargo":
                    renovate["enabledManagers"].remove("cargo")
                elif case == "duplicate_cargo":
                    renovate["enabledManagers"].append("cargo")
                elif case == "custom_owner":
                    renovate["customManagers"].append({"depNameTemplate": "libc"})
                elif case == "custom_regex_owner":
                    renovate["customManagers"].append(
                        {"matchStrings": ["libc = (?<currentValue>[^ ]+)"]}
                    )
                with self.assertRaises(AssertionError):
                    self.assert_exact_dev_pin_contract(manifest, lock, renovate)

    def test_each_closed_failure_stage_survives_later_cleanup_without_private_suffix(self):
        selected = "native_health_metadata_tests::live_health_metadata_matches_engine"
        for stage in ("derive", "grace_positive", "period_zero", "inherited_failure", "disabled"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                cargo = root / "cargo"
                cargo.write_text(
                    "#!/usr/bin/env bash\n"
                    f'if [[ " $* " == *" --list "* ]]; then echo "{selected}: test"; exit 0; fi\n'
                    f'echo "DOCKERLENS_NATIVE_CHECK: health_metadata_{stage}"\n'
                    f'echo "DOCKERLENS_NATIVE_CHECK: health_metadata_{stage} PRIVATE_HEALTH_CANARY"\n'
                    'echo "DOCKERLENS_NATIVE_CHECK: health_metadata_cleanup"\n'
                    'echo "DOCKERLENS_NATIVE_CHECK: health_metadata_cleanup_unverified"\n'
                    'echo "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out;"\n'
                    "exit 101\n"
                )
                cargo.chmod(0o700)
                result = subprocess.run(
                    [
                        "bash",
                        str(ROOT / "scripts/run-exact-native-test.sh"),
                        "native_health_metadata",
                        "live_health_metadata_matches_engine",
                    ],
                    env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"]},
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"DOCKERLENS_NATIVE_CHECK: health_metadata_{stage}\n", result.stderr)
                self.assertIn(
                    "DOCKERLENS_NATIVE_CHECK: health_metadata_cleanup_unverified\n", result.stderr
                )
                self.assertNotIn("PRIVATE_HEALTH_CANARY", result.stdout + result.stderr)
