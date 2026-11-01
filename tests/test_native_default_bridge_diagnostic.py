"""Hermetic fixed-marker sanitizer controls; no native runtime is reachable."""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
MARKER = "DOCKERLENS_NATIVE_DEFAULT_BRIDGE_SUBNET_DIAG: sidecar_on_default_bridge_subnet="
SELECTED = "native_network_tests::live_internal_network_blocks_external_egress"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;"
PASSED = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
CANARY = "protected-canary /private/socket 10.23.7.9 id=private"


class DefaultBridgeDiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dockerlens-default-bridge-marker-")
        self.addCleanup(temporary.cleanup)
        self.tools = Path(temporary.name) / "bin"
        self.tools.mkdir(mode=0o700)
        # The fake cargo is the only test subject. No ambient PATH or runtime
        # client, shell discovery, network access or privilege helper is used.
        for name, target in (("timeout", "/usr/bin/timeout"), ("grep", "/usr/bin/grep"),
                             ("sed", "/usr/bin/sed"), ("tail", "/usr/bin/tail"),
                             ("date", "/usr/bin/date")):
            (self.tools / name).symlink_to(target)

    def run_fixture(self, lines, *, status=101, summary=FAILED):
        cargo = self.tools / "cargo"
        cargo.write_text(
            f"#!{sys.executable}\nimport sys\n"
            f"if '--list' in sys.argv:\n print({SELECTED + ': test'!r})\n"
            f"else:\n print({chr(10).join([*lines, summary])!r})\n raise SystemExit({status})\n"
        )
        cargo.chmod(0o700)
        return subprocess.run(
            ["/bin/bash", str(ROOT / "scripts/run-exact-native-test.sh"),
             "native_network", "live_internal_network_blocks_external_egress"],
            env={"PATH": str(self.tools)}, capture_output=True, text=True, timeout=4,
        )

    def test_closed_observations_preserve_failure_status_summary_and_old_markers(self):
        old = ["DOCKERLENS_NATIVE_WGET_DIAG: category=timeout",
               "DOCKERLENS_NATIVE_INTERNAL_SUBNET_DIAG: sidecar_on_internal_subnet=false",
               "DOCKERLENS_NATIVE_CONTROL_SUBNET_DIAG: sidecar_on_control_subnet=unknown"]
        for value in ("true", "false", "unknown reason=unavailable", "unknown reason=budget_exhausted"):
            with self.subTest(value=value):
                result = self.run_fixture([*old, MARKER + value, CANARY])
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertIn("failed (exit 101)", result.stderr)
                self.assertIn(FAILED + "\n", result.stderr)
                self.assertIn(MARKER + value + "\n", result.stderr)
                for line in old:
                    self.assertIn(line + "\n", result.stderr)
                self.assertNotIn("protected-canary", result.stderr)
                self.assertNotIn("/private/socket", result.stderr)
                self.assertNotIn("10.23.7.9", result.stderr)

    def test_noncanonical_or_split_lines_never_export_a_partial_match(self):
        for line in (
            MARKER + CANARY, MARKER + "unknown", MARKER + "TRUE", MARKER + "null",
            MARKER + "true reason=unavailable", MARKER + "false reason=budget_exhausted",
            MARKER + "unknown reason=timeout", MARKER + "unknown reason=" + CANARY,
            MARKER + "unknown reason=unavailable extra=private",
            "prefix " + MARKER + "true", MARKER + "true suffix-private",
            MARKER + "true\r", MARKER + "false\t", MARKER + "true\x1b[0m",
            MARKER + "unknown\nreason=unavailable", MARKER + "unknown reason=\nunavailable",
            MARKER + "'true'", MARKER + "true\x00private",
        ):
            with self.subTest(line=line):
                result = self.run_fixture([line])
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(MARKER, result.stdout + result.stderr)
                self.assertNotIn("protected-canary", result.stdout + result.stderr)
                self.assertIn(FAILED + "\n", result.stderr)

    def test_only_last_complete_closed_line_is_projected(self):
        result = self.run_fixture([MARKER + "true", MARKER + "false",
                                   MARKER + "unknown reason=" + CANARY])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr.count(MARKER), 1)
        self.assertIn(MARKER + "false\n", result.stderr)
        self.assertNotIn("protected-canary", result.stderr)

    def test_success_never_exports_failure_diagnostic_and_exact_summary_still_matters(self):
        result = self.run_fixture([MARKER + "true", CANARY], status=0, summary=PASSED)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(MARKER, result.stdout + result.stderr)
        self.assertNotIn("protected-canary", result.stdout + result.stderr)
        result = self.run_fixture([MARKER + "true"], status=0,
                                  summary="test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;")
        self.assertEqual(result.returncode, 1)
        self.assertIn("did not execute exactly once", result.stderr)

    def test_test_only_serde_pin_integrity_and_unique_cargo_renovate_ownership(self):
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        renovate = json.loads((ROOT / "renovate.json").read_text())
        pin = manifest["dev-dependencies"]["serde"]
        self.assertRegex(pin, r"^=[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertNotIn("serde", manifest["dependencies"])
        packages = [package for package in lock["package"] if package["name"] == "serde"]
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["version"], pin[1:])
        self.assertRegex(packages[0]["checksum"], r"^[a-f0-9]{64}$")
        self.assertEqual(packages[0]["source"], "registry+https://github.com/rust-lang/crates.io-index")
        roots = [package for package in lock["package"] if package["name"] == manifest["package"]["name"]]
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]["dependencies"].count("serde"), 1)
        self.assertEqual(renovate["enabledManagers"].count("cargo"), 1)
        for manager in renovate.get("customManagers", []):
            self.assertNotIn("serde", json.dumps(manager))
            for pattern in manager.get("managerFilePatterns", []):
                self.assertTrue(pattern.startswith("/") and pattern.endswith("/"))
                self.assertIsNone(re.search(pattern[1:-1], "Cargo.toml"))
                self.assertIsNone(re.search(pattern[1:-1], "Cargo.lock"))
        for rule in renovate.get("packageRules", []):
            if "cargo" in rule.get("matchManagers", []):
                self.assertIsNot(rule.get("enabled"), False)


if __name__ == "__main__":
    unittest.main()
