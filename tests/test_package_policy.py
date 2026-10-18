"""The first-release package is product source, not live test infrastructure."""

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PackagePolicyTests(unittest.TestCase):
    def test_explicit_package_boundary_and_manual_release(self) -> None:
        package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
        self.assertEqual(package["publish"], ["crates-io"])
        self.assertEqual(package["readme"], "README.md")
        self.assertEqual(
            set(package["include"]),
            {"Cargo.toml", "Cargo.lock", "LICENSE", "README.md", "src/**", "docs/**"},
        )
        for required in ("LICENSE", "README.md", "docs/releasing.md"):
            self.assertTrue((ROOT / required).is_file())
        release = (ROOT / ".github/workflows/release-validation.yml").read_text()
        self.assertNotIn("cargo publish", release)
        self.assertNotIn("contents: write", release)

    def test_release_handoff_retains_unadmitted_and_exact_candidate_gates(self) -> None:
        package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
        handoff = " ".join((ROOT / "docs/releasing.md").read_text().split())
        self.assertIn(f'MSRV `{package["rust-version"]}`', handoff)
        self.assertIn("`0.1.0` is already published", handoff)
        self.assertIn("Do not attempt to publish that version again", handoff)
        self.assertIn("choice is closed", handoff)
        self.assertIn(
            "reviewed lifecycle cohort at Debian 34 capabilities/56 shapes and upstream 36/60",
            handoff,
        )
        self.assertIn("`raw_source_only`/`catalogue_admission: unadmitted`", handoff)
        self.assertIn("Those three process groups remain unselected", handoff)
        self.assertIn("canonical twenty-four exact test invocations", handoff)
        self.assertIn("all six actual authored-fixture volume-only rehearsals", handoff)
        self.assertIn("actual Nextcloud/Supabase bind and desired-external expectation consumers", handoff)
        self.assertIn("a separate explicit request", handoff)
        self.assertIn("Any subsequent source change invalidates that qualification", handoff)


if __name__ == "__main__":
    unittest.main()
