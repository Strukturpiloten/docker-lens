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


if __name__ == "__main__":
    unittest.main()
