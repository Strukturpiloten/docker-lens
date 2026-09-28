"""Closed native evidence cannot admit unreviewed identity or leak API bodies."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native-evidence.py"
SHA = "a" * 40
IMAGE = ("ghcr.io/strukturpiloten/docker-29-rootful:v29.8.1@sha256:"
         + "b" * 64)


class NativeEvidenceTests(unittest.TestCase):
    def test_acquisition_cap_matches_manifest_calculation(self) -> None:
        acquisition = (ROOT / "src/acquisition.rs").read_text(encoding="utf-8")
        evidence = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("const MAX_KNOWN_API_MINOR: u16 = 49;", acquisition)
        self.assertIn("selected = min(int(maximum.split(\".\")[1]), 49)", evidence)

    def run_emit(self, version: dict, image: str = IMAGE, sha: str = SHA,
                 lane: str = "upstream-rootful", mode: str = "rootful",
                 package: str = "") -> tuple[subprocess.CompletedProcess[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        version_path = root / "version.json"
        destination = root / "out" / f"{lane}.json"
        version_path.write_text(json.dumps(version), encoding="utf-8")
        result = subprocess.run(
            ["python3", str(SCRIPT), str(version_path), str(destination),
             lane, image, mode, package, sha],
            capture_output=True, text=True, check=False,
        )
        return result, destination

    def test_advertised_and_negotiated_api_are_distinct(self) -> None:
        result, path = self.run_emit({
            "Version": "29.8.1", "ApiVersion": "1.52",
            "MinAPIVersion": "1.44", "Private": "protected-secret",
            "Components": [{"Name": "containerd", "Version": "2.3.5"},
                           {"Name": "runc", "Version": "1.5.1"}],
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["engine_api_max"], "1.52")
        self.assertEqual(evidence["engine_api_min"], "1.44")
        self.assertEqual(evidence["acquisition_api"], "1.49")
        self.assertEqual(evidence["rendering_api"], "1.52")
        self.assertEqual(evidence["runtime_components"], {"containerd": "2.3.5", "runc": "1.5.1"})
        self.assertEqual(len(evidence["capability_outcome"]), 10)
        self.assertEqual(set(evidence["capability_outcome"].values()), {"available"})
        self.assertNotIn("protected-secret", path.read_text(encoding="utf-8"))

    def test_rejects_unreviewed_identity_and_unacquirable_api(self) -> None:
        version = {"Version": "29.8.1", "ApiVersion": "1.52", "MinAPIVersion": "1.44"}
        cases = (
            {"image": IMAGE.replace("docker-29-rootful", "docker-29-rootless")},
            {"sha": "invalid"},
            {"mode": "rootless"},
            {"package": "unexpected"},
        )
        for options in cases:
            with self.subTest(options=options):
                result, path = self.run_emit(version, **options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
        result, path = self.run_emit({**version, "MinAPIVersion": "1.50"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())

    def test_debian_package_is_exact_and_private_fields_stay_private(self) -> None:
        image = ("ghcr.io/strukturpiloten/docker-debian-11-rootless:v1.0.0@sha256:"
                 + "c" * 64)
        version = {"Version": "20.10.5+dfsg1", "ApiVersion": "1.41",
                   "MinAPIVersion": "1.12", "Private": "protected-secret"}
        result, path = self.run_emit(
            version, image=image, lane="debian11-rootless", mode="rootless",
            package="20.10.5+dfsg1-1+deb11u2",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["debian_docker_package"], "20.10.5+dfsg1-1+deb11u2")
        self.assertEqual(evidence["acquisition_api"], "1.41")
        self.assertNotIn("protected-secret", path.read_text(encoding="utf-8"))
        result, path = self.run_emit(
            version, image=image, lane="debian11-rootless", mode="rootless",
            package="20.10.5+dfsg1-1+deb11u4",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
