"""Checked-in reviewed records must bind the exact native artifact bytes."""

import hashlib
import json
import re
import unittest
from pathlib import Path

from test_native_evidence import SHAPES


ROOT = Path(__file__).resolve().parents[1]
RUN = "https://github.com/Strukturpiloten/docker-lens/actions/runs/36451790131/attempts/1"
CANDIDATE = "d51d7dbfda5ee6f8fefe92605afe8baea3dc504e"
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
LANE_VARIANTS = {
    "Debian11Rootful": "debian11-rootful",
    "Debian11Rootless": "debian11-rootless",
    "UpstreamRootful": "upstream-rootful",
    "UpstreamRootless": "upstream-rootless",
}
RECORD_TUPLE = re.compile(
    r'\(\s*NativeEvidenceLane::(?P<variant>\w+),\s*'
    r'"(?P<digest>[0-9a-f]{64})",\s*include_str!\(\s*'
    r'"\.\./docs/evidence/reviewed/sha256/(?P<path_digest>[0-9a-f]{64})\.json"\s*\),\s*\)',
    re.DOTALL,
)


def hashed_json(kind: str) -> list[tuple[Path, dict]]:
    directory = ROOT / "docs/evidence" / kind / "sha256"
    result = []
    for path in sorted(directory.glob("*.json")):
        content = path.read_bytes()
        assert path.stem == hashlib.sha256(content).hexdigest()
        result.append((path, json.loads(content)))
    return result


class ReviewedCatalogTests(unittest.TestCase):
    def test_rust_record_tuples_pair_exact_lane_digest_and_file(self) -> None:
        source = (ROOT / "src/reviewed_catalog.rs").read_text(encoding="utf-8")
        section = source.split("const RECORDS:", 1)[1].split("pub(crate) fn records", 1)[0]
        tuples = list(RECORD_TUPLE.finditer(section))
        self.assertEqual(len(tuples), 4)
        self.assertEqual(section.count("NativeEvidenceLane::"), 4)
        reviewed = {data["lane"]: path.stem for path, data in hashed_json("reviewed")}
        self.assertEqual(set(reviewed), set(LANES))
        self.assertEqual({match["variant"] for match in tuples}, set(LANE_VARIANTS))
        for match in tuples:
            lane = LANE_VARIANTS[match["variant"]]
            self.assertEqual(match["digest"], reviewed[lane])
            self.assertEqual(match["path_digest"], reviewed[lane])

    def test_four_records_bind_exact_manifest_bytes_and_shapes(self) -> None:
        raw = {data["lane"]: (path, data) for path, data in hashed_json("native")}
        reviewed = {data["lane"]: (path, data) for path, data in hashed_json("reviewed")}
        self.assertEqual(set(raw), set(LANES))
        self.assertEqual(set(reviewed), set(LANES))
        for lane in LANES:
            with self.subTest(lane=lane):
                raw_path, manifest = raw[lane]
                reviewed_path, record = reviewed[lane]
                self.assertEqual(record["schema_version"], 1)
                self.assertEqual(record["run_url"], RUN)
                self.assertEqual(record["candidate_sha"], CANDIDATE)
                self.assertEqual(manifest["candidate_sha"], CANDIDATE)
                self.assertEqual(record["native_manifest_artifact_name"], f"dockerlens-native-{lane}")
                self.assertEqual(record["native_manifest_sha256"], raw_path.stem)
                identity = record["identity"]
                self.assertEqual(identity["engine_release"], manifest["engine_version"])
                self.assertEqual(identity["advertised_api"], manifest["engine_api_max"])
                self.assertEqual(identity["acquisition_api"], manifest["acquisition_api"])
                self.assertEqual(identity["rendering_api"], manifest["rendering_api"])
                self.assertEqual(identity["mode"], manifest["expected_mode"])
                self.assertEqual(identity["mode"], lane.rsplit("-", 1)[1])
                if lane.startswith("debian11-"):
                    self.assertEqual(identity["build"], {
                        "kind": "debian-package", "distribution": "debian11",
                        "package_name": "docker.io",
                        "package_revision": manifest["debian_docker_package"],
                    })
                else:
                    self.assertEqual(identity["build"], {"kind": "upstream"})
                    self.assertIsNone(manifest["debian_docker_package"])
                capabilities = {entry["name"]: entry for entry in record["capabilities"]}
                self.assertEqual(set(capabilities), set(SHAPES))
                self.assertEqual(sum(map(len, SHAPES.values())), 20)
                for name, shapes in SHAPES.items():
                    self.assertEqual(capabilities[name]["state"], "available")
                    self.assertEqual(capabilities[name]["admitted_shapes"], shapes)
                    self.assertEqual(manifest["capability_outcome"][name], "available")
                    self.assertEqual(manifest["admitted_shapes"][name], shapes)
                self.assertEqual(len(reviewed_path.stem), 64)

    def test_evidence_is_in_published_package_rule(self) -> None:
        manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('"docs/**"', manifest)


if __name__ == "__main__":
    unittest.main()
