"""Logging component CLI/private evidence; shared integration is tested separately."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_native_logging_proof import LANES, fixture, mutations, rebind
import native_logging_proof as reader

ROOT = Path(__file__).resolve().parents[1]


class LoggingEvidenceTests(unittest.TestCase):
    def run_reader(self, lane="upstream-rootful", backend="podman", fault=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            proof = fixture(lane, outer_backend=backend)
            context = proof["context"]
            context["outer"]["socket_source"] = str(root / "socket")
            path = root / "logging-v1.json"
            arguments = [str(root), context["candidate_sha"], context["run_id"], lane,
                         context["engine_release"], context["rendering_api"], context["mode"],
                         context["docker_package"], context["fixture_image"], context["outer"]["image"],
                         context["outer"]["id"], str(context["daemon_uid"])]
            if fault in mutations():
                mutations()[fault](proof)
                rebind(proof)
            path.write_text(json.dumps(proof, separators=(",", ":")))
            path.chmod(0o600)
            if fault == "missing-file":
                path.unlink()
            elif fault == "private-mode":
                path.chmod(0o644)
            elif fault == "duplicate-json":
                path.write_text('{"schema_version":1,"schema_version":1}')
            elif fault == "argument-count":
                arguments.pop()
            elif fault == "argument-candidate":
                arguments[1] = "e" * 40
            elif fault == "argument-uid-bool":
                arguments[-1] = "True"
            elif fault == "argument-uid-leading-zero":
                arguments[-1] = "00"
            environment = {**os.environ, "NATIVE_OUTER_ENGINE": backend}
            if fault == "backend-missing":
                environment.pop("NATIVE_OUTER_ENGINE")
            elif fault == "backend-auto":
                environment["NATIVE_OUTER_ENGINE"] = "auto"
            result = subprocess.run([sys.executable, str(ROOT / "scripts/native_logging_proof.py"), *arguments],
                                    env=environment, capture_output=True, timeout=5, check=False)
            self.assertEqual(list(root.glob("native-evidence*")), [])
            return result

    def test_standalone_twelve_argument_reader_all_lanes_and_outer_backends(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                with self.subTest(lane=lane, backend=backend):
                    result = self.run_reader(lane, backend)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((result.stdout, result.stderr), (b"", b""))

    def test_missing_false_semantics_custody_context_and_backend_refuse_opaquely(self):
        faults = ["missing-file", "private-mode", "duplicate-json", "argument-count", "argument-candidate",
                  "argument-uid-bool", "argument-uid-leading-zero", "backend-missing", "backend-auto",
                  "none-empty-success", "none-permission", "none404", "none-timeout", "canary-rebound",
                  "max-size", "wrong-owner", "borrowed-delete", "unknown-key"]
        # Keep mutation names independently explicit and fail on fixture drift.
        for name in faults[9:]:
            self.assertIn(name, mutations())
        for fault in faults:
            with self.subTest(fault=fault):
                result = self.run_reader(fault=fault)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"invalid private logging proof\n")

    def test_reader_returns_exact_typed_non_admitting_shape_without_native_data(self):
        for backend in ("podman", "docker"):
            proof = fixture(outer_backend=backend)
            expected = {"contract": "logging-v1", "capability_admission": [], "catalogue_admission": False}
            result = reader.validate_logging_proof(proof, deepcopy(proof["context"]), outer_backend=backend)
            self.assertEqual(result, expected)
            self.assertIs(type(result), dict)
            self.assertIs(type(result["contract"]), str)
            self.assertIs(type(result["capability_admission"]), list)
            self.assertIs(type(result["catalogue_admission"]), bool)
            serialized = json.dumps(result)
            for private in (proof["context"]["run_id"], "raw", "frame", "ordinary_calls", "dl-log-", "max-size"):
                self.assertNotIn(private, serialized)
            for extra in ({"catalogue_admission": 0}, {"capability_admission": ["LogConfig"]}, {"PRIVATE_LOGGING_CANARY": True}):
                changed = deepcopy(proof)
                changed.update(extra)
                with self.assertRaisesRegex(ValueError, "invalid private logging proof"):
                    reader.validate_logging_proof(changed, proof["context"], outer_backend=backend)

    def test_standalone_main_binds_external_context_and_backend_to_held_reader(self):
        proof = fixture()
        context = proof["context"]
        arguments = ["/private/capture", context["candidate_sha"], context["run_id"], context["lane"],
                     context["engine_release"], context["rendering_api"], context["mode"], context["docker_package"],
                     context["fixture_image"], context["outer"]["image"], context["outer"]["id"], str(context["daemon_uid"])]
        context = deepcopy(context)
        context["outer"]["socket_source"] = "/private/capture/socket"
        with patch.dict(os.environ, {"NATIVE_OUTER_ENGINE": "podman"}, clear=True), patch.object(reader, "read_logging_proof") as held:
            reader.main(arguments)
        held.assert_called_once_with(Path("/private/capture/logging-v1.json"), "/private/capture", context, outer_backend="podman")


if __name__ == "__main__":
    unittest.main()
