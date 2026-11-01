"""Mandatory device revalidation without a public projection or admission."""
from hashlib import sha256
import importlib.util
import inspect
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import test_native_evidence as legacy
import test_native_external_network_evidence as canonical
from test_native_command_clear_projection import expected_shapes
from test_native_device_mapping_proof import LANES, mutations

ROOT = Path(__file__).resolve().parents[1]


class DeviceMappingEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit
    emit = canonical.ExternalNetworkEvidenceTests.emit

    def rerun(self, result, path, backend):
        return subprocess.run(result.args, env={**os.environ, "NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                              "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                              "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if path.stem.endswith("-rootless") else "0",
                              "NATIVE_OUTER_ENGINE": backend}, capture_output=True, text=True, timeout=10, check=False)

    def test_all_lanes_and_backends_require_private_proof_without_public_admission(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                with self.subTest(lane=lane, backend=backend):
                    result, path = self.emit(lane, outer_backend=backend)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    record = json.loads(path.read_text())
                    self.assertEqual(record["admitted_shapes"], expected_shapes(lane))
                    self.assertEqual(len(result.args) - 2, 19)
                    for private in ("device_mapping", "device-mapping", "DeviceMappings", "dl-device-", "report_sha256", "held_fd", "ordinary_calls"):
                        self.assertNotIn(private, path.read_text())
                    result, path = self.emit(lane, outer_backend=backend, device_mapping_missing=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(path.exists())
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "native evidence rejected\n")

    def test_false_semantics_and_rebound_transcript_refuse_before_output(self):
        for name in ("permission", "swapped-roles", "symlink", "rdev", "read-failed", "timeout", "cancelled",
                     "candidate", "daemon-uid", "calls", "unknown-cleanup", "borrowed-removal", "private-extra"):
            with self.subTest(name=name):
                result, path = self.emit()
                self.assertEqual(result.returncode, 0, result.stderr)
                source = path.parent.parent / "device-mapping-v1.json"
                proof = json.loads(source.read_text())
                mutations()[name](proof)
                source.write_text(json.dumps(proof))
                path.unlink()
                rejected = self.rerun(result, path, "podman")
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(path.exists())
                self.assertEqual(rejected.stderr, "native evidence rejected\n")
                self.assertEqual(rejected.stdout, "")
        result, path = self.emit(outer_backend="docker")
        source = path.parent.parent / "device-mapping-v1.json"
        proof = json.loads(source.read_text())
        effect = proof["containers"][0]["effect"]
        effect["report"] = effect["report"].replace("read 0", "read 1")
        effect["report_sha256"] = sha256(effect["report"].encode()).hexdigest()
        source.write_text(json.dumps(proof)); path.unlink()
        self.assertNotEqual(self.rerun(result, path, "docker").returncode, 0)
        self.assertFalse(path.exists())

    def test_reader_result_has_exact_closed_typed_shape(self):
        spec = importlib.util.spec_from_file_location("device_mapping_emitter_control", ROOT / "scripts/native-evidence.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(len(inspect.signature(module.emit).parameters), 19)
        empty = {"contract": "device-mapping-v1", "capability_admission": [], "catalogue_admission": False}
        for backend in ("podman", "docker"):
            result, path = self.emit("upstream-rootless", outer_backend=backend)
            self.assertEqual(result.returncode, 0, result.stderr)
            path.unlink(); path.parent.rmdir()
            arguments = [Path(value) for value in result.args[2:15]] + result.args[15:]
            expected = json.loads((path.parent.parent / "device-mapping-v1.json").read_text())["context"]
            environment = {"NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                           "NATIVE_BIND_RELABEL_DAEMON_UID": "1000", "NATIVE_OUTER_ENGINE": backend}
            for invalid in (None, [], {}, {**empty, "extra": "PRIVATE_DEVICE_CANARY"}, {**empty, "contract": 1},
                            {**empty, "contract": "wrong"}, {**empty, "capability_admission": ()},
                            {**empty, "capability_admission": ["DeviceMappings"]},
                            {**empty, "catalogue_admission": True}, {**empty, "catalogue_admission": 0}):
                with (self.subTest(backend=backend, result=invalid), patch.dict(os.environ, environment, clear=True),
                      patch.object(module, "read_device_mapping_proof", return_value=invalid) as reader,
                      self.assertRaises(ValueError)):
                    module.emit(*arguments)
                self.assertFalse(path.parent.exists())
                reader.assert_called_once_with(path.parent.parent / "device-mapping-v1.json", path.parent.parent,
                                               expected, outer_backend=backend)
            with (patch.dict(os.environ, environment, clear=True),
                  patch.object(module, "read_device_mapping_proof", wraps=module.read_device_mapping_proof) as reader):
                module.emit(*arguments)
            self.assertTrue(path.exists())
            reader.assert_called_once_with(path.parent.parent / "device-mapping-v1.json", path.parent.parent,
                                           expected, outer_backend=backend)


if __name__ == "__main__":
    unittest.main()
