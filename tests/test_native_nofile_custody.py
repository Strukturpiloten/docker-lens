"""Real bounded custody of complete synthetic proofs, never native evidence."""

import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

from test_native_nofile_proof import fixture, reader


class CompleteNofileCustody(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve() / "capture"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / "nofile-v1.json"

    def write(self, proof):
        payload = json.dumps(proof, ensure_ascii=False, separators=(",", ":")).encode()
        self.path.write_bytes(payload)
        self.path.chmod(0o600)
        return len(payload)

    def rejected(self, expected):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with self.assertRaisesRegex(ValueError, "^invalid private nofile proof$"):
                reader.read_nofile_proof(self.path, self.directory, expected, outer_backend="podman")
        self.assertEqual(output.getvalue(), "")

    def test_all_four_complete_maximum_inventory_proofs_use_real_shared_reader(self):
        for backend in ("podman", "docker"):
            for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
                with self.subTest(lane=lane, backend=backend):
                    proof = fixture(lane, baseline=16, maximal=True, outer_backend=backend)
                    before = reader.metadata_size(proof)
                    proof["context"]["outer"]["socket_source"] = "/" + "x" * (
                        65536 - before + len(proof["context"]["outer"]["socket_source"]) - 8) + "/socket"
                    self.assertEqual(reader.metadata_size(proof), 65536)
                    length = self.write(proof)
                    self.assertGreater(length, 16384)
                    self.assertLessEqual(length, 524288)
                    self.assertEqual(reader.read_nofile_proof(self.path, self.directory, proof["context"],
                                                            outer_backend=backend),
                                     {"contract": "nofile-v1", "capability_admission": [], "catalogue_admission": False})

    def test_complete_proof_wrong_context_and_private_mode_fail_silently(self):
        proof = fixture(baseline=16, maximal=True)
        self.assertGreater(self.write(proof), 16384)
        expected = deepcopy(proof["context"])
        expected["candidate_sha"] = "e" * 40
        self.rejected(expected)
        self.path.chmod(0o644)
        self.rejected(proof["context"])
        self.path.chmod(0o600)
        original = self.directory / "original"
        self.path.rename(original)
        self.path.symlink_to(original)
        self.rejected(proof["context"])

    def test_oversized_and_incomplete_full_inventory_cannot_become_admission(self):
        proof = fixture(baseline=16, maximal=True)
        self.write(proof)
        with self.path.open("ab") as output:
            output.write(b" " * (524289 - self.path.stat().st_size))
        self.rejected(proof["context"])
        proof["cases"][0]["containers"][0]["effect"]["witness"]["descriptors"]["restored"].pop()
        self.write(proof)
        self.rejected(proof["context"])


if __name__ == "__main__":
    unittest.main()
