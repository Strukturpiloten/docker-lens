"""Explicit local-proof bounds never change legacy custody or output budgets."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "private_proof_bounds", ROOT / "scripts/native_network_attachment_proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


class ExplicitProofBounds(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve() / "capture"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / "bounded.json"

    def payload(self, size):
        data = json.dumps("x" * (size - 2)).encode()
        self.assertEqual(len(data), size)
        self.path.write_bytes(data)
        self.path.chmod(0o600)

    def read(self, **kwargs):
        def length(value, context):
            if type(value) is not str:
                raise ValueError("unexpected proof shape")
            return len(value)
        return PROOF.read_private_proof(
            self.path, self.directory, "bounded.json", None,
            length, **kwargs)

    def rejected(self, **kwargs):
        with self.assertRaisesRegex(ValueError, "^invalid private network attachment proof$"):
            self.read(**kwargs)

    def test_legacy_default_remains_16384_and_oversize_is_not_an_opt_in(self):
        self.payload(16384)
        self.assertEqual(self.read(), 16382)
        self.payload(16385)
        self.rejected()
        self.assertEqual(self.read(max_bytes=524288), 16383)
        # The scoped override cannot mutate the next caller's default.
        self.rejected()

    def test_exact_reviewed_ceiling_and_one_byte_over(self):
        self.payload(524288)
        self.assertEqual(self.read(max_bytes=524288), 524286)
        self.payload(524289)
        self.rejected(max_bytes=524288)

    def test_invalid_limit_refuses_before_any_file_open(self):
        for limit in (True, False, 0, -1, 524289, 2**128, 1.0, "524288", None):
            with self.subTest(limit=limit), patch.object(PROOF.os, "open") as opened:
                self.rejected(max_bytes=limit)
                opened.assert_not_called()

    def test_empty_short_and_growing_reads_fail_with_override(self):
        self.path.touch(mode=0o600)
        self.rejected(max_bytes=524288)
        self.payload(32768)
        for returned in (b"", b'"short"', b"x" * 524289):
            with self.subTest(length=len(returned)), patch.object(PROOF.os, "read", return_value=returned):
                self.rejected(max_bytes=524288)

    def test_larger_bound_preserves_modes_and_exclusive_file_identity(self):
        self.payload(32768)
        self.path.chmod(0o644)
        self.rejected(max_bytes=524288)
        self.path.chmod(0o600)
        alias = self.directory / "alias"
        os.link(self.path, alias)
        self.rejected(max_bytes=524288)
        alias.unlink()
        source = self.directory / "original"
        self.path.rename(source)
        self.path.symlink_to(source)
        self.rejected(max_bytes=524288)
        self.path.unlink()
        os.mkfifo(self.path, mode=0o600)
        self.rejected(max_bytes=524288)

    def test_real_growing_replaced_file_and_renamed_directory_fail(self):
        original_read = PROOF.os.read
        for iteration, mutation in enumerate(("grow", "replace", "rename_directory") * 2):
            with self.subTest(mutation=mutation, iteration=iteration):
                self.payload(32768)
                completed = []

                def changed_read(descriptor, count):
                    payload = original_read(descriptor, count)
                    if mutation == "grow":
                        with self.path.open("ab") as output:
                            output.write(b" ")
                    elif mutation == "replace":
                        replacement = self.directory / "replacement"
                        replacement.write_bytes(payload)
                        replacement.chmod(0o600)
                        replacement.replace(self.path)
                    else:
                        destination = self.directory.with_name(f"renamed-{iteration}")
                        self.assertEqual(destination.parent, Path(self.temporary.name).resolve())
                        self.directory.rename(destination)
                        self.directory.mkdir(mode=0o700)
                    completed.append(mutation)
                    return payload

                with patch.object(PROOF.os, "read", side_effect=changed_read):
                    self.rejected(max_bytes=524288)
                # An OSError caught by the custody reader must not fake a
                # successful mutation witness followed by identity refusal.
                self.assertEqual(completed, [mutation])

    def test_directory_mode_and_owner_checks_still_apply_to_large_proof(self):
        self.payload(32768)
        self.directory.chmod(0o755)
        self.rejected(max_bytes=524288)
        self.directory.chmod(0o700)
        with patch.object(PROOF.os, "geteuid", return_value=os.geteuid() + 1):
            self.rejected(max_bytes=524288)

    def test_limit_is_encoded_bytes_not_unicode_characters(self):
        data = json.dumps("é", ensure_ascii=False).encode("utf-8")
        self.assertEqual(len(data), 4)
        self.path.write_bytes(data)
        self.path.chmod(0o600)
        self.rejected(max_bytes=3)
        self.assertEqual(self.read(max_bytes=4), 1)
        data = json.dumps("\n").encode()
        self.assertEqual(len(data), 4)
        self.path.write_bytes(data)
        self.rejected(max_bytes=3)
        self.assertEqual(self.read(max_bytes=4), 1)

    def test_larger_bound_preserves_json_and_domain_validation(self):
        for payload in (b'{"duplicate":1,"duplicate":2}', b'{', b'\xff', b'[' * 2000 + b']' * 2000):
            with self.subTest(payload=payload[:20]):
                self.path.write_bytes(payload)
                self.path.chmod(0o600)
                self.rejected(max_bytes=524288)
        self.payload(32768)
        with patch.object(PROOF.json, "loads", side_effect=RecursionError):
            self.rejected(max_bytes=524288)

    def test_shared_publisher_retains_legacy_default_and_same_ceiling(self):
        source = (ROOT / "src/native_health_metadata_tests.rs").read_text()
        self.assertIn("const PRIVATE_PROOF_LIMIT: usize = 16 * 1024;", source)
        self.assertIn("const MAX_PRIVATE_PROOF_LIMIT: usize = 512 * 1024;", source)
        publish = source.split("fn publish(&self, proof: &Value)", 1)[1].split("fn publish_bounded", 1)[0]
        self.assertIn("self.publish_bounded(proof, PRIVATE_PROOF_LIMIT);", publish)
        bounded = source.split("fn publish_bounded", 1)[1].split("#[test]", 1)[0]
        for required in ("self.check();", "private_proof_bytes(proof, max_bytes)", ".create_new(true)",
                         ".mode(0o600)", "libc::O_NOFOLLOW", "file.sync_all()", "named.nlink() == 1"):
            self.assertIn(required, bounded)


if __name__ == "__main__":
    unittest.main()
