"""UID context is independently observed, bounded and never a software pin."""

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("daemon_uid", ROOT / "scripts/native-daemon-uid.py")
UID = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UID)


class DaemonUidTests(unittest.TestCase):
    def test_exact_uid_output_mode_and_u32_bounds(self):
        self.assertEqual(UID.uid(b"0\n", b"", 0, "rootful"), 0)
        self.assertEqual(UID.uid(b"1000\n", b"", 0, "rootless"), 1000)
        self.assertEqual(UID.uid(b"4294967295\n", b"", 0, "rootless"), 4294967295)
        for stdout, stderr, status, mode in (
            (b"", b"", 0, "rootful"), (b"0", b"", 0, "rootful"),
            (b"00\n", b"", 0, "rootful"), (b"0\n0\n", b"", 0, "rootful"),
            (b"0\n", b"private-canary", 0, "rootful"), (b"0\n", b"", 1, "rootful"),
            (b"1\n", b"", 0, "rootful"), (b"0\n", b"", 0, "rootless"),
            (b"4294967296\n", b"", 0, "rootless"), (b"-1\n", b"", 0, "rootless"),
            (b"1000\n", b"", 0, "unknown"), (b"private-canary\n", b"", 0, "rootless"),
        ):
            with self.subTest(stdout=stdout, mode=mode):
                with self.assertRaisesRegex(ValueError, "^invalid daemon UID evidence$"):
                    UID.uid(stdout, stderr, status, mode)

    def test_root_owns_the_fixed_timeout_and_only_exact_outer_is_queried(self):
        with patch.object(UID.os, "geteuid", return_value=1000):
            args = UID.command("a" * 64)
            self.assertEqual(args[:9], ["sudo", "-n", "timeout", "--signal=TERM", "--kill-after=2s",
                                        "8s", "podman", "exec", "a" * 64])
        with patch.object(UID.os, "geteuid", return_value=0):
            self.assertEqual(UID.command("b" * 64)[:4], ["timeout", "--signal=TERM", "--kill-after=2s", "8s"])
        for value in ("", "a" * 63, "A" * 64, "private; command"):
            with self.assertRaisesRegex(ValueError, "^invalid daemon UID context$"):
                UID.command(value)
        with patch.object(UID.subprocess, "Popen") as start:
            with self.assertRaises(ValueError):
                UID.observe("a" * 64, "unknown")
            start.assert_not_called()
