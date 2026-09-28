"""Effective mount-flag admission for the historical Debian rootless lane."""

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native-storage-options.py"
DESTINATION = "/home/docker/.local/share/docker"


def mountinfo(options: str, destination: str = DESTINATION) -> str:
    return f"18 7 0:42 / {destination} {options} - ext4 /dev/private-store rw\n"


class NativeStorageOptionsTests(unittest.TestCase):
    def test_requires_one_effective_writable_suid_dev_mount(self) -> None:
        cases = (
            (mountinfo("rw,relatime"), True),
            (mountinfo("rw,nosuid,relatime"), False),
            (mountinfo("rw,nodev,relatime"), False),
            (mountinfo("ro,relatime"), False),
            (mountinfo("rw,ro,relatime"), False),
            (f"18 7 0:42 / {DESTINATION} rw\n", False),
            (mountinfo("rw").replace(" - ", " malformed "), False),
            (mountinfo("rw").replace(" rw\n", "\n"), False),
            (mountinfo("rw,relatime", "/other"), False),
            (mountinfo("rw,relatime") * 2, False),
        )
        for source, admitted in cases:
            with self.subTest(source=source):
                result = subprocess.run(
                    ["python3", str(SCRIPT), DESTINATION],
                    input=source + "protected-secret\n",
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, admitted)
                self.assertEqual(result.stdout + result.stderr, "")


if __name__ == "__main__":
    unittest.main()
