"""The same fixed host timer entry point used by native production callers."""
from pathlib import Path
import subprocess

TIMER = str(Path(__file__).resolve().parents[1] / "scripts/native_gnu_timeout.py")


def system_timer():
    return subprocess.check_output([TIMER, "--path"], text=True, timeout=5).strip()
