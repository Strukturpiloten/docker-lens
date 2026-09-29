#!/usr/bin/env python3
"""Closed host bridge-filter preflight for the isolated native validation harness.

The hosted-runner identity prevents accidental local module loading. It is not
authentication: a root caller can forge environment variables and alter the host.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Callable, Mapping


MODULE = Path("/sys/module/br_netfilter")
IPTABLES = Path("/proc/sys/net/bridge/bridge-nf-call-iptables")
IP6TABLES = Path("/proc/sys/net/bridge/bridge-nf-call-ip6tables")
LOAD = ("sudo", "-n", "timeout", "--signal=TERM", "--kill-after=2s", "10s",
        "modprobe", "br_netfilter")


class BridgePrerequisiteError(Exception):
    """The host does not meet this validation-only prerequisite."""


def hosted_main_native_job(environment: Mapping[str, str]) -> bool:
    return (
        environment.get("GITHUB_ACTIONS") == "true"
        and environment.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and environment.get("RUNNER_OS") == "Linux"
        and environment.get("GITHUB_REPOSITORY") == "Strukturpiloten/docker-lens"
        and environment.get("GITHUB_EVENT_NAME") in ("push", "workflow_dispatch")
        and environment.get("GITHUB_REF") == "refs/heads/main"
        and environment.get("GITHUB_JOB") == "native-conformance"
    )


def sysctl_state(path: Path) -> str:
    try:
        with path.open("r", encoding="ascii") as source:
            value = source.read(8)
    except (OSError, UnicodeError):
        return "unavailable"
    if value == "1\n" or value == "1":
        return "enabled"
    if value == "0\n" or value == "0":
        return "disabled"
    return "invalid"


def state(module: Path, iptables: Path, ip6tables: Path) -> tuple[str, str, str]:
    return (
        "present" if module.is_dir() else "absent",
        sysctl_state(iptables),
        sysctl_state(ip6tables),
    )


def bounded_module_command(
    command: list[str], *, check: bool, timeout: float, stdout: int, stderr: int,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
) -> subprocess.CompletedProcess[bytes]:
    """Root-owned timeout bounds modprobe; group kill is a fallback only."""
    if command != list(LOAD) or check or timeout <= 0 or stdout != subprocess.DEVNULL or stderr != subprocess.DEVNULL:
        raise BridgePrerequisiteError("module load command is not the reviewed bounded operation")
    process = popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
    try:
        status = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            # The runner may not signal sudo's root process group. The GNU
            # timeout *inside* sudo is the host-mutation deadline.
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise
    if status != 0:
        # A failed sudo can still leave a child behind; do not allow it to
        # perform a delayed host mutation after the helper reports failure.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    return subprocess.CompletedProcess(command, status)


def ensure_bridge_prerequisite(
    environment: Mapping[str, str],
    *,
    module: Path = MODULE,
    iptables: Path = IPTABLES,
    ip6tables: Path = IP6TABLES,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = bounded_module_command,
) -> str:
    """Return a closed success marker, never native command output or host values."""
    observed = state(module, iptables, ip6tables)
    if observed == ("present", "enabled", "enabled"):
        return "DOCKERLENS_NATIVE_HOST_NETWORK: bridge_filter=ready module_load=not-needed"
    if not hosted_main_native_job(environment):
        raise BridgePrerequisiteError(
            "bridge filter prerequisite unavailable in read-only local or untrusted context"
        )
    if observed[0] == "present":
        raise BridgePrerequisiteError(
            "bridge filter module is present but required iptables/ip6tables settings are not enabled"
        )
    try:
        result = run(
            list(LOAD),
            check=False,
            timeout=15,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BridgePrerequisiteError("bounded bridge filter module load failed") from error
    if result.returncode != 0:
        raise BridgePrerequisiteError("bounded bridge filter module load failed")
    if state(module, iptables, ip6tables) != ("present", "enabled", "enabled"):
        raise BridgePrerequisiteError("bridge filter post-load readback is not ready")
    return "DOCKERLENS_NATIVE_HOST_NETWORK: bridge_filter=ready module_load=hosted-only"


def main() -> int:
    try:
        print(ensure_bridge_prerequisite(os.environ))
        return 0
    except BridgePrerequisiteError as error:
        print(f"DOCKERLENS_NATIVE_HOST_NETWORK: failure={error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
