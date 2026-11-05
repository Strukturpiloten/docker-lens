#!/usr/bin/env python3
"""Provision development-only tools from the immutable shared source inventory."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from boxferry_ci import bootstrap, renovate_runtime, tooling

ROOT = Path(__file__).resolve().parents[1]
MAX_NODE_METADATA = 64 * 1024


class SetupError(ValueError):
    """A canonical prerequisite is unavailable; never substitute an ambient version."""


def _metadata(repository: Path, revision: str, relative: str) -> str:
    """Read a bounded regular Git blob only after checking its mode, type and size."""
    listing = bootstrap.run_git(repository, "ls-tree", "-z", revision, "--", relative, binary=True)
    if not isinstance(listing, bytes):
        raise SetupError("canonical Node metadata has no regular Git blob")
    match = re.fullmatch(
        rb"(?:100644|100755) blob ([a-f0-9]{40})\t" + re.escape(relative.encode()) + rb"\x00",
        listing,
    )
    if match is None:
        raise SetupError("canonical Node metadata has no regular Git blob")
    oid = match[1].decode("ascii")
    kind = bootstrap.run_git(repository, "cat-file", "-t", oid)
    size = bootstrap.run_git(repository, "cat-file", "-s", oid)
    if kind != "blob" or not isinstance(size, str) or not re.fullmatch(r"[0-9]{1,5}", size):
        raise SetupError("canonical Node metadata has invalid Git type or size")
    if not 0 < int(size) <= MAX_NODE_METADATA:
        raise SetupError("canonical Node metadata exceeds its read budget")
    data = bootstrap.run_git(repository, "cat-file", "blob", oid, binary=True)
    if not isinstance(data, bytes) or len(data) != int(size):
        raise SetupError("canonical Node metadata changed during its bounded read")
    return data.decode("utf-8")


def canonical_nodes() -> tuple[str, str, str]:
    """Derive CI and Dev Container versions from the same verified immutable source.

    Interface-1 archives retain Cargo metadata but do not export producer CI YAML.
    Read that DATA from their already verified Git object cache, never current main
    or an ancestor repository. A changed producer layout must fail explicitly.
    """
    try:
        revision = bootstrap.load_config(ROOT)["revision"]
        identity = bootstrap.automation_identity(ROOT, revision)
        project = Path(bootstrap.__file__).absolute().parents[2]
        if identity["kind"] == "interface-1-archive":
            repository = ROOT / "target/boxferry-automation" / f"{revision}.git"
        elif identity["kind"] == "git-checkout":
            repository = project.parent
        else:
            raise SetupError("Node authority must be immutable shared source")
        ci = _metadata(repository, revision, ".github/workflows/ci.yml")
        image = _metadata(repository, revision, ".devcontainer/Dockerfile")
        ci_values = re.findall(r"^[ \t]*node-version:[ \t]*([^\r\n]*)$", ci, re.MULTILINE)
        stages = re.findall(r"^FROM [^\r\n]+ AS node_toolchain$", image, re.MULTILINE)
        if (
            len(ci_values) != 1
            or len(stages) != 1
            or re.search(r"^[ \t]*node-version-file:", ci, re.MULTILINE)
        ):
            raise SetupError("canonical Node versions are missing or ambiguous")
        ci_version = ci_values[0].strip()
        image_match = re.fullmatch(
            r"FROM docker\.io/library/node:([0-9]+\.[0-9]+\.[0-9]+)-[a-z0-9.-]+"
            r"@sha256:[a-f0-9]{64} AS node_toolchain",
            stages[0],
        )
        if (
            len(ci_version) > 64
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", ci_version) is None
            or image_match is None
            or len(image_match[1]) > 64
        ):
            raise SetupError("canonical Node versions must be exact numeric releases")
        return revision, ci_version, image_match[1]
    except SetupError:
        raise
    except (bootstrap.BootstrapError, OSError, UnicodeError, ValueError, KeyError):
        raise SetupError(
            "canonical Node authority is unavailable; verify the manifest-selected shared source"
        ) from None


def node_preflight(context: str) -> tuple[str, str, str]:
    """Require exact context membership and bind the actual absolute executable."""
    revision, ci, image = canonical_nodes()
    allowed = (ci,) if context == "hosted" else tuple(dict.fromkeys((ci, image)))
    expected = ", ".join(allowed)
    guidance = (
        f"required Node {expected} for {context} from automation {revision}; "
        "run the hosted setup-node composite or use a reviewed local Node installation, then rerun"
    )
    selected = shutil.which("node")
    if selected is None:
        raise SetupError(f"Node prerequisite missing; {guidance}")
    try:
        executable = str(Path(selected).resolve(strict=True))
        output = renovate_runtime.run_command((executable, "--version"), 10)
    except (OSError, renovate_runtime.RenovateRuntimeError):
        raise SetupError(f"Node version check failed or timed out; {guidance}") from None
    match = re.fullmatch(r"v([0-9]+\.[0-9]+\.[0-9]+)\r?\n?", output)
    if match is None or len(match[1]) > 64:
        raise SetupError(f"Node returned an invalid version; {guidance}")
    version = match[1]
    if version not in allowed:
        raise SetupError(f"Node version v{version} is not selected; {guidance}")
    return executable, version, revision


def _runtime_command(node: str, argv: Sequence[str], timeout: float) -> str:
    command = (node, *argv[1:]) if argv and argv[0] == "node" else argv
    return renovate_runtime.run_command(command, timeout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("podman", "docker"))
    parser.add_argument("--cargo-tools", action="store_true")
    parser.add_argument("--node-context", choices=("local", "hosted"), default="local")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--node-version", action="store_true")
    modes.add_argument("--verify-node", action="store_true")
    options = parser.parse_args(argv)
    if (options.node_version or options.verify_node) and (options.engine or options.cargo_tools):
        parser.error("Node query/preflight modes do not provision tools or accept an engine")
    if not (options.node_version or options.verify_node) and options.engine is None:
        parser.error("tool provisioning requires an explicit --engine")
    stage = "Node prerequisite"
    version = "unverified"
    image = "unresolved shared runtime"
    try:
        if options.node_version:
            revision, ci, local = canonical_nodes()
            print(ci if options.node_context == "hosted" else ", ".join(dict.fromkeys((ci, local))))
            if options.node_context == "hosted" and os.environ.get("GITHUB_OUTPUT"):
                with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
                    output.write(f"node_version={ci}\n")
            return 0
        node, version, revision = node_preflight(options.node_context)
        if options.verify_node:
            print(f"Verified Node {version} for {options.node_context} at automation {revision}")
            return 0
        shared = Path(tooling.__file__).resolve().parents[3]
        tools = ROOT / "target/shared-tools"
        stage = "Renovate runtime metadata"
        pin = shared / "automation/renovate-runtime.json"
        with pin.open("rb") as stream:
            data = stream.read(4097)
        if len(data) > 4096:
            raise SetupError("canonical Renovate runtime identity exceeds its read budget")
        record = json.loads(data)
        if not isinstance(record, dict) or not isinstance(record.get("image"), str):
            raise SetupError("canonical Renovate runtime identity is unavailable")
        image = record["image"]
        if len(image) > 256 or renovate_runtime.IMAGE_PATTERN.fullmatch(image) is None:
            raise SetupError("canonical Renovate runtime identity is invalid")
        stage = "file tool installation"
        tooling.install(tools / "bin", ("actionlint", "shfmt", "shellcheck"))
        stage = "Renovate runtime preparation/native RE2 verification"
        renovate_runtime.prepare_runtime(
            pin,
            ROOT / "target/tools/renovate",
            engine=options.engine,
            command=lambda command, timeout: _runtime_command(node, command, timeout),
        )
        if options.cargo_tools:
            stage = "Cargo tool installation"
            inventory = (shared / ".devcontainer/Dockerfile").read_text(encoding="utf-8")
            for key, package in (
                ("CARGO_DENY", "cargo-deny"),
                ("CARGO_SEMVER_CHECKS", "cargo-semver-checks"),
            ):
                found = re.findall(
                    r"^ARG " + key + r"_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$", inventory, re.M
                )
                if len(found) != 1:
                    raise SetupError(f"canonical {package} version is missing or ambiguous")
                subprocess.run(
                    ["cargo", "install", "--locked", "--version", found[0], package],
                    check=True,
                    timeout=900,
                )
        if os.environ.get("GITHUB_PATH"):
            with Path(os.environ["GITHUB_PATH"]).open("a", encoding="utf-8") as output:
                output.write(str(tools / "bin") + "\n")
        return 0
    except SetupError as error:
        print(f"DockerLens tool setup: {error}", file=sys.stderr)
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ):
        print(
            f"DockerLens tool setup: {stage} failed with Node {version}, engine {options.engine}, "
            f"runtime {image}; check the selected prerequisites and rerun. "
            "The child failure reason is unavailable; no alternate Node or engine was selected.",
            file=sys.stderr,
        )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
