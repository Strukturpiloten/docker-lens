#!/usr/bin/env python3
"""Emit closed, reviewable native evidence only after all lane checks pass."""

import json
import re
import sys
from pathlib import Path


CAPABILITIES = (
    "StandaloneContainer", "NamedVolume", "BridgeNetwork", "PortPublish",
    "BindMount", "EnvironmentAssignment", "Command", "Entrypoint",
    "Healthcheck", "RestartPolicy",
)
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")


def emit(version_path: Path, destination: Path, lane: str, image: str,
         mode: str, package: str, candidate_sha: str) -> None:
    if lane not in LANES or mode != lane.rsplit("-", 1)[1]:
        raise ValueError("invalid native lane or mode")
    if not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
        raise ValueError("invalid candidate SHA")
    if not re.fullmatch(
        r"ghcr\.io/strukturpiloten/docker-(?:debian-11|29)-(?:rootful|rootless):"
        r"v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}", image,
    ) or image.rsplit("/", 1)[1].split(":", 1)[0] != "docker-" + (
        "debian-11" if lane.startswith("debian11-") else "29"
    ) + "-" + mode:
        raise ValueError("invalid native image identity")
    if lane.startswith("debian11-"):
        if package != "20.10.5+dfsg1-1+deb11u2":
            raise ValueError("invalid Debian package revision")
    elif package:
        raise ValueError("upstream image has no Debian Engine package")

    version = json.loads(version_path.read_text(encoding="utf-8"))
    engine = version.get("Version")
    maximum = version.get("ApiVersion")
    minimum = version.get("MinAPIVersion")
    expected_engines = ("20.10.5", "20.10.5+dfsg1") if lane.startswith("debian11-") else ("29.8.1",)
    if engine not in expected_engines:
        raise ValueError("unexpected Engine release")
    if not all(isinstance(value, str) and re.fullmatch(r"1\.[0-9]{1,3}", value)
               for value in (maximum, minimum)):
        raise ValueError("invalid Engine API bounds")
    selected = min(int(maximum.split(".")[1]), 49)
    if selected < 41 or int(minimum.split(".")[1]) > selected:
        raise ValueError("Engine API cannot be acquired")

    components = version.get("Components", [])
    if not isinstance(components, list):
        raise ValueError("invalid runtime components")
    runtime_components = {}
    for name in ("containerd", "runc"):
        matches = [item.get("Version") for item in components
                   if isinstance(item, dict) and item.get("Name") == name]
        if len(matches) > 1:
            raise ValueError("duplicate runtime component")
        value = matches[0] if matches else None
        if value is not None and (not isinstance(value, str) or
                                  not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,79}", value)):
            raise ValueError("invalid runtime component version")
        runtime_components[name] = value

    record = {
        "schema_version": 1,
        "lane": lane,
        "candidate_sha": candidate_sha,
        "outer_image": image,
        "expected_mode": mode,
        "engine_version": engine,
        "engine_api_max": maximum,
        "engine_api_min": minimum,
        "acquisition_api": f"1.{selected}",
        "rendering_api": maximum,
        "debian_docker_package": package or None,
        "runtime_components": runtime_components,
        "capability_version": maximum,
        "capability_outcome": {name: "available" for name in CAPABILITIES},
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 8:
        raise SystemExit("usage: native-evidence.py VERSION_JSON DESTINATION LANE IMAGE MODE PACKAGE SHA")
    try:
        emit(Path(sys.argv[1]), Path(sys.argv[2]), *sys.argv[3:])
    except (ValueError, OSError, json.JSONDecodeError):
        raise SystemExit("native evidence rejected") from None
