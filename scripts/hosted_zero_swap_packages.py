"""Trusted host-only APT observations. Never transferred to or imported by the guest."""

import re
from contextlib import contextmanager

TARGETS = ("qemu-system-x86", "qemu-system-common", "qemu-system-data", "qemu-utils", "xorriso")


def messages(operation, stdout, stderr, versions):
    """Report recognized wording, never a causal verdict or native value."""
    text = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    lines = text.splitlines()
    facts = []
    patterns = {
        "permission": r"^(?:E:|W:).*Permission denied",
        "lock": r"^(?:E:|W:).*(?:Could not get lock|Unable to acquire .*lock)",
        "cache": r"^E:.*(?:package lists or status file could not be parsed or opened|Problem with MergeList)",
    }
    if operation == "update":
        patterns.update(
            fetch=r"^(?:E:|W:).*(?:Failed to fetch|Some index files failed to download)",
            authentication=r"^(?:E:|W:).*(?:NO_PUBKEY|signatures couldn't be verified|not signed|signature verification|[Cc]learsigned file isn't valid)",
            index_validity=r"^(?:E:|W:).*Release file.*(?:expired|not valid yet)",
            transport=r"^(?:E:|W:).*(?:Could not resolve|Temporary failure resolving|Could not connect|Unable to connect|Could not handshake|Connection refused|Connection timed out)",
        )
    elif operation == "plan":
        patterns.update(
            removal_disabled=r"^E: Packages need to be removed but remove is disabled\.$",
            unmet_dependencies=r"^(?:E: Unmet dependencies|The following packages have unmet dependencies:)",
            held_broken=r"^E:.*held broken packages",
            package_unavailable=r"^E: Unable to locate package ",
        )
        if any(
            line == f"E: Version '{version}' for '{name}' was not found"
            for name, version in versions.items()
            if name in TARGETS
            for line in lines
        ):
            facts.append("requested_version_missing")
    facts.extend(
        code
        for code, pattern in patterns.items()
        if any(re.search(pattern, line) for line in lines)
    )
    return facts or ["unclassified"]


def unobserved():
    return {
        name: {"installed": "unobserved", "wanted_archive_version": "unobserved"}
        for name in TARGETS
    }


def policy(raw, pins, archive, *, complete=False, status_file="/var/lib/dpkg/status"):
    """Only complete five-target records support facts; Candidate never selects a version."""
    unknown = unobserved()
    if not complete or not raw.endswith(b"\n"):
        return unknown
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        return unknown
    blocks = {}
    current = None
    for line in lines:
        if line and not line[0].isspace():
            if line not in [name + ":" for name in TARGETS] or line[:-1] in blocks:
                return unknown
            current = line[:-1]
            blocks[current] = []
        elif current is None:
            return unknown
        else:
            blocks[current].append(line)
    if tuple(blocks) != TARGETS:
        return unknown
    versions = pins["host_packages"]
    origin = archive + pins["apt_snapshot"]
    suite = pins["host_apt_suite"]
    suites = {suite, suite + "-updates", suite + "-security"}
    for name, block in blocks.items():
        if (
            len(block) < 5
            or not block[0].startswith("  Installed: ")
            or not block[1].startswith("  Candidate: ")
            or block[2] != "  Version table:"
        ):
            continue
        actual, candidate = block[0][13:], block[1][13:]
        version = r"[0-9][0-9A-Za-z.+:~\-]*"
        if any(
            value != "(none)" and not re.fullmatch(version, value) for value in (actual, candidate)
        ):
            continue
        entries = []
        invalid = False
        for line in block[3:]:
            row = re.fullmatch(r" +(\*\*\* )?(\S+) (-?[0-9]+)", line)
            if row:
                if not re.fullmatch(version, row[2]):
                    invalid = True
                    break
                entries.append([row[2], bool(row[1]), []])
            else:
                source = re.fullmatch(r" +(-?[0-9]+) (.+)", line)
                if source is None or not entries:
                    invalid = True
                    break
                entries[-1][2].append(source[2])
        if invalid or not entries or any(not entry[2] for entry in entries):
            continue
        selected = [entry for entry in entries if entry[1]]
        status = [entry for entry in entries if status_file in entry[2]]
        if actual == "(none)":
            if selected or status:
                continue
            installed = "none"
        else:
            if (
                len(selected) != 1
                or selected[0][0] != actual
                or len(status) != 1
                or status[0] is not selected[0]
            ):
                continue
            installed = "exact" if actual == versions[name] else "different"
        if candidate != "(none)" and candidate not in [entry[0] for entry in entries]:
            continue
        origins = set()
        present = False
        for value, _, sources in entries:
            for source in sources:
                key = (value, source)
                if key in origins:
                    invalid = True
                origins.add(key)
                if source == status_file:
                    continue
                parts = source.split(" ")
                if (
                    len(parts) != 4
                    or parts[0].rstrip("/") != origin
                    or parts[2:] != ["amd64", "Packages"]
                ):
                    invalid = True
                    continue
                pocket = parts[1].split("/")
                if (
                    len(pocket) != 2
                    or pocket[0] not in suites
                    or pocket[1] not in ("main", "universe")
                ):
                    invalid = True
                    continue
                if value == versions[name]:
                    present = True
        if not invalid:
            unknown[name]["installed"] = installed
            unknown[name]["wanted_archive_version"] = "present" if present else "absent"
    return unknown


def install(api, pins, work, deadline, result):
    """Observe only native failures after capture's original cleanup has settled."""
    current = None
    query = None

    def eligible():
        return (
            api["cancelled"] is None
            and not api["command_cleanup_failed"]
            and api["time"].monotonic() < deadline
        )

    def observe(name, error):
        result["host_package_messages"] = ["unobserved"]
        if name == "plan":
            result["host_package_policy"] = unobserved()
        try:
            if not eligible():
                return
            stdout, stderr = error._native_output
            if any(
                type(raw) is not bytes or len(raw) > api["OUTPUT_LIMIT"] for raw in (stdout, stderr)
            ):
                return
            result["host_package_messages"] = messages(name, stdout, stderr, pins["host_packages"])
            if (
                name != "plan"
                or query is None
                or tuple(pins["host_packages"]) != TARGETS
                or not eligible()
            ):
                return
            until = min(deadline, api["time"].monotonic() + 2)
            code, raw, err = api["capture"](query + ["policy", *TARGETS], until)
            if (
                code == 0
                and type(raw) is bytes
                and len(raw) <= api["OUTPUT_LIMIT"]
                and not err
                and eligible()
                and api["time"].monotonic() < until
            ):
                result["host_package_policy"] = policy(raw, pins, api["ARCHIVE"], complete=True)
        except Exception:
            # Diagnostics never replace the original Refusal, including cleanup errors.
            pass

    @contextmanager
    def operation(name):
        nonlocal current
        current = name
        result["host_package_operation"] = name
        try:
            yield
        except api["Refusal"] as error:
            if (
                name in ("update", "plan")
                and error.reason == "command_failed"
                and hasattr(error, "_native_output")
            ):
                observe(name, error)
            raise
        else:
            result.pop("host_package_operation")
        finally:
            current = None

    def run(argv, until):
        nonlocal query
        if current == "update":
            argv = [*argv[:-1], "--error-on=any", argv[-1]]
        elif current == "plan":
            query = [
                "apt-cache" if arg == "apt-get" else arg for arg in argv[: argv.index("--simulate")]
            ]
        return api["capture"](argv, until)

    return api["packages"](pins, "host", work, deadline, op=operation, run=run)
