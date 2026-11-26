#!/usr/bin/env python3
"""Build only the test witness; never execute it or install a target/toolchain.

The caller supplies the original CLOCK_MONOTONIC deadline and an existing private
output directory. A successful manifest is an artifact receipt, not native proof.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time


MAX_BINARY = 8 * 1024 * 1024
MAX_LOG = 1024 * 1024
CLEANUP_NS = 46_000_000_000
MAX_RUN_NS = 180_000_000_000
TARGETS = {
    "x86_64": ("x86_64-unknown-linux-gnu", 62),
    "aarch64": ("aarch64-unknown-linux-gnu", 183),
}
FLAGS = "-C target-feature=+crt-static -C panic=abort -C strip=symbols"
# Cargo owns LTO/embedded-bitcode coordination; keep these out of RUSTFLAGS.
PROFILE_SETTINGS = (("opt-level", "z"), ("lto", "fat"), ("codegen-units", 1))
OUTPUT = "native-pids-worker"
MANIFEST = "native-pids-worker.json"
LOG = "native-pids-worker-build.log"
_CANCEL_REQUESTED = False
MAX_SYSTEM_FILE = 32 * 1024 * 1024
MAX_TOOL_INPUTS = 128 * 1024 * 1024
MAX_LINK_RECORD = 65536
MAX_LINK_DEPS = 131072
MAX_WRAPPER = 16384
SYSTEM_ROOTS = (Path("/usr"), Path("/lib"), Path("/lib64"), Path("/bin"), Path("/nix/store"))
CRT_ROLES = {
    "crt1.o": "start", "Scrt1.o": "start", "rcrt1.o": "start",
    "crti.o": "init", "crtn.o": "fini", "crtbegin.o": "begin",
    "crtbeginS.o": "begin", "crtbeginT.o": "begin", "crtend.o": "end",
    "crtendS.o": "end", "libc.a": "libc", "libgcc.a": "gcc-runtime",
    "libgcc_eh.a": "gcc-eh",
}
TOOL_FILES = ("native-pids-worker-driver.py", "native-pids-worker-ld.py",
              "native-pids-worker-link.json", "native-pids-worker-link.d")


class Refused(Exception):
    """Only closed, value-free phases may escape the builder."""


def inspect_elf(data, machine):
    """Bounded ELF64 little-endian parser; static PIE dynamic metadata is legal.

    Program headers, including PT_DYNAMIC, are authoritative. Section names and
    external tools are deliberately unnecessary. Reject extended header counts.
    """
    if not 64 <= len(data) <= MAX_BINARY:
        raise Refused("elf")
    if data[:7] != b"\x7fELF\x02\x01\x01":
        raise Refused("elf")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    _, kind, actual_machine, version, _, phoff, _, _, ehsize, phsize, phnum, _, _, _ = header
    if (kind not in (2, 3) or actual_machine != machine or version != 1
            or ehsize != 64 or phsize != 56 or not 1 <= phnum <= 128
            or phoff < ehsize or phoff + phsize * phnum > len(data)):
        raise Refused("elf")
    loads = 0
    dynamics = 0
    for index in range(phnum):
        ptype, _, offset, _, _, size, memsize, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phsize)
        if offset > len(data) or size > len(data) - offset or memsize < size:
            raise Refused("elf")
        if ptype == 1:  # PT_LOAD
            loads += 1
        if ptype == 3:  # PT_INTERP
            raise Refused("loader")
        if ptype == 2:  # PT_DYNAMIC; static PIE may have relative relocations
            dynamics += 1
            if dynamics > 1 or size == 0 or size % 16 or size > 65536:
                raise Refused("elf")
            terminated = False
            for dynamic in range(offset, offset + size, 16):
                tag, _ = struct.unpack_from("<qQ", data, dynamic)
                if tag == 1:  # DT_NEEDED
                    raise Refused("loader")
                if tag == 0:
                    terminated = True
                    break
            if not terminated:
                raise Refused("elf")
    if not loads:
        raise Refused("elf")
    return {"class": 64, "endianness": "little", "machine": machine,
            "pt_interp": False, "dt_needed": False}


def regular_bytes(path, limit, owner=None):
    """Strict artifact/source reader: exactly one owned regular-file link."""
    return _stable_regular_bytes(path, limit, owner, (1,))


def compiler_bytes(path, limit):
    """Snapshot only a private compiler output, which Cargo may hardlink twice.

    This is not an artifact reader. Its bytes must pass ELF inspection and be
    copied through O_EXCL into a fresh single-link artifact before acceptance.
    """
    return _stable_regular_bytes(path, limit, None, (1, 2))


def _stable_regular_bytes(path, limit, owner, allowed_links):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink not in allowed_links
                or before.st_uid != (os.geteuid() if owner is None else owner)
                or before.st_size <= 0 or before.st_size > limit):
            raise Refused("artifact")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns,
                              s.st_ctime_ns, s.st_nlink, s.st_mode, s.st_uid)
        if (len(data) != before.st_size or len(data) > limit
                or identity(before) != identity(after) or identity(after) != identity(named)):
            raise Refused("artifact")
        return bytes(data)
    finally:
        os.close(fd)


def private_directory(path):
    path = Path(path)
    if not path.is_absolute():
        raise Refused("output")
    # Reject symlink ancestors as well as a symlink at the final component.
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise Refused("output")
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.geteuid()):
        raise Refused("output")
    return path


def reserve(deadline):
    if _CANCEL_REQUESTED:
        raise Refused("cancelled")
    remaining = deadline - time.monotonic_ns()
    if remaining <= CLEANUP_NS or remaining > MAX_RUN_NS:
        raise Refused("deadline")


def command(argv, env, deadline, log, guarded=()):
    """Capture a bounded private compiler log without waiting past work cutoff."""
    reserve(deadline)
    process = None
    captured = bytearray()
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env=env, start_new_session=True)
        # CLI cancellation records a flag instead of throwing through Popen's
        # constructor. Once its child is owned here, ordinary refusal unwinds
        # through the exact process-group cleanup below.
        reserve(deadline)
        guard_metadata(guarded)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                reserve(deadline)
                guard_metadata(guarded)
                timeout = min(0.05, max(0, (deadline - CLEANUP_NS - time.monotonic_ns()) / 1e9))
                for key, _ in selector.select(timeout):
                    block = os.read(key.fd, 8192)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    if len(log) + len(block) > MAX_LOG:
                        raise Refused("build-log")
                    log.extend(block)
                    captured.extend(block)
            while True:
                reserve(deadline)
                guard_metadata(guarded)
                timeout = min(0.05, (deadline - CLEANUP_NS - time.monotonic_ns()) / 1e9)
                if timeout <= 0:
                    raise Refused("deadline")
                try:
                    status = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    continue
                if status != 0:
                    raise Refused("compiler")
                reserve(deadline)
                break
        return bytes(captured)
    finally:
        if process is not None:
            try:
                if process.returncode is None:
                    # Keep an unreaped leader's PID reserved until the group
                    # signal; poll() here could reap it before group cleanup.
                    # Build subprocess group only, never a native workload.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=max(0.001, (deadline - time.monotonic_ns()) / 1e9))
                    except subprocess.TimeoutExpired as error:
                        raise Refused("cleanup") from error
            finally:
                process.stdout.close()


def guard_metadata(paths):
    for path, limit in paths:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_size > limit):
            raise Refused("build-tools")


def system_path(path, *, tool_alias=False):
    path = Path(path)
    if (not path.is_absolute() or len(str(path)) > 4096
            or (not tool_alias and not any(Path(os.path.normpath(path)).is_relative_to(root) for root in SYSTEM_ROOTS))):
        raise Refused("build-tools")
    actual = path.resolve(strict=True)
    if not any(actual.is_relative_to(root.resolve()) for root in SYSTEM_ROOTS):
        raise Refused("build-tools")
    return actual


def file_identity(info):
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
            "gid": info.st_gid, "mode": info.st_mode, "links": info.st_nlink,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def native_gnu_target(reported, rust_target):
    """Accept explicit GNU Linux forms and two closed native vendor aliases.

    Keep the GCC spelling in the receipt; this predicate never canonicalizes an
    unknown Linux ABI into GNU or aliases a different CPU to the Rust target.
    """
    architecture = {"x86_64-unknown-linux-gnu": "x86_64",
                    "aarch64-unknown-linux-gnu": "aarch64"}.get(rust_target)
    if (architecture is None or not isinstance(reported, str) or not reported.isascii()
            or len(reported) > 128 or any(marker in reported.lower() for marker in ("musl", "uclibc", "android"))):
        return False
    if reported in (architecture + "-suse-linux", architecture + "-redhat-linux"):
        return True
    parts = reported.split("-")
    if parts[0] != architecture or parts[-2:] != ["linux", "gnu"]:
        return False
    if len(parts) == 3:
        return True
    return len(parts) == 4 and re.fullmatch(r"[A-Za-z0-9_.+]+", parts[1]) is not None


def system_file(path, deadline, remaining=MAX_TOOL_INPUTS, expected_kinds=None):
    path = system_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.geteuid())
                or before.st_mode & 0o7022 or not 0 < before.st_size <= min(MAX_SYSTEM_FILE, remaining)):
            raise Refused("build-tools")
        digest = hashlib.sha256()
        reserve(deadline)
        first = os.read(fd, min(64, before.st_size + 1))
        kind = ("elf" if first.startswith(b"\x7fELF") else "script" if first.startswith(b"#!")
                else "archive" if first.startswith(b"!<arch>\n") else "other")
        if expected_kinds is not None and kind not in expected_kinds:
            raise Refused("build-tools")
        digest.update(first)
        count = len(first)
        while count <= before.st_size:
            reserve(deadline)
            block = os.read(fd, min(65536, before.st_size + 1 - count))
            if not block:
                break
            count += len(block)
            digest.update(block)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (count != before.st_size or file_identity(before) != file_identity(after)
                or file_identity(after) != file_identity(named) or after.st_size != before.st_size
                or named.st_size != before.st_size):
            raise Refused("build-tools")
        hint = path.parts[3] if path.is_relative_to("/nix/store") and len(path.parts) > 3 else None
        return {"path": str(path), "file_kind": kind, "size": count, "sha256": digest.hexdigest(),
                "identity": file_identity(before),
                "package": {"status": "unavailable", "reason": "os-bootstrap-not-queried",
                            "unverified_path_hint": hint}}
    finally:
        os.close(fd)


def link_output(arguments):
    found = []
    for index, argument in enumerate(arguments):
        if argument in ("-o", "--output"):
            if index + 1 == len(arguments):
                raise Refused("build-tools")
            found.append(arguments[index + 1])
        elif argument.startswith("--output="):
            found.append(argument.split("=", 1)[1])
    if len(found) != 1 or not Path(found[0]).is_absolute():
        raise Refused("build-tools")
    return found[0]


def dependency_inputs(data, output):
    """Parse bounded GNU -M/-MP dependency rules, without evaluation or I/O."""
    if len(data) > MAX_LINK_DEPS:
        raise Refused("build-tools")
    text = data.decode("utf-8", "strict").replace("\\\n", " ")
    if any(character in text for character in ("\0", "\r", "$")):
        raise Refused("build-tools")
    rules = []
    for line in text.splitlines():
        if len(line) > MAX_LINK_DEPS:
            raise Refused("build-tools")
        words, word, escaped = [], [], False
        for character in line:
            if escaped:
                if character not in " \\#:\t":
                    raise Refused("build-tools")
                word.append(character)
                escaped = False
            elif character == "\\":
                escaped = True
            elif character in " \t:":
                if word:
                    words.append("".join(word)); word = []
                if character == ":":
                    words.append(":")
            elif character == "#":
                raise Refused("build-tools")
            else:
                word.append(character)
        if escaped:
            raise Refused("build-tools")
        if word:
            words.append("".join(word))
        if not words:
            continue
        if words.count(":") != 1 or words.index(":") != 1 or len(words) > 514:
            raise Refused("build-tools")
        rules.append((words[0], words[2:]))
        if len(rules) > 513:
            raise Refused("build-tools")
    if not rules or rules[0][0] != output or not rules[0][1]:
        raise Refused("build-tools")
    inputs = set(rules[0][1])
    if any(values or target not in inputs for target, values in rules[1:]):
        raise Refused("build-tools")
    if any(len(path) > 4096 for path in inputs):
        raise Refused("build-tools")
    return inputs


def require_unprivileged():
    if os.geteuid() == 0:
        raise Refused("build-tools")


def prepare_tools(scratch, target, env, deadline, log):
    require_unprivileged()
    # PATH may expose an OS profile symlink. Resolve only these two fixed tool
    # names, then require the actual executed entrypoint inside trusted roots.
    driver = system_path(shutil.which("gcc") or "", tool_alias=True)
    linker = system_path(shutil.which("ld.bfd") or "", tool_alias=True)
    files = {}
    for path in (driver, linker):
        record = system_file(path, deadline, MAX_TOOL_INPUTS - sum(value["size"] for value in files.values()), ("elf", "script"))
        if not record["identity"]["mode"] & 0o111:
            raise Refused("build-tools")
        files[str(path)] = record
    def query(arguments):
        raw = command(arguments, env, deadline, log)
        if len(raw) > 8192:
            raise Refused("build-tools")
        return raw.decode("utf-8", "strict").strip()
    driver_lines = query([str(driver), "--version"]).splitlines()
    linker_lines = query([str(linker), "--version"]).splitlines()
    if not driver_lines or not linker_lines:
        raise Refused("build-tools")
    driver_version, linker_version = driver_lines[0], linker_lines[0]
    native = query([str(driver), "-dumpmachine"])
    if ("gcc" not in driver_version.lower() or "clang" in driver_version.lower()
            or not linker_version.startswith("GNU ld")
            or not re.search(r"[0-9]+\.[0-9]+", driver_version)
            or not re.search(r"[0-9]+\.[0-9]+", linker_version)
            or len(driver_version) > 512 or len(linker_version) > 512
            or not native_gnu_target(native, target)):
        raise Refused("build-tools")
    crt = {}
    for name, role in CRT_ROLES.items():
        path = query([str(driver), "-print-file-name=" + name])
        if path == name:
            continue
        actual = system_path(path)
        if actual.name not in CRT_ROLES or CRT_ROLES[actual.name] != role:
            raise Refused("build-tools")
        if str(actual) not in files:
            kind = "archive" if actual.name.endswith(".a") else "elf"
            files[str(actual)] = system_file(actual, deadline, MAX_TOOL_INPUTS - sum(value["size"] for value in files.values()), (kind,))
        crt[str(actual)] = role
    if not {"start", "init", "fini", "begin", "end", "libc"}.issubset(crt.values()):
        raise Refused("build-tools")
    prefix = scratch / "linker"
    prefix.mkdir(mode=0o700)
    receipt, depfile = prefix / "invocation.json", prefix / "inputs.d"
    # GNU ld truncates this already-private regular file. Missing/empty output
    # still refuses after the build; no trace path is selected by caller input.
    exclusive_write(prefix, "inputs.d", b"", 0o600)
    target_root = scratch / "target"
    native_root = target_root / target / "release" / "examples"
    interpreter = str(Path(sys.executable).resolve())
    if any(character.isspace() for character in interpreter):
        raise Refused("build-tools")
    driver_source = (f"#!{interpreter}\nimport os,sys,time\n"
                     f"if os.geteuid()==0 or time.monotonic_ns()>={deadline - CLEANUP_NS}: raise SystemExit(1)\n"
                     f"os.execv({str(driver)!r},[{str(driver)!r},*sys.argv[1:],'-B'+{str(prefix) + '/'!r},'-fuse-ld=bfd'])\n").encode()
    linker_source = f'''#!{interpreter}
import json,os,re,sys,time
if os.geteuid()==0 or time.monotonic_ns()>={deadline - CLEANUP_NS}: raise SystemExit(1)
args=sys.argv[1:]
if len(json.dumps(args).encode())>{MAX_LINK_RECORD}: raise SystemExit(1)
if args in (['--version'],['-v'],['--help']): os.execv({str(linker)!r},[{str(linker)!r},*args])
outputs=[]
for i,a in enumerate(args):
    if a in ('-o','--output'):
        if i+1==len(args): raise SystemExit(1)
        outputs.append(args[i+1])
    elif a.startswith('--output='): outputs.append(a.split('=',1)[1])
if len(outputs)!=1 or not os.path.isabs(outputs[0]): raise SystemExit(1)
output=os.path.normpath(outputs[0])
if not output.startswith({str(target_root) + '/'!r}): raise SystemExit(1)
native=os.path.dirname(output)=={str(native_root)!r} and re.fullmatch(r'native[-_]pids[-_]worker-[0-9a-f]{{16}}',os.path.basename(output))
if native:
    if any(a.startswith('--dependency-file') for a in args): raise SystemExit(1)
    args.append('--dependency-file='+{str(depfile)!r})
    raw=(json.dumps({{'schema':'dockerlens-pids-link-v1','linker':{str(linker)!r},'output':output,'argv':args}},sort_keys=True,separators=(',',':'))+'\\n').encode()
    if len(raw)>{MAX_LINK_RECORD}: raise SystemExit(1)
    fd=os.open({str(receipt)!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        if os.write(fd,raw)!=len(raw): raise SystemExit(1)
        os.fsync(fd)
    finally: os.close(fd)
os.execv({str(linker)!r},[{str(linker)!r},*args])
'''.encode()
    if len(driver_source) > MAX_WRAPPER or len(linker_source) > MAX_WRAPPER:
        raise Refused("build-tools")
    exclusive_write(prefix, "driver", driver_source, 0o700)
    exclusive_write(prefix, "ld.bfd", linker_source, 0o700)
    return {"driver": {**files[str(driver)], "version": driver_version, "native_target": native},
            "linker": {**files[str(linker)], "version": linker_version}, "files": files, "crt": crt,
            "driver_source": driver_source, "linker_source": linker_source, "wrapper": prefix / "driver",
            "receipt": receipt, "depfile": depfile, "native_root": native_root,
            "guarded": ((receipt, MAX_LINK_RECORD), (depfile, MAX_LINK_DEPS))}


def finish_tools(plan, binary_path, binary, deadline):
    if (regular_bytes(plan["wrapper"], MAX_WRAPPER) != plan["driver_source"]
            or regular_bytes(plan["wrapper"].with_name("ld.bfd"), MAX_WRAPPER) != plan["linker_source"]):
        raise Refused("build-tools")
    raw = regular_bytes(plan["receipt"], MAX_LINK_RECORD)
    def closed_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Refused("build-tools")
            value[key] = item
        return value
    invocation = json.loads(raw, object_pairs_hook=closed_pairs)
    if (not isinstance(invocation, dict) or set(invocation) != {"schema", "linker", "output", "argv"}
            or invocation["schema"] != "dockerlens-pids-link-v1"
            or invocation["linker"] != plan["linker"]["path"]
            or not isinstance(invocation["argv"], list)
            or not all(isinstance(arg, str) and len(arg) <= 4096 for arg in invocation["argv"])):
        raise Refused("build-tools")
    output = link_output(invocation["argv"])
    if (output != invocation["output"] or Path(output).parent != plan["native_root"]
            or not re.fullmatch(r"native[-_]pids[-_]worker-[0-9a-f]{16}", Path(output).name)
            or [arg for arg in invocation["argv"] if arg.startswith("--dependency-file")]
            != ["--dependency-file=" + str(plan["depfile"])]):
        raise Refused("build-tools")
    original, named = os.stat(binary_path, follow_symlinks=False), os.stat(output, follow_symlinks=False)
    if (original.st_dev, original.st_ino) != (named.st_dev, named.st_ino) or compiler_bytes(output, MAX_BINARY) != binary:
        raise Refused("build-tools")
    deps = regular_bytes(plan["depfile"], MAX_LINK_DEPS)
    inputs = dependency_inputs(deps, output)
    consumed = {}
    basenames = set(CRT_ROLES) | {Path(path).name for path in plan["crt"]}
    for path in inputs:
        name = Path(path).name
        if name in basenames:
            actual = str(system_path(path))
            if actual not in plan["crt"]:
                raise Refused("build-tools")
            consumed[actual] = plan["crt"][actual]
        elif name.startswith("crt") and name.endswith(".o"):
            raise Refused("build-tools")
    for role in ("start", "init", "fini", "begin", "end", "libc"):
        if list(consumed.values()).count(role) != 1:
            raise Refused("build-tools")
    for path, before in plan["files"].items():
        if system_file(path, deadline, expected_kinds=(before["file_kind"],)) != before:
            raise Refused("build-tools")
    record = {"schema": "dockerlens-pids-build-tools-v1", "policy": "native-gcc-bfd-v1",
              "driver": plan["driver"], "linker": plan["linker"],
              "wrappers": {"driver_sha256": hashlib.sha256(plan["driver_source"]).hexdigest(),
                           "linker_sha256": hashlib.sha256(plan["linker_source"]).hexdigest()},
              "invocation": {"count": 1, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                             "output_size": len(binary), "output_sha256": hashlib.sha256(binary).hexdigest()},
              "dependencies": {"size": len(deps), "sha256": hashlib.sha256(deps).hexdigest()},
              "crt": [{**plan["files"][path], "role": role} for path, role in sorted(consumed.items())],
              "hashed_input_bytes": 2 * sum(value["size"] for value in plan["files"].values()),
              "scope": "installed-tools-and-consumed-crt-only-v1",
              "implementation_closure": "unresolved"}
    return record, (plan["driver_source"], plan["linker_source"], raw, deps)


def exclusive_write(directory, name, data, mode):
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    created = None
    try:
        created = os.fstat(fd)
        os.fchmod(fd, mode)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode):
            raise Refused("output")
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise Refused("output")
            view = view[count:]
        os.fsync(fd)
        closing = fd
        fd = -1
        os.close(closing)
        return (info.st_dev, info.st_ino)
    except BaseException:
        # Remove only the inode this call actually created. Never unlink a
        # preexisting name or another owner's replacement after an I/O failure.
        try:
            named = os.stat(directory / name, follow_symlinks=False)
            if created is not None and (named.st_dev, named.st_ino) == (created.st_dev, created.st_ino):
                (directory / name).unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def build(output, candidate, deadline):
    reserve(deadline)
    output = private_directory(output)
    if not re.fullmatch(r"[0-9a-f]{40}", candidate):
        raise Refused("candidate")
    if platform.system() != "Linux" or platform.machine() not in TARGETS:
        raise Refused("target")
    target, machine = TARGETS[platform.machine()]
    repository = Path(__file__).resolve().parents[1]
    # Read the existing canonical pin, never duplicate it as a new operational pin.
    import tomllib
    toolchain_bytes = regular_bytes(repository / "rust-toolchain.toml", 4096)
    toolchain = tomllib.loads(toolchain_bytes.decode())["toolchain"]["channel"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchain):
        raise Refused("toolchain")
    if any((output / name).exists() or (output / name).is_symlink() for name in (OUTPUT, MANIFEST, LOG, *TOOL_FILES)):
        raise Refused("output")
    log = bytearray()
    published = []
    log_attempted = False
    try:
        with tempfile.TemporaryDirectory(prefix="dl-pids-build-") as scratch:
            scratch = Path(scratch)
            worker_source = regular_bytes(repository / "examples" / f"{OUTPUT}.rs", 128 * 1024)
            controller_path = repository / "examples" / "native-pids-controller" / "mod.rs"
            controller_source = regular_bytes(controller_path, 128 * 1024)
            cargo_lock = regular_bytes(repository / "Cargo.lock", 1024 * 1024)
            cargo_manifest = regular_bytes(repository / "Cargo.toml", 65536)
            # Remove Cargo/Rust flag injection and wrapper configuration inherited
            # from callers. Ordinary trusted toolchain/cache discovery is retained.
            env = {key: value for key, value in os.environ.items()
                   if (key in ("CARGO_HOME", "RUSTUP_HOME")
                       or (not key.startswith(("CARGO_", "RUST", "CC", "CXX", "AR_", "LD_"))
                           and not key.startswith(("GCC_", "COLLECT_"))
                           and key not in ("CC", "CXX", "AR", "LD", "COMPILER_PATH", "LIBRARY_PATH", "LDEMULATION")))}
            env["RUSTUP_TOOLCHAIN"] = toolchain
            env["RUSTUP_AUTO_INSTALL"] = "0"
            env["CARGO_NET_OFFLINE"] = "true"
            env["CARGO_TARGET_DIR"] = str(scratch / "target")
            env["RUSTFLAGS"] = FLAGS
            compiler = command(["rustc", "-vV"], env, deadline, log).decode("utf-8", "strict")
            metadata = dict(line.split(": ", 1) for line in compiler.splitlines() if ": " in line)
            if metadata.get("release") != toolchain or metadata.get("host") != target:
                raise Refused("toolchain")
            compiler_record = {
                "release": metadata["release"], "host": metadata["host"],
                "commit_hash": metadata.get("commit-hash"),
                "commit_date": metadata.get("commit-date"),
                "llvm_version": metadata.get("LLVM version"),
            }
            tools = prepare_tools(scratch, target, env, deadline, log)
            effective_flags = FLAGS + " -C linker-flavor=gcc"
            if target == "x86_64-unknown-linux-gnu":
                effective_flags += " -C linker-features=-lld"
            env["RUSTFLAGS"] = effective_flags
            profile_args = [argument for key, value in PROFILE_SETTINGS
                            for argument in ("--config", f"profile.release.{key}={json.dumps(value)}")]
            command(["cargo", "build", "--offline", "--locked", "--jobs", "2", "--release", *profile_args,
                     "--config", f"target.{target}.linker={json.dumps(str(tools['wrapper']))}", "--target", target,
                     "--manifest-path", str(repository / "Cargo.toml"), "--example", OUTPUT], env, deadline, log,
                    guarded=tools["guarded"])
            binary_path = scratch / "target" / target / "release" / "examples" / OUTPUT
            binary = compiler_bytes(binary_path, MAX_BINARY)
            elf = inspect_elf(binary, machine)
            build_tools, tool_records = finish_tools(tools, binary_path, binary, deadline)
            if (worker_source != regular_bytes(repository / "examples" / f"{OUTPUT}.rs", 128 * 1024)
                    or controller_source != regular_bytes(controller_path, 128 * 1024)
                    or cargo_lock != regular_bytes(repository / "Cargo.lock", 1024 * 1024)
                    or cargo_manifest != regular_bytes(repository / "Cargo.toml", 65536)
                    or toolchain_bytes != regular_bytes(repository / "rust-toolchain.toml", 4096)):
                raise Refused("source")
            reserve(deadline)
            # The mandatory log is durable and verified before any executable or
            # success manifest becomes available. A log failure cannot leave a
            # usable artifact pair behind.
            log_bytes = bytes(log) or b"build completed\n"
            log_attempted = True
            exclusive_write(output, LOG, log_bytes, 0o600)
            if regular_bytes(output / LOG, MAX_LOG) != log_bytes:
                raise Refused("build-log")
            reserve(deadline)
            for name, data in zip(TOOL_FILES, tool_records, strict=True):
                identity = exclusive_write(output, name, data, 0o600)
                published.append((name, *identity))
                if regular_bytes(output / name, max(MAX_LINK_DEPS, MAX_LINK_RECORD, MAX_WRAPPER)) != data:
                    raise Refused("build-tools")
            manifest = {
                "schema": "dockerlens-pids-worker-build-v1", "candidate": candidate,
                "toolchain": toolchain, "compiler": compiler_record, "target": target,
                "flags": effective_flags, "binary": OUTPUT, "size": len(binary),
                "profile": {"name": "release", **dict(PROFILE_SETTINGS)},
                "build_tools": build_tools,
                "sha256": hashlib.sha256(binary).hexdigest(), "elf": elf,
                "source_sha256": hashlib.sha256(worker_source).hexdigest(),
                "controller_source_sha256": hashlib.sha256(controller_source).hexdigest(),
                "cargo_lock_sha256": hashlib.sha256(cargo_lock).hexdigest(),
                "cargo_manifest_sha256": hashlib.sha256(cargo_manifest).hexdigest(),
                "build_log_sha256": hashlib.sha256(log_bytes).hexdigest(), "build_log_size": len(log_bytes),
                "original_deadline_ns": deadline,
            }
            identity = exclusive_write(output, OUTPUT, binary, 0o700)
            published.append((OUTPUT, *identity))
            verified = regular_bytes(output / OUTPUT, MAX_BINARY)
            if verified != binary:
                raise Refused("artifact")
            reserve(deadline)
            identity = exclusive_write(output, MANIFEST, (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o600)
            published.append((MANIFEST, *identity))
            reserve(deadline)
        # Include private target cleanup in the cancellation/rollback owner.
        reserve(deadline)
    except BaseException:
        for name, device, inode in reversed(published):
            try:
                named = os.stat(output / name, follow_symlinks=False)
                if (named.st_dev, named.st_ino) == (device, inode):
                    (output / name).unlink()
            except FileNotFoundError:
                pass
        if not log_attempted:
            # Retain a failed compiler's log when possible; its publication can
            # also fail, but no executable or manifest has been committed then.
            exclusive_write(output, LOG, bytes(log) or b"build refused\n", 0o600)
        raise


def run_cli_build(output, candidate, deadline):
    """Scope CLI cancellation to this build, including child cleanup/rollback."""
    global _CANCEL_REQUESTED
    previous_cancel = _CANCEL_REQUESTED
    previous_handlers = {number: signal.getsignal(number)
                         for number in (signal.SIGTERM, signal.SIGINT)}
    _CANCEL_REQUESTED = False

    def cancel(_number, _frame):
        global _CANCEL_REQUESTED
        _CANCEL_REQUESTED = True
        # Returning protects Popen startup and finally cleanup from asynchronous
        # exceptions. Safe reserve checkpoints unwind within bounded I/O/waits.
        # Repeated TERM/INT cannot interrupt killing/reaping or artifact rollback.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        for number in previous_handlers:
            signal.signal(number, cancel)
        build(output, candidate, deadline)
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        _CANCEL_REQUESTED = previous_cancel


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--deadline-ns", required=True, type=int)
    args = parser.parse_args()
    try:
        run_cli_build(args.output_directory, args.candidate, args.deadline_ns)
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit("native-pids-worker-build: refused") from None


if __name__ == "__main__":
    main()
