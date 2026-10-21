#!/usr/bin/env python3
"""Closed test-harness observations, never native compatibility/admission proof.

Only peer checks read local Linux process/socket metadata; JSON normalization is
pure. Data preparation touches only an independently creation-bound empty named
volume, not the shared host store. No daemon discovery or Docker SDK is used.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys

LIMIT = 65536
ID = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


class Refused(ValueError):
    """Finite, value-free harness refusal."""


GROUPS = frozenset({
    "arguments", "input-json", "operation", "socket-metadata", "peer-connect",
    "peer-credentials", "service-state", "systemd-peer", "process-identity",
    "process-uid", "process-executable", "process-root", "socket-aliases",
    "socket-listener", "listener-owner", "process-stability", "peer-close", "socket-stability",
    "info-storage", "info-security", "info-version", "receipt-input",
    "receipt-versions", "receipt-destination", "receipt-publication",
})
OBSERVATION_ERRORS = (Refused, OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError)


class GroupRefused(Refused):
    """Only fixed group/category labels survive native failures."""

    def __init__(self, group, category):
        need(group in GROUPS and category in {"refused", "io"})
        self.group = group
        self.category = category
        super().__init__("outer runtime observation unavailable")


def need(value):
    if not value:
        raise Refused("outer runtime observation unavailable")


def pairs(items):
    value = {}
    for key, item in items:
        need(key not in value)
        value[key] = item
    return value


def document(raw):
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT)
    def nonfinite(_value):
        raise Refused("outer runtime observation unavailable")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        need(depth <= 20 and count <= 8192)
        if type(item) is dict:
            pending.extend((part, depth + 1) for pair in item.items() for part in pair)
        elif type(item) is list:
            pending.extend((part, depth + 1) for part in item)
        else:
            need(type(item) in {str, int, bool, type(None)})
    need(type(value) is dict)
    return value


def docker_info(value):
    """Rootful peer identity is checked separately; absent rootless is not proof."""
    group = "info-storage"
    try:
        need(value.get("OSType") == "linux" and type(value.get("DockerRootDir")) is str
             and re.fullmatch(r"/[A-Za-z0-9_./-]+", value["DockerRootDir"]) is not None
             and ".." not in Path(value["DockerRootDir"]).parts and value["DockerRootDir"] != "/")
        group = "info-security"
        options = value.get("SecurityOptions")
        need(type(options) is list and all(type(item) is str for item in options)
             and not any(item == "name=rootless" or item.startswith("name=rootless,")
                         or item == "name=userns" or item.startswith("name=userns,") for item in options))
        group = "info-version"
        need(type(value.get("OperatingSystem")) is str and "desktop" not in value["OperatingSystem"].lower()
             and type(value.get("ServerVersion")) is str
             and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?", value["ServerVersion"]) is not None)
        return value["DockerRootDir"]
    except OBSERVATION_ERRORS as error:
        raise GroupRefused(group, "io" if isinstance(error, OSError) else "refused") from None


def service_pid(raw):
    need(type(raw) is str and 0 < len(raw) <= 4096)
    values = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        need(separator and key in {"MainPID", "ActiveState", "SubState"} and key not in values)
        values[key] = value
    need(set(values) == {"MainPID", "ActiveState", "SubState"}
         and values["ActiveState"] == "active" and values["SubState"] == "running"
         and re.fullmatch(r"[1-9][0-9]{0,9}", values["MainPID"]) is not None)
    pid = int(values["MainPID"])
    need(1 < pid <= 2**31 - 1)
    return pid


def listener_inode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT)
    lines = raw.decode("ascii").splitlines()
    need(len(lines) <= 4096 and lines[0].split() == ["Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path"])
    matches = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) == 8 and fields[7] in {"/run/docker.sock", "/var/run/docker.sock"}:
            need(fields[3] == "00010000" and fields[4] == "0001" and fields[5] == "01"
                 and re.fullmatch(r"[1-9][0-9]{0,19}", fields[6]) is not None)
            matches.append(fields[6])
    need(len(matches) == 1)
    return matches[0]


def docker_peer(path, service):
    """Positive root daemon/local-root check, not merely an info boolean absence."""
    group = "socket-metadata"
    try:
        need(path == "/var/run/docker.sock")
        metadata = os.lstat(path)
        need(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == 0)
        group = "peer-connect"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(1.0)
            peer.connect(path)
            group = "peer-credentials"
            peer_pid, uid, gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            group = "service-state"
            pid = service_pid(service)
            group = "peer-credentials"
            need(peer_pid in {1, pid} and uid == 0 and gid == 0)
            if peer_pid == 1:
                group = "systemd-peer"
                need(Path("/proc/1/comm").read_bytes() == b"systemd\n"
                     and os.readlink("/proc/1/exe") in {"/usr/lib/systemd/systemd", "/lib/systemd/systemd"})
            group = "process-identity"
            process = Path(f"/proc/{pid}")
            before = (process / "stat").read_bytes()
            need(len(before) <= 4096 and (process / "comm").read_bytes() == b"dockerd\n")
            group = "process-uid"
            status = (process / "status").read_bytes()
            need(len(status) <= 16384)
            uids = [line.split()[1:] for line in status.splitlines() if line.startswith(b"Uid:")]
            need(uids == [[b"0", b"0", b"0", b"0"]])
            group = "process-executable"
            executable = os.readlink(process / "exe")
            need(executable in {"/usr/bin/dockerd", "/usr/sbin/dockerd", "/usr/local/bin/dockerd"})
            executable_info = os.stat(process / "exe")
            need(stat.S_ISREG(executable_info.st_mode) and executable_info.st_uid == 0
                 and executable_info.st_mode & 0o022 == 0 and executable_info.st_mode & stat.S_IXUSR)
            group = "process-root"
            root, ours = os.stat(process / "root"), os.stat("/")
            need((root.st_dev, root.st_ino) == (ours.st_dev, ours.st_ino))
            group = "socket-aliases"
            canonical = os.stat("/run/docker.sock")
            daemon_socket = os.stat(process / "root/run/docker.sock")
            need(stat.S_ISSOCK(canonical.st_mode) and stat.S_ISSOCK(daemon_socket.st_mode)
                 and (canonical.st_dev, canonical.st_ino) == (metadata.st_dev, metadata.st_ino)
                 and (daemon_socket.st_dev, daemon_socket.st_ino) == (metadata.st_dev, metadata.st_ino))
            group = "socket-listener"
            inode = listener_inode((process / "net/unix").read_bytes())
            group = "listener-owner"
            descriptors = os.listdir(process / "fd")
            need(len(descriptors) <= 4096 and all(re.fullmatch(r"0|[1-9][0-9]{0,9}", fd) for fd in descriptors))
            owned = 0
            for descriptor in descriptors:
                try:
                    target = os.readlink(process / "fd" / descriptor)
                except FileNotFoundError:
                    continue  # A concurrently closed unrelated fd grants nothing.
                if target == f"socket:[{inode}]":
                    owned += 1
            need(owned > 0)
            group = "process-stability"
            after = (process / "stat").read_bytes()
            # The mutable counters can change; bind PID and immutable start time.
            def identity(raw):
                prefix, separator, suffix = raw.rpartition(b") ")
                fields = suffix.split()
                need(separator and len(fields) >= 20 and prefix.startswith(str(pid).encode() + b" (")
                     and fields[19].isdigit())
                return fields[19]
            need(identity(before) == identity(after))
            group = "peer-close"
        group = "socket-stability"
        current = os.lstat(path)
        need((metadata.st_dev, metadata.st_ino, metadata.st_uid) == (current.st_dev, current.st_ino, current.st_uid))
        return {"schema_version": 1, "kind": "local-root-dockerd-observation", "socket": path,
                "socket_device": metadata.st_dev, "socket_inode": metadata.st_ino,
                "peer_pid": peer_pid, "listener_inode": int(inode),
                "daemon_pid": pid, "daemon_starttime": int(identity(before)), "uid": uid, "gid": gid,
                "executable": executable, "executable_device": executable_info.st_dev,
                "executable_inode": executable_info.st_ino}
    except OBSERVATION_ERRORS as error:
        raise GroupRefused(group, "io" if isinstance(error, OSError) else "refused") from None


def runtime_receipt(peer, path, client, server, image_version, storage_root):
    group = "receipt-input"
    try:
        # A fresh private observation for auditing, NEVER accepted as runtime/capture
        # authority. No caller may replay this file to skip a live preflight.
        need(set(peer) == {"schema_version", "kind", "socket", "socket_device", "socket_inode", "peer_pid", "listener_inode", "daemon_pid",
                           "daemon_starttime", "uid", "gid", "executable", "executable_device", "executable_inode"}
             and peer["kind"] == "local-root-dockerd-observation" and peer["uid"] == peer["gid"] == 0)
        group = "receipt-versions"
        need(all(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?", version) for version in (client, server))
             and re.fullmatch(r"[0-9]{8}\.[0-9]+\.[0-9]+", image_version) is not None)
        group = "receipt-destination"
        destination = Path(path)
        need(destination.name == "outer-runtime.json" and destination.parent.is_dir() and not destination.parent.is_symlink())
        record = {"schema_version": 1, "kind": "test-only-outer-docker-prerequisite", "native_qualified": False,
                  "runner": "ubuntu-24.04", "runner_image_version": image_version, "client_version": client,
                  "server_version": server, "storage_root": storage_root, "peer": peer}
        raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        group = "receipt-publication"
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except OBSERVATION_ERRORS as error:
        raise GroupRefused(group, "io" if isinstance(error, OSError) else "refused") from None


def binding(value, kind, identity, name, owner_key, run):
    need(kind in {"container", "network", "volume"} and NAME.fullmatch(name) is not None
         and type(owner_key) is str and re.fullmatch(r"io\.(?:dockerlens\.native-run|boxferry\.docker-core-run)", owner_key) is not None
         and NAME.fullmatch(run) is not None)
    actual_name = value.get("Name")
    need(type(actual_name) is str)
    if kind == "container":
        need(ID.fullmatch(identity) is not None and value.get("Id") == identity
             and actual_name in {name, "/" + name})
        configuration = value.get("Config")
        need(type(configuration) is dict)
        labels = configuration.get("Labels")
    else:
        need(actual_name == name)
        if kind == "network":
            need(ID.fullmatch(identity) is not None and value.get("Id") == identity)
        else:
            need(identity == name and value.get("Driver") == "local"
                 and type(value.get("Mountpoint")) is str and value["Mountpoint"].startswith("/")
                 and type(value.get("CreatedAt")) is str)
        labels = value.get("Labels")
    need(type(labels) is dict and labels.get(owner_key) == run)
    return identity + "|" + name + "|" + run


def observe(value, kind, engine):
    """Normalize backend identity keys, retaining all required native fields."""
    need(kind in {"container", "network", "volume"} and engine in {"podman", "docker"})
    result = dict(value)
    if engine == "podman" and kind == "network":
        for native, canonical in (("id", "Id"), ("name", "Name"), ("labels", "Labels")):
            need(native in value and canonical not in value)
            result[canonical] = value[native]
    need(type(result.get("Name")) is str)
    if kind != "volume":
        need(type(result.get("Id")) is str and ID.fullmatch(result["Id"]) is not None)
    return result


def client_context(directory, engine):
    need(engine in {"podman", "docker"})
    root = Path(directory)
    need(root.is_absolute() and root.resolve() == root)
    metadata = os.lstat(root)
    need(stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700)
    if engine == "docker":
        client = root / "docker-client"
        actual = os.lstat(client)
        need(stat.S_ISDIR(actual.st_mode) and stat.S_IMODE(actual.st_mode) == 0o700
             and actual.st_uid in {metadata.st_uid, 0} and not list(client.iterdir()))


def created_cid(path):
    file = Path(path)
    need(file.name == "outer-create.cid" and file.parent.resolve() == file.parent)
    parent = os.lstat(file.parent)
    need(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700)
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        need(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
             and metadata.st_uid in {parent.st_uid, 0} and metadata.st_mode & 0o022 == 0
             and metadata.st_size in {64, 65})
        raw = os.read(descriptor, 66)
        after = os.fstat(descriptor)
        current = os.lstat(file)
        need(len(raw) == metadata.st_size
             and (current.st_dev, current.st_ino) == (metadata.st_dev, metadata.st_ino)
             and (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        identity = raw.decode("ascii")
        need(ID.fullmatch(identity) is not None)
        return identity
    finally:
        os.close(descriptor)


def snapshot_image(value, identity=None):
    if identity is not None:
        if ID.fullmatch(identity) is not None:
            need(value.get("Id") == identity)
        else:
            need(NAME.fullmatch(identity) is not None and value.get("Name") in {identity, "/" + identity})
    configuration = value.get("Config")
    need(type(configuration) is dict)
    reference = configuration.get("Image")
    need(type(reference) is str
         and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]+@sha256:[0-9a-f]{64}", reference) is not None
         and type(value.get("Image")) is str
         and re.fullmatch(r"sha256:[0-9a-f]{64}", value["Image"]) is not None)
    return reference


def snapshot(value, image):
    reference = snapshot_image(value)
    repository, digest = reference.rsplit("@", 1)
    # RepoDigests omits an optional tag, but never a registry port/repository.
    head, separator, tail = repository.rpartition("/")
    repository = (head + separator if separator else "") + tail.split(":", 1)[0]
    expected = repository + "@" + digest
    need(image.get("Id") == value["Image"] and type(image.get("RepoDigests")) is list
         and all(type(item) is str for item in image["RepoDigests"])
         and image["RepoDigests"].count(expected) == 1)
    name = value.get("Name")
    need(type(name) is str and name.startswith("/") and NAME.fullmatch(name[1:]) is not None
         and "ImageDigest" not in value)
    result = dict(value)
    result["Name"] = name[1:]
    result["ImageDigest"] = digest
    return result


def daemon_binding(value, engine, identity, name, owner, run, image):
    need(engine in {"podman", "docker"} and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]+@sha256:[0-9a-f]{64}", image) is not None)
    actual = binding(value, "container", identity, name, owner, run)
    need(value.get("ImageDigest") == image.rsplit("@", 1)[1])
    if engine == "docker":
        need(value["Config"].get("Image") == image)
    return actual


def image_config(value, mode):
    need(mode in {"rootful", "rootless"})
    destination = "/home/docker/.local/share/docker" if mode == "rootless" else "/var/lib/docker"
    volumes = value.get("Volumes")
    need(type(volumes) is dict and set(volumes) == {destination})
    need(value.get("User", "") in ({"docker", "1000", "1000:1000"} if mode == "rootless" else {"", "0", "0:0", "root"}))
    return destination


def image_info(value):
    identity = value.get("Id", value.get("ID"))
    if type(identity) is str and ID.fullmatch(identity) is not None:
        identity = "sha256:" + identity
    need(type(identity) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", identity) is not None
         and value.get("Os") == "linux" and value.get("Architecture") in {"amd64", "arm64"})
    return {"Id": identity, "Os": value["Os"], "Architecture": value["Architecture"]}


def volume_path(value, name, owner, run):
    binding(value, "volume", name, name, owner, run)
    path = value["Mountpoint"]
    need(re.fullmatch(r"/[A-Za-z0-9_./-]+", path) is not None
         and ".." not in Path(path).parts and path != "/")
    return path


def mounts(value, volume, destination, source, guest, data_path):
    need(NAME.fullmatch(volume) is not None and type(source) is str and source.startswith("/")
         and guest in {"/dockerlens-native", "/boxferry-core"})
    observed = value.get("Mounts")
    need(type(observed) is list and len(observed) == 2)
    data = [item for item in observed if type(item) is dict and item.get("Destination") == destination]
    socket_mount = [item for item in observed if type(item) is dict and item.get("Destination") == guest]
    need(len(data) == 1 and len(socket_mount) == 1)
    need(data[0].get("Type") == "volume" and data[0].get("Name") == volume and data[0].get("RW") is True
         and data[0].get("Driver") == "local" and data[0].get("Source") == data_path
         and socket_mount[0].get("Type") == "bind" and socket_mount[0].get("Source") == source
         and socket_mount[0].get("RW") is True)


def prepare_data(path, root, volume, mode):
    """No recursive ownership operation and no ambient path/anonymous volume."""
    need(mode in {"rootful", "rootless"} and NAME.fullmatch(volume) is not None
         and path == root.rstrip("/") + "/volumes/" + volume + "/_data" and os.geteuid() == 0)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid == 0 and before.st_gid == 0
             and not os.listdir(descriptor))
        owner = 1000 if mode == "rootless" else 0
        os.fchown(descriptor, owner, owner)
        after = os.fstat(descriptor)
        need((after.st_uid, after.st_gid) == (owner, owner)
             and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino))
    finally:
        os.close(descriptor)


def check_data(path, root, volume, mode):
    need(mode in {"rootful", "rootless"} and NAME.fullmatch(volume) is not None
         and path == root.rstrip("/") + "/volumes/" + volume + "/_data")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        owner = 1000 if mode == "rootless" else 0
        need((info.st_uid, info.st_gid) == (owner, owner))
    finally:
        os.close(descriptor)


def main(argv):
    mode = "other"
    group = "arguments"
    try:
        need(bool(argv))
        command, *args = argv
        mode = {"docker-peer": "peer", "docker-info": "info", "runtime-receipt": "receipt"}.get(command, "other")
        if command == "docker-peer" and len(args) == 2:
            print(json.dumps(docker_peer(*args), sort_keys=True, separators=(",", ":")))
        elif command == "prepare-data" and len(args) == 4:
            prepare_data(*args)
        elif command == "check-data" and len(args) == 4:
            check_data(*args)
        elif command == "client-context" and len(args) == 2:
            client_context(*args)
        elif command == "created-cid" and len(args) == 1:
            print(created_cid(*args))
        else:
            group = "input-json"
            value = document(sys.stdin.buffer.read(LIMIT + 1))
            group = "operation"
            if command == "docker-info" and not args:
                print(docker_info(value))
            elif command == "binding" and len(args) == 5:
                print(binding(value, *args))
            elif command == "daemon-binding" and len(args) == 6:
                print(daemon_binding(value, *args))
            elif command == "image-config" and len(args) == 1:
                print(image_config(value, *args))
            elif command == "mounts" and len(args) == 5:
                mounts(value, *args)
            elif command == "runtime-receipt" and len(args) == 5:
                runtime_receipt(value, *args)
            elif command == "observe" and len(args) == 2:
                raw = json.dumps(observe(value, *args), separators=(",", ":"))
                need(len(raw.encode()) <= LIMIT)
                print(raw)
            elif command == "snapshot-image" and len(args) == 1:
                print(snapshot_image(value, args[0]))
            elif command == "snapshot" and len(args) == 1:
                raw = json.dumps(snapshot(document(args[0].encode()), value), separators=(",", ":"))
                need(len(raw.encode()) <= LIMIT)
                print(raw)
            elif command == "image-info" and not args:
                print(json.dumps(image_info(value), separators=(",", ":")))
            elif command == "volume-path" and len(args) == 3:
                print(volume_path(value, *args))
            else:
                raise Refused()
        return 0
    except OBSERVATION_ERRORS as error:
        if mode != "other":
            if (isinstance(error, GroupRefused) and error.group in GROUPS
                    and error.category in {"refused", "io"}):
                group, category = error.group, error.category
            else:
                category = "io" if isinstance(error, OSError) else "refused"
            print(f"outer runtime observation unavailable: mode={mode} group={group} category={category}", file=sys.stderr)
        else:
            print("outer runtime observation unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
