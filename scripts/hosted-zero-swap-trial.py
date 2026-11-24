#!/usr/bin/env python3
"""Bounded infrastructure trial. The native validation harness is a separate owner."""

import errno
import fcntl
import grp
import hashlib
import json
import os
import re
import secrets
import selectors
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

GIB = 1 << 30
MEMORY = 7 * GIB
CPUS = 2
DISK = 8 * GIB
IMAGE = "ubuntu-24.04-server-cloudimg-amd64.img"
SIGNER = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
REPO = "Strukturpiloten/docker-lens"
WORKFLOW = ".github/workflows/hosted-zero-swap-trial.yml"
RESULT = "dockerlens-hosted-zero-swap-trial.json"
ARCHIVE = "https://snapshot.ubuntu.com/ubuntu/"
KVM_PATH = "/dev/kvm"
KVM_RDEV = os.makedev(10, 232)
KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
OUTPUT_LIMIT = 512 * 1024
GUEST_STAGES = (
    "boot",
    "packages",
    "docker_peer",
    "fixture_pull",
    "fixture_create",
    "fixture_observe",
    "complete",
)
REASONS = (
    "refused",
    "command_failed",
    "timeout",
    "output_limit",
    "unavailable",
    "cancelled",
    "io",
    "cleanup_failed",
    "guest_failed",
    "guest_response",
)
cancelled = None
command_cleanup_failed = False


class Refusal(Exception):
    def __init__(self, reason="refused", code=1):
        self.reason, self.code = reason, code


def require(assertion):
    if not assertion:
        raise Refusal()


def request_cancel(number, _frame):
    global cancelled
    if cancelled is None:
        cancelled = number


def exit_status(returncode):
    return returncode if returncode >= 0 else 128 - returncode


def active(deadline):
    if cancelled is not None:
        raise Refusal("cancelled", 128 + cancelled)
    if time.monotonic() >= deadline:
        raise Refusal("timeout", 124)


def reap(process):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        process.poll()
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return process.poll() is not None
        except OSError:
            return False
        until = time.monotonic() + 2
        while time.monotonic() < until:
            process.poll()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return process.poll() is not None
            except OSError:
                return False
            time.sleep(0.05)
    return False


def capture(argv, deadline, *, input_bytes=None, allow_failure=False):
    """Retain bounded private bytes. Never log argv, errors, or arbitrary output."""
    global command_cleanup_failed
    active(deadline)
    with tempfile.TemporaryFile() as stdin:
        if input_bytes is not None:
            require(len(input_bytes) <= 65536)
            stdin.write(input_bytes)
            stdin.seek(0)
        try:
            p = subprocess.Popen(
                argv,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                start_new_session=True,
            )
        except FileNotFoundError:
            raise Refusal("unavailable", 127) from None
        buffers = [bytearray(), bytearray()]
        failed = False
        try:
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((p.stdout, p.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map():
                    active(deadline)
                    for key, _ in selector.select(0.1):
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        buf = buffers[key.data]
                        if len(buf) + len(chunk) > OUTPUT_LIMIT:
                            raise Refusal("output_limit")
                        buf.extend(chunk)
                while p.poll() is None:
                    active(deadline)
                    time.sleep(0.05)
            if p.returncode and not allow_failure:
                raise Refusal("command_failed", exit_status(p.returncode))
            return p.returncode, bytes(buffers[0]), bytes(buffers[1])
        except BaseException:
            failed = True
            raise
        finally:
            p.stdout.close()
            p.stderr.close()
            if not reap(p):
                command_cleanup_failed = True
                if not failed:
                    raise Refusal("cleanup_failed")


def json_document(raw):
    def pairs(entries):
        result = dict(entries)
        require(len(result) == len(entries))
        return result

    return json.loads(raw, object_pairs_hook=pairs)


def swap_zero():
    values = re.findall(
        r"(?m)^SwapTotal:[ \t]+(0|[1-9][0-9]*) kB$", Path("/proc/meminfo").read_text()
    )
    with open("/proc/swaps", encoding="ascii") as source:
        table = source.read(4097).splitlines()
    require(
        len(values) == 1
        and table
        and table[0].split() == ["Filename", "Type", "Size", "Used", "Priority"]
    )
    require(values[0] == "0" and len(table) == 1)


def boot_id():
    contents = Path("/proc/sys/kernel/random/boot_id").read_bytes()
    require(re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", contents))
    return hashlib.sha256(contents).hexdigest()


def packages(pins, scope, work, deadline):
    source = work / "apt.sources"
    snapshot = pins["apt_snapshot"]
    suite = pins[scope + "_apt_suite"]
    require(re.fullmatch("[0-9]{8}T[0-9]{6}Z", snapshot))
    require(re.fullmatch("[a-z]+", suite))
    source.write_text(
        f"Types: deb\nURIs: {ARCHIVE}{snapshot}/\n"
        f"Suites: {suite} {suite}-updates {suite}-security\nComponents: main universe\n"
        f"Architectures: amd64\nSigned-By: {KEYRING}\nCheck-Valid-Until: no\n"
    )
    pins = pins[scope + "_packages"]
    prefix = [] if scope == "guest" else ["sudo", "-n"]
    command = prefix + [
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "NEEDRESTART_MODE=l",
        "apt-get",
        "-o",
        f"Dir::Etc::sourcelist={source}",
        "-o",
        "Dir::Etc::sourceparts=-",
        "-o",
        f"Dir::State::lists={work / 'lists'}",
        "-o",
        "Dir::Cache::pkgcache=",
        "-o",
        "Dir::Cache::srcpkgcache=",
        "-o",
        "Acquire::Retries=0",
        "-o",
        "Acquire::https::Timeout=15",
        "-o",
        "DPkg::Lock::Timeout=2",
    ]
    # Update privately without sudo on the host. Installation uses this
    # fixed source and the disposable system's normal authenticated cache.
    (work / "lists").mkdir()
    (work / "lists" / "partial").mkdir()
    capture(command[len(prefix) :] + ["-qq", "update"], min(deadline, time.monotonic() + 100))
    install = [
        "--no-install-recommends",
        "--no-upgrade",
        "--no-remove",
        "install",
        *(f"{pkg}={version}" for pkg, version in pins.items()),
    ]
    _, plan, _ = capture(command[len(prefix) :] + ["--simulate", *install], deadline)
    require(not re.search(rb"(?m)^(?:Remv |Inst [^\n ]+ \[)", plan))
    _, audit, _ = capture(["dpkg", "--audit"], deadline)
    require(not audit)
    capture(command + ["-qq", "-y", *install], min(deadline, time.monotonic() + 170))
    _, actual, _ = capture(
        ["dpkg-query", "-W", r"-f=${Package}=${Version} ${db:Status-Status}\n", *pins], deadline
    )
    require(
        set(actual.decode("ascii").splitlines()) == {f"{p}={v} installed" for p, v in pins.items()}
    )
    return pins


def fetch(url, path, limit, deadline):
    # curl bounds the actual sink even if the server provides no trustworthy size.
    capture(
        [
            "curl",
            "--disable",
            "--proto",
            "=https",
            "--fail",
            "--silent",
            "--show-error",
            "--max-filesize",
            str(limit),
            "--max-time",
            "150",
            "--output",
            str(path),
            url,
        ],
        deadline,
    )
    require(0 < path.stat().st_size <= limit)


def verify_cloud_manifest(work, date, digest, deadline):
    prefix = f"https://cloud-images.ubuntu.com/releases/noble/release-{date}/"
    for name in ("SHA256SUMS", "SHA256SUMS.gpg"):
        fetch(prefix + name, work / name, 24_000, deadline)
    key = work / "image-key.asc"
    fetch(
        f"https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x{SIGNER}", key, 20_000, deadline
    )
    keyring = work / "cloud-key.gpg"
    capture(
        [
            "gpg",
            "--batch",
            "--no-options",
            "--homedir",
            str(work),
            "--dearmor",
            "-o",
            str(keyring),
            str(key),
        ],
        deadline,
    )
    _, signed, _ = capture(
        [
            "gpgv",
            "--status-fd",
            "1",
            "--keyring",
            str(keyring),
            str(work / "SHA256SUMS.gpg"),
            str(work / "SHA256SUMS"),
        ],
        deadline,
    )
    require(re.findall(rb"(?m)^\[GNUPG:\] VALIDSIG ([0-9A-F]{40}) ", signed) == [SIGNER.encode()])
    verify_manifest_row((work / "SHA256SUMS").read_text(), digest)
    return prefix


def verify_manifest_row(text, digest):
    rows = re.findall(rf"(?m)^([0-9a-f]{{64}}) [ *]{re.escape(IMAGE)}$", text)
    require(rows == [digest])


def registry_read(path, token=None):
    host = "https://ghcr.io"
    headers = {
        "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json,"
        "application/vnd.docker.distribution.manifest.list.v2+json,"
        "application/vnd.docker.distribution.manifest.v2+json"
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    # The fixed GHCR token and manifest endpoints are expected to be direct.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(urllib.request.Request(host + path, headers=headers), timeout=7) as response:
        data = response.read(65537)
    require(0 < len(data) <= 65536)
    return data


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        raise Refusal()


def fixture_identity(pins, read=registry_read):
    reference = pins["fixture_image"]
    match = re.fullmatch(
        r"ghcr\.io/(strukturpiloten/docker-debian-11-rootful):v[0-9.]+@(sha256:[0-9a-f]{64})",
        reference,
    )
    require(match is not None)
    repository, digest = match.groups()
    token = json_document(read(f"/token?service=ghcr.io&scope=repository:{repository}:pull"))[
        "token"
    ]
    require(type(token) is str and re.fullmatch(r"[A-Za-z0-9_.=+/-]{1,4096}", token))

    def manifest(wanted):
        require(re.fullmatch("sha256:[0-9a-f]{64}", wanted))
        raw = read(f"/v2/{repository}/manifests/{wanted}", token)
        require("sha256:" + hashlib.sha256(raw).hexdigest() == wanted)
        return json_document(raw)

    index = manifest(digest)
    amd64 = [
        row["digest"]
        for row in index["manifests"]
        if row["platform"].get("os") == "linux" and row["platform"].get("architecture") == "amd64"
    ]
    require(amd64 == [pins["fixture_platform"]])
    require(manifest(amd64[0])["config"]["digest"] == pins["fixture_config"])
    return f"ghcr.io/{repository}@{digest}"


def make_seed(work, token, deadline):
    for name in ("identity", "guest-host"):
        capture(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "dockerlens-trial",
                "-f",
                str(work / name),
            ],
            deadline,
        )
    identity = (work / "identity.pub").read_text().strip()
    host = (work / "guest-host.pub").read_text().split()
    require(host[0] == "ssh-ed25519" and len(host) == 3)
    (work / "known_hosts").write_text("dockerlens-trial " + " ".join(host[:2]) + "\n")
    # JSON is a YAML-compatible cloud-config document. The host key is scoped to
    # the freshly owned guest. Host credentials and the checkout never enter it.
    config = {
        "users": [
            {
                "name": "trial",
                "lock_passwd": True,
                "shell": "/bin/bash",
                "sudo": "ALL=(root) NOPASSWD:ALL",
                "ssh_authorized_keys": [identity],
            }
        ],
        "ssh_pwauth": False,
        "disable_root": True,
        "ssh_deletekeys": True,
        "ssh_keys": {
            "ed25519_private": (work / "guest-host").read_text(),
            "ed25519_public": " ".join(host[:2]),
        },
        "write_files": [
            {
                "path": "/etc/dockerlens-trial-id",
                "owner": "root:root",
                "permissions": "0600",
                "content": token + "\n",
            }
        ],
        "package_update": False,
        "package_upgrade": False,
    }
    (work / "user-data").write_text("#cloud-config\n" + json.dumps(config))
    (work / "meta-data").write_text(
        json.dumps({"instance-id": token, "local-hostname": "dockerlens-trial"})
    )
    capture(
        [
            "xorriso",
            "-as",
            "mkisofs",
            "-quiet",
            "-V",
            "cidata",
            "-J",
            "-r",
            "-o",
            str(work / "seed.iso"),
            str(work / "user-data"),
            str(work / "meta-data"),
        ],
        deadline,
    )
    for name in ("guest-host", "user-data"):
        (work / name).unlink()


def ssh_command(work, port, remote):
    return [
        "ssh",
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "HostKeyAlias=dockerlens-trial",
        "-o",
        f"UserKnownHostsFile={work / 'known_hosts'}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=3",
        "-o",
        "ServerAliveInterval=3",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "LogLevel=ERROR",
        "-i",
        str(work / "identity"),
        "-p",
        str(port),
        "trial@127.0.0.1",
        shlex.join(remote),
    ]


def docker_peer(deadline):
    _, pid, _ = capture(
        ["systemctl", "show", "--property=MainPID", "--value", "docker.service"], deadline
    )
    require(re.fullmatch(rb"[1-9][0-9]{0,8}\n", pid))
    proc = Path("/proc") / pid.decode().strip()
    require((proc / "exe").samefile("/usr/bin/dockerd"))
    require(re.search(r"(?m)^Uid:[ \t]+0[ \t]+0[ \t]+0[ \t]+0$", (proc / "status").read_text()))
    endpoint = Path("/var/run/docker.sock")
    original = endpoint.stat()
    require(stat.S_ISSOCK(original.st_mode) and original.st_uid == 0)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(2)
        peer.connect(str(endpoint))
        peer_pid, uid, _ = struct.unpack(
            "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        require(uid == 0 and peer_pid in (1, int(pid)))
        if peer_pid == 1:
            require(Path("/proc/1/exe").samefile("/usr/lib/systemd/systemd"))
    names = {"/run/docker.sock", "/var/run/docker.sock"}
    with (proc / "net/unix").open() as stream:
        rows = stream.read(131073)
    require(len(rows) <= 131072)
    inodes = []
    for line in rows.splitlines():
        parts = line.split()
        if len(parts) == 8 and parts[-1] in names and parts[3:6] == ["00010000", "0001", "01"]:
            require(parts[6].isdigit())
            inodes.append(parts[6])
    require(len(inodes) == 1)
    found = False
    with os.scandir(proc / "fd") as directory:
        for number, entry in enumerate(directory):
            require(number < 2048)
            try:
                found |= os.readlink(entry.path) == f"socket:[{inodes[0]}]"
            except FileNotFoundError:
                continue
    require(
        found
        and (original.st_dev, original.st_ino) == (endpoint.stat().st_dev, endpoint.stat().st_ino)
    )
    require(
        capture(["systemctl", "show", "--property=MainPID", "--value", "docker.service"], deadline)[
            1
        ]
        == pid
    )


def inspect(docker, object_id, deadline):
    raw = capture(docker + ["container", "inspect", "--format", "{{json .}}", object_id], deadline)[
        1
    ]
    return json_document(raw)


def bind_image(docker, reference, digest_ref, pins, deadline):
    def inspect_image(arguments):
        raw = capture(
            docker + ["image", "inspect", "--format", "{{json .}}", *arguments, reference], deadline
        )[1]
        image = json_document(raw)
        digests = image["RepoDigests"]
        require(
            type(digests) is list
            and all(type(value) is str for value in digests)
            and digests.count(digest_ref) == 1
            and image["Os"] == "linux"
            and image["Architecture"] == "amd64"
        )
        return image

    image = inspect_image([])
    image_id = image["Id"]
    if image_id == digest_ref.rsplit("@", 1)[-1]:
        # Containerd reports the index and then the selected manifest.
        bind_descriptor(image.get("Descriptor"), image_id)
        selected = inspect_image(["--platform", "linux/amd64"])
        manifest = pins["fixture_platform"]
        require(selected["Id"] == manifest)
        bind_descriptor(selected.get("Descriptor"), manifest)
        return image_id, manifest
    require(image_id == pins["fixture_config"])
    bind_descriptor(image.get("Descriptor"), None)
    return image_id, None


def bind_descriptor(descriptor, digest):
    if digest is None:
        require(descriptor is None)
    else:
        require(type(descriptor) is dict and descriptor.get("digest") == digest)


def bind_container_image(info, image_id, manifest):
    require(info["Image"] == image_id)
    bind_descriptor(info.get("ImageManifestDescriptor"), manifest)


def bind_container(info, cid, name, token):
    require(info["Id"] == cid and info["Name"] == "/" + name)
    require(info["Config"]["Labels"]["io.dockerlens.boot-trial"] == token)


def remove_container(docker, cid, name, token, deadline, created):
    global cancelled
    pending, cancelled = cancelled, None
    try:
        if cid is None:
            return "unverified" if created else "not_created"
        bind_container(inspect(docker, cid, deadline), cid, name, token)
        capture(docker + ["container", "rm", "--force", "--volumes", cid], deadline)
        for key in (cid, name):
            status, output, error = capture(
                docker + ["container", "inspect", key], deadline, allow_failure=True
            )
            require(
                status == 1
                and output.strip() in (b"", b"[]")
                and error
                in (
                    f"Error: No such object: {key}\n".encode(),
                    f"Error: No such container: {key}\n".encode(),
                    f"Error response from daemon: No such container: {key}\n".encode(),
                )
            )
        return "removed"
    except (Refusal, OSError, ValueError, KeyError, TypeError):
        return "unverified"
    finally:
        cancelled = pending or cancelled


CONTAINER_PROBE = r"""set -eu
test "$(id -u)" = 0
test "$(stat -f -c %T /proc)" = proc
test "$(stat -f -c %T /sys/fs/cgroup)" = cgroup2fs
test "$(cat /proc/1/cgroup)" = '0::/'
test "$(cat /sys/fs/cgroup/memory.max)" = '4294967296'
test "$(cat /sys/fs/cgroup/pids.max)" = '512'
test "$(cat /sys/fs/cgroup/cpu.max)" = '200000 100000'
awk '$1=="SwapTotal:"{n++; if(NF!=3 || $2!="0" || $3!="kB") bad=1}
END{exit bad || n!=1}' /proc/meminfo
test "$(wc -l </proc/swaps)" = 1
stat -c '%d %i' /sys/fs/cgroup
dpkg-query -W -f='${Version}\n' docker.io
cat /proc/sys/kernel/random/boot_id
"""


def within_guest(args):
    token, host_boot, raw_pins = args
    result = {"stage": "boot", "exit": 1, "reason": "refused", "cleanup": "not_created"}
    deadline = time.monotonic() + 330
    docker = ["docker", "--host", "unix:///var/run/docker.sock"]
    cid = None
    created = False
    name = "dockerlens-boot-trial-" + token
    try:
        pins = json_document(raw_pins)
        require(os.geteuid() == 0 and re.fullmatch(r"[0-9a-f]{32}", token))
        require(Path("/etc/dockerlens-trial-id").read_text() == token + "\n")
        require(capture(["systemd-detect-virt", "--vm"], deadline)[1] in (b"kvm\n", b"qemu\n"))
        require(capture(["stat", "-f", "-c", "%T", "/proc"], deadline)[1] == b"proc\n")
        swap_zero()
        boot = boot_id()
        require(boot != host_boot)
        kernel = os.uname().release
        require(re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,79}", kernel))
        require(os.cpu_count() == CPUS)
        memory = re.findall(
            r"(?m)^MemTotal:[ \t]+([1-9][0-9]*) kB$", Path("/proc/meminfo").read_text()
        )
        require(len(memory) == 1 and 6 * GIB <= int(memory[0]) * 1024 <= MEMORY)
        result["boot"] = {"kernel": kernel, "identity_sha256": boot, "swap_kib": 0, "vcpus": CPUS}
        result["stage"] = "packages"
        # A per-guest empty Docker client config prevents ambient credentials.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            result["packages"] = packages(pins, "guest", path, deadline)
            client = path / "client"
            client.mkdir(mode=0o700)
            docker = ["docker", "--config", str(client), "--host", "unix:///var/run/docker.sock"]
            result["stage"] = "docker_peer"
            capture(["systemctl", "start", "docker.service"], deadline)
            docker_peer(deadline)
            info = json_document(capture(docker + ["info", "--format", "{{json .}}"], deadline)[1])
            version = info.get("ServerVersion")
            require(
                type(version) is str
                and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[.+~-][0-9A-Za-z.+~-]+)?", version)
            )
            require(
                len(version) <= 60
                and info["OSType"] == "linux"
                and info["DockerRootDir"] == "/var/lib/docker"
            )
            security_options = info["SecurityOptions"]
            require(
                info["CgroupVersion"] == "2"
                and info.get("Rootless", False) is False
                and type(security_options) is list
                and all(
                    type(value) is str and not value.startswith(("name=rootless", "name=userns"))
                    for value in security_options
                )
            )
            result["docker"] = {"server": version, "rootful_peer": True}
            result["stage"] = "fixture_pull"
            digest_ref = fixture_identity(pins)
            reference = pins["fixture_image"]
            capture(docker + ["pull", "--platform", "linux/amd64", reference], deadline)
            image_id, manifest = bind_image(docker, reference, digest_ref, pins, deadline)
            result["stage"] = "fixture_create"
            cidfile = path / "cid"
            created = True
            create = docker + [
                "container",
                "create",
                "--pull=never",
                "--platform",
                "linux/amd64",
                "--cidfile",
                str(cidfile),
                "--name",
                name,
                "--label",
                f"io.dockerlens.boot-trial={token}",
                "--network",
                "none",
                "--privileged",
                "--cgroupns=private",
                "--memory",
                "4g",
                "--pids-limit",
                "512",
                "--cpu-period",
                "100000",
                "--cpu-quota",
                "200000",
                "--entrypoint",
                "/bin/sleep",
                reference,
                "600",
            ]
            try:
                output = capture(create, deadline)[1]
                require(output == cidfile.read_bytes().strip() + b"\n")
                require(re.fullmatch(rb"[0-9a-f]{64}\n", output))
                cid = output.decode().strip()
                capture(docker + ["container", "start", cid], deadline)
                result["stage"] = "fixture_observe"
                observed = inspect(docker, cid, deadline)
                bind_container(observed, cid, name, token)
                bind_container_image(observed, image_id, manifest)
                host = observed["HostConfig"]
                require(
                    host["CgroupnsMode"] == "private"
                    and host["Privileged"] is True
                    and host["Memory"] == 4 * GIB
                    and host["PidsLimit"] == 512
                    and host["CpuPeriod"] == 100000
                    and host["CpuQuota"] == 200000
                    and host["NetworkMode"] == "none"
                )
                state = observed["State"]
                require(state["Running"] is True and type(state["Pid"]) is int and state["Pid"] > 1)
                require(
                    Path(f"/proc/{state['Pid']}/ns/cgroup").stat().st_ino
                    != Path("/proc/self/ns/cgroup").stat().st_ino
                )
                raw = capture(
                    docker + ["exec", "--user", "0", cid, "sh", "-c", CONTAINER_PROBE], deadline
                )[1]
                scope_identity, package, container_boot = raw.splitlines()
                cgroup = (
                    Path(f"/proc/{state['Pid']}/cgroup").read_text().removeprefix("0::").strip()
                )
                require(
                    re.fullmatch(r"/[0-9A-Za-z._/-]{1,240}", cgroup)
                    and ".." not in cgroup.split("/")
                )
                held = (Path("/sys/fs/cgroup") / cgroup.lstrip("/")).stat()
                require(scope_identity == f"{held.st_dev} {held.st_ino}".encode())
                require(
                    package == pins["fixture_debian_package"].encode()
                    and hashlib.sha256(container_boot + b"\n").hexdigest() == boot
                )
                require(inspect(docker, cid, deadline)["State"] == state)
                swap_zero()
                disk = os.statvfs("/")
                result["fixture"] = {
                    "index": reference.rsplit("@", 1)[-1],
                    "platform": pins["fixture_platform"],
                    "package": package.decode(),
                    "swap_kib": 0,
                    "memory_bytes": 4 * GIB,
                    "pids": 512,
                    "cpu_quota": 200000,
                    "cpu_period": 100000,
                }
                result["disk_used_sample_bytes"] = (disk.f_blocks - disk.f_bfree) * disk.f_frsize
                result.update(stage="complete", exit=0, reason="ok")
            finally:
                if cid is None:
                    try:
                        with cidfile.open("rb") as stored:
                            remembered = stored.read(66)
                    except OSError:
                        remembered = b""
                    if re.fullmatch(rb"[0-9a-f]{64}\n?", remembered):
                        cid = remembered.decode().strip()
                result["cleanup"] = remove_container(
                    docker, cid, name, token, time.monotonic() + 14, created
                )
    except Refusal as error:
        result.update(exit=error.code, reason=error.reason)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        result.update(exit=1, reason="io")
    if command_cleanup_failed:
        result["command_cleanup"] = "unverified"
    if result["exit"] == 0:
        if cancelled is not None:
            result.update(exit=128 + cancelled, reason="cancelled")
        elif result["cleanup"] != "removed" or command_cleanup_failed:
            result.update(exit=1, reason="cleanup_failed")
    print(json.dumps(result, separators=(",", ":")), flush=True)
    return result["exit"]


def admitted_host(root, env):
    expected = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "ImageOS": "ubuntu26",
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_JOB": "hosted-zero-swap-trial",
        "GITHUB_WORKFLOW_REF": f"{REPO}/{WORKFLOW}@refs/heads/main",
    }
    require(all(env.get(key) == value for key, value in expected.items()))
    sha = env.get("GITHUB_SHA", "")
    require(re.fullmatch("[a-f0-9]{40}", sha) and env.get("GITHUB_WORKFLOW_SHA") == sha)
    result = {}
    for source, key, pattern in [
        ("GITHUB_RUN_ID", "run", "[1-9][0-9]{0,19}"),
        ("GITHUB_RUN_ATTEMPT", "attempt", "[1-9][0-9]{0,9}"),
        ("ImageVersion", "runner_image", r"[0-9]{8}\.[0-9]+\.[0-9]+"),
    ]:
        result[key] = env.get(source, "")
        require(re.fullmatch(pattern, result[key]))
    git = ["git", "--no-replace-objects", "--no-optional-locks", "-C", str(root)]
    require(capture(git + ["rev-parse", "HEAD"], time.monotonic() + 6)[1] == (sha + "\n").encode())
    require(
        not capture(git + ["status", "--porcelain", "--untracked-files=all"], time.monotonic() + 6)[
            1
        ]
    )
    return result | {"workflow_sha": sha}


def verify_guest(value, status, pins, host_boot):
    require(
        type(value) is dict
        and set(value)
        <= {
            "stage",
            "reason",
            "exit",
            "cleanup",
            "boot",
            "packages",
            "docker",
            "fixture",
            "disk_used_sample_bytes",
            "command_cleanup",
        }
    )
    require(value["stage"] in GUEST_STAGES and value["reason"] in ("ok", *REASONS))
    require(type(value["exit"]) is int and value["exit"] == status and 0 <= status < 256)
    require(value["cleanup"] in ("not_created", "removed", "unverified"))
    if "command_cleanup" in value:
        require(status != 0 and value["command_cleanup"] == "unverified")
    if "boot" in value:
        boot = value["boot"]
        require(set(boot) == {"kernel", "identity_sha256", "swap_kib", "vcpus"})
        require(
            re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,79}", boot["kernel"])
            and re.fullmatch("[0-9a-f]{64}", boot["identity_sha256"])
            and boot["identity_sha256"] != host_boot
            and type(boot["swap_kib"]) is int
            and boot["swap_kib"] == 0
            and type(boot["vcpus"]) is int
            and boot["vcpus"] == CPUS
        )
    if "docker" in value:
        docker = value["docker"]
        require(set(docker) == {"server", "rootful_peer"} and docker["rootful_peer"] is True)
        require(
            re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[.+~-][0-9A-Za-z.+~-]+)?", docker["server"])
            and len(docker["server"]) <= 60
        )
    if "packages" in value:
        require(value["packages"] == pins["guest_packages"])
    if "fixture" in value:
        fixture = value["fixture"]
        require(
            all(
                type(fixture[key]) is int
                for key in ("swap_kib", "memory_bytes", "pids", "cpu_quota", "cpu_period")
            )
        )
        require(
            fixture
            == {
                "index": pins["fixture_image"].rsplit("@", 1)[-1],
                "platform": pins["fixture_platform"],
                "package": pins["fixture_debian_package"],
                "swap_kib": 0,
                "memory_bytes": 4 * GIB,
                "pids": 512,
                "cpu_quota": 200000,
                "cpu_period": 100000,
            }
        )
    if "disk_used_sample_bytes" in value:
        n = value["disk_used_sample_bytes"]
        require(type(n) is int and 0 < n <= DISK)
    if status == 0:
        require(
            set(value)
            == {
                "stage",
                "reason",
                "exit",
                "cleanup",
                "boot",
                "packages",
                "docker",
                "fixture",
                "disk_used_sample_bytes",
            }
            and value["stage"] == "complete"
            and value["reason"] == "ok"
            and value["cleanup"] == "removed"
        )
    else:
        require(value["reason"] != "ok")
    return value


def guest_report(raw, status, pins, host_boot):
    code = exit_status(status) or 1
    if not raw and status:
        raise Refusal("command_failed", code)
    try:
        require(len(raw) <= 4096 and raw.endswith(b"\n") and raw.count(b"\n") == 1)
        return verify_guest(json_document(raw), status, pins, host_boot)
    except (Refusal, ValueError, KeyError, TypeError) as error:
        raise Refusal("guest_response", code) from error


def kvm_errno(error):
    if error.errno in (errno.EACCES, errno.EPERM):
        return "denied"
    if error.errno in (errno.ENOENT, errno.ENODEV, errno.ENXIO):
        return "absent"
    if error.errno in (errno.ENOTTY, errno.EOPNOTSUPP, errno.ENOSYS):
        return "unsupported"
    return "other"


def kvm_group_observation():
    try:
        device = os.lstat(KVM_PATH)
        group_rw = stat.S_IRGRP | stat.S_IWGRP
        if not (
            stat.S_ISCHR(device.st_mode)
            and device.st_rdev == KVM_RDEV
            and device.st_uid == 0
            and device.st_mode & group_rw == group_rw
            and not device.st_mode & stat.S_IWOTH
        ):
            return "other_layout"
        group = grp.getgrnam("kvm").gr_gid
        if device.st_gid != group:
            return "other_layout"
        if group == os.getegid() or group in os.getgroups():
            return "group_rw_held"
        return "group_rw_not_held"
    except (OSError, KeyError):
        return "unobserved"


def kvm_preflight(probe):
    device_fd = vm_fd = None
    operation, detail, reason = "open", "ok", None
    probe.update(device_close="not_opened", vm_close="not_opened")
    try:
        device_fd = os.open(KVM_PATH, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        operation = "device_stat"
        device = os.fstat(device_fd)
        operation = "device_type"
        require(stat.S_ISCHR(device.st_mode))
        operation = "device_identity"
        require(device.st_rdev == KVM_RDEV)
        operation = "api_version"
        require(fcntl.ioctl(device_fd, 0xAE00) == 12)
        operation = "create_vm"
        vm_fd = fcntl.ioctl(device_fd, 0xAE01, 0)
    except OSError as error:
        detail, reason = kvm_errno(error), "unavailable"
        if operation == "open" and detail == "denied":
            probe["group_observation"] = kvm_group_observation()
    except Refusal:
        detail, reason = "mismatch", "refused"
    finally:
        for fd, close_operation in ((vm_fd, "vm_close"), (device_fd, "device_close")):
            if fd is None:
                continue
            try:
                os.close(fd)
            except OSError as error:
                probe[close_operation] = kvm_errno(error)
                if reason is None:
                    operation, detail, reason = (
                        close_operation,
                        probe[close_operation],
                        "unavailable",
                    )
            else:
                probe[close_operation] = "closed"
    probe.update(operation=operation if reason else "complete", detail=detail)
    if reason:
        raise Refusal(reason)


def allocated(work):
    return sum(path.lstat().st_blocks * 512 for path in work.rglob("*") if path.is_file())


def launch_vm(work, port):
    return subprocess.Popen(
        [
            "qemu-system-x86_64",
            "-no-user-config",
            "-nodefaults",
            "-machine",
            "accel=kvm",
            "-cpu",
            "host",
            "-smp",
            str(CPUS),
            "-m",
            "7168M",
            "-display",
            "none",
            "-serial",
            "none",
            "-monitor",
            "none",
            "-no-reboot",
            "-drive",
            f"file={work / 'overlay.qcow2'},format=qcow2,if=virtio",
            "-drive",
            f"file={work / 'seed.iso'},format=raw,media=cdrom,readonly=on",
            "-netdev",
            f"user,id=net,hostfwd=tcp:127.0.0.1:{port}-:22",
            "-device",
            "virtio-net-pci,netdev=net",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        start_new_session=True,
    )


def open_handoff():
    path = Path(os.environ["GITHUB_OUTPUT"])
    require(path.is_absolute())
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and info.st_size == 0
        )
    except (OSError, Refusal):
        os.close(fd)
        raise
    return fd


def publish_receipt(output, handoff, result):
    partial = output.with_suffix(".partial")
    stream = partial.open("x", encoding="ascii")
    try:
        with stream:
            json.dump(result, stream, separators=(",", ":"))
            stream.write("\n")
        os.link(partial, output)
    finally:
        partial.unlink()
    # The runner accepts the closing delimiter at EOF. End there so any
    # short write necessarily leaves an incomplete output command.
    marker = "DOCKERLENS_RECEIPT"
    entry = f"receipt_path<<{marker}\n{output}\n{marker}".encode("ascii")
    if os.write(handoff, entry) != len(entry):
        raise OSError()


def host_trial():
    root = Path(__file__).resolve().parents[1]
    started = time.monotonic()
    deadline = started + 885
    result = {
        "schema": 1,
        "trial": "hosted_zero_swap_boot",
        "stage": "admission",
        "exit": 1,
        "reason": "refused",
        "cleanup": "not_started",
    }
    work = vm = vm_started = output = handoff = None
    try:
        directory = Path(os.environ["RUNNER_TEMP"])
        require(
            re.fullmatch(r"/[A-Za-z0-9._/-]+", str(directory))
            and directory.resolve() == directory
            and directory.is_dir()
            and directory.stat().st_uid == os.geteuid()
        )
        handoff = open_handoff()
        output = Path(tempfile.mkdtemp(prefix="dockerlens-boot-receipt-", dir=directory)) / RESULT
        result["host"] = admitted_host(root, os.environ)
        result["stage"] = "resources"
        require(os.geteuid() != 0 and os.uname().machine == "x86_64")
        available = re.findall(
            r"(?m)^MemAvailable:[ \t]+([1-9][0-9]*) kB$", Path("/proc/meminfo").read_text()
        )
        require(
            len(available) == 1
            and int(available[0]) * 1024 >= 9 * GIB
            and shutil.disk_usage(directory).free >= 12 * GIB
            and len(os.sched_getaffinity(0)) >= CPUS
        )
        host_boot = boot_id()
        result["host"]["identity_sha256"] = host_boot
        result["host"].update(
            available_memory_bytes=int(available[0]) * 1024,
            free_disk_bytes=shutil.disk_usage(directory).free,
            available_cpus=len(os.sched_getaffinity(0)),
        )
        result["stage"] = "kvm"
        result["host"]["kvm_probe"] = probe = {}
        kvm_preflight(probe)
        result["host"]["kvm_api"] = 12
        work = Path(tempfile.mkdtemp(prefix="dockerlens-boot-", dir=directory))
        require(re.fullmatch(r"[A-Za-z0-9._/-]+", str(work)))
        pins = json_document((root / "scripts/hosted-zero-swap-pins.json").read_bytes())
        source = pins["product_fixture_source"]
        require(re.fullmatch(r"[a-f0-9]{40}", source))
        result["product_fixture_source"] = source
        result["stage"] = "host_packages"
        result["host_packages"] = packages(pins, "host", work, deadline)
        result["stage"] = "cloud_image"
        date, digest = pins["cloud_image"].split("@sha256:")
        require(re.fullmatch("[0-9]{8}", date) and re.fullmatch("[0-9a-f]{64}", digest))
        prefix = verify_cloud_manifest(work, date, digest, deadline)
        base = work / "base.qcow2"
        fetch(prefix + IMAGE, base, GIB, deadline)
        with base.open("rb") as file:
            require(hashlib.file_digest(file, "sha256").hexdigest() == digest)
        base.chmod(0o400)
        info = json_document(
            capture(["qemu-img", "info", "--output=json", "-f", "qcow2", str(base)], deadline)[1]
        )
        require(
            info["format"] == "qcow2"
            and "backing-filename" not in info
            and not info.get("encrypted")
            and 0 < info["virtual-size"] <= DISK
        )
        capture(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(base),
                str(work / "overlay.qcow2"),
                "8G",
            ],
            deadline,
        )
        result["cloud_image"] = {"pin": pins["cloud_image"], "signer": SIGNER}
        result["allocation"] = {"memory_bytes": MEMORY, "virtual_disk_bytes": DISK, "vcpus": CPUS}
        result["stage"] = "boot"
        token = secrets.token_hex(16)
        make_seed(work, token, deadline)
        with socket.socket(socket.AF_INET) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        vm_started = time.monotonic()
        vm = launch_vm(work, port)
        boot_deadline = min(deadline, time.monotonic() + 100)
        while True:
            active(boot_deadline)
            exitcode = vm.poll()
            if exitcode is not None:
                raise Refusal("command_failed", exit_status(exitcode) or 1)
            ready = ssh_command(
                work, port, ["sudo", "-n", "test", "-s", "/etc/dockerlens-trial-id"]
            )
            try:
                status, _, _ = capture(
                    ready, min(boot_deadline, time.monotonic() + 7), allow_failure=True
                )
            except Refusal as error:
                if error.reason != "timeout" or command_cleanup_failed:
                    raise
                active(boot_deadline)
            else:
                if status == 0:
                    active(boot_deadline)
                    break
            time.sleep(1)
        capture(
            ssh_command(work, port, ["sudo", "-n", "cloud-init", "status", "--wait"]),
            min(deadline, time.monotonic() + 45),
        )
        result["stage"] = "guest"
        remote = [
            "sudo",
            "-n",
            "python3",
            "-B",
            "-",
            "guest",
            token,
            host_boot,
            json.dumps(pins, separators=(",", ":")),
        ]
        status, raw, _ = capture(
            ssh_command(work, port, remote),
            deadline,
            input_bytes=Path(__file__).read_bytes(),
            allow_failure=True,
        )
        guest = guest_report(raw, status, pins, host_boot)
        result["guest"] = guest
        if status:
            raise Refusal("guest_failed", status)
        result.update(stage="complete", exit=0, reason="ok")
    except Refusal as error:
        result.update(exit=error.code, reason=error.reason)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        result.update(exit=1, reason="io")
    finally:
        if work is not None:
            try:
                if vm is not None:
                    reaped = reap(vm)
                    result["vm_active_ms"] = round((time.monotonic() - vm_started) * 1000)
                    if not reaped:
                        raise OSError()
                try:
                    result["host_disk_allocated_sample_bytes"] = allocated(work)
                finally:
                    shutil.rmtree(work)
                result["cleanup"] = "verified"
            except OSError:
                result["cleanup"] = "unverified"
                if result["exit"] == 0:
                    result.update(exit=1, reason="cleanup_failed")
        if command_cleanup_failed:
            result["command_cleanup"] = "unverified"
        if cancelled is not None and result["exit"] == 0:
            result.update(exit=128 + cancelled, reason="cancelled")
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        try:
            if output is not None:
                publish_receipt(output, handoff, result)
        except OSError:
            if result["exit"] == 0:
                result.update(exit=1, reason="io")
        finally:
            if handoff is not None:
                os.close(handoff)
        print(
            f"DOCKERLENS_HOSTED_BOOT_TRIAL: stage={result['stage']} exit={result['exit']} "
            f"reason={result['reason']} cleanup={result['cleanup']}",
            flush=True,
        )
    return result["exit"]


if __name__ == "__main__":
    os.umask(0o077)
    signal.signal(signal.SIGTERM, request_cancel)
    signal.signal(signal.SIGINT, request_cancel)
    if len(sys.argv) == 5 and sys.argv[1] == "guest":
        sys.exit(within_guest(sys.argv[2:]))
    if len(sys.argv) == 1:
        sys.exit(host_trial())
    sys.exit(2)
