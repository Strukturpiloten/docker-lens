"""Closed test-only fixture allocation checks; no product/network execution API.

Only preflight executes commands, in its inherited root timeout group. All other
phases parse private held observations or publish one fixed caller-owned file.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import sys
import time

LIMIT = 65536
NODES = 8192
RESERVATION = ipaddress.IPv4Network("10.253.253.0/24")
ID = re.compile(r"[0-9a-f]{64}")
SHA = re.compile(r"[0-9a-f]{40}")
RUN = re.compile(r"[A-Za-z0-9-]{1,64}")
TOKEN = re.compile(r"[A-Za-z0-9_.:@-]{1,128}")
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
ROUTE_KEYS = frozenset({"dst", "type", "table", "protocol", "scope", "metric", "dev", "flags", "gateway", "prefsrc", "nexthops"})
ROUTE_TYPES = frozenset({"unicast", "local", "broadcast", "multicast", "throw", "unreachable", "prohibit", "blackhole"})
ROUTE_FLAGS = frozenset({"onlink", "linkdown", "pervasive"})
LINK_KEYS = frozenset({"ifindex", "ifname", "flags", "mtu", "qdisc", "operstate", "group", "txqlen", "link_type", "address", "broadcast", "master", "link_index", "link_netnsid", "altnames", "addr_info"})
LINK_FLAGS = frozenset({"LOOPBACK", "BROADCAST", "POINTOPOINT", "MULTICAST", "NOARP", "UP", "LOWER_UP", "DORMANT", "PROMISC", "ALLMULTI", "MASTER", "SLAVE", "NOTRAILERS", "DEBUG", "ECHO"})
ADDRESS_FLAGS = frozenset({"secondary", "dynamic", "deprecated", "tentative", "dadfailed", "noprefixroute", "autojoin", "mngtmpaddr", "home", "permanent", "stable-privacy"})
ADDRESS_KEYS = frozenset({"family", "local", "address", "peer", "prefixlen", "broadcast", "scope", "label", "valid_life_time", "preferred_life_time"}) | ADDRESS_FLAGS


class Refused(ValueError):
    """No native value or host path belongs in a public error."""


def need(condition):
    if not condition:
        raise Refused("fixture topology unavailable")


def pairs(items):
    value = {}
    for key, item in items:
        need(key not in value)
        value[key] = item
    return value


def document(raw, expected=dict):
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT)
    def invalid(_value):
        raise Refused("fixture topology unavailable")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        need(depth <= 20 and count <= NODES)
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        else:
            need(type(item) in {str, int, bool, type(None)})
    need(type(value) is expected)
    return value


def encoded(value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(len(raw) <= LIMIT)
    return raw


def integer(value, maximum=2**32 - 1, minimum=0):
    need(type(value) is int and minimum <= value <= maximum)


def token(value):
    need(type(value) is str and TOKEN.fullmatch(value) is not None)


def flags(value, allowed):
    need(type(value) is list and len(value) <= len(allowed)
         and all(type(item) is str and item in allowed for item in value)
         and len(set(value)) == len(value))


def ipv4(value):
    need(type(value) is str)
    address = ipaddress.IPv4Address(value)
    need(str(address) == value)
    return address


def subnet(value):
    need(type(value) is str and "/" in value)
    pool = ipaddress.ip_network(value, strict=True)
    need(str(pool) == value)
    return pool


def clear(pool):
    need(not pool.overlaps(RESERVATION))


def host_addresses(raw):
    interfaces = document(raw, list)
    need(len(interfaces) <= 4096)
    seen = set()
    for interface in interfaces:
        need(type(interface) is dict and set(interface) <= LINK_KEYS
             and {"ifindex", "ifname", "addr_info"} <= set(interface))
        integer(interface["ifindex"], minimum=1)
        token(interface["ifname"])
        need(interface["ifindex"] not in seen)
        seen.add(interface["ifindex"])
        for key, value in interface.items():
            if key in {"ifindex", "addr_info"}:
                continue
            if key == "flags":
                flags(value, LINK_FLAGS)
            elif key in {"mtu", "txqlen", "link_index"}:
                integer(value)
            elif key == "link_netnsid":
                integer(value, minimum=-1)
            elif key == "altnames":
                need(type(value) is list and len(value) <= 64)
                for name in value:
                    token(name)
            elif key == "group" and type(value) is int:
                integer(value)
            else:
                token(value)
        addresses = interface["addr_info"]
        need(type(addresses) is list and len(addresses) <= 4096)
        for address in addresses:
            need(type(address) is dict and set(address) <= ADDRESS_KEYS
                 and {"family", "local", "prefixlen"} <= set(address)
                 and address["family"] == "inet")
            local = ipv4(address["local"])
            prefix = address["prefixlen"]
            integer(prefix, 32)
            need(not {"peer", "address"} <= set(address))
            peer = address.get("peer", address.get("address"))
            if peer is None:
                need("peer" not in address and "address" not in address)
                clear(ipaddress.IPv4Network((local, prefix), strict=False))
            else:
                # For point-to-point addresses prefixlen belongs to the peer.
                clear(ipaddress.IPv4Network((local, 32)))
                clear(ipaddress.IPv4Network((ipv4(peer), prefix), strict=False))
            for key, value in address.items():
                if key in ADDRESS_FLAGS:
                    need(type(value) is bool)
                elif key in {"scope", "label"}:
                    token(value)
                elif key in {"valid_life_time", "preferred_life_time"}:
                    if value != "forever":
                        integer(value)
                elif key == "broadcast":
                    clear(ipaddress.IPv4Network((ipv4(value), 32)))


def host_routes(raw):
    routes = document(raw, list)
    need(len(routes) <= 4096)
    for route in routes:
        need(type(route) is dict and set(route) <= ROUTE_KEYS and "dst" in route)
        need(route.get("type", "unicast") in ROUTE_TYPES)
        destination = route["dst"]
        if destination not in {"default", "0.0.0.0/0"}:
            pool = subnet(destination) if type(destination) is str and "/" in destination else ipaddress.IPv4Network((ipv4(destination), 32))
            need(pool.version == 4)
            clear(pool)
        for key in ("gateway", "prefsrc"):
            if key in route:
                clear(ipaddress.IPv4Network((ipv4(route[key]), 32)))
        for key in ("table", "protocol", "scope"):
            if key in route:
                value = route[key]
                if type(value) is int:
                    integer(value)
                else:
                    token(value)
        if "metric" in route:
            integer(route["metric"])
        if "dev" in route:
            token(route["dev"])
        if "flags" in route:
            flags(route["flags"], ROUTE_FLAGS)
        if "nexthops" in route:
            hops = route["nexthops"]
            need(type(hops) is list and 0 < len(hops) <= 256)
            for hop in hops:
                need(type(hop) is dict and set(hop) <= {"gateway", "dev", "weight", "flags"}
                     and ("gateway" in hop or "dev" in hop))
                if "gateway" in hop:
                    clear(ipaddress.IPv4Network((ipv4(hop["gateway"]), 32)))
                if "dev" in hop:
                    token(hop["dev"])
                if "weight" in hop:
                    integer(hop["weight"], 256, 1)
                if "flags" in hop:
                    flags(hop["flags"], ROUTE_FLAGS)


def context(run, candidate, backend):
    need(RUN.fullmatch(run) is not None and SHA.fullmatch(candidate) is not None
         and backend in {"docker", "podman"})


def native_pools(configs, native):
    need(type(configs) is list and 0 < len(configs) <= 64)
    pools = []
    for config in configs:
        need(type(config) is dict)
        key = "Subnet" if native == "docker" else "subnet"
        allowed = {"Subnet", "Gateway", "IPRange", "AuxiliaryAddresses"} if native == "docker" else {"subnet", "gateway"}
        need(set(config) <= allowed and key in config)
        pool = subnet(config[key])
        gateway = config.get("Gateway" if native == "docker" else "gateway")
        if gateway not in {None, ""}:
            need(type(gateway) is str)
            address = ipaddress.ip_address(gateway)
            need(str(address) == gateway and address.version == pool.version and address in pool)
        if "IPRange" in config and config["IPRange"] != "":
            allocation = subnet(config["IPRange"])
            need(allocation.version == pool.version and allocation.subnet_of(pool))
        if "AuxiliaryAddresses" in config:
            auxiliary = config["AuxiliaryAddresses"]
            need(type(auxiliary) is dict and len(auxiliary) <= 256)
            for name, value in auxiliary.items():
                token(name)
                need(type(value) is str)
                address = ipaddress.ip_address(value)
                need(str(address) == value and address.version == pool.version and address in pool)
        need(all(not pool.overlaps(other) for other in pools if other.version == pool.version))
        pools.append(pool)
    need(any(pool.version == 4 for pool in pools))
    return [str(pool) for pool in pools if pool.version == 4]


def network_projection(value, run, candidate, backend, held_id):
    context(run, candidate, backend)
    name = "dl-native-net-" + run
    need(type(value) is dict and value.get("Name") == name
         and type(value.get("Id")) is str and ID.fullmatch(value["Id"]) is not None
         and type(value.get("Labels")) is dict
         and value["Labels"].get("io.dockerlens.native-run") == run)
    if backend == "docker":
        need(value["Id"] == held_id and value.get("Driver") == "bridge"
             and value.get("Scope") == "local" and type(value.get("IPAM")) is dict
             and value["IPAM"].get("Driver") == "default")
        pools = native_pools(value["IPAM"].get("Config"), "docker")
        need(pools == [str(RESERVATION)])
        scope, driver, ipam = "local", "bridge", "default"
    else:
        need(held_id == "successful-name-create" and value.get("name") == name
             and value.get("driver") == "bridge" and value.get("id") == value["Id"])
        pools = native_pools(value.get("subnets"), "podman")
        options = value.get("ipam_options")
        need(type(options) is dict and options.get("driver") == "host-local")
        scope, driver, ipam = None, "bridge", "host-local"
    return {"schema_version": 1, "kind": "test-only-outer-network-topology", "candidate": candidate,
            "run": run, "backend": backend, "network": {"id": value["Id"], "name": name,
            "driver": driver, "scope": scope, "ipam_driver": ipam, "ipv4_pools": pools}}


def projection(value, run, candidate, backend, endpoints=False):
    context(run, candidate, backend)
    keys = {"schema_version", "kind", "candidate", "run", "backend", "network"}
    need(type(value) is dict and set(value) == keys | ({"endpoints"} if endpoints else set())
         and type(value["schema_version"]) is int and value["schema_version"] == 1
         and value["kind"] == "test-only-outer-network-topology"
         and (value["run"], value["candidate"], value["backend"]) == (run, candidate, backend))
    network = value["network"]
    need(type(network) is dict and set(network) == {"id", "name", "driver", "scope", "ipam_driver", "ipv4_pools"}
         and type(network["id"]) is str and ID.fullmatch(network["id"]) is not None
         and network["name"] == "dl-native-net-" + run and network["driver"] == "bridge"
         and (network["scope"], network["ipam_driver"]) == (("local", "default") if backend == "docker" else (None, "host-local")))
    pools = network["ipv4_pools"]
    need(type(pools) is list and 0 < len(pools) <= 64)
    parsed = [subnet(pool) for pool in pools]
    need(all(pool.version == 4 for pool in parsed)
         and all(not pool.overlaps(other) for index, pool in enumerate(parsed) for other in parsed[index + 1:]))
    if backend == "docker":
        need(pools == [str(RESERVATION)])
    if endpoints:
        observed = value["endpoints"]
        need(type(observed) is dict and set(observed) == {"daemon", "sidecar"})
        for role, prefix in (("daemon", "dl-native-"), ("sidecar", "dl-native-egress-")):
            endpoint = observed[role]
            need(type(endpoint) is dict and set(endpoint) == {"id", "name", "ipv4"}
                 and type(endpoint["id"]) is str and ID.fullmatch(endpoint["id"]) is not None
                 and endpoint["name"] == prefix + run)
            need(any(ipv4(endpoint["ipv4"]) in pool for pool in parsed))
        need(observed["daemon"]["id"] != observed["sidecar"]["id"]
             and observed["daemon"]["ipv4"] != observed["sidecar"]["ipv4"])
    return parsed


def attachment(networks, value, run, candidate, backend):
    pools = projection(value, run, candidate, backend)
    network = value["network"]
    need(type(networks) is dict and set(networks) == {network["name"]})
    endpoint = networks[network["name"]]
    need(type(endpoint) is dict and endpoint.get("NetworkID") == network["id"])
    address = ipv4(endpoint.get("IPAddress"))
    integer(endpoint.get("IPPrefixLen"), 32)
    need(any(address in pool and endpoint["IPPrefixLen"] == pool.prefixlen for pool in pools))


def file_identity(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink


def host_receipt(value, run, candidate, backend):
    need(backend == "docker" and set(value) == {"schema_version", "kind", "candidate", "run", "backend", "reservation", "disjoint", "iproute2", "daemon", "namespace"}
         and type(value["schema_version"]) is int and value["schema_version"] == 1
         and value["kind"] == "test-only-host-network-preflight"
         and (value["run"], value["candidate"], value["backend"]) == (run, candidate, backend)
         and value["reservation"] == str(RESERVATION) and value["disjoint"] is True)
    tool = value["iproute2"]
    need(type(tool) is dict and set(tool) == {"path", "sha256", "version", "device", "inode"}
         and tool["path"] in {"/usr/sbin/ip", "/usr/bin/ip"}
         and type(tool["sha256"]) is str and ID.fullmatch(tool["sha256"]) is not None
         and type(tool["version"]) is str
         and re.fullmatch(r"ip utility, iproute2-[0-9]+\.[0-9]+\.[0-9]+(?:, libbpf [0-9]+\.[0-9]+\.[0-9]+)?", tool["version"]) is not None
         and type(value["namespace"]) is dict and set(value["namespace"]) == {"device", "inode"})
    for key in ("device", "inode"):
        integer(tool[key], 2**64 - 1, 1 if key == "inode" else 0)
        integer(value["namespace"][key], 2**64 - 1, 1 if key == "inode" else 0)
    peer = value["daemon"]
    need(type(peer) is dict and set(peer) == {"schema_version", "kind", "socket", "socket_device", "socket_inode", "peer_pid", "listener_inode", "daemon_pid", "daemon_starttime", "uid", "gid", "executable", "executable_device", "executable_inode"}
         and type(peer["schema_version"]) is int and peer["schema_version"] == 1
         and peer["kind"] == "local-root-dockerd-observation" and peer["socket"] == "/var/run/docker.sock"
         and peer["executable"] in {"/usr/bin/dockerd", "/usr/sbin/dockerd", "/usr/local/bin/dockerd"})
    for key in ("socket_device", "socket_inode", "listener_inode", "daemon_starttime", "executable_device", "executable_inode"):
        integer(peer[key], 2**64 - 1, 1 if key in {"socket_inode", "listener_inode", "daemon_starttime", "executable_inode"} else 0)
    integer(peer["daemon_pid"], 2**31 - 1, 2)
    integer(peer["peer_pid"], 2**31 - 1, 1)
    integer(peer["uid"], 0)
    integer(peer["gid"], 0)
    need(peer["peer_pid"] in {1, peer["daemon_pid"]})


def publish(directory, value, run, candidate, backend, host=False):
    if host:
        host_receipt(value, run, candidate, backend)
        filename = "outer-network-preflight-v1.json"
    else:
        projection(value, run, candidate, backend, endpoints=True)
        filename = "outer-network-topology-v1.json"
    root = Path(directory)
    need(root.is_absolute() and root.name == "dockerlens-native." + run and root.resolve() == root)
    held = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(held)
        need(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o700)
        descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=held)
        with os.fdopen(descriptor, "wb") as output:
            info = os.fstat(output.fileno())
            need(info.st_uid == os.geteuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600)
            output.write(encoded(value))
            output.flush()
            os.fsync(output.fileno())
            need(file_identity(os.stat(filename, dir_fd=held, follow_symlinks=False)) == file_identity(os.fstat(output.fileno())))
        current = os.lstat(root)
        need((current.st_dev, current.st_ino, current.st_uid) == (before.st_dev, before.st_ino, before.st_uid))
    finally:
        os.close(held)


def admitted(environment):
    need(all(environment.get(key) == value for key, value in {
        "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
        "GITHUB_REF": "refs/heads/main", "ImageOS": "ubuntu24"}.items())
         and environment.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch"}
         and re.fullmatch(r"[0-9]{8}\.[0-9]+\.[0-9]+", environment.get("ImageVersion", "")) is not None)
    repository, workflow = environment.get("GITHUB_REPOSITORY"), environment.get("GITHUB_WORKFLOW_REF", "")
    need((repository == "Strukturpiloten/docker-lens" and re.fullmatch(r"Strukturpiloten/docker-lens/\.github/workflows/(check|native-validation|release-validation)\.yml@refs/heads/main", workflow) is not None)
         or (repository == "Strukturpiloten/boxferry" and workflow == "Strukturpiloten/boxferry/.github/workflows/reviewed-docker-consumer-validation.yml@refs/heads/main"))
    need(not any(environment.get(key) for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION", "CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINER_SSHKEY", "PODMAN_CONNECTIONS_CONF")))


def checkpoint(deadline, cancellation):
    cancellation.check()
    need(time.monotonic() < deadline)


def trusted_tool(path, deadline, cancellation):
    # Resolve only reviewed system aliases; no PATH or caller tool authority.
    actual = Path(path).resolve(strict=True)
    need(str(actual) in {"/usr/sbin/ip", "/usr/bin/ip", "/usr/bin/systemctl"})
    for parent in (actual.parent, *actual.parents):
        info = os.stat(parent)
        need(info.st_uid == 0 and info.st_mode & 0o022 == 0)
    descriptor = os.open(actual, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_mode & 0o022 == 0
             and before.st_mode & stat.S_IXUSR and 0 < before.st_size <= 16 * 1024 * 1024)
        digest = hashlib.sha256()
        count = 0
        while True:
            checkpoint(deadline, cancellation)
            raw = os.read(descriptor, 65536)
            if not raw:
                break
            count += len(raw)
            need(count <= 16 * 1024 * 1024)
            digest.update(raw)
        need(count == before.st_size and file_identity(before) == file_identity(os.fstat(descriptor))
             and file_identity(before) == file_identity(os.stat(actual, follow_symlinks=False)))
        return str(actual), file_identity(before), digest.hexdigest()
    finally:
        os.close(descriptor)


def process_start(pid):
    raw = Path(f"/proc/{pid}/stat").read_bytes()
    need(len(raw) <= 4096)
    prefix, separator, suffix = raw.rpartition(b") ")
    fields = suffix.split()
    need(separator and prefix.startswith(str(pid).encode() + b" (") and len(fields) >= 20 and fields[19].isdigit())
    return int(fields[19])


def hold_original_owner():
    # Never leave the timeout's group or return while completion is uncertain:
    # exiting would let GNU timeout cancel its scheduled group KILL.
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, signal.SIG_IGN)
    while True:
        signal.pause()


def preflight(run, candidate, peer_observer):
    from native_outer_diagnostic_capture import Cancelled, Cancellation, CaptureContext
    context(run, candidate, "docker")
    admitted(os.environ)
    need(os.geteuid() == 0 and os.environ.get("DOCKERLENS_NATIVE_CANDIDATE_SHA", candidate) == candidate)
    deadline = time.monotonic() + 7
    cancellation = Cancellation()
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, cancellation.request)
    launched = False
    held = []
    try:
        ip = trusted_tool("/usr/sbin/ip", deadline, cancellation)
        systemctl = trusted_tool("/usr/bin/systemctl", deadline, cancellation)
        service = (systemctl[0], "show", "docker.service", "--property=MainPID", "--property=ActiveState", "--property=SubState")
        version = (ip[0], "-Version")
        addresses = (ip[0], "-j", "-4", "address", "show")
        routes = (ip[0], "-j", "-4", "route", "show", "table", "all")
        capture = CaptureContext(unavailable=Refused, cancelled_type=Cancelled,
            commands=((service, "service"), (version, "version"), (addresses, "addresses"), (routes, "routes")),
            environment=ENVIRONMENT, directory=Path(__file__).resolve().parent,
            stream_limit=LIMIT, total_source_limit=8 * LIMIT, reuse_outputs=True)
        with capture.private_outputs() as files:
            def command(argv, prefix):
                nonlocal launched
                checkpoint(deadline, cancellation)
                launched = True
                result = capture.capture_outcome(argv, files, prefix, deadline, cancellation)
                need(result.returncode == 0 and not result.stderr)
                checkpoint(deadline, cancellation)
                return result.stdout
            before = peer_observer("/var/run/docker.sock", command(service, "service").decode("ascii"))
            pid = before["daemon_pid"]
            held.append(os.pidfd_open(pid, 0))
            held.append(os.open(f"/proc/{pid}/ns/net", os.O_RDONLY))
            held.append(os.open("/proc/self/ns/net", os.O_RDONLY))
            held.append(os.open(f"/proc/{pid}/root", os.O_RDONLY | os.O_DIRECTORY))
            def stable():
                checkpoint(deadline, cancellation)
                need(not select.select([held[0]], [], [], 0)[0] and process_start(pid) == before["daemon_starttime"])
                ours, daemon = os.fstat(held[2]), os.fstat(held[1])
                current = os.stat(f"/proc/{pid}/ns/net")
                observer = os.stat("/proc/self/ns/net")
                need((ours.st_dev, ours.st_ino) == (daemon.st_dev, daemon.st_ino)
                     == (current.st_dev, current.st_ino) == (observer.st_dev, observer.st_ino))
                root, current_root, observer_root = os.fstat(held[3]), os.stat(f"/proc/{pid}/root"), os.stat("/")
                need((root.st_dev, root.st_ino) == (current_root.st_dev, current_root.st_ino) == (observer_root.st_dev, observer_root.st_ino))
            stable()
            tool_version = command(version, "version").decode("ascii").strip()
            need(re.fullmatch(r"ip utility, iproute2-[0-9]+\.[0-9]+\.[0-9]+(?:, libbpf [0-9]+\.[0-9]+\.[0-9]+)?", tool_version) is not None)
            host_addresses(command(addresses, "addresses"))
            stable()
            host_routes(command(routes, "routes"))
            stable()
            after = peer_observer("/var/run/docker.sock", command(service, "service").decode("ascii"))
            need(before == after)
            stable()
            need(ip == trusted_tool(ip[0], deadline, cancellation)
                 and systemctl == trusted_tool(systemctl[0], deadline, cancellation))
        checkpoint(deadline, cancellation)
        namespace = os.fstat(held[1])
        return {"schema_version": 1, "kind": "test-only-host-network-preflight", "candidate": candidate,
            "run": run, "backend": "docker", "reservation": str(RESERVATION), "disjoint": True,
            "iproute2": {"path": ip[0], "sha256": ip[2], "version": tool_version,
                         "device": ip[1][0], "inode": ip[1][1]},
            "daemon": before, "namespace": {"device": namespace.st_dev, "inode": namespace.st_ino}}
    except BaseException:
        if launched:
            hold_original_owner()
        raise
    finally:
        for descriptor in held:
            os.close(descriptor)


def main(argv):
    try:
        need(len(argv) >= 4)
        phase, run, candidate, backend, *args = argv
        context(run, candidate, backend)
        value = document(sys.stdin.buffer.read(LIMIT + 1))
        if phase == "network" and len(args) == 1:
            print(encoded(network_projection(value, run, candidate, backend, args[0])).decode(), end="")
        elif phase == "finalize" and len(args) == 4:
            projection(value, run, candidate, backend)
            daemon_id, sidecar_id, daemon_ip, sidecar_ip = args
            value["endpoints"] = {"daemon": {"id": daemon_id, "name": "dl-native-" + run, "ipv4": daemon_ip},
                                  "sidecar": {"id": sidecar_id, "name": "dl-native-egress-" + run, "ipv4": sidecar_ip}}
            projection(value, run, candidate, backend, endpoints=True)
            print(encoded(value).decode(), end="")
        elif phase == "publish" and len(args) == 1:
            publish(args[0], value, run, candidate, backend)
        elif phase == "publish-host" and len(args) == 1:
            publish(args[0], value, run, candidate, backend, host=True)
        else:
            raise Refused()
        return 0
    except (Refused, OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        print("fixture topology unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
