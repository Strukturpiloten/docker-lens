"""Synthetic fixture allocation contracts; never query a daemon or host network."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("fixture_topology", ROOT / "scripts/native_network_topology.py")
TOPO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOPO)
CANDIDATE = "c" * 40
NETWORK = "a" * 64
CANARY = "private-canary /private/socket 10.253.253.7"
HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
          "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch", "ImageOS": "ubuntu24",
          "ImageVersion": "20261023.1.0", "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens",
          "GITHUB_WORKFLOW_REF": "Strukturpiloten/docker-lens/.github/workflows/native-validation.yml@refs/heads/main"}


def raw(value):
    return json.dumps(value, separators=(",", ":")).encode()


def interface(local="192.0.2.1", prefix=24, **extra):
    return [{"ifindex": 1, "ifname": "eth0", "flags": ["UP", "LOWER_UP", "BROADCAST", "MULTICAST"],
             "mtu": 1500, "qdisc": "fq_codel", "operstate": "UP", "group": "default", "link_type": "ether",
             "address": "02:00:00:00:00:01", "broadcast": "ff:ff:ff:ff:ff:ff",
             "addr_info": [{"family": "inet", "local": local, "prefixlen": prefix, "scope": "global",
                            "valid_life_time": 4294967295, "preferred_life_time": 4294967295, **extra}]}]


def network(backend="docker"):
    value = {"Id": NETWORK, "Name": "dl-native-net-test", "Labels": {"io.dockerlens.native-run": "test"}}
    if backend == "docker":
        return value | {"Driver": "bridge", "Scope": "local", "IPAM": {"Driver": "default", "Config": [{"Subnet": "10.253.253.0/24", "Gateway": "10.253.253.1"}]}}
    return value | {"id": NETWORK, "name": "dl-native-net-test", "driver": "bridge",
                    "subnets": [{"subnet": "10.88.0.0/16", "gateway": "10.88.0.1"}], "ipam_options": {"driver": "host-local"}}


def record(backend="docker"):
    value = TOPO.network_projection(network(backend), "test", CANDIDATE, backend,
                                    NETWORK if backend == "docker" else "successful-name-create")
    prefix = "10.253.253." if backend == "docker" else "10.88.0."
    value["endpoints"] = {"daemon": {"id": "b" * 64, "name": "dl-native-test", "ipv4": prefix + "2"},
                          "sidecar": {"id": "d" * 64, "name": "dl-native-egress-test", "ipv4": prefix + "3"}}
    return value


def host_record():
    return {"schema_version": 1, "kind": "test-only-host-network-preflight", "candidate": CANDIDATE,
            "run": "test", "backend": "docker", "reservation": "10.253.253.0/24", "disjoint": True,
            "iproute2": {"path": "/usr/sbin/ip", "device": 1, "inode": 2, "sha256": "f" * 64,
                         "version": "ip utility, iproute2-6.1.0, libbpf 1.3.0"},
            "namespace": {"device": 1, "inode": 3},
            "daemon": {"schema_version": 1, "kind": "local-root-dockerd-observation", "socket": "/var/run/docker.sock",
                       "socket_device": 1, "socket_inode": 4, "peer_pid": 5, "listener_inode": 6,
                       "daemon_pid": 5, "daemon_starttime": 10, "uid": 0, "gid": 0,
                       "executable": "/usr/bin/dockerd", "executable_device": 1, "executable_inode": 7}}


class ParserTests(unittest.TestCase):
    def test_address_prefix_peer_and_noprefixroute_are_not_host_only_checks(self):
        TOPO.host_addresses(raw(interface()))
        TOPO.host_addresses(raw(interface("10.1.2.3", 8, peer="192.0.2.1")))
        TOPO.host_addresses(raw(interface("10.1.2.3", 8, address="192.0.2.1")))
        for value in (interface("10.0.0.1", 8), interface("10.0.0.1", 8, noprefixroute=True),
                      interface("192.0.2.1", 24, peer="10.253.253.8"),
                      interface("10.253.253.8", 32, peer="192.0.2.1"),
                      interface("192.0.2.1", 24, peer="192.0.2.2", address="192.0.2.3"),
                      interface(prefix=True), interface(peer=None), interface(noprefixroute="true")):
            with self.subTest(value=value), self.assertRaises((TOPO.Refused, ValueError, TypeError)):
                TOPO.host_addresses(raw(value))

    def test_all_tables_and_all_default_gateway_source_and_multipath_addresses(self):
        for route in ({"dst": "default", "gateway": "192.0.2.1", "dev": "eth0"},
                      {"dst": "192.0.2.0/24", "table": 253, "type": "blackhole"},
                      {"dst": "default", "table": "default", "nexthops": [{"dev": "eth0", "weight": 1, "flags": ["onlink"]}]}):
            TOPO.host_routes(raw([route]))
        for route in ({"dst": "10.253.253.0/24", "table": 253},
                      {"dst": "10.0.0.0/8", "table": "default"},
                      {"dst": "default", "gateway": "10.253.253.1"},
                      {"dst": "0.0.0.0/0", "prefsrc": "10.253.253.1"},
                      {"dst": "default", "nexthops": [{"gateway": "192.0.2.1"}, {"gateway": "10.253.253.1"}]},
                      {"dst": "default", "nhid": 1}, {"dst": "default", "via": "192.0.2.1"},
                      {"dst": "default", "encap": {}}, {"dst": "default", "from": "192.0.2.1"},
                      {"dst": "default", "src": "192.0.2.1"}, {"dst": "default", "flags": ["unknown"]},
                      {"dst": "default", "nexthops": [{"gateway": "192.0.2.1", "encap": {}}]},
                      {"dst": "192.0.2.1/24"}, {"dst": "default", "type": "nat"}):
            with self.subTest(route=route), self.assertRaises((TOPO.Refused, ValueError, TypeError)):
                TOPO.host_routes(raw([route]))

    def test_documents_reject_recursive_duplicates_partial_nonfinite_and_caps(self):
        for value in (b'{"x":1,"x":2}', b'{"x":{"k":1,"\\u006b":2}}', b'{} {}', b'{',
                      b'{"x":NaN}', b'{"x":1.2}', b' ' * (TOPO.LIMIT + 1), b'{"x":' + b'[' * 22 + b'0' + b']' * 22 + b'}'):
            with self.subTest(value=value[:32]), self.assertRaises((TOPO.Refused, ValueError, RecursionError)):
                TOPO.document(value)

    def test_complete_native_pools_mixed_family_and_backend_identity(self):
        for backend in ("docker", "podman"):
            value = network(backend)
            key = "Config" if backend == "docker" else "subnets"
            pools = value["IPAM"][key] if backend == "docker" else value[key]
            pools.append({"Subnet": "fd00::/64", "Gateway": "fd00::1"} if backend == "docker" else {"subnet": "fd00::/64", "gateway": "fd00::1"})
            actual = TOPO.network_projection(value, "test", CANDIDATE, backend, NETWORK if backend == "docker" else "successful-name-create")
            TOPO.projection(actual, "test", CANDIDATE, backend)
        for mutation in (lambda v: v.update(Scope="swarm"), lambda v: v.update(Id="f" * 64),
                         lambda v: v["IPAM"].update(Driver="plugin"),
                         lambda v: v["IPAM"]["Config"].append({"Subnet": "192.0.2.0/24"}),
                         lambda v: v["IPAM"]["Config"].append({}),
                         lambda v: v["IPAM"]["Config"].append({"Subnet": "fd00::1/64"})):
            value = network()
            mutation(value)
            with self.assertRaises((TOPO.Refused, ValueError)):
                TOPO.network_projection(value, "test", CANDIDATE, "docker", NETWORK)

    def test_endpoint_attachments_and_private_record_binding(self):
        for backend in ("docker", "podman"):
            value = record(backend)
            TOPO.projection(value, "test", CANDIDATE, backend, endpoints=True)
            projected = {key: part for key, part in value.items() if key != "endpoints"}
            endpoint = {"NetworkID": NETWORK, "IPAddress": value["endpoints"]["sidecar"]["ipv4"], "IPPrefixLen": 24 if backend == "docker" else 16}
            TOPO.attachment({"dl-native-net-test": endpoint}, projected, "test", CANDIDATE, backend)
            for field, wrong in (("NetworkID", "f" * 64), ("IPAddress", "192.0.2.8"), ("IPPrefixLen", 32)):
                with self.assertRaises(TOPO.Refused):
                    TOPO.attachment({"dl-native-net-test": endpoint | {field: wrong}}, projected, "test", CANDIDATE, backend)
        for field, wrong in (("candidate", "d" * 40), ("run", "foreign"), ("backend", "podman")):
            with self.assertRaises(TOPO.Refused):
                TOPO.projection(record() | {field: wrong}, "test", CANDIDATE, "docker", endpoints=True)

    def test_exclusive_caller_owned_publication_no_symlink_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "dockerlens-native.test"
            root.mkdir(mode=0o700)
            TOPO.publish(str(root), record(), "test", CANDIDATE, "docker")
            destination = root / "outer-network-topology-v1.json"
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(destination.stat().st_uid, os.geteuid())
            with self.assertRaises(FileExistsError):
                TOPO.publish(str(root), record(), "test", CANDIDATE, "docker")
            destination.unlink()
            destination.symlink_to(Path(directory) / "unbound")
            with self.assertRaises(FileExistsError):
                TOPO.publish(str(root), record(), "test", CANDIDATE, "docker")
            self.assertFalse((Path(directory) / "unbound").exists())

    def test_host_receipt_is_exact_including_every_peer_field_and_tool_version(self):
        TOPO.host_receipt(host_record(), "test", CANDIDATE, "docker")
        for key in host_record()["daemon"]:
            for action in ("missing", "wrong_type"):
                value = host_record()
                if action == "missing":
                    del value["daemon"][key]
                else:
                    value["daemon"][key] = []
                with self.subTest(key=key, action=action), self.assertRaises((TOPO.Refused, TypeError)):
                    TOPO.host_receipt(value, "test", CANDIDATE, "docker")
        for change in (lambda v: v["daemon"].update(unexpected=CANARY),
                       lambda v: v["daemon"].update(uid=True), lambda v: v["daemon"].update(peer_pid=9),
                       lambda v: v["iproute2"].update(version=""), lambda v: v["iproute2"].update(version=CANARY),
                       lambda v: v["namespace"].update(inode=True)):
            value = host_record()
            change(value)
            with self.assertRaises((TOPO.Refused, TypeError)):
                TOPO.host_receipt(value, "test", CANDIDATE, "docker")

    def test_publication_refuses_unsafe_parent_mode_and_replaced_named_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "dockerlens-native.test"
            root.mkdir(mode=0o755)
            root.chmod(0o755)
            with self.assertRaises(TOPO.Refused):
                TOPO.publish(str(root), record(), "test", CANDIDATE, "docker")
            self.assertEqual(list(root.iterdir()), [])
            root.chmod(0o700)
            actual_stat = os.stat
            def replaced(path, *args, **kwargs):
                info = actual_stat(path, *args, **kwargs)
                if path == "outer-network-topology-v1.json":
                    values = {key: getattr(info, key) for key in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")}
                    values["st_ino"] += 1
                    return SimpleNamespace(**values)
                return info
            with patch.object(TOPO.os, "stat", side_effect=replaced), self.assertRaises(TOPO.Refused):
                TOPO.publish(str(root), record(), "test", CANDIDATE, "docker")


class PreflightTests(unittest.TestCase):
    def sample(self, bad_route=False, peer_swap=False, dead=False, malformed=None):
        from native_outer_diagnostic_capture import CaptureOutcome
        import native_outer_diagnostic_capture as capture_module
        calls = []
        peer = host_record()["daemon"]
        namespace = SimpleNamespace(st_dev=1, st_ino=9)
        root = SimpleNamespace(st_dev=1, st_ino=11)
        original_stat = os.stat
        class Retained(BaseException):
            pass
        class FakeCapture:
            def __init__(self, **kwargs):
                self.policy = kwargs
            @contextmanager
            def private_outputs(self):
                yield {}
            def capture_outcome(self, argv, files, prefix, deadline, cancellation):
                calls.append((argv, deadline))
                if prefix == "service":
                    stdout = b"MainPID=5\nActiveState=active\nSubState=running\n"
                elif prefix == "version":
                    stdout = b"ip utility, iproute2-6.1.0, libbpf 1.3.0\n"
                elif prefix == "addresses":
                    stdout = raw(interface())
                else:
                    stdout = raw([{"dst": "default", "gateway": "10.253.253.1" if bad_route else "192.0.2.1"}])
                if malformed is not None and prefix == malformed[0]:
                    stdout = malformed[1]
                return CaptureOutcome(stdout, b"", 0, len(stdout), 0)
        def metadata(path, *args, **kwargs):
            text = str(path)
            if text in ("/proc/5/ns/net", "/proc/self/ns/net"):
                return namespace
            if text in ("/", "/proc/5/root"):
                return root
            return original_stat(path, *args, **kwargs)
        peers = [peer, peer | ({"daemon_starttime": 12} if peer_swap else {})]
        with patch.dict(os.environ, HOSTED, clear=True), patch.object(TOPO.os, "geteuid", return_value=0), \
                patch.object(TOPO, "trusted_tool", side_effect=lambda path, *args: (path, (1, 2), "f" * 64)), \
                patch.object(capture_module, "CaptureContext", FakeCapture), \
                patch.object(TOPO.os, "pidfd_open", return_value=100), \
                patch.object(TOPO.os, "open", side_effect=[101, 102, 103]), \
                patch.object(TOPO.os, "fstat", side_effect=lambda fd: root if fd == 103 else namespace), \
                patch.object(TOPO.os, "stat", side_effect=metadata), patch.object(TOPO.os, "close"), \
                patch.object(TOPO, "process_start", return_value=10), \
                patch.object(TOPO.select, "select", return_value=([100] if dead else [], [], [])), \
                patch.object(TOPO.signal, "signal"), \
                patch.object(TOPO, "hold_original_owner", side_effect=Retained), \
                patch.object(TOPO.time, "monotonic", return_value=100):
            if bad_route or peer_swap or dead or malformed is not None:
                with self.assertRaises(Retained):
                    TOPO.preflight("test", CANDIDATE, lambda *_: peers.pop(0))
            else:
                result = TOPO.preflight("test", CANDIDATE, lambda *_: peers.pop(0))
                self.assertEqual(result["reservation"], "10.253.253.0/24")
                self.assertTrue(result["disjoint"])
        self.assertEqual({deadline for _, deadline in calls}, {107})
        return [argv for argv, _ in calls]

    def test_fixed_commands_share_original_deadline_and_bracket_peer(self):
        calls = self.sample()
        self.assertEqual([argv[1:] for argv in calls], [
            ("show", "docker.service", "--property=MainPID", "--property=ActiveState", "--property=SubState"),
            ("-Version",), ("-j", "-4", "address", "show"), ("-j", "-4", "route", "show", "table", "all"),
            ("show", "docker.service", "--property=MainPID", "--property=ActiveState", "--property=SubState")])

    def test_overlap_identity_change_and_dead_pid_keep_original_timeout_owner(self):
        self.sample(bad_route=True)
        self.sample(peer_swap=True)
        self.sample(dead=True)

    def test_unknown_hosted_context_refuses_before_tools(self):
        for key in HOSTED:
            with self.subTest(key=key), patch.dict(os.environ, HOSTED | {key: CANARY}, clear=True), \
                    patch.object(TOPO, "trusted_tool") as tool:
                with self.assertRaises(TOPO.Refused):
                    TOPO.preflight("test", CANDIDATE, lambda *_: {})
                tool.assert_not_called()

    def test_malformed_or_empty_tool_and_host_output_keeps_original_owner(self):
        for prefix, output in (("version", b""), ("version", CANARY.encode()),
                               ("addresses", b""), ("addresses", b"[] trailing"),
                               ("routes", b"{}"), ("routes", b"[{\"dst\":\"default\",\"dst\":\"default\"}]")):
            with self.subTest(prefix=prefix, output=output):
                self.sample(malformed=(prefix, output))


class OriginalOwnerTests(unittest.TestCase):
    def test_real_capture_timeout_keeps_resistant_descendants_late_eof_and_cancellation_owned(self):
        # Only fake Python clients run. The shorter synthetic GNU timeout tests
        # owner mechanics, not the eight-second production host prerequisite.
        for mode in ("resistant", "late_eof", "cancel"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fake = (
                    "import os,signal,sys,time\nfrom pathlib import Path\n"
                    "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                    "signal.signal(signal.SIGINT,signal.SIG_IGN)\n"
                    "if sys.argv[1]=='late_eof':\n"
                    " child=os.fork()\n"
                    " if child: sys.exit(0)\n"
                    "Path(sys.argv[2]).write_text(str(os.getpid()))\n"
                    "os.write(1,b'private-canary')\n"
                    "if sys.argv[1]=='cancel': os.kill(os.getppid(),signal.SIGINT)\n"
                    "time.sleep(10)\n"
                )
                owner = (
                    "import os,signal,sys,tempfile,time\nfrom pathlib import Path\n"
                    f"sys.path.insert(0,{str(ROOT / 'scripts')!r})\n"
                    "import native_network_topology as topology\n"
                    "from native_outer_diagnostic_capture import CaptureContext,Cancelled,Cancellation\n"
                    "base=Path(sys.argv[1]); mode=sys.argv[2]\n"
                    "original=tempfile.mkdtemp\n"
                    "tempfile.mkdtemp=lambda **kw: original(dir=base,**kw)\n"
                    "cancellation=Cancellation()\n"
                    "for signum in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP): signal.signal(signum,cancellation.request)\n"
                    f"command=(sys.executable,'-c',{fake!r},mode,str(base/'child.pid'))\n"
                    "capture=CaptureContext(unavailable=topology.Refused,cancelled_type=Cancelled,commands=((command,'fake'),),environment={},directory=base,stream_limit=1024,total_source_limit=2048,reuse_outputs=False)\n"
                    "try:\n"
                    " with capture.private_outputs() as files:\n"
                    "  capture.capture_outcome(command,files,'fake',time.monotonic()+0.2,cancellation)\n"
                    "except BaseException:\n"
                    " (base/'retained').write_text('original-owner')\n"
                    " topology.hold_original_owner()\n"
                    "raise SystemExit(90)\n"
                )
                started = time.monotonic()
                process = subprocess.Popen(["/usr/bin/timeout", "--signal=TERM", "--kill-after=0.25s", "0.5s",
                                            sys.executable, "-c", owner, str(root), mode],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=True, preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
                try:
                    stdout, stderr = process.communicate(timeout=3)
                    self.assertIn(process.returncode, (124, 137, -signal.SIGKILL))
                    self.assertTrue((root / "retained").exists())
                    self.assertLess(time.monotonic() - started, 3)
                    self.assertEqual(stdout, b"")
                    self.assertNotIn(b"private-canary", stderr)
                    self.assertEqual(list(root.glob("dockerlens-runtime-profile.*")), [])
                    pid = int((root / "child.pid").read_text())
                    status = Path(f"/proc/{pid}/stat")
                    if status.exists():
                        self.assertEqual(status.read_text().rpartition(") ")[2].split()[0], "Z", "fake descendant still executing")
                finally:
                    # Exact synthetic owner group only; never a runtime/host PID.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.communicate(timeout=2)


if __name__ == "__main__":
    unittest.main()
